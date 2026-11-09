"""Provenance findings: what an agent did after untrusted content reached its model.

Each finding names what was observed, not a conclusion. The dashboard implements the
same rules in JavaScript, so keep the two in step.

MNQ-001  untrusted argument   A tool call's arguments carry a destination or identifier
                              (email address, URL or host, account number, long number)
                              that appears in untrusted content in the model's context
                              and nowhere in the system prompt or the user's messages.
MNQ-002  auto-approval        An action was approved without a human after untrusted
                              content reached the model in this run, and the action is
                              sensitive or carries a value from that content. (Approving a
                              reply to the sender is what an inbox agent does all day.)
MNQ-003  egress after taint   An outbound connection (not to loopback, and not the agent's
                              own model API) after untrusted content reached the model in this run.
                              A datagram or raw socket the audit hooks noted counts too.
MNQ-004  untrusted sensitive  A sensitive action (credentials, permissions, deletion,
         action               cancellations, changes to accounts, payments) ran with an
                              argument value that appears in untrusted content and not in
                              the system prompt or the user's messages.
MNQ-005  untrusted link in    The model's answer carries an image, or a link with data in
         answer               its query, to a host that appears in untrusted content and
                              not in the user's or system's words. An image is fetched the
                              moment the answer is shown, so it can carry data out with no
                              tool call at all.
MNQ-006  internal data to     A tool sends data from the company's own systems (tool output
         new recipient        labelled internal) to an address or host that appears neither in
                              those systems nor in the system prompt: the price list to a
                              "new customer", the customer list to an outside address. It
                              needs no injection, only data leaving to someone the company
                              has no record of.
MNQ-000  not evaluated        Not an observation about the agent: the rules could not read this
                              record (a field of a type the recorder never writes), so findings
                              that depend on it, here or later in the run, may be missing.
                              ``mnestiq verify`` reports the same record as invalid. Also a
                              model call whose context could not be restored in full (it is
                              still evaluated on what it has), and a record the rules' work
                              limit stopped. Those two can be on a file that verifies. So can a
                              note in a tainted run saying further datagram or raw socket
                              destinations were not noted, as MNQ-003 cannot see what is unnamed.

MNQ-001 is the hijack signature: an injected instruction has to put the attacker's
address, account or URL into a tool call. MNQ-004 covers hijacks with no destination
("change the password to ...", "delete file 13"), and MNQ-005 hijacks that leak through
the answer itself ("end your reply with this image: ...?u=<the customer's email>"). MNQ-006 covers data handed
to someone who asked for it, with no instruction to plant. Data-driven
work also does all three
(visiting a link a colleague posted, deleting the file a search found), so a finding is
a lead to review, not a verdict.

A tool is sensitive when the recorder marked it (``@recorder.tool(sensitive=True)``),
or, when unmarked, when its name says so (``update_password``, ``delete_file``, ...).

Evidence from the model API proxy (``mnestiq proxy``) has no tool_call events: it sees the model
ask for a tool, not the tool run. There MNQ-004 looks at the tool calls the model asked for, and
says "requested".
"""

from __future__ import annotations

import bisect
import ipaddress
import math
import re
from collections.abc import Iterable
from contextvars import ContextVar
from typing import Any

from .canonical import _format_number
from .context import expand

UNTRUSTED = frozenset({"tool_output", "retrieved_doc", "web", "agent_msg", "memory", "unknown"})
TRUSTED = frozenset({"system", "user", "internal"})

NOT_EVALUATED = "MNQ-000"
RULES = {
    NOT_EVALUATED: "record not evaluated",
    "MNQ-001": "untrusted argument",
    "MNQ-002": "auto-approval",
    "MNQ-003": "egress after taint",
    "MNQ-004": "untrusted sensitive action",
    "MNQ-005": "untrusted link in answer",
    "MNQ-006": "internal data to new recipient",
}

SENSITIVE_NAME = re.compile(
    r"password|passwd|credential|secret|token|api_?key|permission|role|grant|revoke|delete|remove|erase|"
    r"reset|disable|transfer|refund|payment|send_money|pay_|schedule_transaction|update_scheduled|"
    r"update_user|update_email|update_account|create_user|reserve|book_|"
    r"cancel|suspend|deactivate|terminate|close_account|change_|modify_|forward|share_|invite|unsubscribe|"
    r"discount|bank|iban|payout|credit|update_customer|update_supplier|update_vendor|update_payee",
    re.IGNORECASE | re.ASCII)
# For these, a bare number (a record id) is the whole payload: "delete file 13", "cancel order 4100".
_DESTRUCTIVE_NAME = re.compile(r"delete|remove|erase|revoke|disable|cancel|suspend|deactivate|terminate",
                               re.IGNORECASE | re.ASCII)
_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?")

# Every pattern below takes time in proportion to its text, however hostile, and the page has the same ones.
# A repeat that can fail and start again from the next character is bounded, or the match takes the text it
# read with it. re.ASCII keeps word boundaries and ignored case as JavaScript has them. Whitespace is spelled
# out because Python's \s and JavaScript's differ: this is JavaScript's.
_SPACE_CHARS = "".join(map(chr, (9, 10, 11, 12, 13, 32, 0xa0, 0x1680, *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f,
                                 0x205f, 0x3000, 0xfeff)))
_S = re.escape(_SPACE_CHARS)
_TLDS = "com|org|net|io|co|ai|dev|app|info|biz|xyz|me|us|uk|de|eu|ly|gl|link|site|online"
# Limits a real address has: 254 characters in all, a DNS label of 63. A host with more labels is matched by its end.
_EMAIL = re.compile(r"[A-Za-z0-9_.+-]{1,254}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,16}")
_URL = re.compile(rf"(?:https?://|www\.)[^{_S}\"'<>)\]]+"
                  rf"|\b[A-Za-z0-9-]{{1,63}}(?:\.[A-Za-z0-9-]{{1,63}}){{0,6}}\.(?:{_TLDS})\b(?:/[^{_S}\"'<>)\]]*)?",
                  re.IGNORECASE | re.ASCII)
_ACCOUNT = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b", re.ASCII)  # IBAN-shaped
# The same, printed in groups of four: "GR96 0810 0010 0000 0123 4567 890".
_SPACED_ACCOUNT = re.compile(r"\b[A-Z]{2}[0-9]{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?\b",
                             re.IGNORECASE | re.ASCII)
_ACCOUNT_SHAPE = re.compile(r"[a-z]{2}[0-9]{2}[a-z0-9]{10,30}")
_LONG_NUMBER = re.compile(r"\+?[0-9][0-9 -]{7,}[0-9]")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")  # 2024-03-07 is not a number to trace
_SEPARATORS = re.compile(r"[ -]")
_DIGIT_SEPARATOR = re.compile(r"[ -](?<=[0-9][ -])(?=[0-9])")  # "12 34-56" is one number, "account 1234" is not
MAX_REDUCED = 128  # past this many indicators in one value, the longest-form reduction is skipped
_URL_PREFIX = re.compile(r"^(?:https?://)?(?:www\.)?")  # a model may add or drop these when it copies a link
_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_WORD = _ALNUM | {"_", "-"}

# The work one run of findings() may do looking things up in context, in characters scanned. A small hostile
# file can ask for very many lookups in one large context. A real run stays far below this. What the limit
# stops is reported as MNQ-000 on the record it stopped. The page has the same limit.
MAX_EFFORT = 1_000_000_000
EFFORT_PER_RECORD = 100_000  # so that a large file is not held to what a small one gets
EFFORT_PER_CHARACTER = 16  # the same: content the file really holds earns work, and carried context does not
_EFFORT_PER_MATCH = 500  # checking the characters around a match costs about this many characters scanned


class _Effort:
    def __init__(self) -> None:
        self.left = MAX_EFFORT
        self.cut = False  # set when something was not examined, until findings() has reported it
        self.segments: dict[int, tuple[dict, _Segment]] = {}  # a carried segment is read only once

    def spend(self, amount: int) -> bool:
        if amount > self.left:
            self.cut = True
            return False
        self.left -= amount
        return True


_EFFORT: ContextVar[_Effort | None] = ContextVar("mnestiq_findings_effort", default=None)


def _spend(amount: int) -> bool:
    effort = _EFFORT.get()
    return effort is None or effort.spend(amount)


def indicators(text: str) -> set[str]:
    """Destinations and identifiers worth tracing, normalised for comparison."""
    found = {m.group().lower().rstrip(".,;:/") for rx in (_EMAIL, _ACCOUNT) for m in rx.finditer(text)}
    found |= {_URL_PREFIX.sub("", m.group().lower()).rstrip(".,;:/") for m in _URL.finditer(text)}
    found |= {_SEPARATORS.sub("", m.group()) for m in _LONG_NUMBER.finditer(text) if not _DATE.search(m.group())}
    found |= {_SEPARATORS.sub("", m.group()).lower() for m in _SPACED_ACCOUNT.finditer(text)}
    found = {f for f in found if len(f) >= 6}
    if len(found) > MAX_REDUCED:  # a form that is also part of a longer one only costs a lookup
        return found
    # Keep the longest form: an email's domain or an IBAN's digits are not separate indicators.
    return {f for f in found if not any(g != f and f in g for g in found)}


def strings(value: Any) -> list[str]:
    """Every scalar inside a JSON value, as text. A number reads as JSON would write it, as on the page:
    the same number has the same text however the file spells it (4100, 4100.0, 4.1e3)."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    if isinstance(value, float) and math.isfinite(value):
        return [_format_number(value)]
    return [] if value is None else [str(value)]


class _Segment:
    """What the lookups need from one context segment."""

    def __init__(self, segment: dict) -> None:
        self.text = "\n".join(strings(segment.get("content"))).lower()
        self.compact = _DIGIT_SEPARATOR.sub("", self.text)
        self.accounts = {_SEPARATORS.sub("", m.group()) for m in _SPACED_ACCOUNT.finditer(self.text)}


def _read_segment(segment: dict) -> _Segment:
    effort = _EFFORT.get()
    if effort is None:
        return _Segment(segment)
    known = effort.segments.get(id(segment))
    if known is None:
        known = effort.segments[id(segment)] = (segment, _Segment(segment))  # holding it keeps its id unique
        effort.left += EFFORT_PER_CHARACTER * len(known[1].text)
    return known[1]


def _present(text: str, needle: str, before: frozenset[str]) -> bool:
    """Whether ``needle`` is in ``text`` as a whole match: no letter or digit right after it, and no
    character of ``before`` right in front of it."""
    if not _spend(len(text) + 16):
        return False
    at = text.find(needle)
    while at != -1:
        end = at + len(needle)
        if (at == 0 or text[at - 1] not in before) and (end == len(text) or text[end] not in _ALNUM):
            return True
        if not _spend(_EFFORT_PER_MATCH):
            return False
        at = text.find(needle, at + 1)
    return False


class _Corpus:
    """Lower-cased text of some context segments, with a separator-free copy for numbers."""

    def __init__(self, segments: Iterable[dict]) -> None:
        parts = [_read_segment(seg) for seg in segments]
        size = sum(len(p.text) + 16 for p in parts)
        whole = _spend(2 * size)
        self.text = "\n".join(p.text for p in parts) if whole else ""
        self.compact = "\n".join(p.compact for p in parts) if whole else ""
        self.accounts = {a for p in parts for a in p.accounts} if whole else set()

    def __contains__(self, indicator: str) -> bool:
        if _ACCOUNT_SHAPE.fullmatch(indicator) and indicator in self.accounts:
            return True
        # Whole matches only: "billing@acme.exam" must not count as present in "billing@acme.example".
        digits = indicator.isascii() and indicator.isdigit()
        return _present(self.compact if digits or indicator.startswith("+") else self.text, indicator, _WORD)

    def holds(self, value: str) -> bool:
        """Whether ``value`` is in this text as a whole token."""
        return _present(self.text, value, _ALNUM)


def untrusted_arguments(llm_call: dict) -> list[dict]:
    """MNQ-001 for one llm_call record: tool-call arguments introduced by untrusted content."""
    context = llm_call.get("context") or []
    untrusted_segments = [s for s in context if s.get("source") in UNTRUSTED]
    if not untrusted_segments or not llm_call.get("tool_calls"):
        return []
    untrusted = _Corpus(untrusted_segments)
    trusted = _Corpus(s for s in context if s.get("source") in TRUSTED)
    hits = []
    for call in llm_call["tool_calls"]:
        for value in strings(call.get("arguments")):
            for ind in sorted(indicators(value)):
                found = ind if ind in untrusted and ind not in trusted else None
                if found is None and re.search(r"[/?]", ind):
                    # The planted link may end in "?d=" and the model fill in the data: the host is
                    # what came from the untrusted content.
                    host = _host(ind)
                    if len(host) >= 6 and "." in host and host in untrusted and host not in trusted:
                        found = host
                if found:
                    sources = sorted({s["source"] for s in untrusted_segments if found in _Corpus([s])})
                    hits.append({"tool": call.get("name"), "indicator": ind, "sources": sources})
    return hits


_READ_ONLY = re.compile(r"^(get|list|read|search|find|fetch|lookup|query|describe|view|show|check)_")


def _snake(name: str) -> str:
    """sendMoney and SendMoney read as send_money, so the names below match whatever the style."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def is_sensitive(tool_call_record: dict, name: str) -> bool:
    marked = (tool_call_record.get("attributes") or {}).get("sensitive")
    if isinstance(marked, bool):
        return marked
    snake = _snake(name or "")
    # get_cancellation_policy, list_invites: reading about an action is not taking it.
    return not _READ_ONLY.match(snake) and bool(SENSITIVE_NAME.search(snake))


def untrusted_values(tool: str, arguments: Any, context: list[dict]) -> list[dict]:
    """Argument values (whole tokens) found in untrusted context but not in the user's or system's words.

    Dates, true/false and values under three characters ("r" for read access) never count. Plain
    numbers count for destructive tools, where the id is the whole payload, and from four digits
    up for any sensitive action (a credit limit of 60000, a refund of 2400): shorter ones are
    quantities and percentages that match by chance."""
    untrusted_segments = [s for s in context if s.get("source") in UNTRUSTED]
    untrusted = _Corpus(untrusted_segments)
    trusted = _Corpus(s for s in context if s.get("source") in TRUSTED)
    destructive = bool(_DESTRUCTIVE_NAME.search(tool or ""))
    hits = []
    for value in strings(arguments):
        v = value.strip(_SPACE_CHARS).lower()
        if len(v) > 200 or v in ("true", "false", "none", "null") or _DATE.fullmatch(v):
            continue
        if _NUMBER.fullmatch(v):
            if not destructive and len(v.lstrip("+-").split(".")[0]) < 4:
                continue
        elif len(v) < 3:
            continue
        if untrusted.holds(v) and not trusted.holds(v):
            sources = sorted({s["source"] for s in untrusted_segments if _Corpus([s]).holds(v)})
            hits.append({"value": value.strip(_SPACE_CHARS), "sources": sources})
    return hits


# Each of these matches as soon as it has read to the closing bracket, whether or not what follows makes it
# an image: the text it read is not read again from the next "![" inside it.
_IMAGE = re.compile(rf"!\[[^\]]*(?:\]\([{_S}]*<?([^){_S}>]+))?|<img\b([^>]*)", re.IGNORECASE | re.ASCII)
_IMAGE_SRC = re.compile(rf"\bsrc[{_S}]*=[{_S}]*[\"']?([^\"'{_S}>]+)", re.IGNORECASE | re.ASCII)
_LINK = re.compile(rf"https?:[/\\]*[^{_S}\"'<>)\]]+", re.IGNORECASE | re.ASCII)
_REF_IMAGE = re.compile(r"!\[[^\]]*(?:\]\[([^\]]+)\])?")
_REF_DEF = re.compile(rf"^[ \t]*\[([^\]]*)(?:\]:[{_S}]*<?([^{_S}]+?)>?(?:[{_S}]|$))?", re.MULTILINE)


def _images(text: str) -> set[str]:
    """The addresses of the images in an answer: markdown, an HTML tag, or a markdown reference."""
    found = set()
    for m in _IMAGE.finditer(text):
        source = m.group(1) or (_IMAGE_SRC.search(m.group(2)) if m.group(2) else None)
        if source:
            found.add(source if isinstance(source, str) else source.group(1))
    refs = {m.group(1).lower(): m.group(2) for m in _REF_DEF.finditer(text) if m.group(1) and m.group(2)}  # [ref]: url
    labels = (m.group(1).lower() for m in _REF_IMAGE.finditer(text) if m.group(1))
    return found | {refs[label] for label in labels if label in refs}


MAX_LABELS = 16  # a host and its parents, from the end: the end of a longer name is what its owner controls


def _domains(host: str) -> list[str]:
    """The host and its parent domains of two labels or more: a.b.evil.example, b.evil.example, evil.example."""
    labels = host.split(".")[-MAX_LABELS:]
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]
_SKIP_BLOCKS = frozenset({"tool_use", "function_call", "tool_call", "thinking", "redacted_thinking"})


def answer_text(value: Any) -> str:
    """The text of a model's answer (an llm_call's output content), without its tool calls."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(answer_text(v) for v in value)
    if isinstance(value, dict) and value.get("type") not in _SKIP_BLOCKS:
        text = value.get("text")
        return text if isinstance(text, str) else answer_text(value.get("content"))
    return ""


_SCHEME = re.compile(r"^(?:[a-z][a-z0-9+.-]*:)?[/\\]*")  # //host, https:/host and a backslash form all load


def _host(url: str) -> str:
    """The host of a link, lower-cased, without scheme, user, port or path. The dashboard does the same."""
    rest = _SCHEME.sub("", url.lower())
    rest = re.split(r"[/\\?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]  # a browser reads a backslash as a slash
    return rest.split("]")[0] + "]" if rest.startswith("[") else rest.split(":")[0]


def answer_links(llm_call: dict) -> list[dict]:
    """MNQ-005 for one llm_call record: images, and links carrying data, that untrusted content put
    in the model's answer."""
    context = llm_call.get("context") or []
    untrusted_segments = [s for s in context if s.get("source") in UNTRUSTED]
    text = answer_text((llm_call.get("output") or {}).get("content"))
    if not untrusted_segments or not text:
        return []
    untrusted = _Corpus(untrusted_segments)
    trusted = _Corpus(s for s in context if s.get("source") in TRUSTED)
    images = _images(text)
    candidates = [(u, "image") for u in sorted(images)]
    candidates += [(m.group(), "link") for m in _LINK.finditer(text)
                   if m.group() not in images and "?" in m.group() and "=" in m.group().split("?", 1)[1]]
    hits, seen = [], set()
    for url, kind in candidates:
        host = _host(url)
        # img.evil.example loads from evil.example's owner too: the host or a parent domain counts.
        named = next((d for d in _domains(host) if d in untrusted), None)
        if len(host) < 4 or (host, kind) in seen or named is None or any(d in trusted for d in _domains(host)):
            continue
        seen.add((host, kind))
        sources = sorted({s["source"] for s in untrusted_segments if named in _Corpus([s])})
        hits.append({"kind": kind, "host": host, "url": url[:200], "sources": sources})
    return hits


# Model APIs: an agent's calls to its model are recorded as llm_call events, and the recorder leaves
# them out of egress. Evidence from older versions or other tools may hold them: they are not
# "egress after taint". (Data sent to a model API under someone else's key would not show here.
# Pinning which keys and hosts an agent may use is a network control.)
MODEL_API_HOSTS = frozenset({"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
                             "api.mistral.ai", "api.cohere.com", "api.cohere.ai", "api.groq.com", "api.x.ai",
                             "api.deepseek.com", "openrouter.ai"})
_MODEL_API_HOST = re.compile(r"(\.openai\.azure\.com|\.services\.ai\.azure\.com|-aiplatform\.googleapis\.com"
                             r"|^bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com)\Z")


def is_model_api_host(host: Any) -> bool:
    """A model provider's API host: api.openai.com, <resource>.openai.azure.com, bedrock-runtime..."""
    name = str(host or "").lower()
    name = name[:-1] if name.endswith(".") else name  # one dot makes a name absolute, and two make no name at all
    return name in MODEL_API_HOSTS or bool(_MODEL_API_HOST.search(name))


def _is_model_api(egress: dict) -> bool:
    return is_model_api_host(egress.get("host"))


_SOCKET_NOTES = ("udp_connect", "udp_send", "raw_connect", "raw_send")


def _is_own_model_api(record: dict, egress: dict) -> bool:
    """A model API's name in a request sent through a proxy no one vouched for says nothing about who reads it."""
    return _is_model_api(egress) and not _via_proxy(record)


def _via_proxy(record: dict) -> str:
    via = (record.get("attributes") or {}).get("via_proxy")
    return via if isinstance(via, str) else ""


def _network_note(record: dict) -> dict | None:
    """What a note says about a datagram or raw socket, in the shape of an egress entry. The format has no egress
    entry for these, so the audit hooks write notes. Name lookups are left out: nearly every connection makes one."""
    attributes = record.get("attributes")
    note = attributes.get("network") if isinstance(attributes, dict) else None
    if not isinstance(note, dict) or note.get("kind") not in _SOCKET_NOTES:
        return None
    if any(field in note and not isinstance(note[field], str) for field in ("dest_ip", "host")):
        return None  # the recorder writes text here, and the page could not compare anything else the same way
    return note


def _socket_notes_ran_out(record: dict) -> bool:
    """Whether this note says that further datagram or raw socket destinations go unnamed from here on. A limit on
    loopback alone leaves nothing out that MNQ-003 would count."""
    attributes = record.get("attributes")
    note = attributes.get("network") if isinstance(attributes, dict) else None
    if not isinstance(note, dict):
        return False
    if note.get("kind") == "limit_reached":
        return note.get("of") in _SOCKET_NOTES and note.get("loopback") is not True
    by_kind = note.get("by_kind")
    return note.get("kind") == "dropped_summary" and isinstance(by_kind, dict) and any(
        kind in _SOCKET_NOTES for kind in by_kind)


def _is_local(record: dict, egress: dict) -> bool:
    """Loopback traffic never leaves the machine (a local model server, a sidecar): not egress. A
    request for another host sent to a proxy on this machine does leave it, and a loopback name sent
    to a proxy on another machine is that machine's loopback."""
    via = _via_proxy(record)
    if via and not _loopback(via):
        return False
    return _loopback(egress.get("dest_ip") or egress.get("host")) and (
        not egress.get("host") or _loopback(egress.get("host")))


def _loopback(value: Any) -> bool:
    host = str(value or "")
    try:
        address = ipaddress.ip_address(host.strip("[]").split("%")[0])
    except ValueError:
        return host.lower() == "localhost"
    # Python before 3.13 does not look inside ::ffff:127.0.0.1, and the page must agree on every version.
    return (getattr(address, "ipv4_mapped", None) or address).is_loopback


_SENDS = re.compile(r"send|mail|post|upload|share|forward|publish|webhook|message|reply|notify")
_DESTINATION_KEY = re.compile(r"^(to|cc|bcc|recipients?|emails?|address|url|endpoint|webhook|destination|target)$",
                              re.IGNORECASE | re.ASCII)
_DATA_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]*")  # codes, prices, ids: with a digit after the first character
_DIGIT = re.compile(r"[0-9]")
MIN_CARRIED = 5  # distinct pieces of internal data: a reply about one order carries 2 or 3, a list many more


def _destinations(arguments: Any) -> list[str]:
    """Email addresses, links and hosts a call sends to: its to, url and similar arguments, or
    any argument when it has none of those."""
    named = [v for k, v in arguments.items() if _DESTINATION_KEY.match(str(k))] if isinstance(arguments, dict) else []
    return sorted({i for v in strings(named or arguments) for i in indicators(v) if "@" in i or "." in i})


def internal_data_out(tool: str, arguments: Any, context: list[dict]) -> list[dict]:
    """MNQ-006 for one tool call: internal data sent to an address or host the company has no record of."""
    snake = _snake(tool or "")
    internal = [s for s in context if s.get("source") == "internal"]
    if _READ_ONLY.match(snake) or not _SENDS.search(snake) or not internal:
        return []
    system = _Corpus(s for s in context if s.get("source") == "system")
    known = _Corpus([*internal, *(s for s in context if s.get("source") == "system")])
    new = [d for d in _destinations(arguments) if d not in known
           and not any(dom in system for dom in _domains(_host(d.rsplit("@", 1)[-1])))]  # the company's own domains
    if not new:
        return []
    # What the message carries that only the company's systems said: not the sender's words, the
    # user's, or the system prompt's. The model's own text is left out, since it repeats what it read.
    data, others = _Corpus(internal), _Corpus(s for s in context if s.get("source") in UNTRUSTED | {"user", "system"})
    tokens = {t.lower().rstrip(".,;:") for v in strings(arguments)
              for t in _DATA_TOKEN.findall(v) if _DIGIT.search(t, 1)}
    # A price the system returned as 86.4 is written 86.40 in a message.
    tokens |= {t.rstrip("0").rstrip(".") for t in tokens if re.fullmatch(r"[0-9]+\.[0-9]*0", t)}
    carried = sorted(t for t in tokens if len(t) >= 4 and t in data and t not in others)
    if len(carried) < MIN_CARRIED:
        return []
    return [{"destination": d, "carried": carried} for d in new]


def _approval_matters(name: str, call: dict | None, context: list[dict]) -> bool:
    """MNQ-002 keeps quiet about routine approvals: an approval without a human is worth a lead when
    the approved call carries a value from untrusted content. Sensitive alone is not enough: a
    policy approving the discounts it was set up to approve is the policy working. (On 14 October
    test data, adding it back flagged three more normal runs and caught nothing new.)"""
    if call is None:  # no matching tool call in the evidence: judged by the name alone
        return is_sensitive({}, name)
    return (bool(untrusted_values(name, call.get("arguments"), context))
            or bool(untrusted_arguments({"context": context, "tool_calls": [call]})))


class _State:
    def __init__(self) -> None:
        self.out: list[tuple[int, dict]] = []  # (record index, finding), sorted at the end
        self.taint: dict[str, int] = {}  # run_id -> step at which untrusted content first reached the model
        self.context: dict[str, list[dict]] = {}  # run_id -> context of its latest model call
        # run_id -> request key -> contexts of the model calls that asked for it and have not been answered
        self.requests: dict[str, dict[str, list[list[dict]]]] = {}
        self.latest_asked: dict[str, set[str]] = {}  # run_id -> request keys of its latest model call
        # run_id -> tool name -> calls seen, in order: (record index, name, record, call, context at the time)
        self.calls: dict[str, dict[str, list[tuple[int, str, dict, dict, list[dict]]]]] = {}
        # run_id -> approvals without a human, waiting for the tool call they approved
        self.approvals: dict[str, list[tuple[int, dict, dict]]] = {}


def _leaves(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in _leaves(v)]
    if isinstance(value, list):
        return [s for v in value for s in _leaves(v)]
    if isinstance(value, bool):  # as the page writes it
        return ["true" if value else "false"]
    return strings(value)


def _request_key(call: dict) -> str | None:
    """What makes a tool call the one a model asked for: its name and its argument values."""
    try:
        return "\0".join([str(call.get("name") or ""), *sorted(_leaves(call.get("arguments")))])
    except (RecursionError, ValueError):  # too deep to read here: it counts as asked for by no one
        return None


def findings(records: Iterable[dict]) -> list[dict]:
    """All findings in a sequence of records (any mix of runs), in record order. Model calls that
    record only what changed are read with their full context (``mnestiq.context.expand``).

    A record the rules cannot read is never passed over in silence: it comes back as an MNQ-000 entry,
    in its place in the order, because whatever it held may have been what a finding depended on. So is a
    model call whose context could not be restored in full, and a record the work limit stopped."""
    st = _State()
    effort = _Effort()
    token = _EFFORT.set(effort)
    try:
        for i, r in enumerate(expand(records)):
            effort.left += EFFORT_PER_RECORD
            problem = _unreadable_field(r)
            if problem:
                st.out.append((i, _not_evaluated(r, problem)))
                continue
            incomplete = _incomplete_context(r)
            if incomplete:
                st.out.append((i, incomplete))
            try:
                _one(i, r, st)
            except Exception as exc:  # a file can hold anything: one record must not cost the rest
                st.out.append((i, _not_evaluated(r, f"reading it failed ({type(exc).__name__})")))
            if effort.cut:
                effort.cut = False
                st.out.append((i, _not_evaluated(r, _OVER_LIMIT)))
        for run_id, pending in st.approvals.items():
            for i, finding, a in pending:
                # The approved call comes next. Failing that, the latest one before the approval.
                name = str(a.get("action") or "")
                calls = st.calls.get(run_id, {}).get(name, [])
                later = bisect.bisect_right(calls, i, key=lambda c: c[0])
                match = calls[later] if later < len(calls) else calls[-1] if calls else None
                try:
                    call, context = (match[3], match[4]) if match else (None, [])
                    matters = _approval_matters(name, call, context)
                except Exception as exc:
                    st.out.append((i, {**finding, "rule": NOT_EVALUATED, "taint_step": None,
                                       "detail": f"approval could not be judged ({type(exc).__name__}): "
                                                 "an MNQ-002 finding may be missing"}))
                    continue
                if effort.cut:
                    effort.cut = False
                    st.out.append((i, {**finding, "rule": NOT_EVALUATED, "taint_step": None,
                                       "detail": f"approval could not be judged ({_OVER_LIMIT}): "
                                                 "an MNQ-002 finding may be missing"}))
                if matters:
                    st.out.append((i, finding))
    finally:
        _EFFORT.reset(token)
    return [f for _, f in sorted(st.out, key=lambda x: x[0])]


_OVER_LIMIT = "the rules reached their work limit on this file"
_CONTEXT_MARKS = (("x-context-truncated", "it is past the limit on carried context"),
                  ("x-context-missing", "the call it builds on was not found"))


def _incomplete_context(r: dict) -> dict | None:
    """The MNQ-000 entry for a model call whose full context could not be put back, or None. What it does
    have is still evaluated, but a finding that depends on the rest cannot appear."""
    if r.get("event_type") != "llm_call":
        return None
    for mark, why in _CONTEXT_MARKS:
        if r.get(mark) is not None:
            return {**_not_evaluated(r, ""), "detail": f"llm_call context is incomplete: {why}. "
                                                       "Findings that depend on the rest of it may be missing"}
    attributes = r.get("attributes")
    if isinstance(attributes, dict) and attributes.get("output_captured") is False and not _no_answer(r, attributes):
        return {**_not_evaluated(r, ""), "detail": "llm_call output was not captured. "
                                                   "Findings that depend on what the model asked for may be missing"}
    if isinstance(attributes, dict) and (attributes.get("output_captured") == "partial"
                                         or attributes.get("partial") is True):
        return {**_not_evaluated(r, ""), "detail": "llm_call output was only partly captured: the stream stopped "
                                                   "early or went past the size limit. Findings that depend on the "
                                                   "rest of what the model asked for may be missing"}
    return None


def _no_answer(record: dict, attributes: dict) -> bool:
    """The provider answered with an error, or not at all: there was no output to miss. An answer cut off on the way
    carries a capture note and still counts."""
    return record.get("status") == "error" and not attributes.get("capture_note")


_EVALUATED = frozenset({"llm_call", "tool_call", "approval", "egress"})
_FIELD_TYPES = (("run_id", str), ("context", list), ("tool_calls", list), ("approvals", list), ("egress", list),
                ("attributes", dict), ("output", dict), ("seq", int), ("step_id", int))
_MAY_BE_NULL = frozenset({"attributes", "output"})  # nothing the rules depend on is lost when these are empty
# Inside each list, what the rules compare as text. A number there would read as "not untrusted" or "not approved".
_ENTRY_TEXT = (("context", ("source",)), ("tool_calls", ("name",)),
               ("approvals", ("action", "decision", "approver_type")), ("egress", ("host", "dest_ip")))
MAX_NAME = 1024  # a tool's name is matched against many patterns, and no real one is this long


def _unreadable_field(r: Any) -> str | None:
    """Why the rules cannot read this record, or None. Records the rules have no use for (a checkpoint, a
    run's start and end) pass. Anything else must hold what the recorder writes, or an empty or missing
    field would read as "nothing happened"."""
    if not isinstance(r, dict):
        return "it is not a JSON object"
    kind = r.get("event_type")
    if kind is None and r.get("kind") != "event":
        return None
    if not isinstance(kind, str):
        return "event_type is not text"
    if kind not in _EVALUATED:
        return None
    if "run_id" not in r:
        return "it has no run_id"
    for name, expected in _FIELD_TYPES:
        if name not in r or (r[name] is None and name in _MAY_BE_NULL):
            continue
        if not _is_a(r[name], expected):
            return f"{name} is not a {expected.__name__}"
    for name, texts in _ENTRY_TEXT:
        for entry in r.get(name) or []:
            if not isinstance(entry, dict):
                return f"an entry of {name} is not an object"
            for text in texts:
                if entry.get(text) is not None and not isinstance(entry[text], str):
                    return f"{text} in an entry of {name} is not text"
                if text in ("name", "action") and len(entry.get(text) or "") > MAX_NAME:
                    return f"{text} in an entry of {name} is over {MAX_NAME} characters"
    return None


def _is_a(value: Any, expected: type) -> bool:
    if isinstance(value, bool):
        return False
    if expected is int and isinstance(value, float):  # JSON's 4.0 is the number 4, and hashes the same
        return value.is_integer()
    return isinstance(value, expected)


def _not_evaluated(r: Any, why: str) -> dict:
    fields = r if isinstance(r, dict) else {}
    run_id, seq, step, kind = (fields.get(k) for k in ("run_id", "seq", "step_id", "event_type"))
    return {"run_id": run_id if isinstance(run_id, str) else None,
            "seq": seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
            "step": step if isinstance(step, int) and not isinstance(step, bool) else None,
            "rule": NOT_EVALUATED, "taint_step": None,
            "detail": f"{kind[:40] if isinstance(kind, str) else 'record'} not evaluated: {why}. "
                      "Findings that depend on it may be missing"}


def _one(i: int, r: dict, st: _State) -> None:
    run_id, kind = r.get("run_id"), r.get("event_type")
    if run_id is None:
        return
    base = {"run_id": run_id, "seq": r.get("seq"), "step": r.get("step_id")}
    taint, context = st.taint, st.context

    def add(finding: dict) -> None:
        st.out.append((i, {**base, **finding}))

    if kind == "llm_call":
        context[run_id] = r.get("context") or []
        st.latest_asked[run_id] = set()
        for call in r.get("tool_calls") or []:
            key = _request_key(call)
            if key is not None:
                st.requests.setdefault(run_id, {}).setdefault(key, []).append(context[run_id])
                st.latest_asked[run_id].add(key)
        if run_id not in taint and any(s.get("source") in UNTRUSTED for s in context[run_id]):
            taint[run_id] = r.get("step_id", 0)
        for hit in untrusted_arguments(r):
            add({"rule": "MNQ-001", "taint_step": r.get("step_id"),
                 "detail": f"{hit['tool']} <- {hit['indicator']} (from {','.join(hit['sources'])})"})
        for link in answer_links(r):
            add({"rule": "MNQ-005", "taint_step": r.get("step_id"),
                 "detail": f"{link['kind']} to {link['host']} in the answer (from "
                           f"{','.join(link['sources'])}): {link['url']}"})
        if (r.get("attributes") or {}).get("captured_by") == "proxy":
            # Behind the proxy, the model asking for an action is as near as the evidence gets to
            # the action itself.
            for call in r.get("tool_calls") or []:
                if run_id in taint and is_sensitive(r, call.get("name")):
                    for hit in untrusted_values(call.get("name"), call.get("arguments"), context[run_id]):
                        add({"rule": "MNQ-004", "taint_step": taint[run_id],
                             "detail": f"{call.get('name')} (requested) <- {hit['value']!r} "
                                       f"(from {','.join(hit['sources'])})"})
                for out in internal_data_out(call.get("name"), call.get("arguments"), context[run_id]):
                    add({"rule": "MNQ-006", "taint_step": taint.get(run_id, r.get("step_id")),
                         "detail": f"{call.get('name')} (requested) -> {out['destination']} carrying "
                                   f"{', '.join(out['carried'][:3])} (from internal)"})
    elif (run_id in taint and kind == "egress" and not _is_local(r, (r.get("egress") or [{}])[0])
          and not _is_own_model_api(r, (r.get("egress") or [{}])[0])):
        e = (r.get("egress") or [{}])[0]
        add({"rule": "MNQ-003", "taint_step": taint[run_id],
             "detail": f"{e.get('source_ip', '?')}:{e.get('source_port', '?')} -> "
                       f"{e.get('dest_ip', '?')}:{e.get('dest_port', '?')}"})
    elif (run_id in taint and kind == "note" and (socket_note := _network_note(r)) is not None
          and not _is_local(r, socket_note) and not _is_own_model_api(r, socket_note)):
        add({"rule": "MNQ-003", "taint_step": taint[run_id],
             "detail": f"{socket_note['kind']} -> {socket_note.get('dest_ip') or socket_note.get('host') or '?'}:"
                       f"{'?' if socket_note.get('dest_port') is None else socket_note['dest_port']}"})
    elif run_id in taint and kind == "note" and _socket_notes_ran_out(r):
        add({"rule": NOT_EVALUATED, "taint_step": None,
             "detail": "further datagram or raw socket destinations were not noted. "
                       "Findings that depend on them may be missing"})
    elif run_id in taint and kind == "approval":
        a = (r.get("approvals") or [{}])[0]
        if a.get("decision") == "approved" and a.get("approver_type") != "human":
            st.approvals.setdefault(run_id, []).append(
                (i, {**base, "rule": "MNQ-002", "taint_step": taint[run_id],
                     "detail": f"{a.get('action')} by {a.get('approver')}"}, a))
    elif kind == "tool_call":
        for call in r.get("tool_calls") or []:
            # The model call that asked for this tool call, when another thread's has come in between.
            # In a run that goes one step at a time the latest model call asked for it, and is the one used.
            key = _request_key(call)
            asked = st.requests.get(run_id, {}).get(key or "")
            older = asked.pop() if asked else None
            ctx = context.get(run_id, []) if older is None or key in st.latest_asked.get(run_id, ()) else older
            name = str(call.get("name") or "")
            st.calls.setdefault(run_id, {}).setdefault(name, []).append((i, name, r, call, ctx))
            for out in internal_data_out(call.get("name"), call.get("arguments"), ctx):
                add({"rule": "MNQ-006", "taint_step": taint.get(run_id, r.get("step_id")),
                     "detail": f"{call.get('name')} -> {out['destination']} carrying "
                               f"{', '.join(out['carried'][:3])} (from internal)"})
            if run_id not in taint or not is_sensitive(r, call.get("name")):
                continue
            for hit in untrusted_values(call.get("name"), call.get("arguments"), ctx):
                add({"rule": "MNQ-004", "taint_step": taint[run_id],
                     "detail": f"{call.get('name')} <- {hit['value']!r} (from {','.join(hit['sources'])})"})
