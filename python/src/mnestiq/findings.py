"""Provenance findings: what an agent did after untrusted content reached its model.

Each finding names what was observed, not a conclusion. The dashboard implements the
same rules in JavaScript, so keep the two in step.

MNQ-001  untrusted argument   A tool call's arguments carry a destination or identifier
                              (email address, URL or host, account number, long number)
                              that appears in untrusted content in the model's context
                              and nowhere in the system prompt or the user's messages.
MNQ-002  auto-approval        An action was approved without a human after untrusted
                              content reached the model in this run.
MNQ-003  egress after taint   An outbound connection (not to loopback) after untrusted
                              content reached the model in this run.
MNQ-004  untrusted sensitive  A sensitive action (credentials, permissions, deletion,
         action               cancellations, changes to accounts, payments) ran with an
                              argument value that appears in untrusted content and not in
                              the system prompt or the user's messages.
MNQ-005  untrusted link in    The model's answer carries an image, or a link with data in
         answer               its query, to a host that appears in untrusted content and
                              not in the user's or system's words. An image is fetched the
                              moment the answer is shown, so it can carry data out with no
                              tool call at all.

MNQ-001 is the hijack signature: an injected instruction has to put the attacker's
address, account or URL into a tool call. MNQ-004 covers hijacks with no destination
("change the password to ...", "delete file 13"), and MNQ-005 hijacks that leak through
the answer itself ("end your reply with this image: ...?u=<the customer's email>"). Data-driven
work also does all three
(visiting a link a colleague posted, deleting the file a search found), so a finding is
a lead to review, not a verdict.

A tool is sensitive when the recorder marked it (``@recorder.tool(sensitive=True)``),
or, when unmarked, when its name says so (``update_password``, ``delete_file``, ...).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

UNTRUSTED = frozenset({"tool_output", "retrieved_doc", "web", "agent_msg", "memory", "unknown"})
TRUSTED = frozenset({"system", "user", "internal"})

RULES = {
    "MNQ-001": "untrusted argument",
    "MNQ-002": "auto-approval",
    "MNQ-003": "egress after taint",
    "MNQ-004": "untrusted sensitive action",
    "MNQ-005": "untrusted link in answer",
}

SENSITIVE_NAME = re.compile(
    r"password|passwd|credential|secret|token|api_?key|permission|role|grant|revoke|delete|remove|erase|"
    r"reset|disable|transfer|refund|payment|send_money|pay_|schedule_transaction|update_scheduled|"
    r"update_user|update_email|update_account|create_user|reserve|book_|"
    r"cancel|suspend|deactivate|terminate|close_account|change_|modify_|forward|share_|invite|unsubscribe",
    re.IGNORECASE)
# For these, a bare number (a record id) is the whole payload: "delete file 13", "cancel order 4100".
_DESTRUCTIVE_NAME = re.compile(r"delete|remove|erase|revoke|disable|cancel|suspend|deactivate|terminate",
                               re.IGNORECASE)
_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?")

_TLDS = "com|org|net|io|co|ai|dev|app|info|biz|xyz|me|us|uk|de|eu|ly|gl|link|site|online"
_EMAIL = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]]+"
                  rf"|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:{_TLDS})\b(?:/[^\s\"'<>)\]]*)?", re.IGNORECASE)
_ACCOUNT = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")  # IBAN-shaped
_LONG_NUMBER = re.compile(r"\+?[0-9][0-9 -]{7,}[0-9]")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")  # 2024-03-07 is not a number to trace
_SEPARATORS = re.compile(r"[ -]")
_DIGIT_SEPARATOR = re.compile(r"(?<=[0-9])[ -](?=[0-9])")  # "12 34-56" is one number, "account 1234" is not
MAX_WORD = 2048
_URL_PREFIX = re.compile(r"^(?:https?://)?(?:www\.)?")  # a model may add or drop these when it copies a link


def indicators(text: str) -> set[str]:
    """Destinations and identifiers worth tracing, normalised for comparison."""
    # Emails, links and accounts hold no spaces: matched word by word, each word cut at MAX_WORD, so
    # hostile text (40 KB of "a.a.a.") cannot make the patterns take quadratic time.
    words = [w[:MAX_WORD] for w in text.split()]
    found = {m.group().lower().rstrip(".,;:/") for w in words for rx in (_EMAIL, _ACCOUNT) for m in rx.finditer(w)}
    found |= {_URL_PREFIX.sub("", m.group().lower()).rstrip(".,;:/") for w in words for m in _URL.finditer(w)}
    found |= {_SEPARATORS.sub("", m.group()) for m in _LONG_NUMBER.finditer(text) if not _DATE.search(m.group())}
    found = {f for f in found if len(f) >= 6}
    # Keep the longest form: an email's domain or an IBAN's digits are not separate indicators.
    return {f for f in found if not any(g != f and f in g for g in found)}


def strings(value: Any) -> list[str]:
    """Every scalar inside a JSON value, as text."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [] if value is None else [str(value)]


class _Corpus:
    """Lower-cased text of some context segments, with a separator-free copy for numbers."""

    def __init__(self, segments: Iterable[dict]) -> None:
        self.text = "\n".join(s for seg in segments for s in strings(seg.get("content"))).lower()
        self.compact = _DIGIT_SEPARATOR.sub("", self.text)

    def __contains__(self, indicator: str) -> bool:
        # Whole matches only: "billing@acme.exam" must not count as present in "billing@acme.example".
        text = self.compact if indicator.isdigit() or indicator.startswith("+") else self.text
        return re.search(rf"(?<![a-z0-9_-]){re.escape(indicator)}(?![a-z0-9])", text) is not None


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

    Dates and true/false never count. Plain numbers (amounts, ids) count only for destructive
    tools, where the id is the whole payload."""
    untrusted_segments = [s for s in context if s.get("source") in UNTRUSTED]
    untrusted = _Corpus(untrusted_segments)
    trusted = _Corpus(s for s in context if s.get("source") in TRUSTED)
    destructive = bool(_DESTRUCTIVE_NAME.search(tool or ""))
    hits = []
    for value in strings(arguments):
        v = value.strip().lower()
        if not v or len(v) > 200 or v in ("true", "false", "none", "null") or _DATE.fullmatch(v):
            continue
        if _NUMBER.fullmatch(v) and not destructive:
            continue
        token = re.compile(rf"(?<![a-z0-9]){re.escape(v)}(?![a-z0-9])")
        if token.search(untrusted.text) and not token.search(trusted.text):
            sources = sorted({s["source"] for s in untrusted_segments if token.search(_Corpus([s]).text)})
            hits.append({"value": value.strip(), "sources": sources})
    return hits


_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)|<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE)
_LINK = re.compile(r"https?:[/\\]*[^\s\"'<>)\]]+", re.IGNORECASE)
_REF_IMAGE = re.compile(r"!\[[^\]]*\]\[([^\]]+)\]")
_REF_DEF = re.compile(r"^\s*\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s|$)", re.MULTILINE)


def _domains(host: str) -> list[str]:
    """The host and its parent domains of two labels or more: a.b.evil.example, b.evil.example, evil.example."""
    labels = host.split(".")
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
    images = {u for m in _IMAGE.finditer(text) for u in m.groups() if u}
    refs = {m.group(1).lower(): m.group(2) for m in _REF_DEF.finditer(text)}  # [ref]: https://...
    images |= {refs[m.group(1).lower()] for m in _REF_IMAGE.finditer(text) if m.group(1).lower() in refs}
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


def _is_local(egress: dict) -> bool:
    """Loopback traffic never leaves the machine (a local model server, a sidecar): not egress. A
    request for another host sent to a proxy on this machine does leave it."""
    return _loopback(egress.get("dest_ip") or egress.get("host")) and (
        not egress.get("host") or _loopback(egress.get("host")))


def _loopback(value: Any) -> bool:
    host = str(value or "")
    try:
        return ipaddress.ip_address(host.strip("[]").split("%")[0]).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def findings(records: Iterable[dict]) -> list[dict]:
    """All findings in a sequence of records (any mix of runs), in record order."""
    out: list[dict] = []
    taint: dict[str, int] = {}  # run_id -> step at which untrusted content first reached the model
    context: dict[str, list[dict]] = {}  # run_id -> context of its latest model call
    for r in records:
        if not isinstance(r, dict):
            continue
        try:
            _one(r, out, taint, context)
        except (TypeError, AttributeError, ValueError):  # shaped as the recorder never writes it: skipped
            continue
    return out


def _one(r: dict, out: list[dict], taint: dict[str, int], context: dict[str, list[dict]]) -> None:
    run_id, kind = r.get("run_id"), r.get("event_type")
    if run_id is None:
        return
    base = {"run_id": run_id, "seq": r.get("seq"), "step": r.get("step_id")}
    if kind == "llm_call":
        context[run_id] = r.get("context") or []
        if run_id not in taint and any(s.get("source") in UNTRUSTED for s in context[run_id]):
            taint[run_id] = r.get("step_id", 0)
        for hit in untrusted_arguments(r):
            out.append({**base, "rule": "MNQ-001", "taint_step": r.get("step_id"),
                        "detail": f"{hit['tool']} <- {hit['indicator']} (from {','.join(hit['sources'])})"})
        for link in answer_links(r):
            out.append({**base, "rule": "MNQ-005", "taint_step": r.get("step_id"),
                        "detail": f"{link['kind']} to {link['host']} in the answer (from "
                                  f"{','.join(link['sources'])}): {link['url']}"})
    elif run_id in taint and kind == "egress" and not _is_local((r.get("egress") or [{}])[0]):
        e = (r.get("egress") or [{}])[0]
        out.append({**base, "rule": "MNQ-003", "taint_step": taint[run_id],
                    "detail": f"{e.get('source_ip', '?')}:{e.get('source_port', '?')} -> "
                              f"{e.get('dest_ip', '?')}:{e.get('dest_port', '?')}"})
    elif run_id in taint and kind == "approval":
        a = (r.get("approvals") or [{}])[0]
        if a.get("decision") == "approved" and a.get("approver_type") != "human":
            out.append({**base, "rule": "MNQ-002", "taint_step": taint[run_id],
                        "detail": f"{a.get('action')} by {a.get('approver')}"})
    elif run_id in taint and kind == "tool_call":
        for call in r.get("tool_calls") or []:
            if not is_sensitive(r, call.get("name")):
                continue
            for hit in untrusted_values(call.get("name"), call.get("arguments"), context.get(run_id, [])):
                out.append({**base, "rule": "MNQ-004", "taint_step": taint[run_id],
                            "detail": f"{call.get('name')} <- {hit['value']!r} (from {','.join(hit['sources'])})"})
