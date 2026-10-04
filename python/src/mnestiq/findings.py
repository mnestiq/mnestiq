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
         action               payments) ran with an argument value that appears in
                              untrusted content and not in the system prompt or the
                              user's messages.

MNQ-001 is the hijack signature: an injected instruction has to put the attacker's
address, account or URL into a tool call. MNQ-004 covers hijacks with no destination
("change the password to ...", "delete file 13"). Data-driven work also does both
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
}

SENSITIVE_NAME = re.compile(
    r"password|passwd|credential|secret|token|api_?key|permission|role|grant|revoke|delete|remove|erase|"
    r"reset|disable|transfer|refund|payment|send_money|pay_|schedule_transaction|update_scheduled|"
    r"update_user|update_email|update_account|create_user|reserve|book_", re.IGNORECASE)
# For these, a bare number (a record id) is the whole payload: "delete file 13".
_DESTRUCTIVE_NAME = re.compile(r"delete|remove|erase|revoke|disable", re.IGNORECASE)
_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?")

_TLDS = "com|org|net|io|co|ai|dev|app|info|biz|xyz|me|us|uk|de|eu|ly|gl|link|site|online"
_EMAIL = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_URL = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]]+"
                  rf"|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:{_TLDS})\b(?:/[^\s\"'<>)\]]*)?", re.IGNORECASE)
_ACCOUNT = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")  # IBAN-shaped
_LONG_NUMBER = re.compile(r"\+?[0-9][0-9 -]{7,}[0-9]")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")  # 2024-03-07 is not a number to trace
_SEPARATORS = re.compile(r"[ -]")
_URL_PREFIX = re.compile(r"^(?:https?://)?(?:www\.)?")  # a model may add or drop these when it copies a link


def indicators(text: str) -> set[str]:
    """Destinations and identifiers worth tracing, normalised for comparison."""
    found = {m.group().lower().rstrip(".,;:/") for rx in (_EMAIL, _ACCOUNT) for m in rx.finditer(text)}
    found |= {_URL_PREFIX.sub("", m.group().lower()).rstrip(".,;:/") for m in _URL.finditer(text)}
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
        self.compact = _SEPARATORS.sub("", self.text)

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
                if ind in untrusted and ind not in trusted:
                    sources = sorted({s["source"] for s in untrusted_segments if ind in _Corpus([s])})
                    hits.append({"tool": call.get("name"), "indicator": ind, "sources": sources})
    return hits


def is_sensitive(tool_call_record: dict, name: str) -> bool:
    marked = (tool_call_record.get("attributes") or {}).get("sensitive")
    return marked if isinstance(marked, bool) else bool(SENSITIVE_NAME.search(name or ""))


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


def _is_local(egress: dict) -> bool:
    """Loopback traffic never leaves the machine (a local model server, a sidecar): not egress."""
    host = str(egress.get("dest_ip") or egress.get("host") or "")
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
        run_id, kind = r.get("run_id"), r.get("event_type")
        if run_id is None:
            continue
        base = {"run_id": run_id, "seq": r.get("seq"), "step": r.get("step_id")}
        if kind == "llm_call":
            context[run_id] = r.get("context") or []
            if run_id not in taint and any(s.get("source") in UNTRUSTED for s in context[run_id]):
                taint[run_id] = r.get("step_id", 0)
            for hit in untrusted_arguments(r):
                out.append({**base, "rule": "MNQ-001", "taint_step": r.get("step_id"),
                            "detail": f"{hit['tool']} <- {hit['indicator']} (from {','.join(hit['sources'])})"})
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
    return out
