"""Which run a model call belongs to, worked out from outside the agent.

In order of certainty:

1. ``X-Mnestiq-Run`` header: the agent names its run (one line of client configuration).
2. ``traceparent`` header: an agent using OpenTelemetry already sends one. The run is the trace.
3. ``previous_response_id`` (Responses API): the run of that earlier answer.
4. A tool result handed back: tool call ids are unique to the answer that asked for them.
5. The conversation: a request that continues an earlier one, holding all of it and more.
6. Otherwise a new run.

A request that only repeats an earlier one is not a continuation: agents run on a schedule often
start every run with the same words, and those are separate runs. Each record says which rule
grouped it, so an investigator knows how sure the grouping is.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from collections import OrderedDict
from typing import Any

from ..recorder import Recorder, Run
from .formats import RESPONSES, conversation, tool_result_ids

RUN_HEADER = "X-Mnestiq-Run"
HEADER, TRACE, PREVIOUS, TOOL_RESULT, CONVERSATION, NEW = (
    "header", "traceparent", "previous_response", "tool_result", "conversation", "new")

_RUN_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")
_ID_KEYS = ("id", "tool_use_id", "tool_call_id", "call_id")
_SKIP_KEYS = frozenset({"thinking", "signature", "cache_control"})  # frameworks drop or move these


class _Bounded(OrderedDict):
    """A map that forgets its oldest entries past ``limit``: the proxy runs for months."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit

    def put(self, key: Any, value: Any) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.limit:
            self.popitem(last=False)


class Runs:
    def __init__(self, recorder: Recorder, agent_id: str, operator_id: str | None = None, *,
                 limit: int = 100_000) -> None:
        self.recorder = recorder
        self.agent_id = agent_id
        self.operator_id = operator_id
        self._lock = threading.Lock()
        self._runs = _Bounded(10_000)  # run_id -> Run
        self._by_call = _Bounded(limit)  # tool call id -> run_id
        self._by_response = _Bounded(limit)  # response id -> run_id
        self._by_conversation = _Bounded(limit)  # conversation digest -> run_id

    def assign(self, api: str, body: dict, headers: Any) -> tuple[Run, str]:
        """The run for this request, and the rule that chose it."""
        with self._lock:
            try:
                run_id, how = self._find(api, body, headers)
            except Exception as exc:  # grouping is a guess: it never stops the call
                self.recorder._record_failure(exc)
                run_id, how = uuid.uuid4().hex, NEW
            run = self._runs.get(run_id)
            new = run is None
            if run is None:
                run = Run(self.recorder, run_id=run_id, parent_run_id=None, agent_id=self.agent_id,
                          operator_id=self.operator_id)
            self._runs.put(run_id, run)
        if new:
            run.emit("run_start", attributes={"captured_by": "proxy", "grouping": how})
        return run, how

    def learn(self, run: Run, api: str, body: dict, answer: dict[str, Any]) -> None:
        """Remember an answered call, so the calls that follow it find their run."""
        with self._lock:
            for call in answer.get("tool_calls") or []:
                if isinstance(call.get("id"), str):
                    self._by_call.put(call["id"], run.run_id)
            if isinstance(answer.get("response_id"), str):
                self._by_response.put(answer["response_id"], run.run_id)
            digests = _digests(conversation(api, body))
            self._by_conversation.put(digests[-1], run.run_id)
            if api != RESPONSES and "output" in answer:
                # The next request holds this answer too, as the agent sends it back.
                reply = answer["output"] if isinstance(answer["output"], dict) else {
                    "role": "assistant", "content": answer["output"]}
                self._by_conversation.put(_next(digests[-1], reply), run.run_id)

    def _find(self, api: str, body: dict, headers: Any) -> tuple[str, str]:
        named = (headers.get(RUN_HEADER) or "").strip()
        if _RUN_ID.match(named):
            return named, HEADER
        trace = _TRACEPARENT.match((headers.get("traceparent") or "").strip().lower())
        if trace and trace.group(1) != "0" * 32:
            return trace.group(1), TRACE
        previous = body.get("previous_response_id") if api == RESPONSES else None
        if isinstance(previous, str) and previous in self._by_response:
            return self._by_response[previous], PREVIOUS
        for call_id in reversed(tool_result_ids(api, body)):
            if call_id in self._by_call:
                return self._by_call[call_id], TOOL_RESULT
        digests = _digests(conversation(api, body))
        # Longest first, never the whole request (a repeat is a new run), and at least one message.
        for digest in reversed(digests[1:-1]):
            if digest in self._by_conversation:
                return self._by_conversation[digest], CONVERSATION
        return uuid.uuid4().hex, NEW


def _digests(elements: list[Any]) -> list[str]:
    """One digest per prefix of the conversation: [system], [system, first message], ..."""
    out: list[str] = []
    for element in elements:
        out.append(_next(out[-1] if out else "", element))
    return out


def _next(previous: str, element: Any) -> str:
    return hashlib.sha256((previous + json.dumps(_essence(element), sort_keys=True, ensure_ascii=False,
                                                 default=str)).encode("utf-8", "replace")).hexdigest()


def _essence(element: Any) -> list[Any]:
    """What stays the same when an agent sends a message back: who said it, its words and the ids
    it carries. Not how it is laid out, which differs between a provider's answer and the agent's
    own copy of it (fields left out, null, a string in place of a list of blocks)."""
    if not isinstance(element, dict):
        return ["", _words(element), []]
    role = element.get("role") or element.get("type") or ""
    ids: list[str] = []
    _collect_ids(element, ids)
    return [str(role), _words(element.get("content", element) if "role" in element else element), sorted(set(ids))]


def _words(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_words(v) for v in value)
    if isinstance(value, dict):
        # A tool call's input is left out: agents send it back re-encoded. Its id is kept.
        return "".join(_words(v) for k, v in value.items()
                       if k in ("text", "content", "output") or (k == "input" and not isinstance(v, dict)))
    return ""


def _collect_ids(value: Any, out: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _ID_KEYS and isinstance(item, str):
                out.append(item)
            elif key not in _SKIP_KEYS:
                _collect_ids(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_ids(item, out)
