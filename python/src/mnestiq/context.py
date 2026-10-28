"""Full model context from evidence that records only what changed (spec 1.0, ``context_base``).

A model call usually sends the whole conversation again. Since spec 1.0 the recorder writes only the
segments that are new since the run's previous call, and points back to that call. Detection rules,
the dashboard and reports need each call's full context: ``expand`` puts it back.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

# A small hostile file could point many calls at one large context and make readers copy it again and
# again. Carried context is therefore budgeted: this much, or this many times the content the file itself
# holds, whichever is more. A real conversation stays far below it.
CARRY_FLOOR = 64 * 1024 * 1024
CARRY_RATIO = 20


def expand(records: Iterable[dict]) -> Iterator[dict]:
    """Yield the records in order, each model call with its full ``context``.

    A call that records only what changed comes back as a copy with the carried segments put in front
    of its own, ``context_base`` removed and ``x-context-carried`` set to how many segments came from
    earlier calls. Other records are yielded as they are. The base is looked up in the same chain and run
    only. A base that can't be found (a file cut short, redacted to a sample, or records of several
    chains mixed) leaves the call's own segments, with ``x-context-missing`` set to how many segments
    are missing. A call past the carry budget does the same with ``x-context-truncated``: its context is
    incomplete, never wrong. ``mnestiq verify`` reports a missing base as an error.
    """
    # (chain_id, seq) -> (run_id, full context, running byte total of that context)
    full: dict[tuple[Any, int], tuple[Any, list[dict], list[int]]] = {}
    own_bytes = carried_bytes = 0
    for rec in records:
        if not isinstance(rec, dict) or rec.get("event_type") != "llm_call":
            yield rec
            continue
        raw = rec.get("context")
        own: list[dict] = raw if isinstance(raw, list) else []
        sizes = [_size(s) for s in own]
        own_bytes += sum(sizes)
        seq, chain, run = rec.get("seq"), rec.get("chain_id"), rec.get("run_id")
        chain = chain if isinstance(chain, str) else None  # anything else is not a chain id (the schema says so)
        base = rec.get("context_base")
        context, totals = own, _running(sizes, 0)
        out = rec
        if isinstance(base, dict):
            out = {k: v for k, v in rec.items() if k != "context_base"}
            base_seq, wanted = base.get("seq"), base.get("segments")
            segments = wanted if isinstance(wanted, int) and not isinstance(wanted, bool) else 0
            earlier = None
            if isinstance(base_seq, int) and isinstance(seq, int) and base_seq < seq:
                earlier = full.get((chain, base_seq))
            if earlier is None or earlier[0] != run or not 0 < segments <= len(earlier[1]):
                out["x-context-missing"] = segments
            elif carried_bytes + earlier[2][segments - 1] > max(CARRY_FLOOR, CARRY_RATIO * own_bytes):
                out["x-context-truncated"] = segments
            else:
                carried_bytes += earlier[2][segments - 1]
                context = earlier[1][:segments] + own
                totals = earlier[2][:segments] + _running(sizes, earlier[2][segments - 1])
                out["x-context-carried"] = segments
            out["context"] = context
        if isinstance(seq, int):
            full[(chain, seq)] = (run, context, totals)
        yield out


def expanded(records: Iterable[dict]) -> list[dict]:
    """``expand`` as a list."""
    return list(expand(records))


def _size(segment: Any) -> int:
    try:
        return len(json.dumps(segment, default=str))
    except (TypeError, ValueError, RecursionError):
        return 0


def _running(sizes: list[int], start: int) -> list[int]:
    out, total = [], start
    for n in sizes:
        total += n
        out.append(total)
    return out
