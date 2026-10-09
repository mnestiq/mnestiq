"""Best-effort conversion of SDK objects into plain JSON values."""

from __future__ import annotations

import base64
import dataclasses
import math
from typing import Any

from .canonical import MAX_SAFE_INTEGER

_MAX_DEPTH = 64
_MAX_NODES = 100_000  # an object graph with shared references can be exponentially larger as a tree


def to_jsonable(obj: Any, _depth: int = 0, _budget: list[int] | None = None) -> Any:
    if _budget is None:
        _budget = [_MAX_NODES]
    _budget[0] -= 1
    if _depth > _MAX_DEPTH:
        return "<max depth exceeded>"
    if _budget[0] < 0:
        return "<too large>"
    d = _depth + 1
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, str):
        return valid_text(obj)
    if isinstance(obj, int):
        return obj if abs(obj) <= MAX_SAFE_INTEGER else str(obj)
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else str(obj)
    if isinstance(obj, dict):
        return {valid_text(str(k)): to_jsonable(v, d, _budget) for k, v in obj.items() if not is_not_given(v)}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v, d, _budget) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return {"$base64": base64.b64encode(bytes(obj)).decode("ascii")}
    if hasattr(obj, "model_dump"):  # pydantic v2 (Anthropic and OpenAI SDK types)
        try:
            return to_jsonable(obj.model_dump(mode="json", exclude_unset=True), d, _budget)
        except Exception:
            pass
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        # Field by field: dataclasses.asdict deep-copies, which fails on locks, clients and sockets.
        return {f.name: to_jsonable(getattr(obj, f.name, None), d, _budget) for f in dataclasses.fields(obj)}
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        return to_jsonable({k: v for k, v in vars(obj).items() if not k.startswith("_")}, d, _budget)
    return repr(obj)


def valid_text(text: str) -> str:
    """``text`` as valid Unicode. A lone surrogate (from a JSON escape such as ud83d, or a file name)
    cannot be written as UTF-8 and would lose the whole event, so it becomes U+FFFD. A surrogate
    pair split in two is joined back into its character."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def valid_texts(value: Any) -> Any:
    """``valid_text`` applied to every string and key in a JSON-like value."""
    if isinstance(value, str):
        return valid_text(value)
    if isinstance(value, dict):
        return {valid_text(str(k)): valid_texts(v) for k, v in value.items()}
    if isinstance(value, list):
        return [valid_texts(v) for v in value]
    return value


def is_not_given(value: Any) -> bool:
    """True for the SDKs' NOT_GIVEN / Omit sentinels."""
    return type(value).__name__ in ("NotGiven", "Omit")


def get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict or attribute from an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
