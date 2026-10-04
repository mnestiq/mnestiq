"""Best-effort conversion of SDK objects into plain JSON values."""

from __future__ import annotations

import base64
import dataclasses
import math
from typing import Any

from .canonical import MAX_SAFE_INTEGER

_MAX_DEPTH = 64


def to_jsonable(obj: Any, _depth: int = 0) -> Any:
    if _depth > _MAX_DEPTH:
        return "<max depth exceeded>"
    d = _depth + 1
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        return obj if abs(obj) <= MAX_SAFE_INTEGER else str(obj)
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else str(obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v, d) for k, v in obj.items() if not is_not_given(v)}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v, d) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return {"$base64": base64.b64encode(bytes(obj)).decode("ascii")}
    if hasattr(obj, "model_dump"):  # pydantic v2 (Anthropic and OpenAI SDK types)
        try:
            return to_jsonable(obj.model_dump(mode="json", exclude_unset=True), d)
        except Exception:
            pass
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_jsonable(dataclasses.asdict(obj), d)
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        return to_jsonable({k: v for k, v in vars(obj).items() if not k.startswith("_")}, d)
    return repr(obj)


def is_not_given(value: Any) -> bool:
    """True for the SDKs' NOT_GIVEN / Omit sentinels."""
    return type(value).__name__ in ("NotGiven", "Omit")


def get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict or attribute from an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
