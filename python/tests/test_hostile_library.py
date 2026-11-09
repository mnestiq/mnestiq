"""The library side under hostile input: everything that runs inside the agent's own process.

Four promises are checked. Recording never raises into the agent or changes what its call returns.
What is written always verifies. Content only goes in slots that redact can remove. Key and token
files that are damaged fail with a clear error.
"""

import asyncio
import base64
import concurrent.futures
import contextlib
import dataclasses
import datetime
import decimal
import enum
import errno
import hashlib
import http.server
import importlib.util
import inspect
import json
import logging
import os
import random
import shutil
import socket
import stat
import sys
import threading
import time
import types
import uuid
import warnings
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from mnestiq import (
    FileSink,
    HeadFile,
    MemorySink,
    Recorder,
    Segment,
    SinkError,
    TimestampError,
    Timestamper,
    verify_file,
    verify_lines,
)
from mnestiq import identity
from mnestiq.canonical import CanonicalizationError, canonical_json, parse_json
from mnestiq.cli import EXIT_USAGE, main
from mnestiq.egress import _http_scope, instrument_egress, sanitize_url, uninstrument_egress
from mnestiq.hashing import hashed_form, record_hash, salted_digest
from mnestiq.integrations.anthropic import instrument_anthropic
from mnestiq.integrations.openai import instrument_openai
from mnestiq.jsonable import to_jsonable
from mnestiq.keys import (
    generate_private_key,
    key_id,
    load_private_key,
    load_public_key_b64,
    normalize_p256,
    p256_raw_signature,
    public_key_b64,
    save_keypair,
    verify_signature,
)
from mnestiq.merkle import merkle_root
from mnestiq.timestamps import _chain_to_root, default_roots, token_from_response, verify_token

from conftest import load

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

SECRET = "sentinel-7f3a9c"
REPOSITORY = Path(__file__).resolve().parents[2]
VECTORS = REPOSITORY / "spec" / "vectors"  # the tests that need it skip without it, as in the source package
DATA = Path(__file__).parent / "data"
needs_rfc3161 = pytest.mark.skipif(importlib.util.find_spec("rfc3161_client") is None, reason="needs rfc3161_client")


def _record(tmp_path, key, write, **options):
    """Run ``write(run)`` against a signed recorder on a real file, then close it."""
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=5, **options)
    with rec.run() as run:
        write(run)
    rec.close()
    return rec, path


def _verified(path, pub=None):
    report = verify_file(path, [pub] if pub else [])
    assert report.ok, report.errors
    return load(path)


def _of_type(records, event_type):
    return [r for r in records if r.get("event_type") == event_type]


def _verified_memory(sink):
    report = verify_lines(canonical_json(r) for r in sink.records)
    assert report.ok, report.errors


class FullSink(MemorySink):
    def append(self, record):
        raise OSError(errno.ENOSPC, "No space left on device")


class Boom(Exception):
    pass


class Thing:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


# --- what agents really pass ----------------------------------------------------------------------


def _circular_list():
    a = []
    a.append(a)
    return a


def _circular_dict():
    a = {}
    a["me"] = a
    return a


def _circular_object():
    a = Thing()
    a.me = a
    return a


def _shared_tree():  # about 2**80 nodes when walked as a tree
    a = [1]
    for _ in range(80):
        a = [a, a]
    return a


def _deep(depth=30_000):
    a = []
    for _ in range(depth):
        a = [a]
    return a


def _deep_objects():
    a = Thing()
    for _ in range(5000):
        a = Thing(child=a)
    return a


def _generator():
    yield 1


class Colour(enum.Enum):
    RED = "red"


class Level(enum.IntEnum):
    HIGH = 3


class Word(str, enum.Enum):
    YES = "yes"


@dataclasses.dataclass
class Holder:
    lock: object
    child: object = None


def _recursive_dataclass():
    a = Holder(threading.Lock())
    a.child = a
    return a


def _pydantic_model():
    pydantic = pytest.importorskip("pydantic")

    class Model(pydantic.BaseModel):
        text: str = "x"
        score: float = float("nan")

    return Model()


ODD_VALUES = {
    "none": lambda: None,
    "bytes": lambda: b"\x00\xff",
    "bytearray": lambda: bytearray(b"\x00\xff"),
    "memoryview": lambda: memoryview(b"abc"),
    "nan": lambda: float("nan"),
    "infinity": lambda: float("inf"),
    "minus_infinity": lambda: float("-inf"),
    "minus_zero": lambda: -0.0,
    "largest_double": lambda: sys.float_info.max,
    "smallest_double": lambda: 5e-324,
    "large_int": lambda: 2**200,
    "edge_of_safe_int": lambda: 2**53,
    "lone_high_surrogate": lambda: "bad \ud83d text",
    "lone_low_surrogate": lambda: "\udc00",
    "split_surrogate_pair": lambda: "\ud83d\ude00",
    "surrogate_in_key": lambda: {"\ud83d": 1},
    "nul": lambda: "a\x00b",
    "byte_order_mark": lambda: "\ufeffx",
    "not_a_character": lambda: "\uffff",
    "control_characters": lambda: "".join(map(chr, range(32))),
    "empty_key": lambda: {"": 1},
    "none_key": lambda: {None: 1},
    "tuple_key": lambda: {(1, 2): 3},
    "frozenset_key": lambda: {frozenset({1}): 3},
    "keys_that_clash": lambda: {1: "a", "1": "b"},
    "set": lambda: {1, 2},
    "frozenset": lambda: frozenset({"a"}),
    "tuple": lambda: (1, (2, (3,))),
    "generator": _generator,
    "map": lambda: map(str, [1]),
    "range": lambda: range(10**12),
    "decimal": lambda: decimal.Decimal("1.1"),
    "decimal_nan": lambda: decimal.Decimal("NaN"),
    "datetime": lambda: datetime.datetime.now(datetime.timezone.utc),
    "uuid": uuid.uuid4,
    "path": lambda: Path("a/b"),
    "complex": lambda: 1 + 2j,
    "class": lambda: Thing,
    "int_enum": lambda: Level.HIGH,
    "str_enum": lambda: Word.YES,
    "lock": threading.Lock,
    "circular_list": _circular_list,
    "circular_dict": _circular_dict,
    "circular_object": _circular_object,
    "shared_tree": _shared_tree,
    "deep_list": _deep,
    "deep_objects": _deep_objects,
    "dataclass_with_lock": _recursive_dataclass,
    "namespace": lambda: types.SimpleNamespace(a=1),
    "magic_mock": mock.MagicMock,
    "pydantic_model": _pydantic_model,
}


@pytest.mark.parametrize("make", ODD_VALUES.values(), ids=ODD_VALUES.keys())
def test_any_value_is_recorded_everywhere_and_verifies(tmp_path, key, pub, make):
    value = make()

    def write(run):
        run.tool_call("t", {"v": value}, value)
        run.llm_call(
            provider="p",
            model="m",
            context=[Segment("user", value), {"source": "web", "content": value}],
            output=value,
            params={"p": value},
            system_prompt=value,
            tool_calls=[{"id": "1", "name": "t", "arguments": value}],
        )
        run.note("n", v=value)

    rec, path = _record(tmp_path, key, write)
    records = _verified(path, pub)
    assert rec.failures == 0
    assert (
        len(_of_type(records, "tool_call")) == len(_of_type(records, "llm_call")) == len(_of_type(records, "note")) == 1
    )


@pytest.mark.parametrize("make", ODD_VALUES.values(), ids=ODD_VALUES.keys())
def test_a_tool_gets_and_returns_exactly_its_own_objects(make):
    value = make()
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t(x):
        assert x is value
        return x

    with rec.run():
        assert t(value) is value


def test_a_generator_is_not_used_up_by_being_recorded():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t(items):
        return (i * 2 for i in items)

    with rec.run() as run:
        given = (i for i in [1, 2])
        out = t(given)
        run.note("n", v=given)
    assert list(out) == [2, 4]


def test_a_value_that_goes_too_deep_says_so(tmp_path, key, pub):
    _, path = _record(tmp_path, key, lambda run: run.tool_call("t", _deep(), None))
    (call,) = _of_type(_verified(path, pub), "tool_call")
    assert "<max depth exceeded>" in json.dumps(call["tool_calls"][0]["arguments"])


def test_a_value_with_too_many_parts_says_so(tmp_path, key, pub):
    _, path = _record(tmp_path, key, lambda run: run.tool_call("t", _shared_tree(), None), max_content_bytes=10**8)
    (call,) = _of_type(_verified(path, pub), "tool_call")
    assert "<too large>" in json.dumps(call["tool_calls"][0]["arguments"])


def test_a_value_over_the_cap_is_dropped_and_listed(tmp_path, key, pub):
    big = SECRET * 100_000
    _, path = _record(tmp_path, key, lambda run: run.tool_call("t", big, big), max_content_bytes=1000)
    (call,) = _of_type(_verified(path, pub), "tool_call")
    assert len(call["x-omitted"]) == 2
    assert SECRET.encode() not in path.read_bytes()


def test_a_broken_surrogate_is_replaced_visibly(tmp_path, key, pub):
    _, path = _record(tmp_path, key, lambda run: run.tool_call("t", {"\ud83d": "a\udc00"}, "\ud83d\ude00"))
    call = _of_type(_verified(path, pub), "tool_call")[0]["tool_calls"][0]
    assert call["arguments"] == {"\ufffd": "a\ufffd"}
    assert call["result"] == "\U0001f600"  # a pair split in two is joined back


# --- objects that fight back --------------------------------------------------------------------


class BrokenRepr:
    __slots__ = ()

    def __repr__(self):
        raise Boom("repr")


class BrokenStr:
    __slots__ = ()

    def __str__(self):
        raise Boom("str")


class RaisingGetattr:
    __slots__ = ()

    def __getattr__(self, name):
        raise RuntimeError(name)


class RaisingDict:
    @property
    def __dict__(self):
        raise Boom("dict")

    __slots__ = ()


class RaisingModelDump:
    def model_dump(self, **kwargs):
        raise Boom("dump")


class SelfDumping:
    def model_dump(self, **kwargs):
        return self


class BadIterList(list):
    def __iter__(self):
        raise Boom("iter")


class BadItemsDict(dict):
    def items(self):
        raise Boom("items")


class BadEncodeStr(str):
    def encode(self, *args, **kwargs):
        raise Boom("encode")


class BadAbsInt(int):
    def __abs__(self):
        raise Boom("abs")


@dataclasses.dataclass
class RaisingField:
    x: int = 1

    def __getattribute__(self, name):
        if name == "x":
            raise Boom("field")
        return object.__getattribute__(self, name)


HOSTILE_OBJECTS = {
    "broken_repr": BrokenRepr,
    "broken_repr_in_list": lambda: [1, BrokenRepr()],
    "broken_str_key": lambda: {BrokenStr(): 1},
    "getattr_raises": RaisingGetattr,
    "dict_property_raises": RaisingDict,
    "model_dump_raises": RaisingModelDump,
    "model_dump_returns_self": SelfDumping,
    "list_with_bad_iter": lambda: BadIterList([1]),
    "dict_with_bad_items": lambda: BadItemsDict(a=1),
    "str_with_bad_encode": lambda: BadEncodeStr("x"),
    "int_with_bad_abs": lambda: BadAbsInt(1),
    "dataclass_field_raises": RaisingField,
    "int_too_long_to_print": lambda: 10**5000,
    "int_key_too_long_to_print": lambda: {10**5000: 1},
}


@pytest.mark.parametrize("make", HOSTILE_OBJECTS.values(), ids=HOSTILE_OBJECTS.keys())
def test_a_hostile_object_never_reaches_the_agent(tmp_path, key, pub, make):
    value = make()

    def write(run):
        run.tool_call("t", value, value)
        run.llm_call(provider="p", model="m", context=[Segment("user", value)], output=value, params={"p": value})
        run.note("n", v=value)

    _, path = _record(tmp_path, key, write)
    _verified(path, pub)


@pytest.mark.parametrize("make", HOSTILE_OBJECTS.values(), ids=HOSTILE_OBJECTS.keys())
def test_a_hostile_object_still_leaves_a_record_of_the_call(tmp_path, key, pub, make):
    value = make()
    _, path = _record(tmp_path, key, lambda run: run.tool_call("t", {"v": value}, value))
    records = _verified(path, pub)
    (call,) = _of_type(records, "tool_call")
    assert "arguments_hash" in call["tool_calls"][0] and "result_hash" in call["tool_calls"][0]


@pytest.mark.parametrize("make", HOSTILE_OBJECTS.values(), ids=HOSTILE_OBJECTS.keys())
def test_a_tool_with_hostile_values_still_returns_them(make):
    value = make()
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t(x):
        return x

    with rec.run():
        assert t(value) is value
    _verified_memory(rec._sink)


def test_an_error_whose_own_repr_is_broken_stays_out_of_the_agent():
    class BadBoom(Exception):
        def __repr__(self):
            raise BadBoom("again")

    class Sink(MemorySink):
        def append(self, record):
            raise BadBoom("first")

    rec = Recorder(Sink(), agent_id="a")
    with rec.run() as run:
        assert run.note("n") is None
    assert rec.failures == 3


@pytest.mark.parametrize(
    "value",
    [Colour.RED, ValueError("the reason"), _generator, Thing()],
    ids=["enum", "exception", "function", "object_with_nothing_public"],
)
def test_an_object_with_nothing_public_is_not_recorded_as_empty(value):
    assert to_jsonable(value) != {}


# --- bad arguments to the recording calls --------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda run: run.tool_call(None, {}),
        lambda run: run.tool_call(object(), {}),
        lambda run: run.tool_call("t", {}, call_id=5),
        lambda run: run.tool_call("t", {}, error=object()),
        lambda run: run.llm_call(provider=None, model=None, context=[]),
        lambda run: run.llm_call(provider="p", model="m", context=[Segment("user", "x", role=5)]),
        lambda run: run.llm_call(provider="p", model="m", context=[Segment("user", "x", name=object())]),
        lambda run: run.llm_call(provider="p", model="m", context=[], usage=5),
        lambda run: run.llm_call(provider="p", model="m", context=[], tool_calls=[{"arguments": 1}]),
        lambda run: run.llm_call(provider="p", model="m", context=[], output="x", stop_reason=object()),
    ],
)
def test_a_value_of_the_wrong_type_is_kept_as_text(tmp_path, key, pub, call):
    rec, path = _record(tmp_path, key, call)
    records = _verified(path, pub)
    assert rec.failures == 0
    assert _of_type(records, "tool_call") or _of_type(records, "llm_call")


@pytest.mark.parametrize(
    "call",
    [
        lambda run: run.tool_call("t", {}, result_source="nowhere"),
        lambda run: run.tool_call("t", {}, latency_ms="soon"),
        lambda run: run.tool_call(),
        lambda run: run.llm_call(),
        lambda run: run.llm_call(provider="p", model="m", context=None),
        lambda run: run.llm_call(provider="p", model="m", context=5),
        lambda run: run.llm_call(provider="p", model="m", context=["text"]),
        lambda run: run.llm_call(provider="p", model="m", context=[{"source": "nowhere", "content": "x"}]),
        lambda run: run.llm_call(provider="p", model="m", context=[{"role": "user", "content": "x"}]),
        lambda run: run.llm_call(provider="p", model="m", context=[], tool_calls=5),
        lambda run: run.approval("a", "maybe", "b"),
        lambda run: run.approval(None, None, None),
        lambda run: run.approval("a", "approved", "b", approver_type="ghost"),
        lambda run: run.egress("not a dict"),
        lambda run: run.egress({"egress_id": "e", "protocol": "smtp"}),
        lambda run: run.egress({"egress_id": object(), "protocol": "http"}),
        lambda run: run.egress({"egress_id": "e", "protocol": "http", "nope": 1}),
        lambda run: run.note(),
        lambda run: run.note("m", message="again"),
        lambda run: run.emit("Not A Type"),
    ],
)
def test_a_bad_argument_is_counted_and_never_written(tmp_path, key, pub, call):
    rec, path = _record(tmp_path, key, call)
    _verified(path, pub)
    assert rec.failures == 1


def test_a_note_attribute_called_self_does_not_raise():
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run() as run:
        run.note("m", self="x")


@pytest.mark.parametrize(
    "value",
    [object(), float("nan"), 2**60, {"\ud83d": "x"}, b"bytes"],
    ids=["object", "nan", "large_int", "surrogate_key", "bytes"],
)
@pytest.mark.parametrize("where", ["tool_call", "llm_call", "run_start"])
def test_a_non_json_attribute_does_not_lose_the_event(tmp_path, key, pub, value, where):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key)
    attributes = {"v": value} if not isinstance(value, dict) else value
    with rec.run(attributes=attributes if where == "run_start" else None) as run:
        if where == "tool_call":
            run.tool_call("t", {}, attributes=attributes)
        elif where == "llm_call":
            run.llm_call(provider="p", model="m", context=[], attributes=attributes)
    rec.close()
    assert _of_type(_verified(path, pub), where)
    assert rec.failures == 0


@pytest.mark.parametrize("usage", [{"input_tokens": 2**60}, {"cached": True}], ids=["over_safe_int", "boolean"])
def test_an_odd_usage_number_does_not_lose_the_model_call(tmp_path, key, pub, usage):
    _, path = _record(tmp_path, key, lambda run: run.llm_call(provider="p", model="m", context=[], usage=usage))
    assert _of_type(_verified(path, pub), "llm_call")


def test_a_key_that_is_not_text_in_attributes_is_mended(tmp_path, key, pub):
    rec, path = _record(tmp_path, key, lambda run: run.tool_call("t", {}, attributes={1: "x"}))
    assert _of_type(_verified(path, pub), "tool_call")[0]["attributes"] == {"1": "x"}
    assert rec.failures == 0


def test_events_after_a_failed_one_still_chain(tmp_path, key, pub):
    def write(run):
        run.note("before")
        run.egress("not a dict")
        run.tool_call("t", {}, result_source="nowhere")
        run.note("after")

    _, path = _record(tmp_path, key, write)
    assert [r["attributes"]["message"] for r in _of_type(_verified(path, pub), "note")] == ["before", "after"]


def test_a_record_mended_for_broken_text_still_verifies(tmp_path, key, pub):
    def write(run):
        run.llm_call(provider="p", model="m", context=[Segment("user", "fine", name="bad \ud83d")], error="bad \udc00")
        run.tool_call("t\ud83d", {"a": 1}, error="also \ud83d bad")

    rec, path = _record(tmp_path, key, write)
    records = _verified(path, pub)
    assert rec.failures == 0
    assert _of_type(records, "llm_call")[0]["error"] == "bad \ufffd"


def test_a_value_left_out_stays_marked_when_the_event_is_mended(tmp_path, key, pub):
    def write(run):
        run.llm_call(provider="p", model="m", context=[Segment("user", "x" * 2000)], error="bad \ud83d text")

    _, path = _record(tmp_path, key, write, max_content_bytes=100)
    (call,) = _of_type(_verified(path, pub), "llm_call")
    assert call.get("x-omitted") == ["context[0].content (2002 bytes)"]


def test_context_delta_survives_values_left_out(tmp_path, key, pub):
    big = Segment("user", "x" * 5000)

    def write(run):
        run.llm_call(provider="p", model="m", context=[big])
        run.llm_call(provider="p", model="m", context=[big, Segment("model", "y" * 5000)])

    _, path = _record(tmp_path, key, write, max_content_bytes=100)
    calls = _of_type(_verified(path, pub), "llm_call")
    assert calls[1]["context_base"]["segments"] == 1
    assert b"xxxxxxxxxxxxxxxxxxxx" not in path.read_bytes()


# --- the @tool decorator ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ValueError("x"),
        KeyError("x"),
        SystemExit(3),
        KeyboardInterrupt(),
        StopIteration(),
        GeneratorExit(),
        RecursionError(),
        MemoryError(),
        type("Custom", (BaseException,), {})("x"),
    ],
    ids=lambda e: type(e).__name__,
)
@pytest.mark.parametrize("in_run", [True, False], ids=["in_run", "own_run"])
def test_a_tool_that_raises_raises_the_same_thing(error, in_run):
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t():
        raise error

    if in_run:
        with rec.run():
            with pytest.raises(type(error)) as caught:
                t()
    else:
        with pytest.raises(type(error)) as caught:
            t()
    assert caught.value is error
    (call,) = _of_type(rec._sink.records, "tool_call")
    assert call["status"] == "error"
    _verified_memory(rec._sink)


def test_an_async_tool_that_raises_raises_the_same_thing():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    async def t():
        raise ValueError("x")

    with pytest.raises(ValueError, match="x"):
        asyncio.run(t())
    assert _of_type(rec._sink.records, "tool_call")[0]["status"] == "error"


class BrokenMessage(Exception):
    def __str__(self):
        raise Boom("str")


@pytest.mark.parametrize("in_run", [True, False], ids=["in_run", "own_run"])
def test_a_tool_error_that_cannot_be_printed_is_the_one_the_agent_sees(in_run):
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t():
        raise BrokenMessage()

    if in_run:
        with rec.run(), pytest.raises(BrokenMessage):
            t()
    else:
        with pytest.raises(BrokenMessage):
            t()


def test_an_async_tool_error_that_cannot_be_printed_is_the_one_the_agent_sees():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    async def t():
        raise BrokenMessage()

    with pytest.raises(BrokenMessage):
        asyncio.run(t())


def test_a_run_body_error_that_cannot_be_printed_is_the_one_the_agent_sees():
    rec = Recorder(MemorySink(), agent_id="a")
    with pytest.raises(BrokenMessage):
        with rec.run():
            raise BrokenMessage()


def test_a_tool_called_with_the_wrong_arguments_is_recorded():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t(a):
        return a

    with rec.run(), pytest.raises(TypeError):
        t(1, 2, c=object())
    (call,) = _of_type(rec._sink.records, "tool_call")
    assert call["status"] == "error" and call["tool_calls"][0]["arguments"]["args"] == [1, 2]


@pytest.mark.parametrize("fn", [min, dict.update], ids=["min", "dict_update"])
def test_a_builtin_can_be_a_tool(fn):
    rec = Recorder(MemorySink(), agent_id="a")
    rec.tool("name")(fn)


class CallableThing:
    def __call__(self, a):
        return a


def test_a_callable_object_can_be_a_tool_without_a_name():
    rec = Recorder(MemorySink(), agent_id="a")
    tool = rec.tool()(CallableThing())
    with rec.run():
        assert tool(5) == 5


def test_a_method_records_without_self():
    rec = Recorder(MemorySink(), agent_id="a")

    class Client:
        api_key = SECRET

        def __init__(self):
            self.token = SECRET

        @rec.tool()
        def t(self, a):
            return a

    with rec.run():
        assert Client().t(1) == 1
    assert SECRET.encode() not in b"".join(canonical_json(r) for r in rec._sink.records)


def test_tool_output_of_an_unknown_source_is_refused_at_decoration():
    rec = Recorder(MemorySink(), agent_id="a")
    with pytest.raises(ValueError, match="unknown source"):
        rec.tool(source="nowhere")


# --- never in the agent's way ---------------------------------------------------------------------------


def test_warnings_turned_into_errors_do_not_reach_the_agent():
    rec = Recorder(FullSink(), agent_id="a")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with rec.run() as run:
            run.note("x")


def test_recording_near_the_recursion_limit_does_not_raise():
    rec = Recorder(FullSink(), agent_id="a")

    def deep(n, run):
        return run.note("x", v=[[1]]) if n == 0 else deep(n - 1, run)

    limit, here = sys.getrecursionlimit(), len(inspect.stack())
    with rec.run() as run:
        for margin in range(10, 50):
            deep(limit - here - margin, run)


def test_a_failure_warns_once_and_is_counted():
    rec = Recorder(FullSink(), agent_id="a")
    with pytest.warns(RuntimeWarning, match="not being recorded") as seen:
        with rec.run() as run:
            run.note("x")
            run.note("y")
    assert len([w for w in seen if "not being recorded" in str(w.message)]) == 1
    assert rec.failures == 4


def test_a_recorder_that_was_closed_stays_quiet():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    def t():
        return 1

    rec.close()
    with rec.run() as run:
        assert t() == 1
        assert run.note("x") is None
    rec.close()
    assert rec.failures > 0


def test_a_recovery_note_that_cannot_be_written_does_not_stop_the_agent():
    sink = FullSink()
    sink.recovered = {"bytes": 3, "sidecar": "x"}
    rec = Recorder(sink, agent_id="a")
    assert rec.failures == 1


def test_an_empty_identity_field_is_refused_or_recorded():
    sink = MemorySink()
    try:
        rec = Recorder(sink, agent_id="a", agent_identity={"provider": "entra", "app_id": "x", "tenant_id": ""})
    except ValueError:
        return
    with rec.run() as run:
        run.note("x")
    assert sink.records and rec.failures == 0


def test_identity_that_is_not_text_is_refused():
    with pytest.raises(ValueError):
        Recorder(MemorySink(), agent_id="a", agent_identity={"provider": "x", "id": 5})


# --- threads and async ----------------------------------------------------------------------------------


def test_many_threads_on_one_run_leave_a_file_that_verifies(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=7)

    @rec.tool()
    def t(i):
        return {"i": i, "nan": float("nan"), "bytes": b"x", "text": "\ud83d"}

    with rec.run() as run:

        def work(n):
            for i in range(25):
                run.note("n", i=i)
                t(i)
                run.llm_call(provider="p", model="m", context=[Segment("user", str(n)), Segment("user", str(i))])

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(run.bind(work), range(8)))
    rec.close()
    records = _verified(path, pub)
    assert rec.failures == 0
    assert len(_of_type(records, "tool_call")) == len(_of_type(records, "note")) == 200
    steps = [r["step_id"] for r in records if r.get("run_id") == run.run_id]
    assert len(steps) == len(set(steps))


def test_closing_while_threads_write_is_safe(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=3)
    stop = threading.Event()
    problems = []

    with rec.run() as run:

        def work():
            while not stop.is_set():
                try:
                    run.note("n")
                except BaseException as exc:
                    problems.append(exc)
                    return

        threads = [threading.Thread(target=work) for _ in range(4)]
        for th in threads:
            th.start()
        rec.close()
        stop.set()
        for th in threads:
            th.join()
    assert problems == []
    _verified(path, pub)


def test_async_runs_interleave_without_mixing(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=7)

    @rec.tool()
    async def t(i):
        await asyncio.sleep(0)
        return {"i": i, "nan": float("nan")}

    async def one(i):
        with rec.run(run_id=f"r{i}") as run:
            await asyncio.sleep(0)
            out = await t(i)
            assert out["i"] == i and run.run_id == f"r{i}"

    async def everything():
        await asyncio.gather(*(one(i) for i in range(40)))

    asyncio.run(everything())
    rec.close()
    records = _verified(path, pub)
    assert rec.failures == 0
    assert all(r["tool_calls"][0]["arguments"]["i"] == int(r["run_id"][1:]) for r in _of_type(records, "tool_call"))


def test_a_cancelled_async_tool_is_recorded_and_stays_cancelled():
    rec = Recorder(MemorySink(), agent_id="a")

    @rec.tool()
    async def t():
        await asyncio.sleep(60)

    async def everything():
        task = asyncio.create_task(t())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(everything())
    (call,) = _of_type(rec._sink.records, "tool_call")
    assert "CancelledError" in call["error"]


def test_a_run_finished_in_another_task_does_not_raise():
    rec = Recorder(MemorySink(), agent_id="a")
    scope = rec.run()

    async def opens():
        scope.__enter__()

    async def closes():
        scope.__exit__(None, None, None)

    async def everything():
        await asyncio.create_task(opens())
        await asyncio.create_task(closes())

    asyncio.run(everything())
    assert _of_type(rec._sink.records, "run_end")[0]["status"] == "ok"


def test_a_generator_left_open_inside_a_run_does_not_raise():
    rec = Recorder(MemorySink(), agent_id="a")

    def agent():
        with rec.run():
            yield 1
            yield 2

    gen = agent()
    assert next(gen) == 1
    gen.close()
    assert _of_type(rec._sink.records, "run_end")[0]["status"] == "error"
    _verified_memory(rec._sink)


# --- what may be written, and where ---------------------------------------------------------------------


def _everything_with_content(run):
    run.llm_call(
        provider="p",
        model="m",
        context=[Segment("system", SECRET), Segment("user", {"k": SECRET})],
        output=[{"type": "text", "text": SECRET}],
        system_prompt=SECRET,
        tool_calls=[{"id": "1", "name": "t", "arguments": {"a": SECRET}}],
    )
    run.llm_call(
        provider="p",
        model="m",
        context=[Segment("system", SECRET), Segment("user", {"k": SECRET}), Segment("web", SECRET, name="page")],
    )
    run.tool_call("t", {"a": SECRET}, {"r": SECRET})


def test_redact_removes_all_ordinary_content(tmp_path, key, pub):
    _, path = _record(tmp_path, key, _everything_with_content)
    assert SECRET.encode() in path.read_bytes()
    out = tmp_path / "redacted.jsonl"
    assert main(["redact", str(path), str(out)]) == 0
    assert SECRET.encode() not in out.read_bytes()
    report = verify_file(out, [pub])
    assert report.ok, report.errors


def test_a_cap_of_zero_writes_no_content_at_all(tmp_path, key, pub):
    _, path = _record(tmp_path, key, _everything_with_content, max_content_bytes=0)
    _verified(path, pub)
    assert SECRET.encode() not in path.read_bytes()


def _tool_raises(rec, run):
    @rec.tool()
    def t():
        raise ValueError(f"card {SECRET} was declined")

    with pytest.raises(ValueError):
        t()


def _sdk_raises(rec, run):
    class Messages:
        def create(self, **kwargs):
            raise ValueError(f"could not process: {SECRET}")

    client = types.SimpleNamespace(messages=Messages())
    instrument_anthropic(client, rec)
    with pytest.raises(ValueError):
        client.messages.create(model="m", messages=[{"role": "user", "content": "x"}])


@pytest.mark.parametrize("cause", [_tool_raises, _sdk_raises], ids=["tool_error", "sdk_error"])
def test_error_text_can_be_removed_by_redact(tmp_path, key, pub, cause):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, max_content_bytes=0)
    with rec.run() as run:
        cause(rec, run)
    rec.close()
    out = tmp_path / "redacted.jsonl"
    assert main(["redact", str(path), str(out)]) == 0
    assert SECRET.encode() not in out.read_bytes()


@pytest.mark.parametrize(
    "cap, expected",
    [(0, "ValueError"), (5, "ValueError"), (24, "ValueError"), (1_000_000, f"ValueError: {'e' * 400}")],
    ids=["zero", "smaller_than_the_name", "no_room_for_a_message", "under_the_cap"],
)
def test_error_text_takes_the_cap_and_keeps_its_type_name(tmp_path, key, pub, cap, expected):
    rec = Recorder(MemorySink(), agent_id="a", max_content_bytes=cap)

    @rec.tool()
    def t():
        raise ValueError("e" * 400)

    with rec.run(), pytest.raises(ValueError):
        t()
    (call,) = _of_type(rec._sink.records, "tool_call")
    assert call["error"] == call["tool_calls"][0]["error"] == expected
    _verified_memory(rec._sink)


def test_error_text_cut_short_says_so_and_stays_within_the_cap():
    rec = Recorder(MemorySink(), agent_id="a", max_content_bytes=60)

    @rec.tool()
    def t():
        raise ValueError("\u00e9" * 400)

    with rec.run(), pytest.raises(ValueError):
        t()
    error = _of_type(rec._sink.records, "tool_call")[0]["error"]
    assert error.startswith("ValueError: \u00e9") and error.endswith(" <truncated>")
    assert len(error.encode("utf-8")) <= 60
    _verified_memory(rec._sink)


def test_a_tool_call_field_outside_the_slots_is_not_written(tmp_path, key, pub):
    rec, path = _record(
        tmp_path,
        key,
        lambda run: run.llm_call(
            provider="p", model="m", context=[], tool_calls=[{"id": "1", "name": "t", "input": {"a": SECRET}}]
        ),
    )
    _verified(path, pub)
    assert rec.failures == 1
    assert SECRET.encode() not in path.read_bytes()


def test_a_failure_message_does_not_carry_the_content(tmp_path, key, pub, caplog):
    with caplog.at_level(logging.ERROR, logger="mnestiq"), warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        rec, _ = _record(
            tmp_path, key, lambda run: run.tool_call("t", {"a": SECRET}, result_source="nowhere", error=SECRET)
        )
    assert rec.failures == 1
    assert SECRET not in caplog.text
    assert not any(SECRET in str(w.message) for w in seen)


def test_private_attributes_are_not_written():
    assert SECRET not in json.dumps(to_jsonable(Thing(_password=SECRET, ok=1)))


def test_a_pydantic_secret_is_not_written():
    pydantic = pytest.importorskip("pydantic")

    class Model(pydantic.BaseModel):
        key: pydantic.SecretStr

    assert SECRET not in json.dumps(to_jsonable(Model(key=SECRET)))
    assert SECRET not in json.dumps(to_jsonable(pydantic.SecretStr(SECRET)))


# --- sinks ---------------------------------------------------------------------------------------------


def _enospc(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


def test_a_full_disk_is_survived_and_the_chain_goes_on(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    rec = Recorder(sink, agent_id="a", signing_key=key, checkpoint_every=2)

    @rec.tool()
    def t():
        return 7

    with rec.run() as run:
        run.note("before")
        real = sink._fh.write
        sink._fh.write = _enospc
        assert t() == 7
        assert run.note("lost") is None
        sink._fh.write = real
        run.note("after")
    rec.close()
    assert rec.failures >= 2
    assert [r["attributes"]["message"] for r in _of_type(_verified(path, pub), "note")] == ["before", "after"]


def test_a_half_line_that_cannot_be_removed_does_not_poison_the_file(tmp_path):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    rec = Recorder(sink, agent_id="a")
    with rec.run() as run:
        run.note("before")
        real_write, real_truncate = sink._fh.write, sink._fh.truncate

        def half(data):
            real_write(bytes(data[: len(data) // 2]))
            raise OSError(errno.ENOSPC, "No space left on device")

        sink._fh.write, sink._fh.truncate = half, _enospc
        run.note("lost")
        sink._fh.write, sink._fh.truncate = real_write, real_truncate
        run.note("after")
    rec.close()
    assert verify_file(path).ok


def test_two_half_lines_in_a_row_leave_nothing_behind(tmp_path):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    rec = Recorder(sink, agent_id="a")
    with rec.run() as run:
        run.note("before")
        real = sink._fh.write

        def half(data):
            real(bytes(data[: len(data) // 2]))
            raise OSError(errno.ENOSPC, "No space left on device")

        sink._fh.write = half
        run.note("lost")
        run.note("lost too")
        sink._fh.write = real
        run.note("after")
    rec.close()
    assert [r["attributes"]["message"] for r in _of_type(_verified(path), "note")] == ["before", "after"]


def test_short_writes_are_finished(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    real = sink._fh.write
    sink._fh.write = lambda data: real(bytes(data[:5]))
    rec = Recorder(sink, agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("x")
    rec.close()
    _verified(path, pub)


@pytest.mark.parametrize("wrote", [0, None], ids=["zero", "none"])
def test_a_write_that_writes_nothing_is_a_failure_not_a_hang(tmp_path, wrote):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    real = sink._fh.write
    sink._fh.write = lambda data: wrote
    rec = Recorder(sink, agent_id="a")
    with rec.run() as run:
        assert run.note("x") is None
    sink._fh.write = real
    rec.close()
    assert rec.failures > 0


def test_a_failing_fsync_is_a_failure_and_leaves_no_half_record(tmp_path, key, pub, monkeypatch):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path, fsync=True), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.note("before")
        monkeypatch.setattr(os, "fsync", _enospc)
        assert run.note("lost") is None
        monkeypatch.undo()
        run.note("after")
    rec.close()
    assert [r["attributes"]["message"] for r in _of_type(_verified(path, pub), "note")] == ["before", "after"]


def test_a_failing_close_does_not_keep_the_file_locked(tmp_path, monkeypatch):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path, fsync=True), agent_id="a")
    with rec.run():
        pass
    monkeypatch.setattr(os, "fsync", _enospc)
    rec.close()
    monkeypatch.undo()
    assert rec.failures == 1
    FileSink(path).close()


def test_a_directory_as_the_evidence_file_is_a_clear_error(tmp_path):
    with pytest.raises(SinkError, match="not a regular file"):
        FileSink(tmp_path)


@pytest.mark.skipif(getattr(os, "geteuid", lambda: 1)() == 0, reason="root ignores file modes")
def test_a_read_only_evidence_file_is_a_clear_error(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b"")
    path.chmod(stat.S_IREAD)
    try:
        with pytest.raises(OSError):
            FileSink(path)
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.parametrize("name", ["a\x00b", "x" * 5000], ids=["nul", "very_long"])
def test_an_impossible_file_name_is_a_clear_error(tmp_path, name):
    with pytest.raises((OSError, ValueError)):
        FileSink(tmp_path / name)


def test_a_file_where_the_folder_should_be_is_a_clear_error(tmp_path):
    (tmp_path / "f").write_bytes(b"")
    with pytest.raises(OSError):
        FileSink(tmp_path / "f" / "e.jsonl")
    with pytest.raises(OSError):
        HeadFile(tmp_path / "f" / "head.json")


def _head_is_directory(tmp_path):
    (tmp_path / "head").mkdir()
    return HeadFile(tmp_path / "head")


def _head_tmp_is_directory(tmp_path):
    (tmp_path / "head.tmp").mkdir()
    return HeadFile(tmp_path / "head")


def _head_with_nul(tmp_path):
    return HeadFile(tmp_path / "he\x00ad")


def _head_very_long(tmp_path):
    return HeadFile(tmp_path / ("x" * 5000))


def _head_folder_removed(tmp_path):
    head = HeadFile(tmp_path / "gone" / "head")
    shutil.rmtree(tmp_path / "gone")
    return head


def _head_empty(tmp_path):
    return HeadFile("")


@pytest.mark.parametrize(
    "make",
    [_head_is_directory, _head_tmp_is_directory, _head_with_nul, _head_very_long, _head_folder_removed, _head_empty],
    ids=lambda f: f.__name__,
)
def test_a_head_file_that_cannot_be_written_is_counted_not_raised(tmp_path, key, pub, make):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    path = evidence / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key, checkpoint_every=1, on_checkpoint=make(tmp_path))
    with rec.run() as run:
        run.note("x")
    rec.close()
    assert rec.failures >= 1
    assert _of_type(_verified(path, pub), "note")


def test_an_on_checkpoint_hook_that_raises_is_counted(tmp_path, key, pub):
    def hook(checkpoint):
        raise Boom()

    rec, path = _record(tmp_path, key, lambda run: run.note("x"), on_checkpoint=hook)
    assert rec.failures >= 1
    _verified(path, pub)


# --- keys ----------------------------------------------------------------------------------------------


def _pem(key, password=None):
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


BAD_PRIVATE_KEYS = {
    "empty": lambda: b"",
    "garbage": lambda: SECRET.encode() * 10,
    "binary": lambda: bytes(range(256)) * 16,
    "pem_header_only": lambda: b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
    "pem_bad_body": lambda: b"-----BEGIN PRIVATE KEY-----\nAAAA!!!!\n-----END PRIVATE KEY-----\n",
    "pem_truncated": lambda: _pem(generate_private_key())[:60],
    "huge": lambda: b"A" * (20 * 1024 * 1024),
    "public_key_pem": lambda: (
        generate_private_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ),
    "rsa": lambda: _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    "p384": lambda: _pem(ec.generate_private_key(ec.SECP384R1())),
    "ed448": lambda: _pem(ed448.Ed448PrivateKey.generate()),
    "x25519": lambda: _pem(x25519.X25519PrivateKey.generate()),
}


def _bad_private_key_params():
    return [
        *[pytest.param(make, id=name) for name, make in BAD_PRIVATE_KEYS.items()],
        pytest.param(lambda: _pem(generate_private_key(), b"pw"), id="encrypted"),
    ]


@pytest.mark.parametrize("make", _bad_private_key_params())
def test_a_bad_private_key_file_is_a_clear_error(tmp_path, make):
    path = tmp_path / "bad.key"
    path.write_bytes(make())
    with pytest.raises(ValueError) as caught:
        load_private_key(path)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("make", _bad_private_key_params())
def test_a_bad_private_key_file_is_a_clear_error_through_the_cli(tmp_path, capsys, make):
    path = tmp_path / "bad.key"
    path.write_bytes(make())
    assert main(["proxy", str(tmp_path / "e.jsonl"), "--agent", "a", "--key", str(path)]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert captured.err.startswith("error:") and "Traceback" not in captured.err
    assert SECRET not in captured.err


def test_a_private_key_path_that_is_not_a_file_is_a_clear_error(tmp_path):
    with pytest.raises(OSError):
        load_private_key(tmp_path)
    with pytest.raises(OSError):
        load_private_key(tmp_path / "missing.key")


BAD_PUBLIC_KEYS = {
    "empty": b"",
    "garbage": b"not base64 at all!",
    "binary": bytes(range(256)),
    "too_short": base64.b64encode(b"x" * 16),
    "wrong_length": base64.b64encode(b"x" * 33),
    "off_the_curve": base64.b64encode(b"\x04" + b"\x01" * 64),
    "huge": b"A" * (5 * 1024 * 1024),
}


@pytest.mark.parametrize("content", BAD_PUBLIC_KEYS.values(), ids=BAD_PUBLIC_KEYS.keys())
def test_a_bad_public_key_file_is_a_clear_error(tmp_path, content):
    path = tmp_path / "bad.pub"
    path.write_bytes(content)
    with pytest.raises(ValueError):
        load_public_key_b64(str(path))


@pytest.mark.parametrize("content", BAD_PUBLIC_KEYS.values(), ids=BAD_PUBLIC_KEYS.keys())
def test_a_bad_public_key_file_is_a_clear_error_through_the_cli(tmp_path, capsys, content):
    evidence = tmp_path / "e.jsonl"
    with Recorder(FileSink(evidence), agent_id="a") as rec, rec.run():
        pass
    path = tmp_path / "bad.pub"
    path.write_bytes(content)
    assert main(["verify", str(evidence), "--trusted-key", str(path)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


@pytest.mark.parametrize(
    "value",
    ["", "a\x00b", "x" * 100_000, "\u00e9\u00e9", "a" * 42 + "=="],
    ids=["empty", "nul", "very_long", "not_ascii", "not_a_key"],
)
def test_a_bad_literal_public_key_is_a_clear_error(tmp_path, capsys, value):
    evidence = tmp_path / "e.jsonl"
    with Recorder(FileSink(evidence), agent_id="a") as rec, rec.run():
        pass
    assert main(["verify", str(evidence), "--trusted-key", value]) == EXIT_USAGE
    assert capsys.readouterr().err.startswith("error:")


def test_a_directory_as_a_public_key_is_a_clear_error(tmp_path, capsys):
    evidence = tmp_path / "e.jsonl"
    with Recorder(FileSink(evidence), agent_id="a") as rec, rec.run():
        pass
    assert main(["verify", str(evidence), "--trusted-key", str(tmp_path)]) == EXIT_USAGE
    assert capsys.readouterr().err.startswith("error:")


@pytest.mark.parametrize(
    "signature",
    [b"", b"x", b"x" * 63, b"x" * 64, b"x" * 65, b"\xff" * 64, b"\x00" * 64],
    ids=lambda s: f"{len(s)}_bytes_{s[:1].hex()}",
)
@pytest.mark.parametrize("alg", ["ed25519", "ecdsa-p256-sha256"])
def test_a_bad_signature_is_only_ever_invalid(alg, signature):
    key = generate_private_key(alg)
    with pytest.raises(InvalidSignature):
        verify_signature(alg, public_key_b64(key), signature, b"payload")


@pytest.mark.parametrize(
    "public",
    ["", "====", "not base64", "AAAA", base64.b64encode(b"\x04" + b"\x01" * 64).decode()],
    ids=["empty", "padding", "text", "short", "off_curve"],
)
def test_a_bad_public_key_cannot_verify_anything(public):
    with pytest.raises(InvalidSignature):
        verify_signature("ed25519", public, b"x" * 64, b"payload")


def test_a_high_s_signature_is_refused():
    key = generate_private_key("ecdsa-p256-sha256")
    good = p256_raw_signature(key.sign(b"payload", ec.ECDSA(hashes.SHA256())))
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    high = good[:32] + (order - int.from_bytes(good[32:], "big")).to_bytes(32, "big")
    with pytest.raises(InvalidSignature):
        verify_signature("ecdsa-p256-sha256", public_key_b64(key), high, b"payload")


@pytest.mark.parametrize(
    "der", [b"", b"garbage", encode_dss_signature(1, 2)[:-1]], ids=["empty", "garbage", "truncated"]
)
def test_a_bad_der_signature_is_a_clear_error(der):
    with pytest.raises(ValueError):
        p256_raw_signature(der)


def test_a_der_signature_with_numbers_too_long_is_a_clear_error():
    with pytest.raises(ValueError):
        p256_raw_signature(encode_dss_signature(2**300, 1))


@pytest.mark.parametrize("sig", [b"", b"x" * 63, b"x" * 65], ids=["empty", "short", "long"])
def test_a_raw_signature_of_the_wrong_size_is_a_clear_error(sig):
    with pytest.raises(ValueError):
        normalize_p256(sig)


@pytest.mark.parametrize("public", ["", "not base64!", "AAAA"], ids=["empty", "text", "short"])
def test_a_key_id_of_a_bad_key_is_a_clear_error(public):
    with pytest.raises(ValueError):
        key_id(public)


def test_a_key_is_never_overwritten(tmp_path):
    save_keypair(generate_private_key(), tmp_path)
    with pytest.raises(FileExistsError):
        save_keypair(generate_private_key(), tmp_path)


# --- timestamps -----------------------------------------------------------------------------------------


class FakeTSA(Timestamper):
    def __init__(self, *replies):
        super().__init__(urls=[f"http://tsa{i}.invalid/" for i in range(len(replies))], timeout=0.1)
        self.replies = list(replies)
        self.asked = []

    def _post(self, url, body):
        self.asked.append(url)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _real_token():
    cp = next(r for r in load(DATA / "timestamped.jsonl") if r["kind"] == "checkpoint")
    return base64.b64decode(cp["timestamp_token"]), base64.b64decode(cp["signature"])


def _der(tag, content):
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


GRANTED = _der(0x30, b"\x02\x01\x00")
HOSTILE_REPLIES = {
    "empty": b"",
    "one_byte": b"\x00",
    "garbage": b"\xff" * 1000,
    "only_a_tag": b"\x30",
    "length_past_the_end": b"\x30\x84\xff\xff\xff\xff",
    "indefinite_length": b"\x30\x80\x00\x00",
    "length_of_length_too_long": b"\x30\x85\x01\x01\x01\x01\x01",
    "wrong_outer_tag": _der(0x31, GRANTED),
    "refused": _der(0x30, _der(0x30, b"\x02\x01\x02")),
    "refused_with_huge_status": _der(0x30, _der(0x30, b"\x02\x08" + b"\xff" * 8)),
    "status_is_not_an_integer": _der(0x30, _der(0x30, b"\x04\x01\x00")),
    "status_is_not_a_sequence": _der(0x30, _der(0x31, b"\x02\x01\x00")),
    "granted_no_token": _der(0x30, GRANTED),
    "granted_garbage_token": _der(0x30, GRANTED + _der(0x30, b"junk")),
    "huge_garbage": b"\x30\x83\x10\x00\x00" + b"\x00" * (1 << 20),
}


@needs_rfc3161
@pytest.mark.parametrize("reply", HOSTILE_REPLIES.values(), ids=HOSTILE_REPLIES.keys())
def test_a_hostile_answer_from_a_tsa_is_a_timestamp_error(reply):
    with pytest.raises(TimestampError):
        FakeTSA(reply)(b"signature")


@needs_rfc3161
def test_a_real_token_replayed_by_a_tsa_is_refused():
    token, signature = _real_token()
    with pytest.raises(TimestampError):
        FakeTSA(_der(0x30, GRANTED + token))(signature)


@needs_rfc3161
def test_the_next_tsa_is_tried_after_a_bad_answer():
    tsa = FakeTSA(b"garbage", OSError("refused"))
    with pytest.raises(TimestampError):
        tsa(b"signature")
    assert len(tsa.asked) == 2


@needs_rfc3161
def test_a_tsa_url_that_cannot_be_parsed_does_not_stop_the_next_one():
    tsa = FakeTSA(ValueError("bad"), b"garbage")
    tsa.urls = ["http://[bad", "http://tsa.invalid/"]
    with pytest.raises(TimestampError):
        tsa(b"signature")
    assert len(tsa.asked) == 2


@needs_rfc3161
def test_a_password_in_a_tsa_url_stays_out_of_the_error():
    tsa = FakeTSA(OSError("refused"))
    tsa.urls = [f"http://user:{SECRET}@tsa.invalid/"]
    with pytest.raises(TimestampError) as caught:
        tsa(b"signature")
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "reply",
    [
        *[pytest.param(v, id=k) for k, v in HOSTILE_REPLIES.items()],
        pytest.param(b"\x30\x00", id="empty_sequence"),
    ],
)
def test_token_from_response_only_raises_timestamp_error(reply):
    with contextlib.suppress(TimestampError):  # a reply can hold a token that is only checked later
        token_from_response(reply)


@needs_rfc3161
@pytest.mark.parametrize(
    "token",
    [
        b"",
        b"\x00",
        b"\x30\x00",
        b"\xff" * 64,
        _der(0x30, b"x"),
        _der(0x30, _der(0x06, b"\x01") + _der(0xA0, b"")),
        _der(0x30, _der(0x06, b"\x01") + _der(0xA0, _der(0x30, _der(0xA0, b"junk")))),
    ],
    ids=lambda t: t[:6].hex() or "empty",
)
def test_a_broken_token_is_a_timestamp_error(token):
    with pytest.raises(TimestampError):
        verify_token(token, b"signature", default_roots())


@needs_rfc3161
def test_no_trusted_roots_is_a_timestamp_error():
    token, signature = _real_token()
    with pytest.raises(TimestampError, match="no trusted"):
        verify_token(token, signature, [])


@needs_rfc3161
def test_a_damaged_real_token_is_only_ever_a_timestamp_error():
    token, signature = _real_token()
    roots = default_roots()
    original = verify_token(token, signature, roots)
    rng = random.Random(8675309)
    for _ in range(300):
        damaged = bytearray(token)
        for _ in range(rng.randint(1, 8)):
            damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        if rng.random() < 0.3:
            damaged = damaged[: rng.randrange(len(damaged))]
        with contextlib.suppress(TimestampError):
            # A byte in a spare certificate is outside what is signed, so such a token may still pass.
            assert verify_token(bytes(damaged), signature, roots) == original


def _certificate(subject, issuer, public_key, signing_key, ca):
    name = lambda text: x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, text)])  # noqa: E731
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signing_key, None)
    )


def test_a_certificate_loop_ends_in_refusal():
    a_key, b_key, root_key = (
        ed25519.Ed25519PrivateKey.generate(),
        ed25519.Ed25519PrivateKey.generate(),
        ed25519.Ed25519PrivateKey.generate(),
    )
    a = _certificate("A", "B", a_key.public_key(), b_key, True)
    b = _certificate("B", "A", b_key.public_key(), a_key, True)
    root = _certificate("root", "root", root_key.public_key(), root_key, True)
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(TimestampError, match="does not chain"):
        _chain_to_root(a, [b], [root], now)


def test_a_certificate_with_the_name_of_a_root_is_not_the_root():
    root_key, fake_key = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    root = _certificate("root", "root", root_key.public_key(), root_key, True)
    fake = _certificate("root", "root", fake_key.public_key(), fake_key, True)
    leaf = _certificate("tsa", "root", ed25519.Ed25519PrivateKey.generate().public_key(), fake_key, False)
    with pytest.raises(TimestampError, match="does not chain"):
        _chain_to_root(leaf, [fake], [root], datetime.datetime.now(datetime.timezone.utc))


class _DripHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        with contextlib.suppress(OSError):
            for _ in range(20):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)

    def log_message(self, *args):
        pass


@needs_rfc3161
def test_a_tsa_that_drips_its_answer_cannot_hold_up_the_agent():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DripHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        tsa = Timestamper(urls=[f"http://127.0.0.1:{server.server_port}/"], timeout=0.3)
        started = time.perf_counter()
        with pytest.raises(TimestampError):
            tsa(b"signature")
        assert time.perf_counter() - started < 1.5
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "answer", [lambda s: "text", lambda s: None, lambda s: 5, lambda s: 1 / 0], ids=["str", "none", "int", "raises"]
)
def test_a_timestamper_that_misbehaves_costs_only_the_token(tmp_path, key, pub, answer):
    rec, path = _record(tmp_path, key, lambda run: run.note("x"), timestamper=answer)
    records = _verified(path, pub)
    assert any(r["kind"] == "checkpoint" and "timestamp_token" not in r for r in records)
    assert rec.failures == 0


def test_an_empty_token_costs_only_the_token(tmp_path, key, pub):
    _, path = _record(tmp_path, key, lambda run: run.note("x"), timestamper=lambda s: b"")
    _verified(path, pub)


@needs_rfc3161
def test_a_token_that_is_not_a_token_is_not_written(tmp_path, key, pub):
    _, path = _record(tmp_path, key, lambda run: run.note("x"), timestamper=lambda s: b"not a token")
    _verified(path, pub)


@needs_rfc3161
def test_a_hostile_tsa_never_stops_a_checkpoint(tmp_path, key, pub):
    tsa = FakeTSA(b"garbage", b"\x30\x00")
    _, path = _record(tmp_path, key, lambda run: run.note("x"), timestamper=tsa)
    records = _verified(path, pub)
    assert [r for r in records if r["kind"] == "checkpoint"]
    assert not any("timestamp_token" in r for r in records)


# --- egress ---------------------------------------------------------------------------------------------


@pytest.fixture
def egress():
    instrument_egress()
    yield
    uninstrument_egress()


def _http(handler):
    httpx2 = pytest.importorskip("httpx2")
    return httpx2.Client(transport=httpx2.MockTransport(handler))


def _ok(request):
    httpx2 = pytest.importorskip("httpx2")
    return httpx2.Response(200, text="fine")


SECRET_PARAMS = [
    "api_key",
    "apikey",
    "API-KEY",
    "key",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "signature",
    "sig",
    "X-Amz-Signature",
    "X-Amz-Credential",
    "credential",
    "auth",
    "authorization",
    "code",
    "session",
    "sessionid",
    "jwt",
    "bearer",
    "private_key",
    "cookie",
    "otp",
]


@pytest.mark.parametrize("name", SECRET_PARAMS)
def test_a_secret_looking_parameter_is_masked(name):
    assert SECRET not in sanitize_url(f"https://h.example/p?{name}={SECRET}&keep=1")


@pytest.mark.parametrize("name", ["pwd", "pass", "access_key", "pin"])
def test_common_short_secret_names_are_masked(name):
    assert SECRET not in sanitize_url(f"https://h.example/p?{name}={SECRET}")


def test_a_secret_after_a_semicolon_is_masked():
    assert SECRET not in sanitize_url(f"https://h.example/p?a=1;token={SECRET}")


@pytest.mark.parametrize(
    "url",
    [
        f"https://user:{SECRET}@h.example/p",
        f"https://h.example/p#{SECRET}",
        f"https://h.example/p?%74oken={SECRET}",
        f"https://h.example/p?a=1&token[]={SECRET}",
        f"HTTP://user:{SECRET}@h.example:8080/?Token={SECRET}",
        f"https://user:{SECRET}@[::1]:8080/p",
    ],
    ids=["userinfo", "fragment", "encoded_name", "array_name", "upper_case", "ipv6"],
)
def test_a_secret_in_a_url_is_taken_out(url):
    assert SECRET not in sanitize_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://[bad",
        "http://h:99999/",
        "http://h:port/",
        "",
        "::",
        "a" * 1_000_000,
        "http://\ud83d/",
        "http://h/\ud83d?a=\udc00",
        "http://h/a\nb",
        "http://h/\x00",
        "//",
        "?",
        "http://[::1",
    ],
    ids=lambda u: repr(u[:12]),
)
def test_a_hostile_url_gives_text_and_no_error(url):
    assert isinstance(sanitize_url(url), str)


def test_a_url_with_a_port_it_cannot_read_is_marked():
    assert sanitize_url("http://h:99999/") == "<unparseable url>"


def test_a_request_goes_through_when_recording_fails(egress):
    rec = Recorder(FullSink(), agent_id="a")
    with rec.run():
        assert _http(_ok).get("http://h.test/").status_code == 200
    assert rec.failures >= 3


def test_a_request_goes_through_after_the_recorder_closes(egress):
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run():
        rec.close()
        assert _http(_ok).get("http://h.test/").status_code == 200


def test_a_run_id_that_is_not_text_does_not_break_the_request(egress):
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run(run_id=12345):
        assert _http(_ok).get("http://h.test/").status_code == 200


def test_a_run_id_a_header_cannot_carry_is_left_out(egress):
    rec = Recorder(MemorySink(), agent_id="a")
    seen = []

    def handler(request):
        seen.append(dict(request.headers))
        return _ok(request)

    with rec.run(run_id="bad\r\nX-Injected: 1"):
        assert _http(handler).get("http://h.test/").status_code == 200
    assert "x-injected" not in seen[0] and "x-mnestiq-run-id" not in seen[0]
    _verified_memory(rec._sink)


class OddStream:
    def __init__(self, addr):
        self.addr = addr

    def get_extra_info(self, name):
        return self.addr


@pytest.mark.parametrize(
    "addr",
    [("127.0.0.1", "port"), ("127.0.0.1", None), ("127.0.0.1", 99999)],
    ids=["text_port", "none_port", "port_too_big"],
)
def test_an_odd_connection_address_does_not_break_the_request(egress, addr):
    httpx2 = pytest.importorskip("httpx2")
    rec = Recorder(MemorySink(), agent_id="a")

    def handler(request):
        return httpx2.Response(200, extensions={"network_stream": OddStream(addr)})

    with rec.run():
        assert _http(handler).get("http://h.test/").status_code == 200
    assert _of_type(rec._sink.records, "egress")


def test_a_request_error_that_cannot_be_printed_is_the_one_the_agent_sees(egress):
    rec = Recorder(MemorySink(), agent_id="a")

    def handler(request):
        raise BrokenMessage()

    with rec.run(), pytest.raises(BrokenMessage):
        _http(handler).get("http://h.test/")


def test_a_url_that_cannot_be_parsed_does_not_break_the_request(egress):
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run():
        with _http_scope("GET", "http://[bad"):
            pass


def test_a_real_connection_is_recorded_and_verifies(egress):
    rec = Recorder(MemorySink(), agent_id="a")
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        with rec.run(), socket.socket() as client:
            client.connect(server.getsockname())
    (event,) = _of_type(rec._sink.records, "egress")
    assert event["egress"][0]["protocol"] == "tcp"
    _verified_memory(rec._sink)


@pytest.mark.parametrize(
    "address, error",
    [(("127.0.0.1", 99999), OverflowError), ("not a tuple", TypeError)],
    ids=["port_too_big", "not_a_tuple"],
)
def test_a_connect_with_bad_arguments_fails_as_it_always_did(egress, address, error):
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run(), socket.socket() as client, pytest.raises(error):
        client.connect(address)


# --- identity -------------------------------------------------------------------------------------------


def test_a_host_with_no_name_does_not_stop_the_recorder(monkeypatch):
    def fail():
        raise OSError(errno.EINVAL, "no host name")

    monkeypatch.delenv("MNESTIQ_SANDBOX_ID", raising=False)
    monkeypatch.setattr(identity.socket, "gethostname", fail)
    rec = Recorder(MemorySink(), agent_id="a")
    assert rec.sandbox_id is None or isinstance(rec.sandbox_id, str)


@pytest.mark.parametrize("sandbox_id", ["\ud83d", "x" * 100_000, "\x00", ""], ids=["surrogate", "huge", "nul", "empty"])
def test_an_odd_sandbox_id_still_verifies(tmp_path, key, pub, sandbox_id):
    rec, path = _record(tmp_path, key, lambda run: run.note("x"), sandbox_id=sandbox_id)
    assert _of_type(_verified(path, pub), "note")
    assert rec.failures == 0


def test_unreadable_container_files_give_a_host_id(monkeypatch):
    monkeypatch.delenv("MNESTIQ_SANDBOX_ID", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)

    def fail(self, *args, **kwargs):
        raise PermissionError("no")

    monkeypatch.setattr(Path, "read_text", fail)
    assert identity.detect_sandbox_id().startswith("host:")


def test_a_pod_with_no_namespace_file_gets_a_default(monkeypatch, tmp_path):
    monkeypatch.delenv("MNESTIQ_SANDBOX_ID", raising=False)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setattr(identity, "_K8S_NAMESPACE", tmp_path / "missing")
    assert identity.detect_sandbox_id().startswith("k8s:default/")


def test_a_huge_cgroup_file_is_read_quickly(monkeypatch):
    monkeypatch.setattr(identity, "_read", lambda path: "docker-" * 200_000)
    assert identity._container_id() is None


# --- merkle ---------------------------------------------------------------------------------------------


def _rfc9162_root(leaves):
    """An independent bottom-up build: a stack of completed subtrees, merged as a binary counter."""
    stack = []
    for count, leaf in enumerate(leaves, start=1):
        node = hashlib.sha256(b"\x00" + leaf).digest()
        n = count
        while n % 2 == 0:
            node = hashlib.sha256(b"\x01" + stack.pop() + node).digest()
            n //= 2
        stack.append(node)
    node = stack.pop()
    while stack:
        node = hashlib.sha256(b"\x01" + stack.pop() + node).digest()
    return node


@pytest.mark.parametrize("n", [*range(1, 34), 64, 65, 127, 128, 129, 1000])
def test_merkle_roots_match_an_independent_build(n):
    leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(n)]
    assert merkle_root(leaves) == _rfc9162_root(leaves)


def test_merkle_root_of_nothing_is_the_hash_of_nothing():
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_merkle_leaves_of_any_size():
    leaves = [b"", b"\x00", b"x" * 1_000_000]
    assert merkle_root(leaves) == _rfc9162_root(leaves)


def test_merkle_copying_the_last_leaf_changes_the_root():
    x, y, z = b"x" * 32, b"y" * 32, b"z" * 32
    assert merkle_root([x, y, z]) != merkle_root([x, y, z, z])


def test_merkle_a_node_cannot_pass_as_a_leaf():
    x, y = b"x" * 32, b"y" * 32
    joined = hashlib.sha256(b"\x00" + x).digest() + hashlib.sha256(b"\x00" + y).digest()
    assert merkle_root([x, y]) != merkle_root([joined])


def test_merkle_many_leaves_do_not_overflow_the_stack():
    assert len(merkle_root([b"x"] * 100_000)) == 32


# --- canonical JSON ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("line", (VECTORS / "valid.jsonl").read_bytes().splitlines() if VECTORS.exists() else [])
def test_a_published_record_is_already_canonical(line):
    assert canonical_json(parse_json(line)) == line


@pytest.mark.skipif(not VECTORS.exists(), reason="needs spec/vectors from the repository")
def test_the_worked_example_of_the_spec():
    expected = json.loads((VECTORS / "expected.json").read_text("utf-8"))
    example = expected["worked_example"]
    salted = example["salted_digest"]
    assert canonical_json(parse_json(salted["value_jcs"])).decode("utf-8") == salted["value_jcs"]
    assert salted_digest(salted["salt_base64"], parse_json(salted["value_jcs"])) == salted["digest"]
    record = next(r for r in load(VECTORS / "valid.jsonl") if r["seq"] == example["record_seq"])
    assert canonical_json(hashed_form(record)).decode("utf-8") == example["hashed_form_jcs"]
    assert record_hash(record) == record["record_hash"]


@pytest.mark.parametrize(
    "char, expected",
    [
        ("\b", '"\\b"'),
        ("\t", '"\\t"'),
        ("\n", '"\\n"'),
        ("\f", '"\\f"'),
        ("\r", '"\\r"'),
        ('"', '"\\""'),
        ("\\", '"\\\\"'),
        ("\x00", '"\\u0000"'),
        ("\x0b", '"\\u000b"'),
        ("\x1f", '"\\u001f"'),
        ("\x7f", '"\x7f"'),
        ("/", '"/"'),
        ("\u2028", '"\u2028"'),
        ("\u2029", '"\u2029"'),
        ("\U0001f600", '"\U0001f600"'),
        ("\ufeff", '"\ufeff"'),
    ],
)
def test_strings_are_escaped_as_rfc_8785_says(char, expected):
    assert canonical_json(char) == expected.encode("utf-8")


def test_the_rfc_8785_key_order_with_equal_prefixes():
    value = {"a": 1, "": 2, "aa": 3, "\U0001f600": 4, "\ufb33": 5, "\x80": 6, "A": 7}
    assert list(json.loads(canonical_json(value))) == ["", "A", "a", "aa", "\x80", "\U0001f600", "\ufb33"]


@pytest.mark.parametrize("bad", ["\ud83d", ["\udc00"], {"a": "\ud83d"}], ids=["alone", "in_list", "in_value"])
def test_broken_text_is_a_canonicalization_error(bad):
    with pytest.raises(CanonicalizationError):
        canonical_json(bad)


def test_a_broken_key_is_a_canonicalization_error():
    with pytest.raises(CanonicalizationError):
        canonical_json({"\ud83d": 1})


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), 2**53, -(2**53), b"x", object(), {1: 2}, {b"k": 1}, {(1,): 2}, {1, 2}],
    ids=["nan", "inf", "over_safe", "under_safe", "bytes", "object", "int_key", "bytes_key", "tuple_key", "set"],
)
def test_what_json_cannot_hold_is_refused(bad):
    with pytest.raises(CanonicalizationError):
        canonical_json(bad)


def test_every_control_character_round_trips():
    text = "".join(map(chr, range(0x80)))
    assert json.loads(canonical_json(text)) == text


def test_numbers_at_the_limits_round_trip():
    for x in (5e-324, 2.2250738585072014e-308, sys.float_info.max, 1e21, 1e-7, 1e20, 9007199254740992.0, -1.5):
        assert parse_json(canonical_json(x)) == x
    assert canonical_json(-0.0) == b"0"
    assert canonical_json(2**53 - 1) == b"9007199254740991"


# --- the SDK wrappers -------------------------------------------------------------------------------------


class AttrRaises:
    def __getattr__(self, name):
        raise Boom(name)


class PropertyRaises:
    @property
    def content(self):
        raise Boom("content")

    @property
    def choices(self):
        raise Boom("choices")


def _namespace(**kwargs):
    return types.SimpleNamespace(**kwargs)


ODD_ANTHROPIC_RESPONSES = {
    "none": None,
    "int": 5,
    "text": "text",
    "list": [],
    "empty_dict": {},
    "object": object(),
    "magic_mock": mock.MagicMock(),
    "attribute_raises": AttrRaises(),
    "property_raises": PropertyRaises(),
    "content_is_text": {"content": "text"},
    "content_is_int": {"content": 5},
    "content_holds_junk": {"content": [None, 1, "x", [], {"type": 5}]},
    "tool_use_empty": {"content": [{"type": "tool_use"}]},
    "tool_use_id_is_int": {"content": [{"type": "tool_use", "id": 5, "name": "t", "input": {}}]},
    "tool_use_name_is_dict": {"content": [{"type": "tool_use", "id": "1", "name": {"a": 1}, "input": {}}]},
    "tool_use_input_is_deep": {"content": [{"type": "tool_use", "id": "1", "name": "t", "input": _deep(20_000)}]},
    "usage_is_text": {"content": [], "usage": "lots"},
    "usage_is_huge": {"content": [], "usage": {"input_tokens": 2**70}},
    "usage_is_negative": {"content": [], "usage": {"input_tokens": -1}},
    "model_is_int": {"content": [], "model": 5},
    "model_is_object": {"content": [], "model": object()},
    "id_is_dict": {"content": [], "id": {"a": 1}},
    "stop_reason_is_object": {"content": [], "stop_reason": object()},
    "surrogates": {"content": [{"type": "text", "text": "\ud83d"}], "id": "\ud83d", "stop_reason": "\udc00"},
    "namespace": _namespace(content=[_namespace(type="text", text="hi")], usage=_namespace(input_tokens=1), id="x"),
}


def _fake_anthropic(result, client_name="Client"):
    class Messages:
        def create(self, **kwargs):
            return result

    return type(client_name, (), {"messages": Messages()})()


@pytest.mark.parametrize("response", ODD_ANTHROPIC_RESPONSES.values(), ids=ODD_ANTHROPIC_RESPONSES.keys())
def test_an_odd_anthropic_response_reaches_the_agent_unchanged(response):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _fake_anthropic(response)
    instrument_anthropic(client, rec)
    with rec.run():
        assert client.messages.create(model="m", messages=[{"role": "user", "content": "hi"}]) is response
    assert rec.failures > 0 or _of_type(rec._sink.records, "llm_call")
    _verified_memory(rec._sink)


@pytest.mark.parametrize(
    "messages",
    [
        None,
        5,
        "text",
        [None],
        [5],
        ["x"],
        [{"role": 5, "content": 5}],
        [{"content": [None, 5, {"type": 5}]}],
        [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": [1]}]}],
        [{}],
        (m for m in [{"role": "user", "content": "x"}]),
    ],
    ids=lambda m: repr(m)[:20],
)
def test_odd_messages_do_not_break_the_call(messages):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _fake_anthropic("answer")
    instrument_anthropic(client, rec)
    with rec.run():
        assert client.messages.create(model="m", messages=messages) == "answer"
    _verified_memory(rec._sink)


def test_a_generator_of_messages_reaches_the_sdk_and_the_record():
    rec = Recorder(MemorySink(), agent_id="a")
    got = []

    class Messages:
        def create(self, **kwargs):
            got.extend(kwargs["messages"])
            return {}

    client = _namespace(messages=Messages())
    instrument_anthropic(client, rec)
    client.messages.create(model="m", messages=(m for m in [{"role": "user", "content": "x"}]))
    assert got == [{"role": "user", "content": "x"}]
    assert _of_type(rec._sink.records, "llm_call")[0]["context"][0]["content"] == "x"


def test_an_sdk_error_reaches_the_agent_unchanged():
    rec = Recorder(MemorySink(), agent_id="a")
    failure = ValueError("no \ud83d")

    class Messages:
        def create(self, **kwargs):
            raise failure

    client = _namespace(messages=Messages())
    instrument_anthropic(client, rec)
    with pytest.raises(ValueError) as caught:
        client.messages.create(model="m", messages=[])
    assert caught.value is failure
    assert _of_type(rec._sink.records, "llm_call")[0]["status"] == "error"


def test_an_sdk_error_that_cannot_be_printed_is_the_one_the_agent_sees():
    rec = Recorder(MemorySink(), agent_id="a")

    class Messages:
        def create(self, **kwargs):
            raise BrokenMessage()

    client = _namespace(messages=Messages())
    instrument_anthropic(client, rec)
    with pytest.raises(BrokenMessage):
        client.messages.create(model="m", messages=[])


def _stream_client(result_stream):
    class Manager:
        def __enter__(self):
            return result_stream

        def __exit__(self, *exc):
            return False

    class Messages:
        def create(self, **kwargs):
            return {}

        def stream(self, **kwargs):
            return Manager()

    return _namespace(messages=Messages())


class SnapshotRaises:
    @property
    def current_message_snapshot(self):
        raise Boom("snapshot")


@pytest.mark.parametrize(
    "stream",
    [
        SnapshotRaises(),
        _namespace(),
        _namespace(current_message_snapshot=object()),
        _namespace(current_message_snapshot={"content": "x"}),
    ],
    ids=["raises", "missing", "object", "text_content"],
)
def test_an_odd_stream_is_handed_over_and_closed_quietly(stream):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _stream_client(stream)
    instrument_anthropic(client, rec)
    with client.messages.stream(model="m", messages=[{"role": "user", "content": "x"}]) as got:
        assert got is stream
    _verified_memory(rec._sink)


def test_an_error_inside_a_stream_reaches_the_agent():
    rec = Recorder(MemorySink(), agent_id="a")
    client = _stream_client(SnapshotRaises())
    instrument_anthropic(client, rec)
    with pytest.raises(ValueError, match="mine"):
        with client.messages.stream(model="m", messages=[]):
            raise ValueError("mine")
    assert _of_type(rec._sink.records, "llm_call")[0]["status"] == "error"


def test_an_error_in_a_stream_that_cannot_be_printed_is_the_one_the_agent_sees():
    rec = Recorder(MemorySink(), agent_id="a")
    client = _stream_client(SnapshotRaises())
    instrument_anthropic(client, rec)
    with pytest.raises(BrokenMessage):
        with client.messages.stream(model="m", messages=[]):
            raise BrokenMessage()


ODD_OPENAI_RESPONSES = {
    "none": None,
    "int": 5,
    "text": "text",
    "object": object(),
    "magic_mock": mock.MagicMock(),
    "attribute_raises": AttrRaises(),
    "property_raises": PropertyRaises(),
    "choices_is_text": {"choices": "abc"},
    "choices_holds_none": {"choices": [None]},
    "choice_has_no_message": {"choices": [{}]},
    "message_is_text": {"choices": [{"message": "hello"}]},
    "tool_calls_is_text": {"choices": [{"message": {"tool_calls": "abc"}}]},
    "tool_call_has_no_function": {"choices": [{"message": {"tool_calls": [{}]}}]},
    "function_is_text": {"choices": [{"message": {"tool_calls": [{"function": "abc"}]}}]},
    "arguments_are_not_json": {
        "choices": [{"message": {"tool_calls": [{"id": "1", "function": {"name": "t", "arguments": "{oops"}}]}}]
    },
    "arguments_hold_nan": {
        "choices": [{"message": {"tool_calls": [{"id": "1", "function": {"name": "t", "arguments": '{"a": NaN}'}}]}}]
    },
    "usage_is_text": {"choices": [], "usage": "lots"},
    "usage_is_huge": {"choices": [], "usage": {"prompt_tokens": 2**70}},
    "surrogates": {"choices": [{"message": {"content": "\ud83d"}, "finish_reason": "\udc00"}], "id": "\ud83d"},
}


def _fake_openai(result):
    class Completions:
        def create(self, **kwargs):
            return result

    class Responses:
        def create(self, **kwargs):
            return result

    return _namespace(chat=_namespace(completions=Completions()), responses=Responses())


@pytest.mark.parametrize("response", ODD_OPENAI_RESPONSES.values(), ids=ODD_OPENAI_RESPONSES.keys())
def test_an_odd_openai_response_reaches_the_agent_unchanged(response):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _fake_openai(response)
    instrument_openai(client, rec)
    with rec.run():
        assert client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}]) is response
        assert client.responses.create(model="m", input="hi") is response
    assert rec.failures > 0 or _of_type(rec._sink.records, "llm_call")
    _verified_memory(rec._sink)


@pytest.mark.parametrize("arguments", ["[" * 200_000, "9" * 5000], ids=["nested_too_deep", "number_too_long"])
@pytest.mark.parametrize("api", ["chat", "responses"])
def test_model_chosen_arguments_cannot_remove_the_record_of_the_call(api, arguments):
    rec = Recorder(MemorySink(), agent_id="a")
    if api == "chat":
        response = {
            "choices": [{"message": {"tool_calls": [{"id": "1", "function": {"name": "t", "arguments": arguments}}]}}]
        }
    else:
        response = {"output": [{"type": "function_call", "call_id": "1", "name": "t", "arguments": arguments}]}
    client = _fake_openai(response)
    instrument_openai(client, rec)
    with rec.run():
        if api == "chat":
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        else:
            client.responses.create(model="m", input="hi")
    (call,) = _of_type(rec._sink.records, "llm_call")
    assert call["tool_calls"][0]["name"] == "t"


@pytest.mark.parametrize(
    "given",
    [
        None,
        5,
        [None],
        [5],
        ["x"],
        [{"role": 5}],
        [{"role": "assistant", "tool_calls": "abc"}],
        [{"role": "assistant", "tool_calls": [5]}],
        [{"role": "tool", "tool_call_id": [1], "content": b"x"}],
        [{}],
    ],
    ids=lambda m: repr(m)[:20],
)
def test_odd_openai_messages_do_not_break_the_call(given):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _fake_openai("answer")
    instrument_openai(client, rec)
    with rec.run():
        assert client.chat.completions.create(model="m", messages=given) == "answer"
    _verified_memory(rec._sink)


@pytest.mark.parametrize(
    "given",
    [
        None,
        5,
        [None],
        [5],
        ["x"],
        [{}],
        [{"type": 5}],
        [{"type": "function_call"}],
        [{"type": "function_call_output", "call_id": [1]}],
        "\ud83d",
        b"x",
    ],
    ids=lambda m: repr(m)[:20],
)
def test_odd_openai_input_does_not_break_the_call(given):
    rec = Recorder(MemorySink(), agent_id="a")
    client = _fake_openai("answer")
    instrument_openai(client, rec)
    with rec.run():
        assert client.responses.create(model="m", input=given) == "answer"
    _verified_memory(rec._sink)


def _real_sdk_call(rec, raw):
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")

    def handler(request):
        return httpx2.Response(200, content=raw, headers={"content-type": "application/json"})

    client = anthropic.Anthropic(
        api_key="test", max_retries=0, http_client=httpx2.Client(transport=httpx2.MockTransport(handler))
    )
    if rec is not None:
        instrument_anthropic(client, rec)
    try:
        return repr(client.messages.create(model="m", max_tokens=1, messages=[{"role": "user", "content": "x"}])), None
    except Exception as exc:
        return None, type(exc)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b"[1,2]",
        b'"text"',
        b'{"content":"text"}',
        b'{"content":[{"type":"tool_use"}]}',
        b'{"content":[{"type":"text","text":"\\ud83d"}],"id":"\\ud83d"}',
        b'{"content":[],"usage":{"input_tokens":1e400}}',
        b'{"content":[],"usage":{"input_tokens":"many"},"model":5,"stop_reason":[]}',
        b'{"content":[{"type":"never_seen","x":{"y":1}}]}',
        b'{"content":[{"type":"tool_use","id":1,"name":2,"input":3}]}',
    ],
    ids=lambda r: r[:24].decode(),
)
def test_the_real_sdk_with_odd_bodies_gives_the_agent_what_it_would_get_anyway(raw):
    rec = Recorder(MemorySink(), agent_id="a")
    with rec.run():
        seen = _real_sdk_call(rec, raw)
    assert seen == _real_sdk_call(None, raw)
    assert rec.failures > 0 or _of_type(rec._sink.records, "llm_call")
    _verified_memory(rec._sink)


def test_a_retried_checkpoint_is_the_identical_request(tmp_path):
    """A signing service repeats only an identical request: if its answer is lost, the retry must not differ."""
    from mnestiq.signers import LocalSigner, SignerError

    class LosesFirstAnswer(LocalSigner):
        def __init__(self, key):
            super().__init__(key)
            self.payloads = []

        def sign(self, payload):
            self.payloads.append(payload)
            if len(self.payloads) == 1:
                raise SignerError("the answer was lost")
            return super().sign(payload)

    signer = LosesFirstAnswer(generate_private_key())
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a", signer=signer, checkpoint_every=1000)
    with rec.run(run_id="r") as run:
        run.note("one")
    for _ in range(2):
        with contextlib.suppress(Exception):
            rec.checkpoint()
    rec.close()
    assert len(signer.payloads) >= 2 and signer.payloads[0] == signer.payloads[1]
