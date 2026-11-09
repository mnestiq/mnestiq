"""Hostile input on the surfaces that face other programs: the signing service and its client, the model
API proxy, and the recorder opening a file it did not just write.

What every test holds to: nothing ends in an unhandled exception, one bad client cannot stop another,
the service refuses what its docstring says it refuses, the proxy passes on what it was given and is
honest about what it could not read, and a damaged evidence file is refused."""

import base64
import contextlib
import copy
import gzip
import http.client
import json
import os
import re
import shutil
import socket
import struct
import sys
import threading
import time
import tracemalloc
import zlib
from datetime import datetime, timedelta, timezone
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Listener
from types import SimpleNamespace

import pytest

from mnestiq import (FileSink, MemorySink, Recorder, RecorderError, SignerClient, SignerError, signer_service,
                     verify_file)
from mnestiq.canonical import canonical_json
from mnestiq.hashing import GENESIS_HASH, digest_bytes, record_hash
from mnestiq.keys import generate_private_key, key_id, public_key_b64
from mnestiq.merkle import merkle_root
from mnestiq.proxy import ModelProxy
from mnestiq.proxy.formats import EventStream
from mnestiq.proxy.server import _Capture
from mnestiq.recorder import Run
from mnestiq.signer_service import MAX_REQUEST, SignerServer, SignerService, init_signer
from mnestiq.sinks import SinkError

from conftest import dump, load, record_demo
from proxy_fake import FakeProvider, Reply, _anthropic_events, _chat_events, _responses_events

DEEP = b"[" * 200_000
WRONG = (1.5, "0", [], {}, None, True, [1, "x"], 5, {"a": 1})


def _wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.002)
    return predicate()


def _paths(obj, path=()):
    """Every place in a JSON value, as a tuple of keys and indexes."""
    if path:
        yield path
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, (*path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, (*path, i))


def _with(obj, path, value):
    """A copy of ``obj`` with the place at ``path`` replaced."""
    out = copy.deepcopy(obj)
    parent = out
    for step in path[:-1]:
        parent = parent[step]
    parent[path[-1]] = value
    return out


def _name(path):
    return ".".join(map(str, path))


def _label(value):
    return _name(value) if isinstance(value, tuple) else str(value)


# The signing service


def _wall(offset=0.0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _cp(svc, chain="c", seq=2, first=0, last=1, root="sha256:" + "ab" * 32, wall=None, **extra):
    record = {"spec_version": "1.0", "kind": "checkpoint", "chain_id": chain, "seq": seq,
              "ts": {"wall": wall or _wall(), "mono_us": 1}, "prev_hash": GENESIS_HASH,
              "covers": {"from_seq": first, "to_seq": last}, "merkle_root": root,
              "sig_alg": svc.signer.sig_alg, "public_key": svc.signer.public_key, "key_id": svc.key_id}
    record.update(extra)
    return record


def _ask(svc, record, leaves=None):
    payload = record if isinstance(record, bytes) else canonical_json(record)
    request = {"op": "sign", "payload": base64.b64encode(payload).decode("ascii")}
    if leaves is not None:
        request["leaves"] = leaves
    return svc.handle(request)


def _signed(reply):
    return isinstance(reply, dict) and "signature" in reply and "error" not in reply


def _refused(reply):
    return isinstance(reply, dict) and "signature" not in reply and bool(reply.get("error"))


def _log(svc):
    path = svc.dir / "signatures.jsonl"
    return path.read_text("utf-8").splitlines() if path.exists() else []


@pytest.fixture(scope="module")
def signer_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("signer") / "template"
    init_signer(directory)  # starts PowerShell on Windows, so once per module and copied after
    return directory


@pytest.fixture
def svc(signer_template, tmp_path):
    shutil.copytree(signer_template, tmp_path / "signer")
    return SignerService(tmp_path / "signer")


def _b64(data):
    return base64.b64encode(data).decode("ascii")


BAD_REQUESTS = {
    "null": None, "number": 5, "text": "sign", "list": [], "true": True,
    "no_op": {}, "op_null": {"op": None}, "op_number": {"op": 5}, "op_list": {"op": ["sign"]}, "op_dict": {"op": {}},
    "op_case": {"op": "SIGN"}, "op_space": {"op": "sign "}, "op_long": {"op": "x" * 100_000},
    "no_payload": {"op": "sign"}, "payload_null": {"op": "sign", "payload": None},
    "payload_number": {"op": "sign", "payload": 5}, "payload_list": {"op": "sign", "payload": []},
    "payload_dict": {"op": "sign", "payload": {"a": 1}},
    "payload_not_base64": {"op": "sign", "payload": "%%%"},
    "payload_non_ascii": {"op": "sign", "payload": "é"},
    "payload_wrong_padding": {"op": "sign", "payload": "e30"},
    "payload_empty": {"op": "sign", "payload": ""},
    "payload_garbage": {"op": "sign", "payload": _b64(os.urandom(64))},
    "payload_invalid_utf8": {"op": "sign", "payload": _b64(b'{"kind":"checkpoint\xff"}')},
    "payload_list_json": {"op": "sign", "payload": _b64(b"[]")},
    "payload_null_json": {"op": "sign", "payload": _b64(b"null")},
    "payload_number_json": {"op": "sign", "payload": _b64(b"1")},
    "payload_empty_object": {"op": "sign", "payload": _b64(b"{}")},
    "payload_duplicate_key": {"op": "sign", "payload": _b64(b'{"kind":"event","kind":"checkpoint"}')},
    "payload_nan": {"op": "sign", "payload": _b64(b'{"kind":"checkpoint","seq":NaN}')},
    "payload_huge_int": {"op": "sign", "payload": _b64(b'{"kind":"checkpoint","seq":' + b"9" * 5000 + b"}")},
    "payload_lone_surrogate": {"op": "sign", "payload": _b64(b'{"kind":"checkpoint","chain_id":"\\ud800"}')},
    "bare_checkpoint": {"op": "sign", "payload": _b64(b'{"kind":"checkpoint"}')},
}


@pytest.mark.parametrize("name", BAD_REQUESTS)
def test_a_request_of_any_shape_is_refused(svc, name):
    assert _refused(svc.handle(BAD_REQUESTS[name]))
    assert _log(svc) == []


@pytest.mark.parametrize("leaves", [5, "x", {"a": 1}, [1], [None], ["x", 2], True, 1.5])
def test_leaves_of_the_wrong_type_are_refused(svc, leaves):
    assert _refused(_ask(svc, _cp(svc), leaves=leaves))
    assert _log(svc) == []


def test_a_checkpoint_nested_too_deep_is_refused(svc):
    assert _refused(svc.handle({"op": "sign", "payload": _b64(DEEP)}))
    assert _log(svc) == []


def _nested(depth):
    return b"[" * depth + b"]" * depth


def test_a_checkpoint_as_deep_as_the_parser_allows_is_refused(svc):
    payload = b'{"kind":"checkpoint","x":' + _nested(900) + b"}"
    assert _refused(svc.handle({"op": "sign", "payload": _b64(payload)}))
    assert _log(svc) == []


def test_a_checkpoint_not_in_canonical_form_is_refused(svc):
    assert _refused(_ask(svc, json.dumps(_cp(svc), indent=1).encode()))
    assert _refused(_ask(svc, canonical_json(_cp(svc)) + b" "))
    assert _refused(_ask(svc, b" " + canonical_json(_cp(svc))))
    assert _log(svc) == []


@pytest.mark.parametrize("field", ["kind", "chain_id", "seq", "covers", "sig_alg", "public_key", "key_id"])
@pytest.mark.parametrize("bad", WRONG, ids=repr)
def test_a_checkpoint_field_of_the_wrong_type_is_refused(svc, field, bad):
    if field == "chain_id" and isinstance(bad, str):
        pytest.skip("any text is a chain name")
    assert _refused(_ask(svc, _cp(svc, **{field: bad})))
    assert _log(svc) == [] and not (svc.dir / "state.json").exists()


@pytest.mark.parametrize("field", [("covers", "from_seq"), ("covers", "to_seq"), ("ts", "wall")], ids=_name)
@pytest.mark.parametrize("bad", WRONG, ids=repr)
def test_a_nested_checkpoint_field_of_the_wrong_type_is_refused(svc, field, bad):
    assert _refused(_ask(svc, _with(_cp(svc), field, bad)))
    assert _log(svc) == []


@pytest.mark.parametrize("bad", [None, [], {}, 0, "", {"a": 1}], ids=repr)
def test_a_time_that_is_empty_is_refused(svc, bad):
    assert _refused(_ask(svc, _cp(svc, ts=bad)))


@pytest.mark.parametrize("bad", [1.5, "0", True, [1, "x"], 5], ids=repr)
def test_a_time_that_is_not_an_object_is_refused(svc, bad):
    assert _refused(_ask(svc, _cp(svc, ts=bad)))
    assert _log(svc) == []


@pytest.mark.parametrize("wall", ["", "yesterday", "2026-13-45T00:00:00.000000Z", "2026-01-01T00:00:00Z",
                                  "2026-01-01T00:00:00.000000+00:00", "0000-01-01T00:00:00.000000Z",
                                  "9999-99-99T99:99:99.999999Z", "1" * 10_000])
def test_a_time_that_is_not_rfc3339_is_refused(svc, wall):
    assert _refused(_ask(svc, _cp(svc, ts={"wall": wall, "mono_us": 1})))


@pytest.mark.parametrize("offset", [-301, 301, -86_400, 86_400 * 365])
def test_a_time_far_from_the_clock_is_refused(svc, offset):
    assert _refused(_ask(svc, _cp(svc, wall=_wall(offset))))
    assert _log(svc) == []


@pytest.mark.parametrize("wall", ["0001-01-01T00:00:00.000000Z", "9999-12-31T23:59:59.999999Z"])
def test_the_ends_of_the_calendar_are_refused(svc, wall):
    assert _refused(_ask(svc, _cp(svc, wall=wall)))


@pytest.mark.parametrize("kind", ["event", "Checkpoint", "checkpoint ", "", "heartbeat"])
def test_only_checkpoints_are_signed(svc, kind):
    assert _refused(_ask(svc, _cp(svc, kind=kind)))
    assert _log(svc) == []


@pytest.mark.parametrize("field", ["sig_alg", "public_key", "key_id"])
def test_a_checkpoint_naming_another_key_is_refused(svc, field):
    other = generate_private_key()
    value = {"sig_alg": "p256", "public_key": public_key_b64(other), "key_id": key_id(public_key_b64(other))}[field]
    assert _refused(_ask(svc, _cp(svc, **{field: value})))


@pytest.mark.parametrize(("seq", "first", "last"), [(1, 0, 1), (3, 0, 1), (0, 0, -1), (-1, 0, -2), (2, 5, 1),
                                                     (2, -1, 1),
                                                     (9_007_199_254_740_991, 0, 1)])
def test_a_range_that_does_not_lead_to_the_checkpoint_is_refused(svc, seq, first, last):
    assert _refused(_ask(svc, _cp(svc, seq=seq, first=first, last=last)))


@pytest.mark.parametrize("payload", [b'{"kind":"checkpoint","seq":9007199254740993,"covers":{"from_seq":0,"to_seq":1}}',
                                     b'{"kind":"checkpoint","seq":2.0,"covers":{"from_seq":0,"to_seq":1}}',
                                     b'{"kind":"checkpoint","seq":2e0,"covers":{"from_seq":0,"to_seq":1}}'])
def test_numbers_that_only_look_like_positions_are_refused(svc, payload):
    assert _refused(_ask(svc, payload))


def _chain(svc, chain="c"):
    """Two checkpoints in a row: 0..1 at seq 2, then 3..4 at seq 5."""
    first = _cp(svc, chain=chain)
    second = _cp(svc, chain=chain, seq=5, first=3, last=4, root="sha256:" + "cd" * 32)
    assert _signed(_ask(svc, first)) and _signed(_ask(svc, second))
    return first, second


def test_history_is_never_signed_again(svc):
    first, _ = _chain(svc)
    logged = len(_log(svc))
    rewritten = dict(first, merkle_root="sha256:" + "ee" * 32)
    # The old checkpoint itself, the old range with other records, and every position behind the head.
    for attempt in (first, rewritten, _cp(svc, seq=1, first=0, last=0), _cp(svc, seq=3, first=0, last=2),
                    _cp(svc, seq=4, first=3, last=3), _cp(svc, seq=5, first=0, last=4)):
        assert _refused(_ask(svc, attempt)), attempt
    assert len(_log(svc)) == logged
    assert _signed(_ask(svc, _cp(svc, seq=8, first=6, last=7, root="sha256:" + "aa" * 32)))  # the chain goes on


def test_a_chain_cannot_skip_forward(svc):
    _chain(svc)
    assert _refused(_ask(svc, _cp(svc, seq=20, first=19, last=19)))
    assert _refused(_ask(svc, _cp(svc, seq=20, first=7, last=19)))


def test_the_same_range_with_other_records_is_refused_after_a_restart(svc):
    _, second = _chain(svc)
    fresh = SignerService(svc.dir)
    assert _refused(_ask(fresh, dict(second, merkle_root="sha256:" + "ee" * 32)))
    assert _signed(_ask(fresh, second))  # the same records again, for an answer that was lost


@pytest.mark.parametrize("change", ["next_key", "prev_hash"])
def test_a_repeat_may_only_repeat_what_was_signed(svc, change):
    """A lost answer is asked for again. The same position with a key hand-over added is not that repeat:
    it is a new statement about a checkpoint already signed, and threat-model.md says old checkpoints are
    not signed again."""
    _, second = _chain(svc)
    attacker = public_key_b64(generate_private_key())
    values = {"next_key": {"sig_alg": "ed25519", "public_key": attacker, "key_id": key_id(attacker)},
              "prev_hash": "sha256:" + "ee" * 32}
    assert _refused(_ask(svc, dict(second, **{change: values[change]})))


def test_a_repeat_with_a_new_time_is_not_a_repeat(svc):
    """A repeat is only ever the identical request: a new time would be a second statement about the position."""
    _, second = _chain(svc)
    assert _refused(_ask(svc, dict(second, ts={"wall": _wall(1), "mono_us": 2})))


def test_a_state_written_before_repeats_were_exact_does_not_allow_one(svc):
    _, second = _chain(svc)
    state = json.loads((svc.dir / "state.json").read_text("utf-8"))
    del state["c"]["request"]
    (svc.dir / "state.json").write_text(json.dumps(state), "utf-8")
    assert _refused(_ask(SignerService(svc.dir), second))


def test_a_lost_answer_is_made_good_by_the_next_checkpoint(served, tmp_path):
    """The recorder stamps each try with its own time, so its retry is not a repeat. The records written
    since then let the next checkpoint extend the one whose answer was lost, and no record stays unsigned."""
    client = SignerClient(served.server.address, served.token.decode())
    real, lost = client.sign, []

    def loses_the_first_answer(payload, leaves=None):
        signature = real(payload, leaves)
        if not lost:
            lost.append(payload)
            raise SignerError("the answer never arrived")
        return signature

    client.sign = loses_the_first_answer
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2, retry_after=0)
    for i in range(5):
        rec.append_event({"event_type": "note", "run_id": "r", "agent_id": "a", "attributes": {"i": i}})
    rec.close()
    client.close()
    assert lost and verify_file(path, [served.svc.signer.public_key]).ok
    assert load(path)[-1]["kind"] == "checkpoint"


@pytest.mark.parametrize("bad", [None, 5, "", "junk", [], {}, "sha256:zz"], ids=repr)
def test_a_checkpoint_with_no_usable_root_is_refused(svc, bad):
    record = _cp(svc)
    if bad is None:
        del record["merkle_root"]
    else:
        record["merkle_root"] = bad
    assert _refused(_ask(svc, record))
    assert _log(svc) == []


def test_chains_are_kept_apart(svc):
    _chain(svc, "one")
    assert _signed(_ask(svc, _cp(svc, chain="two")))  # a position taken in one chain is free in another
    assert _refused(_ask(svc, _cp(svc, chain="one")))


def _extension(svc, leaves, signed_root, signed_leaves=2):
    """A signed checkpoint that never reached the file, and the longer one that replaces it."""
    digests = [digest_bytes(h) for h in leaves]
    assert _signed(_ask(svc, _cp(svc, seq=signed_leaves, first=0, last=signed_leaves - 1, root=signed_root)))
    return _cp(svc, seq=len(leaves), first=0, last=len(leaves) - 1, root="sha256:" + merkle_root(digests).hex())


def _leaves(n):
    return ["sha256:" + f"{i:02x}" * 32 for i in range(n)]


def test_an_honest_extension_is_signed(svc):
    leaves = _leaves(4)
    root = "sha256:" + merkle_root([digest_bytes(h) for h in leaves[:2]]).hex()
    assert _signed(_ask(svc, _extension(svc, leaves, root), leaves=leaves))


@pytest.mark.parametrize("bad", [[], ["sha256:zz"], ["nope"] * 4, ["sha256:" + "00" * 4] * 4, ["md5:" + "00" * 16] * 4,
                                 _leaves(3), _leaves(5), [""] * 4], ids=lambda v: str(len(v)) + repr(v[:1]))
def test_an_extension_with_leaves_that_do_not_fit_is_refused(svc, bad):
    leaves = _leaves(4)
    root = "sha256:" + merkle_root([digest_bytes(h) for h in leaves[:2]]).hex()
    extension = _extension(svc, leaves, root)
    logged = len(_log(svc))
    assert _refused(_ask(svc, extension, leaves=bad))
    assert len(_log(svc)) == logged


def test_an_extension_cannot_change_the_records_already_signed(svc):
    leaves = _leaves(4)
    root = "sha256:" + merkle_root([digest_bytes(h) for h in leaves[:2]]).hex()
    extension = _extension(svc, leaves, root)
    changed = ["sha256:" + "ff" * 32, *leaves[1:]]
    extension["merkle_root"] = "sha256:" + merkle_root([digest_bytes(h) for h in changed]).hex()
    assert _refused(_ask(svc, extension, leaves=changed))


def test_an_extension_that_starts_somewhere_else_is_refused(svc):
    leaves = _leaves(4)
    root = "sha256:" + merkle_root([digest_bytes(h) for h in leaves[:2]]).hex()
    assert _signed(_ask(svc, _cp(svc, seq=2, first=0, last=1, root=root)))
    moved = _cp(svc, seq=5, first=1, last=4, root="sha256:" + merkle_root([digest_bytes(h) for h in leaves]).hex())
    assert _refused(_ask(svc, moved, leaves=leaves))


def test_an_extension_of_a_chain_never_signed_needs_no_proof_but_moves_the_state(svc):
    # A first checkpoint may start anywhere: that is limit 3 in the threat model. It must still move
    # the state, so the same position cannot be signed twice with other records.
    assert _signed(_ask(svc, _cp(svc, chain="fresh", seq=11, first=10, last=10)))
    assert _refused(_ask(svc, _cp(svc, chain="fresh", seq=11, first=10, last=10, root="sha256:" + "11" * 32)))


def test_every_signature_is_logged_and_no_refusal_is(svc):
    first, second = _chain(svc)
    _ask(svc, first)
    assert _signed(_ask(svc, second))  # a repeat is a signature too
    entries = [json.loads(line) for line in _log(svc)]
    assert [e["seq"] for e in entries] == [2, 5, 5]
    assert all(e["key_id"] == svc.key_id and e["signature"] for e in entries)


def test_racing_clients_get_one_signature_for_one_position(svc):
    replies = []
    barrier = threading.Barrier(8)

    def attempt(n):
        barrier.wait()
        replies.append(_ask(svc, _cp(svc, root="sha256:" + f"{n:02x}" * 32)))

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(_signed(r) for r in replies) == 1 and len(_log(svc)) == 1


@pytest.mark.parametrize("state", [b"[]", b"5", b"null", b'"x"', b'{"c": 5}', b'{"c": {}}', b'{"c": {"seq": "x"}}',
                                   b'{"c": {"seq": null}}', b'{"c": []}'])
def test_a_damaged_state_file_refuses_and_never_signs(svc, state):
    (svc.dir / "state.json").write_bytes(state)
    try:
        fresh = SignerService(svc.dir)
    except (ValueError, SignerError):
        return  # refusing to start is a clear answer
    assert _refused(_ask(fresh, _cp(fresh, first=9, last=9, seq=10)))


@pytest.mark.parametrize("state", [b"", b"{", b"\xff\xfe", b"{}x"])
def test_a_state_file_that_is_not_json_stops_the_service_from_starting(svc, state):
    (svc.dir / "state.json").write_bytes(state)
    with pytest.raises(ValueError):
        SignerService(svc.dir)


@pytest.mark.parametrize("blocked", ["signatures.jsonl", "state.json.tmp"])
def test_a_disk_that_cannot_be_written_gets_a_refusal_and_no_signature(svc, blocked):
    (svc.dir / blocked).mkdir()  # opening a folder as a file fails the way a full or read-only disk does
    record = _cp(svc)
    assert _refused(_ask(svc, record))
    assert _refused(_ask(svc, record))  # asked again, it is still not a repeat of anything handed out


# The service on its socket


@pytest.fixture
def served(svc, monkeypatch):
    """A running service, watching for what kills a connection's thread."""
    crashes, count = [], {"started": 0, "finished": 0}
    real = SignerServer._serve

    def watched(self, conn):
        count["started"] += 1
        try:
            real(self, conn)
        except BaseException as exc:  # what escaped is what is being tested for
            crashes.append(exc)
        finally:
            count["finished"] += 1

    monkeypatch.setattr(SignerServer, "_serve", watched)
    server = svc.start("127.0.0.1:0")
    host, port = server.address.split(":")
    yield SimpleNamespace(svc=svc, server=server, addr=(host, int(port)), token=svc.token, crashes=crashes, count=count)
    server.close()


def _authed(s):
    return Client(s.addr, authkey=s.token)


def _still_serving(s):
    """A good client gets a good answer, and no connection's thread died on the way."""
    conn = _authed(s)
    conn.send_bytes(json.dumps({"op": "public_key"}).encode())
    assert conn.poll(5)
    assert json.loads(conn.recv_bytes())["key_id"] == s.svc.key_id
    conn.close()
    assert _wait_for(lambda: s.count["started"] == s.count["finished"])
    assert s.crashes == []


FRAMES = {"empty": b"", "binary": b"\xff\xfe\x00", "truncated": b'{"op":', "null": b"null", "list": b"[]",
          "number": b"5", "nan": b'{"op":NaN}', "huge_int": b'{"op":' + b"9" * 5000 + b"}",
          "lone_surrogate": b'{"op":"\\ud800"}', "unknown_op": b'{"op":"x"}',
          "bad_payload": b'{"op":"sign","payload":"%"}'}


@pytest.mark.parametrize("name", FRAMES)
def test_a_bad_frame_gets_an_answer_and_the_connection_keeps_working(served, name):
    conn = _authed(served)
    conn.send_bytes(FRAMES[name])
    assert conn.poll(5) and "error" in json.loads(conn.recv_bytes())
    conn.send_bytes(json.dumps({"op": "public_key"}).encode())
    assert conn.poll(5) and "key_id" in json.loads(conn.recv_bytes())
    conn.close()
    _still_serving(served)


def _answer_or_hang_up(conn):
    try:
        if conn.poll(5):
            return json.loads(conn.recv_bytes())
    except (EOFError, OSError):
        pass
    return None


def _killer_frames(svc):
    """Frames that today end their connection's thread. Each is sent by the two tests below."""
    return {"deep_request": DEEP,
            "deep_checkpoint": json.dumps({"op": "sign", "payload": _b64(DEEP)}).encode(),
            "time_of_the_wrong_type": json.dumps({"op": "sign",
                                                  "payload": _b64(canonical_json(_cp(svc, ts=5)))}).encode()}


KILLER_FRAMES = ("deep_request", "deep_checkpoint", "time_of_the_wrong_type")


@pytest.mark.parametrize("name", KILLER_FRAMES)
def test_a_frame_that_cannot_be_read_gets_an_answer(served, name):
    conn = _authed(served)
    conn.send_bytes(_killer_frames(served.svc)[name])
    assert isinstance(_answer_or_hang_up(conn), dict)
    conn.close()
    _still_serving(served)


@pytest.mark.parametrize("name", KILLER_FRAMES)
def test_a_frame_that_ends_its_connection_does_not_stop_another_client(served, name):
    """What the tests above leave open: the bad client is lost, and the next one must still be answered."""
    conn = _authed(served)
    conn.send_bytes(_killer_frames(served.svc)[name])
    _answer_or_hang_up(conn)
    conn.close()
    other = _authed(served)
    other.send_bytes(json.dumps({"op": "public_key"}).encode())
    assert other.poll(5) and json.loads(other.recv_bytes())["key_id"] == served.svc.key_id
    other.close()


def test_a_client_that_leaves_before_its_answer_does_no_harm(served):
    conn = _authed(served)
    conn.send_bytes(json.dumps({"op": "sign", "payload": _b64(canonical_json(_cp(served.svc)))}).encode())
    conn.close()
    _still_serving(served)


def test_a_frame_over_the_limit_ends_that_connection_only(served):
    conn = _authed(served)
    with contextlib.suppress(OSError):  # on Linux the service's hang-up can reach the sender before it has finished
        conn.send_bytes(b"x" * (MAX_REQUEST + 1))
    assert _answer_or_hang_up(conn) is None
    conn.close()
    _still_serving(served)


@pytest.mark.parametrize("header", [struct.pack("!i", -5), struct.pack("!i", -1) + struct.pack("!Q", 1 << 40),
                                    struct.pack("!i", -1) + struct.pack("!Q", 10), struct.pack("!i", 1 << 30),
                                    b"\x00\x00",
                                    struct.pack("!i", 100)], ids=lambda b: b.hex())
def test_a_broken_frame_header_ends_that_connection_only(served, header):
    conn = _authed(served)
    conn._send(header)
    time.sleep(0.01)
    conn.close()
    _still_serving(served)


PRE_AUTH = {"hang_up": None, "partial": b"\x00\x00", "negative": struct.pack("!i", -5),
            "too_long": struct.pack("!i", 300) + b"x" * 300, "empty": struct.pack("!i", 0),
            "bad_digest": struct.pack("!i", 8) + b"{bad}xxx", "non_ascii_digest": struct.pack("!i", 8) + b"{\xff}xxxx",
            "no_brace": struct.pack("!i", 8) + b"{sha256x", "short_mac": struct.pack("!i", 11) + b"{sha256}abc",
            "wrong_md5": struct.pack("!i", 20) + b"\x00" * 20,
            "wrong_sha256": struct.pack("!i", 40) + b"{sha256}" + b"\x00" * 32,
            "sign_request": None}
SIGN_FRAME = b'{"op":"sign","payload":"e30="}'
PRE_AUTH["sign_request"] = struct.pack("!i", len(SIGN_FRAME)) + SIGN_FRAME


@pytest.mark.parametrize("name", PRE_AUTH)
def test_anything_before_the_token_is_proven_goes_nowhere(served, name):
    sock = socket.create_connection(served.addr, timeout=5)
    if PRE_AUTH[name] is not None:
        sock.recv(4096)
        sock.sendall(PRE_AUTH[name])
    sock.close()
    _still_serving(served)
    assert _log(served.svc) == []


def test_a_wrong_token_gets_nothing_signed(served):
    with pytest.raises((AuthenticationError, EOFError, OSError)):
        Client(served.addr, authkey=b"0" * 64)
    with pytest.raises(SignerError, match="did not accept the token"):
        SignerClient(served.server.address, "0" * 64, timeout=2)
    _still_serving(served)
    assert _log(served.svc) == []


def test_a_client_that_says_nothing_is_cut_off_before_the_token(served, monkeypatch):
    monkeypatch.setattr(signer_service, "HANDSHAKE_SECONDS", 0.1)
    sock = socket.create_connection(served.addr, timeout=5)
    with contextlib.closing(sock):
        sock.recv(4096)  # the challenge, which is never answered
        with contextlib.suppress(ConnectionError):
            assert sock.recv(4096) == b""
    _still_serving(served)


def test_silent_clients_do_not_stop_a_good_one(served):
    quiet_unproven = socket.create_connection(served.addr, timeout=5)
    quiet_proven = _authed(served)
    half = _authed(served)
    half._send(struct.pack("!i", 1000))  # says a frame is coming and never sends it
    try:
        conn = _authed(served)
        conn.send_bytes(json.dumps({"op": "public_key"}).encode())
        assert conn.poll(5) and "key_id" in json.loads(conn.recv_bytes())
        conn.close()
    finally:
        quiet_unproven.close()
        quiet_proven.close()
        half.close()
    _still_serving(served)


def test_many_bad_clients_at_once_leave_the_service_running(served):
    def bad(n):
        with contextlib.suppress(OSError, EOFError, AuthenticationError):
            if n % 2:
                sock = socket.create_connection(served.addr, timeout=5)
                sock.sendall(b"\x00" * n)
                sock.close()
            else:
                conn = _authed(served)
                conn.send_bytes(b"nonsense")
                conn.close()

    threads = [threading.Thread(target=bad, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _still_serving(served)


def test_a_good_client_signs_after_a_bad_one(served, tmp_path):
    served.svc.handle(None)
    with contextlib.suppress(EOFError, OSError):
        bad = _authed(served)
        bad.send_bytes(b"\xff")
        bad.close()
    client = SignerClient(served.server.address, served.token.decode())
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signer=client, checkpoint_every=2)
    for i in range(4):
        rec.append_event({"event_type": "note", "run_id": "r", "agent_id": "a", "attributes": {"i": i}})
    rec.close()
    client.close()
    assert rec.failures == 0 and verify_file(path, [served.svc.signer.public_key]).ok


# The client, against a service that lies or breaks


class HostileSigner:
    """Proves the token as a real service does, then answers from a script. None hangs up."""

    def __init__(self, token, replies):
        self.replies, self.count = list(replies), 0
        self.listener = Listener(("127.0.0.1", 0), authkey=token)
        self.address = "{}:{}".format(*self.listener.address)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn = self.listener.accept()
            except (OSError, EOFError, AuthenticationError):
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with contextlib.closing(conn):
            while True:
                try:
                    conn.recv_bytes()
                except (EOFError, OSError):
                    return
                reply = self.replies[min(self.count, len(self.replies) - 1)]
                self.count += 1
                if reply is None:
                    return
                if callable(reply):
                    reply(conn)
                else:
                    conn.send_bytes(reply)

    def close(self):
        self.listener.close()


@pytest.fixture
def hostile():
    made = []

    def make(replies):
        made.append(HostileSigner(b"t" * 64, replies))
        return made[-1]

    yield make
    for signer in made:
        signer.close()


GOOD_KEY = generate_private_key()
GOOD_INFO = json.dumps({"sig_alg": "ed25519", "public_key": public_key_b64(GOOD_KEY),
                        "key_id": key_id(public_key_b64(GOOD_KEY))}).encode()
BAD_INFO = {"not_json": b"not json", "invalid_utf8": b"\xff\xfe", "deep": DEEP, "missing_fields": b"{}",
            "no_public_key": b'{"sig_alg":"ed25519"}', "no_alg": b'{"public_key":"x"}',
            "unknown_alg": b'{"sig_alg":"rot13","public_key":"x"}',
            "null": b"null", "list": b"[]", "number": b"5", "error": b'{"error":"no"}', "empty_frame": b"",
            "hang_up": None, "too_large": b"x" * ((1 << 20) + 1)}
BAD_SIGNATURES = {"not_json": b"not json", "invalid_utf8": b"\xff\xfe", "deep": DEEP, "missing": b"{}",
                  "null": b'{"signature":null}', "number": b'{"signature":5}', "list": b'{"signature":[1]}',
                  "error": b'{"error":"no"}', "empty_error": b'{"error":""}', "not_a_dict": b"[]", "hang_up": None,
                  "non_ascii": '{"signature":"é"}'.encode()}


@pytest.mark.parametrize("name", BAD_INFO)
def test_a_signer_that_answers_nonsense_is_a_signer_error(hostile, name):
    signer = hostile([BAD_INFO[name]])
    with pytest.raises(SignerError):
        SignerClient(signer.address, "t" * 64, timeout=2).close()


@pytest.mark.parametrize("name", BAD_SIGNATURES)
def test_a_signature_that_makes_no_sense_is_a_signer_error(hostile, name):
    signer = hostile([GOOD_INFO, BAD_SIGNATURES[name]])
    client = SignerClient(signer.address, "t" * 64, timeout=2)
    with pytest.raises(SignerError):
        client.sign(b"{}")
    client.close()


def test_a_signer_that_goes_silent_is_given_up_on(hostile):
    signer = hostile([GOOD_INFO, lambda conn: None])  # takes the request and never answers
    client = SignerClient(signer.address, "t" * 64, timeout=0.1)
    with pytest.raises(SignerError, match="not reachable"):
        client.sign(b"{}")
    client.close()


def _sign_in_a_thread(client, wait):
    """True if the call returned within ``wait`` seconds, by any exit."""
    def attempt():
        with contextlib.suppress(Exception):
            client.sign(b"{}")

    thread = threading.Thread(target=attempt, daemon=True)
    thread.start()
    thread.join(wait)
    return not thread.is_alive()


def test_a_signer_that_stops_in_the_middle_of_a_frame_is_given_up_on(hostile):
    """The first bytes of the answer arrive, and the rest never does."""
    signer = hostile([GOOD_INFO, lambda conn: conn._send(struct.pack("!i", 1000) + b"xx")])
    client = SignerClient(signer.address, "t" * 64, timeout=0.1)
    assert _sign_in_a_thread(client, 1.0)


def test_a_signer_with_a_key_that_is_not_one_writes_no_checkpoint(hostile):
    info = json.dumps({"sig_alg": "ed25519", "public_key": "not a key", "key_id": "x"}).encode()
    client = SignerClient(hostile([info]).address, "t" * 64, timeout=2)
    rec = Recorder(MemorySink(), agent_id="a", signer=client, checkpoint_every=1, retry_after=0)
    with rec.run() as run:
        assert run.note("working") is not None  # the agent carries on
    assert rec.failures >= 1 and all(r["kind"] == "event" for r in rec._sink.records)
    client.close()


@pytest.mark.parametrize("name", [*BAD_SIGNATURES, "junk_base64", "wrong_length", "right_length_wrong_bytes"])
def test_the_recorder_writes_no_checkpoint_from_a_lying_signer(hostile, name):
    extra = {"junk_base64": b'{"signature":"!!!"}', "wrong_length": b'{"signature":"AAAA"}',
             "right_length_wrong_bytes": json.dumps({"signature": _b64(b"\0" * 64)}).encode()}
    signer = hostile([GOOD_INFO, {**BAD_SIGNATURES, **extra}[name]])
    client = SignerClient(signer.address, "t" * 64, timeout=2)
    rec = Recorder(MemorySink(), agent_id="a", signer=client, checkpoint_every=1, retry_after=0)
    with rec.run() as run:
        assert run.note("working") is not None  # the agent carries on
    assert rec.failures >= 1 and all(r["kind"] == "event" for r in rec._sink.records)
    client.close()


# The recorder opening a file it did not just write


def _open(path, key, **kw):
    """Open as a restarted agent would. Returns the recorder, or None if it refused."""
    sink = None
    try:
        sink = FileSink(path)
        return Recorder(sink, agent_id="a", signing_key=key, **kw)
    except (RecorderError, SinkError):
        if sink is not None:
            sink.close()
        return None
    except BaseException:
        if sink is not None:
            sink.close()
        raise


def _relink(records, start=0):
    """Fix every hash from ``start`` on, as someone rewriting the file would."""
    prev = records[start - 1]["record_hash"] if start else records[0]["prev_hash"]
    for r in records[start:]:
        r["prev_hash"] = prev
        r["record_hash"] = record_hash(r)
        prev = r["record_hash"]
    return records


@pytest.fixture
def tail(tmp_path, key):
    """A file with a checkpoint at index 4 and three unsigned records after it, as after a crash."""
    path = record_demo(tmp_path / "e.jsonl", key, close=False)
    assert [r["kind"] for r in load(path)] == ["event"] * 4 + ["checkpoint"] + ["event"] * 3
    return path


@pytest.fixture
def closed(tmp_path, key):
    """A closed file: its last record is a checkpoint."""
    path = record_demo(tmp_path / "e.jsonl", key)
    assert load(path)[-1]["kind"] == "checkpoint"
    return path


def test_an_intact_file_resumes_and_verifies(tail, key, pub):
    rec = _open(tail, key)
    assert rec is not None
    with rec.run() as run:
        run.note("back")
    rec.close()
    assert verify_file(tail, [pub]).ok and rec.failures == 0


def _bytes_of(path):
    return path.read_bytes().splitlines(keepends=True)


LINES = {"garbage": b"not json\n", "binary": b"\x00\xff\xfe\n", "nul_line": b"\x00" * 40 + b"\n",
         "deep": DEEP + b"\n", "nan": b'{"chain_id":"c","seq":0,"record_hash":NaN}\n',
         "duplicate_key": b'{"chain_id":"c","chain_id":"d","seq":0,"record_hash":"x"}\n',
         "huge_int": b'{"seq":' + b"9" * 5000 + b"}\n", "number": b"5\n", "list": b"[]\n", "text": b'"x"\n',
         "null": b"null\n", "true": b"true\n", "empty_object": b"{}\n", "not_a_record": b'{"a":1}\n',
         "half_a_record": b'{"chain_id":"c","seq":0}\n', "invalid_utf8": b'{"chain_id":"\xff"}\n'}


@pytest.mark.parametrize("position", ["first", "middle", "last"])
@pytest.mark.parametrize("name", tuple(LINES))
def test_a_line_that_is_not_a_record_is_refused(tail, key, name, position):
    lines = _bytes_of(tail)
    at = {"first": 0, "middle": 3, "last": len(lines)}[position]
    tail.write_bytes(b"".join([*lines[:at], LINES[name], *lines[at:]]))
    assert _open(tail, key) is None


@pytest.mark.parametrize("name", ["garbage", "number", "half_a_record"])
def test_a_refusal_leaves_the_file_as_it_was(tail, key, name):
    tail.write_bytes(tail.read_bytes() + LINES[name])
    before = tail.read_bytes()
    assert _open(tail, key) is None
    assert tail.read_bytes() == before


def test_a_folder_in_the_place_of_the_file_is_refused(tmp_path, key):
    assert _open(tmp_path, key) is None


@pytest.mark.parametrize("name", ["empty", "only_newlines", "only_spaces"])
def test_a_file_with_nothing_in_it_starts_a_new_chain(tmp_path, key, name):
    path = tmp_path / "e.jsonl"
    path.write_bytes({"empty": b"", "only_newlines": b"\n\n\n", "only_spaces": b"   \n  \t\n"}[name])
    rec = _open(path, key)
    assert rec is not None and rec._seq == 0
    rec.close()


@pytest.mark.parametrize("name", ["utf16", "utf8_bom", "crlf", "blank_lines", "whole_file_on_one_line"])
def test_the_same_records_in_another_encoding_give_a_refusal_or_a_working_recorder(tail, key, name):
    data = tail.read_bytes()
    tail.write_bytes({"utf16": data.decode().encode("utf-16"), "utf8_bom": b"\xef\xbb\xbf" + data,
                      "crlf": data.replace(b"\n", b"\r\n"), "blank_lines": data.replace(b"\n", b"\n\n"),
                      "whole_file_on_one_line": data.replace(b"\n", b" ")}[name])
    rec = _open(tail, key)
    if rec is not None:
        rec.close()


@pytest.mark.parametrize("torn", [b'{"chain_id":"c","se', b"\xff\xfe\x00", b"[" * 100, b'{"a":', b"\x00" * 4096,
                                  b'{"x":"' + b"a" * 200_000], ids=lambda b: f"{b[:6]!r}x{len(b)}")
def test_a_torn_last_line_is_set_aside_and_noted(tail, key, pub, torn):
    data = tail.read_bytes()
    tail.write_bytes(data + torn)
    rec = _open(tail, key)
    assert rec is not None
    rec.close()
    sidecars = list(tail.parent.glob("e.jsonl.torn-*"))
    assert len(sidecars) == 1 and sidecars[0].read_bytes() == torn
    assert verify_file(tail, [pub]).ok
    assert any(r.get("attributes", {}).get("message") == "recovered from an interrupted write" for r in load(tail))


def test_a_torn_last_line_nested_too_deep_is_set_aside_or_refused(tail, key):
    tail.write_bytes(tail.read_bytes() + DEEP)
    rec = _open(tail, key)
    if rec is not None:
        rec.close()


def test_a_whole_last_record_without_its_newline_carries_on(tail, key, pub):
    tail.write_bytes(tail.read_bytes().rstrip(b"\n"))
    rec = _open(tail, key)
    assert rec is not None
    with rec.run() as run:
        run.note("back")
    rec.close()
    assert verify_file(tail, [pub]).ok and list(tail.parent.glob("e.jsonl.torn-*")) == []


def test_a_file_with_no_newline_at_all_is_refused_and_left_alone(tail, key):
    """A write is torn inside one record. Cutting several away as a crash would start a clean chain over damage."""
    original = tail.read_bytes().replace(b"\n", b" ")
    tail.write_bytes(original)
    assert _open(tail, key) is None
    assert tail.read_bytes() == original and list(tail.parent.glob("e.jsonl.torn-*")) == []


@pytest.mark.parametrize("tail_line", [b"5", b"null", b"[]", b'"x"', b'{"a":1}'])
def test_a_last_line_without_a_newline_that_is_not_a_record_is_refused(tail, key, tail_line):
    tail.write_bytes(tail.read_bytes() + tail_line)
    assert _open(tail, key) is None


def test_a_memory_sink_with_a_foreign_value_is_refused(key):
    sink = MemorySink()
    sink.records = [5]
    with pytest.raises(RecorderError):
        Recorder(sink, agent_id="a", signing_key=key)


def test_the_wrong_chain_name_is_refused_clearly(tail, key):
    sink = FileSink(tail)
    with pytest.raises(ValueError, match="already holds chain"):
        Recorder(sink, agent_id="a", signing_key=key, chain_id="other")
    sink.close()


def test_a_file_signed_by_another_key_is_refused(closed):
    assert _open(closed, generate_private_key()) is None


@pytest.mark.parametrize("field", ["agent_id", "run_id", "event_type", "status"])
@pytest.mark.parametrize("index", [0, 2, 5, 7])  # before the checkpoint, and in the unsigned part
def test_a_changed_record_is_refused(tail, key, index, field):
    records = load(tail)
    records[index][field] = "changed"
    dump(tail, records)
    assert _open(tail, key) is None


@pytest.mark.parametrize("index", [0, 5])
def test_a_record_with_a_broken_chain_link_is_refused(tail, key, index):
    records = load(tail)
    records[index]["prev_hash"] = "sha256:" + "ab" * 32
    records[index]["record_hash"] = record_hash(records[index])
    dump(tail, records)
    assert _open(tail, key) is None


def _content_slot(records):
    return next(i for i in range(5, len(records)) if isinstance(records[i].get("tool_calls"), list))


def test_a_changed_value_under_its_digest_in_the_unsigned_part_is_refused(tail, key):
    """Record hashes leave out redactable values and cover their digests, so a value changed while the agent
    was down keeps the same record_hash. The next checkpoint would vouch for that record."""
    records = load(tail)
    at = _content_slot(records)
    field = "result" if "result" in records[at]["tool_calls"][0] else "arguments"
    records[at]["tool_calls"][0][field] = {"status": "nothing happened"}
    dump(tail, records)
    assert _open(tail, key) is None


CRAFTED_LAST_EVENT = [("seq", "x"), ("seq", None), ("seq", 1.5), ("seq", True), ("seq", []), ("seq", {}), ("seq", -5),
                      ("seq", 1 << 53), ("seq", 99), ("chain_id", 5), ("chain_id", None), ("chain_id", []),
                      ("chain_id", {}), ("chain_id", ""), ("chain_id", "x" * 200), ("chain_id", "another-chain"),
                      ("kind", 5), ("kind", []), ("kind", None), ("kind", "Checkpoint"), ("spec_version", 5),
                      ("ts", 5), ("agent_id", 5), ("event_type", 5)]


@pytest.mark.parametrize(("field", "bad"), CRAFTED_LAST_EVENT, ids=repr)
def test_a_crafted_last_event_with_good_hashes_is_refused(tail, key, field, bad):
    records = load(tail)
    records[-1][field] = bad
    with contextlib.suppress(ValueError):  # a value with no canonical form keeps the copied hash
        records[-1]["record_hash"] = record_hash(records[-1])
    tail.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records))
    assert _open(tail, key) is None


CRAFTED_CHECKPOINT = [("seq", "x"), ("seq", None), ("seq", 1.5), ("seq", True), ("seq", []), ("seq", -5), ("seq", 99),
                      ("chain_id", 5), ("chain_id", None), ("chain_id", []), ("chain_id", "another-chain"),
                      ("record_hash", 5), ("record_hash", None), ("record_hash", []), ("record_hash", "junk"),
                      ("prev_hash", 5), ("prev_hash", "sha256:" + "ab" * 32),
                      ("next_key", 5), ("next_key", "x"), ("next_key", [1]), ("next_key", True), ("next_key", {}),
                      ("key_id", 5), ("key_id", []), ("key_id", None), ("covers", 5), ("covers", None),
                      ("merkle_root", 5), ("merkle_root", "sha256:" + "ab" * 32), ("signature", "AAAA"),
                      ("signature", None), ("sig_alg", "rot13"), ("ts", 5)]


@pytest.mark.parametrize(("field", "bad"), CRAFTED_CHECKPOINT, ids=repr)
def test_a_crafted_last_checkpoint_is_refused(closed, key, field, bad):
    records = load(closed)
    records[-1][field] = bad
    dump(closed, records)
    assert _open(closed, key) is None


def test_a_record_deleted_from_the_unsigned_part_and_relinked_is_refused(tail, key):
    records = load(tail)
    del records[6]
    dump(tail, _relink(records, 6))
    assert _open(tail, key) is None


def test_a_record_deleted_before_a_checkpoint_is_refused(tail, key):
    records = load(tail)
    del records[3]
    dump(tail, records)
    assert _open(tail, key) is None


def test_a_record_added_to_the_unsigned_part_with_a_repeated_position_is_refused(tail, key):
    records = load(tail)
    records.insert(6, copy.deepcopy(records[5]))
    dump(tail, _relink(records, 6))
    assert _open(tail, key) is None


def test_a_file_that_starts_part_way_through_a_chain_is_refused(tail, key):
    records = load(tail)[5:]  # everything up to the checkpoint is gone, and the rest is relinked from nothing
    records[0]["prev_hash"] = GENESIS_HASH
    dump(tail, _relink(records))
    assert _open(tail, key) is None


def test_a_fake_checkpoint_cannot_stand_in_for_a_signature(tail, key):
    """Without this the unsigned records before it would never be signed, and nothing would say so."""
    records = load(tail)
    last = records[-1]
    fake = {"spec_version": last["spec_version"], "kind": "checkpoint", "chain_id": last["chain_id"],
            "seq": last["seq"] + 1, "ts": last["ts"], "prev_hash": last["record_hash"]}
    fake["record_hash"] = record_hash(fake)
    dump(tail, [*records, fake])
    assert _open(tail, key) is None


def test_taking_the_key_id_off_a_checkpoint_does_not_let_another_key_carry_on(closed):
    records = load(closed)
    for r in records:
        r.pop("key_id", None)
    dump(closed, records)
    assert _open(closed, generate_private_key()) is None


CRAFTED_FILES = {
    "deleted_and_relinked": lambda r: (r.pop(6), _relink(r, 6))[1],
    "repeated_position": lambda r: (r.insert(6, copy.deepcopy(r[5])), _relink(r, 6))[1],
    "changed_checkpoint_root": lambda r: (r[4].update(merkle_root="sha256:" + "ab" * 32), r)[1],
    "changed_checkpoint_signature": lambda r: (r[4].update(signature="AAAA"), r)[1],
    "another_chain_in_the_middle": lambda r: (r[6].update(chain_id="another"), _relink(r, 6))[1],
}


@pytest.mark.parametrize("name", CRAFTED_FILES)
def test_a_damaged_file_never_verifies_after_the_recorder_carries_on(tail, key, pub, name):
    """Whatever the recorder accepts, what it signs next must not make the damage disappear."""
    dump(tail, CRAFTED_FILES[name](load(tail)))
    assert not verify_file(tail, [pub]).ok
    try:
        rec = _open(tail, key)
    except Exception:  # the tests above hold the recorder to refusing cleanly
        return
    if rec is not None:
        with rec.run() as run:
            run.note("back")
        rec.close()
    assert not verify_file(tail, [pub]).ok


def test_a_changed_value_stays_visible_after_the_recorder_carries_on(tail, key, pub):
    records = load(tail)
    at = _content_slot(records)
    field = "result" if "result" in records[at]["tool_calls"][0] else "arguments"
    records[at]["tool_calls"][0][field] = {"status": "nothing happened"}
    dump(tail, records)
    rec = _open(tail, key)
    if rec is not None:
        rec.close()
    assert not verify_file(tail, [pub]).ok


# The proxy


class RawUpstream:
    """A provider that answers with exact bytes, however broken, then hangs up."""

    def __init__(self):
        self.replies = []
        self.seen = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with contextlib.closing(conn), contextlib.suppress(OSError):
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                piece = conn.recv(65536)
                if not piece:
                    return
                data += piece
            head, _, rest = data.partition(b"\r\n\r\n")
            found = re.search(rb"(?i)content-length:\s*(\d+)", head)
            need = int(found.group(1)) if found else 0
            while len(rest) < need:
                piece = conn.recv(65536)
                if not piece:
                    break
                rest += piece
            self.seen.append(rest)
            reply = self.replies.pop(0) if self.replies else _http(b"{}")
            if callable(reply):
                reply(conn)
            else:
                conn.sendall(reply)
            conn.shutdown(socket.SHUT_WR)

    def close(self):
        self.sock.close()


def _http(body, status=b"200 OK", ctype=b"application/json", headers=b""):
    return (b"HTTP/1.1 " + status + b"\r\nContent-Type: " + ctype + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n" + headers + b"\r\n" + body)


def _sse_response(data):
    return b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n" + data


def _sse(events):
    out = bytearray()
    for name, data in events:
        payload = data if isinstance(data, str) else json.dumps(data)
        out += ((f"event: {name}\n" if name else "") + "data: " + payload + "\n\n").encode()
    return bytes(out)


CHAT = ("/openai/v1/chat/completions", "/rawopenai/v1/chat/completions")
RESPONSES = ("/openai/v1/responses", "/rawopenai/v1/responses")
MESSAGES = ("/anthropic/v1/messages", "/rawanthropic/v1/messages")
ROUTES = {"chat": CHAT, "responses": RESPONSES, "messages": MESSAGES}
GOOD = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()


class Air:
    """The proxy shared by the tests below, and what one test expects of it."""

    def __init__(self, proxy, rec, path, pub, fake, raw):
        self.proxy, self.rec, self.path, self.pub, self.fake, self.raw = proxy, rec, path, pub, fake, raw
        self.crashes = []
        self.size = 0
        self.failures = 0
        proxy._server.handle_error = self._crashed

    def _crashed(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, OSError):  # a client hanging up is normal
            self.crashes.append(exc)

    def begin(self):
        self.fake.replies.clear()
        self.fake.seen.clear()
        self.raw.replies.clear()
        self.raw.seen.clear()
        self.crashes.clear()
        self.settle()
        self.size = self.path.stat().st_size
        self.failures = self.rec.failures

    def settle(self):
        with self.proxy._idle:  # woken at once: a sleep costs 15 ms on Windows, for each of thousands of calls
            assert self.proxy._idle.wait_for(lambda: self.proxy._busy == 0, 10), "the proxy never finished a call"

    def post(self, path, body=GOOD, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=10)
        try:
            conn.request("POST", path, body=body, headers=headers or {})
            response = conn.getresponse()
            try:
                data = response.read()
            except http.client.IncompleteRead as exc:
                data = exc.partial
            return response.status, data
        finally:
            conn.close()
            self.settle()

    def records(self, event_type="llm_call"):
        self.settle()
        with open(self.path, "rb") as fh:
            fh.seek(self.size)
            lines = fh.read().splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return [r for r in records if event_type is None or r.get("event_type") == event_type]

    def problems(self, calls=1):
        """What went wrong with the calls since ``begin``, in words."""
        found = []
        got = self.records()
        if len(got) != calls:
            found.append(f"{len(got)} model call record(s), expected {calls}")
        if self.rec.failures != self.failures:
            found.append(f"{self.rec.failures - self.failures} recording failure(s)")
        if self.crashes:
            found.append(f"crashed: {self.crashes[0]!r}")
        return found

    def alive(self):
        self.begin()
        status, data = self.post(CHAT[0])
        assert status == 200 and b"chat.completion" in data
        assert self.problems() == []


@pytest.fixture(scope="module")
def flight(tmp_path_factory):
    key = generate_private_key()
    path = tmp_path_factory.mktemp("proxy") / "evidence.jsonl"
    rec = Recorder(FileSink(path), agent_id="bot", signing_key=key, checkpoint_every=25)
    fake, raw = FakeProvider(), RawUpstream()
    proxy = ModelProxy(rec, upstreams=[f"openai={fake.url}", f"anthropic={fake.url}", f"rawopenai=openai:{raw.url}",
                                       f"rawanthropic=anthropic:{raw.url}"], listen="127.0.0.1:0",
                       client_timeout=1.0, upstream_timeout=3.0)
    proxy.start()
    yield Air(proxy, rec, path, public_key_b64(key), fake, raw)
    proxy.close()
    rec.close()
    raw.close()
    fake.close()


@pytest.fixture
def air(flight):
    flight.begin()
    return flight


_PLAIN = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
BODIES = {"empty": b"", "not_json": b"not json", "binary": b"\xff\xfe\x00bad", "list": b"[]", "number": b"5",
          "text": b'"x"', "null": b"null", "true": b"true", "truncated": b'{"model":"m","messages":[{', "deep": DEEP,
          "deep_inside": b'{"model":"m","x":' + DEEP + b"}", "nan": b'{"model":"m","temperature":NaN}',
          "infinity": b'{"model":"m","temperature":Infinity}', "overflow": b'{"model":"m","temperature":1e999}',
          "big_int": b'{"model":"m","seed":' + b"9" * 30 + b"}",
          "huge_int": b'{"model":"m","seed":' + b"9" * 5000 + b"}",
          "duplicate_keys": b'{"model":"a","model":"b"}', "lone_surrogate": b'{"model":"\\ud800","x":"\\udfff"}',
          "bom": b"\xef\xbb\xbf" + GOOD, "utf16": GOOD.decode().encode("utf-16"), "nul": b'{"model":"\x00"}',
          "control": b'{"model":"m\\u0000"}', "empty_object": b"{}",
          "long_model": b'{"model":"' + b"m" * 100_000 + b'"}',
          "many_keys": b"{" + b",".join(b'"k%d":1' % i for i in range(2000)) + b"}"}


@pytest.mark.parametrize("api", ROUTES)
@pytest.mark.parametrize("name", BODIES)
def test_a_hostile_request_body_is_passed_on_unchanged_and_recorded(air, api, name):
    status, _ = air.post(ROUTES[api][0], BODIES[name])
    assert status == 200 and air.fake.seen[-1].body == BODIES[name]
    assert air.problems() == []


REQUESTS = {
    "chat": {"model": "m", "temperature": 0.5, "messages": [
        {"role": "system", "content": "s"},
        {"role": "assistant", "content": None,
         "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "t1", "content": "r"}]},
    "responses": {"model": "m", "instructions": "s", "previous_response_id": "r0", "input": [
        {"role": "user", "content": "hi"}, {"type": "function_call", "call_id": "t1", "name": "f", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "t1", "output": "r"}]},
    "messages": {"model": "m", "max_tokens": 5, "system": "s", "messages": [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "f", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "r"}]}]},
}
REQUEST_FIELDS = [(api, path) for api, body in REQUESTS.items() for path in _paths(body)]


@pytest.mark.parametrize(("api", "where"), REQUEST_FIELDS, ids=_label)
def test_a_request_field_of_the_wrong_type_is_passed_on_and_recorded(air, api, where):
    problems = []
    for bad in WRONG:
        air.begin()
        body = json.dumps(_with(REQUESTS[api], where, bad)).encode()
        status, _ = air.post(ROUTES[api][0], body)
        if status != 200 or air.fake.seen[-1].body != body:
            problems.append((bad, "not passed on"))
        problems += [(bad, p) for p in air.problems()]
    assert problems == []


ANSWERS = {
    "chat": {"id": "c1", "model": "m", "choices": [{"index": 0, "finish_reason": "stop", "message": {
        "role": "assistant", "content": "hi",
        "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}}],
             "usage": {"prompt_tokens": 1, "completion_tokens": 2}},
    "responses": {"id": "r1", "model": "m", "status": "completed", "output": [
        {"type": "function_call", "call_id": "t1", "name": "f", "arguments": "{}"},
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}],
                  "usage": {"input_tokens": 1, "output_tokens": 2}},
    "messages": {"id": "m1", "model": "m", "stop_reason": "end_turn", "content": [
        {"type": "text", "text": "hi"}, {"type": "tool_use", "id": "t1", "name": "f", "input": {}}],
                 "usage": {"input_tokens": 1, "output_tokens": 2}},
}
ANSWER_FIELDS = [(api, path) for api, body in ANSWERS.items() for path in _paths(body)]


@pytest.mark.parametrize(("api", "where"), ANSWER_FIELDS, ids=_label)
def test_an_answer_field_of_the_wrong_type_reaches_the_agent_and_is_recorded(air, api, where):
    problems = []
    for bad in WRONG:
        air.begin()
        body = json.dumps(_with(ANSWERS[api], where, bad)).encode()
        air.raw.replies.append(_http(body))
        status, data = air.post(ROUTES[api][1])
        if status != 200 or data != body:
            problems.append((bad, "not passed on unchanged"))
        problems += [(bad, p) for p in air.problems()]
    assert problems == []


UNREADABLE_ANSWERS = {"not_json": b"not json", "html": b"<html>bad gateway</html>", "invalid_utf8": b'{"id":"\xff"}',
                      "truncated": b'{"id":"c1","choices":[{', "list": b"[]", "number": b"5", "null": b"null",
                      "empty_string": b'""', "deep": DEEP}


@pytest.mark.parametrize("api", ROUTES)
@pytest.mark.parametrize("name", UNREADABLE_ANSWERS)
def test_an_answer_that_cannot_be_read_reaches_the_agent_and_is_marked_not_captured(air, api, name):
    air.raw.replies.append(_http(UNREADABLE_ANSWERS[name]))
    status, data = air.post(ROUTES[api][1])
    assert status == 200 and data == UNREADABLE_ANSWERS[name]
    assert air.problems() == []
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False and "output" not in call


def test_an_empty_answer_is_marked_not_captured(air):
    air.raw.replies.append(_http(b""))
    assert air.post(CHAT[1]) == (200, b"")
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False


@pytest.mark.parametrize("name", ["duplicate_id", "duplicate_content"])
def test_an_answer_with_duplicate_keys_is_not_recorded_as_clean(air, name):
    """A JSON parser may keep the first of two equal keys or the last. The agent's parser and the record
    could then disagree about what the model said, the reason parse_json refuses these in evidence."""
    body = {"duplicate_id": b'{"id":"first","id":"second","model":"m","choices":[]}',
            "duplicate_content": b'{"id":"x","model":"m","choices":[{"index":0,"message":{"role":"assistant",'
                                 b'"content":"safe","content":"evil"},"finish_reason":"stop"}]}'}[name]
    air.raw.replies.append(_http(body))
    assert air.post(CHAT[1]) == (200, body)
    (call,) = air.records()
    assert call["attributes"].get("output_captured") is False


def test_a_request_with_duplicate_keys_is_not_recorded_as_clean(air):
    body = (b'{"model":"m","messages":[{"role":"user","content":"safe"}],'
            b'"messages":[{"role":"user","content":"evil"}]}')
    assert air.post(CHAT[0], body)[0] == 200 and air.fake.seen[-1].body == body
    (call,) = air.records()
    assert call["attributes"].get("request_understood") is False


@pytest.mark.parametrize("api", ROUTES)
@pytest.mark.parametrize("name", ["not_json", "list", "number", "truncated"])
def test_a_request_that_could_not_be_read_is_not_recorded_as_clean(air, api, name):
    """Not JSON, so the proxy holds only the bytes. The record keeps them or says it did not understand them."""
    body = {"not_json": b"SECRET WORDS", "list": b'["SECRET WORDS"]', "number": b"5",
            "truncated": b'{"model":"m","messages":[{"role":"user","content":"SECRET WORDS'}[name]
    assert air.post(ROUTES[api][0], body)[0] == 200
    (call,) = air.records()
    assert call["attributes"].get("request_understood") is False or "SECRET WORDS" in json.dumps(call["context"])


@pytest.mark.parametrize(("api", "field", "value"), [
    ("chat", "messages", "SECRET WORDS"), ("chat", "messages", ["SECRET WORDS"]),
    ("messages", "messages", "SECRET WORDS"), ("messages", "messages", ["SECRET WORDS"]),
])
def test_messages_of_the_wrong_shape_are_not_dropped_as_if_they_were_not_there(air, api, field, value):
    body = json.dumps({"model": "m", field: value}).encode()
    assert air.post(ROUTES[api][0], body)[0] == 200
    (call,) = air.records()
    assert call["attributes"].get("request_understood") is False or "SECRET WORDS" in json.dumps(call["context"])


def test_a_request_too_deep_for_the_record_is_marked_as_cut(air):
    nested: object = "bottom"
    for _ in range(200):
        nested = [nested]
    body = json.dumps({"model": "m", "messages": [{"role": "user", "content": nested}]}).encode()
    assert air.post(CHAT[0], body)[0] == 200
    assert air.problems() == []
    (call,) = air.records()
    assert "<max depth exceeded>" in json.dumps(call["context"])  # the record says it stopped reading


def test_a_request_as_deep_as_the_parser_allows_is_passed_on_and_recorded(air):
    body = b'{"model":"m","messages":[{"role":"user","content":' + _nested(900) + b"}]}"
    assert air.post(CHAT[0], body)[0] == 200 and air.fake.seen[-1].body == body
    assert air.problems() == []


def test_a_call_whose_record_is_refused_is_still_written_with_a_marker(air, monkeypatch):
    real, tries = Run.llm_call, []

    def refuses_the_first(self, **fields):
        tries.append(fields)
        return None if len(tries) == 1 else real(self, **fields)

    monkeypatch.setattr(Run, "llm_call", refuses_the_first)
    assert air.post(CHAT[0])[0] == 200
    (call,) = air.records()
    assert len(tries) == 2 and call["model"]["name"] == "m" and call["context"] == []
    assert call["attributes"]["request_understood"] is False and call["attributes"]["output_captured"] is False
    assert "could not be written" in call["attributes"]["capture_note"]


def test_a_stream_with_a_hole_keeps_what_was_read_and_says_so(air):
    events = STREAMS["chat"]
    stream = _sse([*events[:2], (None, "{broken"), *events[2:]])
    air.raw.replies.append(_sse_response(stream))
    assert air.post(CHAT[1], json.dumps({"model": "m", "stream": True}).encode()) == (200, stream)
    (call,) = air.records()
    assert call["output"]["content"]["content"] == "Hello there"
    assert call["attributes"]["output_captured"] is False and "could not be read" in call["attributes"]["capture_note"]


def test_a_huge_request_and_answer_pass_whole_and_the_record_says_what_it_left_out(air):
    big = "x" * (3 << 20)
    body = json.dumps({"model": "m", "messages": [{"role": "user", "content": big}]}).encode()
    answer = json.dumps(_with(ANSWERS["chat"], ("choices", 0, "message", "content"), big)).encode()
    air.raw.replies.append(_http(answer))
    assert air.post(CHAT[1], body) == (200, answer) and air.raw.seen[-1] == body
    assert air.problems() == []
    (call,) = air.records()
    assert len(call["x-omitted"]) == 2 and big not in json.dumps(call)


def test_an_answer_as_deep_as_the_parser_allows_is_recorded(air):
    depth = 900
    body = b'{"id":"x","model":"m","choices":[{"index":0,"finish_reason":"stop",' \
           b'"message":{"role":"assistant","content":' \
           + b"[" * depth + b"]" * depth + b"}}]}"
    air.raw.replies.append(_http(body))
    assert air.post(CHAT[1]) == (200, body)
    assert air.problems() == []


def test_an_error_answer_as_deep_as_the_parser_allows_is_recorded(air):
    depth = 900
    body = b'{"error":{"message":' + b"[" * depth + b"]" * depth + b"}}"
    air.raw.replies.append(_http(body, status=b"500 Oops"))
    assert air.post(CHAT[1]) == (500, body)
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error"


@pytest.mark.parametrize("status", [b"400 X", b"404 X", b"429 X", b"500 X", b"503 X", b"599 X", b"999 X"])
@pytest.mark.parametrize("body", [b"not json", b"[]", b"{}", b'{"error":5}', b'{"error":null}',
                                  b'{"error":{"message":[1]}}',
                                  b'{"error":"\\ud800"}'], ids=repr)
def test_an_error_status_of_any_shape_is_passed_on_and_recorded_as_an_error(air, status, body):
    air.raw.replies.append(_http(body, status=status))
    assert air.post(CHAT[1]) == (int(status.split()[0]), body)
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error" and call["attributes"]["output_captured"] is False


WIRE = {
    "nothing": b"", "bad_status_line": b"NOT HTTP\r\n\r\n", "http_0_9": b"hello there",
    "status_too_low": b"HTTP/1.1 99 X\r\n\r\n", "status_too_high": b"HTTP/1.1 1000 X\r\n\r\n",
    "status_not_a_number": b"HTTP/1.1 abc X\r\n\r\n",
    "too_many_headers": b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-%d: 1\r\n" % i for i in range(200)) + b"\r\n",
    "header_too_long": b"HTTP/1.1 200 OK\r\nX: " + b"a" * 70_000 + b"\r\n\r\n",
}


@pytest.mark.parametrize("name", WIRE)
def test_a_provider_that_breaks_http_gives_the_agent_an_error_and_is_recorded(air, name):
    air.raw.replies.append(WIRE[name])
    status, _ = air.post(CHAT[1])
    assert status == 502
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error" and "could not be reached" in call["error"]
    air.alive()


@pytest.mark.parametrize("head", [b"HTTP/1.1 200", b"HTTP/1.1 200 OK\r\nContent-Type: appl"], ids=["status", "headers"])
def test_a_head_cut_short_reads_as_an_empty_answer_and_is_marked_not_captured(air, head):
    """http.client cannot tell these from a provider that hung up after an empty answer, so the agent gets
    the 200 it would get from that provider. The record must not claim to have read anything."""
    air.raw.replies.append(head)
    assert air.post(CHAT[1]) == (200, b"")
    assert air.problems() == []
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False
    air.alive()


def _hang(first=b""):
    """A reply that sends ``first`` and then goes quiet until the proxy gives up."""
    def reply(conn):
        conn.sendall(first)
        with contextlib.suppress(OSError):
            conn.recv(1)
    return reply


@pytest.mark.parametrize("first", [b"", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{"],
                         ids=["before_the_head", "in_the_body"])
def test_a_provider_that_goes_silent_is_given_up_on_and_recorded(tmp_path, first):
    raw = RawUpstream()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"rawopenai=openai:{raw.url}"], listen="127.0.0.1:0", upstream_timeout=0.2)
    proxy.start()
    raw.replies.append(_hang(first))
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request("POST", CHAT[1], body=GOOD)
    with contextlib.suppress(http.client.HTTPException, OSError):
        conn.getresponse().read()
    conn.close()
    proxy.close()
    rec.close()
    raw.close()
    (call,) = [r for r in load(path) if r.get("event_type") == "llm_call"]
    assert call["status"] == "error" and rec.failures == 0


BROKEN_BODIES = {
    "chunk_size_not_hex": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
    "chunk_cut": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc",
    "chunk_never_ends": b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n',
    "chunk_size_line_too_long": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1" * 70_000 + b"\r\n",
    "shorter_than_announced": b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{}",
}


@pytest.mark.parametrize("name", BROKEN_BODIES)
def test_a_body_broken_off_is_recorded_as_an_error_and_not_as_clean(air, name):
    air.raw.replies.append(BROKEN_BODIES[name])
    air.post(CHAT[1])
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error" and "broke off" in call["error"]
    assert "output" not in call or call["output"].get("content") in (None, {})
    air.alive()


ODD_BODIES = {
    "length_not_a_number": b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\nConnection: close\r\n\r\n{}",
    "length_negative": b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\nConnection: close\r\n\r\n{}",
    "two_lengths": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{}",
    "length_and_chunked": b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nTransfer-Encoding: chunked\r\n\r\n"
                          b"2\r\n{}\r\n0\r\n\r\n",
    "no_length_at_all": b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}",
    "http_1_0": b"HTTP/1.0 200 OK\r\n\r\n{}",
    "no_content": b"HTTP/1.1 204 No Content\r\n\r\n",
    "not_modified_with_a_body": b"HTTP/1.1 304 Not Modified\r\n\r\nsurprise",
    "informational_first": b"HTTP/1.1 100 Continue\r\n\r\n"
                           b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    "odd_reason": b"HTTP/1.1 200 \xff\xfe\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    "binary_header": b"HTTP/1.1 200 OK\r\nX-Odd: \xff\x01\xfe\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    "bad_header_line": b"HTTP/1.1 200 OK\r\nno colon here\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    "connection_names_content_type": b"HTTP/1.1 200 OK\r\nContent-Type: a/b\r\nConnection: close, content-type\r\n"
                                     b"Content-Length: 2\r\n\r\n{}",
    "switching_protocols": b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\nsurprise",
    "two_encodings": b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n"
                     b"Connection: close\r\n\r\n{}",
}


@pytest.mark.parametrize("name", ODD_BODIES)
def test_an_odd_but_readable_answer_does_not_break_the_proxy(air, name):
    air.raw.replies.append(ODD_BODIES[name])
    conn = http.client.HTTPConnection("127.0.0.1", air.proxy.port, timeout=10)
    conn.request("POST", CHAT[1], body=GOOD)
    with contextlib.suppress(http.client.HTTPException, OSError):
        conn.getresponse().read()
    conn.close()
    assert air.problems() == []
    air.alive()


def test_a_binary_header_reaches_the_agent(air):
    air.raw.replies.append(b"HTTP/1.1 200 OK\r\nX-Odd: \xff\xfe\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
    conn = http.client.HTTPConnection("127.0.0.1", air.proxy.port, timeout=10)
    conn.request("POST", CHAT[1], body=GOOD)
    response = conn.getresponse()
    assert response.getheader("X-Odd") == "\xff\xfe" and response.read() == b"{}"
    conn.close()


_GOOD_ANSWER = json.dumps(ANSWERS["chat"]).encode()


def _deflate(data):
    return zlib.compress(data)


def _raw_deflate(data):
    packer = zlib.compressobj(wbits=-15)
    return packer.compress(data) + packer.flush()


READABLE_ENCODED = {"gzip": (b"gzip", gzip.compress), "deflate": (b"deflate", _deflate)}
UNREADABLE_ENCODED = {
    "gzip_garbage": (b"gzip", lambda d: b"this is not gzip at all"),
    "gzip_cut": (b"gzip", lambda d: gzip.compress(d)[:20]),
    "deflate_raw": (b"deflate", _raw_deflate),
    "deflate_garbage": (b"deflate", lambda d: b"\xff" * 40),
    "brotli_claimed": (b"br", lambda d: d),
    "stacked": (b"gzip, gzip", lambda d: gzip.compress(gzip.compress(d))),
    "unknown": (b"x-rot13", lambda d: d),
}


@pytest.mark.parametrize("name", READABLE_ENCODED)
def test_a_compressed_answer_is_passed_on_compressed_and_recorded(air, name):
    encoding, pack = READABLE_ENCODED[name]
    body = pack(_GOOD_ANSWER)
    air.raw.replies.append(_http(body, headers=b"Content-Encoding: " + encoding + b"\r\n"))
    assert air.post(CHAT[1]) == (200, body)
    (call,) = air.records()
    assert call["attributes"].get("output_captured") is not False and call["output"]["content"]["content"] == "hi"


@pytest.mark.parametrize("name", UNREADABLE_ENCODED)
def test_a_compressed_answer_that_cannot_be_read_is_passed_on_and_marked(air, name):
    encoding, pack = UNREADABLE_ENCODED[name]
    body = pack(_GOOD_ANSWER)
    air.raw.replies.append(_http(body, headers=b"Content-Encoding: " + encoding + b"\r\n"))
    assert air.post(CHAT[1]) == (200, body)
    assert air.problems() == []
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False and "output" not in call


def test_a_decompression_bomb_is_passed_on_and_not_kept(tmp_path):
    bomb = gzip.compress(b"\0" * (8 << 20))
    raw = RawUpstream()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"rawopenai=openai:{raw.url}"], listen="127.0.0.1:0", max_capture_bytes=1024)
    proxy.start()
    raw.replies.append(_http(bomb, headers=b"Content-Encoding: gzip\r\n"))
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request("POST", CHAT[1], body=GOOD)
    assert conn.getresponse().read() == bomb
    conn.close()
    proxy.close()
    rec.close()
    raw.close()
    (call,) = [r for r in load(path) if r.get("event_type") == "llm_call"]
    assert call["attributes"]["output_captured"] is False


@pytest.mark.parametrize("streaming", [False, True], ids=["answer", "stream"])
def test_a_decompression_bomb_does_not_fill_the_memory(streaming):
    bomb = gzip.compress(b"\0" * (32 << 20))
    capture = _Capture("chat", streaming, "gzip", 1024)
    tracemalloc.start()
    try:
        capture.feed(bomb)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 << 20  # the limit is 1 KiB, and it should not take 32 MiB to find that out


def test_an_answer_over_the_capture_limit_is_passed_on_and_marked(tmp_path):
    raw = RawUpstream()
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"rawopenai=openai:{raw.url}"], listen="127.0.0.1:0", max_capture_bytes=32)
    proxy.start()
    raw.replies.append(_http(_GOOD_ANSWER))
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request("POST", CHAT[1], body=GOOD)
    assert conn.getresponse().read() == _GOOD_ANSWER
    conn.close()
    proxy.close()
    rec.close()
    raw.close()
    (call,) = [r for r in load(path) if r.get("event_type") == "llm_call"]
    assert call["attributes"]["output_captured"] is False


# Streams


_STREAM_REPLY = Reply(text="Hello there", tool=("f", {"a": 1}), call_id="t1")
_STREAM_BODY = {"model": "m"}
STREAMS = {"chat": _chat_events(_STREAM_BODY, _STREAM_REPLY, 1),
           "responses": _responses_events(_STREAM_BODY, _STREAM_REPLY, 1),
           "messages": _anthropic_events(_STREAM_BODY, _STREAM_REPLY, 1)}


def _stream_fields():
    """One case for each distinct place in each API's events: the first event of that type that has it."""
    cases = []
    for api, events in STREAMS.items():
        seen = set()
        for i, (name, data) in enumerate(events):
            if not isinstance(data, dict):
                continue
            for path in _paths(data):
                if len(path) > 5:
                    continue
                label = (str(data.get("type") or name), tuple(p if isinstance(p, str) else "#" for p in path))
                if label not in seen:
                    seen.add(label)
                    cases.append((api, i, path))
    return cases


STREAM_WRONG = ("0", [1, "x"], {"a": 1}, None, True)  # one of each kind: there are many fields and each is a whole call

@pytest.mark.parametrize(("api", "index", "where"), _stream_fields(), ids=_label)
def test_a_stream_field_of_the_wrong_type_reaches_the_agent_and_is_recorded(air, api, index, where):
    problems = []
    events = STREAMS[api]
    for bad in STREAM_WRONG:
        air.begin()
        changed = [*events[:index], (events[index][0], _with(events[index][1], where, bad)), *events[index + 1:]]
        stream = _sse(changed)
        air.raw.replies.append(_sse_response(stream))
        status, data = air.post(ROUTES[api][1], json.dumps({"model": "m", "stream": True}).encode())
        if status != 200 or data != stream:
            problems.append((bad, "not passed on unchanged"))
        problems += [(bad, p) for p in air.problems()]
    assert problems == []


NOT_EVENTS = {"bad_json": "{broken", "null": "null", "number": "5", "text": '"x"', "list": "[]", "empty": "",
              "deep": "[" * 100_000 + "]" * 100_000}


@pytest.mark.parametrize("api", ROUTES)
@pytest.mark.parametrize("name", NOT_EVENTS)
def test_an_unreadable_event_reaches_the_agent_and_is_not_recorded_as_a_whole_answer(air, api, name):
    """An event in the middle could not be read, so what is rebuilt has a hole in it and must say so."""
    events = STREAMS[api]
    middle = len(events) // 2
    stream = _sse([*events[:middle], (events[middle][0], NOT_EVENTS[name]), *events[middle:]])
    air.raw.replies.append(_sse_response(stream))
    status, data = air.post(ROUTES[api][1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == stream
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error" or call["attributes"].get("output_captured") is False


STREAM_BYTES = {"no_final_blank_line": b"data: {}", "no_data_field": b"event: x\n\n",
                "comments_only": b": hi\n\n: there\n\n",
                "carriage_returns_only": b"data: {}\r\rdata: {}\r\r", "invalid_utf8": b"data: \xff\xfe\n\n",
                "nul": b"data: \x00\n\n", "field_without_colon": b"data\n\n",
                "huge_field_name": b"x" * 100_000 + b": 1\n\n",
                "empty": b""}


_STREAM_CASES = [(api, name) for api in ROUTES for name in STREAM_BYTES]


@pytest.mark.parametrize(("api", "name"), _STREAM_CASES)
def test_a_stream_that_is_not_one_reaches_the_agent_and_is_marked_not_captured(air, api, name):
    air.raw.replies.append(_sse_response(STREAM_BYTES[name]))
    status, data = air.post(ROUTES[api][1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == STREAM_BYTES[name]
    assert air.problems() == []
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False


@pytest.mark.parametrize("api", ROUTES)
def test_a_stream_cut_before_its_last_event_is_not_recorded_as_whole(air, api):
    """The provider hangs up politely, so only the missing last event shows the answer was not finished."""
    stream = _sse(STREAMS[api][:len(STREAMS[api]) // 2])
    air.raw.replies.append(_sse_response(stream))
    status, data = air.post(ROUTES[api][1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == stream
    assert air.problems() == []
    (call,) = air.records()
    assert call["status"] == "error" or call["attributes"].get("output_captured") is False


def test_an_event_with_duplicate_keys_is_not_recorded_as_clean(air):
    chunk = {"id": "c1", "model": "m", "choices": [{"index": 0, "delta": {"content": "evil"}}]}
    event = json.dumps(chunk).replace('"content": "evil"', '"content": "safe", "content": "evil"')
    stream = _sse([(None, event), (None, "[DONE]")])
    air.raw.replies.append(_sse_response(stream))
    status, data = air.post(CHAT[1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == stream
    (call,) = air.records()
    assert call["status"] == "error" or call["attributes"].get("output_captured") is False


def _sse_gzip(body):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n"
            + body)


def test_a_compressed_stream_reaches_the_agent_compressed_and_is_read(air):
    body = gzip.compress(_sse(STREAMS["chat"]))
    air.raw.replies.append(_sse_gzip(body))
    assert air.post(CHAT[1], json.dumps({"model": "m", "stream": True}).encode()) == (200, body)
    assert air.problems() == []
    (call,) = air.records()
    assert call["output"]["content"]["content"] == "Hello there"


def test_a_compressed_stream_that_cannot_be_read_reaches_the_agent_and_is_marked(air):
    air.raw.replies.append(_sse_gzip(b"this is not gzip at all"))
    status, data = air.post(CHAT[1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == b"this is not gzip at all"
    (call,) = air.records()
    assert call["attributes"]["output_captured"] is False


def test_an_event_over_the_size_limit_reaches_the_agent_and_is_not_recorded_as_whole(air, monkeypatch):
    monkeypatch.setattr(air.proxy, "client_timeout", 30.0)  # a busy machine can take over a second to read this much
    events = STREAMS["chat"]
    huge = b"data: " + b"x" * (EventStream.MAX_BUFFER + 1024) + b"\n\n"
    stream = _sse(events[:3]) + huge + _sse(events[3:])
    air.raw.replies.append(_sse_response(stream))
    status, data = air.post(CHAT[1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == stream
    (call,) = air.records()
    assert call["status"] == "error" or call["attributes"].get("output_captured") is False


def test_an_unfinished_tool_call_too_deep_to_read_is_still_recorded(air):
    """The stream ends inside a tool call whose arguments are nested past what a JSON parser can read."""
    start = {"id": "m1", "model": "m", "role": "assistant", "type": "message", "content": [], "usage": {}}
    stream = _sse([("message_start", {"type": "message_start", "message": start}),
                   ("content_block_start", {"type": "content_block_start", "index": 0,
                                            "content_block": {"type": "tool_use", "id": "t1", "name": "f",
                                                              "input": {}}}),
                   ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {
                       "type": "input_json_delta", "partial_json": "[" * 100_000}})])
    air.raw.replies.append(_sse_response(stream))
    status, data = air.post(MESSAGES[1], json.dumps({"model": "m", "stream": True}).encode())
    assert status == 200 and data == stream
    assert air.problems() == []


def test_a_stream_arriving_one_byte_at_a_time_is_read_the_same():
    stream = _sse(STREAMS["chat"]).replace(b"\n", b"\r\n")
    whole, trickled = _Capture("chat", True, "", 1 << 20), _Capture("chat", True, "", 1 << 20)
    whole.feed(stream)
    for i in range(len(stream)):
        trickled.feed(stream[i:i + 1])
    assert trickled.answer() == whole.answer() and whole.answer()["id"] == "chatcmpl-1"


# Hostile clients on the wire


def _exchange(air, data, wait=1.5):
    """Send exact bytes as a client, and read until the proxy hangs up or goes quiet."""
    sock = socket.create_connection(("127.0.0.1", air.proxy.port), timeout=wait)
    with contextlib.closing(sock):
        with contextlib.suppress(OSError):
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
        out = b""
        with contextlib.suppress(OSError):
            while piece := sock.recv(65536):
                out += piece
        return out


_POST = b"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\n"
CLIENTS = {
    "bad_request_line": b"GET /openai/v1/models HTTP/1.1 extra\r\n\r\n",
    "binary": b"\xff\xfe\x00\x01\r\n\r\n",
    "nothing_but_newlines": b"\r\n\r\n\r\n",
    "request_line_too_long": b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\n\r\n",
    "header_too_long": b"GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nX: " + b"a" * 70_000 + b"\r\n\r\n",
    "too_many_headers": b"GET /openai/v1/models HTTP/1.1\r\n" + b"".join(b"X-%d: 1\r\n" % i for i in range(200))
                        + b"\r\n",
    "future_http": b"GET /openai/v1/models HTTP/9.9\r\nHost: 127.0.0.1\r\n\r\n",
    "bad_version": b"GET /openai/v1/models HTTP/x.y\r\nHost: 127.0.0.1\r\n\r\n",
    "unknown_method": b"PROPFIND /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    "absolute_uri": b"GET http://evil.example/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    "asterisk": b"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    "no_host": b"GET /openai/v1/models HTTP/1.1\r\n\r\n",
    "broken_host": b"GET /openai/v1/models HTTP/1.1\r\nHost: [::1\r\n\r\n",
    "control_in_host": b"GET /openai/v1/models HTTP/1.1\r\nHost: localhost\x01\r\n\r\n",
    "non_ascii_path": b"GET /openai/v1/\xff\xfe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    "non_ascii_model_path": b"POST /openai/v1/\xff/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            b"Content-Length: 2\r\n\r\n{}",
    "folded_header": _POST + b"X-Fold: a\r\n b\r\nContent-Length: 2\r\n\r\n{}",
    "binary_header": _POST + b"X-Odd: \xff\x01\r\nContent-Length: 2\r\n\r\n{}",
    "length_not_a_number": _POST + b"Content-Length: abc\r\n\r\n{}",
    "length_negative": _POST + b"Content-Length: -1\r\n\r\n{}",
    "length_superscript": _POST + b"Content-Length: \xb2\r\n\r\n{}",
    "length_huge": _POST + b"Content-Length: " + b"9" * 5000 + b"\r\n\r\n{}",
    "length_too_big": _POST + b"Content-Length: 99999999999\r\n\r\n{}",
    "shorter_than_length": _POST + b"Content-Length: 100\r\n\r\n{}",
    "two_lengths": _POST + b"Content-Length: 2\r\nContent-Length: 500\r\n\r\n{}",
    "length_and_chunked": _POST + b"Content-Length: 500\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    "chunk_not_hex": _POST + b"Transfer-Encoding: chunked\r\n\r\nzz\r\n{}\r\n0\r\n\r\n",
    "chunk_cut": _POST + b"Transfer-Encoding: chunked\r\n\r\n10\r\nab",
    "chunk_no_end": _POST + b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n",
    "chunk_extension_long": _POST + b"Transfer-Encoding: chunked\r\n\r\n2;" + b"x" * 5000 + b"\r\n{}\r\n0\r\n\r\n",
    "too_many_trailers": _POST + b"Transfer-Encoding: chunked\r\n\r\n0\r\n" + b"X: 1\r\n" * 100 + b"\r\n",
    "expect_continue": _POST + b"Expect: 100-continue\r\nContent-Length: 2\r\n\r\n{}",
    "connection_names_auth": _POST + b"Connection: Authorization, Host\r\nAuthorization: x\r\n"
                             b"Content-Length: 2\r\n\r\n{}",
    "head_with_body": b"HEAD /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
    "http_1_0": b"POST /openai/v1/chat/completions HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
    "two_in_one_packet": _POST + b"Content-Length: 2\r\n\r\n{}" + _POST + b"Content-Length: 2\r\n\r\n{}",
}


def _is_an_answer(reply):
    """Nothing, an HTTP response, or the JSON error alone: a request line that cannot be read has no version
    yet, and the HTTP layer then answers as to HTTP/0.9, with no head."""
    if reply == b"" or reply.startswith(b"HTTP/1."):
        return True
    return json.loads(reply)["error"]["type"] == "mnestiq_proxy"


@pytest.mark.parametrize("name", CLIENTS)
def test_a_hostile_client_gets_an_answer_or_a_hang_up_and_the_proxy_goes_on(air, name):
    reply = _exchange(air, CLIENTS[name])
    assert _is_an_answer(reply), reply[:200]
    air.settle()
    assert air.crashes == [] and air.rec.failures == air.failures
    air.alive()


def test_the_answer_to_a_malformed_request_is_json_and_does_not_repeat_it(air):
    reply = _exchange(air, b"GET /x?key=SECRETWORD HTTP/1.1 extra\r\n\r\n")
    answer = json.loads(reply.split(b"\r\n\r\n", 1)[-1])["error"]  # from Python 3.13 the headers come first
    assert answer["type"] == "mnestiq_proxy" and answer["message"].startswith("400") and b"SECRETWORD" not in reply


HOSTILE_HEADERS = {
    "run_with_path_characters": {"X-Mnestiq-Run": "../../etc\\passwd"}, "run_too_long": {"X-Mnestiq-Run": "r" * 5000},
    "run_empty": {"X-Mnestiq-Run": ""}, "run_control": {"X-Mnestiq-Run": "a b"},
    "traceparent_junk": {"traceparent": "zz"}, "traceparent_zero": {"traceparent": f"00-{'0' * 32}-{'0' * 16}-00"},
    "traceparent_long": {"traceparent": "0" * 20_000}, "auth_scheme_only": {"Authorization": "Bearer"},
    "auth_spaces": {"Authorization": "   "}, "agent_latin1": {"User-Agent": "caf\xe9"},
    "agent_long": {"User-Agent": "u" * 20_000}, "content_type_latin1": {"Content-Type": "text/plain; x=\xe9"},
    "kept_header_odd": {"anthropic-version": "\xff\xfe", "openai-beta": ""},
    "mnestiq_prefixed": {"X-Mnestiq-Other": "x"},
}


@pytest.mark.parametrize("api", ROUTES)
@pytest.mark.parametrize("name", HOSTILE_HEADERS)
def test_hostile_headers_are_passed_on_and_recorded(air, api, name):
    status, _ = air.post(ROUTES[api][0], GOOD, HOSTILE_HEADERS[name])
    assert status == 200 and air.fake.seen[-1].body == GOOD
    assert air.problems() == []


ODD_PATHS = ["/openai/v1/chat/completions?key=SECRETWORD&x=%zz", "/openai//v1/chat/completions",
             "/OPENAI/v1/chat/completions",
             "/openai/v1/chat/completions/", "/openai/../openai/v1/chat/completions", "/openai/v1/[x/chat/completions",
             "/openai/%00/chat/completions", "/openai", "/openai?x", "/", "//", "/nobody/v1/chat/completions"]


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("path", ODD_PATHS)
def test_an_odd_path_is_answered_and_a_key_in_it_is_not_written_down(air, method, path):
    conn = http.client.HTTPConnection("127.0.0.1", air.proxy.port, timeout=10)
    conn.request(method, path, body=GOOD if method == "POST" else None)
    assert 200 <= conn.getresponse().status < 600
    conn.close()
    air.settle()
    assert air.crashes == [] and air.rec.failures == air.failures
    assert all("SECRETWORD" not in json.dumps(r) for r in air.records(None))


def test_bad_clients_do_not_hold_up_good_ones_at_the_same_time(air):
    bad = list(CLIENTS.values()) * 2
    answers = []
    threads = [threading.Thread(target=_exchange, args=(air, data)) for data in bad]
    threads += [threading.Thread(target=lambda: answers.append(air.post(CHAT[0]))) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [status for status, _ in answers] == [200] * 16
    assert air.crashes == [] and air.rec.failures == air.failures


def test_a_stalled_client_does_not_hold_up_another_and_is_let_go(air):
    sock = socket.create_connection(("127.0.0.1", air.proxy.port), timeout=5)
    sock.sendall(_POST + b"Content-Length: 100\r\n\r\n{")  # the rest never comes
    try:
        air.alive()
        started = time.monotonic()
        assert sock.recv(4096) == b""  # the proxy hangs up after client_timeout
        assert time.monotonic() - started < 4
    finally:
        sock.close()
    air.alive()


def test_an_agent_that_resets_before_the_answer_starts_is_still_recorded(air):
    """The provider did the work and was paid for it. An agent gone by then must not erase the call."""
    finished = threading.Event()

    def slow(conn):
        time.sleep(0.2)
        with contextlib.suppress(OSError):
            conn.sendall(_http(_GOOD_ANSWER))
        finished.set()

    air.raw.replies.append(slow)
    sock = socket.create_connection(("127.0.0.1", air.proxy.port), timeout=5)
    sock.sendall(b"POST " + CHAT[1].encode() + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: "
                 + str(len(GOOD)).encode() + b"\r\n\r\n" + GOOD)
    assert _wait_for(lambda: air.raw.seen)  # the provider has the request
    fmt = "hh" if os.name == "nt" else "ii"
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(fmt, 1, 0))
    sock.close()  # a reset, not a polite close
    assert finished.wait(5)
    assert _wait_for(lambda: air.proxy._busy == 0)
    assert len(air.records()) == 1


def test_a_request_body_over_the_limit_is_refused_chunked_too(tmp_path):
    fake = FakeProvider()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"openai={fake.url}"], listen="127.0.0.1:0", max_request_bytes=100)
    proxy.start()
    try:
        data = (_POST + b"Transfer-Encoding: chunked\r\n\r\n" + b"40\r\n" + b"x" * 64 + b"\r\n" + b"40\r\n" + b"x" * 64
                + b"\r\n0\r\n\r\n")
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        sock.sendall(data)
        assert sock.recv(4096).startswith(b"HTTP/1.1 413")
        sock.close()
        assert fake.seen == []
    finally:
        proxy.close()
        rec.close()
        fake.close()


def test_connections_past_the_limit_are_turned_away_and_the_slots_come_back(tmp_path):
    fake = FakeProvider()
    rec = Recorder(FileSink(tmp_path / "e.jsonl"), agent_id="a")
    proxy = ModelProxy(rec, upstreams=[f"openai={fake.url}"], listen="127.0.0.1:0", max_connections=2, client_timeout=5)
    proxy.start()
    try:
        held = [socket.create_connection(("127.0.0.1", proxy.port), timeout=5) for _ in range(2)]
        for sock in held:
            sock.sendall(b"GET ")  # enough to tie up a slot

        def turned_away():
            third = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            with contextlib.closing(third):  # says nothing: the answer comes at accept, and bytes unread would reset it
                return third.recv(4096).startswith(b"HTTP/1.1 503")

        assert _wait_for(turned_away)
        for sock in held:
            sock.close()

        def served_again():
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            with contextlib.closing(conn):
                conn.request("GET", "/openai/v1/models")
                return conn.getresponse().status == 200

        assert _wait_for(served_again)
    finally:
        proxy.close()
        rec.close()
        fake.close()


def test_all_the_evidence_the_hostile_traffic_left_behind_verifies(flight):
    """Runs last in this file, over everything the shared proxy recorded above."""
    flight.settle()
    report = verify_file(flight.path, [flight.pub])
    assert report.ok, report.errors[:3]
