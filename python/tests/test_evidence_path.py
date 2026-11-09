"""The evidence path is the file itself: a link put there redirects nothing and gets nothing cut.

Windows cannot make a symbolic link without a privilege, so the first test skips there and the others stand in for
what the operating system would report."""

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from mnestiq import FileSink, HeadFile, Recorder, SinkError, verify_file
from mnestiq.canonical import canonical_json

BEFORE = b"line one\nline two with no newline"


@pytest.fixture
def torn(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(BEFORE)
    return path


def test_a_link_at_the_evidence_path_is_refused_and_its_target_keeps_every_byte(tmp_path, torn):
    link = tmp_path / "link.jsonl"
    try:
        os.symlink(torn, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"the OS refused to create a symlink here: {exc}")
    with pytest.raises(SinkError, match="symbolic link"):
        FileSink(link)
    assert torn.read_bytes() == BEFORE
    assert not list(tmp_path.glob("*.torn-*"))


def test_a_path_reported_as_a_link_is_refused_before_it_is_opened(torn, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(Path, "is_symlink", lambda self: True)
        with pytest.raises(SinkError, match="symbolic link"):
            FileSink(torn)
    assert torn.read_bytes() == BEFORE


def test_a_link_swapped_in_while_the_file_is_opened_is_refused(torn, monkeypatch):
    answers = iter([False, True])
    with monkeypatch.context() as m:
        m.setattr(Path, "is_symlink", lambda self: next(answers))
        with pytest.raises(SinkError, match="symbolic link"):
            FileSink(torn)
    assert torn.read_bytes() == BEFORE


def test_a_file_replaced_before_recovery_is_not_cut_and_stays_unlocked(torn, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(os.path, "samestat", lambda a, b: False)
        with pytest.raises(SinkError, match="replaced"):
            FileSink(torn)
    assert torn.read_bytes() == BEFORE
    FileSink(torn).close()  # the failed open left no lock behind, and recovery runs as usual
    assert torn.read_bytes() == b"line one\n"


# Which tails are one torn record


WHOLE = b'{"prev_hash":"aa","result":{"prev_hash":"ab"},"seq":1}'


def test_a_torn_record_that_holds_a_prev_hash_key_of_its_own_is_set_aside(tmp_path):
    path = tmp_path / "e.jsonl"
    torn = WHOLE[:-4]
    path.write_bytes(b'{"seq":0}\n' + torn)
    sink = FileSink(path)
    sink.close()
    assert path.read_bytes() == b'{"seq":0}\n'
    assert (tmp_path / sink.recovered["sidecar"]).read_bytes() == torn


def test_a_whole_record_that_holds_a_prev_hash_key_gets_its_newline_and_the_next_its_own_line(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(WHOLE)
    sink = FileSink(path)
    sink.append({"seq": 2})
    sink.close()
    assert sink.recovered is None and path.read_bytes() == WHOLE + b"\n" + canonical_json({"seq": 2}) + b"\n"


def test_a_recorder_starts_over_a_torn_tool_result_that_holds_a_prev_hash_key(tmp_path, key, pub):
    path = tmp_path / "e.jsonl"
    rec = Recorder(FileSink(path), agent_id="a", signing_key=key)
    with rec.run() as run:
        run.tool_call("lookup", {}, {"prev_hash": "ab"})
    rec._sink.close()
    lines = path.read_bytes().splitlines(keepends=True)
    at = next(i for i, line in enumerate(lines) if line.count(b'"prev_hash":') > 1)
    path.write_bytes(b"".join(lines[:at]) + lines[at][:-12])
    Recorder(FileSink(path), agent_id="a", signing_key=key).close()
    assert len(list(tmp_path.glob("e.jsonl.torn-*"))) == 1
    assert verify_file(path, [pub]).ok


@pytest.mark.parametrize("tail", [b'{"a":"}{","b":', b'{"a":"\\"}{","b":', b'{"a":[1,{"b":"]"}', b'{"a":"\\'],
                         ids=["brackets_in_a_string", "an_escaped_quote", "still_open", "cut_inside_an_escape"])
def test_brackets_inside_a_string_do_not_make_a_torn_record_look_like_several(tmp_path, tail):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":0}\n' + tail)
    FileSink(path).close()
    assert path.read_bytes() == b'{"seq":0}\n'


@pytest.mark.parametrize("tail", [b'{"seq":1}{"seq":2', b'{"seq":1} {"seq":2}', b'[1]x', b'{"a":"}"}{'],
                         ids=["torn_second", "two_whole", "array_then_text", "string_then_open"])
def test_a_value_that_closes_before_the_end_of_the_line_is_damage_and_stays(tmp_path, tail):
    path = tmp_path / "e.jsonl"
    before = b'{"seq":0}\n' + tail
    path.write_bytes(before)
    FileSink(path).close()
    assert path.read_bytes() == before and not list(tmp_path.glob("*.torn-*"))


# The head's temporary name


def test_a_hard_link_at_the_heads_temporary_name_is_not_written_through(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(BEFORE)
    head = tmp_path / "head.json"
    os.link(victim, tmp_path / "head.json.tmp")
    HeadFile(head)({"kind": "checkpoint"})
    assert victim.read_bytes() == BEFORE
    assert json.loads(head.read_bytes()) == {"kind": "checkpoint"} and not (tmp_path / "head.json.tmp").exists()


@pytest.mark.parametrize("dangling", [False, True], ids=["to_a_file", "dangling"])
def test_a_symbolic_link_at_the_heads_temporary_name_is_not_written_through(tmp_path, dangling):
    victim = tmp_path / "victim.txt"
    if not dangling:
        victim.write_bytes(BEFORE)
    try:
        os.symlink(victim, tmp_path / "head.json.tmp")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"the OS refused to create a symlink here: {exc}")
    HeadFile(tmp_path / "head.json")({"kind": "checkpoint"})
    assert victim.read_bytes() == BEFORE if not dangling else not victim.exists()


# Hard links at the evidence path


def test_a_hard_linked_file_with_a_torn_tail_is_refused_and_keeps_every_byte(tmp_path, torn):
    other = tmp_path / "other.txt"
    os.link(torn, other)
    with pytest.raises(SinkError, match="hard links"):
        FileSink(torn)
    assert torn.read_bytes() == BEFORE and other.read_bytes() == BEFORE
    assert not list(tmp_path.glob("*.torn-*"))
    other.unlink()
    FileSink(torn).close()  # the failed open left no lock behind, and with one name the cut is safe
    assert torn.read_bytes() == b"line one\n"


def test_a_hard_linked_file_that_needs_no_cut_is_opened(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":0}\n')
    os.link(path, tmp_path / "snapshot.jsonl")
    sink = FileSink(path)
    assert list(sink.existing()) == [{"seq": 0}]
    sink.close()


def test_a_hard_linked_file_missing_only_its_newline_gets_it(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":0}')
    os.link(path, tmp_path / "snapshot.jsonl")
    FileSink(path).close()
    assert path.read_bytes() == b'{"seq":0}\n'


def test_a_path_that_names_another_file_than_the_one_opened_is_refused(torn, monkeypatch):
    real = os.lstat

    def another(path, *args, **kwargs):
        seen = real(path, *args, **kwargs)
        return SimpleNamespace(st_mode=seen.st_mode, st_dev=seen.st_dev, st_ino=seen.st_ino + 1)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", another)
        with pytest.raises(SinkError, match="replaced"):
            FileSink(torn)
    assert torn.read_bytes() == BEFORE
    FileSink(torn).close()


@pytest.mark.parametrize("zeroed", ["lstat", "fstat"])
@pytest.mark.parametrize("field", ["st_ino", "st_dev"])
def test_a_filesystem_that_reports_zeros_is_not_taken_for_a_swap(tmp_path, monkeypatch, zeroed, field):
    path = tmp_path / "e.jsonl"
    real = getattr(os, zeroed)

    def blank(target, *args, **kwargs):
        seen = real(target, *args, **kwargs)
        fields = {name: getattr(seen, name) for name in ("st_mode", "st_dev", "st_ino", "st_size", "st_nlink")}
        return SimpleNamespace(**{**fields, field: 0})

    with monkeypatch.context() as m:
        m.setattr(os, zeroed, blank)
        FileSink(path).close()
    assert path.exists()


# Things that are not a regular file


def test_a_folder_at_the_evidence_path_is_refused(tmp_path):
    with pytest.raises(SinkError, match="not a regular file"):
        FileSink(tmp_path)


def test_a_device_at_the_evidence_path_is_refused():
    with pytest.raises(SinkError, match="not a regular file"):
        FileSink(os.devnull)


def test_a_failed_open_leaves_no_descriptor_behind(monkeypatch):
    opened = []
    real = os.open

    def spying(*args, **kwargs):
        opened.append(real(*args, **kwargs))
        return opened[-1]

    with monkeypatch.context() as m:
        m.setattr(os, "open", spying)
        with pytest.raises(SinkError, match="not a regular file"):
            FileSink(os.devnull)
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


def _opening_gives_up(path):
    """What opening ``path`` raised, or None if it is stuck: an open that hangs must fail the test, not hang it."""
    outcome = []

    def attempt():
        try:
            FileSink(path)
            outcome.append("opened")
        except Exception as exc:
            outcome.append(exc)

    threading.Thread(target=attempt, daemon=True).start()
    for _ in range(100):
        if outcome:
            return outcome[0]
        threading.Event().wait(0.1)
    return None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this OS has no FIFOs")
def test_a_fifo_with_no_reader_is_refused_and_does_not_hang(tmp_path):
    fifo = tmp_path / "e.jsonl"
    os.mkfifo(fifo)
    assert isinstance(_opening_gives_up(fifo), SinkError)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this OS has no FIFOs")
def test_a_fifo_with_a_reader_is_refused_and_nothing_stays_open_on_it(tmp_path):
    fifo = tmp_path / "e.jsonl"
    os.mkfifo(fifo)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert isinstance(_opening_gives_up(fifo), SinkError)
        assert os.read(reader, 1) == b""
    finally:
        os.close(reader)


def test_the_descriptor_of_a_regular_file_ends_up_blocking(tmp_path):
    path = tmp_path / "e.jsonl"
    sink = FileSink(path)
    try:
        if os.name == "posix":  # elsewhere this only works on pipes
            assert os.get_blocking(sink._fh.fileno())
    finally:
        sink.close()


# What a sink reads back


def test_existing_reads_the_file_it_holds_and_refuses_another(tmp_path, monkeypatch):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":1}\n')
    sink = FileSink(path)
    assert list(sink.existing()) == [{"seq": 1}]
    with monkeypatch.context() as m:
        m.setattr(os.path, "samestat", lambda a, b: False)
        with pytest.raises(SinkError, match="replaced"):
            list(sink.existing())
    sink.close()
    assert list(sink.existing()) == [{"seq": 1}]  # closed, there is no held file to compare with


def test_a_file_swapped_in_after_open_gives_up_none_of_its_records(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":1}\n')
    other = tmp_path / "other.jsonl"
    other.write_bytes(b'{"seq":99}\n')
    sink = FileSink(path)
    try:
        os.replace(other, path)
    except PermissionError as exc:
        sink.close()
        pytest.skip(f"this OS will not replace a file that is open: {exc}")
    with pytest.raises(SinkError, match="replaced"):
        list(sink.existing())
    sink.close()


def test_a_link_swapped_in_after_open_gives_up_none_of_its_target(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"seq":1}\n')
    other = tmp_path / "other.jsonl"
    other.write_bytes(b'{"seq":99}\n')
    sink = FileSink(path)
    try:
        link = tmp_path / "link.jsonl"
        os.symlink(other, link)
        os.replace(link, path)
    except (OSError, NotImplementedError) as exc:
        sink.close()
        pytest.skip(f"the OS refused the swap: {exc}")
    with pytest.raises(SinkError, match="symbolic link"):
        list(sink.existing())
    sink.close()
