"""Append-only sinks for evidence records."""

from __future__ import annotations

import errno
import os
import re
import stat
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Protocol
from collections.abc import Iterator

from .canonical import canonical_json, parse_json
from .verify import is_blank


class RecorderError(Exception):
    pass


class SinkError(RecorderError):
    pass


class Sink(Protocol):
    def append(self, record: dict) -> None: ...
    def existing(self) -> Iterator[dict]: ...
    def close(self) -> None: ...


class FileSink:
    """JSON Lines file, opened in append mode. One canonical record per line.

    Crash safety:
      * On open, a torn final line (the process died mid-write) is moved to a
        ``<file>.torn-<time>`` sidecar, never deleted, and ``recovered`` describes it.
      * If a write fails (disk full, I/O error), any partial bytes are truncated so
        the file never holds half a record, then the error is raised.

    ``fsync=True`` forces each record to disk before the agent proceeds: slower,
    but nothing is lost if the host dies mid-incident. New files are created
    owner-read/write only on Linux and macOS (evidence can contain prompts and customer
    data). On Windows a file takes the access list of its folder: keep evidence in a
    folder only the agent's account can read.

    One writer per file: a second sink on a file that is already open for writing,
    in this process or another, raises ``SinkError``. The lock goes away with the
    process, so a crash never leaves the file locked.

    The evidence path must be the file itself. A symbolic link there raises ``SinkError``, so that a link
    put in the folder cannot redirect the records or have another file cut by crash recovery. A link higher up
    the path is not checked: keep the evidence folder writable only by the agent's account. So does anything that
    is not a regular file (a FIFO, a device such as ``/dev/null``, a folder), where records would hang or vanish.
    A hard-linked file is accepted, as snapshot tools make them, unless recovery would have to cut it.
    """

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._lock = threading.Lock()
        self._cut_at: int | None = None  # where a half-written line that could not be removed starts
        fd = _open_evidence(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        # Unbuffered: a write that fails must not stay in a buffer and land in the file later.
        self._fh = os.fdopen(fd, "ab", buffering=0)
        try:
            _lock_exclusive(self._fh)
        except OSError as exc:
            self._fh.close()
            raise SinkError(f"{self.path} is already being written by another recorder") from exc
        try:
            self.recovered: dict | None = self._recover_torn_tail()
        except Exception:
            _unlock(self._fh)
            self._fh.close()
            raise
        self._fh.seek(0, os.SEEK_END)

    def _recover_torn_tail(self) -> dict | None:
        locked = os.fstat(self._fh.fileno())
        if locked.st_size == 0:
            return None
        with os.fdopen(_open_evidence(self.path, os.O_RDWR), "rb+") as fh:
            if not os.path.samestat(os.fstat(fh.fileno()), locked):  # cutting a line is for the file this sink holds
                raise SinkError(f"{self.path} was replaced while it was being opened")
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 1))
            if fh.read(1) == b"\n":
                return None
            # Find the start of the incomplete last line.
            pos, chunk = size, 65536
            start = 0
            while pos > 0:
                read_from = max(0, pos - chunk)
                fh.seek(read_from)
                block = fh.read(pos - read_from)
                nl = block.rfind(b"\n")
                if nl != -1:
                    start = read_from + nl + 1
                    break
                pos = read_from
            fh.seek(start)
            tail = fh.read()
            try:
                parse_json(tail)
                complete = True
            except (ValueError, RecursionError):
                complete = False
            if complete:  # the record was fully written, only the newline is missing
                fh.seek(0, os.SEEK_END)
                fh.write(b"\n")
                return None
            if _ends_before_its_end(tail):
                # A write is torn inside one record. Several in one line is a damaged file, which this must not cut
                # away as if it were a crash: it stays, and reading it back reports a line that is not JSON.
                return None
            if os.fstat(fh.fileno()).st_nlink > 1:  # the cut would reach every other name of this file
                raise SinkError(f"{self.path} has a torn last line and other hard links: recovery will not cut a "
                                "file that has other names. Give this file its own copy and open that")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            sidecar = self.path.with_name(f"{self.path.name}.torn-{stamp}")
            fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as side:  # what was cut off is evidence too: owner-only like the file
                side.write(tail)
            fh.truncate(start)
        return {"bytes": len(tail), "sidecar": sidecar.name}

    def append(self, record: dict) -> None:
        line = canonical_json(record) + b"\n"
        with self._lock:
            if self._fh.closed:
                raise SinkError(f"{self.path} is closed")
            if self._cut_at is not None:  # nothing may land on the end of a half-written line
                self._fh.truncate(self._cut_at)
                self._cut_at = None
            pos = self._fh.seek(0, os.SEEK_END)  # not tell(): a truncate leaves the position past the end
            try:
                view = memoryview(line)
                while view:  # an unbuffered write may take part of the line
                    written = self._fh.write(view)
                    if not written:
                        raise OSError("no bytes written")
                    view = view[written:]
                if self._fsync:
                    os.fsync(self._fh.fileno())
            except OSError:
                try:  # drop the partial write
                    self._fh.truncate(pos)
                except OSError:
                    self._cut_at = pos  # tried again before the next record
                raise

    def existing(self) -> Iterator[dict]:
        try:
            fd = _open_evidence(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return
        with open(fd, "rb") as fh:
            # The records of the file this sink holds, not those of one swapped in at its path since.
            if not self._fh.closed and not os.path.samestat(os.fstat(fh.fileno()), os.fstat(self._fh.fileno())):
                raise SinkError(f"{self.path} was replaced while it was open")
            for n, line in enumerate(fh, start=1):
                if is_blank(line):  # the verifier's own test: a line it reads as a record is one here too
                    continue
                try:
                    yield parse_json(line)
                except (ValueError, RecursionError) as exc:
                    raise SinkError(f"{self.path} line {n} is not valid JSON ({exc}); "
                                    "the chain cannot be resumed. Verify the file and start a new one.") from exc

    def sync(self) -> None:
        """Make sure what was written is on the disk."""
        with self._lock:
            if not self._fh.closed:
                os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                try:
                    self._fh.flush()
                    if self._fsync:
                        os.fsync(self._fh.fileno())
                finally:  # a full disk must not keep the file locked for the life of the process
                    _unlock(self._fh)
                    self._fh.close()


# A whole string, which may hold brackets of its own and may be cut off, or one bracket.
_JSON_TOKEN = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"?|[\[\]{}]', re.DOTALL)


def _ends_before_its_end(tail: bytes) -> bool:
    """Whether a JSON value closes before the last byte of ``tail``, so that more than one record is on the line."""
    depth = 0
    for match in _JSON_TOKEN.finditer(tail):
        token = match.group()
        if token in (b"{", b"["):
            depth += 1
        elif token in (b"}", b"]") and depth:
            depth -= 1
            if not depth and match.end() < len(tail):
                return True
    return False


def _open_evidence(path: Path, flags: int) -> int:
    """A descriptor on the evidence file itself, refusing a link and anything but a regular file. Windows has no
    ``O_NOFOLLOW``, so there the check runs on both sides of the open."""
    refused = f"{path} is a symbolic link. Evidence is written to the file itself: give the recorder the real path"
    not_a_file = f"{path} is not a regular file. Evidence needs a file of its own, not a device, a pipe or a folder"
    if path.is_symlink():
        raise SinkError(refused)
    try:
        # O_NONBLOCK so that a FIFO with no reader fails here and does not hang the agent.
        extra = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags | extra, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SinkError(refused) from exc
        if exc.errno == errno.ENXIO or path.is_dir():  # ENXIO is that FIFO
            raise SinkError(not_a_file) from exc
        raise
    try:
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode):
            raise SinkError(not_a_file)
        if path.is_symlink():
            raise SinkError(refused)
        _refuse_if_swapped(path, held)
        if sys.platform != "win32":  # only the open had to be non-blocking
            os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _refuse_if_swapped(path: Path, held: os.stat_result) -> None:
    """Closes the gap Windows leaves without ``O_NOFOLLOW``: the path must still name the file that was opened."""
    replaced = f"{path} was replaced while it was being opened"
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise SinkError(replaced) from exc
    # Some network filesystems report zeros, and then the two say nothing about each other.
    known = all((held.st_ino, held.st_dev, named.st_ino, named.st_dev))
    if known and (held.st_ino, held.st_dev) != (named.st_ino, named.st_dev):
        raise SinkError(replaced)


# Windows locks are mandatory, so a lock on the data itself would stop the dashboard and
# verify from reading a file that is being written. Lock one byte far past the end instead.
_LOCK_OFFSET = 1 << 40


def _lock_exclusive(fh: BinaryIO) -> None:
    if sys.platform == "win32":
        import msvcrt

        fh.seek(_LOCK_OFFSET)
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        finally:
            fh.seek(0, os.SEEK_END)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fh: BinaryIO) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(_LOCK_OFFSET)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


class HeadFile:
    """Keeps a copy of the latest checkpoint somewhere else: ``Recorder(on_checkpoint=HeadFile(path))``.

    An evidence file cut back to an earlier checkpoint still verifies on its own. Checked
    against the head (``mnestiq verify --head``), it does not. Put the head where whoever
    can edit the evidence cannot: another disk, host, or account. Each write replaces the
    file atomically, so a crash leaves the previous head, never half of one.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def __call__(self, checkpoint: dict) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.unlink(missing_ok=True)  # with O_EXCL below, a planted link is removed, never followed
        # 0o666 is what open() asked for: the head stays readable as the umask allows, for whoever checks it.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o666)
        with open(fd, "wb") as fh:
            fh.write(canonical_json(checkpoint) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


class MemorySink:
    """Keeps records in a list. For tests and short-lived scripts."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self.recovered: dict | None = None

    def append(self, record: dict) -> None:
        # Round-trip through canonical JSON, read back as a file is read, so these records match what a file would hold.
        self.records.append(parse_json(canonical_json(record)))

    def existing(self) -> Iterator[dict]:
        return iter(list(self.records))

    def close(self) -> None:
        pass
