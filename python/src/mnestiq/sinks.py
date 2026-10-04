"""Append-only sinks for evidence records."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from collections.abc import Iterator

from .canonical import canonical_json


class SinkError(Exception):
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
    owner-read/write only (evidence can contain prompts and customer data).
    """

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._lock = threading.Lock()
        self.recovered: dict | None = self._recover_torn_tail()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        self._fh = os.fdopen(fd, "ab")

    def _recover_torn_tail(self) -> dict | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with open(self.path, "rb+") as fh:
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
                json.loads(tail)
                complete = True
            except ValueError:
                complete = False
            if complete:  # the record was fully written, only the newline is missing
                fh.seek(0, os.SEEK_END)
                fh.write(b"\n")
                return None
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            sidecar = self.path.with_name(f"{self.path.name}.torn-{stamp}")
            sidecar.write_bytes(tail)
            fh.truncate(start)
        return {"bytes": len(tail), "sidecar": sidecar.name}

    def append(self, record: dict) -> None:
        line = canonical_json(record) + b"\n"
        with self._lock:
            if self._fh.closed:
                raise SinkError(f"{self.path} is closed")
            pos = self._fh.tell()
            try:
                self._fh.write(line)
                self._fh.flush()
                if self._fsync:
                    os.fsync(self._fh.fileno())
            except OSError:
                try:  # drop the partial write
                    self._fh.truncate(pos)
                    self._fh.flush()
                except OSError:
                    pass
                raise

    def existing(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    raise SinkError(f"{self.path} line {n} is not valid JSON ({exc}); "
                                    "the chain cannot be resumed. Verify the file and start a new one.") from exc

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                if self._fsync:
                    os.fsync(self._fh.fileno())
                self._fh.close()


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
        with open(tmp, "wb") as fh:
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
        # Round-trip through canonical JSON so in-memory records match what a file would hold.
        self.records.append(json.loads(canonical_json(record)))

    def existing(self) -> Iterator[dict]:
        return iter(list(self.records))

    def close(self) -> None:
        pass
