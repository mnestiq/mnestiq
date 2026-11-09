"""Local evidence dashboard.

    mnestiq dashboard ./evidence --trusted-key keys/signing.pub

Serves a single-page dashboard on 127.0.0.1 that reads evidence files from disk,
verifies them with the same verifier as the CLI, and live-updates as agents write.

Containment: binds to loopback only, rejects non-local Host headers (DNS
rebinding), answers data requests only with the random key in the link it prints
(other accounts on the same machine can reach 127.0.0.1 too), and sends a
Content-Security-Policy that forbids the page from loading or contacting anything
except this server.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import secrets
import threading
from collections import OrderedDict, deque
from collections.abc import Iterator
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from itertools import islice
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qs, urlsplit

from ..canonical import parse_json
from ..context import expand
from ..verify import ChainVerifier, Issue, Report, is_blank

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
MAX_RECORDS = 20_000   # sent to the browser per file, verification still reads everything
MAX_ERRORS = 1_000     # a file is checked until it has this many problems
MAX_LOAD_BYTES = 256 * 1024 * 1024  # the largest file read into memory and verified here
_VERIFY_BATCH = 1_024  # lines verified between looks at how many problems were found
MAX_CACHED = 32        # files whose prepared answer is kept in memory
SNIFF_LINES = 200      # lines read to tell an evidence file from other JSON lines in the folder
SNIFF_BYTES = 64 * 1024 * 1024  # how far into a file to look for evidence: past this, it cannot be ruled out
_SNIFF_PIECE = 1_048_576  # the most read at once while looking, however long a line is
_SNIFF_MARKS = (b'"spec_version":', b'"chain_id":')  # two keys every record of a chain holds
KEY_HEADER = "X-Mnestiq-Key"


@dataclass
class _Loaded:
    stamp: tuple[int, int]
    summary: dict
    payload: bytes
    etag: str


class EvidenceStore:
    """Finds evidence files under a path and caches their verified contents."""

    def __init__(self, path: str | Path, trusted_keys: list[str], max_records: int = MAX_RECORDS) -> None:
        self.root = Path(path).resolve()
        self.trusted_keys = trusted_keys
        self.max_records = max_records
        self._sniffed: dict[Path, tuple[int, bool | None]] = {}
        self._cache: OrderedDict[Path, _Loaded] = OrderedDict()
        self._lock = threading.Lock()

    def files(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        if not self.root.is_dir():
            return []
        # A file a recorder set aside as damaged (on_damaged="new_file") is evidence too, under a longer name.
        found = {p for pattern in ("*.jsonl", "*.jsonl.damaged-*") for p in self.root.rglob(pattern)
                 if p.is_file() and self._sniff(p) is not False}
        return sorted(found, key=_mtime, reverse=True)

    def _sniff(self, path: Path) -> bool | None:
        """Whether a file is a Mnestiq evidence chain: True or False, or None when that could not be told.
        Other JSON-lines files (proxy logs, exports) sit in the same folders, and showing them would report
        them as 'tampered' by mistake. A file that cannot be ruled out is listed as unrecognised."""
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:  # renamed or removed since the folder was listed
            return False
        cached = self._sniffed.get(path)
        if cached and cached[0] == stamp:
            return cached[1]
        verdict: bool | None
        try:
            with open(path, "rb") as fh:
                verdict = _sniff_file(fh)
        except (OSError, ValueError, RecursionError):
            verdict = None
        self._sniffed[path] = (stamp, verdict)
        return verdict

    def name(self, path: Path) -> str:
        return path.name if self.root.is_file() else path.relative_to(self.root).as_posix()

    def resolve(self, name: str) -> Path | None:
        # Only names we listed ourselves, never a path built from user input.
        return next((p for p in self.files() if self.name(p) == name), None)

    def _unrecognised(self, path: Path, st: os.stat_result) -> _Loaded:
        """The entry for a file that could not be looked through: listed and said so, never read in whole."""
        report = Report()
        report.error("unrecognised", "this file may be evidence, but it is too large to look through here or could "
                                     "not be read. It was not verified. Run mnestiq verify on it")
        summary = {"name": self.name(path), "size": st.st_size, "mtime_ns": st.st_mtime_ns, "ok": False,
                   "records": 0, "errors": 1, "warnings": 0, "unrecognised": True}
        body = {"file": summary, "report": {**report.to_dict(), "errors_total": 1}, "pinned": bool(self.trusted_keys),
                "records": [], "records_total": 0, "records_shown_from": 0}
        payload = json.dumps(body).encode("utf-8")
        return _Loaded((st.st_mtime_ns, st.st_size), summary, payload,
                       '"' + hashlib.sha256(payload).hexdigest()[:32] + '"')

    def load(self, path: Path) -> _Loaded:
        st = path.stat()
        if st.st_size > MAX_LOAD_BYTES or (not self.root.is_file() and self._sniff(path) is None):
            return self._unrecognised(path, st)
        stamp = (st.st_mtime_ns, st.st_size)
        with self._lock:
            cached = self._cache.get(path)
            if cached and cached.stamp == stamp:
                self._cache.move_to_end(path)
                return cached
        # One read: the records shown are the ones verified, even while the file grows.
        data = path.read_bytes()
        stamp = (st.st_mtime_ns, len(data))
        stream = io.BytesIO(data)  # as a file is read: split at newlines only, as the verifier sees it
        lines: list[bytes] = []
        # Verification covers the whole file unless it is past saving. The browser only gets the most recent records.
        verifier = ChainVerifier(self.trusted_keys)
        while len(verifier.report.errors) < MAX_ERRORS and (batch := list(islice(stream, _VERIFY_BATCH))):
            verifier.feed(batch)
            lines.extend(batch)
        report = verifier.result()
        if stream.read(1):  # first in the list, so that the cut below keeps it
            report.errors.insert(0, Issue("too_many_errors", f"checking stopped at line {len(lines)}, after "
                                          f"{len(report.errors)} problems. The rest of this file was not checked. "
                                          "Run mnestiq verify on it"))
        records: deque[dict] = deque(maxlen=self.max_records)
        total = 0
        # A record of a shape the recorder never writes goes to the page as text only: the page reads fields
        # as the recorder writes them. An unknown field is still a well-formed record.
        malformed = {e.line for e in report.errors if e.code in ("schema", "unreadable", "parse", "canonical")
                     and not e.message.startswith("unknown field")}

        def parsed() -> Iterator[dict]:
            nonlocal total
            for line_no, raw in enumerate(lines, start=1):
                if is_blank(raw):
                    continue
                total += 1
                try:
                    rec = parse_json(raw)
                    if not isinstance(rec, dict) or line_no in malformed:
                        raise ValueError
                except (ValueError, RecursionError):
                    rec = {"_unparseable": True, "_line": line_no, "_raw": raw[:300].decode("utf-8", "replace")}
                yield rec

        # Model calls that record only what changed are shown with their full context.
        records.extend(expand(parsed()))
        summary = {
            "name": self.name(path),
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "ok": report.ok,
            "records": report.records,
            "errors": len(report.errors),
            "warnings": len(report.warnings),
        }
        report_dict = report.to_dict()
        report_dict["errors_total"] = len(report.errors)
        report_dict["errors"] = report_dict["errors"][:MAX_ERRORS]
        body = {"file": summary, "report": report_dict, "pinned": bool(self.trusted_keys),
                "records": list(records), "records_total": total,
                "records_shown_from": total - len(records)}
        # "replace": a lone surrogate parses from JSON (the verifier reports it) but has no UTF-8 form
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8", "replace")
        loaded = _Loaded(stamp, summary, payload, '"' + hashlib.sha256(payload).hexdigest()[:32] + '"')
        with self._lock:
            self._cache[path] = loaded
            while len(self._cache) > MAX_CACHED:
                self._cache.popitem(last=False)
        return loaded


def _sniff_file(fh: BinaryIO) -> bool | None:
    """True if ``fh`` holds a Mnestiq record, False if it does not, None if it is too large to tell."""

    def lines() -> Iterator[bytes]:
        while fh.tell() < SNIFF_BYTES and (raw := fh.readline(_SNIFF_PIECE)):
            if not is_blank(raw):
                yield raw

    for raw in islice(lines(), SNIFF_LINES):
        # Any of the first lines will do: a damaged first line must be reported, not hidden.
        with contextlib.suppress(ValueError, RecursionError):
            record = json.loads(raw)
            if isinstance(record, dict) and "spec_version" in record and "chain_id" in record:
                return True
    # Junk lines in front, or damage to every line, must not hide a chain: look through the whole file for a line with
    # what every record holds. A piece of a long line counts with the other pieces of that line.
    fh.seek(0)
    found: set[bytes] = set()
    tail = b""
    overlap = max(map(len, _SNIFF_MARKS)) - 1  # so that a mark split between two pieces is still found
    while fh.tell() < SNIFF_BYTES:
        piece = fh.readline(min(_SNIFF_PIECE, SNIFF_BYTES - fh.tell()))
        if not piece:
            return False
        tail += piece
        found.update(mark for mark in _SNIFF_MARKS if mark in tail)
        if len(found) == len(_SNIFF_MARKS):
            return True
        if piece.endswith(b"\n"):
            found.clear()
            tail = b""
        else:
            tail = tail[-overlap:]
    return None if fh.read(1) else False


def _mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:  # renamed or removed since the folder was listed: the others are still shown
        return 0


def make_handler(store: EvidenceStore, port: int, key: str) -> type[BaseHTTPRequestHandler]:
    page = resources.files(__package__).joinpath("index.html").read_bytes()
    allowed_hosts = {f"{h}:{port}" for h in LOCAL_HOSTS}

    class Handler(BaseHTTPRequestHandler):
        server_version = "mnestiq-dashboard"

        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            if self.headers.get("Host", "") not in allowed_hosts:
                return self._send(HTTPStatus.FORBIDDEN, b"forbidden host", "text/plain")
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if url.path.startswith("/api/") and not hmac.compare_digest(self.headers.get(KEY_HEADER, ""), key):
                return self._send(HTTPStatus.FORBIDDEN, b'{"error":"open the link the dashboard printed"}',
                                  "application/json")
            try:
                if url.path == "/":
                    return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
                if url.path == "/api/files":
                    files = []
                    for p in store.files():  # one damaged or hostile file must not hide the others
                        try:
                            files.append(store.load(p).summary)
                        except (OSError, ValueError, RecursionError, MemoryError):
                            files.append({"name": store.name(p), "ok": False, "unreadable": True})
                    body = {"root": str(store.root), "pinned": bool(store.trusted_keys), "files": files}
                    return self._send(HTTPStatus.OK, json.dumps(body).encode(), "application/json")
                if url.path == "/api/file":
                    path = store.resolve((query.get("name") or [""])[0])
                    if path is None:
                        return self._send(HTTPStatus.NOT_FOUND, b'{"error":"unknown file"}', "application/json")
                    loaded = store.load(path)
                    if self.headers.get("If-None-Match") == loaded.etag:
                        return self._send(HTTPStatus.NOT_MODIFIED, b"", None, etag=loaded.etag)
                    return self._send(HTTPStatus.OK, loaded.payload, "application/json", etag=loaded.etag)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:  # one hostile file, not the server
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR,
                                  json.dumps({"error": str(exc)[:200]}).encode(), "application/json")
            return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")

        def _send(self, status: HTTPStatus, body: bytes, ctype: str | None, etag: str | None = None) -> None:
            self.send_response(status)
            if ctype:
                self.send_header("Content-Type", ctype)
            if etag:
                self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if body and status != HTTPStatus.NOT_MODIFIED:
                self.wfile.write(body)

    return Handler


class DashboardServer(ThreadingHTTPServer):
    request_queue_size = 128  # the default of 5 drops requests in a burst on Linux
    store: EvidenceStore
    key: str
    # On Windows SO_REUSEADDR lets a second server bind a port already in use, and the browser
    # would show the other folder's evidence: there, binding a used port fails instead.
    allow_reuse_address = os.name != "nt"


def create_server(path: str | Path, *, trusted_keys: list[str] | None = None,
                  port: int = 8765, key: str | None = None) -> DashboardServer:
    """Bind on loopback. ``port=0`` picks a free port. ``key`` (random by default) is what data
    requests must carry: it is in the link ``serve`` prints."""
    store = EvidenceStore(path, trusted_keys or [])
    server = DashboardServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    server.key = key or secrets.token_urlsafe(24)
    # The Host check needs the real port, which is only known after binding.
    server.RequestHandlerClass = make_handler(store, server.server_address[1], server.key)
    server.store = store
    return server


def serve(path: str | Path, *, trusted_keys: list[str] | None = None, port: int = 8765,
          open_browser: bool = True) -> None:
    server = create_server(path, trusted_keys=trusted_keys, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/?key={server.key}"
    print(f"Mnestiq dashboard: {url}  (serving {server.store.root}, Ctrl+C to stop)", flush=True)
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
