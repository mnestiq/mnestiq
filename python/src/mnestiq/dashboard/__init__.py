"""Local evidence dashboard.

    mnestiq dashboard ./evidence --trusted-key keys/signing.pub

Serves a single-page dashboard on 127.0.0.1 that reads evidence files from disk,
verifies them with the same verifier as the CLI, and live-updates as agents write.

Containment: binds to loopback only, rejects non-local Host headers (DNS
rebinding), and sends a Content-Security-Policy that forbids the page from
loading or contacting anything except this server.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import deque
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ..verify import verify_file

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
MAX_RECORDS = 20_000   # sent to the browser per file, verification still reads everything
MAX_ERRORS = 1_000


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
        self._sniffed: dict[Path, tuple[int, bool]] = {}
        self._cache: dict[Path, _Loaded] = {}
        self._lock = threading.Lock()

    def files(self) -> list[Path]:
        if self.root.is_file():
            return [self.root]
        if not self.root.is_dir():
            return []
        found = [p for p in self.root.rglob("*.jsonl") if p.is_file() and self._is_evidence(p)]
        return sorted(found, key=lambda p: p.stat().st_mtime_ns, reverse=True)

    def _is_evidence(self, path: Path) -> bool:
        """Only Mnestiq evidence chains. Other JSON-lines files (proxy logs, exports) sit in
        the same folders, and showing them would report them as 'tampered' by mistake."""
        stamp = path.stat().st_mtime_ns
        cached = self._sniffed.get(path)
        if cached and cached[0] == stamp:
            return cached[1]
        verdict = False
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    if raw.strip():
                        first = json.loads(raw[:1_000_000])
                        verdict = isinstance(first, dict) and "spec_version" in first and "chain_id" in first
                        break
        except (OSError, ValueError):
            verdict = False
        self._sniffed[path] = (stamp, verdict)
        return verdict

    def name(self, path: Path) -> str:
        return path.name if self.root.is_file() else path.relative_to(self.root).as_posix()

    def resolve(self, name: str) -> Path | None:
        # Only names we listed ourselves, never a path built from user input.
        return next((p for p in self.files() if self.name(p) == name), None)

    def load(self, path: Path) -> _Loaded:
        st = path.stat()
        stamp = (st.st_mtime_ns, st.st_size)
        with self._lock:
            cached = self._cache.get(path)
            if cached and cached.stamp == stamp:
                return cached
        # Verification covers the whole file. The browser only gets the most recent records.
        report = verify_file(path, self.trusted_keys)
        records: deque[dict] = deque(maxlen=self.max_records)
        total = 0
        with open(path, "rb") as fh:
            for line_no, raw in enumerate(fh, start=1):
                if not raw.strip():
                    continue
                total += 1
                try:
                    rec = json.loads(raw)
                    if not isinstance(rec, dict):
                        raise ValueError
                except ValueError:
                    rec = {"_unparseable": True, "_line": line_no, "_raw": raw[:300].decode("utf-8", "replace")}
                records.append(rec)
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
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        loaded = _Loaded(stamp, summary, payload, '"' + hashlib.sha256(payload).hexdigest()[:32] + '"')
        with self._lock:
            self._cache[path] = loaded
        return loaded


def make_handler(store: EvidenceStore, port: int) -> type[BaseHTTPRequestHandler]:
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
            try:
                if url.path == "/":
                    return self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
                if url.path == "/api/files":
                    files = [store.load(p).summary for p in store.files()]
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
            except OSError as exc:
                return self._send(HTTPStatus.INTERNAL_SERVER_ERROR,
                                  json.dumps({"error": str(exc)}).encode(), "application/json")
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
    store: EvidenceStore


def create_server(path: str | Path, *, trusted_keys: list[str] | None = None,
                  port: int = 8765) -> DashboardServer:
    """Bind on loopback. ``port=0`` picks a free port."""
    store = EvidenceStore(path, trusted_keys or [])
    server = DashboardServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    # The Host check needs the real port, which is only known after binding.
    server.RequestHandlerClass = make_handler(store, server.server_address[1])
    server.store = store
    return server


def serve(path: str | Path, *, trusted_keys: list[str] | None = None, port: int = 8765,
          open_browser: bool = True) -> None:
    server = create_server(path, trusted_keys=trusted_keys, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Mnestiq dashboard: {url}  (serving {server.store.root}; Ctrl+C to stop)")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
