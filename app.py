"""Zero-dependency local web server for the AI SOC Analyst MVP."""

from __future__ import annotations

import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from phishing_analyzer import analyze_email_with_report
from soc_analyzer import analyze_with_report


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
MAX_REQUEST_BYTES = 512_000


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


class Handler(BaseHTTPRequestHandler):
    server_version = "AISOCAnalyst/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            self._send_file(STATIC_ROOT / "index.html")
            return
        if self.path.startswith("/static/"):
            relative = unquote(self.path.removeprefix("/static/").split("?", 1)[0])
            self._send_file(STATIC_ROOT / relative)
            return
        if self.path.startswith("/samples/"):
            relative = unquote(self.path.removeprefix("/samples/").split("?", 1)[0])
            self._send_file(ROOT / "samples" / relative)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path not in {"/api/analyze", "/api/analyze-email"}:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_REQUEST_BYTES:
            self._send_json({"error": "Input is too large for this MVP."}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        try:
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body)
            content = str(payload.get("content", "")).strip()
            use_llm = bool(payload.get("use_llm", True))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "Invalid JSON request."}, HTTPStatus.BAD_REQUEST)
            return

        if not content:
            self._send_json({"error": "No log or report content was provided."}, HTTPStatus.BAD_REQUEST)
            return

        try:
            if self.path == "/api/analyze-email":
                result = analyze_email_with_report(content, use_llm=use_llm)
            else:
                result = analyze_with_report(content, use_llm=use_llm)
        except Exception as exc:  # noqa: BLE001 - server should return useful local error details.
            self._send_json({"error": f"Analysis failed: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_json(result)

    def _send_file(self, path: Path) -> None:
        try:
            resolved = path.resolve()
            allowed_roots = [STATIC_ROOT.resolve(), (ROOT / "samples").resolve()]
            if not any(resolved == root or root in resolved.parents for root in allowed_roots):
                self._send_json({"error": "Forbidden"}, HTTPStatus.FORBIDDEN)
                return
            if not resolved.exists() or not resolved.is_file():
                self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
                return
            content_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
            data = resolved.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        except OSError as exc:
            self._send_json({"error": f"File error: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    load_dotenv()
    port = int(os.getenv("PORT", "8787"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"AI SOC Analyst running at http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
