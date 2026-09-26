"""
Local synthetic HTTP BOLA server for T2 pipeline integration tests.

Real TCP + HTTP. Behavior selected by scenario name.
Identity is conveyed via Cookie: sid=<identity_id>
No answer-key headers; engine sees only status + body.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse


SCENARIOS = {
    "positive": {
        "path": "/api/orders/1001",
        "user_a": (200, {"id": 1001, "owner": "user_a", "amount": 42.0, "email": "a@example.test"}),
        "user_b": (200, {"id": 1001, "owner": "user_a", "amount": 42.0, "email": "a@example.test"}),
    },
    "secure": {
        "path": "/api/orders/1001",
        "user_a": (200, {"id": 1001, "owner": "user_a"}),
        "user_b": (403, {"error": "forbidden"}),
    },
    "public": {
        "path": "/api/catalog/item/5",
        "user_a": (200, {"id": 5, "visibility": "public", "name": "widget"}),
        "user_b": (200, {"id": 5, "visibility": "public", "name": "widget"}),
    },
    "shared": {
        "path": "/api/docs/shared-9",
        "user_a": (200, {"id": "shared-9", "acl": ["user_a", "user_b"], "title": "notes"}),
        "user_b": (200, {"id": "shared-9", "acl": ["user_a", "user_b"], "title": "notes"}),
    },
    "ambiguous": {
        "path": "/api/orders/1001",
        "user_a": (200, {"id": 1001, "status": "ok"}),
        "user_b": (200, {"id": 1001, "status": "ok"}),
    },
}


def _identity_from_cookie(header: str) -> str:
    # Cookie: sid=user_a
    for part in (header or "").split(";"):
        part = part.strip()
        if part.startswith("sid="):
            return part[4:].strip()
    return "anonymous"


class _Handler(BaseHTTPRequestHandler):
    scenario_name: str = "positive"

    def log_message(self, fmt: str, *args) -> None:  # quiet tests
        return

    def do_GET(self) -> None:
        sc = SCENARIOS.get(self.scenario_name) or SCENARIOS["positive"]
        path = urlparse(self.path).path
        if path != sc["path"]:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"not_found"}')
            return
        ident = _identity_from_cookie(self.headers.get("Cookie", ""))
        if ident in ("user_a", "user_b"):
            status, body = sc[ident]
        else:
            status, body = 401, {"error": "unauthorized"}
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class BolaLocalServer:
    """Context manager: starts ThreadingHTTPServer on 127.0.0.1:0."""

    def __init__(self, scenario: str = "positive"):
        self.scenario = scenario
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.host = "127.0.0.1"
        self.port = 0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def object_path(self) -> str:
        return SCENARIOS[self.scenario]["path"]

    def __enter__(self) -> "BolaLocalServer":
        handler = type(f"Handler_{self.scenario}", (_Handler,), {"scenario_name": self.scenario})
        self._httpd = ThreadingHTTPServer((self.host, 0), handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
