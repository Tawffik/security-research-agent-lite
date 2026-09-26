"""Minimal localhost HTTP app for Playwright browser_lab (stdlib only)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


HTML_LOGIN = """<!DOCTYPE html><html><body>
<h1>Synthetic Lab Login</h1>
<p>user={user}</p>
<form method="GET" action="/auth">
<input type="hidden" name="user" value="{user}"/>
<button id="login" type="submit">Login</button>
</form>
</body></html>"""

HTML_HOME = """<!DOCTYPE html><html><body>
<h1>Authenticated</h1>
<p id="who">identity={user}</p>
<a href="/resource/a">Resource A</a>
<a href="/resource/b">Resource B</a>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        return

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/login":
            user = (qs.get("user") or ["anon"])[0]
            body = HTML_LOGIN.format(user=user).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/auth":
            user = (qs.get("user") or ["anon"])[0]
            body = HTML_HOME.format(user=user).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", f"lab_sid={user}; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path.startswith("/resource/"):
            body = b"<html><body>resource ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def serve(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    return HTTPServer((host, port), Handler)
