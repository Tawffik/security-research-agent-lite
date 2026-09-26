"""Safe serialization: never persist secrets in observations/artifacts/logs."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlparse

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-session-id",
    "api-key",
    "apikey",
}

SENSITIVE_BODY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "access_token",
    "refresh_token",
    "session_id",
    "sessionid",
    "api_key",
    "apikey",
    "client_secret",
)


def _is_sensitive_header(name: str) -> bool:
    n = (name or "").lower().strip()
    if n in SENSITIVE_HEADER_NAMES:
        return True
    if n.startswith("x-") and any(k in n for k in ("token", "auth", "session", "key", "secret")):
        return True
    return False


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not headers:
        return out
    for k, v in headers.items():
        if _is_sensitive_header(str(k)):
            out[str(k)] = "[REDACTED]"
        else:
            out[str(k)] = str(v)[:500]
    return out


def redact_body_metadata(body: str | None, max_store: int = 4096) -> dict[str, Any]:
    """Return size/hash-like metadata and a truncated safe preview; never raw secrets."""
    raw = body or ""
    size = len(raw)
    lower = raw.lower()
    has_sensitive = any(m in lower for m in SENSITIVE_BODY_MARKERS)
    preview = raw[:max_store]
    if has_sensitive:
        # conservative: strip likely secret-looking substrings from preview
        for m in SENSITIVE_BODY_MARKERS:
            if m in lower:
                preview = preview.replace(m, "[REDACTED_MARKER]")
                # also common JSON patterns
                preview = preview.replace(f'"{m}"', '"[REDACTED_KEY]"')
    return {
        "size_bytes": size,
        "truncated": size > max_store,
        "preview": preview[:max_store],
        "sensitive_markers_detected": has_sensitive,
    }


def safe_body_for_storage(body: str | None, max_store: int = 4096) -> str:
    meta = redact_body_metadata(body, max_store=max_store)
    return meta["preview"]


def parse_host_path(url: str) -> tuple[str, str, str]:
    """Return (scheme, host, path)."""
    p = urlparse(url or "")
    host = p.hostname or ""
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return (p.scheme or "").lower(), host.lower(), path
