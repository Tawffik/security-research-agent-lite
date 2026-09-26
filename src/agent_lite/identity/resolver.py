"""
Identity (reasoning) vs Credential (runtime secret).

The research engine only sees identity_id.
Credentials are resolved at execute time inside the auth/executor boundary
and must never appear in observations, ledger, evidence, reports, or logs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Identity:
    identity_id: str
    credential_ref: str = ""  # env key prefix, e.g. TEST_USER_A
    role: str = "user"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        # never expose resolved secrets
        return {
            "identity_id": self.identity_id,
            "credential_ref": self.credential_ref,
            "role": self.role,
            "notes": self.notes,
        }


@dataclass
class SessionMaterial:
    """Runtime-only. Not serializable to artifacts."""

    identity_id: str
    headers: dict = field(default_factory=dict)  # e.g. Cookie / Authorization
    cookies: dict = field(default_factory=dict)


class IdentityResolver:
    """
    Resolves credential_ref → SessionMaterial using environment variables.

    Expected pattern (GitHub Actions Secrets):
      TEST_USER_A_EMAIL / TEST_USER_A_PASSWORD
      or TEST_USER_A_COOKIE / TEST_USER_A_TOKEN

    For this milestone we prefer pre-issued session cookie/token when present;
    password-based login is lab-specific and stays inside a lab adapter.
    """

    def __init__(self, identities: dict[str, Identity] | None = None):
        self._identities = identities or {}
        self._sessions: dict[str, SessionMaterial] = {}

    def register(self, identity: Identity) -> None:
        self._identities[identity.identity_id] = identity

    def get(self, identity_id: str) -> Optional[Identity]:
        return self._identities.get(identity_id)

    def resolve_session(self, identity_id: str) -> Optional[SessionMaterial]:
        if identity_id in self._sessions:
            return self._sessions[identity_id]
        ident = self._identities.get(identity_id)
        if not ident or not ident.credential_ref:
            return None
        ref = ident.credential_ref.upper()
        # Prefer token/cookie over password material
        token = os.environ.get(f"{ref}_TOKEN") or os.environ.get(f"{ref}_ACCESS_TOKEN")
        cookie = os.environ.get(f"{ref}_COOKIE") or os.environ.get(f"{ref}_SESSION")
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = cookie
            # keep opaque; do not parse into logs
        if not headers and not cookies:
            # password path is intentionally not auto-logged-in here;
            # lab adapters may inject SessionMaterial after explicit login.
            return None
        sess = SessionMaterial(identity_id=identity_id, headers=headers, cookies=cookies)
        self._sessions[identity_id] = sess
        return sess

    def inject_session(self, identity_id: str, session: SessionMaterial) -> None:
        """Lab/auth adapter only. Material stays in memory."""
        self._sessions[identity_id] = session

    def clear_sessions(self) -> None:
        self._sessions.clear()
