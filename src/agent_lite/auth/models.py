"""Auth/session models — no secrets in serializable forms."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Explicit auth state machine
class AuthState:
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    AUTHENTICATING = "AUTHENTICATING"
    OTP_REQUIRED = "OTP_REQUIRED"
    WAITING_FOR_OTP = "WAITING_FOR_OTP"
    OTP_RECEIVED = "OTP_RECEIVED"
    VERIFYING_OTP = "VERIFYING_OTP"
    AUTHENTICATED = "AUTHENTICATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    AUTH_FAILED = "AUTH_FAILED"
    WAITING_FOR_IDENTITY = "WAITING_FOR_IDENTITY"
    WAITING_FOR_AUTH = "WAITING_FOR_AUTH"


@dataclass
class TestIdentity:
    identity_id: str
    role: str = "user"
    label: str = ""
    email_reference: str = ""  # opaque ref, not address in public dict if sensitive
    credential_reference: str = ""
    allowed_targets: list[str] = field(default_factory=list)
    authentication_method: str = "browser"  # password | browser | browser_otp
    mailbox_reference: str = ""
    status: str = "registered"
    session_reference: str = ""
    provenance: str = "config"

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "role": self.role,
            "label": self.label or self.identity_id,
            "email_reference": self.email_reference,
            "credential_reference": self.credential_reference,
            "allowed_targets": list(self.allowed_targets),
            "authentication_method": self.authentication_method,
            "mailbox_reference": self.mailbox_reference,
            "status": self.status,
            "session_reference": self.session_reference,
            "provenance": self.provenance,
        }


@dataclass
class AuthChallenge:
    challenge_id: str
    identity_id: str
    target: str
    challenge_type: str = "EMAIL_OTP"  # OTP | EMAIL_OTP
    status: str = "pending"
    created_at: str = field(default_factory=_now)
    expires_at: str = ""
    provider: str = "mock"

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SessionHandle:
    """Public session handle — secrets stay inside provider memory."""

    session_id: str
    identity_id: str
    target: str
    status: str = "active"  # active | expired | revoked
    created_at: str = field(default_factory=_now)
    expires_at: str = ""
    provider: str = "mock"
    auth_method: str = "browser_otp"

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuthTraceEvent:
    step: str
    identity_id: str = ""
    status: str = ""
    detail: str = ""
    at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_session_id() -> str:
    return f"sess_{uuid4().hex[:12]}"


def new_challenge_id() -> str:
    return f"chal_{uuid4().hex[:12]}"
