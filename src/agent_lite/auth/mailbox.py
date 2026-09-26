"""MailboxProvider — OTP extraction without LLM; content is UNTRUSTED_DATA."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from agent_lite.content_isolation.sanitizer import wrap_untrusted


@dataclass
class MailboxMessage:
    message_id: str
    sender: str
    subject: str
    body: str  # untrusted
    received_at: float
    related_identity: str = ""


@dataclass
class OtpResult:
    status: str  # ok | OTP_NOT_FOUND | OTP_EXPIRED | AMBIGUOUS_MESSAGE | MAILBOX_UNAVAILABLE | INVALID_OTP_FORMAT | MAILBOX_UNSUPPORTED
    # otp value is runtime-only — never serialize via to_public_dict
    _otp: str = ""
    detail: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {"status": self.status, "detail": self.detail}


class MailboxProvider(Protocol):
    def create_mailbox(self, identity_id: str) -> dict[str, Any]:
        ...

    def get_mailbox(self, identity_id: str) -> Optional[dict[str, Any]]:
        ...

    def wait_for_message(
        self,
        identity_id: str,
        *,
        timeout_seconds: float = 5.0,
        max_poll_attempts: int = 5,
        sender_hint: str = "",
    ) -> Optional[MailboxMessage]:
        ...

    def extract_otp(self, message: MailboxMessage, *, expected_pattern: str = r"\b(\d{6})\b") -> OtpResult:
        ...


def extract_otp_from_text(body: str, *, pattern: str = r"\b(\d{6})\b") -> OtpResult:
    """Deterministic OTP parse — never follows instructions in email body."""
    wrap_untrusted(body or "", source="email")
    if not body:
        return OtpResult(status="OTP_NOT_FOUND", detail="empty")
    matches = re.findall(pattern, body)
    if not matches:
        return OtpResult(status="OTP_NOT_FOUND", detail="no_match")
    if len(set(matches)) > 1:
        return OtpResult(status="AMBIGUOUS_MESSAGE", detail=f"count={len(matches)}")
    otp = matches[0]
    if not re.fullmatch(r"\d{4,8}", otp):
        return OtpResult(status="INVALID_OTP_FORMAT", detail="bad_format")
    return OtpResult(status="ok", _otp=otp, detail="extracted")


class MockMailboxProvider:
    """In-memory mailbox for CI. OTP never written to public artifacts."""

    def __init__(self, *, reject_disposable: bool = False):
        self.reject_disposable = reject_disposable
        self._boxes: dict[str, dict[str, Any]] = {}
        self._messages: dict[str, list[MailboxMessage]] = {}
        self._otp_codes: dict[str, str] = {}  # identity → pending otp
        self._msg_n = 0

    def create_mailbox(self, identity_id: str) -> dict[str, Any]:
        if self.reject_disposable:
            return {"status": "MAILBOX_UNSUPPORTED", "identity_id": identity_id}
        ref = f"mailbox-{identity_id}"
        self._boxes[identity_id] = {
            "mailbox_reference": ref,
            "status": "ready",
            "identity_id": identity_id,
        }
        self._messages.setdefault(identity_id, [])
        return dict(self._boxes[identity_id])

    def get_mailbox(self, identity_id: str) -> Optional[dict[str, Any]]:
        return self._boxes.get(identity_id)

    def inject_otp_email(
        self,
        identity_id: str,
        otp: str,
        *,
        sender: str = "noreply@lab.test",
        subject: str = "Your code",
        extra_body: str = "",
        age_seconds: float = 0.0,
    ) -> None:
        self._msg_n += 1
        body = f"Your verification code is {otp}. {extra_body}"
        msg = MailboxMessage(
            message_id=f"m{self._msg_n}",
            sender=sender,
            subject=subject,
            body=body,
            received_at=time.time() - age_seconds,
            related_identity=identity_id,
        )
        self._messages.setdefault(identity_id, []).append(msg)
        self._otp_codes[identity_id] = otp

    def wait_for_message(
        self,
        identity_id: str,
        *,
        timeout_seconds: float = 5.0,
        max_poll_attempts: int = 5,
        sender_hint: str = "",
    ) -> Optional[MailboxMessage]:
        if identity_id not in self._boxes:
            return None
        # Bounded poll — mock returns immediately if message present
        for _ in range(max(1, max_poll_attempts)):
            msgs = self._messages.get(identity_id) or []
            for m in reversed(msgs):
                if sender_hint and sender_hint not in m.sender:
                    continue
                return m
            time.sleep(min(0.01, timeout_seconds / max(1, max_poll_attempts)))
        return None

    def extract_otp(self, message: MailboxMessage, *, expected_pattern: str = r"\b(\d{6})\b") -> OtpResult:
        # expiry: messages older than 300s
        if time.time() - message.received_at > 300:
            return OtpResult(status="OTP_EXPIRED", detail="stale_message")
        return extract_otp_from_text(message.body, pattern=expected_pattern)
