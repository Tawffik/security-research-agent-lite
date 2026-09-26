"""MailSlurp mailbox provider — optional real inbox; secrets via env only."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from agent_lite.auth.mailbox import MailboxMessage, OtpResult, extract_otp_from_text


class MailSlurpMailboxProvider:
    """
    Real provider when MAILSLURP_API_KEY is set.
    API: https://api.mailslurp.com (x-api-key header).
    Never logs API key or OTP.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = "https://api.mailslurp.com",
        timeout: float = 30.0,
    ):
        self.api_key = (api_key or os.environ.get("MAILSLURP_API_KEY") or "").strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._boxes: dict[str, dict[str, Any]] = {}

    def available(self) -> bool:
        return bool(self.api_key)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[dict] = None,
        query: str = "",
    ) -> tuple[int, Any]:
        if not self.api_key:
            return 401, {"message": "missing_api_key"}
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                code = resp.status
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            try:
                return e.code, json.loads(detail)
            except Exception:  # noqa: BLE001
                return e.code, {"message": detail}
        except Exception as e:  # noqa: BLE001
            return 0, {"message": type(e).__name__}
        if not raw:
            return code, {}
        try:
            return code, json.loads(raw)
        except json.JSONDecodeError:
            return code, {"raw": raw[:200]}

    def create_mailbox(self, identity_id: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "status": "MAILBOX_UNAVAILABLE",
                "identity_id": identity_id,
                "provider": "mailslurp",
                "reason": "missing_mailslurp_api_key",
            }
        code, data = self._request("POST", "/inboxes", body={})
        if code not in (200, 201) or not isinstance(data, dict):
            return {
                "status": "MAILBOX_UNAVAILABLE",
                "identity_id": identity_id,
                "provider": "mailslurp",
                "reason": f"http_{code}",
            }
        inbox_id = str(data.get("id") or "")
        email = str(data.get("emailAddress") or data.get("email") or "")
        meta = {
            "status": "ready",
            "provider": "mailslurp",
            "mailbox_id": inbox_id,
            "mailbox_reference": inbox_id,
            "email_address": email,
            "identity_id": identity_id,
            "created_at": str(data.get("createdAt") or ""),
        }
        self._boxes[identity_id] = meta
        return dict(meta)

    def get_mailbox(self, identity_id: str) -> Optional[dict[str, Any]]:
        return self._boxes.get(identity_id)

    def wait_for_message(
        self,
        identity_id: str,
        *,
        timeout_seconds: float = 60.0,
        max_poll_attempts: int = 12,
        sender_hint: str = "",
    ) -> Optional[MailboxMessage]:
        box = self._boxes.get(identity_id)
        if not box or not box.get("mailbox_id"):
            return None
        inbox_id = box["mailbox_id"]
        interval = max(0.5, timeout_seconds / max(1, max_poll_attempts))
        for _ in range(max(1, max_poll_attempts)):
            code, data = self._request(
                "GET",
                f"/inboxes/{inbox_id}/emails",
                query="size=5&sort=DESC",
            )
            if code == 200 and isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    sender = str(
                        item.get("from")
                        or (item.get("sender") or {}).get("emailAddress")
                        or ""
                    )
                    if sender_hint and sender_hint.lower() not in sender.lower():
                        continue
                    eid = str(item.get("id") or "")
                    # fetch body
                    bcode, body_data = self._request("GET", f"/emails/{eid}")
                    body = ""
                    subject = str(item.get("subject") or "")
                    if bcode == 200 and isinstance(body_data, dict):
                        body = str(
                            body_data.get("body")
                            or body_data.get("textBody")
                            or body_data.get("htmlBody")
                            or ""
                        )
                        subject = str(body_data.get("subject") or subject)
                    return MailboxMessage(
                        message_id=eid,
                        sender=sender,
                        subject=subject,
                        body=body,
                        received_at=time.time(),
                        related_identity=identity_id,
                    )
            time.sleep(interval)
        return None

    def extract_otp(
        self, message: MailboxMessage, *, expected_pattern: str = r"\b(\d{6})\b"
    ) -> OtpResult:
        return extract_otp_from_text(message.body, pattern=expected_pattern)
