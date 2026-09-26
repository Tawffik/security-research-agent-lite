"""
Temp mailbox provider — configurable HTTP endpoint, no hard-coded disposable sites.

Expected generic API (configurable base URL):
  POST {base}/mailboxes           → {id, email}
  GET  {base}/mailboxes/{id}/messages → [{id, from, subject, body, received_at}]
  DELETE {base}/mailboxes/{id}    → optional

Env:
  TEMP_MAIL_API_KEY
  TEMP_MAIL_BASE_URL  (required for real use)
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from agent_lite.auth.mailbox import MailboxMessage, OtpResult, extract_otp_from_text


class TempMailboxProvider:
    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.api_key = (api_key or os.environ.get("TEMP_MAIL_API_KEY") or "").strip()
        self.base_url = (
            base_url or os.environ.get("TEMP_MAIL_BASE_URL") or ""
        ).strip().rstrip("/")
        self.timeout = timeout
        self._boxes: dict[str, dict[str, Any]] = {}

    def available(self) -> bool:
        return bool(self.base_url)

    def _request(
        self, method: str, path: str, *, body: Optional[dict] = None
    ) -> tuple[int, Any]:
        if not self.base_url:
            return 0, {"message": "missing_temp_mail_base_url"}
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                code = resp.status
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:400]
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
        if not self.base_url:
            return {
                "status": "MAILBOX_UNAVAILABLE",
                "identity_id": identity_id,
                "provider": "temp",
                "reason": "missing_temp_mail_base_url",
            }
        code, data = self._request("POST", "/mailboxes", body={"label": identity_id})
        if code not in (200, 201) or not isinstance(data, dict):
            return {
                "status": "MAILBOX_UNAVAILABLE",
                "identity_id": identity_id,
                "provider": "temp",
                "reason": f"http_{code}",
            }
        mid = str(data.get("id") or data.get("mailbox_id") or "")
        email = str(data.get("email") or data.get("email_address") or "")
        meta = {
            "status": "ready",
            "provider": "temp",
            "mailbox_id": mid,
            "mailbox_reference": mid,
            "email_address": email,
            "identity_id": identity_id,
            "created_at": str(data.get("created_at") or ""),
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
        mid = box["mailbox_id"]
        interval = max(0.5, timeout_seconds / max(1, max_poll_attempts))
        for _ in range(max(1, max_poll_attempts)):
            code, data = self._request("GET", f"/mailboxes/{mid}/messages")
            items = data if isinstance(data, list) else (data.get("messages") if isinstance(data, dict) else [])
            if code == 200 and isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    sender = str(item.get("from") or item.get("sender") or "")
                    if sender_hint and sender_hint.lower() not in sender.lower():
                        continue
                    return MailboxMessage(
                        message_id=str(item.get("id") or ""),
                        sender=sender,
                        subject=str(item.get("subject") or ""),
                        body=str(item.get("body") or item.get("text") or ""),
                        received_at=time.time(),
                        related_identity=identity_id,
                    )
            time.sleep(interval)
        return None

    def extract_otp(
        self, message: MailboxMessage, *, expected_pattern: str = r"\b(\d{6})\b"
    ) -> OtpResult:
        return extract_otp_from_text(message.body, pattern=expected_pattern)

    def destroy_mailbox(self, identity_id: str) -> dict[str, Any]:
        box = self._boxes.get(identity_id)
        if not box:
            return {"status": "ok", "detail": "none"}
        mid = box.get("mailbox_id") or ""
        if mid:
            self._request("DELETE", f"/mailboxes/{mid}")
        self._boxes.pop(identity_id, None)
        return {"status": "ok", "detail": "destroyed"}
