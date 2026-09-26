"""IdentityProvider — provision/consume test identities without secrets in public API."""

from __future__ import annotations

import os
from typing import Any, Optional, Protocol

from agent_lite.auth.models import TestIdentity


class IdentityProvider(Protocol):
    def provision_identity(self, identity_id: str, **kwargs: Any) -> TestIdentity:
        ...

    def get_identity(self, identity_id: str) -> Optional[TestIdentity]:
        ...

    def validate_identity(self, identity_id: str) -> tuple[bool, str]:
        ...

    def release_identity(self, identity_id: str) -> None:
        ...


class ExistingTestIdentityProvider:
    """
    Loads Identity A/B from config/env refs.
    Env examples: TEST_IDENTITY_A_EMAIL (optional), credential_ref for secrets.
    """

    def __init__(self, identities: Optional[dict[str, TestIdentity]] = None):
        self._ids: dict[str, TestIdentity] = dict(identities or {})

    def provision_identity(self, identity_id: str, **kwargs: Any) -> TestIdentity:
        if identity_id in self._ids:
            return self._ids[identity_id]
        role = str(kwargs.get("role") or "user")
        cred = str(kwargs.get("credential_reference") or f"TEST_IDENTITY_{identity_id.upper()}")
        ident = TestIdentity(
            identity_id=identity_id,
            role=role,
            label=str(kwargs.get("label") or identity_id),
            email_reference=str(kwargs.get("email_reference") or f"mailbox-{identity_id}"),
            credential_reference=cred,
            allowed_targets=list(kwargs.get("allowed_targets") or []),
            authentication_method=str(kwargs.get("authentication_method") or "browser_otp"),
            mailbox_reference=str(kwargs.get("mailbox_reference") or f"mailbox-{identity_id}"),
            status="provisioned",
            provenance="existing_test_identity",
        )
        self._ids[identity_id] = ident
        return ident

    def get_identity(self, identity_id: str) -> Optional[TestIdentity]:
        return self._ids.get(identity_id)

    def validate_identity(self, identity_id: str) -> tuple[bool, str]:
        ident = self._ids.get(identity_id)
        if not ident:
            return False, "MISSING_CREDENTIAL"
        # Optional: check env has something for credential_ref
        ref = (ident.credential_reference or "").upper()
        if ref and not (
            os.environ.get(f"{ref}_PASSWORD")
            or os.environ.get(f"{ref}_TOKEN")
            or os.environ.get(f"{ref}_COOKIE")
            or ident.authentication_method.startswith("browser")
        ):
            # For mock browser_otp we still allow without env
            if ident.authentication_method == "browser_otp":
                return True, "ok_mock_or_browser"
            return False, "MISSING_CREDENTIAL"
        return True, "ok"

    def release_identity(self, identity_id: str) -> None:
        self._ids.pop(identity_id, None)

    def list_public(self) -> list[dict[str, Any]]:
        return [i.to_public_dict() for i in self._ids.values()]


class MockIdentityProvider(ExistingTestIdentityProvider):
    """Two standard test users for CI."""

    def __init__(self) -> None:
        super().__init__()
        self.provision_identity(
            "user_a",
            role="owner",
            label="test-user-a",
            authentication_method="browser_otp",
        )
        self.provision_identity(
            "user_b",
            role="non_owner",
            label="test-user-b",
            authentication_method="browser_otp",
        )
