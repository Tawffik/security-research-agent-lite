"""
BrowserSessionProvider contract.

Browser is a bootstrap/session helper for authorized labs.
It does NOT detect vulnerabilities and does NOT replace HttpExecutor.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class LabBootstrapContext:
    """Structured lab bootstrap result. No raw passwords in serializable form."""

    provider: str
    lab_id: str = ""
    lab_url: str = ""
    target_origin: str = ""
    known_object_path: str = ""
    identity_context: dict[str, str] = field(default_factory=dict)  # identity_id → role
    session_reference: dict[str, str] = field(
        default_factory=dict
    )  # identity_id → opaque ref only (not secret material)
    authorization_state: str = "unknown"  # authorized | unauthorized | blocked
    bootstrap_status: str = "pending"  # ok | blocked | error
    block_reasons: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    notes: str = ""
    # Runtime-only session headers (never written by to_public_dict)
    _session_headers: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        """Safe for artifacts/logs — excludes session header material."""
        return {
            "provider": self.provider,
            "lab_id": self.lab_id,
            "lab_url": self.lab_url,
            "target_origin": self.target_origin,
            "known_object_path": self.known_object_path,
            "identity_context": dict(self.identity_context),
            "session_reference": dict(self.session_reference),  # opaque refs only
            "authorization_state": self.authorization_state,
            "bootstrap_status": self.bootstrap_status,
            "block_reasons": list(self.block_reasons),
            "evidence_refs": list(self.evidence_refs),
            "notes": self.notes,
        }


@dataclass
class BrowserActionResult:
    status: str  # ok | blocked | error
    action: str = ""
    block_reasons: list[str] = field(default_factory=list)
    detail: str = ""
    # Untrusted page text may appear only as data
    page_excerpt_untrusted: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BrowserSessionProvider(Protocol):
    """
    Minimal operations. Implementations must fail closed on scope/auth failures.
    """

    def bootstrap_lab(self, engagement: Any) -> LabBootstrapContext:
        """Open/prepare authorized lab context. No vulnerability verdict."""
        ...

    def establish_session(
        self, engagement: Any, identity_id: str, context: LabBootstrapContext
    ) -> BrowserActionResult:
        """Establish session for one identity; material stays in provider memory."""
        ...

    def collect_lab_context(self, engagement: Any) -> LabBootstrapContext:
        """Return known object path + origins from engagement / prior bootstrap."""
        ...

    def close_session(self) -> BrowserActionResult:
        """Clear in-memory sessions."""
        ...
