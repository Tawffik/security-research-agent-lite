"""
Lab fixtures provide environment + raw observations only.
They do NOT encode research verdicts for the engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class LabObservation:
    identity: str
    method: str
    path: str
    host: str
    status: int
    body: str
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "status": self.status,
            "body": self.body,
            "notes": self.notes,
        }


@dataclass
class LabScenario:
    """Controlled environment. No final_verdict field."""

    name: str
    observations: list
    expected_if_secure: str = ""
    # policy hint for *environment* ownership only — not a verdict
    owner_identity: str = "user_a"
    object_path: str = "/api/orders/1001"


def bola_positive_lab(host: str = "api.acme-demo.test") -> LabScenario:
    """Environment where non-owner receives private fields (ground truth for tests only)."""
    return LabScenario(
        name="lab_env_cross_identity_private_fields",
        expected_if_secure="Non-owner denied or non-private",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200,
                           '{"id":1001,"owner":"user_a","amount":42.0,"email":"a@example.test"}'),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 200,
                           '{"id":1001,"owner":"user_a","amount":42.0,"email":"a@example.test"}',
                           "non-owner response"),
        ],
    )


def bola_negative_secure(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_env_ownership_enforced",
        expected_if_secure="Non-owner blocked",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200, '{"id":1001,"owner":"user_a"}'),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 403, '{"error":"forbidden"}'),
        ],
    )


def bola_negative_public(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_env_public_resource",
        expected_if_secure="Public by design",
        object_path="/api/catalog/item/5",
        observations=[
            LabObservation("user_a", "GET", "/api/catalog/item/5", host, 200,
                           '{"id":5,"visibility":"public","name":"widget"}'),
            LabObservation("user_b", "GET", "/api/catalog/item/5", host, 200,
                           '{"id":5,"visibility":"public","name":"widget"}'),
        ],
    )


def bola_negative_shared(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_env_shared_acl",
        expected_if_secure="Shared ACL permits both",
        object_path="/api/docs/shared-9",
        observations=[
            LabObservation("user_a", "GET", "/api/docs/shared-9", host, 200,
                           '{"id":"shared-9","acl":["user_a","user_b"],"title":"notes"}'),
            LabObservation("user_b", "GET", "/api/docs/shared-9", host, 200,
                           '{"id":"shared-9","acl":["user_a","user_b"],"title":"notes"}'),
        ],
    )


def bola_ambiguous_status_only(host: str = "api.acme-demo.test") -> LabScenario:
    """Both get 200 but no private/owner fields — false correlation trap."""
    return LabScenario(
        name="lab_env_ambiguous_status_only",
        expected_if_secure="Insufficient evidence for authz violation",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200, '{"id":1001,"status":"ok"}'),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 200, '{"id":1001,"status":"ok"}'),
        ],
    )


# --- Observation parsers (research-side heuristics on RAW body, not verdict injectors) ---

def body_private_fields(body: str) -> bool:
    b = (body or "").lower()
    return any(k in b for k in ("email", "amount", "ssn", "phone", "address"))


def body_public_marker(body: str) -> bool:
    b = body or ""
    return '"visibility":"public"' in b.replace(" ", "") or '"visibility": "public"' in b


def body_shared_acl(body: str) -> bool:
    b = body or ""
    return '"acl"' in b.lower() and ("user_a" in b and "user_b" in b)


def body_owner_marker(body: str) -> str | None:
    import re
    m = re.search(r'"owner"\s*:\s*"([^"]+)"', body or "")
    return m.group(1) if m else None
