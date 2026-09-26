"""Authorization/BOLA skill logic — candidates + evidence, not auto-findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LabObservation:
    identity: str
    method: str
    path: str
    host: str
    status: int
    body: str
    notes: str = ""


@dataclass
class LabScenario:
    name: str
    observations: list[LabObservation]
    suggests_authz_issue: bool
    expected_if_secure: str = ""


def bola_positive_lab(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_bola_positive",
        suggests_authz_issue=True,
        expected_if_secure="Non-owner denied",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200,
                           '{"id":1001,"owner":"user_a","amount":42.0,"email":"a@example.test"}'),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 200,
                           '{"id":1001,"owner":"user_a","amount":42.0,"email":"a@example.test"}',
                           "non-owner received private fields"),
        ],
    )


def bola_negative_secure(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_bola_secure",
        suggests_authz_issue=False,
        expected_if_secure="Non-owner blocked",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200, '{"id":1001,"owner":"user_a"}'),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 403, '{"error":"forbidden"}'),
        ],
    )


def bola_negative_public(host: str = "api.acme-demo.test") -> LabScenario:
    return LabScenario(
        name="lab_public_resource",
        suggests_authz_issue=False,
        expected_if_secure="Public by design",
        observations=[
            LabObservation("user_a", "GET", "/api/catalog/item/5", host, 200,
                           '{"id":5,"visibility":"public","name":"widget"}'),
            LabObservation("user_b", "GET", "/api/catalog/item/5", host, 200,
                           '{"id":5,"visibility":"public","name":"widget"}'),
        ],
    )


def body_private_fields(body: str) -> bool:
    b = (body or "").lower()
    return any(k in b for k in ("email", "amount", "ssn", "phone", "address", "owner"))


def body_public_marker(body: str) -> bool:
    return "visibility\":\"public" in (body or "").replace(" ", "") or '"visibility": "public"' in (body or "")


def body_shared_acl(body: str) -> bool:
    b = body or ""
    return '"acl"' in b.lower() and ("user_a" in b and "user_b" in b)
