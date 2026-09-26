"""Synthetic authenticated BOLA lab — secure vs vulnerable cross-user access."""

from __future__ import annotations

from agent_lite.skills.authz_bola import LabObservation, LabScenario


def authenticated_bola_secure(host: str = "api.acme-demo.test") -> LabScenario:
    """A→A allowed shape; B→A resource denied."""
    return LabScenario(
        name="auth_bola_secure",
        expected_if_secure="Non-owner blocked",
        owner_identity="user_a",
        object_path="/api/orders/1001",
        observations=[
            LabObservation(
                "user_a", "GET", "/api/orders/1001", host, 200,
                '{"id":1001,"owner":"user_a","email":"a@lab.test","amount":10}',
                "owner_resource",
            ),
            LabObservation(
                "user_b", "GET", "/api/orders/1001", host, 403,
                '{"error":"forbidden"}',
                "cross_user_denied",
            ),
        ],
    )


def authenticated_bola_vulnerable(host: str = "api.acme-demo.test") -> LabScenario:
    body = '{"id":1001,"owner":"user_a","email":"a@lab.test","amount":99}'
    return LabScenario(
        name="auth_bola_vulnerable",
        expected_if_secure="Non-owner blocked",
        owner_identity="user_a",
        object_path="/api/orders/1001",
        observations=[
            LabObservation("user_a", "GET", "/api/orders/1001", host, 200, body, "owner_baseline"),
            LabObservation("user_b", "GET", "/api/orders/1001", host, 200, body, "cross_user_leak"),
        ],
    )


def authenticated_bola_no_identity_signal(host: str = "api.acme-demo.test") -> LabScenario:
    """Single observation — pipeline must not treat as confirmed multi-identity BOLA."""
    return LabScenario(
        name="auth_bola_no_identity",
        expected_if_secure="Need second identity",
        observations=[
            LabObservation(
                "user_a", "GET", "/api/orders/1001", host, 200,
                '{"id":1001,"owner":"user_a","email":"a@lab.test"}',
                "single_identity",
            ),
        ],
    )
