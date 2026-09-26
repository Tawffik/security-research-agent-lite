"""
T2: Synthetic HTTP BOLA matrix via HttpExecutor.

Positive  → evidence supports CONFIRMED path (private fields to non-owner)
Secure    → non-owner denied → REJECTED
Public    → explicit public → REJECTED
Shared    → ACL shared → REJECTED
Ambiguous → 200 without private evidence → never CONFIRMED
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.models import ActionRequest
from agent_lite.identity.resolver import Identity, IdentityResolver, SessionMaterial
from agent_lite.scope.guard import ScopeGuard
from agent_lite.skills.authz_bola import (
    body_owner_marker,
    body_private_fields,
    body_public_marker,
    body_shared_acl,
)
from agent_lite.verification.fp_gate import FalsePositiveGate
from agent_lite.verification.loop import VerificationLoop


HOST = "lab.example.test"
PATH = "/api/orders/1001"


def _executor(tmp_path: Path, transport):
    scope_data = {
        "in_scope": [{"host": HOST, "methods": ["GET"]}],
        "out_of_scope": [],
        "allow_mutations": False,
    }
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.dump(scope_data))
    idr = IdentityResolver()
    for iid in ("user_a", "user_b"):
        idr.register(Identity(identity_id=iid, credential_ref=f"TEST_{iid.upper()}"))
        idr.inject_session(iid, SessionMaterial(identity_id=iid, headers={"Cookie": f"sid={iid}"}))
    return HttpExecutor(
        scope=ScopeGuard.from_file(p),
        budget=BudgetGuard(BudgetState(max_requests=10)),
        identities=idr,
        transport=transport,
    )


def _run_differential(ex: HttpExecutor, owner_body: str, non_owner_status: int, non_owner_body: str):
    def transport(req: ActionRequest, hdrs: dict):
        # identity encoded in Cookie value for mock
        cookie = (hdrs or {}).get("Cookie", "")
        if "user_a" in cookie:
            return 200, {"Content-Type": "application/json"}, owner_body, 5.0
        return non_owner_status, {"Content-Type": "application/json"}, non_owner_body, 5.0

    ex.transport = transport
    o_a = ex.execute(
        ActionRequest(
            method="GET",
            url=f"https://{HOST}{PATH}",
            identity_id="user_a",
            experiment_id="EXP-BOLA",
            purpose="owner_baseline",
        )
    )
    o_b = ex.execute(
        ActionRequest(
            method="GET",
            url=f"https://{HOST}{PATH}",
            identity_id="user_b",
            experiment_id="EXP-BOLA",
            purpose="non_owner_probe",
        )
    )
    assert o_a.blocked is False and o_b.blocked is False
    facts = {
        "in_scope": True,
        "action_authorized": True,
        "evidence_ids": [o_a.observation_id, o_b.observation_id],
        "multi_identity": True,
        "has_resource_or_object": True,
        "non_owner_status": o_b.response_status,
        "private_fields": body_private_fields(o_b.response_body),
        "public_marker": body_public_marker(o_b.response_body),
        "shared_acl": body_shared_acl(o_b.response_body),
        "owner_marker_mismatch": bool(
            body_owner_marker(o_b.response_body)
            and body_owner_marker(o_b.response_body) != "user_b"
        ),
    }
    gate = FalsePositiveGate().evaluate(facts)
    verdict = VerificationLoop().run(
        claim="INV-AUTHZ-001 under test from HTTP observations",
        gate_status=gate.status,
        evidence_ids=facts["evidence_ids"],
        facts=facts,
    )
    return o_a, o_b, gate, verdict, facts


def test_positive_bola_confirmed(tmp_path):
    body = '{"id":1001,"owner":"user_a","amount":42.0,"email":"a@example.test"}'
    ex = _executor(tmp_path, None)
    _, _, gate, verdict, facts = _run_differential(ex, body, 200, body)
    assert facts["private_fields"] is True
    assert verdict.status == "CONFIRMED"


def test_secure_rejected(tmp_path):
    owner = '{"id":1001,"owner":"user_a"}'
    non = '{"error":"forbidden"}'
    ex = _executor(tmp_path, None)
    _, _, _, verdict, facts = _run_differential(ex, owner, 403, non)
    assert facts["non_owner_status"] >= 400
    assert verdict.status == "REJECTED"


def test_public_rejected(tmp_path):
    body = '{"id":5,"visibility":"public","name":"widget"}'
    ex = _executor(tmp_path, None)
    _, _, _, verdict, facts = _run_differential(ex, body, 200, body)
    assert facts["public_marker"] is True
    assert verdict.status == "REJECTED"


def test_shared_rejected(tmp_path):
    body = '{"id":1001,"owner":"user_a","shared_with":["user_b"],"acl":"shared"}'
    ex = _executor(tmp_path, None)
    _, _, _, verdict, facts = _run_differential(ex, body, 200, body)
    assert facts["shared_acl"] is True
    assert verdict.status == "REJECTED"


def test_ambiguous_never_confirmed(tmp_path):
    # 200 but no private fields / owner marker usable as proof
    body = '{"id":1001,"status":"ok"}'
    ex = _executor(tmp_path, None)
    _, _, gate, verdict, facts = _run_differential(ex, body, 200, body)
    assert facts["private_fields"] is False
    assert verdict.status != "CONFIRMED"
    assert verdict.status in ("REJECTED", "NEED_MORE_EVIDENCE")
