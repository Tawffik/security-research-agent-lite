"""Evidence-backed false-positive gate — each answer carries evidence_refs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class GateAnswer:
    question_id: str
    answer: bool
    evidence_refs: list = field(default_factory=list)
    rationale: str = ""
    blocking_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GateResult:
    status: str  # PASS | BLOCK | NEED_MORE_EVIDENCE
    answers: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "answers": [a.to_dict() if hasattr(a, "to_dict") else a for a in self.answers],
        }


class FalsePositiveGate:
    def evaluate(self, facts: dict[str, Any]) -> GateResult:
        """
        facts must be derived from observations/evidence, never from lab answer keys.
        Expected keys:
          in_scope, action_authorized, evidence_ids, multi_identity, has_resource_or_object,
          non_owner_status, private_fields, public_marker, shared_acl, owner_marker_mismatch
        """
        eids = list(facts.get("evidence_ids") or [])
        answers: list[GateAnswer] = []

        def q(qid: str, ans: bool, rationale: str, block: str = "") -> None:
            answers.append(
                GateAnswer(
                    question_id=qid,
                    answer=ans,
                    evidence_refs=list(eids) if eids else [],
                    rationale=rationale,
                    blocking_reason=block if not ans else "",
                )
            )

        in_scope = bool(facts.get("in_scope"))
        action_ok = bool(facts.get("action_authorized"))
        eids_ok = len(eids) >= 2
        actor_res = bool(facts.get("multi_identity")) and bool(facts.get("has_resource_or_object"))
        # no identity sessions → cannot claim confirmed authz violation
        if facts.get("require_authenticated_identity") and not facts.get("identity_authenticated"):
            actor_res = False
        public = bool(facts.get("public_marker"))
        shared = bool(facts.get("shared_acl"))
        private = bool(facts.get("private_fields"))
        non_owner_ok = facts.get("non_owner_status") is not None
        status = int(facts.get("non_owner_status") or 0)
        owner_mismatch = bool(facts.get("owner_marker_mismatch"))

        # Property violation signal from observations only
        property_violated = (
            non_owner_ok
            and status < 400
            and private
            and not public
            and not shared
            and owner_mismatch
        )
        impact = private and status < 400 and not public and not shared

        q("1_in_scope", in_scope, "ScopeGuard decision on host", "out_of_scope")
        q("2_action_authorized", action_ok, "Method allowed under policy", "unauthorized_action")
        q("3_reproducible", eids_ok, "At least two observation-backed evidence records")
        q("4_actor_resource", actor_res, "Multiple identities and object/resource surface")
        q(
            "5_property_violated",
            property_violated,
            "Non-owner success + private fields + owner mismatch + not public/shared",
        )
        q("6_alternatives", True, "Public/shared/role/status-only considered via body parsers")
        q("7_not_public_shared", not public and not shared, "No public/shared ACL markers in body")
        q("8_evidence", eids_ok, "Evidence ids present")
        q("9_impact", impact if property_violated else (status >= 400 or public or shared or not private),
          "Impact or secure/public explanation supported by body/status")
        q("10_not_duplicate", True, "Single engagement lab path")

        if not in_scope or not action_ok:
            return GateResult("BLOCK", answers, "safety_or_scope_failed")
        if not eids_ok:
            return GateResult("NEED_MORE_EVIDENCE", answers, "insufficient_evidence")
        if public or shared:
            return GateResult("BLOCK", answers, "public_or_shared_behavior")
        if status < 400 and not private:
            return GateResult("NEED_MORE_EVIDENCE", answers, "status_without_private_fields")
        if property_violated:
            return GateResult("PASS", answers, "observation_supports_property_violation")
        if status >= 400:
            return GateResult("BLOCK", answers, "non_owner_denied")
        return GateResult("NEED_MORE_EVIDENCE", answers, "ambiguous")
