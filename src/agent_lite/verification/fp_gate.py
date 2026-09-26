"""Ten-question false-positive gate — evidence-backed, not confidence theater."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class GateAnswer:
    question: str
    answer: bool
    note: str = ""


@dataclass
class GateResult:
    status: str  # PASS | BLOCK | NEED_MORE_EVIDENCE
    answers: list[GateAnswer] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "answers": [asdict(a) for a in self.answers],
        }


class FalsePositiveGate:
    def evaluate(
        self,
        *,
        in_scope: bool,
        action_authorized: bool,
        observation_reproducible: bool,
        actor_resource_understood: bool,
        security_property_violated: bool,
        alternatives_considered: bool,
        not_public_or_shared: bool,
        evidence_sufficient: bool,
        impact_supported: bool,
        not_duplicate: bool,
    ) -> GateResult:
        checks = [
            ("1_in_scope", in_scope, "Target must be in scope"),
            ("2_action_authorized", action_authorized, "Action must be authorized"),
            ("3_reproducible", observation_reproducible, "Observation must be reproducible"),
            ("4_actor_resource", actor_resource_understood, "Actor/resource relationship required"),
            ("5_property_violated", security_property_violated, "Concrete security property violation"),
            ("6_alternatives", alternatives_considered, "Benign explanations considered"),
            ("7_not_public_shared", not_public_or_shared, "Not merely public/shared behavior"),
            ("8_evidence", evidence_sufficient, "Evidence sufficient"),
            ("9_impact", impact_supported, "Impact supported by evidence"),
            ("10_not_duplicate", not_duplicate, "Not duplicate/unsupported escalation"),
        ]
        answers = [GateAnswer(q, a, n) for q, a, n in checks]
        failed = [a for a in answers if not a.answer]
        if any(a.question.startswith(("1_", "2_")) and not a.answer for a in answers):
            return GateResult("BLOCK", answers, "safety_or_scope_failed")
        if not evidence_sufficient or not observation_reproducible:
            return GateResult("NEED_MORE_EVIDENCE", answers, "insufficient_evidence")
        if failed:
            return GateResult("BLOCK", answers, "fp_checks_failed:" + ",".join(a.question for a in failed))
        return GateResult("PASS", answers, "all_checks_passed")
