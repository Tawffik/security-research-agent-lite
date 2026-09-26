"""Researcher → Skeptic → Referee. Referee decides on evidence, not LLM confidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class Verdict:
    status: str  # CONFIRMED | REJECTED | NEED_MORE_EVIDENCE
    reason: str
    researcher_claim: str = ""
    skeptic_notes: str = ""
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VerificationLoop:
    def run(
        self,
        *,
        suggests_authz_issue: bool,
        gate_status: str,
        evidence_ids: list[str],
        claim: str,
        non_owner_status: int,
        body_has_private_fields: bool,
        body_public_marker: bool,
        body_shared_acl: bool,
    ) -> Verdict:
        if gate_status == "BLOCK":
            return Verdict("REJECTED", "fp_gate_blocked", claim, "Gate blocked candidate", evidence_ids)
        if gate_status == "NEED_MORE_EVIDENCE":
            return Verdict("NEED_MORE_EVIDENCE", "fp_gate_need_more", claim, "Incomplete evidence", evidence_ids)

        # Skeptic: try to kill finding
        skeptic = []
        if body_public_marker:
            skeptic.append("public visibility marker present")
        if body_shared_acl:
            skeptic.append("shared ACL lists multiple actors")
        if non_owner_status >= 400:
            skeptic.append("non-owner denied — ownership may hold")
        if not body_has_private_fields and non_owner_status < 400:
            skeptic.append("200 without private fields — weak impact")

        if body_public_marker or body_shared_acl:
            return Verdict(
                "REJECTED",
                "benign_public_or_shared",
                claim,
                "; ".join(skeptic),
                evidence_ids,
            )

        if suggests_authz_issue and non_owner_status < 400 and body_has_private_fields and evidence_ids:
            return Verdict(
                "CONFIRMED",
                "cross_identity_private_access",
                claim,
                "Skeptic checked public/shared/role; markers absent; private fields present",
                evidence_ids,
            )

        if non_owner_status >= 400:
            return Verdict(
                "REJECTED",
                "ownership_enforced",
                claim,
                "; ".join(skeptic) or "non-owner denied",
                evidence_ids,
            )

        return Verdict("NEED_MORE_EVIDENCE", "ambiguous", claim, "; ".join(skeptic) or "unclear", evidence_ids)
