"""Researcher builds case; Skeptic attacks; Referee decides on evidence only."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ResearcherCase:
    claim: str
    evidence_ids: list
    supporting_facts: list
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SkepticReport:
    challenges: list
    benign_explanations_found: list
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    status: str  # CONFIRMED | REJECTED | NEED_MORE_EVIDENCE
    reason: str
    researcher_claim: str = ""
    skeptic_notes: str = ""
    evidence_ids: list = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Researcher:
    def build(self, *, claim: str, evidence_ids: list, facts: dict) -> ResearcherCase:
        supporting = []
        if facts.get("owner_marker_mismatch"):
            supporting.append("owner marker indicates different owner than requester")
        if facts.get("private_fields") and int(facts.get("non_owner_status") or 0) < 400:
            supporting.append("non-owner received private fields")
        return ResearcherCase(claim=claim, evidence_ids=list(evidence_ids), supporting_facts=supporting)


class Skeptic:
    def challenge(self, facts: dict, researcher: ResearcherCase) -> SkepticReport:
        challenges = []
        benign = []
        if facts.get("public_marker"):
            benign.append("public visibility marker")
            challenges.append("behavior may be intentional public read")
        if facts.get("shared_acl"):
            benign.append("shared ACL lists both actors")
            challenges.append("authorization relationship may exist")
        if int(facts.get("non_owner_status") or 0) >= 400:
            benign.append("non-owner denied")
            challenges.append("ownership boundary may hold")
        if int(facts.get("non_owner_status") or 0) < 400 and not facts.get("private_fields"):
            challenges.append("200 without private fields — false correlation risk")
            benign.append("status-only similarity")
        if not researcher.evidence_ids:
            challenges.append("no evidence ids")
        return SkepticReport(challenges=challenges, benign_explanations_found=benign)


class Referee:
    def decide(self, gate_status: str, researcher: ResearcherCase, skeptic: SkepticReport, facts: dict) -> Verdict:
        eids = list(researcher.evidence_ids)
        if gate_status == "BLOCK":
            reason = "fp_gate_blocked"
            if skeptic.benign_explanations_found:
                reason = "benign:" + ",".join(skeptic.benign_explanations_found)
            if int(facts.get("non_owner_status") or 0) >= 400:
                reason = "ownership_enforced"
            return Verdict("REJECTED", reason, researcher.claim, "; ".join(skeptic.challenges), eids)
        if gate_status == "NEED_MORE_EVIDENCE":
            return Verdict(
                "NEED_MORE_EVIDENCE",
                "insufficient_or_ambiguous",
                researcher.claim,
                "; ".join(skeptic.challenges),
                eids,
            )
        # PASS gate
        if skeptic.benign_explanations_found:
            return Verdict("REJECTED", "skeptic_benign", researcher.claim, "; ".join(skeptic.challenges), eids)
        if researcher.supporting_facts and eids:
            return Verdict(
                "CONFIRMED",
                "evidence_supports_invariant_violation",
                researcher.claim,
                "Skeptic found no public/shared/denial explanation",
                eids,
            )
        return Verdict("NEED_MORE_EVIDENCE", "gate_pass_but_weak_case", researcher.claim, "; ".join(skeptic.challenges), eids)


class VerificationLoop:
    def __init__(self) -> None:
        self.researcher = Researcher()
        self.skeptic = Skeptic()
        self.referee = Referee()

    def run(self, *, claim: str, gate_status: str, evidence_ids: list, facts: dict) -> Verdict:
        case = self.researcher.build(claim=claim, evidence_ids=evidence_ids, facts=facts)
        sk = self.skeptic.challenge(facts, case)
        return self.referee.decide(gate_status, case, sk, facts)
