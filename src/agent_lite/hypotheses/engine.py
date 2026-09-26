"""Hypothesis from Opportunity + Invariant — not from lab answer keys."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from agent_lite.opportunities.engine import Opportunity
from agent_lite.security.invariants import InvariantRegistry
from agent_lite.target.context import TargetContext


@dataclass
class Hypothesis:
    hypothesis_id: str
    opportunity_id: str
    target: str
    security_property: str
    claim: str
    expected_behavior: str
    suspected_violation: str
    required_identity: str
    relevant_resource: str
    evidence_required: list = field(default_factory=list)
    competing_explanations: list = field(default_factory=list)
    proposed_experiment: str = ""
    risk: str = "low"
    budget: float = 0.3
    status: str = "open"
    provenance: str = "hypothesis_engine"
    invariant_id: str = "INV-AUTHZ-001"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HypothesisEngine:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._n = 0
        self.invariants = InvariantRegistry()

    def from_opportunities(self, opps: list, ctx: TargetContext) -> list:
        inv = self.invariants.authz_object()
        hyps = []
        for opp in opps:
            if opp.status != "open":
                continue
            if "multi_identity" not in opp.signals:
                continue
            self._n += 1
            resource = opp.related_resources[0] if opp.related_resources else "object"
            hyps.append(
                Hypothesis(
                    hypothesis_id=f"H-{self._n:03d}",
                    opportunity_id=opp.opportunity_id,
                    target=opp.target,
                    security_property=inv.statement,
                    claim=(
                        f"Observation path may violate {inv.invariant_id}: "
                        f"non-owner access to protected object via {opp.target}"
                    ),
                    expected_behavior=(
                        "Non-owner is denied (4xx) or receives no private owner-bound fields"
                    ),
                    suspected_violation=f"Possible violation of {inv.invariant_id}",
                    required_identity="owner + non-owner authenticated identities",
                    relevant_resource=resource,
                    evidence_required=[
                        "owner_baseline_response",
                        "non_owner_response",
                        "identity_binding",
                        "ownership_or_denial_marker",
                    ],
                    competing_explanations=[
                        "Resource is intentionally public",
                        "Resource is shared via ACL by design",
                        "Role grants broader access than ownership",
                        "Response lacks private fields (false correlation on status)",
                        "Cache/shared edge artifact without authz failure",
                    ],
                    proposed_experiment=(
                        "Discriminating cross-identity request on same object id; "
                        "compare status AND sensitive fields; single pair not ID spray"
                    ),
                    risk="low",
                    budget=0.25,
                    invariant_id=inv.invariant_id,
                )
            )
        return hyps
