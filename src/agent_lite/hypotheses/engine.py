"""Deterministic hypothesis engine — observation → property → suspected violation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from agent_lite.target.context import TargetContext


@dataclass
class Hypothesis:
    hypothesis_id: str
    target: str
    security_property: str
    claim: str
    expected_behavior: str
    suspected_violation: str
    required_identity: str
    relevant_resource: str
    evidence_required: list[str] = field(default_factory=list)
    competing_explanations: list[str] = field(default_factory=list)
    proposed_experiment: str = ""
    risk: str = "low"
    budget: float = 0.3
    status: str = "open"
    provenance: str = "deterministic_authz"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HypothesisEngine:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._n = 0

    def generate(self, ctx: TargetContext) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        if not ctx.multi_identity:
            return hyps
        for ep in ctx.object_endpoints:
            method = str(ep.get("method") or "GET")
            path = str(ep.get("path") or "")
            # Skip pure health/public markers
            if path in ("/health", "/") or "catalog" in path.lower():
                # public catalog may still get a weak hyp — better: skip for BOLA primary
                if "catalog" in path.lower():
                    continue
            self._n += 1
            hid = f"H-{self._n:03d}"
            resource = "object"
            if ctx.resources:
                resource = str(ctx.resources[0].get("name") or "object")
            hyps.append(
                Hypothesis(
                    hypothesis_id=hid,
                    target=f"{method} {path} @ {ctx.primary_host}",
                    security_property="Only the authorized owner may access the object resource",
                    claim=f"Non-owner may access {path} object without ownership binding",
                    expected_behavior="Non-owner receives 403/404 or empty non-sensitive denial",
                    suspected_violation="Missing object-level authorization (BOLA/IDOR)",
                    required_identity="two authenticated identities (owner + non-owner)",
                    relevant_resource=resource,
                    evidence_required=[
                        "owner_baseline_response",
                        "non_owner_response",
                        "identity_proof",
                        "ownership_marker_or_denial",
                    ],
                    competing_explanations=[
                        "Resource is intentionally public",
                        "Resource is shared via ACL by design",
                        "Role grants broader access than ownership",
                        "Response is cached/shared without private fields",
                    ],
                    proposed_experiment=(
                        "Cross-identity differential: request same object id as owner then non-owner; "
                        "compare status + sensitive fields; do not rely on status alone"
                    ),
                    risk="low" if method == "GET" else "medium",
                    budget=0.25,
                )
            )
        return hyps
