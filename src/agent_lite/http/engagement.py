"""Engagement configuration loader for bounded live/synthetic HTTP runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.identity.resolver import Identity, IdentityResolver
from agent_lite.scope.guard import ScopeGuard


@dataclass
class EngagementConfig:
    engagement_id: str
    mode: str  # synthetic | live_lab
    base_url: str
    scope_rules: dict
    identities: dict[str, Identity]
    budget: BudgetState
    object_path: str = "/api/orders/1001"
    allowed_schemes: set[str] = field(default_factory=lambda: {"https", "http"})
    allowed_methods: list[str] = field(default_factory=lambda: ["GET"])
    raw: dict = field(default_factory=dict)

    def build_scope(self) -> ScopeGuard:
        return ScopeGuard(self.scope_rules)

    def build_budget(self) -> BudgetGuard:
        return BudgetGuard(self.budget)

    def build_identities(self) -> IdentityResolver:
        r = IdentityResolver()
        for ident in self.identities.values():
            r.register(ident)
        return r


def load_engagement(path: Union[str, Path]) -> EngagementConfig:
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    eng = data.get("engagement") or {}
    target = data.get("target") or {}
    scope = data.get("scope") or {}
    idents_raw = data.get("identities") or {}
    exp = data.get("experiment") or {}

    # Normalize scope rules to ScopeGuard shape
    in_scope = []
    for h in scope.get("allowed_hosts") or []:
        if isinstance(h, str):
            in_scope.append({"host": h, "methods": exp.get("allowed_methods") or ["GET"]})
        else:
            in_scope.append(
                {
                    "host": h.get("host"),
                    "methods": h.get("methods") or exp.get("allowed_methods") or ["GET"],
                }
            )
    scope_rules = {
        "in_scope": in_scope,
        "out_of_scope": scope.get("out_of_scope") or [],
        "allow_mutations": bool(scope.get("allow_mutations", False)),
    }

    identities: dict[str, Identity] = {}
    for iid, meta in idents_raw.items():
        if isinstance(meta, str):
            identities[iid] = Identity(identity_id=iid, credential_ref=meta)
        else:
            identities[iid] = Identity(
                identity_id=iid,
                credential_ref=str(meta.get("credential_ref") or ""),
                role=str(meta.get("role") or "user"),
            )

    budget = BudgetState(
        max_requests=int(exp.get("max_requests", 10)),
        max_experiments=int(exp.get("max_experiments", 2)),
        max_response_bytes=int(exp.get("max_response_bytes", 500_000)),
        timeout_seconds=float(exp.get("timeout_seconds", 15)),
        min_delay_seconds=float(exp.get("min_delay_seconds", 0)),
    )

    schemes = set(scope.get("allowed_schemes") or ["https", "http"])
    return EngagementConfig(
        engagement_id=str(eng.get("id") or "eng_unknown"),
        mode=str(eng.get("mode") or "synthetic"),
        base_url=str(target.get("base_url") or ""),
        scope_rules=scope_rules,
        identities=identities,
        budget=budget,
        object_path=str(exp.get("object_path") or "/api/orders/1001"),
        allowed_schemes=schemes,
        allowed_methods=list(exp.get("allowed_methods") or ["GET"]),
        raw=data,
    )
