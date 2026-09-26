"""Engagement configuration loader for bounded live/synthetic HTTP runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union
from urllib.parse import urlparse

import yaml

from agent_lite.budget.guard import BudgetGuard, BudgetState
from agent_lite.identity.resolver import Identity, IdentityResolver
from agent_lite.scope.guard import ScopeGuard


@dataclass
class EngagementConfig:
    engagement_id: str
    mode: str  # synthetic | live_lab
    engagement_type: str  # generic | portswigger | ...
    authorized: bool
    base_url: str
    scope_rules: dict
    identities: dict[str, Identity]
    budget: BudgetState
    object_path: str = "/api/orders/1001"
    allowed_schemes: set[str] = field(default_factory=lambda: {"https", "http"})
    allowed_methods: list[str] = field(default_factory=lambda: ["GET"])
    owner_identity: str = "user_a"
    non_owner_identity: str = "user_b"
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

    def authorization_errors(self) -> list[str]:
        """Fail-closed checks. Empty list = may proceed to ActionRequest construction."""
        errors: list[str] = []
        if not self.engagement_id or self.engagement_id == "eng_unknown":
            errors.append("missing_engagement_id")
        if not self.authorized:
            errors.append("engagement_not_authorized")
        if not self.base_url:
            errors.append("missing_base_url")
        else:
            parsed = urlparse(self.base_url)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower()
            if scheme not in self.allowed_schemes:
                errors.append("scheme_not_allowed")
            if not host:
                errors.append("invalid_host")
            else:
                # Host must appear in scope in_scope rules
                matched = False
                for rule in self.scope_rules.get("in_scope") or []:
                    pat = rule if isinstance(rule, str) else str(rule.get("host") or "")
                    pat = pat.lower().strip()
                    if pat.startswith("*."):
                        if host.endswith(pat[1:]) or host == pat[2:]:
                            matched = True
                    elif host == pat:
                        matched = True
                if not matched:
                    errors.append("host_not_in_scope")
        if not self.object_path:
            errors.append("missing_object_path")
        if not self.identities:
            errors.append("missing_identities")
        if self.owner_identity not in self.identities:
            errors.append("missing_owner_identity")
        if self.non_owner_identity not in self.identities:
            errors.append("missing_non_owner_identity")
        methods = [m.upper() for m in self.allowed_methods]
        if "GET" not in methods and not methods:
            errors.append("no_allowed_methods")
        return errors

    def is_authorized_for_execution(self) -> bool:
        return len(self.authorization_errors()) == 0


def load_engagement(path: Union[str, Path]) -> EngagementConfig:
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    eng = data.get("engagement") or {}
    target = data.get("target") or {}
    scope = data.get("scope") or {}
    idents_raw = data.get("identities") or {}
    exp = data.get("experiment") or {}

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
    owner = str(exp.get("owner_identity") or "user_a")
    non_owner = str(exp.get("non_owner_identity") or "user_b")
    # Prefer explicit identity keys if present
    if identities and owner not in identities:
        owner = next(iter(identities.keys()))
    if identities and non_owner not in identities:
        keys = list(identities.keys())
        non_owner = keys[1] if len(keys) > 1 else keys[0]

    return EngagementConfig(
        engagement_id=str(eng.get("id") or "eng_unknown"),
        mode=str(eng.get("mode") or "synthetic"),
        engagement_type=str(eng.get("type") or "generic").lower(),
        authorized=bool(eng.get("authorized", False)),
        base_url=str(target.get("base_url") or ""),
        scope_rules=scope_rules,
        identities=identities,
        budget=budget,
        object_path=str(exp.get("object_path") or "/api/orders/1001"),
        allowed_schemes=schemes,
        allowed_methods=list(exp.get("allowed_methods") or ["GET"]),
        owner_identity=owner,
        non_owner_identity=non_owner,
        raw=data,
    )
