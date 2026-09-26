"""
PortSwigger lab adapter.

Does NOT replace HttpExecutor.
Does NOT embed vulnerability verdicts.
Does NOT invent a generic login framework.

Flow:
  EngagementConfig (authorized)
    → ActionRequest (owner + non-owner, one known object)
    → HttpExecutor
    → HttpObservation
    → (caller feeds into ResearchPipeline.run_http or consumes observations)

Fail closed when authorization conditions are missing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from agent_lite.http.engagement import EngagementConfig
from agent_lite.http.executor import HttpExecutor
from agent_lite.http.models import ActionRequest, HttpObservation


@dataclass
class AdapterResult:
    """Structured adapter outcome. Never contains credentials or lab answer keys."""

    status: str  # READY | BLOCKED | EXECUTED
    engagement_id: str = ""
    block_reasons: list[str] = field(default_factory=list)
    action_requests: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PortSwiggerAdapter:
    """
    Controlled observation source for an explicitly configured PortSwigger engagement.

    Construction of ActionRequests is the primary job.
    Execution always goes through the injected HttpExecutor.
    """

    def __init__(self, engagement: EngagementConfig, executor: Optional[HttpExecutor] = None):
        self.engagement = engagement
        self.executor = executor

    def validate(self) -> AdapterResult:
        """Authorization gate. No network."""
        errs = self.engagement.authorization_errors()
        if self.engagement.engagement_type not in ("portswigger", "generic", "synthetic"):
            errs = list(errs) + [f"unsupported_engagement_type:{self.engagement.engagement_type}"]
        # PortSwigger path requires explicit type when mode is live_lab
        if self.engagement.mode == "live_lab" and self.engagement.engagement_type != "portswigger":
            if "engagement_type_mismatch" not in errs:
                errs.append("live_lab_requires_type_portswigger")
        if errs:
            return AdapterResult(
                status="BLOCKED",
                engagement_id=self.engagement.engagement_id,
                block_reasons=errs,
                notes="fail_closed_authorization",
            )
        return AdapterResult(
            status="READY",
            engagement_id=self.engagement.engagement_id,
            notes="authorization_ok",
        )

    def build_bola_action_requests(
        self, *, method: str = "GET"
    ) -> AdapterResult:
        """
        One known object, two identities. No enumeration.
        Returns ActionRequest dicts (no secrets) or BLOCKED.
        """
        gate = self.validate()
        if gate.status == "BLOCKED":
            return gate

        method = (method or "GET").upper()
        if method not in [m.upper() for m in self.engagement.allowed_methods]:
            return AdapterResult(
                status="BLOCKED",
                engagement_id=self.engagement.engagement_id,
                block_reasons=["method_not_allowed"],
                notes="fail_closed_method",
            )

        base = self.engagement.base_url.rstrip("/")
        path = self.engagement.object_path
        if not path.startswith("/"):
            path = "/" + path
        url = base + path
        exp_id = "EXP-PS-BOLA-001"

        reqs = [
            ActionRequest(
                method=method,
                url=url,
                identity_id=self.engagement.owner_identity,
                experiment_id=exp_id,
                purpose="owner_baseline",
                timeout_seconds=self.engagement.budget.timeout_seconds,
            ),
            ActionRequest(
                method=method,
                url=url,
                identity_id=self.engagement.non_owner_identity,
                experiment_id=exp_id,
                purpose="non_owner_probe",
                timeout_seconds=self.engagement.budget.timeout_seconds,
            ),
        ]
        # Serialize without secrets (ActionRequest has no credential fields)
        return AdapterResult(
            status="READY",
            engagement_id=self.engagement.engagement_id,
            action_requests=[r.to_dict() for r in reqs],
            notes="bola_differential_requests_built",
        )

    def execute_bola_differential(self) -> AdapterResult:
        """
        Build requests and execute via HttpExecutor.
        Observations only — no CONFIRMED/REJECTED verdict here.
        """
        built = self.build_bola_action_requests()
        if built.status == "BLOCKED":
            return built
        if self.executor is None:
            return AdapterResult(
                status="BLOCKED",
                engagement_id=self.engagement.engagement_id,
                block_reasons=["missing_http_executor"],
                notes="adapter_requires_executor",
                action_requests=built.action_requests,
            )

        observations: list[dict] = []
        for req_dict in built.action_requests:
            req = ActionRequest(
                method=req_dict["method"],
                url=req_dict["url"],
                headers=req_dict.get("headers") or {},
                query=req_dict.get("query") or {},
                body=req_dict.get("body"),
                identity_id=req_dict.get("identity_id") or "",
                timeout_seconds=float(req_dict.get("timeout_seconds") or 15),
                experiment_id=req_dict.get("experiment_id") or "",
                purpose=req_dict.get("purpose") or "",
            )
            obs: HttpObservation = self.executor.execute(req)
            observations.append(obs.to_dict())
            if obs.blocked:
                return AdapterResult(
                    status="BLOCKED",
                    engagement_id=self.engagement.engagement_id,
                    block_reasons=[obs.block_reason or obs.scope_decision or "executor_blocked"],
                    action_requests=built.action_requests,
                    observations=observations,
                    notes="executor_fail_closed",
                )

        return AdapterResult(
            status="EXECUTED",
            engagement_id=self.engagement.engagement_id,
            action_requests=built.action_requests,
            observations=observations,
            notes="observations_only_no_verdict",
        )
