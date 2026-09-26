"""
Evidence-driven research pipeline.

Modes:
  synthetic (default) — LabScenario injects observations (no sockets).
  http — ActionRequest → HttpExecutor → HttpObservation → same evidence path.

Verdicts always come from evidence + gate + R/S/R, never from scenario labels.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol, Union

from agent_lite.content_isolation.sanitizer import wrap_untrusted
from agent_lite.evidence.store import EvidenceStore
from agent_lite.experiments.model import Experiment
from agent_lite.hypotheses.engine import HypothesisEngine
from agent_lite.ledger.sqlite_ledger import SQLiteLedger
from agent_lite.opportunities.engine import OpportunityEngine
from agent_lite.recon.adapter import ReconAdapter
from agent_lite.reporting.report import build_report
from agent_lite.episode.model import build_episode
from agent_lite.skills.registry import SkillRegistry
from agent_lite.scope.guard import ScopeDecision, ScopeGuard
from agent_lite.skills.authz_bola import (
    LabObservation,
    LabScenario,
    body_owner_marker,
    body_private_fields,
    body_public_marker,
    body_shared_acl,
    bola_positive_lab,
)
from agent_lite.target.context import TargetContext, build_target_context
from agent_lite.verification.fp_gate import FalsePositiveGate
from agent_lite.verification.loop import VerificationLoop, Verdict


class _ObsLike(Protocol):
    identity: str
    method: str
    path: str
    host: str
    status: int
    body: str


@dataclass
class RunResult:
    engagement_id: str
    run_id: str
    scope_allowed: bool
    mode: str = "synthetic"
    opportunities: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    experiments: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    gate_status: str = ""
    verdict: Optional[Verdict] = None
    report: Optional[dict] = None
    limitations: list = field(default_factory=list)
    summary: str = ""
    facts: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "run_id": self.run_id,
            "scope_allowed": self.scope_allowed,
            "mode": self.mode,
            "opportunities": [o.to_dict() for o in self.opportunities],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "experiments": [e.to_dict() for e in self.experiments],
            "evidence_ids": self.evidence_ids,
            "gate_status": self.gate_status,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "report": self.report,
            "limitations": self.limitations,
            "summary": self.summary,
            "facts": self.facts,
        }


class ResearchPipeline:
    def __init__(
        self,
        *,
        engagement_id: str,
        scope_path: Union[str, Path],
        artifacts_dir: Optional[Path] = None,
        run_id: Optional[str] = None,
        llm_provider: Any = None,
        require_llm: bool = False,
    ):
        self.engagement_id = engagement_id
        self.run_id = run_id or f"run_{uuid.uuid4().hex[:10]}"
        self.scope = ScopeGuard.from_file(scope_path)
        self.artifacts_dir = Path(artifacts_dir or "artifacts") / engagement_id
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = SQLiteLedger(self.artifacts_dir / "ledger.db", self.run_id, engagement_id)
        self.evidence = EvidenceStore(engagement_id)
        self.llm_provider = llm_provider
        self.require_llm = require_llm
        self.llm_notes: list[str] = []

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def run(
        self,
        recon_path: Union[str, Path],
        scenario: Optional[LabScenario] = None,
    ) -> RunResult:
        """Synthetic path (default). Observations come from LabScenario — no sockets."""
        limitations = [
            "Lab/fixture observations — not live HTTP",
            "Verdict derived from observations only (no scenario answer key)",
        ]
        self.ledger.record("start", "ok", f"{self.engagement_id}:synthetic")

        recon, ctx, scope_block = self._prepare(recon_path)
        if scope_block is not None:
            return scope_block

        opps, hyps = self._opportunities_and_hypotheses(ctx)
        hyps = self._llm_enrich(ctx, hyps)
        scenario = scenario or bola_positive_lab(ctx.primary_host)
        for obs in scenario.observations:
            wrap_untrusted(obs.body, source="lab_response")

        return self._investigate(
            mode="synthetic",
            recon=recon,
            ctx=ctx,
            opps=opps,
            hyps=hyps,
            observations=list(scenario.observations),
            limitations=limitations,
            evidence_source="lab_observation",
            evidence_provenance="synthetic_lab_observation",
        )

    def run_http(
        self,
        recon_path: Union[str, Path],
        *,
        base_url: str,
        object_path: str,
        executor: Any,
        owner_identity: str = "user_a",
        non_owner_identity: str = "user_b",
        method: str = "GET",
    ) -> RunResult:
        """
        HTTP mode: real ActionRequest → HttpExecutor → HttpObservation.

        executor must be a configured HttpExecutor (scope/budget/identities already set).
        Credentials stay inside the executor boundary; pipeline only sees identity_id.
        """
        from agent_lite.http.models import ActionRequest
        from agent_lite.http.models import HttpObservation

        limitations = [
            "HTTP mode: observations from HttpExecutor (real or injected transport)",
            "Verdict derived from observations only (no scenario answer key)",
            "Credentials never enter evidence/ledger/report",
        ]
        self.ledger.record("start", "ok", f"{self.engagement_id}:http")

        recon, ctx, scope_block = self._prepare(recon_path)
        if scope_block is not None:
            return scope_block

        opps, hyps = self._opportunities_and_hypotheses(ctx)
        hyps = self._llm_enrich(ctx, hyps)
        hyp = hyps[0] if hyps else None
        exp_id = "EXP-HTTP-001"
        url = base_url.rstrip("/") + object_path

        exp = Experiment(
            experiment_id=exp_id,
            hypothesis_ids=[hyp.hypothesis_id] if hyp else [],
            objective="Discriminate INV-AUTHZ-001 via owner vs non-owner same object over HTTP",
            action=f"{method} {object_path} as {owner_identity} then {non_owner_identity}",
            expected_observation="Non-owner denied or lacks private owner-bound fields",
            risk="low",
            cost=0.4,
        )

        observations: list[LabObservation] = []
        http_obs_list: list[HttpObservation] = []
        blocked = False
        block_reason = ""

        for ident, purpose in (
            (owner_identity, "owner_baseline"),
            (non_owner_identity, "non_owner_probe"),
        ):
            req = ActionRequest(
                method=method,
                url=url,
                identity_id=ident,
                experiment_id=exp_id,
                purpose=purpose,
                timeout_seconds=10.0,
            )
            hobs: HttpObservation = executor.execute(req)
            http_obs_list.append(hobs)
            self.ledger.record(
                "http_action",
                "blocked" if hobs.blocked else "ok",
                f"{ident}:{hobs.response_status}:{hobs.block_reason or hobs.scope_decision}",
            )
            if hobs.blocked:
                blocked = True
                block_reason = hobs.block_reason or hobs.scope_decision
                break
            wrap_untrusted(hobs.response_body, source="http_response")
            observations.append(
                LabObservation(
                    identity=hobs.identity_id or ident,
                    method=hobs.method,
                    path=hobs.path.split("?")[0] if hobs.path else object_path,
                    host=hobs.host,
                    status=hobs.response_status,
                    body=hobs.response_body,
                    notes=f"http_obs={hobs.observation_id}",
                )
            )

        if blocked or len(observations) < 2:
            exp.result = "blocked"
            exp.scope_decision = block_reason or "incomplete_observations"
            exp.request_count = sum(1 for h in http_obs_list if not h.blocked)
            self.ledger.finish("blocked")
            result = RunResult(
                engagement_id=self.engagement_id,
                run_id=self.run_id,
                scope_allowed=True,
                mode="http",
                opportunities=opps,
                hypotheses=hyps,
                experiments=[exp],
                gate_status="BLOCK",
                limitations=limitations,
                summary=f"EXPERIMENT_BLOCKED: {exp.scope_decision}",
            )
            self._write_artifacts(result, ctx, recon, mode="http")
            return result

        exp.scope_decision = "ALLOW"
        exp.result = "executed"
        exp.request_count = len(observations)
        exp.target_interactions = len(observations)
        exp.actual_observation = "; ".join(f"{o.identity}:{o.status}" for o in observations)
        exp.information_gained = "cross_identity_http_status_and_body"

        return self._investigate(
            mode="http",
            recon=recon,
            ctx=ctx,
            opps=opps,
            hyps=hyps,
            observations=observations,
            limitations=limitations,
            evidence_source="http_observation",
            evidence_provenance="http_executor_observation",
            experiment=exp,
        )

    def run_from_engagement(
        self,
        recon_path: Union[str, Path],
        *,
        engagement: Any,
        executor: Optional[Any] = None,
        method: str = "GET",
    ) -> RunResult:
        """
        Single integration path for lab adapters (PortSwigger or generic).

        PortSwiggerAdapter validates authorization → then this method calls
        run_http() so Evidence / FP Gate / R-S-R stay in one place.

        Does NOT invent a parallel verdict path.
        Fail-closed when engagement is not authorized.
        """
        from agent_lite.http.engagement import EngagementConfig
        from agent_lite.http.executor import HttpExecutor
        from agent_lite.labs.portswigger import PortSwiggerAdapter

        if not isinstance(engagement, EngagementConfig):
            raise TypeError("engagement must be EngagementConfig")

        adapter = PortSwiggerAdapter(engagement, executor=None)
        gate = adapter.validate()
        if gate.status == "BLOCKED":
            self.ledger.record("start", "blocked", ",".join(gate.block_reasons))
            self.ledger.finish("blocked")
            return RunResult(
                engagement_id=self.engagement_id,
                run_id=self.run_id,
                scope_allowed=False,
                mode="http",
                gate_status="BLOCK",
                limitations=[
                    "engagement_authorization_failed",
                    *gate.block_reasons,
                ],
                summary=f"ENGAGEMENT_BLOCKED: {','.join(gate.block_reasons)}",
            )

        # Known object only — path comes from engagement config, never enumerated
        if executor is None:
            idr = engagement.build_identities()
            executor = HttpExecutor(
                scope=engagement.build_scope(),
                budget=engagement.build_budget(),
                identities=idr,
                allowed_schemes=set(engagement.allowed_schemes),
            )

        return self.run_http(
            recon_path,
            base_url=engagement.base_url,
            object_path=engagement.object_path,
            executor=executor,
            owner_identity=engagement.owner_identity,
            non_owner_identity=engagement.non_owner_identity,
            method=method,
        )

    # ------------------------------------------------------------------
    # Shared internals
    # ------------------------------------------------------------------

    def _prepare(
        self, recon_path: Union[str, Path]
    ) -> tuple[Any, TargetContext, Optional[RunResult]]:
        recon = ReconAdapter().from_file(recon_path)
        self.ledger.record("normalize", "ok", recon.primary_host)
        ctx = build_target_context(self.engagement_id, recon)
        scope_res = self.scope.check(ctx.primary_host, "GET")
        if scope_res.decision != ScopeDecision.ALLOW:
            self.ledger.record("scope", "blocked", scope_res.reason)
            self.ledger.finish("blocked")
            report = build_report(
                engagement_id=self.engagement_id,
                verdict_status="REJECTED",
                claim="scope_denied",
                evidence_ids=[],
                gate_status="BLOCK",
                limitations=[f"ScopeGuard: {scope_res.reason}"],
            )
            result = RunResult(
                engagement_id=self.engagement_id,
                run_id=self.run_id,
                scope_allowed=False,
                gate_status="BLOCK",
                report=report,
                limitations=[f"ScopeGuard: {scope_res.reason}"],
                summary=f"SCOPE_BLOCKED: {scope_res.reason}",
            )
            self._write_artifacts(result, ctx, recon)
            return recon, ctx, result
        return recon, ctx, None


    def _llm_enrich(self, ctx: TargetContext, hyps: list) -> list:
        """Optional LLM proposals; never executes HTTP. Fail-closed if require_llm."""
        if self.llm_provider is None:
            if self.require_llm:
                self.llm_notes.append("missing_llm_api_key")
            return hyps
        try:
            from agent_lite.llm.reasoning import propose_hypotheses
            from agent_lite.skills.router import SkillRouter
            from agent_lite.hypotheses.engine import Hypothesis

            resp = propose_hypotheses(self.llm_provider, ctx)
            self.llm_notes.append(f"llm:{resp.status}:{resp.reason or resp.model}")
            self.ledger.record("llm", resp.status, resp.model or resp.reason)
            if resp.status != "ok":
                if self.require_llm:
                    self.llm_notes.append("llm_unavailable")
                return hyps
            router = SkillRouter()
            proposals = router.from_llm_hypotheses(resp.structured or {})
            # Attach as extra hypotheses (candidates), keep existing deterministic ones first
            extra = []
            for i, pr in enumerate(proposals[:3], start=1):
                extra.append(
                    Hypothesis(
                        hypothesis_id=f"H-LLM-{i:03d}",
                        opportunity_id="llm",
                        target=ctx.primary_host,
                        security_property=pr.get("security_property") or "candidate",
                        claim=pr.get("claim") or "LLM proposed investigation",
                        expected_behavior="Evidence-backed validation required",
                        suspected_violation=pr.get("claim") or "",
                        required_identity="as skill requires",
                        relevant_resource="from_context",
                        evidence_required=["observation", "identity_binding"],
                        competing_explanations=["benign design", "public resource", "insufficient data"],
                        proposed_experiment="skill:" + str(pr.get("skill_id")),
                        risk="low",
                        budget=0.2,
                        status="open",
                        provenance="llm_proposal",
                    )
                )
            # Write llm artifact side-channel via notes
            self.llm_notes.append(f"proposals:{len(extra)}")
            return list(hyps) + extra
        except Exception as e:  # noqa: BLE001
            self.llm_notes.append(f"llm_error:{type(e).__name__}")
            return hyps

    def _opportunities_and_hypotheses(self, ctx: TargetContext):
        opps = OpportunityEngine(self.engagement_id).extract(ctx)
        hyps = HypothesisEngine(self.engagement_id).from_opportunities(opps, ctx)
        self.ledger.record("opportunity_hypothesis", "ok", f"opps={len(opps)} hyps={len(hyps)}")
        self.ledger.checkpoint(
            f"cp_{self.run_id}_hyp",
            "hypotheses",
            {"opportunities": [o.to_dict() for o in opps], "hypotheses": [h.to_dict() for h in hyps]},
        )
        return opps, hyps

    def _investigate(
        self,
        *,
        mode: str,
        recon: Any,
        ctx: TargetContext,
        opps: list,
        hyps: list,
        observations: list,
        limitations: list,
        evidence_source: str,
        evidence_provenance: str,
        experiment: Optional[Experiment] = None,
    ) -> RunResult:
        hyp = hyps[0] if hyps else None

        if experiment is None:
            experiment = Experiment(
                experiment_id="EXP-001",
                hypothesis_ids=[hyp.hypothesis_id] if hyp else [],
                objective="Discriminate INV-AUTHZ-001 via owner vs non-owner same object",
                action="GET same object path as owner then non-owner",
                expected_observation="Non-owner denied or lacks private owner-bound fields",
                risk="low",
                cost=0.2,
            )
            # Per-action scope for synthetic observations
            for obs in observations:
                sr = self.scope.check(obs.host, obs.method)
                if sr.decision != ScopeDecision.ALLOW:
                    experiment.result = "blocked"
                    experiment.scope_decision = sr.reason
                    self.ledger.record("experiment_action", "blocked", sr.reason)
                    self.ledger.finish("blocked")
                    result = RunResult(
                        engagement_id=self.engagement_id,
                        run_id=self.run_id,
                        scope_allowed=True,
                        mode=mode,
                        opportunities=opps,
                        hypotheses=hyps,
                        experiments=[experiment],
                        gate_status="BLOCK",
                        limitations=limitations,
                        summary=f"EXPERIMENT_BLOCKED: {experiment.scope_decision}",
                    )
                    self._write_artifacts(result, ctx, recon, mode=mode)
                    return result
            experiment.scope_decision = "ALLOW"
            experiment.result = "executed"
            experiment.request_count = len(observations)
            experiment.target_interactions = len(observations)
            experiment.actual_observation = "; ".join(
                f"{o.identity}:{o.status}" for o in observations
            )
            experiment.information_gained = "cross_identity_status_and_body"

        # Evidence from observations only
        for obs in observations:
            pol = "neutral"
            if obs.identity in ("user_b",) or str(obs.identity).endswith("_b"):
                if obs.status < 400 and body_private_fields(obs.body):
                    pol = "positive"
                elif obs.status >= 400:
                    pol = "negative"
            rec = self.evidence.add(
                target=f"{obs.method} {obs.path}@{obs.host}",
                source=evidence_source,
                action=f"{obs.identity}:{obs.method}:{obs.path}",
                observation=f"status={obs.status} body={obs.body[:500]}",
                polarity=pol,
                hypothesis_id=hyp.hypothesis_id if hyp else "",
                provenance=evidence_provenance,
            )
            experiment.evidence_produced.append(rec.evidence_id)

        owner = observations[0]
        non_owner = next(
            (o for o in observations if o.identity != owner.identity),
            observations[-1],
        )
        owner_mark = body_owner_marker(non_owner.body)
        facts = {
            "in_scope": True,
            "action_authorized": True,
            "evidence_ids": self.evidence.ids(),
            "multi_identity": ctx.multi_identity,
            "has_resource_or_object": bool(ctx.resources or ctx.object_endpoints),
            "non_owner_status": non_owner.status,
            "private_fields": body_private_fields(non_owner.body),
            "public_marker": body_public_marker(non_owner.body),
            "shared_acl": body_shared_acl(non_owner.body),
            "owner_marker_mismatch": bool(
                owner_mark and owner_mark != non_owner.identity
            ),
            "observation_mode": mode,
        }

        gate = FalsePositiveGate().evaluate(facts)
        self.ledger.record("fp_gate", gate.status, gate.reason)

        claim = hyp.claim if hyp else "INV-AUTHZ-001 under test from observations"
        verdict = VerificationLoop().run(
            claim=claim,
            gate_status=gate.status,
            evidence_ids=self.evidence.ids(),
            facts=facts,
        )
        self.ledger.record("verification", verdict.status, verdict.reason)
        self.ledger.checkpoint(
            f"cp_{self.run_id}_done",
            "verification",
            {"verdict": verdict.to_dict(), "facts": facts, "mode": mode},
        )
        self.ledger.finish("completed")

        report = build_report(
            engagement_id=self.engagement_id,
            verdict_status=verdict.status,
            claim=claim,
            evidence_ids=self.evidence.ids(),
            gate_status=gate.status,
            limitations=limitations,
            hypothesis=hyp.to_dict() if hyp else None,
            facts=facts,
            experiments=[experiment.to_dict()],
            mode=mode,
        )

        result = RunResult(
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            scope_allowed=True,
            mode=mode,
            opportunities=opps,
            hypotheses=hyps,
            experiments=[experiment],
            evidence_ids=self.evidence.ids(),
            gate_status=gate.status,
            verdict=verdict,
            report=report,
            limitations=limitations,
            summary=f"{verdict.status}: {verdict.reason}",
            facts=facts,
        )
        self._write_artifacts(result, ctx, recon, gate.to_dict(), mode=mode)
        return result

    def _write_artifacts(
        self,
        result: RunResult,
        ctx: TargetContext,
        recon: Any,
        gate_dict: Optional[dict] = None,
        mode: str = "synthetic",
    ) -> None:
        d = self.artifacts_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "engagement.json").write_text(
            json.dumps(
                {
                    "engagement_id": self.engagement_id,
                    "run_id": self.run_id,
                    "mode": mode,
                },
                indent=2,
            )
        )
        (d / "normalized_recon.json").write_text(json.dumps(recon.to_dict(), indent=2))
        (d / "target_context.json").write_text(json.dumps(ctx.to_dict(), indent=2))
        (d / "opportunities.json").write_text(
            json.dumps([o.to_dict() for o in result.opportunities], indent=2)
        )
        (d / "hypotheses.json").write_text(
            json.dumps([h.to_dict() for h in result.hypotheses], indent=2)
        )
        (d / "experiments.json").write_text(
            json.dumps([e.to_dict() for e in result.experiments], indent=2)
        )
        self.evidence.write_jsonl(d / "evidence.jsonl")
        (d / "decisions.jsonl").write_text(
            json.dumps(
                {
                    "gate": gate_dict,
                    "verdict": result.verdict.to_dict() if result.verdict else None,
                    "facts": result.facts,
                    "mode": mode,
                }
            )
            + "\n"
        )
        findings = []
        if result.verdict and result.verdict.status == "CONFIRMED":
            findings.append(
                {
                    "finding_id": f"F-{self.run_id}",
                    "title": "Possible object-level authorization failure",
                    "vulnerability_class": "BOLA/IDOR",
                    "security_property": "INV-AUTHZ-001",
                    "summary": result.verdict.researcher_claim,
                    "evidence_refs": result.evidence_ids,
                    "verification_decision": result.verdict.status,
                    "status": "CONFIRMED",
                    "provenance": "agent_lite",
                    "mode": mode,
                }
            )
        (d / "findings.json").write_text(json.dumps(findings, indent=2))
        if result.report:
            (d / "final-report.md").write_text(result.report.get("markdown") or "")
            (d / "report.json").write_text(json.dumps(result.report, indent=2))

        # Rejected hypotheses preserved as research knowledge
        rejected = []
        if result.verdict and result.verdict.status in ("REJECTED", "NEED_MORE_EVIDENCE"):
            for h in result.hypotheses:
                rejected.append(
                    {
                        "hypothesis_id": h.hypothesis_id,
                        "status": result.verdict.status,
                        "claim": h.claim,
                        "reason": result.verdict.reason,
                    }
                )
        (d / "rejected_hypotheses.json").write_text(json.dumps(rejected, indent=2))

        hyp_dict = result.hypotheses[0].to_dict() if result.hypotheses else None
        episode = build_episode(
            episode_id=f"EP-{self.run_id}",
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            target=(hyp_dict or {}).get("target") or ctx.primary_host,
            mode=mode,
            hypothesis=hyp_dict,
            experiments=[e.to_dict() for e in result.experiments],
            evidence_ids=result.evidence_ids,
            verdict=result.verdict.to_dict() if result.verdict else None,
            facts=result.facts,
            skill_id="authz-bola",
        )
        (d / "research_episode.json").write_text(json.dumps(episode.to_dict(), indent=2))

        reg = SkillRegistry()
        reg.load_builtin()
        meta = reg.get("authz-bola")
        (d / "skill_used.json").write_text(
            json.dumps(meta.to_dict() if meta else {"skill_id": "authz-bola"}, indent=2)
        )
        if self.llm_notes:
            (d / "llm_notes.json").write_text(json.dumps({"notes": self.llm_notes}, indent=2))

