"""
Evidence-driven research pipeline.

Lab provides observations only. Verdicts come from evidence + gate + R/S/R.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from agent_lite.content_isolation.sanitizer import wrap_untrusted
from agent_lite.evidence.store import EvidenceStore
from agent_lite.experiments.model import Experiment
from agent_lite.hypotheses.engine import Hypothesis, HypothesisEngine
from agent_lite.ledger.sqlite_ledger import SQLiteLedger
from agent_lite.opportunities.engine import Opportunity, OpportunityEngine
from agent_lite.recon.adapter import ReconAdapter
from agent_lite.reporting.report import build_report
from agent_lite.scope.guard import ScopeDecision, ScopeGuard
from agent_lite.skills.authz_bola import (
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


@dataclass
class RunResult:
    engagement_id: str
    run_id: str
    scope_allowed: bool
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
    ):
        self.engagement_id = engagement_id
        self.run_id = run_id or f"run_{uuid.uuid4().hex[:10]}"
        self.scope = ScopeGuard.from_file(scope_path)
        self.artifacts_dir = Path(artifacts_dir or "artifacts") / engagement_id
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.ledger = SQLiteLedger(self.artifacts_dir / "ledger.db", self.run_id, engagement_id)
        self.evidence = EvidenceStore(engagement_id)

    def run(
        self,
        recon_path: Union[str, Path],
        scenario: Optional[LabScenario] = None,
    ) -> RunResult:
        limitations = [
            "Lab/fixture observations — not live HTTP unless extended",
            "Verdict derived from observations only (no scenario answer key)",
        ]
        self.ledger.record("start", "ok", self.engagement_id)

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
                limitations=limitations + [f"ScopeGuard: {scope_res.reason}"],
            )
            result = RunResult(
                engagement_id=self.engagement_id,
                run_id=self.run_id,
                scope_allowed=False,
                gate_status="BLOCK",
                report=report,
                limitations=limitations,
                summary=f"SCOPE_BLOCKED: {scope_res.reason}",
            )
            self._write_artifacts(result, ctx, recon)
            return result

        opps = OpportunityEngine(self.engagement_id).extract(ctx)
        hyps = HypothesisEngine(self.engagement_id).from_opportunities(opps, ctx)
        self.ledger.record("opportunity_hypothesis", "ok", f"opps={len(opps)} hyps={len(hyps)}")
        self.ledger.checkpoint(
            f"cp_{self.run_id}_hyp",
            "hypotheses",
            {"opportunities": [o.to_dict() for o in opps], "hypotheses": [h.to_dict() for h in hyps]},
        )

        scenario = scenario or bola_positive_lab(ctx.primary_host)
        # Isolate target-origin content
        for obs in scenario.observations:
            wrap_untrusted(obs.body, source="lab_response")

        # Experiment: cross-identity differential (designed from hypothesis, executed against lab env)
        hyp = hyps[0] if hyps else None
        exp = Experiment(
            experiment_id="EXP-001",
            hypothesis_ids=[hyp.hypothesis_id] if hyp else [],
            objective="Discriminate INV-AUTHZ-001 via owner vs non-owner same object",
            action="GET same object path as owner then non-owner",
            expected_observation="Non-owner denied or lacks private owner-bound fields",
            risk="low",
            cost=0.2,
        )

        # Per-action scope for each observation host/method
        for obs in scenario.observations:
            sr = self.scope.check(obs.host, obs.method)
            if sr.decision != ScopeDecision.ALLOW:
                exp.result = "blocked"
                exp.scope_decision = sr.reason
                self.ledger.record("experiment_action", "blocked", sr.reason)
                break
        else:
            exp.scope_decision = "ALLOW"
            exp.result = "executed"
            exp.request_count = len(scenario.observations)
            exp.target_interactions = len(scenario.observations)
            exp.actual_observation = "; ".join(
                f"{o.identity}:{o.status}" for o in scenario.observations
            )
            exp.information_gained = "cross_identity_status_and_body"

        if exp.result == "blocked":
            self.ledger.finish("blocked")
            result = RunResult(
                engagement_id=self.engagement_id,
                run_id=self.run_id,
                scope_allowed=True,
                opportunities=opps,
                hypotheses=hyps,
                experiments=[exp],
                gate_status="BLOCK",
                limitations=limitations,
                summary=f"EXPERIMENT_BLOCKED: {exp.scope_decision}",
            )
            self._write_artifacts(result, ctx, recon)
            return result

        # Evidence from observations only
        for obs in scenario.observations:
            pol = "neutral"
            if obs.identity in ("user_b",) or str(obs.identity).endswith("_b"):
                if obs.status < 400 and body_private_fields(obs.body):
                    pol = "positive"
                elif obs.status >= 400:
                    pol = "negative"
            rec = self.evidence.add(
                target=f"{obs.method} {obs.path}@{obs.host}",
                source="lab_observation",
                action=f"{obs.identity}:{obs.method}:{obs.path}",
                observation=f"status={obs.status} body={obs.body[:500]}",
                polarity=pol,
                hypothesis_id=hyp.hypothesis_id if hyp else "",
                provenance="synthetic_lab_observation",
            )
            exp.evidence_produced.append(rec.evidence_id)

        # Facts derived from observations — NEVER from scenario.suggests_*
        owner = scenario.observations[0]
        non_owner = next(
            (o for o in scenario.observations if o.identity != owner.identity),
            scenario.observations[-1],
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
            {"verdict": verdict.to_dict(), "facts": facts},
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
        )

        result = RunResult(
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            scope_allowed=True,
            opportunities=opps,
            hypotheses=hyps,
            experiments=[exp],
            evidence_ids=self.evidence.ids(),
            gate_status=gate.status,
            verdict=verdict,
            report=report,
            limitations=limitations,
            summary=f"{verdict.status}: {verdict.reason}",
            facts=facts,
        )
        self._write_artifacts(result, ctx, recon, gate.to_dict())
        return result

    def _write_artifacts(self, result: RunResult, ctx: TargetContext, recon: Any, gate_dict: Optional[dict] = None) -> None:
        d = self.artifacts_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "engagement.json").write_text(
            json.dumps({"engagement_id": self.engagement_id, "run_id": self.run_id, "mode": "lab"}, indent=2)
        )
        (d / "normalized_recon.json").write_text(json.dumps(recon.to_dict(), indent=2))
        (d / "target_context.json").write_text(json.dumps(ctx.to_dict(), indent=2))
        (d / "opportunities.json").write_text(json.dumps([o.to_dict() for o in result.opportunities], indent=2))
        (d / "hypotheses.json").write_text(json.dumps([h.to_dict() for h in result.hypotheses], indent=2))
        (d / "experiments.json").write_text(json.dumps([e.to_dict() for e in result.experiments], indent=2))
        self.evidence.write_jsonl(d / "evidence.jsonl")
        (d / "decisions.jsonl").write_text(
            json.dumps({"gate": gate_dict, "verdict": result.verdict.to_dict() if result.verdict else None, "facts": result.facts})
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
                }
            )
        (d / "findings.json").write_text(json.dumps(findings, indent=2))
        if result.report:
            (d / "final-report.md").write_text(result.report.get("markdown") or "")
            (d / "report.json").write_text(json.dumps(result.report, indent=2))
