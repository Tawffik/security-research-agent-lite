"""
Smallest complete loop:

Recon → Normalize → Scope → Context → Hypothesis → Skill/Lab experiment
  → Evidence → FP Gate → Researcher/Skeptic/Referee → Finding → Report → Ledger
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from agent_lite.content_isolation.sanitizer import wrap_untrusted
from agent_lite.evidence.store import EvidenceStore
from agent_lite.hypotheses.engine import Hypothesis, HypothesisEngine
from agent_lite.ledger.store import Ledger
from agent_lite.recon.adapter import ReconAdapter
from agent_lite.reporting.report import build_report
from agent_lite.scope.guard import ScopeDecision, ScopeGuard
from agent_lite.skills.authz_bola import (
    LabScenario,
    body_private_fields,
    body_public_marker,
    body_shared_acl,
    bola_negative_public,
    bola_negative_secure,
    bola_positive_lab,
)
from agent_lite.target.context import TargetContext, build_target_context
from agent_lite.verification.fp_gate import FalsePositiveGate
from agent_lite.verification.loop import VerificationLoop, Verdict


@dataclass
class RunResult:
    engagement_id: str
    scope_allowed: bool
    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    gate_status: str = ""
    verdict: Optional[Verdict] = None
    report: Optional[dict[str, Any]] = None
    limitations: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "scope_allowed": self.scope_allowed,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "evidence_ids": self.evidence_ids,
            "gate_status": self.gate_status,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "report": self.report,
            "limitations": self.limitations,
            "summary": self.summary,
        }


class ResearchPipeline:
    def __init__(
        self,
        *,
        engagement_id: str,
        scope_path: Union[str, Path],
        artifacts_dir: Optional[Path] = None,
    ):
        self.engagement_id = engagement_id
        self.scope = ScopeGuard.from_file(scope_path)
        self.artifacts_dir = Path(artifacts_dir or "artifacts") / engagement_id
        self.ledger = Ledger(engagement_id)
        self.evidence = EvidenceStore(engagement_id)

    def run(
        self,
        recon_path: Union[str, Path],
        scenario: Optional[LabScenario] = None,
    ) -> RunResult:
        limitations = [
            "Lab/fixture mode — not live BugBountyCI E2E unless artifact provided",
            "No LLM required for baseline path",
        ]
        self.ledger.record("start", "ok", engagement_id=self.engagement_id)

        recon = ReconAdapter().from_file(recon_path)
        self.ledger.record("normalize", "ok", host=recon.primary_host)
        ctx = build_target_context(self.engagement_id, recon)

        # Scope check on primary host before any "target" action
        scope_res = self.scope.check(ctx.primary_host, "GET")
        if scope_res.decision != ScopeDecision.ALLOW:
            self.ledger.record("scope", "blocked", reason=scope_res.reason)
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
                scope_allowed=False,
                gate_status="BLOCK",
                report=report,
                limitations=limitations,
                summary=f"SCOPE_BLOCKED: {scope_res.reason}",
            )
            self._write_artifacts(result, ctx, recon)
            return result

        hyps = HypothesisEngine(self.engagement_id).generate(ctx)
        self.ledger.record("hypotheses", "ok", count=len(hyps))

        scenario = scenario or bola_positive_lab(ctx.primary_host)
        # Content isolation on bodies
        for obs in scenario.observations:
            wrap_untrusted(obs.body, source="lab_response")

        # Record evidence from lab observations
        for obs in scenario.observations:
            pol = "neutral"
            if obs.identity.endswith("_b") or obs.identity == "user_b":
                if obs.status < 400 and body_private_fields(obs.body):
                    pol = "positive"
                elif obs.status >= 400:
                    pol = "negative"
            self.evidence.add(
                target=f"{obs.method} {obs.path}@{obs.host}",
                source="lab_fixture",
                action=f"{obs.identity}:{obs.method}:{obs.path}",
                observation=f"status={obs.status} body={obs.body[:500]}",
                polarity=pol,
                hypothesis_id=hyps[0].hypothesis_id if hyps else "",
                provenance="synthetic_lab",
            )

        non_owner = next((o for o in scenario.observations if o.identity in ("user_b",) or o.identity.endswith("_b")), scenario.observations[-1])
        owner = scenario.observations[0]
        private = body_private_fields(non_owner.body)
        public = body_public_marker(non_owner.body)
        shared = body_shared_acl(non_owner.body)

        gate = FalsePositiveGate().evaluate(
            in_scope=True,
            action_authorized=True,
            observation_reproducible=True,
            actor_resource_understood=ctx.multi_identity and bool(ctx.resources or ctx.object_endpoints),
            security_property_violated=scenario.suggests_authz_issue and non_owner.status < 400 and private,
            alternatives_considered=True,
            not_public_or_shared=not public and not shared,
            evidence_sufficient=len(self.evidence.ids()) >= 2,
            impact_supported=private if scenario.suggests_authz_issue else non_owner.status >= 400,
            not_duplicate=True,
        )
        self.ledger.record("fp_gate", gate.status, reason=gate.reason)

        claim = hyps[0].claim if hyps else "authorization property under test"
        verdict = VerificationLoop().run(
            suggests_authz_issue=scenario.suggests_authz_issue,
            gate_status=gate.status,
            evidence_ids=self.evidence.ids(),
            claim=claim,
            non_owner_status=non_owner.status,
            body_has_private_fields=private,
            body_public_marker=public,
            body_shared_acl=shared,
        )
        self.ledger.record("verification", verdict.status, reason=verdict.reason)

        report = build_report(
            engagement_id=self.engagement_id,
            verdict_status=verdict.status,
            claim=claim,
            evidence_ids=self.evidence.ids(),
            gate_status=gate.status,
            limitations=limitations,
            hypothesis=hyps[0].to_dict() if hyps else None,
        )

        result = RunResult(
            engagement_id=self.engagement_id,
            scope_allowed=True,
            hypotheses=hyps,
            evidence_ids=self.evidence.ids(),
            gate_status=gate.status,
            verdict=verdict,
            report=report,
            limitations=limitations,
            summary=f"{verdict.status}: {verdict.reason}",
        )
        self._write_artifacts(result, ctx, recon, gate_dict=gate.to_dict())
        return result

    def _write_artifacts(
        self,
        result: RunResult,
        ctx: TargetContext,
        recon: Any,
        gate_dict: Optional[dict] = None,
    ) -> None:
        d = self.artifacts_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "engagement.json").write_text(json.dumps({"engagement_id": self.engagement_id, "mode": "lab"}, indent=2))
        (d / "normalized_recon.json").write_text(json.dumps(recon.to_dict(), indent=2))
        (d / "target_context.json").write_text(json.dumps(ctx.to_dict(), indent=2))
        (d / "hypotheses.json").write_text(json.dumps([h.to_dict() for h in result.hypotheses], indent=2))
        self.evidence.write_jsonl(d / "evidence.jsonl")
        (d / "decisions.jsonl").write_text(
            json.dumps({"gate": gate_dict, "verdict": result.verdict.to_dict() if result.verdict else None}) + "\n"
        )
        findings = []
        if result.verdict and result.verdict.status == "CONFIRMED":
            findings.append({"status": "CONFIRMED", "claim": result.verdict.researcher_claim, "evidence_ids": result.evidence_ids})
        (d / "findings.json").write_text(json.dumps(findings, indent=2))
        if result.report:
            (d / "final-report.md").write_text(result.report.get("markdown") or "")
            (d / "report.json").write_text(json.dumps(result.report, indent=2))
        self.ledger.write(d / "ledger.json")
