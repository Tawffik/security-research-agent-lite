"""Portable research episode — small artifact for Full Agent memory later."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class ResearchEpisode:
    episode_id: str
    engagement_id: str
    run_id: str
    target: str
    mode: str
    hypothesis: Optional[dict] = None
    experiments: list = field(default_factory=list)
    evidence_ids: list = field(default_factory=list)
    decision: Optional[dict] = None
    rejected_alternatives: list = field(default_factory=list)
    rejected_hypotheses: list = field(default_factory=list)
    lesson: str = ""
    provenance: str = "agent_lite"
    skill_id: str = "authz-bola"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_episode(
    *,
    episode_id: str,
    engagement_id: str,
    run_id: str,
    target: str,
    mode: str,
    hypothesis: Optional[dict],
    experiments: list,
    evidence_ids: list,
    verdict: Optional[dict],
    facts: dict,
    skill_id: str = "authz-bola",
) -> ResearchEpisode:
    rejected_alts = []
    if hypothesis:
        rejected_alts = list(hypothesis.get("competing_explanations") or [])
    lesson = ""
    status = (verdict or {}).get("status") or ""
    if status == "CONFIRMED":
        lesson = "Authorization boundary failed discrimination test under controlled identities."
    elif status == "REJECTED":
        lesson = "No evidence-backed authorization property violation after FP gate and skepticism."
    elif status == "NEED_MORE_EVIDENCE":
        lesson = "Observations insufficient to confirm or fully reject authorization claim."
    else:
        lesson = "Run blocked or incomplete; no finding."

    rejected_hyps = []
    if status in ("REJECTED", "NEED_MORE_EVIDENCE") and hypothesis:
        rejected_hyps.append(
            {
                "hypothesis_id": hypothesis.get("hypothesis_id"),
                "status": status,
                "reason": (verdict or {}).get("reason") or "",
            }
        )

    return ResearchEpisode(
        episode_id=episode_id,
        engagement_id=engagement_id,
        run_id=run_id,
        target=target,
        mode=mode,
        hypothesis=hypothesis,
        experiments=experiments,
        evidence_ids=evidence_ids,
        decision=verdict,
        rejected_alternatives=rejected_alts,
        rejected_hypotheses=rejected_hyps,
        lesson=lesson,
        skill_id=skill_id,
    )
