"""Evidence-linked report — no free-form vulnerability claims without evidence ids."""

from __future__ import annotations

from typing import Any, Optional


def build_report(
    *,
    engagement_id: str,
    verdict_status: str,
    claim: str,
    evidence_ids: list[str],
    gate_status: str,
    limitations: list[str],
    hypothesis: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    blocked = not evidence_ids and verdict_status == "CONFIRMED"
    md_lines = [
        f"# Research Report — {engagement_id}",
        "",
        f"**Verdict:** {verdict_status}",
        f"**FP Gate:** {gate_status}",
        f"**Claim:** {claim}",
        "",
        "## Evidence",
        ", ".join(evidence_ids) if evidence_ids else "_none_",
        "",
        "## Limitations",
    ]
    for lim in limitations:
        md_lines.append(f"- {lim}")
    if hypothesis:
        md_lines.extend(["", "## Hypothesis", f"- Property: {hypothesis.get('security_property')}", f"- Expected: {hypothesis.get('expected_behavior')}"])
    if blocked:
        md_lines.append("\n**REPORT BLOCKED:** confirmed claim without evidence ids.")
    return {
        "engagement_id": engagement_id,
        "verdict": verdict_status,
        "claim": claim,
        "evidence_ids": evidence_ids,
        "gate_status": gate_status,
        "report_blocked": blocked,
        "limitations": limitations,
        "markdown": "\n".join(md_lines),
    }
