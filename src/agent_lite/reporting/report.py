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
    facts: Optional[dict[str, Any]] = None,
    experiments: Optional[list] = None,
    mode: str = "synthetic",
) -> dict[str, Any]:
    facts = facts or {}
    blocked = not evidence_ids and verdict_status == "CONFIRMED"
    hyp = hypothesis or {}
    md_lines = [
        f"# Research Report — {engagement_id}",
        "",
        f"**Verdict:** {verdict_status}",
        f"**FP Gate:** {gate_status}",
        f"**Mode:** {mode}",
        f"**Claim:** {claim}",
        "",
        "## Target / Security property",
        f"- Target: {hyp.get('target') or 'n/a'}",
        f"- Security property: {hyp.get('security_property') or 'INV-AUTHZ-001'}",
        f"- Affected resource: {hyp.get('relevant_resource') or 'n/a'}",
        f"- Identity relationship: {hyp.get('required_identity') or 'n/a'}",
        "",
        "## Expected vs observed",
        f"- Expected: {hyp.get('expected_behavior') or 'n/a'}",
        f"- Suspected violation: {hyp.get('suspected_violation') or 'n/a'}",
        f"- Non-owner status: {facts.get('non_owner_status', 'n/a')}",
        f"- Private fields: {facts.get('private_fields')}",
        f"- Public marker: {facts.get('public_marker')}",
        f"- Shared ACL: {facts.get('shared_acl')}",
        "",
        "## Evidence",
        ", ".join(evidence_ids) if evidence_ids else "_none_",
        "",
        "## Alternative explanations considered",
    ]
    for alt in hyp.get("competing_explanations") or []:
        md_lines.append(f"- {alt}")
    if not hyp.get("competing_explanations"):
        md_lines.append("- _none recorded_")
    md_lines.extend(["", "## Experiments"])
    for exp in experiments or []:
        if isinstance(exp, dict):
            md_lines.append(
                f"- {exp.get('experiment_id')}: {exp.get('result')} "
                f"(requests={exp.get('request_count')})"
            )
    md_lines.extend(["", "## Limitations"])
    for lim in limitations:
        md_lines.append(f"- {lim}")
    if blocked:
        md_lines.append("\n**REPORT BLOCKED:** confirmed claim without evidence ids.")
    return {
        "engagement_id": engagement_id,
        "verdict": verdict_status,
        "claim": claim,
        "evidence_ids": evidence_ids,
        "gate_status": gate_status,
        "mode": mode,
        "target": hyp.get("target"),
        "security_property": hyp.get("security_property"),
        "affected_resource": hyp.get("relevant_resource"),
        "identity_relationship": hyp.get("required_identity"),
        "expected_behavior": hyp.get("expected_behavior"),
        "observed_facts": {
            "non_owner_status": facts.get("non_owner_status"),
            "private_fields": facts.get("private_fields"),
            "public_marker": facts.get("public_marker"),
            "shared_acl": facts.get("shared_acl"),
            "owner_marker_mismatch": facts.get("owner_marker_mismatch"),
        },
        "alternative_explanations": hyp.get("competing_explanations") or [],
        "report_blocked": blocked,
        "limitations": limitations,
        "markdown": "\n".join(md_lines),
    }
