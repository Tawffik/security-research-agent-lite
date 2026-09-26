# REPAIR AUDIT — security-research-agent-lite

**Date:** 2026-09-26  
**Source of truth:** Notion «Small Security Research Agent — Standalone MVP Specification» + actual repo `79bd814`

## Current State
Vertical slice exists and tests pass (7). Loop runs end-to-end on synthetic fixtures. Architecture files minimal.

## What Already Works
- ReconAdapter (host/endpoints/actors/resources normalize)
- ScopeGuard fail-closed on unknown host
- Content isolation flags (UNTRUSTED_DATA)
- Evidence store with polarity
- FP gate structure (10 questions)
- VerificationLoop returns CONFIRMED/REJECTED/NEED_MORE_EVIDENCE
- Artifact writers + CLI + GHA skeletons
- Positive/secure/public lab scenarios produce expected *test* outcomes

## What Is Simulated
- Lab fixtures inject HTTP-like observations (no live HTTP)
- Ledger is JSON file, not SQLite
- No real ModelProvider (N/A for baseline)
- Scope checked once per run, not per experiment action in a multi-action path

## What Is Real
- Deterministic schemas and pipeline orchestration
- Scope policy YAML
- Independent package (no full-agent import)

## What Is Incorrect (critical)
1. **Pre-known verdict coupling:** `LabScenario.suggests_authz_issue` is passed into gate/verification as if it were evidence. Lab must not tell the engine the answer.
2. **Missing Opportunity layer:** Recon → Hypothesis skips Opportunity.
3. **No Security Invariant object:** Hypotheses are free-form claims, not INV-bound.
4. **No Experiment abstraction:** Observations are recorded without experiment_id/objective/result contract.
5. **FP Gate answers are pipeline-fed booleans** derived partly from scenario flag, not solely from observation-derived facts + evidence_refs.
6. **Object detection** is path-substring only (`{id}` / `id` in path).
7. **No Actor–Resource–Endpoint relationship model** beyond loose lists.
8. **Ledger** is not SQLite; no checkpoint/resume API.

## What Is Missing
- Opportunity model + generator
- Invariant registry (INV-AUTHZ-001)
- Experiment model + executor boundary
- Per-action ScopeGuard for experiment steps
- Shared-ACL scenario test
- Ambiguous / false-correlation tests
- Evidence-backed gate answers with evidence_refs
- Finding full contract
- BBCI live.txt contract path (partially conceptual only)

## Coupled
- `pipeline.run` tightly couples scenario → gate → verdict via `suggests_authz_issue`
- Skill module owns both lab data *and* body heuristics used as research logic (acceptable if heuristics are observation parsers, not verdict injectors)

## Must Reimplement
- Pipeline observation→evidence→reasoning path without scenario truth flag
- Hypothesis from Opportunity + Invariant
- Experiment records
- FP Gate evidence refs

## Reuse Conceptually (from Full Agent)
- Scope fail-closed, isolation, polarity, R/S/R, FP checklist, artifact names, BOLA competing explanations

## Deferred
Full JEV, Target Graph DB, LLM, browser, skill evolution, second recon engine

## Risk Assessment
High: false confidence in “research” that already knows the lab answer.  
Medium: scope only once.  
Low: JSON ledger loss on crash.

## Repair Order
1. Audit (this doc)
2. Remove pre-known verdict from reasoning
3. Invariants + Opportunity
4. Experiment abstraction
5. Observation-only BOLA investigation
6. Evidence-backed FP Gate
7. Clear R/S/R separation
8. Recon contract notes
9. SQLite ledger + checkpoint
10. E2E tests expanded + GHA

