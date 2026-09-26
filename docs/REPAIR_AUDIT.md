# REPAIR AUDIT — security-research-agent-lite

**Date:** 2026-09-26  
**HEAD:** post-PortSwigger adapter (see git log)  
**Sources of truth:** Notion MVP Spec + `origin/main`

---

## CURRENT STATE

```
Synthetic: ResearchPipeline.run() → LabScenario → Evidence → FP Gate → R/S/R
HTTP:      ResearchPipeline.run_http() → ActionRequest → HttpExecutor → HttpObservation → same loop
Adapter:   PortSwiggerAdapter → ActionRequest → HttpExecutor → observations only (no verdict)
```

**Tests:** 60 passed (T0–T3 + PortSwigger adapter deterministic tests).  
**Live PortSwigger Academy execution:** still **disabled by default** (template `authorized: false`, live-lab.yml requires `confirm_authorized=AUTHORIZED`).

---

## ALREADY IMPLEMENTED

| Component | Status |
|-----------|--------|
| e81debd evidence-driven BOLA (no lab answer key) | Done |
| Opportunity, INV-AUTHZ-001, Experiment, SQLite ledger | Done |
| HttpExecutor + ActionRequest + HttpObservation | Done |
| Identity vs Credential, redaction, budget | Done |
| ResearchPipeline.run_http | Done |
| T2 local real HTTP server matrix | Done |
| T3 adversarial (injection, redirects, secrets, …) | Done |
| No auto-follow redirects | Done |
| PortSwiggerAdapter (fail-closed, uses HttpExecutor) | Done |
| EngagementConfig: type, authorized, authorization_errors | Done |
| portswigger_bola_template.yaml (authorized: false) | Done |
| live-lab.yml explicit dispatch only | Done |

---

## PORTSWIGGER GAP (remaining for T4)

- No Academy lab login/session acquisition implementation (session inject / env secrets only)
- No live network call to `*.web-security-academy.net` in CI by default
- ResearchPipeline not yet wired as `run_portswigger(engagement)` convenience (adapter + run_http exist separately)
- T4 manual authorized lab validation not run

---

## SAFETY GUARANTEES (held)

- Unauthorized engagement → BLOCK  
- Missing base URL / host not in scope / bad scheme / bad method → BLOCK  
- Secrets not in observations/artifacts  
- Redirects not auto-followed  
- No `is_vulnerable` / verdict inside adapter  
- Synthetic `run()` behavior unchanged  

---

## DEFERRED

Browser, MCP, LLM, JEV, planner, SSRF/SQLi/XSS, fuzzing, distributed infra, second recon engine, generic auth framework.

---

## NEXT CHECKPOINT (T4)

Explicit engagement with `authorized: true` + live-lab.yml `confirm_authorized=AUTHORIZED` + secrets + one known object path + budget/scope → observations → existing BOLA loop.  
Do not claim vulnerability without evidence-backed CONFIRMED from pipeline.
