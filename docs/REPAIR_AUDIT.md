# REPAIR AUDIT — security-research-agent-lite (Post-e81debd)

**Date:** 2026-09-26  
**Commit under audit:** `e81debd` — *fix: evidence-driven BOLA path without pre-known lab verdicts*  
**Sources of truth:** Notion «🧩 Small Security Research Agent — Standalone MVP Specification» + actual repository state

---

## CURRENT STATE

Vertical slice is **evidence-driven and synthetic-lab complete**.  
13 tests green. Pipeline produces CONFIRMED / REJECTED / NEED_MORE_EVIDENCE from observations only (no lab answer key).

```
Recon → Opportunity → Hypothesis + INV-AUTHZ-001 → Experiment
  → Observations (synthetic) → Evidence → FP Gate → R/S/R → Report + SQLite ledger
```

**Still missing for this milestone:** real bounded HTTP execution path.

---

## ALREADY IMPLEMENTED (do not rebuild)

| Component | Status | Notes |
|-----------|--------|-------|
| ReconAdapter | Done | Normalizes host/endpoints/actors/resources; validates |
| ScopeGuard | Done | Fail-closed unknown host; method checks; used at run + per-obs |
| Content isolation | Done | `wrap_untrusted` / UNTRUSTED_DATA |
| Opportunity layer | Done | `OpportunityEngine` |
| INV-AUTHZ-001 | Done | `security/invariants.py` |
| Hypothesis from Opportunity + Invariant | Done | No free-form claims only |
| Experiment abstraction | Done | `Experiment` model with objective / actual / evidence |
| Observation-driven facts | Done | No `suggests_authz_issue` in reasoning path |
| Evidence store + polarity | Done | |
| FP Gate with evidence_refs | Done | 10 questions, facts from observations |
| Researcher / Skeptic / Referee | Done | Separate roles in `VerificationLoop` |
| SQLite ledger + checkpoint | Done | `sqlite_ledger.py` |
| Positive / secure / public / shared / ambiguous labs | Done | Synthetic fixtures |
| Report + artifacts | Done | findings, evidence.jsonl, final-report.md |
| GHA synthetic E2E | Done | `security-research.yml` |
| Independent package | Done | No runtime import of Full Agent |

---

## PARTIALLY IMPLEMENTED

| Item | Gap |
|------|-----|
| ScopeGuard | Applied per observation host/method, but **not** yet behind a real ActionRequest → Policy → Identity → Risk → Budget → HTTP Executor pipeline |
| Experiment | Records synthetic observations; no real HTTP executor boundary |
| Identity | Lab strings `user_a` / `user_b` only; no Credential-ref resolution layer |
| Budget | Config exists (`config/budget.yaml`); not enforced per request at executor |
| Redaction | Bodies truncated in evidence; no systematic header/cookie/token redaction |
| BBCI adapter | Basic normalize; no versioned schema_version contract yet |
| Checkpoint resume | Recorded; full safe re-entry of target-affecting steps not fully proven under interruption |

---

## MISSING (required for Real HTTP BOLA milestone)

1. **HTTP Executor contract** (bounded, structured Observation return)
2. **ActionRequest → Policy → ScopeGuard → IdentityResolver → Risk → Budget → Execute** boundary
3. **Identity vs Credential separation** (credential_ref only; secrets never in ledger/evidence/artifacts)
4. **Request/response redaction** (Authorization, Cookie, Set-Cookie, tokens → [REDACTED])
5. **Budget + rate-limit enforcement** at action level (max_requests, max_response_bytes, min_delay)
6. **Live-lab engagement configuration** (allowed hosts/schemes/methods/paths, identities, budget)
7. **Auth session layer** minimal for selected lab (login → session kept inside executor boundary)
8. **Synthetic HTTP server fixtures** (positive/secure/public/shared/ambiguous) for T2
9. **Adversarial HTTP response tests** (T3: injection, oversized, misleading status)
10. **PortSwigger engagement config** (authorized lab only; no answer key)
11. **GHA live mode** (explicit workflow_dispatch; default = synthetic)
12. **Report fields** for real BOLA (Actor A/B, Expected vs Observed, Resource, Reproduction)

---

## INCORRECT / UNSAFE (none critical in e81debd)

- Pre-known verdict coupling: **fixed** in e81debd.
- No “allow everything” fallback: Scope remains fail-closed.
- Credentials: currently none present (synthetic only) — must stay that way when HTTP is added.

---

## PRIORITY FOR THIS MILESTONE

```
Correctness > Safety > Authorization/Scope > Evidence integrity >
Research validity > Reproducibility > State/Resume > Observability >
Extensibility > Performance > Advanced intelligence
```

**Target:** Real authorized HTTP observation-driven BOLA (one discriminating experiment), not autonomy expansion.

---

## NON-GOALS (deferred)

Browser/MCP, LLM, JEV, SSRF/SQLi/XSS, large-scale fuzzing, recon engine, vector/graph DB, Redis/Kafka/K8s, Full Agent runtime import.

---

## NEXT ACTIONS (implementation order)

1. Update this audit (done)
2. Introduce `ActionRequest` + bounded `HttpExecutor` + structured `HttpObservation`
3. Wire ScopeGuard + Budget + redaction into every execute path
4. IdentityResolver (credential_ref → session material inside executor only)
5. T0/T1 unit + component tests for executor/scope/redaction/budget
6. T2 synthetic HTTP server (positive/secure/public/shared/ambiguous)
7. T3 adversarial responses
8. Live-lab engagement YAML + PortSwigger config (authorized lab)
9. GHA: keep synthetic default; add explicit live dispatch
10. Upgrade report for real BOLA fields
11. Sync Notion: Implemented / Changed / Deferred / Limitations / Test results / Next

---

## SAFETY INVARIANTS (must remain 0)

- Unauthorized actions = 0  
- Out-of-scope actions = 0  
- Credential leakage into artifacts/logs/ledger/Notion = 0  
- CONFIRMED never from status-only  
- Target content never becomes trusted instructions
