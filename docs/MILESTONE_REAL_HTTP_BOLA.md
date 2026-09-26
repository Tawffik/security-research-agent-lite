# Milestone: Real HTTP BOLA (Post-e81debd) — Progress Report

**Date:** 2026-09-26  
**Base commit:** e81debd  
**Tests:** 28 passed (13 prior + 10 HTTP executor + 5 BOLA matrix)

---

## CURRENT STATE

Synthetic evidence-driven BOLA vertical slice remains intact.  
New bounded HTTP execution boundary is in place and tested with mock transport.

```
ActionRequest
  → ScopeGuard
  → IdentityResolver (credential_ref only)
  → Risk
  → BudgetGuard
  → HTTP Executor (injectable transport)
  → HttpObservation (redacted)
```

Pipeline still defaults to synthetic lab fixtures for the CLI path.  
Live path is gated behind explicit engagement config + workflow_dispatch + AUTHORIZED confirmation.

---

## IMPLEMENTED (this session)

- `docs/REPAIR_AUDIT.md` updated against e81debd (already / partial / missing)
- `http/models.py` — ActionRequest, HttpObservation
- `http/redaction.py` — header + body redaction (no secrets in artifacts)
- `http/executor.py` — full Policy→Scope→Identity→Risk→Budget→Execute
- `http/engagement.py` — engagement YAML loader
- `budget/guard.py` — max_requests / experiments / response_bytes / delay
- `identity/resolver.py` — Identity vs Credential; session inject only in memory
- `config/engagements/synthetic_bola.yaml`
- `.github/workflows/live-lab.yml` — explicit dispatch, confirm_authorized=AUTHORIZED, no push trigger
- T0/T1 tests: scope, scheme, budget, identity, redaction
- T2 matrix via HttpExecutor: positive / secure / public / shared / ambiguous

---

## CHANGED

- ScopeGuard still fail-closed; now also invoked inside every HttpExecutor action
- Observations from HTTP never carry Authorization / Cookie / Set-Cookie / tokens
- Budget counters enforced at request level

---

## DEFERRED (unchanged)

- Browser / MCP
- LLM / ModelProvider
- JEV / full planner
- PortSwigger live runner adapter (config shape ready; auth login lab-specific)
- Full CLI `--mode live` wire into ResearchPipeline
- Additional vulnerability families
- Autonomous skill evolution

---

## KNOWN LIMITATIONS

1. CLI pipeline still uses synthetic LabScenario observations (not yet calling HttpExecutor).
2. Auth is session-inject only; no password-login adapter for PortSwigger yet.
3. Live GHA job runs tests + guards; does not yet open network to PortSwigger until lab adapter + secrets are configured.
4. Rate limiting is sequential min_delay only (no concurrency).
5. Object path is single known resource (no enumeration by design).

---

## SECURITY RISKS

| Risk | Mitigation |
|------|------------|
| Credential leakage | Never in observation/ledger/artifacts; redaction on all headers |
| Out-of-scope HTTP | ScopeGuard per action; unknown host = BLOCK |
| Accidental live on push | live-lab.yml requires dispatch + AUTHORIZED string |
| Status-only FP | Matrix tests: ambiguous never CONFIRMED |
| Prompt injection in body | Content isolation still wraps untrusted bodies; bodies treated as data |

---

## TEST RESULTS

| Level | Result |
|-------|--------|
| T0 unit (scope, redaction, budget, identity) | PASS |
| T1 executor component | PASS |
| T2 HTTP BOLA matrix (pos/sec/pub/shared/amb) | PASS |
| Prior synthetic E2E (13) | PASS |
| T3 adversarial | Not yet expanded |
| T4 PortSwigger live | Not yet (gated) |

**Total: 28 passed**

---

## PORTSWIGGER RESULT

Not executed. Prerequisites remaining:

1. Authorized Academy lab URL + engagement YAML
2. TEST_USER_A/B session secrets in GHA
3. Minimal login adapter → SessionMaterial inject
4. Explicit workflow_dispatch with confirm_authorized=AUTHORIZED

---

## ARTIFACTS

- `docs/REPAIR_AUDIT.md`
- `docs/MILESTONE_REAL_HTTP_BOLA.md` (this file)
- `src/agent_lite/http/*`
- `src/agent_lite/budget/*`
- `src/agent_lite/identity/*`
- `config/engagements/synthetic_bola.yaml`
- `.github/workflows/live-lab.yml`
- `tests/test_http_executor.py`
- `tests/test_http_bola_matrix.py`

---

## ANSWERS TO EXPLICIT QUESTIONS

| Question | Answer |
|----------|--------|
| Did the live path execute real HTTP? | Not yet against PortSwigger. Executor can use real urllib when transport is not injected; currently validated with mock transport. |
| Did it use real identities? | Identity abstraction yes; sessions injected in tests (no passwords persisted). |
| Were credentials kept out of artifacts? | Yes — redaction + SessionMaterial in-memory only. |
| Was every target-affecting action scope-checked? | Yes inside HttpExecutor. |
| Was the BOLA verdict derived from observations? | Yes (facts from response body/status only). |
| Could the system reject secure/public/shared? | Yes (T2). |
| Could it avoid confirming ambiguous? | Yes (T2). |

---

## NEXT MILESTONE

1. Wire ResearchPipeline optional `--mode http` path through HttpExecutor for synthetic server.
2. Minimal PortSwigger lab adapter (login → session inject).
3. T3 adversarial responses.
4. T4 authorized PortSwigger validation under live-lab.yml.
5. Notion sync: Implemented / Deferred / Limitations / Test results.

**Principle preserved:** observation → property → hypothesis → experiment → evidence → skepticism → verification — now with a real, bounded HTTP execution boundary.
