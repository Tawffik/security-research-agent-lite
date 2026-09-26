# T4 — Live Authorized Validation Runbook

**Prerequisite commit:** `2590464` (single path: adapter → `run_from_engagement` → `run_http` → BOLA loop)  
**Live traffic is optional and manual.** This document does not enable live by default.

---

## Architecture under test

```
PortSwiggerAdapter.validate()
        ↓
ResearchPipeline.run_from_engagement()
        ↓
ResearchPipeline.run_http()
        ↓
HttpExecutor  (sessions from env / inject only)
        ↓
HttpObservation ×2  (Actor A, Actor B, same known object)
        ↓
_investigate()
        ↓
Evidence → FP Gate → Researcher → Skeptic → Referee
        ↓
CONFIRMED | REJECTED | NEED_MORE_EVIDENCE | BLOCKED
```

No parallel PortSwigger verdict. No enumeration. No LLM/JEV/Browser.

---

## Success criteria (all required)

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | Authorization explicit | `engagement.authorized: true` + operator intent |
| 2 | Host in scope | `authorization_errors()` empty; ScopeGuard ALLOW |
| 3 | Object path pre-known | Single path in YAML; exactly 2 ActionRequests |
| 4 | No enumeration | `request_count == 2` in experiment artifact |
| 5 | Credentials isolated | No password/token in `artifacts/**` |
| 6 | Budget enforced | `max_requests` ≥ 2; no silent expansion |
| 7 | Real observations | `evidence.jsonl` has http provenance |
| 8 | Same `_investigate` | `facts.observation_mode == "http"` |
| 9 | FP Gate ran | `decisions.jsonl` has gate status |
| 10 | R/S/R ran | `verdict` present with status |
| 11 | Verdict not from adapter | AdapterResult has no `verdict` field |
| 12 | Reproducible | Artifacts reconstruct experiment + evidence + decision |

Any status among CONFIRMED / REJECTED / NEED_MORE_EVIDENCE / BLOCKED is a **valid** research outcome. Only evidence decides which.

---

## Operator checklist (before first live call)

1. Copy `config/engagements/portswigger_bola_template.yaml` → e.g. `config/engagements/portswigger_bola_live.yaml` (**do not commit secrets**).
2. Set real `base_url` and matching `allowed_hosts`.
3. Set **one** known `object_path` (from lab description — not discovered by the agent).
4. Set `authorized: true` only for that file, only when you intend live use.
5. Provide sessions via environment (never in YAML):
   - `TEST_USER_A_COOKIE` or `TEST_USER_A_TOKEN`
   - `TEST_USER_B_COOKIE` or `TEST_USER_B_TOKEN`
6. Prepare a minimal recon JSON whose `primary_host` matches the lab host.
7. Dry-run validation only:
   ```bash
   python -m agent_lite.cli \
     --mode engagement \
     --engagement config/engagements/portswigger_bola_live.yaml \
     --recon path/to/recon.json \
     --scope path/to/scope.yaml \
     --dry-run
   ```
   Expect `ENGAGEMENT_BLOCKED` if `authorized: false`, or `READY` validation without HTTP if dry-run.
8. Live (local or GHA `live-lab.yml` with `confirm_authorized=AUTHORIZED`):
   ```bash
   python -m agent_lite.cli \
     --mode engagement \
     --engagement config/engagements/portswigger_bola_live.yaml \
     --recon path/to/recon.json \
     --scope path/to/scope.yaml \
     --artifacts-dir artifacts
   ```
9. Review artifacts: `experiments.json`, `evidence.jsonl`, `decisions.jsonl`, `findings.json`, `final-report.md`.
10. Confirm no secrets in artifact files; confirm `request_count == 2`.

---

## GitHub Actions

`.github/workflows/live-lab.yml`:

- Trigger: **workflow_dispatch only**
- Required input: `confirm_authorized=AUTHORIZED`
- Default engagement template remains `authorized: false` → dry validate / BLOCK
- No `on: push` live traffic

---

## Explicit non-goals for T4

- LLM, JEV, Planner, Browser, MCP  
- Enumeration, fuzzing, crawling  
- Generic login framework  
- Second recon engine  
- Claiming success based solely on HTTP 200  

---

## After a successful T4

Only then decide:

- deepen BOLA (more controlled differentials), or  
- next skill family  

Do not expand architecture until this vertical slice is proven on one authorized Academy object.
