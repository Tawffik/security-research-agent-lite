# Implementation plan (post-repair)

| Phase | Status |
|-------|--------|
| 1 Audit + REPAIR_AUDIT | done |
| 2 Remove pre-known verdicts | done |
| 3 Invariants + Opportunity | done |
| 4 Experiment abstraction | done |
| 5 Observation-only BOLA | done |
| 6 Evidence-backed FP Gate | done |
| 7 Researcher/Skeptic/Referee | done |
| 8 Recon contract (adapter) | done (v1) |
| 9 SQLite ledger + checkpoint | done |
| 10 E2E cases + GHA | done |

## Flow
```
Recon → Opportunity → Hypothesis(INV) → Experiment
  → Observations → Evidence → FP Gate(evidence_refs)
  → Researcher → Skeptic → Referee → Report
```

Lab fixtures supply **observations only**. No `suggests_authz_issue` in reasoning.
