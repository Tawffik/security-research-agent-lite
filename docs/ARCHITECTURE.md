# Architecture — Security Research Agent Lite

Standalone vertical slice. Full agent remains canonical long-term architecture.

```
BugBountyCI artifact → ReconAdapter → ScopeGuard → TargetContext
  → HypothesisEngine → authz-bola skill (lab experiment)
  → EvidenceStore → FalsePositiveGate → Researcher/Skeptic/Referee
  → Report + Ledger + artifacts/
```

## Ownership
- BugBountyCI: recon production
- Lite: ingestion, reasoning, evidence, verification, report
- Full agent: graphs, JEV, knowledge compiler, skill evolution (deferred)

## Safety
- Fail-closed scope
- UNTRUSTED_DATA isolation
- No finding without evidence
- Independent skeptic/referee
