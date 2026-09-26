# Implementation plan

| Milestone | Status |
|-----------|--------|
| M0 Foundation | done |
| M1 Recon ingestion | done |
| M2 Hypothesis core | done |
| M3 Authz/BOLA skill + lab | done |
| M4 Evidence + FP gate | done |
| M5 Verification | done |
| M6 Reporting + Actions | done (workflow skeleton) |
| M7 Expansion | deferred |

## Classification vs full agent
- **REUSE CONCEPT:** ScopeGuard, isolation, evidence polarity, R/S/R, FP gate, skill progressive disclosure, artifact names
- **REIMPLEMENT:** all modules under `agent_lite` (no runtime import of full agent)
- **DEFER:** full JEV, target graph DB, knowledge compiler, LLM provider, browser/MCP
- **DO NOT PORT:** recon engine, multi-agent swarm, Redis/K8s
