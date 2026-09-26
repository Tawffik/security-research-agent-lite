# Security Research Agent Lite — Completion Status

**HEAD target:** post-episode/skill-registry finish  
**Purpose:** Small, complete, portable vertical slice — not the Full Agent.

## Core loop (proven)

```
BugBountyCI recon → ReconAdapter → TargetContext → Scope
→ Opportunity → Hypothesis → Experiment
→ Observations (synthetic | HTTP | engagement)
→ Evidence → FP Gate → Researcher/Skeptic/Referee
→ Finding | Rejected hypothesis → Report → Research Episode
```

## Portable primitives (Full Agent–ready interfaces)

| Primitive | Location |
|-----------|----------|
| ScopeGuard | `scope/guard.py` |
| Content isolation | `content_isolation/` |
| Target context | `target/context.py` |
| Hypothesis | `hypotheses/engine.py` |
| Experiment | `experiments/model.py` |
| Evidence | `evidence/store.py` |
| FP Gate | `verification/fp_gate.py` |
| R/S/R | `verification/loop.py` |
| HttpExecutor | `http/executor.py` |
| IdentityResolver | `identity/resolver.py` |
| BrowserSessionProvider | `browser/provider.py` |
| SkillRegistry | `skills/registry.py` |
| ResearchEpisode | `episode/model.py` |

## Intentionally NOT in Lite

Full JEV, planner, knowledge/target graphs, vector/graph DB, Redis/Kafka/K8s, autonomous skill evolution, unrestricted browser agent, second recon engine, multi-family orchestration.

## Browser MCP

- Contract + **Mock** implemented  
- Real MCP **unavailable** in package/GHA runtime — fail-closed, documented  

## T4 external Academy

- Architecture ready (`run_from_engagement`)  
- Live Academy traffic **not** claimed complete without operator secrets + authorized engagement  

## Local lab

Deterministic HTTP + synthetic scenarios: positive / secure / public / shared / ambiguous + T3 adversarial.

## Artifacts produced

```
normalized_recon.json, target_context.json, opportunities.json,
hypotheses.json, experiments.json, evidence.jsonl, decisions.jsonl,
findings.json, rejected_hypotheses.json, research_episode.json,
skill_used.json, final-report.md, report.json, ledger.db
```


## Auth providers (post-acdf610)

- Mock: offline complete
- MailSlurp / Temp: implemented, opt-in, fail-closed without secrets/browser
- Real authenticated BOLA: blocked on browser runtime + authorized target


## Browser (post-20a06ba)

- FakeAuthBrowserProvider: offline A/B sessions + BOLA lab integration tested
- Real browser (Playwright/MCP): unavailable in default GHA; capability detection fail-closed


## Playwright (optional)

- Extra: `[project.optional-dependencies] browser = ["playwright>=1.40"]`
- Provider: `PlaywrightBrowserProvider` (lazy import)
- GHA: `.github/workflows/browser_lab.yml` (dispatch only)
- Default CI: no browser install
