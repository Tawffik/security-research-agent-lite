# security-research-agent-lite

Standalone **evidence-driven** Security Research Agent vertical slice.

Not a scanner. Not a full V3/V4 copy. Not a BugBountyCI fork.

```text
Recon artifact → Normalize → Scope → Hypothesis → BOLA skill
  → Evidence → FP Gate → Researcher/Skeptic/Referee → Report
```

## BBCI recon

```bash
python -m agent_lite.cli \
  --recon examples/fixtures/bbci_recon_sample.json \
  --scope config/scope.yaml \
  --scenario positive
```

See `docs/BBCI_RECON.md` for real artifact drop-in.

## Quick start

```bash
pip install -e ".[dev]"
pytest -q
python -m agent_lite.cli \
  --recon examples/fixtures/sample_recon.json \
  --scope config/scope.yaml \
  --scenario positive \
  --engagement-id eng_demo
```

## Scenarios
- `positive` — lab BOLA → CONFIRMED
- `secure` — ownership holds → REJECTED
- `public` — public resource → REJECTED

## Relationship
| Repo | Role |
|------|------|
| BugBountyCI | Recon producer |
| **this repo** | Research / validation loop |
| security-research-agent | Canonical long-term architecture |

No runtime dependency on the full agent.

## LLM + GitHub Actions

1. Repo **Settings → Secrets → Actions → `LLM_API_KEY`** (optional `LLM_BASE_URL`, `LLM_MODEL`)
2. **Actions → Security Research → Run workflow**
3. Inputs: `recon_path`, `scenario`, `use_llm`
4. Download artifact: `final-report.md`, `findings.json`, `research_episode.json`

```bash
# Local analysis (mock LLM if no key)
export LLM_API_KEY=...   # optional
python -m agent_lite.cli \
  --recon examples/fixtures/bbci_recon_sample.json \
  --mode analysis --use-llm \
  --engagement-id eng_demo
```

LLM proposes hypotheses only. ScopeGuard / HttpExecutor still gate every external action.

## Skills (initial set)

`authz-bola` · `authentication-session` · `api-business-logic` · `client-side-js` · `web-anomaly`

## Safety
Unauthorized / out-of-scope actions: **fail closed**. Target content: **UNTRUSTED_DATA**.
