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

## Safety
Unauthorized / out-of-scope actions: **fail closed**. Target content: **UNTRUSTED_DATA**.
