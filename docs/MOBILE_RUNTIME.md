# Mobile runtime (GitHub Actions)

## One-time setup

1. GitHub → **Settings** → **Secrets and variables** → **Actions**
2. **New repository secret**
   - `OPENROUTER_API_KEY` (preferred) **or** `LLM_API_KEY`
   - Optional: `OPENROUTER_BASE_URL`, `LLM_BASE_URL`, `LLM_MODEL`

## Run from phone

1. Open repo → **Actions** → **Security Research Agent**
2. **Run workflow**
3. Choose:
   - `engagement_id` (recon resolved automatically)
   - `model_profile` = `free` (or `mock` offline)
   - `execution_mode` = `analysis`
4. Wait → **Artifacts** → open `final-report.md`

## Engagement → recon map

`config/engagements/index.yaml`

| engagement_id | recon |
|---------------|-------|
| eng_demo | examples/fixtures/bbci_recon_sample.json |
| eng_gha | examples/fixtures/bbci_recon_sample.json |
| eng_sample | examples/fixtures/sample_recon.json |

Override with workflow input `recon_artifact` if needed.

## Free model routing

`model_profile=free` uses `config/models/free_registry.yaml` priority list with bounded fallback.
Keys never appear in logs or artifacts (`model_trace.json` is metadata only).
