# BugBountyCI → Lite Recon Adapter

Lite **does not** run recon. It consumes BBCI (or BBCI-shaped) JSON.

## Required for BOLA path

| Field | Required | Notes |
|-------|----------|--------|
| `primary_host` or `host` | yes | Scope + target |
| `endpoints` and/or `urls` | recommended | Methods, paths, parameters |
| `actors` / `identities` (≥2) | for BOLA | Multi-identity signal |
| `resources` | recommended | Ownership hints |
| `hosts` | optional | All in-scope hosts |
| `technologies` | optional | Preserved, not used for verdicts |
| `observations` / `http_observations` | optional | Probe metadata only |

## Example fixture

`examples/fixtures/bbci_recon_sample.json`

```bash
python -m agent_lite.cli \
  --recon examples/fixtures/bbci_recon_sample.json \
  --scope config/scope.yaml \
  --scenario positive \
  --engagement-id eng_bbci
```

## Real BBCI drop-in

1. Export BBCI recon artifact as JSON.
2. Point `--recon` at that file (or wrap under `bundle` / `recon` / `artifact`).
3. Ensure scope.yaml allows the primary host.
4. Prefer explicit `actors` + `resources` for BOLA; without them the pipeline may lack multi-identity opportunity.
5. No live HTTP unless `mode=http|engagement` + authorized engagement.

## Not invented by adapter

Missing fields stay empty. Adapter never fabricates endpoints, actors, or ownership.
