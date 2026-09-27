# Authenticated testing layer + Browser

## Fake Browser
**PASS** — offline register→OTP→login→Session A/B → synthetic BOLA.

## Playwright provider
**IMPLEMENTED** (optional extra `.[browser]`).

```bash
pip install ".[browser]"
python -m playwright install chromium
```

Default `pip install .` does **not** install Playwright.

## Default CI
Browser-independent — existing tests pass without Playwright (browser tests skipped).

## Browser Lab (GHA)
Workflow: **Browser Lab** (`workflow_dispatch`, confirm=`RUN`)
- installs `.[dev,browser]`
- `playwright install --with-deps chromium`
- runs `tests/test_playwright_browser_capability.py` against **localhost synthetic app only**

## Real A/B authentication
Still **blocked** unless real target + mailbox + authorized credentials exist.

## Real authenticated BOLA
**NOT CLAIMED.**


## GHA runner (aligned with BugBountyCI Ubuntu)

Lite workflows use **`ubuntu-24.04`** (same Ubuntu generation as BugBountyCI hunter notes).

BugBountyCI heavy job may use private label `sengi-standard-2-ubuntu-2404` — that runner is **not** available on this repo unless you attach the same self-hosted/org runner.

## MCP browser

**Not implemented as a real provider in Lite.**  
`BROWSER_MCP_ENABLED` → `BROWSER_MISCONFIGURED` until an MCP adapter is wired.

Available today:

| Provider | Status |
|----------|--------|
| FakeAuthBrowser | offline tests |
| PlaywrightBrowserProvider | optional `.[browser]` + Browser Lab workflow |
| MCP | contract only — not executable in GHA Lite |
