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
