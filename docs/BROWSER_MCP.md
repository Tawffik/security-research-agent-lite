# Browser MCP Integration (bounded)

## Purpose

Bootstrap an **authorized** PortSwigger Academy lab context (sessions / known object / origin) so the **existing** research pipeline can run T4-style validation.

Browser is **not** the vulnerability detector, verdict engine, recon engine, or a replacement for `HttpExecutor`.

## Architecture

```
Engagement (authorized)
        ↓
BrowserSessionProvider.bootstrap_lab()
        ↓
LabBootstrapContext  (public fields only in artifacts)
        ↓
establish_session × identities  (in-memory headers)
        ↓
IdentityResolver.inject_session
        ↓
HttpExecutor  (existing)
        ↓
ResearchPipeline.run_from_engagement → run_http → _investigate
        ↓
Evidence → FP Gate → Researcher → Skeptic → Referee → Verdict
```

## Provider contract

| Method | Role |
|--------|------|
| `bootstrap_lab(engagement)` | Scope/auth checks; return `LabBootstrapContext` |
| `establish_session(engagement, identity_id, context)` | In-memory session for one identity |
| `collect_lab_context(engagement)` | Known object path / origin |
| `close_session()` | Clear memory |

`LabBootstrapContext.to_public_dict()` **never** includes Cookie / Authorization material.

## Implementations

| Provider | Status |
|----------|--------|
| `MockBrowserSessionProvider` | **Implemented** — deterministic tests, no network |
| Real Browser MCP adapter | **Not implemented** — no Browser MCP exposed to this package runtime |

### Real Browser MCP status

Connected services for this agent environment do **not** currently provide a Browser MCP tool API callable from `security-research-agent-lite` (CLI / GitHub Actions).

Grok chat may have a separate `browser_tab` tool; that is **not** part of the Lite package and must not be assumed in CI.

When a real MCP browser becomes available, implement `McpBrowserSessionProvider` against the **actual** tool contract only — do not invent APIs.

## Safety

- Fail closed: missing auth, unknown host, origin mismatch, budget, ambiguous identity  
- No unrestricted `navigate(any_url)` public API (`attempt_navigate` is constrained + test-oriented)  
- Page text = `UNTRUSTED_DATA` (injection strings never become verdicts)  
- Redirects / foreign origins → BLOCK (aligned with HttpExecutor)  
- No browser-produced `CONFIRMED` / `is_vulnerable`

## T4

Browser does **not** complete T4 by itself. T4 still requires authorized real-lab validation per `docs/T4_LIVE_RUNBOOK.md`.

## CLI / GHA

Browser MCP must **not** run on `push`. Prefer explicit `workflow_dispatch` + existing `confirm_authorized=AUTHORIZED`. Mock path is the default for automated tests.
