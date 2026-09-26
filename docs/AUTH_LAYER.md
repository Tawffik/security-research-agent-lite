# Authenticated testing layer

## Wiring (important)

```
auth_profile
  → factory.build_orchestrator()
  → AuthOrchestrator(mailbox=<Mock|MailSlurp|Temp>, provider_kind=...)
  → run_two_users()
```

- **Mock** (`two_test_users` / `two_test_users_mock`): injects synthetic OTP, completes sessions offline.
- **MailSlurp / Temp**: factory **wires the real mailbox class** into the orchestrator.
  - Missing credentials → `WAITING_FOR_AUTH` (no mock fallback).
  - Credentials present, no browser → orchestrator runs and returns `WAITING_FOR_AUTH` / `BROWSER_UNAVAILABLE` (no fake sessions, no OTP inject).
  - Full register→OTP→login needs `BROWSER_MCP_ENABLED` + authorized target (not available in default GHA).

## Profiles

| Profile | Mailbox class | Completes sessions offline? |
|---------|---------------|----------------------------|
| `two_test_users_mock` | MockMailboxProvider | Yes |
| `two_test_users_mailslurp` | MailSlurpMailboxProvider | No (needs browser + live API) |
| `two_test_users_temp` | TempMailboxProvider | No (needs browser + base URL) |
| `manual` | — | WAITING_FOR_AUTH |

## Secrets

`MAILSLURP_API_KEY`, `TEMP_MAIL_BASE_URL`, `TEMP_MAIL_API_KEY`, `BROWSER_MCP_ENABLED`

## Safety

OTP/cookies/API keys never in artifacts. Real profiles never call `inject_otp_email`.
