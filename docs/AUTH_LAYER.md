# Authenticated testing layer

## Profiles (`--auth-profile` / GHA)

| Profile | Behavior |
|---------|----------|
| `two_test_users` / `two_test_users_mock` | Offline Mock OTP + sessions |
| `two_test_users_mailslurp` | Requires `MAILSLURP_API_KEY` **and** `BROWSER_MCP_ENABLED` |
| `two_test_users_temp` | Requires `TEMP_MAIL_BASE_URL` (+ optional key) **and** browser |
| `manual` | `WAITING_FOR_AUTH` |

**No silent fallback:** requesting mailslurp/temp without secrets → `WAITING_FOR_AUTH`, not mock success.

## Providers

```
MailboxProvider
├── MockMailboxProvider          # default CI
├── MailSlurpMailboxProvider      # optional real inbox
└── TempMailboxProvider           # configurable HTTP temp-mail API
```

## Secrets (GitHub Actions)

- `MAILSLURP_API_KEY`
- `TEMP_MAIL_API_KEY` / `TEMP_MAIL_BASE_URL`
- `BROWSER_MCP_ENABLED=1` only when a real browser runtime is attached

## Safety

OTP, passwords, cookies, API keys never in artifacts / LLM / episodes.

## Real authenticated BOLA

**Not claimed complete.** Architecture + MailSlurp/Temp clients exist; full register→OTP→browser→BOLA needs authorized target + browser runtime + working mailbox credentials.
