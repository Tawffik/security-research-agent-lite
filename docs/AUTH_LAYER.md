# Authenticated testing layer

## Wiring

```
auth_profile → factory → AuthOrchestrator(mailbox, provider_kind, browser?)
                         → run_two_users()
                         → Session A/B (or WAITING_FOR_AUTH)
```

## Browser

| Runtime | Status |
|---------|--------|
| **FakeAuthBrowserProvider** | DONE — offline register→OTP→login→isolated sessions → BOLA labs |
| **Playwright / MCP real** | BLOCKED — not in package deps / GHA by default (`detect_browser_capability`) |

No silent real→fake fallback on real auth profiles.

## Profiles

| Profile | Behavior |
|---------|----------|
| `two_test_users_mock` | Mock mailbox + optional fake browser path |
| `two_test_users_mailslurp` | Real MailSlurp wired; needs key + browser for full auth |
| `two_test_users_temp` | Temp API wired; needs base URL + browser |
| `manual` | WAITING_FOR_AUTH |

## BOLA

- Synthetic secure + fake browser auth → REJECTED  
- Synthetic vulnerable + fake browser auth → CONFIRMED (evidence + R/S/R)  
- **Real authorized target BOLA: not claimed**
