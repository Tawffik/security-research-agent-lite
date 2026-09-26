# Authenticated testing layer

## Abstractions
- `TestIdentity` / `IdentityProvider`
- `MailboxProvider` + OTP extract (no LLM)
- `AuthProvider` + state machine
- `SessionHandle` (secrets stay in provider memory)
- `AuthOrchestrator` (`auth_profile=two_test_users`)

## Safety
OTP, passwords, cookies never in reports, episodes, model_trace, or LLM prompts.

## Mock / CI
Fully offline. Real mailbox vendors are **not** wired by default.

## GHA
`auth_profile: two_test_users` → `auth_trace.json` + `identities.json` (sanitized).
