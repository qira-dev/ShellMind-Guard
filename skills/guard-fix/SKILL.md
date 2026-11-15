---
name: guard-fix
description: Inspect ShellMind Guard findings via MCP, apply minimal verified fixes for Auth, IDOR, Race, Injection, Secrets, or Misconfig bugs, and re-scan to confirm zero remaining critical or high issues.
---
# ShellMind Guard Fix

Remediate verified `shellmind-guard` findings cleanly with zero regressions.

## Workflow

1. Run `shellmind_guard_scan` on the target path to get current findings.
2. Inspect each `CRITICAL` or `HIGH` finding with `shellmind_guard_explain_finding`.
3. Apply the minimal, idiomatic fix matching the finding's root cause:
   - `VF-AUTH-*`: Attach authentication/authorization middleware before the route handler.
   - `VF-RACE-*`: Wrap state/balance/quota mutations in an ACID transaction (`FOR UPDATE`, `db.Transaction`, `$transaction`) or atomic idempotency key.
   - `VF-SQLI-*`: Replace string interpolation/concatenation with parameterized queries (`$1`, `?`).
   - `VF-XSS-*`: Escape or sanitize untrusted HTML (`DOMPurify.sanitize`, `bluemonday`, `bleach.clean`, `ammonia::clean`) and avoid raw `dangerouslySetInnerHTML` / `template.HTML` / `|safe`.
   - `VF-CSRF-*`: Add CSRF middleware (`csurf`, `csrfProtect`), remove `@csrf_exempt`, or scope cookie sessions with `SameSite=Strict`/`Lax`.
   - `VF-CMDI-*`: Replace shell string execution with argument-array APIs (`shell: false`).
   - `VF-IDOR-*`: Scope DB queries by authenticated actor (`user_id` / `owner_id` / `tenant_id`).
   - `VF-SEC-*` / `VF-CFG-*`: Move secrets to environment variables, update `.gitignore`, enforce JWT signature algorithms (no `alg: "none"` or `verify_signature=False`), and harden CORS/TLS/cookie flags.
4. Re-run `shellmind_guard_scan` (or `shellmind-guard replay <ID> --patch-file fix.diff --apply-check` to test unified diffs in an isolated temp workspace) and project tests to verify the finding is resolved.
