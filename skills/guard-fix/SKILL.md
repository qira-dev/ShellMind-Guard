---
name: guard-fix
description: Inspect ShellMind Guard findings via MCP or CLI, apply minimal verified fixes across Auth, IDOR, Race, Injection, Secrets, Config/IaC, Deps, Frontend, Engine Concurrency/Memory, Mobile, and --deep Schema rules, then verify elimination with re-scan or --apply-check.
---
# ShellMind Guard Fix

Remediate verified `shellmind-guard` findings cleanly across both plugin MCP and standalone CLI workflows with zero regressions.

## Workflow

1. Run `shellmind_guard_scan` (`deep: true` when schema/fuzz rules apply) or `shellmind-guard scan . --deep --format json` on the target path.
2. Inspect each `CRITICAL` or `HIGH` finding with `shellmind_guard_explain_finding` (or `shellmind-guard replay <ID> --patch --boot-cmd ...` for minimal <= 2 KB witness context).
3. Apply the minimal, idiomatic fix matching the rule family:
   - `VF-AUTH-*`: Attach authentication/authorization middleware before the route handler.
   - `VF-IDOR-*`: Scope DB queries by authenticated caller identity (`user_id` / `owner_id` / `tenant_id`).
   - `VF-CSRF-*`: Add CSRF middleware (`csurf`, `csrfProtect`), remove `@csrf_exempt`, or enforce `SameSite=Strict`/`Lax` cookies.
   - `VF-RACE-*`: Wrap balance/quota/state mutations in an ACID transaction (`FOR UPDATE`, `db.Transaction`, `$transaction`) or atomic idempotency key.
   - `VF-SQLI-*`: Use parameterized queries (`$1`, `?`) or safe tagged templates (`VF-SQLI-001`), strict `$eq`/primitive allowlists for MongoDB/Redis (`VF-SQLI-NOSQL`), and explicit field picking instead of raw `req.body` ORM mass assignment (`VF-SQLI-MASS`).
   - `VF-XSS-*`: Escape or sanitize untrusted HTML (`DOMPurify.sanitize`, `bluemonday`, `bleach.clean`, `ammonia::clean`, `html.escape`) and avoid raw `dangerouslySetInnerHTML` / `template.HTML` / `|safe`.
   - `VF-CMDI-*`: Replace shell strings with argument-array APIs (`shell: false`), avoid interpolating input into templates (`VF-CMDI-SSTI`), and replace `pickle.loads`/`yaml.load`/`unserialize`/`ObjectInputStream` with safe parsers (`VF-CMDI-DESER`).
   - `VF-PATH-*`: Normalize with `path.basename` / `filepath.Clean` and enforce canonical base-directory prefix checks before filesystem I/O.
   - `VF-SSRF-*`: Enforce explicit hostname allowlists (`allowedHosts`), safe `https` schemes, private/link-local IP blocking, and non-user-controlled redirects (`VF-SSRF-REDIRECT`).
   - `VF-SEC-*` / `VF-CFG-*`: Move secrets to server env vars (never `NEXT_PUBLIC_*`/`VITE_*` client bundles), gitignore `.env*`, enforce verified JWT algorithms, sanitize `__proto__`/`constructor` keys (`VF-CFG-PROTO`), disable XML external entities (`VF-CFG-XXE`), harden `.sql` procedures (`SET search_path`, RLS), and lock down Terraform IaC (`VF-CFG-IAC-*` ACLs, `0.0.0.0/0` ingress, encryption, IAM).
   - `VF-DEP-001`: Pin `*`/`latest` specs, switch `http://` registries to `https://`, and upgrade vulnerable dependencies (`shellmind-guard deps sync` refreshes local OSV advisories).
   - `VF-FE-*`: Align frontend calls with backend routes (`VF-FE-404`), handle async rejections (`VF-FE-ERR`), store tokens in `HttpOnly` cookies rather than Web Storage (`VF-FE-STORAGE`), validate `event.origin` on `postMessage` (`VF-FE-MSG`), and add `rel="noopener noreferrer"` (`VF-FE-TABNAB`).
   - `VF-ENG-*` / `VF-MEM-*`: Enforce canonical lock ordering (`std::scoped_lock`) and drop sync mutexes before `.await` (`VF-ENG-DEADLOCK`), close file/socket/DB handles across all error returns via RAII/`defer`/`try-finally` (`VF-ENG-LEAK`), use checked arithmetic for allocations (`VF-ENG-INT`), and replace unbounded copies or unguarded `unsafe` indexing with bounds-checked APIs (`VF-MEM-BOUNDS`).
   - `VF-MOB-*`: Store secrets in `EncryptedSharedPreferences`/Keychain/`FlutterSecureStorage` (`VF-MOB-STORAGE`), restrict exported components and WebView JS bridges (`VF-MOB-IPC`), and remove trust-all TLS/ATS bypasses (`VF-MOB-TLS`).
   - `VF-FUZZ-*`: Enforce finite positive schema validation (`amount > 0`, Zod `.finite().positive()`, Pydantic `gt=0`) for `VF-FUZZ-SCHEMA`/`VF-FUZZ-TAMPER`, and return structured `400/422` errors on malformed/non-UTF-8 inputs (`VF-FUZZ-CRASH`/`VF-FUZZ-ENCODING`).
4. Verify elimination cleanly before committing: re-run `shellmind_guard_scan` (with `deep: true` for schema fixes), or test a unified diff in an isolated workspace with `shellmind-guard replay <ID> --patch-file fix.diff --apply-check [--boot-cmd "..."]`, plus the project's test suite.
