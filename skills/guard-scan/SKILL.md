---
name: guard-scan
description: Run ShellMind Guard's deterministic 6-layer security and bug scan (Auth, Race, SQLi/CMDi/Path/SSRF, IDOR, Secrets, Misconfigs, Offline Deps, Frontend Contract) via MCP before committing, merging, or shipping backend/full-stack code.
---
# ShellMind Guard Scan

Use the `shellmind-guard` MCP tools to audit the current repository deterministically in milliseconds without guessing.

## Workflow

1. Call `shellmind_guard_scan` with `path: "."` (or the target project root).
2. Group findings by severity (`CRITICAL` -> `HIGH` -> `MEDIUM`).
3. For any `CRITICAL` or `HIGH` finding, call `shellmind_guard_explain_finding` with its `finding_id` to inspect the exact cross-file witness hops and source excerpt before proposing edits.
4. Report exact file paths, line numbers, rule IDs, and concrete remediation steps. Never claim a codebase is clean without running `shellmind_guard_scan`.
