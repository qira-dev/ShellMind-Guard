---
name: guard-scan
description: Run ShellMind Guard's deterministic 6-layer security and bug scan (Secrets, Misconfigs/JWT logic, Offline Deps, SQLi/CMDi/Path/SSRF/XSS, Auth/IDOR/CSRF, Race, Frontend Contract) via MCP before committing, merging, or shipping backend/full-stack code.
---
# ShellMind Guard Scan

Use the `shellmind-guard` MCP tools to audit the current repository deterministically in milliseconds without guessing.

## Workflow

1. Call `shellmind_guard_scan` with `path: "."` (optionally filtering `layers` such as `["xss","csrf"]` or `min_confidence: "confirmed"` to suppress heuristic findings in CI gates).
2. Group findings by confidence (`PROVEN` -> `CONFIRMED` -> `HEURISTIC`) and severity (`CRITICAL` -> `HIGH` -> `MEDIUM`).
3. For any `CRITICAL` or `HIGH` finding, call `shellmind_guard_explain_finding` with its `finding_id` to inspect the exact cross-file witness hops and source excerpt before proposing edits.
4. Report exact file paths, line numbers, rule IDs, confidence levels, and concrete remediation steps. Never claim a codebase is clean without running `shellmind_guard_scan`.
