---
name: guard-scan
description: Run ShellMind Guard's deterministic 16-language security, business-logic, concurrency, memory, mobile, and --deep schema scan via MCP or standalone CLI before committing, merging, or shipping code.
---
# ShellMind Guard Scan

Use the `shellmind-guard` MCP tools (when connected as a plugin) **or** the standalone `shellmind-guard` CLI to audit a repository deterministically in milliseconds without guessing.

## Mode Selection (Plugin MCP vs Standalone CLI)

- **Plugin / MCP Mode:** Call `shellmind_guard_scan` (`path`, optional `layers`, `min_confidence`, `deep`) and `shellmind_guard_explain_finding` (`finding_id`, `path`). Initialize missing configs with `shellmind_guard_init`.
- **Standalone CLI Mode (when MCP is unavailable or runtime sandbox proofs are needed):**
  - Environment & readiness check: `shellmind-guard doctor .`
  - Optional offline OSV advisory sync (keeps scans 100% offline): `shellmind-guard deps sync .`
  - Fast static + deep schema scan: `shellmind-guard scan . --deep --format json` (add `--min-confidence confirmed` or `--ci` for merge gates)
  - Live Bubblewrap exploit & fuzz proof: `shellmind-guard scan . --deep --boot-cmd "<cmd>" [--sandbox-tls] [--mock-shims]`

## Supported Layer Filters (`layers` / `--layers`)

`secrets`, `config` (incl. CORS/JWT/Docker/XXE/Proto/SQL/IaC), `deps`, `taint`, `sqli`, `cmdi`, `path`, `ssrf`, `xss`, `csrf`, `auth`, `idor`, `race`, `frontend`, `engine` (`VF-ENG-DEADLOCK`, `VF-ENG-LEAK`, `VF-ENG-INT`), `memory` (`VF-MEM-BOUNDS`), `mobile` (`VF-MOB-STORAGE`, `VF-MOB-IPC`, `VF-MOB-TLS`), `deep` (`VF-FUZZ-SCHEMA`).

## Workflow

1. Run `shellmind_guard_scan` with `path: "."` and `deep: true` (or `shellmind-guard scan . --deep --format json`). Optionally scope `layers` or set `min_confidence: "confirmed"` to filter heuristics in CI gates.
2. Group findings by confidence (`PROVEN` -> `CONFIRMED_STATIC` -> `HEURISTIC`) and severity (`CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW`).
3. For any `CRITICAL` or `HIGH` finding, inspect its exact cross-file witness hops and source excerpt with `shellmind_guard_explain_finding` (MCP) or the `--patch` witness excerpt (CLI) before editing.
4. Report exact file paths, line numbers, rule IDs, confidence levels, and concrete remediation steps. Never claim a codebase is clean without running `shellmind_guard_scan` or `shellmind-guard scan`.
