---
name: guard-scan
description: Run ShellMind Guard's deterministic 18-language security, business-logic, concurrency, memory, mobile, HW/Web3/PQC/AI, and live DAST/SQLi/Proxy/Nuclei scans via MCP or standalone CLI before committing, merging, or shipping code.
---
# ShellMind Guard Scan

Use the `shellmind-guard` MCP tools (when connected as a plugin) **or** the standalone `smg` CLI (`shellmind-guard` alias also works) to audit a repository deterministically in milliseconds without guessing.

## Mode Selection (Plugin MCP vs Standalone CLI)

- **Plugin / MCP Mode:** Call `shellmind_guard_scan` (`path`, optional `layers`, `min_confidence`, `deep`) and `shellmind_guard_explain_finding` (`finding_id`, `path`). Initialize missing configs with `shellmind_guard_init`.
- **Standalone CLI Mode (when MCP is unavailable or runtime/live proofs are needed):**
  - Launch interactive TUI workspace (default when run in TTY): `smg` (or `smg ui . --deep`)
  - Environment & readiness check: `smg doctor .`
  - Optional offline OSV advisory sync (keeps scans 100% offline): `smg deps sync .` (or `--online-osv` on `smg scan` / `smg image`)
  - Fast static + deep schema scan: `smg scan . --deep --format json` (add `--git-history`, `--gitleaks-config .gitleaks.toml`, `--openvex out.vex.json`, `--cbom out.cbom.json`, `--min-confidence confirmed`, `--baseline .smg-baseline.json`, or `--ci` for merge gates)
  - Container image scan: `smg image <TAR_OR_DIR> [--online-osv] [--json]`
  - Live loopback/lab auditors: `smg dast <URL> [--spa] [--cookie ...] [--auth-header ...]`, `smg sqli <URL> [--data ...] [--test-headers auto] [--test-cookies ...]`, `smg proxy [--mitm-ca]` (`smg proxy export-ca`), `smg templates <TARGET> --templates <DIR> [--oob-server <ADDR>]` (`smg oob serve`), `smg tls <HOST:PORT> [--starttls smtp|imap|ftp]`, `smg idor --config <FILE> [--allow-mutations]`, `smg verify-attestation --platform tdx|sev-snp|nitro --input <FILE>`
  - Rule catalog & remediation lookup: `smg rules` and `smg explain <RULE_OR_FINDING_ID>`
  - Live Bubblewrap/Seatbelt exploit & fuzz proof: `smg scan . --deep --boot-cmd "<cmd>" [--sandbox-tls] [--mock-shims]`

## Supported Layer Filters (`layers` / `--layers`)

`secrets`, `config` (incl. CORS/JWT/Docker/XXE/Proto/SQL/78 Checkov IaC), `deps`, `taint`, `sqli`, `cmdi`, `path`, `ssrf`, `xss`, `csrf`, `auth`, `idor`, `race`, `frontend`, `engine` (`SMG-ENG-DEADLOCK`, `SMG-ENG-LEAK`, `SMG-ENG-INT`), `memory` (`SMG-MEM-BOUNDS`), `mobile` (`SMG-MOB-STORAGE`, `SMG-MOB-IPC`, `SMG-MOB-TLS`), `deep` (`SMG-FUZZ-SCHEMA`), `hw`, `web3`, `pqc`, `ai`.

## Workflow

1. Run `shellmind_guard_scan` with `path: "."` and `deep: true` (or `smg scan . --deep --format json`). Optionally scope `layers`, set `--exclude-rule`/`--baseline`, or set `min_confidence: "confirmed"` to filter heuristics in CI gates.
2. Group findings by confidence (`PROVEN` -> `CONFIRMED_STATIC` -> `HEURISTIC`) and severity (`CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW`).
3. For any `CRITICAL` or `HIGH` finding, inspect its exact cross-file witness hops and source excerpt with `shellmind_guard_explain_finding` (MCP) or `smg explain <ID>` / `--patch` (CLI) before editing.
4. Report exact file paths, line numbers, rule IDs, confidence levels, and concrete remediation steps. Never claim a codebase is clean without running `shellmind_guard_scan` or `smg scan`.
