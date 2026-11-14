# VeriForge — Engineering Roadmap (v2 Audited)

> **Goal:** Build VeriForge from zero to a compiler-grade, zero-false-positive multi-file security & business-logic verifier in 5 structured phases. Every phase has strict mathematical/performance SLAs and a binary verification gate.

---

## Phase 0: Workspace, Config & Two-Phase Cache (`vf-core`)
- **Deliverables:**
  - Cargo workspace (`vf-core`, `vf-graph`, `vf-sandbox`, `vf-tui`, `vf-report`, `vf-ai`).
  - `.veriforge.toml` parser (custom `auth_guards`, `ignore_paths`, `sandbox_boot_cmd`).
  - `ignore`-based parallel directory walker + `BLAKE3` file fingerprinter.
  - `SQLite` (`rusqlite` with `bundled` + `WAL` + `FTS5`) two-phase symbol cache.
- **Performance Target:** Walk 13,000 files and compute/check `BLAKE3` hashes in **< 250ms**.
- **Verification Gate:** Run `veriforge index <enterprise_13k_repo>` twice; verify cold pass < 500ms and warm delta pass < 50ms.

## Phase 1: Parallel AST, Middleware Resolution & Guard-Lattice Solver (`vf-graph`)
- **Deliverables:**
  - `tree-sitter` parsers for **TypeScript/JavaScript**, **Rust**, and **Python**.
  - Cross-file symbol linker (`tsconfig.json` aliases, `index.ts` barrel re-exports, Rust `mod`/`use`, route-level middleware attachment).
  - **$O(V + E)$ Guard-Set Lattice Solver** (fixed-point intersection across incoming paths—zero exponential $O(V!)$ path explosion) + BFS shortest unguarded witness extractor.
- **Performance Target:** Parse 3,000 active source files across 3 Rayon threads in **< 2.0s**; re-link global graph + solve lattice in **< 120ms**.
- **Verification Gate:** Automated test suite proving: (1) cross-file edit to `auth.ts` immediately flags unmodified `routes.ts`, and (2) cyclic call graphs terminate in linear time.

## Phase 2: Bubblewrap Sandbox, Mock Shims & Last-Byte Sync PoC Engine (`vf-sandbox`)
- **Deliverables:**
  - Unprivileged `/usr/bin/bwrap` launcher with `--ro-bind` code, `--tmpfs` writable overlays, isolated loopback, `RLIMIT_AS` (1 GiB), and `cgroup v2` / process-group reaper on drop/Ctrl+C.
  - In-sandbox deterministic HTTP/Webhook mock responder (`127.0.0.1`) + explicit `UNBOOTABLE` status when external dependencies cannot be mocked.
  - **Last-Byte Sync (Single-Packet Attack) Race Runner:** `tokio::sync::Barrier`-synchronized raw TCP/HTTP frames flushing final byte in `< 50 µs` to prove double-spend / over-credit bugs.
  - **Auth/IDOR Swapper & Negative-Qty/Price-Tamper Runner** + `PROVEN` vs `MITIGATED` classifier + 1-command `veriforge replay <id>` & `curl` PoC.
- **Verification Gate:** Run against `fixtures/vuln-payment-node` and `fixtures/vuln-auth-rust`; confirm 100% detection of double-spend & IDOR with **0 false positives** on patched builds and **0 orphan processes** on `SIGINT`.

## Phase 3: Panic-Safe `ratatui` TUI, SARIF & Interactive HTML Graph (`vf-tui`, `vf-report`)
- **Deliverables:**
  - Panic-safe 3-pane `ratatui` TUI (Proven Flows, Multi-File Trace & Sandbox Proof, Action Bar) + toggleable `[L] Logs` ring-buffer drawer (zero stdout corruption).
  - `g` hotkey to open self-contained interactive HTML/SVG taint-flow graph.
  - `--json`, `--sarif` (SARIF 2.1.0), and `--ci --fail-on proven` exit-code flags.
- **Verification Gate:** End-to-end interactive test on a 13,000-file codebase + live Last-Byte Sync replay inside TUI + `Ctrl+C` terminal cleanliness check.

## Phase 4: Optional Hybrid AI Patcher (`vf-ai`)
- **Deliverables:**
  - Opt-in BYOK / Local Ollama adapter (strictly disabled by default; 0 API cost in core mode).
  - Context minimizer: sends ONLY the proven 3–5 hop witness trace (< 2 KB) to generate a minimal unified `.patch` diff.
  - Closed-loop verification: applies patch in `tmpfs` sandbox and re-runs the exact Last-Byte Sync / IDOR PoC to confirm `[MITIGATED]`.
- **Verification Gate:** Patch `vuln-payment-node` double-spend via AI adapter and automatically verify the fix passes the Last-Byte Sync race PoC.

## Phase 5: Universal 6-Layer Engine, MCP Server & Open-Source Release
- **Deliverables:**
  - Universal 6-layer verification engine: Secrets & Misconfigurations (`VF-SEC-*`, `VF-CFG-*`), Offline Dependency & Lockfile Audit (`VF-DEP-001`), Sanitizer-Aware Cross-File Taint (`VF-SQLI-001`, `VF-CMDI-001`, `VF-PATH-001`, `VF-SSRF-001`), Auth & IDOR Ownership Lattice (`VF-AUTH-001`, `VF-IDOR-001`), 12-Way Barrier Race Prover (`VF-RACE-001`), and Frontend ↔ Backend API Contract Verification (`VF-FE-404`, `VF-FE-ERR`).
  - Polyglot `Tree-sitter` support across TypeScript/TSX, JavaScript/JSX, Go (`net/http`, Gin, Echo, Chi), Python (FastAPI, Flask, Django), and Rust (Axum, Actix-Web).
  - Stdio JSON-RPC 2.0 Model Context Protocol server (`veriforge mcp`) for AI coding agents (`veriforge_scan`, `veriforge_explain_finding`, `veriforge_init`).
  - GitHub Actions CI workflow (`veriforge init --ci`), release binary stripping, benchmark suite, and complete documentation.
- **Verification Gate:** Clean release binary (< 15 MB), full 27-test suite green, 0 clippy warnings, 0 self-scan false positives.
