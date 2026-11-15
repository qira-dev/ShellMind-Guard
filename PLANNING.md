# ShellMind Guard — Execution Planning & Change-Safety Contract (v3 Next-Gen)

> **Purpose:** Actionable engineering plan anchored strictly to what currently exists in `d21223c`, protecting working components from unnecessary rewrites while executing Phase 6–10 upgrades cleanly.

---

## 1. Change-Safety Contract: Protected Core vs Extension Seams

**Rule:** Do **not** break or refactor stable code unless a specific milestone requires extending it.

| Crate / File | Current Role (Verified at `d21223c`) | Status | Planned Modification Scope |
| :--- | :--- | :--- | :--- |
| `crates/sh-core/src/config.rs` | `.shellmind-guard.toml` parsing, `2..=6` thread clamp, `[sandbox]` stub | **LOCKED / EXTEND ONLY** | Append optional `[sandbox]` test identity/probe fields (`user_a_header`, `user_b_header`, `probe_body`), `[advisories]` & `[ai]` keys with `#[serde(default)]` |
| `crates/sh-core/src/scanner.rs` | `ignore` parallel walk, bounded `rayon` pool, `BLAKE3`, `256 KiB` cap | **LOCKED / EXTEND ONLY** | Add new file extensions to `Language::from_path` only when that grammar ships in Phase 8 |
| `crates/sh-core/src/store.rs` | XDG cache SQLite WAL + FTS5 + `ast_cache` (+ unused `symbols`/`edges` tables) | **LOCKED / EXTEND ONLY** | Migrate `findings` to include confidence level (Phase 6), clean unused `symbols`/`edges` schema, add read-only `advisories.db` handle (Phase 7) |
| `crates/sh-graph/src/lattice.rs` | $O(V+E)$ Guard-Set Lattice + BFS witness builder | **PROTECTED** | Preserve exact fixed-point intersection logic; add new `GuardKind`/`SinkKind` variants & confidence tag cleanly |
| `crates/sh-graph/src/ast.rs` | `2,439` lines handling 5 working languages (`TS/JS, Rust, Py, Go`) | **PROTECTED / SEAM-EXTEND** | Keep working 5-language extractors intact (no risky rewrite); add Phase 8 languages cleanly via parallel `crates/sh-graph/src/langs/` submodules feeding `FileAstSummary` |
| `crates/sh-graph/src/taint.rs` | SQLi/CMDi/Path/SSRF/FE-ERR rules | **EXTEND** | Add `XSS`/`CSRF`/Confidence tracking (Phase 6), then inter-procedural field flow (Phase 10) |
| `crates/sh-graph/src/deps.rs` | 4-ecosystem parser + 26 hardcoded `OFFLINE_ADVISORIES` | **UPGRADE (Phase 7)** | Keep offline fallback list; layer SQLite advisory DB lookup (`advisories.db`) + lockfile precision |
| `crates/sh-sandbox/src/{lib.rs,bwrap.rs,verifier.rs}` | Linux `bwrap` (`--unshare-all --unshare-net`), PGID reaper, HTTP/1.1 `Auth` & `TxLock` tests | **EXTEND (Phase 6 & 10)** | Keep existing `Auth` + Last-Byte Sync intact; wire `[sandbox]` profiles + `IDOR` two-user swapper (Phase 6), then TLS/cross-OS/mock shims & `RLIMIT_AS` (Phase 10) |
| `crates/sh-ai/src/lib.rs` | `2048`-byte witness prompt builder + disabled provider stub (no HTTP crate yet) | **COMPLETE IN PHASE 6** | Add minimal HTTP client (e.g., `ureq` + `rustls`) to `sh-ai/Cargo.toml` & closed-loop `tmpfs` diff verification |
| `crates/sh-tui`, `sh-report`, `src/{main.rs,mcp.rs}` | Panic-safe TUI, SARIF/HTML, CLI, hooks, MCP server | **PROTECTED / WIRE FLAGS** | Keep 12 existing `--layers` tokens intact; add confidence badges, `xss`/`csrf` layer filters, `has_dynamic_targets` IDOR trigger (`main.rs:304`), MCP schema sync, and `deps sync` subcommand |

---

## 2. Immediate Next Sprint (`Sprint 2` — Phase 6 Execution Plan)

Do not start Phase 8 languages before locking Web/API accuracy and verification quality in Sprint 2:

| Task ID | Crate / File Target | Concrete Task | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `S2-01` | `sh-core/store.rs`, `sh-graph`, `sh-report`, `sh-tui`, `main.rs`, `mcp.rs` | Add explicit finding confidence/verification tier (`PROVEN`, `CONFIRMED`, `HEURISTIC`) consistently across SQLite store, graph output, SARIF/HTML, TUI badges, CLI `--fail-on`, and MCP JSON | CI gates and MCP callers distinguish verified findings cleanly; 0 breaking schema regressions |
| `S2-02` | `sh-graph/src/{ast.rs,taint.rs,lattice.rs}`, `main.rs`, `mcp.rs` | Implement sanitizer-aware AST taint rules for `VF-XSS-001` and `VF-CSRF-001`, add corresponding `GuardKind` variants, and wire `--layers xss,csrf` in CLI + MCP schemas | Precision unit tests pass on vulnerable vs sanitized TS/JS/Python/Go handlers (0 false positives on escaped/CSRF-protected routes) |
| `S2-03` | `sh-graph/src/secrets_config.rs` + `ast.rs` | Add `VF-CFG-JWT-LOGIC` detecting `alg: "none"` and disabled signature checks (`jwt.decode(..., verify=False)` / unverified claims decode) | Flags unsafe JWT verification across JS/TS/Python/Go while ignoring properly verified calls |
| `S2-04` | `sh-core/config.rs`, `main.rs`, `sh-sandbox/src/{lib.rs,verifier.rs}` | Extend `[sandbox]` config (`user_a_header`, `user_b_header`, `probe_body`, wire `base_url`), update `main.rs:301-304` `has_dynamic_targets` to include `OwnershipCheck`, and add live `IDOR` prober inside `bwrap` | Broken-ownership fixture yields `PROVEN`; properly scoped fixture yields `MITIGATED`; missing tokens cleanly yield `SuspectUnverified` |
| `S2-05` | `sh-ai/{Cargo.toml,src/lib.rs}` + `sh-sandbox` | Add zero-bloat HTTP client (`ureq` + `rustls`), implement opt-in `--patch --apply-check` applying unified diff in Linux `bwrap --tmpfs` copy, and re-run `verify_finding` | Requires explicit provider config (still `Disabled` by default, 0 cost); rejects invalid paths and verifies patch transitions finding to `MITIGATED` |
| `S2-06` | `README.md`, `store.rs`, `skills/` | Sync stale doc claims (`VF-SEC-JWT`, `pyproject.toml`, XDG cache path) and safely clean/retire unused `symbols`/`edges` dead SQLite schema | Docs and DB schema match actual runtime code 100% |
| `S2-07` | Full workspace verification | Run `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --locked`, and self-scan (`cargo run -- scan src --ci` & `crates --ci`) | Zero warnings, all workspace + Sprint 2 tests pass on Linux/macOS/Windows CI matrix, zero self-scan false positives |

---

## 3. Speed & Accuracy Guardrails (Mandatory Engineering Rules)

1. **No Accuracy-Destroying Shortcuts:** Never replace AST/taint checks with global raw-text regexes just to shave parse time. Optimize via `BLAKE3` file-level skipping and `ast_cache`, not weaker analysis.
2. **Tier Separation:** Keep default `shellmind-guard scan .` strictly offline, static, bounded to `max_threads` (`2..=6`), and memory-capped (`256 KiB` cached file cap) so developer desktops never lag. Dynamic fuzzing, sandbox loops, and advisory syncing run only when requested (`--boot-cmd`, `--deep`, `deps sync`).
3. **Incremental Modularity (Preserve Working Code):** Keep the existing 5-language parser in `crates/sh-graph/src/ast.rs` intact and add Phase 8 languages via clean `crates/sh-graph/src/langs/` submodules implementing a shared extractor feeding `FileAstSummary`, so existing suites never regress.

---

## 4. Risk & Anti-Bloat Matrix

| Risk | Consequence | Concrete Mitigation |
| :--- | :--- | :--- |
| Adding 7+ new languages inside `ast.rs` at once | Unmaintainable 8,000+ line file, slow compile, regressions in TS/JS/Rust/Py/Go | Route new Phase 8 grammars through isolated `langs/` modules with parity tests while preserving existing `ast.rs` |
| False positives from new Core-Engine / Mobile rules | Erodes user trust ("noisy alerts = useless tool") | Require AST structural evidence (missing unlock / missing sanitize / exported without permission) + label unconfirmed patterns `HEURISTIC` |
| Heavy external CVE DB or sandbox spawning stalls low-end PC | Violates core "zero PC hang" workflow | Store compressed SQLite `advisories.db` indexed by `(ecosystem, pkg)` outside repo; sync only on explicit `deps sync`; keep `bwrap` under strict `IO_TIMEOUT` + PGID kill |
| Sandbox probes breaking on apps needing custom seed users/DBs | `IDOR` tests misclassified as `MITIGATED` | Reuse `.shellmind-guard.toml` `[sandbox]` seed/header hooks and report inconclusive runs strictly as `SuspectUnverified`, never `Mitigated` |
| Refactoring `lattice.rs` or `scanner.rs` unnecessarily | Breaks battle-tested $O(V+E)$ convergence and BLAKE3 delta speed | Treat `scanner.rs`, `store.rs`, and `lattice.rs` core loop as **Protected Core**; cover with snapshot regression tests |
