# ShellMind Guard — Engineering Roadmap (v3 Next-Gen)

> **Guiding Principle:** Preserve 100% of the working `v0.1.0` deterministic core (`d21223c`), close Web/API verification gaps first without sacrificing accuracy or speed, then expand systematically into **Desktop Core Engines** and **Mobile Application Codebases**.

---

## Baseline Completed (`v0.1.0` — Locked Foundation at `d21223c`)

The initial 5-phase v0.1 build is **done, verified, and must not be broken**:
- **Core & Delta Cache (`vf-core`):** `.shellmind-guard.toml` config, `ignore` + bounded `rayon` (`2..=6` threads) + `BLAKE3` walker, XDG SQLite WAL + FTS5 store (`ast_cache`).
- **6-Layer Graph Engine (`vf-graph`):** `tree-sitter` across **TS/JS, Rust, Python, Go**; $O(V+E)$ Guard-Set Lattice (`Auth`, `TxLock`, `IDOR`, taint sinks `SQLI/CMDI/PATH/SSRF`, secrets, misconfigs, offline manifest advisories, frontend API mismatch/error contract).
- **Isolated Runtime Prover (`vf-sandbox`):** Linux `/usr/bin/bwrap` `--unshare-all --unshare-net` execution, PGID reaper, cancel-safe Last-Byte Sync (`TxLock`) and `Auth` bypass invariant probers.
- **Surfaces (`src/`, `vf-tui`, `vf-report`, `vf-ai`):** CLI, CI workflow generator, `--watch`, `--sarif`, `--html`, panic-safe `ratatui` TUI, Git & Claude `pre-commit` hooks, stdio MCP server (`scan`, `explain_finding`, `init`), and 2 KB root-confined patch prompt builder.

---

## Phase 6: Web/API Priority Closure, Accuracy Hardening & Closed-Loop AI
**Goal:** Make Web & API scanning deeply reliable with lower false positives and real runtime proof expansion.

- **Deliverables:**
  1. **End-to-End Confidence & Verification Grading:** Propagate `PROVEN`, `CONFIRMED_STATIC`, and `HEURISTIC` levels consistently across `vf-graph`, `vf-core` (`store.rs` `findings`), `vf-report` (SARIF/HTML), `vf-tui`, `src/main.rs` (`--fail-on`), and `src/mcp.rs` so CI gates never block on noisy guesses.
  2. **AST-Level Web Security Rules:** Add sanitizer-aware `VF-XSS-001` (unsanitized DOM/HTML sinks), `VF-CSRF-001` (cookie-authenticated state mutations missing CSRF/SameSite guards), and `VF-CFG-JWT-LOGIC` (`alg: "none"`, skipped signature checks), cleanly wired into `--layers` (`xss,csrf`) and MCP tool schemas.
  3. **Configurable Sandbox Profiles + Live `IDOR` Prover (`vf-core` + `vf-sandbox`):** Extend `.shellmind-guard.toml` `[sandbox]` (`base_url` wiring, custom `probe_body`, seeded `user_a_header` / `user_b_header`) and extend `verifier.rs` / `vf-sandbox/src/lib.rs` to prove cross-tenant `GuardKind::OwnershipCheck` (`VF-IDOR-001`) over loopback HTTP inside `bwrap`.
  4. **Real Closed-Loop `vf-ai` Patcher (Opt-in Only):** Add a minimal HTTP client (`ureq` + `rustls` or equivalent zero-bloat crate) in `vf-ai` behind explicit opt-in config (`Disabled` by default), generate minimal unified diff patches, apply in `--tmpfs` inside Linux `bwrap`, and re-run `verify_finding` to confirm `[MITIGATED]`.
  5. **Docs & Repo Hygiene Sync:** Align `README.md` (`VF-SEC-JWT`, `pyproject.toml`, XDG cache path) and remove unused `symbols`/`edges` dead SQLite schema or `.veriforge` fixture cache remnants safely.
- **Verification Gate:** `cargo test --workspace` + fixture regression proving live `IDOR` detection (`PROVEN` when vulnerable, `MITIGATED` when ownership-scoped) with zero impact on existing `Auth`/`TxLock` tests.

---

## Phase 7: High-Speed Offline-First CVE & Advisory Cache (`VF-DEP` Upgrade)
**Goal:** Replace the 26-entry hardcoded `OFFLINE_ADVISORIES` limit without adding network latency or memory bloat to `scan`.

- **Deliverables:**
  1. **Local SQLite Advisory Index (`~/.cache/shellmind-guard/advisories.db`):** Compact indexed lookup by `(ecosystem, package, version_range)` built with Zstd/OSV feeds.
  2. **Explicit Opt-In Sync (`shellmind-guard deps sync`):** Fetches/updates OSV advisory bundles separately on demand. Regular `shellmind-guard scan` stays **100% offline** and fast.
  3. **Strict Semver/Lockfile Matching:** Parse exact resolved versions from `package-lock.json`, `Cargo.lock`, `go.mod`, and pinned `requirements.txt` / poetry / uv lockfiles to minimize false dependency alerts.
- **Verification Gate:** Cold `scan` makes zero network calls; offline advisory lookups complete in `< 20 ms` across real lockfiles with deterministic regression fixtures.

---

## Phase 8: Language & Ecosystem Expansion (Modular AST Plugin Split)
**Goal:** Expand reach to **Mobile Apps, Enterprise Backends, and Native Core Software** while preserving fast compile times and maintainable `vf-graph` modules.

- **Deliverables:**
  1. **Preserve Working 5-Language Core + Modular Trait for New Languages:** Keep the existing 5-language `ast.rs` parser (`TS/JS, Rust, Python, Go`) intact and covered by regression tests, while introducing a clean per-language extractor module (`crates/vf-graph/src/langs/`) feeding the shared `FileAstSummary` and `solve_guard_lattice`.
  2. **Web & Enterprise Expansion:** Add `tree-sitter` extractors for **PHP** (Laravel/Symfony), **Java** (Spring Boot), and **C#** (.NET minimal APIs/controllers).
  3. **Mobile & Native Core Languages:** Add `tree-sitter` extractors for **Kotlin** (Android/Ktor), **Swift** (iOS/Vapor), **Dart** (Flutter), and **C / C++** (native engines, desktop cores, shared libraries).
- **Verification Gate:** Each new language adds parity fixture tests (`routes/functions/imports/sinks/guards`) and keeps incremental delta scans bounded via `max_threads`.

---

## Phase 9: Complex Core-Engine, Desktop Software & Mobile Logic Rules
**Goal:** Move beyond web/payment routes so complex software cores (e.g., cross-OS desktop engines, native libraries, mobile apps) catch reliability, concurrency, and memory hazards accurately.

- **Deliverables:**
  1. **Domain-Aware Analyzer Routing:** Automatically activate Web/API checks for web backends, System/Engine checks for native software cores, and Mobile checks for Android/iOS trees—never running irrelevant rules blindly.
  2. **Core Engine Concurrency & Resource Invariants:**
     - `VF-ENG-DEADLOCK`: Cross-function inconsistent lock acquisition ordering / lock held across blocking or async `.await` calls.
     - `VF-ENG-LEAK`: Unclosed file/socket/DB handles on error-return paths (missing `defer`/`Drop`/RAII/`finally`).
  3. **Native Memory & Boundary Safety (C/C++/Unsafe Rust):**
     - `VF-MEM-BOUNDS`: Unbounded string/buffer copies (`strcpy`, `sprintf`, `memcpy` with untrusted/unchecked length) and unchecked `unsafe` pointer/slice offsets.
     - `VF-ENG-INT`: Untrusted arithmetic leading to allocation size or buffer-index integer overflow.
  4. **Mobile App Security Rules (`Kotlin`/`Swift`/`Dart`):**
     - `VF-MOB-STORAGE` (unencrypted sensitive storage in `SharedPreferences` / plain `UserDefaults`), `VF-MOB-IPC` (exported Android components without permissions), `VF-MOB-TLS` (custom trust-all cert verifiers).
- **Verification Gate:** Dedicated fixture test suites for C++ core-engine concurrency/memory bugs and Kotlin/Swift mobile issues with strict low-false-positive validation.

---

## Phase 10: Deep Inter-Procedural Taint, Targeted Fuzzing & Sandbox Hardening
**Goal:** Raise detection accuracy on multi-hop real-world codebases and complex runtime paths (CI / `--deep` mode).

- **Deliverables:**
  1. **Inter-Procedural Dataflow Propagation:** Track tainted struct/object fields and callback closures across files (`a.foo -> helper(a) -> sink`), reducing both missed multi-hop bugs and false alerts when sanitizers wrap objects.
  2. **Cross-OS Sandbox & Loopback TLS Hardening (`bwrap.rs`, `verifier.rs`):** Add optional `RLIMIT_AS` / `cgroups v2` (Linux), macOS (`sandbox-exec`) / Windows (Job Objects / restricted container) parity beyond Linux-only `bwrap`, optional local `rustls` HTTPS loopback probing, deterministic mock shims, and explicit `UNBOOTABLE` status reporting when external DBs cannot start.
  3. **Targeted Route Spec & Payload Fuzzing (`--deep`):** Extract parameter schemas from AST/OpenAPI specs to test malformed boundaries, price/quantity tampering, and malformed UTF-8/null-byte edge cases in isolated CI runs.
- **Verification Gate:** End-to-end `--deep` verification passes on all fixture apps with zero orphan processes on `SIGINT` and sub-minute CI budgets.
