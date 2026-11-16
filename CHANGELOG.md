# Changelog

All notable changes to **ShellMind Guard** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **16-Language Modular AST & Deep-Stack Engine (`smg-graph`):**
  - Expanded from 5 to 16 languages: added **PHP** (Laravel/Symfony), **Java** (Spring/JAX-RS), **C#** (ASP.NET Core MVC/Minimal APIs), **Kotlin** (Ktor/Android), **Swift** (Vapor/iOS), **Dart** (Dart Frog/Shelf), **C/C++** (`#include` header-to-impl linking, Crow, `cpp-httplib`), **Ruby** (Rails/Sinatra), **Bash/Shell** (`source` linking), and **Terraform/HCL** (module linking & IaC policies).
  - Added deep SQL/NoSQL/ORM mass-assignment rules (`SMG-SQLI-NOSQL`, `SMG-SQLI-MASS`), DOM/browser security (`SMG-FE-STORAGE`, `SMG-FE-MSG`, `SMG-FE-TABNAB`), SSTI/deserialization/prototype pollution/XXE/open-redirect/JWT logic rules (`SMG-CMDI-SSTI`, `SMG-CMDI-DESER`, `SMG-CFG-PROTO`, `SMG-CFG-XXE`, `SMG-SSRF-REDIRECT`, `SMG-CFG-JWT-LOGIC`), and `.sql` migration security checks (`SMG-CFG-SQL-*`).
  - Added domain-aware routing (`web`, `system_engine`, `mobile`) with cross-function lock-order inversion & `.await`-under-lock deadlock detection (`SMG-ENG-DEADLOCK`), resource-handle leak detection (`SMG-ENG-LEAK`), native memory bounds & integer overflow checks (`SMG-MEM-BOUNDS`, `SMG-ENG-INT`), and Android/iOS/Flutter mobile rules (`SMG-MOB-*`).
  - Added Phase 10 cross-file struct-field & callback/closure taint propagation, cross-file sanitizer wrapper disproof, OpenAPI/AST route schema bounds (`--deep`, `SMG-FUZZ-SCHEMA`), and live route tampering/crash/UTF-8 fuzzing (`SMG-FUZZ-TAMPER`, `SMG-FUZZ-CRASH`, `SMG-FUZZ-ENCODING`).
- **Offline SQLite OSV Advisory Cache (`smg-core` & `smg deps sync`):**
  - Added `AdvisoryStore` (`$XDG_CACHE_HOME/shellmind-guard/advisories.db`), `pyproject.toml`, `poetry.lock`, and `uv.lock` parsing, and explicit opt-in `smg deps sync [--from-file]` / `smg deps status`.
- **Ergonomic CLI, Dual Binaries & Developer Workflow (`smg` / `shellmind-guard`):**
  - Added short `smg` primary binary (launches interactive `ratatui` TUI directly on TTY) alongside `shellmind-guard` compatibility alias.
  - Added `smg rules`, `smg explain <RULE_ID>`, `smg completions <SHELL>`, `--format` (`text`, `compact`, `table`, `markdown`, `json`, `sarif`), `--baseline` / `--write-baseline`, `--exclude-rule`, and inline `// smg-ignore: <RULE_ID>` suppression.
  - Added `smg replay --patch-file <DIFF> --apply-check` isolated workspace patch verifier and opt-in `[ai]` patcher (`Ollama` / `OpenAI-compatible` over `rustls`).
  - Added `smg doctor [--probe-ai]`, `smg hook install/uninstall/status`, and `smg hook claude-pre-commit`.
- **Hardened Cross-OS Sandbox (`smg-sandbox`):**
  - Added `--sandbox-tls` (`rustls` loopback), `--mock-shims` offline service stubs, `--sandbox-mem-mb` (`RLIMIT_AS`), `--cgroup-v2` (`systemd-run` user scopes), fast `UNBOOTABLE` diagnostics, macOS `sandbox-exec` Seatbelt execution, and Windows host-fallback support.

### Changed & Fixed
- Refactored internal workspace crates from `sh-*` / `vf-*` to `smg-*` (`smg-core`, `smg-graph`, `smg-sandbox`, `smg-report`, `smg-tui`, `smg-ai`) and unified all rule IDs under `SMG-*`.
- Hardened lattice & taint soundness: fixed cross-file `__AUTH_PREFIX__:` subpath auth propagation, added 2-pass `build_idor_unguarded_bfs_tree` for `SMG-IDOR-001`, per-bit `taint_bit_parents` witness reconstruction, `unrestricted_taint_mask` precision, must-analysis intersection on `var_cleared_masks` in `TaintEnv::join`, tainted local variable rejection in `has_ownership_filter_with_env`, early-return guard support in `classify_fn_guards_cfg`, and deterministic depth-bounded lock-order cycle detection.
- Fixed TS/JS import/require inverted-brace slice panics, restricted `bwrap` home mounts to `.local/bin`, `.cargo/bin`, and `go/bin`, added unique `systemd-run` scope unit IDs, prevented false `PROVEN` verdicts on HTTP `202`/idempotent/queued responses, added metadata-only `scan --watch` polling, bounded OSV/AI HTTP response reads, hardened MCP framing & path confinement, and expanded `claude-pre-commit` hook parsing for `cd -P`, `sh -c`/`bash -lc`/`eval`, and 2-token git flags.

---

## [0.1.0] - 2026-11-14

### Added
- **`smg-core` — Two-Phase Incremental Ingestion & Storage:**
  - Parallel `.gitignore`-aware directory walker (`ignore::WalkParallel`) with multi-segment `ignore_paths` and automatic test/fixture filtering.
  - Fast `(mtime_ns, size_bytes)` metadata pre-check + `BLAKE3` 128-bit content fingerprinting.
  - `SQLite WAL + FTS5` state store (`.shellmind-guard/state.db`) caching per-file `FileAstSummary` blobs (`ast_cache`) and scan findings.
  - Stack auto-detection (`shellmind-guard init [--ci]`) generating `.shellmind-guard.toml` and `.github/workflows/shellmind-guard.yml`.
- **`smg-graph` — Polyglot `Tree-sitter` AST & 6-Layer Guard-Set Lattice Engine:**
  - Parallel `rayon` AST extraction for **TypeScript/TSX**, **JavaScript/JSX**, **Go**, **Python**, and **Rust**.
  - Universal route discovery for Express, Fastify, Hono, Koa, Next.js App Router, NestJS, tRPC, Go `net/http`/Gin/Echo/Chi, Python FastAPI/Flask/Django, and Rust Axum/Actix-Web.
  - Cross-file module resolver supporting `tsconfig.json` path aliases, barrel `index.ts` re-exports, Go package directories, Python relative imports, and Rust `mod`/`use` trees.
  - **Layer 1 (`secrets_config.rs`):** Provider secret detectors (`SMG-SEC-AWS`, `SMG-SEC-STRIPE`, `SMG-SEC-GITHUB`, `SMG-SEC-OPENAI`, `SMG-SEC-ANTHROPIC`, `SMG-SEC-GOOGLE`, `SMG-SEC-SLACK`, `SMG-SEC-PRIVKEY`, `SMG-SEC-DBURL`), Shannon entropy detector (`SMG-SEC-ENTROPY`), `.gitignore` `.env` exposure check (`SMG-SEC-ENV`), and framework/container misconfiguration rules (`SMG-CFG-CORS`, `SMG-CFG-JWT`, `SMG-CFG-TLS`, `SMG-CFG-DEBUG`, `SMG-CFG-COOKIE`, `SMG-CFG-DOCKER`).
  - **Layer 2 (`deps.rs`):** Offline-first manifest and lockfile auditor (`SMG-DEP-001`) for `package.json`, `package-lock.json`, `Cargo.toml`, `Cargo.lock`, `go.mod`, and `requirements.txt`.
  - **Layer 3 (`taint.rs` + `lattice.rs`):** Intra-procedural and cross-file parameter-forwarding taint engine with sanitizer disproof for SQL Injection (`SMG-SQLI-001`), Command Injection (`SMG-CMDI-001`), Path Traversal (`SMG-PATH-001`), and SSRF (`SMG-SSRF-001`).
  - **Layer 4 (`lattice.rs`):** $O(V + E)$ monotone Guard-Set Lattice solver for missing authentication (`SMG-AUTH-001`) and missing resource ownership filters (`SMG-IDOR-001`).
  - **Layer 5 (`lattice.rs`):** Missing transaction/lock invariant detection (`SMG-RACE-001`) on balance and payment mutations.
  - **Layer 6 (`taint.rs` + `lattice.rs`):** Frontend-to-backend route contract verifier (`SMG-FE-404`) and unhandled async mutation / dead handler detector (`SMG-FE-ERR`).
- **`smg-sandbox` — OS-Isolated Bubblewrap (`bwrap`) & Concurrent Race Prover:**
  - Unprivileged Linux namespace sandbox (`bwrap --unshare-all`, `--ro-bind`, `--tmpfs`, `RLIMIT_AS`, process-group `SIGKILL` reaper).
  - Synchronized 12-way concurrent HTTP burst prover (`tokio::sync::Barrier` + `tokio::task::JoinSet` Last-Byte Sync) upgrading static `SMG-AUTH-*` and `SMG-RACE-*` findings to `PROVEN` or `MITIGATED`.
- **`smg-report`, `smg-tui`, `smg-ai` & `shellmind-guard mcp`:**
  - Standard `SARIF 2.1.0` exporter and self-contained Carbon-Slate HTML/SVG witness graph generator.
  - Panic-safe 60fps 3-pane `ratatui` terminal UI (`shellmind-guard ui`).
  - Minimal (<4 KB) witness-hop patch context generator (`--patch`).
  - Stdio JSON-RPC 2.0 Model Context Protocol server (`shellmind-guard mcp`) exposing `shellmind_guard_scan`, `shellmind_guard_explain_finding`, and `shellmind_guard_init`.
