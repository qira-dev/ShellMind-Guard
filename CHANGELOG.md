# Changelog

All notable changes to **ShellMind Guard** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-14

### Added
- **`vf-core` — Two-Phase Incremental Ingestion & Storage:**
  - Parallel `.gitignore`-aware directory walker (`ignore::WalkParallel`) with multi-segment `ignore_paths` and automatic test/fixture filtering.
  - Fast `(mtime_ns, size_bytes)` metadata pre-check + `BLAKE3` 128-bit content fingerprinting.
  - `SQLite WAL + FTS5` state store (`.shellmind-guard/state.db`) caching per-file `FileAstSummary` blobs (`ast_cache`) and scan findings.
  - Stack auto-detection (`shellmind-guard init [--ci]`) generating `.shellmind-guard.toml` and `.github/workflows/shellmind-guard.yml`.
- **`vf-graph` — Polyglot `Tree-sitter` AST & 6-Layer Guard-Set Lattice Engine:**
  - Parallel `rayon` AST extraction for **TypeScript/TSX**, **JavaScript/JSX**, **Go**, **Python**, and **Rust**.
  - Universal route discovery for Express, Fastify, Hono, Koa, Next.js App Router, NestJS, tRPC, Go `net/http`/Gin/Echo/Chi, Python FastAPI/Flask/Django, and Rust Axum/Actix-Web.
  - Cross-file module resolver supporting `tsconfig.json` path aliases, barrel `index.ts` re-exports, Go package directories, Python relative imports, and Rust `mod`/`use` trees.
  - **Layer 1 (`secrets_config.rs`):** Provider secret detectors (`VF-SEC-AWS`, `VF-SEC-STRIPE`, `VF-SEC-GITHUB`, `VF-SEC-OPENAI`, `VF-SEC-ANTHROPIC`, `VF-SEC-GOOGLE`, `VF-SEC-SLACK`, `VF-SEC-PRIVKEY`, `VF-SEC-DBURL`), Shannon entropy detector (`VF-SEC-ENTROPY`), `.gitignore` `.env` exposure check (`VF-SEC-ENV`), and framework/container misconfiguration rules (`VF-CFG-CORS`, `VF-CFG-JWT`, `VF-CFG-TLS`, `VF-CFG-DEBUG`, `VF-CFG-COOKIE`, `VF-CFG-DOCKER`).
  - **Layer 2 (`deps.rs`):** Offline-first manifest and lockfile auditor (`VF-DEP-001`) for `package.json`, `package-lock.json`, `Cargo.toml`, `Cargo.lock`, `go.mod`, and `requirements.txt`.
  - **Layer 3 (`taint.rs` + `lattice.rs`):** Intra-procedural and cross-file parameter-forwarding taint engine with sanitizer disproof for SQL Injection (`VF-SQLI-001`), Command Injection (`VF-CMDI-001`), Path Traversal (`VF-PATH-001`), and SSRF (`VF-SSRF-001`).
  - **Layer 4 (`lattice.rs`):** $O(V + E)$ monotone Guard-Set Lattice solver for missing authentication (`VF-AUTH-001`) and missing resource ownership filters (`VF-IDOR-001`).
  - **Layer 5 (`lattice.rs`):** Missing transaction/lock invariant detection (`VF-RACE-001`) on balance and payment mutations.
  - **Layer 6 (`taint.rs` + `lattice.rs`):** Frontend-to-backend route contract verifier (`VF-FE-404`) and unhandled async mutation / dead handler detector (`VF-FE-ERR`).
- **`vf-sandbox` — OS-Isolated Bubblewrap (`bwrap`) & Concurrent Race Prover:**
  - Unprivileged Linux namespace sandbox (`bwrap --unshare-all`, `--ro-bind`, `--tmpfs`, `RLIMIT_AS`, process-group `SIGKILL` reaper).
  - Synchronized 12-way concurrent HTTP burst prover (`tokio::sync::Barrier` + `tokio::task::JoinSet` Last-Byte Sync) upgrading static `VF-AUTH-*` and `VF-RACE-*` findings to `PROVEN` or `MITIGATED`.
- **`vf-report`, `vf-tui`, `vf-ai` & `shellmind-guard mcp`:**
  - Standard `SARIF 2.1.0` exporter and self-contained Carbon-Slate HTML/SVG witness graph generator.
  - Panic-safe 60fps 3-pane `ratatui` terminal UI (`shellmind-guard ui`).
  - Minimal (<4 KB) witness-hop patch context generator (`--patch`).
  - Stdio JSON-RPC 2.0 Model Context Protocol server (`shellmind-guard mcp`) exposing `shellmind_guard_scan`, `shellmind_guard_explain_finding`, and `shellmind_guard_init`.
