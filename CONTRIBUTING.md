# Contributing to ShellMind Guard

Thank you for contributing to **ShellMind Guard (`smg`)**! ShellMind Guard is built to compiler-grade standards: deterministic whole-program static verification, cross-OS isolated exploit proving, zero AI API dependency in core verification, and zero documentation/catalog drift.

Every pull request must preserve the architectural invariants, precision guarantees, and verification gates documented below.

---

## 1. Quick Development Setup & Build Profiles

- **Prerequisites:**
  - Rust stable toolchain (**Rust 2024 Edition**, `rustfmt`, `clippy` via [rustup.rs](https://rustup.rs)).
  - *Optional (for live `--boot-cmd` sandbox tests on Linux):* `bubblewrap` (`sudo apt install bubblewrap` / `sudo dnf install bubblewrap`). macOS uses built-in `/usr/bin/sandbox-exec`; Windows uses WSL2 `bwrap` + Win32 Job Objects. All static, formal, and mock-socket unit tests run everywhere without `bubblewrap`.

```bash
# Build full workspace (includes default frontier domains: hw, web3, pqc, enterprise)
cargo build --workspace --locked

# Build lightweight core binary without optional frontier crates
cargo check -p shellmind-guard --all-targets --no-default-features --locked

# Check individual optional feature isolation
cargo check -p shellmind-guard --no-default-features --features hw --locked
cargo check -p shellmind-guard --no-default-features --features web3 --locked
cargo check -p shellmind-guard --no-default-features --features pqc --locked
cargo check -p shellmind-guard --no-default-features --features enterprise --locked
```

---

## 2. Seven Non-Negotiable Systems & Security Invariants

1. **Linear $O(V + E)$ Lattice & Bounded Graph/AST Complexity:**
   - Never enumerate all simple paths ($O(V!)$) across call graphs. Whole-program analyses in [`crates/smg-graph/src/lattice.rs`](crates/smg-graph/src/lattice.rs) must use monotone fixed-point worklists and multi-source BFS.
   - Recursive AST walkers, CFG block builders, and WCSD call-graph traversals (`crates/smg-hw/src/wcsd_dma.rs`) must enforce explicit depth/step caps and depth-valid memoization (`min_valid_depth`), never disabling ancestor memoization on horizon cutoffs.
2. **Single-Pass Parsing, `OnceLock<Regex>`, & Zero Global Map Clone Storms:**
   - Parse each source file at most once per pass with `tree-sitter` on bounded `rayon` pools, borrowing `IndexedFile::cached_bytes` via `Cow<'_, str>` instead of redundant `fs::read_to_string` calls.
   - Compile regexes exclusively via `std::sync::OnceLock<Regex>`—never inside per-file, per-function, or per-line loops.
   - Read immutable global context tables (such as firmware `#define` constants in `FirmwareContext`) via $O(1)$ shared references rather than cloning into per-function or per-branch maps.
3. **Two-Phase Incremental Cache Soundness:**
   - Per-file `FileAstSummary` records may be cached by `(mtime_ns, size_bytes)` + `BLAKE3` digest in SQLite WAL (`crates/smg-core/src/store.rs`).
   - Global cross-file linking and `solve_guard_lattice` **must always execute fresh in RAM** so modifying a shared middleware (`auth.ts`) immediately updates downstream callers (`routes.ts`).
4. **Fail-Closed Untrusted Repository & Network Hygiene:**
   - `trust_repo_config` defaults to `false`: untrusted `.shellmind-guard.toml` files and `.gitleaks.toml` allowlists must **never** suppress findings, widen `ignore_paths`, execute `[sandbox] boot_cmd`, or trigger `[ai]` network calls unless `--trust-repo-config` is explicitly passed.
   - Every live network engine (`src/dast_audit.rs`, `src/sqli_audit.rs`, `src/idor_audit.rs`, `src/templates_audit.rs`, `src/http_audit.rs`, `src/proxy.rs`, `crates/smg-ai`) must enforce DNS pinning and **unconditionally block cloud IMDS / link-local (`169.254.0.0/16`, `fe80::/10`) and loopback smuggling**, even when `--allow-remote` is passed.
   - GitHub Actions workflows under `.github/workflows/` must pin third-party actions to full 40-character commit SHAs and set `persist-credentials: false` with `permissions: contents: read`.
5. **Cross-OS Determinism & Graceful Async Socket Lifecycle:**
   - Normalize path separators (`replace('\\', "/")`) across Windows/Unix and sort `HashMap` keys before building fallback suffix indexes so scan outputs are 100% deterministic across runs.
   - In async Tokio socket proxies and tests (`crates/smg-sandbox`), split full-duplex streams cleanly (`into_split()` + `tokio::join!`) and call `.shutdown().await` before dropping sockets to avoid `XNU`/Winsock `ECONNRESET` (`RST`) races on macOS and Windows CI runners.
6. **Strict `stdio` MCP & Alternate-Screen TUI Hygiene:**
   - In `smg mcp` (`src/mcp.rs`), `stdout` is strictly reserved for newline-delimited JSON-RPC 2.0 payloads bounded to `<= 32,768` bytes (`MAX_MCP_RESPONSE_BYTES`); send all diagnostics to `stderr`.
   - In `smg ui` (`crates/smg-tui`), route child sandbox/proxy logs to the bounded ring buffer (`[L]` drawer) so `ratatui` alternate-screen rendering never tears.
7. **Memory Safety & Zero Self-Dogfood Findings:**
   - Keep `unsafe_code = "forbid"` at workspace level (`Cargo.toml`).
   - Running `smg scan src --ci` and `smg scan crates --ci` on ShellMind Guard itself must always report **0 findings** (`fixtures/` intentionally holds vulnerable test apps).

---

## 3. Contributor Crate & Module Map

| Area | Location | Responsibility |
| :--- | :--- | :--- |
| **CLI & Live Engines** | `src/lib.rs`, `src/*_audit.rs`, `src/proxy*.rs`, `src/cdp_engine.rs`, `src/mcp.rs` | 23-subcommand CLI, MCP server, OCI image scanner, TLS/STARTTLS, DAST/CDP, SQLi, IDOR, Nuclei templates, OOB listener, and MITM proxy. |
| **Ingestion & Cache** | `crates/smg-core` | `.shellmind-guard.toml` trust loader, `ignore::WalkParallel`, `BLAKE3` hashing, `Language` enum, SQLite WAL + FTS5 cache, and OSV `advisories.db`. |
| **AST, Lattice & Catalog** | `crates/smg-graph` | 16 Tree-sitter grammars + `.sql` analyzer, taint/CFG/SMT (`QF_BV`/`QF_LIA`), Phase 9 memory/concurrency, AI/MCP/IaC rules, and `RULE_CATALOG`. |
| **Cross-OS Sandbox** | `crates/smg-sandbox` | `bwrap` / macOS Seatbelt / Windows WSL2+Job isolation, 12-way Last-Byte Sync, JSON ledger state classifier, `WireDiffProxy`, and HTTP/2 `DbStateSnapshot`. |
| **Reports & TUI & AI** | `crates/smg-report`, `crates/smg-tui`, `crates/smg-ai` | SARIF 2.1.0, CycloneDX 1.5 VEX, OpenVEX v0.2.0, HTML/SVG graphs, 60fps `ratatui` UI, deterministic AST codemods, and opt-in CEGIS patcher. |
| **Frontier Crates** | `crates/smg-hw`, `crates/smg-web3`, `crates/smg-pqc`, `crates/smg-enterprise` | Feature-gated Firmware (`Tnum`/`SparseOctagon`/SVD/WCSD), Web3 (`tree-sitter-solidity`/`revm`/Solana/Move), PQC (`CBOM`/HNDL), and TEE attestation. |

---

## 4. Adding a New Security Rule (4-Step Zero-Drift Protocol)

CI automatically cross-checks every emitted `SMG-*` rule ID against `RULE_CATALOG` and `README.md` via [`tests/readme_catalog_sync.rs`](tests/readme_catalog_sync.rs). Follow all 4 steps whenever adding or renaming a rule:

1. **Implement the Detector & Sanitizer Disproof:**
   - Add the static/AST/frontier check in the appropriate module (`crates/smg-graph/src/*`, `crates/smg-hw/src/*`, `crates/smg-web3/src/*`, `crates/smg-pqc/src/*`, or `src/*_audit.rs`).
   - Assign an honest `Confidence` tier (`Proven` only for mathematical/bytecode/exact structural invariants; `Confirmed` for unguarded route-to-sink witness paths; `Heuristic` for local patterns).
2. **Register `RuleDoc` in `RULE_CATALOG`:**
   - Add a complete `RuleDoc` entry (`rule_id`, `layer`, `severity`, `title`, `description`, `vulnerable_example`, `fixed_example`, `remediation`) in [`crates/smg-graph/src/rules.rs`](crates/smg-graph/src/rules.rs).
   - Verify `smg explain <NEW_RULE_ID>` renders cleanly.
3. **Add Paired Vulnerable (`TP`) + Adversarial Safe-Twin (`TN`) Tests:**
   - Add at least one positive case (`expect_finding: true`) **and** one realistic hardened/sanitized lookalike (`expect_finding: false`) in [`crates/smg-graph/tests/adversarial_precision_bench.rs`](crates/smg-graph/tests/adversarial_precision_bench.rs) (or the crate's unit test suite for frontier/live rules) so `FP` and `FN` remain strictly `0`.
4. **Update `README.md` & Run the Sync Gate:**
   - Add the new canonical rule ID to the matching layer/domain row in [`README.md`](README.md) (update rule count badges if applicable) and run:
     ```bash
     cargo test --test readme_catalog_sync --locked
     ```

---

## 5. Mandatory Pre-PR Verification Checklist

Run these 7 gates locally before opening a Pull Request (identical to `.github/workflows/ci.yml` and `.github/workflows/benchmarks.yml`):

```bash
# 1. Formatting check
cargo fmt --all -- --check

# 2. Default-features Clippy (0 warnings allowed)
cargo clippy --workspace --all-targets --locked -- -D warnings

# 3. Minimal --no-default-features Clippy & unit tests
cargo clippy -p shellmind-guard --all-targets --no-default-features --locked -- -D warnings
cargo test -p shellmind-guard --no-default-features --locked

# 4. Full workspace test suite + 125-case adversarial precision gate
SMG_ENFORCE_PRECISION_GATE=1 cargo test --workspace --locked

# 5. Catalog <-> Code <-> README drift gate
cargo test --test readme_catalog_sync --locked

# 6. Automated benchmark & phase-telemetry suite (writes target/benchmarks/benchmark-report.md)
bash scripts/run_benchmarks.sh

# 7. Self-dogfooding gate (must report 0 findings)
cargo run --release --locked -- scan src --ci
cargo run --release --locked -- scan crates --ci
```
