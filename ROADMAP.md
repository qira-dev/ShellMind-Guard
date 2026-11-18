# ShellMind Guard — Engineering Roadmap (v3 Next-Gen)

> **Guiding Principle:** Preserve 100% of the working `v0.1.0` deterministic core (`d21223c`), close Web/API verification gaps first without sacrificing accuracy or speed, then expand systematically into **Desktop Core Engines** and **Mobile Application Codebases**.

---

## Baseline Completed (`v0.1.0` — Locked Foundation at `d21223c`)

The initial 5-phase v0.1 build is **done, verified, and must not be broken**:
- **Core & Delta Cache (`smg-core`):** `.shellmind-guard.toml` config, `ignore` + bounded `rayon` (`2..=6` threads) + `BLAKE3` walker, XDG SQLite WAL + FTS5 store (`ast_cache`).
- **6-Layer Graph Engine (`smg-graph`):** `tree-sitter` across **TS/JS, Rust, Python, Go**; $O(V+E)$ Guard-Set Lattice (`Auth`, `TxLock`, `IDOR`, taint sinks `SQLI/CMDI/PATH/SSRF`, secrets, misconfigs, offline manifest advisories, frontend API mismatch/error contract).
- **Isolated Runtime Prover (`smg-sandbox`):** Linux `/usr/bin/bwrap` `--unshare-all --unshare-net` execution, PGID reaper, cancel-safe Last-Byte Sync (`TxLock`) and `Auth` bypass invariant probers.
- **Surfaces (`src/`, `smg-tui`, `smg-report`, `smg-ai`):** CLI, CI workflow generator, `--watch`, `--sarif`, `--html`, panic-safe `ratatui` TUI, Git & Claude `pre-commit` hooks, stdio MCP server (`scan`, `explain_finding`, `init`), and 2 KB root-confined patch prompt builder.

---

## Phase 6: Web/API Priority Closure, Accuracy Hardening & Closed-Loop AI
**Goal:** Make Web & API scanning deeply reliable with lower false positives and real runtime proof expansion.

- **Deliverables:**
  1. **End-to-End Confidence & Verification Grading:** Propagate `PROVEN`, `CONFIRMED_STATIC`, and `HEURISTIC` levels consistently across `smg-graph`, `smg-core` (`store.rs` `findings`), `smg-report` (SARIF/HTML), `smg-tui`, `src/main.rs` (`--fail-on`), and `src/mcp.rs` so CI gates never block on noisy guesses.
  2. **AST-Level Web Security Rules:** Add sanitizer-aware `SMG-XSS-001` (unsanitized DOM/HTML sinks), `SMG-CSRF-001` (cookie-authenticated state mutations missing CSRF/SameSite guards), and `SMG-CFG-JWT-LOGIC` (`alg: "none"`, skipped signature checks), cleanly wired into `--layers` (`xss,csrf`) and MCP tool schemas.
  3. **Configurable Sandbox Profiles + Live `IDOR` Prover (`smg-core` + `smg-sandbox`):** Extend `.shellmind-guard.toml` `[sandbox]` (`base_url` wiring, custom `probe_body`, seeded `user_a_header` / `user_b_header`) and extend `verifier.rs` / `smg-sandbox/src/lib.rs` to prove cross-tenant `GuardKind::OwnershipCheck` (`SMG-IDOR-001`) over loopback HTTP inside `bwrap`.
  4. **Real Closed-Loop `smg-ai` Patcher (Opt-in Only):** Add a minimal HTTP client (`ureq` + `rustls` or equivalent zero-bloat crate) in `smg-ai` behind explicit opt-in config (`Disabled` by default), generate minimal unified diff patches, apply in `--tmpfs` inside Linux `bwrap`, and re-run `verify_finding` to confirm `[MITIGATED]`.
  5. **Docs & Repo Hygiene Sync:** Align `README.md` (`SMG-SEC-JWT`, `pyproject.toml`, XDG cache path) and remove unused `symbols`/`edges` dead SQLite schema or `.veriforge` fixture cache remnants safely.
- **Verification Gate:** `cargo test --workspace` + fixture regression proving live `IDOR` detection (`PROVEN` when vulnerable, `MITIGATED` when ownership-scoped) with zero impact on existing `Auth`/`TxLock` tests.

---

## Phase 7: High-Speed Offline-First CVE & Advisory Cache (`SMG-DEP` Upgrade — Completed)
**Goal:** Replace the 26-entry hardcoded `OFFLINE_ADVISORIES` limit without adding network latency or memory bloat to `scan`.

- **Delivered:**
  1. **Local SQLite Advisory Index (`$XDG_CACHE_HOME/shellmind-guard/advisories.db`):** Compact indexed lookup by `(ecosystem, package)` with strict semver range matching (`introduced <= installed < fixed`, `<= last_affected`, skipping Go pseudo-versions) and `advisories_db_stamp()` cache invalidation.
  2. **Explicit Opt-In Sync (`shellmind-guard deps sync` / `deps sync --from-file` / `deps status`):** Fetches OSV `/v1/querybatch` + `/v1/vulns/<id>` over HTTPS/`rustls` (or imports offline OSV JSON files) separately on demand. Regular `shellmind-guard scan` stays **100% offline** and fast.
  3. **Strict Semver/Lockfile Matching:** Parses exact resolved versions from `package-lock.json`, `Cargo.lock`, `go.mod`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `uv.lock` alongside the built-in offline advisory fallback.
- **Verification Gate:** Cold `scan` makes zero network calls; offline advisory lookups complete in `< 20 ms` across real lockfiles with deterministic regression fixtures.

---

## Phase 8: Language & Ecosystem Expansion (Modular AST Plugin Split — Completed)
**Goal:** Expand reach to **Mobile Apps, Enterprise Backends, and Native Core Software** while preserving fast compile times and maintainable `smg-graph` modules.

- **Delivered:**
  1. **Preserved 5-Language Core + Modular Language Plugin Layer:** Kept the existing 5-language `ast.rs` parser (`TS/JS, Rust, Python, Go`) intact with full regression stability, while adding `crates/smg-graph/src/langs/` (`LangProfile`, `build_analyzed_symbol`, and per-language extractors) feeding the shared `FileAstSummary`, cross-file package/header linker, and `solve_guard_lattice`.
  2. **Web & Enterprise Expansion:** Added `tree-sitter` extractors and parity test suites for **PHP** (`tree-sitter-php`: Laravel/Symfony), **Java** (`tree-sitter-java`: Spring Boot/JAX-RS), and **C#** (`tree-sitter-c-sharp`: ASP.NET Core MVC + Minimal APIs).
  3. **Mobile, Native Core, Scripting & Infrastructure-as-Code:** Added `tree-sitter` extractors and parity test suites for **Kotlin** (`tree-sitter-kotlin-ng`: Android/Ktor/Spring), **Swift** (`tree-sitter-swift`: iOS/Vapor), **Dart** (`tree-sitter-dart`: Flutter/Shelf/Dart Frog), **C / C++** (`tree-sitter-c` + `tree-sitter-cpp`: native engines, Crow, cpp-httplib, `#include` header-to-source edge resolution), **Ruby** (`tree-sitter-ruby`: Rails/Sinatra/ActiveRecord), **Bash / Shell** (`tree-sitter-bash`: `eval`/`sh -c`/`curl|bash`/DB CLI/SSRF/destructive path taint + `source` resolution), and **Terraform / HCL** (`tree-sitter-hcl`: `SMG-CFG-IAC-*` public storage, `0.0.0.0/0` network ingress, weak TLS/unencrypted storage, IAM `*` wildcards, and module edge resolution), alongside test-file exclusion in `smg-core` and bounded `max_threads` delta scans.
- **Verification Gate:** All 16 languages covered by regression tests (`routes/functions/imports/sinks/guards/IaC` + clean/sanitized/real `install.sh` zero-false-positive fixtures) with `cargo test --workspace --locked` passing.

---

## Phase 9: Complex Core-Engine, Desktop Software & Mobile Logic Rules (Completed)
**Goal:** Move beyond web/payment routes so complex software cores (e.g., cross-OS desktop engines, native libraries, mobile apps) catch reliability, concurrency, and memory hazards accurately.

- **Delivered:**
  1. **Domain-Aware Analyzer Routing:** [`detect_domain_hints`](crates/smg-graph/src/phase9/mod.rs) & [`resolve_repo_domains`](crates/smg-graph/src/phase9/mod.rs) automatically detect and activate `web`, `system_engine`, and `mobile` domains (`active_domains`), ensuring mobile rules stay dormant on pure backend servers and C/C++ memory rules target native code.
  2. **Core Engine Concurrency & Resource Invariants:**
     - `SMG-ENG-DEADLOCK`: Cross-function `A->B / B->A` lock-order inversion graph solver ([`solve_cross_function_deadlocks`](crates/smg-graph/src/phase9/concurrency.rs)), synchronous mutex guards held across `.await`/blocking sleeps, re-entrant self-deadlocks, and un-released manual locks on early returns (while honoring `std::scoped_lock`, `defer Unlock()`, `tokio::sync::Mutex`, and scoped drops).
     - `SMG-ENG-LEAK`: Unclosed file/socket/DB handles on early error-return paths across C/C++, Go, Python, Java/Kotlin, and JS/TS (skipping factory returns, `if (!fp) return`, RAII, `defer Close()`, `with`, `.use`, and `try/finally`).
  3. **Native Memory & Boundary Safety (C/C++/Unsafe Rust):**
     - `SMG-MEM-BOUNDS`: Unbounded C/C++ copies (`gets`/`strcpy`/`strcat`/`sprintf`/`scanf("%s")`), unchecked variable-length `memcpy`/`memmove`/`strncpy`/`read`/`recv`, and unguarded Rust `unsafe` slice/pointer operations (`get_unchecked`, `from_raw_parts`, `copy_nonoverlapping`, `.offset`).
     - `SMG-ENG-INT`: Unchecked arithmetic in `malloc`/`realloc`/`new[]`/`alloca`, Rust `wrapping_mul`/`wrapping_add` near allocations, and raw multiplication in `unsafe` memory sizing.
  4. **Mobile App Security Rules (`Kotlin`/`Java`/`Swift`/`Dart` + `AndroidManifest.xml`/`network_security_config.xml`/`Info.plist`):**
     - `SMG-MOB-STORAGE` (plaintext `SharedPreferences` / `UserDefaults` credentials, `android:allowBackup="true"`), `SMG-MOB-IPC` (exported permissionless components, dynamic `registerReceiver`, WebView bridges & unvalidated iOS deep links), and `SMG-MOB-TLS` (empty `X509TrustManager`, `HostnameVerifier => true`, `SslErrorHandler.proceed()`, iOS `NSAllowsArbitraryLoads` / `URLCredential(trust:)`, Flutter `badCertificateCallback => true`).
- **Verification Gate:** Dedicated Phase 9 test suite covering C++ cross-function deadlocks, C/Go resource leaks, C++/Rust memory bounds & overflows, Android/iOS/Flutter mobile vulnerabilities, and domain isolation with zero false positives on hardened fixtures.

---

## Phase 10: Deep Inter-Procedural Taint, Targeted Fuzzing & Sandbox Hardening (Completed)
**Goal:** Raise detection accuracy on multi-hop real-world codebases and complex runtime paths (CI / `--deep` mode).

- **Delivered:**
  1. **Inter-Procedural Dataflow Propagation (`ast.rs`, `taint.rs`, `lattice.rs`):** Cross-file struct/object field taint tracking (`a.foo -> helper(a) -> sink`) with safe-field suppression (`a.safe`), inline/cross-file callback closure propagation, and cross-file sanitizer wrapper provenance.
  2. **Cross-OS Sandbox & Loopback TLS Hardening (`bwrap.rs`, `verifier.rs`, `lib.rs`):** Added cross-platform backend detection (`LinuxBubblewrap`, `MacOsSandboxExec`, `WindowsJobObject`, `LocalLoopback`) and Seatbelt/Job-Object helpers alongside optional `RLIMIT_AS` (`--sandbox-mem-mb`) / `systemd-run` cgroups v2 (`--cgroup-v2`) caps on Linux, local `rustls` HTTPS loopback verification (`--sandbox-tls` / `https://` `sandbox.base_url`), deterministic loopback mock shims (`--mock-shims` serving `/v1/charges`, `/oauth/token`, `/webhooks`), and fast `UNBOOTABLE` diagnostics via `/proc/<pid>/stat` process monitoring.
  3. **Targeted Route Spec & Payload Fuzzing (`phase10.rs`, `--deep`):** Extracts parameter schemas from AST route handlers and OpenAPI/Swagger specs (`openapi.*` / `swagger.*`), emits static schema-bound warnings (`SMG-FUZZ-SCHEMA`), and executes sandboxed `--deep` payload fuzzing (`SMG-FUZZ-TAMPER`, `SMG-FUZZ-CRASH`, `SMG-FUZZ-ENCODING`).
- **Verification Gate:** Verified workspace `clippy --all-targets -- -D warnings`, offline `--locked` unit & integration suites across all crates, and live Bubblewrap `--deep` fixture scans with zero orphan processes.

---

## Frontier Expansion & 4-Audit Hardening (Completed)
**Goal:** Extend deterministic verification into Hardware/Firmware, Web3/DeFi (`revm`), Post-Quantum Crypto-Agility, Confidential Compute TEEs, and Cross-OS Sandbox parity—with zero false positives and zero overhead on standard Web/AppSec repositories.

- **Delivered:**
  1. **Hardware & Firmware (`crates/smg-hw`):** `compile_commands.json` + CMSIS-SVD (`derivedFrom`, `<addressBlock>`) + GNU `.ld` linker region ingestion, width-masked `Tnum`/`WrappedInterval`, `i128` `SparseOctagon` with Miné integer tightening, branch-aware alloc/free typestate, MMIO read/write & bitmask checks, and per-lock ISR/ABBA deadlock detection (`SMG-HW-*`).
  2. **Web3 & Smart Contracts (`crates/smg-web3`):** `tree-sitter-solidity` CST, Foundry/Hardhat artifact & storage layout ingestion, EIP-1967/ERC-7201/mapping Keccak slot algebra, branch-disjoint 5-tuple CEI + read-only reentrancy, `U256` AMM skew & ERC-4626 inflation solver, in-process **`revm` v43.0.3** concrete exploit oracle (`PROVEN`), `Context<T>`-scoped Solana Anchor checks, and Sui/Aptos Move capability checks (`SMG-WEB3-*`).
  3. **Post-Quantum Crypto-Agility (`crates/smg-pqc`):** Shor/Grover/BHT post-quantum bit reduction, Mosca HNDL urgency $T_{\text{HNDL}} = (X_u + Y_u) - Z$, hybrid KDF combiner & silent downgrade checks, NIST Cat 1/3/5 `ML-KEM`/`ML-DSA`/`SLH-DSA` checks, and partial **CycloneDX 1.5 Static CBOM** (`--compliance pqc`, `--cbom`).
  4. **Enterprise Licensing & Remote TEE (`crates/smg-enterprise`):** Fail-closed `ring` Ed25519 license verification with constant-time BLAKE3 binary pinning, Linux `/dev/{nsm,tdx_guest,sev-guest}` probing, no-redirect HTTPS enclave client, and constant-time PCR0/MRTD + nonce + transcript BLAKE3 quote verification.
  5. **Cross-OS Sandbox & Precision Gates (`smg-sandbox`, `smg-graph`, `ci.yml`):** Full Linux `bwrap`, macOS `/usr/bin/sandbox-exec` Seatbelt, and Windows WSL2 `bwrap` + Win32 Job Object parity, `SMG_ENFORCE_PRECISION_GATE=1` (`FP = 0`, `FN = 0`), and `--no-default-features` minimal build CI verification across all 11 workspace members (`140/140` tests passing).
