# Changelog

All notable changes to **ShellMind Guard** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.2.0] - 2026-11-22

### Security & Hardening (8-Phase Full-Repo Audit Remediation)
- **Security Perimeter & Core (`smg-core`):** Blocked IPv6 `[::1]@evil.com` SSRF & port-0 bypasses, clamped untrusted `.shellmind-guard.toml` limits (`load_trusted_from_dir`), zero-copy YAML document slicing with 16 MiB cap, distro-aware dpkg/apk/Go/PEP 503/CVSS v3.1 advisory matching, TOCTOU-safe `File::take` scanning, and `BEGIN IMMEDIATE` transactional SQLite migrations with `0700`/`0600` permissions.
- **Graph, SMT & Specialist Engines (`smg-graph`, `smg-web3`, `smg-hw`, `smg-pqc`, `smg-enterprise`):** Eliminated UTF-8 boundary panics and unbounded AST/scope/taint/CFG recursion, bounded external `z3` execution with kill/reap, capped `RegexBuilder` NFA/DFA limits (`256 KiB`), fixed `smg-web3` reentrancy/solvency precision, enforced `SMG-HW-BOOT` allowlist, dynamic `SystemTime` PQC clock, and mandatory BLAKE3 transcript binding in `smg-enterprise` TEE quotes.
- **Sandbox, AI Patcher, OCI & Live Auditors (`smg-sandbox`, `smg-ai`, `src/`):** Stripped URLs from `reqwest::Error` in `live_verify` (preventing token leaks), bounded `oci_image` `maybe_gunzip` (256 MiB) + POSIX PAX/OCI-layout support, blocked `169.254.169.254` IMDS link-local SSRF across live HTTP/DAST/SQLi/IDOR/Template auditors, enforced 2 MiB bounded HTTP reads, fixed `proxy.rs` tunnel deadlock, enforced 32 KiB MCP response budget, hardened TUI/Proxy panic recovery + `0700`/`0600` exports, and replaced Windows `cmd /C start` with shell-free `explorer.exe`.
- **Workspace, CI/CD & Installers:** Enforced `[workspace.lints]` (`unsafe_code = "forbid"`, `todo = "deny"`, `unimplemented = "deny"`), release `overflow-checks = true`, SHA-pinned GitHub Actions with `actions/attest-build-provenance` SLSA attestations, full `src/` + `crates/` dogfood CI gate, and TLS 1.2+ / fail-closed checksum verification in `install.sh` and `install.ps1`.

### Added (Phases 6–26b + `smg-hw`, `smg-web3`, `smg-pqc`, and `smg-enterprise` Frontier Modules)
- **Confidential Compute Remote TEE & Commercial Licensing (`crates/smg-enterprise`, `--features enterprise`, `smg enterprise ...`):**
  - Added isolated opt-in crate `smg-enterprise` implementing fail-closed `ring` Ed25519 signed license tokens with optional binary BLAKE3 digest pinning, hardware device node detection (`AWS Nitro /dev/nsm`, `Intel TDX`, `AMD SEV-SNP`), PCR0/MRTD + anti-replay nonce quote attestation verification (`verify_tee_attestation_quote`), and HTTPS-enforced `remote-scan` enclave wire client.
- **Post-Quantum Crypto-Agility & Static CBOM (`crates/smg-pqc`, `--features pqc`, `--compliance pqc`, `--cbom <FILE>`):**
  - Added isolated opt-in crate `crates/smg-pqc` implementing Shor/Grover/BHT post-quantum bit reduction (`B_PQ(a)`), Mosca Harvest-Now-Decrypt-Later urgency (`T_HNDL = (X_u + Y_u) - Z`), hybrid KDF combiner & silent downgrade detection, NIST Category 3+ parameter checks (`ML-KEM-768+`, `ML-DSA-65+`, `SMG-PQC-*`), and honest partial CycloneDX 1.5 Static Source & Config CBOM export explicitly tagging `runtimeUnobserved: true`.
- **Web3, Smart Contracts & EVM Execution Oracle (`crates/smg-web3`, `--features web3`):**
  - Added isolated feature-gated crate `crates/smg-web3` (`default = ["hw", "web3"]`, zero overhead on non-Web3 repos) with `tree-sitter-solidity` 1.2.13 CST extraction, Foundry (`out/*.json`) / Hardhat artifact ingestion, exact EVM storage layout slot algebra (ERC-1967, ERC-7201, mapping/array Keccak slots), interprocedural 5-tuple storage-effect graph (`SMG-WEB3-REENTRANCY` including read-only view reentrancy), ERC-4626/AMM rational rounding & Oracle staleness checks (`SMG-WEB3-ROUNDING`, `SMG-WEB3-ORACLE`), ECDSA/EIP-712 replay checks (`SMG-WEB3-REPLAY`), access-control/initializer/delegatecall checks (`SMG-WEB3-ACCESS`), Solana Anchor/`tree-sitter-rust` SVM checks (`SMG-WEB3-SOLANA`), Sui/Aptos Move checks (`SMG-WEB3-MOVE`), and in-process **`revm` v43.0.3 concrete EVM bytecode execution oracle** upgrading verified bytecode exploits to `PROVEN`.
- **Hardware, Firmware & Kernel Driver Verification (`crates/smg-hw`, `--features hw`):**
  - Added isolated optional crate `smg-hw` (default feature `hw`, zero overhead on non-firmware repos) implementing `compile_commands.json` + CMSIS-SVD + GNU `.ld` linker region ingestion, eBPF-style `Tnum` known-bits algebra, wrapped signed/unsigned bitvector intervals (`I_w ⋈ T_w`), bounded `SparseOctagon` ($k \le 12$), Steensgaard pointer alias union-find, product typestate automaton $Q_{\text{hw}}$, and bounded backward-slice `PureRustBvSliceSolver` (`SMG-HW-MMIO`, `SMG-HW-BOUNDS`, `SMG-HW-TOCTOU`, `SMG-HW-IRQ`, `SMG-HW-TYPESTATE`, `SMG-HW-BOOT`, `SMG-HW-CT`, `SMG-HW-SECRETS`), wired into `--layers hw` and `smg rules`/`smg explain`.
- **Precision & CFG/Arena Kernel (`smg-graph`):**
  - Added interned `u32` `SymbolArena` graph compilation, Cooper-Harvey-Kennedy CFG Dominators, 1-hop wrapper lattice inlining, `--changed-since <git-ref>` reverse-caller subgraph slicing, and CycloneDX VEX + BLAKE3 report digests (`smg-report`).
  - Deepened intra/inter-procedural taint precision: pure constant literal folding (`safe_literals` in `TaintEnv`), dynamic handler-map call resolution (`handler_maps` / `handler_aliases`), discarded-sanitizer conditional hardening, and AST-based Rust `#[cfg(test)]` & detector-literal suppression so self-scans stay clean.
  - Added `--layers` rules for CI/CD workflows (`SMG-CICD-001/002`), Kubernetes/RBAC (`SMG-K8S-001/002`), ReDoS (`SMG-DOS-001`), ZipSlip (`SMG-ZIP-001`), weak crypto/timing (`SMG-CRYPTO-001`), async queues (`SMG-QUEUE-001`), GraphQL/WebSocket/gRPC (`SMG-API-001`), LLM/Agent prompt-to-tool execution (`SMG-AI-001`), OAuth2 PKCE/`state`/`redirect_uri` (`SMG-AUTH-PKCE`), HTTP CRLF/Host poisoning (`SMG-HTTP-SMUGGLE`), and workflow state-machine bypass (`SMG-STATE-001`).
- **Warm Sandbox Pool, Wire Oracle, Audit Ledger, MCP Budget & Adaptive TUI (`smg-sandbox`, `smg-ai`, `smg-tui`):**
  - Added `OobSsrfCatcher`, `WireDiffProxy` differential mutation corroboration, filesystem integrity digests, schema-synthesized PoCs, and shared warm server batch probing (`--mode verify-batch`).
  - Added 6 deterministic AST security codemods + tree-sitter syntax validation gate + 3-iteration CEGIS loop (`smg-ai`), 32 KiB bounded MCP scan responses (`src/mcp.rs`), non-secret `.shellmind-guard/audit-history.jsonl` event logging, and adaptive wide-terminal (`width >= 110`) Side-by-Side Diff modal (`smg-tui`).
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
- **Master 4-Audit Security & Mathematical Hardening (`smg-hw`, `smg-web3`, `smg-pqc`, `smg-enterprise`, `smg-graph`, `smg-report`):**
  - **`smg-hw`:** Parameterized `Tnum` & `WrappedInterval` with bit-width masking (`width_mask`) and two's-complement sign-boundary conversion; widened `SparseOctagon` bounds to `i128` with Miné Euclidean floor integer tightening prior to negative-cycle detection; upgraded SVD/linker parsing for per-peripheral `derivedFrom`, `<addressBlock>`, arithmetic expressions, and `!w` negation; added file-matched `compile_commands.json` lookup; and hardened `SMG-HW-TYPESTATE` (branch/return/null-aware), `SMG-HW-MMIO` (read vs write & bitmask filtering), `SMG-HW-BOUNDS` (pointer parameter filtering & dynamic octagon bounds), `SMG-HW-IRQ` (per-lock IRQ state, unlock tracking & all-pairs ABBA), `SMG-HW-BOOT` (checked `verify_signature`), `SMG-HW-SECRETS` (comment-stripped + typed Rust/C `#define`), `SMG-HW-TOCTOU`, per-buffer zeroize, and word-bounded `SMG-HW-CT`.
  - **`smg-web3`:** Replaced Cartesian proxy collision checks with family-stem/file-paired checking; linearized inherited `bases` state variables and recursive multi-dimensional array slots (`uint256[2][3]`) with `u64` `numberOfBytes` and struct-scoped ERC-7201; enforced comment-stripped active `msg.sender` guards and inherited custom modifiers; added byte-offset and branch-disjoint CEI reentrancy tracking with 1-hop internal helper expansion; refined `revm` selector probing to count true storage mutations and construct parameterized ABI calldata; made `decode_hex_bytecode` ASCII-safe; upgraded `check_amm_spot_skew_bps` to 256-bit `U256` arithmetic; and scoped Solana `Context<T>` & Move capability type checks.
  - **`smg-pqc` & `smg-enterprise`:** Enabled `_`/`-` sub-token cipher-suite boundary matching, split FIPS 205 `SLH-DSA` into Categories 1/3/5, classified `RS256` as `AsymmetricSig`, prevented ephemeral KEX (`ECDHE`) from zeroing Mosca HNDL urgency, fixed `#[cfg(test)]` braceless item resets and Rust lifetime `'a` handling in `strip_comments_simple`, verified KDF combiner lines bind both classical and PQC secrets, retained highest severity on deduplication, blocked HTTP redirects (`Policy::none()`) and `|` delimiter injection in remote TEE scans, enforced constant-time digest/nonce comparisons (`ct_eq_bytes`), added transcript BLAKE3 binding, and enforced fail-closed 256-file/symlink/4MiB/TOCTOU and license window/seat invariants.
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
