# ShellMind Guard — Master Architecture & Next-Gen Blueprint (v3 Reality-Synced)

> **Mission:** Ultra-fast, zero-bloat, zero-false-positive static + runtime verifier that protects **Web/API backends (First Priority)** as well as **Complex Core Engines, Desktop Software, and Mobile Apps**.
>
> **Non-Negotiable Rule:** **Never sacrifice accuracy or depth for artificial micro-speed.** Keep scans insanely fast by eliminating redundant work (delta caching, bounded parallelism, tiered execution), never by downgrading checks into shallow guesses.
>
> **Codebase Anchor:** Workspace v`1.5.0` (Rust 2024 edition, **11 workspace members**: unified `smg`/`shellmind-guard` root binary + 10 specialized crates including 4 isolated Frontier Domain crates `smg-hw`, `smg-web3`, `smg-pqc`, and `smg-enterprise`).

---

## 1. Existing Implemented Architecture (Preserved Core — Do Not Break)

The current repository (`d21223c`) already delivers a complete, tested deterministic core. All next-generation extensions build **additively** around these locked primitives without breaking existing behavior:

```text
+==========================================================================================+
|                               SHELLMIND-GUARD UNIFIED BINARY                             |
|                     src/main.rs (CLI/CI/Hooks/Watch) + src/mcp.rs (MCP)                  |
+==========================================================================================+
          |                                   |                                   |
          v                                   v                                   v
+--------------------+             +---------------------+             +-------------------+
|  CLI / CI / Watch  |             |  Panic-Safe TUI     |             | Stdio JSON-RPC    |
|  init, index, scan |             |  crates/smg-tui      |             | MCP Server (mcp)  |
|  replay, hook, doc |             |  ratatui + [L] logs |             | scan/explain/init |
+--------------------+             +---------------------+             +-------------------+
          |                                   |                                   |
          +-----------------------------------+-----------------------------------+
                                              |
                                              v
+==========================================================================================+
|                 STAGE 1: TWO-PHASE INCREMENTAL INGESTION (crates/smg-core)                |
+==========================================================================================+
|  config.rs (.shellmind-guard.toml)  -> max_threads clamped to 2..=6 (prevents PC lag)    |
|  scanner.rs (ignore::WalkBuilder + bounded rayon + BLAKE3 + 256 KiB in-mem read cap)    |
|  store.rs (XDG ~/.cache/shellmind-guard/<16-hex>/state.db, SQLite WAL + FTS5 + ast_cache)|
+==========================================================================================+
                                              |
                                              v
+==========================================================================================+
|           STAGE 2: 6-LAYER AST + O(V + E) GUARD-SET LATTICE (crates/smg-graph)            |
+==========================================================================================+
|  Tree-sitter (16 AST languages): TS/TSX, JS/JSX, Rust, Python, Go (`ast.rs`) +             |
|    modular `langs/`: PHP, Java, C#, Kotlin, Swift, Dart, C, C++, Ruby, Bash, HCL/Terraform|
|  Deep scanners: .sql migrations, Dockerfile/.env/TLS/JWT/XXE/Proto, lockfiles & manifests|
|  Domain Routing (web, system_engine, mobile) + AndroidManifest.xml / Info.plist          |
|  Frontier Domain Crates (default feature-gated, 0ms overhead when domain absent):        |
|   - smg-hw         : CMSIS-SVD, GNU .ld, Tnum/WrappedInterval/SparseOctagon, IRQ/MMIO/Boot|
|   - smg-web3       : Solidity/Foundry/Hardhat, revm v43.0.3 EVM oracle, Solana & Move    |
|   - smg-pqc        : Shor/Grover/BHT, Mosca HNDL, hybrid KDF, CycloneDX 1.5 Static CBOM  |
|   - smg-enterprise : Fail-closed Ed25519 licensing + Nitro/TDX/SEV-SNP remote TEE client |
|                                                                                          |
|  GuardKind Lattice + Cross-File BFS Witness Extractor (trace hops):                      |
|   - SMG-AUTH-001 (Auth)         - SMG-RACE-001 (TxLock)     - SMG-IDOR-001 (OwnershipCheck) |
|   - SMG-SQLI* (SQL/NoSQL/Mass) - SMG-CMDI* (Cmd/SSTI/Deser) - SMG-PATH-001 / SMG-SSRF*       |
|   - SMG-SEC-* (Secrets/Env/UI) - SMG-CFG-* (SQL/JWT/Proto/XXE) - SMG-FE-* / SMG-XSS-001      |
|   - SMG-ENG-* (ABBA Deadlock/.await/Leak/Int) - SMG-MEM-BOUNDS - SMG-MOB-* (Storage/IPC/TLS)|
|   - SMG-DEP-001 (Offline SQLite OSV cache + 26 fallback advisories; 9 manifests)          |
+==========================================================================================+
                                              |
                +-----------------------------+-----------------------------+
                v                                                           v
+===============================================+   +======================================+
| STAGE 3: ISOLATED RUNTIME PROVER (smg-sandbox) |   | STAGE 4 & 5: REPORT & PATCH PROMPT   |
+===============================================+   +======================================+
| Linux /usr/bin/bwrap (--unshare-all,          |   | smg-report:                           |
|   --unshare-net, --cap-drop ALL, --ro-bind    |   |  - SARIF 2.1.0 + FNV-1a fingerprints |
|   code, --tmpfs /tmp, PGID kill-on-drop)      |   |  - Self-contained HTML/SVG flow card |
| verifier.rs:                                  |   | smg-ai:                               |
|   Executes dynamic checks for:                |   |  - Path-confined 2KB witness prompt  |
|   - GuardKind::Auth   (verify_auth_invariant) |   |  - Opt-in HTTP/TLS client (`reqwest` |
|   - GuardKind::OwnershipCheck (IDOR A/B probe)|   |    + `rustls` ring, loopback/HTTPS)  |
|   - GuardKind::TxLock (Last-Byte Sync Barrier)|   |  - Safe pure-Rust diff applier +     |
|   - GuardKind::InputValidation (--deep fuzz)  |   |    `--apply-check` temp re-verifier  |
| Status: Proven | Mitigated | Suspect | Unboot |   +--------------------------------------+
+===============================================+

### Implemented Reality vs Spec Alignment

Current codebase architecture aligned with Phases 1–10:
1. **Cache location:** `state.db` lives outside repositories under `$XDG_CACHE_HOME/shellmind-guard/<repo_hash_16>/state.db`, so scans never dirty `git status`.
2. **Sandbox isolation & OS parity:** On Linux, `bwrap.rs` enforces `--unshare-all --unshare-net --new-session --cap-drop ALL --die-with-parent`, process-group `kill -9 -<pgid>` on Drop/Ctrl+C, optional `--sandbox-mem-mb` (`RLIMIT_AS`), and optional `--cgroup-v2` (`systemd-run --user --scope`). Cross-platform detection (`detect_sandbox_backend()`) and helpers exist for macOS Seatbelt (`build_macos_seatbelt_profile`) and Windows Job Objects (`build_windows_job_wrapper_script`), failing closed on hosts without `bwrap` unless `--unsafe-host-fallback` is explicitly passed.
3. **Dynamic protocol, TLS, mocks & `--deep` fuzzing:** `smg-sandbox` dynamically executes `GuardKind::Auth`, `GuardKind::OwnershipCheck` (`IDOR` User A vs User B probes), `GuardKind::TxLock` (Last-Byte Sync), and `--deep` route schema fuzzing (`SMG-FUZZ-TAMPER`, `SMG-FUZZ-CRASH`, `SMG-FUZZ-ENCODING`) over both HTTP/1.1 and local `rustls` HTTPS (`--sandbox-tls` / `https://` `base_url`), with opt-in loopback mock shims (`--mock-shims` for `/v1/charges`, `/oauth/token`, `/webhooks`) and fast `VerificationStatus::Unbootable` diagnostics when external DBs or deps prevent startup.
4. **AI integration:** `smg-ai` stays `Disabled` by default (`0` network calls), builds bounded `<= 2048`-byte root-confined prompts, supports opt-in Ollama (loopback-restricted) & OpenAI-compatible HTTP/TLS endpoints (`--trust-repo-config`), and verifies unified diffs via `--apply-check` inside an isolated temporary workspace copy without mutating the repository.
5. **Schema & rule-ID hygiene:** Unused `symbols`/`edges` SQLite tables are dropped (`findings` tracks `confidence TEXT NOT NULL DEFAULT 'CONFIRMED'` with safe `ALTER TABLE` migration). Hardcoded JWT secret detection emits `SMG-SEC-JWT`, JWT verification logic bypasses emit `SMG-CFG-JWT-LOGIC`, web taint/CSRF rules emit `SMG-XSS-001` & `SMG-CSRF-001`, and `--layers` includes `xss,csrf` alongside the original 12 filter tokens (`auth,race,taint,sqli,cmdi,path,ssrf,idor,secrets,config,deps,frontend`).

---

## 2. Target Next-Gen Architecture (Web First + Core Software & Mobile Engines)

To cover **Websites/APIs (Priority 1)** alongside **Desktop Core Engines (`C/C++/C#/Rust`) and Mobile Apps (`Kotlin/Java/Swift/Dart/PHP`)** while keeping host machines completely responsive, execution splits cleanly into **Two Execution Tiers** feeding one **Unified Verification & Confidence Engine**:

```text
+------------------------------------------------------------------------------------------+
|                    TIER 1: HOT-PATH STATIC GATE (Save / Pre-Commit / Watch)              |
|  Bounded Rayon Pool (2..=6 threads) + BLAKE3 Delta Cache + Native Tree-sitter Parsers    |
+------------------------------------------------------------------------------------------+
|  [Domain Router]  Selects analyzers per detected file/project ecosystem (zero wasted I/O) |
|    ├── Web & API (Priority 1): Auth, TxLock, IDOR, SQLi/CMDi/Path/SSRF + XSS/CSRF/JWT    |
|    ├── Core Engine / Native  : Deadlock/lock-order, unclosed handles/sockets, unsafe mem |
|    ├── Mobile App Source     : Manifest permissions, insecure storage, exported components |
|    └── Shared Hygiene        : Secrets (SMG-SEC-*), Config (SMG-CFG-*), Local CVE Index     |
+------------------------------------------------------------------------------------------+
                                              |
                                              v
+------------------------------------------------------------------------------------------+
|                    TIER 2: DEEP PROOF ENGINE (--sandbox / --deep / CI Mode)              |
+------------------------------------------------------------------------------------------+
|  1. Cross-File Dataflow & Framework Routing Refinement (Eliminates static guesses)       |
|  2. Expanded bwrap Runtime Provers: Auth Bypass + Last-Byte Race + User-A/B IDOR Swapper |
|  3. Mock Loopback Shims & Strict Confidence Grading (PROVEN vs CONFIRMED vs POTENTIAL)   |
|  4. Closed-Loop Patch Verification (Optional BYOK/Ollama diff -> tmpfs -> re-run PoC)    |
+------------------------------------------------------------------------------------------+
```

---

## 3. Core Architectural Invariants (Non-Negotiables)

1. **Speed Comes From Incremental Architecture, Never Shallow Checks:**
   - Default `scan` stays strictly offline with zero network I/O.
   - `BLAKE3` + `ast_cache` skips unchanged files; global RAM graph linking stays linear $O(V + E)$.
   - Never strip out sanitizer checks or cross-file resolution to shave milliseconds at the cost of missed bugs or false positives.
2. **True Accuracy ("Zero Noise" Gate):**
   - Every finding reports explicit confidence/verification tiers:
     - `PROVEN`: Dynamically exploited inside isolated `bwrap` (HTTP/TCP proof).
     - `HIGH` (Deterministic): Unbroken source-to-sink trace or guard absence with verified no sanitizer.
     - `WARNING` / `POTENTIAL`: Heuristic/unverified match kept strictly non-blocking under `--fail-on proven`.
3. **Zero Host-PC Hang Guarantee:**
   - Maintain `default_max_threads()` cap (`2..=6`), per-file size ceiling (`max_file_bytes`), `256 KiB` in-memory cache bound, bounded HTTP body reads (`256 KiB` / `3s` I/O timeout), and zero embedded JVM/Docker/Chromium runtimes inside the core Rust binary.
4. **Domain-Scoped Analyzer Modularity:**
   - As languages expand beyond the 5 initial grammars, `crates/smg-graph` exposes clean per-language/per-domain extractors feeding the shared `SymbolInfo`, `SinkKind`, and `GuardKind` lattice—preventing `ast.rs` (currently 2,439 lines) from turning into an unmaintainable monolith.
