# ShellMind Guard — Master Architecture & Next-Gen Blueprint (v3 Reality-Synced)

> **Mission:** Ultra-fast, zero-bloat, zero-false-positive static + runtime verifier that protects **Web/API backends (First Priority)** as well as **Complex Core Engines, Desktop Software, and Mobile Apps**.
>
> **Non-Negotiable Rule:** **Never sacrifice accuracy or depth for artificial micro-speed.** Keep scans insanely fast by eliminating redundant work (delta caching, bounded parallelism, tiered execution), never by downgrading checks into shallow guesses.
>
> **Codebase Anchor:** Workspace v`0.1.0` (commit `d21223c`, Rust 2024 edition, ~13.3k lines across 7 workspace members).

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
|  init, index, scan |             |  crates/vf-tui      |             | MCP Server (mcp)  |
|  replay, hook, doc |             |  ratatui + [L] logs |             | scan/explain/init |
+--------------------+             +---------------------+             +-------------------+
          |                                   |                                   |
          +-----------------------------------+-----------------------------------+
                                              |
                                              v
+==========================================================================================+
|                 STAGE 1: TWO-PHASE INCREMENTAL INGESTION (crates/vf-core)                |
+==========================================================================================+
|  config.rs (.shellmind-guard.toml)  -> max_threads clamped to 2..=6 (prevents PC lag)    |
|  scanner.rs (ignore::WalkBuilder + bounded rayon + BLAKE3 + 256 KiB in-mem read cap)    |
|  store.rs (XDG ~/.cache/shellmind-guard/<16-hex>/state.db, SQLite WAL + FTS5 + ast_cache)|
+==========================================================================================+
                                              |
                                              v
+==========================================================================================+
|           STAGE 2: 6-LAYER AST + O(V + E) GUARD-SET LATTICE (crates/vf-graph)            |
+==========================================================================================+
|  Tree-sitter (5 AST languages): TypeScript/TSX, JavaScript/JSX, Rust, Python, Go         |
|  Text/Config/Manifest scanners: .sql, Dockerfile/.env/configs, lockfiles & manifests     |
|                                                                                          |
|  GuardKind Lattice + Cross-File BFS Witness Extractor (trace hops):                      |
|   - VF-AUTH-001 (Auth)         - VF-RACE-001 (TxLock)     - VF-IDOR-001 (OwnershipCheck) |
|   - VF-SQLI / CMDI / PATH / SSRF (Taint + Sanitizers)     - VF-FE-404 / VF-FE-ERR (UI)   |
|   - VF-SEC-* (Secrets & .env)  - VF-CFG-* (CORS/TLS/Docker/Crypto/Debug/Cookie)          |
|   - VF-DEP-001 (Offline SQLite OSV cache `advisories.db` + 26 fallback advisories; 9 manifests)|
+==========================================================================================+
                                              |
                +-----------------------------+-----------------------------+
                v                                                           v
+===============================================+   +======================================+
| STAGE 3: ISOLATED RUNTIME PROVER (vf-sandbox) |   | STAGE 4 & 5: REPORT & PATCH PROMPT   |
+===============================================+   +======================================+
| Linux /usr/bin/bwrap (--unshare-all,          |   | vf-report:                           |
|   --unshare-net, --cap-drop ALL, --ro-bind    |   |  - SARIF 2.1.0 + FNV-1a fingerprints |
|   code, --tmpfs /tmp, PGID kill-on-drop)      |   |  - Self-contained HTML/SVG flow card |
| verifier.rs:                                  |   | vf-ai:                               |
|   Executes dynamic checks for:                |   |  - Path-confined 2KB witness prompt  |
|   - GuardKind::Auth   (verify_auth_invariant) |   |  - Opt-in HTTP/TLS client (`reqwest` |
|   - GuardKind::OwnershipCheck (IDOR A/B probe)|   |    + `rustls` ring, loopback/HTTPS)  |
|   - GuardKind::TxLock (Last-Byte Sync Barrier)|   |  - Safe pure-Rust diff applier +     |
| Statuses: Proven | Mitigated | SuspectUnverif |   |    `--apply-check` temp re-verifier  |
+===============================================+   +--------------------------------------+
```

### Explicit Gap Correction (Implemented Reality vs Previous v2 Claims)

Future planning strictly anchors to what actually exists in code today rather than stale v2 documentation:
1. **Cache location:** `state.db` lives outside repositories under `$XDG_CACHE_HOME/shellmind-guard/<repo_hash_16>/state.db`, so scans never dirty `git status`.
2. **Sandbox isolation & OS parity:** On Linux, `bwrap.rs` enforces `--unshare-all --unshare-net --new-session --cap-drop ALL --die-with-parent` + process-group `kill -9 -<pgid>` on Drop/Ctrl+C. On **Windows (`#[cfg(not(unix))]`) and macOS (without `bwrap`)**, isolated runtime sandboxing currently fails closed unless `--unsafe-host-fallback` (Unix) is used; `cgroups v2`, `RLIMIT_AS`, macOS `sandbox-exec`, and Windows Job-Object isolation remain future hardening items.
3. **Dynamic protocol & payload support:** `vf-sandbox` dynamically executes `GuardKind::Auth`, `GuardKind::OwnershipCheck` (`IDOR` User A vs User B probes via `SandboxConfig` headers), and `GuardKind::TxLock` over plaintext loopback HTTP/1.1 (`tokio::net::TcpStream` + `SandboxConfig::loopback_port()`) using configurable `probe_body` or default JSON payloads. Webhook signature/Stripe mocks and an explicit `UNBOOTABLE` status remain future expansion.
4. **AI integration:** `vf-ai` stays `Disabled` by default (`0` network calls), builds bounded `<= 2048`-byte root-confined prompts, supports opt-in Ollama (loopback-restricted) & OpenAI-compatible HTTP/TLS endpoints (`--trust-repo-config`), and verifies unified diffs via `--apply-check` inside an isolated temporary workspace copy without mutating the repository.
5. **Schema & rule-ID hygiene:** Unused `symbols`/`edges` SQLite tables are dropped (`findings` tracks `confidence TEXT NOT NULL DEFAULT 'CONFIRMED'` with safe `ALTER TABLE` migration). Hardcoded JWT secret detection emits `VF-SEC-JWT`, JWT verification logic bypasses emit `VF-CFG-JWT-LOGIC`, web taint/CSRF rules emit `VF-XSS-001` & `VF-CSRF-001`, and `--layers` includes `xss,csrf` alongside the original 12 filter tokens (`auth,race,taint,sqli,cmdi,path,ssrf,idor,secrets,config,deps,frontend`).

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
|    └── Shared Hygiene        : Secrets (VF-SEC-*), Config (VF-CFG-*), Local CVE Index     |
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
   - As languages expand beyond the 5 initial grammars, `crates/vf-graph` exposes clean per-language/per-domain extractors feeding the shared `SymbolInfo`, `SinkKind`, and `GuardKind` lattice—preventing `ast.rs` (currently 2,439 lines) from turning into an unmaintainable monolith.
