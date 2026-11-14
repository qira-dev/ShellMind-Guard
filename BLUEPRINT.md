# ShellMind Guard — Master Architecture & Engineering Blueprint (v2 Audited)

> **Mission:** Zero-False-Positive, Compiler-Grade Multi-File Business-Logic & AI-Code Security Verifier.  
> **Target Machine Baseline:** Linux (Ubuntu/GNOME Wayland), 4-Core CPU, 15 GiB RAM, `rustc 1.98.0`, `/usr/bin/bwrap`.  
> **Core Principle:** 90% Deterministic Rust + Lattice Data-Flow Math + OS Sandbox Proof (0 API cost) + 10% Optional AI Patcher.

---

## 1. High-Level System Architecture (ASCII)

```text
+=========================================================================================+
|                                    SHELLMIND GUARD BINARY                                     |
|                  Single Static Rust Executable (CLI + TUI + HTTP Report)                |
+=========================================================================================+
         |                                    |                                   |
         v                                    v                                   v
+-------------------+              +--------------------+              +------------------+
|   CLI / CI Mode   |              |  Interactive TUI   |              |   Agent / MCP    |
| shellmind-guard scan .  |              |  (ratatui 60fps)   |              |  --json / --sarif|
| Exit Code 0 / 2   |              |  Panic-Safe Raw    |              |  Claude / ZCode  |
+-------------------+              +--------------------+              +------------------+
         |                                    |                                   |
         +------------------------------------+-----------------------------------+
                                              |
                                              v
+=========================================================================================+
|                  STAGE 1: 13,000-FILE INGESTION & TWO-PHASE DELTA CACHE                 |
+=========================================================================================+
|  [ignore::WalkParallel]  --->  [BLAKE3 Hasher]  --->  [SQLite WAL Symbol Cache]         |
|  Skips .git, node_modules,     1.2 GB/s SIMD          Per-file AST symbols cached.      |
|  target/, dist/, binaries      fingerprinting         Only modified files re-parsed.    |
|                                                       Global Edge Linker ALWAYS runs    |
|                                                       on cached symbols (<80ms) so      |
|                                                       cross-file edits never go stale!  |
+-----------------------------------------------------------------------------------------+
                                              | (~1,500–3,500 active source files)
                                              v
+=========================================================================================+
|         STAGE 2: MULTI-FILE CALL GRAPH & GUARD-LATTICE SOLVER (O(V + E) Linear)         |
+=========================================================================================+
|  [Rayon Pool: bounded workers] Tree-sitter Parsers (TS/TSX, JS/JSX, Go, Python, Rust)   |
|    - Layer 1: Secrets (`VF-SEC-*`) & Misconfigurations (`VF-CFG-*`, `Dockerfile`)       |
|    - Layer 2: Offline Manifest & Lockfile Audit (`VF-DEP-001`)                          |
|    - Layer 3: Cross-File Taint & Sanitizer Disproof (`VF-SQLI/CMDI/PATH/SSRF`)          |
|    - Layer 4: Auth & Ownership Lattice (`VF-AUTH-001`, `VF-IDOR-001`)                   |
|    - Layer 5: Concurrency / Transaction Lock Lattice (`VF-RACE-001`)                    |
|    - Layer 6: Frontend <-> Backend Route Contract (`VF-FE-404`, `VF-FE-ERR`)            |
|                                                                                         |
|  [Mathematical Guard-Set Lattice (NO exponential all_simple_paths O(V!) explosion!)]    |
|    For every node v:  G(v) = Intersection_{p in Pred(v)} ( G(p) U Guards(p -> v) )      |
|    If Sink s has RequiredGuard(r) NOT IN G(s):                                          |
|      => Mathematically PROVEN unguarded path exists! Reconstruct 1 concrete witness.    |
+-----------------------------------------------------------------------------------------+
                                              | (Pruned to top 5–25 reachable witness paths)
                                              v
+=========================================================================================+
|           STAGE 3: OS-ISOLATED SANDBOX & LAST-BYTE SYNC PoC VERIFICATION ENGINE         |
+=========================================================================================+
|  [Bubblewrap (/usr/bin/bwrap)] + [cgroups v2 subtree kill] + [Ephemeral Loopback]       |
|    - Unprivileged PID/IPC/Mount/Net isolation (--ro-bind code + --tmpfs cache/data)     |
|    - In-Sandbox Deterministic Shims: Mock Stripe/Webhook/KV responders on 127.0.0.1     |
|      (Prevents false crashes when target app expects external API or local DB)          |
|    - Last-Byte Sync (Single-Packet Attack) Race Runner:                                 |
|        1. Open N=10..25 connections, send headers + body MINUS final 1 byte             |
|        2. Synchronize all N tasks at tokio::sync::Barrier(N)                            |
|        3. Flush final 1 byte simultaneously (<50us skew) -> triggers real DB races!     |
|    - Auth/IDOR Swapper & Negative-Qty / Price-Tamper Engine                             |
|                                                                                         |
|  STATUS CLASSIFICATION:                                                                 |
|   [PROVEN]     Exploit succeeded in sandbox (HTTP 200 / Double-Spend / Cross-Tenant)    |
|   [MITIGATED]  Blocked by runtime lock/DB constraint/middleware (Discarded -> 0 noise)  |
|   [UNBOOTABLE] Target needs external DB/service not mocked -> marked SUSPECT explicitly |
+-----------------------------------------------------------------------------------------+
                                              |
                     +------------------------+------------------------+
                     v                                                 v
+----------------------------------------+      +-----------------------------------------+
|   STAGE 4: PROOF, SARIF & GRAPH HTML   |      |  STAGE 5: OPTIONAL AI PATCHER (BYOK)    |
|  - SQLite WAL + FTS5 History Store     |      |  - Disabled by default (0 API cost)     |
|  - Reproducible `curl` + PoC script    |      |  - Receives ONLY the 3-5 proven lines   |
|  - SARIF 2.1.0 + Interactive Web Graph |      |  - Patches tmpfs & re-runs exact PoC!   |
+----------------------------------------+      +-----------------------------------------+
```

---

## 2. Mathematical & Scale Guarantees (13,000 Files / 575 Directories)

Why ShellMind Guard stays sub-4-second and never suffers $O(V!)$ path explosion or stale cross-file edges:

1. **Two-Phase Incremental Cache (No Cross-File Staleness):**
   - **Phase A (Cached by `BLAKE3`):** File $\to$ Local Symbols, Imports, Exports, Local Calls. If `file_hash` matches `SQLite`, skip `Tree-sitter` completely.
   - **Phase B (Always Re-linked in RAM, $<80\text{ms}$):** All cached symbols across 3,000 files are linked into a fresh `petgraph` directed graph. Modifying `auth.ts` immediately invalidates every route in `routes.ts` that imports it.
2. **Guard-Set Lattice Data-Flow ($O(V + E)$):**
   - Instead of enumerating all paths (which explodes on cyclic/enterprise graphs), ShellMind Guard runs a **Worklist Fixed-Point Lattice** from all Entry Points:
     $$\mathcal{G}(v) = \bigcap_{p \in \text{Pred}(v)} \left( \mathcal{G}(p) \cup \text{EdgeGuards}(p \to v) \right)$$
   - A sink $s$ is flagged **only** when a required guard (e.g., `Auth`, `TxLock`, `IdempotencyKey`, `OwnershipCheck`) is absent from $\mathcal{G}(s)$, and BFS extracts the shortest unguarded witness path.
3. **Last-Byte Sync Race-Condition Physics:**
   - Standard `tokio::join!` HTTP requests suffer TCP/TLS jitter ($5\text{–}40\text{ms}$), missing narrow SQLite/Postgres `READ COMMITTED` race windows.
   - ShellMind Guard holds the **final byte** of $N$ pre-buffered HTTP/1.1 or HTTP/2 frames behind a `tokio::sync::Barrier`, releasing all $N$ final bytes within $<50\,\mu\text{s}$ to hit the server's event loop in the same tick.

---

## 3. UI / UX Design — Panic-Safe `ratatui` TUI (60fps)

```text
+-----------------------------------------------------------------------------------------+
| ShellMind Guard v0.1  |  Target: /home/km-abdullah/CloudNest (2,640 src / 13,120 total)       |
| Mode: [Hybrid-NoAI]  |  Scan: 1.38s  |  PROVEN: 2 CRITICAL  |  MITIGATED: 5  |  [?]Help |
+-----------------------------------------------------------------------------------------+
| [1] PROVEN FLOWS (2)       | [2] MULTI-FILE TRACE & SANDBOX PROOF                       |
|                            |                                                            |
| > [CRIT] Double-Spend Race | Flow: POST /api/v1/wallet/withdraw                         |
|   src/routes/wallet.ts:44  |   [1] src/routes/wallet.ts:44   req.body.amount            |
|                            |   [2] src/services/ledger.ts:89 checkBalance() [NO LOCK]   |
|   [HIGH] Cross-Tenant IDOR |   [3] src/db/queries.ts:112     UPDATE balance = bal - amt |
|   src/routes/share.ts:19   |                                                            |
|                            | Sandbox Verification (bwrap, Last-Byte Sync N=15, 38us):   |
| [ ] SUSPECT / UNBOOTABLE   |   Initial Balance: 100.00  |  Sent: 15x $80.00 simultaneously|
|   (0 items)                |   Result: 3x HTTP 200 OK   |  Final Balance: -140.00       |
|                            |                                                            |
|                            | Replay PoC:                                                |
|                            |   $ shellmind-guard replay VF-2026-001 --sync-race 15            |
+----------------------------+------------------------------------------------------------+
| [3] ACTION BAR:  [Enter] Replay PoC  [g] Graph HTML  [L] Logs  [p] AI Patch  [e] Export |
+-----------------------------------------------------------------------------------------+
```

### Terminal & UX Safeguards
- **Panic-Safe Raw Mode:** Global `std::panic::set_hook` guarantees `disable_raw_mode()` + `LeaveAlternateScreen` before printing any panic, never leaving the user's terminal broken.
- **Zero Stdout Pollution:** Child `bwrap` processes and internal `tracing` logs write exclusively to a bounded ring-buffer (`[L]` drawer), never corrupting `ratatui` frames.
- **Configurable Rules (`.shellmind-guard.toml`):** Users can declare custom auth middleware names, ignored paths, or sandbox boot commands in 5 lines of TOML.

---

## 4. OS-Level Sandbox Isolation & Cleanup (`Bubblewrap` + `cgroups v2`)

```text
+------------------------------------------------------------------+
| HOST OS (Ubuntu GNOME) — Untouched & Protected                   |
| - ~/.ssh, ~/.aws, host .env, host DBs NEVER mounted              |
+------------------------------------------------------------------+
          |
          v  Spawns /usr/bin/bwrap --unshare-all --die-with-parent
+------------------------------------------------------------------+
| SANDBOXED MICRO-ENVIRONMENT (Wrapped in cgroup v2 subtree)       |
|  1. Filesystem:                                                  |
|     --ro-bind <project_dir> /app          (Source is Read-Only)  |
|     --tmpfs /tmp  --tmpfs /app/.next/cache --tmpfs /app/data     |
|  2. Network & Mock Shims:                                        |
|     --unshare-net + isolated 127.0.0.1 loopback                  |
|     In-sandbox mock listeners (Payment/Webhook/KV) on 127.0.0.1  |
|  3. Cleanup & Resource Limits:                                   |
|     nice -n 15 + RLIMIT_AS (1 GiB cap)                           |
|     On Drop / Ctrl+C: cgroup.kill = 1 reaps ALL grandchildren!   |
+------------------------------------------------------------------+
```

---

## 5. SQLite Data Model (`WAL Mode + FTS5`)

Stored per-project in `.shellmind-guard/state.db` (or `~/.cache/shellmind-guard/<project_hash>.db`):

| Table | Purpose | Key Columns |
| :--- | :--- | :--- |
| `files` | Incremental BLAKE3 cache | `id`, `rel_path`, `blake3_hash`, `mtime_ns`, `lang`, `last_scan_id` |
| `symbols` | Cached per-file AST nodes | `id`, `file_id`, `kind` (`route`/`middleware`/`auth`/`sink`/`fn`), `name`, `line_start`, `line_end` |
| `edges` | Re-linked call & taint links | `id`, `src_symbol_id`, `dst_symbol_id`, `edge_type`, `guard_tag`, `taint_var` |
| `findings` | Proven & suspect findings | `id`, `scan_id`, `rule_id`, `severity`, `status` (`PROVEN`/`MITIGATED`/`SUSPECT`/`UNBOOTABLE`), `trace_json`, `poc_cmd` |
| `findings_fts` | Instant FTS5 search | Virtual table indexing `rule_id`, `trace_json`, `poc_cmd` |
