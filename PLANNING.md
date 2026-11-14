# ShellMind Guard — Execution Planning & Module Specification (v2 Audited)

---

## 1. Cargo Workspace & Directory Structure

```text
ShellMind Guard/
├── BLUEPRINT.md               # Master ASCII architecture, lattice math & OS/UX design
├── ROADMAP.md                 # Phase 0–5 milestones & verification gates
├── PLANNING.md                # Sprint tasks, crate layout & risk matrix
├── Cargo.toml                 # Workspace root (resolver = "2")
├── crates/
│   ├── vf-core/               # .shellmind-guard.toml, BLAKE3 walker (ignore), SQLite WAL+FTS5 store
│   ├── vf-graph/              # Rayon + Tree-sitter AST (TS/JS/Go/Python/Rust), 6-layer taint & O(V+E) Lattice
│   ├── vf-sandbox/            # Bubblewrap + process-group reaper, 12-way Barrier + JoinSet race & auth prover
│   ├── vf-tui/                # Panic-safe ratatui 3-pane workspace + [L] log ring-buffer
│   ├── vf-report/             # JSON, SARIF 2.1.0, CI exit-codes & self-contained HTML graph
│   └── vf-ai/                 # Optional BYOK / Ollama minimal-context (<4 KB) patch prompt builder
├── src/
│   ├── main.rs                # Unified CLI/TUI entrypoint (`init`, `index`, `scan`, `replay`, `ui`, `mcp`)
│   └── mcp.rs                 # Stdio JSON-RPC 2.0 Model Context Protocol server (`shellmind-guard mcp`)
└── fixtures/                  # Intentionally vulnerable multi-file test apps (Node/TS, Rust)
    ├── vuln-payment-node/     # Double-spend race condition + negative-amount checkout bug
    └── vuln-auth-rust/        # Cross-tenant IDOR + missing middleware guard
```

---

## 2. Sprint 1 Actionable Plan (Phase 0 + Phase 1 Start)

| Task ID | Component | Concrete Engineering Task | Acceptance Criteria |
| :--- | :--- | :--- | :--- |
| `S1-01` | Workspace | Initialize Cargo workspace + `vf-core` + `vf-graph` crates | `cargo check` passes cleanly |
| `S1-02` | `vf-core` | Implement `ignore::WalkParallel`, `.shellmind-guard.toml` & `BLAKE3` scanner | Ignores `node_modules`/`.git`/`target`, hashes 13k files < 250ms |
| `S1-03` | `vf-core` | Implement `.shellmind-guard/state.db` (`SQLite` WAL + FTS5 symbol cache) | Warm delta skips 100% of unchanged files; cross-file link stays fresh |
| `S1-04` | `vf-graph` | Integrate `tree-sitter-typescript` & `tree-sitter-rust` | Extracts routes, middleware, functions, imports, DB/payment sinks |
| `S1-05` | `vf-graph` | Build `petgraph` linker + $O(V + E)$ Guard-Set Lattice solver | Traces `route -> service -> sink` across 3+ files; no $O(V!)$ blowup |
| `S1-06` | `fixtures` | Create `vuln-payment-node` & `vuln-auth-rust` multi-file fixtures | Scanner flags missing lock/auth witness path in < 500ms |

---

## 3. Core Rust Crate Stack (Locked Choices)

- **CLI & Async Runtime:** `clap` (derive), `tokio` (multi-thread), `anyhow`, `tracing`
- **13k-File Walker & Hashing:** `ignore`, `rayon`, `blake3`, `toml`
- **AST & Lattice Graph Engine:** `tree-sitter`, `tree-sitter-typescript`, `tree-sitter-javascript`, `tree-sitter-go`, `tree-sitter-rust`, `tree-sitter-python`, `petgraph`
- **Database:** `rusqlite` (`features = ["bundled", "fts5"]`)
- **TUI & Web Report:** `ratatui`, `crossterm`, `axum` (ephemeral report server), `serde_json`
- **Sandbox & Last-Byte Sync PoC:** `/usr/bin/bwrap`, raw `tokio::net::TcpStream` (for `<50us` Last-Byte Sync), `reqwest` (rustls)

---

## 4. Engineering Risk & Mitigation Matrix

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Path explosion ($O(V!)$) on 3,000+ file cyclic graphs** | Scanner hangs or OOMs | Use $O(V+E)$ Guard-Set Lattice fixed-point solver instead of enumerating all paths |
| **Cross-file cache staleness on partial edits** | Missed bugs when `auth.ts` changes | Cache per-file AST symbols by `BLAKE3`, always re-link global graph in RAM (<80ms) |
| **TCP/TLS jitter hiding real DB race conditions** | False `MITIGATED` on race bugs | Use Last-Byte Sync (`tokio::sync::Barrier` + final-byte flush in `<50us`) |
| **Orphan sandbox processes or terminal corruption** | Zombie processes / broken TTY | Wrap `bwrap` in cgroup v2 subtree (`cgroup.kill=1`) + global `ratatui` panic hook |
| **Target app crashes without external DB/Stripe** | Unverifiable flows | Spin up in-sandbox mock shims on `127.0.0.1` or explicitly label `UNBOOTABLE` |
| **CPU saturation on 4-core PC during 13k scan** | Desktop UI lag | Cap Rayon pool to `num_cpus - 1` (max 3 threads) and run sandbox at `nice -n 15` |
