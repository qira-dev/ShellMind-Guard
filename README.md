# VeriForge

**Zero-false-positive multi-file business-logic & AI-code security verifier.**  
Traces cross-file taint via an $O(V+E)$ Guard-Set Lattice and proves exploits in an isolated Linux Bubblewrap (`bwrap`) sandbox—with **zero AI cost** and **zero false-positive noise**.

---

## Why VeriForge?

1. **90% Deterministic Rust Core (0 API Cost):** Uses `ignore` + `BLAKE3` + `SQLite WAL` + parallel `Tree-sitter` ASTs to map cross-file routes, auth middleware, and payment/DB sinks in milliseconds.
2. **$O(V+E)$ Guard-Set Lattice:** Computes the intersection of active security guards across every incoming path—catching unauthenticated routes and missing transaction locks without exponential $O(V!)$ path explosion.
3. **OS-Isolated Sandbox & Last-Byte Sync PoC:** Spawns your app inside `/usr/bin/bwrap` (`--unshare-pid --unshare-ipc --unshare-uts --ro-bind`) and executes barrier-synchronized Last-Byte Sync concurrent bursts (`tokio::sync::Barrier`) to mathematically prove double-spend race conditions and auth bypasses.
4. **Enterprise Scale Verified:** Benchmarked on **575 directories / 13,225 TypeScript files**:
   - Cold full scan (walk + BLAKE3 + AST + lattice): **788 ms** (debug build)
   - Warm incremental delta index: **122 ms**

---

## Quickstart

```bash
# Build VeriForge
cargo build --release

# 1. Index a codebase with BLAKE3 + SQLite WAL delta cache
./target/release/veriforge index /path/to/project

# 2. Scan multi-file flows + prove in isolated bwrap sandbox + export SARIF & HTML graph
./target/release/veriforge scan fixtures/vuln-payment-node \
  --boot-cmd "node server.mjs" \
  --sarif .veriforge/report.sarif \
  --html .veriforge/report.html \
  --ci

# 3. Launch interactive 3-pane ratatui TUI
./target/release/veriforge ui fixtures/vuln-payment-node --boot-cmd "node server.mjs"
```

---

## Architecture

- `crates/vf-core` — `.veriforge.toml` config, `ignore` + `BLAKE3` parallel scanner, `SQLite WAL + FTS5` store
- `crates/vf-graph` — `Tree-sitter` AST (TS/JS/Rust/Python) + `petgraph` $O(V+E)$ Guard-Set Lattice
- `crates/vf-sandbox` — `/usr/bin/bwrap` runner + Last-Byte Sync concurrency & auth invariant verifier
- `crates/vf-tui` — Panic-safe `ratatui` 3-pane workspace with `[L]` log drawer & `[g]`/`[s]` export
- `crates/vf-report` — Standard `SARIF 2.1.0` & self-contained GitHub Carbon Slate HTML/SVG graph exporter
- `crates/vf-ai` — Optional BYOK / Ollama minimal-context (<2 KB) patch prompt builder

See [`BLUEPRINT.md`](BLUEPRINT.md), [`ROADMAP.md`](ROADMAP.md), and [`PLANNING.md`](PLANNING.md) for deep technical details.

## License

Licensed under the [Apache License 2.0](LICENSE).
