# Contributing to ShellMind Guard

Thank you for contributing to **ShellMind Guard**! To keep the codebase fast, deterministic, and compiler-grade, every contribution must uphold the architectural invariants below.

---

## Non-Negotiable Architectural Invariants

1. **Linear $O(V + E)$ Graph & Lattice Complexity:**
   - Never enumerate all simple paths ($O(V!)$) on call graphs.
   - All whole-program analyses in `crates/vf-graph/src/lattice.rs` must use monotone fixed-point worklist propagation or linear multi-source BFS ($O(V + E)$).
   - Must pass `test_b11_2000_node_all_sink_chain_is_linear` in `< 500ms`.

2. **Single-Pass AST & Pre-Compiled Regexes:**
   - Each modified source file is parsed **at most once** per scan via `tree-sitter` on the `rayon` thread pool (`crates/vf-graph/src/ast.rs`).
   - Never compile a `Regex::new(...)` inside a per-file or per-node loop; always use `std::sync::OnceLock<Regex>`.

3. **Two-Phase Incremental Cache Correctness:**
   - Per-file `FileAstSummary` records may be cached by `(mtime_ns, size_bytes)` and `BLAKE3` content hash in `.shellmind-guard/state.db` (`crates/vf-core/src/store.rs`).
   - Global cross-file symbol linking and lattice solving (`solve_guard_lattice`) **must always run fresh in RAM** so edits to imported middleware or services immediately propagate across unmodified caller files.

4. **Strict Stdout Hygiene in `mcp` & `ui` Modes:**
   - In `shellmind-guard mcp` (`src/mcp.rs`), `stdout` is strictly reserved for newline-delimited JSON-RPC 2.0 responses; all diagnostics must go to `stderr`.
   - In `shellmind-guard ui` (`crates/vf-tui`), child `bwrap` output and internal logs must route to the bounded ring-buffer (`[L]` drawer), never corrupting the `ratatui` alternate screen.

5. **Zero Self-Scan False Positives:**
   - Running `shellmind-guard scan .` on the ShellMind Guard repository itself must always produce **0 findings** across all ShellMind Guard crates (`crates/*` and `src/*`).

---

## Development Workflow & Verification Checklist

Before opening a Pull Request, run the full verification gate locally:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy with all warnings treated as errors
cargo clippy --workspace --all-targets -- -D warnings

# 3. Run all unit & integration tests across all 6 crates
cargo test --workspace

# 4. Dogfooding check: verify 0 false positives on ShellMind Guard crates
cargo run --release -- scan .
```

---

## Adding a New Security Rule or Language Grammar

- **Layer 1 (Secrets / Misconfigurations):** Add rule patterns and false-positive guards in `crates/vf-graph/src/secrets_config.rs` with unit tests covering both positive hits and benign lookalikes.
- **Layer 2 (Dependency Manifests):** Extend parsers and offline advisory tables in `crates/vf-graph/src/deps.rs`.
- **Layer 3–6 (AST, Taint, IDOR, Auth, Race, Frontend Contract):**
  - Extract AST route/guard/sink semantics in `crates/vf-graph/src/ast.rs` and `crates/vf-graph/src/taint.rs`.
  - Wire lattice propagation or witness reconstruction in `crates/vf-graph/src/lattice.rs`.
