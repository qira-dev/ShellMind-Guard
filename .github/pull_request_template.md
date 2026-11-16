## Summary

<!-- Briefly describe the architectural change, rule improvement, or bug fix. -->

## Architectural Invariants Checklist

- [ ] Preserves $O(V + E)$ linear time complexity in `smg-graph` (no path-enumeration blowup)
- [ ] Pre-compiles any regular expressions via `std::sync::OnceLock<Regex>` (zero per-file regex compilation)
- [ ] Preserves strict `stdout` hygiene in `shellmind-guard mcp` and `shellmind-guard ui`
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with 0 warnings
- [ ] `cargo test --workspace` passes
- [ ] `cargo run --release -- scan .` produces 0 false positives on ShellMind Guard crates
