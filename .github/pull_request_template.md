## Summary

<!-- Briefly describe the architectural change, rule improvement, or bug fix. -->

## Architectural Invariants Checklist

- [ ] Preserves $O(V + E)$ linear time complexity in `vf-graph` (no path-enumeration blowup)
- [ ] Pre-compiles any regular expressions via `std::sync::OnceLock<Regex>` (zero per-file regex compilation)
- [ ] Preserves strict `stdout` hygiene in `veriforge mcp` and `veriforge ui`
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with 0 warnings
- [ ] `cargo test --workspace` passes
- [ ] `cargo run --release -- scan .` produces 0 false positives on VeriForge crates
