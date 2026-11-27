# Reproducible Benchmarks & Honest Limitations (`v1.6.0`)

## 10-Repo Real-World Verification Suite
All benchmarks run offline with `smg scan <repo> --profile-phases` on pinned open-source repositories:

| Repository | Domain | Verified Behavior (`v1.5.5+`) |
|---|---|---|
| `OWASP/crAPI` | Web / Auth / API | `2.25s`, `30/30` tracked baseline findings (`100%` recall) |
| `wormhole` | Web3 (Solana/Move/Solidity) | `29.29s`, `0` same-line CPI duplicates |
| `vllm` | Python / C++ / AI | `188.87s`, `smg-hw=97ms`, `0` `.pre-commit`/Unicode FPs, runtime `torch.load` kept `CRITICAL` |
| `zephyr` | Embedded RTOS (`71,953` files) | `141.32s`, `smg-hw=14.94s`, `991.7 MB` peak RSS |
| `openssl`, `wasmtime`, `envoy`, `vault`, `Signal-Android`, `grafana` | Systems / Crypto / Go / Mobile | Full 10-repo scalability & precision matrix |

## Determinism & Precision Contracts
- **1T == 16T Bit-for-Bit Determinism:** Enforced in CI via `cargo test --test determinism_1t_vs_16t --locked` (byte-for-byte identical JSON & SARIF 2.1.0 across `max_threads=1` vs `16`, plus UTF-8 BOM, CRLF, Unicode NFC, non-UTF8 skip, and Trojan Source Bidi coverage).
- **Synthetic Adversarial Precision Gate:** `SMG_ENFORCE_PRECISION_GATE=1 cargo test -p smg-graph --test adversarial_precision_bench --locked` enforces `0` FP / `0` FN across the 125-case multi-language precision suite.

## Known Honest Limitations
- Large Python/C++ monorepos (e.g., `vllm`) still take ~3 minutes on cold scans; warm scans use the compact `SMG2` binary `postcard` SQLite cache.
- Live dynamic subcommands (`proxy`, `dast`, `sqli`, `templates`, `oob`) remain opt-in active testing tools; static analysis + SARIF/OpenVEX + Read-Only MCP are the primary production-ready workflow.
- External `z3` solving is strictly opt-in (`--smt-z3`); the default solver is 100% pure-Rust (`QF_IDL` + `CdclSolver` + `Tnum`/`SparseOctagon`).
