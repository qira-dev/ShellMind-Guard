# ShellMind-Guard — Master AI End-to-End Deep Audit Forms (9 Divisions · 100% File Coverage)

> **Purpose:** Copy-paste each form below (one at a time) into an independent AI code auditor with read access to `/home/km-abdullah/ShellMind-Guard`.
> **Coverage:** All **92 Rust source files** across all 11 workspace crates + root binary are explicitly mapped with zero gaps (Form 9 covers the six Phase 25–26 live-HTTP engine files at full depth, including the proxy TUI which is deliberately audited there instead of Form 7).
> **Rule:** Never combine multiple forms into one session—run 1 form per fresh context window so the auditor inspects every line at maximum depth.

---

## Global Rules (Paste at the Top of Every Audit Session)

```text
ROLE: Principal Rust Systems, Compilers, Formal Verification & Security Auditor.
REPO: /home/km-abdullah/ShellMind-Guard (Rust Edition 2024, 11 workspace crates).
MODE: READ-ONLY DEEP AUDIT (do NOT edit code unless explicitly instructed after reporting).

MANDATORY ZERO-HALLUCINATION RULES:
1. You MUST read every single file listed in the assigned Form scope from line 1 to EOF before writing your report.
2. NEVER guess, extrapolate, or emit generic best-practice advice.
3. Every single finding MUST include:
   - Severity: P0 (Crash/Security/Soundness Break) | P1 (Real Bug / High FP or FN) | P2 (Edge Case / Perf / Resource Leak) | P3 (Hygiene / Dead Logic)
   - Exact `file:line` (and symbol name)
   - Root cause (exact code mechanism)
   - Minimal reproducible input or concrete trigger trace
   - Exact surgical fix recommendation
4. Check ALL 6 mandatory lenses on every file:
   (a) Panic / Crash / DoS (`unwrap()`, `expect()`, out-of-bounds slice/index, integer overflow/underflow, `clamp(min > max)`, stack overflow / unbounded recursion)
   (b) Mathematical & Analytical Soundness (false positives, false negatives, wrong lattice join/meet, wrong operator precedence, stale cache keys)
   (c) Self-Security (command injection, path traversal / symlink escape, secret leakage in logs/JSON/SARIF, unsafe HTTP redirects, fail-open auth/crypto)
   (d) Concurrency & Resource Leaks (zombie child processes, unclosed sockets/files, lock ordering deadlocks, Rayon/Tokio starvation)
   (e) Performance & Scaling (hidden O(N^2) loops, quadratic regex backtracking, excessive `.clone()` in hot paths, unbounded allocations on huge files)
   (f) Silent Failures & Dead Logic (`let _ = ...` hiding critical errors, `.unwrap_or_default()` masking parse failures, unreachable branches)
5. At the end of your report, list EVERY file you read with its line count and verdict (`FINDINGS: N` or `CLEAN — verified line-by-line`).
```

---

## FORM 1 — Core Indexing, Delta Cache, OSV Semver & Config (`crates/smg-core`)

```text
AUDIT DIVISION: Form 1 of 9 — Core Engine, Delta Cache & OSV Advisory Store
EXACT FILES TO READ IN FULL (6 files):
- crates/smg-core/src/lib.rs
- crates/smg-core/src/scanner.rs
- crates/smg-core/src/store.rs
- crates/smg-core/src/advisories.rs
- crates/smg-core/src/config.rs
- crates/smg-core/src/yaml.rs

DEEP AUDIT CHECKLIST:
1. `scanner.rs`:
   - Can a malicious repo with symlinks escape `repo_root` during walking or reading?
   - Check file size limits, binary file detection, UTF-8 lossy handling, and test/generated-file path filters (`is_test_source_path`, `set_include_tests` global AtomicBool race in parallel tests!).
   - Verify every lockfile & mobile/IaC manifest filename is classified accurately as `Language::Manifest` or its target language.
2. `store.rs`:
   - Audit SQLite WAL mode setup, busy_timeout, transaction atomicity, schema migration safety, and cache invalidation when `cfg_hash` or `advisories_db_stamp` changes.
   - Check for SQL injection or unescaped dynamic SQL in any query builders.
3. `advisories.rs`:
   - Mathematically audit `parse_semver_with_prerelease`, `parse_semver_key`, `cmp_semver_keys`, and `version_matches_range`:
     * Does `1.0.0-alpha < 1.0.0` hold?
     * How are Debian/Ubuntu epoch versions (`1:3.0.11-1~deb12u2`), Alpine revisions (`1.36.1-r15`), Go pseudo-versions, and `introduced = "0"` handled? Can malformed version strings cause false positives or false negatives?
   - Verify `canonical_ecosystem` and `normalize_package_name` (PEP 503 for PyPI, case sensitivity for Maven/Go/Debian/Alpine).
   - Check `parse_osv_value_into_records` against real OSV JSON edge cases (missing `ranges`, `GIT` vs `SEMVER` vs `ECOSYSTEM` events, multiple affected ranges).
4. `config.rs` & `yaml.rs`:
   - Audit `.shellmind-guard.toml` trust boundaries (`sandbox.boot_cmd` must NEVER auto-execute without `--trust-repo-config`).
   - Check `yaml.rs` for panics on malformed indentation, tabs, anchors/aliases, or deeply nested YAML.

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 2 — 16-Language AST, CFG, Scope, Taint & Guard-Set Lattice (`crates/smg-graph` Core)

```text
AUDIT DIVISION: Form 2 of 9 — Multi-Language AST, CFG, Taint & Guard-Set Lattice
EXACT FILES TO READ IN FULL (27 files):
- crates/smg-graph/src/lib.rs
- crates/smg-graph/src/arena.rs
- crates/smg-graph/src/ast.rs
- crates/smg-graph/src/call_hierarchy.rs
- crates/smg-graph/src/cfg.rs
- crates/smg-graph/src/deep_stack.rs
- crates/smg-graph/src/lattice.rs
- crates/smg-graph/src/phase10.rs
- crates/smg-graph/src/scope.rs
- crates/smg-graph/src/subgraph.rs
- crates/smg-graph/src/taint.rs
- crates/smg-graph/src/phase9/mod.rs
- crates/smg-graph/src/phase9/concurrency.rs
- crates/smg-graph/src/phase9/memory.rs
- crates/smg-graph/src/phase9/tests.rs
- crates/smg-graph/src/langs/mod.rs
- crates/smg-graph/src/langs/bash.rs
- crates/smg-graph/src/langs/c_cpp.rs
- crates/smg-graph/src/langs/csharp.rs
- crates/smg-graph/src/langs/dart.rs
- crates/smg-graph/src/langs/java.rs
- crates/smg-graph/src/langs/kotlin.rs
- crates/smg-graph/src/langs/php.rs
- crates/smg-graph/src/langs/ruby.rs
- crates/smg-graph/src/langs/swift.rs
- crates/smg-graph/src/langs/tests.rs
- crates/smg-graph/tests/adversarial_precision_bench.rs

DEEP AUDIT CHECKLIST:
1. `cfg.rs` & `lattice.rs`:
   - Mathematically verify dominator-tree computation, fixpoint convergence, and GuardBitset meet/join semantics (intersection at merge nodes vs union — is there any unsound over-approximation or missed path?).
   - Check CFG block budget caps (default vs `--deep-audit` 2048 blocks) and witness-path cycle prevention.
   - Verify CHA/RTA polymorphic dispatch resolution (`call_hierarchy.rs`) for soundness and O(N^2) blowup on large class hierarchies.
2. `taint.rs` & `scope.rs`:
   - Audit multi-hop aliasing, object property taint, closure/callback taint (`phase10.rs`), and sanitizer revocation (e.g., variable sanitized then reassigned tainted value).
   - Check parameter shadowing across nested functions and sibling method isolation.
3. `langs/*.rs` & `ast.rs`:
   - Check every Tree-sitter grammar extractor for:
     * UTF-8 byte-offset slicing panics (`&src[node.start_byte()..node.end_byte()]` or string slicing on multi-byte Unicode chars!).
     * Unbounded AST recursion stack overflow on deeply nested expressions (e.g., 10,000 nested parentheses).
     * False positives on safe idioms (parameterized queries, regex `.exec()`, constant strings, test helpers).
4. `phase9/memory.rs` & `phase9/concurrency.rs`:
   - Audit C/C++ `SMG-MEM-BOUNDS` and integer overflow heuristics for false positives on safe bounds checks and macro constants.
   - Audit lock-ordering deadlock detection for cycle detection accuracy and lock-held-across-await/IO false positives.
5. `subgraph.rs`:
   - Verify `--changed-since` reverse-caller/callee slicing and auto-fallback triggers on lockfile/config/middleware changes.

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 3 — Mathematical SMT Path-Feasibility Solver (`crates/smg-graph/src/smt.rs`)

```text
AUDIT DIVISION: Form 3 of 9 — Formal SMT Path-Feasibility Solver
EXACT FILES TO READ IN FULL (1 file — extreme mathematical depth):
- crates/smg-graph/src/smt.rs

DEEP AUDIT CHECKLIST:
1. Built-in `QF_IDL` Difference-Logic Solver (Bellman-Ford):
   - Verify the exact mathematical reduction of `x < y`, `x <= y`, `x > y`, `x >= y`, `x == y`, `x != y`, `x < c`, `x > c` into weighted directed difference constraints `u - v <= w`:
     * Check off-by-one errors in strict integer inequalities (`x < y` <=> `x - y <= -1`; is this valid ONLY for integers, and what happens if variables hold floats or strings?).
     * Check signed 64-bit integer overflow (`i64::MIN` / `i64::MAX` / `saturating_add` vs wrapping in Bellman-Ford relaxation!).
     * Check negative-cycle detection: can a disconnected component or zero-weight cycle cause a false UNSAT (which would dangerously prune a REAL vulnerability!)?
2. Boolean & String Contradiction Engine:
   - Check `parse_condition_expr` for operator precedence (`&&`, `||`, `!`, parentheses, short-circuiting, negated `else` branches).
   - Can an unparsed or complex condition (`a && (b || c)`) be mistakenly dropped or inverted into a false UNSAT? (Soundness rule: unknown/unparseable predicates MUST over-approximate to SAT/Unknown, NEVER UNSAT!)
3. `SMT-LIB2` Emission & External `z3` Bridge:
   - Audit `emit_smtlib2` for SMT-LIB2 syntax injection (variable names containing spaces, quotes, newlines, parentheses, or SMT keywords!).
   - Verify `z3` subprocess execution: strict timeout enforcement, bounded stdout/stderr, no zombie `z3` process on timeout, and graceful fallback to built-in solver if `z3` fails or returns `unknown`.

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 4 — Secrets, Git History, Lockfiles, OCI Images, Mobile & Cloud IaC (Phases 21–23)

```text
AUDIT DIVISION: Form 4 of 9 — Secrets, Supply-Chain, OCI Container, Mobile & IaC Engines
EXACT FILES TO READ IN FULL (18 files):
- crates/smg-graph/src/secrets_config.rs
- crates/smg-graph/src/git_history.rs
- crates/smg-graph/src/gitleaks_config.rs
- crates/smg-graph/src/deps.rs
- crates/smg-graph/src/iac_policy.rs
- crates/smg-graph/src/langs/hcl.rs
- crates/smg-graph/src/infra_dos.rs
- crates/smg-graph/src/protocols_ai.rs
- crates/smg-graph/src/phase9/mobile.rs
- crates/smg-graph/src/rules.rs
- crates/smg-graph/src/rule_pack/mod.rs
- crates/smg-graph/src/rule_pack/ai_supply_chain.rs
- crates/smg-graph/src/rule_pack/cloud_iac.rs
- crates/smg-graph/src/rule_pack/crypto_legacy.rs
- crates/smg-graph/src/rule_pack/web_frameworks.rs
- src/live_verify.rs
- src/oci_image.rs
- src/deps_sync.rs

DEEP AUDIT CHECKLIST:
1. Secrets, `.gitleaks.toml` & Git History (`secrets_config.rs`, `gitleaks_config.rs`, `git_history.rs`, `src/live_verify.rs`):
   - Verify ZERO raw secret leakage in findings, titles, logs, JSON, or SARIF.
   - Check `git_history.rs`:
     * Does `git log -p -U0` line tracking handle filenames with spaces, renames, non-ASCII UTF-8 octal-quoted git paths (`"path/with\303\251"`), or commits with `SMG_COMMIT_HDR:` inside commit diff content?
     * Verify hunk line-number increment accuracy and `skip_hunk` test-module heuristic (could a production function after `mod tests` or a diff without `@@` context be misclassified?).
   - Check `gitleaks_config.rs`: verify `condition = "AND"` vs `"OR"` when multiple allowlist fields are populated, and regex compilation error handling.
   - Check `src/live_verify.rs`:
     * Verify `--verify-live` is strictly OFF by default, `redirect::Policy::none()` is enforced, and every provider endpoint is strictly read-only.
     * Independently verify the pure-Rust SHA-256, HMAC-SHA256, and AWS SigV4 canonical request / credential scope / signature calculation against AWS SigV4 spec!
     * Check `extract_aws_secret_near` and `extract_tokens_from_line` for missed prefixes or ReDoS.
2. Lockfiles, OSV Sync & OCI Images (`deps.rs`, `src/deps_sync.rs`, `src/oci_image.rs`):
   - Audit all lockfile parsers (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` v9, `Cargo.lock`, `poetry.lock`, `uv.lock`, `go.mod`, `go.sum`, `requirements.txt`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, `pubspec.lock`, `packages.lock.json`, `mix.lock`, `pom.xml`, `gradle.lockfile`) for edge cases & silent drops.
   - Audit `src/oci_image.rs`:
     * Check pure-Rust POSIX USTAR tar parser for PAX extended headers (`typeflag == b'x'`), GNU LongLink (`././@LongLink`), truncated headers, integer overflow in `data_start + padded`, and gzip-bomb / unbounded memory allocation in `maybe_gunzip`!
     * Verify `dpkg/status` & `apk/db/installed` multi-line fields and `.trivyignore` date parsing (`exp:YYYY-MM-DD`).
3. Mobile & Cloud IaC (`phase9/mobile.rs`, `iac_policy.rs`, `langs/hcl.rs`, `rule_pack/*.rs`):
   - Check every MobSF-Scan rule in `mobile.rs` for false positives on non-mobile code, comments, or safe patterns.
   - Audit all 52 policies in `iac_policy.rs` + `hcl.rs` recursive nested-block collector for duplicate findings (overlapping with `hcl.rs` built-in checks), Terraform variable/local resolution edge cases, and `var.` defaults with expressions.

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 5 — Deep-Tech Specialized Domains (Web3/revm, HW/Firmware, PQC, Enterprise TEE)

```text
AUDIT DIVISION: Form 5 of 9 — Web3, Embedded Hardware, Post-Quantum Crypto & Enterprise TEE
EXACT FILES TO READ IN FULL (16 files):
- crates/smg-web3/src/lib.rs
- crates/smg-web3/src/context.rs
- crates/smg-web3/src/evm_oracle.rs
- crates/smg-web3/src/solidity.rs
- crates/smg-web3/src/svm_move.rs
- crates/smg-hw/src/lib.rs
- crates/smg-hw/src/context.rs
- crates/smg-hw/src/domains.rs
- crates/smg-hw/src/typestate_irq.rs
- crates/smg-pqc/src/lib.rs
- crates/smg-pqc/src/inventory.rs
- crates/smg-pqc/src/lattice.rs
- crates/smg-pqc/src/x509.rs
- crates/smg-enterprise/src/lib.rs
- crates/smg-enterprise/src/license.rs
- crates/smg-enterprise/src/tee.rs

DEEP AUDIT CHECKLIST:
1. `smg-hw` Abstract Interpretation (`domains.rs`, `typestate_irq.rs`, `context.rs`):
   - Mathematically audit `Tnum` (tristate numbers), `WrappedInterval`, and `SparseOctagon` abstract domains:
     * Check EVERY arithmetic, bitwise, join, meet, widening, and narrowing operation for overflow, `min > max` panics (like `clamp`), or unsoundness (missing concrete values!).
   - Audit IRQ typestate (`disable_irq` / `enable_irq` / ISR context / DMA/MMIO) for false positives on RTOS kernels (`FreeRTOS`, `mcuboot`, `pico-sdk`) and missed deadlocks/race conditions.
2. `smg-web3` (`solidity.rs`, `evm_oracle.rs`, `svm_move.rs`):
   - Audit `revm` EVM simulator and stateful multi-tx invariant campaign + sequence shrinker for panics, unbounded gas/steps, or invalid bytecode/ABI handling.
   - Audit Solidity reentrancy / flash-loan / oracle-manipulation / access-control rules and Solana Anchor / Move rules for FP/FN edge cases.
3. `smg-pqc` (`inventory.rs`, `lattice.rs`, `x509.rs`):
   - Audit NIST PQC quantum bit-reduction / Mosca HNDL urgency math, CycloneDX 1.5 CBOM schema output, hybrid `ML-KEM + X25519` recognition, and X.509 DER parser bounds safety on malformed certificates.
4. `smg-enterprise` (`license.rs`, `tee.rs`):
   - Audit Ed25519 signature verification, expiry checks, binary digest pinning, and TEE attestation quote verification (`aws-nitro`, `intel-tdx`, `amd-sev-snp`) for strict **fail-closed** behavior: can ANY malformed input, empty field, replay nonce, or parse error accidentally bypass verification?

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 6 — Bubblewrap Sandbox, Wire Oracle, Live TLS/PQC & Read-Only IDOR

```text
AUDIT DIVISION: Form 6 of 9 — Sandbox Isolation, Loopback Verifier, TLS/PQC & IDOR
EXACT FILES TO READ IN FULL (6 files):
- crates/smg-sandbox/src/lib.rs
- crates/smg-sandbox/src/bwrap.rs
- crates/smg-sandbox/src/verifier.rs
- crates/smg-sandbox/src/wire_oracle.rs
- src/tls_audit.rs
- src/idor_audit.rs

DEEP AUDIT CHECKLIST:
1. `smg-sandbox` (`bwrap.rs`, `verifier.rs`, `wire_oracle.rs`):
   - Audit Bubblewrap (`--unshare-net`, read-only bind mounts, `RLIMIT_AS`, cgroups v2) and `--unsafe-host-fallback` / `--trust-repo-config` security boundaries.
   - Check process lifecycle cleanup: are spawned target servers and proxy threads guaranteed to be killed/reaped on timeout, error, or panic (no zombie processes or leaked ports)?
   - Audit Last-Byte Sync race-condition barrier synchronization and stateful multi-step HTTP workflow verification for deadlocks or flaky timing assumptions.
2. `src/tls_audit.rs`:
   - Audit `build_client_hello` and `parse_server_hello` byte-by-byte against RFC 5246 (TLS 1.2) and RFC 8446 / RFC 10024 (TLS 1.3 + Hybrid PQC):
     * Can a malformed, truncated, or oversized TLS record from a misbehaving server panic `parse_server_hello` (check every slice index & length calculation!)?
     * Check `CertCollectorVerifier`: verify it is ONLY used for read-only metadata/header inspection in `smg tls` and never leaks into any authenticated HTTP client!
     * Check IPv6 target parsing (`[::1]:8443`) in `parse_tls_target`.
3. `src/idor_audit.rs`:
   - Verify `is_lab_or_loopback_url` cannot be bypassed via IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`), decimal IPs, DNS rebinding, or missing host.
   - Verify non-destructive method restriction (`GET`/`HEAD`/`OPTIONS` only), `redirect::Policy::none()`, and accurate differential verdict logic (`PASS`, `FAIL_IDOR`, `FAIL_BFLA`, `FAIL_UNAUTH`, `INCONCLUSIVE`).

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 7 — AST Auto-Patcher, Reports, TUI, MCP Server & CLI Entrypoint

```text
AUDIT DIVISION: Form 7 of 9 — Auto-Patcher, Reports, TUI, MCP Server & CLI
EXACT FILES TO READ IN FULL (12 files):
- crates/smg-ai/src/lib.rs
- crates/smg-ai/src/codemods.rs
- crates/smg-report/src/lib.rs
- crates/smg-tui/src/lib.rs
- crates/smg-tui/src/palette.rs
- crates/smg-tui/src/session.rs
- crates/smg-tui/src/views.rs
- src/mcp.rs
- src/rules_catalog.rs
- src/lib.rs
- src/main.rs
- src/bin/smg.rs

DEEP AUDIT CHECKLIST:
1. `smg-ai` (`codemods.rs`, `lib.rs`):
   - Audit deterministic AST codemod patch generation: can overlapping byte edits or multi-byte UTF-8 offsets corrupt target source files?
   - Audit `--apply-check` isolated temporary workspace copy cleanup and patch rollback safety.
2. `smg-report` (`lib.rs`):
   - Verify SARIF 2.1.0, CycloneDX 1.5 SBOM/VEX (with BLAKE3 attestation), and HTML graph output for schema validity, XSS escaping in HTML reports, and deterministic ordering.
3. `smg-tui` (`lib.rs`, `palette.rs`, `session.rs`, `views.rs`):
   - Verify terminal raw-mode restore on panic (panic hook), zero out-of-bounds table/scroll indices when findings list is empty or filtered, and responsive event handling.
4. `src/mcp.rs`:
   - Audit JSON-RPC 2.0 framing, error codes, input validation on all MCP tool arguments (path traversal, command injection, unbounded scan output), and strict 32 KiB response budget enforcement.
5. `src/lib.rs` & `src/rules_catalog.rs`:
   - Audit CLI flag interactions (`--changed-since`, `--git-history`, `--verify-live`, `--only-verified`, `--online-osv`, `--baseline`, `--exclude-rule`, `--fail-on`, `--ci`, `--watch`), exit code correctness, and git pre-commit hook install/uninstall safety (never clobbering user's existing hooks).

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 8 — Cross-Repo Hardening: Panics, Silent Errors, Performance & Verification Gate

```text
AUDIT DIVISION: Form 8 of 9 — Whole-Repository Hardening & Adversarial Stress Gate
SCOPE: Entire `/home/km-abdullah/ShellMind-Guard` workspace (non-test production code).

MANDATORY COMMANDS & CHECKS TO RUN:
1. Production Panic Audit:
   - Scan all non-test production code across `src/` and `crates/*/src/` for `.unwrap()`, `.expect(`, `panic!(`, `todo!(`, `unimplemented!(`, and direct unchecked slice indexing `[i]` / `[a..b]`.
   - Flag every site reachable from untrusted repository files, CLI arguments, network bytes, or malformed configs.
2. Silent Error Swallowing Audit:
   - Inspect every `let _ = ...`, `.ok()`, and `.unwrap_or_default()` in production code—flag any case that silently hides I/O failures, security policy parse errors, or cache corruption.
3. Full Compiler & Test Gate:
   - Run `cargo clippy --workspace --all-targets -- -D warnings` (must be 0 warnings).
   - Run `cargo test --workspace` (verify 100% pass, 0 ignored/flaky tests).
   - Run `smg scan . --deep-audit --format compact` (verify 0 findings in `src/` and `crates/`).
4. Adversarial Malformed-Input Crash Audit:
   - Verify how `smg` handles: empty files, 0-byte tar/lockfiles, invalid UTF-8 binary blobs renamed to `.rs`/`.py`/`.tf`, deeply nested brackets, circular symlinks, and empty git repositories (no commits yet).
5. Performance & Binary Hygiene:
   - Check for hot-path allocations/clones, regex recompilation inside loops (missing `OnceLock`), and release binary size (`du -sh ~/.cargo/bin/smg`).
6. Workspace Manifests, Feature-Gate Matrix & CI Hygiene (`Cargo.toml`, `crates/*/Cargo.toml`, `.github/workflows/*.yml`):
   - Verify compilation under `--no-default-features` and each individual feature flag (`hw`, `web3`, `pqc`, `enterprise`) so no conditional-compilation breakage hides behind default features.
   - Check for unused crates in `Cargo.toml` and mutable third-party GitHub Action tags in `.github/workflows/*.yml`.

Apply all Global Rules above and output the structured P0–P3 report.
```

---

## FORM 9 — Phase 25–26 Live HTTP Engines: Nuclei Runner, SQLi Prover, DAST, Proxy, Schema Linter & Proxy TUI

```text
AUDIT DIVISION: Form 9 of 9 — Live HTTP Verification Engines & Proxy TUI (Full Depth)
EXACT FILES TO READ IN FULL (6 files):
- src/templates_audit.rs      (Nuclei-compatible YAML detection template runner: HTTP + DNS + TCP/TLS engines)
- src/sqli_audit.rs           (non-destructive SQLi prover: error-based, boolean differential, time-based, ORDER BY enumeration)
- src/dast_audit.rs           (same-host crawler + passive header audit + proof-based active checks)
- src/proxy.rs                (localhost HTTP inspection proxy engine: interception + CONNECT tunnel + JSONL sink)
- src/http_audit.rs           (passive HTTP posture auditor + static OpenAPI/GraphQL schema linter)
- crates/smg-tui/src/proxy_tui.rs  (proxy TUI: history, Repeater replay, decoder, wordlist Intruder, Compare diff)

CONTEXT: These six files are the Phase 25–26 live verification engines. They are DOCUMENTED as strictly
defensive: detection/proof only; loopback/RFC1918 default with --allow-remote opt-in; NO WAF-evasion/tamper
catalogs, NO data dumping/extraction, NO stacked queries, NO OS-shell payloads, NO headless browser, NO MITM
TLS re-signing (CONNECT tunnels relay transparently). Two audit duties:
(a) GUARDRAIL DRIFT IS A P1 FINDING — verify the code still enforces every documented boundary above;
(b) full software-engineering soundness per the Global Rules' 6 lenses.
NOTE: proxy_tui.rs is audited HERE (not Form 7) because it is the live engine's interactive surface.

DEEP AUDIT CHECKLIST:

1. `src/templates_audit.rs` (Nuclei runner):
   - Substitution soundness: `substitute()` replacement ORDER (template variables/constants applied before
     {{BaseURL}} family) — can a template variable named `BaseURL` or `randstr` shadow/rewrite a scope
     variable? `replace_helper_calls()` — `base64_decode`/`url_decode` failure returns empty string: can a
     malformed helper call silently become an empty path segment instead of failing the block?
   - Unresolved-variable fail-closed: `has_unresolved_vars()` regex `{{[A-Za-z_][A-Za-z0-9_.-]*}}` — does it
     catch lowercase nuclei variables, `{{$_redirect}}`, or helper leftovers? Can any substitution path emit
     a request with an unresolved `{{...}}` in the URL line?
   - Raw-request mode: `parse_raw_request()` offset arithmetic (line_end + 1 vs actual CRLF) — verify body
     offset correctness for LF-only line endings, missing trailing CRLF, and headers repeated twice.
     Header injection: template-supplied header values containing `\r\n` — does `HeaderValue::from_str`
     reject all of them, and does the RAW path (which writes bytes verbatim) bypass that protection
     (request smuggling INTO the lab target)?
   - URL construction: `build_url()` returns any template `path:` that starts with http(s):// AS-IS — the
     lab-scope check validated only the CLI target. Assess: a template pointing at an absolute external URL
     sends the probe off-scope. Severity of guardrail drift, and the minimal surgical fix.
   - Redirects: `HttpRunners` uses `redirect::Policy::limited(10)` when `redirects: true` — redirect targets
     are NOT re-checked against the lab scope. Trace a lab host that 302s to a public host.
   - TLS: `danger_accept_invalid_certs(true)` is justified by an inline `// smg-ignore: SMG-CFG-TLS` — verify
     the justification (lab self-signed certs) is real and cannot reach any non-lab host.
   - DSL evaluator: `split_top_level()` / `take_fn_call()` / `find_top_level_op()` — unbalanced quotes,
     nested parens, `!=` vs `!` prefix, operator precedence, and the multi-expression combination rule
     (`all || any`) in the `dsl` matcher arm: does it respect the matcher-level `condition:` (and/or) for
     2+ expressions, or silently fall back to OR? Verify an UNPARSEABLE dsl atom can never produce `true`
     (fail-closed) on any path.
   - Matcher semantics: `evaluate_matchers()` — empty matchers list = implicit match (is that correct for a
     template with only extractors?); `part_text()` unknown part → empty string (matcher on unknown part
     becomes a silent constant — sound or FP/FN?); `binary` hex decode odd-length handling.
   - DNS engine: `build_dns_query()` label truncation `min(63)` — silent wrong-name queries?; `read_dns_name()`
     compression-pointer loop guard (hops > 32) and out-of-bounds at every index; `parse_dns_response()`
     truncation at every `p + rdlen`; `system_nameservers()` parsing a local /etc/resolv.conf (comment lines,
     `search`/`options` lines, IPv6 nameservers) — can a malformed resolver line panic or select garbage?
   - Network engine: `expand_ports()` range expansion cap (a..b bounded +64 — verify); `execute_network_block()`
     IP-only host requirement (hostname rejection — is the error surfaced as a block-skip, not a panic?);
     read_iters=4 fixed read budget — banner-truncation FN risk.
   - Run-loop orchestration: an empty `if template_matched && !...stop_at_first_match { /* comment */ }` block
     exists near the engine loop — adjudicate it (dead logic P3 or needed control flow?); `stop_at_first_match`
     interplay across http/dns/network engines (does http break skip DNS/network evaluation correctly?);
     skip-reason aggregation when SOME blocks skip and others 404 (INCONCLUSIVE vs unmatched honesty).
   - Filters: severity filter accepts unknown severity strings (typo silently runs nothing — flag DX);
     tag filter case normalization.

2. `src/sqli_audit.rs` (SQLi prover):
   - Statistics soundness: `median_f64()` sorts and takes `samples[len/2]` — for TIME_BASELINE_REPS =
     TIME_PAYLOAD_REPS = 2 the "median" is the LARGER of the two samples. Analyze the bias direction for
     baseline vs payload and whether the `payload_median - baseline_median >= delay * 0.7` rule can produce
     FP (slow lab host) or FN (jitter), and the exact minimal fix (true median / more reps / trimmed mean).
   - Boolean differential thresholds: `body_close` (<=2% delta) and `body_diverges` (>5% delta or any length
     change) — a response differing by 3% is NEITHER close nor divergent; walk the truthy/falsy decision table
     for: identical dynamic tokens per request, CSRF-token pages, compressed-then-decompressed variance,
     and 2-rep consistency (`t2/f2`) — can a state-changing GET (the probe itself) flip the verdict?
   - Error signatures: `scan_error_signatures()` regexes are exported and ALSO used by dast — audit each of
     the 5 families for (i) ReDoS (alternation depth, backtracking), (ii) benign-page false positives (a page
     DOCUMENTING "You have an error in your SQL syntax" or containing ORA-\d5 in an error-code table),
     (iii) case/format gaps (MySQL 8 new messages, MariaDB prefixes, `psycopg` without the `2.`).
   - Injection plumbing: `set_param_in_pairs()` — duplicate parameter names (`?id=1&id=2`): how many
     occurrences get the payload, and does the duplicated payload corrupt the differential? `inject_value()`
     rebuilds from the ORIGINAL URL every time — verify no probe leaks the previous probe's payload.
     `percent_encode_value()` — verify `+`, `&`, `#`, `%`, NUL, and multi-byte UTF-8 payloads round-trip
     through both URL query and urlencoded POST body paths.
   - UNION enumeration: for k=1, a break yields `columns = None` (no report) — is swallowing an ORDER BY 1
     failure a soundness hole (real column-0 / parse-level injection hidden)? Verify the break-vs-continue
     semantics against the mock contract and real DBs.
   - Time-based families: total worst-case duration per param (3 families × 2 reps × delay) and the client
     timeout math (`delay_secs * 2 + 20`) — can a legitimate slow lab endpoint abort mid-campaign and yield
     INCONCLUSIVE, and is that surfaced?
   - Method guard: GET/POST only — verify POST bodies are strictly urlencoded and that a `Content-Type`
     header collision with `--header` is handled.
   - Guardrails: same `is_lab_or_loopback_url` call site — see the Cross-Engine Matrix below.

3. `src/dast_audit.rs` (crawler + posture + proofs):
   - Crawler: visited-set keying and URL normalization (`http://h:80/` vs `http://h/`, trailing slash,
     percent-encoding variants) — prove no infinite loop AND no unbounded queue (js_path_re over a huge JS
     bundle floods paths — bounded only by max_pages? trace the growth). `resolve_url()` same-host equality:
     IPv6 bracket canonicalization (`[::1]` vs `::1` in `host_str()`) — can a lab host with two spellings
     break the same-host rule in either direction (escape or missed crawl)?
   - HTML extraction: `form_full_re` = `(?s)<form\b([^>]*)>(.*?)</form>` on malformed/nested/unterminated HTML
     — linear or backtracking blowup? Input-field regexes (`attr_value` compiles a fresh Regex per call —
     hot-path recompilation, and does it mishandle single-quoted/unquoted attributes?).
   - Proof soundness (each active check): XSS — payload contains a unique token (`alert(smgxss)`), so a page
     documenting `<svg/onload=` without echoing our token must NOT fire; verify the check truly requires our
     marker. SSTI — `resp.body.contains("49")` is UNANCHORED: any page containing the number 49 (a price,
     an ID) makes every parameter look SSTI-vulnerable — verify and rate this FP; propose the minimal
     anchored fix. LFI — same class: `root:x:0:0:` anywhere in a page (a Unix tutorial page) fires.
     CMDi — the arithmetic guard requires the RESULT (`smgcmdi42`) and absence of the LITERAL
     (`smgcmdi$((19+23))`): a server that echoes the literal AND the result (proxy-style app) is silently
     FN — assess the trade-off and a stricter anchor (marker adjacent to response injection point).
     Open redirect — verify the 300..400 status gate and that `Location` is read from OUR captured header
     representation (to_page_response appends Location — double-append risk when the header appears twice?).
   - Active-phase side effects: POST form targets receive real payloads — the module claims non-destructive;
     verify the claim holds for state-changing lab endpoints and that `--passive-only` fully disables POSTs.
   - `to_page_response()`: MAX_BODY_CAPTURE 2MiB truncation — a reflected marker beyond 2MiB is a silent FN;
     Location header appended into `headers` string — duplicates on multi-Location responses?
   - `passive_header_findings()`: `header_value()` returns the FIRST header only — multiple CSP/XFO headers
     (append semantics) misreported? Set-Cookie name extraction for cookies without `=`; the new
     `SMG-DAST-CACHE` rule — verify `no-store`/`private` substring matching is case-safe and that
     `Cache-Control: no-store, max-age=0` plus a second `Cache-Control: public` header (split headers) is
     judged correctly.
   - `harvest_openapi()`: origin reconstruction (scheme://host:port) — verify the Phase-26A malformed-URL fix
     is complete for IPv6 hosts and non-default ports; Swagger-2 path-LEVEL `parameters` (between the path
     map and operations) are not merged — FN; response cap for giant spec files.
   - Orchestrator: `make_param_target()` on duplicate param names; `dedup_insert` key (id, url, param) —
     url_template embeds `{VALUE}` so the same param discovered via link vs OpenAPI dedups — verify;
     `MAX_TARGETS_ACTIVE` truncation is silent (report the skip count?).

4. `src/proxy.rs` (inspection proxy engine):
   - HTTP framing: `read_head()` splits on the FIRST `\r\n\r\n` — a request whose HEAD contains a body-start
     early (HTTP/1.0 style), or multiple pipelined requests on one connection: only the first is intercepted
     and relayed — what happens to the second request (silently dropped? client hang?); **Transfer-Encoding:
     chunked REQUESTS** have no Content-Length — the body read is skipped and an EMPTY body is forwarded:
     trace the origin-side hang/timeout and classify (request-smuggling class bug?).
   - Authority resolution: absolute-form URI vs `Host:` header mismatch — code prefers the absolute-form
     target but forwards the client's original Host header verbatim — construct the misrouting/host-confusion
     request and assess (proxy-smuggling class).
   - Response relay: capture cap MAX_RESPONSE_CAPTURE = 8 MiB — responses LARGER than the cap are TRUNCATED
     MID-STREAM and the truncated bytes are what the client receives (no error, no Content-Length fix-up) —
     verify and rate.
   - Origin connect failure inside `intercept_http()` errors out WITHOUT any 502 written to the client
     (unlike `tunnel()` which writes 502) — client-side hang consistency bug; also verify every
     `handle_connection` error path closes the client socket promptly (30s read timeout interplay).
   - CONNECT tunnels: no lab-scope restriction (a browser through the proxy tunnels anywhere — assess against
     the documented dev-tool boundary and the transparent-relay claim); fd/thread cleanup on partial relay
     errors (`up.join()` after downstream copy fails); byte counters correctness (up/down).
   - Lifecycle: `start_proxy()` nonblocking accept loop (100 ms poll) — CPU cost at idle; per-connection
     threads are spawned detached and NOT joined on stop() — in-flight connections at shutdown; entries cap
     `remove(0)` O(n) memmove per insert after 5000 — per-request cost under load; JSONL writer thread
     termination ordering (channel sender drop) and write failures silently ignored (log-then-continue?).
   - `truncate_for_capture()` char-boundary walk — verify it cannot panic on multi-byte input at the cap;
     request headers captured verbatim (Authorization/Cookie visible in history/JSONL/export) — verify the
     tool never CLAIMS redaction and document the exposure surface (loopback-only files).
   - Summary/records: `ConnCtx::record()` id space (engine AtomicU64) vs TUI `push_entry()` max+1 —
     ID COLLISION between engine and replayed entries — trace the duplicate-id consequences (export
     overwrite, compare selection).

5. `src/http_audit.rs` (passive posture + schema linter):
   - Non-destructive claim: exactly ONE GET to the target + up to 5 plain GETs for OpenAPI probing + ONE
     read-only `__schema` POST — verify nothing else leaves the process, and that `--passive-only`-style
     behavior is inherent (there is no active check here at all).
   - `lint_openapi()`: untrusted JSON — serde_json recursion depth on deeply nested specs (recursion limit
     behavior: error → silent "no lint"? classify as silent-skip); `.take(8)`/`.take(16)` caps silently bound
     findings; `servers[].url` with `{variables}` template substitution unhandled (FN); Swagger-2
     `host`/`basePath` fields (plaintext host) not linted (FN); `securitySchemes` present but non-object →
     treated as absent (verify direction of failure).
   - `lint_graphql_sdl()`: regex FP surface — fields named `executor`, `debugDump`, `passwordPolicy` match the
     debug/sensitive patterns: verify severity labeling (INFO vs MEDIUM) matches the evidence; GraphQL
     detection `detect_schema_kind()` requires `type Query` — a mutations-only SDL (or `schema { mutation: M }`
     root) is silently skipped — FN classification.
   - Live flow: `fetch_passive()` failure = hard bail (no partial report) — is that the right failure mode vs
     INCONCLUSIVE?; introspection probe targets `<origin>/graphql` by default — verify the POST body can be
     misinterpreted by a non-GraphQL endpoint and that the lab-scope guard covers `--graphql <URL>` too.
   - Client: shared `default_headers` applied to schema probes AND introspection — verify a user `--header`
     like `Host=` cannot break the probes; timeout applies to each of the ~7 requests (worst-case total).
   - Guardrails: `is_lab_or_loopback_url` call site (see matrix); offline `--schema` file lint has NO scope
     check by design — verify no network egress exists anywhere in the file-lint path.

6. `crates/smg-tui/src/proxy_tui.rs` (proxy TUI):
   - Lock discipline: `draw()` takes THREE sequential locks (summary, entries len, entries items) plus
     `selected()` re-locks — verify NO nested acquisition exists on any path (the inline
     `// smg-ignore: SMG-ENG-DEADLOCK` must be justified: prove the guards drop before the next acquire,
     including inside the `items` closure).
   - Replay (`replay_entry` + `r` key): header reconstruction `split_once(": ")` — folded/multiline headers,
     duplicate headers, and headers with no space after colon; skip-list (host, content-length, connection,
     accept-encoding, proxy-connection) — is `transfer-encoding` missing (replay of a captured chunked
     request)? `danger_accept_invalid_certs(true)` (smg-ignore justified) — verify replay can only target
     the URL already captured (no free-form URL input).
   - ID collisions: `push_entry()` computes `max(entries)+1` while the engine's AtomicU64 runs independently —
     construct the interleaving that produces duplicate ids, then trace: `/tmp/smg-proxy-{id}.txt` export
     overwrite, Compare `compare_from` resolving the WRONG entry, replay_of chain ambiguity.
   - Intruder: `intruder_run()` blocks the TUI event loop — 100 words × 3 s = up to 300 s frozen UI (no
     progress, no Esc-cancel) — rate and propose the minimal non-blocking fix; wordlist file is read WHOLE
     (`fs::read_to_string`) with no size cap — OOM on a giant list; `URL_SAFE_NO_PAD.decode(trimmed
     .trim_end_matches('='))` and `decode_all()` is_b64ish gate — verify a JWT segment containing `.` or
     unicode cannot panic; JWT with 5 segments (JWE) silently undecoded.
   - Compare: `diff_lines()` LCS DP is 1501×1501 u32 (~9 MB) allocated per keypress — acceptable or flag;
     verify the DP never indexes out of bounds on empty inputs; the `same/removed/added` counters are
     computed over the TRUNCATED (DIFF_MAX_LINES) input — counters can mislead on huge bodies (verify);
     `draw_diff_modal` render cap 900 lines — honest truncation note present?
   - Terminal safety: `run_proxy_tui()` restores raw mode on the happy path and on closure of the inner
     result closure — but a PANIC inside draw/event handling skips `disable_raw_mode` (no panic hook) —
     compare with smg-tui's main TUI and rate; `event::read()` error handling; resize events ignored.
   - Export: `/tmp/smg-proxy-{id}.txt` — predictable filename in a shared directory (symlink preplant by
     another local user → write target hijack) — assess and propose mkstemp-style fix if warranted.

7. CROSS-ENGINE GUARDRAIL & CONSISTENCY MATRIX (verify EVERY row against the actual code, not the docs):
   - Scope enforcement: `is_lab_or_loopback_url()` (idor_audit) is called by templates/sqli/dast/http-audit —
     build the bypass/edge table: `[::ffff:127.0.0.1]`, `0x7f.1`, `127.1`, `2130706433`, `0177.0.0.1`,
     `localhost.evil.com`, `.local` suffix, IPv6 `::1`, DNS-rebinding hostnames, missing/empty host, and
     credentials-in-URL. For EACH engine confirm fail-closed (refused) or flag.
   - Redirect policy: sqli/dast/http-audit = `Policy::none()`; templates = `limited(10)` when the template
     sets `redirects: true` (scope NOT re-checked on redirect targets); proxy replay = reqwest default
     (follows up to 10!) — verify and rate each row.
   - TLS trust: templates + proxy-replay accept invalid certs (2 smg-ignore sites); dast/sqli/http-audit do
     NOT (self-signed lab HTTPS fails silently → FN/INCONCLUSIVE) — verify the inconsistency and whether the
     failures surface to the user.
   - Body caps: templates 2 MiB, dast 2 MiB, http-audit unbounded (`resp.text()`!), sqli `resp.text()`
     unbounded, proxy 8 MiB (with mid-stream truncation) — verify each and rate the OOM surface.
   - Timeouts: every client has connect+total timeout (verify http-audit's per-request total vs the 7-request
     worst case; sqli's `delay*2+20` math).
   - Secret exposure: proxy history/JSONL/export contain full headers incl. Authorization/Cookie (by design,
     loopback dev tool) — verify no other module (mcp.rs, smg-report) consumes these entries and leaks them
     into reports.

Apply all Global Rules above and output the structured P0–P3 report.
```
