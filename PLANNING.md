# ShellMind Guard — Ultra-Maximum Depth Execution Plan & Complexity/Precision Contract

> **Purpose:** Reviewed, end-to-end verified execution blueprint for **Phases 11–14** across all **11 workspace crates** (`~59,400` lines across `crates/` and `src/`). Every file target, symbol name, and line range is verified against disk, paired with explicit **Big-O complexity budgets** and **Zero-Hallucination soundness gates**.
>
> **Verified Baseline (`5511159`):** `96` cataloged rules across `31` layers (`smg rules`), `85` modular `OnceLock<RegexSet>` patterns, `76` entropy-verified secret detectors, `92/92` adversarial precision cases (`100.00%` Precision/Recall/F1), `23/23` test suites (`144/144` passed), `0` self-scan false positives on `src/` & `crates/`.

---

## 1. Change-Safety Contract: Protected Core vs Upgrade Seams

| Crate / Target Files | Verified State (`5511159`) | Policy | Exact Scope & Performance Guardrail |
|---|---|---|---|
| `crates/smg-core/src/{scanner.rs, config.rs, store.rs}` | `BLAKE3` walker, `2..=6` thread clamp, WAL + `ast_cache` (`v20-ultra-max-precision-*`) | **LOCKED / EXTEND** | Keep `256 KiB` read cap & zero default network I/O; add shared zero-dep **Structural YAML Parser** (`smg-core`) to replace 3 ad-hoc scanners |
| `crates/smg-core/src/advisories.rs` + `crates/smg-report/src/lib.rs` | `canonical_ecosystem` maps 4 (`L26-34`); `smg-report` maps 4 PURLs (`L212-219`) | **EXTEND (PH 12)** | Add `Maven`, `Packagist`, `RubyGems`, `Pub`, `NuGet` canonical ecosystems + CycloneDX `purl`s + call-graph VEX justifications |
| `crates/smg-graph/src/{cfg.rs, ast.rs, taint.rs, scope.rs, langs/}` | Separate lowering (`cfg.rs:225/301`, `taint.rs:1079/3351`), global `scope.rs:11`, line loops in `langs/` | **UNIFY (PH 11–12)** | **2-Stage Lazy `UirCfg`**: pre-filter pure functions in $O(N)$ so Braun SSA + Dominator solver runs strictly on candidate functions (`MAX_CFG_BLOCKS = 256`) |
| `crates/smg-graph/src/{deep_stack.rs, protocols_ai.rs, phase10.rs, phase9/}` | Contains line windows (`protocols_ai.rs:114`), raw substring bounds (`phase10.rs:130`, `memory.rs:132`), brace counting (`concurrency.rs:341`) | **MIGRATE TO `UirCfg` (PH 11)** | Re-host SQL RLS, 5 `protocols_ai` sub-engines, `--deep` schema bounds, concurrency unwind locks, memory typestate, & mobile AST onto `UirCfg` |
| `crates/smg-graph/src/{langs/hcl.rs, infra_dos.rs, rule_pack/cloud_iac.rs}` | Single-file `hcl::` resolve (`ast.rs:3116`), `hcl.rs:104` skips vars, K8s `split("---")` & global RBAC FP (`L371, 499`), discarded CI checkout (`L306`) | **UPGRADE (PH 11)** | Hash-indexed $O(R)$ HCL `InfraGraph` + shared YAML K8s RBAC/label-inverted NetPol graph + CI job DAG feeding `langs/bash.rs` AST |
| `crates/smg-graph/src/{lattice.rs, deps.rs}` | Drops external imports (`lattice.rs:533`), strips qualifiers (`ast.rs:906`), misses Py `import`/Go `import_spec`, `deps.rs:1621` ignores `AdvisoryStore` | **EXTEND (PH 12)** | Retain $O(V+E)$ convergence; add `CallSite`, CHA/RTA with `Heuristic` tie-breaker on `>1` targets, & **reverse-seeded CVE-only BFS** `DepReachabilitySolver` |
| `crates/smg-hw/src/{domains.rs, typestate_irq.rs, context.rs, lib.rs}` | Line scan (`L785`), `[-32768,65535]` widths (`L829`), branch leaks (`L806`), ad-hoc `SparseOctagon::new(2)` (`L1817`) + `256`/`512`/`4096` guesses | **UPGRADE (PH 13)** | Tree-sitter AST + branch-joined `(WrappedInterval, Tnum, OctVarMap)` + exact bit-widths + `<= 4`-hop `HwFunctionSummary` + `#define`/SVD offset indexing |
| `crates/smg-web3/src/{evm_oracle.rs, solidity.rs, context.rs, svm_move.rs, lib.rs}` | Uninitialized `revm` DB (`L271, 365, 430`), `CALLDATASIZE==0` only, 1-file Solidity/Solana, no Move `<abilities>` | **UPGRADE (PH 13)** | Static-gated constructor-seeded `revm` (`<= 2M` gas cap) + callback dispatch + view-reentrancy oracle; workspace C3/Anchor/Move graphs |
| `crates/smg-pqc/src/{lattice.rs, inventory.rs}` | No DER/PEM parser (`L341` hardcoded shelf-life, `L580` missing `"certificate"`), global KDF check (`L223`), 1-line HMAC (`L504`) | **EXTEND (PH 13)** | Zero-dep `smg-pqc/src/x509.rs` chain analyzer + function-scoped KDF flow + `±5`-line BHT filter + hybrid/TLS 1.2 checks |
| `crates/smg-sandbox/src/{verifier.rs, wire_oracle.rs, bwrap.rs, lib.rs}` | 4 active `GuardKind`s (`L933`); `WireDiffProxy` (`wire_oracle.rs:87`) & `apply_wire_diff_corroboration` (`L1488`) unwired; `:id="1"` (`L469`) | **EXTEND (PH 14)** | Wire `WireDiffProxy`, add 5 signal-gated protocol probers (`<= 3s` I/O cap) + 2-step IDOR ID discovery + Seatbelt loopback ports |
| `crates/smg-ai/src/codemods.rs` | Single-line `.replace()` on 6 rules (`L41-169`); no `tree-sitter` | **EXTEND (PH 14)** | Add `tree-sitter` + multi-hunk `format_multi_hunk_udiff` for `CMDI`, `PATH`, `SSRF`, `XSS`, `CSRF`, `DESER`, & `IaC` (`--apply-check` verified) |
| `src/{lib.rs, mcp.rs}` + `crates/{smg-tui, smg-enterprise}` | `--layers` help (`L294`) omits 11+ `lattice.rs:279-355` tokens | **SYNC (PH 14)** | Full CLI/MCP/TUI/Report parity + offline enterprise bundle verification + Open-Source Mega-Corpus Precision Gate |

---

## 2. Soundness & Insane-Speed Engineering Laws

1. **Zero-Hallucination Confidence Invariant:**
   - Emit **`PROVEN`** only via verified dynamic exploit trace (`bwrap` HTTP/TCP proof or `revm` concrete tx witness).
   - Emit **`CONFIRMED`** only when a finding survives dominator, SSA def-use, exact destination capacity, single/all-target call resolution, or exact AST construct evidence.
   - Downgrade **every** ambiguous path (`>1` CHA dynamic dispatch targets, `ImportedUnprovenSymbol`, opaque reflection, heuristic regex match) to **`Confidence::Heuristic`** (`non-blocking` by default).
2. **Speed Complexity Budget:**
   - **Pre-Filter Lazy Lowering:** $O(N)$ AST marker check runs first; functions lacking sinks/guards/locks/allocs pay **0** CFG/SSA allocation.
   - **No $O(N^2)$ Scans:** Pre-compile unified `RegexSet`s, index HCL/K8s resources in `HashMap` inverted indexes, seed dependency BFS strictly backward from advisory-hit nodes, and gate `revm` bytecode execution strictly to statically flagged contracts.

---

## 3. Detailed Sprint Backlog (Sprints 1–8 Across Phases 11–14)

### Sprint 1 (Phase 11A): Lazy `UirCfg`, Braun SSA & Structural YAML Core
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P11-01` | `cfg.rs:29, 225, 301, 326, 369-436`, `ast.rs:773-793` | Fix `lower_if` else-abort (`L326-355`); isolate `arrow_function`/`closure_expression`/`func_literal`; build 2-stage lazy `CfgSyntaxSpec` -> `UirCfg` (`MAX_CFG_BLOCKS = 256`) supporting `if/elif/else`, `switch/match`, `try/catch/finally`, 2-pass bounded loops, ternaries, & `&&`/`\|\|` across all 16 languages. | Valid early-exit guards (`if (ok) {...} else { return 401; }`) produce 0 FP; closure returns stay isolated; pure helpers pay 0 CFG cost. |
| `P11-02` | `taint.rs:41-66, 1079, 3351-3957`, `scope.rs:11-115` | Fix `stmt_unconditionally_exits` `else_clause`/`elif_clause`; clone `TaintEnv` across `match`/`catch` arms (`L3440`); fix Go grouped params (`L1079`); retire file-global `FileScopeTable` (`scope.rs`); add per-fn Braun SSA `(SymId, Version)` + `Phi` + `AllocSiteId -> FieldSym` heap alias graph. | Multi-hop mutations (`r = obj; r.q = req.body`) tracked accurately; sibling `match`/`catch` arms never cross-contaminate; `< 10ms` P99 delta. |
| `P11-03` | `cfg.rs`, `taint.rs`, `smg-core` (shared YAML parser) | Expand CFG dominators from 2 guards to all **18 `GuardKind`s + sanitizer masks + relational edge polarity**; add one zero-dep Structural YAML parser in `smg-core` (replacing `phase10.rs:592` & K8s/CI splitters). | Branch polarity (`!auth`, `idx < cap`, `a && b` vs `a \|\| b`) strictly separates dominated safe code from untaken-branch bugs. |

### Sprint 2 (Phase 11B): Re-Host Extension Passes & Cross-Resource `InfraGraph` (`smg-graph`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P11-04` | `langs/mod.rs:303,635,725-755`, `langs/bash.rs:266-558`, `deep_stack.rs:93,513-595`, `protocols_ai.rs:120,298,454,538,622`, `phase10.rs:130,167` | Replace `body_code.lines()`, `deep_stack.rs` fn-booleans, 5 `protocols_ai.rs` line windows (`API`/`AI`/`OAUTH`/`SMUGGLE`/`STATE`), & `phase10.rs:130` `code_low` substring check with `UirCfg` SSA def-use & `BoundsConstraint`; correlate SQL RLS (`scan_sql_file:93`) with backend `IdorDbAccess`. | All 16 languages share one Dominator/SSA core with 0 regression in `langs::tests` or `deep_stack` tests. |
| `P11-05` | `phase9/concurrency.rs:341-410,666-679`, `phase9/memory.rs:132-193,608-633`, `phase9/mobile.rs:342-446`, `infra_dos.rs:560,650,711,971` | Migrate concurrency to CFG unwind-edge locksets + `(ReceiverTypeSym, FieldSym)` lock IDs; replace lexical memory bounds & whole-fn `.len()` substrings with dominated `BoundsConstraint` + SSA `MaybeUninit<T>`; check mobile `registerReceiver`/storage via AST args & SSA; verify queue idempotency/ZipSlip via dominators & star-height ReDoS check (`infra_dos.rs:560`). | C++ early-return `unlock()` FPs = 0; untaken `if (n < 10)` + unguarded `memcpy` caught (`TP`); ReDoS excludes non-backtracking engines cleanly. |
| `P11-06` | `ast.rs:3116-3165`, `hcl.rs:104-178`, `infra_dos.rs:172,306,371,499-544`, `rule_pack/cloud_iac.rs` | Map `hcl::` modules to full dirs (`Vec<FileId>`); build $O(R)$ HashMap `InfraGraph` (`variable`/`locals`/`output`/`resource` edges for S3, SG, IMDSv1/IAM); evaluate K8s `PolicyRule` per entry + label-inverted `SA-RBAC-Workload-NetPol` graph; propagate per-job `saw_unsafe_checkout` (`L306`) & `${{ github.event.* }}` `env:` into `langs/bash.rs` AST. | Cross-rule K8s RBAC FP eliminated; Terraform `aws_s3_bucket_public_access_block` & `bash.rs` CI taint verified with $O(R)$ scaling. |

### Sprint 3 (Phase 12A): Qualified Call Graph & Sound CHA/RTA Hierarchy (`smg-graph`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P12-01` | `ast.rs:906-908, 1574-1742`, `langs/mod.rs:244-246`, `lattice.rs:571-660` | Retain `CallSite { qualifier, member, resolved_recv_type, line }`; emit `ImportRef`s for Python `import_statement` & Go `import_spec`; eliminate blind repo-wide unique-name guessing (`lattice.rs:619`). | Namespace imports (`import * as ns`) & identically named `.save()` methods across classes resolve cleanly without collisions. |
| `P12-02` | `ast.rs`, `langs/*`, `lattice.rs:485-720` | Emit `TypeImplSummary` (`extends`, `implements`, Rust traits, Go interfaces, DI bindings); run bounded CHA/RTA dispatch enforcing **Zero-Hallucination tiering** (`Confirmed` only on unique/all-target proof; `Heuristic` when ambiguous). | Interface-wrapped auth/sanitizer guards traverse cleanly across files with 0 polymorphic FPs. |

### Sprint 4 (Phase 12B): Function-Reachable `SMG-DEP-*` VEX & AI Dataflow (`smg-graph`, `smg-core`, `smg-report`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P12-03` | `advisories.rs:26-34`, `deps.rs:180,831-1122,1621-1765`, `smg-report/src/lib.rs:212-219` | Support `Maven`, `Packagist`, `RubyGems`, `Pub`, `NuGet` in `AdvisoryStore` + CycloneDX PURLs; extract `(pkg@ver -> dep@ver, is_dev)` `LockfileDepGraph`; route `yarn.lock`/`pnpm-lock.yaml` through `AdvisoryStore` (drop `OFFLINE_ADVISORIES`-only gap at `L1621-1765`). | Offline `AdvisoryStore` + lockfile resolution runs `< 20ms` across all 9+ package ecosystems. |
| `P12-04` | `lattice.rs:533-546, 1639-1650`, `deps.rs:56-178`, `protocols_ai.rs:298`, `secrets_config.rs` | Keep external `PackageImportIndex`; run **reverse-seeded CVE BFS** joining `build_any_route_bfs_tree`, `CallSite`, & `vulnerable_symbols` into 4 VEX tiers (`ProvenRouteSymbol`, `ImportedSafeApiOnly`, `ImportedUnprovenSymbol`, `DeclaredUnused`); upgrade `protocols_ai` prompt->tool flows to SSA & refine `secrets_config` AST literal roles. | Importing safe subset APIs (`lodash.pick`) yields `ImportedSafeApiOnly` (`NotAffected`); scanning 2,000+ lockfile packages wastes 0 BFS on clean deps. |

### Sprint 5 (Phase 13A): Hardware `Tnum + SparseOctagon` & Inter-Procedural ISR (`smg-hw`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P13-01` | `smg-hw/src/{domains.rs:7-499, typestate_irq.rs:785-1974}` | Replace raw line walk with Tree-sitter AST traversal; persist `(WrappedInterval, Tnum, OctVarMap)` inside `TypestateBranchFrame`; seed exact bit-widths (`u8`/`i16`/`size_t`); wire `tnum_or`/`tnum_lshift`/`tnum_rshift`/`signed_add` & 12-var `SparseOctagon` (`L1817`); fix `is_early_reject` (`L1343`) & remove hardcoded `256`/`512`/`4096` `dst_cap` guesses (`L1767-1815`). | Narrow `uint8_t` index into `buf[256]` = 0 FP; shift/mask arithmetic tight; opaque `char *dst` never emits bogus overflow FPs. |
| `P13-02` | `smg-hw/src/{lib.rs:92, context.rs:264-355, typestate_irq.rs:1977-2057}` | Add bounded (`<= 4` hop) `HwFunctionSummary` fixed-point worklist (`is_isr`, held-lock calls, `ret_interval`, `alloc`/`free`/`snapshot` wrappers); resolve composed `#define` arithmetic/shifts (`L264`) & full SVD `<register>`/`<dim>` bounds (`L272`). | Indirect `ISR -> helper -> spin_lock / kmalloc(GFP_KERNEL)` deadlocks caught with 0 FP on balanced `if/else` locks. |

### Sprint 6 (Phase 13B): Constructor-Seeded `revm`, Solana/Move Workspaces & X.509 PQC (`smg-web3`, `smg-pqc`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P13-03` | `smg-web3/src/{context.rs:458-608, evm_oracle.rs:220-458, solidity.rs:618-1346, lib.rs:71}` | Key artifacts `(rel_path, name)` + link `__$...$__`; static-gate `deploy_with_mock_ecosystem` (`<= 2M` gas / `50ms` cap per flagged contract); add callback selector dispatch (`onERC721Received`, `onFlashLoan`, UniV3); add `revm` runtime witnesses for Read-Only View Reentrancy & Post-Constructor Unauth Admin; hoist multi-file C3 inheritance & ERC-7201 slot-0 checks. | ERC-721 hook reentrancy & view-oracle manipulation upgrade to `PROVEN`; cross-file `Ownable` produces 0 FPs. |
| `P13-04` | `smg-web3/src/svm_move.rs:58-643`, `smg-pqc/src/{lattice.rs:341, inventory.rs:223,504,580}` + `x509.rs` | Hoist `SolanaWorkspaceContext` (`Anchor.toml`) across split files + duplicate `mut`/cosplay/user-bump checks; parse Move `struct has <abilities>` (`drop`/`copy` hot potatoes, `*Cap` `store`, generic `<T_i>`). Add zero-dep DER/PEM `x509.rs` (`notAfter` -> exact Mosca $X_u$, CA chain links, CycloneDX `"certificate"`); scope hybrid KDF per fn + `±5`-line HMAC filter (`SecP256r1MLKEM768`, `FN-DSA`, `HQC`, `BLAKE3`, TLS <= 1.2). | Split Anchor handlers = 0 FP; weak root/intermediate CA beneath PQC cert emits `SMG-PQC-HNDL`; SHA-256 HMAC multi-line calls = 0 FP. |

### Sprint 7 (Phase 14A): Multi-Protocol Sandbox Provers & Multi-Hunk AST Codemods (`smg-sandbox`, `smg-ai`)
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P14-01` | `smg-sandbox/src/{verifier.rs:469,605,792,933,1488, wire_oracle.rs:87,173,291, bwrap.rs:631, lib.rs}` | Wire `WireDiffProxy` + `apply_wire_diff_corroboration` + FS digests (`L605/1488`); allow Seatbelt loopback `OobSsrfCatcher` ports (`bwrap.rs:631`); implement 5 signal-gated probers (`<= 3s` timeout): GraphQL introspection/depth-11, WebSocket CSWSH, OAuth2 PKCE/state/redirect, Cookie+Origin CSRF, Open-Redirect/CRLF/Host + 2-step stateful IDOR (`L792`). | Targets route cleanly by rule signature (`0ms` overhead when `--sandbox` off); live vulnerable endpoints upgrade to `PROVEN`. |
| `P14-02` | `smg-ai/{Cargo.toml, src/codemods.rs:41-199}` | Add `tree-sitter` + multi-hunk `format_multi_hunk_udiff` (`verify_diff_syntax_before_sandbox` + `--apply-check` verified) covering `SMG-CMDI-001`, `SMG-PATH-001`, `SMG-SSRF-*`, `SMG-XSS-001`, `SMG-CSRF-001`/`COOKIE`, `SMG-CMDI-DESER`, & IaC HCL/Docker/K8s. | Every generated patch compiles/parses cleanly and transitions sandbox verification to `[MITIGATED]`. |

### Sprint 8 (Phase 14B): Surface Parity, Enterprise Verification & Mega-Corpus Gate
| Task ID | Exact Targets | Concrete Engineering Changes | Verification & Speed Target |
|---|---|---|---|
| `P14-03` | `src/lib.rs:294`, `src/mcp.rs:159`, `smg-report`, `smg-tui`, `smg-enterprise` | Align CLI `--layers` help/completions to all 32+ canonical `lattice.rs:279-355` tokens; surface VEX provenance, `"certificate"` CBOM, & per-domain latency in SARIF/HTML/TUI; support signed airgapped enterprise verification bundles. | CLI, MCP, TUI, and SARIF/CycloneDX outputs remain 100% consistent across layers & confidence tiers. |
| `P14-04` | `crates/smg-graph/tests/adversarial_precision_bench.rs` + CI matrix | Expand adversarial precision benchmark beyond `92` cases into a multi-domain **Real-World Open-Source Mega-Corpus** (Web, C++/Firmware, Terraform/K8s, Solidity/Anchor/Move, Android/iOS, PQC/X.509) gated by `SMG_ENFORCE_PRECISION_GATE=1`. | **`FP = 0`, `FN = 0` (`100.00%` P/R/F1)**, RSS `< 512 MiB`, 120-module P99 `< 500ms`, zero warnings (`clippy -D warnings`), 0 self-scan FPs. |

---

## 4. Mandatory 5-Gate Verification Loop (Required After Every Sprint)

1. `cargo +1.100.0 fmt --all -- --check` (0 formatting diffs).
2. `cargo +1.100.0 clippy --workspace --all-targets --locked -- -D warnings` (0 compiler/lint warnings).
3. `cargo +1.100.0 test -p smg-graph --lib rules` (`test_rule_catalog_complete_and_unique` passes; zero missing `RuleDoc`s).
4. `SMG_ENFORCE_PRECISION_GATE=1 cargo +1.100.0 test --workspace --locked` (**0 failures, 0 skipped, 100% Precision/Recall**).
5. `cargo +1.100.0 install --path . --locked --force` + live dogfood `smg scan src --format json` & `smg scan crates --format json` -> **0 findings**, followed by clean `git status`.
