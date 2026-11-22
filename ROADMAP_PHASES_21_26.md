# ShellMind-Guard — Roadmap & Status (Phases 21–26)

- **Repository:** `/home/km-abdullah/ShellMind-Guard` (`https://github.com/qira-dev/ShellMind-Guard`)
- **Binary Footprint:** `42M` single Rust release binary (`~/.cargo/bin/smg` & `~/.cargo/bin/shellmind-guard`)
- **Core Principles:** Offline-first, single Rust binary, zero LLM hallucination, zero clippy warnings (`-D warnings`), deterministic parsers & proof-based verification.

---

## Completed Phases (Implemented, Verified & Pushed to `main`)

### Phase 21 — Secrets & Credential Hygiene (`2825d83`)
- **Status:** Completed & Pushed
- **Modules:**
  - `crates/smg-graph/src/gitleaks_config.rs` — `.gitleaks.toml` (v8) parser supporting `[allowlist]`, `[[allowlists]]` (`AND`/`OR` conditions, `paths`, `regexes`, `commits`, `stopwords`), custom `[[rules]]` (keywords + entropy), and inline `gitleaks:allow` / `smg:ignore` / `smg:allow` / `nosecret`.
  - `crates/smg-graph/src/git_history.rs` — O(1) streaming `git log -p -U0 --full-history` commit-history secret scanner with commit SHA, author, timestamp, hunk test-module filtering, and BLAKE3 deduplication.
  - `src/live_verify.rs` — Opt-in (`--verify-live`, OFF by default) read-only live credential verification across 26+ cloud/SaaS/AI providers + pure-Rust FIPS 180-4 SHA-256 / RFC 2104 HMAC-SHA256 AWS SigV4 `sts:GetCallerIdentity`, with `redirect::Policy::none()` and strict token redaction.
- **CLI Flags (`smg scan`):** `--git-history`, `--git-depth <N>`, `--gitleaks-config <FILE>`, `--verify-live`, `--only-verified`.
- **Verification:** `smg-graph` 78/78 tests, root 22/22 tests, `clippy -D warnings` 0 warnings, self-scan clean.

### Phase 22 — Supply-Chain, Lockfiles & Container Images (`010111f`)
- **Status:** Completed & Pushed
- **Modules:**
  - `crates/smg-graph/src/deps.rs` + `crates/smg-core/src/scanner.rs` — Added lockfile parsers for `go.sum`, `Pipfile.lock`, `mix.lock`, `pom.xml`, and `gradle.lockfile`.
  - `crates/smg-core/src/advisories.rs` + `src/deps_sync.rs` — Normalized 15 canonical OSV ecosystems (`npm`, `PyPI`, `crates.io`, `Go`, `Maven`, `Packagist`, `RubyGems`, `Pub`, `NuGet`, `Hex`, `Debian`, `Alpine`, `Ubuntu`, `Rocky Linux`, `AlmaLinux`, `Red Hat`) and added opt-in `--online-osv` live OSV sync on `smg scan`.
  - `src/oci_image.rs` — Pure-Rust POSIX USTAR tar + gzip layer reader (`smg image <tar-or-dir>`) inspecting `/etc/os-release`, Debian/Ubuntu `/var/lib/dpkg/status`, Alpine `/lib/apk/db/installed`, and embedded application lockfiles; plus `.trivyignore` waiver parser with `exp:YYYY-MM-DD` expiry support.
- **CLI Additions:** `smg scan --online-osv`, `smg image <TARGET> [--online-osv] [--json] [--fail-on <SEVERITY>]`.
- **Verification:** `smg-graph` 79/79 tests, root 24/24 tests, live `smg image /` parsed 2,409 Ubuntu 26.04 OS packages, `clippy -D warnings` 0 warnings, self-scan clean.

### Phase 23 — Static Mobile & Declarative Cloud/IaC Policy Engine (`3d3f863`)
- **Status:** Completed & Pushed
- **Modules:**
  - `crates/smg-graph/src/iac_policy.rs` + `crates/smg-graph/src/langs/hcl.rs` — Data-driven declarative Cloud/IaC Policy Engine with 52 built-in AWS (28), GCP (11), and Azure (13) Checkov-referenced (`CKV_AWS_*`, `CKV_GCP_*`, `CKV_AZURE_*`) policies, recursive nested-block + `var.*`/`local.*` resolution, and custom JSON policy pack loader.
  - `crates/smg-graph/src/phase9/mobile.rs` — Expanded static mobile rules across Android Java/Kotlin (weak cipher/ECB/DES/RC4, hardcoded `IvParameterSpec`, WebView `file://` & unconditional debugging, `Log.*` & `ClipData` secret leaks, SQLite `rawQuery`/`execSQL` concatenation, `BiometricPrompt` without `CryptoObject`), iOS Swift & `Info.plist` (`UIFileSharingEnabled`, `NSFileProtectionNone`, `UIWebView`, `UIPasteboard`, weak CommonCrypto), Flutter (`sqflite` raw SQL interpolation), and React Native (`AsyncStorage` secret storage).
- **Verification:** `smg-graph` 80/80 tests, root 24/24 tests, live multi-cloud Terraform + Kotlin verification, `clippy -D warnings` 0 warnings, self-scan clean.

### Phase 24 — Live TLS/PQC Auditing & Read-Only Authorization Regression (`008ae8a`)
- **Status:** Completed & Pushed
- **Modules:**
  - `src/tls_audit.rs` (`smg tls <host[:port]>`) — Pure-Rust non-destructive TLS wire auditor checking SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, weak cipher rejection (`RC4`, `3DES`, `NULL`), certificate chain length via `rustls`, HSTS response header, and live RFC 10024 Post-Quantum hybrid key exchange (`X25519MLKEM768` `0x11EC`, `SecP256r1MLKEM768` `0x11EB`, `SecP384r1MLKEM1024` `0x11ED`).
  - `src/idor_audit.rs` (`smg idor --config <FILE>`) — Declarative 2-test-user non-destructive read-only authorization/IDOR/BFLA regression verifier (defaults to loopback/RFC1918 private lab hosts; `--allow-remote` opt-in for own staging servers).
- **Verification:** Root 28/28 tests, live `smg tls cloudflare.com` verified (`TLS 1.2, TLS 1.3`, `X25519MLKEM768`, `CertChain: 3`, `HSTS`), `clippy -D warnings` 0 warnings, self-scan clean.

---

## Unimplemented Items & Explicit Project Boundaries

### Phase 25 — Nuclei-Class Template Runner & Non-Destructive SQLi Prover (Implemented)
- **Status:** Completed & Pushed
- **Design Boundary (deliberate):** detection/proof only — **no** WAF-evasion/tamper catalogs, **no** data extraction/dumping, **no** stacked queries, **no** OS shell. Loopback/RFC1918-only by default; `--allow-remote` opt-in. (The `--spa` headless-browser plane below is opt-in, lab-scoped, and renders the operator's own lab pages only.)
- **Modules:**
  - `src/templates_audit.rs` (`smg templates <TARGET> [--templates <DIR>]`) — Nuclei-compatible YAML detection template runner: HTTP engine (path + raw request modes, status/word/regex/dsl/size/binary matchers, extractors, matchers-condition, redirects), a pure-Rust UDP DNS engine (A/AAAA/CNAME/NS/PTR/MX/TXT, compression-pointer parser), and a raw TCP/TLS network engine (rustls insecure-accept for lab banners). Additional engines: `ssl:` (TLS version/cipher/CN/SAN/expiry attribute matching via sync rustls + smg-pqc DER inspection), `websocket:` (sync tungstenite ws:// handshake with mandatory socket timeouts; wss:// needs a webpki-trusted cert), `headless:` (navigate/wait steps through the shared CDP engine, matchers on the rendered DOM), and Interactsh-OOB callback verification via `--oob-server` + `smg oob serve` (per-run random tokens `blake3(run_nonce||template_id||target)`, size-capped hit store). javascript/code/file/whois/flow/lua templates are still skipped with explicit reasons (zero-guessing). Deterministic `{{randstr}}` (BLAKE3 per template id), helper functions (`md5`, `sha1`, `sha2`, `base64`, URL encode/decode, case). Severity/tag filters, `--max-templates`, `--fail-on`, JSON report.
  - `src/sqli_audit.rs` (`smg sqli <URL> [--method] [--data] [--param]`) — non-destructive SQLi detection/prover: error-based signatures (MySQL/MariaDB, PostgreSQL, SQLite, MSSQL, Oracle), boolean-based differential (2 consistent reps, baseline-similarity thresholds), statistically-verified time-based blind (baseline vs payload median across MySQL `sleep`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR DELAY`), and detection-only `ORDER BY` UNION column-count enumeration (≤16). GET/urlencoded-POST only; no dumping, no tamper.
- **Verification:** `shellmind-guard` 55/55 lib tests, `clippy -D warnings` 0 warnings, self-scan clean; live lab loop: error-based MySQL signature + union column detection proven on a loopback mock; remote-target refusal tests green.

### Phase 26 Part A — ZAP-Class DAST & Burp-Class Proxy (Implemented, Defensive Scope)
- **Status:** Completed & Pushed
- **Design Boundary (deliberate):** proof-based, non-destructive, lab-scoped — **no** WAF-evasion catalogs, **no** data extraction, **no** destructive payloads; HTTPS `CONNECT` tunnels are relayed transparently by default, and TLS termination is strictly opt-in via `--mitm-ca` (local rcgen CA at `~/.config/smg/ca-cert.pem`, on-the-fly per-host leaf certs with IP/DNS SANs, ALPN pinned to HTTP/1.1, decrypted traffic captured as `kind: "https"` and replayable; `smg proxy export-ca` prints the CA for trust-store import); proxy binds loopback by default.
- **Modules:**
  - `src/dast_audit.rs` (`smg dast <URL>`) — same-host crawler (HTML `<a>`/`<form>` extraction, JS path discovery, OpenAPI/Swagger schema import, GraphQL introspection probe), passive security-header audit (CSP, HSTS, clickjacking, nosniff, Referrer-Policy, Permissions-Policy, Set-Cookie flags, Server/X-Powered-By banners, permissive CORS), and proof-based active checks: reflected-XSS event-handler marker, open-redirect to a dedicated invalid proof domain, SSTI `7*7`→`49` arithmetic proof, read-only path-traversal marker, **arithmetic CMDi proof** (`$((19+23))`→`42` with literal-absence guard so pure reflection can never fire), and error-based SQLi signature probe. `--passive-only`, `--max-pages/--max-depth`, `--fail-on`-style exit codes, JSON report.
  - `src/proxy.rs` + `crates/smg-tui/src/proxy_tui.rs` (`smg proxy [--listen] [--no-tui] [--log]`) — localhost HTTP inspection proxy: full plain-HTTP interception (origin-form rewrite, `Connection: close`, `Accept-Encoding` stripped so bodies are inspectable), HTTPS `CONNECT` logging + transparent byte relay (or opt-in `--mitm-ca` TLS termination, see below), capture-bounded history, headless JSONL sink, and a ratatui TUI (history list, request/response panes, `r` Repeater replay with `replay_of` provenance, `d` Base64/URL/JWT decoder, `i` bounded wordlist Intruder (`{FUZZ}` marker, GET, ≤100 words), `e` export).
- **Verification:** `smg-tui` 13/13 tests, `clippy -D warnings` 0 warnings, self-scan clean; live lab loop: XSS reflection, open-redirect `Location` proof, SSTI math proof, real-shell arithmetic CMDi proof (and zero CMDi false positives on reflection-only endpoints), headless proxy JSONL capture, and TLS/PQC regression (`smg tls cloudflare.com`) all verified on loopback.

### Phase 26 Part B — Passive Posture Auditor, Schema Linter & Proxy Compare (Implemented, Defensive Scope)
- **Status:** Completed & Pushed
- **Modules:**
  - `src/http_audit.rs` (`smg http-audit <URL> [--schema <FILE>] [--graphql <URL>]`) — strictly non-destructive passive auditor: one GET for the response-header posture (shared `passive_header_findings` engine with dast, now including the **Cache-Control no-store/private on Set-Cookie** check `SMG-DAST-CACHE`), passive OpenAPI/Swagger discovery with **static spec lints** (`SMG-OAPI-INSECURE-SERVER` plaintext `http://` servers / Swagger-2 plaintext-only `schemes`, `SMG-OAPI-NO-AUTH-SCHEME`, `SMG-OAPI-BASIC-AUTH`, `SMG-OAPI-APIKEY-QUERY`), a read-only GraphQL `__schema` introspection probe (`SMG-GQL-INTROSPECTION`), **offline schema-file linting** with zero network (OpenAPI 3 / Swagger 2 JSON + GraphQL SDL: `SMG-GQL-NO-QUERY-ROOT`, `SMG-GQL-SENSITIVE-FIELD`, `SMG-GQL-DEBUG-FIELD`), and remote-host guardrails identical to the other live engines.
  - `crates/smg-tui/src/proxy_tui.rs` — **Compare (Burp-CE diff parity)**: `x` marks a compare-from entry and a second `x` opens a bounded LCS **line diff** modal (`same/removed/added` counters, red/green colouring, 900-line render cap, `DIFF_MAX_LINES` DP bound) between any two captured transactions.
- **Verification:** 225/225 workspace tests (incl. offline schema lint, Cache-Control check, diff LCS correctness), `clippy -D warnings` 0 warnings, dogfood self-scan 0 findings; live lab loop verified: passive posture 8 findings incl. `SMG-DAST-CACHE`, OpenAPI lints (`SMG-OAPI-INSECURE-SERVER`, `SMG-OAPI-APIKEY-QUERY`), `SMG-GQL-INTROSPECTION`, offline GraphQL SDL lint with no network, and remote-target refusal.

---

## Deliberate Out-of-Scope Boundaries (Unchanged)
- **Never implemented, by design:** WAF-evasion/tamper transformation catalogs, live database dumping/extraction, OS-shell payloads, and mass/indiscriminate scanning. (Headless rendering and MITM TLS re-signing were lifted from this list as strictly opt-in, loopback-default lab features: `--spa` / `headless:` templates via the sync CDP engine, and `--mitm-ca` with the local rcgen CA — both documented above and still non-destructive by construction.) `ShellMind-Guard` remains a defensive, offline-first, proof-based verification engine whose live engines (templates/SQLi/DAST/proxy) are lab-scope (loopback/RFC1918 default, `--allow-remote` opt-in for the owner's own staging servers) and non-destructive by construction.

