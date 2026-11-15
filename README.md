<div align="center">

# ShellMind Guard

**Compiler-Grade Multi-File Security, Business-Logic & Concurrency Verifier**

*Traces cross-file taint and guard invariants via an $O(V + E)$ Guard-Set Lattice across 16 languages (TypeScript, JavaScript, Go, Python, Rust, PHP, Java, C#, Kotlin, Swift, Dart, C, C++, Ruby, Bash/Shell, and Terraform/HCL)—then mathematically proves exploitability inside an unprivileged Linux Bubblewrap (`bwrap`) sandbox with zero AI API cost.*

[![CI](https://github.com/qira-dev/ShellMind-Guard/actions/workflows/ci.yml/badge.svg)](https://github.com/qira-dev/ShellMind-Guard/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust Edition](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](Cargo.toml)
[![Sandbox](https://img.shields.io/badge/Sandbox-Bubblewrap_Namespaces-success.svg)](crates/sh-sandbox)
[![MCP Server](https://img.shields.io/badge/MCP-JSON--RPC_2.0_Stdio-purple.svg)](src/mcp.rs)
[![SARIF](https://img.shields.io/badge/Output-SARIF_2.1.0_%7C_HTML_%7C_JSON-informational.svg)](crates/sh-report)

[**Architecture**](#system-architecture) · [**6-Layer Engine**](#the-6-layer-universal-verification-engine) · [**Quickstart**](#quickstart) · [**AI Agent MCP**](#model-context-protocol-shellmind-guard-mcp) · [**Benchmarks**](#verified-performance-benchmarks) · [**Blueprint**](BLUEPRINT.md)

</div>

---

## Why ShellMind Guard?

Modern software—especially high-velocity, AI-assisted full-stack codebases—suffers from vulnerabilities that span multiple files and execution layers: a route in `routes/checkout.ts` delegates to `services/ledger.ts`, which mutates a balance in `db/queries.ts` without an authentication middleware, ownership filter, or `SELECT ... FOR UPDATE` transaction lock.

Conventional security tools fail on these bugs in two predictable ways:

1. **Regex / Single-File SAST Scanners** lack cross-file call-graph and middleware-order semantics, burying engineering teams under hundreds of false positives while missing multi-hop business-logic and race-condition flaws.
2. **LLM-Only Code Scanners** burn tens of thousands of tokens per scan, hallucinate findings on sanitized paths, cannot execute deterministic data-flow proofs, and cannot verify whether a concurrency bug is actually exploitable at runtime.

**ShellMind Guard** solves both problems with a deterministic, systems-engineered architecture:

- **Two-Phase Incremental Ingestion (`BLAKE3` + `SQLite WAL`):** Fingerprints 13,000+ files at >1 GB/s, caching per-file `Tree-sitter` AST summaries in SQLite while **always re-linking the global cross-file call graph in RAM (<80 ms)** so edits to a shared middleware (`auth.ts`) immediately invalidate downstream routes (`routes.ts`).
- **$O(V + E)$ Guard-Set Lattice Solver:** Computes fixed-point security guard intersections across all incoming call paths without exponential $O(V!)$ path enumeration—terminating in linear time even on cyclic enterprise call graphs.
- **Universal 6-Layer Static & Taint Engine:** Covers hardcoded secrets, CORS/JWT/TLS/Dockerfile misconfigurations, offline lockfile advisories, cross-file SQL/Command/Path/SSRF taint with sanitizer disproof, missing auth/transaction locks, IDOR missing ownership filters, and frontend-to-backend API contract drift (`404` dead routes).
- **OS-Isolated Bubblewrap (`bwrap`) Exploit Prover:** Boots your service inside an unprivileged Linux namespace (`--unshare-all`, read-only rootfs, ephemeral `tmpfs`, optional `--sandbox-mem-mb` `RLIMIT_AS` / `--cgroup-v2` resource caps, `--sandbox-tls` loopback `rustls`, `--mock-shims` offline service endpoints, fast `UNBOOTABLE` diagnostics, and process-group reaper) and fires barrier-synchronized **12-way Last-Byte Sync** concurrent HTTP/HTTPS bursts (`tokio::sync::Barrier` + `tokio::task::JoinSet`) to upgrade static `SUSPECT` findings to **`PROVEN`** or **`MITIGATED`**.
- **Native Model Context Protocol (`shellmind-guard mcp`) Server:** Exposes deterministic, zero-token-overhead security verification over `stdio` JSON-RPC 2.0 for **Claude Code, Cursor, AntiGravity, Windsurf, OpenCode, and Z-Code**.

---

## System Architecture

```mermaid
flowchart TD
    subgraph CLI["Unified Rust Binary (shellmind-guard)"]
        A1["CLI / CI Gate\nshellmind-guard scan --ci"]
        A2["60fps Terminal UI\nshellmind-guard ui (ratatui)"]
        A3["Stdio MCP Server\nshellmind-guard mcp (JSON-RPC 2.0)"]
    end

    subgraph S1["Stage 1: Two-Phase Incremental Ingestion (sh-core)"]
        B1["ignore::WalkParallel\n(.gitignore + fast path filter)"]
        B2["BLAKE3 Content Fingerprinting\n+ mtime_ns Fast-Skip"]
        B3["SQLite WAL + FTS5 Store\n($XDG_CACHE_HOME/shellmind-guard/<hash>/state.db)"]
        B1 --> B2 --> B3
    end

    subgraph S2["Stage 2: Polyglot AST & O(V+E) Guard-Set Lattice (sh-graph)"]
        C1["Rayon Parallel Tree-sitter AST (16 Languages)\nTS/JS · Go · Python · Rust · PHP · Java · C# · Kotlin · Swift · Dart · C/C++ · Ruby · Bash · HCL"]
        C2["Cross-File Module, Header & IaC Linker\ntsconfig paths · barrels · Go/Java/Kotlin/C#/PHP/Dart/Ruby/Bash/C++ headers · Terraform modules"]
        C3["6-Layer Guard-Set Lattice & Sink-Typed Bitmask Taint\nG(v) = ⋂ (G(p) ∪ EdgeGuards(p → v))"]
        C1 --> C2 --> C3
    end

    subgraph S3["Stage 3: OS-Isolated Runtime Prover (sh-sandbox)"]
        D1["Linux Bubblewrap (/usr/bin/bwrap)\n--unshare-all · --ro-bind · --tmpfs · PGID Reaper"]
        D2["12-Way Barrier-Synchronized Prober\nAuth Bypass, Cross-Tenant IDOR & Last-Byte Sync Race"]
        D1 --> D2
    end

    subgraph S4["Stage 4: Actionable Outputs (sh-report / sh-ai)"]
        E1["SARIF 2.1.0 + Confidence\nGitHub Code Scanning"]
        E2["Interactive HTML/SVG\nMulti-File Witness Graph"]
        E3["Minimal Patch Prompt (<= 2 KB) & --apply-check\nExact Witness Hops + Opt-In AI Patch Verifier"]
    end

    CLI --> S1 --> S2
    S2 -->|"Static Findings"| S4
    S2 -->|"--boot-cmd"| S3
    S3 -->|"PROVEN / MITIGATED"| S4
```

### Mathematical Formulation: The $O(V + E)$ Guard-Set Lattice

Instead of enumerating all simple paths between routes and sinks (which degrades to $O(V!)$ on cyclic call graphs), ShellMind Guard formulates security invariant verification as a forward data-flow monotone lattice over the finite universe of security guards $\mathcal{U} = \{\text{Auth}, \text{TxLock}, \text{OwnershipCheck}, \text{SqlSanitizer}, \text{CmdSanitizer}, \text{PathSanitizer}, \text{SsrfSanitizer}, \text{XssSanitizer}, \text{CsrfProtection}\}$ paired with a sink-typed bitmask taint semilattice (preventing cross-sink sanitizer confusion) and explicit finding confidence grading (`PROVEN`, `CONFIRMED`, `HEURISTIC`):

$$\mathcal{G}_{\text{in}}(v) = \begin{cases} \emptyset & \text{if } v \in \text{EntryRoutes} \\ \displaystyle\bigcap_{p \in \text{Pred}(v)} \mathcal{G}_{\text{out}}(p) & \text{otherwise} \end{cases}, \qquad \mathcal{G}_{\text{out}}(v) = \mathcal{G}_{\text{in}}(v) \cup \text{LocalGuards}(v)$$

1. **Initialization:** Entry route nodes are initialized with their route-registration and router-level middleware guards; interior nodes start at top ($\top = \mathcal{U}$).
2. **Fixed-Point Convergence:** A worklist algorithm propagates guard sets in $O(V + E)$ time. Because $\mathcal{U}$ is finite and intersection is monotone, convergence is guaranteed on arbitrary cyclic graphs.
3. **Shortest Witness Extraction:** When a reachable sink $s$ requires guard $g \notin \mathcal{G}_{\text{out}}(s)$, a guard-avoiding multi-source BFS reconstructs the shortest unguarded witness chain $(r \to f_1 \to \dots \to s)$ in $O(V + E)$ time.

---

## The 6-Layer Universal Verification Engine

ShellMind Guard executes all 6 verification layers in a single unified pass:

| Layer | Rule ID | Severity | Category & Invariant Checked | Required Guard / Sanitizer Disproof |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `VF-SEC-AWS`<br>`VF-SEC-STRIPE`<br>`VF-SEC-GITHUB`<br>`VF-SEC-OPENAI`<br>`VF-SEC-ANTHROPIC`<br>`VF-SEC-GOOGLE`<br>`VF-SEC-SLACK`<br>`VF-SEC-JWT`<br>`VF-SEC-PRIVKEY`<br>`VF-SEC-DBURL`<br>`VF-SEC-CLIENT-ENV`<br>`VF-SEC-ENTROPY` | `CRITICAL`<br>`HIGH` | **Secrets & Credential Exposure:** Provider-prefixed tokens, hardcoded JWT secrets (`VF-SEC-JWT`), PEM private keys, inline credentials in `postgres://`/`mysql://`/`mongodb://`/`redis://` URLs, private secrets exposed in public frontend bundles (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`), and Shannon entropy ($H > 4.3$) secret literals. | Excluded on lockfiles, test fixtures, example placeholders (`EXAMPLE`, `YOUR_API_KEY`, `changeme`), URLs/SQL, and non-assignment strings. |
| **1** | `VF-SEC-ENV` | `HIGH` | **Unignored `.env` File:** `.env` or `.env.production` containing live secrets is not covered by `.gitignore`. | Add `.env` / `.env.*` to `.gitignore`. |
| **1** | `VF-CFG-CORS`<br>`VF-CFG-JWT-LOGIC`<br>`VF-CFG-TLS`<br>`VF-CFG-DEBUG`<br>`VF-CFG-COOKIE`<br>`VF-CFG-DOCKER`<br>`VF-CFG-PROTO`<br>`VF-CFG-XXE`<br>`VF-CFG-SQL-EXEC`<br>`VF-CFG-SQL-SEARCHPATH`<br>`VF-CFG-SQL-RLS`<br>`VF-CFG-SQL-PRIV` | `CRITICAL`<br>`HIGH`<br>`MEDIUM` | **Security Misconfigurations & SQL Schema Policies:** Wildcard CORS (`origin: "*"`) with `credentials: true`, JWT bypasses (`alg: "none"`, `verify_signature: False`, unverified `jwt.decode`, weak hardcoded JWT secrets), TLS disabled, `DEBUG=True`, insecure cookies, non-root `USER`-less `Dockerfile`, JavaScript prototype pollution (`__proto__`/`constructor.prototype`), unsafe XML/XXE parsers, and `.sql` migration hazards (dynamic `EXECUTE format('%s')`, `SECURITY DEFINER` missing `SET search_path`, `DISABLE ROW LEVEL SECURITY`, `SUPERUSER`/over-privileged grants). | Restrict CORS, enforce strong verified JWT secrets/algorithms, keep TLS checks on, sanitize keys against `__proto__`, disable XML external entities/DTDs, and harden `.sql` procedures/grants. |
| **2** | `VF-DEP-001` | `HIGH`<br>`MEDIUM` | **Offline-First Dependency & Lockfile Audit:** Parses `package.json`, `package-lock.json`, `Cargo.toml`, `Cargo.lock`, `go.mod`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `uv.lock` for unpinned `*`/`latest` versions, `http://` tarball registries, embedded high-risk advisories, and local SQLite OSV advisory index (`$XDG_CACHE_HOME/shellmind-guard/advisories.db`) synced opt-in via `shellmind-guard deps sync`. | Pin deterministic semver ranges and upgrade affected packages (scans stay 100% offline with zero network calls). |
| **3** | `VF-SQLI-001`<br>`VF-SQLI-NOSQL`<br>`VF-SQLI-MASS` | `CRITICAL`<br>`HIGH` | **Cross-File SQL, NoSQL & ORM Injection:** Untrusted HTTP input flows into dynamic SQL (`knex.raw`, `sequelize.query`, `queryRunner.query`, `sql.unsafe`, `db.prepare`, `Fmt`/`f""`/`${...}`), MongoDB queries (`find`/`aggregate`/`$where`/`$function`/`$regex`) or Redis Lua `eval`/`evalsha`, or unvalidated ORM mass assignment (`prisma.create({ data: req.body })`, `bulkCreate`). | Parameterized queries (`$1`, `?`), safe tagged templates (`prisma.$queryRaw\`...\``), `$eq` / strict Zod/integer/UUID allowlists, and explicit field picking. |
| **3** | `VF-XSS-001` | `HIGH` | **Cross-Site Scripting (XSS):** Untrusted HTTP or DOM URL input (`window.location.search`, `window.location.hash`, `URLSearchParams`) flows into `dangerouslySetInnerHTML`, `innerHTML`, `res.send`/`html` responses, `template.HTML(...)`, or Python `Markup(...)`/`render_template_string` without an XSS sanitizer bit. | HTML escaping/sanitization (`DOMPurify.sanitize`, `bluemonday`, `bleach.clean`, `ammonia::clean`, `html.escape`) matching the XSS sink bit. |
| **3** | `VF-CMDI-001`<br>`VF-CMDI-SSTI`<br>`VF-CMDI-DESER` | `CRITICAL` | **Command, SSTI & Deserialization Execution:** Tainted input reaches `exec`/`os.system`/`subprocess.run(..., shell=True)`/`exec.Command`, unsafe template rendering (SSTI), or unsafe deserialization (`pickle.loads`, `yaml.load`, `unserialize`, `ObjectInputStream`). | Argument array execution without shell, `shlex.quote`, `yaml.safe_load`/JSON schemas, or strict allowlist/numeric parser. |
| **3** | `VF-PATH-001` | `HIGH` | **Path Traversal:** Tainted input reaches `fs.readFile`, `fs.writeFile`, `res.sendFile`, `os.Open`, `os.ReadFile`, `http.ServeFile`, `open()`, or `std::fs::read`. | `path.basename`, `filepath.Base`, `filepath.Clean` + `.startsWith(baseDir)` prefix check. |
| **3** | `VF-SSRF-001`<br>`VF-SSRF-REDIRECT` | `HIGH` | **SSRF & Open Redirect:** Tainted URL reaches `fetch`, `axios`, `http.Get`, `requests.get`, `httpx.get`, `reqwest::get`, or unvalidated server/DOM redirects (`window.location.href`, `window.open`, `res.redirect`). | Explicit hostname allowlist (`allowedHosts`, `validateUrl`), scheme validation, and private/link-local CIDR block. |
| **4** | `VF-AUTH-001` | `HIGH` | **Missing Authentication Guard:** Reachable path from an HTTP route to a privileged state-mutating sink (`PaymentMutation`, `BalanceUpdate`, `SqlWrite`, `AuthMutation`, `ResourceDestroy`) without an active `Auth` guard. | Route/router middleware (`requireAuth`, `UseGuards`, `protectedProcedure`, `login_required`, `AuthMiddleware`) or `.shellmind-guard.toml` `public_routes`. |
| **4** | `VF-CSRF-001` | `HIGH` | **Cross-Site Request Forgery (CSRF):** Cookie/session-authenticated state-changing endpoints or explicit `@csrf_exempt` overrides without CSRF token middleware or `SameSite` cookie protection (excludes pure Bearer/JWT APIs, webhooks, and health probes). | `csurf` / `csrfProtect` / `SameSite=Strict` or `SameSite=Lax` cookies, or token-based `Authorization: Bearer` auth. |
| **4** | `VF-IDOR-001` | `HIGH` | **Insecure Direct Object Reference (IDOR):** Authenticated route accepts a resource ID (`:id`, `{id}`, `[id]`) and executes a DB read/update/delete without scoping by caller identity—provable dynamically via User A vs User B sandbox probing. | Include caller ownership predicate (`user_id = req.user.id`, `owner_id`, `tenant_id`, `org_id`, `current_user`) and verify HTTP `401/403/404` across tenants. |
| **5** | `VF-RACE-001`<br>`VF-ENG-DEADLOCK`<br>`VF-ENG-LEAK`<br>`VF-MEM-BOUNDS`<br>`VF-ENG-INT` | `CRITICAL`<br>`HIGH` | **Concurrency, Resource Leaks & Native Memory Safety:** Payment/balance double-spend races (`VF-RACE-001`), cross-function `A->B / B->A` lock-order inversions & sync locks held across `.await` (`VF-ENG-DEADLOCK`), unclosed file/socket/DB handles on early error returns (`VF-ENG-LEAK`), unbounded C/C++ copies (`strcpy`, `sprintf`, unchecked `memcpy`) & unguarded Rust `unsafe` slice/ptr access (`VF-MEM-BOUNDS`), and allocation integer overflow (`VF-ENG-INT`). | Enforce `withTransaction`/`SELECT ... FOR UPDATE`, canonical lock ordering (`std::scoped_lock`), drop mutexes before `.await`, use RAII/`defer`/`try-finally`, and validate bounds + checked arithmetic. |
| **6** | `VF-FE-404`<br>`VF-FE-ERR`<br>`VF-FE-STORAGE`<br>`VF-FE-MSG`<br>`VF-FE-TABNAB` | `HIGH`<br>`MEDIUM`<br>`LOW` | **Frontend ↔ Backend Contract & Browser Security:** Frontend `fetch`/`axios`/`$fetch`/`useFetch`/`this.http.*` calling missing backend routes (`VF-FE-404`), dead `onClick` or unhandled async fetches (`VF-FE-ERR`), auth tokens/secrets persisted in `localStorage`/`sessionStorage` (`VF-FE-STORAGE`), unverified `postMessage` (`*` target origin or `.data` without `.origin` check, `VF-FE-MSG`), and `target="_blank"` missing `noopener` (`VF-FE-TABNAB`). | Align API contracts, handle rejections, store tokens in `httpOnly` cookies, enforce strict `event.origin` checks, and add `rel="noopener noreferrer"`. |
| **Domain** | `VF-MOB-STORAGE`<br>`VF-MOB-IPC`<br>`VF-MOB-TLS` | `CRITICAL`<br>`HIGH`<br>`MEDIUM` | **Domain-Routed Mobile Security (`Android`/`iOS`/`Flutter`):** Activated automatically when mobile code/manifests (`AndroidManifest.xml`, `Info.plist`, `pubspec.yaml`) exist: plaintext `SharedPreferences` / `UserDefaults` credential storage (`VF-MOB-STORAGE`), exported permissionless Android components / dynamic receivers / WebView bridges (`VF-MOB-IPC`), and trust-all TLS verifiers / ATS bypasses (`VF-MOB-TLS`). | Use `EncryptedSharedPreferences`/Keychain/`FlutterSecureStorage`, enforce `android:exported="false"` or signature permissions, and enable strict TLS pinning. |
| **Deep (`--deep`)** | `VF-FUZZ-SCHEMA`<br>`VF-FUZZ-TAMPER`<br>`VF-FUZZ-CRASH`<br>`VF-FUZZ-ENCODING` | `CRITICAL`<br>`HIGH` | **Schema Bounds & Targeted Route Fuzzing (`--deep`):** Extracts route schemas from AST handlers and OpenAPI/Swagger specs to flag unvalidated financial/quantity parameters (`VF-FUZZ-SCHEMA`) and probe live sandboxed routes for negative/zero tampering (`VF-FUZZ-TAMPER`), server 5xx/panic crashes (`VF-FUZZ-CRASH`), and null-byte / invalid UTF-8 (`\xff\xfe`) failures (`VF-FUZZ-ENCODING`). | Enforce finite positive schema validation (`amount > 0`, Zod `.finite().positive()`, Pydantic `gt=0`) and reject malformed/non-UTF-8 payloads with `400/422`. |

### Supported Languages & Frameworks

| Language | AST Grammar | Frameworks & Idioms Extracted Automatically |
| :--- | :--- | :--- |
| **TypeScript / JavaScript** (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`) | `tree-sitter-typescript` (TS & TSX), `tree-sitter-javascript` | Express, Fastify, Hono, Koa, **Next.js App Router** (`export async function GET/POST/PUT/DELETE/PATCH`), **NestJS** (`@Controller`, `@Get`/`@Post`, `@UseGuards`), **tRPC** (`publicProcedure`, `protectedProcedure`), Prisma, Drizzle, React/Next.js Frontend (`fetch`, `axios`) |
| **Go** (`.go`) | `tree-sitter-go` | `net/http` (`http.HandleFunc`, `mux.HandleFunc`), **Gin** (`r.GET`, `r.Group`, `.Use`), **Echo**, **Chi**, `database/sql` (`db.Query`, `db.Exec`, `tx.Exec`), `os/exec` |
| **Python** (`.py`) | `tree-sitter-python` | **FastAPI** (`@app.get`, `@router.post`, `Depends`), **Flask** (`@app.route`, `request.args`), **Django** (`path()`, `@login_required`, `.objects.get/filter`), `cursor.execute`, `subprocess` |
| **Rust** (`.rs`) | `tree-sitter-rust` | **Axum** (`Router::new().route()`, `.layer()`), **Actix-Web** (`#[get("/...")]`, `#[post("/...")]`, `web::Path`, `web::Query`), `sqlx`, `tokio::process::Command` |
| **PHP** (`.php`, `.phtml`) | `tree-sitter-php` | **Laravel** (`Route::get/post/...`, `middleware('auth')`, `DB::transaction`, `DB::select`), **Symfony** (`#[Route]`, `#[IsGranted]`), PDO `prepare()`, PSR-4 `use` resolution |
| **Java** (`.java`) | `tree-sitter-java` | **Spring Boot / MVC** (`@RestController`, `@RequestMapping`, `@GetMapping`/`@PostMapping`, `@PreAuthorize`, `@Transactional`), **JAX-RS** (`@Path`, `@GET`/`@POST`), JDBC `PreparedStatement` |
| **C#** (`.cs`) | `tree-sitter-c-sharp` | **ASP.NET Core MVC** (`[Route]`, `[HttpGet]`/`[HttpPost]`, `[Authorize]`, `[ValidateAntiForgeryToken]`) & **Minimal APIs** (`app.MapGet`/`MapPost`, `.RequireAuthorization()`), Entity Framework (`FromSqlRaw` vs `FromSqlInterpolated`) |
| **Kotlin** (`.kt`, `.kts`) | `tree-sitter-kotlin-ng` | **Ktor** (`routing { get/post }`, `authenticate("...")`, `call.parameters`), **Spring Boot Kotlin** (`@RestController`, `@PreAuthorize`), **Android** (`Intent`, `rawQuery`, `execSQL`) |
| **Swift** (`.swift`) | `tree-sitter-swift` | **Vapor** (`app.get/post`, `app.grouped(User.authenticator())`, `req.db.transaction`, `sql.raw` + `binds:`), **iOS** (`URLSession`, `FileManager`, `sqlite3_exec` vs `sqlite3_prepare`) |
| **Dart** (`.dart`) | `tree-sitter-dart` | **Dart Frog** (`routes/**` `onRequest`), **Shelf** (`shelf_router` `router.get/post`), `rawQuery`/`rawUpdate`/`Process.run` |
| **C / C++** (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx`) | `tree-sitter-c`, `tree-sitter-cpp` | Native engines & libraries (`#include` header-to-implementation edge resolution), **Crow** (`CROW_ROUTE(...).methods(...)`), **cpp-httplib** (`svr.Get/Post`), `sqlite3_prepare_v2`, `std::lock_guard` / `std::mutex` |
| **Ruby** (`.rb`, `.rake`, `.ru`) | `tree-sitter-ruby` | **Ruby on Rails** (`routes.rb` `to: 'ctrl#act'`, `resources`, `before_action :authenticate_user!`, `skip_before_action :verify_authenticity_token`, ActiveRecord `.transaction` / `.where`), **Sinatra** (`get`/`post` blocks), `require_relative`, `Shellwords.escape` |
| **Bash / Shell** (`.sh`, `.bash`, `.zsh`) | `tree-sitter-bash` | `source`/`.` cross-file linking, `eval` / `sh -c` / `curl \| bash` (`VF-CMDI-001`), `psql`/`mysql`/`sqlite3` SQLi, dynamic `curl`/`wget` SSRF, `rm -rf` path taint (clean on `mktemp`/`printf '%q'`/regex guards) |
| **Terraform / HCL** (`.tf`, `.tfvars`) | `tree-sitter-hcl` | Local `module` `source` linking, public S3/GCS/RDS exposure (`VF-CFG-IAC-PUBLIC`), `0.0.0.0/0` non-web SG/firewall ingress (`VF-CFG-IAC-NET`), disabled encryption / TLS < 1.2 (`VF-CFG-IAC-CRYPTO`), IAM `*/*` wildcards (`VF-CFG-IAC-IAM`) |

---

## Verified Performance Benchmarks

Measured on a 4-Core Linux workstation (Ubuntu Wayland, 15 GiB RAM, NVMe SSD, 12 MB stripped release binary):

| Workload | Scope | Cold Scan | Warm Cached Scan | Notes |
| :--- | :--- | :---: | :---: | :--- |
| **Enterprise TypeScript Monorepo** | 575 directories / **13,225 `.ts` files** | **414 ms** | **195 ms** | Full walk + `BLAKE3` + `Tree-sitter` + $O(V+E)$ Lattice (Warm Delta Index: **76 ms**) |
| **2,000-Node Cyclic Sink Chain** | Stress test (`test_b11_2000_node_all_sink_chain_is_linear`) | **< 15 ms** | **< 5 ms** | Proves linear $O(V + E)$ scaling without path explosion |
| **Polyglot 6-Layer Suite** | TS + TSX + Go + Python + Dockerfile + `package.json` + `.env` | **19 ms** | **3 ms** | Detects all 14 rule families across all 6 layers |
| **MCP `shellmind_guard_scan` Tool Call** | JSON-RPC 2.0 `stdio` round-trip | **19 ms** | **4 ms** | Zero LLM token overhead |

---

## Quickstart

### 1. One-Command Install (No Rust Toolchain Required)

**Linux & macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/qira-dev/ShellMind-Guard/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/qira-dev/ShellMind-Guard/main/install.ps1 | iex
```

**Use Standalone CLI or Load as an AI Coding Plugin (Claude Code / MCP + Skills + Commit Hook):**

```bash
# 1. Verify binary, sandbox backend, advisory cache & git hook readiness (Standalone)
shellmind-guard doctor .

# 2. Install standalone Git pre-commit hook (blocks high/critical secrets & misconfigs locally)
shellmind-guard hook install .

# 3. Install as a Claude Code plugin from GitHub Marketplace (Claude Code 2.1.275+)
/plugin marketplace add qira-dev/ShellMind-Guard
/plugin install shellmind-guard@shellmind-guard

# Or load a local clone directly (provides MCP tools, /shellmind-guard:guard-scan, /shellmind-guard:guard-fix & PreToolUse hook)
claude --plugin-dir /path/to/ShellMind-Guard
```

### 2. Build & Install from Source

```bash
git clone https://github.com/qira-dev/ShellMind-Guard.git
cd ShellMind-Guard

# Install the optimized release binary to ~/.cargo/bin/shellmind-guard
cargo install --path .
```

> **Optional Runtime Prover Dependency:** Install `bubblewrap` (`sudo apt install bubblewrap` on Debian/Ubuntu or `sudo dnf install bubblewrap` on Fedora) to enable OS-isolated `--boot-cmd` exploit verification. Static 6-layer verification works everywhere with zero external dependencies.

### 2. Initialize a Project & CI Gate

```bash
# Auto-detect project stack, write .shellmind-guard.toml, and generate .github/workflows/shellmind-guard.yml
shellmind-guard init /path/to/your/repo --ci
```

### 3. Run a Full 6-Layer Scan

```bash
# Human-readable terminal report
shellmind-guard scan /path/to/your/repo

# Machine-readable JSON or SARIF 2.1.0 report
shellmind-guard scan /path/to/your/repo --format json
shellmind-guard scan /path/to/your/repo --format sarif

# Filter specific layers or enforce a minimum confidence threshold (proven | confirmed | heuristic)
shellmind-guard scan /path/to/your/repo --layers secrets,sqli,xss,csrf,idor,race --min-confidence confirmed

# Opt-in sync of local offline SQLite OSV advisory DB (or import offline JSON bundle) & check status
shellmind-guard deps sync /path/to/your/repo
shellmind-guard deps sync --from-file /path/to/osv.json
shellmind-guard deps status
```

### 4. Prove Exploits in the Isolated Bubblewrap Sandbox

Run ShellMind Guard against the included vulnerable Node/TypeScript payment fixture (`fixtures/vuln-payment-node`) to see static `SUSPECT` findings upgraded to **`PROVEN`** via live sandbox execution and 12-way barrier-synchronized race probing (add `--deep` for Phase 10 schema & payload fuzzing, or `--sandbox-tls` / `--mock-shims` / `--sandbox-mem-mb 512` for hardened probing):

```bash
shellmind-guard scan fixtures/vuln-payment-node \
  --deep \
  --boot-cmd "node server.mjs" \
  --sarif .shellmind-guard/report.sarif \
  --html .shellmind-guard/report.html
```

Sample output:

```text
ShellMind Guard Scan | 5 files (14 symbols, 5 edges, 3 routes) | 42ms (delta: +5 / 0 cached)
  [!] 5 finding(s) detected:

  [HIGH] VF-AUTH-001 (VF-AUTH-001) -> Unauthenticated path to BalanceUpdate in `debitBalance`
      Entry: POST /api/v1/checkout/withdraw
      [1] src/routes/checkout.ts:8  POST /api/v1/checkout/withdraw
      [2] src/services/ledger.ts:3  processWithdrawal
      [3] src/db/queries.ts:1       debitBalance

  [CRITICAL] VF-RACE-002 (VF-RACE-001) -> Missing transaction/lock guard before `debitBalance` (Double-Spend Risk)
      Entry: POST /api/v1/checkout/withdraw
      [1] src/routes/checkout.ts:8  POST /api/v1/checkout/withdraw
      [2] src/services/ledger.ts:3  processWithdrawal
      [3] src/db/queries.ts:1       debitBalance

ShellMind Guard Sandbox Proof (bwrap=isolated):
  [PROVEN] VF-AUTH-001 (VF-AUTH-001) -> Unauthenticated POST /api/v1/checkout/withdraw returned HTTP 200 (body: {"ok":true,...})
  [PROVEN] VF-RACE-002 (VF-RACE-001) -> 12/12 concurrent requests returned HTTP 200 (Last-Byte Sync, 1 distinct bodies)
```

### 5. Replay a Finding, Generate Minimal Patch Context (<= 2 KB) & Verify Diffs (`--apply-check`)

```bash
# Replay live exploit proof and print minimal <= 2048 B witness context
shellmind-guard replay VF-RACE-002 fixtures/vuln-payment-node \
  --boot-cmd "node server.mjs" \
  --patch

# Apply a unified diff inside an isolated temporary workspace and verify mitigation
shellmind-guard replay VF-SQLI-001 /path/to/your/repo \
  --patch-file fix.diff \
  --apply-check
```

### 6. Launch the Panic-Safe 60fps Terminal UI (`ratatui`)

```bash
shellmind-guard ui fixtures/vuln-payment-node --boot-cmd "node server.mjs"
```

- **`[j]` / `[k]` or `↑` / `↓`:** Navigate findings across all 6 layers
- **`[Enter]`:** Re-run live Bubblewrap sandbox PoC for the selected finding
- **`[p]`:** Generate minimal (<= 2 KB) multi-file witness patch prompt
- **`[f]`:** Cycle filter mode (`ALL` -> `UNMITIGATED` -> `PROVEN` -> `CONFIRMED+` -> `CRITICAL`)
- **`[g]` / `[s]`:** Export interactive Carbon-Slate HTML/SVG graph and SARIF 2.1.0 report
- **`[L]`:** Toggle internal sandbox & diagnostics ring-buffer drawer (zero stdout corruption)

---

## Model Context Protocol (`shellmind-guard mcp`)

ShellMind Guard includes a built-in, newline-delimited **JSON-RPC 2.0 Stdio MCP Server** (`shellmind-guard mcp`) so AI coding agents (**Claude Code, Cursor, AntiGravity, Windsurf, OpenCode, Z-Code**) can run deterministic multi-file security verification without burning context tokens on raw file reads.

### Add ShellMind Guard to Your AI Agent (`mcpServers` Config)

Add the following to your `.mcp.json`, `~/.claude.json`, or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "shellmind-guard": {
      "command": "shellmind-guard",
      "args": ["mcp"]
    }
  }
}
```

### Exposed MCP Tools

| Tool Name | Input Schema | Description |
| :--- | :--- | :--- |
| `shellmind_guard_scan` | `{ "path"?: string, "layers"?: string[], "min_confidence"?: "proven"\|"confirmed"\|"heuristic", "deep"?: boolean }` | Runs the 16-language AST + Guard-Set Lattice scan (plus optional `deep` schema checks and `engine`/`memory`/`mobile` layers) and returns structured JSON findings with confidence, witness hops, and remediation. |
| `shellmind_guard_explain_finding` | `{ "path"?: string, "finding_id": string }` | Resolves a finding by `id` (e.g. `VF-RACE-002`, `VF-FUZZ-001`) or `rule_id` (e.g. `VF-SQLI-001`) and returns exact source lines around every hop in `witness_path`, a <= 2 KB patch prompt, and concrete remediation guidance. |
| `shellmind_guard_init` | `{ "path"?: string, "ci"?: boolean, "hook"?: boolean, "overwrite"?: boolean }` | Detects the repository language stack, writes `.shellmind-guard.toml`, and optionally scaffolds `.github/workflows/shellmind-guard.yml` or installs `.git/hooks/pre-commit`. |

---

## Configuration (`.shellmind-guard.toml`)

ShellMind Guard works out of the box with zero configuration, or can be customized via `.shellmind-guard.toml` in your repository root:

```toml
[guards]
# Functions, decorators, or middleware identifiers treated as authentication guards
auth_guards = [
  "requireAuth", "authenticate", "verifyJwt", "withAuth", "requireAdmin",
  "ensureAuthenticated", "AuthGuard", "UseGuards", "protectedProcedure",
  "login_required", "AuthMiddleware"
]

# Wrappers or SQL clauses treated as concurrency / transaction lock guards
lock_guards = [
  "withTransaction", "FOR UPDATE", "acquireLock", "idempotencyKey",
  "BeginTx", "db.Transaction", "$transaction"
]

# Intentionally unauthenticated routes (suppresses VF-AUTH-001 only; never suppresses SQLi/CMDi/Race)
public_routes = [
  "/health", "/healthz", "/readyz", "/metrics",
  "/login", "/register", "/signup", "/webhook"
]

# Custom router registration methods (if your framework wraps standard HTTP verbs)
custom_routes = []

[scan]
ignore_paths = ["node_modules", "target", "dist", "build", ".next", ".shellmind-guard"]
max_threads = 4
max_file_bytes = 2097152

[sandbox]
# Default boot command, loopback base_url (http:// or https://), IDOR/body overrides, and resource/mock hardening
# boot_cmd = "node server.mjs"
# base_url = "http://127.0.0.1:3000"
# user_a_header = "Authorization: Bearer token-user-a"
# user_b_header = "Authorization: Bearer token-user-b"
# probe_body = '{"amount": 100}'
# memory_limit_mb = 512
# use_cgroup_v2 = false
# mock_shims = false

[ai]
# Opt-in only (disabled by default = zero network calls; requires --trust-repo-config)
# provider = "disabled"          # "disabled" | "ollama" | "openai_compatible"
# endpoint = "http://127.0.0.1:11434"
# model = "qwen2.5-coder:7b"
# api_key_env = "OPENAI_API_KEY"
```

---

## Workspace Architecture

ShellMind Guard is organized as a modular, 100% pure-Rust Cargo workspace:

```text
ShellMind-Guard/
├── Cargo.toml                     # Workspace root (Rust 2024 Edition)
├── .claude-plugin/
│   ├── plugin.json                # Claude Code / agent plugin manifest & icon
│   └── marketplace.json           # GitHub marketplace index (`qira-dev/ShellMind-Guard`)
├── .mcp.json                      # Standalone & plugin stdio MCP configuration (`shellmind-guard mcp`)
├── hooks/hooks.json               # PreToolUse `Bash|PowerShell` secret/config commit guard hook
├── skills/
│   ├── guard-scan/SKILL.md        # `/shellmind-guard:guard-scan` MCP + CLI workflow
│   └── guard-fix/SKILL.md         # `/shellmind-guard:guard-fix` all-rule remediation + `--apply-check`
├── src/
│   ├── main.rs                    # Unified CLI (`init`, `index`, `scan`, `deps`, `replay`, `ui`, `mcp`, `hook`, `doctor`)
│   ├── deps_sync.rs               # Explicit opt-in OSV `/v1/querybatch` + `--from-file` advisory sync
│   └── mcp.rs                     # Stdio JSON-RPC 2.0 Model Context Protocol server
├── crates/
│   ├── sh-core/                   # .shellmind-guard.toml config, ignore::WalkParallel + BLAKE3 scanner,
│   │                              # XDG SQLite WAL + FTS5 AST/findings store & local `advisories.db` index
│   ├── sh-graph/                  # Parallel Tree-sitter AST across 16 languages (TS/JS/Go/Python/Rust
│   │                              # + modular langs/ for PHP/Java/C#/Kotlin/Swift/Dart/C/C++/Ruby/Bash/HCL),
│   │                              # domain routing (`web`/`system_engine`/`mobile`), deep SQL/DOM/SSTI rules,
│   │                              # Phase 9/10 cross-file field/closure taint, OpenAPI schemas & O(V+E) Lattice
│   ├── sh-sandbox/                # Linux Bubblewrap (--unshare-all) + macOS/Windows sandbox helpers,
│   │                              # RLIMIT_AS/cgroups v2, rustls TLS loopback, mock shims & `--deep` fuzz prover
│   ├── sh-report/                 # SARIF 2.1.0 & self-contained Carbon-Slate HTML/SVG graph exporter
│   ├── sh-tui/                    # Panic-safe 60fps ratatui 3-pane workspace + ring-buffer log drawer
│   └── sh-ai/                     # Opt-in minimal-context (<= 2 KB) HTTP/TLS patcher & safe diff applier
└── fixtures/
    ├── vuln-payment-node/         # Runnable multi-file Node/TS double-spend race, SQLi & auth fixture
    └── vuln-auth-rust/            # Multi-file Rust Axum unauthenticated role-mutation fixture
```

Further engineering documentation:
- [**`BLUEPRINT.md`**](BLUEPRINT.md) — Master System Architecture, Lattice Mathematics & Sandbox Isolation Spec
- [**`PLANNING.md`**](PLANNING.md) — Module Specifications, Crate Stack & Engineering Risk Matrix
- [**`ROADMAP.md`**](ROADMAP.md) — Phase-by-Phase Engineering Milestones & Verification Gates
- [**`SECURITY.md`**](SECURITY.md) — Sandbox Isolation Model & Vulnerability Disclosure Policy
- [**`CONTRIBUTING.md`**](CONTRIBUTING.md) — Architecture Invariants & Developer Contribution Guide
- [**`CHANGELOG.md`**](CHANGELOG.md) — Release History

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
