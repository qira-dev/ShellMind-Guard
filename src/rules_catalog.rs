use clap::{Command, ValueEnum};
use serde::Serialize;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuleDoc {
    pub rule_id: &'static str,
    pub layer: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub vulnerable_example: &'static str,
    pub fixed_example: &'static str,
    pub remediation: &'static str,
}

pub(crate) const RULE_CATALOG: &[RuleDoc] = &[
    RuleDoc {
        rule_id: "SMG-AUTH-001",
        layer: "auth",
        severity: "HIGH",
        title: "Missing authentication middleware on privileged state mutation",
        description: "HTTP route handler reaches a payment, balance, role, or DB mutation sink without an authentication guard on the router mount or call chain.",
        vulnerable_example: "app.post('/api/v1/checkout/withdraw', (req, res) => debitBalance(req.body));",
        fixed_example: "app.post('/api/v1/checkout/withdraw', requireAuth, (req, res) => debitBalance(req.user.id, req.body));",
        remediation: "Attach authentication middleware (`requireAuth`, `verifyJwt`, `UseGuards`, `protectedProcedure`, `@login_required`) before reaching state mutations.",
    },
    RuleDoc {
        rule_id: "SMG-RACE-001",
        layer: "race",
        severity: "CRITICAL",
        title: "Missing ACID transaction / row lock / idempotency guard (Double-Spend Risk)",
        description: "Financial or balance mutation can execute concurrently without an exclusive transaction boundary (`SELECT ... FOR UPDATE`, `$transaction`, `withTransaction`) or atomic idempotency key.",
        vulnerable_example: "const acct = await db.get(id); if (acct.balance >= amt) await db.updateBalance(id, -amt);",
        fixed_example: "await db.transaction(async (tx) => { await tx.query('SELECT balance FROM accounts WHERE id=$1 FOR UPDATE', [id]); /* debit */ });",
        remediation: "Wrap balance and payment mutations in a serializable/locking database transaction (`FOR UPDATE`) or atomic conditional update + idempotency key.",
    },
    RuleDoc {
        rule_id: "SMG-IDOR-001",
        layer: "idor",
        severity: "HIGH",
        title: "Authenticated DB lookup/mutation lacks actor ownership predicate",
        description: "Route takes a caller-supplied identifier (`:id`, `{id}`, `[id]`) and accesses DB records without scoping the query by caller identity (`user_id`, `owner_id`, `tenant_id`).",
        vulnerable_example: "app.get('/orders/:id', requireAuth, (req, res) => Order.findById(req.params.id));",
        fixed_example: "app.get('/orders/:id', requireAuth, (req, res) => Order.findOne({ _id: req.params.id, userId: req.user.id }));",
        remediation: "Scope database reads and updates using the server-verified caller identity (`req.user.id` / `current_user.id`) rather than request parameters alone.",
    },
    RuleDoc {
        rule_id: "SMG-SQLI-001",
        layer: "sqli",
        severity: "CRITICAL",
        title: "Dynamic SQL string construction reachable from untrusted input",
        description: "Tainted HTTP/CLI input flows into string concatenation, template interpolation, or raw SQL execution (`query`, `raw`, `whereRaw`, `EXECUTE format`).",
        vulnerable_example: "db.query(`SELECT * FROM users WHERE name = '${req.query.q}'`);",
        fixed_example: "db.query('SELECT * FROM users WHERE name = $1', [req.query.q]);",
        remediation: "Use parameterized prepared queries (`$1`, `?`) or safe ORM query builders.",
    },
    RuleDoc {
        rule_id: "SMG-SQLI-NOSQL",
        layer: "sqli",
        severity: "CRITICAL",
        title: "NoSQL operator injection or Redis Lua eval with untrusted payload",
        description: "Unvalidated request object (`req.body`/`req.query`) flows directly into MongoDB `.find`/`.findOne` (`$ne`/`$gt`/`$where`) or Redis Lua `eval`.",
        vulnerable_example: "User.findOne(req.body);",
        fixed_example: "User.findOne({ email: String(parsed.email) });",
        remediation: "Validate inputs with Zod/Joi/Pydantic and coerce fields explicitly to primitives or `$eq`.",
    },
    RuleDoc {
        rule_id: "SMG-SQLI-MASS",
        layer: "sqli",
        severity: "HIGH",
        title: "ORM Mass Assignment from raw request payload",
        description: "Raw request body flows directly into `.create(...)` / `.update(...)` without schema field allowlisting, allowing privilege fields like `role` or `isAdmin` to be overwritten.",
        vulnerable_example: "await User.create(req.body);",
        fixed_example: "const { name, email } = UserCreateSchema.parse(req.body); await User.create({ name, email });",
        remediation: "Explicitly allowlist permitted fields or validate through a strict schema before persistence.",
    },
    RuleDoc {
        rule_id: "SMG-CMDI-001",
        layer: "cmdi",
        severity: "CRITICAL",
        title: "OS Command Injection via shell interpolation",
        description: "Untrusted input flows into `exec`, `os.system`, `subprocess.run(..., shell=True)`, or `bash -c` array execution.",
        vulnerable_example: "execSync(`git log -n ${req.query.n}`);",
        fixed_example: "execFileSync('git', ['log', '-n', String(Number.parseInt(req.query.n, 10))]);",
        remediation: "Use argument-array process APIs (`execFile`, `Command::new`, `shell=False`) and strictly validate arguments.",
    },
    RuleDoc {
        rule_id: "SMG-CMDI-SSTI",
        layer: "cmdi",
        severity: "CRITICAL",
        title: "Server-Side Template Injection (SSTI)",
        description: "Untrusted string is compiled/rendered directly as template source (`render_template_string`, `ejs.render`, `pug.render`).",
        vulnerable_example: "return render_template_string(request.args['tpl'])",
        fixed_example: "return render_template('profile.html', name=request.args['name'])",
        remediation: "Always render static template files on disk and pass user data strictly as template context variables.",
    },
    RuleDoc {
        rule_id: "SMG-CMDI-DESER",
        layer: "cmdi",
        severity: "CRITICAL",
        title: "Insecure Deserialization (`pickle.loads` / `yaml.load` / `ObjectInputStream`)",
        description: "Untrusted payload is passed to a code-executing serializer such as Python `pickle`, PyYAML `yaml.load` without `SafeLoader`, PHP `unserialize`, or Java `ObjectInputStream`.",
        vulnerable_example: "data = yaml.load(req.data)",
        fixed_example: "data = yaml.safe_load(req.data)",
        remediation: "Switch to JSON or safe loaders (`yaml.safe_load`) and avoid deserializing untrusted binary object graphs.",
    },
    RuleDoc {
        rule_id: "SMG-PATH-001",
        layer: "path",
        severity: "HIGH",
        title: "Path Traversal to arbitrary filesystem read/write",
        description: "Tainted path segment reaches `fs.readFile`, `sendFile`, `os.Open`, or `open()` without `basename` or canonical prefix containment.",
        vulnerable_example: "res.sendFile(path.join('/srv/uploads', req.query.file));",
        fixed_example: "const safe = path.resolve(BASE, path.basename(String(req.query.file))); if (!safe.startsWith(BASE + path.sep)) return res.status(403).end();",
        remediation: "Canonicalize (`realpath`/`path.resolve`) and enforce a base-directory prefix check or `path.basename`.",
    },
    RuleDoc {
        rule_id: "SMG-SSRF-001",
        layer: "ssrf",
        severity: "HIGH",
        title: "Server-Side Request Forgery (SSRF) on server-side HTTP client",
        description: "Untrusted URL or host reaches `fetch`, `axios`, `requests.get`, `http.Get`, or `reqwest::get` without hostname allowlisting or private-IP blocking.",
        vulnerable_example: "const r = await fetch(req.body.webhookUrl);",
        fixed_example: "if (!ALLOWED_HOSTS.has(new URL(url).hostname)) throw new Error('blocked');",
        remediation: "Enforce HTTPS scheme, explicit hostname allowlist, and block loopback/link-local/RFC1918 targets.",
    },
    RuleDoc {
        rule_id: "SMG-SSRF-REDIRECT",
        layer: "ssrf",
        severity: "MEDIUM",
        title: "Open Redirect via user-controlled destination URL",
        description: "Untrusted parameter flows into `res.redirect` / `window.location.href` without relative-path or allowlist enforcement.",
        vulnerable_example: "res.redirect(req.query.next);",
        fixed_example: "const next = String(req.query.next); res.redirect(next.startsWith('/') && !next.startsWith('//') ? next : '/');",
        remediation: "Allow only verified relative paths (`/dashboard`) or host-allowlisted destinations.",
    },
    RuleDoc {
        rule_id: "SMG-XSS-001",
        layer: "xss",
        severity: "HIGH",
        title: "Cross-Site Scripting (XSS) via unsanitized HTML/DOM sink",
        description: "Untrusted input flows into `dangerouslySetInnerHTML`, `innerHTML`, unescaped template output, or HTML HTTP responses without an HTML sanitizer.",
        vulnerable_example: "<div dangerouslySetInnerHTML={{ __html: req.query.bio }} />",
        fixed_example: "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />",
        remediation: "Escape output contextually or sanitize HTML strictly (`DOMPurify`, `bluemonday`, `bleach.clean`, `ammonia`).",
    },
    RuleDoc {
        rule_id: "SMG-CSRF-001",
        layer: "csrf",
        severity: "HIGH",
        title: "State-changing cookie/session endpoint missing CSRF protection",
        description: "Cookie-authenticated POST/PUT/DELETE route (or `@csrf_exempt` view) lacks CSRF token verification or `SameSite=Strict`/`Lax` protection.",
        vulnerable_example: "app.use(cookieSession(...)); app.post('/transfer', transferHandler);",
        fixed_example: "app.use(csrfProtection); app.post('/transfer', transferHandler);",
        remediation: "Require anti-CSRF tokens (`csurf`/`csrfProtect`), set `SameSite=Lax`/`Strict` on session cookies, or use `Authorization: Bearer` tokens.",
    },
    RuleDoc {
        rule_id: "SMG-SEC-ENTROPY",
        layer: "secrets",
        severity: "HIGH",
        title: "Exposed credential, high-entropy secret, PEM key, or `.env` leak",
        description: "Hardcoded provider API key (`AWS`/`Stripe`/`GitHub`/`OpenAI`/`Anthropic`), high-entropy secret literal, DB password URI, client env exposure, or unignored `.env` file.",
        vulnerable_example: "const STRIPE_KEY = 'sk_live_...';",
        fixed_example: "const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;",
        remediation: "Move secrets into runtime secret managers/server env vars, add `.env*` to `.gitignore`, and rotate any exposed credentials.",
    },
    RuleDoc {
        rule_id: "SMG-CFG-JWT-LOGIC",
        layer: "config",
        severity: "HIGH",
        title: "Unverified JWT signature (`jwt.decode` / `alg: none` / `verify_signature: False`)",
        description: "JWT claims are decoded without signature verification (`jwt.decode()` without local `jwt.verify()`, `verify_signature: False`, or `alg: none`).",
        vulnerable_example: "const payload = jwt.decode(req.headers.authorization);",
        fixed_example: "const payload = jwt.verify(token, pubKey, { algorithms: ['RS256'] });",
        remediation: "Always verify JWT signatures with an explicit strong algorithm allowlist before trusting claims.",
    },
    RuleDoc {
        rule_id: "SMG-CFG-IAC-PUBLIC",
        layer: "config",
        severity: "HIGH",
        title: "Terraform / Dockerfile / SQL policy misconfiguration (`SMG-CFG-IAC-*`, `SMG-CFG-*`)",
        description: "Infrastructure or config exposes public buckets/DBs, `0.0.0.0/0` ingress, wildcard IAM `*/*`, `USER root` Dockerfile, wildcard CORS + credentials, or unsafe SQL `SECURITY DEFINER`.",
        vulnerable_example: "ingress { from_port = 22 to_port = 22 cidr_blocks = ['0.0.0.0/0'] }",
        fixed_example: "ingress { from_port = 22 to_port = 22 cidr_blocks = [var.bastion_cidr] }",
        remediation: "Enforce least-privilege CIDR/IAM rules, enable encryption & non-root containers, and lock down CORS/SQL policies.",
    },
    RuleDoc {
        rule_id: "SMG-DEP-001",
        layer: "deps",
        severity: "HIGH",
        title: "Vulnerable, unpinned, or insecure-registry dependency",
        description: "Package manifest or lockfile (`npm`, `Cargo`, `Go`, `PyPI`) resolves a version matched against offline/OSV CVE ranges, uses `*`/`latest`, or pulls over plain `http://`.",
        vulnerable_example: "\"axios\": \"*\"  // or vulnerable 0.21.x",
        fixed_example: "\"axios\": \"^1.7.7\"",
        remediation: "Upgrade to the fixed version reported in advisory details and sync advisories via `smg deps sync`.",
    },
    RuleDoc {
        rule_id: "SMG-FE-404",
        layer: "frontend",
        severity: "MEDIUM",
        title: "Frontend ↔ Backend contract drift / storage / postMessage / UI error bug",
        description: "Frontend API call targets a missing backend endpoint (`SMG-FE-404`), swallows async rejections (`SMG-FE-ERR`), writes tokens to `localStorage` (`SMG-FE-STORAGE`), skips `event.origin` (`SMG-FE-MSG`), or uses `target=_blank` without `noopener`.",
        vulnerable_example: "localStorage.setItem('authToken', data.jwt);",
        fixed_example: "// Store session tokens exclusively in HttpOnly, Secure, SameSite cookies",
        remediation: "Align frontend paths with mounted backend routes, use `HttpOnly` cookies, and validate `postMessage` origins.",
    },
    RuleDoc {
        rule_id: "SMG-ENG-DEADLOCK",
        layer: "engine",
        severity: "CRITICAL",
        title: "Concurrency deadlock (`A->B`/`B->A` lock inversion or lock across `.await`)",
        description: "Two call chains acquire mutexes in opposite canonical order (`ABBA`), a synchronous mutex guard spans `.await`/sleep, or a manual lock misses an early-return unlock (`SMG-ENG-LEAK` covers unclosed handles).",
        vulnerable_example: "let _g = mu.lock().unwrap(); async_io().await;",
        fixed_example: "{ let data = mu.lock().unwrap().clone(); } async_io().await;",
        remediation: "Acquire multiple locks in canonical order (`std::scoped_lock`) and drop sync guards before `.await`.",
    },
    RuleDoc {
        rule_id: "SMG-MEM-BOUNDS",
        layer: "memory",
        severity: "CRITICAL",
        title: "Native memory bounds / unchecked integer allocation (`SMG-ENG-INT`)",
        description: "Unbounded C/C++ buffer copy (`strcpy`, `sprintf`, unchecked `memcpy`), unchecked allocation multiplication (`malloc(n * sz)`), or unguarded Rust `unsafe` pointer/slice access.",
        vulnerable_example: "void* p = malloc(count * sizeof(Item)); memcpy(dst, src, n);",
        fixed_example: "if (count > SIZE_MAX / sizeof(Item)) return NULL; void* p = calloc(count, sizeof(Item));",
        remediation: "Use checked arithmetic (`checked_mul`), bounded copies (`snprintf`/`memcpy_s`), and safe Rust abstractions.",
    },
    RuleDoc {
        rule_id: "SMG-MOB-STORAGE",
        layer: "mobile",
        severity: "HIGH",
        title: "Mobile insecure storage, IPC exposure, or TLS trust bypass (`SMG-MOB-*`)",
        description: "Android/iOS/Flutter stores secrets in plaintext `SharedPreferences`/`UserDefaults`, exports permissionless receivers/WebView bridges (`SMG-MOB-IPC`), or bypasses TLS (`TrustManager`/`NSAllowsArbitraryLoads`, `SMG-MOB-TLS`).",
        vulnerable_example: "prefs.edit().putString(\"token\", jwt).apply();",
        fixed_example: "EncryptedSharedPreferences.create(...).edit().putString(\"token\", jwt).apply();",
        remediation: "Use `EncryptedSharedPreferences`/Keychain/`FlutterSecureStorage`, set `android:exported=\"false\"`, and enforce strict TLS.",
    },
    RuleDoc {
        rule_id: "SMG-FUZZ-SCHEMA",
        layer: "deep",
        severity: "HIGH",
        title: "Unvalidated financial/numeric route schema & live payload fuzz failure (`SMG-FUZZ-*`)",
        description: "POST/PUT/PATCH financial route parameter (`amount`, `price`, `quantity`) lacks strictly positive schema validation (`SMG-FUZZ-SCHEMA`), accepts negative tampering (`SMG-FUZZ-TAMPER`), crashes (`SMG-FUZZ-CRASH`), or chokes on NUL/invalid UTF-8 (`SMG-FUZZ-ENCODING`).",
        vulnerable_example: "app.post('/pay', (req, res) => charge(req.body.amount));",
        fixed_example: "const { amount } = z.object({ amount: z.number().finite().positive() }).parse(req.body);",
        remediation: "Validate types, finite strictly positive bounds (`> 0`), and UTF-8 / NUL constraints with HTTP 400/422 responses.",
    },
];

pub(crate) fn find_rule_doc(id: &str) -> Option<&'static RuleDoc> {
    let q = id.trim().to_ascii_uppercase();
    RULE_CATALOG.iter().find(|r| r.rule_id == q).or_else(|| {
        // Map specific sub-variants like SMG-CFG-CORS or SMG-SEC-STRIPE to representative rule docs
        RULE_CATALOG.iter().find(|r| {
            let prefix = r
                .rule_id
                .rsplit_once('-')
                .map(|(p, _)| p)
                .unwrap_or(r.rule_id);
            q.starts_with(prefix)
        })
    })
}

pub(crate) fn render_shell_completions(cmd: &Command, shell: CompletionShell) -> String {
    let subs: Vec<String> = cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set())
        .map(|s| s.get_name().to_string())
        .collect();
    let global_opts = "--color --help --version -h -V";
    match shell {
        CompletionShell::Bash => {
            let sub_list = subs.join(" ");
            let mut out = format!(
                "# Bash completion for smg / shellmind-guard\n_smg_completions() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  local sub=\"${{COMP_WORDS[1]:-}}\"\n  if [[ $COMP_CWORD -eq 1 ]]; then\n    COMPREPLY=($(compgen -W \"{sub_list} {global_opts}\" -- \"$cur\"))\n    return\n  fi\n  case \"$sub\" in\n"
            );
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let opts: Vec<String> = sc
                    .get_arguments()
                    .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                    .collect();
                out.push_str(&format!(
                    "    {}) COMPREPLY=($(compgen -W \"{} {}\" -- \"$cur\")) ;;\n",
                    sc.get_name(),
                    opts.join(" "),
                    global_opts
                ));
            }
            out.push_str("  esac\n}\ncomplete -F _smg_completions smg\ncomplete -F _smg_completions shellmind-guard\n");
            out
        }
        CompletionShell::Zsh => {
            let mut out = String::from(
                "#compdef smg shellmind-guard\n_smg() {\n  local -a subcommands\n  subcommands=(\n",
            );
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let desc = sc
                    .get_about()
                    .map(|a| a.to_string().replace('\'', " "))
                    .unwrap_or_default();
                out.push_str(&format!("    '{}:{}'\n", sc.get_name(), desc));
            }
            out.push_str("  )\n  _arguments '1:command:->cmds' '*::arg:->args'\n  case $state in\n    cmds) _describe 'command' subcommands ;;\n    args) case $line[1] in\n");
            for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                let opts: Vec<String> = sc
                    .get_arguments()
                    .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                    .collect();
                out.push_str(&format!(
                    "      {}) compadd -- {} ;;\n",
                    sc.get_name(),
                    opts.join(" ")
                ));
            }
            out.push_str("    esac ;;\n  esac\n}\ncompdef _smg smg shellmind-guard\n");
            out
        }
        CompletionShell::Fish => {
            let mut out = String::from("# Fish completions for smg / shellmind-guard\n");
            for bin in ["smg", "shellmind-guard"] {
                for sc in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
                    let desc = sc
                        .get_about()
                        .map(|a| a.to_string().replace('\'', " "))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "complete -c {bin} -f -n '__fish_use_subcommand' -a '{}' -d '{}'\n",
                        sc.get_name(),
                        desc
                    ));
                    for arg in sc.get_arguments() {
                        if let Some(long) = arg.get_long() {
                            out.push_str(&format!(
                                "complete -c {bin} -f -n '__fish_seen_subcommand_from {}' -l '{}'\n",
                                sc.get_name(),
                                long
                            ));
                        }
                    }
                }
            }
            out
        }
        CompletionShell::Powershell => {
            let sub_arr = subs
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "# PowerShell completion for smg / shellmind-guard\n@('smg', 'shellmind-guard') | ForEach-Object {{\n  Register-ArgumentCompleter -Native -CommandName $_ -ScriptBlock {{\n    param($wordToComplete, $commandAst, $cursorPosition)\n    @({sub_arr}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n  }}\n}}\n"
            )
        }
    }
}
