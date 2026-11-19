use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::{Regex, RegexSet};
use smg_core::Language;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
struct PackRuleSpec {
    rule_id: &'static str,
    severity: &'static str,
    title: &'static str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    confidence: Confidence,
    remediation: &'static str,
    /// If non-empty, skip when language does not match any listed variant.
    langs: &'static [Language],
    /// Case-insensitive substring exemptions checked on the single line.
    line_exempt_any: &'static [&'static str],
    /// Case-insensitive file-context substrings required (if non-empty, at least one must match path or filename).
    path_require_any: &'static [&'static str],
    /// Symbol tag emitted in finding.
    symbol: &'static str,
}

const PY_ONLY: &[Language] = &[Language::Python];
const GO_ONLY: &[Language] = &[Language::Go];
const JAVA_KOTLIN: &[Language] = &[Language::Java, Language::Kotlin];
const CSHARP_ONLY: &[Language] = &[Language::CSharp];
const RUBY_ONLY: &[Language] = &[Language::Ruby];
const PHP_ONLY: &[Language] = &[Language::Php];
const RUST_ONLY: &[Language] = &[Language::Rust];
const JS_TS: &[Language] = &[Language::JavaScript, Language::TypeScript];
const CONFIG_ONLY: &[Language] = &[Language::Config];
const CONFIG_OR_BASH: &[Language] = &[Language::Config, Language::Bash];
const CODE_ALL: &[Language] = &[
    Language::TypeScript,
    Language::JavaScript,
    Language::Python,
    Language::Go,
    Language::Java,
    Language::Kotlin,
    Language::CSharp,
    Language::Ruby,
    Language::Php,
    Language::Rust,
    Language::Swift,
];

fn compiled_pack() -> &'static (RegexSet, Vec<(PackRuleSpec, Regex)>) {
    static PACK: OnceLock<(RegexSet, Vec<(PackRuleSpec, Regex)>)> = OnceLock::new();
    PACK.get_or_init(|| {
        let defs: &[(&str, PackRuleSpec)] = &[
            // 1. Python Unsafe YAML / Marshal / Jsonpickle Deserialization
            (
                r"\byaml\.load\s*\(",
                PackRuleSpec {
                    rule_id: "SMG-CMDI-DESER",
                    severity: "CRITICAL",
                    title: "Python `yaml.load()` without `SafeLoader`/`CSafeLoader` allows arbitrary code execution",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Use `yaml.safe_load(...)` or `Loader=yaml.SafeLoader`.",
                    langs: PY_ONLY,
                    line_exempt_any: &["safeloader", "csafeloader", "baseloader"],
                    path_require_any: &[],
                    symbol: "yaml.load",
                },
            ),
            (
                r"\b(?:marshal\.loads?|jsonpickle\.decode|shelve\.open)\s*\(",
                PackRuleSpec {
                    rule_id: "SMG-CMDI-DESER",
                    severity: "CRITICAL",
                    title: "Python unsafe binary/object deserialization sink (`marshal`/`jsonpickle`/`shelve`)",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Replace binary/pickle-style decoders with JSON/schema-validated serialization.",
                    langs: PY_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "unsafe_deser",
                },
            ),
            // 2. Python / JVM / .NET / Go Weak Symmetric Cipher / Legacy TLS
            (
                r#"(?i)(?:\bCrypto\.Cipher\.(?:DES|DES3|ARC2|ARC4|Blowfish)\b|\brc4\.NewCipher\s*\(|\bdes\.New(?:Triple)?DESCipher\s*\(|\bCipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|Blowfish)(?:/|"))"#,
                PackRuleSpec {
                    rule_id: "SMG-CRYPTO-001",
                    severity: "HIGH",
                    title: "Broken legacy cipher (`DES`/`3DES`/`RC4`/`Blowfish`) used instead of AEAD",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Migrate to `AES-256-GCM` or `ChaCha20-Poly1305`.",
                    langs: CODE_ALL,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "weak_cipher",
                },
            ),
            (
                r#"(?i)(?:tls\.VersionTLS1[01]\b|VersionSSL30\b|ssl\.PROTOCOL_(?:SSLv2|SSLv3|TLSv1(?:_1)?)\b|SslProtocols\.(?:Tls\b|Tls11\b|Ssl3\b)|SSLContext\.getInstance\s*\(\s*"(?:SSL|SSLv3|TLSv1(?:\.1)?)"\))"#,
                PackRuleSpec {
                    rule_id: "SMG-CFG-TLS",
                    severity: "HIGH",
                    title: "Deprecated insecure TLS/SSL protocol version (`TLSv1.0`/`TLSv1.1`/`SSLv3`)",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Enforce minimum TLS 1.2 (`tls.VersionTLS12`) or TLS 1.3 (`tls.VersionTLS13`).",
                    langs: CODE_ALL,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "weak_tls_version",
                },
            ),
            (
                r#"(?i)(?:modulusLength\s*:\s*(?:512|1024)\b|\brsa\.GenerateKey\s*\([^,]+,\s*(?:512|1024)\s*\)|\.initialize\s*\(\s*(?:512|1024)\s*\))"#,
                PackRuleSpec {
                    rule_id: "SMG-CRYPTO-001",
                    severity: "HIGH",
                    title: "Weak RSA modulus length (< 2048 bits) vulnerable to factorization",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Use >= 2048-bit RSA keys (prefer >= 3072-bit) or ECDSA P-256/Ed25519.",
                    langs: CODE_ALL,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "weak_rsa_size",
                },
            ),
            (
                r"\bdanger_accept_invalid_hostnames\s*\(\s*true\s*\)",
                PackRuleSpec {
                    rule_id: "SMG-CFG-TLS",
                    severity: "HIGH",
                    title: "TLS hostname verification explicitly disabled (`danger_accept_invalid_hostnames(true)`)",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Remove `danger_accept_invalid_hostnames(true)` so TLS certificates verify server hostnames.",
                    langs: RUST_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "tls_hostname_bypass",
                },
            ),
            // 3. Java / Spring / .NET / Ruby / PHP High-Signal Sinks
            (
                r"@CrossOrigin\s*\([^)]*\*[^)]*\)",
                PackRuleSpec {
                    rule_id: "SMG-CFG-CORS",
                    severity: "HIGH",
                    title: "Spring `@CrossOrigin` configured with wildcard `*` origin",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Restrict `@CrossOrigin(origins = ...)` to explicit trusted origin domains.",
                    langs: JAVA_KOTLIN,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "@CrossOrigin",
                },
            ),
            (
                r"\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer)\b[^\n]*\.Deserialize\s*\(",
                PackRuleSpec {
                    rule_id: "SMG-CMDI-DESER",
                    severity: "CRITICAL",
                    title: "Unsafe .NET formatter `.Deserialize()` enables remote code execution",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Replace `BinaryFormatter` with `System.Text.Json` or `DataContractSerializer` with known types.",
                    langs: CSHARP_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "BinaryFormatter",
                },
            ),
            (
                r"\bServerCertificateValidationCallback\b[^\n]*=>\s*true\b",
                PackRuleSpec {
                    rule_id: "SMG-CFG-TLS",
                    severity: "HIGH",
                    title: ".NET `ServerCertificateValidationCallback` unconditionally trusts invalid TLS certificates",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Validate certificate chain errors (`sslPolicyErrors == SslPolicyErrors.None`) instead of returning `true`.",
                    langs: CSHARP_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "cert_callback_true",
                },
            ),
            (
                r"\b(?:Marshal\.load|YAML\.load)\s*\(",
                PackRuleSpec {
                    rule_id: "SMG-CMDI-DESER",
                    severity: "CRITICAL",
                    title: "Ruby `Marshal.load` / unsafe `YAML.load` deserialization risk",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Use `YAML.safe_load` or `JSON.parse` on untrusted payloads.",
                    langs: RUBY_ONLY,
                    line_exempt_any: &["safe_load", "permitted_classes"],
                    path_require_any: &[],
                    symbol: "ruby_deser",
                },
            ),
            (
                r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
                PackRuleSpec {
                    rule_id: "SMG-CMDI-DESER",
                    severity: "CRITICAL",
                    title: "PHP `unserialize()` called directly on superglobal request input (POP chain RCE)",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Confirmed,
                    remediation: "Decode untrusted input with `json_decode(...)` or pass `['allowed_classes' => false]`.",
                    langs: PHP_ONLY,
                    line_exempt_any: &["allowed_classes"],
                    path_require_any: &[],
                    symbol: "php_unserialize",
                },
            ),
            (
                r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
                PackRuleSpec {
                    rule_id: "SMG-CFG-PROTO",
                    severity: "HIGH",
                    title: "PHP `extract()` on superglobal request input overwrites local variables",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Access request keys explicitly via `$_POST['field']` or pass `EXTR_SKIP` without `extract`.",
                    langs: PHP_ONLY,
                    line_exempt_any: &["extr_skip"],
                    path_require_any: &[],
                    symbol: "php_extract",
                },
            ),
            // 4. Go / Browser XSS & Unescaped Output Heuristics
            (
                r"\btemplate\.(?:HTML|JS|HTMLAttr)\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*\)",
                PackRuleSpec {
                    rule_id: "SMG-XSS-001",
                    severity: "HIGH",
                    title: "Go `html/template` raw `template.HTML`/`JS` cast bypasses contextual auto-escaping",
                    sink_kind: SinkKind::Xss,
                    missing_guard: GuardKind::XssSanitizer,
                    confidence: Confidence::Heuristic,
                    remediation: "Only pass sanitized HTML (e.g. `bluemonday`) or plain escaped strings into templates.",
                    langs: GO_ONLY,
                    line_exempt_any: &["sanitize", "bluemonday"],
                    path_require_any: &[],
                    symbol: "template.HTML",
                },
            ),
            (
                r"\bdocument\.domain\s*=",
                PackRuleSpec {
                    rule_id: "SMG-FE-MSG",
                    severity: "MEDIUM",
                    title: "Mutating `document.domain` relaxes same-origin isolation boundaries",
                    sink_kind: SinkKind::FrontendContract,
                    missing_guard: GuardKind::FrontendContract,
                    confidence: Confidence::Heuristic,
                    remediation: "Use `window.postMessage` with explicit targetOrigin/origin checks instead of `document.domain`.",
                    langs: JS_TS,
                    line_exempt_any: &[],
                    path_require_any: &[],
                    symbol: "document.domain",
                },
            ),
            // 5. Kubernetes / Docker / Compose / CI-CD Deep Hardening Policies
            (
                r#"(?i)^\s*-\s*['"]?(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)['"]?\s*$"#,
                PackRuleSpec {
                    rule_id: "SMG-K8S-001",
                    severity: "CRITICAL",
                    title: "Container/Kubernetes grants dangerous Linux capability (`SYS_ADMIN`/`NET_ADMIN`/`ALL`)",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Set `capabilities.drop: [ALL]` and avoid privileged Linux capabilities.",
                    langs: CONFIG_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[".yml", ".yaml"],
                    symbol: "k8s_cap_add",
                },
            ),
            (
                r"(?i)^\s*shareProcessNamespace\s*:\s*true\b",
                PackRuleSpec {
                    rule_id: "SMG-K8S-001",
                    severity: "HIGH",
                    title: "Kubernetes Pod sets `shareProcessNamespace: true` across containers",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Disable `shareProcessNamespace` unless explicitly needed for sidecar debugging.",
                    langs: CONFIG_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[".yml", ".yaml"],
                    symbol: "shareProcessNamespace",
                },
            ),
            (
                r"(?i)/var/run/docker\.sock\b",
                PackRuleSpec {
                    rule_id: "SMG-CFG-DOCKER",
                    severity: "CRITICAL",
                    title: "Docker socket `/var/run/docker.sock` mounted into container allows host root escape",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Avoid mounting `/var/run/docker.sock` inside workloads or isolate behind rootless/read-only APIs.",
                    langs: CONFIG_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &["docker-compose", "compose.y", "dockerfile"],
                    symbol: "docker.sock",
                },
            ),
            (
                r"(?i)^\s*ADD\s+https?://",
                PackRuleSpec {
                    rule_id: "SMG-CFG-DOCKER",
                    severity: "MEDIUM",
                    title: "Dockerfile `ADD` fetches remote URL directly without cryptographic checksum verification",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Heuristic,
                    remediation: "Use `curl -fsSL` verified with `sha256sum -c` instead of remote `ADD` URLs.",
                    langs: CONFIG_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &["dockerfile"],
                    symbol: "Dockerfile ADD",
                },
            ),
            (
                r"(?i)\bACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['\x22]?true\b",
                PackRuleSpec {
                    rule_id: "SMG-CICD-002",
                    severity: "HIGH",
                    title: "GitHub Actions enables deprecated `ACTIONS_ALLOW_UNSECURE_COMMANDS` command injection vector",
                    sink_kind: SinkKind::Misconfiguration,
                    missing_guard: GuardKind::ConfigPolicy,
                    confidence: Confidence::Confirmed,
                    remediation: "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS` and write outputs safely via `$GITHUB_OUTPUT` / `$GITHUB_ENV`.",
                    langs: CONFIG_ONLY,
                    line_exempt_any: &[],
                    path_require_any: &[".github/workflows/"],
                    symbol: "ACTIONS_ALLOW_UNSECURE_COMMANDS",
                },
            ),
            (
                r"(?i)\b(?:curl|wget)\s+[^|\n]*https?://[^|\n]+\|\s*(?:sudo\s+)?(?:ba)?sh\b",
                PackRuleSpec {
                    rule_id: "SMG-CICD-001",
                    severity: "HIGH",
                    title: "CI/script pipes remote URL directly into shell (`curl | sh`) without integrity verification",
                    sink_kind: SinkKind::CommandInjection,
                    missing_guard: GuardKind::CmdSanitizer,
                    confidence: Confidence::Heuristic,
                    remediation: "Download release artifacts to disk, verify SHA-256 checksums/signatures, then execute.",
                    langs: CONFIG_OR_BASH,
                    line_exempt_any: &["sha256", "shasum"],
                    path_require_any: &[".github/workflows/", ".gitlab-ci", ".sh", "dockerfile"],
                    symbol: "curl_pipe_sh",
                },
            ),
        ];

        let patterns: Vec<&str> = defs.iter().map(|(p, _)| *p).collect();
        let set = RegexSet::new(&patterns).expect("valid rule_pack RegexSet");
        let specs = defs
            .iter()
            .map(|(p, spec)| (*spec, Regex::new(p).expect("valid rule_pack Regex")))
            .collect();
        (set, specs)
    })
}

fn path_matches_any(rel_low: &str, patterns: &[&str]) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| rel_low.contains(p))
}

fn is_comment_or_doc_line(trimmed: &str, lang: Language) -> bool {
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
    {
        return true;
    }
    if matches!(lang, Language::Rust) && (trimmed.starts_with("r\"") || trimmed.starts_with("r#\""))
    {
        return true;
    }
    crate::taint::is_pattern_matcher_or_doc_line(trimmed)
}

/// Executes compiled `RegexSet` deep multi-domain policy & sink checks in a single linear pass per file.
pub fn scan_rule_pack(rel_path: &str, lang: Language, content: &str) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) {
        return Vec::new();
    }
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if matches!(fname, "package-lock.json" | "Cargo.lock" | "rule_pack.rs") {
        return Vec::new();
    }

    let rel_low = rel_path.replace('\\', "/").to_ascii_lowercase();
    let is_rust = lang == Language::Rust;
    let mut in_cfg_test = false;
    let mut brace_depth: i32 = 0;
    let mut saw_brace = false;

    let (set, specs) = compiled_pack();
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();
    let mut in_capabilities_add = false;
    let mut cap_add_indent = 0usize;

    for (idx, &line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();

        if is_rust {
            if trimmed.starts_with("#[cfg(test)]") {
                in_cfg_test = true;
                brace_depth = 0;
                saw_brace = false;
            }
            if in_cfg_test {
                for ch in line.chars() {
                    if ch == '{' {
                        brace_depth += 1;
                        saw_brace = true;
                    } else if ch == '}' {
                        brace_depth -= 1;
                        if saw_brace && brace_depth <= 0 {
                            in_cfg_test = false;
                            break;
                        }
                    }
                }
                if !saw_brace && !trimmed.starts_with("#[") && trimmed.ends_with(';') {
                    in_cfg_test = false;
                }
                continue;
            }
        }

        if matches!(lang, Language::Config)
            && (rel_low.ends_with(".yml") || rel_low.ends_with(".yaml"))
        {
            let indent = line.len() - line.trim_start().len();
            let low = trimmed.to_ascii_lowercase();
            if in_capabilities_add
                && indent <= cap_add_indent
                && !trimmed.is_empty()
                && !trimmed.starts_with('-')
            {
                in_capabilities_add = false;
            }
            if low.starts_with("add:") && idx > 0 {
                let prev = lines[idx - 1].to_ascii_lowercase();
                if prev.contains("capabilities:")
                    || low.contains("sys_admin")
                    || low.contains("net_admin")
                {
                    in_capabilities_add = true;
                    cap_add_indent = indent;
                }
            }
        }

        if is_comment_or_doc_line(trimmed, lang) {
            continue;
        }
        if trimmed.contains("Regex::new(") || trimmed.contains("RegexSet::new(") {
            continue;
        }

        let matches = set.matches(line);
        if !matches.matched_any() {
            continue;
        }

        let line_low = trimmed.to_ascii_lowercase();
        for pat_idx in matches.iter() {
            let (spec, re) = &specs[pat_idx];
            if !spec.langs.is_empty() && !spec.langs.contains(&lang) {
                continue;
            }
            if !path_matches_any(&rel_low, spec.path_require_any) {
                continue;
            }
            if spec.symbol == "k8s_cap_add" && !in_capabilities_add {
                continue;
            }
            if spec.line_exempt_any.iter().any(|ex| line_low.contains(ex)) {
                continue;
            }
            if re.is_match(line) {
                findings.push(LocalStaticFinding {
                    rule_id: spec.rule_id.to_string(),
                    severity: spec.severity.to_string(),
                    title: spec.title.to_string(),
                    rel_path: rel_path.to_string(),
                    line: ln,
                    symbol: spec.symbol.to_string(),
                    sink_kind: spec.sink_kind,
                    missing_guard: spec.missing_guard,
                    confidence: spec.confidence,
                    remediation: spec.remediation.to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_pack_precision_and_self_scan() {
        let self_src = include_str!("rule_pack.rs");
        assert!(
            scan_rule_pack(
                "crates/smg-graph/src/rule_pack.rs",
                Language::Rust,
                self_src
            )
            .is_empty(),
            "rule_pack.rs must never trigger on itself"
        );

        let py_vuln = "import yaml\ncfg = yaml.load(data, Loader=yaml.Loader)\n";
        let py_safe = "import yaml\ncfg = yaml.load(data, Loader=yaml.SafeLoader)\n";
        assert_eq!(
            scan_rule_pack("app/cfg.py", Language::Python, py_vuln).len(),
            1
        );
        assert!(scan_rule_pack("app/cfg.py", Language::Python, py_safe).is_empty());

        let k8s_vuln = "capabilities:\n  add:\n    - SYS_ADMIN\n";
        let k8s_drop = "capabilities:\n  drop:\n    - ALL\n";
        assert_eq!(
            scan_rule_pack("k8s/pod.yaml", Language::Config, k8s_vuln).len(),
            1
        );
        assert!(
            scan_rule_pack("k8s/pod_safe.yaml", Language::Config, k8s_drop).is_empty(),
            "capabilities.drop: [ALL] must NOT trigger cap_add rule"
        );

        let go_tls_vuln = "cfg := &tls.Config{MinVersion: tls.VersionTLS10}\n";
        let go_tls_safe = "cfg := &tls.Config{MinVersion: tls.VersionTLS13}\n";
        let go_hits = scan_rule_pack("pkg/tls.go", Language::Go, go_tls_vuln);
        assert_eq!(go_hits.len(), 1);
        assert_eq!(go_hits[0].rule_id, "SMG-CFG-TLS");
        assert_eq!(go_hits[0].confidence, Confidence::Confirmed);
        assert!(scan_rule_pack("pkg/tls_safe.go", Language::Go, go_tls_safe).is_empty());
    }
}
