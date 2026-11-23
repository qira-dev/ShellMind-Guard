mod ai_supply_chain;
mod cloud_iac;
mod crypto_legacy;
mod web_frameworks;

use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::{Regex, RegexSet};
use smg_core::Language;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub(crate) struct PackRuleSpec {
    pub rule_id: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    pub confidence: Confidence,
    pub remediation: &'static str,
    /// If non-empty, skip when language does not match any listed variant.
    pub langs: &'static [Language],
    /// Case-insensitive substring exemptions checked on the single line.
    pub line_exempt_any: &'static [&'static str],
    /// Case-insensitive substring exemptions checked across the entire file.
    pub file_exempt_any: &'static [&'static str],
    /// Case-insensitive file-context substrings required (if non-empty, at least one must match path).
    pub path_require_any: &'static [&'static str],
    /// Symbol tag emitted in finding.
    pub symbol: &'static str,
}

pub(crate) const PY_ONLY: &[Language] = &[Language::Python];
pub(crate) const GO_ONLY: &[Language] = &[Language::Go];
pub(crate) const JAVA_KOTLIN: &[Language] = &[Language::Java, Language::Kotlin];
pub(crate) const CSHARP_ONLY: &[Language] = &[Language::CSharp];
pub(crate) const RUBY_ONLY: &[Language] = &[Language::Ruby];
pub(crate) const PHP_ONLY: &[Language] = &[Language::Php];
pub(crate) const RUST_ONLY: &[Language] = &[Language::Rust];
pub(crate) const JS_TS: &[Language] = &[Language::JavaScript, Language::TypeScript];
pub(crate) const CONFIG_ONLY: &[Language] = &[Language::Config];
pub(crate) const CONFIG_OR_BASH: &[Language] = &[Language::Config, Language::Bash];
pub(crate) const TF_ONLY: &[Language] = &[Language::Hcl];
pub(crate) const CODE_ALL: &[Language] = &[
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
        let mut all_defs: Vec<(&'static str, PackRuleSpec)> = Vec::new();
        all_defs.extend_from_slice(web_frameworks::RULES);
        all_defs.extend_from_slice(cloud_iac::RULES);
        all_defs.extend_from_slice(ai_supply_chain::RULES);
        all_defs.extend_from_slice(crypto_legacy::RULES);

        let patterns: Vec<&str> = all_defs.iter().map(|(p, _)| *p).collect();
        let set = RegexSet::new(&patterns).expect("valid modular rule_pack RegexSet");
        let specs = all_defs
            .iter()
            .map(|(p, spec)| (*spec, Regex::new(p).expect("valid rule_pack Regex")))
            .collect();
        (set, specs)
    })
}

/// Returns total number of compiled multi-domain `RegexSet` rules in `rule_pack`.
pub fn pack_rule_count() -> usize {
    compiled_pack().1.len()
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
    if matches!(lang, Language::Rust)
        && (trimmed.starts_with("r\"")
            || trimmed.starts_with("r#\"")
            || trimmed.starts_with("title:")
            || trimmed.starts_with("description:")
            || trimmed.starts_with("vulnerable_example:")
            || trimmed.starts_with("fixed_example:")
            || trimmed.starts_with("remediation:")
            || trimmed.starts_with("rule_id:"))
    {
        return true;
    }
    crate::taint::is_pattern_matcher_or_doc_line(trimmed)
}

/// Executes unified `OnceLock<RegexSet>` multi-domain checks across web frameworks, cloud/IaC, AI supply chain, and crypto/TLS in one linear pass.
pub fn scan_rule_pack(rel_path: &str, lang: Language, content: &str) -> Vec<LocalStaticFinding> {
    if smg_core::is_test_source_path(rel_path) {
        return Vec::new();
    }
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if matches!(
        fname,
        "package-lock.json" | "Cargo.lock" | "go.sum" | "yarn.lock" | "pnpm-lock.yaml" | "bun.lock"
    ) {
        return Vec::new();
    }
    let rel_low = rel_path.replace('\\', "/").to_ascii_lowercase();
    if rel_low.contains("crates/smg-graph/src/rule_pack/") {
        return Vec::new();
    }

    let is_rust = lang == Language::Rust;
    let mut in_cfg_test = false;
    let mut brace_depth: i32 = 0;
    let mut saw_brace = false;

    let (set, specs) = compiled_pack();
    let lines: Vec<&str> = content.lines().collect();
    let mut full_low_cache: Option<String> = None;
    let mut findings = Vec::new();
    let mut in_capabilities_add = false;
    let mut cap_add_indent = 0usize;

    for (idx, &line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();

        if is_rust {
            if !in_cfg_test && trimmed.starts_with("#[cfg(test)]") {
                in_cfg_test = true;
                brace_depth = 0;
                saw_brace = false;
            }
            if in_cfg_test {
                let bytes = line.as_bytes();
                let mut bi = 0usize;
                let mut in_str = false;
                let mut esc = false;
                let mut saw_semi_outside = false;
                while bi < bytes.len() {
                    let b = bytes[bi];
                    if esc {
                        esc = false;
                        bi += 1;
                        continue;
                    }
                    if b == b'\\' && in_str {
                        esc = true;
                        bi += 1;
                        continue;
                    }
                    if b == b'"' {
                        in_str = !in_str;
                        bi += 1;
                        continue;
                    }
                    if !in_str {
                        if b == b'/' && bytes.get(bi + 1) == Some(&b'/') {
                            break;
                        }
                        if b == b'{' {
                            brace_depth += 1;
                            saw_brace = true;
                        } else if b == b'}' {
                            brace_depth -= 1;
                            if saw_brace && brace_depth <= 0 {
                                in_cfg_test = false;
                                break;
                            }
                        } else if b == b';' {
                            saw_semi_outside = true;
                        }
                    }
                    bi += 1;
                }
                if in_cfg_test && !saw_brace && !trimmed.starts_with("#[") && saw_semi_outside {
                    in_cfg_test = false;
                }
                continue;
            }
        }

        let effective_line = if matches!(lang, Language::Config)
            && (rel_low.ends_with(".yml") || rel_low.ends_with(".yaml"))
        {
            smg_core::yaml::strip_yaml_comment_quoted(line)
        } else {
            line
        };
        let eff_trimmed = effective_line.trim();

        if matches!(lang, Language::Config)
            && (rel_low.ends_with(".yml") || rel_low.ends_with(".yaml"))
        {
            let indent = effective_line.len() - effective_line.trim_start().len();
            let low = eff_trimmed.to_ascii_lowercase();
            if in_capabilities_add
                && indent <= cap_add_indent
                && !eff_trimmed.is_empty()
                && !eff_trimmed.starts_with('-')
            {
                in_capabilities_add = false;
            }
            if low.starts_with("cap_add:") {
                in_capabilities_add = true;
                cap_add_indent = indent;
            } else if low.starts_with("add:") && idx > 0 {
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

        if is_comment_or_doc_line(eff_trimmed, lang) {
            continue;
        }
        if eff_trimmed.contains("Regex::new(") || eff_trimmed.contains("RegexSet::new(") {
            continue;
        }

        let matches = set.matches(effective_line);
        if !matches.matched_any() {
            continue;
        }

        let line_low = eff_trimmed.to_ascii_lowercase();
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
            if !spec.file_exempt_any.is_empty() {
                let fl = full_low_cache.get_or_insert_with(|| content.to_ascii_lowercase());
                if spec.file_exempt_any.iter().any(|ex| fl.contains(ex)) {
                    continue;
                }
            }
            if re.is_match(effective_line) {
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
        assert!(
            pack_rule_count() >= 70,
            "expected deep multi-domain pack >= 70 rules, got {}",
            pack_rule_count()
        );
        for (p, s) in [
            ("virtual_rule_pack_mod.rs", include_str!("mod.rs")),
            ("virtual_web_fw.rs", include_str!("web_frameworks.rs")),
            ("virtual_cloud_iac.rs", include_str!("cloud_iac.rs")),
            ("virtual_ai_sc.rs", include_str!("ai_supply_chain.rs")),
            ("virtual_crypto.rs", include_str!("crypto_legacy.rs")),
        ] {
            assert!(
                scan_rule_pack(p, Language::Rust, s).is_empty(),
                "{} triggered on itself: {:?}",
                p,
                scan_rule_pack(p, Language::Rust, s)
            );
        }

        // PyTorch & HuggingFace ML supply chain vs safe
        assert_eq!(
            scan_rule_pack("ml/load.py", Language::Python, "m = torch.load('w.pt')\n").len(),
            1
        );
        assert!(
            scan_rule_pack(
                "ml/safe.py",
                Language::Python,
                "m = torch.load('w.pt', weights_only=True)\n"
            )
            .is_empty()
        );
        assert_eq!(
            scan_rule_pack(
                "ml/hf.py",
                Language::Python,
                "AutoModel.from_pretrained('x/y', trust_remote_code=True)\n"
            )
            .len(),
            1
        );

        // Next.js / Electron
        assert_eq!(
            scan_rule_pack(
                "electron/main.ts",
                Language::TypeScript,
                "webPreferences: { nodeIntegration: true, webSecurity: false }\n"
            )
            .len(),
            2
        );
        assert_eq!(
            scan_rule_pack(
                "next.config.ts",
                Language::TypeScript,
                "images: { dangerouslyAllowSVG: true }\n"
            )
            .len(),
            1
        );

        // Terraform IMDSv1 + GKE ABAC + K8s/Compose cap_add vs drop
        assert_eq!(
            scan_rule_pack(
                "infra/ec2.tf",
                Language::Hcl,
                "metadata_options { http_tokens = \"optional\" }\n"
            )
            .len(),
            1
        );
        assert_eq!(
            scan_rule_pack(
                "docker-compose.yml",
                Language::Config,
                "services:\n  app:\n    network_mode: host\n    cap_add:\n      - SYS_ADMIN\n"
            )
            .len(),
            2
        );
        assert!(
            scan_rule_pack(
                "k8s/pod_safe.yaml",
                Language::Config,
                "capabilities:\n  drop:\n    - ALL\n"
            )
            .is_empty(),
            "capabilities.drop: [ALL] must NOT trigger cap_add rule"
        );

        // Weak C# / Python YAML / Go TLS
        assert_eq!(
            scan_rule_pack(
                "Services/Json.cs",
                Language::CSharp,
                "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"
            )
            .len(),
            1
        );
        assert_eq!(
            scan_rule_pack("pkg/tls.go", Language::Go, "MinVersion: tls.VersionTLS10\n").len(),
            1
        );
        assert!(
            scan_rule_pack(
                "pkg/tls_safe.go",
                Language::Go,
                "MinVersion: tls.VersionTLS13\n"
            )
            .is_empty()
        );
    }
}
