//! Full `.gitleaks.toml` (v8) parser & allowlist/custom-rule evaluator.
//!
//! Supports:
//! - Global `[allowlist]` and array `[[allowlists]]` (`paths`, `regexes`, `commits`, `stopwords`, `condition = "AND" | "OR"`)
//! - Custom `[[rules]]` (`id`, `description`, `regex`, `keywords`, `entropy`, `allowlists`)
//! - Inline line suppressions (`gitleaks:allow`, `smg:ignore`, `smg:allow`)

use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use crate::secrets_config::shannon_entropy;
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
struct RawGitleaksToml {
    #[serde(default)]
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize, Default)]
struct RawAllowlist {
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
    #[serde(default)]
    allowlist: Option<RawAllowlist>,
}

#[derive(Debug, Clone)]
pub struct CompiledAllowlist {
    pub require_all: bool,
    pub paths: Vec<Regex>,
    pub regexes: Vec<Regex>,
    pub commits: Vec<String>,
    pub stopwords: Vec<String>,
}

fn compile_bounded_regex(pat: &str) -> Option<Regex> {
    regex::RegexBuilder::new(pat)
        .size_limit(256 * 1024)
        .dfa_size_limit(256 * 1024)
        .build()
        .ok()
}

impl CompiledAllowlist {
    fn from_raw(raw: RawAllowlist) -> Self {
        let require_all = raw
            .condition
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case("and"));
        let paths = raw
            .paths
            .into_iter()
            .filter_map(|p| compile_bounded_regex(&p))
            .collect();
        let regexes = raw
            .regexes
            .into_iter()
            .filter_map(|r| compile_bounded_regex(&r))
            .collect();
        let commits = raw
            .commits
            .into_iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        let stopwords = raw
            .stopwords
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            require_all,
            paths,
            regexes,
            commits,
            stopwords,
        }
    }

    pub fn matches(
        &self,
        rel_path: &str,
        commit_sha: Option<&str>,
        line: &str,
        matched_token: &str,
    ) -> bool {
        let mut checks: Vec<bool> = Vec::new();
        let norm_path = rel_path.replace('\\', "/");

        if !self.paths.is_empty() {
            checks.push(self.paths.iter().any(|re| re.is_match(&norm_path)));
        }
        if !self.commits.is_empty() {
            let hit = commit_sha.is_some_and(|sha| {
                let low = sha.to_ascii_lowercase();
                self.commits
                    .iter()
                    .any(|c| low == *c || low.starts_with(c.as_str()))
            });
            checks.push(hit);
        }
        if !self.regexes.is_empty() {
            checks.push(
                self.regexes
                    .iter()
                    .any(|re| re.is_match(matched_token) || re.is_match(line)),
            );
        }
        if !self.stopwords.is_empty() {
            let low_tok = matched_token.to_ascii_lowercase();
            let low_line = line.to_ascii_lowercase();
            checks.push(
                self.stopwords
                    .iter()
                    .any(|sw| low_tok.contains(sw) || low_line.contains(sw)),
            );
        }

        if checks.is_empty() {
            return false;
        }
        if self.require_all {
            checks.into_iter().all(|b| b)
        } else {
            checks.into_iter().any(|b| b)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledCustomRule {
    pub id: String,
    pub description: String,
    pub regex: Regex,
    pub keywords: Vec<String>,
    pub min_entropy: Option<f64>,
    pub allowlists: Vec<CompiledAllowlist>,
}

#[derive(Debug, Clone, Default)]
pub struct GitleaksConfig {
    pub allowlists: Vec<CompiledAllowlist>,
    pub custom_rules: Vec<CompiledCustomRule>,
}

impl GitleaksConfig {
    /// Auto-loads `.gitleaks.toml` from `repo_root` (or an explicit override file if provided).
    pub fn load(repo_root: &Path, explicit_path: Option<&Path>) -> Option<Self> {
        let candidate = match explicit_path {
            Some(p) => p.to_path_buf(),
            None => repo_root.join(".gitleaks.toml"),
        };
        let text = fs::read_to_string(&candidate).ok()?;
        Self::parse_toml(&text).ok()
    }

    pub fn parse_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        let raw: RawGitleaksToml = toml::from_str(toml_str)?;
        let mut allowlists = Vec::new();
        if let Some(a) = raw.allowlist {
            allowlists.push(CompiledAllowlist::from_raw(a));
        }
        for a in raw.allowlists {
            allowlists.push(CompiledAllowlist::from_raw(a));
        }

        let mut custom_rules = Vec::new();
        for r in raw.rules {
            if r.id.trim().is_empty() || r.regex.trim().is_empty() {
                continue;
            }
            if let Some(re) = compile_bounded_regex(&r.regex) {
                let mut r_allow = Vec::new();
                if let Some(a) = r.allowlist {
                    r_allow.push(CompiledAllowlist::from_raw(a));
                }
                for a in r.allowlists {
                    r_allow.push(CompiledAllowlist::from_raw(a));
                }
                custom_rules.push(CompiledCustomRule {
                    id: r.id,
                    description: r.description,
                    regex: re,
                    keywords: r
                        .keywords
                        .into_iter()
                        .map(|k| k.to_ascii_lowercase())
                        .collect(),
                    min_entropy: r.entropy,
                    allowlists: r_allow,
                });
            }
        }

        Ok(Self {
            allowlists,
            custom_rules,
        })
    }

    /// Returns true if an inline comment (`gitleaks:allow`, `smg:ignore`, `smg:allow`)
    /// or any global allowlist entry suppresses this match.
    pub fn is_allowed(
        &self,
        rel_path: &str,
        commit_sha: Option<&str>,
        line: &str,
        matched_token: &str,
    ) -> bool {
        if has_inline_allow_marker(line) {
            return true;
        }
        self.allowlists
            .iter()
            .any(|a| a.matches(rel_path, commit_sha, line, matched_token))
    }

    /// Evaluates custom `[[rules]]` from `.gitleaks.toml` on a single line.
    pub fn scan_custom_rules_line(
        &self,
        rel_path: &str,
        line_no: usize,
        line: &str,
        commit_sha: Option<&str>,
    ) -> Vec<(LocalStaticFinding, String)> {
        if self.custom_rules.is_empty() || has_inline_allow_marker(line) {
            return Vec::new();
        }
        let low_line = line.to_ascii_lowercase();
        let mut hits = Vec::new();

        for rule in &self.custom_rules {
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| low_line.contains(k)) {
                continue;
            }
            for caps in rule.regex.captures_iter(line) {
                let m = caps.get(1).or_else(|| caps.get(0));
                let Some(tok_match) = m else { continue };
                let token = tok_match.as_str();
                if let Some(min_e) = rule.min_entropy
                    && shannon_entropy(token) < min_e
                {
                    continue;
                }
                if self.is_allowed(rel_path, commit_sha, line, token)
                    || rule
                        .allowlists
                        .iter()
                        .any(|a| a.matches(rel_path, commit_sha, line, token))
                {
                    continue;
                }
                let desc = if rule.description.is_empty() {
                    format!(
                        "Custom `.gitleaks.toml` rule `{}` matched credential",
                        rule.id
                    )
                } else {
                    format!("{} (custom rule `{}`)", rule.description, rule.id)
                };
                hits.push((
                    LocalStaticFinding {
                        rule_id: format!("SMG-SEC-CUSTOM-{}", sanitize_rule_suffix(&rule.id)),
                        severity: "HIGH".to_string(),
                        title: desc,
                        rel_path: rel_path.to_string(),
                        line: line_no,
                        symbol: "custom-gitleaks-rule".to_string(),
                        sink_kind: SinkKind::SecretLeak,
                        missing_guard: GuardKind::SecretPolicy,
                        confidence: Confidence::Confirmed,
                        remediation:
                            "Rotate this credential immediately, remove it from code/history, and inject it via a secret manager or environment variable."
                                .to_string(),
                    },
                    token.to_string(),
                ));
            }
        }
        hits
    }
}

pub fn has_inline_allow_marker(line: &str) -> bool {
    let low = line.to_ascii_lowercase();
    low.contains("gitleaks:allow")
        || low.contains("smg:ignore")
        || low.contains("smg:allow")
        || low.contains("nosecret")
}

fn sanitize_rule_suffix(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v8_allowlist_and_custom_rules() {
        let toml = r#"
[allowlist]
paths = ["^tests/fixtures/.*"]
commits = ["deadbeef1234"]
stopwords = ["example_dummy"]

[[allowlists]]
condition = "AND"
paths = ["^docs/.*"]
regexes = ["DEMO_TOKEN_[0-9]+"]

[[rules]]
id = "acme-token"
description = "Acme Internal API Token"
regex = 'acme_live_[0-9a-zA-Z]{20,}'
keywords = ["acme_live_"]
entropy = 3.0
"#;
        let cfg = GitleaksConfig::parse_toml(toml).expect("valid gitleaks toml");
        assert!(cfg.is_allowed("tests/fixtures/a.py", None, "k = 1", "tok"));
        assert!(cfg.is_allowed("src/app.py", Some("deadbeef1234567890"), "k = 1", "tok"));
        assert!(cfg.is_allowed(
            "src/app.py",
            None,
            "k = 'example_dummy_999'",
            "example_dummy_999"
        ));
        assert!(cfg.is_allowed(
            "docs/guide.md",
            None,
            "DEMO_TOKEN_12345",
            "DEMO_TOKEN_12345"
        ));
        assert!(!cfg.is_allowed("src/app.rs", None, "DEMO_TOKEN_12345", "DEMO_TOKEN_12345"));
        assert!(cfg.is_allowed(
            "src/app.rs",
            None,
            "let x = 'abc'; // gitleaks:allow",
            "abc"
        ));

        let hits = cfg.scan_custom_rules_line(
            "src/client.rs",
            12,
            r#"let k = "acme_live_9x8K2mPqR7vW4nZ1aB3cD5eF";"#,
            None,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.rule_id, "SMG-SEC-CUSTOM-ACME-TOKEN");
    }
}
