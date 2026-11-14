use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use vf_graph::LatticeFinding;
use vf_sandbox::{VerificationStatus, VerifiedFinding};

const MAX_PROMPT_BYTES: usize = 2048;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum AiProvider {
    #[default]
    Disabled,
    Ollama {
        endpoint: String,
        model: String,
    },
    OpenAiCompatible {
        endpoint: String,
        model: String,
        api_key_env: String,
    },
}

/// Extracts ONLY ±6/+10 lines around each hop in a witness path, strictly contained
/// within `project_root` (blocking symlinks escaping root) and capped at <= 2048 bytes.
pub fn build_minimal_patch_prompt(
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
) -> Result<String> {
    let canon_root = fs::canonicalize(project_root)?;
    let status_label = match verified.map(|v| &v.status) {
        Some(VerificationStatus::Proven) => "PROVEN",
        Some(VerificationStatus::Mitigated) => "MITIGATED",
        _ => "SUSPECT",
    };

    let mut prompt = String::new();
    prompt.push_str(&format!(
        "Fix this {} multi-file finding with a minimal unified diff.\nRule: {} ({})\nTitle: {}\nEntry: {}\n",
        status_label, finding.id, finding.rule_id, finding.title, finding.entry_route
    ));

    if let Some(v) = verified {
        prompt.push_str(&format!("Sandbox Evidence: {}\n", v.evidence));
    }

    prompt.push_str("\nRelevant Witness Hops:\n");
    for (idx, hop) in finding.witness_path.iter().enumerate() {
        let joined = canon_root.join(&hop.file);
        let snippet = match fs::canonicalize(&joined) {
            Ok(canon_file) if canon_file.starts_with(&canon_root) => {
                if let Ok(raw) = fs::read_to_string(&canon_file) {
                    let lines: Vec<&str> = raw.lines().collect();
                    let start = hop.line.saturating_sub(4).max(1);
                    let end = (hop.line + 6).min(lines.len());
                    (start..=end)
                        .map(|ln| {
                            format!("{:>4} | {}", ln, lines.get(ln - 1).copied().unwrap_or(""))
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    "<file unreadable>".to_string()
                }
            }
            Ok(_) => "<blocked: path escapes project root>".to_string(),
            Err(_) => "<file missing>".to_string(),
        };

        let block = format!(
            "\n--- Hop [{}] {}:{} ({}) ---\n{}\n",
            idx + 1,
            hop.file,
            hop.line,
            hop.symbol,
            snippet
        );
        if prompt.len() + block.len() > MAX_PROMPT_BYTES {
            let remaining = MAX_PROMPT_BYTES.saturating_sub(prompt.len() + 32);
            if remaining > 0 {
                let mut end = remaining.min(block.len());
                while !block.is_char_boundary(end) && end > 0 {
                    end -= 1;
                }
                prompt.push_str(&block[..end]);
            }
            prompt.push_str("\n...[truncated to 2KB budget]\n");
            break;
        }
        prompt.push_str(&block);
    }

    Ok(prompt)
}

pub fn generate_patch_plan(
    provider: &AiProvider,
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
) -> Result<Option<String>> {
    match provider {
        AiProvider::Disabled => Ok(None),
        AiProvider::Ollama { endpoint, model } => {
            let prompt = build_minimal_patch_prompt(project_root, finding, verified)?;
            Ok(Some(format!(
                "[AI-READY: Ollama {} @ {}]\nPrompt Size: {} bytes\n\n{}",
                model,
                endpoint,
                prompt.len(),
                prompt
            )))
        }
        AiProvider::OpenAiCompatible {
            endpoint,
            model,
            api_key_env,
        } => {
            let prompt = build_minimal_patch_prompt(project_root, finding, verified)?;
            Ok(Some(format!(
                "[AI-READY: {} @ {} (env: {})]\nPrompt Size: {} bytes\n\n{}",
                model,
                endpoint,
                api_key_env,
                prompt.len(),
                prompt
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vf_graph::{GuardKind, SinkKind, TraceHop};

    #[test]
    fn test_disabled_by_default_and_minimal_prompt_budget() {
        let finding = LatticeFinding {
            id: "VF-RACE-002".into(),
            rule_id: "VF-RACE-001".into(),
            severity: "CRITICAL".into(),
            title: "Missing tx lock".into(),
            file: "src/routes/checkout.ts".into(),
            line: 8,
            status: "PROVEN".into(),
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: vec![TraceHop {
                file: "src/routes/checkout.ts".into(),
                symbol: "POST /api/v1/checkout/withdraw".into(),
                line: 8,
            }],
            remediation: String::new(),
        };

        let disabled =
            generate_patch_plan(&AiProvider::Disabled, Path::new("."), &finding, None).unwrap();
        assert!(disabled.is_none());

        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("vuln-payment-node");
        let prompt = build_minimal_patch_prompt(&fixture_root, &finding, None).unwrap();
        assert!(prompt.len() <= MAX_PROMPT_BYTES);
        assert!(prompt.contains("VF-RACE-002"));
    }
}
