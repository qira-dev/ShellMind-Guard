use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use vf_graph::LatticeFinding;
use vf_sandbox::VerifiedFinding;

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

/// Extracts ONLY ±10 lines around each hop in a proven witness path (< 2 KB context)
/// so an optional LLM or coding agent never wastes tokens reading 13,000 files.
pub fn build_minimal_patch_prompt(
    project_root: &Path,
    finding: &LatticeFinding,
    verified: Option<&VerifiedFinding>,
) -> Result<String> {
    let mut prompt = String::new();
    prompt.push_str(&format!(
        "Fix this PROVEN multi-file vulnerability with a minimal unified diff.\nRule: {} ({})\nTitle: {}\nEntry: {}\n",
        finding.id, finding.rule_id, finding.title, finding.entry_route
    ));

    if let Some(v) = verified {
        prompt.push_str(&format!("Sandbox Proof: {}\n", v.evidence));
    }

    prompt.push_str("\nRelevant Witness Hops (minimal slices):\n");
    for (idx, hop) in finding.witness_path.iter().enumerate() {
        let abs = project_root.join(&hop.file);
        let snippet = if let Ok(raw) = fs::read_to_string(&abs) {
            let lines: Vec<&str> = raw.lines().collect();
            let start = hop.line.saturating_sub(6).max(1);
            let end = (hop.line + 10).min(lines.len());
            (start..=end)
                .map(|ln| format!("{:>4} | {}", ln, lines.get(ln - 1).copied().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            "<file unreadable>".to_string()
        };

        prompt.push_str(&format!(
            "\n--- Hop [{}] {}:{} ({}) ---\n{}\n",
            idx + 1,
            hop.file,
            hop.line,
            hop.symbol,
            snippet
        ));
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
    fn test_disabled_by_default_and_minimal_prompt() {
        let finding = LatticeFinding {
            id: "VF-RACE-004".into(),
            rule_id: "VF-RACE-001".into(),
            severity: "CRITICAL".into(),
            title: "Missing tx lock".into(),
            status: "PROVEN".into(),
            entry_route: "POST /api/v1/checkout/withdraw".into(),
            sink_kind: SinkKind::BalanceUpdate,
            missing_guard: GuardKind::TxLock,
            witness_path: vec![TraceHop {
                file: "src/routes/checkout.ts".into(),
                symbol: "POST /api/v1/checkout/withdraw".into(),
                line: 8,
            }],
        };

        let disabled = generate_patch_plan(&AiProvider::Disabled, Path::new("."), &finding, None).unwrap();
        assert!(disabled.is_none());

        let prompt = build_minimal_patch_prompt(Path::new("fixtures/vuln-payment-node"), &finding, None).unwrap();
        assert!(prompt.len() < 2048);
        assert!(prompt.contains("VF-RACE-004"));
    }
}
