use serde_json::json;
use std::collections::HashMap;
use vf_graph::{Confidence, GraphAnalysisResult, LatticeFinding};
use vf_sandbox::{VerificationStatus, VerifiedFinding};

fn security_severity_score(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "9.0",
        "HIGH" => "7.5",
        "MEDIUM" => "5.0",
        "LOW" => "2.5",
        _ => "5.0",
    }
}

fn fnv1a_hex(s: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

/// Exports findings in standard SARIF 2.1.0 format for GitHub Code Scanning & CI/CD.
pub fn to_sarif_json(findings: &[LatticeFinding], verified: &[VerifiedFinding]) -> String {
    let ver_map: HashMap<&str, &VerifiedFinding> = verified
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut seen_rules: HashMap<String, usize> = HashMap::new();
    for f in findings {
        if !seen_rules.contains_key(&f.rule_id) {
            let idx = rules.len();
            seen_rules.insert(f.rule_id.clone(), idx);
            rules.push(json!({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": { "text": f.title },
                "help": {
                    "text": if f.remediation.is_empty() {
                        f.title.clone()
                    } else {
                        f.remediation.clone()
                    }
                },
                "properties": {
                    "security-severity": security_severity_score(&f.severity),
                    "tags": ["security", "shellmind-guard"]
                }
            }));
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let v_opt = ver_map.get(f.id.as_str()).copied();
            let status_tag = match v_opt.map(|v| &v.status) {
                Some(VerificationStatus::Proven) => "PROVEN",
                Some(VerificationStatus::Mitigated) => "MITIGATED",
                Some(VerificationStatus::Unbootable) => "UNBOOTABLE",
                _ => "SUSPECT",
            };
            let level = if status_tag == "MITIGATED" {
                "note"
            } else if f.severity == "CRITICAL" || f.severity == "HIGH" {
                "error"
            } else {
                "warning"
            };

            let primary_hop = f.witness_path.last().or_else(|| f.witness_path.first());
            let raw_file = primary_hop
                .map(|h| h.file.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| (!f.file.is_empty()).then_some(f.file.as_str()))
                .unwrap_or("unknown");
            let uri = percent_encode_uri_path(raw_file);
            let start_line = primary_hop
                .map(|h| h.line)
                .filter(|&l| l > 0)
                .unwrap_or_else(|| f.line.max(1));

            let thread_locations: Vec<serde_json::Value> = f
                .witness_path
                .iter()
                .map(|h| {
                    json!({
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": { "uri": percent_encode_uri_path(&h.file) },
                                "region": { "startLine": h.line.max(1) }
                            },
                            "message": { "text": format!("Symbol: {}", h.symbol) }
                        }
                    })
                })
                .collect();

            let conf_tag = if status_tag == "PROVEN" || f.confidence == Confidence::Proven {
                Confidence::Proven.as_str()
            } else {
                f.confidence.as_str()
            };
            let msg = match v_opt {
                Some(v) if !f.remediation.is_empty() => format!(
                    "[{}/{}] {} — {} | Fix: {}",
                    status_tag, conf_tag, f.title, v.evidence, f.remediation
                ),
                Some(v) => format!("[{}/{}] {} — {}", status_tag, conf_tag, f.title, v.evidence),
                None if !f.remediation.is_empty() => {
                    format!(
                        "[{}/{}] {} | Fix: {}",
                        status_tag, conf_tag, f.title, f.remediation
                    )
                }
                None => format!("[{}/{}] {}", status_tag, conf_tag, f.title),
            };

            let fingerprint = fnv1a_hex(&format!(
                "{}|{}|{}|{}",
                f.rule_id, raw_file, start_line, f.entry_route
            ));

            json!({
                "ruleId": f.rule_id,
                "ruleIndex": seen_rules.get(&f.rule_id).copied().unwrap_or(0),
                "level": level,
                "message": { "text": msg },
                "properties": {
                    "confidence": conf_tag,
                    "verificationStatus": status_tag,
                    "missingGuard": format!("{:?}", f.missing_guard),
                },
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": start_line }
                    }
                }],
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": thread_locations
                    }]
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ShellMind Guard",
                    "informationUri": "https://github.com/qira-dev/ShellMind-Guard",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".into())
}

/// Generates a self-contained GitHub Carbon Slate HTML + inline SVG multi-file flow report.
pub fn to_html_graph(
    project_name: &str,
    graph: &GraphAnalysisResult,
    verified: &[VerifiedFinding],
) -> String {
    let ver_map: HashMap<&str, &VerifiedFinding> = verified
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let proven_count = verified
        .iter()
        .filter(|v| v.status == VerificationStatus::Proven)
        .count();

    let mut cards = String::new();
    for f in &graph.findings {
        let v_opt = ver_map.get(f.id.as_str()).copied();
        let (badge, badge_cls, evidence_html) = match v_opt {
            Some(v) if v.status == VerificationStatus::Proven => (
                "PROVEN",
                "badge-proven",
                format!(
                    "<div class=\"proof\"><strong>Sandbox Proof:</strong> {}<br><code>{}</code></div>",
                    escape_html(&v.evidence),
                    escape_html(&v.replay_cmd)
                ),
            ),
            Some(v) if v.status == VerificationStatus::Mitigated => (
                "MITIGATED",
                "badge-mitigated",
                format!(
                    "<div class=\"proof\"><strong>Mitigated:</strong> {}</div>",
                    escape_html(&v.evidence)
                ),
            ),
            Some(v) if v.status == VerificationStatus::Unbootable => (
                "UNBOOTABLE",
                "badge-suspect",
                format!(
                    "<div class=\"proof\"><strong>Unbootable in Sandbox:</strong> {}</div>",
                    escape_html(&v.evidence)
                ),
            ),
            _ => ("SUSPECT", "badge-suspect", String::new()),
        };

        let hops_w = (f.witness_path.len().max(1) * 260) + 40;
        let mut svg_nodes = String::new();
        for (idx, hop) in f.witness_path.iter().enumerate() {
            let x = 20 + idx * 260;
            if idx > 0 {
                let prev_x = x - 35;
                svg_nodes.push_str(&format!(
                    "<line x1=\"{}\" y1=\"45\" x2=\"{}\" y2=\"45\" stroke=\"#58a6ff\" stroke-width=\"2\" marker-end=\"url(#arrow)\"/>",
                    prev_x, x
                ));
            }
            svg_nodes.push_str(&format!(
                "<rect x=\"{}\" y=\"12\" width=\"225\" height=\"66\" rx=\"8\" fill=\"#161b22\" stroke=\"#30363d\"/>\
                 <text x=\"{}\" y=\"34\" fill=\"#58a6ff\" font-size=\"12\" font-family=\"monospace\">[{}] {}</text>\
                 <text x=\"{}\" y=\"54\" fill=\"#c9d1d9\" font-size=\"11\" font-family=\"monospace\">{}:{}</text>",
                x,
                x + 12,
                idx + 1,
                escape_html(&hop.symbol),
                x + 12,
                escape_html(&hop.file),
                hop.line
            ));
        }

        cards.push_str(&format!(
            "<div class=\"card\">\
              <div class=\"card-head\">\
                <span class=\"badge {badge_cls}\">{badge}</span>\
                <span class=\"conf {conf_cls}\">{conf}</span>\
                <span class=\"sev\">{sev}</span>\
                <strong>{id}</strong> — {title}\
              </div>\
              <div class=\"route\">Entry: <code>{entry}</code></div>\
              <div class=\"svg-wrap\">\
                <svg width=\"{hops_w}\" height=\"92\" xmlns=\"http://www.w3.org/2000/svg\">\
                  <defs><marker id=\"arrow\" markerWidth=\"8\" markerHeight=\"8\" refX=\"6\" refY=\"3\" orient=\"auto\"><path d=\"M0,0 L0,6 L6,3 z\" fill=\"#58a6ff\"/></marker></defs>\
                  {svg_nodes}\
                </svg>\
              </div>\
              {evidence_html}\
            </div>",
            badge_cls = badge_cls,
            badge = badge,
            conf_cls = if badge == "PROVEN" || f.confidence == Confidence::Proven {
                "conf-proven"
            } else if f.confidence == Confidence::Confirmed {
                "conf-confirmed"
            } else {
                "conf-heuristic"
            },
            conf = if badge == "PROVEN" || f.confidence == Confidence::Proven {
                Confidence::Proven.as_str()
            } else {
                f.confidence.as_str()
            },
            sev = escape_html(&f.severity),
            id = escape_html(&f.id),
            title = escape_html(&f.title),
            entry = escape_html(&f.entry_route),
            hops_w = hops_w,
            svg_nodes = svg_nodes,
            evidence_html = evidence_html
        ));
    }

    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>ShellMind Guard Report — {project}</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:system-ui,-apple-system,sans-serif; margin:0; padding:24px; }}
  .wrap {{ max-width:1100px; margin:0 auto; }}
  h1 {{ margin:0 0 8px; font-size:22px; color:#f0f6fc; }}
  .stats {{ display:flex; gap:12px; margin:16px 0 24px; flex-wrap:wrap; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:10px 16px; font-size:13px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; margin-bottom:16px; }}
  .card-head {{ display:flex; align-items:center; gap:10px; font-size:15px; margin-bottom:8px; }}
  .badge {{ padding:2px 8px; border-radius:99px; font-size:11px; font-weight:700; }}
  .badge-proven {{ background:#da3633; color:#fff; }}
  .badge-mitigated {{ background:#238636; color:#fff; }}
  .badge-suspect {{ background:#9e6a03; color:#fff; }}
  .conf {{ font-size:11px; font-weight:600; padding:1px 7px; border-radius:4px; border:1px solid #30363d; }}
  .conf-proven {{ color:#ff7b72; border-color:#da3633; }}
  .conf-confirmed {{ color:#58a6ff; border-color:#1f6feb; }}
  .conf-heuristic {{ color:#d29922; border-color:#9e6a03; }}
  .sev {{ font-size:11px; color:#8b949e; border:1px solid #30363d; padding:1px 6px; border-radius:4px; }}
  .route {{ font-size:13px; color:#8b949e; margin-bottom:10px; }}
  .svg-wrap {{ overflow-x:auto; background:#0d1117; border:1px solid #21262d; border-radius:8px; padding:6px; }}
  .proof {{ margin-top:10px; background:#0d1117; border-left:3px solid #da3633; padding:10px 12px; font-size:13px; }}
  code {{ font-family:ui-monospace,SFMono-Regular,monospace; color:#79c0ff; }}
</style>
</head>
<body>
<div class=\"wrap\">
  <h1>ShellMind Guard Multi-File Security &amp; Logic Graph — {project}</h1>
  <div class=\"stats\">
    <div class=\"stat\">Parsed Files: <strong>{files}</strong></div>
    <div class=\"stat\">Symbols: <strong>{syms}</strong></div>
    <div class=\"stat\">Edges: <strong>{edges}</strong></div>
    <div class=\"stat\">Routes: <strong>{routes}</strong></div>
    <div class=\"stat\">Findings: <strong>{total}</strong></div>
    <div class=\"stat\">PROVEN: <strong style=\"color:#f85149\">{proven}</strong></div>
  </div>
  {cards}
</div>
</body>
</html>",
        project = escape_html(project_name),
        files = graph.parsed_files,
        syms = graph.symbol_count,
        edges = graph.edge_count,
        routes = graph.route_entries,
        total = graph.findings.len(),
        proven = proven_count,
        cards = cards
    )
}

fn percent_encode_uri_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
