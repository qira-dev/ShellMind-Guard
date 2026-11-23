//! Phase 28C: Data-Driven OSV Auto-Function VEX Extractor & OpenVEX v0.2.0 Exporter.
//!
//! Automatically extracts vulnerable function/symbol names directly from OSV advisory JSON
//! (`affected[].ecosystem_specific.imports[].symbols[]` & `affected[].ecosystem_specific.functions[]`)
//! across Go, Rust, Python, JS/TS, Java, and PHP—eliminating reliance on static hardcoded tables—
//! and exports standards-compliant OpenVEX v0.2.0 JSON statements.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Auto-extracted vulnerable symbols per `(ecosystem, package)` from OSV advisory metadata.
#[derive(Debug, Default, Clone)]
pub struct AutoVexSymbolIndex {
    /// `(ecosystem_lower, package_lower) -> set of lowercase vulnerable symbol names`
    pub symbols: BTreeMap<(String, String), BTreeSet<String>>,
}

impl AutoVexSymbolIndex {
    /// Ingests an OSV advisory JSON document (`v1/vulns/<id>` format) and indexes every
    /// vulnerable symbol listed under `ecosystem_specific.imports[].symbols[]` or `functions[]`.
    pub fn ingest_osv_json(&mut self, osv: &Value) -> usize {
        let mut added = 0usize;
        let Some(affected) = osv.get("affected").and_then(|v| v.as_array()) else {
            return 0;
        };

        for aff in affected {
            let eco = aff
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let pkg = aff
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if eco.is_empty() || pkg.is_empty() {
                continue;
            }
            let Some(es) = aff.get("ecosystem_specific") else {
                continue;
            };
            let entry = self.symbols.entry((eco, pkg)).or_default();

            // Go / Rust / Python OSV format: `ecosystem_specific.imports[].symbols[]`
            if let Some(imports) = es.get("imports").and_then(|v| v.as_array()) {
                for imp in imports {
                    if let Some(syms) = imp.get("symbols").and_then(|v| v.as_array()) {
                        for s in syms.iter().filter_map(|x| x.as_str()) {
                            let norm = normalize_symbol(s);
                            if !norm.is_empty() && entry.insert(norm) {
                                added += 1;
                            }
                        }
                    }
                }
            }

            // Generic OSV format: `ecosystem_specific.functions[]`
            if let Some(fns) = es.get("functions").and_then(|v| v.as_array()) {
                for f in fns.iter().filter_map(|x| x.as_str()) {
                    let norm = normalize_symbol(f);
                    if !norm.is_empty() && entry.insert(norm) {
                        added += 1;
                    }
                }
            }
        }
        added
    }

    pub fn lookup(&self, ecosystem: &str, package: &str) -> Option<&BTreeSet<String>> {
        self.symbols
            .get(&(ecosystem.to_ascii_lowercase(), package.to_ascii_lowercase()))
    }
}

fn normalize_symbol(raw: &str) -> String {
    let trimmed = raw.trim();
    // Extract leaf method/function name from `Type.Method` or `mod::func`
    let leaf = trimmed
        .rsplit("::")
        .next()
        .unwrap_or(trimmed)
        .rsplit('.')
        .next()
        .unwrap_or(trimmed);
    leaf.trim_matches(['(', ')', '*', '&']).to_ascii_lowercase()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVexStatement {
    pub vulnerability_id: String,
    pub product_purl: String,
    /// `"affected"` | `"not_affected"` | `"under_investigation"`
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    pub impact_statement: String,
}

/// Renders an OpenVEX v0.2.0 compliant JSON document from verified VEX statements.
pub fn to_openvex_json(author: &str, statements: &[OpenVexStatement]) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if m <= 2 { y + 1 } else { y };
    let timestamp = format!("{yr:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z");
    let stmts: Vec<serde_json::Value> = statements
        .iter()
        .map(|s| {
            let mut obj = serde_json::json!({
                "vulnerability": { "name": s.vulnerability_id },
                "products": [{ "@id": s.product_purl }],
                "status": s.status,
                "impact_statement": s.impact_statement,
            });
            if s.status == "affected" {
                obj["action_statement"] = serde_json::json!(
                    "Upgrade the affected dependency to a fixed version or apply the vendor mitigation."
                );
            }
            if let Some(ref j) = s.justification {
                obj["justification"] = serde_json::json!(j);
            }
            obj
        })
        .collect();

    let doc = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://shellmind-guard.local/vex/latest",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "statements": stmts,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_extracts_osv_vulnerable_symbols_and_emits_openvex_v02() {
        let osv = serde_json::json!({
            "id": "GO-2024-9999",
            "affected": [{
                "package": { "ecosystem": "Go", "name": "golang.org/x/net" },
                "ecosystem_specific": {
                    "imports": [{
                        "path": "golang.org/x/net/http2",
                        "symbols": ["Server.ServeConn", "Framer.ReadFrame"]
                    }],
                    "functions": ["http2::parseHeaders"]
                }
            }]
        });

        let mut idx = AutoVexSymbolIndex::default();
        let count = idx.ingest_osv_json(&osv);
        assert_eq!(count, 3);
        let syms = idx.lookup("Go", "golang.org/x/net").unwrap();
        assert!(syms.contains("serveconn"));
        assert!(syms.contains("readframe"));
        assert!(syms.contains("parseheaders"));

        let json = to_openvex_json(
            "ShellMind-Guard",
            &[OpenVexStatement {
                vulnerability_id: "GO-2024-9999".into(),
                product_purl: "pkg:golang/golang.org/x/net@0.17.0".into(),
                status: "not_affected".into(),
                justification: Some("vulnerable_code_not_in_execute_path".into()),
                impact_statement: "Call graph proves only safe APIs are invoked.".into(),
            }],
        );
        assert!(json.contains("https://openvex.dev/ns/v0.2.0"));
        assert!(json.contains("vulnerable_code_not_in_execute_path"));
    }
}
