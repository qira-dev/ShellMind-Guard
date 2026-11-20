use crate::{ScanRunOptions, execute_scan_pipeline, write_ci_workflow};
use anyhow::Result;
use serde_json::{Value, json};
use smg_ai::build_minimal_patch_prompt;
use smg_core::{ShellMindGuardConfig, StateStore, scan_repository};
use smg_graph::{analyze_codebase_cached, collect_deep_schema_findings};
use std::io::{self, BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};

const PROTOCOL_VERSION: &str = "2024-11-05";
const MAX_MCP_LINE_BYTES: u64 = 4 * 1024 * 1024;

/// Runs ShellMind Guard's stdio JSON-RPC 2.0 MCP server loop.
/// Reads newline-delimited requests from `stdin` and writes single-line responses exclusively to `stdout`.
pub fn run_stdio_server() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut line = String::new();

    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_MCP_LINE_BYTES)
            .read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if n as u64 == MAX_MCP_LINE_BYTES && !line.ends_with('\n') {
            // Drain remaining bytes up to newline or EOF so the stream does not split into two frames
            let mut discard = Vec::new();
            let _ = reader.read_until(b'\n', &mut discard);
            let err_resp = json_error(
                Value::Null,
                -32600,
                "Invalid Request: JSON-RPC line exceeds 4 MiB limit",
            );
            let encoded = serde_json::to_string(&err_resp)?;
            writer.write_all(encoded.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = handle_jsonrpc_line(trimmed) {
            let encoded = serde_json::to_string(&resp)?;
            writer.write_all(encoded.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Processes a single JSON-RPC 2.0 message line.
/// Returns `None` for notifications (no response required per JSON-RPC 2.0 / MCP spec).
pub fn handle_jsonrpc_line(raw: &str) -> Option<Value> {
    let req: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return Some(json_error(
                Value::Null,
                -32700,
                &format!("Parse error: {}", e),
            ));
        }
    };

    let Some(obj) = req.as_object() else {
        return Some(json_error(
            Value::Null,
            -32600,
            "Invalid Request: expected JSON object",
        ));
    };

    let id_opt = obj.get("id").cloned();
    let Some(method) = obj.get("method").and_then(|m| m.as_str()) else {
        return id_opt.map(|id| json_error(id, -32600, "Invalid Request: missing method"));
    };

    // Per JSON-RPC 2.0, notifications have no `id` (or are `notifications/*`) and receive no reply.
    if id_opt.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id_opt.unwrap_or(Value::Null);
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

    let resp = match method {
        "initialize" => json_ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "shellmind-guard",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),
        "ping" => json_ok(id, json!({})),
        "tools/list" => json_ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => match handle_tool_call(&params) {
            Ok(result) => json_ok(id, result),
            Err(e) => json_ok(
                id,
                json!({
                    "content": [{ "type": "text", "text": json!({ "ok": false, "error": e.to_string() }).to_string() }],
                    "isError": true
                }),
            ),
        },
        other => json_error(id, -32601, &format!("Method not found: {}", other)),
    };

    Some(resp)
}

fn json_ok(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn json_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "shellmind_guard_scan",
            "description": "Scan a repository across ShellMind Guard's deterministic 16-language engine (Secrets, Config/IaC/SQL, Offline OSV Deps, SQL/NoSQL/XSS/CSRF/CMDi/SSTI/Path/SSRF Taint, Auth/IDOR/Race Lattice, Frontend Contract, Engine Deadlocks/Leaks/Memory, Mobile Security, and optional Phase 10 --deep Schema Checks).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to '.')"
                    },
                    "layers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional layer filters: auth, race, concurrency, taint, sqli, cmdi, path, ssrf, xss, csrf, idor, secrets, config, deps, frontend, cicd, k8s, dos, zip, crypto, queue, api, ai, oauth, smuggle, state, engine, memory, mobile, hw, web3, pqc, deep"
                    },
                    "min_confidence": {
                        "type": "string",
                        "enum": ["proven", "confirmed", "heuristic"],
                        "description": "Optional minimum finding confidence tier (default: include all)"
                    },
                    "deep": {
                        "type": "boolean",
                        "description": "Enable Phase 10 deep AST/OpenAPI schema validation (SMG-FUZZ-SCHEMA)"
                    },
                    "deep_audit": {
                        "type": "boolean",
                        "description": "Enable Phase 15 Tier-2 deep audit budget (unlocks 2048-block CFG, 64 CHA targets, 256 witness hops)"
                    }
                }
            }
        },
        {
            "name": "shellmind_guard_explain_finding",
            "description": "Inspect a specific finding ID (e.g. SMG-RACE-002, SMG-SQLI-001, SMG-FUZZ-001) and return its full cross-file trace hops, source code excerpt, remediation, and replay command.",
            "inputSchema": {
                "type": "object",
                "required": ["finding_id"],
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Finding ID or rule ID returned by shellmind_guard_scan (e.g. SMG-AUTH-001, SMG-FUZZ-SCHEMA)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to '.')"
                    }
                }
            }
        },
        {
            "name": "shellmind_guard_init",
            "description": "Auto-detect project languages and frameworks to generate .shellmind-guard.toml (and optionally .github/workflows/shellmind-guard.yml or .git/hooks/pre-commit).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to '.')"
                    },
                    "ci": {
                        "type": "boolean",
                        "description": "Also generate .github/workflows/shellmind-guard.yml GitHub Actions SARIF workflow"
                    },
                    "hook": {
                        "type": "boolean",
                        "description": "Also install standalone Git pre-commit hook (.git/hooks/pre-commit)"
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "Overwrite existing .shellmind-guard.toml if present (default false)"
                    }
                }
            }
        }
    ])
}

fn normalize_and_resolve_path(base_cwd: &Path, raw_path: &Path) -> PathBuf {
    let joined = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        base_cwd.join(raw_path)
    };
    let mut normalized = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::Prefix(p) => normalized.push(p.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(seg) => normalized.push(seg),
        }
    }
    if let Ok(canon) = std::fs::canonicalize(&normalized) {
        return canon;
    }
    // Walk up to the nearest existing ancestor directory, canonicalize it, and re-append non-existent tail components
    let mut cur = normalized.as_path();
    let mut tail = Vec::new();
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            tail.push(name.to_os_string());
        }
        if let Ok(canon_parent) = std::fs::canonicalize(parent) {
            let mut out = canon_parent;
            for seg in tail.into_iter().rev() {
                out.push(seg);
            }
            return out;
        }
        cur = parent;
    }
    normalized
}

fn validate_mcp_target_path(raw_path: &str) -> Result<PathBuf> {
    let cwd = std::fs::canonicalize(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .unwrap_or_else(|_| PathBuf::from("."));
    let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    let canon = normalize_and_resolve_path(&cwd, Path::new(raw_path));

    let env_root = std::env::var("SHELLMIND_GUARD_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| normalize_and_resolve_path(&cwd, Path::new(s.trim())));

    // Block sensitive credential/system dot-directories
    let has_sensitive_component = canon.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".ssh" | ".gnupg" | ".aws" | ".kube" | ".docker" | ".netrc")
        )
    });
    if has_sensitive_component {
        anyhow::bail!(
            "Refusing MCP access to sensitive credential path: {}",
            canon.display()
        );
    }

    let in_allowed = canon.starts_with(&cwd)
        || canon.starts_with(&tmp)
        || env_root.as_ref().is_some_and(|r| canon.starts_with(r));

    if !in_allowed {
        anyhow::bail!(
            "Refusing MCP access outside workspace root ({}) or temp dir: {}",
            cwd.display(),
            canon.display()
        );
    }
    Ok(canon)
}

fn handle_tool_call(params: &Value) -> Result<Value> {
    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing tool name in tools/call params"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let payload = match tool_name {
        "shellmind_guard_scan" => {
            let root =
                validate_mcp_target_path(args.get("path").and_then(|v| v.as_str()).unwrap_or("."))?;
            let layers: Vec<String> = args
                .get("layers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let min_confidence = args
                .get("min_confidence")
                .and_then(|v| v.as_str())
                .and_then(smg_graph::Confidence::parse);

            let deep = args.get("deep").and_then(|v| v.as_bool()).unwrap_or(false);
            let deep_audit = args
                .get("deep_audit")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome = execute_scan_pipeline(ScanRunOptions {
                path: &root,
                layers: &layers,
                min_confidence,
                boot_cmd: None,
                port: 39911,
                sync_race: 12,
                unsafe_host_fallback: false,
                trust_repo_config: false,
                deep,
                deep_audit,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
            })?;

            const MAX_MCP_FINDINGS: usize = 50;
            const MAX_MCP_RESPONSE_BYTES: usize = 32 * 1024;
            let total_findings = outcome.graph.findings.len();
            let mut findings_slice: Vec<_> = outcome
                .graph
                .findings
                .into_iter()
                .take(MAX_MCP_FINDINGS)
                .collect();
            let mut budget_trimmed = false;
            loop {
                let candidate = json!({
                    "ok": true,
                    "elapsed_ms": outcome.elapsed_ms,
                    "parsed_files": outcome.graph.parsed_files,
                    "symbol_count": outcome.graph.symbol_count,
                    "edge_count": outcome.graph.edge_count,
                    "route_entries": outcome.graph.route_entries,
                    "findings_count": total_findings,
                    "returned_count": findings_slice.len(),
                    "truncated": total_findings > findings_slice.len() || budget_trimmed,
                    "budget_bytes": MAX_MCP_RESPONSE_BYTES,
                    "findings": findings_slice,
                    "delta": outcome.delta,
                });
                let encoded = candidate.to_string();
                if encoded.len() <= MAX_MCP_RESPONSE_BYTES || findings_slice.is_empty() {
                    let mut final_val = candidate;
                    if let Some(obj) = final_val.as_object_mut() {
                        obj.insert("response_bytes".into(), json!(encoded.len()));
                    }
                    break final_val;
                }
                budget_trimmed = true;
                if let Some(long_witness) =
                    findings_slice.iter_mut().find(|f| f.witness_path.len() > 2)
                {
                    long_witness.witness_path.truncate(2);
                } else {
                    findings_slice.pop();
                }
            }
        }
        "shellmind_guard_explain_finding" => {
            let finding_id = args
                .get("finding_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing required argument `finding_id`"))?;
            let root =
                validate_mcp_target_path(args.get("path").and_then(|v| v.as_str()).unwrap_or("."))?;
            let cfg = ShellMindGuardConfig::load_from_dir(&root)?;
            let summary = scan_repository(&root, &cfg)?;
            let mut store = StateStore::open(&root)?;
            let _ = store.sync_files(&summary.files)?;
            let graph = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
            let deep_findings = collect_deep_schema_findings(&graph);
            let mut findings = graph.findings;
            findings.extend(deep_findings);
            let finding = findings
                .iter()
                .find(|f| f.id.eq_ignore_ascii_case(finding_id))
                .or_else(|| {
                    findings
                        .iter()
                        .find(|f| f.rule_id.eq_ignore_ascii_case(finding_id))
                })
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("Finding `{}` not found in {}", finding_id, root.display())
                })?;

            let prompt_excerpt = build_minimal_patch_prompt(&root, &finding, None)?;
            json!({
                "ok": true,
                "finding": finding,
                "remediation": finding.remediation,
                "source_context": prompt_excerpt,
                "replay_cmd": format!("smg replay {}", finding.id),
            })
        }
        "shellmind_guard_init" => {
            let root =
                validate_mcp_target_path(args.get("path").and_then(|v| v.as_str()).unwrap_or("."))?;
            let ci = args.get("ci").and_then(|v| v.as_bool()).unwrap_or(false);
            let hook = args.get("hook").and_then(|v| v.as_bool()).unwrap_or(false);
            let overwrite = args
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let cfg_target = root.join(".shellmind-guard.toml");
            if cfg_target.exists() && !overwrite {
                anyhow::bail!(
                    "{} already exists (pass overwrite: true to replace)",
                    cfg_target.display()
                );
            }
            let wf_target = root
                .join(".github")
                .join("workflows")
                .join("shellmind-guard.yml");
            if ci && wf_target.exists() && !overwrite {
                anyhow::bail!(
                    "{} already exists (pass overwrite: true to replace)",
                    wf_target.display()
                );
            }
            let (detected, config_path) = ShellMindGuardConfig::detect_and_write_init(&root)?;
            let ci_path = if ci {
                Some(write_ci_workflow(&root)?)
            } else {
                None
            };
            let hook_path = if hook {
                Some(crate::install_git_hook(&root)?)
            } else {
                None
            };
            json!({
                "ok": true,
                "detected": detected,
                "config_path": config_path.display().to_string(),
                "ci_workflow_path": ci_path.map(|p| p.display().to_string()),
                "hook_path": hook_path.map(|p| p.display().to_string()),
            })
        }
        other => anyhow::bail!("Unknown MCP tool `{}`", other),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string(&payload)?
        }],
        "isError": false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_mcp_initialize_tools_list_notifications_and_errors() {
        let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
        let init_resp = handle_jsonrpc_line(init_req).expect("initialize must reply");
        assert_eq!(init_resp["jsonrpc"], "2.0");
        assert_eq!(init_resp["id"], 1);
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "shellmind-guard");

        let notif = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(
            handle_jsonrpc_line(notif).is_none(),
            "notifications must not produce a JSON-RPC reply"
        );

        let list_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let list_resp = handle_jsonrpc_line(list_req).expect("tools/list must reply");
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"shellmind_guard_scan"));
        assert!(names.contains(&"shellmind_guard_explain_finding"));
        assert!(names.contains(&"shellmind_guard_init"));

        let bad_json = handle_jsonrpc_line("{not valid json").unwrap();
        assert_eq!(bad_json["error"]["code"], -32700);

        let unknown_method =
            handle_jsonrpc_line(r#"{"jsonrpc":"2.0","id":99,"method":"unknown/op"}"#).unwrap();
        assert_eq!(unknown_method["error"]["code"], -32601);
    }

    #[test]
    fn test_mcp_shellmind_guard_scan_and_explain_end_to_end() {
        let dir = std::env::temp_dir().join("smg_mcp_e2e_unit");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/app.ts"),
            "app.get('/api/item', (req, res) => db.query(`SELECT * FROM t WHERE id=${req.query.id}`));",
        )
        .unwrap();

        let scan_req = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "shellmind_guard_scan",
                "arguments": { "path": dir.display().to_string() }
            }
        });
        let scan_resp = handle_jsonrpc_line(&scan_req.to_string()).unwrap();
        assert_eq!(scan_resp["result"]["isError"], false);
        let text = scan_resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        let findings = parsed["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["rule_id"] == "SMG-SQLI-001"),
            "MCP scan must return SQLi finding: {}",
            text
        );
        let sqli_obj = findings
            .iter()
            .find(|f| f["rule_id"] == "SMG-SQLI-001")
            .unwrap();
        assert_eq!(sqli_obj["file"], "src/app.ts");
        assert_eq!(sqli_obj["line"], 1);
        let fid = sqli_obj["id"].as_str().unwrap().to_string();

        let explain_req = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "shellmind_guard_explain_finding",
                "arguments": {
                    "path": dir.display().to_string(),
                    "finding_id": fid
                }
            }
        });
        let explain_resp = handle_jsonrpc_line(&explain_req.to_string()).unwrap();
        assert_eq!(explain_resp["result"]["isError"], false);
        let exp_txt = explain_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(exp_txt.contains("SELECT * FROM t"));

        // Verify schema consistency (`deep` layer + `hook` init) and SMG-FUZZ-SCHEMA resolution via explain_finding
        let defs = tool_definitions();
        let tools = defs.as_array().unwrap();
        let scan_schema_desc = tools[0]["inputSchema"]["properties"]["layers"]["description"]
            .as_str()
            .unwrap();
        assert!(scan_schema_desc.contains("deep"));
        assert!(tools[2]["inputSchema"]["properties"]["hook"].is_object());

        fs::write(
            dir.join("src/pay.ts"),
            "app.post('/api/pay', (req, res) => { const amount = req.body.amount; res.json({ amount }); });",
        )
        .unwrap();
        let deep_scan_req = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "shellmind_guard_scan",
                "arguments": { "path": dir.display().to_string(), "deep": true }
            }
        });
        let deep_resp = handle_jsonrpc_line(&deep_scan_req.to_string()).unwrap();
        let deep_parsed: Value =
            serde_json::from_str(deep_resp["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        let fuzz_obj = deep_parsed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rule_id"] == "SMG-FUZZ-SCHEMA")
            .expect("deep MCP scan must emit SMG-FUZZ-SCHEMA");
        let explain_fuzz = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "shellmind_guard_explain_finding",
                "arguments": {
                    "path": dir.display().to_string(),
                    "finding_id": fuzz_obj["id"].as_str().unwrap()
                }
            }
        });
        let explain_fuzz_resp = handle_jsonrpc_line(&explain_fuzz.to_string()).unwrap();
        assert_eq!(explain_fuzz_resp["result"]["isError"], false);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mcp_scan_budget_caps_under_32_kib() {
        let dir = std::env::temp_dir().join(format!("smg-mcp-budget-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();

        let mut big_routes = String::new();
        for i in 0..80 {
            big_routes.push_str(&format!(
                "app.post('/admin/item-{i}', (req, res) => {{ db.query(\"SELECT * FROM t WHERE x = \" + req.body.q{i}); res.send(req.body.q{i}); }});\n"
            ));
        }
        fs::write(dir.join("src/many.ts"), big_routes).unwrap();

        let req = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "shellmind_guard_scan",
                "arguments": { "path": dir.display().to_string() }
            }
        });
        let resp = handle_jsonrpc_line(&req.to_string()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["ok"], true);
        assert!(
            text.len() <= 34 * 1024,
            "Serialized MCP scan payload should obey <=32 KiB finding budget (got {} bytes)",
            text.len()
        );
        assert!(parsed["response_bytes"].as_u64().unwrap() <= 32 * 1024);

        let _ = fs::remove_dir_all(&dir);
    }
}
