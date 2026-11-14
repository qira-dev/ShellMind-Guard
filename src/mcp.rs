use crate::{ScanRunOptions, execute_scan_pipeline, write_ci_workflow};
use anyhow::Result;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use vf_ai::build_minimal_patch_prompt;
use vf_core::{StateStore, VeriForgeConfig, scan_repository};
use vf_graph::analyze_codebase_cached;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Runs VeriForge's stdio JSON-RPC 2.0 MCP server loop.
/// Reads newline-delimited requests from `stdin` and writes single-line responses exclusively to `stdout`.
pub fn run_stdio_server() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
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
                    "name": "veriforge",
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
            "name": "veriforge_scan",
            "description": "Scan a repository across VeriForge's 6 deterministic layers (Auth & Secrets, Taint/Injection/IDOR/Frontend Contract, Offline Dependencies, Security Misconfigs, Concurrency Race Conditions, and optional Bubblewrap runtime exploit verification).",
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
                        "description": "Optional layer filters: auth, race, taint, sqli, cmdi, path, ssrf, idor, secrets, config, deps, frontend"
                    },
                    "boot_cmd": {
                        "type": "string",
                        "description": "Optional boot command for live Bubblewrap sandbox verification (e.g. 'node server.mjs')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Loopback port used inside sandbox (default 39911)"
                    },
                    "sync_race": {
                        "type": "integer",
                        "description": "Concurrent requests for Last-Byte Sync race probe (default 12)"
                    },
                    "unsafe_host_fallback": {
                        "type": "boolean",
                        "description": "Allow host loopback fallback if /usr/bin/bwrap is unavailable"
                    }
                }
            }
        },
        {
            "name": "veriforge_explain_finding",
            "description": "Inspect a specific finding ID (e.g. VF-RACE-002, VF-SQLI-001) and return its full cross-file trace hops, source code excerpt, remediation, and replay command.",
            "inputSchema": {
                "type": "object",
                "required": ["finding_id"],
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "Finding ID returned by veriforge_scan (e.g. VF-AUTH-001)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to '.')"
                    }
                }
            }
        },
        {
            "name": "veriforge_init",
            "description": "Auto-detect project languages and frameworks to generate .veriforge.toml (and optionally .github/workflows/veriforge.yml).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to repository root (defaults to '.')"
                    },
                    "ci": {
                        "type": "boolean",
                        "description": "Also generate .github/workflows/veriforge.yml GitHub Actions SARIF workflow"
                    }
                }
            }
        }
    ])
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
        "veriforge_scan" => {
            let root = PathBuf::from(args.get("path").and_then(|v| v.as_str()).unwrap_or("."));
            let layers: Vec<String> = args
                .get("layers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let boot_cmd = args
                .get("boot_cmd")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let port = args
                .get("port")
                .and_then(|v| v.as_u64())
                .map(|p| p as u16)
                .unwrap_or(39911);
            let sync_race = args
                .get("sync_race")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(12);
            let unsafe_host_fallback = args
                .get("unsafe_host_fallback")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome = execute_scan_pipeline(ScanRunOptions {
                path: &root,
                layers: &layers,
                boot_cmd,
                port,
                sync_race,
                unsafe_host_fallback,
            })?;

            json!({
                "ok": true,
                "elapsed_ms": outcome.elapsed_ms,
                "findings_count": outcome.graph.findings.len(),
                "findings": outcome.graph.findings,
                "delta": outcome.delta,
                "graph": outcome.graph,
                "sandbox_verification": outcome.sandbox.as_ref().map(|(bwrap, res)| json!({
                    "bwrap_isolated": bwrap,
                    "results": res,
                })),
            })
        }
        "veriforge_explain_finding" => {
            let finding_id = args
                .get("finding_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing required argument `finding_id`"))?;
            let root = PathBuf::from(args.get("path").and_then(|v| v.as_str()).unwrap_or("."));
            let cfg = VeriForgeConfig::load_from_dir(&root)?;
            let summary = scan_repository(&root, &cfg)?;
            let mut store = StateStore::open(&root)?;
            let _ = store.sync_files(&summary.files)?;
            let graph = analyze_codebase_cached(&summary.files, &cfg, &mut store)?;
            let findings = graph.findings;
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
                "replay_cmd": format!("veriforge replay {}", finding.id),
            })
        }
        "veriforge_init" => {
            let root = PathBuf::from(args.get("path").and_then(|v| v.as_str()).unwrap_or("."));
            let ci = args.get("ci").and_then(|v| v.as_bool()).unwrap_or(false);
            let (detected, config_path) = VeriForgeConfig::detect_and_write_init(&root)?;
            let ci_path = if ci {
                Some(write_ci_workflow(&root)?)
            } else {
                None
            };
            json!({
                "ok": true,
                "detected": detected,
                "config_path": config_path.display().to_string(),
                "ci_workflow_path": ci_path.map(|p| p.display().to_string()),
            })
        }
        other => anyhow::bail!("Unknown MCP tool `{}`", other),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&payload)?
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
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "veriforge");

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
        assert!(names.contains(&"veriforge_scan"));
        assert!(names.contains(&"veriforge_explain_finding"));
        assert!(names.contains(&"veriforge_init"));

        let bad_json = handle_jsonrpc_line("{not valid json").unwrap();
        assert_eq!(bad_json["error"]["code"], -32700);

        let unknown_method =
            handle_jsonrpc_line(r#"{"jsonrpc":"2.0","id":99,"method":"unknown/op"}"#).unwrap();
        assert_eq!(unknown_method["error"]["code"], -32601);
    }

    #[test]
    fn test_mcp_veriforge_scan_and_explain_end_to_end() {
        let dir = std::env::temp_dir().join("vf_mcp_e2e_unit");
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
                "name": "veriforge_scan",
                "arguments": { "path": dir.display().to_string() }
            }
        });
        let scan_resp = handle_jsonrpc_line(&scan_req.to_string()).unwrap();
        assert_eq!(scan_resp["result"]["isError"], false);
        let text = scan_resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        let findings = parsed["graph"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["rule_id"] == "VF-SQLI-001"),
            "MCP scan must return SQLi finding: {}",
            text
        );
        let sqli_obj = findings
            .iter()
            .find(|f| f["rule_id"] == "VF-SQLI-001")
            .unwrap();
        assert_eq!(sqli_obj["file"], "src/app.ts");
        assert_eq!(sqli_obj["line"], 1);
        let fid = sqli_obj["id"].as_str().unwrap().to_string();

        let explain_req = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "veriforge_explain_finding",
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

        let _ = fs::remove_dir_all(&dir);
    }
}
