use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::Regex;
use smg_core::Language;
use std::collections::HashSet;
use std::sync::OnceLock;

#[allow(clippy::too_many_arguments)]
fn mk_finding_conf(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    confidence: Confidence,
    remediation: &str,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line: line.max(1),
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence,
        remediation: remediation.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn mk_finding(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    symbol: &str,
    sink_kind: SinkKind,
    missing_guard: GuardKind,
    remediation: &str,
) -> LocalStaticFinding {
    mk_finding_conf(
        rule_id,
        severity,
        title,
        rel_path,
        line,
        symbol,
        sink_kind,
        missing_guard,
        Confidence::Confirmed,
        remediation,
    )
}

fn push_unique(out: &mut Vec<LocalStaticFinding>, hit: LocalStaticFinding) {
    if !out
        .iter()
        .any(|x| x.rule_id == hit.rule_id && x.line == hit.line)
    {
        out.push(hit);
    }
}

/// Scans GraphQL/WebSocket/gRPC protocol security, AI/LLM prompt-to-tool execution,
/// OAuth2 PKCE/state/redirect validation, HTTP CRLF/Host poisoning, and workflow state-machine transitions.
pub fn scan_protocols_ai_and_workflow(
    rel_path: &str,
    language: Language,
    content: &str,
) -> Vec<LocalStaticFinding> {
    if !matches!(
        language,
        Language::TypeScript
            | Language::JavaScript
            | Language::Python
            | Language::Go
            | Language::Rust
            | Language::Java
            | Language::CSharp
            | Language::Php
            | Language::Ruby
    ) {
        return Vec::new();
    }

    let cleaned = crate::taint::strip_comments_simple(content);
    let lines: Vec<&str> = cleaned
        .lines()
        .map(|l| {
            if crate::taint::is_pattern_matcher_or_doc_line(l) {
                ""
            } else {
                l
            }
        })
        .collect();
    let low_full = lines.join("\n").to_ascii_lowercase();
    let mut out = Vec::new();

    scan_graphql_ws_grpc(rel_path, &lines, &low_full, &mut out);
    scan_ai_prompt_and_agent_tools(rel_path, &lines, &low_full, &mut out);
    scan_oauth_pkce_state_redirect(rel_path, &lines, &low_full, &mut out);
    scan_http_crlf_and_host_poisoning(rel_path, &lines, &mut out);
    scan_workflow_state_machine(rel_path, &lines, &mut out);

    out
}

fn block_window(lines: &[&str], center_idx: usize, before: usize, after: usize) -> String {
    let start = center_idx.saturating_sub(before);
    let end = (center_idx + after + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn scan_graphql_ws_grpc(
    rel_path: &str,
    lines: &[&str],
    low_full: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    // 1. GraphQL Server setup checks
    let is_gql_server = low_full.contains("apolloserver")
        || low_full.contains("createyoga(")
        || low_full.contains("graphqlhttp(")
        || low_full.contains("buildschema(")
        || low_full.contains("makexecutable");

    if is_gql_server {
        for (idx, line) in lines.iter().enumerate() {
            let low = line.to_ascii_lowercase();
            if low.contains("introspection:") && low.contains("true") {
                let win_low = block_window(lines, idx, 3, 3).to_ascii_lowercase();
                let gated_env = win_low.contains("node_env")
                    || win_low.contains("is_dev")
                    || win_low.contains("isdev")
                    || win_low.contains("!== 'production'")
                    || win_low.contains("!== \"production\"");
                if !gated_env {
                    push_unique(
                        out,
                        mk_finding_conf(
                            "SMG-API-001",
                            "MEDIUM",
                            "GraphQL introspection unconditionally enabled in server configuration"
                                .into(),
                            rel_path,
                            idx + 1,
                            "graphql-introspection",
                            SinkKind::Misconfiguration,
                            GuardKind::ConfigPolicy,
                            Confidence::Heuristic,
                            "Disable `introspection` in production (`introspection: process.env.NODE_ENV !== 'production'`).",
                        ),
                    );
                }
            }

            if low.contains("new apolloserver(")
                || low.contains("createyoga(")
                || low.contains("graphqlhttp(")
            {
                let win_low = block_window(lines, idx, 6, 12).to_ascii_lowercase();
                let has_depth_guard = win_low.contains("depthlimit")
                    || win_low.contains("depth_limit")
                    || win_low.contains("maxdepth")
                    || win_low.contains("max_depth")
                    || win_low.contains("costlimit")
                    || win_low.contains("querycomplexity")
                    || win_low.contains("validationrules");
                if !has_depth_guard {
                    push_unique(
                        out,
                        mk_finding_conf(
                            "SMG-API-001",
                            "HIGH",
                            "GraphQL server lacks query depth or complexity limiting (`depthLimit` / `validationRules`)"
                                .into(),
                            rel_path,
                            idx + 1,
                            "graphql-depth",
                            SinkKind::Misconfiguration,
                            GuardKind::ConfigPolicy,
                            Confidence::Heuristic,
                            "Add query depth & complexity guards (e.g. `validationRules: [depthLimit(7)]`) to prevent deeply nested DoS queries.",
                        ),
                    );
                }
            }
        }
    }

    // 2. WebSocket unauthenticated message/connection handlers hitting dangerous sinks
    let has_global_ws_auth = low_full.contains("verifyclient")
        || low_full.contains("io.use(")
        || low_full.contains("ws.use(");
    for (idx, line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        let is_ws_handler = (low.contains("wss.on(")
            || low.contains("ws.on(")
            || low.contains("io.on(")
            || low.contains("socket.on("))
            && (low.contains("'message'")
                || low.contains("\"message\"")
                || low.contains("'connection'")
                || low.contains("\"connection\"")
                || low.contains("'exec'")
                || low.contains("\"exec\"")
                || low.contains("'run'")
                || low.contains("\"run\""));
        if is_ws_handler {
            let win_low = block_window(lines, idx, 4, 14).to_ascii_lowercase();
            let has_sink = win_low.contains("exec(")
                || win_low.contains("execsync(")
                || win_low.contains("eval(")
                || win_low.contains("db.query(")
                || win_low.contains("fs.writefile")
                || win_low.contains("subprocess.");
            let has_auth = has_global_ws_auth
                || win_low.contains("jwt.verify")
                || win_low.contains("requireauth")
                || win_low.contains("verifytoken")
                || win_low.contains("handshake.auth")
                || win_low.contains("req.session")
                || win_low.contains("authenticate")
                || win_low.contains("isauthenticated");
            if has_sink && !has_auth {
                push_unique(
                    out,
                    mk_finding(
                        "SMG-API-001",
                        "CRITICAL",
                        "WebSocket handler executes privileged sink without connection/message authentication".into(),
                        rel_path,
                        idx + 1,
                        "websocket-handler",
                        SinkKind::AuthMutation,
                        GuardKind::Auth,
                        "Authenticate WebSocket handshakes (`verifyClient` / `io.use` / `jwt.verify`) and validate every incoming message payload schema.",
                    ),
                );
            }
        }
    }

    // 3. gRPC unauthenticated service handler mutating DB/system
    if low_full.contains("grpc.")
        || low_full.contains("grpcmethod")
        || low_full.contains("serverinterceptor")
    {
        let has_interceptor = low_full.contains("authinterceptor")
            || low_full.contains("grpcauthguard")
            || low_full.contains("serverinterceptor")
            || low_full.contains("jwt.verify")
            || low_full.contains("metadata.get('authorization')")
            || low_full.contains("metadata.get(\"authorization\")");
        for (idx, line) in lines.iter().enumerate() {
            let low = line.to_ascii_lowercase();
            if (low.contains("addservice(") || low.contains("@grpcmethod") || low.contains("rpc "))
                && !has_interceptor
            {
                let win_low = block_window(lines, idx, 2, 12).to_ascii_lowercase();
                if win_low.contains("exec(")
                    || win_low.contains("db.query")
                    || win_low.contains("delete")
                    || win_low.contains("update")
                {
                    push_unique(
                        out,
                        mk_finding(
                            "SMG-API-001",
                            "HIGH",
                            "gRPC service exposes mutating RPC without metadata auth interceptor"
                                .into(),
                            rel_path,
                            idx + 1,
                            "grpc-service",
                            SinkKind::AuthMutation,
                            GuardKind::Auth,
                            "Enforce metadata token validation in a gRPC server interceptor (`metadata.get('authorization')`) before executing service methods.",
                        ),
                    );
                }
            }
        }
    }
}

fn ai_ident_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\b").expect("valid ident"))
}

fn scan_ai_prompt_and_agent_tools(
    rel_path: &str,
    lines: &[&str],
    low_full: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let uses_ai = low_full.contains("openai")
        || low_full.contains("anthropic")
        || low_full.contains("chat.completions")
        || low_full.contains("messages.create")
        || low_full.contains("generatetext(")
        || low_full.contains("choices[0].message")
        || low_full.contains("llm")
        || low_full.contains("modeloutput")
        || low_full.contains("agentreply")
        || low_full.contains("ragcontext")
        || low_full.contains("toolcall");
    if !uses_ai {
        return;
    }

    let mut ai_vars: HashSet<String> = HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();

        // Track variables assigned directly from LLM completion / tool call output / RAG snippet
        if let Some((lhs, rhs)) = trimmed.split_once('=')
            && !lhs.contains("==")
            && !lhs.contains("!=")
        {
            let rhs_low = rhs.to_ascii_lowercase();
            let is_ai_rhs = rhs_low.contains("choices[0].message")
                || rhs_low.contains("completion.")
                || rhs_low.contains("chat.completions")
                || rhs_low.contains("messages.create")
                || rhs_low.contains("generatetext(")
                || rhs_low.contains("llm.")
                || rhs_low.contains("modeloutput")
                || rhs_low.contains("toolcall.function.arguments")
                || rhs_low.contains("airesponse")
                || rhs_low.contains("ragcontext");
            let is_sanitized_rhs = rhs_low.contains("allowlist")
                || rhs_low.contains("allowed_tools")
                || rhs_low.contains("allowedtools")
                || rhs_low.contains("safeparse(")
                || rhs_low.contains("requireconfirmation(")
                || rhs_low.contains("humanapproval(");
            if let Some(var) = lhs
                .split_whitespace()
                .last()
                .map(|v| v.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_'))
                && !var.is_empty()
            {
                if is_ai_rhs && !is_sanitized_rhs {
                    ai_vars.insert(var.to_string());
                } else if is_sanitized_rhs {
                    ai_vars.remove(var);
                }
            }
        }

        // Unbounded agent tool execution loop (`while (...) { runTool / executeTool ... }`)
        if (low.starts_with("while ") || low.starts_with("while("))
            && !low.contains("max_steps")
            && !low.contains("maxsteps")
            && !low.contains("max_iter")
            && !low.contains("maxiterations")
            && !low.contains("steps <")
        {
            let win_low = block_window(lines, idx, 1, 10).to_ascii_lowercase();
            if (win_low.contains("executetool")
                || win_low.contains("runtool")
                || win_low.contains("toolcall"))
                && !win_low.contains("max_steps")
                && !win_low.contains("maxsteps")
                && !win_low.contains("maxiterations")
                && !win_low.contains("steps >= ")
                && !win_low.contains("step >= ")
            {
                push_unique(
                    out,
                    mk_finding_conf(
                        "SMG-AI-001",
                        "HIGH",
                        "Agent tool-calling loop lacks bounded step/iteration limit (`maxSteps`)"
                            .into(),
                        rel_path,
                        idx + 1,
                        "agent-tool-loop",
                        SinkKind::CommandInjection,
                        GuardKind::CmdSanitizer,
                        Confidence::Heuristic,
                        "Enforce an explicit `maxSteps` iteration cap, tool allowlist, and user confirmation before running side-effecting agent actions.",
                    ),
                );
            }
        }

        // Unsanitized LLM output flowing into eval / shell exec / raw SQL
        let is_code_or_cmd_sink = low.contains("eval(")
            || low.contains("new function(")
            || low.contains("execsync(")
            || low.contains("child_process.exec(")
            || low.contains("os.system(")
            || low.contains("subprocess.run(")
            || low.contains("vm.runinnewcontext(");
        let is_raw_sql_sink = (low.contains("db.query(")
            || low.contains("$queryrawunsafe(")
            || low.contains("cursor.execute("))
            && !low.contains("$1")
            && !low.contains("?");
        if !(is_code_or_cmd_sink || is_raw_sql_sink) {
            continue;
        }

        let rhs_ref_ai_var = ai_ident_re()
            .captures_iter(trimmed)
            .any(|cap| ai_vars.contains(&cap[1]));
        let inline_ai_expr = low.contains("choices[0].message")
            || low.contains("modeloutput")
            || low.contains("agentreply")
            || low.contains("generatedsql")
            || low.contains("generatedcode")
            || low.contains("completion.content");
        if !(rhs_ref_ai_var || inline_ai_expr) {
            continue;
        }

        let win_low = block_window(lines, idx, 5, 2).to_ascii_lowercase();
        let has_guard = win_low.contains("allowlist")
            || win_low.contains("allowed_tools")
            || win_low.contains("allowedtools")
            || win_low.contains("requireconfirmation")
            || win_low.contains("humanapproval")
            || win_low.contains("readonly_role")
            || win_low.contains("safeparse(");
        if !has_guard {
            push_unique(
                out,
                mk_finding(
                    "SMG-AI-001",
                    "CRITICAL",
                    "Unsanitized LLM/agent output executed directly as code, shell command, or raw SQL".into(),
                    rel_path,
                    idx + 1,
                    "llm-output-sink",
                    SinkKind::CommandInjection,
                    GuardKind::CmdSanitizer,
                    "Never pass LLM output to `eval`, shell `exec`, or raw SQL; restrict agents to an explicit allowlisted structured tool schema and require confirmation for state mutations.",
                ),
            );
        }
    }
}

fn scan_oauth_pkce_state_redirect(
    rel_path: &str,
    lines: &[&str],
    low_full: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let is_oauth = low_full.contains("response_type=code")
        || low_full.contains("response_type: 'code'")
        || low_full.contains("response_type: \"code\"")
        || low_full.contains("oauth2")
        || low_full.contains("/oauth/authorize")
        || low_full.contains("authorization_code");
    if !is_oauth {
        return;
    }

    for (idx, line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        // OAuth2 Authorization URL construction without `state` or `code_challenge` (PKCE)
        if low.contains("response_type")
            && low.contains("code")
            && (low.contains("authorize")
                || low.contains("client_id")
                || block_window(lines, idx, 4, 4)
                    .to_ascii_lowercase()
                    .contains("client_id"))
        {
            let win_low = block_window(lines, idx, 6, 8).to_ascii_lowercase();
            let has_state = win_low.contains("state:")
                || win_low.contains("state=")
                || win_low.contains("'state'");
            let has_pkce = win_low.contains("code_challenge");
            if !has_state || !has_pkce {
                push_unique(
                    out,
                    mk_finding_conf(
                        "SMG-AUTH-PKCE",
                        "HIGH",
                        "OAuth2 authorization flow missing PKCE (`code_challenge`) or CSRF `state` binding".into(),
                        rel_path,
                        idx + 1,
                        "oauth-authorize",
                        SinkKind::AuthMutation,
                        GuardKind::Auth,
                        Confidence::Heuristic,
                        "Generate cryptographic per-session `state` and PKCE `code_challenge` (`S256`) on authorize requests, and verify `state` & `code_verifier` on callback.",
                    ),
                );
            }
        }

        // Unvalidated `redirect_uri` from request query/body passed into OAuth redirect/url builder
        if (low.contains("req.query.redirect_uri")
            || low.contains("req.body.redirect_uri")
            || low.contains("request.args.get('redirect_uri')")
            || low.contains("request.args.get(\"redirect_uri\")"))
            && !block_window(lines, idx, 4, 6)
                .to_ascii_lowercase()
                .contains("allowlist")
            && !block_window(lines, idx, 4, 6)
                .to_ascii_lowercase()
                .contains("allowed_redirect")
            && !block_window(lines, idx, 4, 6)
                .to_ascii_lowercase()
                .contains("allowedredirect")
        {
            push_unique(
                out,
                mk_finding(
                    "SMG-AUTH-PKCE",
                    "HIGH",
                    "OAuth `redirect_uri` taken directly from request input without exact allowlist check".into(),
                    rel_path,
                    idx + 1,
                    "oauth-redirect-uri",
                    SinkKind::AuthMutation,
                    GuardKind::Auth,
                    "Validate OAuth `redirect_uri` against a strict exact-match allowlist of pre-registered callback URLs.",
                ),
            );
        }
    }
}

fn scan_http_crlf_and_host_poisoning(
    rel_path: &str,
    lines: &[&str],
    out: &mut Vec<LocalStaticFinding>,
) {
    for (idx, line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        // 1. CRLF Header Injection (`Set-Cookie`, `Location`, etc. with req input)
        let is_header_sink = low.contains("setheader(")
            || low.contains(".header(")
            || low.contains("header().set(")
            || low.contains("res.set(")
            || low.contains("res.redirect(");
        let has_req_input = low.contains("req.query")
            || low.contains("req.params")
            || low.contains("req.body")
            || low.contains("request.args")
            || low.contains("r.url.query");
        if is_header_sink && has_req_input {
            let win_low = block_window(lines, idx, 5, 2).to_ascii_lowercase();
            let strips_crlf = win_low.contains("\\r")
                || win_low.contains("\\n")
                || win_low.contains("encodeuricomponent(")
                || win_low.contains("allowlist");
            if !strips_crlf
                && !low.starts_with("res.redirect('/")
                && !low.starts_with("res.redirect(\"/")
            {
                push_unique(
                    out,
                    mk_finding(
                        "SMG-HTTP-SMUGGLE",
                        "HIGH",
                        "Unsanitized request input written into HTTP response header or redirect (CRLF / header injection risk)".into(),
                        rel_path,
                        idx + 1,
                        "http-header-crlf",
                        SinkKind::Misconfiguration,
                        GuardKind::ConfigPolicy,
                        "Reject or strip `\\r`/`\\n` control characters from response header values and validate redirects against relative paths or an allowlist.",
                    ),
                );
            }
        }

        // 2. Host / X-Forwarded-Host header poisoning in password-reset / magic links
        let uses_untrusted_host = low.contains("req.headers.host")
            || low.contains("req.headers['host']")
            || low.contains("req.headers['x-forwarded-host']")
            || low.contains("req.headers[\"x-forwarded-host\"]")
            || low.contains("request.host");
        if uses_untrusted_host {
            let win_low = block_window(lines, idx, 5, 6).to_ascii_lowercase();
            let is_sensitive_link = win_low.contains("reset")
                || win_low.contains("forgot")
                || win_low.contains("magic")
                || win_low.contains("invite")
                || win_low.contains("verify-email")
                || win_low.contains("token=");
            let has_host_allowlist = win_low.contains("allowed_hosts")
                || win_low.contains("allowedhosts")
                || win_low.contains("allowlist")
                || win_low.contains("app_url")
                || win_low.contains("public_url");
            if is_sensitive_link && !has_host_allowlist {
                push_unique(
                    out,
                    mk_finding(
                        "SMG-HTTP-SMUGGLE",
                        "HIGH",
                        "Untrusted HTTP `Host` / `X-Forwarded-Host` header used to construct security-sensitive URL".into(),
                        rel_path,
                        idx + 1,
                        "host-header-poisoning",
                        SinkKind::Misconfiguration,
                        GuardKind::ConfigPolicy,
                        "Build password-reset and verification URLs from a fixed trusted `APP_URL` environment variable or validate `Host` against an explicit allowlist.",
                    ),
                );
            }
        }
    }
}

fn scan_workflow_state_machine(rel_path: &str, lines: &[&str], out: &mut Vec<LocalStaticFinding>) {
    for (idx, line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        let is_workflow_op = (low.contains("function shiporder")
            || low.contains("function fulfillorder")
            || low.contains("function releasepayout")
            || low.contains("function processrefund")
            || low.contains("function grantentitlement")
            || low.contains("'/ship'")
            || low.contains("\"/ship\"")
            || low.contains("'/fulfill'")
            || low.contains("\"/fulfill\"")
            || low.contains("'/payout/release'")
            || low.contains("\"/payout/release\"")
            || low.contains("set status = 'shipped'")
            || low.contains("set status = 'completed'")
            || low.contains("set status = 'refunded'")
            || low.contains("status: 'shipped'")
            || low.contains("status: 'completed'")
            || low.contains("status: 'released'"))
            && !low.starts_with("//");
        if !is_workflow_op {
            continue;
        }

        let win_low = block_window(lines, idx, 4, 14).to_ascii_lowercase();
        let mutates_state = win_low.contains("update ")
            || win_low.contains(".update(")
            || win_low.contains("status =")
            || win_low.contains("status:");
        let checks_prior_state = win_low.contains(".status ==")
            || win_low.contains(".status ===")
            || win_low.contains(".status !=")
            || win_low.contains(".status !==")
            || win_low.contains("and status =")
            || win_low.contains("and status in")
            || win_low.contains("allowed_transitions")
            || win_low.contains("cantransition")
            || win_low.contains("order.paid")
            || win_low.contains(".state ===");
        if mutates_state && !checks_prior_state {
            push_unique(
                out,
                mk_finding_conf(
                    "SMG-STATE-001",
                    "HIGH",
                    "Workflow state transition mutates fulfillment/payout/refund status without asserting prerequisite state".into(),
                    rel_path,
                    idx + 1,
                    "workflow-state-transition",
                    SinkKind::BalanceUpdate,
                    GuardKind::InputValidation,
                    Confidence::Heuristic,
                    "Enforce an explicit finite-state transition guard (`if (order.status !== 'PAID') throw ...` AND atomic `WHERE id = $1 AND status = 'PAID'`) before granting fulfillment or payout.",
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave3b_positive_and_negative_rules() {
        let vuln_gql_ws = r#"
const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
wss.on('connection', (ws) => {
  ws.on('message', (msg) => execSync(msg.toString()));
});
"#;
        let safe_gql_ws = r#"
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  validationRules: [depthLimit(6)],
});
const wss = new WebSocketServer({ verifyClient: checkJwt });
wss.on('connection', (ws, req) => {
  ws.on('message', (msg) => { jwt.verify(msg.token, SECRET); console.log(msg); });
});
"#;
        let vh = scan_protocols_ai_and_workflow("src/api.ts", Language::TypeScript, vuln_gql_ws);
        let sh = scan_protocols_ai_and_workflow("src/api.ts", Language::TypeScript, safe_gql_ws);
        assert!(vh.iter().filter(|h| h.rule_id == "SMG-API-001").count() >= 2);
        assert!(
            !sh.iter().any(|h| h.rule_id == "SMG-API-001"),
            "Hardened GraphQL/WS must not fire SMG-API-001: {:?}",
            sh
        );

        let vuln_ai = r#"
import OpenAI from 'openai';
async function runAgent(prompt) {
  const res = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });
  const sql = res.choices[0].message.content;
  return db.query(sql);
}
"#;
        let safe_ai = r#"
import OpenAI from 'openai';
async function runAgent(prompt) {
  const ALLOWED_TOOLS = { lookup: true };
  const res = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });
  const call = ToolSchema.safeParse(res.choices[0].message);
  if (ALLOWED_TOOLS[call.tool]) return db.query('SELECT * FROM items WHERE id = $1', [call.id]);
}
"#;
        assert!(
            scan_protocols_ai_and_workflow("src/agent.ts", Language::TypeScript, vuln_ai)
                .iter()
                .any(|h| h.rule_id == "SMG-AI-001")
        );
        assert!(
            !scan_protocols_ai_and_workflow("src/agent.ts", Language::TypeScript, safe_ai)
                .iter()
                .any(|h| h.rule_id == "SMG-AI-001")
        );

        let vuln_oauth = r#"
const url = `https://idp.example.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=${req.query.redirect_uri}`;
"#;
        let safe_oauth = r#"
const ALLOWED_REDIRECT_URIS = ['https://app.example.com/cb'];
const url = `https://idp.example.com/oauth/authorize?response_type=code&client_id=abc&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`;
"#;
        assert!(
            scan_protocols_ai_and_workflow("src/oauth.ts", Language::TypeScript, vuln_oauth)
                .iter()
                .any(|h| h.rule_id == "SMG-AUTH-PKCE")
        );
        assert!(
            !scan_protocols_ai_and_workflow("src/oauth.ts", Language::TypeScript, safe_oauth)
                .iter()
                .any(|h| h.rule_id == "SMG-AUTH-PKCE")
        );

        let vuln_smuggle = r#"
function resetPassword(req, res) {
  res.setHeader('Location', req.query.next);
  return `https://${req.headers['x-forwarded-host']}/reset?token=${tok}`;
}
"#;
        let safe_smuggle = r#"
function resetPassword(req, res) {
  const next = encodeURIComponent(String(req.query.next || ''));
  res.setHeader('Location', next);
  return `${process.env.APP_URL}/reset?token=${tok}`;
}
"#;
        assert!(
            scan_protocols_ai_and_workflow("src/reset.ts", Language::TypeScript, vuln_smuggle)
                .iter()
                .any(|h| h.rule_id == "SMG-HTTP-SMUGGLE")
        );
        assert!(
            !scan_protocols_ai_and_workflow("src/reset.ts", Language::TypeScript, safe_smuggle)
                .iter()
                .any(|h| h.rule_id == "SMG-HTTP-SMUGGLE")
        );

        let vuln_state = r#"
async function shipOrder(req, db) {
  await db.query("UPDATE orders SET status = 'SHIPPED' WHERE id = $1", [req.params.id]);
}
"#;
        let safe_state = r#"
async function shipOrder(req, db) {
  const order = await db.findOne(req.params.id);
  if (order.status !== 'PAID') throw new Error('Must be paid before shipping');
  await db.query("UPDATE orders SET status = 'SHIPPED' WHERE id = $1 AND status = 'PAID'", [req.params.id]);
}
"#;
        assert!(
            scan_protocols_ai_and_workflow("src/orders.ts", Language::TypeScript, vuln_state)
                .iter()
                .any(|h| h.rule_id == "SMG-STATE-001")
        );
        assert!(
            !scan_protocols_ai_and_workflow("src/orders.ts", Language::TypeScript, safe_state)
                .iter()
                .any(|h| h.rule_id == "SMG-STATE-001")
        );
    }
}
