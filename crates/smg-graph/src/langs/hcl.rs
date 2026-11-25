use crate::ast::{
    Confidence, GuardKind, ImportRef, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    node_text,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

use super::{ExtractContext, strip_quotes};

const SENSITIVE_PORTS: &[u16] = &[22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017];
const MAX_HCL_NESTED_DEPTH: usize = 16;

#[derive(Default, Clone)]
pub(crate) struct WorkspaceHclVars {
    /// Cross-file `var.<name>` defaults and `*.tfvars` overrides.
    pub var_defaults: HashMap<String, String>,
    /// S3 bucket resource names protected by an `aws_s3_bucket_public_access_block` anywhere in the repo.
    pub protected_s3_buckets: HashSet<String>,
}

static WORKSPACE_HCL_VARS: std::sync::RwLock<Option<WorkspaceHclVars>> =
    std::sync::RwLock::new(None);

/// Pre-collects `variable "<name>" { default = ... }`, `*.tfvars` key-values, and
/// `aws_s3_bucket_public_access_block` resources across all `.tf`/`.tfvars`/`.hcl` files
/// in the scanned workspace so cross-file `var.xyz` references and S3 public-access blocks resolve.
pub(crate) fn set_workspace_hcl_vars(files: &[smg_core::IndexedFile]) {
    let mut ws = WorkspaceHclVars::default();
    let mut tfvars_overrides: HashMap<String, String> = HashMap::new();
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = tree_sitter_hcl::LANGUAGE.into();
    let _ = parser.set_language(&lang);

    for f in files {
        let low = f.rel_path.to_ascii_lowercase();
        let is_tf_or_hcl = low.ends_with(".tf") || low.ends_with(".hcl");
        let is_tfvars = low.ends_with(".tfvars") || low.ends_with(".auto.tfvars.json");
        if !is_tf_or_hcl && !is_tfvars {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&f.abs_path) else {
            continue;
        };
        if low.ends_with(".auto.tfvars.json") {
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(&content) {
                for (k, v) in map {
                    let val_str = match v {
                        serde_json::Value::String(s) => format!("\"{s}\""),
                        other => other.to_string(),
                    };
                    tfvars_overrides.insert(format!("var.{}", k.to_ascii_lowercase()), val_str);
                }
            }
            continue;
        }
        if low.ends_with(".tfvars") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_ascii_lowercase();
                    let val = v.trim().trim_end_matches(',').to_string();
                    if !key.is_empty() && !val.is_empty() {
                        tfvars_overrides.insert(format!("var.{key}"), val);
                    }
                }
            }
            continue;
        }
        if let Some(tree) = parser.parse(&content, None) {
            let mut file_g = HclFileGraph::default();
            collect_hcl_file_graph(tree.root_node(), content.as_bytes(), &mut file_g, 0);
            for (k, v) in file_g.var_defaults {
                if k.starts_with("var.") {
                    ws.var_defaults.insert(k, v);
                }
            }
            ws.protected_s3_buckets.extend(file_g.protected_s3_buckets);
        }
    }
    // `.tfvars` overrides take precedence over `variable { default = ... }`
    ws.var_defaults.extend(tfvars_overrides);

    if let Ok(mut guard) = WORKSPACE_HCL_VARS.write() {
        *guard = Some(ws);
    }
}

pub(crate) fn clear_workspace_hcl_vars() {
    if let Ok(mut guard) = WORKSPACE_HCL_VARS.write() {
        *guard = None;
    }
}

#[derive(Default)]
struct HclFileGraph {
    /// `var.<name>` and `local.<name>` resolved default/literal values.
    var_defaults: HashMap<String, String>,
    /// S3 bucket resource names protected by an `aws_s3_bucket_public_access_block` with all 4 flags = true.
    protected_s3_buckets: HashSet<String>,
}

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    let mut graph = HclFileGraph::default();
    if let Ok(guard) = WORKSPACE_HCL_VARS.read()
        && let Some(ref ws) = *guard
    {
        graph.var_defaults.extend(ws.var_defaults.clone());
        graph
            .protected_s3_buckets
            .extend(ws.protected_s3_buckets.iter().cloned());
    }
    collect_hcl_file_graph(root, ctx.src, &mut graph, 0);
    walk_hcl_blocks(root, ctx, &graph, 0);
}

fn collect_hcl_file_graph(node: Node, src: &[u8], graph: &mut HclFileGraph, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "block" {
        let (btype, labels) = block_header(node, src);
        if let Some(body) = find_block_body(node) {
            let raw_attrs = collect_body_attrs(body, src);
            if btype == "variable"
                && let Some(vname) = labels.first()
                && let Some(def_val) = raw_attrs.get("default")
            {
                graph.var_defaults.insert(
                    format!("var.{}", vname.to_ascii_lowercase()),
                    def_val.clone(),
                );
            } else if btype == "locals" {
                for (k, v) in raw_attrs {
                    graph.var_defaults.insert(format!("local.{}", k), v);
                }
            } else if btype == "resource"
                && labels.first().map(String::as_str) == Some("aws_s3_bucket_public_access_block")
            {
                let disabled_by_count = raw_attrs
                    .get("count")
                    .is_some_and(|c| strip_quotes(c).trim() == "0");
                let all_four_true = !disabled_by_count
                    && [
                        "block_public_acls",
                        "block_public_policy",
                        "ignore_public_acls",
                        "restrict_public_buckets",
                    ]
                    .iter()
                    .all(|k| attr_is_bool(&raw_attrs, k, true));
                if all_four_true && let Some(bkt_ref) = raw_attrs.get("bucket") {
                    // Extract `my_bkt` from `aws_s3_bucket.my_bkt.id` or `"my_bkt"`
                    let clean = strip_quotes(bkt_ref);
                    if let Some(rest) = clean.strip_prefix("aws_s3_bucket.")
                        && let Some(bname) = rest.split('.').next()
                    {
                        graph.protected_s3_buckets.insert(bname.to_string());
                    } else if !clean.is_empty() {
                        graph.protected_s3_buckets.insert(clean);
                    }
                }
            }
        }
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_hcl_file_graph(ch, src, graph, depth + 1);
    }
}

fn walk_hcl_blocks(node: Node, ctx: &mut ExtractContext<'_>, graph: &HclFileGraph, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if node.kind() == "block" {
        analyze_top_block(node, ctx, graph);
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_hcl_blocks(ch, ctx, graph, depth + 1);
    }
}

fn block_header(node: Node, src: &[u8]) -> (String, Vec<String>) {
    let mut kind = String::new();
    let mut labels = Vec::new();
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "identifier" => {
                if kind.is_empty() {
                    kind = node_text(ch, src).trim().to_string();
                } else {
                    labels.push(strip_quotes(node_text(ch, src)));
                }
            }
            "string_lit" => {
                let s = strip_quotes(node_text(ch, src));
                if !s.is_empty() {
                    labels.push(s);
                }
            }
            "body" | "block_start" | "block_end" => break,
            _ => {}
        }
    }
    (kind, labels)
}

fn collect_body_attrs(body: Node, src: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut c = body.walk();
    for ch in body.children(&mut c) {
        if ch.kind() == "attribute" {
            let mut key = None;
            let mut val = None;
            let mut ac = ch.walk();
            for part in ch.children(&mut ac) {
                match part.kind() {
                    "identifier" if key.is_none() => {
                        key = Some(node_text(part, src).trim().to_ascii_lowercase());
                    }
                    "expression" => {
                        val = Some(
                            crate::ast::strip_comments(node_text(part, src))
                                .trim()
                                .to_string(),
                        );
                    }
                    _ => {}
                }
            }
            if let (Some(k), Some(v)) = (key, val) {
                map.insert(k, v);
            }
        }
    }
    map
}

fn collect_resolved_body_attrs(
    body: Node,
    src: &[u8],
    var_defaults: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut attrs = collect_body_attrs(body, src);
    for val in attrs.values_mut() {
        for _ in 0..4 {
            let key_low = val.trim().to_ascii_lowercase();
            if let Some(resolved) = var_defaults.get(&key_low) {
                if resolved == val {
                    break;
                }
                *val = resolved.clone();
            } else {
                break;
            }
        }
    }
    attrs
}

fn find_block_body(block: Node) -> Option<Node> {
    block.child_by_field_name("body").or_else(|| {
        let mut c = block.walk();
        block.children(&mut c).find(|ch| ch.kind() == "body")
    })
}

fn collect_nested_blocks(body: Node) -> Vec<Node> {
    collect_nested_blocks_depth(body, 0)
}

fn collect_nested_blocks_depth(body: Node, depth: usize) -> Vec<Node> {
    if depth >= MAX_HCL_NESTED_DEPTH {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut c = body.walk();
    for ch in body.children(&mut c) {
        if ch.kind() == "block" {
            out.push(ch);
        } else if ch.kind() == "body" {
            out.extend(collect_nested_blocks_depth(ch, depth + 1));
        }
    }
    out
}

fn analyze_top_block(block: Node, ctx: &mut ExtractContext<'_>, graph: &HclFileGraph) {
    let (block_type, labels) = block_header(block, ctx.src);
    let Some(body) = find_block_body(block) else {
        return;
    };
    let attrs = collect_resolved_body_attrs(body, ctx.src, &graph.var_defaults);
    let line = block.start_position().row + 1;
    let end_line = block.end_position().row + 1;

    if block_type == "module" {
        let mod_name = labels
            .first()
            .cloned()
            .unwrap_or_else(|| "module".to_string());
        if let Some(raw_src) = attrs.get("source") {
            let clean_src = strip_quotes(raw_src);
            if !clean_src.is_empty()
                && (clean_src.starts_with('.')
                    || (!clean_src.contains("registry.terraform.io")
                        && !clean_src.contains("://")
                        && !clean_src.starts_with("git::")))
            {
                ctx.imports.push(ImportRef {
                    symbol_name: "*".to_string(),
                    from_specifier: format!("hcl::{}", clean_src),
                    remote_name: None,
                });
            }
        }
        ctx.symbols.push(SymbolInfo {
            id: format!("hcl:{}:module.{}:{}", ctx.rel_path, mod_name, line),
            rel_path: ctx.rel_path.to_string(),
            name: format!("module.{}", mod_name),
            kind: SymbolKind::Function,
            line_start: line,
            line_end: end_line,
            ..Default::default()
        });
        return;
    }

    if !matches!(block_type.as_str(), "resource" | "data") {
        return;
    }

    let res_type = labels.first().cloned().unwrap_or_default();
    let res_name = labels.get(1).cloned().unwrap_or_default();
    let sym_name = if res_name.is_empty() {
        res_type.clone()
    } else {
        format!("{}.{}", res_type, res_name)
    };

    // Extract cross-resource reference edges (`aws_security_group.web`, `aws_s3_bucket.logs`, `module.vpc`)
    let mut ref_calls = Vec::new();
    for v in attrs.values() {
        for tok in v.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.') {
            let parts: Vec<&str> = tok.split('.').collect();
            if parts.len() >= 2
                && (parts[0].starts_with("aws_")
                    || parts[0].starts_with("google_")
                    || parts[0].starts_with("azurerm_")
                    || parts[0] == "module")
            {
                let target = format!("{}.{}", parts[0], parts[1]);
                if target != sym_name && !ref_calls.contains(&target) {
                    ref_calls.push(target);
                }
            }
        }
    }

    ctx.symbols.push(SymbolInfo {
        id: format!("hcl:{}:{}:{}", ctx.rel_path, sym_name, line),
        rel_path: ctx.rel_path.to_string(),
        name: sym_name.clone(),
        kind: SymbolKind::Function,
        line_start: line,
        line_end: end_line,
        calls: ref_calls,
        ..Default::default()
    });

    // 1. Public Storage / Database Exposure (`SMG-CFG-IAC-PUBLIC`)
    check_public_exposure(
        ctx, &res_type, &res_name, &sym_name, line, body, &attrs, graph,
    );

    // 2. Public Network Ingress (`SMG-CFG-IAC-NET`)
    check_network_exposure(ctx, &res_type, &sym_name, line, body, &attrs, graph);

    // 3. Encryption & TLS Posture (`SMG-CFG-IAC-CRYPTO`)
    check_crypto_posture(ctx, &res_type, &sym_name, line, body, &attrs, graph);

    // 4. Over-permissive IAM Policies (`SMG-CFG-IAC-IAM`)
    check_iam_wildcards(ctx, &res_type, &sym_name, line, body, &attrs, graph);

    // 5. Phase 23: Declarative Checkov-class Cloud/IaC Policy Pack (60 unique AWS/GCP/Azure policies)
    if block_type == "resource" {
        let mut nested_map: HashMap<String, Vec<HashMap<String, String>>> = HashMap::new();
        collect_nested_block_attrs(body, ctx.src, &graph.var_defaults, &mut nested_map, 0);
        let view = crate::iac_policy::HclResourceView {
            rel_path: ctx.rel_path,
            res_type: &res_type,
            res_name: &res_name,
            line,
            attrs: &attrs,
            nested: &nested_map,
        };
        for hit in crate::iac_policy::evaluate_hcl_resource_policies(&view) {
            let dup = ctx
                .static_findings
                .iter()
                .any(|e| e.rule_id == hit.rule_id && e.line == hit.line && e.title == hit.title);
            if !dup {
                ctx.static_findings.push(hit);
            }
        }
    }
}

fn collect_nested_block_attrs(
    body: Node,
    src: &[u8],
    var_defaults: &HashMap<String, String>,
    out: &mut HashMap<String, Vec<HashMap<String, String>>>,
    depth: usize,
) {
    if depth >= MAX_HCL_NESTED_DEPTH {
        return;
    }
    for nb in collect_nested_blocks(body) {
        let (nb_type, _) = block_header(nb, src);
        if let Some(nb_body) = find_block_body(nb) {
            let nb_attrs = collect_resolved_body_attrs(nb_body, src, var_defaults);
            out.entry(nb_type.to_ascii_lowercase())
                .or_default()
                .push(nb_attrs);
            // Bounded recursion for nested blocks (e.g., `settings { ip_configuration { ... } }`)
            collect_nested_block_attrs(nb_body, src, var_defaults, out, depth + 1);
        }
    }
}

fn push_iac_finding(
    ctx: &mut ExtractContext<'_>,
    rule_id: &str,
    severity: &str,
    title: String,
    line: usize,
    remediation: &str,
) {
    push_iac_finding_conf(
        ctx,
        rule_id,
        severity,
        title,
        line,
        Confidence::Confirmed,
        remediation,
    );
}

fn push_iac_finding_conf(
    ctx: &mut ExtractContext<'_>,
    rule_id: &str,
    severity: &str,
    title: String,
    line: usize,
    confidence: Confidence,
    remediation: &str,
) {
    ctx.static_findings.push(LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: ctx.rel_path.to_string(),
        line,
        symbol: format!("{}:{}", ctx.rel_path, line),
        sink_kind: SinkKind::Misconfiguration,
        missing_guard: GuardKind::ConfigPolicy,
        confidence,
        remediation: remediation.to_string(),
    });
}

fn attr_is_bool(attrs: &HashMap<String, String>, key: &str, expected: bool) -> bool {
    attrs.get(key).is_some_and(|v| {
        v.trim()
            .eq_ignore_ascii_case(if expected { "true" } else { "false" })
    })
}

#[allow(clippy::too_many_arguments)]
fn check_public_exposure(
    ctx: &mut ExtractContext<'_>,
    res_type: &str,
    res_name: &str,
    sym_name: &str,
    line: usize,
    body: Node,
    attrs: &HashMap<String, String>,
    graph: &HclFileGraph,
) {
    if res_type == "aws_lambda_function_url"
        && attrs
            .get("authorization_type")
            .is_some_and(|v| strip_quotes(v).eq_ignore_ascii_case("NONE"))
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-PUBLIC",
            "HIGH",
            format!(
                "AWS Lambda Function URL `{}` allows unauthenticated invocation (`NONE`)",
                sym_name
            ),
            line,
            "Require IAM authorization (`authorization_type = \"AWS_IAM\"`) or front behind authenticated API Gateway.",
        );
    }

    // `aws_instance` and `aws_launch_template` are checked by `iac_policy` (CKV_AWS_79 / CKV_AWS_8);
    // keep manual check for `aws_launch_configuration`.
    if res_type == "aws_launch_configuration" {
        for nested in collect_nested_blocks(body) {
            let (nt, _) = block_header(nested, ctx.src);
            if nt == "metadata_options"
                && let Some(nb) = find_block_body(nested)
            {
                let nattrs = collect_resolved_body_attrs(nb, ctx.src, &graph.var_defaults);
                if nattrs
                    .get("http_tokens")
                    .is_some_and(|v| strip_quotes(v).eq_ignore_ascii_case("optional"))
                {
                    push_iac_finding(
                        ctx,
                        "SMG-CFG-IAC-NET",
                        "HIGH",
                        format!(
                            "EC2 metadata allows IMDSv1 (`http_tokens = \"optional\"`) on `{}`",
                            sym_name
                        ),
                        nested.start_position().row + 1,
                        "Enforce IMDSv2 by setting `http_tokens = \"required\"` in `metadata_options`.",
                    );
                }
            }
        }
    }

    if res_type == "google_sql_database_instance" {
        for settings in collect_nested_blocks(body) {
            if block_header(settings, ctx.src).0 == "settings"
                && let Some(sb) = find_block_body(settings)
            {
                for ipc in collect_nested_blocks(sb) {
                    if block_header(ipc, ctx.src).0 == "ip_configuration"
                        && let Some(ib) = find_block_body(ipc)
                    {
                        for auth_net in collect_nested_blocks(ib) {
                            if block_header(auth_net, ctx.src).0 == "authorized_networks"
                                && let Some(ab) = find_block_body(auth_net)
                            {
                                let aattrs =
                                    collect_resolved_body_attrs(ab, ctx.src, &graph.var_defaults);
                                if aattrs
                                    .get("value")
                                    .is_some_and(|v| v.contains("0.0.0.0/0") || v.contains("::/0"))
                                {
                                    push_iac_finding(
                                        ctx,
                                        "SMG-CFG-IAC-PUBLIC",
                                        "CRITICAL",
                                        format!(
                                            "CloudSQL instance `{}` authorizes public `0.0.0.0/0` network access",
                                            sym_name
                                        ),
                                        auth_net.start_position().row + 1,
                                        "Remove `0.0.0.0/0` from `authorized_networks` and use Private Service Connect / Cloud SQL Proxy.",
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if matches!(
        res_type,
        "aws_s3_bucket_policy" | "aws_sqs_queue_policy" | "aws_sns_topic_policy" | "aws_kms_key"
    ) && let Some(pol) = attrs.get("policy")
    {
        let compact: String = pol
            .replace("\\\"", "\"")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let has_unrestricted_public_stmt =
            split_json_statement_objects(&compact)
                .into_iter()
                .any(|stmt| {
                    let has_wildcard_principal = stmt.contains("\"principal\":\"*\"")
                        || stmt.contains("\"principal\":{\"aws\":\"*\"}")
                        || stmt.contains("\"principal\":{\"aws\":[\"*\"]}");
                    has_wildcard_principal
                        && !stmt.contains("\"condition\"")
                        && !stmt.contains("\"effect\":\"deny\"")
                });
        if has_unrestricted_public_stmt {
            push_iac_finding(
                ctx,
                "SMG-CFG-IAC-PUBLIC",
                "CRITICAL",
                format!(
                    "Resource policy `{}` grants `Principal: \"*\"` without restricting `Condition`",
                    sym_name
                ),
                line,
                "Scope `Principal` to explicit IAM roles/accounts or enforce an `aws:PrincipalOrgID`/`aws:SourceArn` `Condition`.",
            );
        }
    }
    if matches!(res_type, "aws_s3_bucket" | "aws_s3_bucket_acl")
        && let Some(acl) = attrs.get("acl")
    {
        let clean = strip_quotes(acl).to_ascii_lowercase();
        let blocked_by_companion = graph.protected_s3_buckets.contains(res_name)
            || attrs.get("bucket").is_some_and(|b| {
                let cb = strip_quotes(b);
                cb.strip_prefix("aws_s3_bucket.")
                    .and_then(|r| r.split('.').next())
                    .is_some_and(|bn| graph.protected_s3_buckets.contains(bn))
                    || graph.protected_s3_buckets.contains(&cb)
            });
        if !blocked_by_companion
            && matches!(
                clean.as_str(),
                "public-read" | "public-read-write" | "authenticated-read"
            )
        {
            push_iac_finding(
                ctx,
                "SMG-CFG-IAC-PUBLIC",
                "CRITICAL",
                format!("Public S3 bucket ACL (`{}`) on `{}`", clean, sym_name),
                line,
                "Set S3 bucket ACL to `private` and enforce `aws_s3_bucket_public_access_block`.",
            );
        }
    }

    if res_type == "aws_s3_bucket_public_access_block"
        && ([
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ]
        .iter()
        .any(|k| attr_is_bool(attrs, k, false)))
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-PUBLIC",
            "HIGH",
            format!("S3 public access block disabled on `{}`", sym_name),
            line,
            "Set all four `aws_s3_bucket_public_access_block` flags to `true`.",
        );
    }

    if (res_type.starts_with("google_storage_bucket_iam_")
        || res_type == "google_storage_bucket_access_control")
        && attrs.iter().any(|(k, v)| {
            (k == "member" || k == "members" || k == "entity")
                && (v.contains("allUsers") || v.contains("allAuthenticatedUsers"))
        })
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-PUBLIC",
            "CRITICAL",
            format!("Public GCS bucket IAM grant (`allUsers`) on `{}`", sym_name),
            line,
            "Remove `allUsers` and `allAuthenticatedUsers` from GCS IAM bindings and restrict to specific principals.",
        );
    }

    if (res_type.contains("db_instance")
        || res_type.contains("rds_cluster")
        || res_type.contains("sql_database_instance"))
        && (attr_is_bool(attrs, "publicly_accessible", true)
            || attr_is_bool(attrs, "public_network_access_enabled", true))
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-PUBLIC",
            "CRITICAL",
            format!("Database resource `{}` is publicly accessible", sym_name),
            line,
            "Set `publicly_accessible = false` / `public_network_access_enabled = false` and restrict access to private VPC subnets.",
        );
    }
}

fn check_network_exposure(
    ctx: &mut ExtractContext<'_>,
    res_type: &str,
    sym_name: &str,
    block_line: usize,
    body: Node,
    top_attrs: &HashMap<String, String>,
    graph: &HclFileGraph,
) {
    if res_type == "aws_security_group" {
        for nested in collect_nested_blocks(body) {
            let (nt, _) = block_header(nested, ctx.src);
            if nt == "ingress"
                && let Some(nb) = find_block_body(nested)
            {
                let nattrs = collect_resolved_body_attrs(nb, ctx.src, &graph.var_defaults);
                check_ingress_attrs(ctx, sym_name, nested.start_position().row + 1, &nattrs);
            }
        }
        return;
    }

    if matches!(
        res_type,
        "aws_security_group_rule" | "aws_vpc_security_group_ingress_rule"
    ) {
        let is_ingress = res_type == "aws_vpc_security_group_ingress_rule"
            || top_attrs
                .get("type")
                .is_some_and(|t| strip_quotes(t).eq_ignore_ascii_case("ingress"));
        if is_ingress {
            check_ingress_attrs(ctx, sym_name, block_line, top_attrs);
        }
        return;
    }

    if res_type == "azurerm_network_security_rule"
        && top_attrs
            .get("direction")
            .is_some_and(|d| strip_quotes(d).eq_ignore_ascii_case("Inbound"))
        && top_attrs
            .get("access")
            .is_some_and(|a| strip_quotes(a).eq_ignore_ascii_case("Allow"))
    {
        check_ingress_attrs(ctx, sym_name, block_line, top_attrs);
    } else if res_type == "google_compute_firewall" {
        let is_egress = top_attrs
            .get("direction")
            .is_some_and(|d| strip_quotes(d).eq_ignore_ascii_case("EGRESS"));
        let has_world_cidr = top_attrs
            .get("source_ranges")
            .is_some_and(|v| v.contains("0.0.0.0/0") || v.contains("::/0"));
        if !is_egress && has_world_cidr {
            let mut has_allow_block = false;
            let mut allow_non_http_port = false;
            for nested in collect_nested_blocks(body) {
                let (nt, _) = block_header(nested, ctx.src);
                if nt == "allow"
                    && let Some(nb) = find_block_body(nested)
                {
                    has_allow_block = true;
                    let nattrs = collect_resolved_body_attrs(nb, ctx.src, &graph.var_defaults);
                    let only_http_ports = nattrs.get("ports").is_some_and(|ports| {
                        let inner: Vec<String> = ports
                            .trim_matches(['[', ']', ' ', '\n', '\r', '\t'])
                            .split(',')
                            .map(|p| strip_quotes(p).trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect();
                        !inner.is_empty() && inner.iter().all(|p| p == "80" || p == "443")
                    });
                    if !only_http_ports {
                        allow_non_http_port = true;
                    }
                }
            }
            if has_allow_block && allow_non_http_port {
                push_iac_finding(
                    ctx,
                    "SMG-CFG-IAC-NET",
                    "CRITICAL",
                    format!(
                        "Firewall rule `{}` allows ingress from `0.0.0.0/0`",
                        sym_name
                    ),
                    block_line,
                    "Restrict `source_ranges` to trusted CIDR blocks instead of `0.0.0.0/0`.",
                );
            }
        }
    }
}

fn check_ingress_attrs(
    ctx: &mut ExtractContext<'_>,
    sym_name: &str,
    line: usize,
    attrs: &HashMap<String, String>,
) {
    let has_world_cidr = [
        "cidr_blocks",
        "ipv6_cidr_blocks",
        "cidr_ipv4",
        "cidr_ipv6",
        "source_address_prefix",
        "source_address_prefixes",
    ]
    .iter()
    .any(|k| {
        attrs.get(*k).is_some_and(|v| {
            v.contains("0.0.0.0/0") || v.contains("::/0") || strip_quotes(v) == "*"
        })
    });
    if !has_world_cidr {
        return;
    }

    let proto = attrs
        .get("protocol")
        .or_else(|| attrs.get("ip_protocol"))
        .map(|s| strip_quotes(s).to_ascii_lowercase())
        .unwrap_or_default();

    let parse_port_range = |raw: &str, take_end: bool| -> Option<u16> {
        let clean = strip_quotes(raw);
        if let Ok(single) = clean.parse::<u16>() {
            return Some(single);
        }
        if let Some((a, b)) = clean.split_once('-') {
            return if take_end { b } else { a }.trim().parse::<u16>().ok();
        }
        None
    };

    let from_port = attrs
        .get("from_port")
        .and_then(|v| strip_quotes(v).parse::<u16>().ok())
        .or_else(|| {
            attrs
                .get("destination_port_range")
                .and_then(|v| parse_port_range(v, false))
        });
    let to_port = attrs
        .get("to_port")
        .and_then(|v| strip_quotes(v).parse::<u16>().ok())
        .or_else(|| {
            attrs
                .get("destination_port_range")
                .and_then(|v| parse_port_range(v, true))
        });

    // Permit public HTTP (80) / HTTPS (443) listeners explicitly
    if proto == "tcp"
        && let (Some(fp), Some(tp)) = (from_port, to_port)
        && fp == tp
        && (fp == 80 || fp == 443)
    {
        return;
    }

    let wildcard_proto = matches!(proto.as_str(), "-1" | "all" | "*");
    let dest_star = attrs
        .get("destination_port_range")
        .is_some_and(|v| strip_quotes(v) == "*");
    let exposes_sensitive_port = match (from_port, to_port) {
        (Some(fp), Some(tp)) => {
            (fp..=tp).any(|p| SENSITIVE_PORTS.contains(&p)) || (fp == 0 && tp >= 1024)
        }
        _ => wildcard_proto || dest_star,
    };

    if wildcard_proto || dest_star || exposes_sensitive_port {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-NET",
            "CRITICAL",
            format!(
                "Open ingress (`0.0.0.0/0`) exposing sensitive port/protocol on `{}`",
                sym_name
            ),
            line,
            "Restrict ingress CIDRs to internal VPC subnets or bastion/VPN IPs instead of `0.0.0.0/0`.",
        );
    }
}

fn check_crypto_posture(
    ctx: &mut ExtractContext<'_>,
    res_type: &str,
    sym_name: &str,
    line: usize,
    body: Node,
    attrs: &HashMap<String, String>,
    graph: &HclFileGraph,
) {
    // `aws_ebs_volume` missing encryption is covered by CKV_AWS_3; keep default-off heuristic for RDS.
    if matches!(res_type, "aws_db_instance" | "aws_rds_cluster")
        && !attrs.contains_key("storage_encrypted")
        && !attrs.contains_key("encrypted")
        && !attrs.contains_key("kms_key_id")
        && !attrs.contains_key("replicate_source_db")
        && !attrs.contains_key("snapshot_identifier")
    {
        push_iac_finding_conf(
            ctx,
            "SMG-CFG-IAC-CRYPTO",
            "HIGH",
            format!(
                "Resource `{}` omits `storage_encrypted = true`/`encrypted = true` (Terraform defaults encryption off)",
                sym_name
            ),
            line,
            Confidence::Heuristic,
            "Explicitly set `storage_encrypted = true` (or `encrypted = true`) with a KMS key.",
        );
    }

    if matches!(res_type, "aws_lb_listener" | "aws_alb_listener")
        && attrs
            .get("protocol")
            .is_some_and(|p| strip_quotes(p).eq_ignore_ascii_case("HTTP"))
    {
        let mut is_https_redirect = false;
        for nested in collect_nested_blocks(body) {
            if block_header(nested, ctx.src).0 == "default_action"
                && let Some(nb) = find_block_body(nested)
            {
                let nattrs = collect_resolved_body_attrs(nb, ctx.src, &graph.var_defaults);
                if nattrs
                    .get("type")
                    .is_some_and(|t| strip_quotes(t).eq_ignore_ascii_case("redirect"))
                {
                    is_https_redirect = true;
                }
            }
        }
        if !is_https_redirect {
            push_iac_finding(
                ctx,
                "SMG-CFG-IAC-CRYPTO",
                "HIGH",
                format!(
                    "Load balancer listener `{}` forwards plaintext `HTTP` without HTTPS redirect",
                    sym_name
                ),
                line,
                "Use `protocol = \"HTTPS\"` or configure `default_action { type = \"redirect\" }` to port 443.",
            );
        }
    }
    // Avoid duplicating resources with explicit declarative Checkov encryption rules
    let covered_by_iac_encryption = matches!(
        res_type,
        "aws_db_instance" | "aws_ebs_volume" | "aws_redshift_cluster" | "aws_efs_file_system"
    );
    if !covered_by_iac_encryption
        && (attr_is_bool(attrs, "storage_encrypted", false)
            || attr_is_bool(attrs, "encrypted", false)
            || attr_is_bool(attrs, "encryption_at_rest_enabled", false))
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-CRYPTO",
            "HIGH",
            format!("Encryption at rest explicitly disabled on `{}`", sym_name),
            line,
            "Enable encryption at rest (`storage_encrypted = true` / `encrypted = true`) using KMS.",
        );
    }

    if res_type != "azurerm_storage_account"
        && (attr_is_bool(attrs, "enable_https_traffic_only", false)
            || attr_is_bool(attrs, "https_traffic_only_enabled", false))
    {
        push_iac_finding(
            ctx,
            "SMG-CFG-IAC-CRYPTO",
            "HIGH",
            format!("HTTPS-only transport disabled on `{}`", sym_name),
            line,
            "Enforce HTTPS-only traffic (`https_traffic_only_enabled = true`).",
        );
    }

    if matches!(
        res_type,
        "aws_lb_listener" | "aws_alb_listener" | "aws_api_gateway_domain_name"
    ) {
        for key in [
            "ssl_policy",
            "security_policy",
            "min_tls_version",
            "minimum_tls_version",
        ] {
            if let Some(val) = attrs.get(key) {
                let low = strip_quotes(val).to_ascii_lowercase();
                if low.contains("tlsv1_0")
                    || low.contains("tlsv1_1")
                    || low.contains("tls_1_0")
                    || low.contains("tls_1_1")
                    || low.contains("tlsv1.0")
                    || low.contains("tlsv1.1")
                    || low.contains("2015-05")
                    || low.contains("2016-08")
                {
                    push_iac_finding(
                        ctx,
                        "SMG-CFG-IAC-CRYPTO",
                        "HIGH",
                        format!(
                            "Weak TLS policy (`{}`) configured on `{}`",
                            strip_quotes(val),
                            sym_name
                        ),
                        line,
                        "Upgrade TLS policy to `TLSv1.2` or `TLSv1.3` (`ELBSecurityPolicy-TLS13-1-2-2021-06`).",
                    );
                }
            }
        }
    }
}

fn check_iam_wildcards(
    ctx: &mut ExtractContext<'_>,
    _res_type: &str,
    sym_name: &str,
    block_line: usize,
    body: Node,
    top_attrs: &HashMap<String, String>,
    graph: &HclFileGraph,
) {
    // Pattern A: `data "aws_iam_policy_document"` nested `statement { actions = ["*"] resources = ["*"] }`
    for nested in collect_nested_blocks(body) {
        let (nt, _) = block_header(nested, ctx.src);
        if nt == "statement"
            && let Some(nb) = find_block_body(nested)
        {
            let nattrs = collect_resolved_body_attrs(nb, ctx.src, &graph.var_defaults);
            let is_deny = nattrs
                .get("effect")
                .is_some_and(|e| strip_quotes(e).eq_ignore_ascii_case("Deny"));
            if !is_deny {
                let act_star = nattrs
                    .get("actions")
                    .or_else(|| nattrs.get("action"))
                    .is_some_and(|a| contains_exact_wildcard_token(a));
                let res_star = nattrs
                    .get("resources")
                    .or_else(|| nattrs.get("resource"))
                    .is_some_and(|r| contains_exact_wildcard_token(r));
                if act_star && res_star {
                    push_iac_finding(
                        ctx,
                        "SMG-CFG-IAC-IAM",
                        "CRITICAL",
                        format!(
                            "Over-permissive IAM wildcard statement (`*` actions & resources) in `{}`",
                            sym_name
                        ),
                        nested.start_position().row + 1,
                        "Scope IAM `actions` and `resources` to least-privilege ARNs and specific actions.",
                    );
                }
            }
        }
    }

    // Pattern B: Inline JSON / heredoc / jsonencode `policy` attribute with Allow-effect `Action: "*"` & `Resource: "*"`
    if let Some(policy_expr) = top_attrs.get("policy") {
        let unescaped = policy_expr.replace("\\\"", "\"");
        let compact: String = unescaped.chars().filter(|c| !c.is_whitespace()).collect();
        let low = compact.to_ascii_lowercase();
        let check_stmt_chunk = |chunk: &str| -> bool {
            let has_star_action = chunk.contains("\"action\":\"*\"")
                || chunk.contains("\"action\":[\"*\"]")
                || chunk.contains("action=\"*\"")
                || chunk.contains("action=[\"*\"]");
            let has_star_res = chunk.contains("\"resource\":\"*\"")
                || chunk.contains("\"resource\":[\"*\"]")
                || chunk.contains("resource=\"*\"")
                || chunk.contains("resource=[\"*\"]");
            let is_deny =
                chunk.contains("\"effect\":\"deny\"") || chunk.contains("effect=\"deny\"");
            has_star_action && has_star_res && !is_deny
        };
        // Split top-level JSON objects inside `"Statement":[{...},{...}]` respecting nested braces (fixes `Condition` split FPs)
        let chunks = split_json_statement_objects(&low);
        if chunks.into_iter().any(check_stmt_chunk) {
            push_iac_finding(
                ctx,
                "SMG-CFG-IAC-IAM",
                "CRITICAL",
                format!(
                    "Over-permissive inline IAM policy (`Action: *` & `Resource: *`) in `{}`",
                    sym_name
                ),
                block_line,
                "Replace `*` wildcards in inline IAM policies with least-privilege actions and resource ARNs.",
            );
        }
    }
}

fn split_json_statement_objects(compact_low: &str) -> Vec<&str> {
    if let Some(pos) = compact_low.find("\"statement\":[") {
        let arr = &compact_low[pos + "\"statement\":[".len()..];
        let mut out = Vec::new();
        let mut depth = 0usize;
        let mut obj_start: Option<usize> = None;
        let mut in_str = false;
        let mut esc = false;
        for (i, ch) in arr.char_indices() {
            if esc {
                esc = false;
                continue;
            }
            if ch == '\\' && in_str {
                esc = true;
                continue;
            }
            if ch == '"' {
                in_str = !in_str;
                continue;
            }
            if in_str {
                continue;
            }
            match ch {
                '{' => {
                    if depth == 0 {
                        obj_start = Some(i);
                    }
                    depth += 1;
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0
                        && let Some(s) = obj_start.take()
                    {
                        out.push(&arr[s..=i]);
                    }
                }
                ']' if depth == 0 => break,
                _ => {}
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    vec![compact_low]
}

fn contains_exact_wildcard_token(expr: &str) -> bool {
    let trimmed = expr.trim();
    if strip_quotes(trimmed) == "*" {
        return true;
    }
    trimmed.contains("\"*\"") || trimmed.contains("'*'")
}
