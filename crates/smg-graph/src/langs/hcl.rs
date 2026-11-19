use crate::ast::{
    Confidence, GuardKind, ImportRef, LocalStaticFinding, SinkKind, SymbolInfo, SymbolKind,
    node_text,
};
use std::collections::HashMap;
use tree_sitter::Node;

use super::{ExtractContext, strip_quotes};

const SENSITIVE_PORTS: &[u16] = &[22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017];

pub(crate) fn extract(root: Node, ctx: &mut ExtractContext<'_>) {
    walk_hcl_blocks(root, ctx);
}

fn walk_hcl_blocks(node: Node, ctx: &mut ExtractContext<'_>) {
    if node.kind() == "block" {
        analyze_top_block(node, ctx);
        return;
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        walk_hcl_blocks(ch, ctx);
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

fn find_block_body(block: Node) -> Option<Node> {
    block.child_by_field_name("body").or_else(|| {
        let mut c = block.walk();
        block.children(&mut c).find(|ch| ch.kind() == "body")
    })
}

fn collect_nested_blocks(body: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut c = body.walk();
    for ch in body.children(&mut c) {
        if ch.kind() == "block" {
            out.push(ch);
        } else if ch.kind() == "body" {
            out.extend(collect_nested_blocks(ch));
        }
    }
    out
}

fn analyze_top_block(block: Node, ctx: &mut ExtractContext<'_>) {
    let (block_type, labels) = block_header(block, ctx.src);
    let Some(body) = find_block_body(block) else {
        return;
    };
    let attrs = collect_body_attrs(body, ctx.src);
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

    ctx.symbols.push(SymbolInfo {
        id: format!("hcl:{}:{}:{}", ctx.rel_path, sym_name, line),
        rel_path: ctx.rel_path.to_string(),
        name: sym_name.clone(),
        kind: SymbolKind::Function,
        line_start: line,
        line_end: end_line,
        ..Default::default()
    });

    // 1. Public Storage / Database Exposure (`SMG-CFG-IAC-PUBLIC`)
    check_public_exposure(ctx, &res_type, &sym_name, line, body, &attrs);

    // 2. Public Network Ingress (`SMG-CFG-IAC-NET`)
    check_network_exposure(ctx, &res_type, &sym_name, line, body, &attrs);

    // 3. Encryption & TLS Posture (`SMG-CFG-IAC-CRYPTO`)
    check_crypto_posture(ctx, &res_type, &sym_name, line, body, &attrs);

    // 4. Over-permissive IAM Policies (`SMG-CFG-IAC-IAM`)
    check_iam_wildcards(ctx, &res_type, &sym_name, line, body, &attrs);
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

fn check_public_exposure(
    ctx: &mut ExtractContext<'_>,
    res_type: &str,
    sym_name: &str,
    line: usize,
    body: Node,
    attrs: &HashMap<String, String>,
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

    if matches!(
        res_type,
        "aws_instance" | "aws_launch_template" | "aws_launch_configuration"
    ) {
        for nested in collect_nested_blocks(body) {
            let (nt, _) = block_header(nested, ctx.src);
            if nt == "metadata_options"
                && let Some(nb) = find_block_body(nested)
            {
                let nattrs = collect_body_attrs(nb, ctx.src);
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
                                let aattrs = collect_body_attrs(ab, ctx.src);
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
        let has_wildcard_principal = compact.contains("\"principal\":\"*\"")
            || compact.contains("\"principal\":{\"aws\":\"*\"}")
            || compact.contains("\"principal\":{\"aws\":[\"*\"]}");
        if has_wildcard_principal
            && !compact.contains("\"condition\"")
            && !compact.contains("\"effect\":\"deny\"")
        {
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
        if matches!(
            clean.as_str(),
            "public-read" | "public-read-write" | "authenticated-read"
        ) {
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
        || res_type.contains("sql_database_instance")
        || res_type.contains("mssql_server"))
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
) {
    if res_type == "aws_security_group" {
        for nested in collect_nested_blocks(body) {
            let (nt, _) = block_header(nested, ctx.src);
            if nt == "ingress"
                && let Some(nb) = find_block_body(nested)
            {
                let nattrs = collect_body_attrs(nb, ctx.src);
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
                    let nattrs = collect_body_attrs(nb, ctx.src);
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
) {
    if matches!(
        res_type,
        "aws_db_instance" | "aws_rds_cluster" | "aws_ebs_volume"
    ) && !attrs.contains_key("storage_encrypted")
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
                let nattrs = collect_body_attrs(nb, ctx.src);
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
    if attr_is_bool(attrs, "storage_encrypted", false)
        || attr_is_bool(attrs, "encrypted", false)
        || attr_is_bool(attrs, "encryption_at_rest_enabled", false)
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

    if attr_is_bool(attrs, "enable_https_traffic_only", false)
        || attr_is_bool(attrs, "https_traffic_only_enabled", false)
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
        "aws_lb_listener"
            | "aws_alb_listener"
            | "aws_api_gateway_domain_name"
            | "azurerm_storage_account"
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
) {
    // Pattern A: `data "aws_iam_policy_document"` nested `statement { actions = ["*"] resources = ["*"] }`
    for nested in collect_nested_blocks(body) {
        let (nt, _) = block_header(nested, ctx.src);
        if nt == "statement"
            && let Some(nb) = find_block_body(nested)
        {
            let nattrs = collect_body_attrs(nb, ctx.src);
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
