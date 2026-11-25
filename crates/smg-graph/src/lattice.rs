use crate::arena::{GuardBitset, SymbolArena, SymbolId};
use crate::ast::{
    Confidence, FileAstSummary, GuardKind, ImportFileIndex, LocalStaticFinding, SinkKind,
    SymbolInfo, SymbolKind, resolve_import_target_indexed,
};
use crate::taint::{TAINT_ALL, TAINT_CMD, TAINT_PATH, TAINT_SQL, TAINT_SSRF, TAINT_XSS};
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub file: String,
    pub symbol: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatticeFinding {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: usize,
    pub status: String,
    #[serde(default)]
    pub confidence: Confidence,
    pub entry_route: String,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    pub witness_path: Vec<TraceHop>,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub proof_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleHitStat {
    pub rule_id: String,
    pub total: usize,
    pub proven: usize,
    pub confirmed: usize,
    pub heuristic: usize,
}

/// Computes per-rule hit counts broken down by verification/confidence tier (`PROVEN`/`CONFIRMED`/`HEURISTIC`).
pub fn compute_rule_telemetry(findings: &[LatticeFinding]) -> Vec<RuleHitStat> {
    let mut map: HashMap<String, RuleHitStat> = HashMap::new();
    for f in findings {
        let entry = map.entry(f.rule_id.clone()).or_insert_with(|| RuleHitStat {
            rule_id: f.rule_id.clone(),
            total: 0,
            proven: 0,
            confirmed: 0,
            heuristic: 0,
        });
        entry.total += 1;
        match f.confidence {
            Confidence::Proven => entry.proven += 1,
            Confidence::Confirmed => entry.confirmed += 1,
            Confidence::Heuristic => entry.heuristic += 1,
        }
    }
    let mut out: Vec<RuleHitStat> = map.into_values().collect();
    out.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnalysisResult {
    pub parsed_files: usize,
    pub symbol_count: usize,
    pub edge_count: usize,
    pub route_entries: usize,
    #[serde(default)]
    pub active_domains: Vec<String>,
    pub findings: Vec<LatticeFinding>,
    #[serde(default)]
    pub route_schemas: Vec<crate::phase10::RouteSchema>,
}

pub fn solve_guard_lattice(summaries: &[FileAstSummary]) -> GraphAnalysisResult {
    solve_guard_lattice_with_public(summaries, &[])
}

fn is_public_route(entry_route: &str, public_routes: &[String]) -> bool {
    let path_part = entry_route.split_whitespace().nth(1).unwrap_or(entry_route);
    let low = path_part.to_ascii_lowercase();
    let has_privileged_seg = low.split('/').any(|seg| {
        matches!(
            seg,
            "admin" | "impersonate" | "refund" | "refund-all" | "users" | "billing" | "role"
        )
    });
    public_routes.iter().any(|p| {
        let pl = p.to_ascii_lowercase();
        if let Some(prefix) = pl.strip_suffix("/*") {
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                return false;
            }
            return !has_privileged_seg
                && (low == trimmed || low.starts_with(&format!("{trimmed}/")));
        }
        let trimmed = pl.trim_end_matches('/');
        low == pl
            || (!trimmed.is_empty()
                && !has_privileged_seg
                && low.starts_with(&format!("{trimmed}/")))
    })
}

fn is_admin_route(entry_route: &str) -> bool {
    let path_part = entry_route.split_whitespace().nth(1).unwrap_or(entry_route);
    path_part
        .split('/')
        .any(|seg| seg.eq_ignore_ascii_case("admin"))
}

fn go_parent_dir(rel_path: &str) -> String {
    match rel_path.rfind('/') {
        Some(idx) => rel_path[..idx].to_string(),
        None => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_symbol_in_file(
    target_file: SymbolId,
    symbol_name: SymbolId,
    file_symbols_map: &HashMap<(SymbolId, SymbolId), Vec<NodeIndex>>,
    defined_symbol_ids: &HashSet<SymbolId>,
    file_imports: &HashMap<SymbolId, Vec<(SymbolId, SymbolId, SymbolId)>>,
    wildcard_id: SymbolId,
    depth: usize,
    resolve_cache: &mut HashMap<(SymbolId, SymbolId), Vec<NodeIndex>>,
) -> Vec<NodeIndex> {
    if let Some(cached) = resolve_cache.get(&(target_file, symbol_name)) {
        return cached.clone();
    }
    if let Some(indices) = file_symbols_map.get(&(target_file, symbol_name))
        && !indices.is_empty()
    {
        return indices.clone();
    }
    let mut visited = HashSet::new();
    let res = resolve_symbol_in_file_memo(
        target_file,
        symbol_name,
        file_symbols_map,
        defined_symbol_ids,
        file_imports,
        wildcard_id,
        depth,
        &mut visited,
        resolve_cache,
    );
    if depth == 0 && resolve_cache.len() < 250_000 {
        resolve_cache.insert((target_file, symbol_name), res.clone());
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn resolve_symbol_in_file_memo(
    target_file: SymbolId,
    symbol_name: SymbolId,
    file_symbols_map: &HashMap<(SymbolId, SymbolId), Vec<NodeIndex>>,
    defined_symbol_ids: &HashSet<SymbolId>,
    file_imports: &HashMap<SymbolId, Vec<(SymbolId, SymbolId, SymbolId)>>,
    wildcard_id: SymbolId,
    depth: usize,
    visited: &mut HashSet<(SymbolId, SymbolId)>,
    resolve_cache: &mut HashMap<(SymbolId, SymbolId), Vec<NodeIndex>>,
) -> Vec<NodeIndex> {
    if visited.len() >= 64 || !visited.insert((target_file, symbol_name)) {
        return Vec::new();
    }
    if let Some(cached) = resolve_cache.get(&(target_file, symbol_name)) {
        return cached.clone();
    }
    if let Some(indices) = file_symbols_map.get(&(target_file, symbol_name))
        && !indices.is_empty()
    {
        return indices.clone();
    }
    if depth >= 6 {
        return Vec::new();
    }
    let Some(imps) = file_imports.get(&target_file) else {
        return Vec::new();
    };
    let can_wildcard_match = defined_symbol_ids.contains(&symbol_name);
    let mut out = Vec::new();
    for &(local_name, next_file, remote_name) in imps {
        if visited.len() >= 64 {
            break;
        }
        if local_name == symbol_name {
            let resolved = resolve_symbol_in_file_memo(
                next_file,
                remote_name,
                file_symbols_map,
                defined_symbol_ids,
                file_imports,
                wildcard_id,
                depth + 1,
                visited,
                resolve_cache,
            );
            for idx in resolved {
                if !out.contains(&idx) {
                    out.push(idx);
                }
            }
        } else if local_name == wildcard_id && can_wildcard_match {
            let resolved = resolve_symbol_in_file_memo(
                next_file,
                symbol_name,
                file_symbols_map,
                defined_symbol_ids,
                file_imports,
                wildcard_id,
                depth + 1,
                visited,
                resolve_cache,
            );
            for idx in resolved {
                if !out.contains(&idx) {
                    out.push(idx);
                }
            }
        }
    }
    out
}

fn remediation_for_guard(g: GuardKind) -> &'static str {
    match g {
        GuardKind::Auth => {
            "Add authentication middleware (e.g. JWT/session check like `requireAuth`) before invoking this handler."
        }
        GuardKind::TxLock => {
            "Wrap balance/payment operations in an ACID transaction with `SELECT ... FOR UPDATE` or enforce an atomic idempotency key."
        }
        GuardKind::SqlSanitizer => {
            "Replace dynamic SQL string interpolation with parameterized queries / prepared statements (`$1`, `?`)."
        }
        GuardKind::CmdSanitizer => {
            "Eliminate shell command concatenation (`exec`/`shell=True`); pass an explicit argument array to `execFile`/`Command::new`."
        }
        GuardKind::PathSanitizer => {
            "Canonicalize user-supplied paths with `path.basename` / `filepath.Clean` and verify `resolved.startsWith(baseDir)`."
        }
        GuardKind::SsrfSanitizer => {
            "Enforce an explicit domain/host allowlist and block private/loopback/metadata IP ranges (127.0.0.0/8, 169.254.0.0/16)."
        }
        GuardKind::XssSanitizer => {
            "Encode or sanitize untrusted HTML with `DOMPurify.sanitize` or strict context-aware template auto-escaping instead of raw HTML sinks."
        }
        GuardKind::CsrfProtection => {
            "Enforce anti-CSRF token validation (`csurf`, Django `CsrfViewMiddleware`, SameSite=Strict/Lax cookies) or switch to stateless `Authorization: Bearer` headers."
        }
        GuardKind::OwnershipCheck => {
            "Enforce object-level authorization by filtering the DB query with the authenticated actor (`WHERE id = $1 AND user_id = req.user.id`)."
        }
        GuardKind::SecretPolicy => {
            "Revoke and rotate the exposed credential immediately, move it to a runtime secret manager, and keep `.env` out of git."
        }
        GuardKind::ConfigPolicy => {
            "Harden the configuration baseline (explicit origins, TLS verification enabled, `httpOnly`/`secure` cookies, AEAD/SHA-256+, debug disabled)."
        }
        GuardKind::DependencyPolicy => {
            "Upgrade to a patched dependency version, pin exact/caret semver ranges instead of `*`/`latest`, and use HTTPS/lockfile registries."
        }
        GuardKind::FrontendContract => {
            "Align frontend request paths/methods with registered backend endpoints and handle errors/empty callbacks cleanly."
        }
        GuardKind::LockOrdering => {
            "Enforce a single canonical lock acquisition order (`std::scoped_lock`), drop lock guards before `.await`, and release manual locks on error returns."
        }
        GuardKind::ResourceCleanup => {
            "Ensure every opened handle/socket/DB connection is freed on all error-return paths using RAII, `defer`, `try/finally`, or `goto cleanup`."
        }
        GuardKind::MemoryBounds => {
            "Validate buffer lengths (`<= sizeof(dst)`), use bounded copy APIs (`snprintf`/`fgets`), check integer multiplication overflow (`checked_mul`/`__builtin_mul_overflow`), and guard `unsafe` slices."
        }
        GuardKind::MobilePolicy => {
            "Harden mobile storage (Android Keystore/EncryptedSharedPreferences, iOS Keychain, FlutterSecureStorage), restrict exported IPC components, and enforce TLS certificate pinning."
        }
        GuardKind::InputValidation => {
            "Validate financial/numeric and boundary inputs (reject NaN, Infinity, <= 0 amounts/quantities, oversized arrays, null bytes, and malformed UTF-8) before mutating state."
        }
    }
}

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

/// Shared CLI & TUI layer filter matching `--layers` tokens against a finding's guard/rule.
pub fn finding_matches_layer(f: &LatticeFinding, layer: &str) -> bool {
    let norm = layer.trim().to_ascii_lowercase();
    match norm.as_str() {
        "all" | "*" => true,
        "1" | "layer1" => matches!(f.missing_guard, GuardKind::Auth | GuardKind::SecretPolicy),
        "2" | "layer2" => matches!(
            f.missing_guard,
            GuardKind::SqlSanitizer
                | GuardKind::CmdSanitizer
                | GuardKind::PathSanitizer
                | GuardKind::SsrfSanitizer
                | GuardKind::XssSanitizer
                | GuardKind::CsrfProtection
                | GuardKind::OwnershipCheck
                | GuardKind::FrontendContract
                | GuardKind::InputValidation
        ),
        "deep" | "fuzz" | "schema" => {
            f.missing_guard == GuardKind::InputValidation || f.rule_id.starts_with("SMG-FUZZ-")
        }
        "3" | "layer3" | "deps" | "dep" | "dependencies" | "vex" | "reachable" => {
            f.missing_guard == GuardKind::DependencyPolicy || f.rule_id.starts_with("SMG-DEP-")
        }
        "4" | "layer4" | "config" | "misconfig" => f.missing_guard == GuardKind::ConfigPolicy,
        "cicd" | "gha" | "actions" => f.rule_id.starts_with("SMG-CICD-"),
        "k8s" | "kubernetes" | "helm" | "rbac" => {
            f.rule_id.starts_with("SMG-K8S-") || f.rule_id == "SMG-CFG-DOCKER"
        }
        "dos" | "redos" => f.rule_id.starts_with("SMG-DOS-"),
        "zip" | "zipslip" => f.rule_id.starts_with("SMG-ZIP-"),
        "crypto" => f.rule_id.starts_with("SMG-CRYPTO-") || f.rule_id == "SMG-CFG-CRYPTO",
        "queue" | "async" | "mq" => f.rule_id.starts_with("SMG-QUEUE-"),
        "api" | "graphql" | "ws" | "websocket" | "grpc" => f.rule_id.starts_with("SMG-API-"),
        "ai" | "llm" | "agent" | "prompt" => f.rule_id.starts_with("SMG-AI-"),
        "oauth" | "pkce" => f.rule_id == "SMG-AUTH-PKCE",
        "smuggle" | "crlf" | "header" => f.rule_id == "SMG-HTTP-SMUGGLE",
        "state" | "workflow" => f.rule_id.starts_with("SMG-STATE-"),
        "hw" | "hardware" | "firmware" | "embedded" => {
            f.rule_id.starts_with("SMG-HW-") || f.missing_guard == GuardKind::MemoryBounds
        }
        "web3" | "blockchain" | "smartcontract" | "solidity" | "evm" | "solana" | "move"
        | "defi" => f.rule_id.starts_with("SMG-WEB3-"),
        "pqc" | "quantum" | "post-quantum" | "cbom" => f.rule_id.starts_with("SMG-PQC-"),
        "5" | "layer5" | "6" | "layer6" | "race" => f.missing_guard == GuardKind::TxLock,
        "concurrency" => matches!(f.missing_guard, GuardKind::TxLock | GuardKind::LockOrdering),
        "engine" | "deadlock" | "leak" | "int" => {
            matches!(
                f.missing_guard,
                GuardKind::LockOrdering | GuardKind::ResourceCleanup
            ) || f.rule_id.starts_with("SMG-ENG-")
        }
        "memory" | "mem" | "bounds" => {
            f.missing_guard == GuardKind::MemoryBounds || f.rule_id.starts_with("SMG-MEM-")
        }
        "mobile" | "mob" | "android" | "ios" | "flutter" => {
            f.missing_guard == GuardKind::MobilePolicy || f.rule_id.starts_with("SMG-MOB-")
        }
        "auth" => f.missing_guard == GuardKind::Auth,
        "taint" | "injection" => matches!(
            f.missing_guard,
            GuardKind::SqlSanitizer
                | GuardKind::CmdSanitizer
                | GuardKind::PathSanitizer
                | GuardKind::SsrfSanitizer
                | GuardKind::XssSanitizer
        ),
        "sql" | "sqli" => f.missing_guard == GuardKind::SqlSanitizer,
        "cmd" | "cmdi" => f.missing_guard == GuardKind::CmdSanitizer,
        "path" => f.missing_guard == GuardKind::PathSanitizer,
        "ssrf" => f.missing_guard == GuardKind::SsrfSanitizer,
        "xss" => f.missing_guard == GuardKind::XssSanitizer,
        "csrf" => f.missing_guard == GuardKind::CsrfProtection,
        "idor" => f.missing_guard == GuardKind::OwnershipCheck,
        "secrets" | "secret" => f.missing_guard == GuardKind::SecretPolicy,
        "frontend" | "fe" | "contract" => f.missing_guard == GuardKind::FrontendContract,
        other => {
            f.rule_id.to_ascii_lowercase().contains(other)
                || f.id.to_ascii_lowercase().contains(other)
        }
    }
}

fn prefix_for_guard(g: GuardKind) -> &'static str {
    match g {
        GuardKind::Auth => "SMG-AUTH",
        GuardKind::TxLock => "SMG-RACE",
        GuardKind::SqlSanitizer => "SMG-SQLI",
        GuardKind::CmdSanitizer => "SMG-CMDI",
        GuardKind::PathSanitizer => "SMG-PATH",
        GuardKind::SsrfSanitizer => "SMG-SSRF",
        GuardKind::XssSanitizer => "SMG-XSS",
        GuardKind::CsrfProtection => "SMG-CSRF",
        GuardKind::OwnershipCheck => "SMG-IDOR",
        GuardKind::SecretPolicy => "SMG-SEC",
        GuardKind::ConfigPolicy => "SMG-CFG",
        GuardKind::DependencyPolicy => "SMG-DEP",
        GuardKind::FrontendContract => "SMG-FE",
        GuardKind::LockOrdering => "SMG-ENG",
        GuardKind::ResourceCleanup => "SMG-ENG",
        GuardKind::MemoryBounds => "SMG-MEM",
        GuardKind::MobilePolicy => "SMG-MOB",
        GuardKind::InputValidation => "SMG-FUZZ",
    }
}

fn sink_bit_for_guard(g: GuardKind) -> u8 {
    match g {
        GuardKind::SqlSanitizer => TAINT_SQL,
        GuardKind::CmdSanitizer => TAINT_CMD,
        GuardKind::PathSanitizer => TAINT_PATH,
        GuardKind::SsrfSanitizer => TAINT_SSRF,
        GuardKind::XssSanitizer => TAINT_XSS,
        _ => TAINT_ALL,
    }
}

fn sink_bit_index(bit: u8) -> Option<usize> {
    match bit {
        TAINT_SQL => Some(0),
        TAINT_CMD => Some(1),
        TAINT_PATH => Some(2),
        TAINT_SSRF => Some(3),
        TAINT_XSS => Some(4),
        _ => None,
    }
}

fn record_bit_parents(
    taint_bit_parents: &mut [[Option<NodeIndex>; 5]],
    vi: usize,
    mask: u8,
    src_node: NodeIndex,
) {
    for (bi, bit) in [TAINT_SQL, TAINT_CMD, TAINT_PATH, TAINT_SSRF, TAINT_XSS]
        .into_iter()
        .enumerate()
    {
        if (mask & bit) != 0 && taint_bit_parents[vi][bi].is_none() {
            taint_bit_parents[vi][bi] = Some(src_node);
        }
    }
}

fn push_taint_edges(
    resolved_callee_map: &HashMap<(usize, String), Vec<NodeIndex>>,
    src_node: NodeIndex,
    callee: &str,
    out_mask: u8,
    taint_parents: &mut [Option<NodeIndex>],
    taint_mask: &mut [u8],
    taint_q: &mut VecDeque<NodeIndex>,
) {
    if out_mask == 0 {
        return;
    }
    if let Some(vs) = resolved_callee_map.get(&(src_node.index(), callee.to_string())) {
        for &v in vs {
            let vi = v.index();
            if taint_parents[vi].is_none() {
                taint_parents[vi] = Some(src_node);
            }
            let next = taint_mask[vi] | out_mask;
            if next != taint_mask[vi] {
                taint_mask[vi] = next;
                taint_q.push_back(v);
            }
        }
    }
}

fn is_phase8_pkg_scoped(rel_path: &str) -> bool {
    matches!(
        Path::new(rel_path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some(
            "php"
                | "java"
                | "cs"
                | "kt"
                | "kts"
                | "swift"
                | "dart"
                | "c"
                | "h"
                | "cpp"
                | "cc"
                | "cxx"
                | "hpp"
                | "hh"
                | "hxx"
                | "rb"
                | "rake"
                | "ru"
                | "sh"
                | "bash"
                | "zsh"
                | "tf"
                | "tfvars"
        )
    )
}

/// Global Cross-File Call Graph + True O(V + E) Guard-Set Lattice, Taint & 6-Layer Witness Solver
pub fn solve_guard_lattice_with_public(
    summaries: &[FileAstSummary],
    public_routes: &[String],
) -> GraphAnalysisResult {
    solve_guard_lattice_with_options(summaries, public_routes, false)
}

/// Global Cross-File Call Graph + Guard-Set Lattice with explicit Tier-2 `--deep-audit` budget control.
pub fn solve_guard_lattice_with_options(
    summaries: &[FileAstSummary],
    public_routes: &[String],
    deep_audit: bool,
) -> GraphAnalysisResult {
    let max_cha_targets: usize = if deep_audit { 64 } else { 8 };
    let max_witness_hops: usize = if deep_audit { 256 } else { 64 };

    let mut arena = SymbolArena::default();
    let wildcard_id = arena.intern("*");
    let mut graph = DiGraph::<SymbolInfo, ()>::new();
    let mut id_to_idx: HashMap<SymbolId, NodeIndex> = HashMap::new();
    let mut file_symbols_map: HashMap<(SymbolId, SymbolId), Vec<NodeIndex>> = HashMap::new();
    let mut type_methods_map: HashMap<(SymbolId, SymbolId), Vec<NodeIndex>> = HashMap::new();
    let mut go_dir_map: HashMap<(SymbolId, SymbolId), Vec<NodeIndex>> = HashMap::new();
    let mut known_go_dirs: HashSet<String> = HashSet::new();
    let mut pkg_dir_map: HashMap<(SymbolId, SymbolId), Vec<NodeIndex>> = HashMap::new();
    let mut known_files: HashSet<String> = HashSet::new();

    // Phase 12A (`P12-02`): Global Type Hierarchy (CHA), Go Structural Interfaces, DI Bindings & RTA Instantiations
    let mut direct_implements: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();
    let mut concrete_type_methods: HashMap<SymbolId, HashSet<String>> = HashMap::new();
    let mut interface_defs: Vec<(SymbolId, bool /* is_go */, Vec<String>)> = Vec::new();
    let mut interface_type_ids: HashSet<SymbolId> = HashSet::new();
    let mut rta_instantiated_types: HashSet<SymbolId> = HashSet::new();

    for f in summaries {
        known_files.insert(f.rel_path.clone());
        let file_id = arena.intern(&f.rel_path);
        let is_go = f.rel_path.ends_with(".go");
        let is_pkg = is_phase8_pkg_scoped(&f.rel_path);
        let go_dir_str = if is_go || is_pkg {
            go_parent_dir(&f.rel_path)
        } else {
            String::new()
        };
        if is_go && !go_dir_str.is_empty() {
            known_go_dirs.insert(go_dir_str.clone());
        }
        let dir_id = if is_go || is_pkg {
            arena.intern(&go_dir_str)
        } else {
            SymbolId(0)
        };
        for sym in &f.symbols {
            let idx = graph.add_node(sym.clone());
            let sym_uid = arena.intern(&sym.id);
            let name_id = arena.intern(&sym.name);
            id_to_idx.insert(sym_uid, idx);
            file_symbols_map
                .entry((file_id, name_id))
                .or_default()
                .push(idx);
            if let Some(ref enc_ty) = sym.enclosing_type {
                let ty_id = arena.intern(enc_ty);
                type_methods_map
                    .entry((ty_id, name_id))
                    .or_default()
                    .push(idx);
                concrete_type_methods
                    .entry(ty_id)
                    .or_default()
                    .insert(sym.name.clone());
            }
            if is_go {
                go_dir_map.entry((dir_id, name_id)).or_default().push(idx);
            } else if is_pkg {
                pkg_dir_map.entry((dir_id, name_id)).or_default().push(idx);
            }
        }
        for ti in &f.type_impls {
            let tid = arena.intern(&ti.type_name);
            if ti.is_interface {
                interface_type_ids.insert(tid);
                interface_defs.push((tid, is_go, ti.methods.clone()));
            } else {
                let mset = concrete_type_methods.entry(tid).or_default();
                for m in &ti.methods {
                    mset.insert(m.clone());
                }
            }
            for base in &ti.implements {
                let bid = arena.intern(base);
                let subs = direct_implements.entry(bid).or_default();
                if !subs.contains(&tid) {
                    subs.push(tid);
                }
            }
        }
        for (token, concrete) in &f.di_bindings {
            let tok_id = arena.intern(token);
            let conc_id = arena.intern(concrete);
            let subs = direct_implements.entry(tok_id).or_default();
            if !subs.contains(&conc_id) {
                subs.push(conc_id);
            }
            rta_instantiated_types.insert(conc_id);
        }
        for inst in &f.instantiated_types {
            rta_instantiated_types.insert(arena.intern(inst));
        }
    }

    // Go Structural Interface Satisfaction: concrete Go struct with superset of interface methods implements interface
    for &(iface_id, is_go_iface, ref req_methods) in &interface_defs {
        if !is_go_iface || req_methods.is_empty() {
            continue;
        }
        for (&cand_ty, cand_methods) in &concrete_type_methods {
            if cand_ty == iface_id || interface_type_ids.contains(&cand_ty) {
                continue;
            }
            if req_methods.iter().all(|m| cand_methods.contains(m)) {
                let subs = direct_implements.entry(iface_id).or_default();
                if !subs.contains(&cand_ty) {
                    subs.push(cand_ty);
                }
            }
        }
    }

    // Bounded transitive CHA closure (depth <= 6) from base/interface/DI token -> concrete types
    let mut cha_implementors: HashMap<SymbolId, Vec<SymbolId>> = HashMap::new();
    for (&base_id, direct_subs) in &direct_implements {
        let mut visited: HashSet<SymbolId> = HashSet::new();
        let mut q: VecDeque<(SymbolId, usize)> = VecDeque::new();
        for &sub in direct_subs {
            if visited.insert(sub) {
                q.push_back((sub, 1));
            }
        }
        let mut concrete_list = Vec::new();
        while let Some((cur, depth)) = q.pop_front() {
            if !interface_type_ids.contains(&cur) && !concrete_list.contains(&cur) {
                concrete_list.push(cur);
            }
            if depth < 6
                && let Some(next_subs) = direct_implements.get(&cur)
            {
                for &ns in next_subs {
                    if visited.insert(ns) {
                        q.push_back((ns, depth + 1));
                    }
                }
            }
        }
        if !concrete_list.is_empty() {
            cha_implementors.insert(base_id, concrete_list);
        }
    }

    let mut file_imports: HashMap<SymbolId, Vec<(SymbolId, SymbolId, SymbolId)>> = HashMap::new();
    let mut namespace_imports: HashMap<(SymbolId, SymbolId), SymbolId> = HashMap::new();
    let mut go_pkg_imports: HashMap<(SymbolId, SymbolId), Vec<SymbolId>> = HashMap::new();

    let import_index = ImportFileIndex::new(&known_files);
    for f in summaries {
        let fid = arena.intern(&f.rel_path);
        let mut imps = Vec::new();
        for imp in &f.imports {
            if let Some(go_path) = imp.from_specifier.strip_prefix("go::") {
                let clean_go = go_path.trim().trim_matches('/');
                let local_id = arena.intern(&imp.symbol_name);
                for dir in &known_go_dirs {
                    if clean_go == dir.as_str() || clean_go.ends_with(&format!("/{dir}")) {
                        let dir_id = arena.intern(dir);
                        let entry = go_pkg_imports.entry((fid, local_id)).or_default();
                        if !entry.contains(&dir_id) {
                            entry.push(dir_id);
                        }
                    }
                }
                continue;
            }
            if let Some(target_file) =
                resolve_import_target_indexed(&f.rel_path, &imp.from_specifier, &import_index)
            {
                let remote = imp.remote_name.as_deref().unwrap_or(&imp.symbol_name);
                let local_id = arena.intern(&imp.symbol_name);
                let target_id = arena.intern(&target_file);
                let remote_id = arena.intern(remote);
                if remote_id == wildcard_id && local_id != wildcard_id {
                    namespace_imports.insert((fid, local_id), target_id);
                }
                imps.push((local_id, target_id, remote_id));
            }
        }
        if !imps.is_empty() {
            file_imports.insert(fid, imps);
        }
    }

    // B11: O(1) edge deduplication via HashSet<(usize, usize)> & u32 SymbolId arena keys
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    let mut resolved_callee_map: HashMap<(usize, SymbolId), Vec<NodeIndex>> = HashMap::new();
    // Phase 12A: Ambiguous polymorphic dispatch edges `(src, dst) -> all concrete sibling targets`
    let mut ambiguous_dispatch_edges: HashMap<(usize, usize), Vec<NodeIndex>> = HashMap::new();
    // Phase 12A: Track CHA-resolved guard callees per caller for sound interface-wrapped guard propagation
    let mut caller_cha_guard_groups: HashMap<usize, Vec<Vec<NodeIndex>>> = HashMap::new();

    let defined_symbol_ids: HashSet<SymbolId> =
        file_symbols_map.keys().map(|&(_, sym_id)| sym_id).collect();
    let mut resolve_cache: HashMap<(SymbolId, SymbolId), Vec<NodeIndex>> = HashMap::new();

    for f in summaries {
        let file_id = arena.intern(&f.rel_path);
        let is_go = f.rel_path.ends_with(".go");
        let go_dir = if is_go {
            go_parent_dir(&f.rel_path)
        } else {
            String::new()
        };
        let go_dir_id = arena.intern(&go_dir);
        let pkg_dir_id = if is_phase8_pkg_scoped(&f.rel_path) {
            arena.intern(&go_parent_dir(&f.rel_path))
        } else {
            SymbolId(0)
        };
        for sym in &f.symbols {
            let Some(&src_idx) = arena.get(&sym.id).and_then(|sid| id_to_idx.get(&sid)) else {
                continue;
            };
            let src_enclosing_ty_id = sym.enclosing_type.as_deref().map(|t| arena.intern(t));

            // 1. Resolve qualified `CallSite`s first (namespace imports, Go package imports, CHA/RTA receiver dispatch)
            let mut qualified_members_handled: HashSet<SymbolId> = HashSet::new();
            for cs in &sym.call_sites {
                let member_id = arena.intern(&cs.member);
                let mut dst_indices: Vec<NodeIndex> = Vec::new();
                let mut is_cha_dispatch = false;

                // 1a. Explicit namespace/module import (`ns.fn()` / `db.query()`)
                if let Some(ref qual) = cs.qualifier {
                    let qual_id = arena.intern(qual);
                    if let Some(&target_file_id) = namespace_imports.get(&(file_id, qual_id)) {
                        let resolved = resolve_symbol_in_file(
                            target_file_id,
                            member_id,
                            &file_symbols_map,
                            &defined_symbol_ids,
                            &file_imports,
                            wildcard_id,
                            0,
                            &mut resolve_cache,
                        );
                        for idx in resolved {
                            if !dst_indices.contains(&idx) {
                                dst_indices.push(idx);
                            }
                        }
                        qualified_members_handled.insert(member_id);
                    } else if is_go
                        && let Some(target_dirs) = go_pkg_imports.get(&(file_id, qual_id))
                    {
                        for &tdir in target_dirs {
                            if let Some(pkg_idxs) = go_dir_map.get(&(tdir, member_id)) {
                                for &idx in pkg_idxs {
                                    if !dst_indices.contains(&idx) {
                                        dst_indices.push(idx);
                                    }
                                }
                            }
                        }
                        qualified_members_handled.insert(member_id);
                    }
                }

                // 1b. Typed receiver / Class / Interface / Trait / DI CHA+RTA dispatch
                if dst_indices.is_empty()
                    && let Some(ref recv_ty) = cs.resolved_recv_type
                {
                    let recv_ty_id = arena.intern(recv_ty);
                    // Direct method on concrete receiver type
                    if !interface_type_ids.contains(&recv_ty_id)
                        && let Some(direct) = type_methods_map.get(&(recv_ty_id, member_id))
                    {
                        for &idx in direct {
                            if !dst_indices.contains(&idx) {
                                dst_indices.push(idx);
                            }
                        }
                    }
                    // CHA/RTA subtype & DI implementor dispatch
                    if let Some(all_impls) = cha_implementors.get(&recv_ty_id) {
                        // RTA narrowing: if any implementor of `recv_ty` is instantiated, narrow to instantiated subset
                        let rta_subset: Vec<SymbolId> = all_impls
                            .iter()
                            .copied()
                            .filter(|t| rta_instantiated_types.contains(t))
                            .collect();
                        let chosen_impls = if !rta_subset.is_empty() {
                            &rta_subset
                        } else {
                            all_impls
                        };
                        let cha_truncated = chosen_impls.len() > max_cha_targets;
                        for &impl_ty_id in chosen_impls.iter().take(max_cha_targets) {
                            if let Some(m_idxs) = type_methods_map.get(&(impl_ty_id, member_id)) {
                                for &idx in m_idxs {
                                    if !dst_indices.contains(&idx) {
                                        dst_indices.push(idx);
                                    }
                                }
                            }
                        }
                        if !dst_indices.is_empty() && !cha_truncated {
                            is_cha_dispatch = true;
                        }
                    }
                    if !dst_indices.is_empty() || interface_type_ids.contains(&recv_ty_id) {
                        qualified_members_handled.insert(member_id);
                    }
                }

                if !dst_indices.is_empty() {
                    let is_ambiguous = is_cha_dispatch && dst_indices.len() > 1;
                    if is_cha_dispatch {
                        caller_cha_guard_groups
                            .entry(src_idx.index())
                            .or_default()
                            .push(dst_indices.clone());
                    }
                    for &dst_idx in &dst_indices {
                        if src_idx != dst_idx {
                            let entry = resolved_callee_map
                                .entry((src_idx.index(), member_id))
                                .or_default();
                            if !entry.contains(&dst_idx) {
                                entry.push(dst_idx);
                            }
                            if seen_edges.insert((src_idx.index(), dst_idx.index())) {
                                graph.add_edge(src_idx, dst_idx, ());
                            }
                            if is_ambiguous {
                                ambiguous_dispatch_edges.insert(
                                    (src_idx.index(), dst_idx.index()),
                                    dst_indices.clone(),
                                );
                            }
                        }
                    }
                }
            }

            // 2. Standard unqualified / imported / package-scoped call resolution for remaining callees
            let mut resolve_one = |callee: &String, add_edge: bool| {
                let callee_id = arena.intern(callee);
                if qualified_members_handled.contains(&callee_id) {
                    return;
                }
                let mut dst_indices: Vec<NodeIndex> = Vec::new();
                if let Some(same_file_idxs) = file_symbols_map.get(&(file_id, callee_id)) {
                    // Prefer free functions or methods on the same enclosing type to avoid sibling-class `.save()` collisions
                    let scoped: Vec<NodeIndex> = same_file_idxs
                        .iter()
                        .copied()
                        .filter(|&idx| {
                            let dst_enc = graph[idx].enclosing_type.as_deref();
                            match (dst_enc, src_enclosing_ty_id) {
                                (None, _) => true,
                                (Some(dt), Some(st_id)) => arena.get(dt) == Some(st_id),
                                (Some(_), None) => false,
                            }
                        })
                        .collect();
                    if !scoped.is_empty() {
                        dst_indices.extend(scoped);
                    } else if !sym.call_sites.iter().any(|cs| {
                        cs.member == *callee
                            && cs.qualifier.is_some()
                            && cs.qualifier.as_deref() != Some("this")
                            && cs.qualifier.as_deref() != Some("self")
                    }) {
                        dst_indices.extend(same_file_idxs.iter().copied());
                    }
                }
                if dst_indices.is_empty()
                    && let Some(imps) = file_imports.get(&file_id)
                {
                    for &(local_name_id, target_file_id, remote_name_id) in imps {
                        if local_name_id == callee_id {
                            let resolved = resolve_symbol_in_file(
                                target_file_id,
                                remote_name_id,
                                &file_symbols_map,
                                &defined_symbol_ids,
                                &file_imports,
                                wildcard_id,
                                0,
                                &mut resolve_cache,
                            );
                            for idx in resolved {
                                if !dst_indices.contains(&idx) {
                                    dst_indices.push(idx);
                                }
                            }
                        } else if local_name_id == wildcard_id {
                            let resolved = resolve_symbol_in_file(
                                target_file_id,
                                callee_id,
                                &file_symbols_map,
                                &defined_symbol_ids,
                                &file_imports,
                                wildcard_id,
                                0,
                                &mut resolve_cache,
                            );
                            for idx in resolved {
                                if !dst_indices.contains(&idx) {
                                    dst_indices.push(idx);
                                }
                            }
                        }
                    }
                }
                if dst_indices.is_empty() && is_go {
                    if let Some(same_pkg_idxs) = go_dir_map.get(&(go_dir_id, callee_id)) {
                        dst_indices.extend(same_pkg_idxs.iter().copied());
                    }
                    // Go dot-import `. "pkg/path"` resolves unqualified exported symbols strictly from imported dirs
                    if dst_indices.is_empty()
                        && let Some(dot_dirs) = go_pkg_imports.get(&(file_id, wildcard_id))
                    {
                        for &tdir in dot_dirs {
                            if let Some(pkg_idxs) = go_dir_map.get(&(tdir, callee_id)) {
                                for &idx in pkg_idxs {
                                    if !dst_indices.contains(&idx) {
                                        dst_indices.push(idx);
                                    }
                                }
                            }
                        }
                    }
                } else if dst_indices.is_empty()
                    && pkg_dir_id != SymbolId(0)
                    && let Some(same_dir_idxs) = pkg_dir_map.get(&(pkg_dir_id, callee_id))
                {
                    dst_indices.extend(same_dir_idxs.iter().copied());
                }

                for dst_idx in dst_indices {
                    if src_idx != dst_idx {
                        let entry = resolved_callee_map
                            .entry((src_idx.index(), callee_id))
                            .or_default();
                        if !entry.contains(&dst_idx) {
                            entry.push(dst_idx);
                        }
                        if add_edge && seen_edges.insert((src_idx.index(), dst_idx.index())) {
                            graph.add_edge(src_idx, dst_idx, ());
                        }
                    }
                }
            };

            for callee in sym
                .calls
                .iter()
                .chain(sym.tainted_calls.iter())
                .chain(sym.param_forwarding_calls.iter())
            {
                resolve_one(callee, true);
            }
            for (_, cb_name, _) in &sym.callback_forwards {
                resolve_one(cb_name, false);
            }
        }
    }

    // Phase 10: materialize callback edges (`runner -> cb`) when `runner` invokes its callback param
    let mut cb_graph_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();
    for u in graph.node_indices() {
        for (runner, cb_name, _) in &graph[u].callback_forwards {
            if let (Some(rid), Some(cid)) = (arena.get(runner), arena.get(cb_name))
                && let (Some(runners), Some(cbs)) = (
                    resolved_callee_map.get(&(u.index(), rid)),
                    resolved_callee_map.get(&(u.index(), cid)),
                )
            {
                for &rn in runners {
                    if graph[rn].invokes_callback_mask != 0 {
                        for &cn in cbs {
                            cb_graph_edges.push((rn, cn));
                        }
                    }
                }
            }
        }
    }
    for (rn, cn) in cb_graph_edges {
        if rn != cn && seen_edges.insert((rn.index(), cn.index())) {
            graph.add_edge(rn, cn, ());
        }
    }

    // Apply cross-file subpath auth prefixes (`app.use('/admin', requireAuth)`) across all Route nodes
    let mut global_auth_prefixes: Vec<String> = Vec::new();
    for f in summaries {
        for p in &f.route_prefixes {
            if let Some(sub) = p.strip_prefix("__AUTH_PREFIX__:")
                && !sub.is_empty()
                && !global_auth_prefixes.iter().any(|x| x == sub)
            {
                global_auth_prefixes.push(sub.to_string());
            }
        }
    }
    if !global_auth_prefixes.is_empty() {
        for idx in graph.node_indices() {
            if graph[idx].kind == SymbolKind::Route
                && let Some(ref rp) = graph[idx].route_path
                && global_auth_prefixes
                    .iter()
                    .any(|ap| rp == ap || rp.starts_with(&format!("{}/", ap.trim_end_matches('/'))))
            {
                graph[idx].guards.insert(GuardKind::Auth);
            }
        }
    }

    // Propagate CFG-verified Auth/TxLock guards from resolved middleware & interface-wrapped CHA guard callees
    // to full convergence (Council CASE-001 T2 ruling: true fixpoint loop, not hardcoded 2 rounds).
    let mut ambiguous_guard_callers: HashSet<(usize, GuardKind)> = HashSet::new();
    let max_mw_rounds = graph.node_count().clamp(4, 256);
    for _ in 0..max_mw_rounds {
        let mut add_guards: Vec<(NodeIndex, HashSet<GuardKind>)> = Vec::new();
        for u in graph.node_indices() {
            let mut found = HashSet::new();
            if !graph[u].middleware_callees.is_empty() {
                let mw_set: HashSet<&str> = graph[u]
                    .middleware_callees
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                for v in graph.neighbors_directed(u, Direction::Outgoing) {
                    let vname = graph[v].name.as_str();
                    let vshort = vname.rsplit('.').next().unwrap_or(vname);
                    if mw_set.contains(vname) || mw_set.contains(vshort) {
                        if graph[v].guards.contains(&GuardKind::Auth) {
                            found.insert(GuardKind::Auth);
                        }
                        if graph[v].guards.contains(&GuardKind::TxLock) {
                            found.insert(GuardKind::TxLock);
                        }
                    }
                }
            }
            // Phase 12A (`P12-02`): Interface-wrapped Auth/TxLock guard propagation (sound universal intersection)
            if let Some(groups) = caller_cha_guard_groups.get(&u.index()) {
                for targets in groups {
                    if targets.is_empty() {
                        continue;
                    }
                    for gk in [GuardKind::Auth, GuardKind::TxLock] {
                        let any_has = targets.iter().any(|&t| graph[t].guards.contains(&gk));
                        let all_have = targets.iter().all(|&t| graph[t].guards.contains(&gk));
                        if all_have {
                            found.insert(gk);
                        } else if any_has && targets.len() > 1 {
                            ambiguous_guard_callers.insert((u.index(), gk));
                        }
                    }
                }
            }
            if !found.is_empty() {
                add_guards.push((u, found));
            }
        }
        let mut changed = false;
        for (u, fg) in add_guards {
            let before = graph[u].guards.len();
            graph[u].guards.extend(fg);
            if graph[u].guards.len() > before {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // O(V + E) Worklist Fixed-Point Guard-Set Lattice using Copy-only 4-byte GuardBitset(u32):
    // G(v) = Intersection_{p in Pred(v)} ( G(p) ) U NodeGuards(v)
    let node_count = graph.node_count();
    let sym_guard_bits: Vec<GuardBitset> = graph
        .node_indices()
        .map(|idx| GuardBitset::from_set(&graph[idx].guards))
        .collect();
    let mut reachable = vec![false; node_count];
    let mut guard_in: Vec<Option<GuardBitset>> = vec![None; node_count];
    let mut guard_out: Vec<GuardBitset> = vec![GuardBitset::EMPTY; node_count];
    let mut queue = VecDeque::new();
    let mut route_entries = 0usize;

    for idx in graph.node_indices() {
        let sym = &graph[idx];
        if sym.kind == SymbolKind::Route {
            route_entries += 1;
            reachable[idx.index()] = true;
            guard_in[idx.index()] = Some(GuardBitset::EMPTY);
            guard_out[idx.index()] = sym_guard_bits[idx.index()];
            queue.push_back(idx);
        }
    }

    while let Some(u) = queue.pop_front() {
        let u_out = guard_out[u.index()];
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            let changed = if !reachable[vi] {
                reachable[vi] = true;
                guard_in[vi] = Some(u_out);
                guard_out[vi] = u_out.union(sym_guard_bits[vi]);
                true
            } else {
                let prev_in = guard_in[vi].unwrap_or(GuardBitset::EMPTY);
                let intersected = prev_in.intersect(u_out);
                if intersected != prev_in {
                    guard_in[vi] = Some(intersected);
                    let next_out = intersected.union(sym_guard_bits[vi]);
                    if next_out != guard_out[vi] {
                        guard_out[vi] = next_out;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if changed {
                queue.push_back(v);
            }
        }
    }

    // B11: Precompute ONE single forward multi-source BFS tree per GuardKind -> O(V + E) total!
    let auth_parents = build_unguarded_bfs_tree(&graph, GuardKind::Auth, public_routes);
    let lock_parents = build_unguarded_bfs_tree(&graph, GuardKind::TxLock, public_routes);
    let route_parents = build_any_route_bfs_tree(&graph);

    // Phase 10 helper: resolve cross-file sanitizer wrapper clear bitmask for `(caller, wrapper_fn, field_opt)`
    let resolved_wrapper_clear_mask =
        |caller_idx: NodeIndex, wrapper_fn: &str, field_opt: Option<&str>| -> u8 {
            let Some(wid) = arena.get(wrapper_fn) else {
                return 0;
            };
            let Some(targets) = resolved_callee_map.get(&(caller_idx.index(), wid)) else {
                return 0;
            };
            if targets.is_empty() {
                return 0;
            }
            let mut combined = u8::MAX;
            for &t in targets {
                let ts = &graph[t];
                let clear = match field_opt {
                    Some(fld) => {
                        ts.clears_field_masks.get(fld).copied().unwrap_or(0) | ts.clears_taint_mask
                    }
                    None => ts.clears_taint_mask,
                };
                combined &= clear;
            }
            if combined == u8::MAX { 0 } else { combined }
        };

    // O(V + E) Sink-Typed Bitmask Join-Semilattice Taint Propagation (`tainted_call_masks`, field maps, & callbacks)
    let mut taint_parents: Vec<Option<NodeIndex>> = vec![None; node_count];
    let mut taint_bit_parents: Vec<[Option<NodeIndex>; 5]> = vec![[None; 5]; node_count];
    let mut taint_mask: Vec<u8> = vec![0; node_count];
    let mut unrestricted_taint_mask: Vec<u8> = vec![0; node_count];
    let mut taint_field_masks: Vec<HashMap<String, u8>> = vec![HashMap::new(); node_count];
    let mut has_field_restriction: Vec<bool> = vec![false; node_count];
    let mut taint_q = VecDeque::new();

    #[allow(clippy::too_many_arguments)]
    let push_field_taint_edges =
        |arena: &SymbolArena,
         resolved_callee_map: &HashMap<(usize, SymbolId), Vec<NodeIndex>>,
         src_node: NodeIndex,
         callee: &str,
         out_mask: u8,
         src_fields: Option<&[(String, u8)]>,
         taint_parents: &mut [Option<NodeIndex>],
         taint_bit_parents: &mut [[Option<NodeIndex>; 5]],
         taint_mask: &mut [u8],
         unrestricted_taint_mask: &mut [u8],
         taint_field_masks: &mut [HashMap<String, u8>],
         has_field_restriction: &mut [bool],
         taint_q: &mut VecDeque<NodeIndex>| {
            if out_mask == 0 {
                return;
            }
            let Some(cid) = arena.get(callee) else {
                return;
            };
            if let Some(vs) = resolved_callee_map.get(&(src_node.index(), cid)) {
                for &v in vs {
                    let vi = v.index();
                    if taint_parents[vi].is_none() {
                        taint_parents[vi] = Some(src_node);
                    }
                    record_bit_parents(taint_bit_parents, vi, out_mask, src_node);
                    let mut changed = false;
                    let next = taint_mask[vi] | out_mask;
                    if next != taint_mask[vi] {
                        taint_mask[vi] = next;
                        changed = true;
                    }
                    if let Some(fields) = src_fields {
                        has_field_restriction[vi] = true;
                        for (fld, fm) in fields {
                            let effective_fm = *fm & out_mask;
                            if effective_fm != 0 {
                                let entry = taint_field_masks[vi].entry(fld.clone()).or_insert(0);
                                let nfm = *entry | effective_fm;
                                if nfm != *entry {
                                    *entry = nfm;
                                    changed = true;
                                }
                            }
                        }
                    } else {
                        let next_unrest = unrestricted_taint_mask[vi] | out_mask;
                        if next_unrest != unrestricted_taint_mask[vi] {
                            unrestricted_taint_mask[vi] = next_unrest;
                            changed = true;
                        }
                    }
                    if changed {
                        taint_q.push_back(v);
                    }
                }
            }
        };

    for routes_first in [true, false] {
        for u in graph.node_indices() {
            let is_route_entry = graph[u].kind == SymbolKind::Route;
            if is_route_entry != routes_first {
                continue;
            }
            let seed_delegated_route_calls = is_route_entry
                && graph[u].tainted_calls.is_empty()
                && graph[u].param_forwarding_calls.is_empty()
                && !graph[u].has_taint_source
                && graph[u].has_resource_id;
            let seed_iter = graph[u]
                .tainted_calls
                .iter()
                .chain(if is_route_entry {
                    graph[u].param_forwarding_calls.as_slice()
                } else {
                    &[]
                })
                .chain(if seed_delegated_route_calls {
                    graph[u].calls.as_slice()
                } else {
                    &[]
                });
            for callee in seed_iter {
                let mut edge_mask = graph[u]
                    .tainted_call_masks
                    .get(callee)
                    .copied()
                    .unwrap_or(TAINT_ALL);
                for (wc, wfn, wfld, wmask) in &graph[u].tainted_call_wrappers {
                    if wc == callee {
                        let cleared = resolved_wrapper_clear_mask(u, wfn, wfld.as_deref()) & *wmask;
                        edge_mask &= !cleared;
                    }
                }
                let src_fields = graph[u]
                    .tainted_field_calls
                    .get(callee)
                    .map(|v| v.as_slice());
                push_field_taint_edges(
                    &arena,
                    &resolved_callee_map,
                    u,
                    callee,
                    edge_mask,
                    src_fields,
                    &mut taint_parents,
                    &mut taint_bit_parents,
                    &mut taint_mask,
                    &mut unrestricted_taint_mask,
                    &mut taint_field_masks,
                    &mut has_field_restriction,
                    &mut taint_q,
                );
            }
            // Phase 10: cross-file callback dispatch (`dispatchTask(req.body.cmd, workerCb)`)
            for (runner, cb_name, cb_mask) in &graph[u].callback_forwards {
                let (Some(rid), Some(cid)) = (arena.get(runner), arena.get(cb_name)) else {
                    continue;
                };
                let Some(runner_targets) = resolved_callee_map.get(&(u.index(), rid)) else {
                    continue;
                };
                let Some(cb_targets) = resolved_callee_map.get(&(u.index(), cid)) else {
                    continue;
                };
                if let Some(&runner_node) = runner_targets
                    .iter()
                    .find(|&&rn| graph[rn].invokes_callback_mask != 0)
                {
                    let ri = runner_node.index();
                    if taint_parents[ri].is_none() {
                        taint_parents[ri] = Some(u);
                    }
                    let eff_mask = *cb_mask & graph[runner_node].invokes_callback_mask;
                    record_bit_parents(&mut taint_bit_parents, ri, eff_mask, u);
                    if eff_mask != 0 {
                        for &cb_node in cb_targets {
                            let ci = cb_node.index();
                            if taint_parents[ci].is_none() {
                                taint_parents[ci] = Some(runner_node);
                            }
                            record_bit_parents(&mut taint_bit_parents, ci, eff_mask, runner_node);
                            unrestricted_taint_mask[ci] |= eff_mask;
                            let next = taint_mask[ci] | eff_mask;
                            if next != taint_mask[ci] {
                                taint_mask[ci] = next;
                                taint_q.push_back(cb_node);
                            }
                        }
                    }
                }
            }
        }
    }
    while let Some(w) = taint_q.pop_front() {
        let w_mask = taint_mask[w.index()];
        let w_unrest = unrestricted_taint_mask[w.index()];
        let w_fields: Vec<(String, u8)> = taint_field_masks[w.index()]
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        let w_restricted = has_field_restriction[w.index()];
        for callee in &graph[w].tainted_calls {
            let mut edge_mask = graph[w]
                .tainted_call_masks
                .get(callee)
                .copied()
                .unwrap_or(TAINT_ALL);
            for (wc, wfn, wfld, wmask) in &graph[w].tainted_call_wrappers {
                if wc == callee {
                    let cleared = resolved_wrapper_clear_mask(w, wfn, wfld.as_deref()) & *wmask;
                    edge_mask &= !cleared;
                }
            }
            let src_fields = graph[w]
                .tainted_field_calls
                .get(callee)
                .map(|v| v.as_slice());
            push_field_taint_edges(
                &arena,
                &resolved_callee_map,
                w,
                callee,
                edge_mask,
                src_fields,
                &mut taint_parents,
                &mut taint_bit_parents,
                &mut taint_mask,
                &mut unrestricted_taint_mask,
                &mut taint_field_masks,
                &mut has_field_restriction,
                &mut taint_q,
            );
        }
        for callee in &graph[w].param_forwarding_calls {
            let mut edge_mask = graph[w]
                .tainted_call_masks
                .get(callee)
                .copied()
                .unwrap_or(TAINT_ALL);
            for (wc, wfn, wfld, wmask) in &graph[w].tainted_call_wrappers {
                if wc == callee {
                    let cleared = resolved_wrapper_clear_mask(w, wfn, wfld.as_deref()) & *wmask;
                    edge_mask &= !cleared;
                }
            }
            let forwarded_fields = if let Some(explicit) = graph[w].tainted_field_calls.get(callee)
            {
                Some(explicit.as_slice())
            } else if w_restricted {
                Some(w_fields.as_slice())
            } else {
                None
            };
            push_field_taint_edges(
                &arena,
                &resolved_callee_map,
                w,
                callee,
                w_mask & edge_mask,
                forwarded_fields,
                &mut taint_parents,
                &mut taint_bit_parents,
                &mut taint_mask,
                &mut unrestricted_taint_mask,
                &mut taint_field_masks,
                &mut has_field_restriction,
                &mut taint_q,
            );
            if !graph[w].tainted_field_calls.contains_key(callee)
                && w_restricted
                && (w_unrest & edge_mask) != 0
            {
                push_field_taint_edges(
                    &arena,
                    &resolved_callee_map,
                    w,
                    callee,
                    w_unrest & edge_mask,
                    None,
                    &mut taint_parents,
                    &mut taint_bit_parents,
                    &mut taint_mask,
                    &mut unrestricted_taint_mask,
                    &mut taint_field_masks,
                    &mut has_field_restriction,
                    &mut taint_q,
                );
            }
        }
        for (runner, cb_name, cb_mask) in &graph[w].callback_forwards {
            let (Some(rid), Some(cid)) = (arena.get(runner), arena.get(cb_name)) else {
                continue;
            };
            let Some(runner_targets) = resolved_callee_map.get(&(w.index(), rid)) else {
                continue;
            };
            let Some(cb_targets) = resolved_callee_map.get(&(w.index(), cid)) else {
                continue;
            };
            if let Some(&runner_node) = runner_targets
                .iter()
                .find(|&&rn| graph[rn].invokes_callback_mask != 0)
            {
                let ri = runner_node.index();
                if taint_parents[ri].is_none() {
                    taint_parents[ri] = Some(w);
                }
                let eff_mask = w_mask & *cb_mask & graph[runner_node].invokes_callback_mask;
                record_bit_parents(&mut taint_bit_parents, ri, eff_mask, w);
                if eff_mask != 0 {
                    for &cb_node in cb_targets {
                        let ci = cb_node.index();
                        if taint_parents[ci].is_none() {
                            taint_parents[ci] = Some(runner_node);
                        }
                        record_bit_parents(&mut taint_bit_parents, ci, eff_mask, runner_node);
                        unrestricted_taint_mask[ci] |= eff_mask;
                        let next = taint_mask[ci] | eff_mask;
                        if next != taint_mask[ci] {
                            taint_mask[ci] = next;
                            taint_q.push_back(cb_node);
                        }
                    }
                }
            }
        }
    }
    let _ = push_taint_edges;

    // O(V + E) Sound IDOR Unguarded Witness Tree & Resource-ID Reachability
    let (idor_parents, idor_res_reaches) =
        build_idor_unguarded_bfs_tree(&graph, &guard_out, public_routes);

    let mut repo_has_cookie_session = false;
    let mut repo_has_bearer_auth = false;
    let mut repo_has_global_csrf = false;
    for f in summaries {
        repo_has_cookie_session |= f.has_cookie_session_setup;
        repo_has_bearer_auth |= f.has_bearer_auth_setup;
        repo_has_global_csrf |= f.has_global_csrf_guard;
    }
    let repo_bearer_only = repo_has_bearer_auth && !repo_has_cookie_session;

    // Deduplicate on the fly by (entry_route, rule_id)
    let mut best_by_key: HashMap<(String, String), LatticeFinding> = HashMap::new();

    // Helper: returns true if a witness path traverses an ambiguous polymorphic dispatch edge
    // where NOT all concrete sibling targets share the vulnerability/missing guard (Zero-Hallucination gate).
    let witness_is_polymorphically_ambiguous =
        |tree: &BfsTree, sink: NodeIndex, required_guard: GuardKind| -> bool {
            let mut cur = sink;
            for _ in 0..max_witness_hops {
                if ambiguous_guard_callers.contains(&(cur.index(), required_guard)) {
                    return true;
                }
                let Some(p) = tree.parent[cur.index()] else {
                    break;
                };
                if p == cur {
                    break;
                }
                if let Some(siblings) = ambiguous_dispatch_edges.get(&(p.index(), cur.index())) {
                    // Confirmed ONLY if every concrete implementor lacks the guard AND is a matching sink;
                    // if any sibling implementor is safe/guarded or not a sink, downgrade to Heuristic.
                    let all_vulnerable = siblings.iter().all(|&sib| {
                        !guard_out[sib.index()].contains(required_guard)
                            && graph[sib].sink_kind.is_some()
                    });
                    if !all_vulnerable {
                        return true;
                    }
                }
                cur = p;
            }
            false
        };

    for idx in graph.node_indices() {
        let vi = idx.index();
        let sym = &graph[idx];
        let active_guards = guard_out[vi];

        // Layer 1 & Layer 2 (Auth & Concurrency/TxLock) — requires reachable Route + SinkKind
        if reachable[vi]
            && let Some(sink_kind) = sym.sink_kind
        {
            if !active_guards.contains(GuardKind::Auth)
                && can_improve_witness(&best_by_key, &graph, &auth_parents, idx, "SMG-AUTH-001")
                && let Some((entry_name, witness)) = reconstruct_witness(&graph, &auth_parents, idx)
                && !is_public_route(&entry_name, public_routes)
            {
                let poly_ambig =
                    witness_is_polymorphically_ambiguous(&auth_parents, idx, GuardKind::Auth);
                let mut reasons = vec![
                    "O(V+E)Lattice".into(),
                    "CFGDominated".into(),
                    "AuthGuardMissing".into(),
                ];
                if poly_ambig {
                    reasons.push("AmbiguousPolymorphicDispatch".into());
                }
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "SMG-AUTH-001".into(),
                        severity: "HIGH".into(),
                        title: format!("Unauthenticated path to {:?} in `{}`", sink_kind, sym.name),
                        file: String::new(),
                        line: 0,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: if poly_ambig {
                            Confidence::Heuristic
                        } else {
                            Confidence::Confirmed
                        },
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::Auth,
                        witness_path: witness,
                        remediation: remediation_for_guard(GuardKind::Auth).into(),
                        proof_reasons: reasons,
                    },
                );
            }

            if matches!(
                sink_kind,
                SinkKind::PaymentMutation | SinkKind::BalanceUpdate
            ) && !active_guards.contains(GuardKind::TxLock)
                && can_improve_witness(&best_by_key, &graph, &lock_parents, idx, "SMG-RACE-001")
                && let Some((entry_name, witness)) = reconstruct_witness(&graph, &lock_parents, idx)
            {
                let poly_ambig =
                    witness_is_polymorphically_ambiguous(&lock_parents, idx, GuardKind::TxLock);
                let mut reasons = vec![
                    "O(V+E)Lattice".into(),
                    "CFGDominated".into(),
                    "TxLockMissing".into(),
                ];
                if poly_ambig {
                    reasons.push("AmbiguousPolymorphicDispatch".into());
                }
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "SMG-RACE-001".into(),
                        severity: "CRITICAL".into(),
                        title: format!(
                            "Missing transaction/lock guard before `{}` (Double-Spend Risk)",
                            sym.name
                        ),
                        file: String::new(),
                        line: 0,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: if poly_ambig {
                            Confidence::Heuristic
                        } else {
                            Confidence::Confirmed
                        },
                        entry_route: entry_name,
                        sink_kind,
                        missing_guard: GuardKind::TxLock,
                        witness_path: witness,
                        remediation: remediation_for_guard(GuardKind::TxLock).into(),
                        proof_reasons: reasons,
                    },
                );
            }
        }

        // Layer 2a: Intra-procedural Injection / Path / SSRF / XSS hits (`Source -> Sink` inside node)
        for hit in &sym.local_taint_hits {
            if reachable[vi] && active_guards.contains(hit.missing_guard) {
                continue;
            }
            let req_bit = sink_bit_for_guard(hit.missing_guard);
            let sanitized_via_cross_file_wrapper =
                sym.local_hit_wrappers.iter().any(|(rid, ln, wfn, wf)| {
                    rid == &hit.rule_id
                        && *ln == hit.line
                        && (resolved_wrapper_clear_mask(idx, wfn, wf.as_deref()) & req_bit) != 0
                });
            if sanitized_via_cross_file_wrapper {
                continue;
            }
            let (entry_route, mut witness) =
                if let Some((er, w)) = reconstruct_witness(&graph, &route_parents, idx) {
                    (er, w)
                } else {
                    (
                        format!("{}:{}", hit.rel_path, hit.line),
                        vec![TraceHop {
                            file: hit.rel_path.clone(),
                            symbol: hit.symbol.clone(),
                            line: hit.line,
                        }],
                    )
                };
            if let Some(last) = witness.last_mut() {
                last.line = hit.line;
            }
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: hit.rule_id.clone(),
                    severity: hit.severity.clone(),
                    title: hit.title.clone(),
                    file: hit.rel_path.clone(),
                    line: hit.line,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: hit.confidence,
                    entry_route,
                    sink_kind: hit.sink_kind,
                    missing_guard: hit.missing_guard,
                    witness_path: witness,
                    remediation: hit.remediation.clone(),
                    proof_reasons: vec!["IntraProceduralTaint".into(), "ReceiverTyped".into()],
                },
            );
        }

        // Layer 2b: Cross-file / Inter-procedural Taint (`Source -> param_forwarding -> ParamSink`)
        if taint_parents[vi].is_some() && taint_mask[vi] != 0 {
            for hit in &sym.param_sinks {
                let req_bit = sink_bit_for_guard(hit.missing_guard);
                if (taint_mask[vi] & req_bit) == 0 {
                    continue;
                }
                if has_field_restriction[vi]
                    && (unrestricted_taint_mask[vi] & req_bit) == 0
                    && let Some((_, Some(fld))) = sym
                        .param_sink_fields
                        .iter()
                        .find(|(h, _)| h.rule_id == hit.rule_id && h.line == hit.line)
                {
                    let fm = taint_field_masks[vi].get(fld).copied().unwrap_or(0);
                    if (fm & req_bit) == 0 {
                        continue;
                    }
                }
                if reachable[vi] && active_guards.contains(hit.missing_guard) {
                    continue;
                }
                if let Some((entry_route, mut witness)) = reconstruct_taint_witness(
                    &graph,
                    &taint_parents,
                    &taint_bit_parents,
                    req_bit,
                    &route_parents,
                    idx,
                ) {
                    if let Some(last) = witness.last_mut() {
                        last.line = hit.line;
                    }
                    // Check whether cross-file taint traversed an ambiguous polymorphic dispatch edge
                    let mut poly_ambig = false;
                    let mut cur_t = idx;
                    for _ in 0..max_witness_hops {
                        let parent_opt = taint_bit_parents[cur_t.index()]
                            .get(req_bit.trailing_zeros() as usize)
                            .copied()
                            .flatten()
                            .or(taint_parents[cur_t.index()]);
                        let Some(p) = parent_opt else {
                            break;
                        };
                        if p == cur_t {
                            break;
                        }
                        if let Some(siblings) =
                            ambiguous_dispatch_edges.get(&(p.index(), cur_t.index()))
                        {
                            let all_vuln = siblings.iter().all(|&sib| {
                                graph[sib]
                                    .param_sinks
                                    .iter()
                                    .any(|ps| ps.rule_id == hit.rule_id)
                            });
                            if !all_vuln {
                                poly_ambig = true;
                                break;
                            }
                        }
                        cur_t = p;
                    }
                    let mut reasons = vec!["CrossFileTaint".into(), "ParamForwarding".into()];
                    if poly_ambig {
                        reasons.push("AmbiguousPolymorphicDispatch".into());
                    }
                    insert_shorter(
                        &mut best_by_key,
                        LatticeFinding {
                            id: String::new(),
                            rule_id: hit.rule_id.clone(),
                            severity: hit.severity.clone(),
                            title: hit.title.clone(),
                            file: hit.rel_path.clone(),
                            line: hit.line,
                            status: "SUSPECT_UNGUARDED".into(),
                            confidence: if poly_ambig {
                                Confidence::Heuristic
                            } else {
                                hit.confidence
                            },
                            entry_route,
                            sink_kind: hit.sink_kind,
                            missing_guard: hit.missing_guard,
                            witness_path: witness,
                            remediation: hit.remediation.clone(),
                            proof_reasons: reasons,
                        },
                    );
                }
            }
        }

        // Layer 2c: IDOR (`Auth` route + `resource_id` + DB CRUD read/update/delete without ownership filter)
        if reachable[vi]
            && sym.has_db_crud_sink
            && idor_res_reaches[vi]
            && !active_guards.contains(GuardKind::OwnershipCheck)
            && can_improve_witness(&best_by_key, &graph, &idor_parents, idx, "SMG-IDOR-001")
            && let Some((entry_name, mut witness)) = reconstruct_witness(&graph, &idor_parents, idx)
            && !is_public_route(&entry_name, public_routes)
            && !is_admin_route(&entry_name)
        {
            if let Some(last) = witness.last_mut()
                && let Some(ln) = sym.db_crud_line
            {
                last.line = ln;
            }
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: "SMG-IDOR-001".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "Potential IDOR: authenticated resource query in `{}` lacks ownership filter",
                        sym.name
                    ),
                    file: String::new(),
                    line: 0,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: Confidence::Confirmed,
                    entry_route: entry_name,
                    sink_kind: SinkKind::IdorDbAccess,
                    missing_guard: GuardKind::OwnershipCheck,
                    witness_path: witness,
                    remediation: remediation_for_guard(GuardKind::OwnershipCheck).into(),
                    proof_reasons: vec!["O(V+E)Lattice".into(), "OwnershipCheckMissing".into()],
                },
            );
        }

        // Layer 2e: CSRF (`SMG-CSRF-001`) on `@csrf_exempt` views or unguarded state-changing cookie/session routes
        let lower_sym_name = sym.name.to_ascii_lowercase();
        let is_webhook_or_health = (!is_admin_route(&sym.name)
            && (lower_sym_name.contains("/webhook") || lower_sym_name.ends_with("webhook")))
            || lower_sym_name.contains("/health")
            || lower_sym_name.contains("/metrics");
        if sym.csrf_exempt && !is_webhook_or_health && !sym.has_bearer_header_auth {
            let (entry_name, witness) =
                if let Some((er, w)) = reconstruct_witness(&graph, &route_parents, idx) {
                    (er, w)
                } else {
                    (
                        sym.name.clone(),
                        vec![TraceHop {
                            file: sym.rel_path.clone(),
                            symbol: sym.name.clone(),
                            line: sym.line_start,
                        }],
                    )
                };
            insert_shorter(
                &mut best_by_key,
                LatticeFinding {
                    id: String::new(),
                    rule_id: "SMG-CSRF-001".into(),
                    severity: "HIGH".into(),
                    title: format!(
                        "CSRF protection explicitly disabled (`@csrf_exempt`) on `{}`",
                        sym.name
                    ),
                    file: sym.rel_path.clone(),
                    line: sym.line_start,
                    status: "SUSPECT_UNGUARDED".into(),
                    confidence: Confidence::Confirmed,
                    entry_route: entry_name,
                    sink_kind: SinkKind::Csrf,
                    missing_guard: GuardKind::CsrfProtection,
                    witness_path: witness,
                    remediation: remediation_for_guard(GuardKind::CsrfProtection).into(),
                    proof_reasons: vec!["CsrfExemptExplicit".into()],
                },
            );
        } else if sym.kind == SymbolKind::Route
            && !is_webhook_or_health
            && !active_guards.contains(GuardKind::CsrfProtection)
            && !repo_has_global_csrf
            && !sym.has_bearer_header_auth
        {
            let method = sym.name.split_whitespace().next().unwrap_or("");
            let is_state_changing = matches!(method, "POST" | "PUT" | "PATCH" | "DELETE");
            let cookie_session_route = sym.has_cookie_session_auth
                || (active_guards.contains(GuardKind::Auth)
                    && repo_has_cookie_session
                    && !repo_bearer_only);
            if is_state_changing
                && cookie_session_route
                && !is_public_route(&sym.name, public_routes)
            {
                insert_shorter(
                    &mut best_by_key,
                    LatticeFinding {
                        id: String::new(),
                        rule_id: "SMG-CSRF-001".into(),
                        severity: "HIGH".into(),
                        title: format!(
                            "State-changing cookie/session endpoint `{}` lacks CSRF protection",
                            sym.name
                        ),
                        file: sym.rel_path.clone(),
                        line: sym.line_start,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Heuristic,
                        entry_route: sym.name.clone(),
                        sink_kind: SinkKind::Csrf,
                        missing_guard: GuardKind::CsrfProtection,
                        witness_path: vec![TraceHop {
                            file: sym.rel_path.clone(),
                            symbol: sym.name.clone(),
                            line: sym.line_start,
                        }],
                        remediation: remediation_for_guard(GuardKind::CsrfProtection).into(),
                        proof_reasons: vec!["CookieSessionStateChange".into()],
                    },
                );
            }
        }
    }

    // Layer 2d: Frontend <-> Backend API Contract Check (`SMG-FE-404`)
    if route_entries > 0 {
        let mut all_prefixes: Vec<String> = Vec::new();
        for f in summaries {
            for p in &f.route_prefixes {
                if !p.starts_with("__AUTH_PREFIX__:") && !all_prefixes.iter().any(|x| x == p) {
                    all_prefixes.push(p.clone());
                }
            }
        }

        let mut routes_by_seg_len: HashMap<usize, Vec<(String, Vec<String>)>> = HashMap::new();
        let mut wildcard_prefix_routes: Vec<(String, Vec<String>)> = Vec::new();
        let mut index_route = |method: &str, rp: &str, segs: Vec<String>| {
            if rp.ends_with("/*") {
                let mut prefix_segs = segs.clone();
                if prefix_segs.last().is_some_and(|s| s == "*") {
                    prefix_segs.pop();
                }
                if !prefix_segs.is_empty() {
                    wildcard_prefix_routes.push((method.to_string(), prefix_segs));
                }
            }
            routes_by_seg_len
                .entry(segs.len())
                .or_default()
                .push((method.to_string(), segs));
        };
        for idx in graph.node_indices() {
            let sym = &graph[idx];
            if sym.kind == SymbolKind::Route
                && let Some(ref rp) = sym.route_path
            {
                let method = sym
                    .name
                    .split_whitespace()
                    .next()
                    .unwrap_or("ANY")
                    .to_ascii_uppercase();
                let norm = crate::taint::normalize_api_path(rp);
                let segs: Vec<String> = norm
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                index_route(&method, rp, segs);

                for pref in &all_prefixes {
                    if !rp.starts_with(pref) {
                        let combined = format!(
                            "{}/{}",
                            pref.trim_end_matches('/'),
                            rp.trim_start_matches('/')
                        );
                        let pnorm = crate::taint::normalize_api_path(&combined);
                        let psegs: Vec<String> = pnorm
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        index_route(&method, &combined, psegs);
                    }
                }
            }
        }

        for f in summaries {
            for call in &f.frontend_calls {
                let csegs: Vec<&str> = call
                    .normalized_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                let exact_match = routes_by_seg_len.get(&csegs.len()).is_some_and(|cands| {
                    cands.iter().any(|(rmethod, rsegs)| {
                        let method_ok = rmethod == &call.method
                            || matches!(rmethod.as_str(), "HTTP" | "DJANGO" | "ANY");
                        method_ok
                            && rsegs
                                .iter()
                                .zip(csegs.iter())
                                .all(|(b, fseg)| b == *fseg || b == "*" || *fseg == "*")
                    })
                });
                let wildcard_match = wildcard_prefix_routes.iter().any(|(rmethod, psegs)| {
                    let method_ok = rmethod == &call.method
                        || matches!(rmethod.as_str(), "HTTP" | "DJANGO" | "ANY");
                    method_ok
                        && csegs.len() >= psegs.len()
                        && psegs
                            .iter()
                            .zip(csegs.iter())
                            .all(|(b, fseg)| b == *fseg || b == "*" || *fseg == "*")
                });
                let matched = exact_match || wildcard_match;
                if !matched {
                    let key = (
                        format!("{}:{}", call.rel_path, call.line),
                        "SMG-FE-404".to_string(),
                    );
                    best_by_key.entry(key).or_insert_with(|| LatticeFinding {
                        id: String::new(),
                        rule_id: "SMG-FE-404".into(),
                        severity: "MEDIUM".into(),
                        title: format!(
                            "Frontend `{}` call to `{}` has no matching backend route handler",
                            call.method, call.raw_path
                        ),
                        file: call.rel_path.clone(),
                        line: call.line,
                        status: "SUSPECT_UNGUARDED".into(),
                        confidence: Confidence::Heuristic,
                        entry_route: format!("{} {}", call.method, call.raw_path),
                        sink_kind: SinkKind::FrontendContract,
                        missing_guard: GuardKind::FrontendContract,
                        witness_path: vec![TraceHop {
                            file: call.rel_path.clone(),
                            symbol: call.symbol.clone(),
                            line: call.line,
                        }],
                        remediation: "Verify the backend route path, HTTP method, and router prefix match the frontend API call.".into(),
                        proof_reasons: vec!["FrontendBackendContractMismatch".into()],
                    });
                }
            }
        }
    }

    // Phase 9: Domain-Aware Analyzer Routing + Cross-Function Lock-Order Deadlock Solver
    let active_domains = crate::phase9::resolve_repo_domains(summaries);
    let active_domain_set: HashSet<&str> = active_domains.iter().map(|s| s.as_str()).collect();
    for deadlock_hit in crate::phase9::concurrency::solve_cross_function_deadlocks(
        &graph,
        &arena,
        &resolved_callee_map,
    ) {
        insert_shorter(&mut best_by_key, deadlock_hit);
    }

    // Layer 1 (Secrets), Layer 3 (Deps), Layer 4 (Misconfigs), Layer 2 UI Bugs (`SMG-FE-ERR`), & Phase 9 Domain Rules
    let mut sensitive_files: Vec<&str> = Vec::new();
    let mut gitignore_files: Vec<(&str, &[String])> = Vec::new();
    for f in summaries {
        if f.is_sensitive_env_or_pem {
            sensitive_files.push(&f.rel_path);
        }
        if let Some(ref lines) = f.gitignore_lines {
            gitignore_files.push((&f.rel_path, lines.as_slice()));
        }
        for sf in &f.static_findings {
            if crate::phase9::should_keep_finding_for_domain(sf, &active_domain_set) {
                insert_static_finding(&mut best_by_key, sf);
            }
        }
    }
    for env_hit in
        crate::secrets_config::check_gitignore_exposure(&sensitive_files, &gitignore_files)
    {
        insert_static_finding(&mut best_by_key, &env_hit);
    }

    let mut deduped: Vec<LatticeFinding> = best_by_key.into_values().collect();
    // Phase 12B (`P12-04`): Reverse-seeded CVE-only VEX reachability solver.
    // Only build `PackageImportIndex` and route-reachable symbol set when at least one `SMG-DEP-*`
    // advisory finding exists — wasting 0 work on clean lockfile dependencies.
    let has_dep_finding = deduped.iter().any(|f| f.rule_id.starts_with("SMG-DEP-"));
    if has_dep_finding {
        let pkg_index = crate::deps::build_package_import_index(summaries);
        let mut route_reachable_sym_ids: HashSet<String> = HashSet::new();
        for n in graph.node_indices() {
            if route_parents
                .root
                .get(n.index())
                .copied()
                .flatten()
                .is_some()
            {
                route_reachable_sym_ids.insert(graph[n].id.clone());
            }
        }
        for finding in &mut deduped {
            if let Some(tier) = crate::deps::assess_dependency_vex_tier(
                finding,
                &pkg_index,
                &route_reachable_sym_ids,
            ) {
                match tier {
                    crate::deps::VexReachabilityTier::ProvenRouteSymbol => {
                        finding.confidence = Confidence::Confirmed;
                        finding.proof_reasons.push("ProvenRouteSymbolVEX".into());
                        finding.proof_reasons.push("ReachableImport".into());
                    }
                    crate::deps::VexReachabilityTier::ImportedSafeApiOnly => {
                        if finding.confidence != Confidence::Proven {
                            finding.confidence = Confidence::Heuristic;
                        }
                        finding.proof_reasons.push("ImportedSafeApiOnlyVEX".into());
                    }
                    crate::deps::VexReachabilityTier::ImportedUnprovenSymbol => {
                        if finding.confidence != Confidence::Proven {
                            finding.confidence = Confidence::Heuristic;
                        }
                        finding
                            .proof_reasons
                            .push("ImportedUnprovenSymbolVEX".into());
                        finding.proof_reasons.push("ReachableImport".into());
                    }
                    crate::deps::VexReachabilityTier::DeclaredUnused => {
                        if finding.confidence != Confidence::Proven {
                            finding.confidence = Confidence::Heuristic;
                        }
                        finding.proof_reasons.push("DeclaredUnusedVEX".into());
                    }
                }
            }
        }
    }
    deduped.sort_by(|a, b| {
        let ta = if matches!(a.missing_guard, GuardKind::Auth | GuardKind::TxLock) {
            0u8
        } else {
            1u8
        };
        let tb = if matches!(b.missing_guard, GuardKind::Auth | GuardKind::TxLock) {
            0u8
        } else {
            1u8
        };
        ta.cmp(&tb).then_with(|| {
            if ta == 0 {
                a.entry_route
                    .cmp(&b.entry_route)
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
            } else {
                severity_rank(&a.severity)
                    .cmp(&severity_rank(&b.severity))
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
                    .then_with(|| a.entry_route.cmp(&b.entry_route))
                    .then_with(|| a.title.cmp(&b.title))
                    .then_with(|| {
                        let al = a.witness_path.first().map(|h| h.line).unwrap_or(0);
                        let bl = b.witness_path.first().map(|h| h.line).unwrap_or(0);
                        al.cmp(&bl)
                    })
            }
        })
    });

    let mut prefix_counts: HashMap<&'static str, usize> = HashMap::new();
    for item in deduped.iter_mut() {
        if let Some(primary) = item
            .witness_path
            .last()
            .or_else(|| item.witness_path.first())
        {
            if item.file.is_empty() {
                item.file = primary.file.clone();
            }
            if item.line == 0 {
                item.line = primary.line;
            }
        }
        let prefix = prefix_for_guard(item.missing_guard);
        let c = prefix_counts.entry(prefix).or_insert(0);
        *c += 1;
        item.id = format!("{}-{:03}", prefix, *c);
    }

    GraphAnalysisResult {
        parsed_files: summaries.len(),
        symbol_count: graph.node_count(),
        edge_count: graph.edge_count(),
        route_entries,
        active_domains,
        findings: deduped,
        route_schemas: crate::phase10::merge_repo_route_schemas(summaries),
    }
}

fn insert_shorter(best: &mut HashMap<(String, String), LatticeFinding>, cand: LatticeFinding) {
    let key = (cand.entry_route.clone(), cand.rule_id.clone());
    let replace = match best.get(&key) {
        Some(prev) => cand.witness_path.len() < prev.witness_path.len(),
        None => true,
    };
    if replace {
        best.insert(key, cand);
    }
}

fn proof_reasons_for_static_rule(rule_id: &str, confidence: Confidence) -> Vec<String> {
    if rule_id.starts_with("SMG-CICD-") {
        vec!["YamlStructuralAudit".into(), "ExpressionInjection".into()]
    } else if rule_id.starts_with("SMG-K8S-") || rule_id == "SMG-CFG-DOCKER" {
        vec!["ManifestStructuralAudit".into(), "PrivilegeBoundary".into()]
    } else if rule_id.starts_with("SMG-DOS-") || rule_id.starts_with("SMG-ZIP-") {
        vec!["AstStructuralSink".into(), "BoundsMissing".into()]
    } else if rule_id.starts_with("SMG-CRYPTO-") || rule_id == "SMG-CFG-CRYPTO" {
        vec!["CryptoPrimitiveAudit".into()]
    } else if rule_id.starts_with("SMG-QUEUE-") {
        vec!["AsyncQueueContextLoss".into()]
    } else if rule_id.starts_with("SMG-DEP-") {
        vec!["ManifestVersionMatch".into()]
    } else if rule_id.starts_with("SMG-HW-") {
        vec![
            "HardwareDomainProof".into(),
            "ReducedProductInterval".into(),
        ]
    } else if rule_id.starts_with("SMG-WEB3-") {
        if matches!(confidence, Confidence::Proven) {
            vec![
                "Web3StorageEffectGraph".into(),
                "RevmConcreteExecutionOracle".into(),
            ]
        } else {
            vec!["Web3StorageEffectGraph".into()]
        }
    } else if rule_id.starts_with("SMG-PQC-") {
        vec![
            "PostQuantumBitReductionLattice".into(),
            "MoscaHndlUrgency".into(),
        ]
    } else if rule_id.starts_with("SMG-SEC-") {
        vec!["EntropyAndTokenPattern".into()]
    } else {
        vec!["StaticPatternVerified".into()]
    }
}

/// Converts and appends isolated crate static findings (such as `smg-hw`) into `findings`
/// with deduplicated deterministic sequential IDs and proof metadata.
pub fn append_local_static_findings(
    findings: &mut Vec<LatticeFinding>,
    extra: &[LocalStaticFinding],
) {
    if extra.is_empty() {
        return;
    }
    fn norm_rule(r: &str) -> &str {
        if r == "SMG-MEM-BOUNDS" || r == "SMG-HW-BOUNDS" {
            "__BOUNDS__"
        } else {
            r
        }
    }
    let mut index_by_key: HashMap<(String, String), usize> =
        HashMap::with_capacity(findings.len().saturating_add(extra.len()));
    for (i, f) in findings.iter().enumerate() {
        index_by_key
            .entry((f.entry_route.clone(), norm_rule(&f.rule_id).to_string()))
            .or_insert(i);
    }
    let mut seq = findings.len();
    for sf in extra {
        let entry_route = format!("{}:{}", sf.rel_path, sf.line);
        let key = (entry_route.clone(), norm_rule(&sf.rule_id).to_string());
        if let Some(&idx) = index_by_key.get(&key) {
            let existing = &mut findings[idx];
            let should_replace = (existing.rule_id == "SMG-MEM-BOUNDS"
                && sf.rule_id == "SMG-HW-BOUNDS")
                || (matches!(sf.confidence, Confidence::Proven)
                    && !matches!(existing.confidence, Confidence::Proven))
                || (sf.severity == "CRITICAL" && existing.severity != "CRITICAL");
            if should_replace {
                existing.rule_id = sf.rule_id.clone();
                existing.severity = sf.severity.clone();
                existing.title = sf.title.clone();
                existing.confidence = sf.confidence;
                existing.status = if matches!(sf.confidence, Confidence::Proven) {
                    "PROVEN".into()
                } else {
                    "SUSPECT_UNGUARDED".into()
                };
                existing.remediation = sf.remediation.clone();
                existing.proof_reasons = proof_reasons_for_static_rule(&sf.rule_id, sf.confidence);
            }
            continue;
        }
        seq += 1;
        let new_idx = findings.len();
        index_by_key.insert(key, new_idx);
        findings.push(LatticeFinding {
            id: format!("{}-{}", sf.rule_id, seq),
            rule_id: sf.rule_id.clone(),
            severity: sf.severity.clone(),
            title: sf.title.clone(),
            file: sf.rel_path.clone(),
            line: sf.line,
            status: if matches!(sf.confidence, Confidence::Proven) {
                "PROVEN".into()
            } else {
                "SUSPECT_UNGUARDED".into()
            },
            confidence: sf.confidence,
            entry_route,
            sink_kind: sf.sink_kind,
            missing_guard: sf.missing_guard,
            witness_path: vec![TraceHop {
                file: sf.rel_path.clone(),
                symbol: sf.symbol.clone(),
                line: sf.line,
            }],
            remediation: sf.remediation.clone(),
            proof_reasons: proof_reasons_for_static_rule(&sf.rule_id, sf.confidence),
        });
    }
}

fn is_example_or_benchmark_path(rel_path: &str) -> bool {
    let low = rel_path.replace('\\', "/").to_ascii_lowercase();
    low.split('/')
        .any(|seg| matches!(seg, "examples" | "example" | "benchmark" | "benchmarks"))
}

fn insert_static_finding(
    best: &mut HashMap<(String, String), LatticeFinding>,
    sf: &LocalStaticFinding,
) {
    if smg_core::is_test_source_path(&sf.rel_path) {
        // Suppress dummy test-fixture certificates/keys and non-secret findings inside test trees
        // while keeping real provider credential leaks (`SMG-SEC-AWS`, `SMG-SEC-STRIPE`, etc.) active.
        let is_dummy_test_cert_or_env = matches!(
            sf.rule_id.as_str(),
            "SMG-SEC-KEY" | "SMG-SEC-PRIVKEY" | "SMG-SEC-ENV"
        );
        if is_dummy_test_cert_or_env
            || (sf.missing_guard != GuardKind::SecretPolicy && !sf.rule_id.starts_with("SMG-SEC-"))
        {
            return;
        }
    }
    if is_example_or_benchmark_path(&sf.rel_path)
        && matches!(
            sf.rule_id.as_str(),
            "SMG-ENG-INT" | "SMG-MEM-BOUNDS" | "SMG-ENG-LEAK" | "SMG-SEC-KEY" | "SMG-SEC-ENV"
        )
    {
        return;
    }
    let entry_route = format!("{}:{}", sf.rel_path, sf.line);
    let dedup_rule_key = if sf.rule_id.starts_with("SMG-DEP-") {
        format!("{}#{}", sf.rule_id, sf.title)
    } else {
        sf.rule_id.clone()
    };
    let key = (entry_route.clone(), dedup_rule_key);
    best.entry(key).or_insert_with(|| LatticeFinding {
        id: String::new(),
        rule_id: sf.rule_id.clone(),
        severity: sf.severity.clone(),
        title: sf.title.clone(),
        file: sf.rel_path.clone(),
        line: sf.line,
        status: "SUSPECT_UNGUARDED".into(),
        confidence: sf.confidence,
        entry_route,
        sink_kind: sf.sink_kind,
        missing_guard: sf.missing_guard,
        witness_path: vec![TraceHop {
            file: sf.rel_path.clone(),
            symbol: sf.symbol.clone(),
            line: sf.line,
        }],
        remediation: sf.remediation.clone(),
        proof_reasons: proof_reasons_for_static_rule(&sf.rule_id, sf.confidence),
    });
}

struct BfsTree {
    parent: Vec<Option<NodeIndex>>,
    root: Vec<Option<NodeIndex>>,
    depth: Vec<usize>,
}

fn can_improve_witness(
    best: &HashMap<(String, String), LatticeFinding>,
    graph: &DiGraph<SymbolInfo, ()>,
    tree: &BfsTree,
    sink: NodeIndex,
    rule_id: &str,
) -> bool {
    let si = sink.index();
    let Some(root_idx) = tree.root[si] else {
        return false;
    };
    let entry_name = &graph[root_idx].name;
    let cand_len = tree.depth[si].min(graph.node_count().min(64));
    match best.get(&(entry_name.clone(), rule_id.to_string())) {
        Some(prev) => cand_len < prev.witness_path.len(),
        None => true,
    }
}

/// Single O(V + E) multi-source forward BFS from ALL `Route` entries (unblocked by guards).
fn build_any_route_bfs_tree(graph: &DiGraph<SymbolInfo, ()>) -> BfsTree {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut root = vec![None; n];
    let mut depth = vec![0usize; n];
    let mut q = VecDeque::new();
    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route {
            let i = idx.index();
            parent[i] = Some(idx);
            root[i] = Some(idx);
            depth[i] = 1;
            q.push_back(idx);
        }
    }
    while let Some(u) = q.pop_front() {
        let ui = u.index();
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() {
                parent[vi] = Some(u);
                root[vi] = root[ui];
                depth[vi] = depth[ui] + 1;
                q.push_back(v);
            }
        }
    }
    BfsTree {
        parent,
        root,
        depth,
    }
}

/// Builds a dedicated O(V + E) witness BFS tree for `SMG-IDOR-001` rooted strictly at authenticated,
/// non-public, non-admin `Route` entries without `OwnershipCheck`, prioritizing routes with `has_resource_id`.
fn build_idor_unguarded_bfs_tree(
    graph: &DiGraph<SymbolInfo, ()>,
    guard_out: &[GuardBitset],
    public_routes: &[String],
) -> (BfsTree, Vec<bool>) {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut root = vec![None; n];
    let mut depth = vec![0usize; n];
    let mut res_reaches = vec![false; n];
    let mut q = VecDeque::new();

    // Pass 1: seed from authenticated Route entries that directly carry `has_resource_id`
    for pass_has_res in [true, false] {
        for idx in graph.node_indices() {
            let i = idx.index();
            let sym = &graph[idx];
            if sym.kind == SymbolKind::Route
                && sym.has_resource_id == pass_has_res
                && guard_out[i].contains(GuardKind::Auth)
                && !sym.guards.contains(&GuardKind::OwnershipCheck)
                && !is_public_route(&sym.name, public_routes)
                && !is_admin_route(&sym.name)
                && parent[i].is_none()
            {
                parent[i] = Some(idx);
                root[i] = Some(idx);
                depth[i] = 1;
                res_reaches[i] = sym.has_resource_id;
                q.push_back(idx);
            }
        }
        while let Some(u) = q.pop_front() {
            let ui = u.index();
            for v in graph.neighbors_directed(u, Direction::Outgoing) {
                let vi = v.index();
                if graph[v].guards.contains(&GuardKind::OwnershipCheck) {
                    continue;
                }
                let next_res = res_reaches[ui] || graph[v].has_resource_id;
                if parent[vi].is_none() || (!res_reaches[vi] && next_res) {
                    parent[vi] = Some(u);
                    root[vi] = root[ui];
                    depth[vi] = depth[ui] + 1;
                    res_reaches[vi] = next_res;
                    q.push_back(v);
                }
            }
        }
    }

    (
        BfsTree {
            parent,
            root,
            depth,
        },
        res_reaches,
    )
}

fn reconstruct_taint_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    taint_parents: &[Option<NodeIndex>],
    taint_bit_parents: &[[Option<NodeIndex>; 5]],
    req_bit: u8,
    route_parents: &BfsTree,
    sink: NodeIndex,
) -> Option<(String, Vec<TraceHop>)> {
    let mut rev_taint = Vec::new();
    let mut cur = sink;
    let mut seen: HashSet<usize> = HashSet::new();
    let bit_idx = sink_bit_index(req_bit);
    let source_node = loop {
        if !seen.insert(cur.index()) || rev_taint.len() >= 32 {
            break cur;
        }
        let s = &graph[cur];
        rev_taint.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        let next_parent = bit_idx
            .and_then(|bi| taint_bit_parents[cur.index()][bi])
            .or(taint_parents[cur.index()]);
        match next_parent {
            Some(p) if p != cur => cur = p,
            _ => break cur,
        }
    };
    rev_taint.reverse();

    if let Some((entry_name, mut prefix_hops)) =
        reconstruct_witness(graph, route_parents, source_node)
    {
        if !rev_taint.is_empty() {
            // Avoid duplicating `source_node` which appears at the end of `prefix_hops` and start of `rev_taint`
            prefix_hops.extend(rev_taint.into_iter().skip(1));
        }
        Some((entry_name, prefix_hops))
    } else {
        let entry = rev_taint
            .first()
            .map(|h| format!("{}:{}", h.file, h.line))
            .unwrap_or_else(|| graph[sink].rel_path.clone());
        Some((entry, rev_taint))
    }
}

/// Single O(V + E) multi-source forward BFS from all unguarded `Route` entries.
/// Returns `BfsTree` with `parent[node]`, `root[node]`, and `depth[node]` in O(1) per node.
fn build_unguarded_bfs_tree(
    graph: &DiGraph<SymbolInfo, ()>,
    guard: GuardKind,
    public_routes: &[String],
) -> BfsTree {
    let n = graph.node_count();
    let mut parent = vec![None; n];
    let mut root = vec![None; n];
    let mut depth = vec![0usize; n];
    let mut q = VecDeque::new();

    for idx in graph.node_indices() {
        if graph[idx].kind == SymbolKind::Route
            && !graph[idx].guards.contains(&guard)
            && (guard != GuardKind::Auth || !is_public_route(&graph[idx].name, public_routes))
        {
            let i = idx.index();
            parent[i] = Some(idx);
            root[i] = Some(idx);
            depth[i] = 1;
            q.push_back(idx);
        }
    }

    while let Some(u) = q.pop_front() {
        let ui = u.index();
        for v in graph.neighbors_directed(u, Direction::Outgoing) {
            let vi = v.index();
            if parent[vi].is_none() && !graph[v].guards.contains(&guard) {
                parent[vi] = Some(u);
                root[vi] = root[ui];
                depth[vi] = depth[ui] + 1;
                q.push_back(v);
            }
        }
    }
    BfsTree {
        parent,
        root,
        depth,
    }
}

fn reconstruct_witness(
    graph: &DiGraph<SymbolInfo, ()>,
    tree: &BfsTree,
    sink: NodeIndex,
) -> Option<(String, Vec<TraceHop>)> {
    let root_idx = tree.root[sink.index()]?;
    let entry_name = graph[root_idx].name.clone();
    let mut rev_hops = Vec::new();
    let mut cur = sink;
    let mut steps = 0usize;
    let max_steps = graph.node_count().min(64);

    loop {
        let s = &graph[cur];
        rev_hops.push(TraceHop {
            file: s.rel_path.clone(),
            symbol: s.name.clone(),
            line: s.line_start,
        });
        let p = tree.parent[cur.index()]?;
        if p == cur {
            break;
        }
        steps += 1;
        if steps >= max_steps {
            break;
        }
        cur = p;
    }

    rev_hops.reverse();
    Some((entry_name, rev_hops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{FrontendApiCall, parse_file_ast};
    use smg_core::{IndexedFile, Language, ShellMindGuardConfig};
    use std::time::Instant;

    #[test]
    fn test_b11_2000_node_all_sink_chain_is_linear() {
        let mut symbols = Vec::with_capacity(2001);
        symbols.push(SymbolInfo {
            id: "a.ts::route:1".into(),
            rel_path: "a.ts".into(),
            name: "POST /api/chain".into(),
            kind: SymbolKind::Route,
            sink_kind: None,
            line_start: 1,
            line_end: 1,
            guards: HashSet::new(),
            calls: vec!["sink_0".into()],
            route_path: Some("/api/chain".into()),
            ..Default::default()
        });
        for i in 0..2000 {
            let next_call = if i + 1 < 2000 {
                vec![format!("sink_{}", i + 1)]
            } else {
                Vec::new()
            };
            symbols.push(SymbolInfo {
                id: format!("a.ts::sink_{}", i),
                rel_path: "a.ts".into(),
                name: format!("sink_{}", i),
                kind: SymbolKind::Sink,
                sink_kind: Some(SinkKind::BalanceUpdate),
                line_start: i + 2,
                line_end: i + 2,
                guards: HashSet::new(),
                calls: next_call,
                route_path: None,
                ..Default::default()
            });
        }
        let summaries = vec![FileAstSummary {
            rel_path: "a.ts".into(),
            imports: Vec::new(),
            symbols,
            ..Default::default()
        }];

        let t0 = Instant::now();
        let res = solve_guard_lattice(&summaries);
        let elapsed_ms = t0.elapsed().as_millis();
        assert!(!res.findings.is_empty());
        assert!(
            elapsed_ms < 500,
            "2000-node all-sink chain took {}ms (must be linear!)",
            elapsed_ms
        );
    }

    #[test]
    fn test_cross_file_sqli_idor_and_frontend_contract() {
        let dir = std::env::temp_dir().join("smg_lattice_6layer_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("routes")).unwrap();
        std::fs::create_dir_all(dir.join("db")).unwrap();
        std::fs::create_dir_all(dir.join("web")).unwrap();

        let route_src = r#"
import { runUserQuery } from '../db/queries';
export function requireAuth(req: any, res: any, next: any) { next(); }
app.use('/api/v1', requireAuth);
app.get('/users/:id', async (req, res) => {
    const uid = req.params.id;
    return await runUserQuery(uid);
});
"#;
        let query_src = r#"
export async function runUserQuery(userId: string) {
    return await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
}
"#;
        let fe_src = r#"
export async function syncData() {
    await fetch('/api/v1/users/42');
    await fetch('/api/v1/nonexistent/endpoint', { method: 'POST' });
}
"#;
        std::fs::write(dir.join("routes/users.ts"), route_src).unwrap();
        std::fs::write(dir.join("db/queries.ts"), query_src).unwrap();
        std::fs::write(dir.join("web/app.ts"), fe_src).unwrap();

        let cfg = ShellMindGuardConfig::default();
        let f1 = IndexedFile {
            abs_path: dir.join("routes/users.ts"),
            rel_path: "routes/users.ts".into(),
            language: Language::TypeScript,
            size_bytes: route_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(route_src.as_bytes().to_vec()),
        };
        let f2 = IndexedFile {
            abs_path: dir.join("db/queries.ts"),
            rel_path: "db/queries.ts".into(),
            language: Language::TypeScript,
            size_bytes: query_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(query_src.as_bytes().to_vec()),
        };
        let f3 = IndexedFile {
            abs_path: dir.join("web/app.ts"),
            rel_path: "web/app.ts".into(),
            language: Language::TypeScript,
            size_bytes: fe_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(fe_src.as_bytes().to_vec()),
        };

        let s1 = parse_file_ast(&f1, &cfg).unwrap();
        let s2 = parse_file_ast(&f2, &cfg).unwrap();
        let s3 = parse_file_ast(&f3, &cfg).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        let res = solve_guard_lattice(&[s1, s2, s3]);
        let sqli = res
            .findings
            .iter()
            .find(|f| f.rule_id == "SMG-SQLI-001")
            .expect("Cross-file SQLi must be detected");
        assert!(
            sqli.witness_path.len() >= 2,
            "Cross-file witness must trace Route -> sink: {:?}",
            sqli.witness_path
        );

        assert!(
            res.findings.iter().any(|f| f.rule_id == "SMG-IDOR-001"),
            "Authenticated /users/:id DB read without user_id filter must trigger SMG-IDOR-001"
        );

        let fe404: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "SMG-FE-404")
            .collect();
        assert_eq!(
            fe404.len(),
            1,
            "Mounted /api/v1/users/42 must match, only /nonexistent/endpoint must trigger SMG-FE-404: {:?}",
            fe404
        );
        // Ensure FrontendApiCall import stays used cleanly
        let _dummy = std::mem::size_of::<FrontendApiCall>();
    }

    #[test]
    fn test_fastapi_route_param_injection_taint_propagation() {
        let py_src = r#"
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: str):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"#;
        let cfg = ShellMindGuardConfig::default();
        let file = IndexedFile {
            abs_path: "api.py".into(),
            rel_path: "api.py".into(),
            language: Language::Python,
            size_bytes: py_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(py_src.as_bytes().to_vec()),
        };
        let summary = parse_file_ast(&file, &cfg).unwrap();
        let res = solve_guard_lattice(&[summary]);
        assert!(
            res.findings.iter().any(|f| f.rule_id == "SMG-SQLI-001"),
            "FastAPI route handler parameter user_id must propagate taint to SQL sink: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_aliased_barrel_imports_idor_masking_and_subpath_auth() {
        let cfg = ShellMindGuardConfig::default();

        let route_src = r#"
import { executeUnsafeSql as runSql } from './barrel';

app.use('/admin', requireAuth);

app.post('/billing/charge', async (req, res) => {
    const uid = req.body.userId;
    await runSql(uid);
});

app.get('/orders/:id', requireAuth, async (req, res) => {
    const order = await prisma.order.findFirst({
        where: { id: req.params.id, user_id: req.query.user_id }
    });
    return res.json(order);
});

app.get('/admin/orders/:id', requireAuth, async (req, res) => {
    const order = await prisma.order.findUnique({
        where: { id: req.params.id }
    });
    return res.json(order);
});
"#;
        let barrel_src = r#"
export * from './db';
"#;
        let db_src = r#"
export async function executeUnsafeSql(targetId: string) {
    let q = "UPDATE balances SET amount = 0 WHERE user_id = '";
    q += targetId;
    return await db.query(q);
}
"#;
        let f_route = IndexedFile {
            abs_path: "src/routes.ts".into(),
            rel_path: "src/routes.ts".into(),
            language: Language::TypeScript,
            size_bytes: route_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(route_src.as_bytes().to_vec()),
        };
        let f_barrel = IndexedFile {
            abs_path: "src/barrel.ts".into(),
            rel_path: "src/barrel.ts".into(),
            language: Language::TypeScript,
            size_bytes: barrel_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(barrel_src.as_bytes().to_vec()),
        };
        let f_db = IndexedFile {
            abs_path: "src/db.ts".into(),
            rel_path: "src/db.ts".into(),
            language: Language::TypeScript,
            size_bytes: db_src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(db_src.as_bytes().to_vec()),
        };

        let s1 = parse_file_ast(&f_route, &cfg).unwrap();
        let s2 = parse_file_ast(&f_barrel, &cfg).unwrap();
        let s3 = parse_file_ast(&f_db, &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2, s3]);

        // 1. Sub-path middleware `/admin` must NOT protect `/billing/charge`, and aliased + barrel import must resolve
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route == "POST /billing/charge"),
            "Sub-path /admin middleware must not protect POST /billing/charge: {:?}",
            res.findings
        );
        // 2. Multi-statement SQL concatenation via aliased barrel import must trigger SMG-SQLI-001
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-SQLI-001" && f.entry_route == "POST /billing/charge"),
            "Aliased barrel import + multi-statement += SQLi must be detected: {:?}",
            res.findings
        );
        // 3. `user_id: req.query.user_id` must NOT satisfy ownership check (must trigger SMG-IDOR-001 on /orders/:id)
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-IDOR-001" && f.entry_route == "GET /orders/:id"),
            "Tainted user_id: req.query.user_id must still trigger SMG-IDOR-001: {:?}",
            res.findings
        );
        // 4. Admin route `/admin/orders/:id` must NOT trigger SMG-IDOR-001
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-IDOR-001" && f.entry_route == "GET /admin/orders/:id"),
            "Admin route GET /admin/orders/:id must not trigger SMG-IDOR-001: {:?}",
            res.findings
        );
    }

    fn make_indexed(rel: &str, lang: Language, code: &str) -> IndexedFile {
        IndexedFile {
            abs_path: rel.into(),
            rel_path: rel.into(),
            language: lang,
            size_bytes: code.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(code.as_bytes().to_vec()),
        }
    }

    #[test]
    fn test_sprint2_bitmask_taint_precision_and_early_return_narrowing() {
        let cfg = ShellMindGuardConfig::default();
        let route_src = r#"
import { writeNote, queryUser } from './helpers';

app.get('/report', async (req, res) => {
    if (!req.query.id) {
        return res.status(400).send("missing req.query.id parameter");
    }
    const safeName = path.basename(req.query.name);
    await writeNote(safeName);
    await queryUser(safeName);

    const targetUrl = req.query.url;
    if (!isAllowedHost(targetUrl)) {
        return res.status(400).send("blocked");
    }
    await fetch(targetUrl);
    return res.json({ ok: true });
});
"#;
        let helpers_src = r#"
import * as fs from 'fs';
export async function writeNote(fileName: string) {
    return fs.readFileSync('/var/notes/' + fileName, 'utf8');
}
export async function queryUser(userKey: string) {
    return await db.query(`SELECT * FROM notes WHERE key = '${userKey}'`);
}
"#;
        let s1 = parse_file_ast(
            &make_indexed("src/route.ts", Language::TypeScript, route_src),
            &cfg,
        )
        .unwrap();
        let s2 = parse_file_ast(
            &make_indexed("src/helpers.ts", Language::TypeScript, helpers_src),
            &cfg,
        )
        .unwrap();
        let res = solve_guard_lattice(&[s1, s2]);

        assert!(
            !res.findings.iter().any(|f| f.rule_id == "SMG-PATH-001"),
            "path.basename clears TAINT_PATH across call boundaries: {:?}",
            res.findings
        );
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "SMG-SSRF-001"),
            "Early-return !isAllowedHost guard must narrow SSRF taint: {:?}",
            res.findings
        );
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "SMG-XSS-001"),
            "Static string literal error messages and JSON responses must not trigger SMG-XSS-001: {:?}",
            res.findings
        );
        let sqli = res.findings.iter().find(|f| f.rule_id == "SMG-SQLI-001");
        assert!(
            sqli.is_some(),
            "path.basename must NOT clear TAINT_SQL on SQL sink: {:?}",
            res.findings
        );
        assert_eq!(sqli.unwrap().confidence, Confidence::Confirmed);
    }

    #[test]
    fn test_sprint2_xss_partial_sanitization_and_multilang() {
        let cfg = ShellMindGuardConfig::default();
        let ts_src = r#"
app.get('/profile', (req, res) => {
    const clean = DOMPurify.sanitize(req.query.clean);
    el1.innerHTML = clean;
    const partial = DOMPurify.sanitize(req.query.a) + req.query.raw;
    el2.innerHTML = partial;
});
app.get('/banner', (req, res) => {
    res.send(`<div>${req.query.msg}</div>`);
});
"#;
        let py_src = r#"
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.get("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<h1>" + name + "</h1>")
"#;
        let go_src = r#"
package main
import ("html/template"; "net/http")

func Register(r *http.ServeMux) {
    r.HandleFunc("/card", func(w http.ResponseWriter, req *http.Request) {
        bio := req.URL.Query().Get("bio")
        _ = template.HTML(bio)
    })
}
"#;
        let s1 = parse_file_ast(
            &make_indexed("web/xss.tsx", Language::TypeScript, ts_src),
            &cfg,
        )
        .unwrap();
        let s2 =
            parse_file_ast(&make_indexed("api/app.py", Language::Python, py_src), &cfg).unwrap();
        let s3 = parse_file_ast(&make_indexed("srv/card.go", Language::Go, go_src), &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2, s3]);

        let xss_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "SMG-XSS-001")
            .collect();
        assert!(
            xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 6),
            "Partial sanitization DOMPurify + raw must still trigger SMG-XSS-001 on line 6: {:?}",
            xss_hits
        );
        assert!(
            !xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 4),
            "Full DOMPurify.sanitize must NOT trigger SMG-XSS-001 on line 4: {:?}",
            xss_hits
        );
        assert!(
            xss_hits
                .iter()
                .any(|f| f.file == "web/xss.tsx" && f.line == 9),
            "HTML template response res.send(`<div>${{...}}</div>`) must trigger SMG-XSS-001: {:?}",
            xss_hits
        );
        assert!(
            xss_hits.iter().any(|f| f.file == "api/app.py"),
            "Flask render_template_string with request.args must trigger SMG-XSS-001: {:?}",
            xss_hits
        );
        assert!(
            xss_hits.iter().any(|f| f.file == "srv/card.go"),
            "Go template.HTML with tainted query input must trigger SMG-XSS-001: {:?}",
            xss_hits
        );
    }

    #[test]
    fn test_sprint2_csrf_precision_cookie_vs_bearer_and_exempt() {
        let cfg = ShellMindGuardConfig::default();
        let cookie_app = r#"
app.use(session({ secret: process.env.SESSION_SECRET }));
app.get('/me', requireAuth, (req, res) => res.json({ user: req.session.uid }));
app.post('/transfer', requireAuth, (req, res) => {
    const u = req.session.uid;
    return res.json({ transferred: u });
});
app.post('/webhooks/stripe', (req, res) => res.sendStatus(200));
"#;
        let bearer_api = r#"
function bearerAuth(req: any, res: any, next: any) {
    const hdr = req.headers.authorization;
    if (!hdr) return res.status(401).end();
    next();
}
app.post('/api/v1/orders', bearerAuth, (req, res) => res.json({ ok: true }));
"#;
        let dj_views = r#"
@csrf_exempt
def update_email(request):
    return HttpResponse("ok")
"#;
        let rust_detector_helper = r##"
fn inspect_helper(sym: &mut Sym) {
    let s = "csrf_exempt";
    let doc = r#"@csrf_exempt"#;
    sym.csrf_exempt = false;
}
"##;
        let s_cookie = parse_file_ast(
            &make_indexed("cookie_app.ts", Language::TypeScript, cookie_app),
            &cfg,
        )
        .unwrap();
        let s_dj =
            parse_file_ast(&make_indexed("views.py", Language::Python, dj_views), &cfg).unwrap();
        let s_rust = parse_file_ast(
            &make_indexed("detector.rs", Language::Rust, rust_detector_helper),
            &cfg,
        )
        .unwrap();
        let res_vuln = solve_guard_lattice(&[s_cookie, s_dj, s_rust]);
        assert!(
            !res_vuln
                .findings
                .iter()
                .any(|f| f.file == "detector.rs" && f.rule_id == "SMG-CSRF-001"),
            "Rust helper referencing sym.csrf_exempt or quoted literals must NOT trigger SMG-CSRF-001: {:?}",
            res_vuln.findings
        );
        let csrf_routes: Vec<&str> = res_vuln
            .findings
            .iter()
            .filter(|f| f.rule_id == "SMG-CSRF-001")
            .map(|f| f.entry_route.as_str())
            .collect();
        assert!(
            csrf_routes.contains(&"POST /transfer"),
            "State-changing cookie/session POST /transfer must trigger SMG-CSRF-001: {:?}",
            csrf_routes
        );
        assert!(
            csrf_routes.contains(&"update_email"),
            "Django @csrf_exempt view must trigger SMG-CSRF-001: {:?}",
            csrf_routes
        );
        assert!(
            !csrf_routes.contains(&"GET /me") && !csrf_routes.contains(&"POST /webhooks/stripe"),
            "GET and webhook endpoints must NOT trigger SMG-CSRF-001: {:?}",
            csrf_routes
        );

        let s_bearer = parse_file_ast(
            &make_indexed("bearer_api.ts", Language::TypeScript, bearer_api),
            &cfg,
        )
        .unwrap();
        let res_bearer = solve_guard_lattice(&[s_bearer]);
        assert!(
            !res_bearer
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-CSRF-001"),
            "Stateless Authorization: Bearer API must NOT trigger SMG-CSRF-001: {:?}",
            res_bearer.findings
        );
    }

    #[test]
    fn test_sprint2_jwt_logic_flaws() {
        let cfg = ShellMindGuardConfig::default();
        let bad_ts = r#"
export function decodeUnsafe(token: string, key: string) {
    return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}
export function safeVerify(token: string, pubKey: string) {
    return jwt.verify(token, pubKey, { algorithms: ['RS256'] });
}
"#;
        let bad_py = r#"
import jwt
def parse_tok(tok: str):
    return jwt.decode(tok, options={"verify_signature": False})
"#;
        let s1 = parse_file_ast(
            &make_indexed("auth_jwt.ts", Language::TypeScript, bad_ts),
            &cfg,
        )
        .unwrap();
        let s2 =
            parse_file_ast(&make_indexed("auth_jwt.py", Language::Python, bad_py), &cfg).unwrap();
        let res = solve_guard_lattice(&[s1, s2]);
        let jwt_hits: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.rule_id == "SMG-CFG-JWT-LOGIC")
            .collect();
        assert_eq!(
            jwt_hits.len(),
            2,
            "Both alg:none and verify_signature=False must trigger SMG-CFG-JWT-LOGIC while safe RS256 does not: {:?}",
            jwt_hits
        );
        assert!(
            jwt_hits
                .iter()
                .all(|f| f.confidence == Confidence::Confirmed)
        );
    }

    #[test]
    fn test_audit_regressions_slice_safety_cross_file_auth_and_taint_invariants() {
        let cfg = ShellMindGuardConfig::default();

        // 1. CRITICAL-01: inverted braces in import/export/require must never panic
        let weird_imports = r#"
import x from "pkg}with{braces";
export const braceStr = "}"; export { helperFn } from "./sub";
const y = require("mod}with{brace");
"#;
        let _ = parse_file_ast(
            &make_indexed("weird.ts", Language::TypeScript, weird_imports),
            &cfg,
        );

        // 2. HIGH-01, HIGH-02, HIGH-03, HIGH-04, HIGH-05 & Formal Invariants #1-#5
        let app_ts = r#"
import { runSink, sharedHelper } from './service';
app.use('/admin', requireAuth);

app.post('/early-guarded', async (req, res) => {
    if (!verifyJwt(req)) {
        return res.status(401).json({ error: "unauthorized" });
    }
    await stripe.charges.create({ amount: 100 });
    return res.json({ ok: true });
});

app.get('/items/:id', requireAuth, async (req, res) => {
    const targetOwner = req.query.owner;
    const item = await prisma.item.findFirst({
        where: { id: req.params.id, user_id: targetOwner }
    });
    return res.json(item);
});

app.post('/run', requireAuth, async (req, res) => {
    const safeObj = { safe: "ok", cmd: req.body.cmd };
    await sharedHelper(safeObj);
    await sharedHelper(req.body);
    return res.json({ ok: true });
});
"#;
        let admin_routes_ts = r#"
app.post('/admin/refund', async (req, res) => {
    await db.exec("UPDATE ledger SET refunded = 1");
    return res.json({ ok: true });
});
"#;
        let service_ts = r#"
import { execSync } from 'child_process';
export async function sharedHelper(payload: any) {
    return await runSink(req.query.localFlag, payload);
}
export async function runSink(flag: any, data: any) {
    execSync(data.otherField);
}
"#;
        let s_app =
            parse_file_ast(&make_indexed("app.ts", Language::TypeScript, app_ts), &cfg).unwrap();
        let s_admin = parse_file_ast(
            &make_indexed("routes/admin.ts", Language::TypeScript, admin_routes_ts),
            &cfg,
        )
        .unwrap();
        let s_srv = parse_file_ast(
            &make_indexed("service.ts", Language::TypeScript, service_ts),
            &cfg,
        )
        .unwrap();
        let res = solve_guard_lattice(&[s_app, s_admin, s_srv]);

        // Cross-file `app.use('/admin', requireAuth)` must protect `/admin/refund` in `routes/admin.ts`
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route == "POST /admin/refund"),
            "Cross-file __AUTH_PREFIX__:/admin must protect POST /admin/refund: {:?}",
            res.findings
        );
        // Early-return `if (!verifyJwt(req)) return ...` must protect `/early-guarded` from SMG-AUTH-001
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route == "POST /early-guarded"),
            "Early-return verifyJwt guard must satisfy GuardKind::Auth: {:?}",
            res.findings
        );
        // Local tainted variable `targetOwner = req.query.owner` in `user_id: targetOwner` must NOT suppress SMG-IDOR-001
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-IDOR-001" && f.entry_route == "GET /items/:id"),
            "Tainted local variable in user_id filter must still trigger SMG-IDOR-001: {:?}",
            res.findings
        );
        // Unrestricted `sharedHelper(req.body)` + mixed `(d_mask, p_mask)` forwarding to `runSink` must trigger SMG-CMDI-001 on `data.otherField`
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001" && f.entry_route == "POST /run"),
            "Unrestricted req.body + mixed direct/param forwarding must trigger SMG-CMDI-001: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_wave1_audit_invariants_h21_a2_f87_f88_f89_f90() {
        let cfg = ShellMindGuardConfig::default();

        // H-21 + F-89 + F-87 (TypeScript routes)
        let h21_and_sqli_ts = r#"
import * as fs from 'fs';

app.get('/read', requireAuth, (req, res) => {
    const data = fs.readFileSync(req.query.file);
    if (isValidUrl(req.query.cb)) {
        return res.send(data);
    }
    res.send(data);
});

app.get('/search', requireAuth, async (req, res) => {
    const rows = await db('users').whereRaw(`name = '${req.query.q}'`);
    return res.json(rows);
});

app.post('/users/find', requireAuth, async (req, res) => {
    const cfgObj = JSON.parse(req.body.meta || '{}');
    const u = await User.findOne(req.body);
    return res.json({ cfgObj, u });
});
"#;
        // F-88 (Python list-form subprocess with shell -c)
        let cmdi_py = r#"
from flask import request
import subprocess

@app.route('/run')
def run_cmd():
    cmd = request.args.get("cmd")
    return subprocess.run(["bash", "-c", cmd])
"#;
        let s_ts = parse_file_ast(
            &make_indexed("routes/wave1.ts", Language::TypeScript, h21_and_sqli_ts),
            &cfg,
        )
        .unwrap();
        let s_py =
            parse_file_ast(&make_indexed("app.py", Language::Python, cmdi_py), &cfg).unwrap();
        let res = solve_guard_lattice(&[s_ts, s_py]);

        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-PATH-001" && f.entry_route == "GET /read"),
            "H-21: unrelated/post-sink Sanitizer must not hide earlier fs.readFileSync: {:?}",
            res.findings
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-SQLI-001" && f.entry_route == "GET /search"),
            "F-89: Knex .whereRaw template SQLi must emit SMG-SQLI-001: {:?}",
            res.findings
        );
        assert!(
            res.findings.iter().any(|f| f.rule_id == "SMG-SQLI-NOSQL"),
            "F-87: JSON.parse() must not satisfy schema validation for NoSQL sink: {:?}",
            res.findings
        );
        assert!(
            res.findings.iter().any(|f| f.rule_id == "SMG-CMDI-001"),
            "F-88: subprocess.run(['bash', '-c', tainted]) must emit SMG-CMDI-001: {:?}",
            res.findings
        );

        // A-2: jwt.verify in one region must NOT silence jwt.decode >15 lines away
        let mut jwt_ts =
            String::from("export function ok(t: string, k: string) { return jwt.verify(t, k); }\n");
        for _ in 0..20 {
            jwt_ts.push_str("const padding = 1;\n");
        }
        jwt_ts.push_str("export function bad(raw: string) { return jwt.decode(raw); }\n");
        let jwt_hits = crate::secrets_config::scan_secrets_and_config("src/auth.ts", &jwt_ts);
        assert!(
            jwt_hits.iter().any(|f| f.rule_id == "SMG-CFG-JWT-LOGIC"),
            "A-2: distant jwt.verify must not mask unverified jwt.decode: {:?}",
            jwt_hits
        );

        // F-90: OpenAPI 3.0 minimum: 0 + exclusiveMinimum: true -> strict positive bound
        let spec = r#"
openapi: 3.0.3
paths:
  /pay-strict:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                amount:
                  type: number
                  minimum: 0
                  exclusiveMinimum: true
  /pay-zero-ok:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                amount:
                  type: number
                  minimum: 0
"#;
        let schemas = crate::phase10::parse_openapi_route_schemas("openapi.yaml", spec);
        let strict_route = schemas
            .iter()
            .find(|r| r.path == "/pay-strict")
            .expect("strict route parsed");
        assert!(
            strict_route
                .params
                .iter()
                .any(|p| p.name == "amount" && p.has_positive_bound)
        );
        let zero_ok = schemas
            .iter()
            .find(|r| r.path == "/pay-zero-ok")
            .expect("zero-ok route parsed");
        assert!(
            zero_ok
                .params
                .iter()
                .any(|p| p.name == "amount" && !p.has_positive_bound)
        );
    }

    #[test]
    fn dense_cyclic_call_graph_linear_termination() {
        let mut syms = Vec::new();
        for i in 0..40 {
            let calls = vec![
                format!("fn_{}", (i + 1) % 40),
                format!("fn_{}", (i + 7) % 40),
                format!("fn_{}", (i + 13) % 40),
            ];
            let mut sym = SymbolInfo::base(
                format!("fn_{}", i),
                "src/cycle.ts",
                if i == 0 {
                    "POST /cycle-entry".into()
                } else {
                    format!("fn_{}", i)
                },
                if i == 0 {
                    SymbolKind::Route
                } else if i == 39 {
                    SymbolKind::Sink
                } else {
                    SymbolKind::Function
                },
                if i == 39 {
                    Some(SinkKind::CommandInjection)
                } else {
                    None
                },
                i + 1,
                i + 2,
                HashSet::new(),
                calls,
                if i == 0 {
                    Some("/cycle-entry".into())
                } else {
                    None
                },
            );
            sym.has_taint_source = i == 0;
            if i < 39 {
                let nxt = format!("fn_{}", (i + 1) % 40);
                sym.tainted_calls.push(nxt.clone());
                sym.tainted_call_masks.insert(nxt, crate::taint::TAINT_ALL);
            }
            sym.param_forwarding_calls
                .push(format!("fn_{}", (i + 7) % 40));
            syms.push(sym);
        }
        let ast = FileAstSummary {
            rel_path: "src/cycle.ts".into(),
            symbols: syms,
            ..Default::default()
        };
        let t0 = std::time::Instant::now();
        let res = solve_guard_lattice(&[ast]);
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "Dense 40-node cyclic graph must terminate linearly: {:?}",
            t0.elapsed()
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.sink_kind == SinkKind::CommandInjection),
            "Must report sink reachability cleanly through dense cycle: {:?}",
            res.findings
        );
    }

    #[test]
    fn wave3a_precision_constant_literal_and_discarded_sanitizer_and_dynamic_dispatch() {
        let code = r#"
const handlers = { run: execHelper };

function execHelper(cmd) {
    execSync(cmd);
}

app.post('/safe-literal-sql', requireAuth, async (req, res) => {
    const TABLE = "audit_logs";
    const id = req.query.id;
    return db.query("SELECT * FROM " + TABLE + " WHERE id = $1", [id]);
});

app.post('/discarded-sanitizer', requireAuth, async (req, res) => {
    const html = req.body.bio;
    DOMPurify.sanitize(html);
    if (escapeHtml(html)) {
        res.send(`<div>${html}</div>`);
    }
});

app.post('/clean-sanitizer', requireAuth, async (req, res) => {
    const clean = DOMPurify.sanitize(req.body.bio);
    res.send(`<div>${clean}</div>`);
});

app.post('/dynamic-dispatch', requireAuth, async (req, res) => {
    const action = req.body.action;
    const cmd = req.body.cmd;
    handlers[action](cmd);
});
"#;
        let f = IndexedFile {
            abs_path: std::path::PathBuf::from("src/wave3a.ts"),
            rel_path: "src/wave3a.ts".into(),
            language: Language::TypeScript,
            size_bytes: code.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(code.as_bytes().to_vec()),
        };
        let cfg = ShellMindGuardConfig::default();
        let ast = parse_file_ast(&f, &cfg).expect("parse wave3a ts");
        let res = solve_guard_lattice_with_public(&[ast], &cfg.guards.public_routes);
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-SQLI-001" && f.entry_route.contains("/safe-literal-sql")),
            "Pure constant TABLE literal in parameterized query must not trigger SQLi: {:?}",
            res.findings
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-XSS-001"
                    && f.entry_route.contains("/discarded-sanitizer")),
            "Discarded DOMPurify/escapeHtml statements must still trigger XSS: {:?}",
            res.findings
        );
        assert!(
            !res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-XSS-001" && f.entry_route.contains("/clean-sanitizer")),
            "Assigned DOMPurify.sanitize(html) must suppress XSS: {:?}",
            res.findings
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id == "SMG-CMDI-001" && f.entry_route.contains("/dynamic-dispatch")),
            "Dynamic handler map dispatch handlers[action](cmd) must propagate taint to sink: {:?}",
            res.findings
        );
    }

    #[test]
    fn test_sprint3_p12_01_qualified_calls_sibling_isolation_and_python_go_imports() {
        let cfg = ShellMindGuardConfig::default();

        // 1. TS sibling-class `.save()` isolation + namespace import (`import * as billing`)
        let repo_src = r#"
export class UserRepo {
    async save(userId: string) {
        return await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
    }
}
export class AuditLogger {
    async save(msg: string) {
        console.log(msg);
    }
}
"#;
        let billing_src = r#"
export async function chargeCard(amount: number) {
    return await stripe.charges.create({ amount });
}
"#;
        let routes_src = r#"
import { UserRepo, AuditLogger } from './repo';
import * as billing from './billing';

app.post('/api/audit-only', requireAuth, async (req, res) => {
    const logger: AuditLogger = new AuditLogger();
    await logger.save(req.body.msg);
    res.json({ ok: true });
});

app.post('/api/user-save', requireAuth, async (req, res) => {
    const repo: UserRepo = new UserRepo();
    await repo.save(req.body.userId);
    res.json({ ok: true });
});

app.post('/api/unauth-billing', async (req, res) => {
    await billing.chargeCard(req.body.amount);
    res.json({ ok: true });
});
"#;
        let mk = |rel: &str, lang: Language, src: &str| IndexedFile {
            abs_path: std::path::PathBuf::from(rel),
            rel_path: rel.into(),
            language: lang,
            size_bytes: src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(src.as_bytes().to_vec()),
        };

        let s_repo =
            parse_file_ast(&mk("src/repo.ts", Language::TypeScript, repo_src), &cfg).unwrap();
        let s_bill = parse_file_ast(
            &mk("src/billing.ts", Language::TypeScript, billing_src),
            &cfg,
        )
        .unwrap();
        let s_rt =
            parse_file_ast(&mk("src/routes.ts", Language::TypeScript, routes_src), &cfg).unwrap();
        let ts_res = solve_guard_lattice(&[s_repo, s_bill, s_rt]);

        assert!(
            !ts_res
                .findings
                .iter()
                .any(|f| f.entry_route.contains("/api/audit-only")),
            "Sibling class AuditLogger.save() must NOT collide with UserRepo.save(): {:?}",
            ts_res.findings
        );
        assert!(
            ts_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-SQLI-001" && f.entry_route.contains("/api/user-save")),
            "Qualified UserRepo.save() must still resolve cross-file SQLi: {:?}",
            ts_res.findings
        );
        assert!(
            ts_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001"
                    && f.entry_route.contains("/api/unauth-billing")),
            "Namespace import `billing.chargeCard()` must resolve to billing.ts::chargeCard: {:?}",
            ts_res.findings
        );

        // 2. Python `import services.db as db` qualified resolution
        let py_db = r#"
def run_raw_sql(user_id):
    return cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")
"#;
        let py_app = r#"
import services.db as db

@app.get("/py/account")
def get_account(request):
    uid = request.args.get("id")
    return db.run_raw_sql(uid)
"#;
        let s_py_db = parse_file_ast(&mk("services/db.py", Language::Python, py_db), &cfg).unwrap();
        let s_py_app = parse_file_ast(&mk("app.py", Language::Python, py_app), &cfg).unwrap();
        assert!(
            s_py_app.imports.iter().any(|i| {
                i.from_specifier == "py::services.db"
                    && i.symbol_name == "db"
                    && i.remote_name.as_deref() == Some("*")
            }),
            "Python `import services.db as db` must emit namespace ImportRef: {:?}",
            s_py_app.imports
        );
        let py_res = solve_guard_lattice(&[s_py_db, s_py_app]);
        assert!(
            py_res.findings.iter().any(|f| f.rule_id == "SMG-SQLI-001"),
            "Python `import services.db as db` + `db.run_raw_sql(uid)` must detect cross-file SQLi: {:?}",
            py_res.findings
        );

        // 3. Go `import_spec` (standard, aliased, blank) + NO blind repo-wide unique-name guessing
        let go_unimported = r#"
package secret
func UniqueChargeUnimported() {
    stripe.charges.Create(100)
}
"#;
        let go_pay = r#"
package pay
func ExecuteCharge() {
    stripe.charges.Create(100)
}
"#;
        let go_api = r#"
package api
import (
    _ "myapp/pkg/unused"
    pay "myapp/pkg/pay"
    "net/http"
)
func Register(mux *http.ServeMux) {
    mux.HandleFunc("POST /go/unimported", handleUnimported)
    mux.HandleFunc("POST /go/imported", handleImported)
}
func handleUnimported(w http.ResponseWriter, r *http.Request) {
    UniqueChargeUnimported()
}
func handleImported(w http.ResponseWriter, r *http.Request) {
    pay.ExecuteCharge()
}
"#;
        let s_go_unimp = parse_file_ast(
            &mk("pkg/secret/secret.go", Language::Go, go_unimported),
            &cfg,
        )
        .unwrap();
        let s_go_pay = parse_file_ast(&mk("pkg/pay/pay.go", Language::Go, go_pay), &cfg).unwrap();
        let s_go_api =
            parse_file_ast(&mk("pkg/api/handler.go", Language::Go, go_api), &cfg).unwrap();
        assert!(
            !s_go_api
                .imports
                .iter()
                .any(|i| i.from_specifier.contains("unused")),
            "Blank Go import `_` must be ignored: {:?}",
            s_go_api.imports
        );
        let go_res = solve_guard_lattice(&[s_go_unimp, s_go_pay, s_go_api]);
        assert!(
            !go_res
                .findings
                .iter()
                .any(|f| f.entry_route.contains("/go/unimported")),
            "Unimported Go symbol must NOT be blindly linked repo-wide: {:?}",
            go_res.findings
        );
        assert!(
            go_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route.contains("/go/imported")),
            "Aliased Go import `pay.ExecuteCharge()` must resolve cross-package: {:?}",
            go_res.findings
        );
    }

    #[test]
    fn test_sprint3_p12_02_cha_rta_polymorphic_dispatch_and_zero_hallucination_tiering() {
        let cfg = ShellMindGuardConfig::default();
        let mk = |rel: &str, lang: Language, src: &str| IndexedFile {
            abs_path: std::path::PathBuf::from(rel),
            rel_path: rel.into(),
            language: lang,
            size_bytes: src.len() as u64,
            mtime_ns: 0,
            blake3_hash: String::new(),
            cached_bytes: Some(src.as_bytes().to_vec()),
        };

        // 1. Interface-wrapped AuthGuard (single implementor + NestJS DI binding) -> 0 FP
        let auth_iface_src = r#"
export interface AuthService {
    verify(req: any): Promise<void>;
}
export class JwtAuthService implements AuthService {
    async verify(req: any) {
        verifyJwt(req.headers.authorization);
    }
}
export const AUTH_PROVIDERS = [
    { provide: 'AUTH_SVC', useClass: JwtAuthService }
];
"#;
        let auth_route_src = r#"
import { AuthService, JwtAuthService } from './auth';
const boot = new JwtAuthService();

app.post('/api/cha-guarded', async (req, res) => {
    const auth: AuthService = boot;
    await auth.verify(req);
    await stripe.charges.create({ amount: 500 });
    res.json({ ok: true });
});
"#;
        let s_ai = parse_file_ast(
            &mk("src/auth.ts", Language::TypeScript, auth_iface_src),
            &cfg,
        )
        .unwrap();
        let s_ar = parse_file_ast(
            &mk("src/route.ts", Language::TypeScript, auth_route_src),
            &cfg,
        )
        .unwrap();
        assert!(
            s_ai.di_bindings
                .iter()
                .any(|(k, v)| k == "AUTH_SVC" && v == "JwtAuthService"),
            "NestJS DI binding must be extracted: {:?}",
            s_ai.di_bindings
        );
        let auth_res = solve_guard_lattice(&[s_ai, s_ar]);
        assert!(
            !auth_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001"),
            "Single-implementor CHA AuthGuard must suppress SMG-AUTH-001: {:?}",
            auth_res.findings
        );

        // 2. Ambiguous polymorphic dispatch (2 instantiated implementors: 1 guarded, 1 unguarded) -> Heuristic!
        let poly_src = r#"
export interface PaymentGateway {
    process(req: any): Promise<void>;
}
export class SafeGateway implements PaymentGateway {
    async process(req: any) {
        verifyJwt(req.headers.authorization);
        await stripe.charges.create({ amount: 100 });
    }
}
export class RawGateway implements PaymentGateway {
    async process(req: any) {
        await stripe.charges.create({ amount: 100 });
    }
}
const g1 = new SafeGateway();
const g2 = new RawGateway();
app.post('/api/poly-pay', async (req, res) => {
    const gw: PaymentGateway = req.body.safe ? g1 : g2;
    await gw.process(req);
    res.json({ ok: true });
});
"#;
        let s_poly =
            parse_file_ast(&mk("src/poly.ts", Language::TypeScript, poly_src), &cfg).unwrap();
        let poly_res = solve_guard_lattice(&[s_poly]);
        let poly_auth = poly_res
            .findings
            .iter()
            .find(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route.contains("/api/poly-pay"))
            .expect("Ambiguous polymorphic route with unguarded RawGateway must emit finding");
        assert_eq!(
            poly_auth.confidence,
            Confidence::Heuristic,
            "Ambiguous polymorphic dispatch MUST downgrade to Confidence::Heuristic (Zero Hallucination): {:?}",
            poly_auth
        );
        assert!(
            poly_auth
                .proof_reasons
                .iter()
                .any(|r| r.contains("AmbiguousPolymorphicDispatch")),
            "Finding proof_reasons must note AmbiguousPolymorphicDispatch: {:?}",
            poly_auth.proof_reasons
        );

        // 3. RTA narrowing: DeadMockGateway is NOT instantiated -> narrows to SafeGateway -> 0 FP!
        let rta_src = r#"
export interface WalletGateway {
    debit(req: any): Promise<void>;
}
export class SafeWalletGateway implements WalletGateway {
    async debit(req: any) {
        verifyJwt(req.headers.authorization);
        await stripe.charges.create({ amount: 100 });
    }
}
export class DeadMockGateway implements WalletGateway {
    async debit(req: any) {
        await stripe.charges.create({ amount: 100 });
    }
}
const liveGw = new SafeWalletGateway();
app.post('/api/rta-pay', async (req, res) => {
    const gw: WalletGateway = liveGw;
    await gw.debit(req);
    res.json({ ok: true });
});
"#;
        let s_rta = parse_file_ast(&mk("src/rta.ts", Language::TypeScript, rta_src), &cfg).unwrap();
        let rta_res = solve_guard_lattice(&[s_rta]);
        assert!(
            !rta_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route.contains("/api/rta-pay")),
            "RTA must prune uninstantiated DeadMockGateway and suppress FP: {:?}",
            rta_res.findings
        );

        // 4. Go structural interface satisfaction
        let go_iface_src = r#"
package billing
import "net/http"

type Charger interface {
    Charge()
}
type StripeCharger struct{}
func (s *StripeCharger) Charge() {
    stripe.charges.Create(100)
}
func Register(mux *http.ServeMux) {
    mux.HandleFunc("POST /go/cha-charge", handleCharge)
}
func handleCharge(w http.ResponseWriter, r *http.Request) {
    var c Charger = &StripeCharger{}
    c.Charge()
}
"#;
        let s_go_iface = parse_file_ast(
            &mk("pkg/billing/charger.go", Language::Go, go_iface_src),
            &cfg,
        )
        .unwrap();
        let go_iface_res = solve_guard_lattice(&[s_go_iface]);
        assert!(
            go_iface_res
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-AUTH-001" && f.entry_route.contains("/go/cha-charge")),
            "Go structural interface Charger.Charge() must resolve to StripeCharger.Charge(): {:?}",
            go_iface_res.findings
        );
    }
}
