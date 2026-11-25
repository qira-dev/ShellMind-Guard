use serde::{Deserialize, Serialize};
use smg_core::{IndexedFile, Language, ShellMindGuardConfig};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Parser};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Route,
    #[default]
    Function,
    Sink,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    #[default]
    Heuristic,
    Confirmed,
    Proven,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Proven => "PROVEN",
            Confidence::Confirmed => "CONFIRMED",
            Confidence::Heuristic => "HEURISTIC",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "PROVEN" => Some(Confidence::Proven),
            "CONFIRMED" => Some(Confidence::Confirmed),
            "HEURISTIC" => Some(Confidence::Heuristic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    PaymentMutation,
    BalanceUpdate,
    SqlWrite,
    AuthMutation,
    SqlInjection,
    CommandInjection,
    PathTraversal,
    Ssrf,
    Xss,
    Csrf,
    IdorDbAccess,
    SecretLeak,
    Misconfiguration,
    DependencyRisk,
    FrontendContract,
    ConcurrencyHazard,
    ResourceLeak,
    MemorySafety,
    IntegerOverflow,
    MobileSecurity,
    SchemaTampering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardKind {
    Auth,
    TxLock,
    SqlSanitizer,
    CmdSanitizer,
    PathSanitizer,
    SsrfSanitizer,
    XssSanitizer,
    CsrfProtection,
    OwnershipCheck,
    SecretPolicy,
    ConfigPolicy,
    DependencyPolicy,
    FrontendContract,
    LockOrdering,
    ResourceCleanup,
    MemoryBounds,
    MobilePolicy,
    InputValidation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStaticFinding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub rel_path: String,
    pub line: usize,
    pub symbol: String,
    pub sink_kind: SinkKind,
    pub missing_guard: GuardKind,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendApiCall {
    pub rel_path: String,
    pub line: usize,
    pub method: String,
    pub raw_path: String,
    pub normalized_path: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportRef {
    pub symbol_name: String,
    pub from_specifier: String,
    #[serde(default)]
    pub remote_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockOrderEdge {
    pub first: String,
    pub second: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHeldCall {
    pub lock_name: String,
    pub callee: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainHints {
    pub web: bool,
    pub system_engine: bool,
    pub mobile: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSite {
    #[serde(default)]
    pub qualifier: Option<String>,
    pub member: String,
    #[serde(default)]
    pub resolved_recv_type: Option<String>,
    #[serde(default)]
    pub line: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeImplSummary {
    pub type_name: String,
    #[serde(default)]
    pub implements: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub is_interface: bool,
    #[serde(default)]
    pub line: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub id: String,
    pub rel_path: String,
    pub name: String,
    pub kind: SymbolKind,
    pub sink_kind: Option<SinkKind>,
    pub line_start: usize,
    pub line_end: usize,
    pub guards: HashSet<GuardKind>,
    pub calls: Vec<String>,
    pub route_path: Option<String>,
    #[serde(default)]
    pub has_taint_source: bool,
    #[serde(default)]
    pub has_resource_id: bool,
    #[serde(default)]
    pub has_db_crud_sink: bool,
    #[serde(default)]
    pub db_crud_line: Option<usize>,
    #[serde(default)]
    pub tainted_calls: Vec<String>,
    #[serde(default)]
    pub tainted_call_masks: std::collections::HashMap<String, u8>,
    #[serde(default)]
    pub param_forwarding_calls: Vec<String>,
    #[serde(default)]
    pub local_taint_hits: Vec<LocalStaticFinding>,
    #[serde(default)]
    pub param_sinks: Vec<LocalStaticFinding>,
    #[serde(default)]
    pub has_cookie_session_auth: bool,
    #[serde(default)]
    pub has_bearer_header_auth: bool,
    #[serde(default)]
    pub csrf_exempt: bool,
    #[serde(default)]
    pub lock_pairs: Vec<LockOrderEdge>,
    #[serde(default)]
    pub locks_held_calls: Vec<LockHeldCall>,
    #[serde(default)]
    pub locks_acquired: Vec<(String, usize)>,
    /// Phase 10: per-callee struct/object field taint masks `callee -> [(field_name, bitmask)]`.
    #[serde(default)]
    pub tainted_field_calls: std::collections::HashMap<String, Vec<(String, u8)>>,
    /// Phase 10: field names read from parameters by each `param_sinks` hit (`None` = whole param).
    #[serde(default)]
    pub param_sink_fields: Vec<(LocalStaticFinding, Option<String>)>,
    /// Phase 10: sanitizer bits cleared on this function's returned value (cross-file sanitizer wrapper).
    #[serde(default)]
    pub clears_taint_mask: u8,
    /// Phase 10: per-field sanitizer bits cleared on returned object literal (`field -> clear_mask`).
    #[serde(default)]
    pub clears_field_masks: std::collections::HashMap<String, u8>,
    /// Phase 10: taint mask when this function invokes a callback parameter (`cb(data)`).
    #[serde(default)]
    pub invokes_callback_mask: u8,
    /// Phase 10: `(dispatcher_callee, callback_symbol, taint_mask)` for cross-file callback handoffs.
    #[serde(default)]
    pub callback_forwards: Vec<(String, String, u8)>,
    /// Phase 10: `(rule_id, line, wrapper_fn, field)` for local sink args sourced purely via cross-file wrappers.
    #[serde(default)]
    pub local_hit_wrappers: Vec<(String, usize, String, Option<String>)>,
    /// Phase 10: `(callee, wrapper_fn, field, mask)` for inter-procedural wrapper suppression.
    #[serde(default)]
    pub tainted_call_wrappers: Vec<(String, String, Option<String>, u8)>,
    /// Route middleware wrapper callees (e.g. `RequireSession(h)`, `r.With(mw)`).
    #[serde(default)]
    pub middleware_callees: Vec<String>,
    /// Phase 12A: Qualified call sites preserving `(qualifier, member, resolved_recv_type, line)`.
    #[serde(default)]
    pub call_sites: Vec<CallSite>,
    /// Phase 12A: Enclosing class, struct, impl, or Go receiver type name (if this symbol is a method).
    #[serde(default)]
    pub enclosing_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAstSummary {
    pub rel_path: String,
    pub imports: Vec<ImportRef>,
    pub symbols: Vec<SymbolInfo>,
    #[serde(default)]
    pub static_findings: Vec<LocalStaticFinding>,
    #[serde(default)]
    pub frontend_calls: Vec<FrontendApiCall>,
    #[serde(default)]
    pub route_prefixes: Vec<String>,
    #[serde(default)]
    pub gitignore_lines: Option<Vec<String>>,
    #[serde(default)]
    pub is_sensitive_env_or_pem: bool,
    #[serde(default)]
    pub has_cookie_session_setup: bool,
    #[serde(default)]
    pub has_bearer_auth_setup: bool,
    #[serde(default)]
    pub has_global_csrf_guard: bool,
    #[serde(default)]
    pub domain_hints: DomainHints,
    #[serde(default)]
    pub route_schemas: Vec<crate::phase10::RouteSchema>,
    /// Phase 12A: Extracted class/interface/trait/struct type hierarchy summaries.
    #[serde(default)]
    pub type_impls: Vec<TypeImplSummary>,
    /// Phase 12A: Extracted DI container bindings `(abstract_token, concrete_impl_type)`.
    #[serde(default)]
    pub di_bindings: Vec<(String, String)>,
    /// Phase 12A: Concrete types instantiated in this file (for RTA narrowing).
    #[serde(default)]
    pub instantiated_types: Vec<String>,
}

impl SymbolInfo {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn base(
        id: String,
        rel_path: &str,
        name: String,
        kind: SymbolKind,
        sink_kind: Option<SinkKind>,
        line_start: usize,
        line_end: usize,
        guards: HashSet<GuardKind>,
        calls: Vec<String>,
        route_path: Option<String>,
    ) -> Self {
        Self {
            id,
            rel_path: rel_path.to_string(),
            name,
            kind,
            sink_kind,
            line_start,
            line_end,
            guards,
            calls,
            route_path,
            has_taint_source: false,
            has_resource_id: false,
            has_db_crud_sink: false,
            db_crud_line: None,
            tainted_calls: Vec::new(),
            tainted_call_masks: std::collections::HashMap::new(),
            param_forwarding_calls: Vec::new(),
            local_taint_hits: Vec::new(),
            param_sinks: Vec::new(),
            has_cookie_session_auth: false,
            has_bearer_header_auth: false,
            csrf_exempt: false,
            lock_pairs: Vec::new(),
            locks_held_calls: Vec::new(),
            locks_acquired: Vec::new(),
            tainted_field_calls: std::collections::HashMap::new(),
            param_sink_fields: Vec::new(),
            clears_taint_mask: 0,
            clears_field_masks: std::collections::HashMap::new(),
            invokes_callback_mask: 0,
            callback_forwards: Vec::new(),
            local_hit_wrappers: Vec::new(),
            tainted_call_wrappers: Vec::new(),
            middleware_callees: Vec::new(),
            call_sites: Vec::new(),
            enclosing_type: None,
        }
    }

    fn apply_taint(&mut self, t: crate::taint::FunctionTaintSummary) {
        self.guards.extend(t.guards);
        self.has_taint_source = self.has_taint_source || t.has_taint_source;
        self.has_resource_id = self.has_resource_id || t.has_resource_id;
        self.has_db_crud_sink = self.has_db_crud_sink || t.has_db_crud_sink;
        self.has_cookie_session_auth = self.has_cookie_session_auth || t.has_cookie_session_auth;
        self.has_bearer_header_auth = self.has_bearer_header_auth || t.has_bearer_header_auth;
        self.csrf_exempt = self.csrf_exempt || t.csrf_exempt;
        for (callee, mask) in t.tainted_call_masks {
            *self.tainted_call_masks.entry(callee).or_insert(0) |= mask;
        }
        if self.db_crud_line.is_none() {
            self.db_crud_line = t.db_crud_line;
        }
        for c in t.tainted_calls {
            if !self.tainted_calls.iter().any(|x| x == &c) {
                self.tainted_calls.push(c);
            }
        }
        for c in t.param_forwarding_calls {
            if !self.param_forwarding_calls.iter().any(|x| x == &c) {
                self.param_forwarding_calls.push(c);
            }
        }
        for (callee, pairs) in t.tainted_field_calls {
            let entry = self.tainted_field_calls.entry(callee).or_default();
            for (fld, m) in pairs {
                if let Some(ex) = entry.iter_mut().find(|(f, _)| f == &fld) {
                    ex.1 |= m;
                } else {
                    entry.push((fld, m));
                }
            }
        }
        self.param_sink_fields.extend(t.param_sink_fields);
        self.clears_taint_mask |= t.clears_taint_mask;
        for (fld, m) in t.clears_field_masks {
            *self.clears_field_masks.entry(fld).or_insert(0) |= m;
        }
        self.invokes_callback_mask |= t.invokes_callback_mask;
        for cb in t.callback_forwards {
            if !self.callback_forwards.contains(&cb) {
                self.callback_forwards.push(cb);
            }
        }
        self.local_hit_wrappers.extend(t.local_hit_wrappers);
        self.tainted_call_wrappers.extend(t.tainted_call_wrappers);
        self.local_taint_hits.extend(t.local_taint_hits);
        self.param_sinks.extend(t.param_sinks);
    }
}

pub fn parse_file_ast_with_hash(
    file: &IndexedFile,
    cfg: &ShellMindGuardConfig,
) -> Option<(String, FileAstSummary)> {
    let owned_bytes;
    let bytes: &[u8] = if let Some(ref cached) = file.cached_bytes {
        cached.as_slice()
    } else {
        owned_bytes = fs::read(&file.abs_path).ok()?;
        owned_bytes.as_slice()
    };
    let actual_hash = if file.cached_bytes.is_some() && !file.blake3_hash.is_empty() {
        file.blake3_hash.clone()
    } else {
        blake3::hash(bytes).to_hex().to_string()
    };
    let is_sensitive_path = crate::secrets_config::is_sensitive_env_or_pem(&file.rel_path);
    let source = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            if is_sensitive_path {
                return Some((
                    actual_hash,
                    FileAstSummary {
                        rel_path: file.rel_path.clone(),
                        is_sensitive_env_or_pem: true,
                        ..Default::default()
                    },
                ));
            }
            return None;
        }
    };
    let is_sensitive =
        crate::secrets_config::is_sensitive_env_or_pem_with_content(&file.rel_path, source);

    let gitignore_lines = if Path::new(&file.rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        == Some(".gitignore")
    {
        Some(source.lines().map(|l| l.to_string()).collect())
    } else {
        None
    };

    let is_scanner_rule_cfg = matches!(
        std::path::Path::new(&file.rel_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(""),
        ".gitleaks.toml"
            | "gitleaks.toml"
            | ".trufflehog.yaml"
            | ".trufflehog.yml"
            | ".detect-secrets.cfg"
            | ".semgrep.yml"
            | ".semgrep.yaml"
    );
    let mut static_findings = if is_scanner_rule_cfg {
        Vec::new()
    } else {
        crate::secrets_config::scan_secrets_and_config(&file.rel_path, source)
    };
    if !is_scanner_rule_cfg && !matches!(file.language, Language::Solidity | Language::Move) {
        static_findings.extend(crate::infra_dos::scan_infra_dos_crypto_and_queues(
            &file.rel_path,
            file.language,
            source,
        ));
        static_findings.extend(crate::protocols_ai::scan_protocols_ai_and_workflow(
            &file.rel_path,
            file.language,
            source,
        ));
        for pf in crate::rule_pack::scan_rule_pack(&file.rel_path, file.language, source) {
            let already_covered = static_findings.iter().any(|x| {
                x.line == pf.line
                    && (x.rule_id == pf.rule_id
                        || (x.rule_id.starts_with("SMG-AI-")
                            && matches!(
                                pf.symbol.as_str(),
                                "torch.load"
                                    | "ml_pickle_load"
                                    | "np_allow_pickle"
                                    | "hf_trust_remote_code"
                            )))
            });
            if !already_covered {
                static_findings.push(pf);
            }
        }
    }
    if matches!(file.language, Language::Manifest) {
        static_findings.extend(crate::deps::scan_dependencies(&file.rel_path, source));
    }
    if matches!(file.language, Language::Sql) {
        static_findings.extend(crate::deep_stack::scan_sql_file(&file.rel_path, source));
    }
    if matches!(file.language, Language::Config | Language::Manifest) {
        static_findings.extend(crate::phase9::scan_mobile_config(&file.rel_path, source));
    }

    if matches!(
        file.language,
        Language::Config | Language::Manifest | Language::Sql | Language::Solidity | Language::Move
    ) {
        let domain_hints =
            crate::phase9::detect_domain_hints(file.language, &file.rel_path, source, &[]);
        let route_schemas = if matches!(file.language, Language::Config) {
            crate::phase10::parse_openapi_route_schemas(&file.rel_path, source)
        } else {
            Vec::new()
        };
        return Some((
            actual_hash,
            FileAstSummary {
                rel_path: file.rel_path.clone(),
                static_findings,
                gitignore_lines,
                is_sensitive_env_or_pem: is_sensitive,
                domain_hints,
                route_schemas,
                ..Default::default()
            },
        ));
    }

    let mut parser = Parser::new();
    if !configure_parser_language(&mut parser, file.language, &file.rel_path) {
        return None;
    }

    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    let src_bytes = source.as_bytes();

    if file.language == Language::Rust {
        let mut test_ranges: Vec<(usize, usize)> = Vec::new();
        let mut rc = root.walk();
        for ch in root.children(&mut rc) {
            if is_rust_test_item(ch, src_bytes) {
                test_ranges.push((ch.start_position().row + 1, ch.end_position().row + 1));
            }
        }
        if !test_ranges.is_empty() {
            static_findings.retain(|sf| {
                let in_cfg_test = test_ranges
                    .iter()
                    .any(|(s, e)| sf.line >= *s && sf.line <= *e);
                !in_cfg_test
                    || sf.missing_guard == GuardKind::SecretPolicy
                    || sf.rule_id.starts_with("SMG-SEC-")
            });
        }
    }

    let mut imports = Vec::new();
    let mut symbols = Vec::new();
    let mut route_prefixes = Vec::new();

    let mut file_middleware_guards = HashSet::new();
    if matches!(
        file.language,
        Language::TypeScript
            | Language::JavaScript
            | Language::Rust
            | Language::Python
            | Language::Go
    ) {
        extract_node(
            root,
            src_bytes,
            &file.rel_path,
            file.language,
            cfg,
            &mut file_middleware_guards,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
    } else {
        crate::langs::extract_extension_language(
            root,
            src_bytes,
            &file.rel_path,
            file.language,
            cfg,
            &mut file_middleware_guards,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
            &mut static_findings,
        );
    }

    let call_hier = crate::call_hierarchy::enrich_file_call_hierarchy(
        root,
        src_bytes,
        file.language,
        &mut symbols,
    );

    let mut frontend_calls = Vec::new();
    crate::taint::extract_frontend_calls_and_bugs(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        &mut frontend_calls,
        &mut static_findings,
    );

    let scope_table = crate::scope::extract_file_scope(root, src_bytes, file.language, &imports);

    crate::deep_stack::scan_ast_deep(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        &scope_table,
        &mut symbols,
        &mut static_findings,
    );

    crate::phase9::analyze_ast_phase9(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        &mut symbols,
        &mut static_findings,
    );

    let domain_hints =
        crate::phase9::detect_domain_hints(file.language, &file.rel_path, source, &symbols);

    let code_only = strip_comments(source);
    let has_cookie_session_setup = crate::taint::has_cookie_session_expr(&code_only);
    let has_bearer_auth_setup = crate::taint::has_bearer_header_expr(&code_only);
    let has_global_csrf_guard = file_middleware_guards.contains(&GuardKind::CsrfProtection)
        || crate::taint::has_global_csrf_middleware(&code_only);
    route_prefixes.retain(|p| !p.starts_with("__AUTH_PREFIX__:MOUNT:"));
    let route_schemas = crate::phase10::extract_ast_route_schemas(
        root,
        src_bytes,
        &file.rel_path,
        file.language,
        &symbols,
    );

    Some((
        actual_hash,
        FileAstSummary {
            rel_path: file.rel_path.clone(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            gitignore_lines,
            is_sensitive_env_or_pem: is_sensitive,
            has_cookie_session_setup,
            has_bearer_auth_setup,
            has_global_csrf_guard,
            domain_hints,
            route_schemas,
            type_impls: call_hier.type_impls,
            di_bindings: call_hier.di_bindings,
            instantiated_types: call_hier.instantiated_types,
        },
    ))
}

fn configure_parser_language(parser: &mut Parser, language: Language, rel_path: &str) -> bool {
    match language {
        Language::TypeScript => {
            let is_tsx = rel_path.ends_with(".tsx");
            let lang = if is_tsx {
                tree_sitter_typescript::LANGUAGE_TSX.into()
            } else {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            };
            parser.set_language(&lang).is_ok()
        }
        Language::JavaScript => parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .is_ok(),
        Language::Rust => parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .is_ok(),
        Language::Python => parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .is_ok(),
        Language::Go => parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .is_ok(),
        other => crate::langs::ts_language_for(other)
            .is_some_and(|ts_lang| parser.set_language(&ts_lang).is_ok()),
    }
}

/// Validates syntax cleanly using the embedded Tree-sitter parser before running sandbox checks.
pub fn check_source_syntax(language: Language, rel_path: &str, source: &str) -> anyhow::Result<()> {
    if matches!(
        language,
        Language::Config | Language::Manifest | Language::Sql | Language::Solidity | Language::Move
    ) {
        if rel_path.ends_with(".json") {
            serde_json::from_str::<serde_json::Value>(source)
                .map_err(|e| anyhow::anyhow!("JSON syntax error in {}: {}", rel_path, e))?;
        }
        return Ok(());
    }
    let mut parser = Parser::new();
    if !configure_parser_language(&mut parser, language, rel_path) {
        return Ok(());
    }
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Tree-sitter failed to parse {}", rel_path))?;
    if tree.root_node().has_error() {
        anyhow::bail!("Syntax error detected by Tree-sitter in {}", rel_path);
    }
    Ok(())
}

pub fn parse_file_ast(file: &IndexedFile, cfg: &ShellMindGuardConfig) -> Option<FileAstSummary> {
    parse_file_ast_with_hash(file, cfg).map(|(_, s)| s)
}

pub(crate) fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

pub(crate) fn strip_comments(src: &str) -> String {
    crate::taint::strip_comments_simple(src)
}

pub(crate) fn is_auth_guard_ident(name: &str, cfg: &ShellMindGuardConfig) -> bool {
    let low = name.to_ascii_lowercase();
    if low.contains("unauthenticated")
        || low.contains("allowanonymous")
        || low.contains("optionalauth")
        || low.contains("optional_auth")
        || low.contains("noauth")
        || low.contains("no_auth")
        || low.contains("skipauth")
        || low.contains("skip_auth")
    {
        return false;
    }
    cfg.guards.auth_guards.iter().any(|pat| {
        let p = pat.to_ascii_lowercase();
        low == p || low.ends_with(&format!(".{}", p)) || low.starts_with(&format!("{}(", p))
    })
}

pub(crate) fn is_lock_guard_ident(name: &str, cfg: &ShellMindGuardConfig) -> bool {
    let low = name.to_ascii_lowercase();
    cfg.guards.lock_guards.iter().any(|pat| {
        let p = pat.to_ascii_lowercase();
        low == p || low.ends_with(&format!(".{}", p)) || low.starts_with(&format!("{}(", p))
    })
}

pub(crate) fn contains_guard_pattern(low_text: &str, pat_low: &str) -> bool {
    if pat_low == "authenticate" && low_text.contains("unauthenticated") {
        let cleaned = low_text.replace("unauthenticated", "");
        return cleaned.contains("authenticate");
    }
    if (pat_low.contains("auth") || pat_low.contains("session"))
        && (low_text.contains("optionalauth")
            || low_text.contains("optional_auth")
            || low_text.contains("skipauth")
            || low_text.contains("noauth"))
    {
        let cleaned = low_text
            .replace("optionalauth", "")
            .replace("optional_auth", "")
            .replace("skipauth", "")
            .replace("noauth", "");
        return cleaned.contains(pat_low);
    }
    if pat_low == "useguards"
        && (low_text.contains("throttlerguard") || low_text.contains("ratelimitguard"))
    {
        return low_text.contains("auth")
            || low_text.contains("jwt")
            || low_text.contains("session");
    }
    low_text.contains(pat_low)
}

pub(crate) fn classify_guards(text: &str, cfg: &ShellMindGuardConfig) -> HashSet<GuardKind> {
    let mut g = HashSet::new();
    let code_only = crate::taint::strip_comments_and_non_attr_strings(text);
    let low = code_only.to_ascii_lowercase();
    if cfg
        .guards
        .auth_guards
        .iter()
        .any(|pat| contains_guard_pattern(&low, &pat.to_ascii_lowercase()))
    {
        g.insert(GuardKind::Auth);
    }
    if cfg
        .guards
        .lock_guards
        .iter()
        .any(|pat| contains_guard_pattern(&low, &pat.to_ascii_lowercase()))
    {
        g.insert(GuardKind::TxLock);
    }
    if crate::taint::has_csrf_guard_expr(&code_only) {
        g.insert(GuardKind::CsrfProtection);
    }
    g
}

pub(crate) fn collect_call_names_shallow(node: Node, src: &[u8], out: &mut Vec<String>) {
    collect_call_names_shallow_depth(node, src, out, 0);
}

fn collect_call_names_shallow_depth(node: Node, src: &[u8], out: &mut Vec<String>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    let k = node.kind();
    if matches!(
        k,
        "if_statement"
            | "if_expression"
            | "switch_statement"
            | "expression_switch_statement"
            | "type_switch_statement"
            | "match_expression"
            | "try_statement"
            | "for_statement"
            | "for_in_statement"
            | "while_statement"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
    ) || crate::cfg::is_nested_fn_or_closure_kind(k)
    {
        return;
    }
    if (k == "call_expression" || k == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let txt = node_text(func, src).trim();
        if !txt.is_empty() {
            out.push(txt.to_string());
        }
        let short = txt.rsplit('.').next().unwrap_or(txt);
        let short = short.rsplit("::").next().unwrap_or(short);
        if !short.is_empty() && short != txt {
            out.push(short.to_string());
        }
    }
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_call_names_shallow_depth(ch, src, out, depth + 1);
    }
}

pub(crate) fn stmt_has_sink_or_mutation(stmt: Node, src: &[u8]) -> bool {
    let raw_low = strip_comments(node_text(stmt, src)).to_ascii_lowercase();
    let txt = crate::taint::strip_comments_and_non_attr_strings(node_text(stmt, src))
        .to_ascii_lowercase();
    let has_sql_write_call = (raw_low.contains(".query(")
        || raw_low.contains(".execute(")
        || raw_low.contains(".exec("))
        && (raw_low.contains("update ")
            || raw_low.contains("insert into ")
            || raw_low.contains("delete from "));
    has_sql_write_call
        || txt.contains("stripe.")
        || txt.contains("charges.create")
        || txt.contains("paymentintent")
        || txt.contains("update ")
        || txt.contains("insert into ")
        || txt.contains("delete from ")
        || txt.contains("debit")
        || txt.contains("withdraw")
        || txt.contains("balance")
}

fn collect_returned_closures<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    let mut stack = vec![(node, 0usize)];
    while let Some((cur, d)) = stack.pop() {
        if d > 6 {
            continue;
        }
        if cur.kind() == "return_statement" {
            let mut rc = cur.walk();
            for ret_expr in cur.children(&mut rc) {
                if let Some(closure) = find_inline_fn_node(ret_expr) {
                    out.push(closure);
                }
            }
            continue;
        }
        if matches!(
            cur.kind(),
            "function_declaration" | "method_declaration" | "func_literal" | "arrow_function"
        ) && cur.id() != node.id()
        {
            continue;
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            stack.push((ch, d + 1));
        }
    }
}

/// Control-flow & Dominator-tree aware guard extractor backed by `crate::cfg`.
fn classify_fn_guards_cfg(
    fn_node: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
) -> HashSet<GuardKind> {
    let mut guards = crate::cfg::compute_cfg_guard_dominance(fn_node, src, cfg);
    if !guards.contains(&GuardKind::Auth)
        && let Some(body) = fn_node.child_by_field_name("body")
    {
        let mut closures = Vec::new();
        collect_returned_closures(body, &mut closures);
        for closure in closures {
            guards.extend(crate::cfg::compute_cfg_guard_dominance(closure, src, cfg));
        }
    }
    guards
}

pub(crate) fn classify_sink(name: &str, body: &str) -> Option<SinkKind> {
    let low_name = name.to_ascii_lowercase();
    let low_body = strip_comments(body).to_ascii_lowercase();

    if low_body.contains("stripe.")
        || low_body.contains("charges.create")
        || low_body.contains("paymentintent")
        || low_body.contains("paypal.")
        || low_body.contains("razorpay.")
        || low_body.contains("paddle.")
        || low_body.contains("sslcommerz")
        || low_body.contains("braintree.")
        || (low_name.contains("charge") && low_body.contains("amount"))
    {
        return Some(SinkKind::PaymentMutation);
    }
    if (low_body.contains("balance")
        || low_name.contains("balance")
        || low_name.contains("withdraw")
        || low_name.contains("debit"))
        && (low_body.contains("update")
            || low_body.contains("-=")
            || low_body.contains("+=")
            || low_body.contains("set ")
            || low_body.contains(".save("))
    {
        return Some(SinkKind::BalanceUpdate);
    }
    if (low_body.contains("update ") && low_body.contains("set "))
        || low_body.contains("insert into ")
        || low_body.contains("delete from ")
        || ((low_body.contains("prisma.") || low_body.contains("db."))
            && (low_body.contains(".create(")
                || low_body.contains(".update(")
                || low_body.contains(".upsert(")
                || low_body.contains(".delete(")))
        || low_body.contains("db.insert(")
        || low_body.contains("db.update(")
        || low_body.contains("db.delete(")
        || low_body.contains(".updates(")
        || low_body.contains("db.exec(")
        || low_body.contains("tx.exec(")
        || low_body.contains("session.commit(")
    {
        return Some(SinkKind::SqlWrite);
    }
    if low_name.contains("role") && (low_body.contains("admin") || low_body.contains("update")) {
        return Some(SinkKind::AuthMutation);
    }
    None
}

fn collect_calls(node: Node, src: &[u8], calls: &mut Vec<String>) {
    collect_calls_depth(node, src, calls, 0);
}

fn collect_calls_depth(node: Node, src: &[u8], calls: &mut Vec<String>, depth: usize) {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return;
    }
    if (node.kind() == "call_expression" || node.kind() == "call")
        && let Some(func) = node.child_by_field_name("function")
    {
        let txt = node_text(func, src).trim();
        let short = txt.rsplit('.').next().unwrap_or(txt);
        let short = short.rsplit("::").next().unwrap_or(short);
        if !short.is_empty() && !calls.iter().any(|c| c == short) {
            calls.push(short.to_string());
        }
        // Connect named spawned workers (`tokio::spawn(worker)`, `std::thread::spawn(worker)`)
        if matches!(short, "spawn" | "spawn_blocking" | "spawn_local")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut ac = args.walk();
            for arg in args.children(&mut ac) {
                if arg.kind() == "identifier" {
                    let cname = node_text(arg, src).trim();
                    if !cname.is_empty()
                        && !matches!(cname, "true" | "false" | "None" | "null")
                        && !calls.iter().any(|c| c == cname)
                    {
                        calls.push(cname.to_string());
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_calls_depth(child, src, calls, depth + 1);
    }
}

fn find_inline_fn_node(arg: Node) -> Option<Node> {
    find_inline_fn_node_depth(arg, 0)
}

fn find_inline_fn_node_depth(arg: Node, depth: usize) -> Option<Node> {
    if depth >= crate::taint::MAX_AST_WALK_DEPTH {
        return None;
    }
    if matches!(
        arg.kind(),
        "arrow_function" | "function_expression" | "func_literal"
    ) {
        return Some(arg);
    }
    if matches!(arg.kind(), "expression_list" | "parenthesized_expression") {
        let mut c = arg.walk();
        for ch in arg.children(&mut c) {
            if let Some(found) = find_inline_fn_node_depth(ch, depth + 1) {
                return Some(found);
            }
        }
    }
    if (arg.kind() == "call_expression" || arg.kind() == "call")
        && let Some(inner_args) = arg.child_by_field_name("arguments")
    {
        let mut c = inner_args.walk();
        for ch in inner_args.children(&mut c) {
            if let Some(found) = find_inline_fn_node_depth(ch, depth + 1) {
                return Some(found);
            }
        }
    }
    None
}

pub(crate) fn is_rust_test_item(node: Node, src: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let txt = node_text(p, src);
            if txt.contains("cfg(test)") || txt.contains("#[test]") || txt.contains("::test") {
                return true;
            }
            prev = p.prev_sibling();
        } else if matches!(p.kind(), "line_comment" | "block_comment") {
            prev = p.prev_sibling();
        } else {
            break;
        }
    }
    false
}

#[derive(Debug, Clone)]
struct GoRouteSpan {
    start_byte: usize,
    end_byte: usize,
    prefix: String,
    guards: HashSet<GuardKind>,
    mw_calls: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct GoRouterVarScope {
    prefix: String,
    guards: HashSet<GuardKind>,
    mw_calls: Vec<String>,
}

#[derive(Debug, Default)]
struct GoRouterScopes {
    spans: Vec<GoRouteSpan>,
    router_vars: std::collections::HashMap<String, GoRouterVarScope>,
    wrapped_routers: std::collections::HashMap<String, (HashSet<GuardKind>, Vec<String>)>,
}

fn join_route_prefix(prefix: &str, path: &str) -> String {
    let p = prefix.trim().trim_end_matches('/');
    let c = path.trim();
    if p.is_empty() {
        if c.is_empty() {
            return "/".to_string();
        }
        return if c.starts_with('/') {
            c.to_string()
        } else {
            format!("/{}", c)
        };
    }
    let clean_c = c.trim_start_matches('/');
    if clean_c.is_empty() {
        p.to_string()
    } else {
        format!("{}/{}", p, clean_c)
    }
}

fn split_go_method_and_path(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    if let Some((verb, rest)) = trimmed.split_once(char::is_whitespace) {
        let up = verb.trim().to_ascii_uppercase();
        let rest_t = rest.trim();
        if matches!(
            up.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) && rest_t.starts_with('/')
        {
            return (Some(up), rest_t.to_string());
        }
    }
    (None, trimmed.to_string())
}

fn collect_go_mw_arg_recursive(
    node: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
    is_mw_pos: bool,
    guards: &mut HashSet<GuardKind>,
    mw_calls: &mut Vec<String>,
    calls: &mut Vec<String>,
) {
    let k = node.kind();
    if matches!(k, "(" | ")" | "," | "comment") {
        return;
    }
    if k == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let ftxt = node_text(func, src).trim();
            let short = ftxt
                .rsplit('.')
                .next()
                .unwrap_or(ftxt)
                .rsplit("::")
                .next()
                .unwrap_or(ftxt)
                .trim();
            let is_adapter = matches!(ftxt, "http.HandlerFunc" | "HandlerFunc");
            if !is_adapter && !short.is_empty() {
                if is_auth_guard_ident(short, cfg) {
                    guards.insert(GuardKind::Auth);
                } else if is_lock_guard_ident(short, cfg) {
                    guards.insert(GuardKind::TxLock);
                }
                guards.extend(classify_guards(ftxt, cfg));
                calls.push(short.to_string());
                if !mw_calls.iter().any(|x| x == short) {
                    mw_calls.push(short.to_string());
                }
            }
        }
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut c = args.walk();
            let mut arg_nodes: Vec<Node> = args
                .children(&mut c)
                .filter(|a| !matches!(a.kind(), "(" | ")" | "," | "comment"))
                .collect();
            let total = arg_nodes.len();
            for (idx, a) in arg_nodes.drain(..).enumerate() {
                collect_go_mw_arg_recursive(
                    a,
                    src,
                    cfg,
                    idx + 1 < total || is_mw_pos,
                    guards,
                    mw_calls,
                    calls,
                );
            }
        }
        return;
    }
    let txt = node_text(node, src).trim();
    if txt.is_empty() || txt.starts_with('"') || txt.starts_with('`') {
        return;
    }
    let short = txt
        .split('(')
        .next()
        .unwrap_or(txt)
        .rsplit('.')
        .next()
        .unwrap_or(txt)
        .trim();
    if short.is_empty() {
        return;
    }
    if is_auth_guard_ident(short, cfg) || is_auth_guard_ident(txt, cfg) {
        guards.insert(GuardKind::Auth);
        if !mw_calls.iter().any(|x| x == short) {
            mw_calls.push(short.to_string());
        }
    } else if is_lock_guard_ident(short, cfg) {
        guards.insert(GuardKind::TxLock);
    } else if is_mw_pos && !mw_calls.iter().any(|x| x == short) {
        mw_calls.push(short.to_string());
    }
    if !calls.iter().any(|x| x == short) {
        calls.push(short.to_string());
    }
}

fn extract_go_chained_receiver<'a>(
    call_fn: Node<'a>,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
) -> (Option<String>, HashSet<GuardKind>, Vec<String>, String) {
    let mut guards = HashSet::new();
    let mut mw_calls = Vec::new();
    let mut prefix = String::new();
    let mut cur = call_fn;
    loop {
        if cur.kind() == "selector_expression"
            && let Some(op) = cur.child_by_field_name("operand")
        {
            if op.kind() == "call_expression" {
                if let Some(inner_fn) = op.child_by_field_name("function") {
                    let m = node_text(inner_fn, src)
                        .rsplit('.')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if let Some(args) = op.child_by_field_name("arguments") {
                        let mut c = args.walk();
                        for a in args.children(&mut c) {
                            let atxt = node_text(a, src).trim();
                            if matches!(a.kind(), "(" | ")" | "," | "comment") {
                                continue;
                            }
                            if (atxt.starts_with('"') || atxt.starts_with('`'))
                                && matches!(m, "PathPrefix" | "Group" | "Route")
                            {
                                let unq = atxt.trim_matches(|q| q == '"' || q == '`');
                                if unq.starts_with('/') {
                                    prefix = join_route_prefix(unq, &prefix);
                                }
                            } else if matches!(m, "With" | "Use" | "Group") {
                                let mut dummy = Vec::new();
                                collect_go_mw_arg_recursive(
                                    a,
                                    src,
                                    cfg,
                                    true,
                                    &mut guards,
                                    &mut mw_calls,
                                    &mut dummy,
                                );
                            }
                        }
                    }
                    cur = inner_fn;
                    continue;
                }
            } else if op.kind() == "identifier" {
                return (
                    Some(node_text(op, src).trim().to_string()),
                    guards,
                    mw_calls,
                    prefix,
                );
            }
        } else if cur.kind() == "identifier" {
            return (
                Some(node_text(cur, src).trim().to_string()),
                guards,
                mw_calls,
                prefix,
            );
        }
        return (None, guards, mw_calls, prefix);
    }
}

fn scan_direct_go_block_use(
    fn_lit: Node,
    src: &[u8],
    cfg: &ShellMindGuardConfig,
    guards: &mut HashSet<GuardKind>,
    mw_calls: &mut Vec<String>,
) {
    let Some(body) = fn_lit.child_by_field_name("body") else {
        return;
    };
    let mut c = body.walk();
    for stmt in body.children(&mut c) {
        if stmt.kind() != "call_expression" {
            // Check single-expression child in expression_statement wrapper if needed
            let mut sc = stmt.walk();
            for ch in stmt.children(&mut sc) {
                if ch.kind() == "call_expression"
                    && let Some(func) = ch.child_by_field_name("function")
                    && node_text(func, src).trim().ends_with(".Use")
                    && let Some(args) = ch.child_by_field_name("arguments")
                {
                    let mut ac = args.walk();
                    let mut dummy = Vec::new();
                    for a in args.children(&mut ac) {
                        collect_go_mw_arg_recursive(
                            a, src, cfg, true, guards, mw_calls, &mut dummy,
                        );
                    }
                }
            }
            continue;
        }
        if let Some(func) = stmt.child_by_field_name("function")
            && node_text(func, src).trim().ends_with(".Use")
            && let Some(args) = stmt.child_by_field_name("arguments")
        {
            let mut ac = args.walk();
            let mut dummy = Vec::new();
            for a in args.children(&mut ac) {
                collect_go_mw_arg_recursive(a, src, cfg, true, guards, mw_calls, &mut dummy);
            }
        }
    }
}

fn collect_go_router_scopes(root: Node, src: &[u8], cfg: &ShellMindGuardConfig) -> GoRouterScopes {
    let mut info = GoRouterScopes::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let k = node.kind();
        if k == "call_expression"
            && let Some(func) = node.child_by_field_name("function")
        {
            let ftxt = node_text(func, src).trim();
            let m = ftxt.rsplit('.').next().unwrap_or("");
            if matches!(m, "Route" | "Group")
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let mut prefix = String::new();
                let (_, mut guards, mut mw_calls, chained_pref) =
                    extract_go_chained_receiver(func, src, cfg);
                if !chained_pref.is_empty() {
                    prefix = chained_pref;
                }
                let mut fn_lit_opt: Option<Node> = None;
                let mut ac = args.walk();
                let mut dummy = Vec::new();
                for a in args.children(&mut ac) {
                    if matches!(a.kind(), "(" | ")" | "," | "comment") {
                        continue;
                    }
                    let atxt = node_text(a, src).trim();
                    if (atxt.starts_with('"') || atxt.starts_with('`')) && prefix.is_empty() {
                        let unq = atxt.trim_matches(|q| q == '"' || q == '`');
                        if unq.starts_with('/') {
                            prefix = unq.to_string();
                        }
                    } else if a.kind() == "func_literal" {
                        fn_lit_opt = Some(a);
                    } else {
                        collect_go_mw_arg_recursive(
                            a,
                            src,
                            cfg,
                            true,
                            &mut guards,
                            &mut mw_calls,
                            &mut dummy,
                        );
                    }
                }
                if let Some(fn_lit) = fn_lit_opt {
                    scan_direct_go_block_use(fn_lit, src, cfg, &mut guards, &mut mw_calls);
                    info.spans.push(GoRouteSpan {
                        start_byte: fn_lit.start_byte(),
                        end_byte: fn_lit.end_byte(),
                        prefix,
                        guards,
                        mw_calls,
                    });
                }
            } else if m == "Use"
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let (base_opt, _, _, _) = extract_go_chained_receiver(func, src, cfg);
                if let Some(base_var) = base_opt
                    && let Some(entry) = info.router_vars.get_mut(&base_var)
                {
                    let mut ac = args.walk();
                    let mut dummy = Vec::new();
                    for a in args.children(&mut ac) {
                        collect_go_mw_arg_recursive(
                            a,
                            src,
                            cfg,
                            true,
                            &mut entry.guards,
                            &mut entry.mw_calls,
                            &mut dummy,
                        );
                    }
                }
            } else if m == "ListenAndServe"
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let mut ac = args.walk();
                for a in args.children(&mut ac) {
                    if a.kind() == "call_expression" {
                        let mut g = HashSet::new();
                        let mut mc = Vec::new();
                        let mut dummy = Vec::new();
                        collect_go_mw_arg_recursive(a, src, cfg, true, &mut g, &mut mc, &mut dummy);
                        for cand in &dummy {
                            if matches!(cand.as_str(), "mux" | "router" | "r" | "app" | "handler")
                                || info.router_vars.contains_key(cand)
                            {
                                let entry = info.wrapped_routers.entry(cand.clone()).or_default();
                                entry.0.extend(g.iter().copied());
                                for call in &mc {
                                    if call != cand && !entry.1.contains(call) {
                                        entry.1.push(call.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if matches!(k, "short_var_declaration" | "assignment_statement")
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        {
            let lhs = node_text(left, src).trim();
            let rhs_node = right.named_child(0).unwrap_or(right);
            if is_plain_ident_ast(lhs) && rhs_node.kind() == "call_expression" {
                let mut lhs_scope = GoRouterVarScope::default();
                if let Some(rfunc) = rhs_node.child_by_field_name("function") {
                    let rm = node_text(rfunc, src).rsplit('.').next().unwrap_or("");
                    let (base_opt, c_guards, c_mw, c_pref) =
                        extract_go_chained_receiver(rfunc, src, cfg);
                    if let Some(ref b) = base_opt
                        && let Some(parent) = info.router_vars.get(b)
                    {
                        lhs_scope.prefix = parent.prefix.clone();
                        lhs_scope.guards.extend(parent.guards.iter().copied());
                        lhs_scope.mw_calls.extend(parent.mw_calls.iter().cloned());
                    }
                    if !c_pref.is_empty() {
                        lhs_scope.prefix = join_route_prefix(&lhs_scope.prefix, &c_pref);
                    }
                    lhs_scope.guards.extend(c_guards);
                    lhs_scope.mw_calls.extend(c_mw);
                    if matches!(rm, "Group" | "PathPrefix" | "Subrouter" | "With")
                        && let Some(rargs) = rhs_node.child_by_field_name("arguments")
                    {
                        let mut ac = rargs.walk();
                        let mut dummy = Vec::new();
                        for a in rargs.children(&mut ac) {
                            let atxt = node_text(a, src).trim();
                            if atxt.starts_with('"') || atxt.starts_with('`') {
                                let unq = atxt.trim_matches(|q| q == '"' || q == '`');
                                if unq.starts_with('/') {
                                    lhs_scope.prefix = join_route_prefix(&lhs_scope.prefix, unq);
                                }
                            } else {
                                collect_go_mw_arg_recursive(
                                    a,
                                    src,
                                    cfg,
                                    true,
                                    &mut lhs_scope.guards,
                                    &mut lhs_scope.mw_calls,
                                    &mut dummy,
                                );
                            }
                        }
                        info.router_vars.insert(lhs.to_string(), lhs_scope);
                    } else if let Some(rargs) = rhs_node.child_by_field_name("arguments") {
                        // Outer wrapper call: `handler := RequireSession(mux)`
                        let mut wrap_guards = HashSet::new();
                        let mut wrap_mw = Vec::new();
                        let mut dummy = Vec::new();
                        collect_go_mw_arg_recursive(
                            rhs_node,
                            src,
                            cfg,
                            true,
                            &mut wrap_guards,
                            &mut wrap_mw,
                            &mut dummy,
                        );
                        let _ = rargs;
                        for cand in &dummy {
                            if matches!(cand.as_str(), "mux" | "router" | "r" | "app" | "api")
                                || info.router_vars.contains_key(cand)
                            {
                                let entry = info.wrapped_routers.entry(cand.clone()).or_default();
                                entry.0.extend(wrap_guards.iter().copied());
                                for call in &wrap_mw {
                                    if call != cand && !entry.1.contains(call) {
                                        entry.1.push(call.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if k == "return_statement" {
            let mut rc = node.walk();
            for ch in node.children(&mut rc) {
                let target_call = if ch.kind() == "expression_list" {
                    ch.named_child(0)
                } else {
                    Some(ch)
                };
                if let Some(call_n) = target_call
                    && call_n.kind() == "call_expression"
                {
                    let mut wrap_guards = HashSet::new();
                    let mut wrap_mw = Vec::new();
                    let mut dummy = Vec::new();
                    collect_go_mw_arg_recursive(
                        call_n,
                        src,
                        cfg,
                        true,
                        &mut wrap_guards,
                        &mut wrap_mw,
                        &mut dummy,
                    );
                    for cand in &dummy {
                        if matches!(cand.as_str(), "mux" | "router" | "r" | "app" | "api")
                            || info.router_vars.contains_key(cand)
                        {
                            let entry = info.wrapped_routers.entry(cand.clone()).or_default();
                            entry.0.extend(wrap_guards.iter().copied());
                            for call in &wrap_mw {
                                if call != cand && !entry.1.contains(call) {
                                    entry.1.push(call.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        let prev_len = stack.len();
        let mut cursor = node.walk();
        for ch in node.children(&mut cursor) {
            stack.push(ch);
        }
        stack[prev_len..].reverse();
    }
    info.spans.sort_by_key(|s| s.start_byte);
    info
}

fn is_plain_ident_ast(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[allow(clippy::too_many_arguments)]
fn extract_node<'a>(
    root: Node<'a>,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    cfg: &ShellMindGuardConfig,
    file_middleware_guards: &mut HashSet<GuardKind>,
    imports: &mut Vec<ImportRef>,
    symbols: &mut Vec<SymbolInfo>,
    route_prefixes: &mut Vec<String>,
) {
    let go_scopes = if lang == Language::Go {
        Some(collect_go_router_scopes(root, src, cfg))
    } else {
        None
    };
    if let Some(ref gs) = go_scopes {
        for sp in &gs.spans {
            if !sp.prefix.is_empty()
                && sp.prefix != "/"
                && !route_prefixes.iter().any(|p| p == &sp.prefix)
            {
                route_prefixes.push(sp.prefix.clone());
            }
        }
        for rv in gs.router_vars.values() {
            if !rv.prefix.is_empty()
                && rv.prefix != "/"
                && !route_prefixes.iter().any(|p| p == &rv.prefix)
            {
                route_prefixes.push(rv.prefix.clone());
            }
        }
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !extract_single_node(
            node,
            src,
            rel_path,
            lang,
            cfg,
            file_middleware_guards,
            imports,
            symbols,
            route_prefixes,
            go_scopes.as_ref(),
            &mut stack,
        ) {
            continue;
        }
        let prev_len = stack.len();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
        stack[prev_len..].reverse();
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_single_node<'a>(
    node: Node<'a>,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    cfg: &ShellMindGuardConfig,
    file_middleware_guards: &mut HashSet<GuardKind>,
    imports: &mut Vec<ImportRef>,
    symbols: &mut Vec<SymbolInfo>,
    route_prefixes: &mut Vec<String>,
    go_scopes: Option<&GoRouterScopes>,
    stack: &mut Vec<Node<'a>>,
) -> bool {
    let kind = node.kind();
    if lang == Language::Rust
        && matches!(kind, "mod_item" | "function_item")
        && is_rust_test_item(node, src)
    {
        return false;
    }

    // 1a. Cross-file imports & re-exports (TS/JS: named, aliased `a as b`, default, namespace `* as`, barrel `export * from`)
    if kind == "import_statement" || kind == "export_statement" {
        let txt = node_text(node, src);
        if let Some(spec_node) = node.child_by_field_name("source") {
            let spec = node_text(spec_node, src).trim_matches(|c| c == '\'' || c == '"');
            if let Some(lbrace) = txt.find('{')
                && let Some(rel_rbrace) = txt[lbrace + 1..].find('}')
            {
                let rbrace = lbrace + 1 + rel_rbrace;
                for item in txt[lbrace + 1..rbrace].split(',') {
                    let clean_item = item.trim().trim_start_matches("type ").trim();
                    if clean_item.is_empty() {
                        continue;
                    }
                    if let Some((orig, alias)) = clean_item.split_once(" as ") {
                        let orig = orig.trim();
                        let alias = alias.trim();
                        if !alias.is_empty() && !orig.is_empty() {
                            imports.push(ImportRef {
                                symbol_name: alias.to_string(),
                                from_specifier: spec.to_string(),
                                remote_name: Some(orig.to_string()),
                            });
                        }
                    } else {
                        imports.push(ImportRef {
                            symbol_name: clean_item.to_string(),
                            from_specifier: spec.to_string(),
                            remote_name: None,
                        });
                    }
                }
            } else if kind == "export_statement" && txt.contains('*') {
                imports.push(ImportRef {
                    symbol_name: "*".to_string(),
                    from_specifier: spec.to_string(),
                    remote_name: None,
                });
            }
            // Also extract default import (`import foo from './y'`) or namespace (`import * as ns from './y'`)
            if let Some(clause) = txt
                .strip_prefix("import ")
                .and_then(|s| s.split(" from ").next())
            {
                let before_brace = clause
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(',');
                if let Some((_, ns)) = before_brace.split_once("* as ") {
                    let sym = ns.trim();
                    if !sym.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: sym.to_string(),
                            from_specifier: spec.to_string(),
                            remote_name: Some("*".to_string()),
                        });
                    }
                } else if !before_brace.is_empty() && !before_brace.contains('*') {
                    imports.push(ImportRef {
                        symbol_name: before_brace.to_string(),
                        from_specifier: spec.to_string(),
                        remote_name: None,
                    });
                }
            }
        }
    }

    // 1a-cjs. CommonJS `const { a, b: alias } = require('./y')` or `const mod = require('./y')`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "variable_declarator"
        && let (Some(name_node), Some(val_node)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        && val_node.kind() == "call_expression"
        && let Some(fn_node) = val_node.child_by_field_name("function")
        && node_text(fn_node, src).trim() == "require"
        && let Some(args) = val_node.child_by_field_name("arguments")
    {
        let args_txt = node_text(args, src);
        let spec = args_txt.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '\'' || c == '"' || c.is_whitespace()
        });
        if !spec.is_empty() {
            let ntxt = node_text(name_node, src).trim();
            if let Some(lbrace) = ntxt.find('{')
                && let Some(rel_rbrace) = ntxt[lbrace + 1..].find('}')
            {
                let rbrace = lbrace + 1 + rel_rbrace;
                for item in ntxt[lbrace + 1..rbrace].split(',') {
                    if let Some((orig, alias)) = item.split_once(':') {
                        let orig = orig.trim();
                        let alias = alias.trim();
                        if !alias.is_empty() {
                            imports.push(ImportRef {
                                symbol_name: alias.to_string(),
                                from_specifier: spec.to_string(),
                                remote_name: Some(orig.to_string()),
                            });
                        }
                    } else {
                        let sym = item.trim();
                        if !sym.is_empty() {
                            imports.push(ImportRef {
                                symbol_name: sym.to_string(),
                                from_specifier: spec.to_string(),
                                remote_name: None,
                            });
                        }
                    }
                }
            } else if !ntxt.is_empty() {
                imports.push(ImportRef {
                    symbol_name: ntxt.to_string(),
                    from_specifier: spec.to_string(),
                    remote_name: None,
                });
            }
        }
    }

    // 1b. Rust `use crate::foo::bar;` or `use super::foo::bar;`
    if lang == Language::Rust && kind == "use_declaration" {
        let txt = node_text(node, src)
            .trim_start_matches("pub ")
            .trim_start_matches("use ")
            .trim_end_matches(';')
            .trim();
        if let Some((mod_path, tail)) = txt.rsplit_once("::") {
            let spec = format!("rust::{}", mod_path.replace("::", "/"));
            if tail.starts_with('{') && tail.ends_with('}') {
                for item in tail[1..tail.len() - 1].split(',') {
                    let sym = item.trim();
                    if !sym.is_empty() {
                        if let Some((orig, alias)) = sym.split_once(" as ") {
                            imports.push(ImportRef {
                                symbol_name: alias.trim().to_string(),
                                from_specifier: spec.clone(),
                                remote_name: Some(orig.trim().to_string()),
                            });
                        } else {
                            imports.push(ImportRef {
                                symbol_name: sym.to_string(),
                                from_specifier: spec.clone(),
                                remote_name: None,
                            });
                        }
                    }
                }
            } else if let Some((orig, alias)) = tail.split_once(" as ") {
                imports.push(ImportRef {
                    symbol_name: alias.trim().to_string(),
                    from_specifier: spec,
                    remote_name: Some(orig.trim().to_string()),
                });
            } else {
                imports.push(ImportRef {
                    symbol_name: tail.trim().to_string(),
                    from_specifier: spec,
                    remote_name: None,
                });
            }
        }
    }

    // 1c. Python `from .services import foo, bar as baz`
    if lang == Language::Python && kind == "import_from_statement" {
        let txt = node_text(node, src);
        if let Some(rest) = txt.strip_prefix("from ")
            && let Some((mod_part, imp_part)) = rest.split_once(" import ")
        {
            let spec = format!("py::{}", mod_part.trim());
            for item in imp_part.split(',') {
                let clean = item.trim().trim_matches(|c| c == '(' || c == ')').trim();
                if clean.is_empty() {
                    continue;
                }
                if let Some((orig, alias)) = clean.split_once(" as ") {
                    imports.push(ImportRef {
                        symbol_name: alias.trim().to_string(),
                        from_specifier: spec.clone(),
                        remote_name: Some(orig.trim().to_string()),
                    });
                } else {
                    imports.push(ImportRef {
                        symbol_name: clean.to_string(),
                        from_specifier: spec.clone(),
                        remote_name: None,
                    });
                }
            }
        }
    }

    // 1c-py. Python `import pkg.sub`, `import services.db as db`
    if lang == Language::Python && kind == "import_statement" {
        let txt = node_text(node, src);
        if let Some(rest) = txt.strip_prefix("import ") {
            for item in rest.split(',') {
                let clean = item.trim();
                if clean.is_empty() {
                    continue;
                }
                if let Some((mod_path, alias)) = clean.split_once(" as ") {
                    let mod_path = mod_path.trim();
                    let alias = alias.trim();
                    if !mod_path.is_empty() && !alias.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: alias.to_string(),
                            from_specifier: format!("py::{mod_path}"),
                            remote_name: Some("*".to_string()),
                        });
                    }
                } else {
                    let leaf = clean.rsplit('.').next().unwrap_or(clean).trim();
                    if !leaf.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: leaf.to_string(),
                            from_specifier: format!("py::{clean}"),
                            remote_name: Some("*".to_string()),
                        });
                    }
                    if clean.contains('.') {
                        imports.push(ImportRef {
                            symbol_name: clean.to_string(),
                            from_specifier: format!("py::{clean}"),
                            remote_name: Some("*".to_string()),
                        });
                    }
                }
            }
        }
    }

    // 1d. Go `import_spec`: `import "acme/internal/auth"`, `import a "acme/auth"`, `import . "acme/dot"`, skipping `_`
    if lang == Language::Go
        && kind == "import_spec"
        && let Some(path_n) = node.child_by_field_name("path")
    {
        let raw_path = node_text(path_n, src)
            .trim()
            .trim_matches(|c| c == '"' || c == '`');
        if !raw_path.is_empty() {
            let alias_opt = node
                .child_by_field_name("name")
                .map(|n| node_text(n, src).trim().to_string());
            match alias_opt.as_deref() {
                Some("_") => {}
                Some(".") => {
                    imports.push(ImportRef {
                        symbol_name: "*".to_string(),
                        from_specifier: format!("go::{raw_path}"),
                        remote_name: Some("*".to_string()),
                    });
                }
                Some(alias) if !alias.is_empty() => {
                    imports.push(ImportRef {
                        symbol_name: alias.to_string(),
                        from_specifier: format!("go::{raw_path}"),
                        remote_name: Some("*".to_string()),
                    });
                }
                _ => {
                    let pkg_name = raw_path.rsplit('/').next().unwrap_or(raw_path).trim();
                    if !pkg_name.is_empty() {
                        imports.push(ImportRef {
                            symbol_name: pkg_name.to_string(),
                            from_specifier: format!("go::{raw_path}"),
                            remote_name: Some("*".to_string()),
                        });
                    }
                }
            }
        }
    }

    // 2a-use. File-level `app.use(requireAuth)` / `router.use(requireAuth)` & prefix capture (B03)
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if ftxt.ends_with(".use")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut use_prefix: Option<String> = None;
            let mut has_auth_mw = false;
            let mut has_csrf_mw = false;
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('\'') || atxt.starts_with('"') {
                    let unq = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    if unq.starts_with('/') {
                        use_prefix = Some(unq.to_string());
                        if unq.len() > 1 && !route_prefixes.iter().any(|p| p == unq) {
                            route_prefixes.push(unq.to_string());
                        }
                    }
                }
                let short_mw = atxt.split('(').next().unwrap_or(atxt).trim();
                if is_auth_guard_ident(atxt, cfg) || is_auth_guard_ident(short_mw, cfg) {
                    has_auth_mw = true;
                }
                if crate::taint::has_csrf_guard_expr(atxt) {
                    has_csrf_mw = true;
                }
            }
            if has_csrf_mw {
                file_middleware_guards.insert(GuardKind::CsrfProtection);
            }
            if has_auth_mw {
                match use_prefix.as_deref() {
                    None | Some("/") => {
                        file_middleware_guards.insert(GuardKind::Auth);
                    }
                    Some(p) if p == "/api" || p.starts_with("/api/v") => {
                        route_prefixes.push(format!("__AUTH_PREFIX__:{}", p));
                        route_prefixes.push(format!("__AUTH_PREFIX__:MOUNT:{}", p));
                    }
                    Some(sub) => {
                        route_prefixes.push(format!("__AUTH_PREFIX__:{}", sub));
                    }
                }
            }
        }
    }

    // 2a-nest-ctrl. NestJS `@Controller("prefix")` decorator capture
    if (lang == Language::TypeScript || lang == Language::JavaScript) && kind == "decorator" {
        let dtxt = node_text(node, src).trim();
        if dtxt.contains("@Controller(")
            && let Some(raw) = dtxt.split('(').nth(1).and_then(|s| s.split(')').next())
        {
            let cleaned = raw.trim().trim_matches(|ch| ch == '\'' || ch == '"');
            if !cleaned.is_empty() && cleaned != "/" {
                let pref = if cleaned.starts_with('/') {
                    cleaned.to_string()
                } else {
                    format!("/{}", cleaned)
                };
                if !route_prefixes.iter().any(|p| p == &pref) {
                    route_prefixes.push(pref);
                }
            }
        }
    }

    // 2a. Universal TS/JS HTTP Route entries (Express, Fastify, Hono, Koa, custom routers):
    // `<router>.(get|post|put|patch|delete)('/...', ...middlewares, handler)`
    // Also supports chained `router.route('/...').post(handler)` and wrapped `asyncHandler(async (req, res) => ...)`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        let method = ftxt.rsplit('.').next().unwrap_or("");
        let is_custom = cfg
            .guards
            .custom_routes
            .iter()
            .any(|cr| ftxt == cr || ftxt.ends_with(&format!(".{}", cr)));
        let is_http_method =
            ftxt.contains('.') && matches!(method, "get" | "post" | "put" | "patch" | "delete");
        if (is_http_method || is_custom)
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path: Option<String> = None;
            // Support Express chained `router.route('/api/pay').post(handler)`
            if let Some(rpos) = ftxt.find(".route(") {
                let rest = &ftxt[rpos + 7..];
                if let Some(q1) = rest.find(['\'', '"']) {
                    let qch = rest.as_bytes()[q1] as char;
                    if let Some(q2) = rest[q1 + 1..].find(qch) {
                        let cand = &rest[q1 + 1..q1 + 1 + q2];
                        if cand.starts_with('/') {
                            route_path = Some(cand.to_string());
                        }
                    }
                }
            }
            let mut calls = Vec::new();
            let mut mw_callees = Vec::new();
            let mut guards = file_middleware_guards.clone();
            let mut seen_handler = false;
            let mut route_taints = Vec::new();
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;

            let mut c = args.walk();
            let arg_list: Vec<Node> = args
                .children(&mut c)
                .filter(|a| !matches!(a.kind(), "(" | ")" | "," | "comment"))
                .collect();
            let arg_count = arg_list.len();
            for (arg_idx, arg) in arg_list.into_iter().enumerate() {
                let ak = arg.kind();
                let atxt = node_text(arg, src).trim();
                let has_more_args = arg_idx + 1 < arg_count;
                if (atxt.starts_with('\'') || atxt.starts_with('"')) && route_path.is_none() {
                    let unq = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    if unq.starts_with('/') || is_custom {
                        route_path = Some(unq.to_string());
                    }
                } else if route_path.is_some() {
                    if ak == "identifier" {
                        if !seen_handler && is_auth_guard_ident(atxt, cfg) {
                            guards.insert(GuardKind::Auth);
                            mw_callees.push(atxt.to_string());
                        } else if !seen_handler && is_lock_guard_ident(atxt, cfg) {
                            guards.insert(GuardKind::TxLock);
                        } else {
                            if !seen_handler && has_more_args {
                                mw_callees.push(atxt.to_string());
                            }
                            seen_handler = true;
                        }
                        calls.push(atxt.to_string());
                    } else if let Some(fn_arg) = find_inline_fn_node(arg) {
                        seen_handler = true;
                        let inline_body = node_text(fn_arg, src);
                        let inline_guards = classify_fn_guards_cfg(fn_arg, src, cfg);
                        guards.extend(inline_guards);
                        collect_calls(fn_arg, src, &mut calls);

                        let handler_label = route_path
                            .as_deref()
                            .map(|rp| format!("{} {}", method.to_ascii_uppercase(), rp))
                            .unwrap_or_else(|| format!("inline_{}", line_start));
                        let t_inline = crate::taint::analyze_function_taint(
                            fn_arg,
                            src,
                            rel_path,
                            lang,
                            &handler_label,
                            route_path.as_deref(),
                        );

                        if let Some(sk) =
                            classify_sink(route_path.as_deref().unwrap_or("inline"), inline_body)
                        {
                            let inline_id = format!("{}::inline_sink:{}", rel_path, line_start);
                            let inline_name = format!("inline_sink_{}", line_start);
                            let mut inline_calls = Vec::new();
                            collect_calls(fn_arg, src, &mut inline_calls);
                            let mut sink_sym = SymbolInfo::base(
                                inline_id,
                                rel_path,
                                inline_name.clone(),
                                SymbolKind::Sink,
                                Some(sk),
                                fn_arg.start_position().row + 1,
                                fn_arg.end_position().row + 1,
                                classify_fn_guards_cfg(fn_arg, src, cfg),
                                inline_calls,
                                None,
                            );
                            sink_sym.has_db_crud_sink = t_inline.has_db_crud_sink;
                            sink_sym.db_crud_line = t_inline.db_crud_line;
                            sink_sym.has_resource_id = t_inline.has_resource_id;
                            sink_sym.has_taint_source = t_inline.has_taint_source;
                            sink_sym.guards.extend(t_inline.guards.iter().copied());
                            for (callee, mask) in &t_inline.tainted_call_masks {
                                *sink_sym
                                    .tainted_call_masks
                                    .entry(callee.clone())
                                    .or_insert(0) |= *mask;
                            }
                            symbols.push(sink_sym);
                            calls.push(inline_name);
                        }
                        route_taints.push(t_inline);
                    } else {
                        let short_call = atxt.split('(').next().unwrap_or(atxt).trim();
                        if !seen_handler
                            && (is_auth_guard_ident(atxt, cfg)
                                || is_auth_guard_ident(short_call, cfg))
                        {
                            guards.insert(GuardKind::Auth);
                        } else if !seen_handler
                            && (is_lock_guard_ident(atxt, cfg)
                                || is_lock_guard_ident(short_call, cfg))
                        {
                            guards.insert(GuardKind::TxLock);
                        }
                        if !seen_handler && has_more_args {
                            let s = short_call.rsplit('.').next().unwrap_or(short_call).trim();
                            if !s.is_empty() {
                                mw_callees.push(s.to_string());
                            }
                        }
                        collect_calls(arg, src, &mut calls);
                    }
                }
            }
            if let Some(rp) = route_path {
                let rp_low = rp.to_ascii_lowercase();
                let is_explicit_unauth_sub = matches!(
                    rp_low.as_str(),
                    "/public"
                        | "/health"
                        | "/healthz"
                        | "/readyz"
                        | "/metrics"
                        | "/login"
                        | "/register"
                        | "/signup"
                ) || rp_low.starts_with("/public/")
                    || rp_low.starts_with("/health/")
                    || rp_low.starts_with("/webhook");
                for marker in route_prefixes.iter() {
                    if let Some(_mount) = marker.strip_prefix("__AUTH_PREFIX__:MOUNT:") {
                        if !is_explicit_unauth_sub {
                            guards.insert(GuardKind::Auth);
                        }
                    } else if let Some(sub) = marker.strip_prefix("__AUTH_PREFIX__:")
                        && (rp == sub || rp.starts_with(&format!("{}/", sub.trim_end_matches('/'))))
                    {
                        guards.insert(GuardKind::Auth);
                    }
                }
                let r_label = format!("{} {}", method.to_ascii_uppercase(), rp);
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    r_label,
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                if has_res_id {
                    route_sym.has_resource_id = true;
                }
                route_sym.middleware_callees = mw_callees;
                for t in route_taints {
                    route_sym.apply_taint(t);
                }
                symbols.push(route_sym);
                return false;
            }
        }
    }

    // 2a-trpc. tRPC `publicProcedure...mutation(...)` / `protectedProcedure...mutation(...)`
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if (ftxt.ends_with(".mutation") || ftxt.ends_with(".query"))
            && (ftxt.contains("publicProcedure") || ftxt.contains("protectedProcedure"))
        {
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            let mut guards = file_middleware_guards.clone();
            if ftxt.contains("protectedProcedure") {
                guards.insert(GuardKind::Auth);
            }
            let mut calls = Vec::new();
            let mut inline_body = "";
            let r_label = format!("TRPC {}:{}", rel_path, line_start);
            let trpc_path = format!("/trpc/{}", line_start);
            let mut trpc_taint = None;
            if let Some(args) = node.child_by_field_name("arguments") {
                inline_body = node_text(args, src);
                collect_calls(args, src, &mut calls);
                trpc_taint = Some(crate::taint::analyze_function_taint(
                    args,
                    src,
                    rel_path,
                    lang,
                    &r_label,
                    Some(&trpc_path),
                ));
            }
            if let Some(sk) = classify_sink(&r_label, inline_body) {
                let inline_name = format!("trpc_sink_{}", line_start);
                let mut sink_sym = SymbolInfo::base(
                    format!("{}::{}", rel_path, inline_name),
                    rel_path,
                    inline_name.clone(),
                    SymbolKind::Sink,
                    Some(sk),
                    line_start,
                    line_end,
                    guards.clone(),
                    calls.clone(),
                    None,
                );
                if let Some(ref t) = trpc_taint {
                    sink_sym.has_db_crud_sink = t.has_db_crud_sink;
                    sink_sym.db_crud_line = t.db_crud_line;
                    sink_sym.has_resource_id = t.has_resource_id;
                    sink_sym.has_taint_source = t.has_taint_source;
                    sink_sym.guards.extend(t.guards.iter().copied());
                    for (callee, mask) in &t.tainted_call_masks {
                        *sink_sym
                            .tainted_call_masks
                            .entry(callee.clone())
                            .or_insert(0) |= *mask;
                    }
                }
                symbols.push(sink_sym);
                calls.push(inline_name);
            }
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                r_label,
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                guards,
                calls,
                Some(trpc_path),
            );
            if let Some(t) = trpc_taint {
                route_sym.apply_taint(t);
            }
            symbols.push(route_sym);
            return false;
        }
    }

    // 2a-nest. NestJS `@Controller` / `@Get` / `@Post` / `@UseGuards` inside `class_declaration`
    if (lang == Language::TypeScript || lang == Language::JavaScript) && kind == "class_declaration"
    {
        let class_txt = node_text(node, src);
        let class_has_auth = class_txt.contains("@UseGuards") && class_txt.contains("Auth");
        if let Some(body) = node.child_by_field_name("body") {
            let mut pending_method: Option<String> = None;
            let mut pending_path: Option<String> = None;
            let mut pending_guards = HashSet::new();
            if class_has_auth {
                pending_guards.insert(GuardKind::Auth);
            }
            let mut c = body.walk();
            for ch in body.children(&mut c) {
                if ch.kind() == "decorator" {
                    let dtxt = node_text(ch, src);
                    for m in ["Get", "Post", "Put", "Patch", "Delete"] {
                        if dtxt.contains(&format!("@{}(", m)) {
                            pending_method = Some(m.to_ascii_uppercase());
                            let rp = dtxt
                                .split('(')
                                .nth(1)
                                .and_then(|s| s.split(')').next())
                                .map(|s| s.trim().trim_matches(|q| q == '\'' || q == '"'))
                                .unwrap_or("/");
                            pending_path = Some(if rp.is_empty() {
                                "/".into()
                            } else {
                                rp.to_string()
                            });
                        }
                    }
                    pending_guards.extend(classify_guards(dtxt, cfg));
                } else if ch.kind() == "method_definition"
                    && let Some(m) = pending_method.take()
                {
                    let rp = pending_path.take().unwrap_or_else(|| "/".into());
                    if let Some(name_node) = ch.child_by_field_name("name") {
                        let mname = node_text(name_node, src).trim().to_string();
                        let line_start = ch.start_position().row + 1;
                        let line_end = ch.end_position().row + 1;
                        let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                        let mut route_sym = SymbolInfo::base(
                            format!("{}::route:{}", rel_path, line_start),
                            rel_path,
                            format!("{} {}", m, rp),
                            SymbolKind::Route,
                            None,
                            line_start,
                            line_end,
                            std::mem::take(&mut pending_guards),
                            vec![mname],
                            Some(rp),
                        );
                        route_sym.has_resource_id = has_res_id;
                        symbols.push(route_sym);
                    }
                    if class_has_auth {
                        pending_guards.insert(GuardKind::Auth);
                    }
                }
            }
        }
    }

    // 2c. Python Flask / FastAPI `@app.post("/api/...")` or `@app.route("/api/...", methods=[...])` decorated_definition (B06)
    if lang == Language::Python && kind == "decorated_definition" {
        let mut route_method = None;
        let mut route_path = None;
        let mut dec_guards = HashSet::new();
        let mut dec_csrf_exempt = false;
        let mut fn_node = None;

        let mut cursor = node.walk();
        for ch in node.children(&mut cursor) {
            if ch.kind() == "decorator" {
                let dtxt = node_text(ch, src);
                if crate::taint::has_csrf_exempt_expr(dtxt) {
                    dec_csrf_exempt = true;
                }
                for m in ["get", "post", "put", "patch", "delete"] {
                    let needle = format!(".{}(", m);
                    if let Some(pos) = dtxt.find(&needle) {
                        route_method = Some(m.to_ascii_uppercase());
                        let rest = &dtxt[pos + needle.len()..];
                        if let Some(q1) = rest.find(['\'', '"']) {
                            let qch = rest.as_bytes()[q1] as char;
                            if let Some(q2) = rest[q1 + 1..].find(qch) {
                                route_path = Some(rest[q1 + 1..q1 + 1 + q2].to_string());
                            }
                        }
                    }
                }
                if route_method.is_none()
                    && let Some(pos) = dtxt.find(".route(")
                {
                    let rest = &dtxt[pos + 7..];
                    if let Some(q1) = rest.find(['\'', '"']) {
                        let qch = rest.as_bytes()[q1] as char;
                        if let Some(q2) = rest[q1 + 1..].find(qch) {
                            route_path = Some(rest[q1 + 1..q1 + 1 + q2].to_string());
                        }
                    }
                    let upper = dtxt.to_ascii_uppercase();
                    if upper.contains("POST") {
                        route_method = Some("POST".to_string());
                    } else if upper.contains("PUT") {
                        route_method = Some("PUT".to_string());
                    } else if upper.contains("PATCH") {
                        route_method = Some("PATCH".to_string());
                    } else if upper.contains("DELETE") {
                        route_method = Some("DELETE".to_string());
                    } else {
                        route_method = Some("GET".to_string());
                    }
                }
                dec_guards.extend(classify_guards(dtxt, cfg));
            } else if ch.kind() == "function_definition" {
                fn_node = Some(ch);
            }
        }

        if let (Some(method), Some(rp), Some(fnode)) = (route_method, route_path, fn_node)
            && let Some(name_node) = fnode.child_by_field_name("name")
        {
            let fn_name = node_text(name_node, src).trim().to_string();
            let sig_guards = crate::cfg::extract_param_signature_guards(fnode, src, cfg).to_set();
            dec_guards.extend(sig_guards);
            let line_start = node.start_position().row + 1;
            let line_end = fnode.end_position().row + 1;
            let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                format!("{} {}", method, rp),
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                dec_guards,
                vec![fn_name],
                Some(rp),
            );
            route_sym.has_resource_id = has_res_id;
            route_sym.csrf_exempt = dec_csrf_exempt;
            symbols.push(route_sym);
            // Continue into `fnode` to emit the Function / Sink symbol itself
            stack.push(fnode);
            return false;
        } else if let Some(fnode) = fn_node
            && (dec_csrf_exempt || !dec_guards.is_empty())
            && let Some(name_node) = fnode.child_by_field_name("name")
        {
            // Decorated helper/Django view (e.g. `@csrf_exempt`, `@login_required`) without FastAPI/Flask route decorator
            let name = node_text(name_node, src).trim().to_string();
            let body = node_text(fnode, src);
            let mut calls = Vec::new();
            collect_calls(fnode, src, &mut calls);
            let mut guards = classify_fn_guards_cfg(fnode, src, cfg);
            guards.extend(dec_guards);
            let sink_kind = classify_sink(&name, body);
            let sym_kind = if sink_kind.is_some() {
                SymbolKind::Sink
            } else {
                SymbolKind::Function
            };
            let line_start = fnode.start_position().row + 1;
            let mut sym = SymbolInfo::base(
                format!("{}::{}:{}", rel_path, name, line_start),
                rel_path,
                name.clone(),
                sym_kind,
                sink_kind,
                line_start,
                fnode.end_position().row + 1,
                guards,
                calls,
                None,
            );
            sym.csrf_exempt = dec_csrf_exempt;
            sym.apply_taint(crate::taint::analyze_function_taint(
                fnode, src, rel_path, lang, &name, None,
            ));
            symbols.push(sym);
            return false;
        }
    }

    // 2b. Rust Axum / Actix `.route("/api/...", post(handler))`
    if lang == Language::Rust
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        if ftxt.ends_with(".route")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path = None;
            let mut method = "POST".to_string();
            let mut calls = Vec::new();
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('"') && route_path.is_none() {
                    route_path = Some(atxt.trim_matches('"').to_string());
                } else if arg.kind() == "call_expression" {
                    if let Some(mfn) = arg.child_by_field_name("function") {
                        let mname = node_text(mfn, src).rsplit("::").next().unwrap_or("post");
                        if matches!(mname, "get" | "post" | "put" | "patch" | "delete") {
                            method = mname.to_ascii_uppercase();
                        }
                    }
                    if let Some(margs) = arg.child_by_field_name("arguments") {
                        let mut mc = margs.walk();
                        for marg in margs.children(&mut mc) {
                            if marg.kind() == "identifier" || marg.kind() == "scoped_identifier" {
                                let hname = node_text(marg, src).rsplit("::").next().unwrap_or("");
                                if !hname.is_empty() {
                                    calls.push(hname.to_string());
                                }
                            }
                        }
                    }
                    collect_calls(arg, src, &mut calls);
                }
            }
            if let Some(rp) = route_path {
                let guards = classify_guards(&calls.join(" "), cfg);
                let line_start = args.start_position().row + 1;
                let line_end = args.end_position().row + 1;
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("{} {}", method, rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                symbols.push(route_sym);
            }
        }
    }

    // 2c-django. Python Django `path("api/...", views.my_view)` or `path("api/...", MyView.as_view())`
    if lang == Language::Python
        && kind == "call"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src).trim();
        if (ftxt == "path" || ftxt == "re_path")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut route_path = None;
            let mut calls = Vec::new();
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if (atxt.starts_with('\'') || atxt.starts_with('"')) && route_path.is_none() {
                    let rp = atxt.trim_matches(|ch| ch == '\'' || ch == '"');
                    route_path = Some(if rp.starts_with('/') {
                        rp.to_string()
                    } else {
                        format!("/{}", rp)
                    });
                } else if !matches!(arg.kind(), "(" | ")" | "," | "keyword_argument") {
                    let cleaned = atxt
                        .strip_suffix(".as_view()")
                        .or_else(|| atxt.split(".as_view(").next())
                        .unwrap_or(atxt);
                    let short = cleaned.rsplit('.').next().unwrap_or(cleaned).trim();
                    if !short.is_empty() {
                        calls.push(short.to_string());
                    }
                }
            }
            if let Some(rp) = route_path
                && !calls.is_empty()
            {
                let line_start = node.start_position().row + 1;
                let line_end = node.end_position().row + 1;
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("DJANGO {}", rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    HashSet::new(),
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                symbols.push(route_sym);
                return false;
            }
        }
    }

    // 2d. Go Gin/Echo/Fiber/Chi + `net/http` `Handle`/`HandleFunc` + Go 1.22 `"METHOD /path"` + scoped `r.Route`/`r.Group`/`r.With`
    if lang == Language::Go
        && kind == "call_expression"
        && let Some(func) = node.child_by_field_name("function")
    {
        let ftxt = node_text(func, src);
        let method = ftxt.rsplit('.').next().unwrap_or("");
        let method_upper = method.to_ascii_uppercase();
        let node_byte = node.start_byte();
        let in_scoped_span = go_scopes.is_some_and(|gs| {
            gs.spans
                .iter()
                .any(|sp| node_byte >= sp.start_byte && node_byte <= sp.end_byte)
        });
        let (chained_recv, chained_guards, chained_mw, chained_pref) =
            extract_go_chained_receiver(func, src, cfg);
        let recv_is_distinct_sub = chained_recv
            .as_deref()
            .and_then(|rname| go_scopes.and_then(|gs| gs.router_vars.get(rname)))
            .is_some();

        let mut group_prefix: Option<String> = None;
        if (method == "Group" || method == "Use" || method == "Route")
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut c = args.walk();
            for arg in args.children(&mut c) {
                let atxt = node_text(arg, src).trim();
                if atxt.starts_with('"') || atxt.starts_with('`') {
                    let unq = atxt.trim_matches(|ch| ch == '"' || ch == '`');
                    if unq.starts_with('/') {
                        group_prefix = Some(unq.to_string());
                        if unq.len() > 1 && !route_prefixes.iter().any(|p| p == unq) {
                            route_prefixes.push(unq.to_string());
                        }
                    }
                }
            }
        }
        // Only root-level `.Use(...)` outside scoped `r.Route` / subrouter var updates `file_middleware_guards`
        if method == "Use" && !in_scoped_span && !recv_is_distinct_sub {
            let gtxt = node_text(node, src);
            let mw_guards = classify_guards(gtxt, cfg);
            if !mw_guards.is_empty() {
                match group_prefix.as_deref() {
                    None | Some("/") | Some("/api") => {
                        file_middleware_guards.extend(mw_guards);
                    }
                    Some(p) if p.starts_with("/api/v") => {
                        file_middleware_guards.extend(mw_guards);
                    }
                    Some(sub) => {
                        if mw_guards.contains(&GuardKind::Auth) {
                            route_prefixes.push(format!("__AUTH_PREFIX__:{}", sub));
                        }
                    }
                }
            }
        } else if method == "Group"
            && !in_scoped_span
            && !recv_is_distinct_sub
            && !node_text(node, src).contains("func(")
        {
            let gtxt = node_text(node, src);
            let mw_guards = classify_guards(gtxt, cfg);
            if !mw_guards.is_empty() {
                match group_prefix.as_deref() {
                    None | Some("/") | Some("/api") => {
                        file_middleware_guards.extend(mw_guards);
                    }
                    Some(p) if p.starts_with("/api/v") => {
                        file_middleware_guards.extend(mw_guards);
                    }
                    Some(sub) => {
                        if mw_guards.contains(&GuardKind::Auth) {
                            route_prefixes.push(format!("__AUTH_PREFIX__:{}", sub));
                        }
                    }
                }
            }
        }

        let is_go_http = matches!(
            method_upper.as_str(),
            "GET"
                | "POST"
                | "PUT"
                | "PATCH"
                | "DELETE"
                | "HEAD"
                | "OPTIONS"
                | "ANY"
                | "HANDLE"
                | "HANDLEFUNC"
        );
        if is_go_http
            && ftxt.contains('.')
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let mut raw_route_path = None;
            let mut calls = Vec::new();
            let mut mw_callees = Vec::new();
            let mut explicit_guards = HashSet::new();
            explicit_guards.extend(chained_guards);
            for call in chained_mw {
                if !mw_callees.iter().any(|x| x == &call) {
                    mw_callees.push(call.clone());
                }
                if !calls.iter().any(|x| x == &call) {
                    calls.push(call);
                }
            }

            let mut seen_handler = false;
            let mut route_taints = Vec::new();
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;

            let mut c = args.walk();
            let arg_nodes: Vec<Node> = args
                .children(&mut c)
                .filter(|a| !matches!(a.kind(), "(" | ")" | "," | "comment"))
                .collect();
            let arg_count = arg_nodes.len();
            for (arg_idx, arg) in arg_nodes.into_iter().enumerate() {
                let ak = arg.kind();
                let atxt = node_text(arg, src).trim();
                let has_more_args = arg_idx + 1 < arg_count;
                if (atxt.starts_with('"') || atxt.starts_with('`')) && raw_route_path.is_none() {
                    raw_route_path =
                        Some(atxt.trim_matches(|ch| ch == '"' || ch == '`').to_string());
                } else if ak == "func_literal" {
                    seen_handler = true;
                    let inline_body = node_text(arg, src);
                    explicit_guards.extend(classify_fn_guards_cfg(arg, src, cfg));
                    collect_calls(arg, src, &mut calls);
                    let handler_label = raw_route_path
                        .as_deref()
                        .map(|rp| format!("{} {}", method_upper, rp))
                        .unwrap_or_else(|| format!("go_inline_{}", line_start));
                    let t_inline = crate::taint::analyze_function_taint(
                        arg,
                        src,
                        rel_path,
                        lang,
                        &handler_label,
                        raw_route_path.as_deref(),
                    );
                    if let Some(sk) =
                        classify_sink(raw_route_path.as_deref().unwrap_or("inline"), inline_body)
                    {
                        let inline_name = format!("inline_sink_{}", line_start);
                        let mut inline_calls = Vec::new();
                        collect_calls(arg, src, &mut inline_calls);
                        let mut sink_sym = SymbolInfo::base(
                            format!("{}::inline_sink:{}", rel_path, line_start),
                            rel_path,
                            inline_name.clone(),
                            SymbolKind::Sink,
                            Some(sk),
                            arg.start_position().row + 1,
                            arg.end_position().row + 1,
                            classify_fn_guards_cfg(arg, src, cfg),
                            inline_calls,
                            None,
                        );
                        sink_sym.has_db_crud_sink = t_inline.has_db_crud_sink;
                        sink_sym.db_crud_line = t_inline.db_crud_line;
                        sink_sym.has_resource_id = t_inline.has_resource_id;
                        sink_sym.has_taint_source = t_inline.has_taint_source;
                        sink_sym.guards.extend(t_inline.guards.iter().copied());
                        for (callee, mask) in &t_inline.tainted_call_masks {
                            *sink_sym
                                .tainted_call_masks
                                .entry(callee.clone())
                                .or_insert(0) |= *mask;
                        }
                        symbols.push(sink_sym);
                        calls.push(inline_name);
                    }
                    route_taints.push(t_inline);
                } else {
                    if let Some(fn_arg) = find_inline_fn_node(arg) {
                        seen_handler = true;
                        explicit_guards.extend(classify_fn_guards_cfg(fn_arg, src, cfg));
                    }
                    collect_go_mw_arg_recursive(
                        arg,
                        src,
                        cfg,
                        !seen_handler && (has_more_args || ak == "call_expression"),
                        &mut explicit_guards,
                        &mut mw_callees,
                        &mut calls,
                    );
                    if !has_more_args {
                        seen_handler = true;
                    }
                    collect_calls(arg, src, &mut calls);
                }
            }

            if let Some(raw_rp) = raw_route_path {
                let (explicit_verb, clean_rp) = split_go_method_and_path(&raw_rp);
                let mut scope_prefix = String::new();
                let mut scope_guards = HashSet::new();
                let mut scope_mw_calls = Vec::new();

                if let Some(gs) = go_scopes {
                    for sp in &gs.spans {
                        if node_byte >= sp.start_byte && node_byte <= sp.end_byte {
                            if !sp.prefix.is_empty() {
                                scope_prefix = join_route_prefix(&scope_prefix, &sp.prefix);
                            }
                            scope_guards.extend(sp.guards.iter().copied());
                            for mc in &sp.mw_calls {
                                if !scope_mw_calls.contains(mc) {
                                    scope_mw_calls.push(mc.clone());
                                }
                            }
                        }
                    }
                    if let Some(ref recv) = chained_recv {
                        if let Some(rv) = gs.router_vars.get(recv) {
                            if !rv.prefix.is_empty() {
                                scope_prefix = join_route_prefix(&scope_prefix, &rv.prefix);
                            }
                            scope_guards.extend(rv.guards.iter().copied());
                            for mc in &rv.mw_calls {
                                if !scope_mw_calls.contains(mc) {
                                    scope_mw_calls.push(mc.clone());
                                }
                            }
                        }
                        if let Some((wg, wmw)) = gs.wrapped_routers.get(recv) {
                            scope_guards.extend(wg.iter().copied());
                            for mc in wmw {
                                if !scope_mw_calls.contains(mc) {
                                    scope_mw_calls.push(mc.clone());
                                }
                            }
                        }
                    }
                }
                if !chained_pref.is_empty() {
                    scope_prefix = join_route_prefix(&scope_prefix, &chained_pref);
                }

                let full_rp = if scope_prefix.is_empty() {
                    clean_rp.clone()
                } else {
                    join_route_prefix(&scope_prefix, &clean_rp)
                };
                if !scope_prefix.is_empty()
                    && scope_prefix != "/"
                    && !route_prefixes.iter().any(|p| p == &scope_prefix)
                {
                    route_prefixes.push(scope_prefix);
                }

                let full_low = full_rp.to_ascii_lowercase();
                let is_explicit_unauth_sub = matches!(
                    full_low.as_str(),
                    "/public"
                        | "/health"
                        | "/healthz"
                        | "/readyz"
                        | "/metrics"
                        | "/login"
                        | "/register"
                        | "/signup"
                ) || full_low.starts_with("/public/")
                    || full_low.starts_with("/health/")
                    || full_low.ends_with("/health")
                    || full_low.ends_with("/healthz")
                    || full_low.ends_with("/readyz")
                    || full_low.ends_with("/metrics")
                    || full_low.ends_with("/login")
                    || full_low.ends_with("/register")
                    || full_low.ends_with("/signup")
                    || full_low.contains("/webhook");

                let mut guards = explicit_guards;
                if !is_explicit_unauth_sub {
                    guards.extend(file_middleware_guards.iter().copied());
                    guards.extend(scope_guards);
                }
                for mc in scope_mw_calls {
                    if !mw_callees.contains(&mc) {
                        mw_callees.push(mc.clone());
                    }
                    if !calls.contains(&mc) {
                        calls.push(mc);
                    }
                }
                for marker in route_prefixes.iter() {
                    if let Some(_mount) = marker.strip_prefix("__AUTH_PREFIX__:MOUNT:") {
                        if !is_explicit_unauth_sub {
                            guards.insert(GuardKind::Auth);
                        }
                    } else if let Some(sub) = marker.strip_prefix("__AUTH_PREFIX__:")
                        && (full_rp == sub
                            || full_rp.starts_with(&format!("{}/", sub.trim_end_matches('/')))
                            || clean_rp == sub
                            || clean_rp.starts_with(&format!("{}/", sub.trim_end_matches('/'))))
                    {
                        guards.insert(GuardKind::Auth);
                    }
                }

                let label_method = explicit_verb.unwrap_or_else(|| {
                    if matches!(method_upper.as_str(), "HANDLEFUNC" | "HANDLE" | "ANY") {
                        "HTTP".to_string()
                    } else {
                        method_upper
                    }
                });
                let rp = clean_rp;
                let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                let mut route_sym = SymbolInfo::base(
                    format!("{}::route:{}", rel_path, line_start),
                    rel_path,
                    format!("{} {}", label_method, rp),
                    SymbolKind::Route,
                    None,
                    line_start,
                    line_end,
                    guards,
                    calls,
                    Some(rp),
                );
                route_sym.has_resource_id = has_res_id;
                route_sym.middleware_callees = mw_callees;
                for t in route_taints {
                    route_sym.apply_taint(t);
                }
                symbols.push(route_sym);
                return false;
            }
        }
    }

    // 2e. Next.js App Router (`app/**/route.ts|js`): exported GET/POST/PUT/PATCH/DELETE (function or const arrow)
    if (lang == Language::TypeScript || lang == Language::JavaScript)
        && (rel_path.ends_with("/route.ts")
            || rel_path.ends_with("/route.tsx")
            || rel_path.ends_with("/route.js")
            || rel_path == "route.ts")
        && (kind == "function_declaration"
            || (kind == "variable_declarator"
                && node
                    .child_by_field_name("value")
                    .is_some_and(|v| matches!(v.kind(), "arrow_function" | "function_expression"))))
        && let Some(name_node) = node.child_by_field_name("name")
    {
        let fn_name = node_text(name_node, src).trim().to_string();
        if matches!(
            fn_name.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            let after_app = rel_path
                .rsplit_once("app/")
                .map(|(_, tail)| tail)
                .unwrap_or_else(|| rel_path.trim_start_matches("src/"));
            let trimmed_route = after_app
                .trim_end_matches("/route.ts")
                .trim_end_matches("/route.tsx")
                .trim_end_matches("/route.js");
            let clean_segs: Vec<&str> = trimmed_route
                .split('/')
                .filter(|seg| !seg.is_empty() && !(seg.starts_with('(') && seg.ends_with(')')))
                .collect();
            let route_p = format!("/{}", clean_segs.join("/"));
            let line_start = node.start_position().row + 1;
            let line_end = node.end_position().row + 1;
            let has_res_id = crate::taint::has_resource_id_expr("", Some(&route_p));
            let mut route_sym = SymbolInfo::base(
                format!("{}::route:{}", rel_path, line_start),
                rel_path,
                format!("{} {}", fn_name, route_p),
                SymbolKind::Route,
                None,
                line_start,
                line_end,
                HashSet::new(),
                vec![fn_name],
                Some(route_p),
            );
            route_sym.has_resource_id = has_res_id;
            symbols.push(route_sym);
        }
    }

    // 2f. Rust Actix-web `#[post("/...")]` / `#[get("/...")]` attribute_item + function_item
    if lang == Language::Rust && kind == "attribute_item" {
        let atxt = node_text(node, src);
        for m in ["get", "post", "put", "patch", "delete"] {
            let needle = format!("#[{}(\"", m);
            if let Some(pos) = atxt.find(&needle) {
                let rest = &atxt[pos + needle.len()..];
                if let Some(q2) = rest.find('"') {
                    let rp = rest[..q2].to_string();
                    if let Some(next_fn) = node.next_named_sibling()
                        && next_fn.kind() == "function_item"
                        && let Some(name_node) = next_fn.child_by_field_name("name")
                    {
                        let fn_name = node_text(name_node, src).trim().to_string();
                        let line_start = next_fn.start_position().row + 1;
                        let line_end = next_fn.end_position().row + 1;
                        let has_res_id = crate::taint::has_resource_id_expr("", Some(&rp));
                        let mut route_sym = SymbolInfo::base(
                            format!("{}::route:{}", rel_path, line_start),
                            rel_path,
                            format!("{} {}", m.to_ascii_uppercase(), rp),
                            SymbolKind::Route,
                            None,
                            line_start,
                            line_end,
                            HashSet::new(),
                            vec![fn_name],
                            Some(rp),
                        );
                        route_sym.has_resource_id = has_res_id;
                        symbols.push(route_sym);
                    }
                }
            }
        }
    }

    // 3. Function / Method declarations (TS/JS, Rust, Python, Go)
    if matches!(
        kind,
        "function_declaration"
            | "method_definition"
            | "function_item"
            | "function_definition"
            | "method_declaration"
    ) && let Some(name_node) = node.child_by_field_name("name")
    {
        let name = node_text(name_node, src).trim().to_string();
        let body = node_text(node, src);
        let mut calls = Vec::new();
        collect_calls(node, src, &mut calls);
        let guards = classify_fn_guards_cfg(node, src, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        let line_start = node.start_position().row + 1;
        let mut sym = SymbolInfo::base(
            format!("{}::{}:{}", rel_path, name, line_start),
            rel_path,
            name.clone(),
            sym_kind,
            sink_kind,
            line_start,
            node.end_position().row + 1,
            guards,
            calls,
            None,
        );
        sym.apply_taint(crate::taint::analyze_function_taint(
            node, src, rel_path, lang, &name, None,
        ));
        symbols.push(sym);
    }

    // 4. Arrow functions assigned to const/let: const foo = async (...) => { ... }
    if kind == "variable_declarator"
        && let (Some(name_node), Some(val_node)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        && matches!(val_node.kind(), "arrow_function" | "function_expression")
    {
        let name = node_text(name_node, src).trim().to_string();
        let body = node_text(val_node, src);
        let mut calls = Vec::new();
        collect_calls(val_node, src, &mut calls);
        let guards = classify_fn_guards_cfg(val_node, src, cfg);
        let sink_kind = classify_sink(&name, body);
        let sym_kind = if sink_kind.is_some() {
            SymbolKind::Sink
        } else {
            SymbolKind::Function
        };
        let line_start = node.start_position().row + 1;
        let mut sym = SymbolInfo::base(
            format!("{}::{}:{}", rel_path, name, line_start),
            rel_path,
            name.clone(),
            sym_kind,
            sink_kind,
            line_start,
            node.end_position().row + 1,
            guards,
            calls,
            None,
        );
        sym.apply_taint(crate::taint::analyze_function_taint(
            val_node, src, rel_path, lang, &name, None,
        ));
        symbols.push(sym);
        return false;
    }

    // 4b. Constructor / module-assigned handler methods: `this.handleFoo = (req, res) => { ... }` or `exports.foo = function(...) { ... }`
    if kind == "assignment_expression"
        && let (Some(left_node), Some(right_node)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
        && left_node.kind() == "member_expression"
        && matches!(right_node.kind(), "arrow_function" | "function_expression")
    {
        let left_txt = node_text(left_node, src).trim();
        if left_txt.starts_with("this.")
            || left_txt.starts_with("exports.")
            || left_txt.starts_with("module.exports.")
        {
            let name = left_txt
                .rsplit('.')
                .next()
                .unwrap_or(left_txt)
                .trim()
                .to_string();
            if !name.is_empty() {
                let body = node_text(right_node, src);
                let mut calls = Vec::new();
                collect_calls(right_node, src, &mut calls);
                let guards = classify_fn_guards_cfg(right_node, src, cfg);
                let sink_kind = classify_sink(&name, body);
                let sym_kind = if sink_kind.is_some() {
                    SymbolKind::Sink
                } else {
                    SymbolKind::Function
                };
                let line_start = node.start_position().row + 1;
                let mut sym = SymbolInfo::base(
                    format!("{}::{}:{}", rel_path, name, line_start),
                    rel_path,
                    name.clone(),
                    sym_kind,
                    sink_kind,
                    line_start,
                    node.end_position().row + 1,
                    guards,
                    calls,
                    None,
                );
                sym.apply_taint(crate::taint::analyze_function_taint(
                    right_node, src, rel_path, lang, &name, None,
                ));
                symbols.push(sym);
                return false;
            }
        }
    }

    true
}

pub fn resolve_import_target(
    from_file: &str,
    spec: &str,
    known_files: &HashSet<String>,
) -> Option<String> {
    // 1. Rust `rust::crate/...` or `rust::super/...`
    if let Some(rs_spec) = spec.strip_prefix("rust::") {
        if let Some(mut rest) = rs_spec.strip_prefix("super") {
            let mut dir = Path::new(from_file).parent()?;
            // If `from_file` is `src/services/account.rs` (not `mod.rs`), `super::` refers to `src/services/`
            if !from_file.ends_with("mod.rs")
                && !from_file.ends_with("lib.rs")
                && !from_file.ends_with("main.rs")
            {
                // `super` in `src/services/account.rs` is `src/services`, and each extra `super/` walks up
                rest = rest.strip_prefix('/').unwrap_or(rest);
            } else if let Some(p) = dir.parent() {
                dir = p;
                rest = rest.strip_prefix('/').unwrap_or(rest);
            }
            while let Some(after) = rest.strip_prefix("super/") {
                if let Some(p) = dir.parent() {
                    dir = p;
                }
                rest = after;
            }
            let base = if rest.is_empty() {
                dir.to_string_lossy().to_string()
            } else {
                dir.join(rest).to_string_lossy().replace('\\', "/")
            };
            for ext in [".rs", "/mod.rs"] {
                let cand = format!("{}{}", base, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
            return None;
        }

        let cleaned = rs_spec.strip_prefix("crate/").unwrap_or(rs_spec);
        // Check workspace crate root relative to `from_file` (e.g. `crates/foo/src/lib.rs`) as well as repo root `src/`
        let crate_src_prefix = from_file
            .rfind("/src/")
            .map(|idx| format!("{}/src/", &from_file[..idx]));
        let mut prefixes = vec!["src/".to_string(), String::new()];
        if let Some(cp) = crate_src_prefix
            && !prefixes.contains(&cp)
        {
            prefixes.insert(0, cp);
        }
        for prefix in &prefixes {
            for ext in [".rs", "/mod.rs"] {
                let cand = format!("{}{}{}", prefix, cleaned, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
        }
        return None;
    }

    // 2. Python `py::...` (handles relative `.db`, `..pkg.db` relative to `from_file`)
    if let Some(py_spec) = spec.strip_prefix("py::") {
        let dot_count = py_spec.chars().take_while(|&c| c == '.').count();
        let mod_tail = py_spec[dot_count..].replace('.', "/");
        if dot_count > 0 {
            let mut dir = Path::new(from_file).parent()?;
            for _ in 1..dot_count {
                if let Some(p) = dir.parent() {
                    dir = p;
                }
            }
            let base = if mod_tail.is_empty() {
                dir.to_string_lossy().to_string()
            } else {
                dir.join(&mod_tail).to_string_lossy().replace('\\', "/")
            };
            for ext in [".py", "/__init__.py"] {
                let cand = format!("{}{}", base, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
            return None;
        }
        for prefix in ["src/", "app/", ""] {
            for ext in [".py", "/__init__.py"] {
                let cand = format!("{}{}{}", prefix, mod_tail, ext);
                if known_files.contains(&cand) {
                    return Some(cand);
                }
            }
        }
        return None;
    }

    // 3. TS/JS `@/` or `~/` path aliases
    if let Some(alias_rest) = spec.strip_prefix("@/").or_else(|| spec.strip_prefix("~/")) {
        let stripped_js = alias_rest
            .strip_suffix(".js")
            .or_else(|| alias_rest.strip_suffix(".mjs"))
            .unwrap_or(alias_rest);
        for prefix in ["src/", ""] {
            for stem in [alias_rest, stripped_js] {
                for ext in ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"] {
                    let cand = format!("{}{}{}", prefix, stem, ext);
                    if known_files.contains(&cand) {
                        return Some(cand);
                    }
                }
            }
        }
        return None;
    }

    // 3b. Extension language imports (PHP, Java, C#, Kotlin, Swift, Dart, C/C++)
    if let Some(resolved) = resolve_extension_import(from_file, spec, known_files) {
        return Some(resolved);
    }

    // 4. Relative `./` or `../` imports (including NodeNext `.js` -> `.ts` resolution)
    if !spec.starts_with('.') {
        return None;
    }
    let parent = Path::new(from_file).parent()?;
    let joined = parent.join(spec);
    let mut stack: Vec<String> = Vec::new();
    for comp in joined.components() {
        match comp {
            std::path::Component::Normal(s) => stack.push(s.to_string_lossy().to_string()),
            std::path::Component::ParentDir => {
                stack.pop();
            }
            _ => {}
        }
    }
    let base = stack.join("/");
    let stripped_js = base
        .strip_suffix(".js")
        .or_else(|| base.strip_suffix(".mjs"))
        .unwrap_or(&base);
    for stem in [base.as_str(), stripped_js] {
        for ext in [
            "",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".php",
            ".dart",
            ".h",
            ".hpp",
            ".c",
            ".cpp",
            ".cc",
            ".rb",
            ".rake",
            ".ru",
            ".sh",
            ".bash",
            ".zsh",
            "/index.ts",
            "/index.js",
        ] {
            let cand = format!("{}{}", stem, ext);
            if known_files.contains(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

fn resolve_extension_import(
    from_file: &str,
    spec: &str,
    known_files: &HashSet<String>,
) -> Option<String> {
    if let Some(inc) = spec.strip_prefix("cpp::") {
        let clean = inc.trim().replace('\\', "/");
        if clean.is_empty() {
            return None;
        }
        let parent = Path::new(from_file)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let stem = clean
            .strip_suffix(".hpp")
            .or_else(|| clean.strip_suffix(".hxx"))
            .or_else(|| clean.strip_suffix(".hh"))
            .or_else(|| clean.strip_suffix(".h"))
            .unwrap_or(&clean);
        // Prefer corresponding implementation file (.cpp/.c/...) so calls resolve to definitions
        let mut impl_candidates = Vec::new();
        for ext in ["cpp", "cc", "cxx", "c"] {
            impl_candidates.push(format!("{}.{}", stem, ext));
        }
        impl_candidates.push(clean.clone());
        for cand in &impl_candidates {
            let joined = normalize_rel_path(&parent.join(cand));
            if known_files.contains(&joined) {
                return Some(joined);
            }
        }
        for cand in &impl_candidates {
            if let Some(hit) = find_known_suffix(cand, &[], known_files) {
                return Some(hit);
            }
        }
        return None;
    }

    if let Some((prefix, body)) = spec.split_once("::") {
        let exts: &[&str] = match prefix {
            "php" => &["php", "phtml"],
            "java" => &["java"],
            "cs" => &["cs"],
            "kt" => &["kt", "kts"],
            "swift" => &["swift"],
            "dart" => &["dart"],
            "rb" => &["rb", "rake", "ru"],
            "sh" => &["sh", "bash", "zsh"],
            "hcl" => &["tf", "tfvars"],
            _ => return None,
        };
        let clean = body
            .trim()
            .trim_start_matches("./")
            .trim_end_matches("/*")
            .trim_end_matches('/');
        if clean.is_empty() {
            return None;
        }
        if prefix == "hcl" && (body.trim().starts_with('.') || !body.contains("://")) {
            let parent = Path::new(from_file)
                .parent()
                .unwrap_or_else(|| Path::new(""));
            let rel_dir = normalize_rel_path(&parent.join(body.trim()));
            if !rel_dir.is_empty() {
                for cand in [format!("{}/main.tf", rel_dir), format!("{}.tf", rel_dir)] {
                    if known_files.contains(&cand) {
                        return Some(cand);
                    }
                }
            }
        }
        if let Some(hit) = find_known_suffix(clean, exts, known_files) {
            return Some(hit);
        }
        // Namespace / package import (e.g. C# `using App.Services;` or Terraform `./modules/vpc`) — match file inside matching folder
        let seg_needle = format!("/{}/", clean.to_ascii_lowercase());
        let mut dir_matches: Vec<&String> = known_files
            .iter()
            .filter(|f| {
                let norm = format!("/{}", f.replace('\\', "/").to_ascii_lowercase());
                let ext_ok = exts.iter().any(|e| norm.ends_with(&format!(".{}", e)));
                ext_ok && norm.contains(&seg_needle)
            })
            .collect();
        dir_matches.sort();
        if prefix == "hcl" {
            if let Some(main_tf) = dir_matches.iter().find(|f| {
                f.replace('\\', "/")
                    .to_ascii_lowercase()
                    .ends_with("/main.tf")
            }) {
                return Some((*main_tf).clone());
            }
            if let Some(first) = dir_matches.first() {
                return Some((*first).clone());
            }
        } else if dir_matches.len() == 1 {
            return Some(dir_matches[0].clone());
        }
        return None;
    }

    // Bare relative requires in PHP / Dart / Ruby / Shell (e.g. `require 'ledger.php';`, `require_relative 'ledger'`, `source lib.sh`)
    let from_ext = Path::new(from_file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if matches!(from_ext, "php" | "phtml" | "dart" | "rb" | "sh" | "bash")
        && !spec.starts_with('.')
        && !spec.contains("://")
    {
        let parent = Path::new(from_file)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let joined = normalize_rel_path(&parent.join(spec.trim_start_matches('/')));
        if known_files.contains(&joined) {
            return Some(joined);
        }
        return find_known_suffix(spec, &[from_ext], known_files);
    }

    None
}

fn normalize_rel_path(path: &Path) -> String {
    let mut stack: Vec<String> = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(s) => stack.push(s.to_string_lossy().to_string()),
            std::path::Component::ParentDir => {
                stack.pop();
            }
            _ => {}
        }
    }
    stack.join("/")
}

/// Precomputed O(1) import lookup index built once per codebase scan.
/// Eliminates O(I * F log F) sorting and linear path scanning on large C++/Java/Kotlin repos.
pub struct ImportFileIndex<'a> {
    known_files: &'a HashSet<String>,
    suffix_map: HashMap<String, String>,
    dir_seg_map: HashMap<(String, String), Vec<String>>,
}

impl<'a> ImportFileIndex<'a> {
    pub fn new(known_files: &'a HashSet<String>) -> Self {
        const INDEXED_DIR_EXTS: &[&str] = &[
            "php", "phtml", "java", "cs", "kt", "kts", "swift", "dart", "rb", "rake", "ru", "sh",
            "bash", "zsh", "tf", "tfvars",
        ];
        let mut sorted: Vec<&String> = known_files.iter().collect();
        sorted.sort();

        let mut suffix_map: HashMap<String, String> = HashMap::with_capacity(sorted.len() * 3);
        let mut dir_seg_map: HashMap<(String, String), Vec<String>> = HashMap::new();

        for f in sorted {
            let norm = f.replace('\\', "/").to_ascii_lowercase();
            let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                continue;
            }
            for start in 0..parts.len() {
                let tail = parts[start..].join("/");
                suffix_map.entry(tail).or_insert_with(|| f.clone());
            }
            if let Some(ext) = parts
                .last()
                .and_then(|name| name.rsplit_once('.').map(|(_, e)| e))
                && INDEXED_DIR_EXTS.contains(&ext)
                && parts.len() >= 2
            {
                let dir_parts = &parts[..parts.len() - 1];
                let dlen = dir_parts.len();
                for i in 0..dlen {
                    let max_j = (i + 4).min(dlen);
                    for j in i..max_j {
                        let seg = dir_parts[i..=j].join("/");
                        let entry = dir_seg_map.entry((ext.to_string(), seg)).or_default();
                        if entry.len() < 4 || ext == "tf" || ext == "tfvars" {
                            entry.push(f.clone());
                        }
                    }
                }
            }
        }

        Self {
            known_files,
            suffix_map,
            dir_seg_map,
        }
    }

    fn find_known_suffix(&self, rel: &str, exts: &[&str]) -> Option<String> {
        let clean = rel.trim_start_matches("./").replace('\\', "/");
        let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }
        for start in 0..parts.len() {
            let tail = parts[start..].join("/").to_ascii_lowercase();
            if exts.is_empty() {
                if let Some(hit) = self.suffix_map.get(&tail) {
                    return Some(hit.clone());
                }
            } else {
                for e in exts {
                    let key = if tail.ends_with(&format!(".{}", e)) {
                        tail.clone()
                    } else {
                        format!("{}.{}", tail, e)
                    };
                    if let Some(hit) = self.suffix_map.get(&key) {
                        return Some(hit.clone());
                    }
                }
            }
        }
        None
    }

    fn find_dir_matches(&self, clean: &str, exts: &[&str]) -> Vec<String> {
        let needle = clean.to_ascii_lowercase();
        let mut out = Vec::new();
        for &e in exts {
            if let Some(hits) = self.dir_seg_map.get(&(e.to_string(), needle.clone())) {
                for h in hits {
                    if !out.contains(h) {
                        out.push(h.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }
}

pub fn resolve_import_target_indexed(
    from_file: &str,
    spec: &str,
    index: &ImportFileIndex<'_>,
) -> Option<String> {
    if spec.starts_with("rust::")
        || spec.starts_with("rs::")
        || spec.starts_with("py::")
        || spec.starts_with("@/")
        || spec.starts_with("~/")
    {
        return resolve_import_target(from_file, spec, index.known_files);
    }
    if let Some(resolved) = resolve_extension_import_indexed(from_file, spec, index) {
        return Some(resolved);
    }
    if spec.starts_with('.') {
        return resolve_import_target(from_file, spec, index.known_files);
    }
    None
}

fn resolve_extension_import_indexed(
    from_file: &str,
    spec: &str,
    index: &ImportFileIndex<'_>,
) -> Option<String> {
    let known_files = index.known_files;
    if let Some(inc) = spec.strip_prefix("cpp::") {
        let clean = inc.trim().replace('\\', "/");
        if clean.is_empty() {
            return None;
        }
        let parent = Path::new(from_file)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let stem = clean
            .strip_suffix(".hpp")
            .or_else(|| clean.strip_suffix(".hxx"))
            .or_else(|| clean.strip_suffix(".hh"))
            .or_else(|| clean.strip_suffix(".h"))
            .unwrap_or(&clean);
        let mut impl_candidates = Vec::new();
        for ext in ["cpp", "cc", "cxx", "c"] {
            impl_candidates.push(format!("{}.{}", stem, ext));
        }
        impl_candidates.push(clean.clone());
        for cand in &impl_candidates {
            let joined = normalize_rel_path(&parent.join(cand));
            if known_files.contains(&joined) {
                return Some(joined);
            }
        }
        for cand in &impl_candidates {
            if let Some(hit) = index.find_known_suffix(cand, &[]) {
                return Some(hit);
            }
        }
        return None;
    }

    if let Some((prefix, body)) = spec.split_once("::") {
        let exts: &[&str] = match prefix {
            "php" => &["php", "phtml"],
            "java" => &["java"],
            "cs" => &["cs"],
            "kt" => &["kt", "kts"],
            "swift" => &["swift"],
            "dart" => &["dart"],
            "rb" => &["rb", "rake", "ru"],
            "sh" => &["sh", "bash", "zsh"],
            "hcl" => &["tf", "tfvars"],
            _ => return None,
        };
        let clean = body
            .trim()
            .trim_start_matches("./")
            .trim_end_matches("/*")
            .trim_end_matches('/');
        if clean.is_empty() {
            return None;
        }
        if prefix == "hcl" && (body.trim().starts_with('.') || !body.contains("://")) {
            let parent = Path::new(from_file)
                .parent()
                .unwrap_or_else(|| Path::new(""));
            let rel_dir = normalize_rel_path(&parent.join(body.trim()));
            if !rel_dir.is_empty() {
                for cand in [format!("{}/main.tf", rel_dir), format!("{}.tf", rel_dir)] {
                    if known_files.contains(&cand) {
                        return Some(cand);
                    }
                }
            }
        }
        if let Some(hit) = index.find_known_suffix(clean, exts) {
            return Some(hit);
        }
        let dir_matches = index.find_dir_matches(clean, exts);
        if prefix == "hcl" {
            if let Some(main_tf) = dir_matches.iter().find(|f| {
                f.replace('\\', "/")
                    .to_ascii_lowercase()
                    .ends_with("/main.tf")
            }) {
                return Some(main_tf.clone());
            }
            if let Some(first) = dir_matches.first() {
                return Some(first.clone());
            }
        } else if dir_matches.len() == 1 {
            return Some(dir_matches[0].clone());
        }
        return None;
    }

    let from_ext = Path::new(from_file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if matches!(from_ext, "php" | "phtml" | "dart" | "rb" | "sh" | "bash")
        && !spec.starts_with('.')
        && !spec.contains("://")
    {
        let parent = Path::new(from_file)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let joined = normalize_rel_path(&parent.join(spec.trim_start_matches('/')));
        if known_files.contains(&joined) {
            return Some(joined);
        }
        return index.find_known_suffix(spec, &[from_ext]);
    }

    None
}

fn find_known_suffix(rel: &str, exts: &[&str], known_files: &HashSet<String>) -> Option<String> {
    let clean = rel.trim_start_matches("./").replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    let mut known_sorted: Vec<&String> = known_files.iter().collect();
    known_sorted.sort();

    for start in 0..parts.len() {
        let tail = parts[start..].join("/").to_ascii_lowercase();
        let candidates: Vec<String> = if exts.is_empty() {
            vec![format!("/{}", tail)]
        } else {
            exts.iter()
                .map(|e| {
                    if tail.ends_with(&format!(".{}", e)) {
                        format!("/{}", tail)
                    } else {
                        format!("/{}.{}", tail, e)
                    }
                })
                .collect()
        };
        for f in &known_sorted {
            let norm = format!("/{}", f.replace('\\', "/").to_ascii_lowercase());
            if candidates.iter().any(|c| norm.ends_with(c)) {
                return Some((*f).clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_comments_preserves_urls_and_strips_for_update_comment() {
        let code = r#"
            const url = "https://api.stripe.com/v1/charges"; // FOR UPDATE
            // requireAuth()
        "#;
        let cleaned = strip_comments(code);
        assert!(cleaned.contains("https://api.stripe.com/v1/charges"));
        assert!(!cleaned.contains("FOR UPDATE"));
        assert!(!cleaned.contains("requireAuth"));
    }

    #[test]
    fn test_resolve_aliases_and_rust_python_relative_modules() {
        let mut known = HashSet::new();
        known.insert("src/services/ledger.ts".to_string());
        known.insert("src/services/helper.rs".to_string());
        known.insert("src/db/queries.rs".to_string());
        known.insert("src/py_pkg/db.py".to_string());
        known.insert("app/db.py".to_string());

        assert_eq!(
            resolve_import_target("src/routes/checkout.ts", "@/services/ledger", &known),
            Some("src/services/ledger.ts".to_string())
        );
        assert_eq!(
            resolve_import_target("src/main.rs", "rust::crate/db/queries", &known),
            Some("src/db/queries.rs".to_string())
        );
        assert_eq!(
            resolve_import_target("src/services/account.rs", "rust::super/helper", &known),
            Some("src/services/helper.rs".to_string())
        );
        assert_eq!(
            resolve_import_target("src/py_pkg/app.py", "py::.db", &known),
            Some("src/py_pkg/db.py".to_string())
        );
    }

    fn parse_inline_ts(code: &str) -> FileAstSummary {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(code, None).unwrap();
        let cfg = ShellMindGuardConfig::default();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            code.as_bytes(),
            "test.ts",
            Language::TypeScript,
            &cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        let mut frontend_calls = Vec::new();
        let mut static_findings = Vec::new();
        crate::taint::extract_frontend_calls_and_bugs(
            tree.root_node(),
            code.as_bytes(),
            "test.ts",
            Language::TypeScript,
            &mut frontend_calls,
            &mut static_findings,
        );
        FileAstSummary {
            rel_path: "test.ts".into(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            ..Default::default()
        }
    }

    #[test]
    fn test_b02_guard_after_write_and_branch_only_do_not_protect() {
        let code = r#"
            function debitLateAuth(amount: number) {
                balance -= amount;
                requireAuth();
            }
            function debitBranchLock(cond: boolean, amount: number) {
                if (cond) { withTransaction(); }
                balance -= amount;
            }
            function debitStringFake(amount: number) {
                const label = "requireAuth FOR UPDATE";
                balance -= amount;
            }
        "#;
        let ast = parse_inline_ts(code);
        for sym in &ast.symbols {
            assert!(
                !sym.guards.contains(&GuardKind::Auth),
                "{} must NOT have Auth guard",
                sym.name
            );
            assert!(
                !sym.guards.contains(&GuardKind::TxLock),
                "{} must NOT have TxLock guard",
                sym.name
            );
        }
    }

    #[test]
    fn test_b03_middleware_order_and_b07_inline_route_sink() {
        let code = r#"
            app.post('/api/late-mw', handler, requireAuth);
            app.post('/api/inline-pay', async (req, res) => {
                await stripe.charges.create({ amount: req.body.amount });
            });
        "#;
        let ast = parse_inline_ts(code);
        let late = ast
            .symbols
            .iter()
            .find(|s| s.name == "POST /api/late-mw")
            .unwrap();
        assert!(!late.guards.contains(&GuardKind::Auth));

        let inline_sink = ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Sink && s.sink_kind == Some(SinkKind::PaymentMutation))
            .expect("inline route sink must be extracted");
        assert!(!inline_sink.guards.contains(&GuardKind::Auth));
    }

    #[test]
    fn test_b06_python_fastapi_route_discovery() {
        let py_code = r#"
@app.post("/api/v1/py/withdraw")
def withdraw(amount: int):
    balance -= amount
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(py_code, None).unwrap();
        let cfg = ShellMindGuardConfig::default();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            py_code.as_bytes(),
            "app.py",
            Language::Python,
            &cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/v1/py/withdraw")
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Sink && s.name == "withdraw")
        );
    }

    fn parse_inline_file(rel_path: &str, code: &str, cfg: &ShellMindGuardConfig) -> FileAstSummary {
        let lang = Language::from_path(Path::new(rel_path)).unwrap_or(Language::TypeScript);
        let mut parser = Parser::new();
        let ts_lang: tree_sitter::Language = match lang {
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Sql
            | Language::Config
            | Language::Manifest
            | Language::Solidity
            | Language::Move => unreachable!(),
            other => crate::langs::ts_language_for(other).expect("supported tree-sitter language"),
        };
        parser.set_language(&ts_lang).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let mut mw = HashSet::new();
        let mut imports = Vec::new();
        let mut symbols = Vec::new();
        let mut route_prefixes = Vec::new();
        extract_node(
            tree.root_node(),
            code.as_bytes(),
            rel_path,
            lang,
            cfg,
            &mut mw,
            &mut imports,
            &mut symbols,
            &mut route_prefixes,
        );
        let mut frontend_calls = Vec::new();
        let mut static_findings = Vec::new();
        crate::taint::extract_frontend_calls_and_bugs(
            tree.root_node(),
            code.as_bytes(),
            rel_path,
            lang,
            &mut frontend_calls,
            &mut static_findings,
        );
        FileAstSummary {
            rel_path: rel_path.into(),
            imports,
            symbols,
            static_findings,
            frontend_calls,
            route_prefixes,
            ..Default::default()
        }
    }

    #[test]
    fn test_universal_go_gin_group_and_net_http() {
        let go_code = r#"
package main

func registerRoutes(r *gin.Engine) {
    api := r.Group("/api/v1")
    api.Use(AuthMiddleware())
    api.POST("/charge", handleCharge)
    http.HandleFunc("/webhook/stripe", handleWebhook)
}

func handleCharge(c *gin.Context) {
    razorpay.Orders.Create(100)
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
    tx.Exec("UPDATE balances SET amt = amt - 1")
}
"#;
        let ast = parse_inline_file("main.go", go_code, &ShellMindGuardConfig::default());
        let charge_route = ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Route && s.name == "POST /charge")
            .expect("Go Gin Group route must be extracted");
        assert!(
            charge_route.guards.contains(&GuardKind::Auth),
            "Go Gin Group.Use(AuthMiddleware) must propagate Auth guard"
        );
        assert!(
            ast.symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "HTTP /webhook/stripe"),
            "net/http HandleFunc route must be extracted"
        );
        assert!(
            ast.symbols.iter().any(|s| s.kind == SymbolKind::Sink
                && s.name == "handleCharge"
                && s.sink_kind == Some(SinkKind::PaymentMutation)),
            "Razorpay sink must be detected"
        );
        assert!(
            ast.symbols.iter().any(|s| s.kind == SymbolKind::Sink
                && s.name == "handleWebhook"
                && s.sink_kind == Some(SinkKind::BalanceUpdate)),
            "tx.Exec sink must be detected"
        );
    }

    #[test]
    fn test_universal_nextjs_nestjs_trpc_django_actix() {
        let cfg = ShellMindGuardConfig::default();

        // Next.js App Router
        let nextjs_code = r#"
export async function POST(req: Request) {
    await prisma.ledger.update({ data: { balance: 0 } });
}
"#;
        let next_ast = parse_inline_file("app/api/pay/route.ts", nextjs_code, &cfg);
        assert!(
            next_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/pay"),
            "Next.js App Router route must be extracted"
        );
        assert!(
            next_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Sink && s.sink_kind == Some(SinkKind::BalanceUpdate)),
            "Prisma sink must be detected"
        );

        // NestJS
        let nest_code = r#"
@Controller("billing")
export class BillingController {
    @Post("payout")
    @UseGuards(AuthGuard)
    async payout() {
        await stripe.transfers.create({});
    }
}
"#;
        let nest_ast = parse_inline_file("billing.controller.ts", nest_code, &cfg);
        let nest_route = nest_ast
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Route && s.name.contains("payout"))
            .expect("NestJS @Post route must be extracted");
        assert!(nest_route.guards.contains(&GuardKind::Auth));

        // tRPC
        let trpc_code = r#"
export const payRouter = router({
    openPay: publicProcedure.mutation(async () => {
        await paddle.transactions.create({});
    }),
    safePay: protectedProcedure.mutation(async () => {
        await paddle.transactions.create({});
    }),
});
"#;
        let trpc_ast = parse_inline_file("trpc/pay.ts", trpc_code, &cfg);
        let trpc_routes: Vec<_> = trpc_ast
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Route && s.name.starts_with("TRPC trpc/pay.ts:"))
            .collect();
        assert_eq!(
            trpc_routes.len(),
            2,
            "Both tRPC mutations must be extracted"
        );
        assert!(
            trpc_routes
                .iter()
                .any(|r| !r.guards.contains(&GuardKind::Auth)),
            "tRPC publicProcedure must NOT have Auth guard"
        );
        assert!(
            trpc_routes
                .iter()
                .any(|r| r.guards.contains(&GuardKind::Auth)),
            "tRPC protectedProcedure must have Auth guard"
        );

        // Django
        let django_code = r#"
urlpatterns = [
    path("api/v1/refund/", refund_view),
]
"#;
        let dj_ast = parse_inline_file("urls.py", django_code, &cfg);
        assert!(
            dj_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "DJANGO /api/v1/refund/"),
            "Django path() route must be extracted"
        );

        // Rust Actix-web
        let actix_code = r#"
#[post("/api/v1/transfer")]
async fn transfer_funds() {
    let amount = 10;
    balance -= amount;
}
"#;
        let actix_ast = parse_inline_file("routes.rs", actix_code, &cfg);
        assert!(
            actix_ast
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Route && s.name == "POST /api/v1/transfer"),
            "Actix-web #[post] route must be extracted"
        );
    }

    #[test]
    fn test_public_routes_suppresses_auth_only() {
        let ts_code = r#"
app.post('/api/v1/auth/2fa/confirm', async (req, res) => {
    await stripe.charges.create({ amount: 100 });
});
"#;
        let cfg = ShellMindGuardConfig::default();
        let ast = parse_inline_file("auth.ts", ts_code, &cfg);
        let res =
            crate::lattice::solve_guard_lattice_with_public(&[ast], &cfg.guards.public_routes);
        assert!(
            !res.findings.iter().any(|f| f.rule_id == "SMG-AUTH-001"),
            "public_routes must suppress SMG-AUTH-001"
        );
        assert!(
            res.findings.iter().any(|f| f.rule_id == "SMG-RACE-001"),
            "public_routes must still report SMG-RACE-001 if unlocked"
        );
    }

    #[test]
    fn test_phase2_taint_idor_and_frontend_extraction() {
        let cfg = ShellMindGuardConfig::default();
        let backend = r#"
app.get('/api/users/:id', requireAuth, async (req, res) => {
    const id = req.params.id;
    return await db.query(`SELECT * FROM users WHERE id = ${id}`);
});
app.post('/api/exec', requireAuth, async (req, res) => {
    const host = req.body.host;
    exec("ping -c 1 " + host);
});
function readSafeFile(req: any) {
    const safe = path.basename(req.query.name);
    return fs.readFileSync('/var/data/' + safe);
}
app.post('/api/proxy', requireAuth, async (req, res) => {
    const u = req.body.url;
    await fetch(u);
});
"#;
        let b_ast = parse_inline_file("routes.ts", backend, &cfg);
        let hits: Vec<_> = b_ast
            .symbols
            .iter()
            .flat_map(|s| s.local_taint_hits.iter())
            .collect();
        assert!(
            hits.iter().any(|h| h.rule_id == "SMG-SQLI-001"),
            "Must detect SQLi in interpolated query"
        );
        assert!(
            hits.iter().any(|h| h.rule_id == "SMG-CMDI-001"),
            "Must detect CMDi in exec()"
        );
        assert!(
            !hits.iter().any(|h| h.rule_id == "SMG-PATH-001"),
            "path.basename sanitizer must clear SMG-PATH-001"
        );
        assert!(
            hits.iter().any(|h| h.rule_id == "SMG-SSRF-001"),
            "Must detect SSRF in outbound fetch(u)"
        );

        let user_route = b_ast
            .symbols
            .iter()
            .find(|s| s.name == "GET /api/users/:id")
            .unwrap();
        assert!(user_route.has_resource_id);
        assert!(user_route.has_db_crud_sink);

        let fe = r#"
export async function loadProfile(id: string) {
    try {
        await fetch(`/api/profile/${id}`);
    } catch (e) {}
    try {
        await fetch(`/api/users/${id}`);
    } catch (e) {
        console.log(e);
    }
}
"#;
        let fe_ast = parse_inline_file("web/profile.tsx", fe, &cfg);
        assert_eq!(fe_ast.frontend_calls.len(), 2);
        assert!(
            fe_ast
                .static_findings
                .iter()
                .filter(|f| f.rule_id == "SMG-FE-ERR")
                .count()
                >= 2,
            "Must flag empty catch and console-only catch as SMG-FE-ERR"
        );

        let safe_tagged = r#"
function runSafeTagged(req: any) {
    const id = req.params.id;
    return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}
"#;
        let safe_ast = parse_inline_file("safe.ts", safe_tagged, &cfg);
        assert!(
            safe_ast
                .symbols
                .iter()
                .all(|s| s.local_taint_hits.is_empty()),
            "prisma.$queryRaw tagged template must NOT trigger SMG-SQLI-001"
        );
    }

    #[test]
    fn test_wave4_rust_cfg_test_and_detector_literal_suppression() {
        let cfg = ShellMindGuardConfig::default();
        let rust_with_tests = r#"
pub fn safe_prod_fn(url: &str) -> bool {
    url.contains("rejectUnauthorized: false")
}

#[cfg(test)]
mod tests {
    #[test]
    fn mock_vuln() {
        let _ = "new ApolloServer({ introspection: true })";
        let _re = regex::Regex::new("^([a-zA-Z0-9]+)+$");
    }
}
"#;
        let rust_ast = parse_inline_file("src/detector.rs", rust_with_tests, &cfg);
        assert!(
            rust_ast.static_findings.is_empty(),
            "Pattern matchers and #[cfg(test)] blocks in Rust files must produce 0 non-secret findings: {:?}",
            rust_ast.static_findings
        );
    }
}
