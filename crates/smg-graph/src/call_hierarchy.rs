//! Phase 12A (`P12-01` & `P12-02`): Qualified `CallSite`, Receiver Type Inference,
//! Multi-Language `TypeImplSummary`, DI Bindings, and RTA Instantiation Extraction.
//!
//! Runs in a single $O(N)$ pass over each parsed Tree-sitter AST with zero per-call regex allocation.

use crate::ast::{CallSite, SymbolInfo, TypeImplSummary};
use smg_core::Language;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

const MAX_WALK_DEPTH: usize = 512;

#[derive(Debug, Default)]
pub struct FileCallHierarchyData {
    pub type_impls: Vec<TypeImplSummary>,
    pub di_bindings: Vec<(String, String)>,
    pub instantiated_types: Vec<String>,
}

#[derive(Debug, Clone)]
struct TypeScope {
    type_name: String,
    start_line: usize,
    end_line: usize,
    field_types: HashMap<String, String>,
}

#[inline]
fn ntxt<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

/// Cleans a type annotation string down to its primary nominal type identifier.
/// Examples: `&'a dyn AuthGuard` -> `AuthGuard`, `Arc<JwtGuard>` -> `JwtGuard`,
/// `*mut UserRepo` -> `UserRepo`, `IUserRepo | null` -> `IUserRepo`, `Optional<AuthService>` -> `AuthService`.
pub(crate) fn clean_nominal_type(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Strip leading reference/pointer/const/dyn/mut/lifetime qualifiers
    loop {
        let prev = s;
        s = s.trim_start_matches(['&', '*', '?', '(']).trim_start();
        for kw in [
            "dyn ",
            "mut ",
            "const ",
            "readonly ",
            "final ",
            "private ",
            "public ",
            "protected ",
            "static ",
            "impl ",
            "ref ",
            "in ",
            "out ",
        ] {
            if let Some(rest) = s.strip_prefix(kw) {
                s = rest.trim_start();
            }
        }
        // Strip Rust lifetime `'a `
        if s.starts_with('\'') {
            let sp = s.find(char::is_whitespace)?;
            s = s[sp..].trim_start();
        }
        if s == prev {
            break;
        }
    }
    // Unwrap common container wrappers: Arc<T>, Box<T>, Rc<T>, Option<T>, Optional<T>, Promise<T>, Vec<T>, Provider<T>
    for wrapper in [
        "Arc<",
        "Box<",
        "Rc<",
        "Option<",
        "Optional<",
        "Promise<",
        "Provider<",
        "Inject<",
        "Lazy<",
        "RefCell<",
        "Mutex<",
        "RwLock<",
    ] {
        if let Some(inner) = s.strip_prefix(wrapper)
            && let Some(end) = inner.rfind('>')
        {
            return clean_nominal_type(&inner[..end]);
        }
    }
    // Strip union/generic/array/pointer tails
    let head = s
        .split(['<', '[', '|', '&', '(', '{', ',', ';', '='])
        .next()
        .unwrap_or(s)
        .trim();
    // Take last path segment (`pkg.AuthGuard`, `crate::auth::AuthGuard`, `App\Auth\Guard`)
    let leaf = head.rsplit(['.', ':', '\\']).next().unwrap_or(head).trim();
    if leaf.is_empty()
        || !leaf
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    // Exclude primitive built-in types that cannot participate in CHA/RTA dispatch
    let low = leaf.to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "string"
            | "str"
            | "number"
            | "boolean"
            | "bool"
            | "void"
            | "any"
            | "unknown"
            | "never"
            | "null"
            | "undefined"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "usize"
            | "isize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "f32"
            | "f64"
            | "float"
            | "double"
            | "char"
            | "byte"
            | "bytes"
            | "error"
            | "object"
            | "dict"
            | "list"
            | "set"
            | "tuple"
            | "none"
            | "self"
            | "this"
            | "var"
            | "let"
            | "const"
            | "auto"
    ) {
        return None;
    }
    Some(leaf.to_string())
}

fn is_valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn push_unique(vec: &mut Vec<String>, val: String) {
    if !val.is_empty() && !vec.iter().any(|x| x == &val) {
        vec.push(val);
    }
}

/// Enriches all `symbols` in a file with `enclosing_type` and qualified `call_sites`,
/// and returns file-level `TypeImplSummary`, `di_bindings`, and RTA `instantiated_types`.
pub fn enrich_file_call_hierarchy(
    root: Node,
    src: &[u8],
    lang: Language,
    symbols: &mut [SymbolInfo],
) -> FileCallHierarchyData {
    let mut data = FileCallHierarchyData::default();
    let mut type_scopes: Vec<TypeScope> = Vec::new();
    let mut type_impl_map: HashMap<String, usize> = HashMap::new();
    let mut inst_set: HashSet<String> = HashSet::new();

    // Pass 1: Extract type declarations, inheritance/traits/interfaces, class field types, DI bindings, and RTA instantiations
    collect_types_and_di(
        root,
        src,
        lang,
        &mut data.type_impls,
        &mut type_impl_map,
        &mut data.di_bindings,
        &mut inst_set,
        &mut type_scopes,
        0,
    );

    // Assign `enclosing_type` to every SymbolInfo inside a class/struct/impl span
    for sym in symbols.iter_mut() {
        let best_scope = type_scopes
            .iter()
            .filter(|sc| sym.line_start >= sc.start_line && sym.line_start <= sc.end_line)
            .min_by_key(|sc| sc.end_line.saturating_sub(sc.start_line));
        if let Some(sc) = best_scope {
            sym.enclosing_type = Some(sc.type_name.clone());
            // Ensure the method name is registered on the TypeImplSummary (essential for Go structural interfaces & CHA)
            if let Some(&idx) = type_impl_map.get(&sc.type_name) {
                push_unique(&mut data.type_impls[idx].methods, sym.name.clone());
            }
        }
    }

    // Pass 2: Extract qualified `CallSite`s with local + field receiver type inference per function/method/route
    if !symbols.is_empty() {
        let mut sym_line_spans: Vec<(usize, usize, usize)> = symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.line_start, s.line_end))
            .collect();
        sym_line_spans.sort_by_key(|&(_, s, e)| (e.saturating_sub(s), s));

        let mut per_sym_local_types: Vec<HashMap<String, String>> =
            vec![HashMap::new(); symbols.len()];

        // Seed each symbol with its enclosing class's field types (`this.x` / `self.x`)
        for (i, sym) in symbols.iter().enumerate() {
            if let Some(ref enc) = sym.enclosing_type {
                per_sym_local_types[i].insert("this".to_string(), enc.clone());
                per_sym_local_types[i].insert("self".to_string(), enc.clone());
                if let Some(sc) = type_scopes.iter().find(|s| &s.type_name == enc) {
                    for (fname, fty) in &sc.field_types {
                        per_sym_local_types[i].insert(fname.clone(), fty.clone());
                        per_sym_local_types[i].insert(format!("this.{fname}"), fty.clone());
                        per_sym_local_types[i].insert(format!("self.{fname}"), fty.clone());
                    }
                }
            }
        }

        // Collect local variable & parameter type bindings per symbol
        collect_local_type_bindings(
            root,
            src,
            lang,
            &sym_line_spans,
            &mut per_sym_local_types,
            0,
        );

        // Collect all qualified CallSites and attach to innermost owning SymbolInfo
        collect_qualified_call_sites(root, src, &sym_line_spans, &per_sym_local_types, symbols, 0);
    }

    let mut inst_vec: Vec<String> = inst_set.into_iter().collect();
    inst_vec.sort();
    data.instantiated_types = inst_vec;
    data
}

fn find_owning_symbol(line: usize, sym_line_spans: &[(usize, usize, usize)]) -> Option<usize> {
    for &(idx, s, e) in sym_line_spans {
        if line >= s && line <= e {
            return Some(idx);
        }
    }
    None
}

fn upsert_type_impl(
    type_impls: &mut Vec<TypeImplSummary>,
    type_impl_map: &mut HashMap<String, usize>,
    type_name: String,
    is_interface: bool,
    line: usize,
) -> usize {
    if let Some(&idx) = type_impl_map.get(&type_name) {
        if !is_interface {
            type_impls[idx].is_interface = false;
        }
        return idx;
    }
    let idx = type_impls.len();
    type_impls.push(TypeImplSummary {
        type_name: type_name.clone(),
        implements: Vec::new(),
        methods: Vec::new(),
        is_interface,
        line,
    });
    type_impl_map.insert(type_name, idx);
    idx
}

#[allow(clippy::too_many_arguments)]
fn collect_types_and_di(
    node: Node,
    src: &[u8],
    lang: Language,
    type_impls: &mut Vec<TypeImplSummary>,
    type_impl_map: &mut HashMap<String, usize>,
    di_bindings: &mut Vec<(String, String)>,
    inst_set: &mut HashSet<String>,
    type_scopes: &mut Vec<TypeScope>,
    depth: usize,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let kind = node.kind();
    let line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;

    // 1. RTA Instantiation sites across languages
    match kind {
        "new_expression" | "object_creation_expression" => {
            if let Some(ctor) = node
                .child_by_field_name("constructor")
                .or_else(|| node.child_by_field_name("type"))
                && let Some(ty) = clean_nominal_type(ntxt(ctor, src))
            {
                inst_set.insert(ty);
            }
        }
        "struct_expression" | "composite_literal" => {
            if let Some(ty_node) = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("type"))
                && let Some(ty) = clean_nominal_type(ntxt(ty_node, src))
            {
                inst_set.insert(ty);
            }
        }
        "call_expression" | "call" => {
            if let Some(func) = node.child_by_field_name("function") {
                let ftxt = ntxt(func, src).trim();
                // Rust `JwtGuard::new(...)` or `JwtGuard::default()`
                if let Some((ty_part, meth)) = ftxt.rsplit_once("::")
                    && matches!(meth, "new" | "default" | "from" | "build")
                    && let Some(ty) = clean_nominal_type(ty_part)
                {
                    inst_set.insert(ty);
                } else if lang == Language::Go
                    && let Some(rest) = ftxt.rsplit('.').next()
                    && let Some(ty_rest) = rest.strip_prefix("New")
                    && ty_rest
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_uppercase())
                {
                    inst_set.insert(ty_rest.to_string());
                } else if matches!(
                    lang,
                    Language::Python | Language::Kotlin | Language::Dart | Language::Swift
                ) && let Some(leaf) = ftxt.rsplit('.').next()
                    && leaf.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
                    && is_valid_ident(leaf)
                {
                    inst_set.insert(leaf.to_string());
                }
            }
        }
        _ => {}
    }

    // 2. NestJS / TS DI object literal `{ provide: Token, useClass: ConcreteImpl }`
    if matches!(lang, Language::TypeScript | Language::JavaScript) && kind == "object" {
        let txt = ntxt(node, src);
        if txt.contains("provide") && txt.contains("useClass") {
            let mut provide_tok: Option<String> = None;
            let mut use_class: Option<String> = None;
            let mut c = node.walk();
            for ch in node.named_children(&mut c) {
                if ch.kind() == "pair"
                    && let (Some(k), Some(v)) = (
                        ch.child_by_field_name("key"),
                        ch.child_by_field_name("value"),
                    )
                {
                    let ktxt = ntxt(k, src).trim().trim_matches(['\'', '"']);
                    let vtxt = ntxt(v, src).trim().trim_matches(['\'', '"']);
                    if ktxt == "provide" && !vtxt.is_empty() {
                        provide_tok = Some(vtxt.to_string());
                    } else if ktxt == "useClass"
                        && let Some(ty) = clean_nominal_type(vtxt)
                    {
                        use_class = Some(ty);
                    }
                }
            }
            if let (Some(tok), Some(cls)) = (provide_tok, use_class) {
                inst_set.insert(cls.clone());
                di_bindings.push((tok, cls));
            }
        }
    }

    // 3. FastAPI DI overrides `app.dependency_overrides[orig] = override_fn`
    if lang == Language::Python && kind == "assignment" {
        let txt = ntxt(node, src);
        if txt.contains("dependency_overrides[")
            && let Some((lhs, rhs)) = txt.split_once('=')
            && let Some(inner) = lhs
                .split_once("dependency_overrides[")
                .and_then(|(_, r)| r.split_once(']'))
                .map(|(k, _)| k.trim())
        {
            let target = rhs.trim();
            if is_valid_ident(inner) && is_valid_ident(target) {
                di_bindings.push((inner.to_string(), target.to_string()));
            }
        }
    }

    // 4. Language-specific Type / Class / Interface / Trait / Struct / Method Receiver extraction
    match lang {
        Language::TypeScript | Language::JavaScript => {
            if matches!(
                kind,
                "class_declaration" | "abstract_class_declaration" | "interface_declaration"
            ) && let Some(name_n) = node.child_by_field_name("name")
            {
                let tname = ntxt(name_n, src).trim().to_string();
                let is_iface = kind == "interface_declaration";
                if is_valid_ident(&tname) {
                    let idx =
                        upsert_type_impl(type_impls, type_impl_map, tname.clone(), is_iface, line);
                    let mut c = node.walk();
                    for ch in node.children(&mut c) {
                        if matches!(
                            ch.kind(),
                            "class_heritage"
                                | "extends_clause"
                                | "extends_type_clause"
                                | "implements_clause"
                        ) {
                            extract_heritage_types(ch, src, &mut type_impls[idx].implements);
                        }
                    }
                    let mut field_types = HashMap::new();
                    extract_ts_class_fields_and_methods(
                        node,
                        src,
                        &mut field_types,
                        &mut type_impls[idx].methods,
                    );
                    type_scopes.push(TypeScope {
                        type_name: tname,
                        start_line: line,
                        end_line,
                        field_types,
                    });
                }
            }
        }
        Language::Rust => {
            if kind == "trait_item"
                && let Some(name_n) = node.child_by_field_name("name")
            {
                let tname = ntxt(name_n, src).trim().to_string();
                if is_valid_ident(&tname) {
                    let idx = upsert_type_impl(type_impls, type_impl_map, tname, true, line);
                    extract_body_method_names(node, src, &mut type_impls[idx].methods);
                }
            } else if kind == "impl_item"
                && let Some(ty_n) = node.child_by_field_name("type")
                && let Some(tname) = clean_nominal_type(ntxt(ty_n, src))
            {
                let idx = upsert_type_impl(type_impls, type_impl_map, tname.clone(), false, line);
                if let Some(tr_n) = node.child_by_field_name("trait")
                    && let Some(tr_name) = clean_nominal_type(ntxt(tr_n, src))
                {
                    push_unique(&mut type_impls[idx].implements, tr_name);
                }
                extract_body_method_names(node, src, &mut type_impls[idx].methods);
                type_scopes.push(TypeScope {
                    type_name: tname,
                    start_line: line,
                    end_line,
                    field_types: HashMap::new(),
                });
            } else if kind == "struct_item"
                && let Some(name_n) = node.child_by_field_name("name")
            {
                let tname = ntxt(name_n, src).trim().to_string();
                if is_valid_ident(&tname) {
                    upsert_type_impl(type_impls, type_impl_map, tname.clone(), false, line);
                    let mut field_types = HashMap::new();
                    extract_rust_struct_fields(node, src, &mut field_types);
                    if !field_types.is_empty() {
                        // Attach field types onto any matching impl scopes later via a synthetic scope or update
                        for sc in type_scopes.iter_mut() {
                            if sc.type_name == tname {
                                sc.field_types.extend(field_types.clone());
                            }
                        }
                        type_scopes.push(TypeScope {
                            type_name: tname,
                            start_line: line,
                            end_line,
                            field_types,
                        });
                    }
                }
            }
        }
        Language::Go => {
            if kind == "type_spec"
                && let (Some(name_n), Some(ty_n)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("type"),
                )
            {
                let tname = ntxt(name_n, src).trim().to_string();
                if is_valid_ident(&tname) {
                    if ty_n.kind() == "interface_type" {
                        let idx = upsert_type_impl(type_impls, type_impl_map, tname, true, line);
                        extract_go_interface_methods(ty_n, src, &mut type_impls[idx].methods);
                    } else if ty_n.kind() == "struct_type" {
                        let idx =
                            upsert_type_impl(type_impls, type_impl_map, tname.clone(), false, line);
                        let mut field_types = HashMap::new();
                        extract_go_struct_fields(
                            ty_n,
                            src,
                            &mut field_types,
                            &mut type_impls[idx].implements,
                        );
                        type_scopes.push(TypeScope {
                            type_name: tname,
                            start_line: line,
                            end_line,
                            field_types,
                        });
                    }
                }
            } else if kind == "method_declaration"
                && let Some(recv_n) = node.child_by_field_name("receiver")
                && let Some((recv_var, recv_ty)) = extract_go_method_receiver(recv_n, src)
            {
                let idx = upsert_type_impl(type_impls, type_impl_map, recv_ty.clone(), false, line);
                if let Some(mname_n) = node.child_by_field_name("name") {
                    push_unique(
                        &mut type_impls[idx].methods,
                        ntxt(mname_n, src).trim().to_string(),
                    );
                }
                let mut field_types = HashMap::new();
                if !recv_var.is_empty() {
                    field_types.insert(recv_var, recv_ty.clone());
                }
                // Inherit struct field types if already parsed
                if let Some(existing) = type_scopes
                    .iter()
                    .find(|s| s.type_name == recv_ty && !s.field_types.is_empty())
                {
                    let cloned = existing.field_types.clone();
                    for (k, v) in cloned {
                        field_types.entry(k).or_insert(v);
                    }
                }
                type_scopes.push(TypeScope {
                    type_name: recv_ty,
                    start_line: line,
                    end_line,
                    field_types,
                });
            }
        }
        Language::Python => {
            if kind == "class_definition"
                && let Some(name_n) = node.child_by_field_name("name")
            {
                let tname = ntxt(name_n, src).trim().to_string();
                if is_valid_ident(&tname) {
                    let mut bases = Vec::new();
                    if let Some(sup) = node.child_by_field_name("superclasses") {
                        extract_heritage_types(sup, src, &mut bases);
                    }
                    let is_iface = bases
                        .iter()
                        .any(|b| matches!(b.as_str(), "ABC" | "Protocol" | "Interface"));
                    let idx =
                        upsert_type_impl(type_impls, type_impl_map, tname.clone(), is_iface, line);
                    for b in bases {
                        if !matches!(b.as_str(), "ABC" | "Protocol" | "object") {
                            push_unique(&mut type_impls[idx].implements, b);
                        }
                    }
                    extract_body_method_names(node, src, &mut type_impls[idx].methods);
                    let mut field_types = HashMap::new();
                    extract_python_self_field_types(node, src, &mut field_types);
                    type_scopes.push(TypeScope {
                        type_name: tname,
                        start_line: line,
                        end_line,
                        field_types,
                    });
                }
            }
        }
        _ => {
            // Extension languages: Java, C#, Kotlin, Swift, Dart, PHP, C++, Ruby
            if matches!(
                kind,
                "class_declaration"
                    | "interface_declaration"
                    | "struct_declaration"
                    | "protocol_declaration"
                    | "class_specifier"
                    | "struct_specifier"
                    | "class"
            ) && let Some(name_n) = node.child_by_field_name("name")
            {
                let tname = ntxt(name_n, src).trim().to_string();
                let is_iface = matches!(kind, "interface_declaration" | "protocol_declaration");
                if is_valid_ident(&tname) {
                    let idx =
                        upsert_type_impl(type_impls, type_impl_map, tname.clone(), is_iface, line);
                    extract_generic_heritage(node, src, &mut type_impls[idx].implements);
                    extract_body_method_names(node, src, &mut type_impls[idx].methods);
                    let mut field_types = HashMap::new();
                    extract_generic_field_types(node, src, &mut field_types);
                    type_scopes.push(TypeScope {
                        type_name: tname,
                        start_line: line,
                        end_line,
                        field_types,
                    });
                }
            }
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_types_and_di(
            ch,
            src,
            lang,
            type_impls,
            type_impl_map,
            di_bindings,
            inst_set,
            type_scopes,
            depth + 1,
        );
    }
}

fn extract_heritage_types(node: Node, src: &[u8], out: &mut Vec<String>) {
    let txt = ntxt(node, src);
    for raw_tok in
        txt.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != ':')
    {
        let t = raw_tok.trim();
        if matches!(
            t,
            "" | "extends" | "implements" | "with" | "public" | "private" | "protected" | "virtual"
        ) {
            continue;
        }
        if let Some(ty) = clean_nominal_type(t)
            && ty.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        {
            push_unique(out, ty);
        }
    }
}

fn extract_generic_heritage(class_node: Node, src: &[u8], out: &mut Vec<String>) {
    let mut c = class_node.walk();
    for ch in class_node.children(&mut c) {
        let k = ch.kind();
        if k.contains("super")
            || k.contains("interface")
            || k.contains("base")
            || k.contains("delegation")
            || k.contains("inheritance")
            || k == "type_list"
        {
            extract_heritage_types(ch, src, out);
        }
    }
}

fn extract_body_method_names(node: Node, src: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(cur) = stack.pop() {
        let k = cur.kind();
        if matches!(
            k,
            "method_definition"
                | "method_signature"
                | "function_item"
                | "function_signature_item"
                | "function_definition"
                | "method_declaration"
                | "function_declaration"
                | "method"
        ) && let Some(nm) = cur.child_by_field_name("name")
        {
            let mname = ntxt(nm, src).trim();
            if is_valid_ident(mname) && !matches!(mname, "constructor" | "__init__") {
                push_unique(out, mname.to_string());
            }
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            if !matches!(
                ch.kind(),
                "class_declaration" | "class_definition" | "impl_item"
            ) {
                stack.push(ch);
            }
        }
    }
}

fn extract_ts_class_fields_and_methods(
    class_node: Node,
    src: &[u8],
    field_types: &mut HashMap<String, String>,
    methods: &mut Vec<String>,
) {
    let mut stack = vec![class_node];
    while let Some(cur) = stack.pop() {
        match cur.kind() {
            "public_field_definition" | "field_definition" | "property_signature" => {
                if let (Some(nm), Some(ty)) = (
                    cur.child_by_field_name("name"),
                    cur.child_by_field_name("type"),
                ) {
                    let fname = ntxt(nm, src).trim();
                    let ty_raw = ntxt(ty, src).trim().trim_start_matches(':').trim();
                    if is_valid_ident(fname)
                        && let Some(clean) = clean_nominal_type(ty_raw)
                    {
                        field_types.insert(fname.to_string(), clean);
                    }
                }
            }
            "required_parameter" | "optional_parameter" => {
                // Constructor parameter properties: `constructor(private readonly auth: AuthGuard)`
                let raw = ntxt(cur, src);
                if (raw.contains("private ")
                    || raw.contains("public ")
                    || raw.contains("protected ")
                    || raw.contains("readonly "))
                    && let (Some(pat), Some(ty)) = (
                        cur.child_by_field_name("pattern"),
                        cur.child_by_field_name("type"),
                    )
                {
                    let fname = ntxt(pat, src).trim();
                    let ty_raw = ntxt(ty, src).trim().trim_start_matches(':').trim();
                    if is_valid_ident(fname)
                        && let Some(clean) = clean_nominal_type(ty_raw)
                    {
                        field_types.insert(fname.to_string(), clean);
                    }
                }
            }
            "method_definition" | "method_signature" => {
                if let Some(nm) = cur.child_by_field_name("name") {
                    let m = ntxt(nm, src).trim();
                    if is_valid_ident(m) && m != "constructor" {
                        push_unique(methods, m.to_string());
                    }
                }
            }
            _ => {}
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            if !matches!(ch.kind(), "class_declaration" | "interface_declaration") {
                stack.push(ch);
            }
        }
    }
}

fn extract_rust_struct_fields(
    struct_node: Node,
    src: &[u8],
    field_types: &mut HashMap<String, String>,
) {
    let mut stack = vec![struct_node];
    while let Some(cur) = stack.pop() {
        if cur.kind() == "field_declaration"
            && let (Some(nm), Some(ty)) = (
                cur.child_by_field_name("name"),
                cur.child_by_field_name("type"),
            )
        {
            let fname = ntxt(nm, src).trim();
            if is_valid_ident(fname)
                && let Some(clean) = clean_nominal_type(ntxt(ty, src))
            {
                field_types.insert(fname.to_string(), clean);
            }
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            stack.push(ch);
        }
    }
}

fn extract_go_interface_methods(iface_node: Node, src: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![iface_node];
    while let Some(cur) = stack.pop() {
        if matches!(cur.kind(), "method_elem" | "method_spec")
            && let Some(nm) = cur.child_by_field_name("name")
        {
            let m = ntxt(nm, src).trim();
            if is_valid_ident(m) {
                push_unique(out, m.to_string());
            }
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            stack.push(ch);
        }
    }
}

fn extract_go_struct_fields(
    struct_node: Node,
    src: &[u8],
    field_types: &mut HashMap<String, String>,
    embedded: &mut Vec<String>,
) {
    let mut stack = vec![struct_node];
    while let Some(cur) = stack.pop() {
        if cur.kind() == "field_declaration" {
            let name_n = cur.child_by_field_name("name");
            let ty_n = cur.child_by_field_name("type");
            if let (Some(nm), Some(ty)) = (name_n, ty_n) {
                let fname = ntxt(nm, src).trim();
                if is_valid_ident(fname)
                    && let Some(clean) = clean_nominal_type(ntxt(ty, src))
                {
                    field_types.insert(fname.to_string(), clean);
                }
            } else if let Some(ty) = ty_n
                && let Some(clean) = clean_nominal_type(ntxt(ty, src))
            {
                push_unique(embedded, clean);
            }
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            stack.push(ch);
        }
    }
}

fn extract_go_method_receiver(recv_node: Node, src: &[u8]) -> Option<(String, String)> {
    let mut c = recv_node.walk();
    for ch in recv_node.named_children(&mut c) {
        if ch.kind() == "parameter_declaration" {
            let var_name = ch
                .child_by_field_name("name")
                .map(|n| ntxt(n, src).trim().to_string())
                .unwrap_or_default();
            if let Some(ty_n) = ch.child_by_field_name("type")
                && let Some(ty) = clean_nominal_type(ntxt(ty_n, src))
            {
                return Some((var_name, ty));
            }
        }
    }
    None
}

fn extract_python_self_field_types(
    class_node: Node,
    src: &[u8],
    field_types: &mut HashMap<String, String>,
) {
    let txt = ntxt(class_node, src);
    for line in txt.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("self.") {
            // `self.guard: AuthGuard = ...` or `self.guard = JwtGuard()`
            if let Some((lhs, rhs)) = rest.split_once(':')
                && is_valid_ident(lhs.trim())
                && let Some(ty) = clean_nominal_type(rhs.split('=').next().unwrap_or(rhs))
            {
                field_types.insert(lhs.trim().to_string(), ty);
            } else if let Some((lhs, rhs)) = rest.split_once('=')
                && is_valid_ident(lhs.trim())
                && let Some(ctor) = rhs.trim().split('(').next()
                && ctor.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
                && let Some(ty) = clean_nominal_type(ctor)
            {
                field_types.insert(lhs.trim().to_string(), ty);
            }
        }
    }
}

fn extract_generic_field_types(
    class_node: Node,
    src: &[u8],
    field_types: &mut HashMap<String, String>,
) {
    let mut stack = vec![class_node];
    while let Some(cur) = stack.pop() {
        if matches!(
            cur.kind(),
            "field_declaration" | "property_declaration" | "property_element"
        ) && let Some(ty_n) = cur.child_by_field_name("type")
            && let Some(clean_ty) = clean_nominal_type(ntxt(ty_n, src))
            && let Some(decl) = cur
                .child_by_field_name("declarator")
                .or_else(|| cur.child_by_field_name("name"))
        {
            let fname = ntxt(decl, src)
                .split(['=', ';', ' '])
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches('$');
            if is_valid_ident(fname) {
                field_types.insert(fname.to_string(), clean_ty);
            }
        }
        let mut c = cur.walk();
        for ch in cur.children(&mut c) {
            if !matches!(
                ch.kind(),
                "method_declaration" | "function_declaration" | "class_declaration"
            ) {
                stack.push(ch);
            }
        }
    }
}

fn collect_local_type_bindings(
    node: Node,
    src: &[u8],
    lang: Language,
    sym_line_spans: &[(usize, usize, usize)],
    per_sym_local_types: &mut [HashMap<String, String>],
    depth: usize,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let kind = node.kind();
    let line = node.start_position().row + 1;

    if let Some(sym_idx) = find_owning_symbol(line, sym_line_spans) {
        let map = &mut per_sym_local_types[sym_idx];
        match kind {
            // Typed parameters across TS, Rust, Go, Python, Java, C#, Kotlin, Swift, Dart
            "required_parameter"
            | "optional_parameter"
            | "parameter"
            | "formal_parameter"
            | "typed_parameter"
            | "typed_default_parameter"
            | "parameter_declaration" => {
                let name_node = node
                    .child_by_field_name("pattern")
                    .or_else(|| node.child_by_field_name("name"));
                let ty_node = node.child_by_field_name("type");
                if let (Some(nm), Some(ty)) = (name_node, ty_node) {
                    let var = ntxt(nm, src).trim().trim_start_matches('$');
                    let raw_ty = ntxt(ty, src).trim().trim_start_matches(':').trim();
                    if is_valid_ident(var)
                        && let Some(clean) = clean_nominal_type(raw_ty)
                    {
                        map.insert(var.to_string(), clean);
                    }
                } else if lang == Language::Python {
                    // `typed_parameter` in tree-sitter-python: child 0 is identifier, child `type` is type
                    let raw = ntxt(node, src);
                    if let Some((lhs, rhs)) = raw.split_once(':') {
                        let var = lhs.trim();
                        let raw_ty = rhs.split('=').next().unwrap_or(rhs).trim();
                        if is_valid_ident(var)
                            && let Some(clean) = clean_nominal_type(raw_ty)
                        {
                            map.insert(var.to_string(), clean);
                        }
                    }
                }
            }
            // Local variable declarations: `const repo: IUserRepo = new SqlRepo()`, `let g = JwtGuard::new()`
            "variable_declarator" | "let_declaration" | "short_var_declaration" | "assignment" => {
                let lhs_n = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    .or_else(|| node.child_by_field_name("left"));
                let rhs_n = node
                    .child_by_field_name("value")
                    .or_else(|| node.child_by_field_name("right"));
                let ty_n = node.child_by_field_name("type");

                if let Some(ln) = lhs_n {
                    let var = ntxt(ln, src).trim().trim_start_matches('$');
                    if is_valid_ident(var) {
                        if let Some(tn) = ty_n
                            && let Some(clean) =
                                clean_nominal_type(ntxt(tn, src).trim_start_matches(':'))
                        {
                            map.insert(var.to_string(), clean);
                        } else if let Some(rn) = rhs_n
                            && let Some(inferred) = infer_expr_type(rn, src, lang)
                        {
                            map.insert(var.to_string(), inferred);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_local_type_bindings(
            ch,
            src,
            lang,
            sym_line_spans,
            per_sym_local_types,
            depth + 1,
        );
    }
}

fn infer_expr_type(expr: Node, src: &[u8], lang: Language) -> Option<String> {
    let txt = ntxt(expr, src).trim();
    // `new Foo(...)`
    if let Some(rest) = txt.strip_prefix("new ") {
        let ctor = rest.split(['(', '<', '{', ' ']).next().unwrap_or("");
        return clean_nominal_type(ctor);
    }
    // Rust `Foo::new(...)` or `Arc::new(Foo::new())`
    if let Some((ty_part, rest)) = txt.split_once("::new(") {
        if ty_part.trim() == "Arc" || ty_part.trim() == "Box" || ty_part.trim() == "Rc" {
            let inner = rest.trim_end_matches(')').trim();
            if let Some((inner_ty, _)) = inner.split_once("::") {
                return clean_nominal_type(inner_ty);
            }
            return clean_nominal_type(inner);
        }
        return clean_nominal_type(ty_part);
    }
    // Go `&Foo{...}` or `Foo{...}` or `NewFoo(...)`
    if lang == Language::Go {
        if let Some(before_brace) = txt.split('{').next()
            && txt.contains('{')
        {
            return clean_nominal_type(before_brace);
        }
        if let Some(before_paren) = txt.split('(').next()
            && let Some(leaf) = before_paren.rsplit('.').next()
            && let Some(ty_rest) = leaf.strip_prefix("New")
            && ty_rest
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_uppercase())
        {
            return Some(ty_rest.to_string());
        }
    }
    // Python/Kotlin/Dart/Swift `Foo(...)`
    if matches!(
        lang,
        Language::Python | Language::Kotlin | Language::Dart | Language::Swift
    ) && txt.contains('(')
    {
        let head = txt.split('(').next().unwrap_or("").trim();
        let leaf = head.rsplit('.').next().unwrap_or(head);
        if leaf.bytes().next().is_some_and(|b| b.is_ascii_uppercase()) {
            return clean_nominal_type(leaf);
        }
    }
    None
}

fn split_qualified_callee(raw: &str) -> (Option<String>, String) {
    let cleaned = raw.trim();
    if let Some((q, m)) = cleaned.rsplit_once('.') {
        let m = m.trim();
        let q_clean = q.trim().trim_end_matches('?');
        // Preserve `this.repo` / `self.repo` when chained, otherwise take immediate receiver ident
        let qual = if q_clean.starts_with("this.") || q_clean.starts_with("self.") {
            q_clean.to_string()
        } else {
            q_clean
                .rsplit(['.', '(', ' ', '!', '?'])
                .next()
                .unwrap_or(q_clean)
                .trim()
                .to_string()
        };
        if !qual.is_empty() && is_valid_ident(m) {
            return (Some(qual), m.to_string());
        }
    }
    if let Some((q, m)) = cleaned.rsplit_once("::") {
        let m = m.trim();
        let qual = q.trim().rsplit("::").next().unwrap_or(q).trim();
        if !qual.is_empty() && is_valid_ident(m) {
            return (Some(qual.to_string()), m.to_string());
        }
    }
    if let Some((q, m)) = cleaned.rsplit_once("->") {
        let m = m.trim();
        let qual = q
            .trim()
            .rsplit("->")
            .next()
            .unwrap_or(q)
            .trim()
            .trim_start_matches('$');
        if !qual.is_empty() && is_valid_ident(m) {
            return (Some(qual.to_string()), m.to_string());
        }
    }
    (None, cleaned.to_string())
}

fn collect_qualified_call_sites(
    node: Node,
    src: &[u8],
    sym_line_spans: &[(usize, usize, usize)],
    per_sym_local_types: &[HashMap<String, String>],
    symbols: &mut [SymbolInfo],
    depth: usize,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    let kind = node.kind();
    let callee_raw: Option<String> = match kind {
        "call_expression" | "call" | "function_call_expression" | "invocation_expression" => {
            if let Some(f) = node.child_by_field_name("function") {
                Some(ntxt(f, src).trim().to_string())
            } else if let Some(m) = node.child_by_field_name("method") {
                let recv = node
                    .child_by_field_name("receiver")
                    .map(|r| format!("{}.{}", ntxt(r, src).trim(), ntxt(m, src).trim()));
                recv.or_else(|| Some(ntxt(m, src).trim().to_string()))
            } else {
                let mut c = node.walk();
                node.named_children(&mut c)
                    .next()
                    .map(|n| ntxt(n, src).trim().to_string())
            }
        }
        "method_invocation" | "member_call_expression" | "scoped_call_expression" => {
            let obj = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("scope"))
                .map(|o| ntxt(o, src).trim().to_string());
            let name = node
                .child_by_field_name("name")
                .map(|n| ntxt(n, src).trim().to_string());
            match (obj, name) {
                (Some(o), Some(n)) => Some(format!("{o}.{n}")),
                (None, Some(n)) => Some(n),
                _ => None,
            }
        }
        _ => None,
    };

    if let Some(raw) = callee_raw {
        let line = node.start_position().row + 1;
        if let Some(sym_idx) = find_owning_symbol(line, sym_line_spans) {
            let (qualifier, member) = split_qualified_callee(&raw);
            if is_valid_ident(&member) {
                let local_types = &per_sym_local_types[sym_idx];
                let resolved_recv_type = qualifier.as_deref().and_then(|q| {
                    if let Some(ty) = local_types.get(q) {
                        return Some(ty.clone());
                    }
                    if let Some(stripped) =
                        q.strip_prefix("this.").or_else(|| q.strip_prefix("self."))
                        && let Some(ty) = local_types.get(stripped)
                    {
                        return Some(ty.clone());
                    }
                    // Static type call: `UserRepo::save(...)` or `AuthGuard.verify(...)`
                    if q.bytes().next().is_some_and(|b| b.is_ascii_uppercase()) && is_valid_ident(q)
                    {
                        return clean_nominal_type(q);
                    }
                    None
                });

                let cs = CallSite {
                    qualifier,
                    member,
                    resolved_recv_type,
                    line,
                };
                let sites = &mut symbols[sym_idx].call_sites;
                if !sites.iter().any(|existing| {
                    existing.qualifier == cs.qualifier
                        && existing.member == cs.member
                        && existing.resolved_recv_type == cs.resolved_recv_type
                }) {
                    sites.push(cs);
                }
            }
        }
    }

    let mut c = node.walk();
    for ch in node.children(&mut c) {
        collect_qualified_call_sites(
            ch,
            src,
            sym_line_spans,
            per_sym_local_types,
            symbols,
            depth + 1,
        );
    }
}
