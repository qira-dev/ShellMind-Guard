pub mod concurrency;
pub mod mem_typestate;
pub mod memory;
pub mod mobile;
#[cfg(test)]
mod tests;

use crate::ast::{
    Confidence, DomainHints, FileAstSummary, GuardKind, LocalStaticFinding, SinkKind, SymbolInfo,
    SymbolKind, node_text,
};
use smg_core::Language;
use std::collections::HashSet;
use tree_sitter::Node;

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_phase9_finding(
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
        line,
        symbol: symbol.to_string(),
        sink_kind,
        missing_guard,
        confidence,
        remediation: remediation.to_string(),
    }
}

/// Checks whether a Rust AST `mod_item` or `function_item` is a `#[test]` or `#[cfg(test)]` item.
pub(crate) fn is_rust_test_subtree(node: Node, src: &[u8]) -> bool {
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

/// Computes lightweight per-file domain signals (`web`, `system_engine`, `mobile`)
/// used by Domain-Aware Analyzer Routing in `lattice.rs`.
pub fn detect_domain_hints(
    lang: Language,
    rel_path: &str,
    source: &str,
    symbols: &[SymbolInfo],
) -> DomainHints {
    let low_path = rel_path.to_ascii_lowercase();
    let low_src = source.to_ascii_lowercase();

    let has_routes = symbols.iter().any(|s| s.kind == SymbolKind::Route);
    let web_import = [
        "express",
        "fastify",
        "@nestjs/",
        "fastapi",
        "flask",
        "django",
        "gin-gonic",
        "net/http",
        "axum",
        "actix_web",
        "actix-web",
        "laravel",
        "symfony",
        "springframework",
        "aspnetcore",
        "rails",
        "sinatra",
        "ktor",
        "vapor",
        "package:shelf",
        "dart_frog",
        "crow_route",
        "httplib",
    ]
    .iter()
    .any(|kw| low_src.contains(kw));
    let web = has_routes || web_import;

    let fname = std::path::Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let is_mobile_cfg = matches!(
        fname,
        "AndroidManifest.xml" | "network_security_config.xml" | "Info.plist" | "Podfile"
    ) || (fname == "pubspec.yaml" && low_src.contains("flutter"))
        || (matches!(fname, "build.gradle" | "build.gradle.kts")
            && (low_src.contains("com.android.") || low_src.contains("android {")));

    let mobile_signal = is_mobile_cfg
        || low_path.contains("/android/app/")
        || low_path.contains("/ios/")
        || low_src.contains("import android.")
        || low_src.contains("import androidx.")
        || low_src.contains("import uikit")
        || low_src.contains("import swiftui")
        || low_src.contains("import package:flutter/")
        || low_src.contains("package:shared_preferences/")
        || low_src.contains("package:flutter_secure_storage/")
        || low_src.contains("encryptedsharedpreferences")
        || low_src.contains("userdefaults")
        || low_src.contains("secitemadd")
        || low_src.contains("badcertificatecallback")
        || low_src.contains("react-native")
        || low_src.contains("asyncstorage");

    let system_engine = matches!(lang, Language::C | Language::Cpp | Language::Rust)
        || [
            "std::mutex",
            "std::lock_guard",
            "std::unique_lock",
            "std::scoped_lock",
            "pthread_mutex",
            "tokio::sync::mutex",
            "parking_lot::",
            "sync.mutex",
            "reentrantlock",
            "unsafe {",
            "malloc(",
            "realloc(",
            "calloc(",
            "fopen(",
            "sqlite3_open(",
        ]
        .iter()
        .any(|kw| low_src.contains(kw));

    DomainHints {
        web,
        system_engine,
        mobile: mobile_signal,
    }
}

/// Resolves active repository domains from file summaries.
pub fn resolve_repo_domains(summaries: &[FileAstSummary]) -> Vec<String> {
    let mut web = false;
    let mut engine = false;
    let mut mobile = false;
    for f in summaries {
        web |= f.domain_hints.web || f.symbols.iter().any(|s| s.kind == SymbolKind::Route);
        engine |= f.domain_hints.system_engine
            || f.symbols
                .iter()
                .any(|s| !s.lock_pairs.is_empty() || !s.locks_acquired.is_empty());
        mobile |= f.domain_hints.mobile;
    }
    let mut domains = Vec::new();
    if web {
        domains.push("web".to_string());
    }
    if engine {
        domains.push("system_engine".to_string());
    }
    if mobile {
        domains.push("mobile".to_string());
    }
    domains
}

/// Filters domain-specific static findings so mobile-only checks do not fire on pure web/CLI backends
/// unless mobile context exists in the repository.
pub fn should_keep_finding_for_domain(
    sf: &LocalStaticFinding,
    repo_domains: &HashSet<&str>,
) -> bool {
    if sf.rule_id.starts_with("SMG-MOB-") {
        return repo_domains.contains("mobile");
    }
    true
}

/// Scans mobile manifest & security config files (`AndroidManifest.xml`, `network_security_config.xml`, `Info.plist`).
pub fn scan_mobile_config(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    mobile::scan_mobile_config(rel_path, source)
}

/// Runs Phase 9 AST analyses: Core-Engine concurrency/deadlocks/leaks, native memory/overflows, and mobile rules.
pub fn analyze_ast_phase9(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    symbols: &mut [SymbolInfo],
    static_findings: &mut Vec<LocalStaticFinding>,
) {
    concurrency::analyze_concurrency_and_leaks(root, src, rel_path, lang, symbols, static_findings);

    if matches!(lang, Language::C | Language::Cpp | Language::Rust) {
        memory::analyze_memory_and_overflows(root, src, rel_path, lang, static_findings);
        if let Ok(src_str) = std::str::from_utf8(src)
            && !smg_core::is_test_source_path(rel_path)
        {
            if matches!(lang, Language::C | Language::Cpp) {
                static_findings.extend(mem_typestate::analyze_c_cpp_memory_typestate(
                    rel_path, src_str,
                ));
            } else if matches!(lang, Language::Rust) {
                for hit in mem_typestate::analyze_rust_async_mutex_across_await(rel_path, src_str) {
                    let already_reported = static_findings.iter().any(|e| {
                        e.rel_path == hit.rel_path
                            && e.line == hit.line
                            && (e.rule_id == "SMG-ENG-DEADLOCK" || e.rule_id == hit.rule_id)
                    });
                    if !already_reported {
                        static_findings.push(hit);
                    }
                }
            }
        }
    }

    if matches!(
        lang,
        Language::Kotlin
            | Language::Java
            | Language::Swift
            | Language::Dart
            | Language::JavaScript
            | Language::TypeScript
    ) {
        mobile::analyze_mobile_ast(root, src, rel_path, lang, static_findings);
    }
}
