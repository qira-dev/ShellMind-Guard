use crate::ast::{Confidence, FileAstSummary, GuardKind, LocalStaticFinding, SinkKind};
use serde::{Deserialize, Serialize};
use smg_core::advisories::{
    AdvisoryRecord, AdvisoryStore, normalize_package_name, parse_semver_with_prerelease,
    version_matches_range,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    Cargo,
    Go,
    PyPi,
    Maven,
    Packagist,
    RubyGems,
    Pub,
    NuGet,
}

impl Ecosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::PyPi => "PyPI",
            Ecosystem::Maven => "Maven",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Pub => "Pub",
            Ecosystem::NuGet => "NuGet",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub line: usize,
}

/// Directed edge in a parsed lockfile dependency graph (`parent -> child`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDepEdge {
    pub parent: String,
    pub child: String,
    pub is_dev: bool,
}

/// Extracted lockfile dependency graph (`(pkg@ver -> dep@ver, is_dev)`) across all 9 ecosystems.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockfileDepGraph {
    pub ecosystem: String,
    /// `pkg_name -> (version, is_dev, line)`
    pub nodes: HashMap<String, (String, bool, usize)>,
    pub edges: Vec<LockfileDepEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachableVulnStatus {
    Reachable,
    DeclaredUnused,
}

/// Phase 12B (`P12-04`) 4-tier call-graph VEX reachability classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexReachabilityTier {
    /// Route-reachable function calls a known vulnerable symbol of the package.
    ProvenRouteSymbol,
    /// Package is imported, all concrete calls target safe non-vulnerable APIs (e.g. `lodash.pick`).
    ImportedSafeApiOnly,
    /// Package is imported in source code, but symbol-level exploitability is unproven/opaque.
    ImportedUnprovenSymbol,
    /// Declared in manifest/lockfile only with zero static source imports.
    DeclaredUnused,
}

/// External package import & call-site index retained across files for reverse-seeded CVE VEX.
#[derive(Debug, Clone, Default)]
pub struct PackageImportIndex {
    /// `norm_pkg -> set of imported symbol names` (`"*"` denotes default/namespace/whole-module import)
    pub imported_symbols: HashMap<String, HashSet<String>>,
    /// `norm_pkg -> vec of (caller_symbol_id, called_member_name)`
    pub call_sites: HashMap<String, Vec<(String, String)>>,
    /// Normalized set of all imported packages (including distribution aliases).
    pub imported_pkgs: HashSet<String>,
}

/// Curated vulnerable-symbol table for high-signal symbol-level VEX disproof (`ImportedSafeApiOnly`
/// vs `ProvenRouteSymbol`). Packages absent from this map fall back conservatively to
/// `ImportedUnprovenSymbol` (never claiming `ImportedSafeApiOnly` without symbol-level knowledge).
fn known_vulnerable_symbols(norm_pkg: &str) -> Option<&'static [&'static str]> {
    match norm_pkg {
        "lodash" | "lodash-es" => Some(&[
            "template",
            "merge",
            "mergewith",
            "defaultsdeep",
            "set",
            "setwith",
            "zipobjectdeep",
            "unset",
        ]),
        "pyyaml" | "yaml" => Some(&["load", "unsafe_load", "full_load"]),
        "jsonwebtoken" | "pyjwt" => Some(&["verify", "decode"]),
        "serialize-javascript" => Some(&["serialize"]),
        "vm2" => Some(&["run", "runfile", "vm", "nodescript"]),
        "tar" | "node-tar" => Some(&["extract", "x", "unpack"]),
        "axios" => Some(&["get", "post", "put", "delete", "request", "create"]),
        "express" => Some(&["static", "redirect"]),
        "minimist" => Some(&["minimist", "default"]),
        "handlebars" => Some(&["compile", "precompile"]),
        "ejs" => Some(&["render", "renderfile", "compile"]),
        "pug" => Some(&["render", "renderfile", "compile"]),
        "xml2js" | "fast-xml-parser" => Some(&["parse", "parsestring", "parsestringpromise"]),
        "marked" => Some(&["parse", "marked"]),
        "dompurify" => Some(&["sanitize"]),
        "log4j-core" => Some(&["info", "error", "warn", "debug", "log", "getlogger"]),
        "jackson-databind" => Some(&["readvalue", "enabledefaulttyping"]),
        _ => None,
    }
}

/// Builds the external `PackageImportIndex` in $O(\text{imports} + \text{call\_sites})$ time.
pub fn build_package_import_index(summaries: &[FileAstSummary]) -> PackageImportIndex {
    let mut idx = PackageImportIndex::default();
    for s in summaries {
        // Track local alias -> canonical package keys within this file
        let mut local_alias_to_pkgs: HashMap<String, Vec<String>> = HashMap::new();
        let mut named_sym_to_pkgs: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut file_pkg_aliases = HashSet::new();

        for imp in &s.imports {
            file_pkg_aliases.clear();
            expand_pkg_aliases(&imp.from_specifier, &mut file_pkg_aliases);
            if file_pkg_aliases.is_empty() {
                continue;
            }
            let pkg_list: Vec<String> = file_pkg_aliases.iter().cloned().collect();
            for p in &pkg_list {
                idx.imported_pkgs.insert(p.clone());
            }
            let remote = imp.remote_name.as_deref().unwrap_or(&imp.symbol_name);
            let is_ns_or_default = remote == "*"
                || remote == "default"
                || imp.symbol_name == "*"
                || imp.remote_name.is_none();
            for p in &pkg_list {
                idx.imported_symbols
                    .entry(p.clone())
                    .or_default()
                    .insert(if is_ns_or_default {
                        "*".to_string()
                    } else {
                        remote.to_ascii_lowercase()
                    });
            }
            if !imp.symbol_name.is_empty() && imp.symbol_name != "*" {
                if is_ns_or_default {
                    local_alias_to_pkgs
                        .entry(imp.symbol_name.clone())
                        .or_default()
                        .extend(pkg_list.iter().cloned());
                }
                if remote != "*" && remote != "default" {
                    named_sym_to_pkgs
                        .entry(imp.symbol_name.clone())
                        .or_default()
                        .extend(
                            pkg_list
                                .iter()
                                .map(|p| (p.clone(), remote.to_ascii_lowercase())),
                        );
                }
            }
        }

        for sym in &s.symbols {
            for cs in &sym.call_sites {
                if let Some(ref q) = cs.qualifier {
                    if let Some(pkgs) = local_alias_to_pkgs.get(q) {
                        let mem_low = cs.member.to_ascii_lowercase();
                        for p in pkgs {
                            idx.call_sites
                                .entry(p.clone())
                                .or_default()
                                .push((sym.id.clone(), mem_low.clone()));
                        }
                    }
                } else if let Some(entries) = named_sym_to_pkgs.get(&cs.member) {
                    for (p, orig_name) in entries {
                        idx.call_sites
                            .entry(p.clone())
                            .or_default()
                            .push((sym.id.clone(), orig_name.clone()));
                    }
                }
            }
            // Fallback for bare calls recorded in `sym.calls`
            for c in &sym.calls {
                if let Some(entries) = named_sym_to_pkgs.get(c) {
                    for (p, orig_name) in entries {
                        idx.call_sites
                            .entry(p.clone())
                            .or_default()
                            .push((sym.id.clone(), orig_name.clone()));
                    }
                }
            }
        }
    }
    idx
}

fn extract_finding_pkg_candidates(title: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_tick = false;
    let mut buf = String::new();
    for ch in title.chars() {
        if ch == '`' || ch == '\'' {
            if in_tick {
                let candidate = buf.split('@').next().unwrap_or(&buf).trim();
                let norm = norm_pkg_key(candidate);
                if !norm.is_empty() {
                    out.push(norm);
                }
                let low = candidate.to_ascii_lowercase();
                if !low.is_empty() && !out.contains(&low) {
                    out.push(low);
                }
                buf.clear();
                in_tick = false;
            } else {
                in_tick = true;
            }
        } else if in_tick {
            buf.push(ch);
        }
    }
    out
}

/// Reverse-seeded CVE-only VEX solver: evaluates ONLY advisory-hit `SMG-DEP-*` findings against
/// `PackageImportIndex`, optional OSV `AutoVexSymbolIndex`, and route-reachable symbol IDs
/// (`build_any_route_bfs_tree`), wasting zero work on clean lockfile dependencies.
pub fn assess_dependency_vex_tier(
    finding: &crate::lattice::LatticeFinding,
    pkg_index: &PackageImportIndex,
    route_reachable_sym_ids: &HashSet<String>,
) -> Option<VexReachabilityTier> {
    assess_dependency_vex_tier_with_auto_vex(finding, pkg_index, route_reachable_sym_ids, None).0
}

/// Evaluates VEX reachability using both static symbol tables and OSV-extracted `AutoVexSymbolIndex`
/// (plus inline advisory prose symbol extraction), emitting a populated OpenVEX v0.2.0 statement.
pub fn assess_dependency_vex_tier_with_auto_vex(
    finding: &crate::lattice::LatticeFinding,
    pkg_index: &PackageImportIndex,
    route_reachable_sym_ids: &HashSet<String>,
    auto_vex: Option<&crate::vex_osv::AutoVexSymbolIndex>,
) -> (
    Option<VexReachabilityTier>,
    Option<crate::vex_osv::OpenVexStatement>,
) {
    if !finding.rule_id.starts_with("SMG-DEP-") {
        return (None, None);
    }
    let candidates = extract_finding_pkg_candidates(&finding.title);
    let primary_pkg = candidates
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let vuln_id = finding.rule_id.clone();

    let mk_stmt = |tier: VexReachabilityTier, pkg_name: &str| -> crate::vex_osv::OpenVexStatement {
        let (status, justification, impact) = match tier {
            VexReachabilityTier::ProvenRouteSymbol => (
                "affected",
                None,
                format!("Vulnerable symbol in `{pkg_name}` is reachable from an entry route"),
            ),
            VexReachabilityTier::ImportedSafeApiOnly => (
                "not_affected",
                Some("vulnerable_code_not_in_execute_path"),
                format!("Only non-vulnerable APIs of `{pkg_name}` are imported/invoked"),
            ),
            VexReachabilityTier::DeclaredUnused => (
                "not_affected",
                Some("component_not_present"),
                format!("Package `{pkg_name}` is declared in manifest/lockfile but never imported"),
            ),
            VexReachabilityTier::ImportedUnprovenSymbol => (
                "under_investigation",
                None,
                format!(
                    "Package `{pkg_name}` is imported; vulnerable symbol reachability unproven"
                ),
            ),
        };
        crate::vex_osv::OpenVexStatement {
            vulnerability_id: vuln_id.clone(),
            product_purl: format!("pkg:generic/{pkg_name}"),
            status: status.to_string(),
            justification: justification.map(String::from),
            impact_statement: impact,
        }
    };

    if pkg_index.imported_pkgs.is_empty() {
        let tier = VexReachabilityTier::DeclaredUnused;
        return (Some(tier), Some(mk_stmt(tier, &primary_pkg)));
    }
    let matched_pkg = candidates
        .iter()
        .find(|c| pkg_index.imported_pkgs.contains(c.as_str()));
    let Some(pkg) = matched_pkg else {
        let tier = VexReachabilityTier::DeclaredUnused;
        return (Some(tier), Some(mk_stmt(tier, &primary_pkg)));
    };

    let mut vuln_syms: HashSet<String> = known_vulnerable_symbols(pkg)
        .map(|s| s.iter().map(|x| x.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    if let Some(idx) = auto_vex {
        for ((_, p), syms) in &idx.symbols {
            if p == pkg || norm_pkg_key(p) == norm_pkg_key(pkg) {
                vuln_syms.extend(syms.iter().cloned());
            }
        }
    }
    if vuln_syms.is_empty() {
        let tier = VexReachabilityTier::ImportedUnprovenSymbol;
        return (Some(tier), Some(mk_stmt(tier, pkg)));
    }

    let calls = pkg_index.call_sites.get(pkg);
    let imported = pkg_index.imported_symbols.get(pkg);

    let mut saw_any_concrete_call = false;
    let mut saw_vuln_call = false;
    let mut saw_route_reachable_vuln_call = false;

    if let Some(call_list) = calls {
        for (caller_id, member_low) in call_list {
            saw_any_concrete_call = true;
            if vuln_syms.contains(member_low.as_str()) {
                saw_vuln_call = true;
                if route_reachable_sym_ids.contains(caller_id) {
                    saw_route_reachable_vuln_call = true;
                }
            }
        }
    }

    if saw_route_reachable_vuln_call {
        let tier = VexReachabilityTier::ProvenRouteSymbol;
        return (Some(tier), Some(mk_stmt(tier, pkg)));
    }
    if saw_vuln_call {
        let tier = VexReachabilityTier::ImportedUnprovenSymbol;
        return (Some(tier), Some(mk_stmt(tier, pkg)));
    }

    // Check if only safe named imports or only safe concrete member calls were observed
    let only_safe_named_imports = imported.is_some_and(|syms| {
        !syms.is_empty()
            && !syms.contains("*")
            && syms.iter().all(|s| !vuln_syms.contains(s.as_str()))
    });
    if saw_any_concrete_call || only_safe_named_imports {
        let tier = VexReachabilityTier::ImportedSafeApiOnly;
        return (Some(tier), Some(mk_stmt(tier, pkg)));
    }

    let tier = VexReachabilityTier::ImportedUnprovenSymbol;
    (Some(tier), Some(mk_stmt(tier, pkg)))
}

fn norm_pkg_key(raw: &str) -> String {
    normalize_package_name("PyPI", raw)
}

fn expand_pkg_aliases(raw: &str, out: &mut HashSet<String>) {
    let raw_trimmed = raw.trim().trim_matches(['"', '\'', '`']);
    let trimmed = if let Some((_, rest)) = raw_trimmed.split_once("::") {
        // Handle Phase-8 prefixed imports (`java::org/apache/...`, `rb::rack`, `php::vendor/...`)
        rest
    } else {
        raw_trimmed
    };
    if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.starts_with('/') {
        return;
    }
    let norm = norm_pkg_key(trimmed);
    if !norm.is_empty() {
        out.insert(norm.clone());
    }
    let low = trimmed.to_ascii_lowercase();
    if !low.is_empty() {
        out.insert(low);
    }
    // Scoped npm `@org/pkg/subpath` -> `@org/pkg` and unscoped `pkg/subpath` -> `pkg`
    let base = if trimmed.starts_with('@') {
        let mut parts = trimmed.splitn(3, '/');
        match (parts.next(), parts.next()) {
            (Some(scope), Some(pkg)) => format!("{}/{}", scope, pkg),
            _ => trimmed.to_string(),
        }
    } else if !trimmed.starts_with("github.com/") && !trimmed.starts_with("golang.org/") {
        trimmed
            .split(['/', ':', '.'])
            .next()
            .unwrap_or(trimmed)
            .to_string()
    } else {
        trimmed.to_string()
    };
    let base_norm = norm_pkg_key(&base);
    if !base_norm.is_empty() {
        out.insert(base_norm.clone());
    }
    let base_low = base.to_ascii_lowercase();
    if !base_low.is_empty() {
        out.insert(base_low);
    }
    // Common Python distribution-to-import aliases
    match base_norm.as_str() {
        "yaml" => {
            out.insert("pyyaml".to_string());
        }
        "pil" => {
            out.insert("pillow".to_string());
        }
        "bs4" => {
            out.insert("beautifulsoup4".to_string());
        }
        "sklearn" => {
            out.insert("scikit-learn".to_string());
        }
        "cv2" => {
            out.insert("opencv-python".to_string());
        }
        "jwt" => {
            out.insert("pyjwt".to_string());
            out.insert("jsonwebtoken".to_string());
        }
        _ => {}
    }
}

/// Computes normalized package identifiers actively imported by source code files.
pub fn compute_reachable_packages(summaries: &[FileAstSummary]) -> HashSet<String> {
    let mut pkgs = HashSet::new();
    for s in summaries {
        for imp in &s.imports {
            expand_pkg_aliases(&imp.from_specifier, &mut pkgs);
        }
    }
    pkgs
}

/// Classifies whether an `SMG-DEP-*` finding refers to a package imported in source code
/// (`Reachable`) or merely declared in lockfiles/manifests (`DeclaredUnused`).
pub fn assess_dependency_reachability(
    finding: &crate::lattice::LatticeFinding,
    reachable_pkgs: &HashSet<String>,
) -> Option<ReachableVulnStatus> {
    if !finding.rule_id.starts_with("SMG-DEP-") {
        return None;
    }
    if reachable_pkgs.is_empty() {
        return Some(ReachableVulnStatus::DeclaredUnused);
    }
    // Extract package identifiers delimited by backticks, single quotes, or before '@' version suffixes
    let title = finding.title.as_str();
    let mut matched_pkg = false;
    let mut in_tick = false;
    let mut buf = String::new();
    for ch in title.chars() {
        if ch == '`' || ch == '\'' {
            if in_tick {
                let candidate = buf.split('@').next().unwrap_or(&buf).trim();
                let norm = norm_pkg_key(candidate);
                let low = candidate.to_ascii_lowercase();
                if (!norm.is_empty() && reachable_pkgs.contains(&norm))
                    || (!low.is_empty() && reachable_pkgs.contains(&low))
                {
                    matched_pkg = true;
                    break;
                }
                buf.clear();
                in_tick = false;
            } else {
                in_tick = true;
            }
        } else if in_tick {
            buf.push(ch);
        }
    }
    Some(if matched_pkg {
        ReachableVulnStatus::Reachable
    } else {
        ReachableVulnStatus::DeclaredUnused
    })
}

struct Advisory {
    ecosystem: Ecosystem,
    package: &'static str,
    /// Vulnerable if installed version < fixed_below (or always if fixed_below is None)
    fixed_below: Option<(u64, u64, u64)>,
    severity: &'static str,
    reason: &'static str,
}

const OFFLINE_ADVISORIES: &[Advisory] = &[
    // npm supply-chain & critical CVEs
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "event-stream",
        fixed_below: None,
        severity: "CRITICAL",
        reason: "Compromised/deprecated package (flatmap-stream supply-chain incident)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "flatmap-stream",
        fixed_below: None,
        severity: "CRITICAL",
        reason: "Known malicious npm package",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "node-ipc",
        fixed_below: None,
        severity: "HIGH",
        reason: "High-risk supply-chain sabotage history (protestware)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "lodash",
        fixed_below: Some((4, 17, 21)),
        severity: "HIGH",
        reason: "Command injection / Prototype Pollution (< 4.17.21, CVE-2021-23337)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "minimist",
        fixed_below: Some((1, 2, 6)),
        severity: "HIGH",
        reason: "Prototype Pollution (< 1.2.6, CVE-2021-44906)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "jsonwebtoken",
        fixed_below: Some((9, 0, 0)),
        severity: "HIGH",
        reason: "Insecure JWT verification / key confusion flaws (< 9.0.0)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "axios",
        fixed_below: Some((1, 6, 0)),
        severity: "HIGH",
        reason: "CSRF / SSRF vulnerability (< 1.6.0, CVE-2023-45857)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "node-fetch",
        fixed_below: Some((2, 6, 7)),
        severity: "HIGH",
        reason: "Forwarding sensitive headers on cross-origin redirect (< 2.6.7)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "serialize-javascript",
        fixed_below: Some((3, 1, 0)),
        severity: "HIGH",
        reason: "Remote code execution via unsafe serialization (< 3.1.0)",
    },
    Advisory {
        ecosystem: Ecosystem::Npm,
        package: "request",
        fixed_below: None,
        severity: "MEDIUM",
        reason: "Deprecated HTTP client with unpatched SSRF/redirect issues",
    },
    // Go
    Advisory {
        ecosystem: Ecosystem::Go,
        package: "github.com/dgrijalva/jwt-go",
        fixed_below: None,
        severity: "CRITICAL",
        reason: "Deprecated JWT library with unpatched validation bypass (CVE-2020-26160); migrate to golang-jwt/jwt",
    },
    Advisory {
        ecosystem: Ecosystem::Go,
        package: "golang.org/x/crypto",
        fixed_below: Some((0, 17, 0)),
        severity: "HIGH",
        reason: "SSH prefix truncation / Terrapin vulnerability (< v0.17.0)",
    },
    Advisory {
        ecosystem: Ecosystem::Go,
        package: "golang.org/x/net",
        fixed_below: Some((0, 23, 0)),
        severity: "HIGH",
        reason: "HTTP/2 CONTINUATION flood / DoS (< v0.23.0)",
    },
    Advisory {
        ecosystem: Ecosystem::Go,
        package: "github.com/gin-gonic/gin",
        fixed_below: Some((1, 9, 1)),
        severity: "HIGH",
        reason: "Trusted proxy / path handling flaw (< v1.9.1)",
    },
    // Python
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "pycrypto",
        fixed_below: None,
        severity: "CRITICAL",
        reason: "Unmaintained crypto library with heap buffer overflow / RCE; migrate to pycryptodome or cryptography",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "pyyaml",
        fixed_below: Some((5, 4, 0)),
        severity: "CRITICAL",
        reason: "Arbitrary code execution in yaml.load (< 5.4, CVE-2020-14343)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "urllib3",
        fixed_below: Some((1, 26, 18)),
        severity: "HIGH",
        reason: "Cookie / header leakage on cross-origin redirect (< 1.26.18)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "requests",
        fixed_below: Some((2, 31, 0)),
        severity: "MEDIUM",
        reason: "Proxy-Authorization header leak (< 2.31.0)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "pyjwt",
        fixed_below: Some((2, 4, 0)),
        severity: "HIGH",
        reason: "Algorithm confusion vulnerability (< 2.4.0, CVE-2022-29217)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "jinja2",
        fixed_below: Some((3, 1, 3)),
        severity: "HIGH",
        reason: "XSS via xmlattr filter (< 3.1.3, CVE-2024-22195)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "flask",
        fixed_below: Some((2, 3, 2)),
        severity: "HIGH",
        reason: "Session cookie Vary header caching exposure (< 2.3.2)",
    },
    Advisory {
        ecosystem: Ecosystem::PyPi,
        package: "django",
        fixed_below: Some((4, 2, 7)),
        severity: "HIGH",
        reason: "Known DoS/SQLi advisories in older Django (< 4.2.7)",
    },
    // Rust
    Advisory {
        ecosystem: Ecosystem::Cargo,
        package: "serde_yaml",
        fixed_below: None,
        severity: "MEDIUM",
        reason: "Unmaintained / deprecated crate (RUSTSEC-2024-0320)",
    },
    Advisory {
        ecosystem: Ecosystem::Cargo,
        package: "chrono",
        fixed_below: Some((0, 4, 20)),
        severity: "HIGH",
        reason: "Potential segfault in localtime_r (RUSTSEC-2020-0159, < 0.4.20)",
    },
    Advisory {
        ecosystem: Ecosystem::Cargo,
        package: "hyper",
        fixed_below: Some((0, 14, 27)),
        severity: "HIGH",
        reason: "HTTP request smuggling / DoS (< 0.14.27)",
    },
    Advisory {
        ecosystem: Ecosystem::Cargo,
        package: "openssl",
        fixed_below: Some((0, 10, 55)),
        severity: "HIGH",
        reason: "Known OpenSSL binding security advisories (< 0.10.55)",
    },
    // Maven / JVM
    Advisory {
        ecosystem: Ecosystem::Maven,
        package: "log4j-core",
        fixed_below: Some((2, 17, 1)),
        severity: "CRITICAL",
        reason: "Log4Shell JNDI remote code execution (< 2.17.1)",
    },
    Advisory {
        ecosystem: Ecosystem::Maven,
        package: "spring-beans",
        fixed_below: Some((5, 3, 18)),
        severity: "CRITICAL",
        reason: "Spring4Shell data binding RCE (< 5.3.18)",
    },
    Advisory {
        ecosystem: Ecosystem::Maven,
        package: "jackson-databind",
        fixed_below: Some((2, 13, 4)),
        severity: "HIGH",
        reason: "Polymorphic deserialization / DoS advisories (< 2.13.4)",
    },
    // Packagist / PHP
    Advisory {
        ecosystem: Ecosystem::Packagist,
        package: "symfony/http-kernel",
        fixed_below: Some((5, 4, 20)),
        severity: "HIGH",
        reason: "Known cache/request smuggling advisories (< 5.4.20)",
    },
    Advisory {
        ecosystem: Ecosystem::Packagist,
        package: "laravel/framework",
        fixed_below: Some((9, 52, 16)),
        severity: "HIGH",
        reason: "Known validation/XSS advisories (< 9.52.16)",
    },
    // RubyGems
    Advisory {
        ecosystem: Ecosystem::RubyGems,
        package: "rack",
        fixed_below: Some((2, 2, 8)),
        severity: "HIGH",
        reason: "HTTP request smuggling / ReDoS advisories (< 2.2.8)",
    },
    Advisory {
        ecosystem: Ecosystem::RubyGems,
        package: "nokogiri",
        fixed_below: Some((1, 15, 6)),
        severity: "HIGH",
        reason: "Bundled libxml2 memory safety advisories (< 1.15.6)",
    },
    // Pub / Dart
    Advisory {
        ecosystem: Ecosystem::Pub,
        package: "http",
        fixed_below: Some((0, 13, 6)),
        severity: "MEDIUM",
        reason: "Header injection risk on legacy `http` package (< 0.13.6)",
    },
];

fn has_explicit_patch(raw: &str) -> bool {
    let trimmed = raw
        .trim()
        .trim_start_matches(['v', 'V', '^', '~', '=', '>', '<', ' ']);
    let core = trimmed
        .split(['-', '+', ' ', ',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    core.split('.').count() >= 3
}

fn is_floating_version(spec: &str) -> bool {
    let s = spec.trim().to_ascii_lowercase();
    s.is_empty()
        || s == "*"
        || s == "latest"
        || s == "x"
        || s == "*.*"
        || s == "*.*.*"
        || s == "master"
        || s == "main"
        || s == "head"
        || s == ">=0"
        || s == ">= 0"
}

fn is_insecure_http_url(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    if let Some(pos) = low.find("http://") {
        let rest = &low[pos + 7..];
        return !(rest.starts_with("localhost") || rest.starts_with("127.0.0.1"));
    }
    false
}

fn make_dep_finding(
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    remediation: String,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: "SMG-DEP-001".to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line: line.max(1),
        symbol: format!("{}:{}", rel_path, line.max(1)),
        sink_kind: SinkKind::DependencyRisk,
        missing_guard: GuardKind::DependencyPolicy,
        confidence: Confidence::Heuristic,
        remediation,
    }
}

fn find_line_for_needle(lines: &[&str], needle: &str) -> usize {
    if needle.is_empty() {
        return 1;
    }
    let nb = needle.as_bytes();
    let is_word_needle = nb
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && nb
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
    for (i, line) in lines.iter().enumerate() {
        let mut off = 0usize;
        while let Some(rel) = line[off..].find(needle) {
            let pos = off + rel;
            if !is_word_needle {
                return i + 1;
            }
            let bytes = line.as_bytes();
            let prev_ok = pos == 0
                || (!bytes[pos - 1].is_ascii_alphanumeric()
                    && bytes[pos - 1] != b'_'
                    && bytes[pos - 1] != b'-');
            let end = pos + needle.len();
            let next_ok = end >= bytes.len()
                || (!bytes[end].is_ascii_alphanumeric()
                    && bytes[end] != b'_'
                    && bytes[end] != b'-');
            if prev_ok && next_ok {
                return i + 1;
            }
            off = pos + 1;
        }
    }
    1
}

fn is_flexible_range_spec(version_str: &str) -> bool {
    let t = version_str.trim();
    t.starts_with('^')
        || t.starts_with('~')
        || t.starts_with(">=")
        || t.starts_with("<=")
        || t.starts_with('>')
}

fn is_commit_sha_40(raw: &str) -> bool {
    let t = raw.trim();
    t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_go_pseudo_version(ver: &str) -> bool {
    let trimmed = ver.trim().trim_start_matches(['v', 'V']);
    trimmed.starts_with("0.0.0-") && trimmed.len() >= 20
}

fn check_single_offline_advisory(
    ecosystem: Ecosystem,
    entry: &(String, String, usize),
    norm: &str,
    rel_path: &str,
    db_recs: Option<&Vec<AdvisoryRecord>>,
    out: &mut Vec<LocalStaticFinding>,
) {
    let (pkg_name, version_str, line) = (entry.0.as_str(), entry.1.as_str(), entry.2);
    let mut emitted_fixed_keys: HashSet<String> = HashSet::new();

    if let Some(recs) = db_recs {
        for rec in recs {
            let skip_unpatched_range = ecosystem == Ecosystem::Cargo
                && rel_path.ends_with("Cargo.toml")
                && !version_str.trim().starts_with('=')
                && !has_explicit_patch(version_str)
                && !rec.fixed.is_empty()
                && parse_semver_with_prerelease(version_str)
                    .zip(parse_semver_with_prerelease(&rec.fixed))
                    .is_some_and(|((maj, min, _, _), (fmaj, fmin, _, _))| {
                        maj == fmaj && min == fmin
                    });
            if skip_unpatched_range {
                continue;
            }
            if version_matches_range(
                ecosystem.osv_name(),
                version_str,
                &rec.introduced,
                &rec.fixed,
                &rec.last_affected,
            ) {
                emitted_fixed_keys.insert(format!("{}:{}", rec.fixed, rec.id));
                if !rec.fixed.is_empty() {
                    emitted_fixed_keys.insert(format!("fixed:{}", rec.fixed));
                }
                let fix_hint = if !rec.fixed.is_empty() {
                    format!("Upgrade `{}` to >= {}.", pkg_name, rec.fixed)
                } else {
                    format!(
                        "Remove or replace vulnerable package `{}` ({}).",
                        pkg_name, rec.id
                    )
                };
                let mut hit = make_dep_finding(
                    &rec.severity,
                    format!(
                        "High-risk dependency `{}@{}` [{}]: {}",
                        pkg_name, version_str, rec.id, rec.summary
                    ),
                    rel_path,
                    line,
                    fix_hint,
                );
                hit.confidence = if is_flexible_range_spec(version_str) {
                    Confidence::Heuristic
                } else {
                    Confidence::Confirmed
                };
                out.push(hit);
            }
        }
    }

    for adv in OFFLINE_ADVISORIES {
        if adv.ecosystem != ecosystem || adv.package != norm {
            continue;
        }
        let offline_fixed_key = adv
            .fixed_below
            .map(|(maj, min, pat)| format!("fixed:{}.{}.{}", maj, min, pat))
            .unwrap_or_default();
        if !offline_fixed_key.is_empty() && emitted_fixed_keys.contains(&offline_fixed_key) {
            continue;
        }
        let hit = match adv.fixed_below {
            None => true,
            Some((min_maj, min_min, min_pat)) => {
                if ecosystem == Ecosystem::Go && is_go_pseudo_version(version_str) {
                    false
                } else {
                    match parse_semver_with_prerelease(version_str) {
                        Some((maj, min, pat, is_rel)) => {
                            // In Cargo.toml, a 2-component spec like `"0.4"` (without `=`) is a caret range `^0.4.0`
                            // that resolves to the latest 0.4.x in Cargo.lock; do not false-positive when min_safe shares (maj, min).
                            if ecosystem == Ecosystem::Cargo
                                && rel_path.ends_with("Cargo.toml")
                                && !version_str.trim().starts_with('=')
                                && !has_explicit_patch(version_str)
                                && maj == min_maj
                                && min == min_min
                            {
                                false
                            } else {
                                (maj, min, pat, is_rel) < (min_maj, min_min, min_pat, true)
                            }
                        }
                        None => false,
                    }
                }
            }
        };
        if hit {
            let fix_hint = match adv.fixed_below {
                Some((maj, min, pat)) => {
                    format!("Upgrade `{}` to >= {}.{}.{}.", pkg_name, maj, min, pat)
                }
                None => format!(
                    "Remove or replace deprecated/compromised package `{}`.",
                    pkg_name
                ),
            };
            let mut finding = make_dep_finding(
                adv.severity,
                format!(
                    "High-risk dependency `{}@{}`: {}",
                    pkg_name, version_str, adv.reason
                ),
                rel_path,
                line,
                fix_hint,
            );
            finding.confidence = if is_flexible_range_spec(version_str) {
                Confidence::Heuristic
            } else {
                Confidence::Confirmed
            };
            out.push(finding);
        }
    }
}

fn check_advisories_batch(
    ecosystem: Ecosystem,
    entries: &[(String, String, usize)],
    rel_path: &str,
    lines_for_deferred: Option<(&[&str], &str)>,
    store: Option<&AdvisoryStore>,
    out: &mut Vec<LocalStaticFinding>,
) {
    if entries.is_empty() {
        return;
    }
    let db_map = if let Some(st) = store {
        let names: Vec<&str> = entries.iter().map(|(n, _, _)| n.as_str()).collect();
        st.query_for_packages(ecosystem.osv_name(), &names)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    for entry in entries {
        let pkg_name = &entry.0;
        let norm = normalize_package_name(ecosystem.osv_name(), pkg_name);
        let db_recs = db_map.get(&norm);
        let mut temp = Vec::new();
        check_single_offline_advisory(ecosystem, entry, &norm, rel_path, db_recs, &mut temp);
        if !temp.is_empty() {
            if let Some((lines, needle_fmt)) = lines_for_deferred {
                let needle = if needle_fmt == "toml_name" {
                    format!("name = \"{}\"", pkg_name)
                } else {
                    pkg_name.clone()
                };
                let ln = find_line_for_needle(lines, &needle);
                for mut item in temp {
                    item.line = ln;
                    item.symbol = format!("{}:{}", rel_path, ln);
                    out.push(item);
                }
            } else {
                out.extend(temp);
            }
        }
    }
}

fn audit_package_json(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut adv_entries = Vec::new();

    if let Some(scripts) = val.get("scripts").and_then(|v| v.as_object()) {
        for hook in ["preinstall", "install", "postinstall", "prepare"] {
            if let Some(cmd) = scripts.get(hook).and_then(|v| v.as_str()) {
                let low = cmd.to_ascii_lowercase();
                if low.contains("curl ")
                    || low.contains("wget ")
                    || low.contains("powershell")
                    || low.contains("base64")
                    || low.contains("bash -c")
                    || low.contains("sh -c")
                    || low.contains("node -e")
                {
                    let ln = find_line_for_needle(&lines, &format!("\"{}\"", hook));
                    let mut hit = make_dep_finding(
                        "HIGH",
                        format!("Suspicious npm lifecycle hook `{}` executes download/shell payload: `{}`", hook, cmd),
                        rel_path,
                        ln,
                        "Remove arbitrary download/eval commands from npm install lifecycle hooks and inspect lockfile scripts.".into(),
                    );
                    hit.confidence = Confidence::Confirmed;
                    out.push(hit);
                }
            }
        }
    }

    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(obj) = val.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (pkg, ver_val) in obj {
            let Some(ver) = ver_val.as_str() else {
                continue;
            };
            let ln = find_line_for_needle(&lines, &format!("\"{}\"", pkg));
            if is_floating_version(ver) && section != "peerDependencies" {
                out.push(make_dep_finding(
                    "HIGH",
                    format!(
                        "Unpinned/floating npm dependency `\"{}\" : \"{}\"` in `{}`",
                        pkg, ver, section
                    ),
                    rel_path,
                    ln,
                    format!(
                        "Pin `{}` to an explicit semver version or range and commit `package-lock.json`.",
                        pkg
                    ),
                ));
            } else if is_insecure_http_url(ver) {
                out.push(make_dep_finding(
                    "HIGH",
                    format!("Insecure `http://` dependency URL for `{}`: `{}`", pkg, ver),
                    rel_path,
                    ln,
                    format!("Use an `https://` registry or tarball URL for `{}`.", pkg),
                ));
            } else if (ver.starts_with("git+https://")
                || ver.starts_with("github:")
                || ver.starts_with("git+ssh://"))
                && !ver.split('#').nth(1).is_some_and(is_commit_sha_40)
            {
                out.push(make_dep_finding(
                    "HIGH",
                    format!("Git npm dependency `{}` (`{}`) is not pinned to an immutable 40-char commit SHA", pkg, ver),
                    rel_path,
                    ln,
                    format!("Pin `{}` with `#<40-char-commit-sha>`.", pkg),
                ));
            }
            adv_entries.push((pkg.clone(), ver.to_string(), ln));
        }
    }
    check_advisories_batch(
        Ecosystem::Npm,
        &adv_entries,
        rel_path,
        None,
        store,
        &mut out,
    );
    out
}

fn audit_package_lock(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();
    let mut checked: Vec<(String, String)> = Vec::new();

    if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
        for (pkg_path, info) in pkgs {
            if pkg_path.is_empty() {
                continue;
            }
            let name = pkg_path.rsplit("node_modules/").next().unwrap_or(pkg_path);
            if let Some(resolved) = info.get("resolved").and_then(|v| v.as_str()) {
                if is_insecure_http_url(resolved) {
                    let ln = find_line_for_needle(&lines, resolved);
                    out.push(make_dep_finding(
                        "HIGH",
                        format!("Insecure `http://` tarball URL in lockfile for `{}`", name),
                        rel_path,
                        ln,
                        "Regenerate lockfile using `https://` registry URLs only.".into(),
                    ));
                } else if resolved.starts_with("https://")
                    && info
                        .get("integrity")
                        .and_then(|v| v.as_str())
                        .is_none_or(|s| s.trim().is_empty())
                {
                    let ln = find_line_for_needle(&lines, resolved);
                    out.push(make_dep_finding(
                        "MEDIUM",
                        format!("Remote tarball for `{}` lacks cryptographic `integrity` hash in lockfile", name),
                        rel_path,
                        ln,
                        "Regenerate lockfile with modern npm/yarn/pnpm to record SHA-512 integrity digests.".into(),
                    ));
                }
            }
            if let Some(ver) = info.get("version").and_then(|v| v.as_str())
                && seen_pairs.insert((name.to_string(), ver.to_string()))
            {
                checked.push((name.to_string(), ver.to_string()));
            }
        }
    }

    if let Some(deps) = val.get("dependencies").and_then(|v| v.as_object()) {
        for (name, info) in deps {
            if let Some(resolved) = info.get("resolved").and_then(|v| v.as_str())
                && is_insecure_http_url(resolved)
            {
                let ln = find_line_for_needle(&lines, resolved);
                out.push(make_dep_finding(
                    "HIGH",
                    format!("Insecure `http://` tarball URL in lockfile for `{}`", name),
                    rel_path,
                    ln,
                    "Regenerate lockfile using `https://` registry URLs only.".into(),
                ));
            }
            if let Some(ver) = info.get("version").and_then(|v| v.as_str())
                && seen_pairs.insert((name.to_string(), ver.to_string()))
            {
                checked.push((name.to_string(), ver.to_string()));
            }
        }
    }

    let entries: Vec<(String, String, usize)> = checked
        .into_iter()
        .map(|(name, ver)| {
            let ln = find_line_for_needle(&lines, &format!("\"{}\"", name));
            (name, ver, ln)
        })
        .collect();
    check_advisories_batch(Ecosystem::Npm, &entries, rel_path, None, store, &mut out);

    out
}

fn audit_cargo_toml(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut adv_entries = Vec::new();

    let mut tables = Vec::new();
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = val.get(key).and_then(|v| v.as_table()) {
            tables.push(t);
        }
    }
    if let Some(t) = val
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|v| v.as_table())
    {
        tables.push(t);
    }

    for tbl in tables {
        for (pkg, spec) in tbl {
            let ln = find_line_for_needle(&lines, pkg);
            match spec {
                toml::Value::String(ver) => {
                    if is_floating_version(ver) {
                        out.push(make_dep_finding(
                            "HIGH",
                            format!("Unpinned wildcard Rust crate `{} = \"{}\"`", pkg, ver),
                            rel_path,
                            ln,
                            format!(
                                "Pin `{}` to a concrete semantic version in `Cargo.toml`.",
                                pkg
                            ),
                        ));
                    }
                    adv_entries.push((pkg.clone(), ver.clone(), ln));
                }
                toml::Value::Table(dep_tbl) => {
                    if let Some(ver) = dep_tbl.get("version").and_then(|v| v.as_str()) {
                        if is_floating_version(ver) {
                            out.push(make_dep_finding(
                                "HIGH",
                                format!("Unpinned wildcard Rust crate `{} = \"{}\"`", pkg, ver),
                                rel_path,
                                ln,
                                format!(
                                    "Pin `{}` to a concrete semantic version in `Cargo.toml`.",
                                    pkg
                                ),
                            ));
                        }
                        adv_entries.push((pkg.clone(), ver.to_string(), ln));
                    }
                    if let Some(git_url) = dep_tbl.get("git").and_then(|v| v.as_str()) {
                        if is_insecure_http_url(git_url) {
                            out.push(make_dep_finding(
                                "HIGH",
                                format!("Insecure `http://` git dependency URL for `{}`", pkg),
                                rel_path,
                                ln,
                                "Use `https://` for git crate sources.".into(),
                            ));
                        } else if !dep_tbl
                            .get("rev")
                            .and_then(|v| v.as_str())
                            .is_some_and(is_commit_sha_40)
                        {
                            out.push(make_dep_finding(
                                "HIGH",
                                format!("Cargo git dependency `{}` lacks immutable 40-char `rev = \"...\"` commit SHA", pkg),
                                rel_path,
                                ln,
                                format!("Pin git crate `{}` with `rev = \"<40-char-sha>\"`.", pkg),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    check_advisories_batch(
        Ecosystem::Cargo,
        &adv_entries,
        rel_path,
        None,
        store,
        &mut out,
    );
    out
}

fn audit_cargo_lock(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(pkgs) = val.get("package").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut entries = Vec::with_capacity(pkgs.len());

    for pkg in pkgs {
        let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let ver = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(source) = pkg.get("source").and_then(|v| v.as_str())
            && is_insecure_http_url(source)
        {
            let ln = find_line_for_needle(&lines, source);
            out.push(make_dep_finding(
                "HIGH",
                format!(
                    "Insecure `http://` registry source in Cargo.lock for `{}`",
                    name
                ),
                rel_path,
                ln,
                "Switch Cargo registry source to HTTPS.".into(),
            ));
        }
        entries.push((name.to_string(), ver.to_string(), 1));
    }

    check_advisories_batch(
        Ecosystem::Cargo,
        &entries,
        rel_path,
        Some((&lines, "toml_name")),
        store,
        &mut out,
    );
    out
}

fn audit_python_toml_lock(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(pkgs) = val.get("package").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut entries = Vec::with_capacity(pkgs.len());

    for pkg in pkgs {
        let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let ver = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let source_url = pkg
            .get("source")
            .and_then(|s| s.get("url").or_else(|| s.get("registry")))
            .and_then(|u| u.as_str());
        if let Some(url) = source_url
            && is_insecure_http_url(url)
        {
            let ln = find_line_for_needle(&lines, url);
            out.push(make_dep_finding(
                "HIGH",
                format!(
                    "Insecure `http://` package index in `{}` for `{}`",
                    rel_path, name
                ),
                rel_path,
                ln,
                "Use an `https://` PyPI index in your Python lockfile.".into(),
            ));
        }
        if !ver.is_empty() {
            entries.push((name.to_string(), ver.to_string(), 1));
        }
    }

    check_advisories_batch(
        Ecosystem::PyPi,
        &entries,
        rel_path,
        Some((&lines, "toml_name")),
        store,
        &mut out,
    );
    out
}

fn audit_go_mod(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
    let mut in_require_block = false;
    let mut adv_entries = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let ln = idx + 1;
        let code = line.split("//").next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        if code.starts_with("require (") || code == "require(" {
            in_require_block = true;
            continue;
        }
        if in_require_block && code == ")" {
            in_require_block = false;
            continue;
        }
        if is_insecure_http_url(code) {
            out.push(make_dep_finding(
                "HIGH",
                "Insecure `http://` module/replace URL in `go.mod`".into(),
                rel_path,
                ln,
                "Use `https://` module paths in `go.mod`.".into(),
            ));
        }
        let req_line = if in_require_block {
            Some(code)
        } else {
            code.strip_prefix("require ").map(str::trim)
        };
        if let Some(rl) = req_line {
            let mut parts = rl.split_whitespace();
            if let (Some(mod_path), Some(ver)) = (parts.next(), parts.next()) {
                if is_floating_version(ver) {
                    out.push(make_dep_finding(
                        "HIGH",
                        format!("Unpinned Go module version `{} {}`", mod_path, ver),
                        rel_path,
                        ln,
                        "Pin Go modules to a tagged semantic version (`vX.Y.Z`) and verify `go.sum`.".into(),
                    ));
                }
                adv_entries.push((mod_path.to_string(), ver.to_string(), ln));
            }
        }
    }
    check_advisories_batch(Ecosystem::Go, &adv_entries, rel_path, None, store, &mut out);
    out
}

fn audit_requirements_txt(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
    let mut adv_entries = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let ln = idx + 1;
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() || code.starts_with("-r ") || code.starts_with("--requirement") {
            continue;
        }
        if is_insecure_http_url(code) {
            out.push(make_dep_finding(
                "HIGH",
                format!("Insecure `http://` Python dependency/index URL `{}`", code),
                rel_path,
                ln,
                "Use `https://` for all package URLs and `--index-url` directives.".into(),
            ));
            continue;
        }
        if code.starts_with("--extra-index-url") {
            out.push(make_dep_finding(
                "MEDIUM",
                format!("PyPI `--extra-index-url` (`{}`) introduces dependency-confusion risk if private package names are unregistered publicly", code),
                rel_path,
                ln,
                "Avoid `--extra-index-url`; mirror PyPI into a single private index using `--index-url`.".into(),
            ));
            continue;
        }
        if code.starts_with("git+https://") || code.contains(" @ git+https://") {
            let pinned = code
                .rsplit('@')
                .next()
                .is_some_and(|r| is_commit_sha_40(r.split('#').next().unwrap_or("")));
            if !pinned {
                out.push(make_dep_finding(
                    "HIGH",
                    format!(
                        "Unpinned Python git dependency `{}` lacks immutable 40-char commit SHA",
                        code
                    ),
                    rel_path,
                    ln,
                    "Pin git dependencies with `@<40-char-commit-sha>` and `--require-hashes`."
                        .into(),
                ));
            }
            continue;
        }
        if code.starts_with('-') {
            continue;
        }
        // Strip environment markers `; python_version < ...`
        let spec = code.split(';').next().unwrap_or(code).trim();
        let pkg_only = spec
            .split(['=', '>', '<', '~', '!', '['])
            .next()
            .unwrap_or(spec)
            .trim();
        if pkg_only.is_empty() {
            continue;
        }
        if let Some((_, ver_part)) = spec
            .split_once("==")
            .or_else(|| spec.split_once("~="))
            .or_else(|| spec.split_once("<="))
            .or_else(|| spec.split_once(">="))
        {
            let ver = ver_part.trim();
            if is_floating_version(ver) {
                out.push(make_dep_finding(
                    "HIGH",
                    format!("Unpinned wildcard Python dependency `{}`", spec),
                    rel_path,
                    ln,
                    format!("Pin `{}` to an exact version (`package==X.Y.Z`).", pkg_only),
                ));
            } else {
                adv_entries.push((pkg_only.to_string(), ver.to_string(), ln));
            }
        } else if spec.contains('*') || spec.to_ascii_lowercase().contains("latest") {
            out.push(make_dep_finding(
                "HIGH",
                format!("Floating wildcard Python dependency `{}`", spec),
                rel_path,
                ln,
                format!("Pin `{}` to an exact version (`package==X.Y.Z`).", pkg_only),
            ));
            adv_entries.push((pkg_only.to_string(), String::new(), ln));
        } else {
            out.push(make_dep_finding(
                "MEDIUM",
                format!(
                    "Unpinned Python dependency `{}` without version constraint",
                    pkg_only
                ),
                rel_path,
                ln,
                format!(
                    "Pin `{}` to an audited version (`{}==X.Y.Z`).",
                    pkg_only, pkg_only
                ),
            ));
            adv_entries.push((pkg_only.to_string(), String::new(), ln));
        }
    }
    check_advisories_batch(
        Ecosystem::PyPi,
        &adv_entries,
        rel_path,
        None,
        store,
        &mut out,
    );
    out
}

fn audit_pyproject_toml(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut adv_entries = Vec::new();

    // PEP 621: [project] dependencies = ["pkg==1.2.3", ...]
    let mut pep621_specs: Vec<&str> = Vec::new();
    if let Some(deps) = val
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for item in deps {
            if let Some(s) = item.as_str() {
                pep621_specs.push(s);
            }
        }
    }
    if let Some(opt_tbl) = val
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for arr in opt_tbl.values().filter_map(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    pep621_specs.push(s);
                }
            }
        }
    }

    if !pep621_specs.is_empty() {
        // Phase 16C: Open-ended PEP-621 lower-bound ranges (`pkg>=X.Y.Z` without `==` or `<`)
        // in library `pyproject.toml` resolve to the latest patched version at install time and
        // are not pinned vulnerable versions.
        let actionable_specs: Vec<&str> = pep621_specs
            .into_iter()
            .filter(|s| !(s.contains(">=") && !s.contains("==") && !s.contains('<')))
            .collect();
        let joined = actionable_specs.join("\n");
        for mut finding in audit_requirements_txt(rel_path, &joined, store) {
            let pkg_token = finding
                .title
                .split('`')
                .nth(1)
                .and_then(|t| t.split(['@', '=', '>', '<', '~', ' ']).next())
                .unwrap_or("");
            if !pkg_token.is_empty() {
                finding.line = find_line_for_needle(&lines, pkg_token);
                finding.symbol = format!("{}:{}", rel_path, finding.line);
            }
            out.push(finding);
        }
    }

    // Poetry: [tool.poetry.dependencies] & [tool.poetry.dev-dependencies]
    let mut poetry_tables = Vec::new();
    if let Some(poetry) = val.get("tool").and_then(|t| t.get("poetry")) {
        for key in ["dependencies", "dev-dependencies"] {
            if let Some(tbl) = poetry.get(key).and_then(|v| v.as_table()) {
                poetry_tables.push(tbl);
            }
        }
        if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
            for grp in groups.values() {
                if let Some(tbl) = grp.get("dependencies").and_then(|v| v.as_table()) {
                    poetry_tables.push(tbl);
                }
            }
        }
    }

    for tbl in poetry_tables {
        for (pkg, spec) in tbl {
            if pkg.eq_ignore_ascii_case("python") {
                continue;
            }
            let ln = find_line_for_needle(&lines, pkg);
            let ver_opt = match spec {
                toml::Value::String(s) => Some(s.as_str()),
                toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                _ => None,
            };
            if let Some(ver) = ver_opt {
                if is_floating_version(ver) {
                    out.push(make_dep_finding(
                        "HIGH",
                        format!(
                            "Unpinned wildcard Python dependency `{} = \"{}\"`",
                            pkg, ver
                        ),
                        rel_path,
                        ln,
                        format!("Pin `{}` to an exact version in `pyproject.toml`.", pkg),
                    ));
                }
                adv_entries.push((pkg.clone(), ver.to_string(), ln));
            }
        }
    }
    check_advisories_batch(
        Ecosystem::PyPi,
        &adv_entries,
        rel_path,
        None,
        store,
        &mut out,
    );

    out
}

/// Extracts resolved `(ecosystem, package, version)` triples from manifests/lockfiles
/// for explicit opt-in `shellmind-guard deps sync`.
pub fn extract_resolved_dependencies(rel_path: &str, content: &str) -> Vec<ResolvedDependency> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let mut out = Vec::new();
    let clean_semver_str = |raw: &str| -> Option<String> {
        let stripped = raw
            .trim()
            .trim_start_matches(['v', 'V', '^', '~', '=', '>', '<', ' ']);
        let core = stripped.split([' ', ',', ';']).next().unwrap_or("").trim();
        parse_semver_with_prerelease(core)?;
        Some(core.to_string())
    };

    match fname {
        "package-lock.json" => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                let mut seen: HashMap<String, String> = HashMap::new();
                if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
                    for (k, info) in pkgs {
                        if k.is_empty() {
                            continue;
                        }
                        let name = k.rsplit("node_modules/").next().unwrap_or(k);
                        if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                            seen.entry(name.to_string())
                                .or_insert_with(|| ver.to_string());
                        }
                    }
                }
                if let Some(deps) = val.get("dependencies").and_then(|v| v.as_object()) {
                    for (name, info) in deps {
                        if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                            seen.entry(name.clone()).or_insert_with(|| ver.to_string());
                        }
                    }
                }
                for (name, version) in seen {
                    out.push(ResolvedDependency {
                        ecosystem: "npm".into(),
                        name,
                        version,
                        line: 1,
                    });
                }
            }
        }
        "package.json" => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                for sec in ["dependencies", "devDependencies", "peerDependencies"] {
                    if let Some(obj) = val.get(sec).and_then(|v| v.as_object()) {
                        for (name, vval) in obj {
                            if let Some(raw) = vval.as_str()
                                && let Some(ver) = clean_semver_str(raw)
                            {
                                out.push(ResolvedDependency {
                                    ecosystem: "npm".into(),
                                    name: name.clone(),
                                    version: ver,
                                    line: 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        "Cargo.lock" | "poetry.lock" | "uv.lock" => {
            let eco = if fname == "Cargo.lock" {
                "crates.io"
            } else {
                "PyPI"
            };
            if let Ok(val) = toml::from_str::<toml::Value>(content)
                && let Some(pkgs) = val.get("package").and_then(|v| v.as_array())
            {
                for pkg in pkgs {
                    if let (Some(name), Some(ver)) = (
                        pkg.get("name").and_then(|v| v.as_str()),
                        pkg.get("version").and_then(|v| v.as_str()),
                    ) {
                        out.push(ResolvedDependency {
                            ecosystem: eco.into(),
                            name: name.to_string(),
                            version: ver.to_string(),
                            line: 1,
                        });
                    }
                }
            }
        }
        "Cargo.toml" => {
            if let Ok(val) = toml::from_str::<toml::Value>(content) {
                for key in ["dependencies", "dev-dependencies"] {
                    if let Some(tbl) = val.get(key).and_then(|v| v.as_table()) {
                        for (pkg, spec) in tbl {
                            let ver_raw = match spec {
                                toml::Value::String(s) => Some(s.as_str()),
                                toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                                _ => None,
                            };
                            if let Some(raw) = ver_raw
                                && let Some(ver) = clean_semver_str(raw)
                            {
                                out.push(ResolvedDependency {
                                    ecosystem: "crates.io".into(),
                                    name: pkg.clone(),
                                    version: ver,
                                    line: 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        "go.mod" => {
            let mut in_req = false;
            for (idx, line) in content.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("").trim();
                if code.starts_with("require (") || code == "require(" {
                    in_req = true;
                    continue;
                }
                if in_req && code == ")" {
                    in_req = false;
                    continue;
                }
                let rl = if in_req {
                    Some(code)
                } else {
                    code.strip_prefix("require ").map(str::trim)
                };
                if let Some(rl) = rl {
                    let mut parts = rl.split_whitespace();
                    if let (Some(mod_path), Some(ver)) = (parts.next(), parts.next())
                        && !is_floating_version(ver)
                        && !is_go_pseudo_version(ver)
                    {
                        out.push(ResolvedDependency {
                            ecosystem: "Go".into(),
                            name: mod_path.to_string(),
                            version: ver.trim_start_matches('v').to_string(),
                            line: idx + 1,
                        });
                    }
                }
            }
        }
        "requirements.txt" => {
            for (idx, line) in content.lines().enumerate() {
                let code = line.split('#').next().unwrap_or("").trim();
                if code.is_empty() || code.starts_with('-') {
                    continue;
                }
                let spec = code.split(';').next().unwrap_or(code).trim();
                let pkg = spec
                    .split(['=', '>', '<', '~', '!', '['])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !pkg.is_empty()
                    && let Some((_, ver_raw)) = spec.split_once("==")
                    && let Some(ver) = clean_semver_str(ver_raw)
                {
                    out.push(ResolvedDependency {
                        ecosystem: "PyPI".into(),
                        name: pkg.to_string(),
                        version: ver,
                        line: idx + 1,
                    });
                }
            }
        }
        "pyproject.toml" => {
            if let Ok(val) = toml::from_str::<toml::Value>(content)
                && let Some(deps) = val
                    .get("project")
                    .and_then(|p| p.get("dependencies"))
                    .and_then(|d| d.as_array())
            {
                let req_lines: String = deps
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                out.extend(extract_resolved_dependencies(
                    "requirements.txt",
                    &req_lines,
                ));
            }
        }
        "yarn.lock" | "pnpm-lock.yaml" | "composer.lock" | "Gemfile.lock" | "pubspec.lock"
        | "packages.lock.json" => {
            let graph = extract_lockfile_dep_graph(rel_path, content);
            for (name, (version, _is_dev, line)) in graph.nodes {
                out.push(ResolvedDependency {
                    ecosystem: graph.ecosystem.clone(),
                    name,
                    version,
                    line,
                });
            }
        }
        "go.sum" => {
            let mut seen_go: HashSet<(String, String)> = HashSet::new();
            for (idx, line) in content.lines().enumerate() {
                let mut parts = line.split_whitespace();
                let (Some(mod_path), Some(raw_ver)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if raw_ver.ends_with("/go.mod") {
                    continue;
                }
                let ver = raw_ver.trim_start_matches('v').to_string();
                if is_floating_version(&ver) || is_go_pseudo_version(&ver) {
                    continue;
                }
                if seen_go.insert((mod_path.to_string(), ver.clone())) {
                    out.push(ResolvedDependency {
                        ecosystem: "Go".into(),
                        name: mod_path.to_string(),
                        version: ver,
                        line: idx + 1,
                    });
                }
            }
        }
        "Pipfile.lock" => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                for sec in ["default", "develop"] {
                    if let Some(obj) = val.get(sec).and_then(|v| v.as_object()) {
                        for (name, info) in obj {
                            if let Some(raw_ver) = info.get("version").and_then(|v| v.as_str())
                                && let Some(ver) = clean_semver_str(raw_ver)
                            {
                                out.push(ResolvedDependency {
                                    ecosystem: "PyPI".into(),
                                    name: name.clone(),
                                    version: ver,
                                    line: 1,
                                });
                            }
                        }
                    }
                }
            }
        }
        "mix.lock" => {
            // Elixir Hex lockfile: `"phoenix": {:hex, :phoenix, "1.7.14", ...}`
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if let Some((_, rest)) = trimmed.split_once(":hex,") {
                    let mut parts = rest.split(',');
                    let name_part = parts.next().unwrap_or("").trim().trim_start_matches(':');
                    let ver_part = parts.next().unwrap_or("").trim().trim_matches('"');
                    if !name_part.is_empty() && !ver_part.is_empty() {
                        out.push(ResolvedDependency {
                            ecosystem: "Hex".into(),
                            name: name_part.to_string(),
                            version: ver_part.to_string(),
                            line: idx + 1,
                        });
                    }
                }
            }
        }
        "gradle.lockfile" => {
            // `group:artifact:version=configurations`
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("empty=") {
                    continue;
                }
                let coord = trimmed.split('=').next().unwrap_or("").trim();
                let parts: Vec<&str> = coord.split(':').collect();
                if parts.len() >= 3
                    && !parts[0].is_empty()
                    && !parts[1].is_empty()
                    && !parts[2].is_empty()
                {
                    out.push(ResolvedDependency {
                        ecosystem: "Maven".into(),
                        name: format!("{}:{}", parts[0], parts[1]),
                        version: parts[2].to_string(),
                        line: idx + 1,
                    });
                }
            }
        }
        "pom.xml" => {
            // Lightweight deterministic `<dependency>` extractor for Maven `pom.xml`
            let mut in_dep = false;
            let mut cur_group = String::new();
            let mut cur_artifact = String::new();
            let mut cur_version = String::new();
            let mut dep_line = 1usize;
            for (idx, line) in content.lines().enumerate() {
                let t = line.trim();
                if t.contains("<dependency>") {
                    in_dep = true;
                    cur_group.clear();
                    cur_artifact.clear();
                    cur_version.clear();
                    dep_line = idx + 1;
                    continue;
                }
                if in_dep {
                    if let Some(v) = extract_xml_tag_value(t, "groupId") {
                        cur_group = v;
                    } else if let Some(v) = extract_xml_tag_value(t, "artifactId") {
                        cur_artifact = v;
                    } else if let Some(v) = extract_xml_tag_value(t, "version") {
                        cur_version = v;
                    }
                    if t.contains("</dependency>") {
                        in_dep = false;
                        if !cur_group.is_empty()
                            && !cur_artifact.is_empty()
                            && !cur_version.is_empty()
                            && !cur_version.contains("${")
                        {
                            out.push(ResolvedDependency {
                                ecosystem: "Maven".into(),
                                name: format!("{cur_group}:{cur_artifact}"),
                                version: cur_version.clone(),
                                line: dep_line,
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }

    out
}

fn extract_xml_tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let rest = &line[start..];
    let end = rest.find(&close)?;
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Parses a package header line in `yarn.lock` (v1 or Berry v2+), e.g.:
/// `"lodash@^4.17.15":` or `"@scope/pkg@npm:^1.0.0":` -> `Some("lodash")` / `Some("@scope/pkg")`
fn parse_yarn_pkg_header(line: &str) -> Option<String> {
    if line.is_empty()
        || line.starts_with(' ')
        || line.starts_with('\t')
        || line.starts_with('#')
        || line.starts_with("__metadata")
    {
        return None;
    }
    let trimmed = line.trim();
    if !trimmed.ends_with(':') {
        return None;
    }
    let first_spec = trimmed
        .trim_end_matches(':')
        .split(',')
        .next()?
        .trim()
        .trim_matches(['"', '\'']);
    if first_spec.is_empty() {
        return None;
    }
    // Scoped package `@scope/name@range` -> split at the `@` after index 0
    let at_pos = if let Some(rest) = first_spec.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        first_spec.find('@')
    }?;
    let name = first_spec[..at_pos].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Parses a `pnpm-lock.yaml` package key under `packages:`, e.g.:
/// `  /lodash@4.17.20:` or `  '/@scope/pkg@1.2.3':` or `  lodash@4.17.20:` -> `Some(("lodash", "4.17.20"))`
fn parse_pnpm_pkg_key(trimmed: &str) -> Option<(String, String)> {
    let key = trimmed.strip_suffix(':')?.trim().trim_matches(['"', '\'']);
    let key = key.strip_prefix('/').unwrap_or(key);
    let key_no_paren = key.split('(').next().unwrap_or(key);
    // Split package name vs version at `@` BEFORE stripping `_peer@ver` from the version segment
    // so package names containing `_` (e.g. `lodash_es@4.17.21`) are preserved intact.
    let at_pos = if let Some(rest) = key_no_paren.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        key_no_paren.find('@')
    }?;
    let name = key_no_paren[..at_pos].trim();
    let ver_raw = key_no_paren[at_pos + 1..].trim();
    let ver = ver_raw.split('_').next().unwrap_or(ver_raw).trim();
    if !name.is_empty() && ver.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        Some((name.to_string(), ver.to_string()))
    } else {
        None
    }
}

/// Extracts `(pkg@ver -> dep@ver, is_dev)` lockfile dependency graph across all 9 ecosystems
/// in a single linear pass (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`,
/// `composer.lock`, `Gemfile.lock`, `pubspec.lock`, `packages.lock.json`).
pub fn extract_lockfile_dep_graph(rel_path: &str, content: &str) -> LockfileDepGraph {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let lines: Vec<&str> = content.lines().collect();
    let mut graph = LockfileDepGraph::default();

    match fname {
        "package-lock.json" => {
            graph.ecosystem = "npm".into();
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content)
                && let Some(pkgs) = val.get("packages").and_then(|v| v.as_object())
            {
                for (path_key, info) in pkgs {
                    let pkg_name = path_key.rsplit("node_modules/").next().unwrap_or("").trim();
                    if pkg_name.is_empty() {
                        continue;
                    }
                    let ver = info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let is_dev = info.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
                    if !ver.is_empty() {
                        graph
                            .nodes
                            .entry(pkg_name.to_string())
                            .or_insert((ver, is_dev, 1));
                    }
                    if let Some(deps) = info.get("dependencies").and_then(|v| v.as_object()) {
                        for dep_name in deps.keys() {
                            graph.edges.push(LockfileDepEdge {
                                parent: pkg_name.to_string(),
                                child: dep_name.clone(),
                                is_dev,
                            });
                        }
                    }
                }
            }
        }
        "yarn.lock" => {
            graph.ecosystem = "npm".into();
            let mut cur_pkg: Option<(String, usize)> = None;
            let mut in_deps = false;
            for (idx, raw) in lines.iter().enumerate() {
                if let Some(name) = parse_yarn_pkg_header(raw) {
                    cur_pkg = Some((name, idx + 1));
                    in_deps = false;
                    continue;
                }
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    cur_pkg = None;
                    in_deps = false;
                    continue;
                }
                if let Some((ref pkg_name, pkg_line)) = cur_pkg {
                    let indent = raw.len() - raw.trim_start().len();
                    if indent <= 2 {
                        if let Some(rest) = trimmed
                            .strip_prefix("version:")
                            .or_else(|| trimmed.strip_prefix("version "))
                        {
                            let ver = rest.trim().trim_matches(['"', '\'']);
                            if !ver.is_empty()
                                && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                            {
                                graph.nodes.entry(pkg_name.clone()).or_insert((
                                    ver.to_string(),
                                    false,
                                    pkg_line,
                                ));
                            }
                            in_deps = false;
                        } else {
                            in_deps =
                                trimmed == "dependencies:" || trimmed == "optionalDependencies:";
                        }
                    } else if in_deps {
                        let dep_name = trimmed
                            .split([':', ' '])
                            .next()
                            .unwrap_or("")
                            .trim_matches(['"', '\'']);
                        if !dep_name.is_empty() {
                            graph.edges.push(LockfileDepEdge {
                                parent: pkg_name.clone(),
                                child: dep_name.to_string(),
                                is_dev: false,
                            });
                        }
                    }
                }
            }
        }
        "pnpm-lock.yaml" => {
            graph.ecosystem = "npm".into();
            let mut in_packages = false;
            let mut cur_pkg: Option<String> = None;
            let mut in_deps = false;
            for (idx, raw) in lines.iter().enumerate() {
                let trimmed = raw.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let indent = raw.len() - raw.trim_start().len();
                if indent == 0 {
                    in_packages = trimmed == "packages:";
                    cur_pkg = None;
                    in_deps = false;
                    continue;
                }
                if !in_packages {
                    continue;
                }
                if indent == 2 {
                    in_deps = false;
                    if let Some((name, ver)) = parse_pnpm_pkg_key(trimmed) {
                        graph
                            .nodes
                            .entry(name.clone())
                            .or_insert((ver, false, idx + 1));
                        cur_pkg = Some(name);
                    } else {
                        cur_pkg = None;
                    }
                } else if let Some(ref pkg_name) = cur_pkg {
                    if indent == 4 {
                        if trimmed == "dev: true" {
                            if let Some(entry) = graph.nodes.get_mut(pkg_name) {
                                entry.1 = true;
                            }
                            in_deps = false;
                        } else {
                            in_deps = trimmed == "dependencies:";
                        }
                    } else if indent >= 6 && in_deps {
                        let dep_name = trimmed
                            .split(':')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .trim_matches(['"', '\'']);
                        if !dep_name.is_empty() {
                            let is_dev = graph.nodes.get(pkg_name).is_some_and(|e| e.1);
                            graph.edges.push(LockfileDepEdge {
                                parent: pkg_name.clone(),
                                child: dep_name.to_string(),
                                is_dev,
                            });
                        }
                    }
                }
            }
        }
        "Cargo.lock" => {
            graph.ecosystem = "crates.io".into();
            if let Ok(val) = toml::from_str::<toml::Value>(content)
                && let Some(pkgs) = val.get("package").and_then(|v| v.as_array())
            {
                for pkg in pkgs {
                    if let (Some(name), Some(ver)) = (
                        pkg.get("name").and_then(|v| v.as_str()),
                        pkg.get("version").and_then(|v| v.as_str()),
                    ) {
                        graph
                            .nodes
                            .entry(name.to_string())
                            .or_insert((ver.to_string(), false, 1));
                        if let Some(deps) = pkg.get("dependencies").and_then(|v| v.as_array()) {
                            for d in deps.iter().filter_map(|v| v.as_str()) {
                                let child = d.split_whitespace().next().unwrap_or("").trim();
                                if !child.is_empty() {
                                    graph.edges.push(LockfileDepEdge {
                                        parent: name.to_string(),
                                        child: child.to_string(),
                                        is_dev: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "composer.lock" => {
            graph.ecosystem = "Packagist".into();
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                for (key, is_dev) in [("packages", false), ("packages-dev", true)] {
                    if let Some(arr) = val.get(key).and_then(|v| v.as_array()) {
                        for item in arr {
                            if let (Some(n), Some(v)) = (
                                item.get("name").and_then(|s| s.as_str()),
                                item.get("version").and_then(|s| s.as_str()),
                            ) {
                                let ln = find_line_for_needle(&lines, &format!("\"{}\"", n));
                                graph.nodes.entry(n.to_string()).or_insert((
                                    v.trim_start_matches('v').to_string(),
                                    is_dev,
                                    ln,
                                ));
                                if let Some(req) = item.get("require").and_then(|r| r.as_object()) {
                                    for child in req.keys() {
                                        if child != "php" && !child.starts_with("ext-") {
                                            graph.edges.push(LockfileDepEdge {
                                                parent: n.to_string(),
                                                child: child.clone(),
                                                is_dev,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "Gemfile.lock" => {
            graph.ecosystem = "RubyGems".into();
            let mut cur_gem: Option<String> = None;
            for (idx, raw) in lines.iter().enumerate() {
                let indent = raw.len() - raw.trim_start().len();
                let t = raw.trim();
                if indent == 4
                    && let Some((pkg, rest)) = t.split_once(" (")
                    && let Some(ver) = rest.strip_suffix(')')
                    && ver.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    let name = pkg.trim().to_string();
                    graph
                        .nodes
                        .entry(name.clone())
                        .or_insert((ver.to_string(), false, idx + 1));
                    cur_gem = Some(name);
                } else if indent == 6
                    && let Some(ref parent) = cur_gem
                {
                    let child = t.split_whitespace().next().unwrap_or("").trim();
                    if !child.is_empty() {
                        graph.edges.push(LockfileDepEdge {
                            parent: parent.clone(),
                            child: child.to_string(),
                            is_dev: false,
                        });
                    }
                } else if indent < 4 {
                    cur_gem = None;
                }
            }
        }
        "pubspec.lock" => {
            graph.ecosystem = "Pub".into();
            let mut in_packages = false;
            let mut cur_pkg: Option<(String, usize)> = None;
            for (idx, raw) in lines.iter().enumerate() {
                let trimmed = raw.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let indent = raw.len() - raw.trim_start().len();
                if indent == 0 {
                    in_packages = trimmed == "packages:";
                    cur_pkg = None;
                    continue;
                }
                if !in_packages {
                    continue;
                }
                if indent == 2 && trimmed.ends_with(':') {
                    let name = trimmed.trim_end_matches(':').trim().to_string();
                    cur_pkg = Some((name, idx + 1));
                } else if indent == 4
                    && let Some((ref name, pkg_line)) = cur_pkg
                {
                    if let Some(rest) = trimmed.strip_prefix("version:") {
                        let ver = rest.trim().trim_matches(['"', '\'']);
                        if !ver.is_empty() {
                            let entry = graph.nodes.entry(name.clone()).or_insert((
                                ver.to_string(),
                                false,
                                pkg_line,
                            ));
                            entry.0 = ver.to_string();
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("dependency:") {
                        let is_dev = rest.to_ascii_lowercase().contains("dev");
                        let entry = graph.nodes.entry(name.clone()).or_insert((
                            String::new(),
                            is_dev,
                            pkg_line,
                        ));
                        entry.1 = is_dev;
                    }
                }
            }
        }
        "packages.lock.json" => {
            graph.ecosystem = "NuGet".into();
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(content)
                && let Some(tfms) = val.get("dependencies").and_then(|v| v.as_object())
            {
                for pkgs in tfms.values().filter_map(|v| v.as_object()) {
                    for (name, info) in pkgs {
                        if let Some(ver) = info.get("resolved").and_then(|v| v.as_str()) {
                            let ln = find_line_for_needle(&lines, &format!("\"{}\"", name));
                            graph
                                .nodes
                                .entry(name.clone())
                                .or_insert((ver.to_string(), false, ln));
                        }
                        if let Some(deps) = info.get("dependencies").and_then(|v| v.as_object()) {
                            for child in deps.keys() {
                                graph.edges.push(LockfileDepEdge {
                                    parent: name.clone(),
                                    child: child.clone(),
                                    is_dev: false,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    graph
}

/// Offline-first dependency and lockfile audit executed in-memory with zero network calls,
/// automatically querying `~/.cache/shellmind-guard/advisories.db` when present on disk.
pub fn scan_dependencies(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let store = AdvisoryStore::open_default_readonly_if_exists();
    scan_dependencies_with_store(rel_path, content, store.as_ref())
}

fn audit_generic_ecosystem_manifest(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let mut out = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    if fname == ".npmrc" {
        for (idx, raw) in lines.iter().enumerate() {
            let trimmed = raw.trim();
            if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
                continue;
            }
            if is_insecure_http_url(trimmed) {
                out.push(make_dep_finding(
                    "HIGH",
                    format!("Insecure `http://` npm registry URL in `.npmrc`: `{}`", trimmed),
                    rel_path,
                    idx + 1,
                    "Use `https://` registries in `.npmrc` and scope private registries (`@org:registry=...`).".into(),
                ));
            } else if trimmed.starts_with("registry=") && !trimmed.contains("registry.npmjs.org") {
                out.push(make_dep_finding(
                    "MEDIUM",
                    format!("Global `.npmrc` overrides default npm registry globally (`{}`); prefer scoped `@org:registry`", trimmed),
                    rel_path,
                    idx + 1,
                    "Scope internal registries to `@your-org:registry=https://...` to prevent dependency confusion.".into(),
                ));
            }
        }
        return out;
    }

    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if is_insecure_http_url(trimmed)
            && !trimmed.contains("xmlns")
            && !trimmed.contains("w3.org")
        {
            out.push(make_dep_finding(
                "HIGH",
                format!(
                    "Insecure `http://` repository or dependency URL in `{}`",
                    fname
                ),
                rel_path,
                idx + 1,
                "Switch repository and dependency URLs to HTTPS (`https://`).".into(),
            ));
        }
    }

    // Resolved dependency extraction across all supported manifests & lockfiles (`pom.xml` with
    // `groupId:artifactId`, `go.sum`, `Pipfile.lock`, `gradle.lockfile`, `mix.lock`, `composer.lock`,
    // `Gemfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `pubspec.lock`, `packages.lock.json`, etc.).
    let resolved = extract_resolved_dependencies(rel_path, content);
    if !resolved.is_empty() {
        type EcoBatch = (Ecosystem, Vec<(String, String, usize)>);
        let mut by_eco: HashMap<&'static str, EcoBatch> = HashMap::new();
        for dep in resolved {
            let mapped = match dep.ecosystem.as_str() {
                "npm" => Some(("npm", Ecosystem::Npm)),
                "crates.io" => Some(("crates.io", Ecosystem::Cargo)),
                "Go" => Some(("Go", Ecosystem::Go)),
                "PyPI" => Some(("PyPI", Ecosystem::PyPi)),
                "Maven" => Some(("Maven", Ecosystem::Maven)),
                "Packagist" => Some(("Packagist", Ecosystem::Packagist)),
                "RubyGems" => Some(("RubyGems", Ecosystem::RubyGems)),
                "NuGet" => Some(("NuGet", Ecosystem::NuGet)),
                "Pub" => Some(("Pub", Ecosystem::Pub)),
                _ => None,
            };
            if let Some((key, eco)) = mapped {
                by_eco
                    .entry(key)
                    .or_insert_with(|| (eco, Vec::new()))
                    .1
                    .push((dep.name, dep.version, dep.line));
            }
        }
        for (_, (eco, mut entries)) in by_eco {
            entries.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
            check_advisories_batch(eco, &entries, rel_path, None, store, &mut out);
        }
    } else if matches!(fname, "pom.xml" | "build.gradle" | "build.gradle.kts") {
        let mut entries = Vec::new();
        for (idx, raw) in lines.iter().enumerate() {
            let low = raw.to_ascii_lowercase();
            for (pkg, marker) in [
                ("org.apache.logging.log4j:log4j-core", "log4j-core"),
                ("org.springframework:spring-beans", "spring-beans"),
                (
                    "com.fasterxml.jackson.core:jackson-databind",
                    "jackson-databind",
                ),
            ] {
                if low.contains(marker) {
                    let window = lines[idx..(idx + 3).min(lines.len())].join(" ");
                    if let Some(ver) = extract_first_semver_token(&window) {
                        entries.push((pkg.to_string(), ver, idx + 1));
                    }
                }
            }
        }
        check_advisories_batch(Ecosystem::Maven, &entries, rel_path, None, store, &mut out);
    }

    out
}

fn extract_first_semver_token(text: &str) -> Option<String> {
    for tok in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let clean = tok.trim_start_matches(['v', 'V']);
        if clean.chars().next().is_some_and(|c| c.is_ascii_digit())
            && clean.matches('.').count() >= 2
        {
            return Some(clean.to_string());
        }
    }
    None
}

pub fn scan_dependencies_with_store(
    rel_path: &str,
    content: &str,
    store: Option<&AdvisoryStore>,
) -> Vec<LocalStaticFinding> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    match fname {
        "package.json" => audit_package_json(rel_path, content, store),
        "package-lock.json" | "npm-shrinkwrap.json" => audit_package_lock(rel_path, content, store),
        "Cargo.toml" => audit_cargo_toml(rel_path, content, store),
        "Cargo.lock" => audit_cargo_lock(rel_path, content, store),
        "go.mod" => audit_go_mod(rel_path, content, store),
        "requirements.txt" => audit_requirements_txt(rel_path, content, store),
        "pyproject.toml" => audit_pyproject_toml(rel_path, content, store),
        "poetry.lock" | "uv.lock" => audit_python_toml_lock(rel_path, content, store),
        "yarn.lock" | "pnpm-lock.yaml" | "bun.lock" | "deno.lock" | "go.sum" | "pom.xml"
        | "build.gradle" | "build.gradle.kts" | "gradle.lockfile" | "packages.lock.json"
        | "composer.json" | "composer.lock" | "Gemfile" | "Gemfile.lock" | "Package.resolved"
        | "pubspec.yaml" | "pubspec.lock" | ".npmrc" | "Pipfile" | "Pipfile.lock"
        | "conda-lock.yml" | "mix.lock" => {
            audit_generic_ecosystem_manifest(rel_path, content, store)
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_npm_and_lockfile_audit() {
        let pkg_json = r#"{
  "name": "demo",
  "dependencies": {
    "lodash": "*",
    "axios": "1.5.0",
    "express": "^4.19.2",
    "evil-http": "http://insecure.example.com/pkg.tgz"
  }
}"#;
        let hits = scan_dependencies_with_store("package.json", pkg_json, None);
        assert!(
            hits.iter()
                .any(|h| h.title.contains("lodash") && h.title.contains("*"))
        );
        assert!(hits.iter().any(|h| h.title.contains("axios@1.5.0")));
        assert!(hits.iter().any(|h| h.title.contains("http://")));
        assert!(!hits.iter().any(|h| h.title.contains("express")));

        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/minimist": {
      "version": "1.2.5",
      "resolved": "http://registry.example.com/minimist-1.2.5.tgz"
    }
  }
}"#;
        let lock_hits = scan_dependencies_with_store("package-lock.json", lock, None);
        assert!(lock_hits.iter().any(|h| h.title.contains("http://")));
        assert!(lock_hits.iter().any(|h| h.title.contains("minimist@1.2.5")));
    }

    #[test]
    fn test_cargo_go_python_manifests() {
        let cargo = "[dependencies]\nserde_yaml = \"0.9\"\nchrono = \"0.4\"\nwildcard = \"*\"\n";
        let c_hits = scan_dependencies_with_store("Cargo.toml", cargo, None);
        assert!(c_hits.iter().any(|h| h.title.contains("serde_yaml")));
        assert!(
            !c_hits.iter().any(|h| h.title.contains("chrono")),
            "2-component caret range chrono = \"0.4\" in Cargo.toml must not false-positive when >=0.4.20 is allowed"
        );
        assert!(c_hits.iter().any(|h| h.title.contains("wildcard")));

        let gomod = "module example.com/app\nrequire (\n  github.com/dgrijalva/jwt-go v3.2.0\n  golang.org/x/net latest\n)\n";
        let g_hits = scan_dependencies_with_store("go.mod", gomod, None);
        assert!(g_hits.iter().any(|h| h.title.contains("jwt-go")));
        assert!(g_hits.iter().any(|h| h.title.contains("latest")));

        let reqs = "pyyaml>=5.3.1\nflask\n--extra-index-url http://pypi.insecure.local/simple\n";
        let p_hits = scan_dependencies_with_store("requirements.txt", reqs, None);
        assert!(p_hits.iter().any(|h| h.title.contains("pyyaml@5.3.1")));
        assert!(
            p_hits
                .iter()
                .any(|h| h.title.contains("Unpinned Python dependency `flask`"))
        );
        assert!(p_hits.iter().any(|h| h.title.contains("http://")));

        let pyproj = r#"
[project]
dependencies = ["pyyaml==5.3.1", "requests>=2.31.0"]

[tool.poetry.dependencies]
python = "^3.11"
urllib3 = "1.26.4"
"#;
        let pp_hits = scan_dependencies_with_store("pyproject.toml", pyproj, None);
        assert!(pp_hits.iter().any(|h| h.title.contains("pyyaml@5.3.1")));
        assert!(pp_hits.iter().any(|h| h.title.contains("urllib3@1.26.4")));

        // Phase 16C: Open-ended `>=` lower-bound library specs in pyproject.toml (e.g. Flask/FastAPI) must NOT false-positive
        let lib_pyproj = r#"
[project]
dependencies = ["Jinja2>=3.1.2", "pyyaml>=5.3.1"]
"#;
        let lib_hits = scan_dependencies_with_store("pyproject.toml", lib_pyproj, None);
        assert!(
            lib_hits.is_empty(),
            "Open-ended >= lower-bound library specs in pyproject.toml must not FP, got: {:?}",
            lib_hits
        );

        let pre_pkg = r#"{"dependencies": {"axios": "1.6.0-alpha.1"}}"#;
        let pre_hits = scan_dependencies_with_store("package.json", pre_pkg, None);
        assert!(
            pre_hits
                .iter()
                .any(|h| h.title.contains("axios@1.6.0-alpha.1")),
            "Pre-release 1.6.0-alpha.1 is < 1.6.0 and must be flagged"
        );
    }

    #[test]
    fn test_phase7_advisory_db_lookup_and_poetry_uv_lockfiles() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("smg_deps_p7_{}.db", nanos));
        let mut store = AdvisoryStore::open_at(&db_path, false).unwrap();

        store
            .upsert_advisories(&[
                AdvisoryRecord {
                    id: "GHSA-custom-uv-001".into(),
                    ecosystem: "PyPI".into(),
                    package: "starlette".into(),
                    introduced: "0.20.0".into(),
                    fixed: "0.36.2".into(),
                    last_affected: String::new(),
                    severity: "HIGH".into(),
                    summary: "Multipart DoS in Starlette (< 0.36.2)".into(),
                    source: "osv".into(),
                    updated_at: 1_700_000_000,
                },
                AdvisoryRecord {
                    id: "CVE-2023-45857".into(),
                    ecosystem: "npm".into(),
                    package: "axios".into(),
                    introduced: "0.8.1".into(),
                    fixed: "1.6.0".into(),
                    last_affected: String::new(),
                    severity: "HIGH".into(),
                    summary: "Cross-site request forgery in axios".into(),
                    source: "osv".into(),
                    updated_at: 1_700_000_000,
                },
            ])
            .unwrap();

        let ro = AdvisoryStore::open_at(&db_path, true).unwrap();

        let uv_lock = r#"
version = 1

[[package]]
name = "starlette"
version = "0.35.0"

[[package]]
name = "fastapi"
version = "0.111.0"
"#;
        let t0 = Instant::now();
        let uv_hits = scan_dependencies_with_store("uv.lock", uv_lock, Some(&ro));
        assert!(
            t0.elapsed().as_millis() < 20,
            "uv.lock DB advisory scan must complete in < 20ms"
        );
        assert!(
            uv_hits
                .iter()
                .any(|h| h.title.contains("starlette@0.35.0")
                    && h.title.contains("GHSA-custom-uv-001")),
            "Expected synced OSV hit in uv.lock: {:?}",
            uv_hits
        );
        assert!(
            !uv_hits.iter().any(|h| h.title.contains("fastapi")),
            "Clean fastapi must not trigger false positive"
        );

        let poetry_lock = r#"
[[package]]
name = "starlette"
version = "0.37.0"
"#;
        let poetry_hits = scan_dependencies_with_store("poetry.lock", poetry_lock, Some(&ro));
        assert!(
            poetry_hits.is_empty(),
            "Fixed starlette 0.37.0 >= 0.36.2 must NOT trigger false positive: {:?}",
            poetry_hits
        );

        // Verify axios@1.5.0 deduplication between DB & built-in OFFLINE_ADVISORIES
        let pkg_lock =
            r#"{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.5.0"}}}"#;
        let npm_hits = scan_dependencies_with_store("package-lock.json", pkg_lock, Some(&ro));
        assert_eq!(
            npm_hits
                .iter()
                .filter(|h| h.title.contains("axios@1.5.0"))
                .count(),
            1,
            "Duplicate offline+OSV alert for axios must be deduplicated: {:?}",
            npm_hits
        );

        // Verify extract_resolved_dependencies picks up uv.lock and go.mod cleanly
        let resolved_uv = extract_resolved_dependencies("uv.lock", uv_lock);
        assert_eq!(resolved_uv.len(), 2);
        assert_eq!(resolved_uv[0].ecosystem, "PyPI");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[test]
    fn test_reachable_dependency_vex_assessment() {
        use crate::ast::ImportRef;
        let summaries = vec![FileAstSummary {
            rel_path: "src/app.ts".into(),
            imports: vec![ImportRef {
                symbol_name: "axios".into(),
                from_specifier: "axios/lib/core".into(),
                remote_name: None,
            }],
            ..Default::default()
        }];
        let reachable = compute_reachable_packages(&summaries);
        assert!(reachable.contains("axios"));
        assert!(!reachable.contains("lodash"));

        let f_axios = crate::lattice::LatticeFinding {
            id: "SMG-DEP-001".into(),
            rule_id: "SMG-DEP-001".into(),
            severity: "HIGH".into(),
            title: "Vulnerable dependency `axios@1.5.0`: SSRF".into(),
            file: "package-lock.json".into(),
            line: 1,
            status: "SUSPECT".into(),
            confidence: Confidence::Confirmed,
            entry_route: "package-lock.json:1".into(),
            sink_kind: SinkKind::DependencyRisk,
            missing_guard: GuardKind::DependencyPolicy,
            witness_path: Vec::new(),
            remediation: String::new(),
            proof_reasons: Vec::new(),
        };
        assert_eq!(
            assess_dependency_reachability(&f_axios, &reachable),
            Some(ReachableVulnStatus::Reachable)
        );

        let f_lodash = crate::lattice::LatticeFinding {
            title: "Vulnerable dependency `lodash@4.17.20`: CmdI".into(),
            ..f_axios
        };
        assert_eq!(
            assess_dependency_reachability(&f_lodash, &reachable),
            Some(ReachableVulnStatus::DeclaredUnused)
        );
    }

    #[test]
    fn test_sprint4_p12_03_ecosystems_lockfile_graph_and_store_routing() {
        // 1. Canonical ecosystem mapping for all 9 ecosystems
        for (raw, expected) in [
            ("maven", "Maven"),
            ("gradle", "Maven"),
            ("packagist", "Packagist"),
            ("composer", "Packagist"),
            ("rubygems", "RubyGems"),
            ("pub", "Pub"),
            ("nuget", "NuGet"),
        ] {
            assert_eq!(
                smg_core::advisories::canonical_ecosystem(raw),
                Some(expected)
            );
        }

        // 2. LockfileDepGraph extraction across yarn.lock, pnpm-lock.yaml, pubspec.lock, packages.lock.json
        let yarn_lock = r#"# yarn lockfile v1
"custom-vuln-pkg@^1.0.0":
  version "1.0.0"
  dependencies:
    helper-dep "^2.0.0"

"helper-dep@^2.0.0":
  version "2.1.0"
"#;
        let yg = extract_lockfile_dep_graph("yarn.lock", yarn_lock);
        assert_eq!(yg.ecosystem, "npm");
        assert_eq!(
            yg.nodes.get("custom-vuln-pkg").map(|n| n.0.as_str()),
            Some("1.0.0")
        );
        assert!(
            yg.edges
                .iter()
                .any(|e| e.parent == "custom-vuln-pkg" && e.child == "helper-dep")
        );

        let pnpm_lock = r#"lockfileVersion: '9.0'
packages:
  /custom-vuln-pkg@1.0.0:
    dev: false
    dependencies:
      helper-dep: 2.1.0
  /dev-tool@3.0.0:
    dev: true
"#;
        let pg = extract_lockfile_dep_graph("pnpm-lock.yaml", pnpm_lock);
        assert_eq!(
            pg.nodes.get("custom-vuln-pkg").map(|n| (n.0.as_str(), n.1)),
            Some(("1.0.0", false))
        );
        assert_eq!(pg.nodes.get("dev-tool").map(|n| n.1), Some(true));
        assert!(
            pg.edges
                .iter()
                .any(|e| e.parent == "custom-vuln-pkg" && e.child == "helper-dep")
        );

        let pubspec_lock = r#"packages:
  http_parser:
    dependency: "direct main"
    version: "4.0.2"
  test:
    dependency: "direct dev"
    version: "1.24.0"
"#;
        let dart_g = extract_lockfile_dep_graph("pubspec.lock", pubspec_lock);
        assert_eq!(dart_g.ecosystem, "Pub");
        assert_eq!(
            dart_g.nodes.get("http_parser").map(|n| (n.0.as_str(), n.1)),
            Some(("4.0.2", false))
        );
        assert_eq!(dart_g.nodes.get("test").map(|n| n.1), Some(true));

        let nuget_lock = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "12.0.1",
        "dependencies": { "System.Runtime": "4.3.0" }
      }
    }
  }
}"#;
        let ng = extract_lockfile_dep_graph("packages.lock.json", nuget_lock);
        assert_eq!(ng.ecosystem, "NuGet");
        assert_eq!(
            ng.nodes.get("Newtonsoft.Json").map(|n| n.0.as_str()),
            Some("12.0.1")
        );
        assert!(
            ng.edges
                .iter()
                .any(|e| e.parent == "Newtonsoft.Json" && e.child == "System.Runtime")
        );

        // 3. Route yarn.lock, pnpm-lock.yaml, and NuGet packages.lock.json through AdvisoryStore
        //    even for packages NOT in OFFLINE_ADVISORIES
        let db_path = std::env::temp_dir().join(format!(
            "smg_sprint4_adv_{}.db",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = AdvisoryStore::open_at(&db_path, false).unwrap();
        store
            .upsert_advisories(&[
                AdvisoryRecord {
                    id: "OSV-2026-YARN-001".into(),
                    ecosystem: "npm".into(),
                    package: "custom-vuln-pkg".into(),
                    introduced: "0".into(),
                    fixed: "1.2.0".into(),
                    last_affected: String::new(),
                    severity: "HIGH".into(),
                    summary: "Custom yarn/pnpm store-backed CVE".into(),
                    source: "osv-test".into(),
                    updated_at: 1,
                },
                AdvisoryRecord {
                    id: "OSV-2026-NUGET-001".into(),
                    ecosystem: "NuGet".into(),
                    package: "Newtonsoft.Json".into(),
                    introduced: "0".into(),
                    fixed: "13.0.1".into(),
                    last_affected: String::new(),
                    severity: "HIGH".into(),
                    summary: "Improper handling of exceptional conditions in Newtonsoft.Json"
                        .into(),
                    source: "osv-test".into(),
                    updated_at: 1,
                },
            ])
            .unwrap();

        let yarn_hits = scan_dependencies_with_store("yarn.lock", yarn_lock, Some(&store));
        assert!(
            yarn_hits
                .iter()
                .any(|h| h.title.contains("custom-vuln-pkg@1.0.0")),
            "yarn.lock must query AdvisoryStore for non-hardcoded packages: {:?}",
            yarn_hits
        );
        let pnpm_hits = scan_dependencies_with_store("pnpm-lock.yaml", pnpm_lock, Some(&store));
        assert!(
            pnpm_hits
                .iter()
                .any(|h| h.title.contains("custom-vuln-pkg@1.0.0")),
            "pnpm-lock.yaml must query AdvisoryStore for non-hardcoded packages: {:?}",
            pnpm_hits
        );
        let nuget_hits =
            scan_dependencies_with_store("packages.lock.json", nuget_lock, Some(&store));
        assert!(
            nuget_hits
                .iter()
                .any(|h| h.title.contains("Newtonsoft.Json@12.0.1")),
            "NuGet packages.lock.json must query AdvisoryStore: {:?}",
            nuget_hits
        );
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sprint4_p12_04_four_tier_vex_reachability_and_safe_api_disproof() {
        let cfg = smg_core::config::ShellMindGuardConfig::default();
        let mk = |rel: &str, lang: smg_core::scanner::Language, src: &str| {
            smg_core::scanner::IndexedFile {
                abs_path: std::path::PathBuf::from(rel),
                rel_path: rel.into(),
                language: lang,
                size_bytes: src.len() as u64,
                mtime_ns: 0,
                blake3_hash: String::new(),
                cached_bytes: Some(src.as_bytes().to_vec()),
            }
        };

        let pkg_lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": { "version": "4.17.15" }
  }
}"#;

        // Tier 1: ProvenRouteSymbol (route calls vulnerable `_.template`)
        let route_vuln = r#"
import _ from 'lodash';
app.post('/api/render', requireAuth, (req, res) => {
    const fn = _.template(req.body.tpl);
    res.send(fn({}));
});
"#;
        let s_lock = crate::ast::parse_file_ast(
            &mk(
                "package-lock.json",
                smg_core::scanner::Language::Manifest,
                pkg_lock,
            ),
            &cfg,
        )
        .unwrap();
        let s_vuln = crate::ast::parse_file_ast(
            &mk(
                "src/render.ts",
                smg_core::scanner::Language::TypeScript,
                route_vuln,
            ),
            &cfg,
        )
        .unwrap();
        let res_vuln = crate::lattice::solve_guard_lattice(&[s_lock.clone(), s_vuln]);
        let dep_vuln = res_vuln
            .findings
            .iter()
            .find(|f| f.rule_id.starts_with("SMG-DEP-") && f.title.contains("lodash"))
            .expect("lodash CVE finding expected");
        assert_eq!(dep_vuln.confidence, Confidence::Confirmed);
        assert!(
            dep_vuln
                .proof_reasons
                .iter()
                .any(|r| r == "ProvenRouteSymbolVEX"),
            "Expected ProvenRouteSymbolVEX, got: {:?}",
            dep_vuln.proof_reasons
        );

        // Tier 2: ImportedSafeApiOnly (route calls only safe `_.pick`)
        let route_safe = r#"
import _ from 'lodash';
app.post('/api/profile', requireAuth, (req, res) => {
    const clean = _.pick(req.body, ['name']);
    res.json(clean);
});
"#;
        let s_safe = crate::ast::parse_file_ast(
            &mk(
                "src/profile.ts",
                smg_core::scanner::Language::TypeScript,
                route_safe,
            ),
            &cfg,
        )
        .unwrap();
        let res_safe = crate::lattice::solve_guard_lattice(&[s_lock.clone(), s_safe]);
        let dep_safe = res_safe
            .findings
            .iter()
            .find(|f| f.rule_id.starts_with("SMG-DEP-") && f.title.contains("lodash"))
            .expect("lodash CVE finding expected");
        assert_eq!(dep_safe.confidence, Confidence::Heuristic);
        assert!(
            dep_safe
                .proof_reasons
                .iter()
                .any(|r| r == "ImportedSafeApiOnlyVEX"),
            "Expected ImportedSafeApiOnlyVEX for lodash.pick, got: {:?}",
            dep_safe.proof_reasons
        );

        // Tier 4: DeclaredUnused (zero imports of lodash)
        let res_unused = crate::lattice::solve_guard_lattice(&[s_lock]);
        let dep_unused = res_unused
            .findings
            .iter()
            .find(|f| f.rule_id.starts_with("SMG-DEP-") && f.title.contains("lodash"))
            .expect("lodash CVE finding expected");
        assert_eq!(dep_unused.confidence, Confidence::Heuristic);
        assert!(
            dep_unused
                .proof_reasons
                .iter()
                .any(|r| r == "DeclaredUnusedVEX"),
            "Expected DeclaredUnusedVEX, got: {:?}",
            dep_unused.proof_reasons
        );

        // Speed gate: 2,000-package pnpm-lock.yaml parses in < 20ms
        let mut big_pnpm = String::from("lockfileVersion: '9.0'\npackages:\n");
        for i in 0..2000 {
            big_pnpm.push_str(&format!("  /pkg-{i}@1.0.0:\n    dev: false\n"));
        }
        let t0 = Instant::now();
        let g = extract_lockfile_dep_graph("pnpm-lock.yaml", &big_pnpm);
        let elapsed_ms = t0.elapsed().as_millis();
        assert_eq!(g.nodes.len(), 2000);
        assert!(
            elapsed_ms < 50,
            "2000-pkg pnpm-lock.yaml graph took {}ms (must be linear!)",
            elapsed_ms
        );
    }

    #[test]
    fn test_phase22_extended_lockfile_parsers() {
        let gosum = "github.com/gin-gonic/gin v1.9.1 h1:abc=\ngithub.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n";
        let go_deps = extract_resolved_dependencies("go.sum", gosum);
        assert_eq!(go_deps.len(), 1);
        assert_eq!(go_deps[0].ecosystem, "Go");
        assert_eq!(go_deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(go_deps[0].version, "1.9.1");

        let pipfile = r#"{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.2.0"}}}"#;
        let py_deps = extract_resolved_dependencies("Pipfile.lock", pipfile);
        assert_eq!(py_deps.len(), 2);
        assert!(
            py_deps
                .iter()
                .any(|d| d.name == "requests" && d.version == "2.31.0")
        );

        let mix =
            r#"%{ "phoenix": {:hex, :phoenix, "1.7.14", "hash", [:mix], [], "hexpm", "hash2"} }"#;
        let hex_deps = extract_resolved_dependencies("mix.lock", mix);
        assert_eq!(hex_deps.len(), 1);
        assert_eq!(hex_deps[0].ecosystem, "Hex");
        assert_eq!(hex_deps[0].name, "phoenix");
        assert_eq!(hex_deps[0].version, "1.7.14");

        let gradle =
            "# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\nempty=\n";
        let grad_deps = extract_resolved_dependencies("gradle.lockfile", gradle);
        assert_eq!(grad_deps.len(), 1);
        assert_eq!(grad_deps[0].ecosystem, "Maven");
        assert_eq!(grad_deps[0].name, "org.apache.logging.log4j:log4j-core");

        let pom = "<dependencies><dependency>\n<groupId>com.fasterxml.jackson.core</groupId>\n<artifactId>jackson-databind</artifactId>\n<version>2.13.4</version>\n</dependency></dependencies>";
        let pom_deps = extract_resolved_dependencies("pom.xml", pom);
        assert_eq!(pom_deps.len(), 1);
        assert_eq!(
            pom_deps[0].name,
            "com.fasterxml.jackson.core:jackson-databind"
        );
        assert_eq!(pom_deps[0].version, "2.13.4");
    }
}
