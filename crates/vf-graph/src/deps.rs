use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ecosystem {
    Npm,
    Cargo,
    Go,
    PyPi,
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
];

/// Returns `(major, minor, patch, is_release)` where `is_release` is `false` for pre-releases (`-alpha`, `-rc.1`)
/// so `(1, 6, 0, false) < (1, 6, 0, true)`.
fn parse_semver_with_prerelease(raw: &str) -> Option<(u64, u64, u64, bool)> {
    let trimmed = raw
        .trim()
        .trim_start_matches(['v', 'V', '^', '~', '=', '>', '<', ' ']);
    let without_meta = trimmed
        .split(['+', ' ', ',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let (core, prerelease) = match without_meta.split_once('-') {
        Some((c, pre)) => (c.trim(), Some(pre.trim())),
        None => (without_meta, None),
    };
    if core.is_empty() || core.contains('*') {
        return None;
    }
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let is_release = prerelease.is_none_or(|p| p.is_empty());
    Some((major, minor, patch, is_release))
}

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
        rule_id: "VF-DEP-001".to_string(),
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
    for (i, line) in lines.iter().enumerate() {
        if line.contains(needle) {
            return i + 1;
        }
    }
    1
}

fn check_advisory(
    ecosystem: Ecosystem,
    pkg_name: &str,
    version_str: &str,
    rel_path: &str,
    line: usize,
    out: &mut Vec<LocalStaticFinding>,
) {
    let norm = match ecosystem {
        Ecosystem::PyPi => pkg_name.to_ascii_lowercase().replace('_', "-"),
        _ => pkg_name.to_ascii_lowercase(),
    };
    for adv in OFFLINE_ADVISORIES {
        if adv.ecosystem != ecosystem || adv.package != norm {
            continue;
        }
        let hit = match adv.fixed_below {
            None => true,
            Some((min_maj, min_min, min_pat)) => match parse_semver_with_prerelease(version_str) {
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
            },
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
            let mut hit = make_dep_finding(
                adv.severity,
                format!(
                    "High-risk dependency `{}@{}`: {}",
                    pkg_name, version_str, adv.reason
                ),
                rel_path,
                line,
                fix_hint,
            );
            hit.confidence = Confidence::Confirmed;
            out.push(hit);
        }
    }
}

fn audit_package_json(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();

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
            if is_floating_version(ver) {
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
            }
            check_advisory(Ecosystem::Npm, pkg, ver, rel_path, ln, &mut out);
        }
    }
    out
}

fn audit_package_lock(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    let mut checked: HashMap<String, String> = HashMap::new();

    if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
        for (pkg_path, info) in pkgs {
            if pkg_path.is_empty() {
                continue;
            }
            let name = pkg_path.rsplit("node_modules/").next().unwrap_or(pkg_path);
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
            if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                checked
                    .entry(name.to_string())
                    .or_insert_with(|| ver.to_string());
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
            if let Some(ver) = info.get("version").and_then(|v| v.as_str()) {
                checked
                    .entry(name.to_string())
                    .or_insert_with(|| ver.to_string());
            }
        }
    }

    for (name, ver) in checked {
        // Only perform line scan when an advisory matches to keep lockfile scanning O(n)
        let mut temp = Vec::new();
        check_advisory(Ecosystem::Npm, &name, &ver, rel_path, 1, &mut temp);
        if !temp.is_empty() {
            let ln = find_line_for_needle(&lines, &name);
            for mut item in temp {
                item.line = ln;
                item.symbol = format!("{}:{}", rel_path, ln);
                out.push(item);
            }
        }
    }

    out
}

fn audit_cargo_toml(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();

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
                    check_advisory(Ecosystem::Cargo, pkg, ver, rel_path, ln, &mut out);
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
                        check_advisory(Ecosystem::Cargo, pkg, ver, rel_path, ln, &mut out);
                    }
                    if let Some(git_url) = dep_tbl.get("git").and_then(|v| v.as_str())
                        && is_insecure_http_url(git_url)
                    {
                        out.push(make_dep_finding(
                            "HIGH",
                            format!("Insecure `http://` git dependency URL for `{}`", pkg),
                            rel_path,
                            ln,
                            "Use `https://` for git crate sources.".into(),
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn audit_cargo_lock(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(pkgs) = val.get("package").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();

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
        let mut temp = Vec::new();
        check_advisory(Ecosystem::Cargo, name, ver, rel_path, 1, &mut temp);
        if !temp.is_empty() {
            let ln = find_line_for_needle(&lines, &format!("name = \"{}\"", name));
            for mut item in temp {
                item.line = ln;
                item.symbol = format!("{}:{}", rel_path, ln);
                out.push(item);
            }
        }
    }
    out
}

fn audit_go_mod(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
    let mut in_require_block = false;
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
                check_advisory(Ecosystem::Go, mod_path, ver, rel_path, ln, &mut out);
            }
        }
    }
    out
}

fn audit_requirements_txt(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let mut out = Vec::new();
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
                check_advisory(Ecosystem::PyPi, pkg_only, ver, rel_path, ln, &mut out);
            }
        } else if spec.contains('*') || spec.to_ascii_lowercase().contains("latest") {
            out.push(make_dep_finding(
                "HIGH",
                format!("Floating wildcard Python dependency `{}`", spec),
                rel_path,
                ln,
                format!("Pin `{}` to an exact version (`package==X.Y.Z`).", pkg_only),
            ));
            check_advisory(Ecosystem::PyPi, pkg_only, "", rel_path, ln, &mut out);
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
            check_advisory(Ecosystem::PyPi, pkg_only, "", rel_path, ln, &mut out);
        }
    }
    out
}

fn audit_pyproject_toml(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();

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
        let joined = pep621_specs.join("\n");
        for mut finding in audit_requirements_txt(rel_path, &joined) {
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
                check_advisory(Ecosystem::PyPi, pkg, ver, rel_path, ln, &mut out);
            }
        }
    }

    out
}

/// Offline-first dependency and lockfile audit executed in-memory with zero network calls.
pub fn scan_dependencies(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    match fname {
        "package.json" => audit_package_json(rel_path, content),
        "package-lock.json" => audit_package_lock(rel_path, content),
        "Cargo.toml" => audit_cargo_toml(rel_path, content),
        "Cargo.lock" => audit_cargo_lock(rel_path, content),
        "go.mod" => audit_go_mod(rel_path, content),
        "requirements.txt" => audit_requirements_txt(rel_path, content),
        "pyproject.toml" => audit_pyproject_toml(rel_path, content),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let hits = scan_dependencies("package.json", pkg_json);
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
        let lock_hits = scan_dependencies("package-lock.json", lock);
        assert!(lock_hits.iter().any(|h| h.title.contains("http://")));
        assert!(lock_hits.iter().any(|h| h.title.contains("minimist@1.2.5")));
    }

    #[test]
    fn test_cargo_go_python_manifests() {
        let cargo = "[dependencies]\nserde_yaml = \"0.9\"\nchrono = \"0.4\"\nwildcard = \"*\"\n";
        let c_hits = scan_dependencies("Cargo.toml", cargo);
        assert!(c_hits.iter().any(|h| h.title.contains("serde_yaml")));
        assert!(
            !c_hits.iter().any(|h| h.title.contains("chrono")),
            "2-component caret range chrono = \"0.4\" in Cargo.toml must not false-positive when >=0.4.20 is allowed"
        );
        assert!(c_hits.iter().any(|h| h.title.contains("wildcard")));

        let gomod = "module example.com/app\nrequire (\n  github.com/dgrijalva/jwt-go v3.2.0\n  golang.org/x/net latest\n)\n";
        let g_hits = scan_dependencies("go.mod", gomod);
        assert!(g_hits.iter().any(|h| h.title.contains("jwt-go")));
        assert!(g_hits.iter().any(|h| h.title.contains("latest")));

        let reqs = "pyyaml>=5.3.1\nflask\n--extra-index-url http://pypi.insecure.local/simple\n";
        let p_hits = scan_dependencies("requirements.txt", reqs);
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
        let pp_hits = scan_dependencies("pyproject.toml", pyproj);
        assert!(pp_hits.iter().any(|h| h.title.contains("pyyaml@5.3.1")));
        assert!(pp_hits.iter().any(|h| h.title.contains("urllib3@1.26.4")));

        let pre_pkg = r#"{"dependencies": {"axios": "1.6.0-alpha.1"}}"#;
        let pre_hits = scan_dependencies("package.json", pre_pkg);
        assert!(
            pre_hits
                .iter()
                .any(|h| h.title.contains("axios@1.6.0-alpha.1")),
            "Pre-release 1.6.0-alpha.1 is < 1.6.0 and must be flagged"
        );
    }
}
