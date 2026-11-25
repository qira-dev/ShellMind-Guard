use crate::ast::{FileAstSummary, ImportFileIndex, resolve_import_target_indexed};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

/// Collects repository-relative file paths modified since `git_ref` (plus staged/untracked changes).
/// Rejects flag-like refs (`-...`) to prevent git argument injection.
pub fn collect_git_changed_files(root: &Path, git_ref: &str) -> Result<HashSet<String>> {
    let trimmed = git_ref.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') || trimmed.contains('\0') {
        bail!("Invalid git reference '{}'", git_ref);
    }

    let mut changed = HashSet::new();
    for args in [
        vec!["diff", "--name-only", trimmed, "--"],
        vec!["diff", "--name-only", "--cached", "--"],
        vec!["ls-files", "--others", "--exclude-standard"],
    ] {
        let out = Command::new("git").args(&args).current_dir(root).output()?;
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                let norm = line.trim().replace('\\', "/");
                if !norm.is_empty() {
                    changed.insert(norm);
                }
            }
        } else if args[0] == "diff" && args[2] == trimmed {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("git diff against '{}' failed: {}", trimmed, err.trim());
        }
    }
    Ok(changed)
}

/// Returns true when any changed file has repository-wide security impact
/// (lockfiles, `.shellmind-guard*` config, or shared auth/middleware/router entrypoints).
pub fn should_force_full_scan_on_diff(changed: &HashSet<String>) -> bool {
    changed.iter().any(|rel| {
        let low = rel.to_ascii_lowercase();
        let fname = low.rsplit('/').next().unwrap_or(&low);
        fname.starts_with(".shellmind-guard")
            || fname.starts_with(".gitleaks")
            || fname == ".trivyignore"
            || fname.starts_with("openapi.")
            || fname.starts_with("swagger.")
            || matches!(
                fname,
                "package.json"
                    | "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "bun.lock"
                    | "deno.lock"
                    | "cargo.toml"
                    | "cargo.lock"
                    | "go.mod"
                    | "go.sum"
                    | "requirements.txt"
                    | "pyproject.toml"
                    | "poetry.lock"
                    | "uv.lock"
                    | "pipfile"
                    | "pipfile.lock"
                    | "conda-lock.yml"
                    | "pom.xml"
                    | "build.gradle"
                    | "build.gradle.kts"
                    | "gradle.lockfile"
                    | "packages.lock.json"
                    | "composer.json"
                    | "composer.lock"
                    | "gemfile"
                    | "gemfile.lock"
                    | "package.resolved"
                    | "pubspec.yaml"
                    | "pubspec.lock"
                    | "mix.lock"
                    | ".gitignore"
                    | "dockerfile"
            )
            || low.contains("/middleware/")
            || low.contains("/auth/")
            || low.contains("/guards/")
            || fname.contains("middleware")
            || fname == "app.ts"
            || fname == "app.js"
            || fname == "server.ts"
            || fname == "server.js"
            || fname == "server.mjs"
            || fname == "main.rs"
            || fname == "main.go"
            || fname == "main.py"
    })
}

/// Computes the impacted file subgraph (changed files + transitive reverse callers + direct callees)
/// for sub-30ms `--changed-since` PR verification, falling back cleanly to all files when a
/// global config/lockfile/middleware file was touched.
pub fn slice_summaries_for_changed_files<'a>(
    summaries: &'a [FileAstSummary],
    changed: &HashSet<String>,
) -> (bool, Vec<&'a FileAstSummary>) {
    if changed.is_empty() {
        return (false, Vec::new());
    }
    if should_force_full_scan_on_diff(changed) {
        return (true, summaries.iter().collect());
    }

    let known_files: HashSet<&str> = summaries.iter().map(|s| s.rel_path.as_str()).collect();
    let known_owned: HashSet<String> = known_files.iter().map(|s| (*s).to_string()).collect();

    // Forward imports: caller -> callee, Reverse callers: callee -> caller
    let mut forward: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();

    // Map exported/top-level symbol names -> defining files as fallback link resolution
    let mut sym_defs: HashMap<&str, Vec<&str>> = HashMap::new();
    for s in summaries {
        for sym in &s.symbols {
            sym_defs
                .entry(sym.name.as_str())
                .or_default()
                .push(s.rel_path.as_str());
        }
    }

    let import_index = ImportFileIndex::new(&known_owned);
    for s in summaries {
        let src = s.rel_path.as_str();
        for imp in &s.imports {
            if let Some(target) =
                resolve_import_target_indexed(src, &imp.from_specifier, &import_index)
                && let Some(&target_ref) = known_files.get(target.as_str())
            {
                forward.entry(src).or_default().push(target_ref);
                reverse.entry(target_ref).or_default().push(src);
            }
        }
        for sym in &s.symbols {
            for callee in &sym.calls {
                let leaf = callee.rsplit('.').next().unwrap_or(callee.as_str());
                if let Some(defs) = sym_defs.get(leaf) {
                    for &d in defs {
                        if d != src {
                            forward.entry(src).or_default().push(d);
                            reverse.entry(d).or_default().push(src);
                        }
                    }
                }
            }
        }
    }

    let mut visited: HashSet<&str> = HashSet::new();
    let mut q = VecDeque::new();
    for s in summaries {
        let rel = s.rel_path.as_str();
        if changed.contains(rel) && visited.insert(rel) {
            q.push_back(rel);
        }
    }

    while let Some(cur) = q.pop_front() {
        for list in [reverse.get(cur), forward.get(cur)].into_iter().flatten() {
            for &nxt in list {
                if visited.insert(nxt) {
                    q.push_back(nxt);
                }
            }
        }
    }

    let slice = summaries
        .iter()
        .filter(|s| visited.contains(s.rel_path.as_str()))
        .collect();
    (false, slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{ImportRef, SymbolInfo, SymbolKind};

    fn dummy_summary(rel: &str, imports: Vec<&str>, calls: Vec<&str>) -> FileAstSummary {
        FileAstSummary {
            rel_path: rel.into(),
            imports: imports
                .into_iter()
                .map(|p| ImportRef {
                    symbol_name: "*".into(),
                    from_specifier: p.into(),
                    remote_name: None,
                })
                .collect(),
            symbols: vec![SymbolInfo {
                id: format!("{}::fn", rel),
                rel_path: rel.into(),
                name: rel.rsplit('/').next().unwrap_or(rel).to_string(),
                kind: SymbolKind::Function,
                calls: calls.into_iter().map(|c| c.to_string()).collect(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_subgraph_slices_reverse_callers_and_falls_back_on_lockfile_or_middleware() {
        let summaries = vec![
            dummy_summary("src/routes/pay.ts", vec!["../services/ledger"], vec![]),
            dummy_summary("src/services/ledger.ts", vec![], vec![]),
            dummy_summary("src/routes/unrelated.ts", vec![], vec![]),
        ];

        // Modifying leaf service `ledger.ts` pulls in its caller `pay.ts` but excludes `unrelated.ts`
        let changed = HashSet::from(["src/services/ledger.ts".to_string()]);
        let (fallback, slice) = slice_summaries_for_changed_files(&summaries, &changed);
        assert!(!fallback);
        let paths: Vec<&str> = slice.iter().map(|s| s.rel_path.as_str()).collect();
        assert!(paths.contains(&"src/services/ledger.ts"));
        assert!(paths.contains(&"src/routes/pay.ts"));
        assert!(!paths.contains(&"src/routes/unrelated.ts"));

        // Modifying shared middleware or lockfile triggers full-graph fallback
        let lock_changed = HashSet::from(["package-lock.json".to_string()]);
        let (fallback_lock, slice_lock) =
            slice_summaries_for_changed_files(&summaries, &lock_changed);
        assert!(fallback_lock);
        assert_eq!(slice_lock.len(), 3);

        let mw_changed = HashSet::from(["src/middleware/auth.ts".to_string()]);
        assert!(should_force_full_scan_on_diff(&mw_changed));

        // Invalid git ref starting with '-' is rejected
        assert!(collect_git_changed_files(Path::new("."), "--exec=evil").is_err());
    }
}
