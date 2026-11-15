use crate::config::ShellMindGuardConfig;
use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    TypeScript,
    JavaScript,
    Rust,
    Python,
    Go,
    Php,
    Java,
    CSharp,
    Kotlin,
    Swift,
    Dart,
    C,
    Cpp,
    Ruby,
    Bash,
    Hcl,
    Sql,
    Config,
    Manifest,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Rust => "rust",
            Language::Python => "python",
            Language::Go => "go",
            Language::Php => "php",
            Language::Java => "java",
            Language::CSharp => "csharp",
            Language::Kotlin => "kotlin",
            Language::Swift => "swift",
            Language::Dart => "dart",
            Language::C => "c",
            Language::Cpp => "cpp",
            Language::Ruby => "ruby",
            Language::Bash => "bash",
            Language::Hcl => "hcl",
            Language::Sql => "sql",
            Language::Config => "config",
            Language::Manifest => "manifest",
        }
    }

    pub fn from_path(path: &Path) -> Option<Self> {
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if matches!(
            fname,
            "package.json"
                | "package-lock.json"
                | "Cargo.toml"
                | "Cargo.lock"
                | "go.mod"
                | "requirements.txt"
                | "pyproject.toml"
                | "poetry.lock"
                | "uv.lock"
        ) {
            return Some(Language::Manifest);
        }
        if fname == ".gitignore"
            || fname == "Dockerfile"
            || fname.starts_with("Dockerfile.")
            || (fname == ".env"
                || (fname.starts_with(".env.")
                    && !matches!(
                        fname,
                        ".env.example" | ".env.sample" | ".env.template" | ".env.dist"
                    )))
        {
            return Some(Language::Config);
        }

        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "rs" => Some(Language::Rust),
            "py" => Some(Language::Python),
            "go" => Some(Language::Go),
            "php" | "phtml" => Some(Language::Php),
            "java" => Some(Language::Java),
            "cs" => Some(Language::CSharp),
            "kt" | "kts" => Some(Language::Kotlin),
            "swift" => Some(Language::Swift),
            "dart" => Some(Language::Dart),
            "c" | "h" => Some(Language::C),
            "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some(Language::Cpp),
            "rb" | "rake" | "ru" => Some(Language::Ruby),
            "sh" | "bash" | "zsh" => Some(Language::Bash),
            "tf" | "tfvars" => Some(Language::Hcl),
            "sql" => Some(Language::Sql),
            "dockerfile" | "yml" | "yaml" | "toml" | "json" | "ini" | "cfg" | "conf"
            | "properties" | "pem" | "key" => Some(Language::Config),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub language: Language,
    pub blake3_hash: String,
    pub mtime_ns: i64,
    pub size_bytes: u64,
    #[serde(skip)]
    pub cached_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_entries_seen: usize,
    pub source_files_hashed: usize,
    pub skipped_ignored_or_binary: usize,
    pub elapsed_ms: u128,
    pub files: Vec<IndexedFile>,
}

pub fn scan_repository(root: &Path, cfg: &ShellMindGuardConfig) -> Result<ScanSummary> {
    let start = Instant::now();
    let canon_root = fs::canonicalize(root)?;
    let total_seen = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);

    let ignore_set: Vec<String> = cfg
        .scan
        .ignore_paths
        .iter()
        .map(|s| s.trim_matches('/').to_string())
        .collect();

    let mut candidate_paths: Vec<(PathBuf, String, Language)> = Vec::new();
    let root_for_filter = canon_root.clone();

    let walker = WalkBuilder::new(&canon_root)
        .hidden(false)
        .require_git(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .threads(cfg.scan.max_threads)
        .filter_entry(move |entry| {
            let name = entry.file_name().to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git"
                    | ".hg"
                    | ".svn"
                    | ".shellmind-guard"
                    | "node_modules"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".mypy_cache"
                    | ".venv"
                    | "venv"
                    | ".next"
                    | ".nuxt"
                    | "__tests__"
                    | "testdata"
            ) {
                return false;
            }
            if let Ok(rel) = entry.path().strip_prefix(&root_for_filter) {
                let rel_norm = rel.to_string_lossy().replace('\\', "/");
                if rel_norm.is_empty() {
                    return true;
                }
                let parent_is_source_pkg = rel_norm
                    .rsplit_once('/')
                    .map(|(parent, _)| {
                        parent.split('/').any(|seg| {
                            matches!(
                                seg,
                                "src"
                                    | "internal"
                                    | "pkg"
                                    | "cmd"
                                    | "lib"
                                    | "app"
                                    | "controllers"
                                    | "services"
                                    | "routes"
                                    | "handlers"
                                    | "domain"
                                    | "core"
                                    | "models"
                            )
                        })
                    })
                    .unwrap_or(false);

                if !parent_is_source_pkg
                    && (name == "target" || ignore_set.iter().any(|ig| ig == name.as_ref()))
                {
                    return false;
                }
                if ignore_set.iter().any(|ig| {
                    let clean = ig.trim_matches('/');
                    !clean.is_empty()
                        && (rel_norm == clean || rel_norm.starts_with(&format!("{}/", clean)))
                }) {
                    return false;
                }
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        total_seen.fetch_add(1, Ordering::Relaxed);
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy();
        if fname.ends_with("_test.go")
            || fname.ends_with(".test.ts")
            || fname.ends_with(".spec.ts")
            || fname.ends_with(".test.tsx")
            || fname.ends_with(".spec.tsx")
            || fname.ends_with(".test.js")
            || fname.ends_with(".spec.js")
            || fname.ends_with(".test.jsx")
            || fname.ends_with(".spec.jsx")
            || fname.ends_with("_test.rs")
            || fname.ends_with("_test.py")
            || (fname.starts_with("test_") && fname.ends_with(".py"))
            || fname.ends_with("Test.java")
            || fname.ends_with("Tests.java")
            || fname.ends_with("Test.kt")
            || fname.ends_with("Tests.kt")
            || fname.ends_with("Test.cs")
            || fname.ends_with("Tests.cs")
            || fname.ends_with("Test.php")
            || fname.ends_with("Tests.php")
            || fname.ends_with("_test.dart")
            || fname.ends_with("Tests.swift")
            || fname.ends_with("_test.c")
            || fname.ends_with("_test.cpp")
            || fname.ends_with("_test.cc")
            || fname.ends_with("_spec.rb")
            || fname.ends_with("_test.rb")
            || fname.ends_with("_test.sh")
            || fname.ends_with(".bats")
        {
            skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if let Some(lang) = Language::from_path(path) {
            if let Ok(rel) = path.strip_prefix(&canon_root) {
                candidate_paths.push((
                    path.to_path_buf(),
                    rel.to_string_lossy().replace('\\', "/"),
                    lang,
                ));
            }
        } else {
            skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.scan.max_threads)
        .build()?;

    let max_bytes = cfg.scan.max_file_bytes;
    let files: Vec<IndexedFile> = pool.install(|| {
        candidate_paths
            .into_par_iter()
            .filter_map(|(abs_path, rel_path, language)| {
                let meta = fs::metadata(&abs_path).ok()?;
                let size_bytes = meta.len();
                let limit = if language == Language::Manifest {
                    max_bytes.max(16 * 1024 * 1024)
                } else {
                    max_bytes
                };
                if size_bytes > limit {
                    return None;
                }
                let mtime_ns = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);

                let bytes = fs::read(&abs_path).ok()?;
                let hash = blake3::hash(&bytes).to_hex().to_string();
                let cached_bytes = if bytes.len() <= 256 * 1024 {
                    Some(bytes)
                } else {
                    None
                };

                Some(IndexedFile {
                    rel_path,
                    abs_path,
                    language,
                    blake3_hash: hash,
                    mtime_ns,
                    size_bytes,
                    cached_bytes,
                })
            })
            .collect()
    });

    Ok(ScanSummary {
        total_entries_seen: total_seen.load(Ordering::Relaxed),
        source_files_hashed: files.len(),
        skipped_ignored_or_binary: skipped.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis(),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_keeps_nested_source_build_dir_and_pyproject() {
        let tmp = std::env::temp_dir().join(format!("vf_scanner_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("src/internal/build")).unwrap();
        fs::create_dir_all(tmp.join("build")).unwrap();
        fs::write(tmp.join("src/internal/build/handler.go"), "package build\n").unwrap();
        fs::write(tmp.join("build/bundle.js"), "console.log(1);\n").unwrap();
        fs::write(
            tmp.join("pyproject.toml"),
            "[project]\ndependencies = [\"pyyaml==5.3\"]\n",
        )
        .unwrap();

        let cfg = ShellMindGuardConfig::default();
        let res = scan_repository(&tmp, &cfg).unwrap();
        let rels: Vec<&str> = res.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(
            rels.contains(&"src/internal/build/handler.go"),
            "Nested source package src/internal/build must not be skipped: {:?}",
            rels
        );
        assert!(
            !rels.contains(&"build/bundle.js"),
            "Top-level build/ output directory must be skipped: {:?}",
            rels
        );
        let pyproj = res
            .files
            .iter()
            .find(|f| f.rel_path == "pyproject.toml")
            .expect("pyproject.toml must be indexed");
        assert_eq!(pyproj.language, Language::Manifest);

        let _ = fs::remove_dir_all(&tmp);
    }
}
