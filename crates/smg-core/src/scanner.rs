use crate::config::ShellMindGuardConfig;
use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, UNIX_EPOCH};

const MAX_TOTAL_CACHED_BYTES: usize = 256 * 1024 * 1024;

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
    Solidity,
    Move,
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
            Language::Solidity => "solidity",
            Language::Move => "move",
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
                | "npm-shrinkwrap.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "bun.lock"
                | "deno.lock"
                | "Cargo.toml"
                | "Cargo.lock"
                | "go.mod"
                | "go.sum"
                | "requirements.txt"
                | "pyproject.toml"
                | "poetry.lock"
                | "uv.lock"
                | "Pipfile"
                | "Pipfile.lock"
                | "conda-lock.yml"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "gradle.lockfile"
                | "packages.lock.json"
                | "composer.json"
                | "composer.lock"
                | "Gemfile"
                | "Gemfile.lock"
                | "Package.resolved"
                | "Cartfile.resolved"
                | "pubspec.yaml"
                | "pubspec.lock"
                | "mix.lock"
                | "rebar.lock"
                | ".npmrc"
        ) {
            return Some(Language::Manifest);
        }
        let low_fname = fname.to_ascii_lowercase();
        if fname == ".gitignore"
            || low_fname == "dockerfile"
            || low_fname.starts_with("dockerfile.")
            || matches!(
                fname,
                ".envrc"
                    | "id_rsa"
                    | "id_ed25519"
                    | "id_ecdsa"
                    | "AndroidManifest.xml"
                    | "network_security_config.xml"
                    | "Info.plist"
                    | "Podfile"
            )
            || matches!(
                low_fname.as_str(),
                "openapi.json"
                    | "openapi.yaml"
                    | "openapi.yml"
                    | "swagger.json"
                    | "swagger.yaml"
                    | "swagger.yml"
            )
            || (low_fname == ".env"
                || (low_fname.starts_with(".env.")
                    && !matches!(
                        low_fname.as_str(),
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
            "tf" | "tfvars" | "hcl" => Some(Language::Hcl),
            "sql" => Some(Language::Sql),
            "sol" => Some(Language::Solidity),
            "move" => Some(Language::Move),
            "dockerfile" | "yml" | "yaml" | "toml" | "json" | "ini" | "cfg" | "conf"
            | "properties" | "pem" | "crt" | "cer" | "key" | "ld" | "lds" | "svd" => {
                Some(Language::Config)
            }
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanOptions {
    #[serde(default)]
    pub include_generated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_entries_seen: usize,
    pub source_files_hashed: usize,
    pub skipped_ignored_or_binary: usize,
    pub elapsed_ms: u128,
    pub files: Vec<IndexedFile>,
}

/// Returns true when a file path matches generated/protobuf/minified stub conventions.
pub fn is_generated_file_path(rel_path: &str) -> bool {
    let low = rel_path.replace('\\', "/").to_ascii_lowercase();
    let fname = low.rsplit('/').next().unwrap_or(&low);
    fname.ends_with(".pb.go")
        || fname.ends_with("_pb2.py")
        || fname.ends_with("_pb2_grpc.py")
        || fname.ends_with(".generated.ts")
        || fname.ends_with(".generated.js")
        || fname.ends_with(".generated.tsx")
        || fname.ends_with(".generated.rs")
        || fname.ends_with(".g.dart")
        || fname.ends_with(".freezed.dart")
        || fname.ends_with(".min.js")
        || fname.ends_with(".bundle.js")
        || low.starts_with("dist/")
        || low.contains("/dist/")
        || low.starts_with("build/generated/")
        || low.contains("/generated/")
}

/// Detects standard compiler/protobuf generated headers within the first 512 bytes.
pub fn has_generated_header(bytes: &[u8]) -> bool {
    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
    let low = prefix.to_ascii_lowercase();
    (low.contains("code generated") && low.contains("do not edit"))
        || low.contains("@generated")
        || low.contains("auto-generated file. do not edit")
}

fn is_skipped_test_filename(fname: &str) -> bool {
    fname.ends_with("_test.go")
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
}

static INCLUDE_TESTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

thread_local! {
    static THREAD_INCLUDE_TESTS: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

fn effective_include_tests() -> bool {
    THREAD_INCLUDE_TESTS
        .with(|c| c.get())
        .unwrap_or_else(|| INCLUDE_TESTS.load(std::sync::atomic::Ordering::SeqCst))
}

/// Runs `f` with a thread-scoped `include_tests` override that never bleeds to concurrent threads.
pub fn with_include_tests<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
    struct Guard(Option<bool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            THREAD_INCLUDE_TESTS.with(|c| c.set(self.0));
        }
    }
    let prev = THREAD_INCLUDE_TESTS.with(|c| {
        let p = c.get();
        c.set(Some(enabled));
        p
    });
    let _g = Guard(prev);
    f()
}

/// Enables or disables scanning of test/mock/harness source paths (used by `--include-tests`
/// for security benchmark / PoC repositories such as `DeFiVulnLabs`).
pub fn set_include_tests(enabled: bool) {
    INCLUDE_TESTS.store(enabled, std::sync::atomic::Ordering::SeqCst);
}

/// Identifies dedicated unit/integration test, mock, and formal-verification harness paths so
/// scanners can suppress noisy non-secret findings while preserving secret/credential leak checks.
pub fn is_test_source_path(rel_path: &str) -> bool {
    if effective_include_tests() {
        return false;
    }
    let low = rel_path.replace('\\', "/").to_ascii_lowercase();
    let fname = low.rsplit('/').next().unwrap_or(&low);
    let has_test_dir = low.split('/').any(|seg| {
        matches!(
            seg,
            "tests"
                | "test"
                | "__tests__"
                | "spec"
                | "testdata"
                | "mocks"
                | "mock"
                | "harnesses"
                | "harness"
        )
    });
    has_test_dir
        || matches!(
            fname,
            "test.rs" | "tests.rs" | "test.py" | "tests.py" | "test.js" | "test.ts"
        )
        || fname.ends_with("_test.go")
        || fname.ends_with("_test.rs")
        || fname.ends_with("_test.py")
        || (fname.starts_with("test_") && fname.ends_with(".py"))
        || fname.ends_with(".test.ts")
        || fname.ends_with(".spec.ts")
        || fname.ends_with(".test.tsx")
        || fname.ends_with(".spec.tsx")
        || fname.ends_with(".test.js")
        || fname.ends_with(".spec.js")
        || fname.ends_with(".test.jsx")
        || fname.ends_with(".spec.jsx")
        || fname.ends_with("_spec.rb")
        || fname.ends_with("_test.rb")
        || fname.ends_with(".t.sol")
        || fname.ends_with("mock.sol")
        || fname.ends_with("harness.sol")
}

fn should_visit_entry(
    entry: &ignore::DirEntry,
    root: &Path,
    ignore_set: &[String],
    include_tests: bool,
) -> bool {
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
    ) {
        return false;
    }
    if !include_tests && matches!(name.as_ref(), "__tests__" | "testdata") {
        return false;
    }
    if let Ok(rel) = entry.path().strip_prefix(root) {
        let rel_norm = rel.to_string_lossy().replace('\\', "/");
        if rel_norm.is_empty() {
            return true;
        }
        let is_cargo_or_maven_target = name == "target"
            && entry
                .path()
                .parent()
                .is_some_and(|p| p.join("Cargo.toml").exists() || p.join("pom.xml").exists());
        if is_cargo_or_maven_target {
            return false;
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
                            | "controllers"
                            | "routes"
                            | "handlers"
                            | "domain"
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
                && (rel_norm == clean
                    || rel_norm
                        .strip_prefix(clean)
                        .is_some_and(|r| r.starts_with('/')))
        }) {
            return false;
        }
    }
    true
}

fn is_extra_sensitive_filename(low: &str) -> bool {
    low == ".env"
        || (low.starts_with(".env.")
            && !matches!(
                low,
                ".env.example" | ".env.sample" | ".env.template" | ".env.dist"
            ))
        || low == ".envrc"
        || low == ".npmrc"
        || low.ends_with(".pem")
        || low.ends_with(".key")
        || low == "id_rsa"
        || low == "id_ecdsa"
        || low == "id_ed25519"
}

pub fn scan_repository(root: &Path, cfg: &ShellMindGuardConfig) -> Result<ScanSummary> {
    scan_repository_with_options(root, cfg, &ScanOptions::default())
}

pub fn scan_repository_with_options(
    root: &Path,
    cfg: &ShellMindGuardConfig,
    opts: &ScanOptions,
) -> Result<ScanSummary> {
    let start = Instant::now();
    let canon_root = fs::canonicalize(root)?;
    let total_seen = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let include_tests = effective_include_tests();

    let ignore_set: Vec<String> = cfg
        .scan
        .ignore_paths
        .iter()
        .map(|s| s.trim_matches('/').to_string())
        .collect();

    let mut candidate_paths: Vec<(PathBuf, String, Language)> = Vec::new();
    let root_for_filter = canon_root.clone();
    let ignore_for_filter = ignore_set.clone();

    let walker = WalkBuilder::new(&canon_root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .threads(cfg.scan.max_threads)
        .filter_entry(move |entry| {
            should_visit_entry(entry, &root_for_filter, &ignore_for_filter, include_tests)
        })
        .build();

    let mut seen_rel: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in walker.flatten() {
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        total_seen.fetch_add(1, Ordering::Relaxed);
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy();
        if !include_tests && is_skipped_test_filename(&fname) {
            skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if let Some(lang) = Language::from_path(path)
            && let Ok(rel) = path.strip_prefix(&canon_root)
        {
            let rel_norm = rel.to_string_lossy().replace('\\', "/");
            if !opts.include_generated && is_generated_file_path(&rel_norm) {
                skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if seen_rel.insert(rel_norm.clone()) {
                candidate_paths.push((path.to_path_buf(), rel_norm, lang));
            }
        } else {
            skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Council CASE-001 T1: Bounded sensitive-file discovery pass so `.gitignore`
    // (including ignored ancestor directories) never blinds working-tree secret scanning
    // while still honoring built-in hard-prunes (`node_modules`, `venv`, `target`, `.git`).
    const MAX_EXTRA_SENSITIVE_FILES: usize = 2048;
    let root_for_sens = canon_root.clone();
    let ignore_for_sens = ignore_set.clone();
    let sens_walker = WalkBuilder::new(&canon_root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .threads(1)
        .filter_entry(move |entry| {
            should_visit_entry(entry, &root_for_sens, &ignore_for_sens, include_tests)
        })
        .build();
    let mut extra_sens = 0usize;
    for entry in sens_walker.flatten() {
        if extra_sens >= MAX_EXTRA_SENSITIVE_FILES {
            break;
        }
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let low = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !is_extra_sensitive_filename(&low) {
            continue;
        }
        let path = entry.path();
        if let Ok(rel) = path.strip_prefix(&canon_root) {
            let rel_norm = rel.to_string_lossy().replace('\\', "/");
            if seen_rel.insert(rel_norm.clone()) {
                candidate_paths.push((path.to_path_buf(), rel_norm, Language::Config));
                extra_sens += 1;
            }
        }
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.scan.max_threads)
        .build()?;

    let max_bytes = cfg.scan.max_file_bytes;
    let include_generated = opts.include_generated;
    let cached_budget_used = AtomicUsize::new(0);
    let files: Vec<IndexedFile> = pool.install(|| {
        candidate_paths
            .into_par_iter()
            .filter_map(|(abs_path, rel_path, language)| {
                let Ok(canon_file) = fs::canonicalize(&abs_path) else {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                if !canon_file.starts_with(&canon_root) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                let Ok(file) = fs::File::open(&canon_file) else {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                let Ok(meta) = file.metadata() else {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                let limit = if language == Language::Manifest {
                    max_bytes.max(16 * 1024 * 1024)
                } else {
                    max_bytes
                };
                if meta.len() > limit {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                let mtime_ns = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
                    .unwrap_or(0);

                let mut bytes = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
                if file
                    .take(limit.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .is_err()
                {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                let size_bytes = bytes.len() as u64;
                if size_bytes > limit {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                // Skip binary blobs containing NUL bytes in the leading 8 KiB
                if bytes[..bytes.len().min(8192)].contains(&0u8) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                if !include_generated && has_generated_header(&bytes) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                let hash = blake3::hash(&bytes).to_hex().to_string();
                let cached_bytes = if bytes.len() <= 256 * 1024 {
                    let mut reserved = false;
                    let mut cur = cached_budget_used.load(Ordering::Relaxed);
                    while let Some(next) = cur.checked_add(bytes.len()) {
                        if next > MAX_TOTAL_CACHED_BYTES {
                            break;
                        }
                        match cached_budget_used.compare_exchange_weak(
                            cur,
                            next,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => {
                                reserved = true;
                                break;
                            }
                            Err(actual) => cur = actual,
                        }
                    }
                    if reserved { Some(bytes) } else { None }
                } else {
                    None
                };

                Some(IndexedFile {
                    rel_path,
                    abs_path: canon_file,
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

/// Fast metadata-only signature (`(rel_path, mtime_ns, size_bytes)`) sorted by `rel_path`
/// for `scan --watch` polling without reading or BLAKE3-hashing file contents on idle ticks.
pub fn scan_repository_metadata_signature(
    root: &Path,
    cfg: &ShellMindGuardConfig,
) -> Result<Vec<(String, i64, u64)>> {
    scan_repository_metadata_signature_with_options(root, cfg, &ScanOptions::default())
}

pub fn scan_repository_metadata_signature_with_options(
    root: &Path,
    cfg: &ShellMindGuardConfig,
    opts: &ScanOptions,
) -> Result<Vec<(String, i64, u64)>> {
    let canon_root = fs::canonicalize(root)?;
    let include_tests = effective_include_tests();
    let ignore_set: Vec<String> = cfg
        .scan
        .ignore_paths
        .iter()
        .map(|s| s.trim_matches('/').to_string())
        .collect();
    let root_for_filter = canon_root.clone();
    let ignore_for_filter = ignore_set.clone();
    let walker = WalkBuilder::new(&canon_root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .threads(cfg.scan.max_threads)
        .filter_entry(move |entry| {
            should_visit_entry(entry, &root_for_filter, &ignore_for_filter, include_tests)
        })
        .build();

    let max_bytes = cfg.scan.max_file_bytes;
    let mut sig = Vec::new();
    let mut seen_rel: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in walker.flatten() {
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy();
        if !include_tests && is_skipped_test_filename(&fname) {
            continue;
        }
        if let Some(lang) = Language::from_path(path)
            && let Ok(rel) = path.strip_prefix(&canon_root)
            && let Ok(canon_file) = fs::canonicalize(path)
            && canon_file.starts_with(&canon_root)
            && let Ok(meta) = fs::metadata(&canon_file)
        {
            let rel_norm = rel.to_string_lossy().replace('\\', "/");
            if !opts.include_generated && is_generated_file_path(&rel_norm) {
                continue;
            }
            let size_bytes = meta.len();
            let limit = if lang == Language::Manifest {
                max_bytes.max(16 * 1024 * 1024)
            } else {
                max_bytes
            };
            if size_bytes > limit {
                continue;
            }
            let mtime_ns = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
                .unwrap_or(0);
            if seen_rel.insert(rel_norm.clone()) {
                sig.push((rel_norm, mtime_ns, size_bytes));
            }
        }
    }

    const MAX_EXTRA_SENSITIVE_FILES: usize = 2048;
    let root_for_sens = canon_root.clone();
    let ignore_for_sens = ignore_set;
    let sens_walker = WalkBuilder::new(&canon_root)
        .hidden(false)
        .follow_links(false)
        .require_git(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .threads(1)
        .filter_entry(move |entry| {
            should_visit_entry(entry, &root_for_sens, &ignore_for_sens, include_tests)
        })
        .build();
    let mut extra_sens = 0usize;
    for entry in sens_walker.flatten() {
        if extra_sens >= MAX_EXTRA_SENSITIVE_FILES {
            break;
        }
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let low = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !is_extra_sensitive_filename(&low) {
            continue;
        }
        let path = entry.path();
        if let Ok(rel) = path.strip_prefix(&canon_root)
            && let Ok(canon_file) = fs::canonicalize(path)
            && canon_file.starts_with(&canon_root)
            && let Ok(meta) = fs::metadata(&canon_file)
        {
            let size_bytes = meta.len();
            if size_bytes > max_bytes {
                continue;
            }
            let rel_norm = rel.to_string_lossy().replace('\\', "/");
            if seen_rel.insert(rel_norm.clone()) {
                let mtime_ns = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
                    .unwrap_or(0);
                sig.push((rel_norm, mtime_ns, size_bytes));
                extra_sens += 1;
            }
        }
    }

    sig.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_keeps_nested_source_build_dir_and_pyproject() {
        let tmp = std::env::temp_dir().join(format!("smg_scanner_test_{}", std::process::id()));
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

    #[test]
    fn test_scanner_skips_generated_stubs_by_default_with_override() {
        let tmp = std::env::temp_dir().join(format!("smg_gen_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("src")).unwrap();
        fs::write(tmp.join("src/api.pb.go"), "package api\nfunc Call() {}\n").unwrap();
        fs::write(
            tmp.join("src/custom_gen.go"),
            "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage api\n",
        )
        .unwrap();
        fs::write(tmp.join("src/app.ts"), "export const x = 1;\n").unwrap();

        let cfg = ShellMindGuardConfig::default();
        let def_res = scan_repository(&tmp, &cfg).unwrap();
        let rels: Vec<&str> = def_res.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(rels.contains(&"src/app.ts"));
        assert!(!rels.contains(&"src/api.pb.go"));
        assert!(!rels.contains(&"src/custom_gen.go"));

        let opt_res = scan_repository_with_options(
            &tmp,
            &cfg,
            &ScanOptions {
                include_generated: true,
            },
        )
        .unwrap();
        let rels_all: Vec<&str> = opt_res.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(rels_all.contains(&"src/api.pb.go"));
        assert!(rels_all.contains(&"src/custom_gen.go"));
        assert!(is_test_source_path("tests/auth_spec.ts"));
        assert!(!is_test_source_path("fixtures/vuln-auth-rust/src/main.rs"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
