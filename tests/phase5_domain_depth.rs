//! Phase 5 — Semantic Precision, Tier-1 Framework Depth & Frontier Zero-Overhead Invariance Tests
//! (`Q107`, `Q151–Q154`, `Q101–Q109`).

use smg_core::{IndexedFile, Language, ShellMindGuardConfig, scan_repository};
use smg_graph::analyze_codebase;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn temp_repo(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("smg_p5_{tag}_{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();
    root
}

#[test]
fn tier1_python_pytorch_multiline_weights_only_safe_vs_unsafe() {
    let root = temp_repo("pytorch");
    fs::write(
        root.join("src/loader.py"),
        r#"import torch

def load_safe_inline(path):
    return torch.load(path, weights_only = True)

def load_safe_multiline(path):
    return torch.load(
        path,
        map_location="cpu",
        weights_only=True,
    )

def load_unsafe(path):
    return torch.load(path)
"#,
    )
    .unwrap();

    let cfg = ShellMindGuardConfig::default();
    let sum = scan_repository(&root, &cfg).unwrap();
    let res = analyze_codebase(&sum.files, &cfg).unwrap();
    let torch_hits: Vec<_> = res
        .findings
        .iter()
        .filter(|f| {
            f.file == "src/loader.py" && f.rule_id.contains("TORCH")
                || f.title.contains("torch.load")
        })
        .collect();

    assert!(
        !torch_hits.iter().any(|f| f.line <= 11),
        "safe weights_only=True torch.load must NOT false-positive: {torch_hits:?}"
    );
    assert!(
        torch_hits.iter().any(|f| f.line >= 13),
        "unsafe torch.load(path) must be detected: {:?}",
        res.findings
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn tier1_ts_prisma_safe_vs_raw_unsafe_and_rust_sqlx_safe() {
    let root = temp_repo("ts_rust_sql");
    fs::write(
        root.join("src/users.ts"),
        r#"export async function getUserSafe(req: any, prisma: any) {
  const id = req.params.id;
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}

export async function getUserUnsafe(req: any, prisma: any) {
  const id = req.params.id;
  return prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + id);
}
"#,
    )
    .unwrap();

    fs::write(
        root.join("src/db.rs"),
        r#"pub async fn find_user_safe(pool: &PgPool, id: &str) {
    let _ = sqlx::query!("SELECT id FROM users WHERE id = $1", id).fetch_one(pool).await;
}
"#,
    )
    .unwrap();

    let cfg = ShellMindGuardConfig::default();
    let sum = scan_repository(&root, &cfg).unwrap();
    let res = analyze_codebase(&sum.files, &cfg).unwrap();

    assert!(
        !res.findings
            .iter()
            .any(|f| f.file == "src/users.ts" && f.line <= 4 && f.rule_id == "SMG-SQLI-001"),
        "Prisma tagged-template $queryRaw must not FP"
    );
    assert!(
        res.findings
            .iter()
            .any(|f| f.file == "src/users.ts" && f.line >= 6 && f.rule_id == "SMG-SQLI-001"),
        "Prisma $queryRawUnsafe with user input must be caught: {:?}",
        res.findings
    );
    assert!(
        !res.findings
            .iter()
            .any(|f| f.file == "src/db.rs" && f.rule_id == "SMG-SQLI-001"),
        "Compile-time sqlx::query! macro must not FP"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn frontier_zero_overhead_invariance_on_pure_web_repo() {
    let root = temp_repo("frontier_zero");
    let ts = "export function greet(name: string) { return 'hi ' + name; }\n";
    fs::write(root.join("src/app.ts"), ts).unwrap();

    let files = vec![IndexedFile {
        rel_path: "src/app.ts".into(),
        abs_path: root.join("src/app.ts"),
        language: Language::TypeScript,
        blake3_hash: "0".into(),
        mtime_ns: 0,
        size_bytes: ts.len() as u64,
        cached_bytes: Some(ts.as_bytes().to_vec()),
    }];

    #[cfg(feature = "hw")]
    {
        let t0 = Instant::now();
        let hw_hits = smg_hw::scan_hardware_repo(&root, &files, false);
        assert!(
            hw_hits.is_empty(),
            "pure web repo must emit 0 smg-hw findings"
        );
        assert!(
            t0.elapsed().as_millis() < 50,
            "smg-hw pre-gate must be near-zero overhead on web repos"
        );
    }

    #[cfg(feature = "web3")]
    {
        let t0 = Instant::now();
        let web3_hits = smg_web3::scan_web3_repo_with_options(&root, &files, false, false);
        assert!(
            web3_hits.is_empty(),
            "pure web repo must emit 0 smg-web3 findings"
        );
        assert!(
            t0.elapsed().as_millis() < 50,
            "smg-web3 pre-gate must be near-zero overhead on web repos"
        );
    }

    let _ = fs::remove_dir_all(&root);
}
