use smg_core::{ShellMindGuardConfig, normalize_rel_path_posix_nfc, scan_repository};
use smg_graph::{GraphAnalysisResult, analyze_codebase, canonical_sort_findings};
use smg_report::to_sarif_json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn run_full_static_pipeline(
    root: &Path,
    max_threads: usize,
) -> (GraphAnalysisResult, String, String) {
    let mut cfg = ShellMindGuardConfig::load_trusted_from_dir(root, false).unwrap_or_default();
    cfg.scan.max_threads = max_threads;
    let summary = scan_repository(root, &cfg).expect("scan_repository should succeed");
    let mut graph =
        analyze_codebase(&summary.files, &cfg).expect("analyze_codebase should succeed");
    canonical_sort_findings(&mut graph.findings);
    let json = serde_json::to_string_pretty(&graph).expect("serialize GraphAnalysisResult");
    let sarif = to_sarif_json(&graph.findings, &[]);
    (graph, json, sarif)
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn determinism_1t_vs_16t_fixtures() {
    for fixture in ["vuln-auth-rust", "vuln-payment-node"] {
        let root = fixture_dir(fixture);
        assert!(root.exists(), "missing fixture dir: {}", root.display());

        let (g1, json_1t, sarif_1t) = run_full_static_pipeline(&root, 1);
        let (g16, json_16t, sarif_16t) = run_full_static_pipeline(&root, 16);

        assert_eq!(
            g1.parsed_files, g16.parsed_files,
            "parsed_files mismatch on {fixture}"
        );
        assert_eq!(
            g1.symbol_count, g16.symbol_count,
            "symbol_count mismatch on {fixture}"
        );
        assert_eq!(
            g1.edge_count, g16.edge_count,
            "edge_count mismatch on {fixture}"
        );
        assert_eq!(
            json_1t, json_16t,
            "1T vs 16T JSON output diverged on fixture {fixture}"
        );
        assert_eq!(
            sarif_1t, sarif_16t,
            "1T vs 16T SARIF 2.1.0 output diverged on fixture {fixture}"
        );
    }
}

#[test]
fn golden_snapshots_match_fixtures() {
    let golden_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    let update = std::env::var("SMG_UPDATE_GOLDEN").is_ok_and(|v| v == "1");

    for (fixture, golden_name) in [
        ("vuln-auth-rust", "vuln_auth_rust.json"),
        ("vuln-payment-node", "vuln_payment_node.json"),
    ] {
        let root = fixture_dir(fixture);
        let (_g, json_1t, _sarif) = run_full_static_pipeline(&root, 1);
        let golden_path = golden_dir.join(golden_name);

        if update {
            fs::create_dir_all(&golden_dir).expect("create tests/golden");
            fs::write(&golden_path, &json_1t).expect("write golden snapshot");
            continue;
        }

        let expected = fs::read_to_string(&golden_path).unwrap_or_else(|e| {
            panic!(
                "missing golden snapshot {} ({e}); run with SMG_UPDATE_GOLDEN=1",
                golden_path.display()
            )
        });
        assert_eq!(
            json_1t, expected,
            "Golden snapshot drift detected on fixture {fixture}! \
             If this behavioral change is intentional, update via SMG_UPDATE_GOLDEN=1."
        );
    }
}

#[test]
fn determinism_1t_vs_16t_bom_crlf_unicode_non_utf8_bidi() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("smg_p1_det_{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();

    // 1. UTF-8 BOM + CRLF Python file with SQLi sink on line 4
    let bom_crlf = "\u{FEFF}import sqlite3\r\ndef get_user(conn, uid):\r\n    q = f\"SELECT * FROM users WHERE id = {uid}\"\r\n    return conn.execute(q)\r\n";
    fs::write(root.join("src/bom_crlf.py"), bom_crlf.as_bytes()).unwrap();

    // 2. Unicode NFD filename (`cafe\u{0301}.py`) -> normalized to NFC (`café.py`)
    let nfd_name = "cafe\u{0301}.py";
    fs::write(
        root.join("src").join(nfd_name),
        "import os\ndef run_cmd(x):\n    os.system('echo ' + x)\n",
    )
    .unwrap();

    // 3. Invalid non-UTF8 file without NUL bytes -> must skip safely & count skipped_non_utf8
    fs::write(
        root.join("src/non_utf8.py"),
        [0x64u8, 0x65, 0x66, 0x20, 0xFF, 0xFE, 0x80, 0x81, b'\n'],
    )
    .unwrap();

    // 4. Trojan Source Bidi U+202E file (valid UTF-8) -> must NOT be skipped and must be detected
    let bidi_src = "fn check_admin(role: &str) -> bool {\n    let access = \"user\u{202E} /* check */\";\n    role == access\n}\n";
    fs::write(root.join("src/access_guard.rs"), bidi_src.as_bytes()).unwrap();

    // 5. Extra parallel files to exercise multi-threaded Rayon work-stealing
    for i in 0..16 {
        let js = format!(
            "const cp = require('child_process');\nexports.handler_{i} = (req, res) => {{\n  cp.exec('ls ' + req.query.dir);\n}};\n"
        );
        fs::write(root.join(format!("src/worker_{i:02}.js")), js).unwrap();
    }

    let mut cfg1 = ShellMindGuardConfig::default();
    cfg1.scan.max_threads = 1;
    let sum1 = scan_repository(&root, &cfg1).expect("1T scan");
    assert!(
        sum1.skipped_non_utf8 >= 1,
        "expected skipped_non_utf8 >= 1, got {}",
        sum1.skipped_non_utf8
    );

    // Verify Unicode NFC + POSIX normalization on relative paths
    let nfc_expected = normalize_rel_path_posix_nfc("src/cafe\u{0301}.py");
    assert_eq!(nfc_expected, "src/caf\u{00E9}.py");
    assert!(
        sum1.files.iter().any(|f| f.rel_path == nfc_expected),
        "expected NFC-normalized rel_path {nfc_expected} in {:?}",
        sum1.files.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
    );

    let (g1, json_1t, sarif_1t) = run_full_static_pipeline(&root, 1);
    let (_g16, json_16t, sarif_16t) = run_full_static_pipeline(&root, 16);

    assert!(
        g1.findings
            .iter()
            .any(|f| f.file == "src/access_guard.rs" && f.rule_id == "SMG-MCP-UNICODE-STEGO"),
        "Trojan Source Bidi detection must remain intact; findings: {:?}",
        g1.findings
            .iter()
            .map(|f| (&f.rule_id, &f.file, f.line))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        json_1t, json_16t,
        "1T vs 16T JSON diverged on edge-case repo"
    );
    assert_eq!(
        sarif_1t, sarif_16t,
        "1T vs 16T SARIF diverged on edge-case repo"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn baseline_v2_survives_unrelated_line_shifts() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("smg_p1_baseline_v2_{nanos}"));
    fs::create_dir_all(root.join("src")).unwrap();

    let vuln_file = root.join("src/exec.js");
    let body = "const cp = require('child_process');\nfunction runCmd(req, res) {\n  cp.exec('ls ' + req.query.dir);\n}\nmodule.exports = { runCmd };\n";
    fs::write(&vuln_file, body).unwrap();

    let baseline_path = root.join(".smg-baseline.json");
    let bin = env!("CARGO_BIN_EXE_smg");

    // 1. Write v2 baseline
    let out1 = Command::new(bin)
        .args([
            "scan",
            root.to_str().unwrap(),
            "--write-baseline",
            baseline_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run smg --write-baseline");
    assert!(
        out1.status.success(),
        "write-baseline failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let baseline_raw = fs::read_to_string(&baseline_path).expect("read baseline");
    assert!(
        baseline_raw.contains("\"version\": 2") && baseline_raw.contains("sink_line_hash"),
        "expected v2 baseline schema with sink_line_hash, got:\n{baseline_raw}"
    );

    // 2. Insert 15 unrelated comment/blank lines ABOVE the vulnerable function
    let shifted = format!("{}{}", "// unrelated header comment\n\n".repeat(8), body);
    fs::write(&vuln_file, shifted).unwrap();

    // 3. Re-scan with --baseline and verify finding is still suppressed (exit 0 with --ci)
    let out2 = Command::new(bin)
        .args([
            "scan",
            root.to_str().unwrap(),
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--ci",
            "--format",
            "json",
        ])
        .output()
        .expect("run smg --baseline after line shift");
    assert!(
        out2.status.success(),
        "expected v2 baseline to suppress shifted finding cleanly; stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&out2.stderr),
        String::from_utf8_lossy(&out2.stdout)
    );

    let _ = fs::remove_dir_all(&root);
}
