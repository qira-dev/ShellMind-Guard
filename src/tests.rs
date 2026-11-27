#[allow(unused_imports)]
use crate::rules_catalog::{
    CompletionShell, RULE_CATALOG, find_rule_doc, render_shell_completions,
};
#[allow(unused_imports)]
use crate::*;
#[allow(unused_imports)]
use anyhow::{Context, Result};
#[allow(unused_imports)]
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
#[allow(unused_imports)]
use smg_ai::{
    ApplyCheckParams, build_minimal_patch_prompt, export_regression_tests, generate_patch_plan,
    provider_from_config, run_cegis_patch_loop, synthesize_deterministic_codemod_diff,
    verify_patch_in_isolated_copy,
};
#[allow(unused_imports)]
use smg_core::{
    DeltaStats, ScanOptions, ShellMindGuardConfig, StateStore, scan_repository,
    scan_repository_with_options,
};
#[allow(unused_imports)]
use smg_graph::{
    Confidence, GraphAnalysisResult, GuardKind, LatticeFinding, analyze_codebase_cached,
    analyze_codebase_cached_changed_since, collect_deep_schema_findings, collect_git_changed_files,
    compute_rule_telemetry, deps::extract_resolved_dependencies, finding_matches_layer,
};
#[allow(unused_imports)]
use smg_report::{to_cyclonedx_vex_json, to_html_graph, to_sarif_json};
#[allow(unused_imports)]
use smg_sandbox::{
    SandboxProbeConfig, VerificationStatus, VerifiedFinding, detect_sandbox_backend,
    verify_deep_fuzz_blocking_with_config, verify_deep_fuzz_in_sandbox,
    verify_finding_blocking_with_config, verify_findings_batch_blocking_with_config,
    verify_findings_in_sandbox_with_config,
};
#[allow(unused_imports)]
use smg_tui::{TuiLaunchConfig, run_tui};
#[allow(unused_imports)]
use std::collections::{HashMap, HashSet};
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::io::{IsTerminal, Write};
#[allow(unused_imports)]
use std::net::SocketAddr;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::process::{Command, ExitCode};
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::sync::atomic::Ordering;
#[allow(unused_imports)]
use std::time::{Duration, Instant};

#[cfg(test)]
struct TempDirCleanup(PathBuf);

#[cfg(test)]
impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod main_tests {
    use super::*;
    use smg_graph::analyze_codebase;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_git_hook_install_preserves_existing_and_uninstalls_cleanly() {
        let tmp = std::env::temp_dir().join(format!("smg_hook_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".git").join("hooks")).unwrap();
        let hook_file = tmp.join(".git").join("hooks").join("pre-commit");
        fs::write(&hook_file, "#!/bin/sh\necho 'custom hook'\n").unwrap();

        install_git_hook(&tmp).unwrap();
        assert!(git_hook_status(&tmp));
        let content = fs::read_to_string(&hook_file).unwrap();
        assert!(content.contains("echo 'custom hook'"));
        assert!(content.contains(HOOK_START));

        // Append trailing line after our block to verify uninstall preserves newline separation
        fs::write(&hook_file, format!("{}\necho 'after hook'\n", content)).unwrap();

        // Idempotent second install
        install_git_hook(&tmp).unwrap();
        let content2 = fs::read_to_string(&hook_file).unwrap();
        assert_eq!(content2.matches(HOOK_START).count(), 1);

        // Uninstall preserves original custom hook lines with newline separation
        assert!(uninstall_git_hook(&tmp).unwrap());
        assert!(!git_hook_status(&tmp));
        let after = fs::read_to_string(&hook_file).unwrap();
        assert!(after.contains("echo 'custom hook'\necho 'after hook'"));
        assert!(!after.contains(HOOK_START));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_parse_git_commit_invocation_variants() {
        assert_eq!(
            parse_git_commit_invocation("git commit -m 'fix'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation(
                "GIT_AUTHOR_NAME=a /usr/bin/git -c commit.gpgsign=false commit -m 'x'"
            ),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("git -C /tmp/subrepo commit -m 'x'"),
            Some(PathBuf::from("/tmp/subrepo"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd services/api && (git commit -am 'msg')"),
            Some(PathBuf::from("services/api"))
        );
        assert_eq!(
            parse_git_commit_invocation("git -C \"sub repo\" commit -m \"fix & deploy\""),
            Some(PathBuf::from("sub repo"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd \"sub dir\"; git commit -m \"ok\""),
            Some(PathBuf::from("sub dir"))
        );
        assert_eq!(
            parse_git_commit_invocation("cd -P services/billing && git commit -m 'ok'"),
            Some(PathBuf::from("services/billing"))
        );
        assert_eq!(
            parse_git_commit_invocation("sh -c \"git commit -m 'nested'\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("cd apps/web && bash -lc \"git commit -m 'nested'\""),
            Some(PathBuf::from("apps/web"))
        );
        assert_eq!(
            parse_git_commit_invocation("eval \"git commit -m 'via-eval'\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation(
                "git --super-prefix sub/ --config-env user.name=GIT_USER commit -m 'opts'"
            ),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("echo \"cd /tmp && git commit -m fake\""),
            None
        );
        assert_eq!(parse_git_commit_invocation("git status && git diff"), None);
    }

    #[test]
    fn test_resolve_hook_scan_path_and_deep_replay_lookup() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_hook_cwd_{}", nanos));
        let _cleanup = TempDirCleanup(tmp.clone());
        let sub = tmp.join("apps/api");
        fs::create_dir_all(&sub).unwrap();

        assert_eq!(
            resolve_hook_scan_path(Path::new("."), Some(&tmp)),
            Some(tmp.clone())
        );
        assert_eq!(
            resolve_hook_scan_path(Path::new("apps/api"), Some(&tmp)),
            Some(sub.clone())
        );
        assert_eq!(
            resolve_hook_scan_path(Path::new("does-not-exist"), Some(&tmp)),
            None
        );

        fs::create_dir_all(sub.join("src")).unwrap();
        fs::write(
            sub.join("src/pay.ts"),
            "app.post('/api/pay', (req, res) => { const amount = req.body.amount; res.json({ amount }); });",
        )
        .unwrap();
        let cfg = ShellMindGuardConfig::default();
        let mut store = StateStore::open(&sub).unwrap();
        let resolved =
            resolve_finding_for_replay(&sub, "SMG-FUZZ-SCHEMA", &cfg, &mut store).unwrap();
        assert_eq!(resolved.rule_id, "SMG-FUZZ-SCHEMA");
    }

    #[test]
    fn test_fail_on_severity_gate() {
        let med = LatticeFinding {
            id: "SMG-FE-001".into(),
            rule_id: "SMG-FE-ERR".into(),
            severity: "MEDIUM".into(),
            title: "Empty catch".into(),
            status: "SUSPECT_UNGUARDED".into(),
            confidence: Confidence::Heuristic,
            entry_route: "app.ts:1".into(),
            file: "app.ts".into(),
            line: 1,
            sink_kind: smg_graph::SinkKind::SqlWrite,
            missing_guard: GuardKind::Auth,
            witness_path: vec![],
            remediation: String::new(),
            proof_reasons: vec![],
        };
        assert!(!should_fail_gate(std::slice::from_ref(&med), true, None));
        assert!(should_fail_gate(
            std::slice::from_ref(&med),
            false,
            Some(FailSeverity::Medium)
        ));
        assert!(!should_fail_gate(&[med], false, Some(FailSeverity::High)));
    }

    #[test]
    fn test_apply_check_eliminates_sqli_without_mutating_source_and_detects_ineffective_patch() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let repo = std::env::temp_dir().join(format!("smg_apply_unit_{}", nanos));
        let _cleanup = TempDirCleanup(repo.clone());
        fs::create_dir_all(repo.join("src")).unwrap();
        let route_src = "import express from 'express';\nconst app = express();\napp.get('/api/items', async (req, res) => {\n  const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n  res.json(rows);\n});\n";
        fs::write(repo.join("src/app.ts"), route_src).unwrap();

        let cfg = ShellMindGuardConfig::default();
        let summary = scan_repository(&repo, &cfg).unwrap();
        let graph = analyze_codebase(&summary.files, &cfg).unwrap();
        let sqli = graph
            .findings
            .iter()
            .find(|f| f.rule_id == "SMG-SQLI-001")
            .expect("expected initial SMG-SQLI-001 finding");

        let probe_cfg = SandboxProbeConfig::from_sandbox_config(&cfg.sandbox);
        let good_diff = "--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,6 +1,6 @@\n import express from 'express';\n const app = express();\n app.get('/api/items', async (req, res) => {\n-  const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n+  const rows = await db.query('SELECT * FROM items WHERE name = $1', [String(req.query.q)]);\n   res.json(rows);\n });\n";
        let ok = verify_patch_apply_check(&ApplyCheckParams {
            project_root: &repo,
            cfg: &cfg,
            finding: sqli,
            raw_diff: good_diff,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            probe_cfg: &probe_cfg,
        })
        .unwrap();
        assert!(ok.mitigated, "good diff failed: {}", ok.summary);
        assert_eq!(ok.modified_files, vec![PathBuf::from("src/app.ts")]);
        // Original repo file must remain untouched!
        assert_eq!(
            fs::read_to_string(repo.join("src/app.ts")).unwrap(),
            route_src
        );

        let ineffective_diff = "--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,6 +1,6 @@\n import express from 'express';\n const app = express();\n app.get('/api/items', async (req, res) => {\n+  // harmless comment\n   const rows = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);\n   res.json(rows);\n });\n";
        let bad = verify_patch_apply_check(&ApplyCheckParams {
            project_root: &repo,
            cfg: &cfg,
            finding: sqli,
            raw_diff: ineffective_diff,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            probe_cfg: &probe_cfg,
        })
        .unwrap();
        assert!(!bad.mitigated, "ineffective diff should fail apply-check");

        let traversal_diff = "--- a/../escape.ts\n+++ b/../escape.ts\n@@ -1,1 +1,1 @@\n-a\n+b\n";
        assert!(
            verify_patch_apply_check(&ApplyCheckParams {
                project_root: &repo,
                cfg: &cfg,
                finding: sqli,
                raw_diff: traversal_diff,
                boot_cmd: None,
                port: 39911,
                sync_race: 12,
                unsafe_host_fallback: false,
                probe_cfg: &probe_cfg,
            })
            .is_err()
        );
    }

    fn copy_dir_recursive(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = entry.file_name();
            if name == ".shellmind-guard" {
                continue;
            }
            let target = dst.join(name);
            if path.is_dir() {
                copy_dir_recursive(&path, &target);
            } else {
                fs::copy(&path, &target).unwrap();
            }
        }
    }

    #[test]
    fn test_phase10_deep_scan_and_layers_filter_on_fixtures() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("smg_p10_main_{}", nanos));
        let _cleanup = TempDirCleanup(tmp.clone());

        let pay_dir = tmp.join("vuln-payment-node");
        copy_dir_recursive(Path::new("fixtures/vuln-payment-node"), &pay_dir);

        let base_scan = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            !base_scan
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-FUZZ-SCHEMA"),
            "deep=false must not emit SMG-FUZZ-SCHEMA"
        );

        let deep_scan = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            deep_scan
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id == "SMG-FUZZ-SCHEMA"),
            "deep=true must emit SMG-FUZZ-SCHEMA on unvalidated payment route amount"
        );

        let deep_layer_only = execute_scan_pipeline(ScanRunOptions {
            path: &pay_dir,
            layers: &["deep".to_string()],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(!deep_layer_only.graph.findings.is_empty());
        assert!(
            deep_layer_only
                .graph
                .findings
                .iter()
                .all(|f| f.missing_guard == GuardKind::InputValidation)
        );

        let auth_dir = tmp.join("vuln-auth-rust");
        copy_dir_recursive(Path::new("fixtures/vuln-auth-rust"), &auth_dir);
        let auth_deep = execute_scan_pipeline(ScanRunOptions {
            path: &auth_dir,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: true,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(
            auth_deep
                .graph
                .findings
                .iter()
                .any(|f| f.missing_guard == GuardKind::Auth),
            "auth fixture must preserve Auth finding under --deep"
        );
    }

    #[test]
    fn test_wave3_git_commit_obfuscation_subshell_hook_and_symlink_refusal() {
        // F-79: backslash obfuscation, double-quoted $(...), --git-dir
        assert_eq!(
            parse_git_commit_invocation("git com\\mit -m 'x'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("g\\it com\\mit -m 'x'"),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("echo \"$(git commit -m 'nested')\""),
            Some(PathBuf::from("."))
        );
        assert_eq!(
            parse_git_commit_invocation("git --git-dir=/tmp/myrepo/.git commit -m 'x'"),
            Some(PathBuf::from("/tmp/myrepo"))
        );
        assert_eq!(
            parse_git_commit_invocation("git -c alias.c=commit c -m 'alias'"),
            Some(PathBuf::from("."))
        );

        // F-59: untrusted non-git hook cwd rejected when invoked inside real git repo
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_f59_f81_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        let clean_dir = root.join("clean_nongit");
        let real_repo = root.join("real_repo");
        fs::create_dir_all(&clean_dir).unwrap();
        fs::create_dir_all(real_repo.join(".git/hooks")).unwrap();
        assert_eq!(
            filter_trusted_hook_cwd(Path::new("."), Some(&clean_dir), Some(&real_repo)),
            None
        );
        assert_eq!(
            filter_trusted_hook_cwd(Path::new("."), Some(&real_repo), Some(&real_repo)),
            Some(real_repo.as_path())
        );

        // F-81: refuse installing pre-commit hook through a symlink
        #[cfg(unix)]
        {
            let target_file = root.join("outside_victim");
            fs::write(&target_file, "#!/bin/sh\necho victim\n").unwrap();
            let hook_link = real_repo.join(".git/hooks/pre-commit");
            std::os::unix::fs::symlink(&target_file, &hook_link).unwrap();
            assert!(
                install_git_hook(&real_repo).is_err(),
                "F-81: install_git_hook must refuse symlinked pre-commit hook"
            );
            assert_eq!(
                fs::read_to_string(&target_file).unwrap(),
                "#!/bin/sh\necho victim\n"
            );
        }
    }

    #[test]
    fn test_cli_rules_catalog_completions_and_parsing() {
        assert!(!RULE_CATALOG.is_empty());
        let race_doc = find_rule_doc("SMG-RACE-001").expect("race rule doc must exist");
        assert_eq!(race_doc.layer, "race");

        let bare = Cli::try_parse_from(["smg"]).unwrap();
        assert!(bare.command.is_none());

        let parsed_replay = Cli::try_parse_from([
            "smg",
            "replay",
            "SMG-RACE-001",
            "--sandbox-mem-mb",
            "512",
            "--sandbox-tls",
            "--mock-shims",
            "--cgroup-v2",
        ])
        .unwrap();
        assert!(matches!(
            parsed_replay.command,
            Some(Commands::Replay {
                sandbox_mem_mb: Some(512),
                sandbox_tls: true,
                mock_shims: true,
                cgroup_v2: true,
                ..
            })
        ));

        let parsed_ui = Cli::try_parse_from([
            "smg",
            "ui",
            "--layers",
            "auth,race",
            "--min-confidence",
            "confirmed",
            "--deep",
            "--sandbox-mem-mb",
            "256",
            "--sandbox-tls",
            "--mock-shims",
            "--cgroup-v2",
        ])
        .unwrap();
        assert!(matches!(
            parsed_ui.command,
            Some(Commands::Ui {
                deep: true,
                sandbox_mem_mb: Some(256),
                sandbox_tls: true,
                mock_shims: true,
                cgroup_v2: true,
                ..
            })
        ));

        let cmd = Cli::command();
        let bash_comp = render_shell_completions(&cmd, CompletionShell::Bash);
        assert!(bash_comp.contains("complete -F _smg_completions smg"));
        assert!(bash_comp.contains("complete -F _smg_completions shellmind-guard"));
        assert!(bash_comp.contains("completions"));
        assert!(bash_comp.contains("explain"));
    }

    #[test]
    fn test_inline_suppression_baseline_and_formats() {
        assert!(line_suppresses_finding(
            "// smg-ignore",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(line_suppresses_finding(
            "const x = 1; // smg-ignore: SMG-SQLI-001",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(!line_suppresses_finding(
            "const x = 1; // smg-ignore: SMG-AUTH-001",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));
        assert!(!line_suppresses_finding(
            "const note = \"smg-ignore\";",
            "SMG-SQLI-001",
            "SMG-SQLI-001"
        ));

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_baseline_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/app.js"),
            "const express = require('express');\nconst app = express();\napp.post('/pay', (req, res) => db.query(req.body.q));\n",
        )
        .unwrap();

        let baseline_path = root.join(".smg-baseline.json");
        let mut outcome1 = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        assert!(!outcome1.graph.findings.is_empty());

        let mut v1 = Vec::new();
        apply_suppressions_and_baseline(
            &root,
            &mut outcome1,
            &mut v1,
            &[],
            None,
            Some(&baseline_path),
        )
        .unwrap();
        assert!(baseline_path.exists());

        let mut outcome2 = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &[],
            min_confidence: None,
            boot_cmd: None,
            port: 39911,
            sync_race: 12,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();
        let mut v2 = Vec::new();
        apply_suppressions_and_baseline(
            &root,
            &mut outcome2,
            &mut v2,
            &[],
            Some(&baseline_path),
            None,
        )
        .unwrap();
        assert!(
            outcome2.graph.findings.is_empty(),
            "All baselined findings should be suppressed cleanly"
        );
        assert!(!should_fail_gate(&outcome2.graph.findings, true, None));

        for fmt in [
            OutputFormat::Text,
            OutputFormat::Compact,
            OutputFormat::Table,
            OutputFormat::Markdown,
        ] {
            let rendered = format_scan_output(
                &root,
                &outcome1,
                &[],
                &RenderOptions {
                    format: fmt,
                    sarif_payload: None,
                    patch: false,
                    color_mode: ColorMode::Never,
                    output: None,
                },
            )
            .unwrap();
            assert!(!rendered.is_empty());
        }

        let _ = append_audit_event(&root, "scan", 1, 0, "unit-test").unwrap();
        let audit_file = root.join(".shellmind-guard").join("audit-history.jsonl");
        let audit_txt = fs::read_to_string(&audit_file).unwrap();
        assert!(audit_txt.contains("\"action\":\"scan\""));
        assert!(audit_txt.contains("\"findings_count\":1"));
        assert!(!audit_txt.contains("Bearer "));
    }

    #[cfg(feature = "hw")]
    #[test]
    fn test_hw_feature_scan_cli_rules_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_hw_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("firmware")).unwrap();
        fs::write(
            root.join("board.ld"),
            "MEMORY {\n  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K\n  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K\n}\n",
        )
        .unwrap();
        fs::write(
            root.join("firmware/boot.c"),
            r#"
void ota_apply(const uint8_t *img, uint32_t len) {
    volatile uint32_t *flash = (volatile uint32_t *)0x08001000;
    *flash = 0x1;
    flash_write(0x08010000, img, len);
}
"#,
        )
        .unwrap();

        let hw_layers = vec!["hw".to_string()];
        let outcome = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &hw_layers,
            min_confidence: None,
            boot_cmd: None,
            port: 39921,
            sync_race: 4,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(ids.contains(&"SMG-HW-MMIO"), "missing MMIO: {:?}", ids);
        assert!(ids.contains(&"SMG-HW-BOOT"), "missing BOOT: {:?}", ids);
        assert!(find_rule_doc("SMG-HW-MMIO").is_some());
        assert!(find_rule_doc("SMG-HW-IRQ").is_some());
    }

    #[cfg(feature = "web3")]
    #[test]
    fn test_web3_feature_scan_cli_rules_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_web3_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("contracts")).unwrap();
        fs::write(
            root.join("foundry.toml"),
            "[profile.default]\nsrc = \"contracts\"\n",
        )
        .unwrap();
        fs::write(
            root.join("contracts/Vault.sol"),
            r#"
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    mapping(address => uint256) public balances;
    function initialize(address _owner) external {
        owner = _owner;
    }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#,
        )
        .unwrap();

        let web3_layers = vec!["web3".to_string()];
        let outcome = execute_scan_pipeline(ScanRunOptions {
            path: &root,
            layers: &web3_layers,
            min_confidence: None,
            boot_cmd: None,
            port: 39923,
            sync_race: 4,
            unsafe_host_fallback: false,
            trust_repo_config: false,
            deep: false,
            deep_audit: false,
            sandbox_mem_mb: None,
            sandbox_tls: false,
            mock_shims: false,
            cgroup_v2: false,
        })
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(
            ids.contains(&"SMG-WEB3-REENTRANCY"),
            "missing REENTRANCY: {:?}",
            ids
        );
        assert!(
            ids.contains(&"SMG-WEB3-ACCESS"),
            "missing ACCESS: {:?}",
            ids
        );
        assert!(find_rule_doc("SMG-WEB3-REENTRANCY").is_some());
        assert!(find_rule_doc("SMG-WEB3-STORAGE").is_some());
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_pqc_feature_compliance_cbom_and_layers() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_pqc_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/tls.rs"),
            r#"
pub fn configure_tls() {
    let suite = "ECDHE-RSA-AES128-GCM-SHA256";
    let downgrade = "mlkem_fallback_to_rsa";
    let seed = [0u8; 32]; ml_kem_keygen(seed);
}
"#,
        )
        .unwrap();

        let cbom_file = root.join("out/cbom.json");
        let default_outcome = execute_scan_pipeline_full(
            ScanRunOptions {
                path: &root,
                layers: &[],
                min_confidence: None,
                boot_cmd: None,
                port: 39925,
                sync_race: 4,
                unsafe_host_fallback: false,
                trust_repo_config: false,
                deep: false,
                deep_audit: false,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
            },
            None,
            false,
            false,
            None,
        )
        .unwrap();
        assert!(
            !default_outcome
                .graph
                .findings
                .iter()
                .any(|f| f.rule_id.starts_with("SMG-PQC-")),
            "default scan must not emit PQC advisories when unrequested"
        );

        let pqc_layers = vec!["pqc".to_string()];
        let outcome = execute_scan_pipeline_full(
            ScanRunOptions {
                path: &root,
                layers: &pqc_layers,
                min_confidence: None,
                boot_cmd: None,
                port: 39926,
                sync_race: 4,
                unsafe_host_fallback: false,
                trust_repo_config: false,
                deep: false,
                deep_audit: false,
                sandbox_mem_mb: None,
                sandbox_tls: false,
                mock_shims: false,
                cgroup_v2: false,
            },
            None,
            false,
            true,
            Some(&cbom_file),
        )
        .unwrap();

        let ids: Vec<&str> = outcome
            .graph
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(ids.contains(&"SMG-PQC-HNDL"), "missing HNDL: {:?}", ids);
        assert!(ids.contains(&"SMG-PQC-GROVER"), "missing GROVER: {:?}", ids);
        assert!(
            ids.contains(&"SMG-PQC-DOWNGRADE"),
            "missing DOWNGRADE: {:?}",
            ids
        );
        assert!(ids.contains(&"SMG-PQC-PARAMS"), "missing PARAMS: {:?}", ids);

        let cbom_raw = fs::read_to_string(&cbom_file).unwrap();
        assert!(cbom_raw.contains("CycloneDX"));
        assert!(cbom_raw.contains("\"runtimeUnobserved\": true"));
        assert!(find_rule_doc("SMG-PQC-HNDL").is_some());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn test_enterprise_license_and_tee_attestation_fail_closed() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("smg_ent_cli_test_{}", nanos));
        let _cleanup = TempDirCleanup(root.clone());
        fs::create_dir_all(&root).unwrap();

        let (pkcs8, pubkey) = smg_enterprise::generate_ed25519_keypair().unwrap();
        let pub_hex = smg_enterprise::encode_hex(&pubkey);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = smg_enterprise::LicenseClaims {
            license_id: "ent-cli-001".into(),
            organization: "ShellMind Enterprise Test".into(),
            tier: smg_enterprise::LicenseTier::EnterpriseTee,
            issued_at_unix: now.saturating_sub(10),
            expires_at_unix: now + 3600,
            max_seats: 10,
            features: vec!["hw".into(), "web3".into(), "pqc".into(), "tee".into()],
            pinned_binary_blake3: None,
        };
        let token = smg_enterprise::sign_license_claims(&pkcs8, &claims).unwrap();
        let lic_path = root.join("license.json");
        fs::write(&lic_path, serde_json::to_string_pretty(&token).unwrap()).unwrap();

        handle_enterprise_command(EnterpriseAction::VerifyLicense {
            license: lic_path.clone(),
            pubkey: pub_hex.clone(),
            tier: "enterprise-tee".into(),
            binary: None,
        })
        .unwrap();

        let pcr0 = "d".repeat(96);
        let nonce = "0102030405060708";
        let quote = smg_enterprise::sign_tee_quote(
            &pkcs8,
            smg_enterprise::TeePlatform::AwsNitro,
            &pcr0,
            nonce,
            now,
            "nitro-cli-01",
        )
        .unwrap();
        let quote_path = root.join("quote.json");
        fs::write(&quote_path, serde_json::to_string_pretty(&quote).unwrap()).unwrap();

        handle_enterprise_command(EnterpriseAction::VerifyAttestation {
            quote: quote_path,
            pubkey: pub_hex.clone(),
            pcr0,
            nonce: nonce.into(),
            platform: "aws-nitro".into(),
        })
        .unwrap();

        // Bad public key must fail closed cleanly
        let bad_pub = "0".repeat(64);
        assert!(
            handle_enterprise_command(EnterpriseAction::VerifyLicense {
                license: lic_path,
                pubkey: bad_pub,
                tier: "enterprise-tee".into(),
                binary: None,
            })
            .is_err()
        );
    }
}
