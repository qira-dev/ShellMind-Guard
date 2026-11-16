pub mod bwrap;
pub mod verifier;

use anyhow::Result;
use smg_graph::LatticeFinding;
use std::path::{Path, PathBuf};

pub use bwrap::{
    SandboxBackend, SandboxGuard, apply_rlimit_as, build_cgroup_v2_args,
    build_macos_seatbelt_profile, build_macos_seatbelt_profile_with_extras,
    build_windows_job_wrapper_script, detect_sandbox_backend, has_bwrap, has_isolated_sandbox,
    kill_active_sandbox_pgid, run_deep_fuzz_in_isolated_netns, run_finding_in_isolated_netns,
    run_finding_in_isolated_netns_with_config, spawn_sandboxed_server,
    spawn_sandboxed_server_with_config,
};
pub use verifier::{
    FuzzProbeHit, MockShimHandle, SandboxProbeConfig, VerificationStatus, VerifiedFinding,
    classify_boot_failure, mock_shim_env_vars, spawn_mock_shim_server,
    spawn_mock_shim_server_on_port, verify_finding, verify_finding_with_config,
    verify_route_fuzz_with_config,
};

fn is_dynamic_probe_target(finding: &LatticeFinding) -> bool {
    matches!(
        finding.missing_guard,
        smg_graph::GuardKind::Auth
            | smg_graph::GuardKind::TxLock
            | smg_graph::GuardKind::OwnershipCheck
    )
}

#[cfg(target_os = "linux")]
fn is_process_dead_or_zombie(pid: u32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    let Ok(stat) = std::fs::read_to_string(&stat_path) else {
        return true;
    };
    if let Some(rparen) = stat.rfind(')') {
        let rest = stat[rparen + 1..].trim_start();
        if let Some(state_ch) = rest.chars().next() {
            return matches!(state_ch, 'Z' | 'X' | 'x');
        }
    }
    false
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_process_dead_or_zombie(pid: u32) -> bool {
    let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    if raw_pid <= 0 {
        return true;
    }
    // SAFETY: `kill(pid, 0)` only queries signal deliverability for `raw_pid`.
    let rc = unsafe { libc::kill(raw_pid, 0) };
    if rc != 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    // `kill(pid, 0) == 0` succeeds for zombies (`Z`); query `ps` without calling `waitpid`
    // so we never reap another caller's `Child` handle.
    let ps_bin = if Path::new("/bin/ps").exists() {
        "/bin/ps"
    } else {
        "ps"
    };
    if let Ok(out) = std::process::Command::new(ps_bin)
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
    {
        let state = String::from_utf8_lossy(&out.stdout);
        let trimmed = state.trim();
        return trimmed.is_empty() || trimmed.starts_with('Z');
    }
    false
}

#[cfg(not(unix))]
fn is_process_dead_or_zombie(_pid: u32) -> bool {
    false
}

fn read_boot_log_snippet(boot_log: Option<&Path>) -> String {
    boot_log
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

async fn wait_for_port_or_boot_exit(
    port: u16,
    srv_pid: Option<u32>,
    boot_log: Option<&Path>,
) -> std::result::Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        if let Some(pid) = srv_pid
            && is_process_dead_or_zombie(pid)
        {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            let log = read_boot_log_snippet(boot_log);
            return Err(classify_boot_failure(&format!(
                "Target boot process {} exited prematurely.\n{}",
                pid, log
            )));
        }
        if std::time::Instant::now() >= deadline {
            let log = read_boot_log_snippet(boot_log);
            if !log.trim().is_empty() {
                return Err(classify_boot_failure(&format!(
                    "Timed out waiting for server on 127.0.0.1:{}.\n{}",
                    port, log
                )));
            }
            return Err(format!(
                "Timed out waiting for server inside --unshare-net on 127.0.0.1:{}",
                port
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    Ok(())
}

fn read_boot_monitor_env() -> (Option<u32>, Option<PathBuf>) {
    let pid = std::env::var("SMG_SRV_PID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok());
    let log = std::env::var("SMG_BOOT_LOG")
        .ok()
        .map(PathBuf::from)
        .or_else(|| pid.map(|_| PathBuf::from("/tmp/smg-boot.log")));
    (pid, log)
}

async fn maybe_start_netns_shim(
    port: u16,
    probe_cfg: &SandboxProbeConfig,
) -> Option<MockShimHandle> {
    if !probe_cfg.mock_shims {
        return None;
    }
    let shim_port = std::env::var("SMG_SHIM_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or_else(|| {
            port.checked_add(1)
                .unwrap_or_else(|| port.saturating_sub(1))
        });
    spawn_mock_shim_server_on_port(shim_port).await.ok()
}

pub fn verify_finding_blocking(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    verify_finding_blocking_with_config(port, finding, concurrency, &SandboxProbeConfig::default())
}

pub fn verify_finding_blocking_with_config(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
    probe_cfg: &SandboxProbeConfig,
) -> Result<VerifiedFinding> {
    let (srv_pid, boot_log) = read_boot_monitor_env();
    verify_finding_blocking_with_boot_monitor(
        port,
        finding,
        concurrency,
        probe_cfg,
        srv_pid,
        boot_log.as_deref(),
    )
}

/// Verifies one finding against loopback `port`, fast-failing to `VerificationStatus::Unbootable`
/// if `srv_pid` terminates before `port` begins listening.
pub fn verify_finding_blocking_with_boot_monitor(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
    probe_cfg: &SandboxProbeConfig,
    srv_pid: Option<u32>,
    boot_log: Option<&Path>,
) -> Result<VerifiedFinding> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let _shim = maybe_start_netns_shim(port, probe_cfg).await;
        if let Err(reason) = wait_for_port_or_boot_exit(port, srv_pid, boot_log).await {
            if reason.contains("UNBOOTABLE:") || srv_pid.is_some() {
                return Ok(VerifiedFinding {
                    finding_id: finding.id.clone(),
                    rule_id: finding.rule_id.clone(),
                    entry_route: finding.entry_route.clone(),
                    status: VerificationStatus::Unbootable,
                    evidence: reason,
                    replay_cmd: format!("smg replay {}", finding.id),
                });
            }
            anyhow::bail!("{}", reason);
        }
        verify_finding_with_config(port, finding, concurrency, probe_cfg).await
    })
}

/// Runs targeted Phase 10 route-schema fuzzing (`SMG-FUZZ-TAMPER`, `SMG-FUZZ-CRASH`,
/// `SMG-FUZZ-ENCODING`) inside the active network namespace against `port`.
pub fn verify_deep_fuzz_blocking_with_config(
    port: u16,
    probe_cfg: &SandboxProbeConfig,
) -> Result<Vec<FuzzProbeHit>> {
    let (srv_pid, boot_log) = read_boot_monitor_env();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let _shim = maybe_start_netns_shim(port, probe_cfg).await;
        if let Err(reason) = wait_for_port_or_boot_exit(port, srv_pid, boot_log.as_deref()).await {
            anyhow::bail!("{}", reason);
        }
        Ok(verify_route_fuzz_with_config(port, &probe_cfg.fuzz_routes, probe_cfg).await)
    })
}

pub fn verify_findings_in_sandbox(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    findings: &[LatticeFinding],
    concurrency: usize,
    allow_unsafe_host_fallback: bool,
) -> Result<(bool, Vec<VerifiedFinding>)> {
    verify_findings_in_sandbox_with_config(
        project_root,
        boot_cmd,
        port,
        findings,
        concurrency,
        allow_unsafe_host_fallback,
        &SandboxProbeConfig::default(),
    )
}

pub fn verify_findings_in_sandbox_with_config(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    findings: &[LatticeFinding],
    concurrency: usize,
    allow_unsafe_host_fallback: bool,
    probe_cfg: &SandboxProbeConfig,
) -> Result<(bool, Vec<VerifiedFinding>)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // B17: Ensure Ctrl+C / SIGINT immediately reaps any active sandbox process group
        tokio::spawn(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                kill_active_sandbox_pgid();
                std::process::exit(130);
            }
        });

        let has_dynamic_findings = findings.iter().any(is_dynamic_probe_target);
        let use_isolated = has_isolated_sandbox();
        if has_dynamic_findings && !use_isolated && !allow_unsafe_host_fallback {
            anyhow::bail!(
                "No isolated OS sandbox backend available (bwrap on Linux/WSL2, sandbox-exec on macOS). Pass --unsafe-host-fallback to override."
            );
        }

        let mut results = Vec::with_capacity(findings.len());
        // B-NET + B-DRAIN: Run BOTH the target server AND `smg __probe-netns` inside the OS sandbox
        // (Linux/WSL2 bwrap `--unshare-all`, or macOS `sandbox-exec` Seatbelt) for each dynamic finding!
        if use_isolated {
            for f in findings {
                let res = if is_dynamic_probe_target(f) {
                    match run_finding_in_isolated_netns_with_config(
                        project_root,
                        boot_cmd,
                        port,
                        f,
                        concurrency,
                        probe_cfg,
                    ) {
                        Ok(vf) => vf,
                        Err(e) => {
                            let msg = e.to_string();
                            let is_unbootable = msg.contains("UNBOOTABLE:");
                            VerifiedFinding {
                                finding_id: f.id.clone(),
                                rule_id: f.rule_id.clone(),
                                entry_route: f.entry_route.clone(),
                                status: if is_unbootable {
                                    VerificationStatus::Unbootable
                                } else {
                                    VerificationStatus::SuspectUnverified
                                },
                                evidence: format!("Sandbox verification inconclusive: {}", msg),
                                replay_cmd: format!("smg replay {}", f.id),
                            }
                        }
                    }
                } else {
                    verifier::verify_finding_with_config(port, f, concurrency, probe_cfg).await?
                };
                results.push(res);
            }
            return Ok((true, results));
        }

        let shim_handle = if has_dynamic_findings && probe_cfg.mock_shims {
            spawn_mock_shim_server().await.ok()
        } else {
            None
        };
        let extra_env = shim_handle
            .as_ref()
            .map(|h| mock_shim_env_vars(h.port))
            .unwrap_or_default();

        for f in findings {
            let res = if is_dynamic_probe_target(f) {
                match spawn_sandboxed_server_with_config(
                    project_root,
                    boot_cmd,
                    port,
                    allow_unsafe_host_fallback,
                    &extra_env,
                    probe_cfg,
                )
                .await
                {
                    Ok(guard) => {
                        let out =
                            match verify_finding_with_config(port, f, concurrency, probe_cfg).await
                            {
                                Ok(vf) => vf,
                                Err(e) => VerifiedFinding {
                                    finding_id: f.id.clone(),
                                    rule_id: f.rule_id.clone(),
                                    entry_route: f.entry_route.clone(),
                                    status: VerificationStatus::SuspectUnverified,
                                    evidence: format!("Sandbox probe error: {}", e),
                                    replay_cmd: format!("smg replay {}", f.id),
                                },
                            };
                        drop(guard);
                        out
                    }
                    Err(e) => VerifiedFinding {
                        finding_id: f.id.clone(),
                        rule_id: f.rule_id.clone(),
                        entry_route: f.entry_route.clone(),
                        status: VerificationStatus::Unbootable,
                        evidence: classify_boot_failure(&e.to_string()),
                        replay_cmd: format!("smg replay {}", f.id),
                    },
                }
            } else {
                verify_finding_with_config(port, f, concurrency, probe_cfg).await?
            };
            results.push(res);
        }

        drop(shim_handle);
        Ok((false, results))
    })
}

/// Runs Phase 10 deep route-schema fuzzing in the sandbox (`bwrap` if available, else guarded host fallback)
/// returning `(isolated_bwrap, fuzz_hits, optional_unbootable_diagnostic)`.
pub fn verify_deep_fuzz_in_sandbox(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    allow_unsafe_host_fallback: bool,
    probe_cfg: &SandboxProbeConfig,
) -> Result<(bool, Vec<FuzzProbeHit>, Option<String>)> {
    if probe_cfg.fuzz_routes.is_empty() {
        return Ok((has_isolated_sandbox(), Vec::new(), None));
    }
    let use_isolated = has_isolated_sandbox();
    if !use_isolated && !allow_unsafe_host_fallback {
        anyhow::bail!(
            "No isolated OS sandbox backend available (bwrap on Linux/WSL2, sandbox-exec on macOS). Pass --unsafe-host-fallback to override."
        );
    }
    if use_isolated {
        return match run_deep_fuzz_in_isolated_netns(project_root, boot_cmd, port, probe_cfg) {
            Ok(hits) => Ok((true, hits, None)),
            Err(e) => Ok((
                true,
                Vec::new(),
                Some(classify_boot_failure(&e.to_string())),
            )),
        };
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let shim_handle = if probe_cfg.mock_shims {
            spawn_mock_shim_server().await.ok()
        } else {
            None
        };
        let extra_env = shim_handle
            .as_ref()
            .map(|h| mock_shim_env_vars(h.port))
            .unwrap_or_default();

        match spawn_sandboxed_server_with_config(
            project_root,
            boot_cmd,
            port,
            allow_unsafe_host_fallback,
            &extra_env,
            probe_cfg,
        )
        .await
        {
            Ok(guard) => {
                let hits =
                    verify_route_fuzz_with_config(port, &probe_cfg.fuzz_routes, probe_cfg).await;
                drop(guard);
                drop(shim_handle);
                Ok((false, hits, None))
            }
            Err(e) => {
                drop(shim_handle);
                Ok((
                    false,
                    Vec::new(),
                    Some(classify_boot_failure(&e.to_string())),
                ))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_log_snippet_and_self_pid_monitor_cross_os() {
        assert!(!is_process_dead_or_zombie(std::process::id()));
        let dir = std::env::temp_dir().join(format!("smg-bootlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("boot.log");
        std::fs::write(&log_path, "Error: ECONNREFUSED 127.0.0.1:5432 DATABASE_URL").unwrap();
        let snippet = read_boot_log_snippet(Some(&log_path));
        let msg = classify_boot_failure(&snippet);
        assert!(msg.contains("UNBOOTABLE:"));
        assert!(msg.contains("PostgreSQL") || msg.contains("ECONNREFUSED"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_unbootable_external_db_classified_fast_without_timeout() {
        use std::time::{Duration, Instant};
        let dir = std::env::temp_dir().join(format!("smg-unbootable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("boot.log");
        let log_str = log_path.to_string_lossy().to_string();

        let mut child = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "echo 'Error: connect ECONNREFUSED 127.0.0.1:5432 DATABASE_URL unreachable' > \"$1\"; exit 1",
                "--",
                &log_str,
            ])
            .spawn()
            .expect("spawn failing boot cmd");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = listener.local_addr().unwrap().port();
        drop(listener);

        let finding = LatticeFinding {
            id: "SMG-BOOT-001".to_string(),
            rule_id: "SMG-AUTH-001".to_string(),
            severity: "CRITICAL".to_string(),
            title: "Unauthenticated payment mutation".to_string(),
            file: "src/routes/pay.ts".to_string(),
            line: 1,
            status: "SUSPECT".to_string(),
            confidence: smg_graph::Confidence::Confirmed,
            entry_route: "POST /api/pay".to_string(),
            sink_kind: smg_graph::SinkKind::BalanceUpdate,
            missing_guard: smg_graph::GuardKind::Auth,
            witness_path: vec![],
            remediation: String::new(),
        };

        let start = Instant::now();
        let verified = verify_finding_blocking_with_boot_monitor(
            unused_port,
            &finding,
            4,
            &SandboxProbeConfig::default(),
            Some(child.id()),
            Some(&log_path),
        )
        .expect("unbootable result must be structured Ok(VerifiedFinding)");
        let elapsed = start.elapsed();

        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            elapsed < Duration::from_secs(2),
            "Exited boot process must fail fast without 6s timeout (took {:?})",
            elapsed
        );
        assert_eq!(verified.status, VerificationStatus::Unbootable);
        assert!(verified.evidence.contains("UNBOOTABLE:"));
        assert!(
            verified.evidence.contains("PostgreSQL") || verified.evidence.contains("ECONNREFUSED")
        );
    }
}
