pub mod bwrap;
pub mod verifier;

use anyhow::Result;
use std::path::Path;
use vf_graph::LatticeFinding;

pub use bwrap::{
    SandboxGuard, has_bwrap, kill_active_sandbox_pgid, run_finding_in_isolated_netns,
    spawn_sandboxed_server,
};
pub use verifier::{VerificationStatus, VerifiedFinding, verify_finding};

pub fn verify_finding_blocking(
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "Timed out waiting for server inside --unshare-net on 127.0.0.1:{}",
                    port
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        verify_finding(port, finding, concurrency).await
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

        let has_dynamic_findings = findings.iter().any(|f| {
            matches!(
                f.missing_guard,
                vf_graph::GuardKind::Auth | vf_graph::GuardKind::TxLock
            )
        });
        let use_bwrap = has_bwrap();
        if has_dynamic_findings && !use_bwrap && !allow_unsafe_host_fallback {
            anyhow::bail!(
                "bwrap is unavailable. Refusing fail-open host execution (pass --unsafe-host-fallback to override)."
            );
        }

        let mut results = Vec::with_capacity(findings.len());
        // B-NET + B-DRAIN: When bwrap is available, run BOTH the target server AND `shellmind-guard __probe-netns`
        // inside a single `--unshare-all` (including `--unshare-net`!) namespace for each dynamic Auth/Race finding!
        if use_bwrap {
            for f in findings {
                let res = if matches!(
                    f.missing_guard,
                    vf_graph::GuardKind::Auth | vf_graph::GuardKind::TxLock
                ) {
                    match run_finding_in_isolated_netns(
                        project_root,
                        boot_cmd,
                        port,
                        f,
                        concurrency,
                    ) {
                        Ok(vf) => vf,
                        Err(e) => VerifiedFinding {
                            finding_id: f.id.clone(),
                            rule_id: f.rule_id.clone(),
                            entry_route: f.entry_route.clone(),
                            status: VerificationStatus::SuspectUnverified,
                            evidence: format!("Sandbox verification inconclusive: {}", e),
                            replay_cmd: format!("shellmind-guard replay {}", f.id),
                        },
                    }
                } else {
                    verifier::verify_finding(port, f, concurrency).await?
                };
                results.push(res);
            }
            return Ok((true, results));
        }

        for f in findings {
            let res = if matches!(
                f.missing_guard,
                vf_graph::GuardKind::Auth | vf_graph::GuardKind::TxLock
            ) {
                match spawn_sandboxed_server(
                    project_root,
                    boot_cmd,
                    port,
                    allow_unsafe_host_fallback,
                )
                .await
                {
                    Ok(guard) => {
                        let out = match verify_finding(port, f, concurrency).await {
                            Ok(vf) => vf,
                            Err(e) => VerifiedFinding {
                                finding_id: f.id.clone(),
                                rule_id: f.rule_id.clone(),
                                entry_route: f.entry_route.clone(),
                                status: VerificationStatus::SuspectUnverified,
                                evidence: format!("Sandbox probe error: {}", e),
                                replay_cmd: format!("shellmind-guard replay {}", f.id),
                            },
                        };
                        drop(guard);
                        out
                    }
                    Err(e) => VerifiedFinding {
                        finding_id: f.id.clone(),
                        rule_id: f.rule_id.clone(),
                        entry_route: f.entry_route.clone(),
                        status: VerificationStatus::SuspectUnverified,
                        evidence: format!("Sandbox server boot inconclusive: {}", e),
                        replay_cmd: format!("shellmind-guard replay {}", f.id),
                    },
                }
            } else {
                verify_finding(port, f, concurrency).await?
            };
            results.push(res);
        }

        Ok((false, results))
    })
}
