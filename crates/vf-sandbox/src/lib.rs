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

        let use_bwrap = has_bwrap();
        if !use_bwrap && !allow_unsafe_host_fallback {
            anyhow::bail!(
                "/usr/bin/bwrap is unavailable. Refusing fail-open host execution (pass --unsafe-host-fallback to override)."
            );
        }

        let mut results = Vec::with_capacity(findings.len());
        // B-NET + B-DRAIN: When bwrap is available, run BOTH the target server AND `veriforge __probe-netns`
        // inside a single `--unshare-all` (including `--unshare-net`!) namespace for each finding!
        if use_bwrap {
            for f in findings {
                let res =
                    run_finding_in_isolated_netns(project_root, boot_cmd, port, f, concurrency)?;
                results.push(res);
            }
            return Ok((true, results));
        }

        for f in findings {
            let guard =
                spawn_sandboxed_server(project_root, boot_cmd, port, allow_unsafe_host_fallback)
                    .await?;
            let res = verify_finding(port, f, concurrency).await?;
            drop(guard);
            results.push(res);
        }

        Ok((false, results))
    })
}
