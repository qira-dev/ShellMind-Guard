pub mod bwrap;
pub mod verifier;

use anyhow::Result;
use std::path::Path;
use vf_graph::LatticeFinding;

pub use bwrap::{SandboxGuard, has_bwrap, kill_active_sandbox_pgid, spawn_sandboxed_server};
pub use verifier::{VerificationStatus, VerifiedFinding, verify_finding};

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

        let mut results = Vec::with_capacity(findings.len());
        let mut used_bwrap = false;

        // B-DRAIN: Always run each finding against a fresh sandboxed server instance
        // so state mutations (e.g. balance drain) from an Auth probe never skew later probes.
        for f in findings {
            let guard =
                spawn_sandboxed_server(project_root, boot_cmd, port, allow_unsafe_host_fallback)
                    .await?;
            used_bwrap = guard.isolated_bwrap;
            let res = verify_finding(port, f, concurrency).await?;
            drop(guard);
            results.push(res);
        }

        Ok((used_bwrap, results))
    })
}
