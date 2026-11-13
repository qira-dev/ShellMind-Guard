pub mod bwrap;
pub mod verifier;

use anyhow::Result;
use std::path::Path;
use vf_graph::{GuardKind, LatticeFinding};

pub use bwrap::{SandboxGuard, has_bwrap, spawn_sandboxed_server};
pub use verifier::{VerificationStatus, VerifiedFinding, verify_finding};

pub fn verify_findings_in_sandbox(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    findings: &[LatticeFinding],
    concurrency: usize,
) -> Result<(bool, Vec<VerifiedFinding>)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async move {
        let mut guard = spawn_sandboxed_server(project_root, boot_cmd, port).await?;
        let used_bwrap = guard.isolated_bwrap;
        let mut results = Vec::with_capacity(findings.len());
        let mut state_mutated = false;

        for f in findings {
            if state_mutated && f.missing_guard == GuardKind::TxLock {
                drop(guard);
                guard = spawn_sandboxed_server(project_root, boot_cmd, port).await?;
            }
            let res = verify_finding(port, f, concurrency).await?;
            if f.missing_guard == GuardKind::TxLock {
                state_mutated = true;
            }
            results.push(res);
        }
        drop(guard);
        Ok((used_bwrap, results))
    })
}
