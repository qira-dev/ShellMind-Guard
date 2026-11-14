use crate::verifier::VerifiedFinding;
use anyhow::{Context, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::sleep;
use vf_graph::LatticeFinding;

static ACTIVE_SANDBOX_PGID: AtomicI32 = AtomicI32::new(0);

pub struct SandboxGuard {
    child: Child,
    pub port: u16,
    pub isolated_bwrap: bool,
}

pub fn kill_active_sandbox_pgid() {
    let pgid = ACTIVE_SANDBOX_PGID.swap(0, Ordering::SeqCst);
    if pgid > 0 {
        let _ = Command::new("/bin/kill")
            .args(["-9", &format!("-{}", pgid)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let pid = self.child.id() as i32;
        ACTIVE_SANDBOX_PGID
            .compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst)
            .ok();
        let _ = Command::new("/bin/kill")
            .args(["-9", &format!("-{}", pid)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
        for _ in 0..25 {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub fn has_bwrap() -> bool {
    Path::new("/usr/bin/bwrap").exists()
}

fn build_base_bwrap_cmd(abs_root: &Path, port: u16) -> Command {
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.process_group(0);
    cmd.args([
        "--unshare-all",
        "--die-with-parent",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "PORT",
        &port.to_string(),
        "--setenv",
        "NODE_ENV",
        "test",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/bin",
        "/bin",
    ]);
    if Path::new("/lib64").exists() {
        cmd.args(["--ro-bind", "/lib64", "/lib64"]);
    }
    if Path::new("/etc").exists() {
        cmd.args(["--ro-bind", "/etc", "/etc"]);
    }
    if let Ok(home) = std::env::var("HOME") {
        let local_bin = format!("{}/.local/bin", home);
        if Path::new(&local_bin).exists() {
            cmd.args(["--ro-bind", &local_bin, &local_bin]);
            cmd.args([
                "--setenv",
                "PATH",
                &format!("{}:/usr/local/bin:/usr/bin:/bin", local_bin),
            ]);
        }
    }
    cmd.args([
        "--ro-bind",
        &abs_root.to_string_lossy(),
        "/app",
        "--tmpfs",
        "/tmp",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        "/app",
    ]);
    cmd
}

/// B-NET: Runs BOTH the target `boot_cmd` AND `veriforge __probe-netns` inside a single
/// `--unshare-all` (including `--unshare-net`) Bubblewrap namespace!
/// Neither the target app nor the probe can dial the host network, LAN, or internet.
pub fn run_finding_in_isolated_netns(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    finding: &LatticeFinding,
    concurrency: usize,
) -> Result<VerifiedFinding> {
    let abs_root = std::fs::canonicalize(project_root)?;
    let self_exe = std::env::current_exe().context("Cannot locate current veriforge executable")?;
    let finding_json = serde_json::to_string(finding)?;

    let mut cmd = build_base_bwrap_cmd(&abs_root, port);
    cmd.args([
        "--ro-bind",
        &self_exe.to_string_lossy(),
        "/tmp/vf-probe",
        "--setenv",
        "VF_FINDING_JSON",
        &finding_json,
        "--",
        "/bin/sh",
        "-c",
        &format!(
            "ulimit -d 1048576 2>/dev/null || true; ({boot_cmd}) >/dev/null 2>&1 & SRV_PID=$!; trap 'kill -9 $SRV_PID 2>/dev/null || true' EXIT; /tmp/vf-probe __probe-netns --port {port} --sync-race {concurrency}; EC=$?; kill -9 $SRV_PID 2>/dev/null || true; exit $EC"
        ),
    ]);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn().context("Failed to spawn --unshare-all bwrap")?;
    ACTIVE_SANDBOX_PGID.store(child.id() as i32, Ordering::SeqCst);
    let output = child.wait_with_output()?;
    ACTIVE_SANDBOX_PGID.store(0, Ordering::SeqCst);

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Isolated netns probe failed (exit {}): {}",
            output.status,
            err_msg.trim()
        );
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: VerifiedFinding = serde_json::from_str(stdout_str.trim()).with_context(|| {
        format!(
            "Failed to parse __probe-netns output: {}",
            stdout_str.chars().take(200).collect::<String>()
        )
    })?;
    Ok(parsed)
}

/// Spawns a local target server for unsafe host fallback or unit tests.
pub async fn spawn_sandboxed_server(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    allow_unsafe_host_fallback: bool,
) -> Result<SandboxGuard> {
    if port == 0 {
        anyhow::bail!("Refusing port 0: specify an explicit loopback port");
    }
    if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
        anyhow::bail!(
            "Port 127.0.0.1:{} is already occupied by an unrelated listener; refusing to probe wrong service",
            port
        );
    }

    let abs_root = std::fs::canonicalize(project_root)?;
    let use_bwrap = has_bwrap();

    if !use_bwrap && !allow_unsafe_host_fallback {
        anyhow::bail!(
            "/usr/bin/bwrap is unavailable. Refusing fail-open host execution (pass --unsafe-host-fallback to override)."
        );
    }

    let wrapped_cmd = format!("ulimit -d 1048576 2>/dev/null || true; exec {}", boot_cmd);

    let child = if use_bwrap {
        let mut cmd = build_base_bwrap_cmd(&abs_root, port);
        cmd.args(["--", "/bin/sh", "-c", &wrapped_cmd]);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().context("Failed to spawn bwrap sandbox")?
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.process_group(0)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("PORT", port.to_string())
            .env("NODE_ENV", "test")
            .args(["-c", &wrapped_cmd])
            .current_dir(&abs_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.spawn().context("Failed to spawn local test server")?
    };

    ACTIVE_SANDBOX_PGID.store(child.id() as i32, Ordering::SeqCst);

    let mut guard = SandboxGuard {
        child,
        port,
        isolated_bwrap: use_bwrap,
    };

    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Ok(Some(status)) = guard.child.try_wait() {
            anyhow::bail!("Sandboxed server exited prematurely with status {}", status);
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "Timed out waiting for sandboxed server on 127.0.0.1:{}",
                port
            );
        }
        sleep(Duration::from_millis(40)).await;
    }

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_conflict_is_refused() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let occupied_port = listener.local_addr().unwrap().port();
        let err = spawn_sandboxed_server(
            Path::new("."),
            "node -e 'setInterval(()=>{},1000)'",
            occupied_port,
            true,
        )
        .await
        .err()
        .expect("must refuse occupied port");
        assert!(err.to_string().contains("already occupied"));
        drop(listener);
    }
}
