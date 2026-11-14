use anyhow::{Context, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

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
    }
}

pub fn has_bwrap() -> bool {
    Path::new("/usr/bin/bwrap").exists()
}

/// Spawns a local target server inside an unprivileged Bubblewrap (`bwrap`) namespace
/// with `--clearenv`, read-only project bind, ephemeral `/tmp`, 1 GiB virtual memory cap,
/// port-conflict refusal, and process-group reaping.
///
/// Fails closed if `/usr/bin/bwrap` is absent unless `allow_unsafe_host_fallback` is explicitly true.
pub async fn spawn_sandboxed_server(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
    allow_unsafe_host_fallback: bool,
) -> Result<SandboxGuard> {
    if port == 0 {
        anyhow::bail!("Refusing port 0: specify an explicit loopback port");
    }
    // B18: Refuse immediately if an unrelated listener already occupies `port`
    if TcpListener::bind(("127.0.0.1", port)).await.is_err() {
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
        let mut cmd = Command::new("/usr/bin/bwrap");
        cmd.process_group(0);
        cmd.args([
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
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
            let local_bin = format!("{}/.local", home);
            if Path::new(&local_bin).exists() {
                cmd.args(["--ro-bind", &local_bin, &local_bin]);
                cmd.args([
                    "--setenv",
                    "PATH",
                    &format!("{}/bin:/usr/local/bin:/usr/bin:/bin", local_bin),
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
            "--",
            "/bin/sh",
            "-c",
            &wrapped_cmd,
        ]);
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
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
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
