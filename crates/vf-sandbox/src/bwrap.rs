use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::sleep;

pub struct SandboxGuard {
    child: Child,
    pub port: u16,
    pub isolated_bwrap: bool,
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn has_bwrap() -> bool {
    Path::new("/usr/bin/bwrap").exists()
}

/// Spawns a local target server inside an unprivileged Bubblewrap (`bwrap`) namespace
/// with read-only project bind, ephemeral `/tmp`, and isolated loopback networking.
pub async fn spawn_sandboxed_server(
    project_root: &Path,
    boot_cmd: &str,
    port: u16,
) -> Result<SandboxGuard> {
    let abs_root = std::fs::canonicalize(project_root)?;
    let use_bwrap = has_bwrap();

    let child = if use_bwrap {
        let mut cmd = Command::new("/usr/bin/bwrap");
        cmd.args([
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
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
        // Bind home .local/bin or nvm if node/cargo lives there (read-only)
        if let Ok(home) = std::env::var("HOME") {
            let local_bin = format!("{}/.local", home);
            if Path::new(&local_bin).exists() {
                cmd.args(["--ro-bind", &local_bin, &local_bin]);
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
            "--setenv",
            "PORT",
            &port.to_string(),
            "--setenv",
            "NODE_ENV",
            "test",
            "--",
            "/bin/sh",
            "-c",
            boot_cmd,
        ]);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().context("Failed to spawn bwrap sandbox")?
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", boot_cmd])
            .current_dir(&abs_root)
            .env("PORT", port.to_string())
            .env("NODE_ENV", "test")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.spawn().context("Failed to spawn local test server")?
    };

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
            anyhow::bail!("Timed out waiting for sandboxed server on 127.0.0.1:{}", port);
        }
        sleep(Duration::from_millis(50)).await;
    }

    Ok(guard)
}
