#[cfg(unix)]
mod imp {
    use crate::verifier::{SandboxProbeConfig, VerifiedFinding};
    use anyhow::{Context, Result};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
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

    fn find_bwrap_path() -> Option<PathBuf> {
        for fixed in ["/usr/bin/bwrap", "/run/current-system/sw/bin/bwrap"] {
            let p = Path::new(fixed);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let cand = dir.join("bwrap");
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
        None
    }

    pub fn has_bwrap() -> bool {
        find_bwrap_path().is_some()
    }

    fn build_sandbox_path() -> String {
        let base = "/usr/local/bin:/usr/bin:/bin";
        match std::env::var("PATH") {
            Ok(host_path) if !host_path.trim().is_empty() => format!("{}:{}", host_path, base),
            _ => base.to_string(),
        }
    }

    fn build_base_bwrap_cmd(bwrap_bin: &Path, abs_root: &Path, port: u16) -> Command {
        let mut cmd = Command::new(bwrap_bin);
        let sandbox_path = build_sandbox_path();
        cmd.process_group(0);
        cmd.args([
            "--unshare-all",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--clearenv",
            "--setenv",
            "PATH",
            &sandbox_path,
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "PORT",
            &port.to_string(),
            "--setenv",
            "HOST",
            "127.0.0.1",
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
        for opt_sys_dir in ["/lib64", "/etc", "/opt", "/run/current-system", "/nix"] {
            if Path::new(opt_sys_dir).exists() {
                cmd.args(["--ro-bind", opt_sys_dir, opt_sys_dir]);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            for sub in [
                ".local", ".cargo", ".rustup", ".nvm", ".fnm", ".volta", ".bun", ".deno", ".pyenv",
                ".asdf", ".sdkman", "go",
            ] {
                let dir = format!("{}/{}", home, sub);
                if Path::new(&dir).exists() {
                    cmd.args(["--ro-bind", &dir, &dir]);
                }
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

    /// Runs BOTH the target `boot_cmd` AND `shellmind-guard __probe-netns` inside a single
    /// `--unshare-all` (including `--unshare-net`) Bubblewrap namespace with a bounded deadline.
    pub fn run_finding_in_isolated_netns(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        finding: &LatticeFinding,
        concurrency: usize,
    ) -> Result<VerifiedFinding> {
        run_finding_in_isolated_netns_with_config(
            project_root,
            boot_cmd,
            port,
            finding,
            concurrency,
            &SandboxProbeConfig::default(),
        )
    }

    pub fn run_finding_in_isolated_netns_with_config(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        finding: &LatticeFinding,
        concurrency: usize,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<VerifiedFinding> {
        let bwrap_bin =
            find_bwrap_path().ok_or_else(|| anyhow::anyhow!("bwrap binary not found on system"))?;
        let abs_root = std::fs::canonicalize(project_root)?;
        let self_exe =
            std::env::current_exe().context("Cannot locate current shellmind-guard executable")?;
        let finding_json = serde_json::to_string(finding)?;
        let probe_cfg_json = serde_json::to_string(probe_cfg)?;

        let mut cmd = build_base_bwrap_cmd(&bwrap_bin, &abs_root, port);
        cmd.args([
            "--ro-bind",
            &self_exe.to_string_lossy(),
            "/tmp/vf-probe",
            "--setenv",
            "VF_FINDING_JSON",
            &finding_json,
            "--setenv",
            "VF_PROBE_CONFIG_JSON",
            &probe_cfg_json,
            "--",
            "/bin/sh",
            "-c",
            &format!(
                "({boot_cmd}) >/dev/null 2>&1 & SRV_PID=$!; trap 'kill -9 $SRV_PID 2>/dev/null || true' EXIT; /tmp/vf-probe __probe-netns --port {port} --sync-race {concurrency}; EC=$?; kill -9 $SRV_PID 2>/dev/null || true; exit $EC"
            ),
        ]);

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn --unshare-all bwrap")?;
        ACTIVE_SANDBOX_PGID.store(child.id() as i32, Ordering::SeqCst);

        // Drain stdout and stderr concurrently on background threads so >64 KiB pipe output never deadlocks `try_wait()`
        let stdout_handle = child.stdout.take().map(|out| {
            std::thread::spawn(move || {
                use std::io::Read;
                let mut s = String::new();
                let _ = out.take(256 * 1024).read_to_string(&mut s);
                s
            })
        });
        let stderr_handle = child.stderr.take().map(|err| {
            std::thread::spawn(move || {
                use std::io::Read;
                let mut s = String::new();
                let _ = err.take(256 * 1024).read_to_string(&mut s);
                s
            })
        });

        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        kill_active_sandbox_pgid();
                        let _ = child.kill();
                        let _ = child.wait();
                        anyhow::bail!("Isolated netns probe timed out after 20s");
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => {
                    kill_active_sandbox_pgid();
                    return Err(e.into());
                }
            }
        };
        ACTIVE_SANDBOX_PGID.store(0, Ordering::SeqCst);

        let stdout_str = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let stderr_str = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();

        if !status.success() {
            anyhow::bail!(
                "Isolated netns probe failed (exit {}): {}",
                status,
                stderr_str.trim()
            );
        }

        let parsed: VerifiedFinding =
            serde_json::from_str(stdout_str.trim()).with_context(|| {
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
        let bwrap_bin = find_bwrap_path();
        let use_bwrap = bwrap_bin.is_some();

        if !use_bwrap && !allow_unsafe_host_fallback {
            anyhow::bail!(
                "bwrap is unavailable. Refusing fail-open host execution (pass --unsafe-host-fallback to override)."
            );
        }

        let wrapped_cmd = format!("({})", boot_cmd);

        let child = if let Some(bin) = bwrap_bin {
            let mut cmd = build_base_bwrap_cmd(&bin, &abs_root, port);
            cmd.args(["--", "/bin/sh", "-c", &wrapped_cmd]);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.spawn().context("Failed to spawn bwrap sandbox")?
        } else {
            let mut cmd = Command::new("/bin/sh");
            cmd.process_group(0)
                .env_clear()
                .env("PATH", build_sandbox_path())
                .env("HOME", "/tmp")
                .env("PORT", port.to_string())
                .env("HOST", "127.0.0.1")
                .env("NODE_ENV", "test")
                .args(["-c", &wrapped_cmd])
                .current_dir(&abs_root)
                .stdin(Stdio::null())
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
}

#[cfg(not(unix))]
mod imp {
    use crate::verifier::{SandboxProbeConfig, VerifiedFinding};
    use anyhow::Result;
    use std::path::Path;
    use vf_graph::LatticeFinding;

    pub struct SandboxGuard {
        pub port: u16,
        pub isolated_bwrap: bool,
    }

    pub fn kill_active_sandbox_pgid() {}

    pub fn has_bwrap() -> bool {
        false
    }

    pub fn run_finding_in_isolated_netns(
        _project_root: &Path,
        _boot_cmd: &str,
        _port: u16,
        _finding: &LatticeFinding,
        _concurrency: usize,
    ) -> Result<VerifiedFinding> {
        anyhow::bail!("Isolated Bubblewrap sandbox verification requires Linux")
    }

    pub fn run_finding_in_isolated_netns_with_config(
        _project_root: &Path,
        _boot_cmd: &str,
        _port: u16,
        _finding: &LatticeFinding,
        _concurrency: usize,
        _probe_cfg: &SandboxProbeConfig,
    ) -> Result<VerifiedFinding> {
        anyhow::bail!("Isolated Bubblewrap sandbox verification requires Linux")
    }

    pub async fn spawn_sandboxed_server(
        _project_root: &Path,
        _boot_cmd: &str,
        _port: u16,
        _allow_unsafe_host_fallback: bool,
    ) -> Result<SandboxGuard> {
        anyhow::bail!("Sandboxed server execution requires Linux Bubblewrap (bwrap)")
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_port_conflict_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let res = spawn_sandboxed_server(Path::new("."), "sleep 1", port, true).await;
        assert!(
            res.is_err(),
            "Occupied port must be refused rather than probing wrong listener"
        );
    }
}
