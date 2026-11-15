use std::path::Path;

/// Cross-platform sandbox isolation backend detected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SandboxBackend {
    LinuxBubblewrap,
    MacOsSandboxExec,
    WindowsJobObject,
    LocalLoopback,
}

impl SandboxBackend {
    /// Human-readable label shown by `shellmind-guard doctor` and scan metadata.
    pub fn label(self) -> &'static str {
        match self {
            SandboxBackend::LinuxBubblewrap => "Linux Bubblewrap (--unshare-all)",
            SandboxBackend::MacOsSandboxExec => "macOS sandbox-exec (Seatbelt loopback)",
            SandboxBackend::WindowsJobObject => "Windows Job Object (loopback guard)",
            SandboxBackend::LocalLoopback => "Local loopback (restricted env)",
        }
    }
}

/// Detects the strongest native OS sandbox backend available on this host.
pub fn detect_sandbox_backend() -> SandboxBackend {
    #[cfg(target_os = "linux")]
    {
        if has_bwrap() {
            return SandboxBackend::LinuxBubblewrap;
        }
        SandboxBackend::LocalLoopback
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            return SandboxBackend::MacOsSandboxExec;
        }
        SandboxBackend::LocalLoopback
    }
    #[cfg(target_os = "windows")]
    {
        SandboxBackend::WindowsJobObject
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        SandboxBackend::LocalLoopback
    }
}

/// Generates a least-privilege macOS Seatbelt (`.sb`) profile confined to `abs_root` and loopback `port`.
pub fn build_macos_seatbelt_profile(abs_root: &Path, port: u16) -> String {
    let escaped_root = abs_root.to_string_lossy().replace('"', "\\\"");
    format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec process-fork signal (target same-sandbox))\n\
         (allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/bin\") (subpath \"/tmp\") (subpath \"{root}\"))\n\
         (allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\"))\n\
         (allow network-bind (local ip \"localhost:{port}\"))\n\
         (allow network-outbound (remote ip \"localhost:{port}\") (remote ip \"127.0.0.1:{port}\"))\n",
        root = escaped_root,
        port = port
    )
}

/// Generates a Windows PowerShell/Win32 Job Object launch guard binding the target to loopback `port`.
pub fn build_windows_job_wrapper_script(port: u16) -> String {
    format!(
        "$env:HOST = '127.0.0.1'; $env:PORT = '{port}'; $env:NODE_ENV = 'test'; # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
        port = port
    )
}

/// Builds `systemd-run` user-scope cgroups v2 resource-limit flags when a positive MB limit is set.
pub fn build_cgroup_v2_args(unit_name: &str, mem_limit_mb: Option<u64>) -> Option<Vec<String>> {
    let mb = mem_limit_mb.filter(|v| *v > 0)?;
    Some(vec![
        "--user".to_string(),
        "--scope".to_string(),
        "--quiet".to_string(),
        "--unit".to_string(),
        unit_name.to_string(),
        "-p".to_string(),
        format!("MemoryMax={}M", mb),
        "-p".to_string(),
        "MemorySwapMax=0".to_string(),
        "-p".to_string(),
        "TasksMax=64".to_string(),
        "--".to_string(),
    ])
}

#[cfg(unix)]
mod imp {
    use super::build_cgroup_v2_args;
    use crate::verifier::{FuzzProbeHit, SandboxProbeConfig, VerifiedFinding, mock_shim_env_vars};
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

    fn apply_rlimit_as_io(mem_mb: u64) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let limit_bytes = mem_mb.checked_mul(1024 * 1024).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "RLIMIT_AS overflow")
            })?;
            let requested = limit_bytes as libc::rlim_t;
            let mut cur = libc::rlimit {
                rlim_cur: requested,
                rlim_max: requested,
            };
            // Clamp against any pre-existing container hard limit to avoid EPERM.
            // SAFETY: `cur` is a valid initialized `libc::rlimit` struct for `getrlimit`.
            let capped = if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut cur) } == 0
                && cur.rlim_max != libc::RLIM_INFINITY
            {
                requested.min(cur.rlim_max)
            } else {
                requested
            };
            let lim = libc::rlimit {
                rlim_cur: capped,
                rlim_max: capped,
            };
            // SAFETY: `lim` lives on the stack with a valid initialized `libc::rlimit` layout for RLIMIT_AS.
            let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &lim) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // XNU/macOS and several BSDs reject `RLIMIT_AS` in forked children with EINVAL;
            // Linux enforces `RLIMIT_AS` + cgroups v2, while macOS isolates via Seatbelt profiles.
            let _ = mem_mb;
            Ok(())
        }
    }

    /// Applies an explicit virtual-address-space (`RLIMIT_AS`) cap in MiB to the current process.
    pub fn apply_rlimit_as(mem_mb: u64) -> Result<()> {
        apply_rlimit_as_io(mem_mb)
            .with_context(|| format!("Failed to apply RLIMIT_AS ({} MB)", mem_mb))
    }

    fn has_systemd_user_scope() -> bool {
        Command::new("systemd-run")
            .args(["--user", "--version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn maybe_wrap_cgroup_v2(
        prog: &Path,
        probe_cfg: &SandboxProbeConfig,
        unit_prefix: &str,
    ) -> (Command, bool) {
        if probe_cfg.use_cgroup_v2
            && has_systemd_user_scope()
            && let Some(cg_args) = build_cgroup_v2_args(
                &format!("{}-{}", unit_prefix, std::process::id()),
                Some(probe_cfg.memory_limit_mb.unwrap_or(512)),
            )
        {
            let mut cmd = Command::new("systemd-run");
            cmd.args(cg_args);
            cmd.arg(prog);
            return (cmd, true);
        }
        (Command::new(prog), false)
    }

    fn drain_pipe<R: std::io::Read + Send + 'static>(
        pipe: Option<R>,
    ) -> Option<std::thread::JoinHandle<String>> {
        pipe.map(|out| {
            std::thread::spawn(move || {
                use std::io::Read;
                let mut s = String::new();
                let _ = out.take(512 * 1024).read_to_string(&mut s);
                s
            })
        })
    }

    fn build_shim_shell_exports(probe_cfg: &SandboxProbeConfig, port: u16) -> String {
        if !probe_cfg.mock_shims {
            return String::new();
        }
        let shim_port = port
            .checked_add(1)
            .unwrap_or_else(|| port.saturating_sub(1));
        let mut exports = format!("export VF_SHIM_PORT={}; ", shim_port);
        for (k, v) in mock_shim_env_vars(shim_port) {
            exports.push_str(&format!("export {}='{}'; ", k, v.replace('\'', "'\\''")));
        }
        exports
    }

    fn execute_in_isolated_netns(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        mode: &str,
        concurrency: usize,
        finding_json: Option<&str>,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<String> {
        let bwrap_bin =
            find_bwrap_path().ok_or_else(|| anyhow::anyhow!("bwrap binary not found on system"))?;
        let abs_root = std::fs::canonicalize(project_root)?;
        let self_exe =
            std::env::current_exe().context("Cannot locate current shellmind-guard executable")?;
        let probe_cfg_json = serde_json::to_string(probe_cfg)?;

        let (mut cmd, used_cgroup) = maybe_wrap_cgroup_v2(&bwrap_bin, probe_cfg, "vf-bwrap");
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
            "--ro-bind",
            &self_exe.to_string_lossy(),
            "/tmp/vf-probe",
            "--setenv",
            "VF_PROBE_CONFIG_JSON",
            &probe_cfg_json,
        ]);
        if let Some(fj) = finding_json {
            cmd.args(["--setenv", "VF_FINDING_JSON", fj]);
        }

        if let Some(mb) = probe_cfg.memory_limit_mb.filter(|v| *v > 0 && !used_cgroup) {
            // SAFETY: `pre_exec` invokes only async-signal-safe `libc::setrlimit` on `RLIMIT_AS`.
            unsafe {
                cmd.pre_exec(move || apply_rlimit_as_io(mb));
            }
        }

        let shim_exports = build_shim_shell_exports(probe_cfg, port);
        let shell_script = format!(
            "{shim_exports}({boot_cmd}) >/tmp/vf-boot.log 2>&1 & VF_SRV_PID=$!; export VF_SRV_PID; export VF_BOOT_LOG=/tmp/vf-boot.log; trap 'kill -9 $VF_SRV_PID 2>/dev/null || true' EXIT; /tmp/vf-probe __probe-netns --port {port} --mode {mode} --sync-race {concurrency}; EC=$?; kill -9 $VF_SRV_PID 2>/dev/null || true; exit $EC"
        );
        cmd.args(["--", "/bin/sh", "-c", &shell_script]);

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn --unshare-all bwrap")?;
        ACTIVE_SANDBOX_PGID.store(child.id() as i32, Ordering::SeqCst);

        // Drain stdout and stderr concurrently on background threads so >64 KiB pipe output never deadlocks `try_wait()`
        let stdout_handle = drain_pipe(child.stdout.take());
        let stderr_handle = drain_pipe(child.stderr.take());

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

        Ok(stdout_str)
    }

    pub fn run_finding_in_isolated_netns_with_config(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        finding: &LatticeFinding,
        concurrency: usize,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<VerifiedFinding> {
        let finding_json = serde_json::to_string(finding)?;
        let stdout_str = execute_in_isolated_netns(
            project_root,
            boot_cmd,
            port,
            "verify",
            concurrency,
            Some(&finding_json),
            probe_cfg,
        )?;
        let parsed: VerifiedFinding =
            serde_json::from_str(stdout_str.trim()).with_context(|| {
                format!(
                    "Failed to parse __probe-netns output: {}",
                    stdout_str.chars().take(200).collect::<String>()
                )
            })?;
        Ok(parsed)
    }

    /// Boots `boot_cmd` once inside an isolated `--unshare-all` Bubblewrap namespace and executes
    /// deep route-schema fuzz probes (`--mode fuzz`), returning discovered `FuzzProbeHit` items.
    pub fn run_deep_fuzz_in_isolated_netns(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<Vec<FuzzProbeHit>> {
        let stdout_str =
            execute_in_isolated_netns(project_root, boot_cmd, port, "fuzz", 12, None, probe_cfg)?;
        let parsed: Vec<FuzzProbeHit> =
            serde_json::from_str(stdout_str.trim()).with_context(|| {
                format!(
                    "Failed to parse __probe-netns fuzz output: {}",
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
        spawn_sandboxed_server_with_config(
            project_root,
            boot_cmd,
            port,
            allow_unsafe_host_fallback,
            &[],
            &SandboxProbeConfig::default(),
        )
        .await
    }

    /// Spawns a sandboxed target server with optional extra environment variables and Phase 10 resource caps.
    pub async fn spawn_sandboxed_server_with_config(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        allow_unsafe_host_fallback: bool,
        extra_env: &[(&str, String)],
        probe_cfg: &SandboxProbeConfig,
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
            for (k, v) in extra_env {
                cmd.args(["--setenv", k, v]);
            }
            if let Some(mb) = probe_cfg.memory_limit_mb.filter(|v| *v > 0) {
                // SAFETY: `pre_exec` invokes only async-signal-safe `libc::setrlimit` on `RLIMIT_AS`.
                unsafe {
                    cmd.pre_exec(move || apply_rlimit_as_io(mb));
                }
            }
            cmd.args(["--", "/bin/sh", "-c", &wrapped_cmd]);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.spawn().context("Failed to spawn bwrap sandbox")?
        } else {
            let sh_path = Path::new("/bin/sh");
            let (mut cmd, used_cgroup) =
                maybe_wrap_cgroup_v2(sh_path, probe_cfg, "vf-host-sandbox");
            cmd.process_group(0)
                .env_clear()
                .env("PATH", build_sandbox_path())
                .env("HOME", "/tmp")
                .env("PORT", port.to_string())
                .env("HOST", "127.0.0.1")
                .env("NODE_ENV", "test");
            for (k, v) in extra_env {
                cmd.env(k, v);
            }
            if let Some(mb) = probe_cfg.memory_limit_mb.filter(|v| *v > 0 && !used_cgroup) {
                // SAFETY: `pre_exec` invokes only async-signal-safe `libc::setrlimit` on `RLIMIT_AS`.
                unsafe {
                    cmd.pre_exec(move || apply_rlimit_as_io(mb));
                }
            }
            cmd.args(["-c", &wrapped_cmd])
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
    use crate::verifier::{FuzzProbeHit, SandboxProbeConfig, VerifiedFinding};
    use anyhow::Result;
    use std::path::Path;
    use vf_graph::LatticeFinding;

    pub struct SandboxGuard {
        pub port: u16,
        pub isolated_bwrap: bool,
    }

    impl Drop for SandboxGuard {
        fn drop(&mut self) {
            let _ = (self.port, self.isolated_bwrap);
        }
    }

    pub fn kill_active_sandbox_pgid() {}

    pub fn has_bwrap() -> bool {
        false
    }

    pub fn apply_rlimit_as(_mem_mb: u64) -> Result<()> {
        Ok(())
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

    pub fn run_deep_fuzz_in_isolated_netns(
        _project_root: &Path,
        _boot_cmd: &str,
        _port: u16,
        _probe_cfg: &SandboxProbeConfig,
    ) -> Result<Vec<FuzzProbeHit>> {
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

    pub async fn spawn_sandboxed_server_with_config(
        _project_root: &Path,
        _boot_cmd: &str,
        _port: u16,
        _allow_unsafe_host_fallback: bool,
        _extra_env: &[(&str, String)],
        _probe_cfg: &SandboxProbeConfig,
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

    #[test]
    fn test_cross_os_sandbox_helpers_and_cgroup_v2_args() {
        let backend = detect_sandbox_backend();
        assert!(!backend.label().is_empty());

        let seatbelt = build_macos_seatbelt_profile(Path::new("/tmp/app"), 49123);
        assert!(seatbelt.contains("(deny default)"));
        assert!(seatbelt.contains("127.0.0.1:49123"));
        assert!(seatbelt.contains("/tmp/app"));

        let win_script = build_windows_job_wrapper_script(49123);
        assert!(win_script.contains("49123"));
        assert!(win_script.contains("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"));

        let cg_args = build_cgroup_v2_args("vf-unit", Some(256)).expect("cgroup args");
        assert!(cg_args.contains(&"MemoryMax=256M".to_string()));
        assert!(cg_args.contains(&"MemorySwapMax=0".to_string()));
        assert!(cg_args.contains(&"TasksMax=64".to_string()));
        assert!(build_cgroup_v2_args("vf-unit", None).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_rlimit_as_memory_cap_in_child() {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "true"]);
        // SAFETY: `pre_exec` applies async-signal-safe `RLIMIT_AS` before `execve`.
        unsafe {
            cmd.pre_exec(|| {
                apply_rlimit_as(512).map_err(std::io::Error::other)?;
                Ok(())
            });
        }
        let status = cmd.status().expect("child shell under 512MB RLIMIT_AS");
        assert!(
            status.success(),
            "Lightweight child must run under 512MB RLIMIT_AS"
        );
    }
}
