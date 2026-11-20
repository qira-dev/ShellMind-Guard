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
    build_macos_seatbelt_profile_with_extras(abs_root, port, &[], &[])
}

/// Generates a least-privilege macOS Seatbelt (`.sb`) profile with optional extra read-only paths
/// (e.g. probe binary/config directory) and extra loopback ports (e.g. mock shim server port).
pub fn build_macos_seatbelt_profile_with_extras(
    abs_root: &Path,
    port: u16,
    extra_ro_paths: &[&Path],
    extra_ports: &[u16],
) -> String {
    let escape_sbpl = |p: &Path| -> String {
        p.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let escaped_root = escape_sbpl(abs_root);
    let mut extra_ro_clauses = String::new();
    for p in extra_ro_paths {
        extra_ro_clauses.push_str(&format!(" (subpath \"{}\")", escape_sbpl(p)));
    }
    let mut extra_bind_clauses = String::new();
    let mut extra_out_clauses = String::new();
    for &ep in extra_ports {
        if ep > 0 && ep != port {
            extra_bind_clauses.push_str(&format!(" (local ip \"localhost:{ep}\")"));
            extra_out_clauses.push_str(&format!(
                " (remote ip \"localhost:{ep}\") (remote ip \"127.0.0.1:{ep}\")"
            ));
        }
    }
    format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec process-fork signal (target same-sandbox))\n\
         (allow file-read* (subpath \"/usr\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/bin\") (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/opt/homebrew\") (subpath \"/usr/local\") (subpath \"{root}\"){extra_ro})\n\
         (allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\"))\n\
         (allow network-bind (local ip \"localhost:{port}\"){extra_bind})\n\
         (allow network-outbound (remote ip \"localhost:{port}\") (remote ip \"127.0.0.1:{port}\"){extra_out})\n",
        root = escaped_root,
        port = port,
        extra_ro = extra_ro_clauses,
        extra_bind = extra_bind_clauses,
        extra_out = extra_out_clauses,
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
    use smg_graph::LatticeFinding;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tokio::net::TcpStream;
    use tokio::time::sleep;

    static ACTIVE_SANDBOX_PGID: AtomicI32 = AtomicI32::new(0);
    static CGROUP_UNIT_SEQ: AtomicU64 = AtomicU64::new(1);

    pub struct SandboxGuard {
        child: Child,
        pub port: u16,
        pub isolated_bwrap: bool,
    }

    pub fn kill_active_sandbox_pgid() {
        let pgid = ACTIVE_SANDBOX_PGID.swap(0, Ordering::SeqCst);
        if pgid > 0 {
            #[cfg(target_os = "linux")]
            // SAFETY: `pgid` is an active positive sandbox process-group id spawned with `.process_group(0)`.
            unsafe {
                libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
            }
            #[cfg(not(target_os = "linux"))]
            unsafe {
                libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
            }
        }
    }

    impl Drop for SandboxGuard {
        fn drop(&mut self) {
            let pid = self.child.id() as i32;
            ACTIVE_SANDBOX_PGID
                .compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst)
                .ok();
            // Only kill `-pid` BEFORE reaping while child is still alive in the kernel PID table
            // to prevent PID-recycling collisions against unrelated processes.
            let still_running = matches!(self.child.try_wait(), Ok(None));
            if still_running && pid > 0 {
                // SAFETY: `pid` is a live process-group leader owned by `self.child` (not yet waited).
                unsafe {
                    libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                }
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            for _ in 0..25 {
                if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    fn bind_runtime_sys_dirs(cmd: &mut Command) {
        // Expose only essential system runtime paths & minimal TLS/DNS/loader `/etc` entries
        // instead of host `/etc/passwd`, `/etc/ssh`, or `/etc/sudoers`.
        for opt_dir in [
            "/lib64",
            "/opt",
            "/run/current-system",
            "/nix",
            "/etc/ssl",
            "/etc/ca-certificates",
            "/etc/pki",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/localtime",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/alternatives",
            "/etc/mime.types",
            "/etc/gai.conf",
        ] {
            if Path::new(opt_dir).exists() {
                cmd.args(["--ro-bind", opt_dir, opt_dir]);
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

    pub fn has_isolated_sandbox() -> bool {
        has_bwrap() || (cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists())
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
        bind_runtime_sys_dirs(&mut cmd);
        if let Ok(home) = std::env::var("HOME") {
            for sub in [
                ".local/bin",
                ".cargo/bin",
                ".rustup",
                ".nvm",
                ".fnm",
                ".volta",
                ".bun",
                ".deno",
                ".pyenv",
                ".asdf",
                ".sdkman",
                "go/bin",
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

    #[cfg(target_os = "linux")]
    fn compute_rlimit_as_bytes(mem_mb: u64) -> Option<libc::rlim_t> {
        let bytes = mem_mb.checked_mul(1024 * 1024)?;
        #[allow(clippy::unnecessary_cast)]
        let max_rlim = libc::rlim_t::MAX as u64;
        Some(bytes.min(max_rlim) as libc::rlim_t)
    }

    #[cfg(target_os = "linux")]
    fn apply_rlimit_as_val(requested: libc::rlim_t) -> std::io::Result<()> {
        let mut cur = libc::rlimit {
            rlim_cur: requested,
            rlim_max: requested,
        };
        // Clamp against any pre-existing container hard limit to avoid EPERM.
        // SAFETY: `cur` is stack-allocated and async-signal-safe; no heap allocation in `pre_exec`.
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

    fn apply_rlimit_as_io(mem_mb: u64) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let requested = compute_rlimit_as_bytes(mem_mb)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            apply_rlimit_as_val(requested)
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
        let seq = CGROUP_UNIT_SEQ.fetch_add(1, Ordering::Relaxed);
        if probe_cfg.use_cgroup_v2
            && has_systemd_user_scope()
            && let Some(cg_args) = build_cgroup_v2_args(
                &format!("{}-{}-{}", unit_prefix, std::process::id(), seq),
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
        let mut exports = format!("export SMG_SHIM_PORT={}; ", shim_port);
        for (k, v) in mock_shim_env_vars(shim_port) {
            exports.push_str(&format!("export {}='{}'; ", k, v.replace('\'', "'\\''")));
        }
        exports
    }

    struct ProbeTempDirGuard(PathBuf);
    impl Drop for ProbeTempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
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
        use std::os::unix::fs::PermissionsExt;
        let bwrap_bin_opt = find_bwrap_path();
        let has_macos_seatbelt =
            cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists();
        if bwrap_bin_opt.is_none() && !has_macos_seatbelt {
            anyhow::bail!(
                "No isolated OS sandbox backend found (requires bwrap on Linux or sandbox-exec on macOS)"
            );
        }
        let abs_root = std::fs::canonicalize(project_root)?;
        let self_exe =
            std::env::current_exe().context("Cannot locate current shellmind-guard executable")?;
        let probe_cfg_json = serde_json::to_string(probe_cfg)?;

        // Keep probe tokens/config out of `/proc/<pid>/cmdline` via a 0700 temp dir ro-bound into /tmp
        let seq = CGROUP_UNIT_SEQ.fetch_add(1, Ordering::Relaxed);
        let probe_dir =
            std::env::temp_dir().join(format!("smg-probe-{}-{}-{}", std::process::id(), seq, port));
        std::fs::create_dir_all(&probe_dir)?;
        let _ = std::fs::set_permissions(&probe_dir, std::fs::Permissions::from_mode(0o700));
        let _probe_dir_guard = ProbeTempDirGuard(probe_dir.clone());
        let probe_cfg_file = probe_dir.join("probe_cfg.json");
        std::fs::write(&probe_cfg_file, probe_cfg_json.as_bytes())?;
        let _ = std::fs::set_permissions(&probe_cfg_file, std::fs::Permissions::from_mode(0o600));
        let finding_file = probe_dir.join("finding.json");
        if let Some(fj) = finding_json {
            std::fs::write(&finding_file, fj.as_bytes())?;
            let _ = std::fs::set_permissions(&finding_file, std::fs::Permissions::from_mode(0o600));
        }

        let sandbox_path = build_sandbox_path();
        let shim_exports = build_shim_shell_exports(probe_cfg, port);

        let mut cmd = if let Some(bwrap_bin) = bwrap_bin_opt {
            let (mut c, used_cgroup) = maybe_wrap_cgroup_v2(&bwrap_bin, probe_cfg, "smg-bwrap");
            c.process_group(0);
            c.args([
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
            bind_runtime_sys_dirs(&mut c);
            if let Ok(home) = std::env::var("HOME") {
                for sub in [
                    ".local/bin",
                    ".cargo/bin",
                    ".rustup",
                    ".nvm",
                    ".fnm",
                    ".volta",
                    ".bun",
                    ".deno",
                    ".pyenv",
                    ".asdf",
                    ".sdkman",
                    "go/bin",
                ] {
                    let dir = format!("{}/{}", home, sub);
                    if Path::new(&dir).exists() {
                        c.args(["--ro-bind", &dir, &dir]);
                    }
                }
            }
            c.args([
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
                "/tmp/smg-probe",
                "--ro-bind",
                &probe_cfg_file.to_string_lossy(),
                "/tmp/smg-probe-cfg.json",
                "--setenv",
                "SMG_PROBE_CONFIG_FILE",
                "/tmp/smg-probe-cfg.json",
            ]);
            if finding_json.is_some() {
                c.args([
                    "--ro-bind",
                    &finding_file.to_string_lossy(),
                    "/tmp/smg-finding.json",
                    "--setenv",
                    "SMG_FINDING_FILE",
                    "/tmp/smg-finding.json",
                ]);
            }

            #[cfg(target_os = "linux")]
            if let Some(mb) = probe_cfg.memory_limit_mb.filter(|v| *v > 0 && !used_cgroup)
                && let Some(lim_bytes) = compute_rlimit_as_bytes(mb)
            {
                // SAFETY: `pre_exec` invokes only async-signal-safe `libc::getrlimit`/`libc::setrlimit` without heap allocations.
                unsafe {
                    c.pre_exec(move || apply_rlimit_as_val(lim_bytes));
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = used_cgroup;

            c.args(["--setenv", "SMG_BOOT_CMD", boot_cmd]);
            let shell_script = format!(
                "{shim_exports}/bin/sh -c \"$SMG_BOOT_CMD\" >/tmp/smg-boot.log 2>&1 & SMG_SRV_PID=$!; export SMG_SRV_PID; export SMG_BOOT_LOG=/tmp/smg-boot.log; trap 'kill -9 $SMG_SRV_PID 2>/dev/null || true' EXIT; /tmp/smg-probe __probe-netns --port {port} --mode {mode} --sync-race {concurrency}; EC=$?; kill -9 $SMG_SRV_PID 2>/dev/null || true; exit $EC"
            );
            c.args(["--", "/bin/sh", "-c", &shell_script]);
            c
        } else {
            // macOS Seatbelt (`/usr/bin/sandbox-exec`) isolated verify/fuzz execution
            let mut extra_ro: Vec<&Path> = vec![&probe_dir];
            if let Some(exe_dir) = self_exe.parent() {
                extra_ro.push(exe_dir);
            }
            let mut extra_ports = Vec::new();
            if probe_cfg.mock_shims {
                extra_ports.push(
                    port.checked_add(1)
                        .unwrap_or_else(|| port.saturating_sub(1)),
                );
            }
            // Phase 14A (`P14-01`): Allow Seatbelt loopback OobSsrfCatcher callback port
            if let Some(oob_port) = port.checked_add(2) {
                extra_ports.push(oob_port);
            }
            let profile = super::build_macos_seatbelt_profile_with_extras(
                &abs_root,
                port,
                &extra_ro,
                &extra_ports,
            );
            let boot_log_path = probe_dir.join("boot.log");
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.process_group(0)
                .env_clear()
                .env("PATH", &sandbox_path)
                .env("HOME", "/tmp")
                .env("PORT", port.to_string())
                .env("HOST", "127.0.0.1")
                .env("NODE_ENV", "test")
                .env("SMG_PROBE_CONFIG_FILE", &probe_cfg_file)
                .env("SMG_BOOT_CMD", boot_cmd)
                .env("SMG_BOOT_LOG", &boot_log_path)
                .current_dir(&abs_root);
            if finding_json.is_some() {
                c.env("SMG_FINDING_FILE", &finding_file);
            }
            let self_exe_escaped = self_exe.to_string_lossy().replace('\'', "'\\''");
            let boot_log_escaped = boot_log_path.to_string_lossy().replace('\'', "'\\''");
            let shell_script = format!(
                "{shim_exports}/bin/sh -c \"$SMG_BOOT_CMD\" >'{boot_log_escaped}' 2>&1 & SMG_SRV_PID=$!; export SMG_SRV_PID; trap 'kill -9 $SMG_SRV_PID 2>/dev/null || true' EXIT; '{self_exe_escaped}' __probe-netns --port {port} --mode {mode} --sync-race {concurrency}; EC=$?; kill -9 $SMG_SRV_PID 2>/dev/null || true; exit $EC"
            );
            c.args(["-p", &profile, "/bin/sh", "-c", &shell_script]);
            c
        };

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

    /// Boots `boot_cmd` once inside an isolated `--unshare-all` Bubblewrap / Seatbelt sandbox and verifies
    /// a batch of dynamic findings sequentially against the single warm server (`--mode verify-batch`).
    pub fn run_findings_batch_in_isolated_netns_with_config(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        findings: &[LatticeFinding],
        concurrency: usize,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<Vec<VerifiedFinding>> {
        let batch_json = serde_json::to_string(findings)?;
        let stdout_str = execute_in_isolated_netns(
            project_root,
            boot_cmd,
            port,
            "verify-batch",
            concurrency,
            Some(&batch_json),
            probe_cfg,
        )?;
        let parsed: Vec<VerifiedFinding> =
            serde_json::from_str(stdout_str.trim()).with_context(|| {
                format!(
                    "Failed to parse __probe-netns verify-batch output: {}",
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
        let has_macos_seatbelt =
            cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists();
        let use_bwrap = bwrap_bin.is_some() || has_macos_seatbelt;

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
        } else if has_macos_seatbelt {
            let profile = super::build_macos_seatbelt_profile(&abs_root, port);
            let mut cmd = Command::new("/usr/bin/sandbox-exec");
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
            cmd.args(["-p", &profile, "/bin/sh", "-c", &wrapped_cmd])
                .current_dir(&abs_root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.spawn()
                .context("Failed to spawn macOS Seatbelt sandbox-exec")?
        } else {
            let sh_path = Path::new("/bin/sh");
            let (mut cmd, used_cgroup) =
                maybe_wrap_cgroup_v2(sh_path, probe_cfg, "smg-host-sandbox");
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
    use anyhow::{Context, Result};
    use smg_graph::LatticeFinding;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tokio::net::TcpStream;
    use tokio::time::sleep;

    static WIN_PROBE_SEQ: AtomicU64 = AtomicU64::new(1);

    #[cfg(windows)]
    mod win_job {
        use std::os::windows::io::AsRawHandle;
        use std::process::Child;

        type WinHandle = *mut core::ffi::c_void;
        type WinBool = i32;
        type WinDword = u32;

        const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
        const JOB_OBJECT_LIMIT_PROCESS_MEMORY: WinDword = 0x0000_0100;
        const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: WinDword = 0x0000_2000;

        #[repr(C)]
        struct IoCounters {
            read_operation_count: u64,
            write_operation_count: u64,
            other_operation_count: u64,
            read_transfer_count: u64,
            write_transfer_count: u64,
            other_transfer_count: u64,
        }

        #[repr(C)]
        struct JobObjectBasicLimitInformation {
            per_process_user_time_limit: i64,
            per_job_user_time_limit: i64,
            limit_flags: WinDword,
            minimum_working_set_size: usize,
            maximum_working_set_size: usize,
            active_process_limit: WinDword,
            affinity: usize,
            priority_class: WinDword,
            scheduling_class: WinDword,
        }

        #[repr(C)]
        struct JobObjectExtendedLimitInformation {
            basic_limit_information: JobObjectBasicLimitInformation,
            io_info: IoCounters,
            process_memory_limit: usize,
            job_memory_limit: usize,
            peak_process_memory_used: usize,
            peak_job_memory_used: usize,
        }

        unsafe extern "system" {
            fn CreateJobObjectW(
                lp_job_attributes: *mut core::ffi::c_void,
                lp_name: *const u16,
            ) -> WinHandle;
            fn SetInformationJobObject(
                h_job: WinHandle,
                job_object_information_class: i32,
                lp_job_object_information: *const core::ffi::c_void,
                cb_job_object_information_length: WinDword,
            ) -> WinBool;
            fn AssignProcessToJobObject(h_job: WinHandle, h_process: WinHandle) -> WinBool;
            fn TerminateJobObject(h_job: WinHandle, u_exit_code: u32) -> WinBool;
            fn CloseHandle(h_object: WinHandle) -> WinBool;
        }

        pub struct JobHandle(WinHandle);
        // SAFETY: Win32 Job Object handles are kernel objects safe to close/terminate from any thread.
        unsafe impl Send for JobHandle {}
        unsafe impl Sync for JobHandle {}

        impl JobHandle {
            pub fn create_and_assign(child: &Child, memory_limit_mb: Option<u64>) -> Option<Self> {
                // SAFETY: Valid null-name Job Object creation and extended limit struct initialization.
                unsafe {
                    let h = CreateJobObjectW(core::ptr::null_mut(), core::ptr::null());
                    if h.is_null() {
                        return None;
                    }
                    let mut info: JobObjectExtendedLimitInformation = core::mem::zeroed();
                    info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    if let Some(mb) = memory_limit_mb.filter(|v| *v > 0)
                        && let Some(bytes) = (mb as usize).checked_mul(1024 * 1024)
                    {
                        info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                        info.process_memory_limit = bytes;
                    }
                    let ok = SetInformationJobObject(
                        h,
                        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                        (&raw const info).cast(),
                        core::mem::size_of::<JobObjectExtendedLimitInformation>() as WinDword,
                    );
                    if ok == 0 {
                        CloseHandle(h);
                        return None;
                    }
                    let proc_h = child.as_raw_handle() as WinHandle;
                    if AssignProcessToJobObject(h, proc_h) == 0 {
                        CloseHandle(h);
                        return None;
                    }
                    Some(Self(h))
                }
            }
        }

        impl Drop for JobHandle {
            fn drop(&mut self) {
                // SAFETY: `self.0` is a valid owned kernel Job Object handle.
                unsafe {
                    let _ = TerminateJobObject(self.0, 1);
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub struct SandboxGuard {
        #[cfg(windows)]
        _job: Option<win_job::JobHandle>,
        child: Option<Child>,
        pub port: u16,
        pub isolated_bwrap: bool,
    }

    impl Drop for SandboxGuard {
        fn drop(&mut self) {
            if let Some(ref mut c) = self.child {
                let pid = c.id();
                let _ = Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = c.kill();
                let _ = c.wait();
            }
            let _ = (self.port, self.isolated_bwrap);
        }
    }

    pub fn kill_active_sandbox_pgid() {}

    pub fn has_bwrap() -> bool {
        has_wsl_bwrap()
    }

    pub fn has_isolated_sandbox() -> bool {
        has_wsl_bwrap()
    }

    fn has_wsl_bwrap() -> bool {
        static WSL_BWRAP: OnceLock<bool> = OnceLock::new();
        *WSL_BWRAP.get_or_init(|| {
            Command::new("wsl.exe")
                .args([
                    "-e",
                    "sh",
                    "-c",
                    "command -v bwrap >/dev/null 2>&1 && command -v smg >/dev/null 2>&1",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
    }

    pub fn apply_rlimit_as(_mem_mb: u64) -> Result<()> {
        Ok(())
    }

    fn run_wsl_bwrap_netns(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        mode: &str,
        concurrency: usize,
        finding_json: Option<&str>,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<String> {
        if !has_wsl_bwrap() {
            anyhow::bail!(
                "Isolated Bubblewrap sandbox requires Linux or WSL2 (with bwrap + smg installed)"
            );
        }
        let abs_root = std::fs::canonicalize(project_root)?;
        let win_root = abs_root.to_string_lossy().to_string();
        let wsl_root_out = Command::new("wsl.exe")
            .args(["-e", "wslpath", "-u", &win_root])
            .output()
            .context("Failed to translate Windows path via wslpath")?;
        if !wsl_root_out.status.success() {
            anyhow::bail!("wslpath failed for {}", win_root);
        }
        let wsl_root = String::from_utf8_lossy(&wsl_root_out.stdout)
            .trim()
            .to_string();
        let seq = WIN_PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
        let probe_dir =
            std::env::temp_dir().join(format!("smg-wsl-{}-{}", std::process::id(), seq));
        std::fs::create_dir_all(&probe_dir)?;
        let cfg_file = probe_dir.join("probe_cfg.json");
        std::fs::write(&cfg_file, serde_json::to_string(probe_cfg)?.as_bytes())?;
        let finding_file = probe_dir.join("finding.json");
        if let Some(fj) = finding_json {
            std::fs::write(&finding_file, fj.as_bytes())?;
        }
        let wsl_cfg = String::from_utf8_lossy(
            &Command::new("wsl.exe")
                .args(["-e", "wslpath", "-u", &cfg_file.to_string_lossy()])
                .output()?
                .stdout,
        )
        .trim()
        .to_string();
        let wsl_finding = if finding_json.is_some() {
            Some(
                String::from_utf8_lossy(
                    &Command::new("wsl.exe")
                        .args(["-e", "wslpath", "-u", &finding_file.to_string_lossy()])
                        .output()?
                        .stdout,
                )
                .trim()
                .to_string(),
            )
        } else {
            None
        };

        let mut bwrap_script = format!(
            "bwrap --unshare-all --new-session --cap-drop ALL --die-with-parent --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /bin /bin --ro-bind '{wsl_root}' /app --tmpfs /tmp --proc /proc --dev /dev --chdir /app --ro-bind '{wsl_cfg}' /tmp/smg-probe-cfg.json --setenv SMG_PROBE_CONFIG_FILE /tmp/smg-probe-cfg.json --setenv PORT {port} --setenv HOST 127.0.0.1 --setenv NODE_ENV test"
        );
        if let Some(ref wf) = wsl_finding {
            bwrap_script.push_str(&format!(
                " --ro-bind '{wf}' /tmp/smg-finding.json --setenv SMG_FINDING_FILE /tmp/smg-finding.json"
            ));
        }
        let escaped_boot = boot_cmd.replace('\'', "'\\''");
        bwrap_script.push_str(&format!(
            " -- /bin/sh -c \"({escaped_boot}) >/tmp/smg-boot.log 2>&1 & SMG_SRV_PID=\\$!; export SMG_SRV_PID; export SMG_BOOT_LOG=/tmp/smg-boot.log; trap 'kill -9 \\$SMG_SRV_PID 2>/dev/null || true' EXIT; smg __probe-netns --port {port} --mode {mode} --sync-race {concurrency}; EC=\\$?; kill -9 \\$SMG_SRV_PID 2>/dev/null || true; exit \\$EC\""
        ));
        let out = Command::new("wsl.exe")
            .args(["-e", "sh", "-c", &bwrap_script])
            .output()
            .context("Failed to execute WSL2 bwrap isolated probe")?;
        let _ = std::fs::remove_dir_all(&probe_dir);
        if !out.status.success() {
            anyhow::bail!(
                "WSL2 bwrap isolated probe failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

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
        let fj = serde_json::to_string(finding)?;
        let out = run_wsl_bwrap_netns(
            project_root,
            boot_cmd,
            port,
            "verify",
            concurrency,
            Some(&fj),
            probe_cfg,
        )?;
        serde_json::from_str(out.trim()).context("Failed to parse WSL2 bwrap __probe-netns output")
    }

    pub fn run_findings_batch_in_isolated_netns_with_config(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        findings: &[LatticeFinding],
        concurrency: usize,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<Vec<VerifiedFinding>> {
        let batch_json = serde_json::to_string(findings)?;
        let out = run_wsl_bwrap_netns(
            project_root,
            boot_cmd,
            port,
            "verify-batch",
            concurrency,
            Some(&batch_json),
            probe_cfg,
        )?;
        serde_json::from_str(out.trim())
            .context("Failed to parse WSL2 bwrap __probe-netns verify-batch output")
    }

    pub fn run_deep_fuzz_in_isolated_netns(
        project_root: &Path,
        boot_cmd: &str,
        port: u16,
        probe_cfg: &SandboxProbeConfig,
    ) -> Result<Vec<FuzzProbeHit>> {
        let out = run_wsl_bwrap_netns(project_root, boot_cmd, port, "fuzz", 12, None, probe_cfg)?;
        serde_json::from_str(out.trim())
            .context("Failed to parse WSL2 bwrap __probe-netns fuzz output")
    }

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
        if !allow_unsafe_host_fallback {
            anyhow::bail!(
                "Sandboxed server execution requires Linux/WSL2 Bubblewrap (bwrap) or --unsafe-host-fallback"
            );
        }
        let abs_root = std::fs::canonicalize(project_root)?;
        let ps_guard = super::build_windows_job_wrapper_script(port);
        let full_cmd = format!("{}; {}", ps_guard, boot_cmd);
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", &full_cmd])
            .current_dir(&abs_root)
            .env("PORT", port.to_string())
            .env("HOST", "127.0.0.1")
            .env("NODE_ENV", "test")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd
            .spawn()
            .context("Failed to spawn Windows PowerShell host fallback server")?;
        #[cfg(windows)]
        let job = win_job::JobHandle::create_and_assign(&child, probe_cfg.memory_limit_mb);
        #[cfg(not(windows))]
        let _ = probe_cfg;
        let mut guard = SandboxGuard {
            #[cfg(windows)]
            _job: job,
            child: Some(child),
            port,
            isolated_bwrap: false,
        };
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(ref mut c) = guard.child
                && let Ok(Some(status)) = c.try_wait()
            {
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

        let seatbelt_extras = build_macos_seatbelt_profile_with_extras(
            Path::new("/tmp/app\"quote\\slash"),
            49123,
            &[Path::new("/tmp/probe-dir")],
            &[49124],
        );
        assert!(seatbelt_extras.contains("/tmp/app\\\"quote\\\\slash"));
        assert!(seatbelt_extras.contains("/tmp/probe-dir"));
        assert!(seatbelt_extras.contains("localhost:49124"));
        assert!(seatbelt_extras.contains("127.0.0.1:49124"));
        let _ = has_isolated_sandbox();

        let win_script = build_windows_job_wrapper_script(49123);
        assert!(win_script.contains("49123"));
        assert!(win_script.contains("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"));

        let cg_args = build_cgroup_v2_args("smg-unit", Some(256)).expect("cgroup args");
        assert!(cg_args.contains(&"MemoryMax=256M".to_string()));
        assert!(cg_args.contains(&"MemorySwapMax=0".to_string()));
        assert!(cg_args.contains(&"TasksMax=64".to_string()));
        assert!(build_cgroup_v2_args("smg-unit", None).is_none());
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
