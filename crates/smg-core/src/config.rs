use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellMindGuardConfig {
    #[serde(default)]
    pub guards: GuardConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub ai: AiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default)]
    pub provider: String,
    #[serde(default = "default_ai_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_ai_model")]
    pub model: String,
    #[serde(default = "default_ai_key_env")]
    pub api_key_env: String,
}

fn default_ai_endpoint() -> String {
    "http://127.0.0.1:11434".to_string()
}

fn default_ai_model() -> String {
    "qwen2.5-coder:7b".to_string()
}

fn default_ai_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            endpoint: default_ai_endpoint(),
            model: default_ai_model(),
            api_key_env: default_ai_key_env(),
        }
    }
}

impl AiConfig {
    pub fn is_enabled(&self) -> bool {
        let p = self.provider.trim().to_ascii_lowercase();
        !p.is_empty() && p != "disabled" && p != "none"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default = "default_auth_guards")]
    pub auth_guards: Vec<String>,
    #[serde(default = "default_lock_guards")]
    pub lock_guards: Vec<String>,
    #[serde(default = "default_public_routes")]
    pub public_routes: Vec<String>,
    #[serde(default)]
    pub custom_routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default = "default_max_threads")]
    pub max_threads: usize,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default)]
    pub deep_audit: bool,
}

impl ScanConfig {
    /// CFG basic-block budget per function (256 standard, 2048 under `--deep-audit`).
    pub fn max_cfg_blocks(&self) -> usize {
        if self.deep_audit { 2048 } else { 256 }
    }

    /// AST block nesting depth budget per function (32 standard, 64 under `--deep-audit`).
    pub fn max_ast_block_depth(&self) -> usize {
        if self.deep_audit { 64 } else { 32 }
    }

    /// Polymorphic CHA/RTA dispatch target fanout cap (8 standard, 64 under `--deep-audit`).
    pub fn max_cha_targets(&self) -> usize {
        if self.deep_audit { 64 } else { 8 }
    }

    /// Cross-file witness & taint hop budget (64 standard, 256 under `--deep-audit`).
    pub fn max_witness_hops(&self) -> usize {
        if self.deep_audit { 256 } else { 64 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxConfig {
    pub boot_cmd: Option<String>,
    pub base_url: Option<String>,
    #[serde(default)]
    pub user_a_header: Option<String>,
    #[serde(default)]
    pub user_b_header: Option<String>,
    #[serde(default)]
    pub probe_body: Option<String>,
    #[serde(default)]
    pub memory_limit_mb: Option<u64>,
    #[serde(default)]
    pub use_cgroup_v2: bool,
    #[serde(default)]
    pub mock_shims: bool,
}

impl SandboxConfig {
    pub fn is_tls(&self) -> bool {
        self.base_url
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| s.to_ascii_lowercase().starts_with("https://"))
    }

    /// Parses `[sandbox].base_url` strictly enforcing loopback-only hosts (`127.0.0.1`, `localhost`, `[::1]`).
    pub fn loopback_port(&self) -> Result<Option<u16>> {
        let Some(raw) = self
            .base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let lower = raw.to_ascii_lowercase();
        let (rest, default_port) = if lower.starts_with("https://") {
            (&raw["https://".len()..], 443u16)
        } else if lower.starts_with("http://") {
            (&raw["http://".len()..], 80u16)
        } else {
            anyhow::bail!(
                "sandbox.base_url must use http:// or https:// on loopback, got: {}",
                raw
            );
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        anyhow::ensure!(
            !authority.contains('@'),
            "Refusing userinfo in sandbox.base_url `{}`",
            raw
        );
        let (host, port_str, is_bracketed_v6) =
            if let Some(after_bracket) = authority.strip_prefix("[::1]") {
                match after_bracket.strip_prefix(':') {
                    Some(p) => ("::1", p, true),
                    None if after_bracket.is_empty() => ("::1", "", true),
                    None => anyhow::bail!("Malformed IPv6 authority in sandbox.base_url `{}`", raw),
                }
            } else if let Some((h, p)) = authority.rsplit_once(':') {
                (h, p, false)
            } else {
                (authority, "", false)
            };
        let host_ok = if is_bracketed_v6 {
            true
        } else {
            matches!(
                host.to_ascii_lowercase().as_str(),
                "127.0.0.1" | "localhost"
            )
        };
        if !host_ok {
            anyhow::bail!(
                "Refusing non-loopback sandbox.base_url `{}` (only 127.0.0.1, localhost, or [::1] allowed)",
                raw
            );
        }
        if port_str.is_empty() {
            Ok(Some(default_port))
        } else {
            let p: u16 = port_str
                .parse()
                .with_context(|| format!("Invalid port in sandbox.base_url `{}`", raw))?;
            anyhow::ensure!(p != 0, "Refusing port 0 in sandbox.base_url `{}`", raw);
            Ok(Some(p))
        }
    }
}

fn default_auth_guards() -> Vec<String> {
    vec![
        "requireAuth".into(),
        "require_auth".into(),
        "RequireAuth".into(),
        "RequireSession".into(),
        "requireSession".into(),
        "require_session".into(),
        "SessionAuth".into(),
        "sessionAuth".into(),
        "session_auth".into(),
        "VerifySession".into(),
        "verifySession".into(),
        "verify_session".into(),
        "EnsureAuth".into(),
        "ensureAuth".into(),
        "ensure_auth".into(),
        "RequireLogin".into(),
        "requireLogin".into(),
        "AuthRequired".into(),
        "authRequired".into(),
        "auth_required".into(),
        "WithAuth".into(),
        "WithSession".into(),
        "withSession".into(),
        "authenticate".into(),
        "verifyJwt".into(),
        "verify_jwt".into(),
        "verify_token".into(),
        "withAuth".into(),
        "with_auth".into(),
        "requireAdmin".into(),
        "require_admin".into(),
        "get_current_user".into(),
        "ensureAuthenticated".into(),
        "AuthGuard".into(),
        "UseGuards".into(),
        "protectedProcedure".into(),
        "login_required".into(),
        "AuthV1".into(),
        "AuthMiddleware".into(),
        "AdminAuth".into(),
        "TeamRequire".into(),
        "MetricsTokenGate".into(),
    ]
}

fn default_lock_guards() -> Vec<String> {
    vec![
        "withTransaction".into(),
        "FOR UPDATE".into(),
        "acquireLock".into(),
        "idempotencyKey".into(),
        "BeginTx".into(),
        "db.Transaction".into(),
        "$transaction".into(),
    ]
}

fn default_public_routes() -> Vec<String> {
    vec![
        "/health".into(),
        "/healthz".into(),
        "/readyz".into(),
        "/metrics".into(),
        "/login".into(),
        "/register".into(),
        "/signup".into(),
        "/webhook".into(),
        "/api/v1/healthz".into(),
        "/api/v1/auth/login".into(),
        "/api/v1/auth/register".into(),
        "/api/v1/auth/2fa/confirm".into(),
    ]
}

fn default_max_threads() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cpus.saturating_sub(1).clamp(2, 6)
}

fn default_max_file_bytes() -> u64 {
    2 * 1024 * 1024
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            auth_guards: default_auth_guards(),
            lock_guards: default_lock_guards(),
            public_routes: default_public_routes(),
            custom_routes: Vec::new(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ignore_paths: vec![
                "node_modules".into(),
                "target".into(),
                "dist".into(),
                "build".into(),
                ".next".into(),
                ".shellmind-guard".into(),
                "deps".into(),
                "vendor".into(),
                "third_party".into(),
                "3rdparty".into(),
                "submodules".into(),
            ],
            max_threads: default_max_threads(),
            max_file_bytes: default_max_file_bytes(),
            deep_audit: false,
        }
    }
}

const MAX_SAFE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_SAFE_FILE_BYTES: u64 = 1024;

impl ShellMindGuardConfig {
    pub fn load_from_dir(root: &Path) -> Result<Self> {
        const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
        let cfg_path = root.join(".shellmind-guard.toml");
        if !cfg_path.exists() {
            return Ok(Self::default());
        }
        let canon_root = fs::canonicalize(root)
            .with_context(|| format!("Failed to canonicalize root {}", root.display()))?;
        let canon_cfg = fs::canonicalize(&cfg_path)
            .with_context(|| format!("Failed to canonicalize {}", cfg_path.display()))?;
        if !canon_cfg.starts_with(&canon_root) {
            anyhow::bail!(
                "Refusing .shellmind-guard.toml that resolves outside project root: {}",
                cfg_path.display()
            );
        }
        use std::io::Read as _;
        let file = fs::File::open(&canon_cfg)
            .with_context(|| format!("Failed to open {}", cfg_path.display()))?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            anyhow::bail!("Refusing non-regular config file {}", cfg_path.display());
        }
        let mut buf = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut buf)
            .with_context(|| format!("Failed to read {}", cfg_path.display()))?;
        if buf.len() as u64 > MAX_CONFIG_BYTES {
            anyhow::bail!(
                "Refusing oversized .shellmind-guard.toml (> {} bytes)",
                MAX_CONFIG_BYTES
            );
        }
        let raw = String::from_utf8(buf)
            .with_context(|| format!("Invalid UTF-8 in {}", cfg_path.display()))?;
        let mut parsed: Self = toml::from_str(&raw)
            .with_context(|| format!("Invalid TOML in {}", cfg_path.display()))?;
        let max_allowed_threads = std::thread::available_parallelism()
            .map(|n| n.get().saturating_mul(2))
            .unwrap_or(16)
            .max(16);
        parsed.scan.max_threads = parsed.scan.max_threads.clamp(1, max_allowed_threads);
        parsed.scan.max_file_bytes = parsed
            .scan
            .max_file_bytes
            .clamp(MIN_SAFE_FILE_BYTES, MAX_SAFE_FILE_BYTES);
        Ok(parsed)
    }

    /// Loads `.shellmind-guard.toml` and strips privileged `[sandbox]`, `[ai]`,
    /// `scan.ignore_paths`, and `[guards]` overrides unless `trust_repo_config`
    /// is explicitly enabled by the operator (Council CASE-001 T1 + F1-02).
    pub fn load_trusted_from_dir(root: &Path, trust_repo_config: bool) -> Result<Self> {
        let mut cfg = Self::load_from_dir(root)?;
        if !trust_repo_config {
            cfg.sandbox = SandboxConfig::default();
            cfg.ai = AiConfig::default();
            cfg.scan.ignore_paths = ScanConfig::default().ignore_paths;
            cfg.guards = GuardConfig::default();
        }
        Ok(cfg)
    }

    pub fn detect_and_write_init(root: &Path) -> Result<(Vec<String>, std::path::PathBuf)> {
        Self::detect_and_write_init_with_force(root, false)
    }

    pub fn detect_and_write_init_with_force(
        root: &Path,
        force: bool,
    ) -> Result<(Vec<String>, std::path::PathBuf)> {
        let out_path = root.join(".shellmind-guard.toml");
        if let Ok(meta) = fs::symlink_metadata(&out_path) {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "Refusing to write through symlinked config path {}",
                    out_path.display()
                );
            }
            if !force {
                anyhow::bail!(
                    "Refusing to overwrite existing {} (pass force=true to overwrite)",
                    out_path.display()
                );
            }
        }
        let mut detected = Vec::new();
        if root.join("package.json").exists() {
            detected.push("Node.js / TypeScript".to_string());
        }
        if root.join("go.mod").exists() {
            detected.push("Go".to_string());
        }
        if root.join("Cargo.toml").exists() {
            detected.push("Rust".to_string());
        }
        if root.join("pyproject.toml").exists() || root.join("requirements.txt").exists() {
            detected.push("Python".to_string());
        }
        if detected.is_empty() {
            detected.push("Generic Multi-Language".to_string());
        }

        let cfg = Self::default();
        let toml_str = toml::to_string_pretty(&cfg)?;
        fs::write(&out_path, toml_str)?;
        Ok((detected, out_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase15b_deep_audit_budget_scaling() {
        let mut cfg = ScanConfig::default();
        assert!(!cfg.deep_audit);
        assert_eq!(cfg.max_cfg_blocks(), 256);
        assert_eq!(cfg.max_ast_block_depth(), 32);
        assert_eq!(cfg.max_cha_targets(), 8);
        assert_eq!(cfg.max_witness_hops(), 64);

        cfg.deep_audit = true;
        assert_eq!(cfg.max_cfg_blocks(), 2048);
        assert_eq!(cfg.max_ast_block_depth(), 64);
        assert_eq!(cfg.max_cha_targets(), 64);
        assert_eq!(cfg.max_witness_hops(), 256);
    }

    #[test]
    fn test_loopback_port_blocks_ipv6_userinfo_ssrf_and_port_zero() {
        let mut sb = SandboxConfig {
            base_url: Some("http://[::1]@evil.com/api".into()),
            ..Default::default()
        };
        assert!(sb.loopback_port().is_err());

        sb.base_url = Some("http://[::1]evil.com/api".into());
        assert!(sb.loopback_port().is_err());

        sb.base_url = Some("http://127.0.0.1:0/api".into());
        assert!(sb.loopback_port().is_err());

        sb.base_url = Some("http://[::1]:8080/api".into());
        assert_eq!(sb.loopback_port().unwrap(), Some(8080));

        sb.base_url = Some("https://[::1]/api".into());
        assert_eq!(sb.loopback_port().unwrap(), Some(443));
    }

    #[test]
    fn test_load_from_dir_clamps_untrusted_limits_and_trust_gate() {
        let tmp = std::env::temp_dir().join(format!("smg_cfg_clamp_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(
            tmp.join(".shellmind-guard.toml"),
            "[scan]\nmax_threads = 999999\nmax_file_bytes = 999999999999\n[guards]\nauth_guards = [\"println\"]\nlock_guards = [\"query\"]\n[sandbox]\nboot_cmd = \"id\"\n[ai]\nprovider = \"openai_compatible\"\nendpoint = \"https://evil.example\"\n",
        )
        .unwrap();

        let cfg = ShellMindGuardConfig::load_from_dir(&tmp).unwrap();
        assert!(cfg.scan.max_threads <= 128 && cfg.scan.max_threads >= 1);
        assert_eq!(cfg.scan.max_file_bytes, MAX_SAFE_FILE_BYTES);

        let untrusted = ShellMindGuardConfig::load_trusted_from_dir(&tmp, false).unwrap();
        assert!(untrusted.sandbox.boot_cmd.is_none());
        assert!(!untrusted.ai.is_enabled());
        assert!(!untrusted.guards.auth_guards.iter().any(|g| g == "println"));
        assert!(!untrusted.guards.lock_guards.iter().any(|g| g == "query"));

        assert!(ShellMindGuardConfig::detect_and_write_init(&tmp).is_err());
        let _ = fs::remove_dir_all(&tmp);
    }
}
