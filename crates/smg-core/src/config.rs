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
        let authority = rest.split('/').next().unwrap_or("");
        let (host, port_str) = if let Some(after_bracket) = authority.strip_prefix("[::1]") {
            ("::1", after_bracket.strip_prefix(':').unwrap_or(""))
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h, p)
        } else {
            (authority, "")
        };
        if !matches!(
            host.to_ascii_lowercase().as_str(),
            "127.0.0.1" | "localhost" | "::1"
        ) {
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
            Ok(Some(p))
        }
    }
}

fn default_auth_guards() -> Vec<String> {
    vec![
        "requireAuth".into(),
        "require_auth".into(),
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
            ],
            max_threads: default_max_threads(),
            max_file_bytes: default_max_file_bytes(),
        }
    }
}

impl ShellMindGuardConfig {
    pub fn load_from_dir(root: &Path) -> Result<Self> {
        let cfg_path = root.join(".shellmind-guard.toml");
        if !cfg_path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&cfg_path)
            .with_context(|| format!("Failed to read {}", cfg_path.display()))?;
        let parsed: Self = toml::from_str(&raw)
            .with_context(|| format!("Invalid TOML in {}", cfg_path.display()))?;
        Ok(parsed)
    }

    pub fn detect_and_write_init(root: &Path) -> Result<(Vec<String>, std::path::PathBuf)> {
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
        let out_path = root.join(".shellmind-guard.toml");
        fs::write(&out_path, toml_str)?;
        Ok((detected, out_path))
    }
}
