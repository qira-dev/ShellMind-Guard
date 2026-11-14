use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VeriForgeConfig {
    #[serde(default)]
    pub guards: GuardConfig,
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default = "default_auth_guards")]
    pub auth_guards: Vec<String>,
    #[serde(default = "default_lock_guards")]
    pub lock_guards: Vec<String>,
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
}

fn default_auth_guards() -> Vec<String> {
    vec![
        "requireAuth".into(),
        "authenticate".into(),
        "verifyJwt".into(),
        "withAuth".into(),
        "requireAdmin".into(),
        "ensureAuthenticated".into(),
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
    ]
}

fn default_max_threads() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cpus.saturating_sub(1).clamp(2, 6)
}

fn default_max_file_bytes() -> u64 {
    2 * 1024 * 1024 // 2 MiB max per source file
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            auth_guards: default_auth_guards(),
            lock_guards: default_lock_guards(),
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
                ".veriforge".into(),
            ],
            max_threads: default_max_threads(),
            max_file_bytes: default_max_file_bytes(),
        }
    }
}

impl VeriForgeConfig {
    pub fn load_from_dir(root: &Path) -> Result<Self> {
        let cfg_path = root.join(".veriforge.toml");
        if !cfg_path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&cfg_path)
            .with_context(|| format!("Failed to read {}", cfg_path.display()))?;
        let parsed: Self = toml::from_str(&raw)
            .with_context(|| format!("Invalid TOML in {}", cfg_path.display()))?;
        Ok(parsed)
    }
}
