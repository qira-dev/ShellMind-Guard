//! ShellMind Guard (`smg`) root library wiring.
//!
//! Decomposed into focused modules (Phase 2 / Q111):
//! - `cli`: Clap CLI definitions and output/palette types
//! - `baseline`: v2 finding fingerprinting, inline `smg-ignore` & baseline suppressions
//! - `pipeline`: Multi-layer scan orchestration, persistence & verification wiring
//! - `render`: Terminal, JSON, SARIF, HTML & patch output formatters
//! - `hooks`: Git pre-commit hooks, Claude Code PreToolUse gate & `smg doctor`
//! - `commands`: Top-level CLI command dispatchers
//! - `mcp`: Read-only/hardened stdio MCP server
//! - `rules_catalog`: Canonical rule docs & shell completion renderer
//! - `smg_dynamic`: Re-exported network/dynamic/OCI/OSV engines

mod baseline;
mod cli;
mod commands;
mod hooks;
mod mcp;
mod pipeline;
mod render;
mod rules_catalog;
#[cfg(test)]
mod tests;

pub use commands::run_cli;
pub use smg_dynamic::{
    cdp_engine, dast_audit, deps_sync, http_audit, idor_audit, live_verify, oci_image, oob_server,
    proxy, proxy_mitm, safe_http, sqli_audit, templates_audit, tls_audit,
};

#[allow(unused_imports)]
pub(crate) use baseline::*;
#[allow(unused_imports)]
pub(crate) use cli::*;
#[allow(unused_imports)]
pub(crate) use commands::*;
#[allow(unused_imports)]
pub(crate) use hooks::*;
#[allow(unused_imports)]
pub(crate) use pipeline::*;
#[allow(unused_imports)]
pub(crate) use render::*;
