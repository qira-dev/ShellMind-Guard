use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub writable: bool,
    pub source_file: String,
}

impl MemoryRegion {
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

#[derive(Debug, Clone)]
pub struct CompileUnitContext {
    pub pointer_width_bits: u32,
    pub defines: HashMap<String, String>,
    pub include_dirs: Vec<String>,
}

impl Default for CompileUnitContext {
    fn default() -> Self {
        Self {
            pointer_width_bits: 32,
            defines: HashMap::new(),
            include_dirs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FirmwareContext {
    pub compile_units: HashMap<String, CompileUnitContext>,
    pub memory_regions: Vec<MemoryRegion>,
    pub global_defines: HashMap<String, i64>,
    pub unresolved_ifdef_files: HashSet<String>,
    pub has_compile_commands: bool,
}

#[derive(Deserialize)]
struct RawCompileCommand {
    #[serde(default)]
    file: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    arguments: Option<Vec<String>>,
}

fn parse_hex_or_dec_u64(raw: &str) -> Option<u64> {
    let s = raw.trim().trim_end_matches([';', ',', ')', '}']).trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(k) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        k.trim().parse::<u64>().ok().map(|v| v.saturating_mul(1024))
    } else if let Some(m) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        m.trim()
            .parse::<u64>()
            .ok()
            .map(|v| v.saturating_mul(1024 * 1024))
    } else {
        s.parse::<u64>().ok()
    }
}

fn ld_mem_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*ORIGIN\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*LENGTH\s*=\s*(0x[0-9a-fA-F]+|\d+\s*[KkMm]?)"#,
        )
        .expect("valid linker region regex")
    })
}

fn svd_periph_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?is)<peripheral[^>]*>.*?<name>\s*([^<\s]+)\s*</name>.*?<baseAddress>\s*(0x[0-9a-fA-F]+|\d+)\s*</baseAddress>.*?<size>\s*(0x[0-9a-fA-F]+|\d+)\s*</size>"#,
        )
        .expect("valid svd regex")
    })
}

fn c_define_int_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?m)^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(0x[0-9a-fA-F]+|\d+)\b"#)
            .expect("valid define int regex")
    })
}

pub fn parse_linker_or_svd_regions(rel_path: &str, content: &str) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let low = rel_path.to_ascii_lowercase();
    if low.ends_with(".ld") || low.ends_with(".lds") {
        for cap in ld_mem_re().captures_iter(content) {
            let name = cap[1].trim().to_string();
            let attrs = cap
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let writable = attrs.contains('w') && !name.eq_ignore_ascii_case("FLASH");
            if let (Some(base), Some(size)) =
                (parse_hex_or_dec_u64(&cap[3]), parse_hex_or_dec_u64(&cap[4]))
            {
                regions.push(MemoryRegion {
                    name,
                    base,
                    size,
                    writable,
                    source_file: rel_path.to_string(),
                });
            }
        }
    } else if low.ends_with(".svd") {
        for cap in svd_periph_re().captures_iter(content) {
            let name = cap[1].trim().to_string();
            if let (Some(base), Some(size)) =
                (parse_hex_or_dec_u64(&cap[2]), parse_hex_or_dec_u64(&cap[3]))
            {
                regions.push(MemoryRegion {
                    name,
                    base,
                    size,
                    writable: true,
                    source_file: rel_path.to_string(),
                });
            }
        }
    }
    regions
}

pub fn ingest_firmware_context(
    project_root: &Path,
    c_sources: &[(String, &str)],
) -> FirmwareContext {
    let mut ctx = FirmwareContext::default();

    for cand in [
        project_root.join("compile_commands.json"),
        project_root.join("build").join("compile_commands.json"),
    ] {
        if let Ok(raw) = fs::read_to_string(&cand)
            && let Ok(entries) = serde_json::from_str::<Vec<RawCompileCommand>>(&raw)
        {
            ctx.has_compile_commands = true;
            for ent in entries {
                let mut cu = CompileUnitContext::default();
                let toks: Vec<String> = if let Some(args) = ent.arguments {
                    args
                } else if let Some(cmd) = ent.command {
                    cmd.split_whitespace().map(|s| s.to_string()).collect()
                } else {
                    Vec::new()
                };
                for (i, tok) in toks.iter().enumerate() {
                    if tok.contains("x86_64")
                        || tok.contains("aarch64")
                        || tok.contains("riscv64")
                        || tok == "-m64"
                    {
                        cu.pointer_width_bits = 64;
                    } else if let Some(def) = tok.strip_prefix("-D") {
                        if let Some((k, v)) = def.split_once('=') {
                            cu.defines.insert(k.to_string(), v.to_string());
                        } else if !def.is_empty() {
                            cu.defines.insert(def.to_string(), "1".to_string());
                        }
                    } else if let Some(inc) = tok.strip_prefix("-I") {
                        if !inc.is_empty() {
                            cu.include_dirs.push(inc.to_string());
                        } else if let Some(next_inc) = toks.get(i + 1) {
                            cu.include_dirs.push(next_inc.clone());
                        }
                    }
                }
                let norm = ent.file.replace('\\', "/");
                if !norm.is_empty() {
                    ctx.compile_units.insert(norm, cu);
                }
            }
            break;
        }
    }

    // Bounded top-level + 1-hop firmware subdir walk for `.ld` / `.svd`
    let mut scan_dirs = vec![project_root.to_path_buf()];
    if let Ok(rd) = fs::read_dir(project_root) {
        for ent in rd.flatten() {
            if ent.file_type().is_ok_and(|t| t.is_dir()) {
                let name = ent.file_name().to_string_lossy().to_string();
                if !matches!(name.as_str(), ".git" | "target" | "node_modules" | "dist") {
                    scan_dirs.push(ent.path());
                }
            }
        }
    }
    for dir in scan_dirs {
        if let Ok(rd) = fs::read_dir(&dir) {
            for ent in rd.flatten() {
                if !ent.file_type().is_ok_and(|t| t.is_file()) {
                    continue;
                }
                let path = ent.path();
                let low = path.to_string_lossy().to_ascii_lowercase();
                if (low.ends_with(".ld") || low.ends_with(".lds") || low.ends_with(".svd"))
                    && let Ok(meta) = ent.metadata()
                    && meta.len() <= 1024 * 1024
                    && let Ok(raw) = fs::read_to_string(&path)
                {
                    let rel = path
                        .strip_prefix(project_root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    ctx.memory_regions
                        .extend(parse_linker_or_svd_regions(&rel, &raw));
                }
            }
        }
    }

    for (rel, content) in c_sources {
        for cap in c_define_int_re().captures_iter(content) {
            if let Some(val) = parse_hex_or_dec_u64(&cap[2])
                && let Ok(iv) = i64::try_from(val)
            {
                ctx.global_defines.insert(cap[1].to_string(), iv);
            }
        }
        if !ctx.has_compile_commands
            && (content.contains("#ifdef ") || content.contains("#if defined("))
        {
            ctx.unresolved_ifdef_files.insert(rel.clone());
        }
    }

    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gnu_linker_and_cmsis_svd_regions() {
        let ld = r#"
MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}
"#;
        let ld_regs = parse_linker_or_svd_regions("linker.ld", ld);
        assert_eq!(ld_regs.len(), 2);
        assert_eq!(ld_regs[0].name, "FLASH");
        assert!(!ld_regs[0].writable);
        assert_eq!(ld_regs[0].base, 0x0800_0000);
        assert_eq!(ld_regs[0].size, 512 * 1024);
        assert!(ld_regs[1].writable);
        assert_eq!(ld_regs[1].size, 128 * 1024);

        let svd = r#"
<device>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0</offset><size>0x400</size></addressBlock>
    </peripheral>
  </peripherals>
</device>
"#;
        let svd_regs = parse_linker_or_svd_regions("stm32.svd", svd);
        assert_eq!(svd_regs.len(), 1);
        assert_eq!(svd_regs[0].name, "GPIOA");
        assert!(svd_regs[0].contains(0x4002_0010));
        assert!(!svd_regs[0].contains(0x4002_0500));
    }
}
