use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
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

impl FirmwareContext {
    pub fn lookup_compile_unit(&self, rel_path: &str) -> Option<&CompileUnitContext> {
        let norm = rel_path.replace('\\', "/");
        let trimmed = norm.trim_start_matches("./");
        if let Some(cu) = self.compile_units.get(trimmed) {
            return Some(cu);
        }
        if let Some(cu) = self.compile_units.get(&norm) {
            return Some(cu);
        }
        let suffix = format!("/{trimmed}");
        for (k, cu) in &self.compile_units {
            if k == trimmed
                || k.ends_with(&suffix)
                || trimmed.ends_with(&format!("/{}", k.trim_start_matches("./")))
            {
                return Some(cu);
            }
        }
        None
    }

    pub fn pointer_width_for_file(&self, rel_path: &str) -> u32 {
        if let Some(cu) = self.lookup_compile_unit(rel_path) {
            return cu.pointer_width_bits;
        }
        // If all compile units share the same pointer width, inherit it; otherwise default to 32-bit MCU.
        let mut widths = self.compile_units.values().map(|c| c.pointer_width_bits);
        if let Some(first) = widths.next()
            && widths.all(|w| w == first)
        {
            return first;
        }
        32
    }

    pub fn has_svd_regions(&self) -> bool {
        self.memory_regions
            .iter()
            .any(|r| r.source_file.to_ascii_lowercase().ends_with(".svd"))
    }
}

#[derive(Deserialize)]
struct RawCompileCommand {
    #[serde(default)]
    directory: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    arguments: Option<Vec<String>>,
}

pub fn parse_hex_or_dec_u64(raw: &str) -> Option<u64> {
    let s = raw
        .trim()
        .trim_matches(['(', ')', ';', ',', '}'])
        .trim()
        .trim_end_matches(['U', 'u', 'L', 'l']);
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex.trim(), 16).ok()
    } else if let Some(g) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        g.trim()
            .parse::<u64>()
            .ok()
            .map(|v| v.saturating_mul(1024 * 1024 * 1024))
    } else if let Some(m) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        m.trim()
            .parse::<u64>()
            .ok()
            .map(|v| v.saturating_mul(1024 * 1024))
    } else if let Some(k) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        k.trim().parse::<u64>().ok().map(|v| v.saturating_mul(1024))
    } else {
        s.parse::<u64>().ok()
    }
}

/// Evaluates GNU linker constant expressions such as `128K - 4K` or `0x08000000 + 64K`.
pub fn eval_linker_expr(raw: &str) -> Option<u64> {
    let mut s = raw.trim().trim_end_matches([';', ',', '}']).trim();
    while s.starts_with('(') && s.ends_with(')') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        if inner.chars().fold(0i32, |acc, c| match c {
            '(' => acc + 1,
            ')' => acc - 1,
            _ => acc,
        }) == 0
        {
            s = inner.trim();
        } else {
            break;
        }
    }
    if let Some(v) = parse_hex_or_dec_u64(s) {
        return Some(v);
    }
    let mut acc: Option<u64> = None;
    let mut op = '+';
    let mut cur = String::new();
    for ch in s.chars() {
        if ch == '+' || ch == '-' {
            let term = parse_hex_or_dec_u64(&cur)?;
            acc = Some(match (acc, op) {
                (None, _) => term,
                (Some(prev), '+') => prev.saturating_add(term),
                (Some(prev), '-') => prev.saturating_sub(term),
                (Some(prev), _) => prev,
            });
            op = ch;
            cur.clear();
        } else if ch != '(' && ch != ')' {
            cur.push(ch);
        }
    }
    let last_term = parse_hex_or_dec_u64(&cur)?;
    Some(match (acc, op) {
        (None, _) => last_term,
        (Some(prev), '+') => prev.saturating_add(last_term),
        (Some(prev), '-') => prev.saturating_sub(last_term),
        (Some(prev), _) => prev,
    })
}

fn parse_ld_writable(name: &str, attrs_opt: Option<&str>) -> bool {
    if name.eq_ignore_ascii_case("FLASH") || name.eq_ignore_ascii_case("ROM") {
        return false;
    }
    let Some(attrs) = attrs_opt else {
        return true;
    };
    let mut negated = false;
    let mut pos_w = false;
    let mut neg_w = false;
    for ch in attrs.chars() {
        if ch == '!' {
            negated = true;
        } else if ch.eq_ignore_ascii_case(&'w') {
            if negated {
                neg_w = true;
            } else {
                pos_w = true;
            }
        }
    }
    pos_w && !neg_w
}

fn ld_mem_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*(?:ORIGIN|org|o)\s*=\s*([^,\r\n]+?)\s*,\s*(?:LENGTH|len|l)\s*=\s*([^\r\n;}]+)"#,
        )
        .expect("valid linker region regex")
    })
}

fn svd_periph_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<peripheral\b([^>]*)>(.*?)</peripheral>"#)
            .expect("valid svd peripheral block regex")
    })
}

fn svd_derived_from_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bderivedFrom\s*=\s*["']([^"']+)["']"#).expect("valid derivedFrom regex")
    })
}

fn svd_registers_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<registers\b[^>]*>.*?</registers>"#).expect("valid registers block")
    })
}

fn svd_addr_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<addressBlock\b[^>]*>(.*?)</addressBlock>"#)
            .expect("valid addressBlock regex")
    })
}

fn svd_register_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<register\b[^>]*>(.*?)</register>"#).expect("valid register regex")
    })
}

fn extract_xml_tag(text: &str, tag: &str) -> Option<String> {
    let low = text.to_ascii_lowercase();
    let tag_low = tag.to_ascii_lowercase();
    let open_pat = format!("<{tag_low}>");
    let close_pat = format!("</{tag_low}>");
    let start = low.find(&open_pat)? + open_pat.len();
    let end_rel = low[start..].find(&close_pat)?;
    let val = text[start..start + end_rel].trim();
    (!val.is_empty() && !val.contains('<')).then(|| val.to_string())
}

fn c_define_int_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(0x[0-9a-fA-F]+|\d+)\b"#)
            .expect("valid define int regex")
    })
}

pub fn parse_linker_or_svd_regions(rel_path: &str, content: &str) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let low = rel_path.to_ascii_lowercase();
    if low.ends_with(".ld") || low.ends_with(".lds") {
        for cap in ld_mem_re().captures_iter(content) {
            let name = cap[1].trim().to_string();
            let writable = parse_ld_writable(&name, cap.get(2).map(|m| m.as_str()));
            if let (Some(base), Some(size)) = (eval_linker_expr(&cap[3]), eval_linker_expr(&cap[4]))
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
        #[derive(Clone)]
        struct RawPeriph {
            name: String,
            base: u64,
            size: Option<u64>,
            writable: Option<bool>,
            derived_from: Option<String>,
        }
        let mut parsed: Vec<RawPeriph> = Vec::new();

        for cap in svd_periph_block_re().captures_iter(content) {
            let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let body = &cap[2];
            let derived_from = svd_derived_from_re()
                .captures(attrs)
                .map(|c| c[1].trim().to_string());
            let header_only = svd_registers_block_re().replace_all(body, "");

            let Some(name) = extract_xml_tag(&header_only, "name") else {
                continue;
            };
            let Some(base_str) = extract_xml_tag(&header_only, "baseAddress") else {
                continue;
            };
            let Some(base) = parse_hex_or_dec_u64(&base_str) else {
                continue;
            };

            let mut max_span: Option<u64> = None;
            let mut block_access: Option<String> = None;
            for ab in svd_addr_block_re().captures_iter(&header_only) {
                let ab_body = &ab[1];
                let off = extract_xml_tag(ab_body, "offset")
                    .and_then(|s| parse_hex_or_dec_u64(&s))
                    .unwrap_or(0);
                if let Some(sz) =
                    extract_xml_tag(ab_body, "size").and_then(|s| parse_hex_or_dec_u64(&s))
                {
                    let end = off.saturating_add(sz);
                    max_span = Some(max_span.map_or(end, |prev| prev.max(end)));
                }
                if block_access.is_none() {
                    block_access = extract_xml_tag(ab_body, "access");
                }
            }

            if max_span.is_none() {
                // Check `<registers>` offsets if `<addressBlock>` was omitted
                let mut reg_max: Option<u64> = None;
                for reg_cap in svd_register_re().captures_iter(body) {
                    let rbody = &reg_cap[1];
                    if let Some(roff) = extract_xml_tag(rbody, "addressOffset")
                        .and_then(|s| parse_hex_or_dec_u64(&s))
                    {
                        let rbits = extract_xml_tag(rbody, "size")
                            .and_then(|s| parse_hex_or_dec_u64(&s))
                            .unwrap_or(32);
                        let rbytes = (rbits / 8).max(4);
                        let end = roff.saturating_add(rbytes);
                        reg_max = Some(reg_max.map_or(end, |prev| prev.max(end)));
                    }
                }
                if let Some(rm) = reg_max {
                    max_span = Some(rm);
                } else if let Some(top_sz) =
                    extract_xml_tag(&header_only, "size").and_then(|s| parse_hex_or_dec_u64(&s))
                {
                    // In SVD, peripheral `<size>` of 8/16/32/64 is register bit-width; larger values specify window size.
                    max_span = Some(if matches!(top_sz, 8 | 16 | 32 | 64) {
                        0x400
                    } else {
                        top_sz
                    });
                }
            }

            let access_str = extract_xml_tag(&header_only, "access").or(block_access);
            let writable = access_str.map(|a| !a.eq_ignore_ascii_case("read-only"));

            parsed.push(RawPeriph {
                name,
                base,
                size: max_span,
                writable,
                derived_from,
            });
        }

        let by_name: HashMap<String, RawPeriph> =
            parsed.iter().map(|p| (p.name.clone(), p.clone())).collect();

        for p in parsed {
            let mut size = p.size;
            let mut writable = p.writable;
            if let Some(ref parent_name) = p.derived_from
                && let Some(parent) = by_name.get(parent_name)
            {
                if size.is_none() {
                    size = parent.size;
                }
                if writable.is_none() {
                    writable = parent.writable;
                }
            }
            if let Some(sz) = size.or(if p.derived_from.is_some() {
                Some(0x400)
            } else {
                None
            }) {
                regions.push(MemoryRegion {
                    name: p.name,
                    base: p.base,
                    size: sz,
                    writable: writable.unwrap_or(true),
                    source_file: rel_path.to_string(),
                });
            }
        }
    }
    regions
}

fn split_command_tokens(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Some(q) => {
                if ch == '\\'
                    && let Some(&nxt) = chars.peek()
                {
                    cur.push(nxt);
                    chars.next();
                } else if ch == q {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn collect_hw_spec_files(
    project_root: &Path,
    max_depth: usize,
    max_files: usize,
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(project_root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if found.len() >= max_files {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for ent in entries {
            if found.len() >= max_files {
                break;
            }
            let Ok(ft) = ent.file_type() else {
                continue;
            };
            let path = ent.path();
            if ft.is_dir() {
                if depth < max_depth {
                    let name = ent.file_name().to_string_lossy().to_string();
                    if !matches!(
                        name.as_str(),
                        ".git" | "target" | "node_modules" | "dist" | "vendor" | ".next"
                    ) {
                        stack.push((path, depth + 1));
                    }
                }
            } else if ft.is_file() {
                let low = path.to_string_lossy().to_ascii_lowercase();
                if low.ends_with(".ld") || low.ends_with(".lds") || low.ends_with(".svd") {
                    found.push(path);
                }
            }
        }
    }
    found
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
        if let Ok(meta) = fs::metadata(&cand)
            && meta.is_file()
            && meta.len() <= 16 * 1024 * 1024
            && let Ok(raw) = fs::read_to_string(&cand)
            && let Ok(entries) = serde_json::from_str::<Vec<RawCompileCommand>>(&raw)
        {
            ctx.has_compile_commands = true;
            for ent in entries {
                let mut cu = CompileUnitContext::default();
                let toks: Vec<String> = if let Some(args) = ent.arguments {
                    args
                } else if let Some(cmd) = ent.command {
                    split_command_tokens(&cmd)
                } else {
                    Vec::new()
                };
                let mut i = 0;
                while i < toks.len() {
                    let tok = &toks[i];
                    if tok.contains("x86_64")
                        || tok.contains("aarch64")
                        || tok.contains("riscv64")
                        || tok == "-m64"
                    {
                        cu.pointer_width_bits = 64;
                    } else if tok == "-m32"
                        || tok.contains("arm-none-eabi")
                        || tok.contains("riscv32")
                    {
                        cu.pointer_width_bits = 32;
                    } else if tok == "-D" {
                        if let Some(def) = toks.get(i + 1) {
                            if let Some((k, v)) = def.split_once('=') {
                                cu.defines.insert(k.to_string(), v.to_string());
                                if let Some(val) = parse_hex_or_dec_u64(v)
                                    && let Ok(iv) = i64::try_from(val)
                                {
                                    ctx.global_defines.insert(k.to_string(), iv);
                                }
                            } else if !def.is_empty() {
                                cu.defines.insert(def.to_string(), "1".to_string());
                            }
                            i += 1;
                        }
                    } else if let Some(def) = tok.strip_prefix("-D") {
                        if let Some((k, v)) = def.split_once('=') {
                            cu.defines.insert(k.to_string(), v.to_string());
                            if let Some(val) = parse_hex_or_dec_u64(v)
                                && let Ok(iv) = i64::try_from(val)
                            {
                                ctx.global_defines.insert(k.to_string(), iv);
                            }
                        } else if !def.is_empty() {
                            cu.defines.insert(def.to_string(), "1".to_string());
                        }
                    } else if tok == "-I" {
                        if let Some(next_inc) = toks.get(i + 1) {
                            cu.include_dirs.push(next_inc.clone());
                            i += 1;
                        }
                    } else if let Some(inc) = tok.strip_prefix("-I")
                        && !inc.is_empty()
                    {
                        cu.include_dirs.push(inc.to_string());
                    }
                    i += 1;
                }
                let norm = ent.file.replace('\\', "/");
                if !norm.is_empty() {
                    if !ent.directory.is_empty() {
                        let full = Path::new(&ent.directory).join(&ent.file);
                        if let Ok(rel) = full.strip_prefix(project_root) {
                            let rel_norm = rel.to_string_lossy().replace('\\', "/");
                            ctx.compile_units.insert(rel_norm, cu.clone());
                        }
                    }
                    if let Ok(rel) = Path::new(&norm).strip_prefix(project_root) {
                        let rel_norm = rel.to_string_lossy().replace('\\', "/");
                        ctx.compile_units.insert(rel_norm, cu.clone());
                    }
                    ctx.compile_units.insert(norm, cu);
                }
            }
            break;
        }
    }

    for path in collect_hw_spec_files(project_root, 6, 512) {
        if let Ok(meta) = fs::metadata(&path)
            && meta.len() <= 4 * 1024 * 1024
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

    for (rel, content) in c_sources {
        let low = rel.to_ascii_lowercase();
        if low.ends_with(".ld") || low.ends_with(".lds") || low.ends_with(".svd") {
            if !ctx.memory_regions.iter().any(|r| &r.source_file == rel) {
                ctx.memory_regions
                    .extend(parse_linker_or_svd_regions(rel, content));
            }
            continue;
        }
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
    fn parses_gnu_linker_and_cmsis_svd_regions_with_inheritance_and_expressions() {
        let ld = r#"
MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
  ROM (rw!w) : ORIGIN = 0x1FFF0000, LENGTH = 32K
  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K - 4K
}
"#;
        let ld_regs = parse_linker_or_svd_regions("linker.ld", ld);
        assert_eq!(ld_regs.len(), 3);
        assert_eq!(ld_regs[0].name, "FLASH");
        assert!(!ld_regs[0].writable);
        assert_eq!(ld_regs[0].base, 0x0800_0000);
        assert_eq!(ld_regs[0].size, 512 * 1024);

        // Negated `!w` attribute makes ROM non-writable
        assert_eq!(ld_regs[1].name, "ROM");
        assert!(!ld_regs[1].writable);

        // Arithmetic `128K - 4K` = 124 * 1024
        assert_eq!(ld_regs[2].name, "SRAM");
        assert!(ld_regs[2].writable);
        assert_eq!(ld_regs[2].size, 124 * 1024);

        // Counterexample HW-03: SVD with peripheral <size>32</size> (register bit-width),
        // read-only OTP peripheral, peripheral without <size>, and derivedFrom peripheral.
        let svd = r#"
<device>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40020000</baseAddress>
      <size>32</size>
      <addressBlock><offset>0</offset><size>0x400</size></addressBlock>
      <registers>
        <register><name>MODER</name><addressOffset>0x00</addressOffset><size>32</size></register>
      </registers>
    </peripheral>
    <peripheral derivedFrom="GPIOA">
      <name>GPIOB</name>
      <baseAddress>0x40020400</baseAddress>
    </peripheral>
    <peripheral>
      <name>OTP_ROM</name>
      <baseAddress>0x1FFF7800</baseAddress>
      <access>read-only</access>
      <addressBlock><offset>0</offset><size>0x200</size></addressBlock>
    </peripheral>
  </peripherals>
</device>
"#;
        let svd_regs = parse_linker_or_svd_regions("stm32.svd", svd);
        assert_eq!(svd_regs.len(), 3);
        assert_eq!(svd_regs[0].name, "GPIOA");
        assert_eq!(svd_regs[0].size, 0x400);
        assert!(svd_regs[0].writable);
        assert!(svd_regs[0].contains(0x4002_0010));
        assert!(!svd_regs[0].contains(0x4002_0500));

        assert_eq!(svd_regs[1].name, "GPIOB");
        assert_eq!(svd_regs[1].base, 0x4002_0400);
        assert_eq!(svd_regs[1].size, 0x400);
        assert!(svd_regs[1].writable);

        assert_eq!(svd_regs[2].name, "OTP_ROM");
        assert!(!svd_regs[2].writable);
    }
}
