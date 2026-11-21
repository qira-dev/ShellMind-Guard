use crate::store::cache_base_dir;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRecord {
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub introduced: String,
    pub fixed: String,
    pub last_affected: String,
    pub severity: String,
    pub summary: String,
    pub source: String,
    pub updated_at: i64,
}

/// Normalizes ecosystem strings to canonical OSV names
/// (`npm`, `crates.io`, `Go`, `PyPI`, `Maven`, `Packagist`, `RubyGems`, `Pub`, `NuGet`,
/// plus versioned Linux distro ecosystems such as `Debian:12`, `Alpine:v3.19`, `Ubuntu:22.04:LTS`).
pub fn canonical_ecosystem(raw: &str) -> Option<&'static str> {
    let base = raw
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "npm" => Some("npm"),
        "cargo" | "crates.io" | "rust" => Some("crates.io"),
        "go" | "golang" => Some("Go"),
        "pypi" | "python" | "pip" => Some("PyPI"),
        "maven" | "java" | "gradle" => Some("Maven"),
        "packagist" | "composer" | "php" => Some("Packagist"),
        "rubygems" | "ruby" | "gem" => Some("RubyGems"),
        "pub" | "dart" | "flutter" => Some("Pub"),
        "nuget" | "dotnet" | "csharp" | "c#" => Some("NuGet"),
        "hex" | "elixir" | "mix" => Some("Hex"),
        "debian" => Some("Debian"),
        "alpine" => Some("Alpine"),
        "ubuntu" => Some("Ubuntu"),
        "rocky linux" | "rocky" => Some("Rocky Linux"),
        "almalinux" | "alma" => Some("AlmaLinux"),
        "red hat" | "rhel" => Some("Red Hat"),
        _ => None,
    }
}

/// Normalizes package identifiers per ecosystem (`PyPI` collapses runs of `-`/`_`/`.` into `-`, PEP 503).
pub fn normalize_package_name(ecosystem: &str, name: &str) -> String {
    let eco = canonical_ecosystem(ecosystem).unwrap_or(ecosystem);
    let lower = name.trim().to_ascii_lowercase();
    if eco == "PyPI" {
        let mut out = String::with_capacity(lower.len());
        let mut prev_dash = false;
        for ch in lower.chars() {
            if matches!(ch, '-' | '_' | '.') {
                if !prev_dash {
                    out.push('-');
                    prev_dash = true;
                }
            } else {
                out.push(ch);
                prev_dash = false;
            }
        }
        out
    } else {
        lower
    }
}

fn is_distro_ecosystem(eco: Option<&str>) -> bool {
    matches!(
        eco,
        Some("Debian" | "Alpine" | "Ubuntu" | "Rocky Linux" | "AlmaLinux" | "Red Hat")
    )
}

fn dpkg_char_order(b: u8) -> u16 {
    if b == b'~' {
        0
    } else if b.is_ascii_alphabetic() {
        b as u16
    } else {
        (b as u16) + 256
    }
}

/// Compares two dpkg/apk version fragments using Debian dpkg ordering:
/// `~` sorts before everything (including end-of-string), digit runs compare numerically,
/// and non-digit runs compare with letters before punctuation.
fn cmp_dpkg_fragment(a: &str, b: &str) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let (mut ia, mut ib) = (0usize, 0usize);
    while ia < ab.len() || ib < bb.len() {
        // Non-digit runs
        while (ia < ab.len() && !ab[ia].is_ascii_digit())
            || (ib < bb.len() && !bb[ib].is_ascii_digit())
        {
            let ca = if ia < ab.len() && !ab[ia].is_ascii_digit() {
                let o = dpkg_char_order(ab[ia]);
                ia += 1;
                Some(o)
            } else {
                None
            };
            let cb = if ib < bb.len() && !bb[ib].is_ascii_digit() {
                let o = dpkg_char_order(bb[ib]);
                ib += 1;
                Some(o)
            } else {
                None
            };
            let ord = match (ca, cb) {
                (Some(0), None) => std::cmp::Ordering::Less,
                (None, Some(0)) => std::cmp::Ordering::Greater,
                (Some(x), Some(y)) => x.cmp(&y),
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        // Digit runs (skip leading zeros, compare by length then lexically for arbitrary precision)
        let da_start = ia;
        while ia < ab.len() && ab[ia].is_ascii_digit() {
            ia += 1;
        }
        let db_start = ib;
        while ib < bb.len() && bb[ib].is_ascii_digit() {
            ib += 1;
        }
        let sa = &ab[da_start..ia];
        let sb = &bb[db_start..ib];
        let za = sa
            .iter()
            .position(|&c| c != b'0')
            .map(|p| &sa[p..])
            .unwrap_or(&[]);
        let zb = sb
            .iter()
            .position(|&c| c != b'0')
            .map(|p| &sb[p..])
            .unwrap_or(&[]);
        let ord = za.len().cmp(&zb.len()).then_with(|| za.cmp(zb));
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

fn parse_distro_version(raw: &str) -> Option<(u64, &str, &str)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('*') {
        return None;
    }
    let (epoch, rest) = if let Some((ep, r)) = trimmed.split_once(':') {
        (ep.parse::<u64>().ok()?, r)
    } else {
        (0u64, trimmed)
    };
    if rest.is_empty() {
        return None;
    }
    let (upstream, rev) = match rest.rsplit_once('-') {
        Some((u, r)) => (u, r),
        None => (rest, ""),
    };
    Some((epoch, upstream, rev))
}

fn cmp_distro_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let (ea, ua, ra) = parse_distro_version(a)?;
    let (eb, ub, rb) = parse_distro_version(b)?;
    Some(
        ea.cmp(&eb)
            .then_with(|| cmp_dpkg_fragment(ua, ub))
            .then_with(|| cmp_dpkg_fragment(ra, rb)),
    )
}

fn split_numeric_and_suffix(part: &str) -> Option<(u64, String)> {
    let trimmed = part.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return Some((n, String::new()));
    }
    let digits_len = trimmed.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }
    let num = trimmed[..digits_len].parse::<u64>().ok()?;
    let tail = trimmed[digits_len..].trim().to_ascii_lowercase();
    Some((num, tail))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemverKey {
    major: u64,
    minor: u64,
    patch: u64,
    fourth: u64,
    /// `0` = pre-release (`-alpha`, `1.0.0rc1`, Go `vX.Y.Z-0.<ts>-<hash>`), `1` = normal release, `2` = PEP 440 post-release (`post1`)
    tier: u8,
    pre: String,
}

fn parse_semver_key(raw: &str) -> Option<SemverKey> {
    let trimmed = raw
        .trim()
        .trim_start_matches(['v', 'V', '^', '~', '=', '>', '<', ' ']);
    let without_meta = trimmed
        .split(['+', ' ', ',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let (core, prerelease) = match without_meta.split_once('-') {
        Some((c, pre)) => (c.trim(), Some(pre.trim())),
        None => (without_meta, None),
    };
    if core.is_empty() || core.contains('*') {
        return None;
    }
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let (minor, minor_tail) = match parts.next() {
        Some(p) => split_numeric_and_suffix(p)?,
        None => (0, String::new()),
    };
    let (patch, patch_tail) = match parts.next() {
        Some(p) => split_numeric_and_suffix(p)?,
        None => (0, String::new()),
    };
    let (fourth, fourth_tail) = match parts.next() {
        Some(p) => split_numeric_and_suffix(p)?,
        None => (0, String::new()),
    };
    let mut pre_norm = prerelease.unwrap_or("").trim().to_ascii_lowercase();
    if !fourth_tail.is_empty() && pre_norm.is_empty() {
        pre_norm = fourth_tail;
    } else if !patch_tail.is_empty() && pre_norm.is_empty() {
        pre_norm = patch_tail;
    } else if !minor_tail.is_empty() && pre_norm.is_empty() {
        pre_norm = minor_tail;
    }
    // PEP 440 post-release (`post1`) sorts AFTER the release; Go `vX.Y.Z-0.<ts>-<hash>` is a pre-release (< vX.Y.Z).
    let is_post_tag = pre_norm.starts_with("post");
    let tier = if pre_norm.is_empty() {
        1
    } else if is_post_tag {
        2
    } else {
        0
    };
    Some(SemverKey {
        major,
        minor,
        patch,
        fourth,
        tier,
        pre: pre_norm,
    })
}

fn split_alpha_num_ident(s: &str) -> Option<(&str, u64)> {
    let alpha_len = s.bytes().take_while(|b| b.is_ascii_alphabetic()).count();
    if alpha_len == 0 || alpha_len == s.len() {
        return None;
    }
    let num = s[alpha_len..].parse::<u64>().ok()?;
    Some((&s[..alpha_len], num))
}

fn cmp_prerelease_ident(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(na), Ok(nb)) => na.cmp(&nb),
        // SemVer 2.0.0 §11.4.3: numeric identifiers always have lower precedence than non-numeric.
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => {
            if let (Some((pa, na)), Some((pb, nb))) =
                (split_alpha_num_ident(a), split_alpha_num_ident(b))
                && pa == pb
            {
                return na.cmp(&nb);
            }
            a.cmp(b)
        }
    }
}

fn cmp_semver_keys(a: &SemverKey, b: &SemverKey) -> std::cmp::Ordering {
    a.major
        .cmp(&b.major)
        .then_with(|| a.minor.cmp(&b.minor))
        .then_with(|| a.patch.cmp(&b.patch))
        .then_with(|| a.fourth.cmp(&b.fourth))
        .then_with(|| a.tier.cmp(&b.tier))
        .then_with(|| {
            if a.pre == b.pre {
                return std::cmp::Ordering::Equal;
            }
            let mut ia = a.pre.split(['.', '-']);
            let mut ib = b.pre.split(['.', '-']);
            loop {
                match (ia.next(), ib.next()) {
                    (Some(sa), Some(sb)) => {
                        let ord = cmp_prerelease_ident(sa, sb);
                        if ord != std::cmp::Ordering::Equal {
                            return ord;
                        }
                    }
                    // SemVer 2.0.0 §11.4.4: larger set of pre-release fields has higher precedence.
                    (None, Some(_)) => return std::cmp::Ordering::Less,
                    (Some(_), None) => return std::cmp::Ordering::Greater,
                    (None, None) => return std::cmp::Ordering::Equal,
                }
            }
        })
}

/// Parses `(major, minor, patch, is_release)` where pre-releases (`-alpha`, `-rc.1`) sort `<` final release.
pub fn parse_semver_with_prerelease(raw: &str) -> Option<(u64, u64, u64, bool)> {
    let k = parse_semver_key(raw)?;
    Some((k.major, k.minor, k.patch, k.tier >= 1))
}

fn is_go_pseudo_version(ver: &str) -> bool {
    let trimmed = ver.trim().trim_start_matches(['v', 'V']);
    trimmed.starts_with("0.0.0-") && trimmed.len() >= 20
}

/// Evaluates an OSV advisory range (`introduced <= installed < fixed`, or `<= last_affected`).
pub fn version_matches_range(
    ecosystem: &str,
    installed: &str,
    introduced: &str,
    fixed: &str,
    last_affected: &str,
) -> bool {
    let canon_eco = canonical_ecosystem(ecosystem);
    if is_distro_ecosystem(canon_eco) {
        if parse_distro_version(installed).is_none() {
            return false;
        }
        let intro_trimmed = introduced.trim();
        if !intro_trimmed.is_empty() && intro_trimmed != "0" {
            let Some(ord) = cmp_distro_versions(installed, intro_trimmed) else {
                return false;
            };
            if ord == std::cmp::Ordering::Less {
                return false;
            }
        }
        let fixed_trimmed = fixed.trim();
        if !fixed_trimmed.is_empty() {
            let Some(ord) = cmp_distro_versions(installed, fixed_trimmed) else {
                return false;
            };
            if ord != std::cmp::Ordering::Less {
                return false;
            }
        }
        let last_trimmed = last_affected.trim();
        if !last_trimmed.is_empty() {
            let Some(ord) = cmp_distro_versions(installed, last_trimmed) else {
                return false;
            };
            if ord == std::cmp::Ordering::Greater {
                return false;
            }
        }
        return true;
    }

    if canon_eco == Some("Go") && is_go_pseudo_version(installed) {
        let fixed_trimmed = fixed.trim();
        let last_trimmed = last_affected.trim();
        let has_pseudo_bound = (!fixed_trimmed.is_empty() && is_go_pseudo_version(fixed_trimmed))
            || (!last_trimmed.is_empty() && is_go_pseudo_version(last_trimmed));
        if !has_pseudo_bound {
            return false;
        }
    }
    let Some(inst) = parse_semver_key(installed) else {
        return false;
    };

    let intro_trimmed = introduced.trim();
    if !intro_trimmed.is_empty() && intro_trimmed != "0" {
        let Some(intro) = parse_semver_key(intro_trimmed) else {
            return false;
        };
        if cmp_semver_keys(&inst, &intro) == std::cmp::Ordering::Less {
            return false;
        }
    }

    let fixed_trimmed = fixed.trim();
    if !fixed_trimmed.is_empty() {
        let Some(fix) = parse_semver_key(fixed_trimmed) else {
            return false;
        };
        if cmp_semver_keys(&inst, &fix) != std::cmp::Ordering::Less {
            return false;
        }
    }

    let last_trimmed = last_affected.trim();
    if !last_trimmed.is_empty() {
        let Some(last) = parse_semver_key(last_trimmed) else {
            return false;
        };
        if cmp_semver_keys(&inst, &last) == std::cmp::Ordering::Greater {
            return false;
        }
    }

    true
}

pub fn default_advisories_db_path() -> PathBuf {
    cache_base_dir()
        .join("shellmind-guard")
        .join("advisories.db")
}

/// Fast stat stamp covering both `advisories.db` and its `-wal` sidecar (`size:mtime_ns|wal_size:wal_mtime_ns`).
pub fn advisories_db_stamp() -> String {
    let path = default_advisories_db_path();
    let Ok(meta) = fs::metadata(&path) else {
        return "none".to_string();
    };
    let meta_stamp = |m: &fs::Metadata| -> String {
        let mtime_ns = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}:{}", m.len(), mtime_ns)
    };
    let wal_path = path.with_extension("db-wal");
    let wal_part = fs::metadata(&wal_path)
        .ok()
        .map(|wm| meta_stamp(&wm))
        .unwrap_or_else(|| "0:0".to_string());
    format!("{}|{}", meta_stamp(&meta), wal_part)
}

pub struct AdvisoryStore {
    conn: Connection,
}

impl AdvisoryStore {
    pub fn open_default() -> Result<Self> {
        Self::open_at(&default_advisories_db_path(), false)
    }

    pub fn open_default_readonly_if_exists() -> Option<Self> {
        let path = default_advisories_db_path();
        if !path.is_file() {
            return None;
        }
        Self::open_at(&path, true).ok()
    }

    pub fn open_at(path: &Path, read_only: bool) -> Result<Self> {
        if read_only {
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .with_context(|| {
                format!("Failed to open advisory DB '{}' read-only", path.display())
            })?;
            conn.busy_timeout(Duration::from_secs(2))?;
            return Ok(Self { conn });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open advisory DB '{}'", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS advisories (
                id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                introduced TEXT NOT NULL DEFAULT '',
                fixed TEXT NOT NULL DEFAULT '',
                last_affected TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'osv',
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (id, ecosystem, package, introduced, fixed, last_affected)
            );

            CREATE INDEX IF NOT EXISTS idx_adv_eco_pkg ON advisories (ecosystem, package);
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn upsert_advisories(&mut self, records: &[AdvisoryRecord]) -> Result<usize> {
        if records.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.transaction()?;
        let mut upserted = 0usize;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO advisories
                 (id, ecosystem, package, introduced, fixed, last_affected, severity, summary, source, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id, ecosystem, package, introduced, fixed, last_affected)
                 DO UPDATE SET
                     severity = excluded.severity,
                     summary = excluded.summary,
                     source = excluded.source,
                     updated_at = excluded.updated_at",
            )?;
            for rec in records {
                let eco = canonical_ecosystem(&rec.ecosystem).unwrap_or(&rec.ecosystem);
                let pkg = normalize_package_name(eco, &rec.package);
                if rec.id.trim().is_empty() || pkg.is_empty() {
                    continue;
                }
                stmt.execute(params![
                    rec.id.trim(),
                    eco,
                    pkg,
                    rec.introduced.trim(),
                    rec.fixed.trim(),
                    rec.last_affected.trim(),
                    normalize_severity(&rec.severity),
                    rec.summary.trim(),
                    rec.source.trim(),
                    rec.updated_at
                ])?;
                upserted += 1;
            }
        }
        tx.commit()?;
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(upserted)
    }

    /// Queries all indexed advisories matching `(ecosystem, package)` pairs in one fast SQLite pass.
    pub fn query_for_packages(
        &self,
        ecosystem: &str,
        packages: &[&str],
    ) -> Result<HashMap<String, Vec<AdvisoryRecord>>> {
        let mut out: HashMap<String, Vec<AdvisoryRecord>> = HashMap::new();
        if packages.is_empty() {
            return Ok(out);
        }
        let eco = canonical_ecosystem(ecosystem).unwrap_or(ecosystem);
        let normalized: Vec<String> = packages
            .iter()
            .map(|p| normalize_package_name(eco, p))
            .collect();

        // Process in chunks of 400 to stay well below SQLite's bind-parameter limit.
        for chunk in normalized.chunks(400) {
            let placeholders: String = (0..chunk.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT id, ecosystem, package, introduced, fixed, last_affected, severity, summary, source, updated_at
                 FROM advisories
                 WHERE ecosystem = ?1 AND package IN ({})
                 ORDER BY id ASC",
                placeholders
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut args: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(chunk.len() + 1);
            args.push(&eco);
            for item in chunk {
                args.push(item);
            }
            let mut rows = stmt.query(rusqlite::params_from_iter(args))?;
            while let Some(row) = rows.next()? {
                let rec = AdvisoryRecord {
                    id: row.get(0)?,
                    ecosystem: row.get(1)?,
                    package: row.get(2)?,
                    introduced: row.get(3)?,
                    fixed: row.get(4)?,
                    last_affected: row.get(5)?,
                    severity: row.get(6)?,
                    summary: row.get(7)?,
                    source: row.get(8)?,
                    updated_at: row.get(9)?,
                };
                out.entry(rec.package.clone()).or_default().push(rec);
            }
        }
        Ok(out)
    }

    pub fn stats(&self) -> Result<(usize, Option<i64>)> {
        let (cnt, latest): (i64, Option<i64>) = self.conn.query_row(
            "SELECT COUNT(*), MAX(updated_at) FROM advisories",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((cnt.max(0) as usize, latest))
    }

    /// Parses an OSV Vulnerability JSON object, array, or `{"vulns": [...]}` document into SQLite.
    pub fn import_osv_json(&mut self, json_text: &str) -> Result<usize> {
        let val: Value =
            serde_json::from_str(json_text).context("Invalid OSV JSON advisory document")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let records = parse_osv_value_into_records(&val, now)?;
        self.upsert_advisories(&records)
    }
}

fn normalize_severity(raw: &str) -> &'static str {
    match raw.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" | "MODERATE" => "MEDIUM",
        "LOW" | "NONE" | "NEGLIGIBLE" | "INFORMATIONAL" | "INFO" | "UNSPECIFIED" | "" => "LOW",
        _ => "HIGH",
    }
}

fn extract_osv_severity(vuln: &Value) -> &'static str {
    if let Some(sev) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)
    {
        return normalize_severity(sev);
    }
    if let Some(sev_arr) = vuln.get("severity").and_then(Value::as_array) {
        for item in sev_arr {
            if let Some(score_str) = item.get("score").and_then(Value::as_str)
                && let Some(sev) = cvss_vector_to_severity(score_str)
            {
                return sev;
            }
        }
    }
    "HIGH"
}

fn cvss_vector_to_severity(vector: &str) -> Option<&'static str> {
    if let Ok(num) = vector.trim().parse::<f64>() {
        return Some(if num >= 9.0 {
            "CRITICAL"
        } else if num >= 7.0 {
            "HIGH"
        } else if num >= 4.0 {
            "MEDIUM"
        } else {
            "LOW"
        });
    }
    if vector.starts_with("CVSS:3.") {
        let mut av = 0.85_f64;
        let mut ac = 0.77_f64;
        let mut ui = 0.85_f64;
        let mut scope_changed = false;
        let mut c = 0.0_f64;
        let mut i = 0.0_f64;
        let mut a = 0.0_f64;
        let mut pr_code = "N";
        for part in vector.split('/').skip(1) {
            if let Some((k, v)) = part.split_once(':') {
                match k {
                    "AV" => {
                        av = match v {
                            "N" => 0.85,
                            "A" => 0.62,
                            "L" => 0.55,
                            "P" => 0.20,
                            _ => 0.85,
                        };
                    }
                    "AC" => ac = if v == "H" { 0.44 } else { 0.77 },
                    "PR" => pr_code = v,
                    "UI" => ui = if v == "R" { 0.62 } else { 0.85 },
                    "S" => scope_changed = v == "C",
                    "C" => {
                        c = match v {
                            "H" => 0.56,
                            "L" => 0.22,
                            _ => 0.0,
                        };
                    }
                    "I" => {
                        i = match v {
                            "H" => 0.56,
                            "L" => 0.22,
                            _ => 0.0,
                        };
                    }
                    "A" => {
                        a = match v {
                            "H" => 0.56,
                            "L" => 0.22,
                            _ => 0.0,
                        };
                    }
                    _ => {}
                }
            }
        }
        let pr = match (pr_code, scope_changed) {
            ("N", _) => 0.85,
            ("L", false) => 0.62,
            ("L", true) => 0.68,
            ("H", false) => 0.27,
            ("H", true) => 0.50,
            _ => 0.85,
        };
        let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
        if iss <= 0.0 {
            return Some("LOW");
        }
        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
        } else {
            6.42 * iss
        };
        if impact <= 0.0 {
            return Some("LOW");
        }
        let exploitability = 8.22 * av * ac * pr * ui;
        let raw = if scope_changed {
            (1.08 * (impact + exploitability)).min(10.0)
        } else {
            (impact + exploitability).min(10.0)
        };
        let score = (raw * 10.0).ceil() / 10.0;
        return Some(if score >= 9.0 {
            "CRITICAL"
        } else if score >= 7.0 {
            "HIGH"
        } else if score >= 4.0 {
            "MEDIUM"
        } else {
            "LOW"
        });
    }
    None
}

/// Parses one OSV Vulnerability JSON object or container (`array` / `{"vulns": [...]}`) into `AdvisoryRecord`s.
pub fn parse_osv_value_into_records(val: &Value, timestamp: i64) -> Result<Vec<AdvisoryRecord>> {
    let items: Vec<&Value> = if let Some(arr) = val.as_array() {
        arr.iter().collect()
    } else if let Some(arr) = val.get("vulns").and_then(Value::as_array) {
        arr.iter().collect()
    } else if val.is_object() {
        vec![val]
    } else {
        bail!("Expected OSV JSON object, array, or `vulns` list");
    };

    let mut out = Vec::new();
    for vuln in items {
        let Some(id) = vuln.get("id").and_then(Value::as_str) else {
            continue;
        };
        let summary = vuln
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| vuln.get("details").and_then(Value::as_str))
            .unwrap_or("Known security advisory")
            .lines()
            .next()
            .unwrap_or("Known security advisory")
            .trim()
            .chars()
            .take(180)
            .collect::<String>();
        let severity = extract_osv_severity(vuln).to_string();

        let Some(affected) = vuln.get("affected").and_then(Value::as_array) else {
            continue;
        };
        for aff in affected {
            let Some(pkg_obj) = aff.get("package") else {
                continue;
            };
            let raw_eco = pkg_obj
                .get("ecosystem")
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(eco) = canonical_ecosystem(raw_eco) else {
                continue;
            };
            let Some(raw_pkg) = pkg_obj.get("name").and_then(Value::as_str) else {
                continue;
            };
            let pkg = normalize_package_name(eco, raw_pkg);

            let mut extracted_any_range = false;
            if let Some(ranges) = aff.get("ranges").and_then(Value::as_array) {
                for r in ranges {
                    let rtype = r.get("type").and_then(Value::as_str).unwrap_or("");
                    if !matches!(rtype, "SEMVER" | "ECOSYSTEM") {
                        continue;
                    }
                    let Some(events) = r.get("events").and_then(Value::as_array) else {
                        continue;
                    };
                    let mut pending_intro: Option<String> = None;
                    for ev in events {
                        if let Some(intro) = ev.get("introduced").and_then(Value::as_str) {
                            if let Some(prev) = pending_intro.take() {
                                out.push(AdvisoryRecord {
                                    id: id.to_string(),
                                    ecosystem: eco.to_string(),
                                    package: pkg.clone(),
                                    introduced: prev,
                                    fixed: String::new(),
                                    last_affected: String::new(),
                                    severity: severity.clone(),
                                    summary: summary.clone(),
                                    source: "osv".into(),
                                    updated_at: timestamp,
                                });
                                extracted_any_range = true;
                            }
                            pending_intro = Some(intro.to_string());
                        } else if let Some(fixed) = ev.get("fixed").and_then(Value::as_str) {
                            let intro = pending_intro.take().unwrap_or_else(|| "0".into());
                            out.push(AdvisoryRecord {
                                id: id.to_string(),
                                ecosystem: eco.to_string(),
                                package: pkg.clone(),
                                introduced: intro,
                                fixed: fixed.to_string(),
                                last_affected: String::new(),
                                severity: severity.clone(),
                                summary: summary.clone(),
                                source: "osv".into(),
                                updated_at: timestamp,
                            });
                            extracted_any_range = true;
                        } else if let Some(last) = ev.get("last_affected").and_then(Value::as_str) {
                            let intro = pending_intro.take().unwrap_or_else(|| "0".into());
                            out.push(AdvisoryRecord {
                                id: id.to_string(),
                                ecosystem: eco.to_string(),
                                package: pkg.clone(),
                                introduced: intro,
                                fixed: String::new(),
                                last_affected: last.to_string(),
                                severity: severity.clone(),
                                summary: summary.clone(),
                                source: "osv".into(),
                                updated_at: timestamp,
                            });
                            extracted_any_range = true;
                        }
                    }
                    if let Some(unfixed_intro) = pending_intro.take() {
                        out.push(AdvisoryRecord {
                            id: id.to_string(),
                            ecosystem: eco.to_string(),
                            package: pkg.clone(),
                            introduced: unfixed_intro,
                            fixed: String::new(),
                            last_affected: String::new(),
                            severity: severity.clone(),
                            summary: summary.clone(),
                            source: "osv".into(),
                            updated_at: timestamp,
                        });
                        extracted_any_range = true;
                    }
                }
            }

            if !extracted_any_range
                && let Some(versions) = aff.get("versions").and_then(Value::as_array)
            {
                for ver in versions.iter().filter_map(Value::as_str) {
                    out.push(AdvisoryRecord {
                        id: id.to_string(),
                        ecosystem: eco.to_string(),
                        package: pkg.clone(),
                        introduced: ver.to_string(),
                        fixed: String::new(),
                        last_affected: ver.to_string(),
                        severity: severity.clone(),
                        summary: summary.clone(),
                        source: "osv".into(),
                        updated_at: timestamp,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_advisories_sqlite_import_range_matching_and_speed() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("smg_adv_test_{}.db", nanos));
        let mut store = AdvisoryStore::open_at(&db_path, false).unwrap();

        let osv_json = r#"{
          "vulns": [
            {
              "id": "GHSA-test-urllib3",
              "summary": "Redirect cookie leak in urllib3",
              "database_specific": { "severity": "HIGH" },
              "affected": [{
                "package": { "ecosystem": "PyPI", "name": "urllib3_pkg" },
                "ranges": [{
                  "type": "ECOSYSTEM",
                  "events": [
                    { "introduced": "1.26.0" },
                    { "fixed": "1.26.18" }
                  ]
                }]
              }]
            },
            {
              "id": "RUSTSEC-test-hyper",
              "summary": "Header parsing edge case",
              "database_specific": { "severity": "CRITICAL" },
              "affected": [{
                "package": { "ecosystem": "crates.io", "name": "hyper" },
                "ranges": [{
                  "type": "SEMVER",
                  "events": [
                    { "introduced": "0.14.0" },
                    { "fixed": "0.14.27" }
                  ]
                }]
              }]
            }
          ]
        }"#;

        let imported = store.import_osv_json(osv_json).unwrap();
        assert_eq!(imported, 2);

        let (cnt, latest) = store.stats().unwrap();
        assert_eq!(cnt, 2);
        assert!(latest.is_some());

        // Range checks prevent false positives below introduced and at/above fixed
        assert!(!version_matches_range(
            "PyPI", "1.25.11", "1.26.0", "1.26.18", ""
        ));
        assert!(version_matches_range(
            "PyPI", "1.26.10", "1.26.0", "1.26.18", ""
        ));
        assert!(!version_matches_range(
            "PyPI", "1.26.18", "1.26.0", "1.26.18", ""
        ));
        assert!(!version_matches_range(
            "PyPI", "2.2.1", "1.26.0", "1.26.18", ""
        ));
        assert!(!version_matches_range(
            "Go",
            "v0.0.0-20230101120000-abcdef123456",
            "0",
            "0.17.0",
            ""
        ));
        // Pre-release ordering within same (major, minor, patch)
        assert!(version_matches_range(
            "npm",
            "1.6.0-alpha.1",
            "1.6.0-alpha.1",
            "1.6.0-beta.2",
            ""
        ));
        assert!(!version_matches_range(
            "npm",
            "1.6.0-beta.2",
            "1.6.0-alpha.1",
            "1.6.0-beta.2",
            ""
        ));

        let ro_store = AdvisoryStore::open_at(&db_path, true).unwrap();
        let t0 = Instant::now();
        let hits = ro_store
            .query_for_packages("PyPI", &["urllib3.pkg", "requests"])
            .unwrap();
        let elapsed_ms = t0.elapsed().as_millis();
        assert!(
            elapsed_ms < 20,
            "indexed SQLite lookup took {}ms",
            elapsed_ms
        );
        assert_eq!(hits.get("urllib3-pkg").map(Vec::len), Some(1));

        let _ = fs::remove_file(&db_path);
        let _ = fs::remove_file(db_path.with_extension("db-wal"));
        let _ = fs::remove_file(db_path.with_extension("db-shm"));
    }

    #[test]
    fn test_wave3_semver_prerelease_go_pseudo_and_wal_checkpoint() {
        // F-69: SemVer 2.0.0 numeric vs lexical prerelease identifiers
        assert!(version_matches_range(
            "npm",
            "1.0.0-alpha.9",
            "1.0.0-alpha.2",
            "1.0.0-alpha.10",
            ""
        ));
        assert!(!version_matches_range(
            "npm",
            "1.0.0-alpha.10",
            "1.0.0-alpha.2",
            "1.0.0-alpha.10",
            ""
        ));
        assert!(version_matches_range(
            "npm",
            "1.0.0-alpha.10",
            "1.0.0-alpha.2",
            "1.0.0-beta.1",
            ""
        ));

        // F-70: Compact prerelease patch suffix `1.0.0rc1 < 1.0.0`
        assert!(version_matches_range(
            "PyPI", "1.0.0rc1", "1.0.0a1", "1.0.0", ""
        ));
        assert!(!version_matches_range(
            "PyPI", "1.0.0", "1.0.0a1", "1.0.0", ""
        ));

        // Go pre-release pseudo-version `v1.2.3-0.20230101120000-abcdef < v1.2.3` per Go module spec
        assert!(version_matches_range(
            "Go",
            "v1.2.3-0.20230101120000-abcdef123456",
            "0",
            "1.2.3",
            ""
        ));
        assert!(!version_matches_range(
            "Go",
            "v1.2.3-0.20230101120000-abcdef123456",
            "1.2.3",
            "1.2.4",
            ""
        ));
        assert!(version_matches_range(
            "Go",
            "v0.0.0-20230101120000-abcdef123456",
            "0",
            "v0.0.0-20240101000000-fedcba654321",
            ""
        ));

        // Distro ecosystems, Debian epochs/+debNuM/tilde, Alpine -rN, PEP 503 & 4-part versions
        assert_eq!(canonical_ecosystem("Debian:12"), Some("Debian"));
        assert_eq!(canonical_ecosystem("Alpine:v3.19"), Some("Alpine"));
        assert_eq!(canonical_ecosystem("Ubuntu:22.04:LTS"), Some("Ubuntu"));
        assert_eq!(normalize_package_name("PyPI", "foo__bar..baz"), "foo-bar-baz");
        assert!(version_matches_range(
            "Debian:12",
            "1:3.0.11-1~deb12u1",
            "0",
            "1:3.0.11-1~deb12u2",
            ""
        ));
        assert!(!version_matches_range(
            "Debian:12",
            "1:3.0.11-1~deb12u2",
            "0",
            "1:3.0.11-1~deb12u2",
            ""
        ));
        assert!(version_matches_range(
            "Debian",
            "1.1.1w-0+deb11u1",
            "0",
            "1.1.1w-0+deb11u2",
            ""
        ));
        assert!(!version_matches_range(
            "Alpine:v3.19",
            "1.36.1-r15",
            "0",
            "1.36.1-r2",
            ""
        ));
        assert!(version_matches_range(
            "Alpine:v3.19",
            "1.36.1-r2",
            "0",
            "1.36.1-r15",
            ""
        ));
        assert!(version_matches_range("NuGet", "1.2.3.4", "1.2.3.0", "1.2.3.5", ""));
        assert_eq!(
            cvss_vector_to_severity("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"),
            Some("MEDIUM")
        );

        // F-67: wal_checkpoint(TRUNCATE) flushes WAL bytes on upsert
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("smg_wal_test_{}.db", nanos));
        let mut store = AdvisoryStore::open_at(&db_path, false).unwrap();
        store
            .upsert_advisories(&[AdvisoryRecord {
                id: "GHSA-test-0001".into(),
                ecosystem: "npm".into(),
                package: "left-pad".into(),
                introduced: "1.0.0".into(),
                fixed: "1.3.0".into(),
                last_affected: "".into(),
                severity: "HIGH".into(),
                summary: "Test advisory".into(),
                source: "OSV".into(),
                updated_at: 1,
            }])
            .unwrap();
        let wal_len = fs::metadata(db_path.with_extension("db-wal"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(
            wal_len, 0,
            "WAL should be truncated after upsert_advisories"
        );
        let _ = fs::remove_file(&db_path);
        let _ = fs::remove_file(db_path.with_extension("db-wal"));
        let _ = fs::remove_file(db_path.with_extension("db-shm"));
    }
}
