//! Pure-Rust OCI / Docker container image & rootfs vulnerability scanner (Trivy parity)
//! plus `.trivyignore` policy parser (with `exp:YYYY-MM-DD` expiry support).
//!
//! Zero external tar/compression crates required:
//! - Parses POSIX USTAR / PAX tar archives directly (512-byte header blocks)
//! - Transparently decompresses gzipped OCI blobs (`1f 8b`) via system `gzip -dc`
//! - Extracts OS identity from `/etc/os-release` (`Debian`, `Ubuntu`, `Alpine`, `Rocky Linux`, `AlmaLinux`, `Red Hat`)
//! - Parses Debian/Ubuntu `/var/lib/dpkg/status` & Alpine `/lib/apk/db/installed`
//! - Extracts embedded application lockfiles (`package-lock.json`, `Cargo.lock`, `requirements.txt`, `go.mod`, `go.sum`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`)
//! - Evaluates all discovered OS & app packages against ShellMind-Guard's local SQLite `AdvisoryStore`
//!   (and optionally syncs fresh CVEs via `--online-osv`).

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use smg_core::advisories::{AdvisoryStore, version_matches_range};
use smg_graph::deps::{ResolvedDependency, extract_resolved_dependencies};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed `.trivyignore` policy file.
#[derive(Debug, Clone, Default)]
pub struct TrivyIgnore {
    pub ignored_ids: HashSet<String>,
}

impl TrivyIgnore {
    /// Auto-loads `.trivyignore` from `repo_root` (if present), honoring `exp:YYYY-MM-DD`.
    pub fn load(repo_root: &Path) -> Option<Self> {
        let text = fs::read_to_string(repo_root.join(".trivyignore")).ok()?;
        Some(Self::parse(&text))
    }

    pub fn parse(content: &str) -> Self {
        let today = current_utc_yyyymmdd();
        let mut ignored_ids = HashSet::new();
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(id) = parts.next() else { continue };
            let mut expired = false;
            for token in parts {
                if let Some(exp_str) = token.strip_prefix("exp:")
                    && let Some(exp_num) = parse_yyyymmdd(exp_str)
                    && exp_num < today
                {
                    expired = true;
                }
            }
            if !expired {
                ignored_ids.insert(id.to_ascii_uppercase());
            }
        }
        Self { ignored_ids }
    }

    pub fn is_ignored(&self, text_or_id: &str) -> bool {
        if self.ignored_ids.is_empty() {
            return false;
        }
        let up = text_or_id.to_ascii_uppercase();
        let bytes = up.as_bytes();
        self.ignored_ids.iter().any(|id| {
            let mut search_from = 0usize;
            while let Some(rel) = up[search_from..].find(id.as_str()) {
                let start = search_from + rel;
                let end = start + id.len();
                let left_ok = start == 0
                    || !matches!(bytes[start - 1], b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_');
                let right_ok = end == bytes.len()
                    || !matches!(bytes[end], b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_');
                if left_ok && right_ok {
                    return true;
                }
                search_from = start + 1;
            }
            false
        })
    }
}

fn parse_yyyymmdd(s: &str) -> Option<u32> {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 8 {
        digits.parse::<u32>().ok()
    } else {
        None
    }
}

fn current_utc_yyyymmdd() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as u32) * 10_000 + (m as u32) * 100 + (d as u32)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVulnFinding {
    pub advisory_id: String,
    pub severity: String,
    pub ecosystem: String,
    pub package: String,
    pub installed_version: String,
    pub affected_range: String,
    pub fixed_version: Option<String>,
    pub source_layer: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageScanReport {
    pub target: String,
    pub os_family: String,
    pub os_version: String,
    pub packages_scanned: usize,
    pub findings: Vec<ImageVulnFinding>,
}

/// Parses `/etc/os-release` into `(OSV Ecosystem, Version)` e.g. `("Debian", "12")`.
pub fn parse_os_release(content: &str) -> (String, String) {
    let mut id = String::new();
    let mut ver = String::new();
    for line in content.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("ID=") {
            id = v.trim_matches('"').trim_matches('\'').to_ascii_lowercase();
        } else if let Some(v) = t.strip_prefix("VERSION_ID=") {
            ver = v.trim_matches('"').trim_matches('\'').to_string();
        }
    }
    let eco = match id.as_str() {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "alpine" => "Alpine",
        "rocky" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        "rhel" | "redhat" | "centos" | "fedora" => "Red Hat",
        "" => "Linux",
        other => other,
    };
    (eco.to_string(), ver)
}

/// Parses Debian/Ubuntu `/var/lib/dpkg/status` into `ResolvedDependency` entries.
pub fn parse_dpkg_status(content: &str, ecosystem: &str) -> Vec<ResolvedDependency> {
    let mut out = Vec::new();
    let mut pkg = String::new();
    let mut ver = String::new();
    let mut installed = true;

    let flush = |pkg: &mut String,
                 ver: &mut String,
                 installed: &mut bool,
                 out: &mut Vec<ResolvedDependency>| {
        if *installed && !pkg.is_empty() && !ver.is_empty() {
            out.push(ResolvedDependency {
                ecosystem: ecosystem.to_string(),
                name: pkg.clone(),
                version: ver.clone(),
                line: 1,
            });
        }
        pkg.clear();
        ver.clear();
        *installed = true;
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            flush(&mut pkg, &mut ver, &mut installed, &mut out);
            continue;
        }
        if let Some(v) = line.strip_prefix("Package:") {
            pkg = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Version:") {
            ver = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Status:") {
            installed = v.contains("installed");
        }
    }
    flush(&mut pkg, &mut ver, &mut installed, &mut out);
    out
}

/// Parses Alpine Linux `/lib/apk/db/installed` into `ResolvedDependency` entries.
pub fn parse_apk_installed(content: &str) -> Vec<ResolvedDependency> {
    let mut out = Vec::new();
    let mut pkg = String::new();
    let mut ver = String::new();

    let flush = |pkg: &mut String, ver: &mut String, out: &mut Vec<ResolvedDependency>| {
        if !pkg.is_empty() && !ver.is_empty() {
            out.push(ResolvedDependency {
                ecosystem: "Alpine".to_string(),
                name: pkg.clone(),
                version: ver.clone(),
                line: 1,
            });
        }
        pkg.clear();
        ver.clear();
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            flush(&mut pkg, &mut ver, &mut out);
            continue;
        }
        if let Some(v) = line.strip_prefix("P:") {
            pkg = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("V:") {
            ver = v.trim().to_string();
        }
    }
    flush(&mut pkg, &mut ver, &mut out);
    out
}

/// Parses a POSIX PAX extended header payload (`<len> key=value\n`) for the `path` record.
fn parse_pax_path(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos < data.len() {
        let sp = data[pos..].iter().position(|&b| b == b' ')?;
        let len_str = std::str::from_utf8(&data[pos..pos + sp]).ok()?;
        let rec_len: usize = len_str.parse().ok()?;
        if rec_len <= sp + 1 || pos.saturating_add(rec_len) > data.len() {
            break;
        }
        let kv = &data[pos + sp + 1..pos + rec_len];
        let kv_str = std::str::from_utf8(kv).ok()?.trim_end_matches('\n');
        if let Some(val) = kv_str.strip_prefix("path=") {
            return Some(val.to_string());
        }
        pos += rec_len;
    }
    None
}

/// Minimal pure-Rust POSIX USTAR/PAX/GNU-LongLink tar reader (zero external crates).
/// Calls `visitor(entry_path, entry_bytes)` for every regular file entry.
pub fn walk_tar_bytes<F>(raw: &[u8], mut visitor: F)
where
    F: FnMut(&str, &[u8]),
{
    let mut offset = 0usize;
    let mut pending_long_name: Option<String> = None;
    while offset + 512 <= raw.len() {
        let header = &raw[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name_end = header[0..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&header[0..name_end]).to_string();
        let prefix_end = header[345..500].iter().position(|&b| b == 0).unwrap_or(155);
        let prefix = String::from_utf8_lossy(&header[345..345 + prefix_end]).to_string();
        let ustar_name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let typeflag = header[156];
        let size_str = String::from_utf8_lossy(&header[124..136]);
        let size_trimmed = size_str.trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace());
        let size = usize::from_str_radix(size_trimmed, 8).unwrap_or(0);

        let data_start = offset + 512;
        if size > raw.len().saturating_sub(data_start) {
            break;
        }
        let data_end = data_start + size;
        let payload = &raw[data_start..data_end];
        if typeflag == b'x' {
            if let Some(p) = parse_pax_path(payload) {
                pending_long_name = Some(p);
            }
        } else if typeflag == b'L' {
            let end = payload
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(payload.len());
            let p = String::from_utf8_lossy(&payload[..end]).trim().to_string();
            if !p.is_empty() {
                pending_long_name = Some(p);
            }
        } else {
            let full_name = pending_long_name.take().unwrap_or(ustar_name);
            if (typeflag == b'0' || typeflag == 0) && !full_name.is_empty() {
                visitor(&full_name, payload);
            }
        }
        let padded = size.saturating_add(511) & !511;
        offset = data_start.saturating_add(padded);
    }
}

const MAX_GUNZIP_BYTES: usize = 256 * 1024 * 1024;
const MAX_TAR_NEST_DEPTH: usize = 6;

fn maybe_gunzip(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() >= 2
        && bytes[0] == 0x1f
        && bytes[1] == 0x8b
        && let Ok(mut child) = Command::new("gzip")
            .arg("-dc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let input = bytes.to_vec();
            let _ = std::thread::spawn(move || {
                let _ = stdin.write_all(&input);
            });
        }
        let mut out = Vec::new();
        let mut exceeded = false;
        if let Some(stdout) = child.stdout.take() {
            use std::io::Read;
            let _ = stdout
                .take((MAX_GUNZIP_BYTES + 1) as u64)
                .read_to_end(&mut out);
            if out.len() > MAX_GUNZIP_BYTES {
                exceeded = true;
            }
        }
        if exceeded {
            let _ = child.kill();
            let _ = child.wait();
            return Vec::new();
        }
        if let Ok(status) = child.wait()
            && status.success()
        {
            return out;
        }
    }
    bytes.to_vec()
}

fn is_supported_app_lockfile(path: &str) -> bool {
    let fname = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    matches!(
        fname,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "go.mod"
            | "go.sum"
            | "requirements.txt"
            | "poetry.lock"
            | "Pipfile.lock"
            | "composer.lock"
            | "Gemfile.lock"
            | "pubspec.lock"
            | "pom.xml"
            | "gradle.lockfile"
            | "mix.lock"
    )
}

fn inspect_layer_tar(
    layer_name: &str,
    tar_bytes: &[u8],
    os_family: &mut String,
    os_version: &mut String,
    collected: &mut Vec<(ResolvedDependency, String)>,
) {
    inspect_layer_tar_depth(layer_name, tar_bytes, os_family, os_version, collected, 0);
}

fn looks_like_tar_or_gzip(data: &[u8]) -> bool {
    (data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b)
        || (data.len() >= 262 && &data[257..262] == b"ustar")
}

fn inspect_layer_tar_depth(
    layer_name: &str,
    tar_bytes: &[u8],
    os_family: &mut String,
    os_version: &mut String,
    collected: &mut Vec<(ResolvedDependency, String)>,
    depth: usize,
) {
    if depth >= MAX_TAR_NEST_DEPTH {
        return;
    }
    let decompressed = maybe_gunzip(tar_bytes);
    let mut dpkg_blobs: Vec<String> = Vec::new();
    let mut apk_blobs: Vec<String> = Vec::new();

    walk_tar_bytes(&decompressed, |entry_path, data| {
        let norm = entry_path.trim_start_matches("./").trim_start_matches('/');
        if norm == "etc/os-release" || norm == "usr/lib/os-release" {
            let text = String::from_utf8_lossy(data);
            let (fam, ver) = parse_os_release(&text);
            if !fam.is_empty() {
                *os_family = fam;
                *os_version = ver;
            }
        } else if norm == "var/lib/dpkg/status" {
            dpkg_blobs.push(String::from_utf8_lossy(data).into_owned());
        } else if norm == "lib/apk/db/installed" {
            apk_blobs.push(String::from_utf8_lossy(data).into_owned());
        } else if is_supported_app_lockfile(norm) && data.len() <= 8 * 1024 * 1024 {
            let text = String::from_utf8_lossy(data);
            for dep in extract_resolved_dependencies(norm, &text) {
                collected.push((dep, format!("{layer_name}:{norm}")));
            }
        } else if data.len() >= 512
            && (norm.ends_with("layer.tar")
                || norm.ends_with(".tar")
                || norm.ends_with(".tar.gz")
                || (norm.starts_with("blobs/sha256/") && looks_like_tar_or_gzip(data)))
        {
            inspect_layer_tar_depth(norm, data, os_family, os_version, collected, depth + 1);
        }
    });

    let deb_eco = if os_family.eq_ignore_ascii_case("Ubuntu") {
        "Ubuntu"
    } else {
        "Debian"
    };
    for blob in dpkg_blobs {
        for dep in parse_dpkg_status(&blob, deb_eco) {
            collected.push((dep, format!("{layer_name}:/var/lib/dpkg/status")));
        }
    }
    for blob in apk_blobs {
        for dep in parse_apk_installed(&blob) {
            collected.push((dep, format!("{layer_name}:/lib/apk/db/installed")));
        }
    }
}

/// Scans an OCI/Docker image `.tar` / `.tar.gz` archive OR an unpacked rootfs directory.
pub fn scan_oci_image(
    target: &Path,
    online_osv: bool,
    osv_base_url: &str,
) -> Result<ImageScanReport> {
    if !target.exists() {
        bail!("OCI image target does not exist: {}", target.display());
    }

    let mut os_family = "Linux".to_string();
    let mut os_version = String::new();
    let mut raw_collected: Vec<(ResolvedDependency, String)> = Vec::new();

    if target.is_file() {
        use std::io::Read as _;
        const MAX_OCI_TAR_BYTES: u64 = 256 * 1024 * 1024;
        let file = fs::File::open(target)
            .with_context(|| format!("Failed opening OCI tar archive {}", target.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_OCI_TAR_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("Failed reading OCI tar archive {}", target.display()))?;
        if bytes.len() as u64 > MAX_OCI_TAR_BYTES {
            bail!(
                "OCI tar archive {} exceeds {MAX_OCI_TAR_BYTES} byte safety cap",
                target.display()
            );
        }
        let label = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("image.tar");
        inspect_layer_tar(
            label,
            &bytes,
            &mut os_family,
            &mut os_version,
            &mut raw_collected,
        );
    } else if target.is_dir() {
        // Unpacked rootfs or OCI layout directory
        for rel in ["etc/os-release", "usr/lib/os-release"] {
            if let Ok(text) = fs::read_to_string(target.join(rel)) {
                let (fam, ver) = parse_os_release(&text);
                os_family = fam;
                os_version = ver;
                break;
            }
        }
        if let Ok(dpkg) = fs::read_to_string(target.join("var/lib/dpkg/status")) {
            let eco = if os_family.eq_ignore_ascii_case("Ubuntu") {
                "Ubuntu"
            } else {
                "Debian"
            };
            for dep in parse_dpkg_status(&dpkg, eco) {
                raw_collected.push((dep, "rootfs:/var/lib/dpkg/status".to_string()));
            }
        }
        if let Ok(apk) = fs::read_to_string(target.join("lib/apk/db/installed")) {
            for dep in parse_apk_installed(&apk) {
                raw_collected.push((dep, "rootfs:/lib/apk/db/installed".to_string()));
            }
        }
    }

    // Deduplicate extracted packages
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut deduped: Vec<(ResolvedDependency, String)> = Vec::new();
    for (dep, src) in raw_collected {
        let key = (
            dep.ecosystem.to_ascii_lowercase(),
            dep.name.to_ascii_lowercase(),
            dep.version.clone(),
        );
        if seen.insert(key) {
            deduped.push((dep, src));
        }
    }

    let mut store = AdvisoryStore::open_default()?;
    if online_osv && !deduped.is_empty() {
        let deps_only: Vec<ResolvedDependency> = deduped.iter().map(|(d, _)| d.clone()).collect();
        let _ = crate::deps_sync::sync_osv_to_store(osv_base_url, &deps_only, &mut store)?;
    }

    let mut by_eco: std::collections::HashMap<String, Vec<(&ResolvedDependency, &String)>> =
        std::collections::HashMap::new();
    for (dep, src) in &deduped {
        by_eco
            .entry(dep.ecosystem.clone())
            .or_default()
            .push((dep, src));
    }

    let mut findings = Vec::new();
    for (eco, entries) in by_eco {
        let pkg_names: Vec<&str> = entries.iter().map(|(d, _)| d.name.as_str()).collect();
        if let Ok(rec_map) = store.query_for_packages(&eco, &pkg_names) {
            for (dep, src) in entries {
                let norm = smg_core::advisories::normalize_package_name(&eco, &dep.name);
                if let Some(records) = rec_map.get(&norm) {
                    for rec in records {
                        if version_matches_range(
                            &eco,
                            &dep.version,
                            &rec.introduced,
                            &rec.fixed,
                            &rec.last_affected,
                        ) {
                            let affected_range = if !rec.fixed.is_empty() {
                                format!(">={} <{}", rec.introduced, rec.fixed)
                            } else if !rec.last_affected.is_empty() {
                                format!(">={} <={}", rec.introduced, rec.last_affected)
                            } else {
                                format!(">={}", rec.introduced)
                            };
                            findings.push(ImageVulnFinding {
                                advisory_id: rec.id.clone(),
                                severity: rec.severity.clone(),
                                ecosystem: dep.ecosystem.clone(),
                                package: dep.name.clone(),
                                installed_version: dep.version.clone(),
                                affected_range,
                                fixed_version: (!rec.fixed.is_empty()).then(|| rec.fixed.clone()),
                                source_layer: src.clone(),
                                summary: rec.summary.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ImageScanReport {
        target: target.display().to_string(),
        os_family,
        os_version,
        packages_scanned: deduped.len(),
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tar_entry(name: &str, content: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len().min(100)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_oct = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_oct.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        let chksum: u32 = header.iter().map(|&b| b as u32).sum();
        let chk_oct = format!("{chksum:06o}\0 ");
        header[148..156].copy_from_slice(chk_oct.as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    #[test]
    fn parses_synthetic_oci_tar_with_debian_dpkg_and_alpine_apk() {
        let mut tar = Vec::new();
        tar.extend_from_slice(&make_tar_entry(
            "etc/os-release",
            b"ID=debian\nVERSION_ID=\"12\"\n",
        ));
        tar.extend_from_slice(&make_tar_entry(
            "var/lib/dpkg/status",
            b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\nPackage: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0.0\n",
        ));
        tar.extend_from_slice(&make_tar_entry(
            "lib/apk/db/installed",
            b"P:busybox\nV:1.36.1-r15\n\nP:musl\nV:1.2.4_git20230717-r4\n",
        ));
        tar.extend(std::iter::repeat_n(0u8, 1024));

        let mut os_fam = String::new();
        let mut os_ver = String::new();
        let mut collected = Vec::new();
        inspect_layer_tar("test.tar", &tar, &mut os_fam, &mut os_ver, &mut collected);

        assert_eq!(os_fam, "Debian");
        assert_eq!(os_ver, "12");
        assert!(collected.iter().any(|(d, _)| d.ecosystem == "Debian"
            && d.name == "openssl"
            && d.version == "3.0.11-1~deb12u2"));
        assert!(!collected.iter().any(|(d, _)| d.name == "removed-pkg"));
        assert!(
            collected
                .iter()
                .any(|(d, _)| d.ecosystem == "Alpine" && d.name == "busybox")
        );
        assert!(
            collected
                .iter()
                .any(|(d, _)| d.ecosystem == "Alpine" && d.name == "musl")
        );
    }

    #[test]
    fn trivyignore_honors_active_and_expired_waivers() {
        let txt = "# comment\nCVE-2024-99999 exp:2099-12-31\nCVE-2020-00001 exp:2020-01-01\nGHSA-abcd-1234-efgh\n";
        let ti = TrivyIgnore::parse(txt);
        assert!(ti.is_ignored("CVE-2024-99999"));
        assert!(ti.is_ignored("GHSA-abcd-1234-efgh"));
        assert!(!ti.is_ignored("CVE-2020-00001"));
    }
}
