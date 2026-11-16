use crate::scanner::IndexedFile;
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStats {
    pub scan_id: i64,
    pub total_files: usize,
    pub added_or_modified: usize,
    pub unchanged_cached: usize,
    pub removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: String,
    pub scan_id: i64,
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub status: String,
    pub trace_json: String,
    pub poc_cmd: String,
}

/// Resolves the per-user XDG / local cache base directory (`$XDG_CACHE_HOME` or `~/.cache`).
pub fn cache_base_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| std::path::PathBuf::from(h).join(".cache"))
        })
        .unwrap_or_else(std::env::temp_dir)
}

pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    pub fn open(project_root: &Path) -> Result<Self> {
        let canon = fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
        let repo_key = blake3::hash(canon.to_string_lossy().as_bytes()).to_hex();
        let smg_dir = cache_base_dir()
            .join("shellmind-guard")
            .join(&repo_key.as_str()[..16]);
        fs::create_dir_all(&smg_dir)?;
        let db_path = smg_dir.join("state.db");
        let conn = Connection::open(db_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;

        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            ",
        )?;

        let user_ver: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if user_ver < 1 {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    total_files INTEGER NOT NULL DEFAULT 0,
                    modified_files INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rel_path TEXT NOT NULL UNIQUE,
                    lang TEXT NOT NULL,
                    blake3_hash TEXT NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    last_scan_id INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ast_cache (
                    rel_path TEXT PRIMARY KEY,
                    blake3_hash TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    ast_json TEXT NOT NULL
                );

                DROP TABLE IF EXISTS edges;
                DROP TABLE IF EXISTS symbols;

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id INTEGER NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'CONFIRMED',
                    status TEXT NOT NULL,
                    trace_json TEXT NOT NULL,
                    poc_cmd TEXT NOT NULL
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                    id UNINDEXED,
                    rule_id,
                    trace_json,
                    poc_cmd
                );
                ",
            )?;

            let mut has_confidence = false;
            {
                let mut stmt = conn.prepare("PRAGMA table_info(findings)")?;
                let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
                for col in cols.flatten() {
                    if col == "confidence" {
                        has_confidence = true;
                        break;
                    }
                }
            }
            if !has_confidence {
                conn.execute(
                    "ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT 'CONFIRMED'",
                    [],
                )?;
            }
            conn.execute_batch("PRAGMA user_version = 1;")?;
        }

        Ok(Self { conn })
    }

    pub fn sync_files(
        &mut self,
        scanned: &[IndexedFile],
    ) -> Result<(DeltaStats, Vec<IndexedFile>)> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO scans (total_files, modified_files) VALUES (?1, 0)",
            params![scanned.len() as i64],
        )?;
        let scan_id = tx.last_insert_rowid();

        let mut existing: HashMap<String, (i64, String)> = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT id, rel_path, blake3_hash FROM files")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (id, rel_path, hash) = row?;
                existing.insert(rel_path, (id, hash));
            }
        }

        let mut changed_files = Vec::new();
        let mut unchanged_cached = 0usize;

        {
            let mut upsert = tx.prepare(
                "INSERT INTO files (rel_path, lang, blake3_hash, mtime_ns, size_bytes, last_scan_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(rel_path) DO UPDATE SET
                   lang = excluded.lang,
                   blake3_hash = excluded.blake3_hash,
                   mtime_ns = excluded.mtime_ns,
                   size_bytes = excluded.size_bytes,
                   last_scan_id = excluded.last_scan_id",
            )?;

            for f in scanned {
                let is_unchanged = existing
                    .get(&f.rel_path)
                    .map(|(_, old_hash)| old_hash == &f.blake3_hash)
                    .unwrap_or(false);

                if is_unchanged {
                    unchanged_cached += 1;
                } else {
                    changed_files.push(f.clone());
                }

                upsert.execute(params![
                    f.rel_path,
                    f.language.as_str(),
                    f.blake3_hash,
                    f.mtime_ns,
                    f.size_bytes as i64,
                    scan_id
                ])?;
            }
        }

        let removed = tx.execute(
            "DELETE FROM files WHERE last_scan_id != ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM ast_cache WHERE rel_path NOT IN (SELECT rel_path FROM files)",
            [],
        )?;

        tx.execute(
            "UPDATE scans SET modified_files = ?1 WHERE id = ?2",
            params![changed_files.len() as i64, scan_id],
        )?;

        tx.commit()?;

        let stats = DeltaStats {
            scan_id,
            total_files: scanned.len(),
            added_or_modified: changed_files.len(),
            unchanged_cached,
            removed,
        };
        Ok((stats, changed_files))
    }

    /// Loads cached per-file AST JSON blobs keyed by `rel_path` where `blake3_hash` and `config_hash` match.
    pub fn load_ast_cache(&self, config_hash: &str) -> Result<HashMap<String, (String, String)>> {
        let mut map = HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT rel_path, blake3_hash, ast_json FROM ast_cache WHERE config_hash = ?1",
        )?;
        let rows = stmt.query_map(params![config_hash], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (rel_path, blake3_hash, ast_json) = row?;
            map.insert(rel_path, (blake3_hash, ast_json));
        }
        Ok(map)
    }

    /// Persists newly parsed per-file AST JSON summaries into the Two-Phase SQLite cache.
    pub fn save_ast_cache(
        &mut self,
        config_hash: &str,
        entries: &[(String, String, String)],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ast_cache (rel_path, blake3_hash, config_hash, ast_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(rel_path) DO UPDATE SET
                   blake3_hash = excluded.blake3_hash,
                   config_hash = excluded.config_hash,
                   ast_json = excluded.ast_json",
            )?;
            for (rel_path, blake3_hash, ast_json) in entries {
                stmt.execute(params![rel_path, blake3_hash, config_hash, ast_json])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save_findings(
        &mut self,
        scan_id: i64,
        rows: &[(&str, &str, &str, &str, &str, &str, &str)],
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM findings", [])?;
        tx.execute("DELETE FROM findings_fts", [])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO findings (id, scan_id, rule_id, severity, confidence, status, trace_json, poc_cmd)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            let mut fts = tx.prepare(
                "INSERT INTO findings_fts (id, rule_id, trace_json, poc_cmd) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (id, rule_id, severity, confidence, status, trace_json, poc_cmd) in rows {
                ins.execute(params![
                    id, scan_id, rule_id, severity, confidence, status, trace_json, poc_cmd
                ])?;
                fts.execute(params![id, rule_id, trace_json, poc_cmd])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_finding(&self, finding_id: &str) -> Result<Option<StoredFinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_id, rule_id, severity, confidence, status, trace_json, poc_cmd
             FROM findings WHERE id = ?1",
        )?;
        let res = stmt
            .query_row(params![finding_id], |r| {
                Ok(StoredFinding {
                    id: r.get(0)?,
                    scan_id: r.get(1)?,
                    rule_id: r.get(2)?,
                    severity: r.get(3)?,
                    confidence: r.get(4)?,
                    status: r.get(5)?,
                    trace_json: r.get(6)?,
                    poc_cmd: r.get(7)?,
                })
            })
            .optional()?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Language;
    use std::path::PathBuf;

    #[test]
    fn test_delta_cache_and_ast_cache() {
        let tmp = std::env::temp_dir().join(format!("smg_core_test_delta_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let mut store = StateStore::open(&tmp).unwrap();
        let f1 = IndexedFile {
            rel_path: "src/app.ts".into(),
            abs_path: PathBuf::from("src/app.ts"),
            language: Language::TypeScript,
            blake3_hash: "abc123".into(),
            mtime_ns: 1,
            size_bytes: 10,
            cached_bytes: None,
        };
        let (d1, c1) = store.sync_files(std::slice::from_ref(&f1)).unwrap();
        assert_eq!(d1.added_or_modified, 1);
        assert_eq!(c1.len(), 1);

        store
            .save_ast_cache(
                "cfg1",
                &[(
                    "src/app.ts".into(),
                    "abc123".into(),
                    "{\"rel_path\":\"src/app.ts\",\"imports\":[],\"symbols\":[]}".into(),
                )],
            )
            .unwrap();
        let loaded = store.load_ast_cache("cfg1").unwrap();
        assert_eq!(loaded.get("src/app.ts").unwrap().0, "abc123");

        let (d2, c2) = store.sync_files(&[f1]).unwrap();
        assert_eq!(d2.added_or_modified, 0);
        assert_eq!(d2.unchanged_cached, 1);
        assert!(c2.is_empty());

        store
            .save_findings(
                d2.scan_id,
                &[(
                    "SMG-SQLI-001",
                    "SMG-SQLI-001",
                    "CRITICAL",
                    "CONFIRMED",
                    "SUSPECT_UNGUARDED",
                    "{}",
                    "shellmind-guard replay SMG-SQLI-001",
                )],
            )
            .unwrap();
        let stored = store.get_finding("SMG-SQLI-001").unwrap().unwrap();
        assert_eq!(stored.confidence, "CONFIRMED");

        let _ = fs::remove_dir_all(&tmp);
    }
}
