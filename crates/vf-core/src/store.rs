use crate::scanner::IndexedFile;
use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStats {
    pub scan_id: i64,
    pub total_files: usize,
    pub added_or_modified: usize,
    pub unchanged_cached: usize,
    pub removed: usize,
}

pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    pub fn open(project_root: &Path) -> Result<Self> {
        let vf_dir = project_root.join(".veriforge");
        fs::create_dir_all(&vf_dir)?;
        let db_path = vf_dir.join("state.db");
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

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

            CREATE TABLE IF NOT EXISTS symbols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                line_start INTEGER NOT NULL,
                line_end INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                dst_symbol_id INTEGER NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
                edge_type TEXT NOT NULL,
                guard_tag TEXT,
                taint_var TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
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

        Ok(Self { conn })
    }

    pub fn sync_files(&mut self, scanned: &[IndexedFile]) -> Result<(DeltaStats, Vec<IndexedFile>)> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO scans (total_files, modified_files) VALUES (?1, 0)",
            params![scanned.len() as i64],
        )?;
        let scan_id = tx.last_insert_rowid();

        let mut existing: HashMap<String, (i64, String)> = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT id, rel_path, blake3_hash FROM files")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
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

    pub fn save_findings(
        &mut self,
        scan_id: i64,
        rows: &[(&str, &str, &str, &str, &str, &str)],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM findings WHERE scan_id = ?1", params![scan_id])?;
        {
            let mut ins = tx.prepare(
                "INSERT OR REPLACE INTO findings (id, scan_id, rule_id, severity, status, trace_json, poc_cmd)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let mut fts = tx.prepare(
                "INSERT INTO findings_fts (id, rule_id, trace_json, poc_cmd) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (id, rule_id, severity, status, trace_json, poc_cmd) in rows {
                ins.execute(params![id, scan_id, rule_id, severity, status, trace_json, poc_cmd])?;
                fts.execute(params![id, rule_id, trace_json, poc_cmd])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Language;
    use std::path::PathBuf;

    #[test]
    fn test_delta_cache_skips_unchanged() {
        let tmp = std::env::temp_dir().join("vf_core_test_delta");
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
        };
        let (d1, c1) = store.sync_files(std::slice::from_ref(&f1)).unwrap();
        assert_eq!(d1.added_or_modified, 1);
        assert_eq!(c1.len(), 1);

        let (d2, c2) = store.sync_files(&[f1]).unwrap();
        assert_eq!(d2.added_or_modified, 0);
        assert_eq!(d2.unchanged_cached, 1);
        assert!(c2.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}
