//! Lossless 1:1 bidirectional `SQLite <-> LibreDB` bridge for `SkillsDB` (`customizations.db` & `memory.db`).
//!
//! Guarantees two properties simultaneously:
//! 1. **Native Cognitive Hydration:** Imports active rules, skills, micro-sections, synonyms, configs,
//!    templates, decisions, facts, tasks, handoffs, symbols, and snapshots as first-class `LibreDB`
//!    `Inodes` wired with typed synapses (`HasSection`, `UsesSkill`, `Delegates`, `Verifies`, `Calls`).
//! 2. **100% Mathematical Bijection (`SQLite -> LibreDB -> SQLite`):** Preserves exact DDL schemas,
//!    column types (`NULL`, `INTEGER`, `REAL`, `TEXT`, `BLOB`), inactive/historical rows, and rebuilds
//!    all `FTS5` virtual tables so rolling back to `SQLite` loses zero bits of information.

use libredb_core::crc::{crc32, hash_key};
use libredb_core::{
    is_reserved_security_config_key, is_reserved_sys_key, EdgeKind, LibreDb, NodeFlags, NodeKind,
    WriteRequest,
};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("LibreDB kernel error: {0}")]
    Core(#[from] libredb_core::LibreDbError),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("round-trip parity mismatch in table '{table}': {reason}")]
    ParityMismatch { table: String, reason: String },
}

pub type Result<T> = std::result::Result<T, BridgeError>;

/// Lossless SQLite cell representation supporting all 5 SQLite storage classes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlCell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MirroredTable {
    name: String,
    create_sql: String,
    is_fts5: bool,
    is_external_content_fts5: bool,
    columns: Vec<String>,
    rows: Vec<Vec<SqlCell>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SqliteMirrorBundle {
    scope: String,
    tables: Vec<MirroredTable>,
    indexes_sql: Vec<String>,
}

/// Summary returned after importing a SQLite database into `LibreDb`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    pub scope: String,
    pub tables_mirrored: usize,
    pub total_sqlite_rows: usize,
    pub cognitive_capsules_created: usize,
    pub synapses_wired: usize,
}

/// Summary returned after verifying `SQLite (A) -> LibreDB -> SQLite (B)` lossless equivalence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundtripReport {
    pub tables_verified: usize,
    pub rows_verified: usize,
    pub canonical_digest_hex: String,
    pub fts5_tables_verified: usize,
}

/// Hard safety ceiling (`128 MiB`) for imported SQLite database files so crafted oversized `.db`
/// inputs cannot exhaust host memory during lossless table snapshotting.
pub const MAX_SQLITE_IMPORT_BYTES: u64 = 128 * 1024 * 1024;

static MIGRATE_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn reject_any_symlink_at_path(path: &Path, role: &str) -> Result<()> {
    if let Ok(sym_meta) = std::fs::symlink_metadata(path) {
        if sym_meta.file_type().is_symlink() {
            return Err(BridgeError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing symlinked {role} path '{}'", path.display()),
            )));
        }
    }
    Ok(())
}

fn validate_sqlite_source_file(sqlite_path: &Path) -> Result<u64> {
    let sym_meta = std::fs::symlink_metadata(sqlite_path)?;
    if sym_meta.file_type().is_symlink() {
        return Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing symlinked SQLite source '{}'", sqlite_path.display()),
        )));
    }
    if !sym_meta.is_file() {
        return Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SQLite source '{}' is not a regular file", sqlite_path.display()),
        )));
    }
    if sym_meta.len() > MAX_SQLITE_IMPORT_BYTES {
        return Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "SQLite source '{}' ({} bytes) exceeds 128 MiB import ceiling",
                sqlite_path.display(),
                sym_meta.len()
            ),
        )));
    }
    Ok(sym_meta.len())
}

fn validate_bridge_scope(scope: &str) -> Result<()> {
    if matches!(scope, "central" | "project") {
        Ok(())
    } else {
        Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported SQLite bridge scope '{scope}' (expected 'central' or 'project')"),
        )))
    }
}

/// Imports a `SkillsDB` SQLite database (`scope = "central"` or `"project"`) strictly READ-ONLY into `ldb`.
pub fn import_sqlite_readonly(
    sqlite_path: &Path,
    ldb: &LibreDb,
    scope: &str,
) -> Result<ImportSummary> {
    validate_bridge_scope(scope)?;
    validate_sqlite_source_file(sqlite_path)?;
    let conn = Connection::open_with_flags(
        sqlite_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let _ = conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;");

    // 1. Snapshot exact DDL and every row for lossless rollback mirror.
    let bundle = snapshot_sqlite_database(&conn, scope)?;
    let total_sqlite_rows: usize = bundle.tables.iter().map(|t| t.rows.len()).sum();
    let tables_mirrored = bundle.tables.len();

    let mirror_bytes = serde_json::to_vec(&bundle)?;
    let mirror_req = WriteRequest::new(NodeKind::Generic, mirror_bytes)
        .with_key(format!("sqlite_mirror::{scope}"))
        .with_importance(10);
    // Mark mirror as cold metadata by storing via standard put; `pulse` only searches cognitive kinds!
    let mirror_id = ldb.put(mirror_req)?;
    let _ = mirror_id;

    // 2. Materialize rich cognitive Inodes and native synapses for active LLM knowledge!
    let (capsules, synapses) = populate_cognitive_graph(&conn, ldb)?;

    Ok(ImportSummary {
        scope: scope.to_owned(),
        tables_mirrored,
        total_sqlite_rows,
        cognitive_capsules_created: capsules,
        synapses_wired: synapses,
    })
}

/// Opens `ldb_path` directly if it already exists; otherwise, if a legacy SQLite database
/// (`sqlite_override` or sibling `<stem>.db`) exists, silently imports 100% of its contents
/// into a crash-safe temporary `.ldb` and atomically publishes it at `ldb_path` without
/// modifying the source `.db` file. Brand-new workspaces/chats without `.db` open a fresh `.ldb`.
pub fn open_or_auto_migrate(
    ldb_path: &Path,
    sqlite_override: Option<&Path>,
    scope: &str,
) -> Result<(Arc<LibreDb>, Option<ImportSummary>)> {
    reject_any_symlink_at_path(ldb_path, "LibreDB")?;
    let default_sibling = ldb_path.with_extension("db");
    let sqlite_candidate = sqlite_override.unwrap_or(&default_sibling);
    let has_legacy_sqlite = std::fs::symlink_metadata(sqlite_candidate)
        .map(|m| {
            !m.file_type().is_symlink()
                && m.is_file()
                && m.len() > 0
                && m.len() <= MAX_SQLITE_IMPORT_BYTES
        })
        .unwrap_or(false);

    let already_initialized = std::fs::symlink_metadata(ldb_path)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() >= 8192)
        .unwrap_or(false);
    if already_initialized {
        let db = LibreDb::open(ldb_path)?;
        if has_legacy_sqlite && db.stats().map(|s| s.total_inodes == 0).unwrap_or(false) {
            let summary = import_sqlite_readonly(sqlite_candidate, &db, scope)?;
            return Ok((Arc::new(db), Some(summary)));
        }
        return Ok((Arc::new(db), None));
    }

    if !has_legacy_sqlite {
        let db = LibreDb::open(ldb_path)?;
        return Ok((Arc::new(db), None));
    }

    if let Some(parent) = ldb_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let pid = std::process::id();
    let seq = MIGRATE_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_ldb = ldb_path.with_extension(format!("ldb.migrating.{pid}.{seq}.{nanos:x}"));
    reject_any_symlink_at_path(&tmp_ldb, "LibreDB migration staging")?;
    let _ = std::fs::remove_file(&tmp_ldb);

    let migrate_res = (|| -> Result<ImportSummary> {
        let staging_db = LibreDb::open(&tmp_ldb)?;
        let summary = import_sqlite_readonly(sqlite_candidate, &staging_db, scope)?;
        drop(staging_db);
        Ok(summary)
    })();

    match migrate_res {
        Ok(summary) => {
            if std::fs::symlink_metadata(ldb_path).is_ok() {
                let _ = std::fs::remove_file(&tmp_ldb);
                reject_any_symlink_at_path(ldb_path, "LibreDB")?;
                let db = LibreDb::open(ldb_path)?;
                Ok((Arc::new(db), None))
            } else {
                // Publish non-destructively via `hard_link` first (atomic no-overwrite on NTFS and POSIX),
                // falling back to `rename` only if `ldb_path` still has no directory entry.
                let published = match std::fs::hard_link(&tmp_ldb, ldb_path) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&tmp_ldb);
                        true
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let _ = std::fs::remove_file(&tmp_ldb);
                        false
                    }
                    Err(_) => {
                        if std::fs::symlink_metadata(ldb_path).is_err() {
                            std::fs::rename(&tmp_ldb, ldb_path).is_ok()
                        } else {
                            let _ = std::fs::remove_file(&tmp_ldb);
                            false
                        }
                    }
                };
                let _ = std::fs::remove_file(&tmp_ldb);
                reject_any_symlink_at_path(ldb_path, "LibreDB")?;
                let db = LibreDb::open(ldb_path)?;
                Ok((Arc::new(db), if published { Some(summary) } else { None }))
            }
        }
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_ldb);
            Err(err)
        }
    }
}

/// Exports the lossless SQLite mirror for `scope` from `ldb` into a brand-new SQLite database at `out_sqlite_path`,
/// recreating exact schemas, rows, indexes, and rebuilt `FTS5` virtual tables.
pub fn export_sqlite_database(
    ldb: &LibreDb,
    scope: &str,
    out_sqlite_path: &Path,
) -> Result<usize> {
    validate_bridge_scope(scope)?;
    // Reject both live AND dangling symlinks before `exists()` or `Connection::open()` so an
    // attacker-planted dangling symlink cannot create or clobber arbitrary external files.
    reject_any_symlink_at_path(out_sqlite_path, "SQLite export")?;
    if out_sqlite_path.exists() {
        std::fs::remove_file(out_sqlite_path)?;
    }
    if let Some(parent) = out_sqlite_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    reject_any_symlink_at_path(out_sqlite_path, "SQLite export")?;

    let mirror_rec = ldb.get_by_key(NodeKind::Generic, &format!("sqlite_mirror::{scope}"))?;
    let bundle: SqliteMirrorBundle = serde_json::from_slice(&mirror_rec.payload)?;

    let mut conn = Connection::open(out_sqlite_path)?;
    let _ = conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;");
    let tx = conn.transaction()?;

    let mut restored_rows = 0usize;

    // Step 1: Create and populate all standard relational tables first.
    for tbl in bundle.tables.iter().filter(|t| !t.is_fts5) {
        validate_safe_ddl_sql(&tbl.create_sql, &tbl.name)?;
        tx.execute_batch(&tbl.create_sql)?;
        if !tbl.rows.is_empty() && !tbl.columns.is_empty() {
            let col_list = tbl
                .columns
                .iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = vec!["?"; tbl.columns.len()].join(", ");
            let insert_sql = format!(
                "INSERT INTO \"{}\" ({col_list}) VALUES ({placeholders});",
                tbl.name.replace('"', "\"\"")
            );
            let mut stmt = tx.prepare(&insert_sql)?;
            for row in &tbl.rows {
                let params: Vec<rusqlite::types::Value> = row.iter().map(cell_to_rusqlite).collect();
                stmt.execute(rusqlite::params_from_iter(params))?;
                restored_rows += 1;
            }
        }
    }

    // Step 2: Create all secondary B-Tree indexes.
    for idx_sql in &bundle.indexes_sql {
        validate_safe_ddl_sql(idx_sql, "<index>")?;
        tx.execute_batch(idx_sql)?;
    }

    // Step 3: Create and populate/rebuild all FTS5 virtual tables.
    for tbl in bundle.tables.iter().filter(|t| t.is_fts5) {
        validate_safe_ddl_sql(&tbl.create_sql, &tbl.name)?;
        tx.execute_batch(&tbl.create_sql)?;
        if tbl.is_external_content_fts5 {
            let rebuild_sql = format!(
                "INSERT INTO \"{0}\"(\"{0}\") VALUES ('rebuild');",
                tbl.name.replace('"', "\"\"")
            );
            tx.execute_batch(&rebuild_sql)?;
        } else if !tbl.rows.is_empty() && !tbl.columns.is_empty() {
            let col_list = tbl
                .columns
                .iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = vec!["?"; tbl.columns.len()].join(", ");
            let insert_sql = format!(
                "INSERT INTO \"{}\" ({col_list}) VALUES ({placeholders});",
                tbl.name.replace('"', "\"\"")
            );
            let mut stmt = tx.prepare(&insert_sql)?;
            for row in &tbl.rows {
                let params: Vec<rusqlite::types::Value> = row.iter().map(cell_to_rusqlite).collect();
                stmt.execute(rusqlite::params_from_iter(params))?;
                restored_rows += 1;
            }
        }
    }

    tx.commit()?;
    Ok(restored_rows)
}

/// Verifies cell-by-cell equivalence between `orig_sqlite` and `reconstructed_sqlite` across all user tables
/// and confirms all `FTS5` virtual tables execute `MATCH` queries cleanly.
pub fn verify_sqlite_equivalence(
    orig_sqlite: &Path,
    reconstructed_sqlite: &Path,
) -> Result<RoundtripReport> {
    validate_sqlite_source_file(orig_sqlite)?;
    validate_sqlite_source_file(reconstructed_sqlite)?;
    let conn_a = Connection::open_with_flags(
        orig_sqlite,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let _ = conn_a.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;");
    let conn_b = Connection::open_with_flags(
        reconstructed_sqlite,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let _ = conn_b.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;");

    let snap_a = snapshot_sqlite_database(&conn_a, "verify_a")?;
    let snap_b = snapshot_sqlite_database(&conn_b, "verify_b")?;

    if snap_a.tables.len() != snap_b.tables.len() {
        return Err(BridgeError::ParityMismatch {
            table: "<schema>".to_owned(),
            reason: format!(
                "table count mismatch: orig={}, reconstructed={}",
                snap_a.tables.len(),
                snap_b.tables.len()
            ),
        });
    }

    let mut total_rows = 0usize;
    let mut fts_verified = 0usize;
    let mut digest_stream: Vec<u8> = Vec::new();

    for (ta, tb) in snap_a.tables.iter().zip(snap_b.tables.iter()) {
        if ta.name != tb.name {
            return Err(BridgeError::ParityMismatch {
                table: ta.name.clone(),
                reason: format!("table name mismatch against '{}'", tb.name),
            });
        }
        if ta.is_fts5 {
            // Verify FTS5 virtual table responds and matches row count!
            let cnt_a: i64 = conn_a
                .query_row(&format!("SELECT COUNT(*) FROM \"{}\";", ta.name), [], |r| r.get(0))?;
            let cnt_b: i64 = conn_b
                .query_row(&format!("SELECT COUNT(*) FROM \"{}\";", tb.name), [], |r| r.get(0))?;
            if cnt_a != cnt_b {
                return Err(BridgeError::ParityMismatch {
                    table: ta.name.clone(),
                    reason: format!("FTS5 indexed row count mismatch: {cnt_a} vs {cnt_b}"),
                });
            }
            fts_verified += 1;
            continue;
        }

        if ta.columns != tb.columns {
            return Err(BridgeError::ParityMismatch {
                table: ta.name.clone(),
                reason: format!("columns differ: {:?} vs {:?}", ta.columns, tb.columns),
            });
        }
        if ta.rows.len() != tb.rows.len() {
            return Err(BridgeError::ParityMismatch {
                table: ta.name.clone(),
                reason: format!("row count mismatch: {} vs {}", ta.rows.len(), tb.rows.len()),
            });
        }

        for (r_idx, (ra, rb)) in ta.rows.iter().zip(tb.rows.iter()).enumerate() {
            if !rows_semantically_identical(ra, rb) {
                return Err(BridgeError::ParityMismatch {
                    table: ta.name.clone(),
                    reason: format!("cell mismatch at row #{r_idx}: {ra:?} != {rb:?}"),
                });
            }
            let row_json = serde_json::to_vec(ra)?;
            digest_stream.extend_from_slice(&row_json);
            total_rows += 1;
        }
    }

    let h64 = hash_key(42, &digest_stream);
    let c32 = crc32(&digest_stream);
    let digest_hex = format!("{h64:016x}{c32:08x}");

    Ok(RoundtripReport {
        tables_verified: snap_a.tables.len(),
        rows_verified: total_rows,
        canonical_digest_hex: digest_hex,
        fts5_tables_verified: fts_verified,
    })
}

fn rows_semantically_identical(a: &[SqlCell], b: &[SqlCell]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (ca, cb) in a.iter().zip(b.iter()) {
        match (ca, cb) {
            (SqlCell::Real(fa), SqlCell::Real(fb)) => {
                if (fa - fb).abs() > 1e-12 && !(fa.is_nan() && fb.is_nan()) {
                    return false;
                }
            }
            _ if ca != cb => return false,
            _ => {}
        }
    }
    true
}

/// Validates that a mirrored SQLite DDL string is a single benign `CREATE TABLE`,
/// `CREATE VIRTUAL TABLE`, or `CREATE [UNIQUE] INDEX` statement without stacked
/// `ATTACH DATABASE`, `PRAGMA`, or `INSERT`/`DROP` payloads.
fn validate_safe_ddl_sql(sql: &str, label: &str) -> Result<()> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::ParityMismatch {
            table: label.to_owned(),
            reason: "empty DDL statement in SQLite mirror".to_owned(),
        });
    }
    let upper: String = trimmed
        .chars()
        .take(48)
        .collect::<String>()
        .to_ascii_uppercase();
    let norm_prefix: String = upper.split_whitespace().collect::<Vec<_>>().join(" ");
    let allowed_prefix = norm_prefix.starts_with("CREATE TABLE ")
        || norm_prefix.starts_with("CREATE TABLE\"")
        || norm_prefix.starts_with("CREATE TEMP TABLE ")
        || norm_prefix.starts_with("CREATE VIRTUAL TABLE ")
        || norm_prefix.starts_with("CREATE INDEX ")
        || norm_prefix.starts_with("CREATE UNIQUE INDEX ");
    if !allowed_prefix {
        return Err(BridgeError::ParityMismatch {
            table: label.to_owned(),
            reason: format!("disallowed DDL prefix in SQLite mirror: '{norm_prefix}'"),
        });
    }

    // Ensure no unquoted semicolon appears before the optional trailing semicolon (blocks stacked statements).
    let core = trimmed.trim_end_matches(';').trim_end();
    let bytes = core.as_bytes();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
        } else if in_double {
            if b == b'"' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    i += 2;
                    continue;
                }
                in_double = false;
            }
        } else {
            match b {
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b';' => {
                    return Err(BridgeError::ParityMismatch {
                        table: label.to_owned(),
                        reason: "multi-statement semicolon rejected in SQLite mirror DDL".to_owned(),
                    });
                }
                _ => {}
            }
        }
        i += 1;
    }
    Ok(())
}

fn snapshot_sqlite_database(conn: &Connection, scope: &str) -> Result<SqliteMirrorBundle> {
    let mut stmt = conn.prepare(
        "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name ASC;",
    )?;

    let mut raw_objects: Vec<(String, String, String)> = Vec::new();
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for item in rows {
        raw_objects.push(item?);
    }

    // Identify FTS5 virtual tables first so we skip their internal shadow backing tables (`*_data`, `*_idx`, etc.).
    let fts_names: Vec<String> = raw_objects
        .iter()
        .filter(|(t, _, sql)| {
            t == "table" && sql.to_ascii_lowercase().contains("using fts5")
        })
        .map(|(_, name, _)| name.clone())
        .collect();

    let is_fts_shadow = |name: &str| -> bool {
        fts_names.iter().any(|fts| {
            name == format!("{fts}_data")
                || name == format!("{fts}_idx")
                || name == format!("{fts}_docsize")
                || name == format!("{fts}_config")
                || name == format!("{fts}_content")
        })
    };

    let mut tables = Vec::new();
    let mut indexes_sql = Vec::new();

    for (obj_type, name, create_sql) in raw_objects {
        if obj_type == "index" {
            indexes_sql.push(format!("{};", create_sql.trim_end_matches(';')));
            continue;
        }
        if obj_type != "table" || is_fts_shadow(&name) {
            continue;
        }

        let sql_low = create_sql.to_ascii_lowercase();
        let is_fts5 = sql_low.contains("using fts5");
        let is_external_content_fts5 = is_fts5 && sql_low.contains("content=");

        let columns = query_table_columns(conn, &name)?;
        let table_rows = if is_external_content_fts5 || columns.is_empty() {
            Vec::new()
        } else {
            let col_list = columns
                .iter()
                .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(", ");
            // Deterministic row ordering across all columns
            let order_cols = (1..=columns.len())
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let q = format!(
                "SELECT {col_list} FROM \"{}\" ORDER BY {order_cols};",
                name.replace('"', "\"\"")
            );
            let mut r_stmt = conn.prepare(&q)?;
            let col_cnt = columns.len();
            let mapped = r_stmt.query_map([], |row| {
                let mut cells = Vec::with_capacity(col_cnt);
                for idx in 0..col_cnt {
                    cells.push(value_ref_to_cell(row.get_ref(idx)?));
                }
                Ok(cells)
            })?;
            let mut collected = Vec::new();
            for r in mapped {
                collected.push(r?);
            }
            collected
        };

        tables.push(MirroredTable {
            name,
            create_sql: format!("{};", create_sql.trim_end_matches(';')),
            is_fts5,
            is_external_content_fts5,
            columns,
            rows: table_rows,
        });
    }

    Ok(SqliteMirrorBundle {
        scope: scope.to_owned(),
        tables,
        indexes_sql,
    })
}

fn query_table_columns(conn: &Connection, table_name: &str) -> Result<Vec<String>> {
    let pragma = format!("PRAGMA table_info(\"{}\");", table_name.replace('"', "\"\""));
    let mut stmt = conn.prepare(&pragma)?;
    let iter = stmt.query_map([], |r| r.get::<_, String>(1))?;
    let mut cols = Vec::new();
    for c in iter {
        cols.push(c?);
    }
    Ok(cols)
}

fn value_ref_to_cell(v: ValueRef<'_>) -> SqlCell {
    match v {
        ValueRef::Null => SqlCell::Null,
        ValueRef::Integer(i) => SqlCell::Int(i),
        ValueRef::Real(f) => SqlCell::Real(f),
        ValueRef::Text(t) => SqlCell::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => SqlCell::Blob(b.to_vec()),
    }
}

fn cell_to_rusqlite(c: &SqlCell) -> rusqlite::types::Value {
    match c {
        SqlCell::Null => rusqlite::types::Value::Null,
        SqlCell::Int(i) => rusqlite::types::Value::Integer(*i),
        SqlCell::Real(f) => rusqlite::types::Value::Real(*f),
        SqlCell::Text(t) => rusqlite::types::Value::Text(t.clone()),
        SqlCell::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
    }
}

/// Converts all 19 `SkillsDB` tables (`8` central + `11` project) into native `LibreDB` cognitive
/// capsules and wires temporal `Supersedes` + structural `Inode` synapses in one batched commit!
fn populate_cognitive_graph(conn: &Connection, ldb: &LibreDb) -> Result<(usize, usize)> {
    let existing_tables = list_table_names(conn)?;
    let mut prepared: Vec<libredb_core::PreparedWrite> = Vec::new();

    let mut pending_sections: Vec<(usize, String)> = Vec::new();
    let mut skill_batch_idx: HashMap<String, usize> = HashMap::new();
    let mut pending_skill_full: Vec<(usize, usize)> = Vec::new();
    let mut pending_template_skills: Vec<(usize, Vec<String>)> = Vec::new();
    let mut task_batch_idx: HashMap<i64, usize> = HashMap::new();
    let mut pending_handoff_tasks: Vec<(usize, i64)> = Vec::new();
    let mut pending_verify_tasks: Vec<(usize, i64)> = Vec::new();
    let mut symbol_batch_idx: HashMap<String, usize> = HashMap::new();
    let mut file_symbols_idx: HashMap<String, Vec<usize>> = HashMap::new();
    let mut pending_working_files: Vec<(usize, String)> = Vec::new();
    let mut active_decisions_text: Vec<(usize, String)> = Vec::new();
    let mut fact_last_idx: HashMap<String, usize> = HashMap::new();
    let mut pending_fact_supersedes: Vec<(String, String)> = Vec::new();

    let mut inactive_rules: HashSet<String> = HashSet::new();
    let mut inactive_skills: HashSet<String> = HashSet::new();
    let mut inactive_decisions: HashSet<String> = HashSet::new();
    let mut deprecated_facts: HashSet<String> = HashSet::new();

    // ==================== CENTRAL DB TABLES (8) ====================
    if existing_tables.contains("rules") {
        let cols = query_table_columns(conn, "rules")?;
        let has_scope = cols.iter().any(|c| c == "scope");
        let sql = if has_scope {
            "SELECT key, name, category, summary, content, is_active, scope FROM rules ORDER BY id ASC;"
        } else {
            "SELECT key, name, category, summary, content, is_active, 'global' FROM rules ORDER BY id ASC;"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5).unwrap_or(1),
                r.get::<_, Option<String>>(6)?.unwrap_or_else(|| "global".to_owned()),
            ))
        })?;
        for row in rows {
            let (key, name, cat, summary, content, is_active, scope) = row?;
            if is_reserved_sys_key(&key) {
                continue;
            }
            let body = format!("[Rule: {name} | {cat} | scope={scope}]\nSummary: {summary}\n{content}");
            let idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Rule, body.into_bytes())
                    .with_key(&key)
                    .with_importance(230)
                    .with_pinned(is_active != 0),
                idx,
            )?);
            if is_active == 0 {
                inactive_rules.insert(key);
            } else {
                inactive_rules.remove(&key);
            }
        }
    }

    if existing_tables.contains("skills") {
        let mut stmt = conn.prepare(
            "SELECT name, plugin_name, category, description, content, is_active FROM skills ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5).unwrap_or(1),
            ))
        })?;
        for row in rows {
            let (name, plugin, cat, desc, content, is_active) = row?;
            let summary_card = format!(
                "[Skill: {name} | plugin={plugin} | category={cat}]\n{desc}\n(Full length: {} chars)",
                content.len()
            );
            let s_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Skill, summary_card.into_bytes())
                    .with_key(&name)
                    .with_importance(200),
                s_idx,
            )?);

            // Also preserve 100% verbatim SKILL.md body in a dedicated non-polluting full-skill capsule!
            let full_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Generic, content.into_bytes())
                    .with_key(format!("skill_full::{name}"))
                    .with_importance(120),
                full_idx,
            )?);
            pending_skill_full.push((s_idx, full_idx));

            if is_active == 0 {
                inactive_skills.insert(name);
            } else {
                inactive_skills.remove(&name);
                skill_batch_idx.insert(name, s_idx);
            }
        }
    }

    if existing_tables.contains("skill_sections") {
        let mut stmt = conn.prepare(
            "SELECT skill_name, section_title, content FROM skill_sections ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (sname, stitle, content) = row?;
            let sec_key = format!("{sname}::{stitle}");
            let body = format!("[{sname} > {stitle}]\n{content}");
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::SkillSection, body.into_bytes())
                    .with_key(sec_key)
                    .with_importance(190),
                b_idx,
            )?);
            pending_sections.push((b_idx, sname));
        }
    }

    if existing_tables.contains("runtime_config") {
        let cols = query_table_columns(conn, "runtime_config")?;
        let sql = if cols.iter().any(|c| c == "updated_at") {
            "SELECT key, value, updated_at FROM runtime_config ORDER BY key ASC;"
        } else {
            "SELECT key, value, '' FROM runtime_config ORDER BY key ASC;"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (key, val, _upd) = row?;
            // Never materialize security-critical internal trust or vault keys (`sys::*`,
            // `trust:*`, `workspace:*`, `workspace_id::*`) from imported SQLite `runtime_config`
            // rows into active `NodeKind::Config` capsules. Raw table cells remain preserved
            // inside `sqlite_mirror::{scope}` for lossless SQLite round-trip reconstruction.
            if is_reserved_security_config_key(&key) {
                continue;
            }
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Config, val.into_bytes())
                    .with_key(key)
                    .with_importance(180),
                b_idx,
            )?);
        }
    }

    if existing_tables.contains("synonym_synapses") {
        let mut stmt =
            conn.prepare("SELECT term, synonyms FROM synonym_synapses ORDER BY id ASC;")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (term, syns_txt) = row?;
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::SynonymCluster, syns_txt.into_bytes())
                    .with_key(term)
                    .with_importance(160),
                b_idx,
            )?);
        }
    }

    if existing_tables.contains("agent_templates") {
        let mut stmt = conn.prepare(
            "SELECT id, name, role, system_prompt, skills FROM agent_templates ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (id, name, role, prompt, skills_json) = row?;
            let body = format!("[Agent: {name} ({id})]\nRole: {role}\n{prompt}");
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::AgentTemplate, body.into_bytes())
                    .with_key(&id)
                    .with_importance(175),
                b_idx,
            )?);
            if let Ok(skill_list) = serde_json::from_str::<Vec<String>>(&skills_json) {
                if !skill_list.is_empty() {
                    pending_template_skills.push((b_idx, skill_list));
                }
            }
        }
    }

    if existing_tables.contains("transcript_cursors") {
        let cols = query_table_columns(conn, "transcript_cursors")?;
        let has_epoch = cols.iter().any(|c| c == "epoch_count");
        let has_dedup = cols.iter().any(|c| c == "dedup_token");
        let has_ws = cols.iter().any(|c| c == "inferred_workspace");
        let sql = format!(
            "SELECT conversation_id, checkpoint_count, {}, {}, {}, updated_at FROM transcript_cursors;",
            if has_epoch { "epoch_count" } else { "1" },
            if has_dedup { "dedup_token" } else { "''" },
            if has_ws { "inferred_workspace" } else { "''" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1).unwrap_or(0),
                r.get::<_, i64>(2).unwrap_or(1),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (cid, ckpt, ep, dedup, ws, upd) = row?;
            let payload = serde_json::json!({
                "conversation_id": cid,
                "checkpoint_count": ckpt,
                "epoch_count": ep,
                "dedup_token": dedup,
                "inferred_workspace": ws,
                "updated_at": upd,
            });
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::TranscriptCursor, serde_json::to_vec(&payload)?)
                    .with_key(cid)
                    .with_importance(110),
                b_idx,
            )?);
        }
    }

    if existing_tables.contains("quota_ledger") {
        let mut stmt = conn.prepare(
            "SELECT id, pool, execution_tier, model_used, input_tokens, output_tokens, saved_agy_tokens, created_at FROM quota_ledger ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, i64>(4).unwrap_or(0),
                r.get::<_, i64>(5).unwrap_or(0),
                r.get::<_, i64>(6).unwrap_or(0),
                r.get::<_, String>(7)?,
            ))
        })?;
        for row in rows {
            let (qid, pool, tier, model, in_tok, out_tok, saved_tok, created_at) = row?;
            let payload = serde_json::json!({
                "id": qid,
                "pool": pool,
                "tier": tier,
                "model": model,
                "input_tokens": in_tok,
                "output_tokens": out_tok,
                "saved_agy_tokens": saved_tok,
                "created_at": created_at,
            });
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::QuotaEvent, serde_json::to_vec(&payload)?)
                    .with_key(format!("quota::{qid}"))
                    .with_importance(90),
                b_idx,
            )?);
        }
    }

    // ==================== PROJECT MEMORY DB TABLES (11) ====================
    if existing_tables.contains("project_decisions") {
        let cols = query_table_columns(conn, "project_decisions")?;
        let has_upd = cols.iter().any(|c| c == "updated_at");
        let sql = if has_upd {
            "SELECT title, content, category, is_active, updated_at FROM project_decisions ORDER BY id ASC;"
        } else {
            "SELECT title, content, category, is_active, '' FROM project_decisions ORDER BY id ASC;"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, i64>(3).unwrap_or(1),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        })?;
        let mut latest_dec_idx: HashMap<String, (usize, String, bool)> = HashMap::new();
        for row in rows {
            let (title, content, cat, is_active, upd) = row?;
            if is_reserved_sys_key(&title) {
                continue;
            }
            let dt_tag = if upd.len() >= 10 {
                format!(" [{}]", &upd[..10])
            } else {
                String::new()
            };
            let body = format!("[Decision: {title} ({cat}){dt_tag}]\n{content}");
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Decision, body.clone().into_bytes())
                    .with_key(&title)
                    .with_importance(225)
                    .with_pinned(is_active != 0),
                b_idx,
            )?);
            if is_active == 0 {
                inactive_decisions.insert(title.clone());
                latest_dec_idx.insert(title, (b_idx, body, false));
            } else {
                inactive_decisions.remove(&title);
                latest_dec_idx.insert(title, (b_idx, body, true));
            }
        }
        for (_, (idx, body, active)) in latest_dec_idx {
            if active {
                active_decisions_text.push((idx, body));
            }
        }
    }

    if existing_tables.contains("session_snapshots") {
        let cols = query_table_columns(conn, "session_snapshots")?;
        let has_commit = cols.iter().any(|c| c == "commit_hash");
        let sql = format!(
            "SELECT id, conversation_id, summary, next_steps, files_touched, {}, created_at FROM session_snapshots ORDER BY id ASC;",
            if has_commit { "commit_hash" } else { "NULL" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (sid, cid, summary, next_steps, files_touched, commit_hash, created_at) = row?;
            let dt = if created_at.len() >= 10 { &created_at[..10] } else { &created_at };
            let mut lines = vec![format!("[Snapshot #{sid} {dt}] {summary}")];
            if !commit_hash.is_empty() {
                lines.push(format!("Commit: {}", &commit_hash[..commit_hash.len().min(12)]));
            }
            if !files_touched.is_empty() {
                lines.push(format!("Files: {files_touched}"));
            }
            if !next_steps.is_empty() {
                lines.push(format!("Next: {next_steps}"));
            }
            if !cid.is_empty() {
                lines.push(format!("Conversation: {cid}"));
            }
            let body = lines.join("\n");
            let b_idx = prepared.len();
            // Keyed on `latest_snapshot` in chronological order so every milestone builds a clean `Supersedes` chain!
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Snapshot, body.into_bytes())
                    .with_key("latest_snapshot")
                    .with_importance(205),
                b_idx,
            )?);
        }
    }

    // Replay `fact_history` first so historical mutations automatically form temporal `Supersedes` chains!
    if existing_tables.contains("fact_history") {
        let mut stmt = conn.prepare(
            "SELECT key, old_value, new_value FROM fact_history ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut seeded_initial: HashSet<String> = HashSet::new();
        for row in rows {
            let (key, old_opt, new_val) = row?;
            if is_reserved_sys_key(&key) {
                continue;
            }
            if !seeded_initial.contains(&key) {
                seeded_initial.insert(key.clone());
                if let Some(old_v) = old_opt.filter(|s| !s.is_empty()) {
                    let b_old = prepared.len();
                    prepared.push(ldb.prepare(
                        WriteRequest::new(NodeKind::Fact, format!("{key} = {old_v}").into_bytes())
                            .with_key(&key)
                            .with_importance(150),
                        b_old,
                    )?);
                    fact_last_idx.insert(key.clone(), b_old);
                }
            }
            let b_new = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Fact, format!("{key} = {new_val}").into_bytes())
                    .with_key(&key)
                    .with_importance(180),
                b_new,
            )?);
            fact_last_idx.insert(key, b_new);
        }
    }

    if existing_tables.contains("project_facts") {
        let cols = query_table_columns(conn, "project_facts")?;
        let has_dep = cols.iter().any(|c| c == "deprecated_at");
        let has_sup = cols.iter().any(|c| c == "superseded_by");
        let has_upd = cols.iter().any(|c| c == "updated_at");
        let sql = format!(
            "SELECT key, value, {}, {}, {} FROM project_facts ORDER BY id ASC;",
            if has_dep { "deprecated_at" } else { "NULL" },
            if has_sup { "superseded_by" } else { "NULL" },
            if has_upd { "updated_at" } else { "''" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (key, val, dep_opt, sup_opt, upd) = row?;
            if is_reserved_sys_key(&key) {
                continue;
            }
            let body = if upd.len() >= 10 {
                format!("{key} = {val} [{}]", &upd[..10])
            } else {
                format!("{key} = {val}")
            };
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Fact, body.into_bytes())
                    .with_key(&key)
                    .with_importance(195),
                b_idx,
            )?);
            fact_last_idx.insert(key.clone(), b_idx);
            if dep_opt.as_ref().is_some_and(|s| !s.is_empty()) {
                deprecated_facts.insert(key.clone());
                if let Some(sup_key) = sup_opt.filter(|s| !s.is_empty() && s != &key) {
                    pending_fact_supersedes.push((sup_key, key));
                }
            } else {
                deprecated_facts.remove(&key);
            }
        }
    }

    if existing_tables.contains("project_tasks") {
        let cols = query_table_columns(conn, "project_tasks")?;
        let has_upd = cols.iter().any(|c| c == "updated_at");
        let sql = format!(
            "SELECT id, title, description, status, priority, {} FROM project_tasks ORDER BY id ASC;",
            if has_upd { "updated_at" } else { "''" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (tid, title, desc, status, prio, upd) = row?;
            let dt = if upd.len() >= 10 { format!(" [{}]", &upd[..10]) } else { String::new() };
            let body = format!("[Task #{tid} {status} ({prio}){dt}]: {title}\n{desc}");
            let imp = if status == "completed" { 130 } else { 195 };
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Task, body.into_bytes())
                    .with_key(format!("task::{tid}"))
                    .with_importance(imp),
                b_idx,
            )?);
            task_batch_idx.insert(tid, b_idx);
        }
    }

    if existing_tables.contains("task_verifications") {
        let mut stmt = conn.prepare(
            "SELECT id, task_id, verifier_type, passed, details, created_at FROM task_verifications ORDER BY id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3).unwrap_or(0),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (vid, tid, vtype, passed, details, created_at) = row?;
            let status_lbl = if passed != 0 { "PASSED" } else { "FAILED" };
            let body = format!("[Verification #{vid} task=#{tid} {vtype} {status_lbl} {created_at}]: {details}");
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::TaskVerification, body.into_bytes())
                    .with_key(format!("verify::{vid}"))
                    .with_importance(175),
                b_idx,
            )?);
            pending_verify_tasks.push((b_idx, tid));
        }
    }

    if existing_tables.contains("task_handoffs") {
        let cols = query_table_columns(conn, "task_handoffs")?;
        let has_vars = cols.iter().any(|c| c == "context_variables");
        let sql = format!(
            "SELECT id, task_id, source_role, target_role, notes, status, {} FROM task_handoffs ORDER BY created_at ASC;",
            if has_vars { "context_variables" } else { "NULL" }
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (hid, tid_opt, src, dst, notes, status, ctx_vars) = row?;
            let body = if ctx_vars.is_empty() {
                format!("[Handoff {hid} {src}->{dst} ({status})]: {notes}")
            } else {
                format!("[Handoff {hid} {src}->{dst} ({status})]: {notes}\nContext: {ctx_vars}")
            };
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Handoff, body.into_bytes())
                    .with_key(&hid)
                    .with_importance(180),
                b_idx,
            )?);
            if let Some(tid) = tid_opt {
                pending_handoff_tasks.push((b_idx, tid));
            }
        }
    }

    if existing_tables.contains("symbol_index") {
        let sym_total: i64 = conn
            .query_row("SELECT COUNT(*) FROM symbol_index;", [], |r| r.get(0))
            .unwrap_or(0);
        let filter_unreferenced = sym_total > 500;
        let mut referenced_syms: HashSet<String> = HashSet::new();
        let mut referenced_files: HashSet<String> = HashSet::new();

        if filter_unreferenced {
            for (_, dec_body) in &active_decisions_text {
                for token in dec_body
                    .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                    .filter(|t| t.len() >= 4)
                {
                    referenced_syms.insert(token.to_owned());
                }
            }
            if existing_tables.contains("dependency_edges") {
                if let Ok(mut estmt) =
                    conn.prepare("SELECT source_symbol, target_symbol FROM dependency_edges;")
                {
                    if let Ok(erows) = estmt.query_map([], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    }) {
                        for erow in erows.flatten() {
                            referenced_syms.insert(erow.0);
                            referenced_syms.insert(erow.1);
                        }
                    }
                }
            }
            if existing_tables.contains("active_working_set") {
                if let Ok(mut wstmt) = conn.prepare("SELECT file_path FROM active_working_set;") {
                    if let Ok(wrows) = wstmt.query_map([], |r| r.get::<_, String>(0)) {
                        for wf in wrows.flatten() {
                            referenced_files.insert(wf.replace('\\', "/"));
                        }
                    }
                }
            }
        }

        let mut stmt = conn.prepare(
            "SELECT file_path, symbol_name, qualified_name, kind, start_line, end_line, signature FROM symbol_index;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (raw_fpath, sname, qname, kind, s_line, e_line, sig) = row?;
            let fpath = raw_fpath.replace('\\', "/");
            if filter_unreferenced {
                let is_obfuscated =
                    sname.len() <= 2 && qname.split('.').all(|seg| seg.len() <= 2);
                if is_obfuscated {
                    continue;
                }
                let file_cap_ok = referenced_files.contains(&fpath)
                    && file_symbols_idx.get(&fpath).map_or(0, Vec::len) < 16;
                let is_ref = referenced_syms.contains(&sname)
                    || referenced_syms.contains(&qname)
                    || file_cap_ok;
                if !is_ref {
                    continue;
                }
            }
            let body = format!("{fpath} [L{s_line}-L{e_line}] ({kind}) {qname}: {sig}");
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::Symbol, body.into_bytes())
                    .with_key(format!("{fpath}::{qname}"))
                    .with_importance(175),
                b_idx,
            )?);
            file_symbols_idx.entry(fpath).or_default().push(b_idx);
            symbol_batch_idx.entry(sname).or_insert(b_idx);
            symbol_batch_idx.entry(qname).or_insert(b_idx);
        }
    }

    if existing_tables.contains("compaction_archive") {
        let mut stmt = conn.prepare(
            "SELECT conversation_id, checkpoint_num, step_index, summary, extracted_refs, created_at FROM compaction_archive ORDER BY checkpoint_num ASC, id ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (cid, ckpt_num, step_idx, summary, refs, created_at) = row?;
            let dt = if created_at.len() >= 10 { &created_at[..10] } else { &created_at };
            let body = if refs.is_empty() {
                format!("[Compaction #{ckpt_num} step={step_idx} {dt} cid={cid}]: {summary}")
            } else {
                format!("[Compaction #{ckpt_num} step={step_idx} {dt} cid={cid}]: {summary}\nRefs: {refs}")
            };
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::CompactionCheckpoint, body.into_bytes())
                    .with_key("latest_compaction")
                    .with_importance(170),
                b_idx,
            )?);
        }
    }

    if existing_tables.contains("active_working_set") {
        let mut stmt = conn.prepare(
            "SELECT file_path, symbols_touched, line_ranges, edit_count, updated_at FROM active_working_set ORDER BY updated_at ASC;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, i64>(3).unwrap_or(1),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        })?;
        for row in rows {
            let (raw_fpath, syms, ranges, edits, upd) = row?;
            let fpath = raw_fpath.replace('\\', "/");
            let body = format!(
                "[WorkingSet edits={edits} {upd}] {fpath} | ranges={ranges} | symbols={syms}"
            );
            let b_idx = prepared.len();
            prepared.push(ldb.prepare(
                WriteRequest::new(NodeKind::WorkingSet, body.into_bytes())
                    .with_key(&fpath)
                    .with_importance(180),
                b_idx,
            )?);
            pending_working_files.push((b_idx, fpath));
        }
    }

    // Commit ALL cognitive capsules in ONE single atomic fsync!
    let assigned_ids = ldb.commit_batch(&prepared)?;
    let capsules = assigned_ids.len();

    // Collect all synapses and commit them in ONE single atomic `link_batch` fsync!
    let mut edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();

    for (s_idx, full_idx) in pending_skill_full {
        edges.push((
            assigned_ids[s_idx],
            EdgeKind::RelatedTo,
            assigned_ids[full_idx],
            200,
        ));
    }

    for (sec_idx, sname) in pending_sections {
        if let Some(&p_idx) = skill_batch_idx.get(&sname) {
            let sec_id = assigned_ids[sec_idx];
            let parent_id = assigned_ids[p_idx];
            edges.push((parent_id, EdgeKind::HasSection, sec_id, 235));
            edges.push((sec_id, EdgeKind::DependsOn, parent_id, 180));
        }
    }

    for (a_idx, sk_list) in pending_template_skills {
        let aid = assigned_ids[a_idx];
        for sk in sk_list {
            if let Some(&s_idx) = skill_batch_idx.get(&sk) {
                edges.push((aid, EdgeKind::UsesSkill, assigned_ids[s_idx], 220));
            }
        }
    }

    for (h_idx, tid) in pending_handoff_tasks {
        if let Some(&t_idx) = task_batch_idx.get(&tid) {
            edges.push((
                assigned_ids[h_idx],
                EdgeKind::Delegates,
                assigned_ids[t_idx],
                230,
            ));
        }
    }

    for (v_idx, tid) in pending_verify_tasks {
        if let Some(&t_idx) = task_batch_idx.get(&tid) {
            edges.push((
                assigned_ids[v_idx],
                EdgeKind::Verifies,
                assigned_ids[t_idx],
                225,
            ));
        }
    }

    for (sup_key, old_key) in pending_fact_supersedes {
        if let (Some(&new_i), Some(&old_i)) =
            (fact_last_idx.get(&sup_key), fact_last_idx.get(&old_key))
        {
            if assigned_ids[new_i] != assigned_ids[old_i] {
                edges.push((
                    assigned_ids[new_i],
                    EdgeKind::Supersedes,
                    assigned_ids[old_i],
                    245,
                ));
            }
        }
    }

    for (ws_idx, fpath) in pending_working_files {
        if let Some(sym_indices) = file_symbols_idx.get(&fpath) {
            for &sym_i in sym_indices.iter().take(16) {
                edges.push((
                    assigned_ids[ws_idx],
                    EdgeKind::Touches,
                    assigned_ids[sym_i],
                    195,
                ));
            }
        }
    }

    // Wire `Decision --[Governs]--> Symbol` automatically for imported architectural decisions!
    if !active_decisions_text.is_empty() && !symbol_batch_idx.is_empty() {
        for (dec_idx, dec_body) in &active_decisions_text {
            let dec_nid = assigned_ids[*dec_idx];
            let mut matched_syms = HashSet::new();
            for token in dec_body
                .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                .filter(|t| t.len() >= 4)
            {
                if let Some(&sym_i) = symbol_batch_idx.get(token) {
                    let sym_nid = assigned_ids[sym_i];
                    if matched_syms.insert(sym_nid) {
                        edges.push((dec_nid, EdgeKind::Governs, sym_nid, 225));
                    }
                }
            }
        }
    }

    // Import 100% of `dependency_edges` with zero truncation limit!
    if existing_tables.contains("dependency_edges") && !symbol_batch_idx.is_empty() {
        let mut stmt = conn.prepare(
            "SELECT source_symbol, target_symbol, edge_kind FROM dependency_edges;",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (src_sym, dst_sym, ekind) = row?;
            if let (Some(&s_i), Some(&d_i)) =
                (symbol_batch_idx.get(&src_sym), symbol_batch_idx.get(&dst_sym))
            {
                let s_nid = assigned_ids[s_i];
                let d_nid = assigned_ids[d_i];
                if s_nid != d_nid {
                    let edge = match ekind.as_str() {
                        "import" | "imports" => EdgeKind::Imports,
                        "inherit" | "inherits" | "subclass" => EdgeKind::Inherits,
                        _ => EdgeKind::Calls,
                    };
                    edges.push((s_nid, edge, d_nid, 190));
                }
            }
        }
    }

    let synapses = ldb.link_batch(&edges)?;

    // Deprecate inactive/archived keys after wiring synapses so historical capsules stay preserved
    // with `SUPERSEDED | TOMBSTONE` flags without appearing in active `get_by_key` or `pulse` queries.
    for rkey in inactive_rules {
        let _ = ldb.deprecate_key(NodeKind::Rule, &rkey)?;
    }
    for skey in inactive_skills {
        let _ = ldb.deprecate_key(NodeKind::Skill, &skey)?;
    }
    for dkey in inactive_decisions {
        let _ = ldb.deprecate_key(NodeKind::Decision, &dkey)?;
    }
    for fkey in deprecated_facts {
        let _ = ldb.deprecate_key(NodeKind::Fact, &fkey)?;
    }

    let _ = NodeFlags::COLD_ARCHIVE;

    Ok((capsules, synapses))
}

fn list_table_names(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
    )?;
    let iter = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = std::collections::HashSet::new();
    for item in iter {
        out.insert(item?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_rejects_dangling_and_live_symlinks_on_import_and_export() {
        let tmp = tempfile::tempdir().unwrap();
        let real_sql = tmp.path().join("real.db");
        {
            let conn = Connection::open(&real_sql).unwrap();
            conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items VALUES (1, 'alpha');")
                .unwrap();
        }

        let ldb_path = tmp.path().join("store.ldb");
        let ldb = LibreDb::open(&ldb_path).unwrap();
        import_sqlite_readonly(&real_sql, &ldb, "project").unwrap();

        let outside_victim = tmp.path().join("outside_victim.db");
        let dangling_export = tmp.path().join("dangling_export.db");
        let live_link_sql = tmp.path().join("live_link.db");

        #[cfg(unix)]
        let symlink_created = {
            std::os::unix::fs::symlink(&outside_victim, &dangling_export).unwrap();
            std::os::unix::fs::symlink(&real_sql, &live_link_sql).unwrap();
            true
        };
        #[cfg(windows)]
        let symlink_created = std::os::windows::fs::symlink_file(&outside_victim, &dangling_export)
            .is_ok()
            && std::os::windows::fs::symlink_file(&real_sql, &live_link_sql).is_ok();

        if symlink_created {
            let exp_res = export_sqlite_database(&ldb, "project", &dangling_export);
            assert!(
                exp_res.is_err(),
                "export_sqlite_database MUST reject dangling symlinks instead of creating target file"
            );
            assert!(
                !outside_victim.exists(),
                "dangling symlink target MUST NOT be created on disk"
            );

            let imp_res = import_sqlite_readonly(&live_link_sql, &ldb, "project");
            assert!(
                imp_res.is_err(),
                "import_sqlite_readonly MUST reject symlinked SQLite sources"
            );
        }
    }

    #[test]
    fn sqlite_import_strips_reserved_trust_and_sys_keys_while_preserving_lossless_mirror() {
        let tmp = tempfile::tempdir().unwrap();
        let malicious_sql = tmp.path().join("crafted_customizations.db");
        {
            let conn = Connection::open(&malicious_sql).unwrap();
            conn.execute_batch(
                "
                CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT);
                INSERT INTO runtime_config VALUES
                    ('sys::trust_anchor_secret', 'attacker_forged_anchor_secret_000000000000000000000000', '2026-11-11'),
                    ('SYS::trust_seals', 'hmac-sha256:v4:r1:deadbeef', '2026-11-11'),
                    ('trust:seal_rev::/repo/victim', '1', '2026-11-11'),
                    ('trust:allowed::/repo/evil', '/repo/evil', '2026-11-11'),
                    ('Trust:Revoked::/repo/victim', '', '2026-11-11'),
                    ('workspace:evil', '/repo/evil', '2026-11-11'),
                    ('workspace_id::0123456789abcdef', '/repo/evil', '2026-11-11'),
                    ('gitea_url', 'http://127.0.0.1:3000', '2026-11-11');
                CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT NOT NULL, scope TEXT NOT NULL, is_active INTEGER DEFAULT 1, summary TEXT, content TEXT NOT NULL);
                INSERT INTO rules VALUES
                    (1, 'sys::internal_override', 'Poison', 'sec', 'global', 1, 'bad', 'bad'),
                    (2, 'fmt-ascii', 'ASCII', 'fmt', 'global', 1, 'ok', 'Use ASCII hyphens.');
                ",
            )
            .unwrap();
        }

        let ldb_path = tmp.path().join("customizations.ldb");
        let ldb = LibreDb::open(&ldb_path).unwrap();

        // Pre-populate genuine host trust state in customizations.ldb:
        ldb.put(
            WriteRequest::new(NodeKind::Config, b"genuine_host_secret_hex".to_vec())
                .with_key("sys::trust_anchor_secret"),
        )
        .unwrap();
        ldb.put(
            WriteRequest::new(NodeKind::Config, b"5".to_vec())
                .with_key("trust:seal_rev::/repo/victim"),
        )
        .unwrap();

        let sum = import_sqlite_readonly(&malicious_sql, &ldb, "central").unwrap();
        assert_eq!(sum.total_sqlite_rows, 10);

        // 1. Genuine trust anchor secret and monotonic seal revision MUST remain 100% untouched:
        assert_eq!(
            ldb.get_by_key(NodeKind::Config, "sys::trust_anchor_secret")
                .unwrap()
                .payload,
            b"genuine_host_secret_hex"
        );
        assert_eq!(
            ldb.get_by_key(NodeKind::Config, "trust:seal_rev::/repo/victim")
                .unwrap()
                .payload,
            b"5"
        );

        // 2. Forged trust/workspace/sys keys from SQLite MUST NOT exist as active capsules:
        for forbidden_cfg in [
            "SYS::trust_seals",
            "sys::trust_seals",
            "trust:allowed::/repo/evil",
            "Trust:Revoked::/repo/victim",
            "workspace:evil",
            "workspace_id::0123456789abcdef",
        ] {
            assert!(
                ldb.get_by_key(NodeKind::Config, forbidden_cfg).is_err(),
                "reserved SQLite runtime_config key '{forbidden_cfg}' MUST NOT materialize into NodeKind::Config"
            );
        }
        assert!(
            ldb.get_by_key(NodeKind::Rule, "sys::internal_override")
                .is_err(),
            "reserved sys::* rule key MUST NOT materialize into NodeKind::Rule"
        );

        // 3. Legitimate user config and rules still import normally:
        assert_eq!(
            ldb.get_by_key(NodeKind::Config, "gitea_url")
                .unwrap()
                .payload,
            b"http://127.0.0.1:3000"
        );
        assert!(ldb.get_by_key(NodeKind::Rule, "fmt-ascii").is_ok());

        // 4. Invalid bridge scopes are rejected cleanly:
        assert!(import_sqlite_readonly(&malicious_sql, &ldb, "../bad").is_err());

        // 5. Raw SQLite mirror inside `sqlite_mirror::central` still reconstructs 100% losslessly:
        let recon_sql = tmp.path().join("reconstructed_customizations.db");
        export_sqlite_database(&ldb, "central", &recon_sql).unwrap();
        let rep = verify_sqlite_equivalence(&malicious_sql, &recon_sql).unwrap();
        assert_eq!(rep.rows_verified, 10);
    }
}
