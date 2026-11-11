//! `libredb-core`: Single-file Chaos-Extent-Inode cognitive storage kernel for LibreDB.
//!
//! Combines `SQLite`'s zero-configuration single-file portability, `PostgreSQL`'s concurrent
//! `MVCC` and strict typing discipline, logistics chaos-warehouse write lanes, and `ext4`-inspired
//! fixed `128-byte` `Inodes` with `64 KB` Gravity locality groups.

pub mod crc;
pub mod engine;
pub mod error;
pub mod format;
pub mod gravity;
pub mod io;

pub use engine::{
    CompactionReport, DbStats, LibreDb, NodeRecord, NodeSummary, PreparedWrite, RecallBundle,
    WriteRequest, SHARD_WRITE_LANES,
};
pub use error::{LibreDbError, Result};
pub use format::{
    EdgeKind, Inode, InodeStorage, NodeFlags, NodeKind, Superblock, Synapse, FORMAT_VERSION,
    INODE_SIZE, MAGIC,
};
pub use io::{FaultInjectingBackend, OsFileBackend, StorageBackend};

/// Returns true if `key` addresses a security-critical internal configuration namespace
/// (`sys::*`, `trust:*`, `workspace:*`, `workspace_id::*`) that must never be written,
/// overwritten, or deprecated via generic configuration commands, low-level `put`/`deprecate`,
/// or SQLite imports.
pub fn is_reserved_security_config_key(key: &str) -> bool {
    let low = key.trim().to_ascii_lowercase();
    low.starts_with("sys::")
        || low.starts_with("trust:")
        || low.starts_with("workspace:")
        || low.starts_with("workspace_id::")
}

/// Returns true if `key` addresses either a reserved internal trust/system namespace
/// (`is_reserved_security_config_key`) or a privileged host/MCP/guardrail security policy
/// switch (`mcp:*`, `gitea_allow_insecure_http`, `guardrail:allow_staged_files`) that must
/// never be imported from SQLite `runtime_config` or mutated via low-level `put`/`deprecate`.
pub fn is_admin_only_security_config_key(key: &str) -> bool {
    if is_reserved_security_config_key(key) {
        return true;
    }
    let low = key.trim().to_ascii_lowercase();
    low.starts_with("mcp:")
        || low == "gitea_allow_insecure_http"
        || low == "guardrail:allow_staged_files"
}

/// Returns true if `key` starts with the reserved internal system prefix `sys::` (case-insensitive).
pub fn is_reserved_sys_key(key: &str) -> bool {
    key.trim().to_ascii_lowercase().starts_with("sys::")
}
