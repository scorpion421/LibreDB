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
