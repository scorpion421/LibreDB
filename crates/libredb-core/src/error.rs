//! Error definitions for the LibreDB storage kernel.

use crate::format::NodeKind;
use thiserror::Error;

/// Canonical result alias for all LibreDB storage operations.
pub type Result<T> = std::result::Result<T, LibreDbError>;

/// Strongly typed storage, integrity, and concurrency errors.
#[derive(Debug, Error)]
pub enum LibreDbError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid file magic header (expected LIBREDB1)")]
    InvalidMagic,

    #[error("unsupported LibreDB format version: {0}")]
    UnsupportedVersion(u32),

    #[error("no valid superblock found in slot A or slot B")]
    NoValidSuperblock,

    #[error("CRC32 checksum mismatch in {context}: expected 0x{expected:08x}, got 0x{actual:08x}")]
    ChecksumMismatch {
        context: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("corrupt binary structure: {0}")]
    CorruptFormat(&'static str),

    #[error("unrecognized node kind discriminant: {0}")]
    InvalidNodeKind(u8),

    #[error("unrecognized edge kind discriminant: {0}")]
    InvalidEdgeKind(u8),

    #[error("node ID {0} not found")]
    NodeNotFound(u64),

    #[error("key '{key}' for kind {kind:?} not found")]
    KeyNotFound { kind: NodeKind, key: String },

    #[error("optimistic generation conflict on node {node_id}: expected gen {expected}, found {actual}")]
    GenerationConflict {
        node_id: u64,
        expected: u32,
        actual: u32,
    },

    #[error("payload size {size} bytes exceeds maximum extent limit ({max} bytes)")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("node ID {0} exceeds 48-bit synapse address space")]
    NodeIdOverflow(u64),

    #[error("LZ4 decompression failed: {0}")]
    Decompression(String),

    #[error("injected fault during simulated crash test at write #{0}")]
    SimulatedPowerLoss(u64),
}
