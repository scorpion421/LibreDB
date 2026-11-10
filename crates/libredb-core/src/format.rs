//! Binary format definitions (`LIBREDB1`): Superblocks, 128-byte Inodes, Synapses, and Commit Frames.

use crate::crc::crc32;
use crate::error::{LibreDbError, Result};
use serde::{Deserialize, Serialize};

/// 8-byte file header magic identifying a LibreDB v1 file.
pub const MAGIC: [u8; 8] = *b"LIBREDB1";
/// 4-byte marker identifying an incremental chaos commit frame.
pub const COMMIT_FRAME_MAGIC: [u8; 4] = *b"LDBC";
/// 4-byte marker identifying a consolidated base snapshot frame.
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"LDBS";
/// Current binary wire format version.
pub const FORMAT_VERSION: u32 = 1;

/// Size of each ping-pong superblock slot (`Slot A` = `0..4096`, `Slot B` = `4096..8192`).
pub const SUPERBLOCK_SLOT_SIZE: u64 = 4096;
/// Byte offset where the data/chaos/snapshot region starts (`8 KB`).
pub const DATA_REGION_START: u64 = SUPERBLOCK_SLOT_SIZE * 2;

/// Fixed byte width of every Inode (`128 bytes` = exactly two 64-byte CPU cache lines).
pub const INODE_SIZE: usize = 128;
/// Maximum payload bytes stored directly inside the Inode (`0` additional disk reads).
pub const MAX_INLINE_BYTES: usize = 43;
/// Number of typed synapses stored inline inside every Inode header.
pub const INLINE_SYNAPSE_CAP: usize = 4;
/// Maximum single payload size (`256 MB`).
pub const MAX_EXTENT_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
/// Minimum payload length before attempting fast LZ4 compression.
pub const LZ4_MIN_COMPRESS_BYTES: usize = 96;
/// Target locality group size (`64 KB`, inspired by `ext4` block groups) during gravity compaction.
pub const GRAVITY_BLOCK_GROUP_BYTES: usize = 65_536;
/// Maximum 48-bit addressable NodeId (`281,474,976,710,655` nodes).
pub const MAX_NODE_ID: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Semantic node kinds covering all 19 SkillsDB entities plus generic cognitive capsules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeKind {
    Generic = 0,
    // Central customizations entities
    Rule = 1,
    Skill = 2,
    SkillSection = 3,
    SynonymCluster = 4,
    Config = 5,
    QuotaEvent = 6,
    TranscriptCursor = 7,
    AgentTemplate = 8,
    // Project memory and code-graph entities
    Decision = 10,
    Fact = 11,
    Snapshot = 12,
    CompactionCheckpoint = 13,
    Task = 14,
    TaskVerification = 15,
    Handoff = 16,
    Symbol = 17,
    WorkingSet = 18,
}

impl NodeKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Generic),
            1 => Ok(Self::Rule),
            2 => Ok(Self::Skill),
            3 => Ok(Self::SkillSection),
            4 => Ok(Self::SynonymCluster),
            5 => Ok(Self::Config),
            6 => Ok(Self::QuotaEvent),
            7 => Ok(Self::TranscriptCursor),
            8 => Ok(Self::AgentTemplate),
            10 => Ok(Self::Decision),
            11 => Ok(Self::Fact),
            12 => Ok(Self::Snapshot),
            13 => Ok(Self::CompactionCheckpoint),
            14 => Ok(Self::Task),
            15 => Ok(Self::TaskVerification),
            16 => Ok(Self::Handoff),
            17 => Ok(Self::Symbol),
            18 => Ok(Self::WorkingSet),
            other => Err(LibreDbError::InvalidNodeKind(other)),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Rule => "rule",
            Self::Skill => "skill",
            Self::SkillSection => "skill_section",
            Self::SynonymCluster => "synonym_cluster",
            Self::Config => "config",
            Self::QuotaEvent => "quota_event",
            Self::TranscriptCursor => "transcript_cursor",
            Self::AgentTemplate => "agent_template",
            Self::Decision => "decision",
            Self::Fact => "fact",
            Self::Snapshot => "snapshot",
            Self::CompactionCheckpoint => "compaction_checkpoint",
            Self::Task => "task",
            Self::TaskVerification => "task_verification",
            Self::Handoff => "handoff",
            Self::Symbol => "symbol",
            Self::WorkingSet => "working_set",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "generic" => Some(Self::Generic),
            "rule" | "rules" => Some(Self::Rule),
            "skill" | "skills" => Some(Self::Skill),
            "skill_section" | "section" => Some(Self::SkillSection),
            "synonym" | "synonym_cluster" => Some(Self::SynonymCluster),
            "config" | "runtime_config" => Some(Self::Config),
            "quota" | "quota_event" => Some(Self::QuotaEvent),
            "cursor" | "transcript_cursor" => Some(Self::TranscriptCursor),
            "agent" | "agent_template" => Some(Self::AgentTemplate),
            "decision" | "project_decision" => Some(Self::Decision),
            "fact" | "project_fact" => Some(Self::Fact),
            "snapshot" | "session_snapshot" => Some(Self::Snapshot),
            "checkpoint" | "compaction_checkpoint" => Some(Self::CompactionCheckpoint),
            "task" | "project_task" => Some(Self::Task),
            "verification" | "task_verification" => Some(Self::TaskVerification),
            "handoff" | "task_handoff" => Some(Self::Handoff),
            "symbol" | "symbol_index" => Some(Self::Symbol),
            "working_set" => Some(Self::WorkingSet),
            _ => None,
        }
    }
}

/// Directed cognitive and structural edge kinds ("synapses") stored in Inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum EdgeKind {
    RelatedTo = 1,
    HasSection = 2,
    UsesSkill = 3,
    Supersedes = 4,
    CausedBy = 5,
    Governs = 6,
    DependsOn = 7,
    Calls = 8,
    Imports = 9,
    Inherits = 10,
    Verifies = 11,
    Delegates = 12,
    Touches = 13,
}

impl EdgeKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::RelatedTo),
            2 => Ok(Self::HasSection),
            3 => Ok(Self::UsesSkill),
            4 => Ok(Self::Supersedes),
            5 => Ok(Self::CausedBy),
            6 => Ok(Self::Governs),
            7 => Ok(Self::DependsOn),
            8 => Ok(Self::Calls),
            9 => Ok(Self::Imports),
            10 => Ok(Self::Inherits),
            11 => Ok(Self::Verifies),
            12 => Ok(Self::Delegates),
            13 => Ok(Self::Touches),
            other => Err(LibreDbError::InvalidEdgeKind(other)),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelatedTo => "related_to",
            Self::HasSection => "has_section",
            Self::UsesSkill => "uses_skill",
            Self::Supersedes => "supersedes",
            Self::CausedBy => "caused_by",
            Self::Governs => "governs",
            Self::DependsOn => "depends_on",
            Self::Calls => "calls",
            Self::Imports => "imports",
            Self::Inherits => "inherits",
            Self::Verifies => "verifies",
            Self::Delegates => "delegates",
            Self::Touches => "touches",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "related" | "related_to" => Some(Self::RelatedTo),
            "has_section" | "section" => Some(Self::HasSection),
            "uses_skill" | "skill" => Some(Self::UsesSkill),
            "supersedes" | "replaces" => Some(Self::Supersedes),
            "caused_by" | "reason" => Some(Self::CausedBy),
            "governs" | "rules" => Some(Self::Governs),
            "depends_on" | "depends" => Some(Self::DependsOn),
            "calls" | "call" => Some(Self::Calls),
            "imports" | "import" => Some(Self::Imports),
            "inherits" | "extends" => Some(Self::Inherits),
            "verifies" | "verify" => Some(Self::Verifies),
            "delegates" | "handoff" => Some(Self::Delegates),
            "touches" | "edits" => Some(Self::Touches),
            _ => None,
        }
    }

    /// Returns true if this edge represents strong structural co-access affinity for Gravity clustering.
    #[inline]
    pub fn has_gravity_pull(self) -> bool {
        !matches!(self, Self::Supersedes)
    }
}

/// Bitmask flags stored in byte 9 of every Inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeFlags(pub u8);

impl NodeFlags {
    pub const ACTIVE: u8 = 0b0000_0001;
    pub const SUPERSEDED: u8 = 0b0000_0010;
    pub const PINNED: u8 = 0b0000_0100;
    pub const INLINE_DATA: u8 = 0b0000_1000;
    pub const COLD_ARCHIVE: u8 = 0b0001_0000;
    pub const COMPRESSED_LZ4: u8 = 0b0010_0000;
    pub const TOMBSTONE: u8 = 0b0100_0000;

    #[inline]
    pub fn contains(self, mask: u8) -> bool {
        (self.0 & mask) != 0
    }

    #[inline]
    pub fn insert(&mut self, mask: u8) {
        self.0 |= mask;
    }

    #[inline]
    pub fn remove(&mut self, mask: u8) {
        self.0 &= !mask;
    }

    #[inline]
    pub fn is_live_active(self) -> bool {
        self.contains(Self::ACTIVE)
            && !self.contains(Self::SUPERSEDED)
            && !self.contains(Self::TOMBSTONE)
    }
}

/// Compact 8-byte directed edge (`1B kind + 1B weight + 6B 48-bit target NodeId`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synapse {
    pub kind: EdgeKind,
    pub weight: u8,
    pub target_id: u64,
}

impl Synapse {
    pub fn new(kind: EdgeKind, weight: u8, target_id: u64) -> Result<Self> {
        if target_id == 0 || target_id > MAX_NODE_ID {
            return Err(LibreDbError::NodeIdOverflow(target_id));
        }
        Ok(Self {
            kind,
            weight,
            target_id,
        })
    }

    pub fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.kind as u8;
        out[1] = self.weight;
        let id_bytes = self.target_id.to_le_bytes();
        out[2..8].copy_from_slice(&id_bytes[0..6]);
        out
    }

    pub fn decode(bytes: [u8; 8]) -> Result<Option<Self>> {
        if bytes[0] == 0 {
            return Ok(None);
        }
        let kind = EdgeKind::from_u8(bytes[0])?;
        let weight = bytes[1];
        let mut id_buf = [0u8; 8];
        id_buf[0..6].copy_from_slice(&bytes[2..8]);
        let target_id = u64::from_le_bytes(id_buf);
        if target_id == 0 {
            return Err(LibreDbError::CorruptFormat("synapse has zero target_id"));
        }
        Ok(Some(Self {
            kind,
            weight,
            target_id,
        }))
    }
}

/// Storage location of a node's payload inside bytes `48..92` of the 128-byte Inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeStorage {
    /// Tiny payload (`<= 43 bytes`) embedded directly inside the Inode (`0` extent reads).
    Inline {
        len: u8,
        bytes: [u8; MAX_INLINE_BYTES],
    },
    /// Contiguous extent in the file body, plus optional overflow synapse extent and vector slot.
    Extent {
        data_offset: u64,
        raw_len: u32,
        stored_len: u32,
        data_crc32: u32,
        edge_extent_offset: u64,
        edge_overflow_count: u32,
        vector_reserved: [u8; 12],
    },
}

/// Fixed 128-byte cache-line-aligned metadata card ("neuron") for a single memory object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    pub node_id: u64,
    pub kind: NodeKind,
    pub flags: NodeFlags,
    pub importance: u8,
    pub token_count: u32,
    pub created_ns: u64,
    pub updated_ns: u64,
    pub access_count: u32,
    pub generation: u32,
    pub key_hash: u64,
    pub storage: InodeStorage,
    pub inline_synapses: [Option<Synapse>; INLINE_SYNAPSE_CAP],
}

impl Inode {
    /// Returns the uncompressed payload byte length.
    pub fn raw_payload_len(&self) -> usize {
        match self.storage {
            InodeStorage::Inline { len, .. } => len as usize,
            InodeStorage::Extent { raw_len, .. } => raw_len as usize,
        }
    }

    /// Returns the number of inline synapses populated in `inline_synapses`.
    pub fn inline_synapse_len(&self) -> usize {
        self.inline_synapses.iter().filter(|s| s.is_some()).count()
    }

    /// Encodes the Inode into its exact 128-byte little-endian disk representation with CRC32.
    pub fn encode(&self) -> [u8; INODE_SIZE] {
        let mut buf = [0u8; INODE_SIZE];
        let mut flags = self.flags;
        match self.storage {
            InodeStorage::Inline { .. } => flags.insert(NodeFlags::INLINE_DATA),
            InodeStorage::Extent { .. } => flags.remove(NodeFlags::INLINE_DATA),
        }

        let inline_syn_cnt = self.inline_synapse_len() as u8;

        buf[0..8].copy_from_slice(&self.node_id.to_le_bytes());
        buf[8] = self.kind as u8;
        buf[9] = flags.0;
        buf[10] = self.importance;
        buf[11] = inline_syn_cnt;
        buf[12..16].copy_from_slice(&self.token_count.to_le_bytes());
        buf[16..24].copy_from_slice(&self.created_ns.to_le_bytes());
        buf[24..32].copy_from_slice(&self.updated_ns.to_le_bytes());
        buf[32..36].copy_from_slice(&self.access_count.to_le_bytes());
        buf[36..40].copy_from_slice(&self.generation.to_le_bytes());
        buf[40..48].copy_from_slice(&self.key_hash.to_le_bytes());

        match self.storage {
            InodeStorage::Inline { len, bytes } => {
                let capped = len.min(MAX_INLINE_BYTES as u8);
                buf[48] = capped;
                buf[49..49 + (capped as usize)].copy_from_slice(&bytes[..capped as usize]);
            }
            InodeStorage::Extent {
                data_offset,
                raw_len,
                stored_len,
                data_crc32,
                edge_extent_offset,
                edge_overflow_count,
                vector_reserved,
            } => {
                buf[48..56].copy_from_slice(&data_offset.to_le_bytes());
                buf[56..60].copy_from_slice(&raw_len.to_le_bytes());
                buf[60..64].copy_from_slice(&stored_len.to_le_bytes());
                buf[64..68].copy_from_slice(&data_crc32.to_le_bytes());
                buf[68..76].copy_from_slice(&edge_extent_offset.to_le_bytes());
                buf[76..80].copy_from_slice(&edge_overflow_count.to_le_bytes());
                buf[80..92].copy_from_slice(&vector_reserved);
            }
        }

        // Bytes 92..124 always store the 4 inline synapses regardless of Inline vs Extent mode.
        let mut slot_idx = 0usize;
        for syn in self.inline_synapses.iter().flatten() {
            if slot_idx < INLINE_SYNAPSE_CAP {
                let start = 92 + slot_idx * 8;
                buf[start..start + 8].copy_from_slice(&syn.encode());
                slot_idx += 1;
            }
        }

        let checksum = crc32(&buf[0..124]);
        buf[124..128].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    /// Decodes and CRC-verifies a 128-byte Inode record.
    pub fn decode(buf: &[u8; INODE_SIZE]) -> Result<Self> {
        let expected_crc = u32::from_le_bytes(buf[124..128].try_into().unwrap());
        let actual_crc = crc32(&buf[0..124]);
        if expected_crc != actual_crc {
            return Err(LibreDbError::ChecksumMismatch {
                context: "inode",
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let node_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        if node_id == 0 {
            return Err(LibreDbError::CorruptFormat("decoded inode with node_id 0"));
        }
        let kind = NodeKind::from_u8(buf[8])?;
        let flags = NodeFlags(buf[9]);
        let importance = buf[10];
        let inline_syn_cnt = buf[11] as usize;
        if inline_syn_cnt > INLINE_SYNAPSE_CAP {
            return Err(LibreDbError::CorruptFormat("inline_synapse_count > 4"));
        }

        let token_count = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let created_ns = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let updated_ns = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let access_count = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        let generation = u32::from_le_bytes(buf[36..40].try_into().unwrap());
        let key_hash = u64::from_le_bytes(buf[40..48].try_into().unwrap());

        let storage = if flags.contains(NodeFlags::INLINE_DATA) {
            let len = buf[48];
            if (len as usize) > MAX_INLINE_BYTES {
                return Err(LibreDbError::CorruptFormat("inline payload length > 43"));
            }
            let mut bytes = [0u8; MAX_INLINE_BYTES];
            bytes[..len as usize].copy_from_slice(&buf[49..49 + (len as usize)]);
            InodeStorage::Inline { len, bytes }
        } else {
            let data_offset = u64::from_le_bytes(buf[48..56].try_into().unwrap());
            let raw_len = u32::from_le_bytes(buf[56..60].try_into().unwrap());
            let stored_len = u32::from_le_bytes(buf[60..64].try_into().unwrap());
            let data_crc32 = u32::from_le_bytes(buf[64..68].try_into().unwrap());
            let edge_extent_offset = u64::from_le_bytes(buf[68..76].try_into().unwrap());
            let edge_overflow_count = u32::from_le_bytes(buf[76..80].try_into().unwrap());
            let mut vector_reserved = [0u8; 12];
            vector_reserved.copy_from_slice(&buf[80..92]);
            InodeStorage::Extent {
                data_offset,
                raw_len,
                stored_len,
                data_crc32,
                edge_extent_offset,
                edge_overflow_count,
                vector_reserved,
            }
        };

        let mut inline_synapses = [None; INLINE_SYNAPSE_CAP];
        for (i, slot) in inline_synapses.iter_mut().enumerate() {
            let start = 92 + i * 8;
            let raw_syn: [u8; 8] = buf[start..start + 8].try_into().unwrap();
            *slot = Synapse::decode(raw_syn)?;
        }

        Ok(Self {
            node_id,
            kind,
            flags,
            importance,
            token_count,
            created_ns,
            updated_ns,
            access_count,
            generation,
            key_hash,
            storage,
            inline_synapses,
        })
    }
}

/// 4 KB ping-pong root block (`Slot A` at `0..4096`, `Slot B` at `4096..8192`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub version: u32,
    pub flags: u32,
    pub commit_seq: u64,
    pub next_node_id: u64,
    pub active_node_count: u64,
    pub base_snapshot_offset: u64,
    pub base_snapshot_len: u64,
    pub delta_start_offset: u64,
    pub data_tail_offset: u64,
    pub created_ns: u64,
    pub last_commit_ns: u64,
    pub compaction_count: u64,
}

impl Superblock {
    pub fn initial(now_ns: u64) -> Self {
        Self {
            version: FORMAT_VERSION,
            flags: 0,
            commit_seq: 1,
            next_node_id: 1,
            active_node_count: 0,
            base_snapshot_offset: 0,
            base_snapshot_len: 0,
            delta_start_offset: DATA_REGION_START,
            data_tail_offset: DATA_REGION_START,
            created_ns: now_ns,
            last_commit_ns: now_ns,
            compaction_count: 0,
        }
    }

    pub fn encode(&self) -> [u8; SUPERBLOCK_SLOT_SIZE as usize] {
        let mut buf = [0u8; SUPERBLOCK_SLOT_SIZE as usize];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&self.commit_seq.to_le_bytes());
        buf[24..32].copy_from_slice(&self.next_node_id.to_le_bytes());
        buf[32..40].copy_from_slice(&self.active_node_count.to_le_bytes());
        buf[40..48].copy_from_slice(&self.base_snapshot_offset.to_le_bytes());
        buf[48..56].copy_from_slice(&self.base_snapshot_len.to_le_bytes());
        buf[56..64].copy_from_slice(&self.delta_start_offset.to_le_bytes());
        buf[64..72].copy_from_slice(&self.data_tail_offset.to_le_bytes());
        buf[72..80].copy_from_slice(&self.created_ns.to_le_bytes());
        buf[80..88].copy_from_slice(&self.last_commit_ns.to_le_bytes());
        buf[88..96].copy_from_slice(&self.compaction_count.to_le_bytes());

        let checksum = crc32(&buf[0..96]);
        buf[96..100].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; SUPERBLOCK_SLOT_SIZE as usize]) -> Result<Self> {
        if buf[0..8] != MAGIC {
            return Err(LibreDbError::InvalidMagic);
        }
        let expected_crc = u32::from_le_bytes(buf[96..100].try_into().unwrap());
        let actual_crc = crc32(&buf[0..96]);
        if expected_crc != actual_crc {
            return Err(LibreDbError::ChecksumMismatch {
                context: "superblock",
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(LibreDbError::UnsupportedVersion(version));
        }

        let sb = Self {
            version,
            flags: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            commit_seq: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            next_node_id: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            active_node_count: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            base_snapshot_offset: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            base_snapshot_len: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            delta_start_offset: u64::from_le_bytes(buf[56..64].try_into().unwrap()),
            data_tail_offset: u64::from_le_bytes(buf[64..72].try_into().unwrap()),
            created_ns: u64::from_le_bytes(buf[72..80].try_into().unwrap()),
            last_commit_ns: u64::from_le_bytes(buf[80..88].try_into().unwrap()),
            compaction_count: u64::from_le_bytes(buf[88..96].try_into().unwrap()),
        };

        if sb.delta_start_offset < DATA_REGION_START || sb.data_tail_offset < sb.delta_start_offset {
            return Err(LibreDbError::CorruptFormat("superblock offsets out of bounds"));
        }
        Ok(sb)
    }
}

/// Key-directory mutation persisted inside a `CommitFrame` or `BaseSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMutation {
    Upsert {
        kind: NodeKind,
        key: String,
        node_id: u64,
    },
    Remove {
        kind: NodeKind,
        key: String,
    },
}

/// Encodes an incremental `CommitFrame` (`LDBC`) or `BaseSnapshot` (`LDBS`) with a CRC32 trailer.
///
/// Binary layout:
/// - `0..4`: `magic` (`LDBC` or `LDBS`)
/// - `4..8`: `total_frame_bytes: u32` (including header and 4-byte CRC trailer)
/// - `8..16`: `commit_seq: u64`
/// - `16..20`: `inode_count: u32`
/// - `20..24`: `key_mutation_count: u32`
/// - `inodes`: `inode_count * 128` bytes
/// - `key_mutations`: variable-length `(op: u8, kind: u8, key_len: u16, node_id: u64, key_utf8)`
/// - `last 4 bytes`: `frame_crc32: u32`
pub fn encode_metadata_frame(
    magic: [u8; 4],
    commit_seq: u64,
    inodes: &[Inode],
    key_ops: &[KeyMutation],
) -> Result<Vec<u8>> {
    let key_bytes_est: usize = key_ops
        .iter()
        .map(|op| match op {
            KeyMutation::Upsert { key, .. } => 12 + key.len(),
            KeyMutation::Remove { key, .. } => 12 + key.len(),
        })
        .sum();
    let mut buf = Vec::with_capacity(24 + inodes.len() * INODE_SIZE + key_bytes_est + 4);

    buf.extend_from_slice(&magic);
    buf.extend_from_slice(&0u32.to_le_bytes()); // placeholder for total_frame_bytes
    buf.extend_from_slice(&commit_seq.to_le_bytes());
    buf.extend_from_slice(&(inodes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(key_ops.len() as u32).to_le_bytes());

    for inode in inodes {
        buf.extend_from_slice(&inode.encode());
    }

    for op in key_ops {
        match op {
            KeyMutation::Upsert { kind, key, node_id } => {
                let kb = key.as_bytes();
                if kb.len() > u16::MAX as usize {
                    return Err(LibreDbError::CorruptFormat("key exceeds 65535 bytes"));
                }
                buf.push(1u8);
                buf.push(*kind as u8);
                buf.extend_from_slice(&(kb.len() as u16).to_le_bytes());
                buf.extend_from_slice(&node_id.to_le_bytes());
                buf.extend_from_slice(kb);
            }
            KeyMutation::Remove { kind, key } => {
                let kb = key.as_bytes();
                if kb.len() > u16::MAX as usize {
                    return Err(LibreDbError::CorruptFormat("key exceeds 65535 bytes"));
                }
                buf.push(2u8);
                buf.push(*kind as u8);
                buf.extend_from_slice(&(kb.len() as u16).to_le_bytes());
                buf.extend_from_slice(&0u64.to_le_bytes());
                buf.extend_from_slice(kb);
            }
        }
    }

    let total_len = (buf.len() + 4) as u32;
    buf[4..8].copy_from_slice(&total_len.to_le_bytes());

    let frame_crc = crc32(&buf);
    buf.extend_from_slice(&frame_crc.to_le_bytes());
    Ok(buf)
}

/// Decodes and CRC-verifies a `CommitFrame` or `BaseSnapshot` buffer.
pub fn decode_metadata_frame(
    expected_magic: [u8; 4],
    buf: &[u8],
) -> Result<(u64, Vec<Inode>, Vec<KeyMutation>)> {
    if buf.len() < 28 {
        return Err(LibreDbError::CorruptFormat("metadata frame shorter than 28 bytes"));
    }
    if buf[0..4] != expected_magic {
        return Err(LibreDbError::CorruptFormat("metadata frame magic mismatch"));
    }
    let declared_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if declared_len != buf.len() {
        return Err(LibreDbError::CorruptFormat("metadata frame length mismatch"));
    }

    let payload_end = buf.len() - 4;
    let expected_crc = u32::from_le_bytes(buf[payload_end..].try_into().unwrap());
    let actual_crc = crc32(&buf[..payload_end]);
    if expected_crc != actual_crc {
        return Err(LibreDbError::ChecksumMismatch {
            context: "metadata_frame",
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    let commit_seq = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let inode_count = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
    let key_op_count = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;

    let mut pos = 24usize;
    let inodes_end = pos
        .checked_add(inode_count.checked_mul(INODE_SIZE).ok_or(LibreDbError::CorruptFormat("inode count overflow"))?)
        .ok_or(LibreDbError::CorruptFormat("inode slice overflow"))?;
    if inodes_end > payload_end {
        return Err(LibreDbError::CorruptFormat("inode array truncated in frame"));
    }

    let mut inodes = Vec::with_capacity(inode_count);
    while pos < inodes_end {
        let raw: &[u8; INODE_SIZE] = buf[pos..pos + INODE_SIZE].try_into().unwrap();
        inodes.push(Inode::decode(raw)?);
        pos += INODE_SIZE;
    }

    let max_possible_key_ops = (payload_end - pos) / 12;
    if key_op_count > max_possible_key_ops {
        return Err(LibreDbError::CorruptFormat(
            "key mutation count exceeds remaining frame bounds",
        ));
    }
    let mut key_ops = Vec::with_capacity(key_op_count);
    for _ in 0..key_op_count {
        if pos + 12 > payload_end {
            return Err(LibreDbError::CorruptFormat("key mutation header truncated"));
        }
        let op = buf[pos];
        let kind = NodeKind::from_u8(buf[pos + 1])?;
        let key_len = u16::from_le_bytes(buf[pos + 2..pos + 4].try_into().unwrap()) as usize;
        let node_id = u64::from_le_bytes(buf[pos + 4..pos + 12].try_into().unwrap());
        pos += 12;

        if pos + key_len > payload_end {
            return Err(LibreDbError::CorruptFormat("key mutation bytes truncated"));
        }
        let key = std::str::from_utf8(&buf[pos..pos + key_len])
            .map_err(|_| LibreDbError::CorruptFormat("invalid UTF-8 in key mutation"))?
            .to_owned();
        pos += key_len;

        match op {
            1 => key_ops.push(KeyMutation::Upsert { kind, key, node_id }),
            2 => key_ops.push(KeyMutation::Remove { kind, key }),
            _ => return Err(LibreDbError::CorruptFormat("unknown key mutation opcode")),
        }
    }

    if pos != payload_end {
        return Err(LibreDbError::CorruptFormat("trailing unparsed bytes in metadata frame"));
    }

    Ok((commit_seq, inodes, key_ops))
}

/// Aligns `offset` upward to the next multiple of `align` (`align` must be a power of two).
#[inline]
pub const fn align_up(offset: u64, align: u64) -> u64 {
    let mask = align - 1;
    (offset + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted_metadata_frame_with_huge_key_op_count_fails_without_oom() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&COMMIT_FRAME_MAGIC);
        frame.extend_from_slice(&28u32.to_le_bytes()); // total_frame_bytes = 28
        frame.extend_from_slice(&1u64.to_le_bytes()); // commit_seq = 1
        frame.extend_from_slice(&0u32.to_le_bytes()); // inode_count = 0
        frame.extend_from_slice(&u32::MAX.to_le_bytes()); // adversarial key_op_count = 4,294,967,295
        let crc = crc32(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());

        let res = decode_metadata_frame(COMMIT_FRAME_MAGIC, &frame);
        assert!(matches!(res, Err(LibreDbError::CorruptFormat(_))));
    }
}
