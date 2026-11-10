//! Core `LibreDb` storage and cognitive memory engine.

use crate::crc::{count_tokens_exact, crc32, hash_key};
use crate::error::{LibreDbError, Result};
use crate::format::{
    align_up, decode_metadata_frame, encode_metadata_frame, EdgeKind, Inode, InodeStorage,
    KeyMutation, NodeFlags, NodeKind, Superblock, Synapse, COMMIT_FRAME_MAGIC, DATA_REGION_START,
    INLINE_SYNAPSE_CAP, LZ4_MIN_COMPRESS_BYTES, MAX_EXTENT_PAYLOAD_BYTES, MAX_INLINE_BYTES,
    SNAPSHOT_MAGIC, SUPERBLOCK_SLOT_SIZE,
};
use crate::gravity::compute_gravity_plan;
use crate::io::{OsFileBackend, StorageBackend};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

struct IpcWriteGuard<'a>(&'a dyn StorageBackend);

impl<'a> IpcWriteGuard<'a> {
    fn acquire(backend: &'a dyn StorageBackend) -> Result<Self> {
        backend.lock_write_region()?;
        Ok(Self(backend))
    }
}

impl Drop for IpcWriteGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock_write_region();
    }
}

/// Number of independent lock-free preparation lanes for concurrent writers.
pub const SHARD_WRITE_LANES: usize = 16;

/// Input specification for writing a cognitive capsule into LibreDB.
#[derive(Debug, Clone)]
pub struct WriteRequest {
    pub kind: NodeKind,
    /// Optional logical unique key within `kind` (e.g., rule key, skill name, fact key).
    /// Writing to an existing `(kind, key)` automatically marks the prior node `SUPERSEDED`
    /// and wires a `Supersedes` synapse from the new node to the prior node.
    pub key: Option<String>,
    pub payload: Vec<u8>,
    pub importance: u8,
    pub pinned: bool,
    pub synapses: Vec<Synapse>,
}

impl WriteRequest {
    pub fn new(kind: NodeKind, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            key: None,
            payload: payload.into(),
            importance: 128,
            pinned: false,
            synapses: Vec::new(),
        }
    }

    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    pub fn with_importance(mut self, importance: u8) -> Self {
        self.importance = importance;
        self
    }

    pub fn with_pinned(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    pub fn with_synapses(mut self, synapses: Vec<Synapse>) -> Self {
        self.synapses = synapses;
        self
    }
}

/// CPU-heavy compression, hashing, and token counting pre-computed on one of 16 sharded lanes
/// before acquiring the lightweight append commit lock.
#[derive(Debug, Clone)]
pub struct PreparedWrite {
    pub lane_id: usize,
    pub kind: NodeKind,
    pub key: Option<String>,
    pub key_hash: u64,
    pub token_count: u32,
    pub importance: u8,
    pub flags: NodeFlags,
    pub raw_len: u32,
    pub encoded_payload: EncodedPayload,
    pub synapses: Vec<Synapse>,
}

#[derive(Debug, Clone)]
pub enum EncodedPayload {
    Inline {
        len: u8,
        bytes: [u8; MAX_INLINE_BYTES],
    },
    Extent {
        bytes: Vec<u8>,
        crc32: u32,
        compressed: bool,
    },
}

/// Hydrated record returned by `get` or `get_by_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: u64,
    pub kind: NodeKind,
    pub flags: NodeFlags,
    pub importance: u8,
    pub token_count: u32,
    pub created_ns: u64,
    pub updated_ns: u64,
    pub access_count: u32,
    pub generation: u32,
    pub synapses: Vec<Synapse>,
    pub payload: Vec<u8>,
}

/// Lightweight metadata summary returned by causal `trace_lineage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSummary {
    pub depth: usize,
    pub via_edge: Option<EdgeKind>,
    pub node_id: u64,
    pub kind: NodeKind,
    pub is_active: bool,
    pub is_superseded: bool,
    pub token_count: u32,
    pub importance: u8,
    pub updated_ns: u64,
    pub payload_preview: String,
}

/// Result of a token-budgeted spreading-activation `recall_within_budget` query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallBundle {
    pub records: Vec<NodeRecord>,
    pub total_tokens: u32,
    pub token_budget: u32,
    /// Actual `StorageBackend::read_at` calls issued after coalescing adjacent Gravity extents.
    pub coalesced_io_reads: usize,
}

/// Summary statistics returned after `compact_with_gravity`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CompactionReport {
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub hot_nodes_packed: usize,
    pub cold_nodes_archived: usize,
    pub locality_groups: usize,
    pub commit_seq: u64,
}

/// Summary diagnostics returned by `stats` and `verify_integrity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    pub file_bytes: u64,
    pub commit_seq: u64,
    pub compaction_count: u64,
    pub total_inodes: usize,
    pub active_nodes: usize,
    pub superseded_nodes: usize,
    pub inline_nodes: usize,
    pub compressed_nodes: usize,
    pub keyed_entries: usize,
    pub total_tokens_active: u64,
    pub backend_read_ops: u64,
    pub backend_write_ops: u64,
    pub is_network_share: bool,
}

/// Immutable MVCC snapshot shared lock-free across concurrent readers via `Arc`.
struct SnapshotState {
    superblock: Superblock,
    inodes: HashMap<u64, Inode>,
    /// Overflow synapses (`> 4`) cached in memory alongside Inodes for `O(1)` zero-hop graph walks.
    overflow_synapses: HashMap<u64, Vec<Synapse>>,
    /// Active logical key directory `(kind, key) -> active_node_id`.
    key_dir: HashMap<(NodeKind, String), u64>,
    /// Reverse lookup `node_id -> (kind, key)` for lossless snapshot serialization.
    reverse_keys: HashMap<u64, (NodeKind, String)>,
}

/// Per-node runtime access reinforcement counters merged into Inodes on mutation/compaction.
#[derive(Default)]
struct AccessTelemetry {
    bumps: RwLock<HashMap<u64, AtomicU32>>,
}

impl AccessTelemetry {
    fn record_hit(&self, node_id: u64) {
        if let Some(counter) = self.bumps.read().get(&node_id) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.bumps
            .write()
            .entry(node_id)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    fn pending_hits(&self, node_id: u64) -> u32 {
        self.bumps
            .read()
            .get(&node_id)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    fn drain_hits(&self, node_id: u64) -> u32 {
        self.bumps
            .read()
            .get(&node_id)
            .map_or(0, |c| c.swap(0, Ordering::Relaxed))
    }
}

/// Thread-safe (`Send + Sync`) single-file Chaos-Extent-Inode cognitive database engine.
pub struct LibreDb {
    backend: Arc<dyn StorageBackend>,
    state: RwLock<Arc<SnapshotState>>,
    /// Serializes physical tail append & superblock flips while allowing 100% parallel preparation & reads.
    commit_lock: Mutex<()>,
    /// 16 sharded lane counters proving parallel lane distribution under concurrent workloads.
    lane_counters: [AtomicU32; SHARD_WRITE_LANES],
    telemetry: AccessTelemetry,
}

impl LibreDb {
    /// Opens an existing `.ldb` file or initializes a new single-file database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let backend = Arc::new(OsFileBackend::open(path)?);
        Self::open_with_backend(backend)
    }

    /// Opens or initializes a database on any `StorageBackend` (OS file or fault simulator).
    pub fn open_with_backend(backend: Arc<dyn StorageBackend>) -> Result<Self> {
        let file_len = backend.len()?;
        let snapshot = if file_len == 0 {
            Self::initialize_fresh(&*backend)?
        } else {
            Self::recover_existing(&*backend, file_len)?
        };

        Ok(Self {
            backend,
            state: RwLock::new(Arc::new(snapshot)),
            commit_lock: Mutex::new(()),
            lane_counters: std::array::from_fn(|_| AtomicU32::new(0)),
            telemetry: AccessTelemetry::default(),
        })
    }

    fn initialize_fresh(backend: &dyn StorageBackend) -> Result<SnapshotState> {
        let now = now_unix_ns();
        let sb = Superblock::initial(now);
        let encoded_a = sb.encode();
        let zero_b = [0u8; SUPERBLOCK_SLOT_SIZE as usize];

        backend.write_at(0, &encoded_a)?;
        backend.write_at(SUPERBLOCK_SLOT_SIZE, &zero_b)?;
        backend.sync_data()?;

        Ok(SnapshotState {
            superblock: sb,
            inodes: HashMap::new(),
            overflow_synapses: HashMap::new(),
            key_dir: HashMap::new(),
            reverse_keys: HashMap::new(),
        })
    }

    fn recover_existing(backend: &dyn StorageBackend, file_len: u64) -> Result<SnapshotState> {
        if file_len < DATA_REGION_START {
            return Err(LibreDbError::NoValidSuperblock);
        }

        let mut buf_a = [0u8; SUPERBLOCK_SLOT_SIZE as usize];
        let mut buf_b = [0u8; SUPERBLOCK_SLOT_SIZE as usize];
        let res_a = backend.read_at(0, &mut buf_a).and_then(|_| Superblock::decode(&buf_a));
        let res_b = backend
            .read_at(SUPERBLOCK_SLOT_SIZE, &mut buf_b)
            .and_then(|_| Superblock::decode(&buf_b));

        let sb = match (res_a, res_b) {
            (Ok(a), Ok(b)) => {
                // Pick the highest commit_seq whose declared data_tail_offset physically exists in file_len.
                let a_fits = a.data_tail_offset <= file_len;
                let b_fits = b.data_tail_offset <= file_len;
                match (a_fits, b_fits) {
                    (true, true) => {
                        if b.commit_seq >= a.commit_seq {
                            b
                        } else {
                            a
                        }
                    }
                    (true, false) => a,
                    (false, true) => b,
                    (false, false) => return Err(LibreDbError::NoValidSuperblock),
                }
            }
            (Ok(a), Err(_)) if a.data_tail_offset <= file_len => a,
            (Err(_), Ok(b)) if b.data_tail_offset <= file_len => b,
            _ => return Err(LibreDbError::NoValidSuperblock),
        };

        let mut inodes: HashMap<u64, Inode> = HashMap::new();
        let mut key_dir: HashMap<(NodeKind, String), u64> = HashMap::new();
        let mut reverse_keys: HashMap<u64, (NodeKind, String)> = HashMap::new();

        // 1. Load consolidated BaseSnapshot (`LDBS`) if present.
        if sb.base_snapshot_offset >= DATA_REGION_START && sb.base_snapshot_len > 0 {
            let mut snap_buf = vec![0u8; sb.base_snapshot_len as usize];
            backend.read_at(sb.base_snapshot_offset, &mut snap_buf)?;
            let (_seq, base_inodes, base_keys) = decode_metadata_frame(SNAPSHOT_MAGIC, &snap_buf)?;
            for inode in base_inodes {
                inodes.insert(inode.node_id, inode);
            }
            apply_key_mutations(&mut key_dir, &mut reverse_keys, base_keys);
        }

        // 2. Replay incremental CommitFrames (`LDBC`) in `[delta_start_offset .. data_tail_offset]`.
        // Note: Within the delta stream, payload/overflow extents precede each `CommitFrame`, so
        // each record in the delta stream is wrapped in a self-describing `DeltaEnvelope`:
        // `[env_magic: "LDBE" (4B)][total_env_len: u32 (4B)][extents...][CommitFrame "LDBC"...]`
        let mut cursor = sb.delta_start_offset;
        while cursor < sb.data_tail_offset {
            if cursor + 12 > sb.data_tail_offset {
                return Err(LibreDbError::CorruptFormat("truncated delta envelope header"));
            }
            let mut hdr = [0u8; 12];
            backend.read_at(cursor, &mut hdr)?;
            if &hdr[0..4] != b"LDBE" {
                return Err(LibreDbError::CorruptFormat("invalid delta envelope magic"));
            }
            let total_env_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
            let meta_rel_offset = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
            if total_env_len < 12
                || meta_rel_offset < 12
                || meta_rel_offset >= total_env_len
                || cursor + total_env_len > sb.data_tail_offset
            {
                return Err(LibreDbError::CorruptFormat("invalid delta envelope bounds"));
            }

            let meta_len = (total_env_len - meta_rel_offset) as usize;
            let mut meta_buf = vec![0u8; meta_len];
            backend.read_at(cursor + meta_rel_offset, &mut meta_buf)?;
            let (_seq, delta_inodes, delta_keys) =
                decode_metadata_frame(COMMIT_FRAME_MAGIC, &meta_buf)?;

            for inode in delta_inodes {
                inodes.insert(inode.node_id, inode);
            }
            apply_key_mutations(&mut key_dir, &mut reverse_keys, delta_keys);

            cursor += total_env_len;
        }

        // 3. Hydrate any overflow synapse extents (`> 4` edges) into RAM for `O(1)` graph traversal.
        let mut overflow_synapses: HashMap<u64, Vec<Synapse>> = HashMap::new();
        for (&nid, inode) in &inodes {
            if let InodeStorage::Extent {
                edge_extent_offset,
                edge_overflow_count,
                ..
            } = inode.storage
            {
                if edge_extent_offset >= DATA_REGION_START && edge_overflow_count > 0 {
                    let syns = read_overflow_synapses(
                        backend,
                        edge_extent_offset,
                        edge_overflow_count as usize,
                    )?;
                    overflow_synapses.insert(nid, syns);
                }
            }
        }

        Ok(SnapshotState {
            superblock: sb,
            inodes,
            overflow_synapses,
            key_dir,
            reverse_keys,
        })
    }

    fn read_disk_superblock(backend: &dyn StorageBackend, file_len: u64) -> Result<Superblock> {
        if file_len < DATA_REGION_START {
            return Err(LibreDbError::NoValidSuperblock);
        }
        let mut buf_a = [0u8; SUPERBLOCK_SLOT_SIZE as usize];
        let mut buf_b = [0u8; SUPERBLOCK_SLOT_SIZE as usize];
        let res_a = backend
            .read_at(0, &mut buf_a)
            .and_then(|_| Superblock::decode(&buf_a));
        let res_b = backend
            .read_at(SUPERBLOCK_SLOT_SIZE, &mut buf_b)
            .and_then(|_| Superblock::decode(&buf_b));
        match (res_a, res_b) {
            (Ok(a), Ok(b)) => {
                let a_fits = a.data_tail_offset <= file_len;
                let b_fits = b.data_tail_offset <= file_len;
                match (a_fits, b_fits) {
                    (true, true) => Ok(if b.commit_seq >= a.commit_seq { b } else { a }),
                    (true, false) => Ok(a),
                    (false, true) => Ok(b),
                    (false, false) => Err(LibreDbError::NoValidSuperblock),
                }
            }
            (Ok(a), Err(_)) if a.data_tail_offset <= file_len => Ok(a),
            (Err(_), Ok(b)) if b.data_tail_offset <= file_len => Ok(b),
            _ => Err(LibreDbError::NoValidSuperblock),
        }
    }

    /// Checks whether another OS process (e.g. a lifecycle hook or CLI command) committed new
    /// frames to the underlying `.ldb` file (`< 8 microseconds` 8 KB superblock read from OS page
    /// cache), and transparently reloads `SnapshotState` if `commit_seq` or `compaction_count` advanced.
    pub fn sync_from_disk_if_changed(&self) -> Result<bool> {
        let file_len = self.backend.len()?;
        if file_len < DATA_REGION_START {
            return Ok(false);
        }
        let disk_sb = Self::read_disk_superblock(&*self.backend, file_len)?;
        let mem_sb = self.state.read().superblock;
        if disk_sb.commit_seq == mem_sb.commit_seq
            && disk_sb.compaction_count == mem_sb.compaction_count
            && disk_sb.data_tail_offset == mem_sb.data_tail_offset
        {
            return Ok(false);
        }
        let reloaded = Self::recover_existing(&*self.backend, file_len)?;
        *self.state.write() = Arc::new(reloaded);
        Ok(true)
    }

    /// Prepares a `WriteRequest` on one of the 16 lock-free chaos lanes (compression, CRC32, token count).
    /// Multiple threads can invoke `prepare` in parallel with zero lock contention.
    pub fn prepare(&self, req: WriteRequest, worker_hint: usize) -> Result<PreparedWrite> {
        if req.payload.len() > MAX_EXTENT_PAYLOAD_BYTES {
            return Err(LibreDbError::PayloadTooLarge {
                size: req.payload.len(),
                max: MAX_EXTENT_PAYLOAD_BYTES,
            });
        }

        let lane_id = worker_hint % SHARD_WRITE_LANES;
        self.lane_counters[lane_id].fetch_add(1, Ordering::Relaxed);

        let token_count = count_tokens_exact(&req.payload);
        let key_hash = match &req.key {
            Some(k) => hash_key(req.kind as u8, k.as_bytes()),
            None => 0,
        };

        let mut flags = NodeFlags(NodeFlags::ACTIVE);
        if req.pinned {
            flags.insert(NodeFlags::PINNED);
        }

        let raw_len = req.payload.len() as u32;
        let can_inline =
            req.payload.len() <= MAX_INLINE_BYTES && req.synapses.len() <= INLINE_SYNAPSE_CAP;

        let encoded_payload = if can_inline {
            flags.insert(NodeFlags::INLINE_DATA);
            let mut bytes = [0u8; MAX_INLINE_BYTES];
            bytes[..req.payload.len()].copy_from_slice(&req.payload);
            EncodedPayload::Inline {
                len: req.payload.len() as u8,
                bytes,
            }
        } else if req.payload.len() >= LZ4_MIN_COMPRESS_BYTES {
            let compressed = lz4_flex::block::compress(&req.payload);
            if compressed.len() < req.payload.len() {
                flags.insert(NodeFlags::COMPRESSED_LZ4);
                let checksum = crc32(&compressed);
                EncodedPayload::Extent {
                    bytes: compressed,
                    crc32: checksum,
                    compressed: true,
                }
            } else {
                let checksum = crc32(&req.payload);
                EncodedPayload::Extent {
                    bytes: req.payload,
                    crc32: checksum,
                    compressed: false,
                }
            }
        } else {
            let checksum = crc32(&req.payload);
            EncodedPayload::Extent {
                bytes: req.payload,
                crc32: checksum,
                compressed: false,
            }
        };

        Ok(PreparedWrite {
            lane_id,
            kind: req.kind,
            key: req.key,
            key_hash,
            token_count,
            importance: req.importance,
            flags,
            raw_len,
            encoded_payload,
            synapses: req.synapses,
        })
    }

    /// Inserts or updates a single cognitive capsule (`prepare` + atomic commit).
    pub fn put(&self, req: WriteRequest) -> Result<u64> {
        let worker_hint = current_thread_lane_hint();
        let prepared = self.prepare(req, worker_hint)?;
        let ids = self.commit_batch(std::slice::from_ref(&prepared))?;
        Ok(ids[0])
    }

    /// Commits a batch of pre-encoded `PreparedWrite` items in a single atomic `fsync` + superblock flip.
    pub fn commit_batch(&self, batch: &[PreparedWrite]) -> Result<Vec<u64>> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }

        let _guard = self.commit_lock.lock();
        let _ipc_guard = IpcWriteGuard::acquire(&*self.backend)?;
        self.sync_from_disk_if_changed()?;
        let old_snap = Arc::clone(&self.state.read());
        let mut next_snap = SnapshotState {
            superblock: old_snap.superblock,
            inodes: old_snap.inodes.clone(),
            overflow_synapses: old_snap.overflow_synapses.clone(),
            key_dir: old_snap.key_dir.clone(),
            reverse_keys: old_snap.reverse_keys.clone(),
        };

        let now = now_unix_ns();
        let env_start = next_snap.superblock.data_tail_offset;
        // Reserve 12-byte DeltaEnvelope header (`"LDBE" + total_len:u32 + meta_rel_offset:u32`).
        let mut envelope_buf: Vec<u8> = vec![0u8; 12];
        let mut modified_inodes: Vec<Inode> = Vec::with_capacity(batch.len() * 2);
        let mut key_mutations: Vec<KeyMutation> = Vec::new();
        let mut assigned_ids: Vec<u64> = Vec::with_capacity(batch.len());

        for item in batch {
            let new_id = next_snap.superblock.next_node_id;
            if new_id > crate::format::MAX_NODE_ID {
                return Err(LibreDbError::NodeIdOverflow(new_id));
            }
            next_snap.superblock.next_node_id += 1;

            let mut all_syns = item.synapses.clone();
            let mut generation = 1u32;

            // Automatic temporal superseding if `(kind, key)` already exists!
            if let Some(ref key) = item.key {
                if let Some(&old_id) = next_snap.key_dir.get(&(item.kind, key.clone())) {
                    if let Some(old_inode) = next_snap.inodes.get_mut(&old_id) {
                        if old_inode.flags.is_live_active() {
                            old_inode.flags.insert(NodeFlags::SUPERSEDED);
                            old_inode.updated_ns = now;
                            old_inode.access_count = old_inode
                                .access_count
                                .saturating_add(self.telemetry.drain_hits(old_id));
                            generation = old_inode.generation.saturating_add(1);
                            modified_inodes.push(old_inode.clone());
                            next_snap.superblock.active_node_count =
                                next_snap.superblock.active_node_count.saturating_sub(1);
                        }
                        // Prepend `Supersedes -> old_id` synapse so causal history is automatic.
                        let sup_syn = Synapse::new(EdgeKind::Supersedes, 255, old_id)?;
                        if !all_syns.iter().any(|s| s.kind == EdgeKind::Supersedes && s.target_id == old_id) {
                            all_syns.insert(0, sup_syn);
                        }
                    }
                }
            }

            let mut inline_synapses = [None; INLINE_SYNAPSE_CAP];
            for (idx, syn) in all_syns.iter().take(INLINE_SYNAPSE_CAP).enumerate() {
                inline_synapses[idx] = Some(*syn);
            }
            let overflow_slice = if all_syns.len() > INLINE_SYNAPSE_CAP {
                &all_syns[INLINE_SYNAPSE_CAP..]
            } else {
                &[]
            };

            let mut flags = item.flags;
            let storage = match &item.encoded_payload {
                EncodedPayload::Inline { len, bytes } if overflow_slice.is_empty() => {
                    InodeStorage::Inline {
                        len: *len,
                        bytes: *bytes,
                    }
                }
                EncodedPayload::Inline { len, bytes } => {
                    // Had `<= 43B` payload initially, but temporal Supersedes pushed synapses > 4:
                    // spill inline bytes cleanly into an extent!
                    flags.remove(NodeFlags::INLINE_DATA);
                    let data_slice = &bytes[..*len as usize];
                    let data_crc = crc32(data_slice);
                    let data_offset = env_start + (envelope_buf.len() as u64);
                    envelope_buf.extend_from_slice(data_slice);
                    let (edge_off, edge_cnt) =
                        append_overflow_synapses(env_start, &mut envelope_buf, overflow_slice);
                    InodeStorage::Extent {
                        data_offset,
                        raw_len: *len as u32,
                        stored_len: *len as u32,
                        data_crc32: data_crc,
                        edge_extent_offset: edge_off,
                        edge_overflow_count: edge_cnt,
                        vector_reserved: [0u8; 12],
                    }
                }
                EncodedPayload::Extent {
                    bytes,
                    crc32: data_crc,
                    compressed,
                } => {
                    if *compressed {
                        flags.insert(NodeFlags::COMPRESSED_LZ4);
                    }
                    let data_offset = env_start + (envelope_buf.len() as u64);
                    envelope_buf.extend_from_slice(bytes);
                    let (edge_off, edge_cnt) =
                        append_overflow_synapses(env_start, &mut envelope_buf, overflow_slice);
                    InodeStorage::Extent {
                        data_offset,
                        raw_len: item.raw_len,
                        stored_len: bytes.len() as u32,
                        data_crc32: *data_crc,
                        edge_extent_offset: edge_off,
                        edge_overflow_count: edge_cnt,
                        vector_reserved: [0u8; 12],
                    }
                }
            };

            let inode = Inode {
                node_id: new_id,
                kind: item.kind,
                flags,
                importance: item.importance,
                token_count: item.token_count,
                created_ns: now,
                updated_ns: now,
                access_count: 0,
                generation,
                key_hash: item.key_hash,
                storage,
                inline_synapses,
            };

            if !overflow_slice.is_empty() {
                next_snap
                    .overflow_synapses
                    .insert(new_id, overflow_slice.to_vec());
            }
            next_snap.inodes.insert(new_id, inode.clone());
            modified_inodes.push(inode);
            next_snap.superblock.active_node_count += 1;

            if let Some(ref key) = item.key {
                next_snap.key_dir.insert((item.kind, key.clone()), new_id);
                next_snap
                    .reverse_keys
                    .insert(new_id, (item.kind, key.clone()));
                key_mutations.push(KeyMutation::Upsert {
                    kind: item.kind,
                    key: key.clone(),
                    node_id: new_id,
                });
            }

            assigned_ids.push(new_id);
        }

        let new_seq = next_snap.superblock.commit_seq + 1;
        let meta_rel_offset = envelope_buf.len() as u32;
        let commit_frame = encode_metadata_frame(
            COMMIT_FRAME_MAGIC,
            new_seq,
            &modified_inodes,
            &key_mutations,
        )?;
        envelope_buf.extend_from_slice(&commit_frame);
        let total_env_len = envelope_buf.len() as u32;

        envelope_buf[0..4].copy_from_slice(b"LDBE");
        envelope_buf[4..8].copy_from_slice(&total_env_len.to_le_bytes());
        envelope_buf[8..12].copy_from_slice(&meta_rel_offset.to_le_bytes());

        // Step 1: Write self-verifying delta envelope at `env_start` and fsync BEFORE touching Superblock.
        self.backend.write_at(env_start, &envelope_buf)?;
        self.backend.sync_data()?;

        // Step 2: Update ping-pong Superblock in the inactive slot and fsync.
        next_snap.superblock.commit_seq = new_seq;
        next_snap.superblock.data_tail_offset = env_start + (total_env_len as u64);
        next_snap.superblock.last_commit_ns = now;
        self.write_superblock_slot(&next_snap.superblock)?;

        *self.state.write() = Arc::new(next_snap);
        Ok(assigned_ids)
    }

    /// Adds or updates a directed synapse `source_id --[kind (weight)]--> target_id` atomically.
    pub fn link(
        &self,
        source_id: u64,
        kind: EdgeKind,
        target_id: u64,
        weight: u8,
    ) -> Result<()> {
        self.link_batch(&[(source_id, kind, target_id, weight)])?;
        Ok(())
    }

    /// Atomically commits thousands of directed synapses in a single `DeltaEnvelope` and a single `fsync`.
    pub fn link_batch(&self, edges: &[(u64, EdgeKind, u64, u8)]) -> Result<usize> {
        if edges.is_empty() {
            return Ok(0);
        }

        let _guard = self.commit_lock.lock();
        let _ipc_guard = IpcWriteGuard::acquire(&*self.backend)?;
        self.sync_from_disk_if_changed()?;
        let old_snap = Arc::clone(&self.state.read());

        // Validate endpoints and group new synapses by `source_id`.
        let mut grouped: HashMap<u64, Vec<Synapse>> = HashMap::new();
        for &(src_id, kind, dst_id, weight) in edges {
            if !old_snap.inodes.contains_key(&src_id) {
                return Err(LibreDbError::NodeNotFound(src_id));
            }
            if !old_snap.inodes.contains_key(&dst_id) {
                return Err(LibreDbError::NodeNotFound(dst_id));
            }
            let syn = Synapse::new(kind, weight, dst_id)?;
            grouped.entry(src_id).or_default().push(syn);
        }

        let mut next_snap = SnapshotState {
            superblock: old_snap.superblock,
            inodes: old_snap.inodes.clone(),
            overflow_synapses: old_snap.overflow_synapses.clone(),
            key_dir: old_snap.key_dir.clone(),
            reverse_keys: old_snap.reverse_keys.clone(),
        };

        let now = now_unix_ns();
        let env_start = next_snap.superblock.data_tail_offset;
        let mut envelope_buf: Vec<u8> = vec![0u8; 12];
        let mut modified_inodes: Vec<Inode> = Vec::with_capacity(grouped.len());

        let mut sorted_sources: Vec<u64> = grouped.keys().copied().collect();
        sorted_sources.sort_unstable();

        for source_id in sorted_sources {
            let incoming = &grouped[&source_id];
            let existing_inode = next_snap.inodes[&source_id].clone();
            let mut syns = collect_node_synapses(&next_snap, &existing_inode);
            let mut node_changed = false;

            for &new_syn in incoming {
                if let Some(slot) = syns
                    .iter_mut()
                    .find(|s| s.kind == new_syn.kind && s.target_id == new_syn.target_id)
                {
                    if slot.weight != new_syn.weight {
                        slot.weight = new_syn.weight;
                        node_changed = true;
                    }
                } else {
                    syns.push(new_syn);
                    node_changed = true;
                }
            }

            if !node_changed {
                continue;
            }

            let mut inline_synapses = [None; INLINE_SYNAPSE_CAP];
            for (idx, syn) in syns.iter().take(INLINE_SYNAPSE_CAP).enumerate() {
                inline_synapses[idx] = Some(*syn);
            }
            let overflow_slice = if syns.len() > INLINE_SYNAPSE_CAP {
                &syns[INLINE_SYNAPSE_CAP..]
            } else {
                &[]
            };

            let mut updated_inode = existing_inode;
            updated_inode.inline_synapses = inline_synapses;
            updated_inode.updated_ns = now;
            updated_inode.generation = updated_inode.generation.saturating_add(1);
            updated_inode.access_count = updated_inode
                .access_count
                .saturating_add(self.telemetry.drain_hits(source_id));

            if !overflow_slice.is_empty() {
                match updated_inode.storage {
                    InodeStorage::Inline { len, bytes } => {
                        updated_inode.flags.remove(NodeFlags::INLINE_DATA);
                        let raw_slice = &bytes[..len as usize];
                        let data_crc = crc32(raw_slice);
                        let data_offset = env_start + (envelope_buf.len() as u64);
                        envelope_buf.extend_from_slice(raw_slice);
                        let (edge_off, edge_cnt) =
                            append_overflow_synapses(env_start, &mut envelope_buf, overflow_slice);
                        updated_inode.storage = InodeStorage::Extent {
                            data_offset,
                            raw_len: len as u32,
                            stored_len: len as u32,
                            data_crc32: data_crc,
                            edge_extent_offset: edge_off,
                            edge_overflow_count: edge_cnt,
                            vector_reserved: [0u8; 12],
                        };
                    }
                    InodeStorage::Extent {
                        data_offset,
                        raw_len,
                        stored_len,
                        data_crc32,
                        vector_reserved,
                        ..
                    } => {
                        let (edge_off, edge_cnt) =
                            append_overflow_synapses(env_start, &mut envelope_buf, overflow_slice);
                        updated_inode.storage = InodeStorage::Extent {
                            data_offset,
                            raw_len,
                            stored_len,
                            data_crc32,
                            edge_extent_offset: edge_off,
                            edge_overflow_count: edge_cnt,
                            vector_reserved,
                        };
                    }
                }
                next_snap
                    .overflow_synapses
                    .insert(source_id, overflow_slice.to_vec());
            } else {
                next_snap.overflow_synapses.remove(&source_id);
                if let InodeStorage::Extent {
                    data_offset,
                    raw_len,
                    stored_len,
                    data_crc32,
                    vector_reserved,
                    ..
                } = updated_inode.storage
                {
                    updated_inode.storage = InodeStorage::Extent {
                        data_offset,
                        raw_len,
                        stored_len,
                        data_crc32,
                        edge_extent_offset: 0,
                        edge_overflow_count: 0,
                        vector_reserved,
                    };
                }
            }

            next_snap.inodes.insert(source_id, updated_inode.clone());
            modified_inodes.push(updated_inode);
        }

        if modified_inodes.is_empty() {
            return Ok(edges.len());
        }

        let new_seq = next_snap.superblock.commit_seq + 1;
        let meta_rel_offset = envelope_buf.len() as u32;
        let commit_frame =
            encode_metadata_frame(COMMIT_FRAME_MAGIC, new_seq, &modified_inodes, &[])?;
        envelope_buf.extend_from_slice(&commit_frame);
        let total_env_len = envelope_buf.len() as u32;

        envelope_buf[0..4].copy_from_slice(b"LDBE");
        envelope_buf[4..8].copy_from_slice(&total_env_len.to_le_bytes());
        envelope_buf[8..12].copy_from_slice(&meta_rel_offset.to_le_bytes());

        self.backend.write_at(env_start, &envelope_buf)?;
        self.backend.sync_data()?;

        next_snap.superblock.commit_seq = new_seq;
        next_snap.superblock.data_tail_offset = env_start + (total_env_len as u64);
        next_snap.superblock.last_commit_ns = now;
        self.write_superblock_slot(&next_snap.superblock)?;

        *self.state.write() = Arc::new(next_snap);
        Ok(edges.len())
    }

    /// Tombstones an active keyed node so it no longer appears in active queries while keeping file integrity.
    pub fn deprecate_key(&self, kind: NodeKind, key: &str) -> Result<bool> {
        let _guard = self.commit_lock.lock();
        let _ipc_guard = IpcWriteGuard::acquire(&*self.backend)?;
        self.sync_from_disk_if_changed()?;
        let old_snap = Arc::clone(&self.state.read());
        let Some(&target_id) = old_snap.key_dir.get(&(kind, key.to_owned())) else {
            return Ok(false);
        };

        let mut next_snap = SnapshotState {
            superblock: old_snap.superblock,
            inodes: old_snap.inodes.clone(),
            overflow_synapses: old_snap.overflow_synapses.clone(),
            key_dir: old_snap.key_dir.clone(),
            reverse_keys: old_snap.reverse_keys.clone(),
        };

        let now = now_unix_ns();
        let inode = next_snap
            .inodes
            .get_mut(&target_id)
            .ok_or(LibreDbError::NodeNotFound(target_id))?;
        if inode.flags.is_live_active() {
            next_snap.superblock.active_node_count =
                next_snap.superblock.active_node_count.saturating_sub(1);
        }
        inode.flags.insert(NodeFlags::TOMBSTONE | NodeFlags::SUPERSEDED);
        inode.updated_ns = now;
        let updated_inode = inode.clone();

        next_snap.key_dir.remove(&(kind, key.to_owned()));
        next_snap.reverse_keys.remove(&target_id);

        let new_seq = next_snap.superblock.commit_seq + 1;
        let key_ops = vec![KeyMutation::Remove {
            kind,
            key: key.to_owned(),
        }];
        let commit_frame = encode_metadata_frame(
            COMMIT_FRAME_MAGIC,
            new_seq,
            std::slice::from_ref(&updated_inode),
            &key_ops,
        )?;

        let env_start = next_snap.superblock.data_tail_offset;
        let total_env_len = (12 + commit_frame.len()) as u32;
        let mut envelope_buf = Vec::with_capacity(total_env_len as usize);
        envelope_buf.extend_from_slice(b"LDBE");
        envelope_buf.extend_from_slice(&total_env_len.to_le_bytes());
        envelope_buf.extend_from_slice(&12u32.to_le_bytes());
        envelope_buf.extend_from_slice(&commit_frame);

        self.backend.write_at(env_start, &envelope_buf)?;
        self.backend.sync_data()?;

        next_snap.superblock.commit_seq = new_seq;
        next_snap.superblock.data_tail_offset = env_start + (total_env_len as u64);
        next_snap.superblock.last_commit_ns = now;
        self.write_superblock_slot(&next_snap.superblock)?;

        *self.state.write() = Arc::new(next_snap);
        Ok(true)
    }

    /// Tombstones a batch of `node_ids` (keyed or unkeyed) in a single atomic commit frame.
    pub fn deprecate_nodes(&self, node_ids: &[u64]) -> Result<usize> {
        if node_ids.is_empty() {
            return Ok(0);
        }
        let _guard = self.commit_lock.lock();
        let _ipc_guard = IpcWriteGuard::acquire(&*self.backend)?;
        self.sync_from_disk_if_changed()?;
        let old_snap = Arc::clone(&self.state.read());

        let mut next_snap = SnapshotState {
            superblock: old_snap.superblock,
            inodes: old_snap.inodes.clone(),
            overflow_synapses: old_snap.overflow_synapses.clone(),
            key_dir: old_snap.key_dir.clone(),
            reverse_keys: old_snap.reverse_keys.clone(),
        };

        let now = now_unix_ns();
        let mut modified_inodes = Vec::new();
        let mut key_ops = Vec::new();

        for &target_id in node_ids {
            let Some(inode) = next_snap.inodes.get_mut(&target_id) else {
                continue;
            };
            if inode.flags.contains(NodeFlags::TOMBSTONE) {
                continue;
            }
            if inode.flags.is_live_active() {
                next_snap.superblock.active_node_count =
                    next_snap.superblock.active_node_count.saturating_sub(1);
            }
            inode.flags.insert(NodeFlags::TOMBSTONE | NodeFlags::SUPERSEDED);
            inode.updated_ns = now;
            modified_inodes.push(inode.clone());

            if let Some((k_kind, k_str)) = next_snap.reverse_keys.remove(&target_id) {
                next_snap.key_dir.remove(&(k_kind, k_str.clone()));
                key_ops.push(KeyMutation::Remove {
                    kind: k_kind,
                    key: k_str,
                });
            }
        }

        if modified_inodes.is_empty() {
            return Ok(0);
        }

        let count = modified_inodes.len();
        let new_seq = next_snap.superblock.commit_seq + 1;
        let commit_frame = encode_metadata_frame(
            COMMIT_FRAME_MAGIC,
            new_seq,
            &modified_inodes,
            &key_ops,
        )?;

        let env_start = next_snap.superblock.data_tail_offset;
        let total_env_len = (12 + commit_frame.len()) as u32;
        let mut envelope_buf = Vec::with_capacity(total_env_len as usize);
        envelope_buf.extend_from_slice(b"LDBE");
        envelope_buf.extend_from_slice(&total_env_len.to_le_bytes());
        envelope_buf.extend_from_slice(&12u32.to_le_bytes());
        envelope_buf.extend_from_slice(&commit_frame);

        self.backend.write_at(env_start, &envelope_buf)?;
        self.backend.sync_data()?;

        next_snap.superblock.commit_seq = new_seq;
        next_snap.superblock.data_tail_offset = env_start + (total_env_len as u64);
        next_snap.superblock.last_commit_ns = now;
        self.write_superblock_slot(&next_snap.superblock)?;

        *self.state.write() = Arc::new(next_snap);
        Ok(count)
    }

    /// Lock-free `O(1)` snapshot read by `NodeId` (never blocks or gets blocked by concurrent writers).
    pub fn get(&self, node_id: u64) -> Result<NodeRecord> {
        let snap = Arc::clone(&self.state.read());
        let inode = snap
            .inodes
            .get(&node_id)
            .ok_or(LibreDbError::NodeNotFound(node_id))?
            .clone();
        let synapses = collect_node_synapses(&snap, &inode);
        // Snapshot read lock is already dropped before performing any disk I/O or decompression!
        drop(snap);

        let payload = match self.read_inode_payload(&inode) {
            Ok(p) => p,
            Err(LibreDbError::ChecksumMismatch { .. }) if self.sync_from_disk_if_changed()? => {
                let fresh_snap = Arc::clone(&self.state.read());
                let fresh_ino = fresh_snap
                    .inodes
                    .get(&node_id)
                    .ok_or(LibreDbError::NodeNotFound(node_id))?
                    .clone();
                drop(fresh_snap);
                self.read_inode_payload(&fresh_ino)?
            }
            Err(e) => return Err(e),
        };
        self.telemetry.record_hit(node_id);
        let access_count = inode
            .access_count
            .saturating_add(self.telemetry.pending_hits(node_id));

        Ok(NodeRecord {
            node_id: inode.node_id,
            kind: inode.kind,
            flags: inode.flags,
            importance: inode.importance,
            token_count: inode.token_count,
            created_ns: inode.created_ns,
            updated_ns: inode.updated_ns,
            access_count,
            generation: inode.generation,
            synapses,
            payload,
        })
    }

    /// Lock-free `O(1)` snapshot lookup by `(kind, logical_key)`.
    pub fn get_by_key(&self, kind: NodeKind, key: &str) -> Result<NodeRecord> {
        let node_id = {
            let snap = self.state.read();
            snap.key_dir
                .get(&(kind, key.to_owned()))
                .copied()
                .ok_or_else(|| LibreDbError::KeyNotFound {
                    kind,
                    key: key.to_owned(),
                })?
        };
        self.get(node_id)
    }

    /// Returns all outgoing synapses of `node_id` directly from the in-memory `Inode` table (`0` disk reads).
    pub fn neighbors(
        &self,
        node_id: u64,
        edge_filter: Option<EdgeKind>,
    ) -> Result<Vec<Synapse>> {
        let snap = self.state.read();
        let inode = snap
            .inodes
            .get(&node_id)
            .ok_or(LibreDbError::NodeNotFound(node_id))?;
        let mut syns = collect_node_synapses(&snap, inode);
        if let Some(kind) = edge_filter {
            syns.retain(|s| s.kind == kind);
        }
        Ok(syns)
    }

    /// Snapshots lightweight `128-byte` `Inode` headers, optional active keys, and synapses in RAM
    /// without performing any payload disk I/O. Used by cognitive indexers and lossless exporters.
    pub fn list_inodes(
        &self,
        kind_filter: Option<NodeKind>,
        include_inactive: bool,
    ) -> Vec<(Inode, Option<String>, Vec<Synapse>)> {
        let snap = self.state.read();
        let mut out = Vec::new();
        for (&nid, inode) in &snap.inodes {
            if inode.flags.contains(NodeFlags::TOMBSTONE) && !include_inactive {
                continue;
            }
            if !include_inactive && !inode.flags.is_live_active() {
                continue;
            }
            if let Some(kf) = kind_filter {
                if inode.kind != kf {
                    continue;
                }
            }
            let key = snap.reverse_keys.get(&nid).map(|(_, k)| k.clone());
            let syns = collect_node_synapses(&snap, inode);
            out.push((inode.clone(), key, syns));
        }
        out.sort_unstable_by_key(|(ino, _, _)| ino.node_id);
        out
    }

    /// Hydrates multiple `NodeId`s in a single sorted, coalesced extent I/O pass.
    pub fn get_many_coalesced(&self, node_ids: &[u64]) -> Result<(Vec<NodeRecord>, usize)> {
        if node_ids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let mut snap = Arc::clone(&self.state.read());
        let mut valid_ids = Vec::with_capacity(node_ids.len());
        for &nid in node_ids {
            if snap.inodes.contains_key(&nid) {
                valid_ids.push(nid);
            } else {
                return Err(LibreDbError::NodeNotFound(nid));
            }
        }
        let (payload_map, io_reads) = match self.read_coalesced_extents(&snap, &valid_ids) {
            Ok(res) => res,
            Err(LibreDbError::ChecksumMismatch { .. }) if self.sync_from_disk_if_changed()? => {
                snap = Arc::clone(&self.state.read());
                self.read_coalesced_extents(&snap, &valid_ids)?
            }
            Err(e) => return Err(e),
        };
        let mut records = Vec::with_capacity(valid_ids.len());
        for nid in valid_ids {
            let inode = &snap.inodes[&nid];
            let synapses = collect_node_synapses(&snap, inode);
            let payload = payload_map.get(&nid).cloned().unwrap_or_default();
            self.telemetry.record_hit(nid);
            let access_count = inode
                .access_count
                .saturating_add(self.telemetry.pending_hits(nid));
            records.push(NodeRecord {
                node_id: nid,
                kind: inode.kind,
                flags: inode.flags,
                importance: inode.importance,
                token_count: inode.token_count,
                created_ns: inode.created_ns,
                updated_ns: inode.updated_ns,
                access_count,
                generation: inode.generation,
                synapses,
                payload,
            });
        }
        Ok((records, io_reads))
    }

    /// Returns the active logical `(kind, key)` bound to `node_id`, if any.
    pub fn active_key_for(&self, node_id: u64) -> Option<(NodeKind, String)> {
        self.state.read().reverse_keys.get(&node_id).cloned()
    }

    /// Returns `(Inode, key, synapses)` for a single `node_id` in `O(1)` directly from the in-RAM snapshot (`0` disk I/O).
    pub fn get_inode_meta(&self, node_id: u64) -> Option<(Inode, Option<String>, Vec<Synapse>)> {
        let snap = self.state.read();
        let ino = snap.inodes.get(&node_id)?.clone();
        let key = snap.reverse_keys.get(&node_id).map(|(_, k)| k.clone());
        let syns = collect_node_synapses(&snap, &ino);
        Some((ino, key, syns))
    }

    /// Matches active logical keys of `kind` against lowercase `query_tokens` in RAM without cloning Inodes (`0` disk I/O).
    pub fn match_active_keys_by_kind(
        &self,
        kind: NodeKind,
        query_tokens: &[String],
        limit: usize,
    ) -> Vec<(u64, f64)> {
        if query_tokens.is_empty() || limit == 0 {
            return Vec::new();
        }
        let snap = self.state.read();
        let mut hits: Vec<(u64, f64)> = Vec::new();
        for ((k_kind, key_str), &nid) in &snap.key_dir {
            if *k_kind != kind {
                continue;
            }
            let Some(ino) = snap.inodes.get(&nid) else {
                continue;
            };
            if !ino.flags.is_live_active() {
                continue;
            }
            let key_low = key_str.to_ascii_lowercase();
            let short_low = key_low.rsplit("::").next().unwrap_or(&key_low);
            let mut score = 0.0_f64;
            for tok in query_tokens {
                if tok.len() < 3 {
                    continue;
                }
                if short_low == tok {
                    score += 6.0;
                } else if short_low.contains(tok.as_str()) {
                    score += 3.5;
                } else if key_low.contains(tok.as_str()) {
                    score += 1.5;
                }
            }
            if score > 0.0 {
                hits.push((nid, score));
            }
        }
        hits.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        hits.truncate(limit);
        hits
    }

    /// Traces temporal and causal lineage (`Supersedes`, `CausedBy`, `Governs`) starting at `root_id`.
    pub fn trace_lineage(&self, root_id: u64, max_depth: usize) -> Result<Vec<NodeSummary>> {
        let snap = Arc::clone(&self.state.read());
        if !snap.inodes.contains_key(&root_id) {
            return Err(LibreDbError::NodeNotFound(root_id));
        }

        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize, Option<EdgeKind>)> = VecDeque::new();
        visited.insert(root_id);
        queue.push_back((root_id, 0, None));

        let mut out = Vec::new();
        while let Some((curr_id, depth, via)) = queue.pop_front() {
            let Some(inode) = snap.inodes.get(&curr_id) else {
                continue;
            };
            let payload = self.read_inode_payload(inode)?;
            let preview_raw = String::from_utf8_lossy(&payload);
            let preview: String = preview_raw.chars().take(120).collect();

            out.push(NodeSummary {
                depth,
                via_edge: via,
                node_id: curr_id,
                kind: inode.kind,
                is_active: inode.flags.is_live_active(),
                is_superseded: inode.flags.contains(NodeFlags::SUPERSEDED),
                token_count: inode.token_count,
                importance: inode.importance,
                updated_ns: inode.updated_ns,
                payload_preview: preview,
            });

            if depth < max_depth {
                for syn in collect_node_synapses(&snap, inode) {
                    if matches!(
                        syn.kind,
                        EdgeKind::Supersedes | EdgeKind::CausedBy | EdgeKind::Governs
                    ) && visited.insert(syn.target_id)
                    {
                        queue.push_back((syn.target_id, depth + 1, Some(syn.kind)));
                    }
                }
            }
        }

        Ok(out)
    }

    /// Spreading-activation recall with strict `token_budget` packing and coalesced Gravity extent reads.
    ///
    /// - Traverses `Inode` synapses in RAM (`0` disk I/O during graph scoring!),
    /// - Filters out `SUPERSEDED` / `TOMBSTONE` nodes unless `include_superseded` is true,
    /// - Packs highest-scoring connected nodes within `token_budget`,
    /// - Coalesces adjacent byte extents (e.g., from `compact_with_gravity`) into single sequential `read_at` calls!
    pub fn recall_within_budget(
        &self,
        seed_ids: &[u64],
        max_hops: usize,
        token_budget: u32,
        include_superseded: bool,
    ) -> Result<RecallBundle> {
        if seed_ids.is_empty() || token_budget == 0 {
            return Ok(RecallBundle {
                records: Vec::new(),
                total_tokens: 0,
                token_budget,
                coalesced_io_reads: 0,
            });
        }

        let snap = Arc::clone(&self.state.read());
        let mut activation: HashMap<u64, u64> = HashMap::new();
        let mut queue: VecDeque<(u64, usize, u64)> = VecDeque::new();

        for &sid in seed_ids {
            if snap.inodes.contains_key(&sid) {
                activation.insert(sid, 10_000);
                queue.push_back((sid, 0, 10_000));
            }
        }

        while let Some((curr_id, hop, energy)) = queue.pop_front() {
            if hop >= max_hops || energy < 50 {
                continue;
            }
            if let Some(inode) = snap.inodes.get(&curr_id) {
                for syn in collect_node_synapses(&snap, inode) {
                    if !include_superseded && syn.kind == EdgeKind::Supersedes {
                        continue;
                    }
                    let propagated = (energy * (syn.weight as u64).max(1)) / 320;
                    if propagated >= 50 {
                        let entry = activation.entry(syn.target_id).or_insert(0);
                        if propagated > *entry {
                            *entry = propagated;
                            queue.push_back((syn.target_id, hop + 1, propagated));
                        }
                    }
                }
            }
        }

        // Rank candidate Inodes by `(score, importance, access_count, -node_id)`.
        #[derive(Eq, PartialEq)]
        struct ScoredCandidate {
            utility: u64,
            node_id: u64,
        }
        impl Ord for ScoredCandidate {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.utility
                    .cmp(&other.utility)
                    .then_with(|| other.node_id.cmp(&self.node_id))
            }
        }
        impl PartialOrd for ScoredCandidate {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut heap = BinaryHeap::with_capacity(activation.len());
        for (&nid, &act) in &activation {
            let Some(inode) = snap.inodes.get(&nid) else {
                continue;
            };
            if inode.flags.contains(NodeFlags::TOMBSTONE) {
                continue;
            }
            if !include_superseded && inode.flags.contains(NodeFlags::SUPERSEDED) {
                continue;
            }
            let hits = inode
                .access_count
                .saturating_add(self.telemetry.pending_hits(nid)) as u64;
            let utility = act
                .saturating_mul((inode.importance as u64).max(1))
                .saturating_add(hits.min(1_000) * 16);
            heap.push(ScoredCandidate {
                utility,
                node_id: nid,
            });
        }

        let mut selected_ids: Vec<u64> = Vec::new();
        let mut used_tokens: u32 = 0;

        while let Some(cand) = heap.pop() {
            let inode = &snap.inodes[&cand.node_id];
            let tok = inode.token_count.max(1);
            if used_tokens.saturating_add(tok) <= token_budget || selected_ids.is_empty() && tok <= token_budget {
                used_tokens += tok;
                selected_ids.push(cand.node_id);
                if used_tokens == token_budget {
                    break;
                }
            }
        }

        // Coalesce adjacent or nearby extent ranges (`gap <= 4096 B`) into single sequential `read_at` calls!
        let (payload_map, coalesced_reads) =
            self.read_coalesced_extents(&snap, &selected_ids)?;

        let mut records = Vec::with_capacity(selected_ids.len());
        for nid in selected_ids {
            let inode = &snap.inodes[&nid];
            let synapses = collect_node_synapses(&snap, inode);
            let payload = payload_map.get(&nid).cloned().unwrap_or_default();
            self.telemetry.record_hit(nid);
            let access_count = inode
                .access_count
                .saturating_add(self.telemetry.pending_hits(nid));
            records.push(NodeRecord {
                node_id: nid,
                kind: inode.kind,
                flags: inode.flags,
                importance: inode.importance,
                token_count: inode.token_count,
                created_ns: inode.created_ns,
                updated_ns: inode.updated_ns,
                access_count,
                generation: inode.generation,
                synapses,
                payload,
            });
        }

        Ok(RecallBundle {
            records,
            total_tokens: used_tokens,
            token_budget,
            coalesced_io_reads: coalesced_reads,
        })
    }

    /// Executes the crash-proof two-phase disjoint-window Gravity Compaction ("sleep phase"):
    ///
    /// 1. Packs active `Inode` families into contiguous `64 KB` Gravity locality groups, retains
    ///    1-hop `Supersedes` history for active knowledge capsules, and garbage-collects all
    ///    superseded system/cache/symbol extents and tombstones.
    /// 2. Stages the compacted image at `T_stage = align_up(max(current_tail, 8192 + Lc), 4096)`,
    ///    flushes, and flips `Superblock #1` (zero overlap with live data!).
    /// 3. Relocates the compacted image to `[8192 .. 8192 + Lc]` (100% disjoint from `T_stage`!),
    ///    flushes, flips `Superblock #2`, and shrinks the file via `set_len(8192 + Lc)`.
    pub fn compact_with_gravity(&self) -> Result<CompactionReport> {
        self.compact_with_options(false)
    }

    /// Executes Gravity Compaction with optional full cold-archive pruning (`prune_all_cold = true`).
    pub fn compact_with_options(&self, prune_all_cold: bool) -> Result<CompactionReport> {
        let _guard = self.commit_lock.lock();
        let _ipc_guard = IpcWriteGuard::acquire(&*self.backend)?;
        self.sync_from_disk_if_changed()?;
        let old_snap = Arc::clone(&self.state.read());
        let bytes_before = self.backend.len()?;

        // Build full synapse map for gravity clustering.
        let mut full_synapses: HashMap<u64, Vec<Synapse>> =
            HashMap::with_capacity(old_snap.inodes.len());
        for (&nid, inode) in &old_snap.inodes {
            full_synapses.insert(nid, collect_node_synapses(&old_snap, inode));
        }

        let plan = compute_gravity_plan(&old_snap.inodes, &full_synapses, prune_all_cold);
        let ordered_ids: Vec<u64> = plan
            .hot_node_ids
            .iter()
            .chain(plan.cold_node_ids.iter())
            .copied()
            .collect();
        let kept_ids: HashSet<u64> = ordered_ids.iter().copied().collect();

        // Read raw stored extent slices once and build relative offsets `0 .. extents_bytes_len`.
        struct RelEntry {
            inode: Inode,
            data_rel: Option<(u64, Vec<u8>, u32)>,
            edge_rel: Option<(u64, Vec<u8>, u32)>,
            overflow_syns: Vec<Synapse>,
        }

        let mut rel_cursor = 0u64;
        let mut rel_entries: Vec<RelEntry> = Vec::with_capacity(ordered_ids.len());
        let mut active_count = 0u64;

        for &nid in &ordered_ids {
            let mut inode = old_snap.inodes[&nid].clone();
            inode.access_count = inode
                .access_count
                .saturating_add(self.telemetry.drain_hits(nid));
            if inode.flags.contains(NodeFlags::SUPERSEDED) {
                inode.flags.insert(NodeFlags::COLD_ARCHIVE);
            }
            if inode.flags.is_live_active() {
                active_count += 1;
            }

            // Strip any synapses pointing to garbage-collected node_ids.
            let mut valid_syns: Vec<Synapse> = full_synapses
                .get(&nid)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| kept_ids.contains(&s.target_id))
                .collect();
            inode.inline_synapses = [None; INLINE_SYNAPSE_CAP];
            for (idx, syn) in valid_syns.iter().take(INLINE_SYNAPSE_CAP).enumerate() {
                inode.inline_synapses[idx] = Some(*syn);
            }
            let over_syns: Vec<Synapse> = if valid_syns.len() > INLINE_SYNAPSE_CAP {
                valid_syns.split_off(INLINE_SYNAPSE_CAP)
            } else {
                Vec::new()
            };

            match inode.storage {
                InodeStorage::Inline { .. } => {
                    rel_entries.push(RelEntry {
                        inode,
                        data_rel: None,
                        edge_rel: None,
                        overflow_syns: Vec::new(),
                    });
                }
                InodeStorage::Extent {
                    data_offset,
                    stored_len,
                    data_crc32,
                    ..
                } => {
                    let mut stored_bytes = vec![0u8; stored_len as usize];
                    self.backend.read_at(data_offset, &mut stored_bytes)?;
                    let actual_crc = crc32(&stored_bytes);
                    if actual_crc != data_crc32 {
                        return Err(LibreDbError::ChecksumMismatch {
                            context: "compaction_extent_read",
                            expected: data_crc32,
                            actual: actual_crc,
                        });
                    }
                    let d_rel = rel_cursor;
                    rel_cursor += stored_bytes.len() as u64;

                    let e_rel = if !over_syns.is_empty() {
                        let e_buf = encode_overflow_synapses(&over_syns);
                        let off = rel_cursor;
                        rel_cursor += e_buf.len() as u64;
                        Some((off, e_buf, over_syns.len() as u32))
                    } else {
                        None
                    };

                    rel_entries.push(RelEntry {
                        inode,
                        data_rel: Some((d_rel, stored_bytes, data_crc32)),
                        edge_rel: e_rel,
                        overflow_syns: over_syns,
                    });
                }
            }
        }

        // Canonical key mutations for BaseSnapshot.
        let mut key_ops: Vec<KeyMutation> = old_snap
            .key_dir
            .iter()
            .filter(|(_, &nid)| !old_snap.inodes[&nid].flags.contains(NodeFlags::TOMBSTONE))
            .map(|((kind, key), &nid)| KeyMutation::Upsert {
                kind: *kind,
                key: key.clone(),
                node_id: nid,
            })
            .collect();
        key_ops.sort_by(|a, b| {
            let ka = match a {
                KeyMutation::Upsert { kind, key, .. } | KeyMutation::Remove { kind, key } => {
                    (*kind, key.as_str())
                }
            };
            let kb = match b {
                KeyMutation::Upsert { kind, key, .. } | KeyMutation::Remove { kind, key } => {
                    (*kind, key.as_str())
                }
            };
            ka.cmp(&kb)
        });

        // Helper closure producing `(full_region_bytes, relocated_inodes, snapshot_rel_offset, snapshot_len)`
        // for any given `base_offset`. Byte length `Lc` is strictly invariant across all `base_offset` values!
        let materialize_for_base =
            |base_offset: u64, seq: u64| -> Result<(Vec<u8>, Vec<Inode>, u64, u64)> {
                let mut region = Vec::with_capacity(rel_cursor as usize + rel_entries.len() * 140);
                let mut out_inodes = Vec::with_capacity(rel_entries.len());

                for entry in &rel_entries {
                    let mut ino = entry.inode.clone();
                    if let InodeStorage::Extent {
                        raw_len,
                        stored_len,
                        vector_reserved,
                        ..
                    } = ino.storage
                    {
                        let (d_rel, ref d_bytes, d_crc) =
                            entry.data_rel.as_ref().expect("extent has data_rel");
                        debug_assert_eq!(region.len() as u64, *d_rel);
                        region.extend_from_slice(d_bytes);

                        let (edge_abs, edge_cnt) = if let Some((e_rel, ref e_bytes, cnt)) = entry.edge_rel {
                            debug_assert_eq!(region.len() as u64, e_rel);
                            region.extend_from_slice(e_bytes);
                            (base_offset + e_rel, cnt)
                        } else {
                            (0u64, 0u32)
                        };

                        ino.storage = InodeStorage::Extent {
                            data_offset: base_offset + *d_rel,
                            raw_len,
                            stored_len,
                            data_crc32: *d_crc,
                            edge_extent_offset: edge_abs,
                            edge_overflow_count: edge_cnt,
                            vector_reserved,
                        };
                    }
                    out_inodes.push(ino);
                }

                let snap_rel_offset = region.len() as u64;
                let snap_frame =
                    encode_metadata_frame(SNAPSHOT_MAGIC, seq, &out_inodes, &key_ops)?;
                let snap_len = snap_frame.len() as u64;
                region.extend_from_slice(&snap_frame);

                Ok((region, out_inodes, snap_rel_offset, snap_len))
            };

        let now = now_unix_ns();
        let seq_stage = old_snap.superblock.commit_seq + 1;
        let (probe_region, _, _, _) = materialize_for_base(DATA_REGION_START, seq_stage)?;
        let lc = probe_region.len() as u64;

        // Disjoint staging offset `T_stage >= max(current_tail, DATA_REGION_START + Lc)`!
        let current_tail = old_snap.superblock.data_tail_offset;
        let t_stage = align_up(current_tail.max(DATA_REGION_START + lc), 4096);

        // Phase 1: Write compacted image to disjoint `[t_stage .. t_stage + lc]` and commit Superblock #1.
        let (stage_bytes, _, stage_snap_rel, stage_snap_len) =
            materialize_for_base(t_stage, seq_stage)?;
        debug_assert_eq!(stage_bytes.len() as u64, lc);

        self.backend.write_at(t_stage, &stage_bytes)?;
        self.backend.sync_data()?;

        let sb_stage = Superblock {
            version: old_snap.superblock.version,
            flags: old_snap.superblock.flags,
            commit_seq: seq_stage,
            next_node_id: old_snap.superblock.next_node_id,
            active_node_count: active_count,
            base_snapshot_offset: t_stage + stage_snap_rel,
            base_snapshot_len: stage_snap_len,
            delta_start_offset: t_stage + lc,
            data_tail_offset: t_stage + lc,
            created_ns: old_snap.superblock.created_ns,
            last_commit_ns: now,
            compaction_count: old_snap.superblock.compaction_count + 1,
        };
        self.write_superblock_slot(&sb_stage)?;

        // Phase 2: Relocate compacted image to `[DATA_REGION_START .. DATA_REGION_START + lc]`
        // (100% disjoint from `[t_stage .. t_stage + lc]`!), commit Superblock #2, and shrink file!
        let seq_final = seq_stage + 1;
        let (final_bytes, final_inodes, final_snap_rel, final_snap_len) =
            materialize_for_base(DATA_REGION_START, seq_final)?;
        debug_assert_eq!(final_bytes.len() as u64, lc);

        self.backend.write_at(DATA_REGION_START, &final_bytes)?;
        self.backend.sync_data()?;

        let final_eof = DATA_REGION_START + lc;
        let sb_final = Superblock {
            commit_seq: seq_final,
            base_snapshot_offset: DATA_REGION_START + final_snap_rel,
            base_snapshot_len: final_snap_len,
            delta_start_offset: final_eof,
            data_tail_offset: final_eof,
            ..sb_stage
        };
        self.write_superblock_slot(&sb_final)?;

        self.backend.set_len(final_eof)?;
        self.backend.sync_data()?;

        // Rebuild clean in-memory SnapshotState without tombstones or pruned cold nodes.
        let mut new_inodes_map = HashMap::with_capacity(final_inodes.len());
        let mut new_overflow = HashMap::new();
        for (entry, ino) in rel_entries.into_iter().zip(final_inodes.into_iter()) {
            if !entry.overflow_syns.is_empty() {
                new_overflow.insert(ino.node_id, entry.overflow_syns);
            }
            new_inodes_map.insert(ino.node_id, ino);
        }

        let mut new_key_dir = HashMap::new();
        let mut new_rev_keys = HashMap::new();
        apply_key_mutations(&mut new_key_dir, &mut new_rev_keys, key_ops);

        *self.state.write() = Arc::new(SnapshotState {
            superblock: sb_final,
            inodes: new_inodes_map,
            overflow_synapses: new_overflow,
            key_dir: new_key_dir,
            reverse_keys: new_rev_keys,
        });

        Ok(CompactionReport {
            bytes_before,
            bytes_after: final_eof,
            hot_nodes_packed: plan.hot_node_ids.len(),
            cold_nodes_archived: plan.cold_node_ids.len(),
            locality_groups: plan.locality_groups,
            commit_seq: seq_final,
        })
    }

    /// Performs a full cryptographic scrub of every Inode, payload extent, and overflow synapse extent.
    pub fn verify_integrity(&self) -> Result<DbStats> {
        let snap = Arc::clone(&self.state.read());
        for (&nid, inode) in &snap.inodes {
            // Re-encode and decode Inode to validate structural invariants.
            let raw = inode.encode();
            let decoded = Inode::decode(&raw)?;
            debug_assert_eq!(nid, decoded.node_id);

            // Read and CRC/decompress-verify every payload extent.
            let _payload = self.read_inode_payload(inode)?;

            if let InodeStorage::Extent {
                edge_extent_offset,
                edge_overflow_count,
                ..
            } = inode.storage
            {
                if edge_extent_offset >= DATA_REGION_START && edge_overflow_count > 0 {
                    let _ = read_overflow_synapses(
                        &*self.backend,
                        edge_extent_offset,
                        edge_overflow_count as usize,
                    )?;
                }
            }
        }
        self.stats()
    }

    /// Returns live engine and storage telemetry.
    pub fn stats(&self) -> Result<DbStats> {
        let snap = self.state.read();
        let file_bytes = self.backend.len()?;
        let mut active_nodes = 0usize;
        let mut superseded_nodes = 0usize;
        let mut inline_nodes = 0usize;
        let mut compressed_nodes = 0usize;
        let mut total_tokens_active = 0u64;

        for inode in snap.inodes.values() {
            if inode.flags.is_live_active() {
                active_nodes += 1;
                total_tokens_active += inode.token_count as u64;
            }
            if inode.flags.contains(NodeFlags::SUPERSEDED) {
                superseded_nodes += 1;
            }
            if inode.flags.contains(NodeFlags::INLINE_DATA) {
                inline_nodes += 1;
            }
            if inode.flags.contains(NodeFlags::COMPRESSED_LZ4) {
                compressed_nodes += 1;
            }
        }

        Ok(DbStats {
            file_bytes,
            commit_seq: snap.superblock.commit_seq,
            compaction_count: snap.superblock.compaction_count,
            total_inodes: snap.inodes.len(),
            active_nodes,
            superseded_nodes,
            inline_nodes,
            compressed_nodes,
            keyed_entries: snap.key_dir.len(),
            total_tokens_active,
            backend_read_ops: self.backend.read_ops_count(),
            backend_write_ops: self.backend.write_ops_count(),
            is_network_share: self.backend.is_network_share(),
        })
    }

    /// Returns per-lane preparation counts across the 16 chaos write lanes.
    pub fn lane_distribution(&self) -> [u32; SHARD_WRITE_LANES] {
        std::array::from_fn(|i| self.lane_counters[i].load(Ordering::Relaxed))
    }

    fn write_superblock_slot(&self, sb: &Superblock) -> Result<()> {
        // Even commit_seq -> Slot B (offset 4096); odd commit_seq -> Slot A (offset 0).
        let slot_offset = if sb.commit_seq % 2 == 0 {
            SUPERBLOCK_SLOT_SIZE
        } else {
            0
        };
        let encoded = sb.encode();
        self.backend.write_at(slot_offset, &encoded)?;
        self.backend.sync_data()?;
        Ok(())
    }

    fn read_inode_payload(&self, inode: &Inode) -> Result<Vec<u8>> {
        match inode.storage {
            InodeStorage::Inline { len, bytes } => Ok(bytes[..len as usize].to_vec()),
            InodeStorage::Extent {
                data_offset,
                raw_len,
                stored_len,
                data_crc32,
                ..
            } => {
                let mut stored = vec![0u8; stored_len as usize];
                self.backend.read_at(data_offset, &mut stored)?;
                let actual_crc = crc32(&stored);
                if actual_crc != data_crc32 {
                    return Err(LibreDbError::ChecksumMismatch {
                        context: "extent_payload",
                        expected: data_crc32,
                        actual: actual_crc,
                    });
                }
                if inode.flags.contains(NodeFlags::COMPRESSED_LZ4) {
                    lz4_flex::block::decompress(&stored, raw_len as usize)
                        .map_err(|e| LibreDbError::Decompression(e.to_string()))
                } else {
                    Ok(stored)
                }
            }
        }
    }

    fn read_coalesced_extents(
        &self,
        snap: &SnapshotState,
        node_ids: &[u64],
    ) -> Result<(HashMap<u64, Vec<u8>>, usize)> {
        #[derive(Clone, Copy)]
        struct ExtentReq {
            node_id: u64,
            offset: u64,
            stored_len: u32,
            raw_len: u32,
            crc32: u32,
            compressed: bool,
        }

        let mut out: HashMap<u64, Vec<u8>> = HashMap::with_capacity(node_ids.len());
        let mut reqs: Vec<ExtentReq> = Vec::new();

        for &nid in node_ids {
            let inode = &snap.inodes[&nid];
            match inode.storage {
                InodeStorage::Inline { len, bytes } => {
                    out.insert(nid, bytes[..len as usize].to_vec());
                }
                InodeStorage::Extent {
                    data_offset,
                    raw_len,
                    stored_len,
                    data_crc32,
                    ..
                } => {
                    reqs.push(ExtentReq {
                        node_id: nid,
                        offset: data_offset,
                        stored_len,
                        raw_len,
                        crc32: data_crc32,
                        compressed: inode.flags.contains(NodeFlags::COMPRESSED_LZ4),
                    });
                }
            }
        }

        if reqs.is_empty() {
            return Ok((out, 0));
        }

        reqs.sort_unstable_by_key(|r| r.offset);

        // Merge spans separated by at most 4 KB (`4096 B`) up to `256 KB` max single read window!
        const MAX_GAP_BYTES: u64 = 4096;
        const MAX_COALESCED_WINDOW: u64 = 262_144;

        let mut io_reads = 0usize;
        let mut i = 0usize;
        while i < reqs.len() {
            let span_start = reqs[i].offset;
            let mut span_end = reqs[i].offset + (reqs[i].stored_len as u64);
            let mut j = i + 1;
            while j < reqs.len() {
                let next_start = reqs[j].offset;
                let next_end = next_start + (reqs[j].stored_len as u64);
                if next_start <= span_end + MAX_GAP_BYTES
                    && (next_end - span_start) <= MAX_COALESCED_WINDOW
                {
                    span_end = span_end.max(next_end);
                    j += 1;
                } else {
                    break;
                }
            }

            let mut window_buf = vec![0u8; (span_end - span_start) as usize];
            self.backend.read_at(span_start, &mut window_buf)?;
            io_reads += 1;

            for req in &reqs[i..j] {
                let rel_start = (req.offset - span_start) as usize;
                let rel_end = rel_start + (req.stored_len as usize);
                let slice = &window_buf[rel_start..rel_end];
                let actual_crc = crc32(slice);
                if actual_crc != req.crc32 {
                    return Err(LibreDbError::ChecksumMismatch {
                        context: "coalesced_extent_payload",
                        expected: req.crc32,
                        actual: actual_crc,
                    });
                }
                let decoded = if req.compressed {
                    lz4_flex::block::decompress(slice, req.raw_len as usize)
                        .map_err(|e| LibreDbError::Decompression(e.to_string()))?
                } else {
                    slice.to_vec()
                };
                out.insert(req.node_id, decoded);
            }

            i = j;
        }

        Ok((out, io_reads))
    }
}

fn collect_node_synapses(snap: &SnapshotState, inode: &Inode) -> Vec<Synapse> {
    let mut out = Vec::with_capacity(INLINE_SYNAPSE_CAP);
    for syn in inode.inline_synapses.iter().flatten() {
        out.push(*syn);
    }
    if let Some(extra) = snap.overflow_synapses.get(&inode.node_id) {
        out.extend_from_slice(extra);
    }
    out
}

fn encode_overflow_synapses(overflow: &[Synapse]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(overflow.len() * 8 + 4);
    for syn in overflow {
        buf.extend_from_slice(&syn.encode());
    }
    let checksum = crc32(&buf);
    buf.extend_from_slice(&checksum.to_le_bytes());
    buf
}

fn append_overflow_synapses(
    env_start: u64,
    envelope_buf: &mut Vec<u8>,
    overflow: &[Synapse],
) -> (u64, u32) {
    if overflow.is_empty() {
        return (0, 0);
    }
    let offset = env_start + (envelope_buf.len() as u64);
    let encoded = encode_overflow_synapses(overflow);
    envelope_buf.extend_from_slice(&encoded);
    (offset, overflow.len() as u32)
}

fn read_overflow_synapses(
    backend: &dyn StorageBackend,
    offset: u64,
    count: usize,
) -> Result<Vec<Synapse>> {
    let byte_len = count
        .checked_mul(8)
        .and_then(|n| n.checked_add(4))
        .ok_or(LibreDbError::CorruptFormat("overflow synapse length overflow"))?;
    let mut buf = vec![0u8; byte_len];
    backend.read_at(offset, &mut buf)?;

    let data_end = byte_len - 4;
    let expected_crc = u32::from_le_bytes(buf[data_end..].try_into().unwrap());
    let actual_crc = crc32(&buf[..data_end]);
    if expected_crc != actual_crc {
        return Err(LibreDbError::ChecksumMismatch {
            context: "overflow_synapses",
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let raw: [u8; 8] = buf[i * 8..i * 8 + 8].try_into().unwrap();
        if let Some(syn) = Synapse::decode(raw)? {
            out.push(syn);
        }
    }
    Ok(out)
}

fn apply_key_mutations(
    key_dir: &mut HashMap<(NodeKind, String), u64>,
    reverse_keys: &mut HashMap<u64, (NodeKind, String)>,
    ops: Vec<KeyMutation>,
) {
    for op in ops {
        match op {
            KeyMutation::Upsert { kind, key, node_id } => {
                if let Some(prev_id) = key_dir.insert((kind, key.clone()), node_id) {
                    if prev_id != node_id {
                        reverse_keys.remove(&prev_id);
                    }
                }
                reverse_keys.insert(node_id, (kind, key));
            }
            KeyMutation::Remove { kind, key } => {
                if let Some(prev_id) = key_dir.remove(&(kind, key)) {
                    reverse_keys.remove(&prev_id);
                }
            }
        }
    }
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

fn current_thread_lane_hint() -> usize {
    // Cheap deterministic hash of current ThreadId debug formatting or stack pointer address.
    let local_var = 0u8;
    let addr = (&local_var as *const u8) as usize;
    (addr >> 12) ^ (addr >> 20)
}
