//! Cross-process `WorkspaceTrustLockGuard`, monotonic `hmac-sha256:v4:r<rev>:` content-and-metadata
//! seals, rollback/deletion ratchets, `PreMutationSealGuard`, and `v2`/`v3` -> `v4` seal migrations.

use super::path_policy::canonicalize_with_missing_tail;
use super::vault::ensure_trust_anchor_secret;
use super::*;
use hmac::Mac;
use libredb_core::crc::count_tokens_exact;
use libredb_core::{EdgeKind, NodeFlags, StorageBackend};
pub(super) struct WsLockSlot {
    owner: Option<std::thread::ThreadId>,
    depth: usize,
    os_backend: Option<OsFileBackend>,
}

pub(super) type WsLockPair = (std::sync::Mutex<WsLockSlot>, std::sync::Condvar);

/// Cross-process (`OsFileBackend::lock_write_region`) and thread-reentrant intra-process
/// (`Mutex + Condvar`) lock serializing workspace trust verification, workspace memory mutations,
/// and two-phase `(proj_db, global_db)` seal updates for a given `(global_db, ws_root)` pair.
pub struct WorkspaceTrustLockGuard {
    slot: std::sync::Arc<WsLockPair>,
}

impl WorkspaceTrustLockGuard {
    pub fn acquire(global_db: &LibreDb, ws_root: &Path) -> Result<Self, String> {
        let norm = normalize_workspace_key(ws_root);
        Self::acquire_norm(global_db, &norm)
    }

    pub(crate) fn acquire_norm(global_db: &LibreDb, norm: &str) -> Result<Self, String> {
        static REGISTRY: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<PathBuf, std::sync::Arc<WsLockPair>>>,
        > = std::sync::OnceLock::new();

        let lock_path = workspace_trust_lock_path(global_db, norm)?;
        let canon_key =
            canonicalize_with_missing_tail(&lock_path).unwrap_or_else(|| lock_path.clone());
        let slot = {
            let map_mtx =
                REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
            let mut map = map_mtx.lock().unwrap_or_else(|e| e.into_inner());
            std::sync::Arc::clone(map.entry(canon_key).or_insert_with(|| {
                std::sync::Arc::new((
                    std::sync::Mutex::new(WsLockSlot {
                        owner: None,
                        depth: 0,
                        os_backend: None,
                    }),
                    std::sync::Condvar::new(),
                ))
            }))
        };

        let tid = std::thread::current().id();
        let mut st = slot.0.lock().unwrap_or_else(|e| e.into_inner());
        while st.owner.is_some_and(|o| o != tid) {
            st = slot.1.wait(st).unwrap_or_else(|e| e.into_inner());
        }
        if st.depth > 0 {
            st.depth += 1;
            drop(st);
            return Ok(Self { slot });
        }

        // Reserve intra-process ownership while blocking on the OS cross-process file lock;
        // `PendingReset` guarantees cleanup even if opening/locking errors or unwinds.
        st.owner = Some(tid);
        st.depth = 1;
        drop(st);

        struct PendingReset<'a> {
            slot: &'a WsLockPair,
            armed: bool,
        }
        impl Drop for PendingReset<'_> {
            fn drop(&mut self) {
                if self.armed {
                    let mut st = self.slot.0.lock().unwrap_or_else(|e| e.into_inner());
                    st.owner = None;
                    st.depth = 0;
                    st.os_backend = None;
                    self.slot.1.notify_all();
                }
            }
        }
        let mut reset_guard = PendingReset {
            slot: &slot,
            armed: true,
        };

        if let Ok(meta) = fs::symlink_metadata(&lock_path) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to use symlinked workspace trust lockfile at '{}'",
                    lock_path.display()
                ));
            }
        }
        let backend = OsFileBackend::open(&lock_path).map_err(|e| {
            format!(
                "Failed to open workspace trust lockfile '{}': {e}",
                lock_path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
        }
        backend.lock_write_region().map_err(|e| {
            format!(
                "Failed to acquire workspace trust lock '{}': {e}",
                lock_path.display()
            )
        })?;

        {
            let mut st = slot.0.lock().unwrap_or_else(|e| e.into_inner());
            st.os_backend = Some(backend);
        }
        reset_guard.armed = false;
        drop(reset_guard);

        Ok(Self { slot })
    }
}

impl Drop for WorkspaceTrustLockGuard {
    fn drop(&mut self) {
        let mut st = self.slot.0.lock().unwrap_or_else(|e| e.into_inner());
        st.depth = st.depth.saturating_sub(1);
        if st.depth == 0 {
            if let Some(backend) = st.os_backend.take() {
                let _ = backend.unlock_write_region();
            }
            st.owner = None;
            self.slot.1.notify_all();
        }
    }
}

pub(super) fn workspace_trust_lock_path(global_db: &LibreDb, norm: &str) -> Result<PathBuf, String> {
    let base_dir = global_db
        .path()
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("libredb_mem_seal_locks_{}", std::process::id()))
        });
    let locks_dir = base_dir.join(".seal_locks");
    if let Ok(meta) = fs::symlink_metadata(&locks_dir) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing to use symlinked workspace seal lock directory '{}'",
                locks_dir.display()
            ));
        }
    } else {
        fs::create_dir_all(&locks_dir).map_err(|e| {
            format!(
                "Failed to create workspace seal lock directory '{}': {e}",
                locks_dir.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&locks_dir, fs::Permissions::from_mode(0o700));
        }
    }
    let mut h = Sha256::new();
    h.update(b"LibreDB::WorkspaceTrustLock::v1\0");
    h.update(norm.as_bytes());
    let digest = h.finalize();
    Ok(locks_dir.join(format!("ws_{}.lock", hex_encode(&digest[..16]))))
}

#[cfg(test)]
pub(crate) fn workspace_trust_lock_path_for_root(
    global_db: &LibreDb,
    ws_root: &Path,
) -> Result<PathBuf, String> {
    let norm = normalize_workspace_key(ws_root);
    workspace_trust_lock_path(global_db, &norm)
}

/// Atomically advances `trust:seal_rev::<norm>` in `global_db` strictly monotonically
/// (`new_rev = max(cur_rev, target_rev)`) under `customizations.ldb`'s exclusive `IpcWriteGuard`.
/// Guarantees that a delayed or concurrent writer can NEVER regress an already confirmed revision.
pub(super) fn advance_global_seal_revision_monotonic(
    global_db: &LibreDb,
    norm: &str,
    target_rev: u64,
) -> Result<u64, String> {
    let rev_key = format!("trust:seal_rev::{norm}");
    let (rec_opt, _) = global_db
        .transact_key(NodeKind::Config, &rev_key, |existing| {
            let cur_rev = match existing {
                None => 0u64,
                Some(rec) => {
                    let raw = std::str::from_utf8(&rec.payload)
                        .map_err(|_| {
                            LibreDbError::CorruptFormat(
                                "Corrupt UTF-8 in trust:seal_rev inside customizations.ldb",
                            )
                        })?
                        .trim();
                    let parsed = raw.parse::<u64>().map_err(|_| {
                        LibreDbError::CorruptFormat(
                            "Corrupt non-numeric trust:seal_rev inside customizations.ldb",
                        )
                    })?;
                    if parsed == 0 || parsed.to_string() != raw {
                        return Err(LibreDbError::CorruptFormat(
                            "Non-canonical trust:seal_rev inside customizations.ldb",
                        ));
                    }
                    parsed
                }
            };
            if target_rev > cur_rev {
                Ok(Some(
                    WriteRequest::new(NodeKind::Config, target_rev.to_string().into_bytes())
                        .with_key(rev_key.clone())
                        .with_importance(185),
                ))
            } else {
                Ok(None)
            }
        })
        .map_err(|e| format!("Failed to advance '{rev_key}' monotonically: {e}"))?;

    match rec_opt {
        Some(r) => {
            let s = String::from_utf8_lossy(&r.payload);
            s.trim()
                .parse::<u64>()
                .map_err(|e| format!("Failed to decode committed '{rev_key}': {e}"))
        }
        None => Ok(0),
    }
}

/// Synchronizes external cross-process commits to `customizations.ldb` and fails closed if the
/// global database file on disk cannot be stat'd, read, or decoded (e.g. superblock/delta corruption).
/// Prevents long-lived processes (`libredb-mcp`) or multi-handle callers from consulting stale RAM trust!
pub fn check_global_trust_sync(global_db: &LibreDb) -> Result<(), String> {
    global_db.sync_from_disk_if_changed().map(|_| ()).map_err(|e| {
        format!(
            "Failed to synchronize global customizations.ldb from disk (failing closed): {e}"
        )
    })
}

/// Checks whether a `NodeKind::Config` key exists in `db`, treating ONLY `LibreDbError::KeyNotFound`
/// as `Ok(false)` and propagating any storage/checksum/corruption error as `Err` (fail-closed).
pub(crate) fn has_config_key_fail_closed(db: &LibreDb, key: &str) -> Result<bool, String> {
    match db.get_by_key(NodeKind::Config, key) {
        Ok(_) => Ok(true),
        Err(LibreDbError::KeyNotFound { .. }) => Ok(false),
        Err(e) => Err(format!(
            "Corrupt or unreadable Config key '{key}' in LibreDB (failing closed): {e}"
        )),
    }
}

pub(super) fn deprecate_config_if_present(db: &LibreDb, key: &str) -> Result<(), String> {
    db.deprecate_key(NodeKind::Config, key)
        .map(|_| ())
        .map_err(|e| format!("Failed to update Config key '{key}': {e}"))
}

pub(super) fn read_global_seal_revision(global_db: &LibreDb, norm: &str) -> Result<u64, String> {
    let rev_key = format!("trust:seal_rev::{norm}");
    match global_db.get_by_key(NodeKind::Config, &rev_key) {
        Ok(rec) => {
            let raw = std::str::from_utf8(&rec.payload)
                .map_err(|e| {
                    format!("Corrupt UTF-8 in '{rev_key}' inside customizations.ldb: {e}")
                })?
                .trim();
            let parsed = raw.parse::<u64>().map_err(|e| {
                format!("Corrupt seal revision '{raw}' in '{rev_key}' inside customizations.ldb: {e}")
            })?;
            if parsed == 0 || parsed.to_string() != raw {
                return Err(format!(
                    "Non-canonical seal revision '{raw}' in '{rev_key}' inside customizations.ldb"
                ));
            }
            Ok(parsed)
        }
        Err(LibreDbError::KeyNotFound { .. }) => Ok(0),
        Err(e) => Err(format!(
            "Failed to read '{rev_key}' from customizations.ldb (failing closed): {e}"
        )),
    }
}

/// Returns true if `ws_root` is recorded as an authorized workspace path in `global_db` (and not revoked).
/// Fails closed (`false`) if `global_db` cannot synchronize from disk or encounters any storage corruption.
#[cfg(test)]
pub fn is_workspace_path_authorized(global_db: Option<&LibreDb>, ws_root: &Path) -> bool {
    let Some(gdb) = global_db else {
        return false;
    };
    if check_global_trust_sync(gdb).is_err() {
        return false;
    }
    is_workspace_path_authorized_synced(gdb, ws_root)
}

pub(crate) fn is_workspace_path_authorized_synced(gdb: &LibreDb, ws_root: &Path) -> bool {
    let norm = normalize_workspace_key(ws_root);
    match has_config_key_fail_closed(gdb, &format!("trust:revoked::{norm}")) {
        Ok(false) => {}
        _ => return false,
    }
    match has_config_key_fail_closed(gdb, &format!("trust:allowed::{norm}")) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return false,
    }
    for (ino, key_opt, _) in gdb.list_inodes(Some(NodeKind::Config), false) {
        if let Some(k) = key_opt {
            if k.starts_with("workspace:") || k.starts_with("workspace_id::") {
                let Ok(rec) = gdb.get(ino.node_id) else {
                    return false;
                };
                let existing_p = PathBuf::from(String::from_utf8_lossy(&rec.payload).trim());
                if normalize_workspace_key(&existing_p) == norm {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns true if the host administrator explicitly enabled `mcp:allow_untrusted_workspaces = true`
/// inside `customizations.ldb`.
pub(crate) fn is_mcp_untrusted_workspaces_allowed(gdb: &LibreDb) -> bool {
    load_bool_config(Some(gdb), None, "mcp:allow_untrusted_workspaces", false)
}

/// Returns true if `ws_root` is authorized for `libredb-mcp` workspace operations according to
/// an already-synchronized `global_db` (`trust:allowed::<ws>`, registered `workspace_id::*` /
/// `workspace:*`, or explicit administrator opt-out `mcp:allow_untrusted_workspaces = true`).
#[cfg(test)]
pub(crate) fn is_mcp_workspace_authorized_in_global(gdb: &LibreDb, ws_root: &Path) -> bool {
    if is_workspace_path_authorized_synced(gdb, ws_root) {
        return true;
    }
    is_mcp_untrusted_workspaces_allowed(gdb)
}


/// Computes a deterministic SHA-256 digest over all active prompt- and context-relevant cognitive
/// capsules in `proj_db` (`Rule`, `Skill`, `SkillSection`, `SynonymCluster`, `AgentTemplate`,
/// `Decision`, `Fact`, `Task`, `TaskVerification`, `Handoff`, `Snapshot`, `CompactionCheckpoint`,
/// and `Config` excluding `sys::trust_seals`), authenticating both content (`kind`, `key`, `payload`)
/// and context-selecting persistent metadata (`node_id`, `importance`, `PINNED` flag, `token_count`,
/// `created_ns`, `updated_ns`, `generation`, and active cognitive graph synapses) while ignoring
/// ephemeral `WorkingSet`, `Symbol`, `Generic`, `TranscriptCursor`, `QuotaEvent`, `access_count`
/// telemetry, and code-indexer `Decision`/`Task -> Symbol` governance link refreshes.
pub fn compute_cognitive_content_digest(proj_db: &LibreDb) -> Result<([u8; 32], usize), String> {
    struct DigestTarget {
        kind_b: u8,
        node_id: u64,
        importance: u8,
        pinned_flag: u8,
        token_count: u32,
        created_ns: u64,
        eff_updated_ns: u64,
        eff_generation: u32,
        key: String,
        raw_syns: Vec<libredb_core::Synapse>,
    }

    let all_inodes = proj_db.list_inodes(None, false);
    let mut active_cognitive_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut targets: Vec<DigestTarget> = Vec::new();

    for (ino, key_opt, syns) in all_inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        let include = match ino.kind {
            NodeKind::Rule
            | NodeKind::Skill
            | NodeKind::SkillSection
            | NodeKind::SynonymCluster
            | NodeKind::AgentTemplate
            | NodeKind::Decision
            | NodeKind::Fact
            | NodeKind::Task
            | NodeKind::TaskVerification
            | NodeKind::Handoff
            | NodeKind::Snapshot
            | NodeKind::CompactionCheckpoint => true,
            NodeKind::Config => key_opt.as_deref() != Some(TRUST_SEALS_KEY),
            _ => false,
        };
        if !include {
            continue;
        }
        active_cognitive_ids.insert(ino.node_id);
        // Background `index_workspace` reconciles `Decision / Task --[Governs]--> Symbol` synapses via
        // `sync_edges_for_kinds`, advancing `updated_ns` and `generation` on `Decision`/`Task` without
        // changing their `node_id`-based `PreInvocation` selection order. All other cognitive kinds
        // (including `Fact`, whose top-12 `PreInvocation` hydration sorts by `(updated_ns, node_id)`)
        // bind `updated_ns` and `generation` directly.
        let (eff_updated_ns, eff_generation) = match ino.kind {
            NodeKind::Decision | NodeKind::Task => (0u64, 0u32),
            _ => (ino.updated_ns, ino.generation),
        };
        targets.push(DigestTarget {
            kind_b: ino.kind as u8,
            node_id: ino.node_id,
            importance: ino.importance,
            pinned_flag: ino.flags.0 & NodeFlags::PINNED,
            token_count: ino.token_count,
            created_ns: ino.created_ns,
            eff_updated_ns,
            eff_generation,
            key: key_opt.unwrap_or_default(),
            raw_syns: syns,
        });
    }

    let count = targets.len();
    struct HashedCapsule {
        kind_b: u8,
        key: String,
        node_id: u64,
        importance: u8,
        pinned_flag: u8,
        token_count: u32,
        created_ns: u64,
        eff_updated_ns: u64,
        eff_generation: u32,
        payload: Vec<u8>,
        cog_syns: Vec<(u8, u8, u64)>,
    }

    let mut entries: Vec<HashedCapsule> = Vec::with_capacity(count);
    if !targets.is_empty() {
        let ids: Vec<u64> = targets.iter().map(|t| t.node_id).collect();
        let (recs, _) = proj_db
            .get_many_coalesced(&ids)
            .map_err(|e| e.to_string())?;
        let mut by_id: std::collections::HashMap<u64, Vec<u8>> =
            std::collections::HashMap::with_capacity(recs.len());
        for r in recs {
            by_id.insert(r.node_id, r.payload);
        }
        for t in targets {
            let payload = by_id.remove(&t.node_id).unwrap_or_default();
            let mut cog_syns: Vec<(u8, u8, u64)> = t
                .raw_syns
                .into_iter()
                .filter(|s| {
                    s.kind != EdgeKind::Supersedes && active_cognitive_ids.contains(&s.target_id)
                })
                .map(|s| (s.kind as u8, s.weight, s.target_id))
                .collect();
            cog_syns.sort_unstable_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.2.cmp(&b.2))
                    .then_with(|| a.1.cmp(&b.1))
            });
            entries.push(HashedCapsule {
                kind_b: t.kind_b,
                key: t.key,
                node_id: t.node_id,
                importance: t.importance,
                pinned_flag: t.pinned_flag,
                token_count: t.token_count,
                created_ns: t.created_ns,
                eff_updated_ns: t.eff_updated_ns,
                eff_generation: t.eff_generation,
                payload,
                cog_syns,
            });
        }
        entries.sort_by(|a, b| {
            a.kind_b
                .cmp(&b.kind_b)
                .then_with(|| a.key.cmp(&b.key))
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(CONTENT_DIGEST_DOMAIN);
    hasher.update((entries.len() as u64).to_le_bytes());
    for e in &entries {
        hasher.update([e.kind_b, e.importance, e.pinned_flag]);
        hasher.update(e.node_id.to_le_bytes());
        hasher.update(e.token_count.to_le_bytes());
        hasher.update(e.created_ns.to_le_bytes());
        hasher.update(e.eff_updated_ns.to_le_bytes());
        hasher.update(e.eff_generation.to_le_bytes());
        hasher.update((e.key.len() as u32).to_le_bytes());
        hasher.update(e.key.as_bytes());
        hasher.update((e.payload.len() as u64).to_le_bytes());
        hasher.update(&e.payload);
        hasher.update((e.cog_syns.len() as u32).to_le_bytes());
        for &(sk, sw, st) in &e.cog_syns {
            hasher.update([sk, sw]);
            hasher.update(st.to_le_bytes());
        }
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok((arr, count))
}

/// Computes the exact legacy `v0.9.1..v0.9.3` content digest (`LibreDB::CognitiveContent::v3\0` over the
/// 10 `(kind, key, payload)` tuples) strictly for read-only cross-version signature verification inside
/// `has_valid_legacy_v3_content_seal` and `migrate_workspace_seal_v3_to_v4`.
pub(crate) fn compute_legacy_cognitive_content_digest_v3(
    proj_db: &LibreDb,
) -> Result<([u8; 32], usize), String> {
    let mut targets: Vec<(u8, String, u64)> = Vec::new();
    for (ino, key_opt, _) in proj_db.list_inodes(None, false) {
        if !ino.flags.is_live_active() {
            continue;
        }
        let include = match ino.kind {
            NodeKind::Rule
            | NodeKind::Skill
            | NodeKind::SkillSection
            | NodeKind::Decision
            | NodeKind::Fact
            | NodeKind::Task
            | NodeKind::Handoff
            | NodeKind::Snapshot
            | NodeKind::CompactionCheckpoint => true,
            NodeKind::Config => key_opt.as_deref() != Some(TRUST_SEALS_KEY),
            _ => false,
        };
        if include {
            targets.push((ino.kind as u8, key_opt.unwrap_or_default(), ino.node_id));
        }
    }

    let count = targets.len();
    let mut entries: Vec<(u8, String, Vec<u8>)> = Vec::with_capacity(count);
    if !targets.is_empty() {
        let ids: Vec<u64> = targets.iter().map(|(_, _, id)| *id).collect();
        let (recs, _) = proj_db
            .get_many_coalesced(&ids)
            .map_err(|e| e.to_string())?;
        let mut by_id: std::collections::HashMap<u64, Vec<u8>> =
            std::collections::HashMap::with_capacity(recs.len());
        for r in recs {
            by_id.insert(r.node_id, r.payload);
        }
        for (kind_b, k, id) in targets {
            let payload = by_id.remove(&id).unwrap_or_default();
            entries.push((kind_b, k, payload));
        }
        entries.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(CONTENT_DIGEST_V3_DOMAIN);
    hasher.update((entries.len() as u64).to_le_bytes());
    for (kind_b, key_str, payload) in &entries {
        hasher.update([*kind_b]);
        hasher.update((key_str.len() as u32).to_le_bytes());
        hasher.update(key_str.as_bytes());
        hasher.update((payload.len() as u64).to_le_bytes());
        hasher.update(payload);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok((arr, count))
}

/// Returns `true` if `global_db` (`customizations.ldb`) records that `ws_root` has ever been
/// cryptographically sealed (`trust:sealed::<ws>`, `trust:seal_rev::<ws>`, `trust:v4_upgraded::<ws>`,
/// or `trust:v3_upgraded::<ws>`). Conservative fail-closed: if `global_db` cannot synchronize from
/// disk or read its config keys cleanly, returns `true` so missing/unsealed workspace DBs are never
/// misclassified as fresh first-time setups.
pub fn has_prior_workspace_seal_marker(global_db: &LibreDb, ws_root: &Path) -> bool {
    if check_global_trust_sync(global_db).is_err() {
        return true;
    }
    let norm = normalize_workspace_key(ws_root);
    has_prior_workspace_seal_marker_norm_checked(global_db, &norm).unwrap_or(true)
}

pub(super) fn has_prior_workspace_seal_marker_norm_checked(
    global_db: &LibreDb,
    norm: &str,
) -> Result<bool, String> {
    Ok(has_config_key_fail_closed(global_db, &format!("trust:sealed::{norm}"))?
        || has_config_key_fail_closed(global_db, &format!("trust:seal_rev::{norm}"))?
        || has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))?
        || has_config_key_fail_closed(global_db, &format!("trust:v3_upgraded::{norm}"))?)
}

/// Returns `true` when `ws_root` was previously sealed on this host, yet `.agents/memory.ldb` is now
/// missing, lacks `sys::trust_seals` (while not explicitly `--revoke`d), or was rolled back to `0`
/// cognitive capsules after previously sealing `>= 1` cognitive capsules (`trust:nonempty_sealed::<ws>`).
/// Used to enforce explicit separation between initial workspace setup and post-loss recovery (`--reinit-lost`).
pub fn is_unsealed_replacement_of_sealed_workspace(global_db: &LibreDb, ws_root: &Path) -> bool {
    if check_global_trust_sync(global_db).is_err() {
        return false;
    }
    let norm = normalize_workspace_key(ws_root);
    let Ok(_ws_lock) = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm) else {
        return false;
    };
    if check_global_trust_sync(global_db).is_err() {
        return false;
    }
    let Ok(true) = has_prior_workspace_seal_marker_norm_checked(global_db, &norm) else {
        return false;
    };
    let Ok(is_revoked) = has_config_key_fail_closed(global_db, &format!("trust:revoked::{norm}"))
    else {
        return false;
    };
    if is_revoked {
        return false;
    }
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if !ldb_path.is_file() {
        return true;
    }
    let Ok(pdb) = LibreDb::open(&ldb_path) else {
        return false;
    };
    if pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY).is_err() {
        return true;
    }
    if has_config_key_fail_closed(global_db, &format!("trust:nonempty_sealed::{norm}"))
        .unwrap_or(false)
    {
        if let Ok((_, capsule_count)) = compute_cognitive_content_digest(&pdb) {
            if capsule_count == 0 {
                return true;
            }
        }
    }
    false
}

/// Detects whether `<ws_root>/.agents/memory.ldb` carries an authentic `HMAC-SHA256` seal for this
/// host whose authenticated revision `proj_rev` is strictly older than `global_rev` recorded in
/// `customizations.ldb` (`trust:seal_rev::<ws>`), returning `Ok(Some((proj_rev, global_rev)))` when
/// a historical snapshot rollback is detected and propagating any `global_db` sync/read failure as `Err`.
pub fn detect_workspace_seal_rollback(
    global_db: &LibreDb,
    ws_root: &Path,
) -> Result<Option<(u64, u64)>, String> {
    check_global_trust_sync(global_db)?;
    let norm = normalize_workspace_key(ws_root);
    let _ws_lock = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm)?;
    check_global_trust_sync(global_db)?;
    let global_rev = read_global_seal_revision(global_db, &norm)?;
    if global_rev == 0 {
        return Ok(None);
    }
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if !ldb_path.is_file() {
        return Ok(None);
    }
    let Ok(pdb) = LibreDb::open(&ldb_path) else {
        return Ok(None);
    };
    let Ok((content_digest, capsule_count)) = compute_cognitive_content_digest(&pdb) else {
        return Ok(None);
    };
    let nonempty_ratcheted =
        has_config_key_fail_closed(global_db, &format!("trust:nonempty_sealed::{norm}"))?;
    if nonempty_ratcheted && capsule_count == 0 {
        // 0-capsule wipe of a previously populated workspace is classified under `--reinit-lost`.
        return Ok(None);
    }
    let Ok(rec) = pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) else {
        return Ok(None);
    };
    let already_v4_ratcheted =
        has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))?;
    let mut secret = ensure_trust_anchor_secret(global_db)?;
    let seals_txt = String::from_utf8_lossy(&rec.payload);
    let proj_rev_opt = verify_and_extract_host_seal_rev(
        &secret,
        &norm,
        &content_digest,
        &seals_txt,
        already_v4_ratcheted,
    );
    secure_zero(&mut secret);
    if let Some(proj_rev) = proj_rev_opt {
        if proj_rev < global_rev {
            return Ok(Some((proj_rev, global_rev)));
        }
    }
    Ok(None)
}

/// Returns `true` strictly for diagnostic classification when `<ws_root>/.agents/memory.ldb`
/// has NOT yet been upgraded to `v4` on this host and carries an authentic `v0.9.1..v0.9.3`
/// `hmac-sha256:v3:` tag over `CognitiveContent::v3`. Never grants runtime trust on its own.
pub fn has_valid_legacy_v3_content_seal(global_db: &LibreDb, ws_root: &Path) -> bool {
    if check_global_trust_sync(global_db).is_err() {
        return false;
    }
    let norm = normalize_workspace_key(ws_root);
    let Ok(_ws_lock) = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm) else {
        return false;
    };
    if check_global_trust_sync(global_db).is_err() {
        return false;
    }
    if has_config_key_fail_closed(global_db, &format!("trust:revoked::{norm}")).unwrap_or(true)
        || has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))
            .unwrap_or(true)
        || has_config_key_fail_closed(global_db, &format!("trust:seal_rev::{norm}"))
            .unwrap_or(true)
    {
        return false;
    }
    if !is_workspace_path_authorized_synced(global_db, ws_root) {
        return false;
    }
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    let Ok(pdb) = LibreDb::open(&ldb_path) else {
        return false;
    };
    let Ok(rec) = pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) else {
        return false;
    };
    let Ok((legacy_v3_digest, _)) = compute_legacy_cognitive_content_digest_v3(&pdb) else {
        return false;
    };
    let Ok(mut secret) = ensure_trust_anchor_secret(global_db) else {
        return false;
    };
    let host_tag = compute_host_seal_slot_id(&secret, &norm);
    let expected_legacy_v3 = compute_workspace_seal_v3(&secret, &norm, &legacy_v3_digest);
    let expected_slot_v3 = format!("{host_tag}={expected_legacy_v3}");
    secure_zero(&mut secret);

    let seals_txt = String::from_utf8_lossy(&rec.payload);
    if seals_txt
        .lines()
        .any(|l| l.trim().starts_with(&format!("{host_tag}=hmac-sha256:v4:")))
    {
        return false;
    }
    seals_txt.lines().any(|line| {
        let trimmed = line.trim().as_bytes();
        constant_time_eq(trimmed, expected_legacy_v3.as_bytes())
            || constant_time_eq(trimmed, expected_slot_v3.as_bytes())
    })
}

/// Determines whether `<ws_root>/.agents/memory.ldb` (or `.db`) is trusted, untampered, AND at the
/// current monotonic workspace revision (`proj_rev >= global_rev`):
/// 1. Private Antigravity conversation brain (`~/.gemini/antigravity*/brain/<cid>`) -> `true`.
/// 2. `global_db` disk synchronization or config read failure -> `false` (strict fail-closed).
/// 3. Explicit revocation (`trust:revoked::<ws>`) -> `false`.
/// 4. Git-tracked `.agents/memory.*` inside `.git/index` -> `false` unless explicitly sealed via `libredb trust`.
/// 5. Brand-new workspace where neither `.ldb` nor `.db` exists yet AND no prior seal marker exists -> `true`.
/// 6. Existing `.agents/memory.ldb` MUST carry a valid `v4` HMAC seal authenticating `(norm, content_digest, proj_rev)`
///    with `proj_rev >= global_rev` (`trust:seal_rev::<ws>`). Replaying any older non-empty `v4`-sealed snapshot
///    (`proj_rev < global_rev`) fails closed until restored or explicitly accepted via `libredb trust --accept-rollback`,
///    while a mid-commit crash after Phase 1 (`proj_rev == global_rev + 1`) remains seamlessly valid (`N + 1 >= N`).
pub fn is_workspace_memory_trusted(global_db: Option<&LibreDb>, ws_root: &Path) -> bool {
    if is_private_brain_workspace(ws_root) {
        return true;
    }
    let norm = normalize_workspace_key(ws_root);

    let Some(gdb) = global_db else {
        let agents_dir = ws_root.join(".agents");
        return !agents_dir.join("memory.ldb").exists() && !agents_dir.join("memory.db").exists();
    };
    if check_global_trust_sync(gdb).is_err() {
        return false;
    }
    let Ok(_ws_lock) = WorkspaceTrustLockGuard::acquire_norm(gdb, &norm) else {
        return false;
    };
    if check_global_trust_sync(gdb).is_err() {
        return false;
    }

    match has_config_key_fail_closed(gdb, &format!("trust:revoked::{norm}")) {
        Ok(false) => {}
        _ => return false,
    }
    let Ok(explicitly_allowed) =
        has_config_key_fail_closed(gdb, &format!("trust:allowed::{norm}"))
    else {
        return false;
    };

    if is_git_index_tracking_agents_db(ws_root) && !explicitly_allowed {
        return false;
    }

    let Ok(has_prior_seal) = has_prior_workspace_seal_marker_norm_checked(gdb, &norm) else {
        return false;
    };
    let Ok(already_v4_ratcheted) =
        has_config_key_fail_closed(gdb, &format!("trust:v4_upgraded::{norm}"))
    else {
        return false;
    };
    let Ok(nonempty_ratcheted) =
        has_config_key_fail_closed(gdb, &format!("trust:nonempty_sealed::{norm}"))
    else {
        return false;
    };
    let Ok(global_rev) = read_global_seal_revision(gdb, &norm) else {
        return false;
    };

    let agents_dir = ws_root.join(".agents");
    let ldb_path = agents_dir.join("memory.ldb");
    let db_path = agents_dir.join("memory.db");
    if !ldb_path.exists() && !db_path.exists() {
        // Once a workspace has been sealed on this host, external deletion of `.agents/memory.ldb`
        // MUST fail closed rather than silently re-authorizing a blank replacement database.
        return !has_prior_seal && global_rev == 0;
    }

    let path_authorized =
        explicitly_allowed || is_workspace_path_authorized_synced(gdb, ws_root);
    if !ldb_path.is_file() {
        // Monotonic anti-downgrade guard: if this workspace was already sealed on this host,
        // deleting `.agents/memory.ldb` and planting a legacy `.agents/memory.db` must NOT bypass seal checks.
        if has_prior_seal || global_rev > 0 {
            return false;
        }
        return path_authorized;
    }

    let Ok(pdb) = LibreDb::open(&ldb_path) else {
        return false;
    };
    let Ok((content_digest, capsule_count)) = compute_cognitive_content_digest(&pdb) else {
        return false;
    };
    if nonempty_ratcheted && capsule_count == 0 {
        // Reject rollback of a previously populated workspace database to a captured 0-capsule snapshot.
        return false;
    }
    let Ok(mut secret) = ensure_trust_anchor_secret(gdb) else {
        return false;
    };

    match pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) {
        Ok(rec) => {
            let seals = String::from_utf8_lossy(&rec.payload);
            let proj_rev_opt = verify_and_extract_host_seal_rev(
                &secret,
                &norm,
                &content_digest,
                &seals,
                already_v4_ratcheted,
            );
            secure_zero(&mut secret);
            matches!(proj_rev_opt, Some(proj_rev) if proj_rev >= global_rev)
        }
        Err(LibreDbError::KeyNotFound { .. }) => {
            secure_zero(&mut secret);
            // Allow cache-only `.agents/memory.ldb` (0 cognitive capsules, e.g. fresh `index-workspace` symbols only)
            // ONLY when the workspace has NEVER been sealed before on this host.
            !has_prior_seal && global_rev == 0 && capsule_count == 0 && path_authorized
        }
        Err(_) => {
            secure_zero(&mut secret);
            false
        }
    }
}

/// Cryptographically seals `ws_root`, the `v4` SHA-256 content+metadata+synapse digest of `proj_db`'s
/// cognitive capsules, AND a monotonically advancing per-workspace seal revision `r<rev>` (`>= 1`) via
/// RFC 2104 `HMAC-SHA256` (`hmac-sha256:v4:r<rev>:<64-hex>`), protected by BOTH:
/// 1. Cross-process + reentrant intra-process `WorkspaceTrustLockGuard` across the entire operation, AND
/// 2. Kernel-locked CAS checks (`proj_db.transact_key` + `advance_global_seal_revision_monotonic`) so
///    even uncooperative concurrent writers can NEVER clobber a newer seal or regress `trust:seal_rev::<ws>`.
pub fn seal_workspace_memory(
    global_db: &LibreDb,
    proj_db: &LibreDb,
    ws_root: &Path,
) -> Result<(), String> {
    seal_workspace_memory_inner(global_db, proj_db, ws_root, true, None)
}

pub(super) fn seal_workspace_memory_inner(
    global_db: &LibreDb,
    proj_db: &LibreDb,
    ws_root: &Path,
    acquire_ws_lock: bool,
    after_phase1_hook: Option<&dyn Fn()>,
) -> Result<(), String> {
    check_global_trust_sync(global_db)?;
    let norm = normalize_workspace_key(ws_root);
    let _ws_lock = if acquire_ws_lock {
        Some(WorkspaceTrustLockGuard::acquire_norm(global_db, &norm)?)
    } else {
        None
    };

    for _attempt in 0..4 {
        check_global_trust_sync(global_db)?;
        proj_db.sync_from_disk_if_changed().map_err(|e| {
            format!("Failed to synchronize workspace memory from disk before sealing: {e}")
        })?;
        let global_rev = read_global_seal_revision(global_db, &norm)?;
        let already_v4_ratcheted =
            has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))?;
        let (content_digest, capsule_count) = compute_cognitive_content_digest(proj_db)?;

        let (expected_seal_ver, existing_seals_txt) =
            match proj_db.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) {
                Ok(rec) => (
                    Some((rec.node_id, rec.generation)),
                    String::from_utf8_lossy(&rec.payload).into_owned(),
                ),
                Err(LibreDbError::KeyNotFound { .. }) => (None, String::new()),
                Err(e) => {
                    return Err(format!(
                        "Failed to read existing sys::trust_seals in workspace memory: {e}"
                    ));
                }
            };

        let mut secret = ensure_trust_anchor_secret(global_db)?;
        let host_tag = compute_host_seal_slot_id(&secret, &norm);
        let existing_valid_rev = if existing_seals_txt.is_empty() {
            None
        } else {
            verify_and_extract_host_seal_rev(
                &secret,
                &norm,
                &content_digest,
                &existing_seals_txt,
                already_v4_ratcheted,
            )
        };
        let target_rev = match existing_valid_rev {
            Some(r) if r >= 1 && r >= global_rev => r,
            _ => {
                let prev_slot_rev = extract_syntactic_host_slot_rev(&existing_seals_txt, &host_tag);
                let bounded_prev = if prev_slot_rev <= global_rev.saturating_add(1024) {
                    prev_slot_rev
                } else {
                    0
                };
                let next_res = global_rev.max(bounded_prev).checked_add(1);
                match next_res {
                    Some(next_rev) => next_rev,
                    None => {
                        secure_zero(&mut secret);
                        return Err("Workspace seal revision counter overflowed u64".to_owned());
                    }
                }
            }
        };
        let bare_seal = compute_workspace_seal_v4_rev(&secret, &norm, &content_digest, target_rev);
        let seal_line = format!("{host_tag}={bare_seal}");
        secure_zero(&mut secret);

        // If an authorized transition reduces `capsule_count` back to `0` (e.g. deprecating the last capsule
        // or running `libredb trust --reinit-lost`), clear `trust:nonempty_sealed` BEFORE writing `proj_db`
        // so concurrent readers never observe `nonempty_ratcheted && capsule_count == 0`.
        let nonempty_key = format!("trust:nonempty_sealed::{norm}");
        if capsule_count == 0 && has_config_key_fail_closed(global_db, &nonempty_key)? {
            deprecate_config_if_present(global_db, &nonempty_key)?;
        }

        // Phase 1: Conditionally commit `hmac-sha256:v4:r<target_rev>:<hex>` into `proj_db` via CAS
        // so concurrent uncooperative writes are detected and retried cleanly instead of clobbered.
        let mut seals: Vec<String> = existing_seals_txt
            .lines()
            .map(str::trim)
            .filter(|s| {
                !s.is_empty()
                    && !s.starts_with(&format!("{host_tag}="))
                    && !s.starts_with("hmac-sha256:v2:")
                    && !s.starts_with("hmac-sha256:v3:")
                    && !s.starts_with("hmac-sha256:v4:")
            })
            .map(ToOwned::to_owned)
            .collect();

        seals.push(bare_seal);
        seals.push(seal_line);
        if seals.len() > 16 {
            let drain_cnt = seals.len() - 16;
            seals.drain(0..drain_cnt);
        }
        let body = seals.join("\n");
        if existing_seals_txt.as_bytes() != body.as_bytes() {
            let body_bytes = body.into_bytes();
            let (_, committed) = proj_db
                .transact_key(NodeKind::Config, TRUST_SEALS_KEY, |cur_opt| {
                    let cur_ver = cur_opt.map(|r| (r.node_id, r.generation));
                    if cur_ver != expected_seal_ver {
                        return Ok(None);
                    }
                    Ok(Some(
                        WriteRequest::new(NodeKind::Config, body_bytes)
                            .with_key(TRUST_SEALS_KEY)
                            .with_importance(200),
                    ))
                })
                .map_err(|e| e.to_string())?;
            if !committed {
                // Concurrent uncooperative writer updated `sys::trust_seals`; reload and retry.
                continue;
            }
            let (post_digest, _) = compute_cognitive_content_digest(proj_db)?;
            if post_digest != content_digest {
                // Concurrent uncooperative writer mutated project capsules during digest calculation; retry.
                continue;
            }
        }

        if let Some(hook) = after_phase1_hook {
            hook();
        }

        // Phase 2: Commit ratchets via `put_if_absent` and strictly monotonic `trust:seal_rev::<ws>`
        // (`new_rev = max(cur_rev, target_rev)`) so delayed writers can NEVER regress `global_rev`.
        deprecate_config_if_present(global_db, &format!("trust:revoked::{norm}"))?;
        let clean_display = crate::gitea::strip_verbatim_prefix(ws_root)
            .to_string_lossy()
            .into_owned();
        let allow_key = format!("trust:allowed::{norm}");
        let allow_payload = clean_display.into_bytes();
        global_db
            .transact_key(NodeKind::Config, &allow_key, |existing| {
                if existing.is_some_and(|r| r.payload == allow_payload) {
                    Ok(None)
                } else {
                    Ok(Some(
                        WriteRequest::new(NodeKind::Config, allow_payload)
                            .with_key(allow_key.clone())
                            .with_importance(185),
                    ))
                }
            })
            .map_err(|e| e.to_string())?;

        for (ratchet_key, marker) in [
            (format!("trust:sealed::{norm}"), b"1".as_slice()),
            (format!("trust:v3_upgraded::{norm}"), b"v3".as_slice()),
            (format!("trust:v4_upgraded::{norm}"), b"v4".as_slice()),
        ] {
            global_db
                .put_if_absent(
                    WriteRequest::new(NodeKind::Config, marker.to_vec())
                        .with_key(ratchet_key)
                        .with_importance(180),
                )
                .map_err(|e| e.to_string())?;
        }

        advance_global_seal_revision_monotonic(global_db, &norm, target_rev)?;

        if capsule_count > 0 {
            global_db
                .put_if_absent(
                    WriteRequest::new(NodeKind::Config, b"1".to_vec())
                        .with_key(nonempty_key)
                        .with_importance(180),
                )
                .map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    Err(format!(
        "Failed to seal workspace '{}' due to sustained uncooperative concurrent modifications across 4 retries.",
        ws_root.display()
    ))
}

/// Type-enforced pre-mutation trust guard holding `WorkspaceTrustLockGuard` continuously from
/// BEFORE verifying `is_workspace_memory_trusted`, across project capsule mutations, through
/// Phase 1 + Phase 2 of `reseal_after_write`.
/// Prevents post-hoc trust laundering AND prevents concurrent writers/readers from observing or
/// clobbering intermediate unsealed mutations.
pub struct PreMutationSealGuard {
    authorized_ws: Option<PathBuf>,
    _ws_lock: Option<WorkspaceTrustLockGuard>,
}

impl PreMutationSealGuard {
    pub fn verify_before_write(
        global_db: Option<&LibreDb>,
        db_path: &Path,
    ) -> Result<Self, String> {
        Self::verify_before_write_ext(global_db, db_path, false)
    }

    pub fn verify_before_write_allow_fresh_global_import(
        global_db: Option<&LibreDb>,
        db_path: &Path,
    ) -> Result<Self, String> {
        Self::verify_before_write_ext(global_db, db_path, true)
    }

    fn verify_before_write_ext(
        global_db: Option<&LibreDb>,
        db_path: &Path,
        allow_fresh_global_import: bool,
    ) -> Result<Self, String> {
        let joined_db = if db_path.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(db_path))
                .unwrap_or_else(|_| db_path.to_path_buf())
        } else {
            db_path.to_path_buf()
        };
        let resolved_db = canonicalize_with_missing_tail(&joined_db).unwrap_or(joined_db);
        let norm_db = normalize_workspace_key(&resolved_db);

        let is_global_target = norm_db.ends_with("/.gemini/libredb/customizations.ldb")
            || global_db
                .and_then(LibreDb::path)
                .is_some_and(|gp| normalize_workspace_key(gp) == norm_db);
        if is_global_target && !(allow_fresh_global_import && !resolved_db.exists()) {
            return Err(format!(
                "Direct CLI mutation of global customizations.ldb ('{}') via low-level commands is blocked to protect sys::trust_anchor_secret and workspace trust ratchets; use 'libredb config' or 'libredb trust' instead.",
                db_path.display()
            ));
        }

        let Some(gdb) = global_db else {
            let is_agents_memory = resolved_db
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(".agents"))
                && resolved_db
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("memory.ldb"));
            if is_agents_memory && resolved_db.is_file() {
                let db = LibreDb::open(&resolved_db).map_err(|e| {
                    format!(
                        "Refusing to mutate unreadable workspace memory '{}' without customizations.ldb: {e}",
                        db_path.display()
                    )
                })?;
                if db.get_by_key(NodeKind::Config, "sys::trust_seals").is_ok() {
                    return Err(format!(
                        "Workspace memory at '{}' carries a cryptographic trust seal, but global customizations.ldb is unavailable; pass '--global <customizations.ldb>' or initialize the host trust store before mutating it.",
                        db_path.display()
                    ));
                }
            }
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: None,
            });
        };
        check_global_trust_sync(gdb)?;

        let Some(parent) = resolved_db.parent() else {
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: None,
            });
        };
        if !parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(".agents"))
        {
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: None,
            });
        }
        let is_memory_ldb = resolved_db
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("memory.ldb"));
        if !is_memory_ldb {
            // Non-`memory.ldb` scratch files inside `.agents/` must never re-seal over the real
            // workspace `.agents/memory.ldb` or advance `trust:seal_rev::<ws>`.
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: None,
            });
        }
        let Some(ws_root) = parent.parent() else {
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: None,
            });
        };
        let norm = normalize_workspace_key(ws_root);
        let lock_guard = WorkspaceTrustLockGuard::acquire_norm(gdb, &norm)?;
        check_global_trust_sync(gdb)?;

        if has_config_key_fail_closed(gdb, &format!("trust:revoked::{norm}"))? {
            return Err(format!(
                "Workspace memory at '{}' belongs to an explicitly revoked workspace '{}'; run 'libredb trust \"{}\"' to re-authorize before writing to it.",
                db_path.display(),
                ws_root.display(),
                ws_root.display()
            ));
        }
        let has_prior_seal = has_prior_workspace_seal_marker_norm_checked(gdb, &norm)?;
        if !has_prior_seal && !is_workspace_path_authorized_synced(gdb, ws_root) {
            // Workspace was never sealed, never revoked, and is not registered as trusted in `global_db`;
            // never auto-authorize or seal it, while still holding `lock_guard` across the write.
            return Ok(Self {
                authorized_ws: None,
                _ws_lock: Some(lock_guard),
            });
        }
        if !is_workspace_memory_trusted(Some(gdb), ws_root) {
            if is_unsealed_replacement_of_sealed_workspace(gdb, ws_root) {
                return Err(format!(
                    "Workspace memory at '{}' was previously sealed on this host, but .agents/memory.ldb is now missing, unsealed, or rolled back to empty. Restore .agents/memory.ldb from backup or explicitly run 'libredb trust --reinit-lost \"{}\"' before writing to it.",
                    db_path.display(),
                    ws_root.display()
                ));
            }
            if let Some((proj_rev, global_rev)) = detect_workspace_seal_rollback(gdb, ws_root)? {
                return Err(format!(
                    "Workspace memory at '{}' carries older seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (historical snapshot rollback detected). Restore the latest .agents/memory.ldb or explicitly run 'libredb trust --accept-rollback \"{}\"' before writing to it.",
                    db_path.display(),
                    ws_root.display()
                ));
            }
            if has_valid_legacy_v3_content_seal(gdb, ws_root) {
                return Err(format!(
                    "Workspace memory at '{}' carries a valid legacy v0.9.3 content seal (CognitiveContent::v3) that does not yet authenticate v4 metadata/synapses. Run 'libredb trust --migrate-v3 \"{}\"' (with '--confirm-metadata' after reviewing unauthenticated metadata if prompted) before writing to it.",
                    db_path.display(),
                    ws_root.display()
                ));
            }
            return Err(format!(
                "Workspace memory at '{}' failed workspace content-seal verification (offline modification or legacy seal detected). Inspect the database and run 'libredb trust \"{}\"' (or 'libredb trust --migrate-v3 \"{}\"' / 'libredb trust --migrate-v2 \"{}\"') before writing to it.",
                db_path.display(),
                ws_root.display(),
                ws_root.display(),
                ws_root.display()
            ));
        }
        Ok(Self {
            authorized_ws: Some(ws_root.to_path_buf()),
            _ws_lock: Some(lock_guard),
        })
    }

    pub fn reseal_after_write(
        &self,
        global_db: Option<&LibreDb>,
        proj_db: &LibreDb,
    ) -> Result<(), String> {
        if let (Some(gdb), Some(ref ws_root)) = (global_db, &self.authorized_ws) {
            seal_workspace_memory(gdb, proj_db, ws_root).map_err(|err| {
                format!(
                    "Workspace mutation succeeded, but updating hmac-sha256:v4 trust seal for '{}' failed: {err}",
                    ws_root.display()
                )
            })
        } else {
            Ok(())
        }
    }
}

/// Explicitly migrates a legacy `v0.9.0` path-bound `hmac-sha256:v2:` workspace seal to a
/// metadata-and-content-bound `hmac-sha256:v4:` seal ONLY after verifying:
/// 1. `ws_root` is authorized in `global_db` and `.agents/memory.*` is not tracked in `.git/index`.
/// 2. `<ws_root>/.agents/memory.ldb` was NOT already upgraded to `v3` or `v4` on this host.
/// 3. `sys::trust_seals` carries a genuine `hmac-sha256:v2:` tag matching this host's `sys::trust_anchor_secret`.
pub fn migrate_workspace_seal_v2_to_v3(
    global_db: &LibreDb,
    ws_root: &Path,
) -> Result<bool, String> {
    check_global_trust_sync(global_db)?;
    let norm = normalize_workspace_key(ws_root);
    let _ws_lock = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm)?;
    check_global_trust_sync(global_db)?;
    if has_config_key_fail_closed(global_db, &format!("trust:revoked::{norm}"))? {
        return Err(format!(
            "Workspace '{}' has been explicitly revoked; run 'libredb trust \"{}\"' to re-authorize.",
            ws_root.display(),
            ws_root.display()
        ));
    }
    if !is_workspace_path_authorized_synced(global_db, ws_root) {
        return Err(format!(
            "Workspace '{}' is not registered as trusted in customizations.ldb.",
            ws_root.display()
        ));
    }
    if is_git_index_tracking_agents_db(ws_root)
        && !has_config_key_fail_closed(global_db, &format!("trust:allowed::{norm}"))?
    {
        return Err(format!(
            "Workspace '{}' tracks .agents/memory.* inside .git/index; refusing automatic v2 seal migration.",
            ws_root.display()
        ));
    }
    if is_workspace_memory_trusted(Some(global_db), ws_root) {
        return Ok(false);
    }

    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if !ldb_path.is_file() {
        if has_prior_workspace_seal_marker_norm_checked(global_db, &norm)? {
            return Err(format!(
                "Previously sealed workspace '{}' is missing .agents/memory.ldb; restore from backup or run 'libredb trust --reinit-lost \"{}\"'.",
                ws_root.display(),
                ws_root.display()
            ));
        }
        return Ok(false);
    }
    let pdb = LibreDb::open(&ldb_path).map_err(|e| e.to_string())?;
    let rec = pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY).map_err(|_| {
        format!(
            "Workspace memory at '{}' has no sys::trust_seals entry; inspect and run 'libredb trust \"{}\"' if trusted.",
            ldb_path.display(),
            ws_root.display()
        )
    })?;

    let mut secret = ensure_trust_anchor_secret(global_db)?;
    let host_tag = compute_host_seal_slot_id(&secret, &norm);
    let expected_v2 = compute_legacy_workspace_seal_v2(&secret, &norm);
    secure_zero(&mut secret);

    let seals_txt = String::from_utf8_lossy(&rec.payload);
    let already_upgraded_in_global =
        has_prior_workspace_seal_marker_norm_checked(global_db, &norm)?;
    let has_failed_host_slot = seals_txt.lines().any(|l| {
        let t = l.trim();
        t.starts_with(&format!("{host_tag}=hmac-sha256:v3:"))
            || t.starts_with(&format!("{host_tag}=hmac-sha256:v4:"))
    });
    if already_upgraded_in_global || has_failed_host_slot {
        return Err(format!(
            "Workspace memory at '{}' was already upgraded beyond hmac-sha256:v2 on this host (content tampering or v2 replay downgrade detected); refusing v2 migration.",
            ldb_path.display()
        ));
    }

    let has_valid_v2 = seals_txt
        .lines()
        .any(|line| constant_time_eq(line.trim().as_bytes(), expected_v2.as_bytes()));
    if !has_valid_v2 {
        return Err(format!(
            "Workspace memory at '{}' does not carry a valid hmac-sha256:v2 seal for this host; inspect and run 'libredb trust \"{}\"'.",
            ldb_path.display(),
            ws_root.display()
        ));
    }

    seal_workspace_memory(global_db, &pdb, ws_root)?;
    Ok(true)
}

/// Explicitly migrates a `v0.9.1..v0.9.3` `CognitiveContent::v3` workspace seal (`hmac-sha256:v3:`)
/// to a `v4` metadata-and-synapse-authenticated seal (`hmac-sha256:v4:r<rev>:`) WITHOUT silent trust laundering:
/// 1. Rejects revoked, unauthorized, git-tracked, or already-`v4`-upgraded workspaces (anti-downgrade ratchet).
/// 2. Verifies the existing `hmac-sha256:v3:` tag in constant time against the exact `v0.9.3`
///    `CognitiveContent::v3` digest (`kind`, `key`, `payload`), rejecting any payload/key tampering.
/// 3. Enforces hard `Inode` binary consistency invariants across all active cognitive capsules
///    (`generation >= 1`, `updated_ns >= created_ns`, `token_count == count_tokens_exact(&payload)`,
///    and `updated_ns == created_ns` on unlinked non-`Decision`/`Task` capsules), unconditionally
///    blocking asymmetric raw binary `Inode` timestamp/token tampering even when `confirm_unauthenticated_metadata` is `true`.
/// 4. Requires explicit human confirmation (`confirm_unauthenticated_metadata == true`, CLI `--confirm-metadata`)
///    for ANY `v0.9.3` database containing `>= 1` active cognitive capsules (`!cognitive_inodes.is_empty()`),
///    because `v0.9.3` never authenticated `created_ns`, `updated_ns`, `node_id`, `importance`, `PINNED`,
///    `generation`, or synapses (so symmetrically patched `created_ns == updated_ns` timestamps cannot be
///    proven authentic from the `v0.9.3` HMAC alone). Only `0`-capsule `v0.9.3` databases have zero
///    unauthenticated capsule metadata and upgrade automatically without `--confirm-metadata`.
pub fn migrate_workspace_seal_v3_to_v4(
    global_db: &LibreDb,
    ws_root: &Path,
    confirm_unauthenticated_metadata: bool,
) -> Result<bool, String> {
    let norm = normalize_workspace_key(ws_root);
    let _ws_lock = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm)?;
    check_global_trust_sync(global_db)?;
    if has_config_key_fail_closed(global_db, &format!("trust:revoked::{norm}"))? {
        return Err(format!(
            "Workspace '{}' has been explicitly revoked; run 'libredb trust \"{}\"' to re-authorize.",
            ws_root.display(),
            ws_root.display()
        ));
    }
    if !is_workspace_path_authorized_synced(global_db, ws_root) {
        return Err(format!(
            "Workspace '{}' is not registered as trusted in customizations.ldb.",
            ws_root.display()
        ));
    }
    if is_git_index_tracking_agents_db(ws_root)
        && !has_config_key_fail_closed(global_db, &format!("trust:allowed::{norm}"))?
    {
        return Err(format!(
            "Workspace '{}' tracks .agents/memory.* inside .git/index; refusing v3->v4 seal migration.",
            ws_root.display()
        ));
    }

    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if !ldb_path.is_file() {
        if has_prior_workspace_seal_marker_norm_checked(global_db, &norm)? {
            return Err(format!(
                "Previously sealed workspace '{}' is missing .agents/memory.ldb; restore from backup or run 'libredb trust --reinit-lost \"{}\"'.",
                ws_root.display(),
                ws_root.display()
            ));
        }
        return Ok(false);
    }
    let pdb = LibreDb::open(&ldb_path).map_err(|e| e.to_string())?;

    // If the workspace already passes `v4` verification (including `v0.9.4`/`v0.9.5` `v3`-over-`v4` seals
    // or pre-`v0.9.8` `r0` `v4` seals), ensure its `hmac-sha256:v4:r<rev>:` tag and `trust:v4_upgraded`
    // ratchet are recorded cleanly.
    if is_workspace_memory_trusted(Some(global_db), ws_root) {
        let already_v4_ratcheted =
            has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))?;
        let global_rev = read_global_seal_revision(global_db, &norm)?;
        if !already_v4_ratcheted || global_rev == 0 {
            seal_workspace_memory(global_db, &pdb, ws_root)?;
            return Ok(true);
        }
        return Ok(false);
    }

    if let Some((proj_rev, global_rev)) = detect_workspace_seal_rollback(global_db, ws_root)? {
        return Err(format!(
            "Workspace memory at '{}' carries older seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (historical snapshot rollback detected); refusing v3->v4 migration. Restore the latest .agents/memory.ldb or run 'libredb trust --accept-rollback \"{}\"'.",
            ldb_path.display(),
            ws_root.display()
        ));
    }

    let rec = pdb.get_by_key(NodeKind::Config, TRUST_SEALS_KEY).map_err(|_| {
        format!(
            "Workspace memory at '{}' has no sys::trust_seals entry; inspect and run 'libredb trust \"{}\"' (or '--reinit-lost' if replaced) if trusted.",
            ldb_path.display(),
            ws_root.display()
        )
    })?;

    let (legacy_v3_digest, v3_capsule_count) = compute_legacy_cognitive_content_digest_v3(&pdb)?;
    let mut secret = ensure_trust_anchor_secret(global_db)?;
    let host_tag = compute_host_seal_slot_id(&secret, &norm);
    let expected_legacy_v3 = compute_workspace_seal_v3(&secret, &norm, &legacy_v3_digest);
    let expected_slot_v3 = format!("{host_tag}={expected_legacy_v3}");
    secure_zero(&mut secret);

    let seals_txt = String::from_utf8_lossy(&rec.payload);
    let already_v4_in_global =
        has_config_key_fail_closed(global_db, &format!("trust:v4_upgraded::{norm}"))?
            || read_global_seal_revision(global_db, &norm)? > 0;
    let has_failed_host_v4 = seals_txt
        .lines()
        .any(|l| l.trim().starts_with(&format!("{host_tag}=hmac-sha256:v4:")));
    if already_v4_in_global || has_failed_host_v4 {
        return Err(format!(
            "Workspace memory at '{}' was already upgraded to hmac-sha256:v4 on this host (content/metadata tampering or v3 replay downgrade detected); refusing v3->v4 migration.",
            ldb_path.display()
        ));
    }

    let has_valid_legacy_v3 = seals_txt.lines().any(|line| {
        let trimmed = line.trim().as_bytes();
        constant_time_eq(trimmed, expected_legacy_v3.as_bytes())
            || constant_time_eq(trimmed, expected_slot_v3.as_bytes())
    });
    if !has_valid_legacy_v3 {
        return Err(format!(
            "Workspace memory at '{}' failed legacy v0.9.3 CognitiveContent::v3 HMAC verification (payload tampering or foreign host seal detected); refusing v3->v4 migration.",
            ldb_path.display()
        ));
    }

    // Hard Inode binary consistency checks + audit of metadata/graph surface not covered by `v0.9.3`:
    let all_inodes = pdb.list_inodes(None, false);
    let mut active_cognitive_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut cognitive_inodes = Vec::new();
    for (ino, key_opt, syns) in all_inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        let include = match ino.kind {
            NodeKind::Rule
            | NodeKind::Skill
            | NodeKind::SkillSection
            | NodeKind::SynonymCluster
            | NodeKind::AgentTemplate
            | NodeKind::Decision
            | NodeKind::Fact
            | NodeKind::Task
            | NodeKind::TaskVerification
            | NodeKind::Handoff
            | NodeKind::Snapshot
            | NodeKind::CompactionCheckpoint => true,
            NodeKind::Config => key_opt.as_deref() != Some(TRUST_SEALS_KEY),
            _ => false,
        };
        if include {
            active_cognitive_ids.insert(ino.node_id);
            cognitive_inodes.push((ino, key_opt, syns));
        }
    }

    let mut newly_covered_kinds = 0usize;
    let mut cognitive_synapses = 0usize;
    let mut pinned_non_rules = 0usize;
    let mut custom_importance = 0usize;
    let mut fact_count = 0usize;
    let mut decision_count = 0usize;
    let mut min_created_ns = u64::MAX;
    let mut max_updated_ns = 0u64;

    if !cognitive_inodes.is_empty() {
        let ids: Vec<u64> = cognitive_inodes.iter().map(|(i, _, _)| i.node_id).collect();
        let (recs, _) = pdb.get_many_coalesced(&ids).map_err(|e| e.to_string())?;
        let mut payload_by_id: std::collections::HashMap<u64, Vec<u8>> =
            std::collections::HashMap::with_capacity(recs.len());
        for r in recs {
            payload_by_id.insert(r.node_id, r.payload);
        }

        for (ino, key_opt, syns) in &cognitive_inodes {
            let label = key_opt.as_deref().unwrap_or("<unkeyed>");
            if ino.generation == 0 || ino.updated_ns < ino.created_ns {
                return Err(format!(
                    "Workspace memory at '{}' contains corrupted Inode timestamps/generation on node #{} ('{}'); refusing v3->v4 migration.",
                    ldb_path.display(),
                    ino.node_id,
                    label
                ));
            }
            let payload = payload_by_id.get(&ino.node_id).ok_or_else(|| {
                format!(
                    "Missing payload record for active cognitive node #{} ('{}')",
                    ino.node_id, label
                )
            })?;
            let expected_tokens = count_tokens_exact(payload);
            if ino.token_count != expected_tokens {
                return Err(format!(
                    "Workspace memory at '{}' has forged token_count={} (expected {}) on node #{} ('{}'); refusing v3->v4 migration.",
                    ldb_path.display(),
                    ino.token_count,
                    expected_tokens,
                    ino.node_id,
                    label
                ));
            }
            let has_non_supersedes_synapse = syns.iter().any(|s| s.kind != EdgeKind::Supersedes);
            if !matches!(ino.kind, NodeKind::Decision | NodeKind::Task)
                && !has_non_supersedes_synapse
                && ino.updated_ns != ino.created_ns
            {
                return Err(format!(
                    "Workspace memory at '{}' has offline-modified updated_ns != created_ns on unlinked {:?} node #{} ('{}'); refusing v3->v4 migration.",
                    ldb_path.display(),
                    ino.kind,
                    ino.node_id,
                    label
                ));
            }

            min_created_ns = min_created_ns.min(ino.created_ns);
            max_updated_ns = max_updated_ns.max(ino.updated_ns);
            if matches!(
                ino.kind,
                NodeKind::SynonymCluster | NodeKind::AgentTemplate | NodeKind::TaskVerification
            ) {
                newly_covered_kinds += 1;
            }
            if ino.kind != NodeKind::Rule && (ino.flags.0 & NodeFlags::PINNED) != 0 {
                pinned_non_rules += 1;
            }
            if ino.importance != 128 {
                custom_importance += 1;
            }
            if ino.kind == NodeKind::Fact {
                fact_count += 1;
            } else if ino.kind == NodeKind::Decision {
                decision_count += 1;
            }
            cognitive_synapses += syns
                .iter()
                .filter(|s| {
                    s.kind != EdgeKind::Supersedes && active_cognitive_ids.contains(&s.target_id)
                })
                .count();
        }
    }

    // Because `v0.9.3` (`CognitiveContent::v3`) never authenticated `created_ns`, `updated_ns`,
    // `node_id`, `importance`, `PINNED`, `generation`, or synapses on ANY capsule, ANY `v0.9.3`
    // database with `>= 1` active cognitive capsule carries unauthenticated metadata (for example,
    // symmetrically modified `created_ns == updated_ns` timestamps with recomputed CRC32s) whose
    // authenticity cannot be proven from the `v0.9.3` HMAC alone. Require explicit `--confirm-metadata`!
    if !cognitive_inodes.is_empty() && !confirm_unauthenticated_metadata {
        return Err(format!(
            "Verified legacy v0.9.3 payload HMAC over {v3_capsule_count} capsule(s) in '{}', but {} active cognitive capsule(s) carry metadata not authenticated by v0.9.3 (created_ns..updated_ns={}..{}, newly_covered_kinds={newly_covered_kinds}, cognitive_synapses={cognitive_synapses}, pinned_non_rules={pinned_non_rules}, custom_importance={custom_importance}, facts={fact_count}, decisions={decision_count}). Inspect the workspace database and re-run 'libredb trust --migrate-v3 \"{}\" --confirm-metadata' to adopt this metadata into a v4 seal.",
            ldb_path.display(),
            cognitive_inodes.len(),
            min_created_ns,
            max_updated_ns,
            ws_root.display()
        ));
    }

    seal_workspace_memory(global_db, &pdb, ws_root)?;
    Ok(true)
}

/// Revokes workspace trust in `global_db` and removes `sys::trust_seals` from `<ws_root>/.agents/memory.ldb` if present.
pub fn revoke_workspace_trust(global_db: &LibreDb, ws_root: &Path) -> Result<(), String> {
    let norm = normalize_workspace_key(ws_root);
    let _ws_lock = WorkspaceTrustLockGuard::acquire_norm(global_db, &norm)?;
    check_global_trust_sync(global_db)?;
    deprecate_config_if_present(global_db, &format!("trust:allowed::{norm}"))?;
    deprecate_config_if_present(global_db, &workspace_id_config_key(&norm))?;

    // Only deprecate legacy `workspace:<basename>` entries whose normalized payload path
    // matches `norm`, so same-basename repositories (e.g. `/org_a/app` vs `/org_b/app`)
    // never revoke each other's discovery metadata.
    let mut matching_legacy_keys = Vec::new();
    for (ino, key_opt, _) in global_db.list_inodes(Some(NodeKind::Config), false) {
        let Some(k) = key_opt else { continue };
        if k.starts_with("workspace:") {
            let rec = global_db
                .get(ino.node_id)
                .map_err(|e| format!("Failed to read Config '{k}': {e}"))?;
            let raw = String::from_utf8_lossy(&rec.payload);
            if normalize_workspace_key(Path::new(raw.trim())) == norm {
                matching_legacy_keys.push(k);
            }
        }
    }
    for leg_key in matching_legacy_keys {
        deprecate_config_if_present(global_db, &leg_key)?;
    }

    global_db
        .put(
            WriteRequest::new(NodeKind::Config, b"revoked".to_vec())
                .with_key(format!("trust:revoked::{norm}"))
                .with_importance(200),
        )
        .map_err(|e| e.to_string())?;

    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if ldb_path.is_file() {
        if let Ok(pdb) = LibreDb::open(&ldb_path) {
            let _ = pdb.deprecate_key(NodeKind::Config, TRUST_SEALS_KEY);
        }
    }
    Ok(())
}

/// Lists all explicitly trusted and learned workspaces from `global_db`, synchronizing from disk
/// first and failing closed with `Err` on any storage or payload corruption.
pub fn list_trusted_workspaces(global_db: &LibreDb) -> Result<Vec<(String, String)>, String> {
    check_global_trust_sync(global_db)?;
    let mut map = std::collections::BTreeMap::new();
    let mut revoked = std::collections::HashSet::new();
    for (ino, key_opt, _) in global_db.list_inodes(Some(NodeKind::Config), false) {
        let Some(k) = key_opt else { continue };
        if let Some(norm) = k.strip_prefix("trust:revoked::") {
            revoked.insert(norm.to_owned());
        } else if let Some(norm) = k.strip_prefix("trust:allowed::") {
            let rec = global_db
                .get(ino.node_id)
                .map_err(|e| format!("Failed to read Config '{k}': {e}"))?;
            map.insert(
                norm.to_owned(),
                String::from_utf8_lossy(&rec.payload).trim().to_owned(),
            );
        } else if k.starts_with("workspace_id::") || k.starts_with("workspace:") {
            let rec = global_db
                .get(ino.node_id)
                .map_err(|e| format!("Failed to read Config '{k}': {e}"))?;
            let raw = String::from_utf8_lossy(&rec.payload).trim().to_owned();
            let norm = normalize_workspace_key(Path::new(&raw));
            map.entry(norm).or_insert(raw);
        }
    }
    Ok(map
        .into_iter()
        .filter(|(norm, _)| !revoked.contains(norm))
        .collect())
}

/// Evaluates whether `PreToolUse` (`write_file`, `edit_file`, etc.) must block modifying `target_path`
/// across both lexical and symlink-canonicalized paths.

pub(crate) fn compute_legacy_workspace_seal_v2(
    secret: &[u8; 32],
    normalized_ws_key: &str,
) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts 256-bit keys");
    mac.update(SEAL_V2_DOMAIN_SEP);
    mac.update(normalized_ws_key.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("hmac-sha256:v2:{}", hex_encode(tag.as_slice()))
}

pub(crate) fn compute_workspace_seal_v3(
    secret: &[u8; 32],
    normalized_ws_key: &str,
    content_digest: &[u8; 32],
) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts 256-bit keys");
    mac.update(SEAL_V3_DOMAIN_SEP);
    mac.update((normalized_ws_key.len() as u32).to_le_bytes().as_slice());
    mac.update(normalized_ws_key.as_bytes());
    mac.update(content_digest);
    let tag = mac.finalize().into_bytes();
    format!("hmac-sha256:v3:{}", hex_encode(tag.as_slice()))
}

pub(crate) fn compute_workspace_seal_v4(
    secret: &[u8; 32],
    normalized_ws_key: &str,
    content_digest: &[u8; 32],
) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts 256-bit keys");
    mac.update(SEAL_V4_DOMAIN_SEP);
    mac.update((normalized_ws_key.len() as u32).to_le_bytes().as_slice());
    mac.update(normalized_ws_key.as_bytes());
    mac.update(content_digest);
    let tag = mac.finalize().into_bytes();
    format!("hmac-sha256:v4:{}", hex_encode(tag.as_slice()))
}

pub(crate) fn compute_workspace_seal_v4_rev(
    secret: &[u8; 32],
    normalized_ws_key: &str,
    content_digest: &[u8; 32],
    seal_rev: u64,
) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts 256-bit keys");
    mac.update(SEAL_V4_REV_DOMAIN_SEP);
    mac.update((normalized_ws_key.len() as u32).to_le_bytes().as_slice());
    mac.update(normalized_ws_key.as_bytes());
    mac.update(content_digest);
    mac.update(seal_rev.to_le_bytes().as_slice());
    let tag = mac.finalize().into_bytes();
    format!("hmac-sha256:v4:r{seal_rev}:{}", hex_encode(tag.as_slice()))
}

pub(super) fn parse_strict_seal_rev_prefix(line: &str, prefix: &str) -> Option<u64> {
    let after_prefix = line.strip_prefix(prefix)?;
    let after_r = after_prefix.strip_prefix('r')?;
    let (rev_str, tag_hex) = after_r.split_once(':')?;
    if tag_hex.len() != 64 || !tag_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let rev = rev_str.parse::<u64>().ok()?;
    if rev == 0 || rev.to_string() != rev_str {
        return None;
    }
    Some(rev)
}

pub(super) fn extract_syntactic_host_slot_rev(seals_txt: &str, host_tag: &str) -> u64 {
    let slot_v4_prefix = format!("{host_tag}=hmac-sha256:v4:");
    let host_eq = format!("{host_tag}=");
    let has_host_slot = seals_txt.lines().any(|l| l.trim().starts_with(&host_eq));
    let mut max_rev = 0u64;
    for line in seals_txt.lines() {
        let t = line.trim();
        if let Some(r) = parse_strict_seal_rev_prefix(t, &slot_v4_prefix) {
            max_rev = max_rev.max(r);
        } else if !has_host_slot {
            if let Some(r) = parse_strict_seal_rev_prefix(t, "hmac-sha256:v4:") {
                max_rev = max_rev.max(r);
            }
        }
    }
    max_rev
}

pub(super) fn verify_and_extract_host_seal_rev(
    secret: &[u8; 32],
    norm: &str,
    content_digest: &[u8; 32],
    seals_txt: &str,
    already_v4_ratcheted: bool,
) -> Option<u64> {
    let host_tag = compute_host_seal_slot_id(secret, norm);
    let host_eq = format!("{host_tag}=");
    let slot_v4_prefix = format!("{host_tag}=hmac-sha256:v4:");
    let has_host_slot = seals_txt.lines().any(|l| l.trim().starts_with(&host_eq));
    let has_host_v4_slot = seals_txt
        .lines()
        .any(|l| l.trim().starts_with(&slot_v4_prefix));

    // 1. Verify revision-bound `hmac-sha256:v4:r<rev>:<64-hex>` (`rev >= 1`):
    let mut best_v4r: Option<u64> = None;
    for line in seals_txt.lines() {
        let trimmed = line.trim();
        if let Some(rev) = parse_strict_seal_rev_prefix(trimmed, &slot_v4_prefix) {
            let expected_bare = compute_workspace_seal_v4_rev(secret, norm, content_digest, rev);
            let expected_slot = format!("{host_tag}={expected_bare}");
            if constant_time_eq(trimmed.as_bytes(), expected_slot.as_bytes()) {
                best_v4r = Some(best_v4r.map_or(rev, |b| b.max(rev)));
            }
        } else if !has_host_slot {
            if let Some(rev) = parse_strict_seal_rev_prefix(trimmed, "hmac-sha256:v4:") {
                let expected_bare =
                    compute_workspace_seal_v4_rev(secret, norm, content_digest, rev);
                if constant_time_eq(trimmed.as_bytes(), expected_bare.as_bytes()) {
                    best_v4r = Some(best_v4r.map_or(rev, |b| b.max(rev)));
                }
            }
        }
    }
    if best_v4r.is_some() {
        return best_v4r;
    }

    // 2. Seamless read compatibility for pre-v0.9.8 `hmac-sha256:v4:<64-hex>` (`rev == 0`):
    let expected_v4 = compute_workspace_seal_v4(secret, norm, content_digest);
    let expected_slot_v4 = format!("{host_tag}={expected_v4}");
    let v4_matches = seals_txt.lines().any(|line| {
        let trimmed = line.trim().as_bytes();
        constant_time_eq(trimmed, expected_slot_v4.as_bytes())
            || (!has_host_slot && constant_time_eq(trimmed, expected_v4.as_bytes()))
    });
    if v4_matches {
        return Some(0);
    }

    // 3. Seamless read compatibility for `v0.9.4`/`v0.9.5` unratcheted `v3`-over-`v4` (`rev == 0`):
    if !already_v4_ratcheted && !has_host_v4_slot {
        let expected_v3_over_v4 = compute_workspace_seal_v3(secret, norm, content_digest);
        let expected_slot_v3_over_v4 = format!("{host_tag}={expected_v3_over_v4}");
        let v3_over_v4_matches = seals_txt.lines().any(|line| {
            let trimmed = line.trim().as_bytes();
            constant_time_eq(trimmed, expected_slot_v3_over_v4.as_bytes())
                || (!has_host_slot && constant_time_eq(trimmed, expected_v3_over_v4.as_bytes()))
        });
        if v3_over_v4_matches {
            return Some(0);
        }
    }

    None
}

pub(super) fn compute_host_seal_slot_id(secret: &[u8; 32], normalized_ws_key: &str) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts 256-bit keys");
    mac.update(b"LibreDB::HostSealSlot::v3\0");
    mac.update(normalized_ws_key.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("slot:{}", hex_encode(&tag.as_slice()[..8]))
}

