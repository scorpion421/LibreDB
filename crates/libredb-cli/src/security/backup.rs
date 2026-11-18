//! Portable unencrypted backup, integrity-verified restore, chat/workspace migration, and
//! own-risk read-only inspection (`libredb backup | restore | migrate | read`).
//!
//! Security model:
//! - Active workspace databases use host-locked `DPAPI`/`vault:v2` secrets and path-bound
//!   `hmac-sha256:v4` trust seals (`sys::trust_seals`). Raw copies made without `/libredb backup`
//!   lack `sys::backup_manifest` and fail closed on other hosts or moved paths.
//! - `/libredb backup` validates integrity and trust, decrypts ciphertext config envelopes into
//!   portable `portable_plain:` records, strips host-bound trust anchors/ratchets, and attaches a
//!   tamper-evident `sys::backup_manifest` (`LIBREDB_BACKUP_V1`).
//! - Dropping a backed-up project `memory.ldb` into a brand-new project's `.agents/memory.ldb`
//!   triggers automatic verification, local secret re-encryption, manifest deletion, and `v4`
//!   host sealing on first open (`is_workspace_memory_trusted`).

use super::ephemeral::ephemeral_workspace_ldb_filename;
use super::seals::{
    check_global_trust_sync, compute_cognitive_content_digest, deprecate_config_if_present,
    is_workspace_memory_trusted, list_trusted_workspaces, revoke_workspace_trust,
    seal_workspace_memory, seal_workspace_memory_inner, verify_and_extract_host_seal_rev,
};
use super::vault::{ensure_trust_anchor_secret, is_ciphertext_envelope, protect_secret, unprotect_secret};
use super::{
    constant_time_eq, hex_encode, is_forbidden_mcp_workspace_root, is_git_index_tracking_agents_db,
    is_private_brain_workspace, normalize_workspace_key, secure_zero, strip_verbatim_prefix,
    BACKUP_MANIFEST_KEY, PORTABLE_SECRET_PREFIX, TRUST_SEALS_KEY, TRUST_SECRET_KEY,
};
use libredb_cognitive::{
    CognitiveEngine, ErrorPitfallBook, ReflexUtilityBook, SymbolCueBridgeBook,
    ERROR_PITFALL_BOOK_KEY, PENDING_ERROR_CUES_KEY, PENDING_MISS_CUES_KEY,
    PENDING_SERVED_BRIDGES_KEY, REFLEX_UTILITY_BOOK_KEY, SYMBOL_CUE_BRIDGES_KEY,
};
use libredb_core::{EdgeKind, LibreDb, LibreDbError, NodeFlags, NodeKind, Synapse, WriteRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const BACKUP_FORMAT_V1: &str = "LIBREDB_BACKUP_V1";
const BACKUP_DIGEST_DOMAIN: &[u8] = b"LibreDB::BackupContent::v1\0";
const BACKUP_MANIFEST_DOMAIN: &[u8] = b"LibreDB::BackupManifest::v1\0";
const TELEMETRY_MARKER_KEY: &str = "sys::telemetry_backup_marker";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupScope {
    Project,
    Instance,
    Chat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format: String,
    pub scope: BackupScope,
    pub exported_at_unix_s: u64,
    pub source_host: String,
    pub source_label: String,
    pub capsule_count: usize,
    pub content_sha256: String,
    pub manifest_integrity_tag: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupIndex {
    pub format: String,
    pub scope: String,
    pub exported_at_unix_s: u64,
    pub source_host: String,
    pub unencrypted_warning: String,
    pub instance_db: Option<String>,
    pub telemetry_db: Option<String>,
    pub chat_db: Option<String>,
    pub projects: Vec<BackupProjectEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupProjectEntry {
    pub slug: String,
    pub original_path: String,
    pub relative_ldb_path: String,
    pub capsule_count: usize,
    pub content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupReport {
    pub destination: String,
    pub scope: String,
    pub unencrypted_warning: String,
    pub instance_exported: bool,
    pub telemetry_exported: bool,
    pub chat_exported: bool,
    pub projects_exported: Vec<BackupProjectEntry>,
    pub secrets_decrypted: usize,
    pub total_capsules: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub source: String,
    pub scope: String,
    pub instance_restored: bool,
    pub telemetry_restored: bool,
    pub projects_restored: Vec<String>,
    pub projects_skipped_missing_dir: Vec<BackupProjectEntry>,
    pub secrets_reencrypted: usize,
    pub backup_files_created: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateReport {
    pub mode: String,
    pub target_project: String,
    pub sources_used: Vec<String>,
    pub nodes_merged: usize,
    pub synapses_merged: usize,
    pub nodes_skipped_older: usize,
    pub artifacts_copied: usize,
    pub relocated_from: Option<String>,
    pub legacy_brain_db_cleaned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadLdbEntry {
    pub kind: String,
    pub key: Option<String>,
    pub importance: u8,
    pub pinned: bool,
    pub token_count: u32,
    pub payload_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadLdbFileReport {
    pub path: String,
    pub file_bytes: u64,
    pub crc_integrity_ok: bool,
    pub provenance_status: String,
    pub provenance_detail: String,
    pub backup_manifest: Option<BackupManifest>,
    pub active_nodes: usize,
    pub kind_counts: BTreeMap<String, usize>,
    pub matched_entries: Vec<ReadLdbEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadLdbReport {
    pub target: String,
    pub own_risk_warning: String,
    pub backup_index: Option<BackupIndex>,
    pub files: Vec<ReadLdbFileReport>,
}

pub struct BackupOptions {
    pub destination: Option<PathBuf>,
    pub project_dir: Option<PathBuf>,
    pub cid: Option<String>,
    pub instance: bool,
    pub all: bool,
    pub global_path: Option<PathBuf>,
    pub allow_prompt: bool,
}

pub struct RestoreOptions {
    pub source: PathBuf,
    pub project_dir: Option<PathBuf>,
    pub instance: bool,
    pub all: bool,
    pub global_path: Option<PathBuf>,
}

pub struct MigrateOptions {
    pub source: Option<PathBuf>,
    pub cid: Option<String>,
    pub target_project: Option<PathBuf>,
    pub from_path: Option<PathBuf>,
    pub include_artifacts: bool,
    pub global_path: Option<PathBuf>,
}

pub struct ReadLdbOptions {
    pub target: PathBuf,
    pub query: Option<String>,
    pub show_secrets: bool,
    pub global_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretTransform {
    DecryptToPortablePlain,
    EncryptPortablePlainToLocalVault,
    KeepUnchanged,
}

struct ExportedNode {
    old_id: u64,
    kind: NodeKind,
    key: Option<String>,
    payload: Vec<u8>,
    importance: u8,
    pinned: bool,
    updated_ns: u64,
    synapses: Vec<Synapse>,
}

fn current_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn current_host_label() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_owned())
}

fn sanitize_slug(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let trimmed = s.trim_matches('_').to_owned();
    if trimmed.is_empty() {
        "workspace".to_owned()
    } else {
        trimmed
    }
}

fn project_backup_slug(ws_root: &Path) -> String {
    let folder = ws_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("project");
    let norm = normalize_workspace_key(ws_root);
    let mut h = Sha256::new();
    h.update(b"LibreDB::BackupProjectSlug::v1\0");
    h.update(norm.as_bytes());
    let digest = h.finalize();
    format!("{}_{}", sanitize_slug(folder), hex_encode(&digest[..4]))
}

fn is_instance_host_ratchet_key(key: &str) -> bool {
    let low = key.trim().to_ascii_lowercase();
    low == TRUST_SECRET_KEY
        || low == TRUST_SEALS_KEY
        || low == BACKUP_MANIFEST_KEY
        || low.starts_with("trust:")
        || low.starts_with("workspace:")
        || low.starts_with("workspace_id::")
}

fn is_project_forbidden_control_config_key(key: &str) -> bool {
    let low = key.trim().to_ascii_lowercase();
    is_instance_host_ratchet_key(&low)
        || low.starts_with("mcp:")
        || low.starts_with("hook:")
        || low == "guardrail:style_rules"
}

fn should_include_in_backup_digest(kind: NodeKind, key_opt: Option<&str>) -> bool {
    match kind {
        NodeKind::Rule
        | NodeKind::Skill
        | NodeKind::SkillSection
        | NodeKind::SynonymCluster
        | NodeKind::AgentTemplate
        | NodeKind::Decision
        | NodeKind::Fact
        | NodeKind::Snapshot
        | NodeKind::CompactionCheckpoint
        | NodeKind::Task
        | NodeKind::TaskVerification
        | NodeKind::Handoff => true,
        NodeKind::Config => !matches!(
            key_opt,
            Some(TRUST_SEALS_KEY)
                | Some(TRUST_SECRET_KEY)
                | Some(BACKUP_MANIFEST_KEY)
                | Some(TELEMETRY_MARKER_KEY)
        ),
        NodeKind::Generic => !matches!(
            key_opt,
            Some("sys::index_snapshot")
                | Some(PENDING_MISS_CUES_KEY)
                | Some(PENDING_SERVED_BRIDGES_KEY)
                | Some(PENDING_ERROR_CUES_KEY)
        ),
        NodeKind::Symbol | NodeKind::WorkingSet | NodeKind::QuotaEvent | NodeKind::TranscriptCursor => false,
    }
}

fn should_export_node(scope: BackupScope, kind: NodeKind, key_opt: Option<&str>) -> bool {
    if !should_include_in_backup_digest(kind, key_opt) {
        return false;
    }
    if kind == NodeKind::Config {
        if let Some(k) = key_opt {
            if scope == BackupScope::Instance && is_instance_host_ratchet_key(k) {
                return false;
            }
            if matches!(scope, BackupScope::Project | BackupScope::Chat)
                && is_project_forbidden_control_config_key(k)
            {
                return false;
            }
        }
    }
    true
}

/// Computes an order-independent, NodeId-independent SHA-256 content digest across all
/// persistent cognitive, config, and learning nodes in `db` (excluding `sys::trust_seals`,
/// `sys::trust_anchor_secret`, `sys::backup_manifest`, and `sys::index_snapshot`).
pub(crate) fn compute_backup_content_digest(db: &LibreDb) -> Result<([u8; 32], usize), String> {
    let all_inodes = db.list_inodes(None, false);
    let mut target_index: HashMap<u64, (u8, String)> = HashMap::new();
    struct DigestRow {
        kind_b: u8,
        importance: u8,
        pinned_flag: u8,
        key: String,
        node_id: u64,
        raw_syns: Vec<Synapse>,
    }
    let mut rows = Vec::new();
    for (ino, key_opt, syns) in all_inodes {
        if !ino.flags.is_live_active()
            || !should_include_in_backup_digest(ino.kind, key_opt.as_deref())
        {
            continue;
        }
        let key_s = key_opt.unwrap_or_default();
        target_index.insert(ino.node_id, (ino.kind as u8, key_s.clone()));
        rows.push(DigestRow {
            kind_b: ino.kind as u8,
            importance: ino.importance,
            pinned_flag: ino.flags.0 & NodeFlags::PINNED,
            key: key_s,
            node_id: ino.node_id,
            raw_syns: syns,
        });
    }

    let ids: Vec<u64> = rows.iter().map(|r| r.node_id).collect();
    let mut by_id: HashMap<u64, Vec<u8>> = HashMap::with_capacity(ids.len());
    if !ids.is_empty() {
        let (recs, _) = db.get_many_coalesced(&ids).map_err(|e| e.to_string())?;
        for r in recs {
            by_id.insert(r.node_id, r.payload);
        }
    }

    struct EncodedDigestRow {
        kind_b: u8,
        importance: u8,
        pinned_flag: u8,
        key: String,
        payload: Vec<u8>,
        syns: Vec<(u8, u8, u8, String)>,
    }
    let mut encoded: Vec<EncodedDigestRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let payload = by_id.remove(&row.node_id).unwrap_or_default();
        let mut syns: Vec<(u8, u8, u8, String)> = row
            .raw_syns
            .into_iter()
            .filter_map(|s| {
                if s.kind == EdgeKind::Supersedes {
                    return None;
                }
                let (tkind, tkey) = target_index.get(&s.target_id)?;
                Some((s.kind as u8, s.weight, *tkind, tkey.clone()))
            })
            .collect();
        syns.sort_unstable();
        encoded.push(EncodedDigestRow {
            kind_b: row.kind_b,
            importance: row.importance,
            pinned_flag: row.pinned_flag,
            key: row.key,
            payload,
            syns,
        });
    }
    encoded.sort_by(|a, b| {
        a.kind_b
            .cmp(&b.kind_b)
            .then_with(|| a.key.cmp(&b.key))
            .then_with(|| a.payload.cmp(&b.payload))
            .then_with(|| a.importance.cmp(&b.importance))
            .then_with(|| a.pinned_flag.cmp(&b.pinned_flag))
            .then_with(|| a.syns.cmp(&b.syns))
    });

    let mut hasher = Sha256::new();
    hasher.update(BACKUP_DIGEST_DOMAIN);
    hasher.update((encoded.len() as u64).to_le_bytes());
    for e in &encoded {
        hasher.update([e.kind_b, e.importance, e.pinned_flag]);
        hasher.update((e.key.len() as u32).to_le_bytes());
        hasher.update(e.key.as_bytes());
        hasher.update((e.payload.len() as u64).to_le_bytes());
        hasher.update(&e.payload);
        hasher.update((e.syns.len() as u32).to_le_bytes());
        for (sk, sw, tk, tkey) in &e.syns {
            hasher.update([*sk, *sw, *tk]);
            hasher.update((tkey.len() as u32).to_le_bytes());
            hasher.update(tkey.as_bytes());
        }
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok((arr, encoded.len()))
}

fn compute_manifest_integrity_tag(m: &BackupManifest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_MANIFEST_DOMAIN);
    let scope_b: &[u8] = match m.scope {
        BackupScope::Project => b"project",
        BackupScope::Instance => b"instance",
        BackupScope::Chat => b"chat",
    };
    for part in [
        m.format.as_bytes(),
        scope_b,
        &m.exported_at_unix_s.to_le_bytes(),
        m.source_host.as_bytes(),
        m.source_label.as_bytes(),
        &m.capsule_count.to_le_bytes(),
        m.content_sha256.as_bytes(),
    ] {
        hasher.update((part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    hex_encode(hasher.finalize().as_slice())
}

fn stamp_backup_manifest(
    db: &LibreDb,
    scope: BackupScope,
    source_label: &str,
) -> Result<BackupManifest, String> {
    let (digest, count) = compute_backup_content_digest(db)?;
    let mut manifest = BackupManifest {
        format: BACKUP_FORMAT_V1.to_owned(),
        scope,
        exported_at_unix_s: current_unix_s(),
        source_host: current_host_label(),
        source_label: source_label.to_owned(),
        capsule_count: count,
        content_sha256: hex_encode(&digest),
        manifest_integrity_tag: String::new(),
    };
    manifest.manifest_integrity_tag = compute_manifest_integrity_tag(&manifest);
    let json_bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    db.put(
        WriteRequest::new(NodeKind::Config, json_bytes)
            .with_key(BACKUP_MANIFEST_KEY)
            .with_importance(240)
            .with_pinned(true),
    )
    .map_err(|e| format!("Failed to persist backup manifest: {e}"))?;
    Ok(manifest)
}

/// Validates whether `db` contains a genuine, uncorrupted `/libredb backup` manifest
/// (`sys::backup_manifest`), optionally restricting `expected_scope`.
pub fn has_valid_portable_backup_manifest(
    db: &LibreDb,
    expected_scope: Option<BackupScope>,
) -> Result<Option<BackupManifest>, String> {
    let rec = match db.get_by_key(NodeKind::Config, BACKUP_MANIFEST_KEY) {
        Ok(r) => r,
        Err(LibreDbError::KeyNotFound { .. }) => return Ok(None),
        Err(e) => {
            return Err(format!(
                "Failed to read backup manifest ({BACKUP_MANIFEST_KEY}): {e}"
            ))
        }
    };
    let manifest: BackupManifest = serde_json::from_slice(&rec.payload).map_err(|e| {
        format!("Invalid backup manifest payload in '{BACKUP_MANIFEST_KEY}': {e}")
    })?;
    if manifest.format != BACKUP_FORMAT_V1 {
        return Err(format!(
            "Unsupported backup manifest format '{}' (expected '{BACKUP_FORMAT_V1}')",
            manifest.format
        ));
    }
    let expected_tag = compute_manifest_integrity_tag(&manifest);
    if !constant_time_eq(
        manifest.manifest_integrity_tag.as_bytes(),
        expected_tag.as_bytes(),
    ) {
        return Err(
            "Backup manifest integrity tag mismatch (manifest was altered outside '/libredb backup')"
                .to_owned(),
        );
    }
    let (actual_digest, actual_count) = compute_backup_content_digest(db)?;
    let actual_hex = hex_encode(&actual_digest);
    if actual_count != manifest.capsule_count
        || !constant_time_eq(manifest.content_sha256.as_bytes(), actual_hex.as_bytes())
    {
        return Err(format!(
            "Backup content digest mismatch (expected {} capsules / {}, found {} capsules / {}): database was modified after '/libredb backup'",
            manifest.capsule_count, manifest.content_sha256, actual_count, actual_hex
        ));
    }
    if let Some(exp) = expected_scope {
        let scope_ok = match exp {
            BackupScope::Instance => manifest.scope == BackupScope::Instance,
            BackupScope::Project => matches!(manifest.scope, BackupScope::Project | BackupScope::Chat),
            BackupScope::Chat => matches!(manifest.scope, BackupScope::Chat | BackupScope::Project),
        };
        if !scope_ok {
            return Err(format!(
                "Backup scope mismatch: backup is '{:?}' but operation requires '{exp:?}'",
                manifest.scope
            ));
        }
    }
    Ok(Some(manifest))
}

fn transform_secret_payload(
    kind: NodeKind,
    payload: Vec<u8>,
    mode: SecretTransform,
    counter: &mut usize,
) -> Result<Vec<u8>, String> {
    if kind != NodeKind::Config || mode == SecretTransform::KeepUnchanged {
        return Ok(payload);
    }
    let Ok(mut raw) = String::from_utf8(payload.clone()) else {
        return Ok(payload);
    };
    let trimmed = raw.trim();
    match mode {
        SecretTransform::DecryptToPortablePlain => {
            if is_ciphertext_envelope(trimmed) {
                let (mut plain, _) = unprotect_secret(trimmed)?;
                let res = format!("{PORTABLE_SECRET_PREFIX}{plain}").into_bytes();
                secure_zero(unsafe { plain.as_bytes_mut() });
                secure_zero(unsafe { raw.as_bytes_mut() });
                *counter += 1;
                Ok(res)
            } else {
                secure_zero(unsafe { raw.as_bytes_mut() });
                Ok(payload)
            }
        }
        SecretTransform::EncryptPortablePlainToLocalVault => {
            if let Some(plain_slice) = trimmed.strip_prefix(PORTABLE_SECRET_PREFIX) {
                let protected = protect_secret(plain_slice)?;
                secure_zero(unsafe { raw.as_bytes_mut() });
                *counter += 1;
                Ok(protected.into_bytes())
            } else {
                secure_zero(unsafe { raw.as_bytes_mut() });
                Ok(payload)
            }
        }
        SecretTransform::KeepUnchanged => Ok(payload),
    }
}

fn collect_exported_nodes(
    src_db: &LibreDb,
    scope: Option<BackupScope>,
    mode: SecretTransform,
    telemetry_only: bool,
) -> Result<(Vec<ExportedNode>, usize), String> {
    let all_inodes = src_db.list_inodes(None, false);
    let mut selected = Vec::new();
    for (ino, key_opt, syns) in all_inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        if telemetry_only {
            if ino.kind == NodeKind::Config
                && key_opt.as_deref() == Some(BACKUP_MANIFEST_KEY)
            {
                continue;
            }
        } else if let Some(sc) = scope {
            if !should_export_node(sc, ino.kind, key_opt.as_deref()) {
                continue;
            }
        } else if !should_include_in_backup_digest(ino.kind, key_opt.as_deref()) {
            continue;
        }
        selected.push((ino, key_opt, syns));
    }

    let ids: Vec<u64> = selected.iter().map(|(ino, _, _)| ino.node_id).collect();
    let mut by_id: HashMap<u64, Vec<u8>> = HashMap::with_capacity(ids.len());
    if !ids.is_empty() {
        let (recs, _) = src_db.get_many_coalesced(&ids).map_err(|e| e.to_string())?;
        for r in recs {
            by_id.insert(r.node_id, r.payload);
        }
    }

    let mut secret_count = 0usize;
    let mut out = Vec::with_capacity(selected.len());
    for (ino, key_opt, syns) in selected {
        let raw_payload = by_id.remove(&ino.node_id).unwrap_or_default();
        let payload = transform_secret_payload(ino.kind, raw_payload, mode, &mut secret_count)?;
        out.push(ExportedNode {
            old_id: ino.node_id,
            kind: ino.kind,
            key: key_opt,
            payload,
            importance: ino.importance,
            pinned: ino.flags.contains(NodeFlags::PINNED),
            updated_ns: ino.updated_ns,
            synapses: syns,
        });
    }
    Ok((out, secret_count))
}

fn replace_db_from_nodes_in_place(
    dst_db: &Arc<LibreDb>,
    nodes: Vec<ExportedNode>,
    preserve_instance_security: bool,
    rebuild_cognitive_snapshot: bool,
) -> Result<(usize, usize), String> {
    let mut deprecate_ids = Vec::new();
    for (ino, key_opt, _) in dst_db.list_inodes(None, false) {
        if !ino.flags.is_live_active() {
            continue;
        }
        if ino.kind == NodeKind::Config {
            if let Some(ref k) = key_opt {
                if preserve_instance_security && is_instance_host_ratchet_key(k) {
                    continue;
                }
                if !preserve_instance_security && k == TRUST_SEALS_KEY {
                    continue;
                }
            }
        }
        deprecate_ids.push(ino.node_id);
    }

    let mut prepared = Vec::with_capacity(nodes.len());
    for (idx, item) in nodes.iter().enumerate() {
        let mut req = WriteRequest::new(item.kind, item.payload.clone())
            .with_importance(item.importance)
            .with_pinned(item.pinned);
        if let Some(ref k) = item.key {
            req = req.with_key(k.clone());
        }
        prepared.push(
            dst_db
                .prepare(req, idx % libredb_core::SHARD_WRITE_LANES)
                .map_err(|e| e.to_string())?,
        );
    }

    let assigned_ids = dst_db
        .commit_batch_with_tombstones(&prepared, &deprecate_ids, &[])
        .map_err(|e| e.to_string())?;

    let mut id_map: HashMap<u64, u64> = HashMap::with_capacity(nodes.len());
    for (item, &new_id) in nodes.iter().zip(assigned_ids.iter()) {
        id_map.insert(item.old_id, new_id);
    }

    let mut edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    for item in &nodes {
        let Some(&src_new) = id_map.get(&item.old_id) else {
            continue;
        };
        for syn in &item.synapses {
            if syn.kind == EdgeKind::Supersedes {
                continue;
            }
            if let Some(&dst_new) = id_map.get(&syn.target_id) {
                edges.push((src_new, syn.kind, dst_new, syn.weight));
            }
        }
    }
    let edge_count = edges.len();
    if !edges.is_empty() {
        dst_db.link_batch(&edges).map_err(|e| e.to_string())?;
    }

    if rebuild_cognitive_snapshot {
        let mut cog = CognitiveEngine::open_db(Arc::clone(dst_db)).map_err(|e| e.to_string())?;
        cog.save_index_snapshot().map_err(|e| e.to_string())?;
    }
    let _ = dst_db
        .compact_with_options(false)
        .map_err(|e| e.to_string())?;
    Ok((nodes.len(), edge_count))
}

fn merge_pitfall_books(existing_payload: &[u8], incoming_payload: &[u8]) -> Option<Vec<u8>> {
    let mut dst_book: ErrorPitfallBook = serde_json::from_slice(existing_payload).ok()?;
    let src_book: ErrorPitfallBook = serde_json::from_slice(incoming_payload).ok()?;
    for (k, entry) in src_book.pitfalls {
        match dst_book.pitfalls.get_mut(&k) {
            Some(cur) => {
                if entry.last_learned_ns > cur.last_learned_ns {
                    *cur = entry;
                }
            }
            None => {
                dst_book.pitfalls.insert(k, entry);
            }
        }
    }
    serde_json::to_vec(&dst_book).ok()
}

fn merge_symbol_bridge_books(existing_payload: &[u8], incoming_payload: &[u8]) -> Option<Vec<u8>> {
    let mut dst_book: SymbolCueBridgeBook = serde_json::from_slice(existing_payload).ok()?;
    let src_book: SymbolCueBridgeBook = serde_json::from_slice(incoming_payload).ok()?;
    for (cue, targets) in src_book.bridges {
        let entry = dst_book.bridges.entry(cue).or_default();
        for (sym, weight) in targets {
            if let Some(existing) = entry.iter_mut().find(|(s, _)| s == &sym) {
                if weight > existing.1 {
                    existing.1 = weight;
                }
            } else {
                entry.push((sym, weight));
            }
        }
        entry.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        entry.truncate(8);
    }
    while dst_book.bridges.len() > 512 {
        if let Some(victim) = dst_book
            .bridges
            .iter()
            .min_by(|(ka, va), (kb, vb)| {
                let wa = va.first().map_or(0.0, |x| x.1);
                let wb = vb.first().map_or(0.0, |x| x.1);
                wa.total_cmp(&wb).then_with(|| ka.cmp(kb))
            })
            .map(|(k, _)| k.clone())
        {
            dst_book.bridges.remove(&victim);
        } else {
            break;
        }
    }
    serde_json::to_vec(&dst_book).ok()
}

fn merge_reflex_utility_books(existing_payload: &[u8], incoming_payload: &[u8]) -> Option<Vec<u8>> {
    let mut dst_book: ReflexUtilityBook = serde_json::from_slice(existing_payload).ok()?;
    let src_book: ReflexUtilityBook = serde_json::from_slice(incoming_payload).ok()?;
    for (id, st) in src_book.stats {
        match dst_book.stats.get_mut(&id) {
            Some(cur) => {
                if st.last_updated_ns > cur.last_updated_ns {
                    *cur = st;
                } else if st.last_updated_ns == cur.last_updated_ns {
                    cur.successes = cur.successes.max(st.successes);
                    cur.failures = cur.failures.max(st.failures);
                }
            }
            None => {
                dst_book.stats.insert(id, st);
            }
        }
    }
    serde_json::to_vec(&dst_book).ok()
}

fn merge_nodes_additive(
    dst_db: &Arc<LibreDb>,
    nodes: Vec<ExportedNode>,
    preserve_instance_security: bool,
) -> Result<(usize, usize, usize), String> {
    struct ExistingDstNode {
        node_id: u64,
        kind: NodeKind,
        importance: u8,
        pinned: bool,
        updated_ns: u64,
        key: Option<String>,
    }

    let mut active_inodes = Vec::new();
    let mut existing_edges: HashSet<(u64, u8, u64)> = HashSet::new();
    for (ino, key_opt, syns) in dst_db.list_inodes(None, false) {
        if !ino.flags.is_live_active() {
            continue;
        }
        for s in &syns {
            existing_edges.insert((ino.node_id, s.kind as u8, s.target_id));
        }
        active_inodes.push(ExistingDstNode {
            node_id: ino.node_id,
            kind: ino.kind,
            importance: ino.importance,
            pinned: ino.flags.contains(NodeFlags::PINNED),
            updated_ns: ino.updated_ns,
            key: key_opt,
        });
    }

    let existing_ids: Vec<u64> = active_inodes.iter().map(|n| n.node_id).collect();
    let mut existing_payloads: HashMap<u64, Vec<u8>> = HashMap::with_capacity(existing_ids.len());
    if !existing_ids.is_empty() {
        let (recs, _) = dst_db
            .get_many_coalesced(&existing_ids)
            .map_err(|e| e.to_string())?;
        for r in recs {
            existing_payloads.insert(r.node_id, r.payload);
        }
    }

    struct ExistingKeyedMeta {
        node_id: u64,
        updated_ns: u64,
        importance: u8,
        pinned: bool,
        payload: Vec<u8>,
    }
    let mut existing_keyed: HashMap<(NodeKind, String), ExistingKeyedMeta> = HashMap::new();
    let mut existing_unkeyed: HashMap<(NodeKind, Vec<u8>), u64> = HashMap::new();
    for n in active_inodes {
        let payload = existing_payloads.remove(&n.node_id).unwrap_or_default();
        if let Some(k) = n.key {
            existing_keyed.insert(
                (n.kind, k),
                ExistingKeyedMeta {
                    node_id: n.node_id,
                    updated_ns: n.updated_ns,
                    importance: n.importance,
                    pinned: n.pinned,
                    payload,
                },
            );
        } else {
            existing_unkeyed.insert((n.kind, payload), n.node_id);
        }
    }

    let mut to_write: Vec<(usize, ExportedNode)> = Vec::new();
    let mut skipped_edge_sources: Vec<(u64, Vec<Synapse>)> = Vec::new();
    let mut id_map: HashMap<u64, u64> = HashMap::new();
    let mut skipped_older = 0usize;
    let mut batch_unkeyed: HashSet<(NodeKind, Vec<u8>)> = HashSet::new();

    for mut item in nodes {
        if item.kind == NodeKind::Config {
            if let Some(ref k) = item.key {
                if k == BACKUP_MANIFEST_KEY || k == TRUST_SEALS_KEY || k == TRUST_SECRET_KEY {
                    continue;
                }
                if preserve_instance_security && is_instance_host_ratchet_key(k) {
                    continue;
                }
                if !preserve_instance_security && is_project_forbidden_control_config_key(k) {
                    continue;
                }
            }
        }
        if item.kind == NodeKind::Generic {
            let merged_opt = match item.key.as_deref() {
                Some(ERROR_PITFALL_BOOK_KEY) => existing_keyed
                    .get(&(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY.to_owned()))
                    .and_then(|cur| {
                        merge_pitfall_books(&cur.payload, &item.payload)
                            .map(|bytes| (cur.node_id, &cur.payload, bytes))
                    }),
                Some(SYMBOL_CUE_BRIDGES_KEY) => existing_keyed
                    .get(&(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY.to_owned()))
                    .and_then(|cur| {
                        merge_symbol_bridge_books(&cur.payload, &item.payload)
                            .map(|bytes| (cur.node_id, &cur.payload, bytes))
                    }),
                Some(REFLEX_UTILITY_BOOK_KEY) => existing_keyed
                    .get(&(NodeKind::Generic, REFLEX_UTILITY_BOOK_KEY.to_owned()))
                    .and_then(|cur| {
                        merge_reflex_utility_books(&cur.payload, &item.payload)
                            .map(|bytes| (cur.node_id, &cur.payload, bytes))
                    }),
                _ => None,
            };
            if let Some((cur_id, cur_payload, merged_bytes)) = merged_opt {
                if cur_payload == &merged_bytes {
                    id_map.insert(item.old_id, cur_id);
                    skipped_older += 1;
                    continue;
                }
                item.payload = merged_bytes;
                let idx = to_write.len();
                to_write.push((idx, item));
                continue;
            }
        }

        if let Some(ref k) = item.key {
            if let Some(existing) = existing_keyed.get(&(item.kind, k.clone())) {
                if existing.updated_ns > item.updated_ns
                    || (existing.payload == item.payload
                        && existing.importance == item.importance
                        && existing.pinned == item.pinned)
                {
                    id_map.insert(item.old_id, existing.node_id);
                    skipped_edge_sources.push((item.old_id, item.synapses));
                    skipped_older += 1;
                    continue;
                }
            }
        } else {
            let unkeyed_sig = (item.kind, item.payload.clone());
            if let Some(&existing_id) = existing_unkeyed.get(&unkeyed_sig) {
                id_map.insert(item.old_id, existing_id);
                skipped_edge_sources.push((item.old_id, item.synapses));
                skipped_older += 1;
                continue;
            }
            if !batch_unkeyed.insert(unkeyed_sig) {
                skipped_older += 1;
                continue;
            }
        }

        let idx = to_write.len();
        to_write.push((idx, item));
    }

    if !to_write.is_empty() {
        let mut prepared = Vec::with_capacity(to_write.len());
        for (lane_idx, item) in &to_write {
            let mut req = WriteRequest::new(item.kind, item.payload.clone())
                .with_importance(item.importance)
                .with_pinned(item.pinned);
            if let Some(ref k) = item.key {
                req = req.with_key(k.clone());
            }
            prepared.push(
                dst_db
                    .prepare(req, lane_idx % libredb_core::SHARD_WRITE_LANES)
                    .map_err(|e| e.to_string())?,
            );
        }

        let assigned_ids = dst_db.commit_batch(&prepared).map_err(|e| e.to_string())?;
        for ((_, item), &new_id) in to_write.iter().zip(assigned_ids.iter()) {
            id_map.insert(item.old_id, new_id);
        }
    }

    let mut edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    for (_, item) in &to_write {
        let Some(&src_new) = id_map.get(&item.old_id) else {
            continue;
        };
        for syn in &item.synapses {
            if syn.kind == EdgeKind::Supersedes {
                continue;
            }
            if let Some(&dst_new) = id_map.get(&syn.target_id) {
                if existing_edges.insert((src_new, syn.kind as u8, dst_new)) {
                    edges.push((src_new, syn.kind, dst_new, syn.weight));
                }
            }
        }
    }
    for (old_id, syns) in &skipped_edge_sources {
        let Some(&src_new) = id_map.get(old_id) else {
            continue;
        };
        for syn in syns {
            if syn.kind == EdgeKind::Supersedes {
                continue;
            }
            if let Some(&dst_new) = id_map.get(&syn.target_id) {
                if existing_edges.insert((src_new, syn.kind as u8, dst_new)) {
                    edges.push((src_new, syn.kind, dst_new, syn.weight));
                }
            }
        }
    }

    let edge_cnt = edges.len();
    if !edges.is_empty() {
        dst_db.link_batch(&edges).map_err(|e| e.to_string())?;
    }

    if !to_write.is_empty() || edge_cnt > 0 {
        let mut cog = CognitiveEngine::open_db(Arc::clone(dst_db)).map_err(|e| e.to_string())?;
        cog.save_index_snapshot().map_err(|e| e.to_string())?;
        let _ = dst_db
            .compact_with_options(false)
            .map_err(|e| e.to_string())?;
    }

    Ok((to_write.len(), edge_cnt, skipped_older))
}

#[cfg(unix)]
fn set_private_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_dir: &Path) {}

#[cfg(unix)]
fn set_private_file_permissions(file: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(file, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_file_permissions(_file: &Path) {}

struct StagingFileGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn has_internet_mark_of_the_web(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let ads_path = format!("{}:Zone.Identifier", path.display());
        if let Ok(content) = fs::read_to_string(&ads_path) {
            for line in content.lines() {
                let cleaned: String = line
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<String>()
                    .to_ascii_lowercase();
                if cleaned.starts_with("zoneid=3") || cleaned.starts_with("zoneid=4") {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// Re-encrypts any `portable_plain:` secret payloads on `proj_db`, strips `sys::backup_manifest`
/// and disallowed control-plane `Config` keys, refreshes snapshots/compaction, and seals `ws_root`
/// on this host (`v4` HMAC).
/// Caller MUST hold `WorkspaceTrustLockGuard` on `(global_db, ws_root)` when calling this `_locked` path.
pub(super) fn adopt_portable_backup_in_place_locked(
    global_db: &LibreDb,
    proj_db: &Arc<LibreDb>,
    ws_root: &Path,
) -> Result<BackupManifest, String> {
    if is_git_index_tracking_agents_db(ws_root) {
        return Err(format!(
            "Refusing to auto-adopt '.agents/memory.ldb' in '{}' because it is tracked in '.git/index'.",
            ws_root.display()
        ));
    }
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if has_internet_mark_of_the_web(&ldb_path) {
        return Err(format!(
            "Refusing to auto-adopt '.agents/memory.ldb' in '{}' because it carries an Internet Mark-of-the-Web (Zone.Identifier).",
            ws_root.display()
        ));
    }
    let Some(manifest) = has_valid_portable_backup_manifest(proj_db, Some(BackupScope::Project))?
    else {
        return Err(format!(
            "No valid sys::backup_manifest found in '{}/.agents/memory.ldb'.",
            ws_root.display()
        ));
    };

    reencrypt_portable_secrets_in_place(proj_db)?;
    let config_inodes = proj_db.list_inodes(Some(NodeKind::Config), false);
    for (ino, key_opt, _) in config_inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        if let Some(k) = key_opt {
            if k != TRUST_SEALS_KEY
                && k != BACKUP_MANIFEST_KEY
                && is_project_forbidden_control_config_key(&k)
            {
                deprecate_config_if_present(proj_db, &k)?;
            }
        }
    }
    deprecate_config_if_present(proj_db, BACKUP_MANIFEST_KEY)?;
    let mut cog = CognitiveEngine::open_db(Arc::clone(proj_db)).map_err(|e| e.to_string())?;
    cog.save_index_snapshot().map_err(|e| e.to_string())?;
    proj_db
        .compact_with_options(false)
        .map_err(|e| format!("Failed to compact adopted backup database: {e}"))?;

    seal_workspace_memory_inner(global_db, proj_db.as_ref(), ws_root, false, None)?;
    Ok(manifest)
}

pub fn adopt_portable_backup_in_place(
    global_db: &LibreDb,
    proj_db: &Arc<LibreDb>,
    ws_root: &Path,
) -> Result<BackupManifest, String> {
    let _ws_lock = super::WorkspaceTrustLockGuard::acquire(global_db, ws_root)?;
    adopt_portable_backup_in_place_locked(global_db, proj_db, ws_root)
}

fn reencrypt_portable_secrets_in_place(db: &LibreDb) -> Result<usize, String> {
    let mut updated = 0usize;
    let inodes = db.list_inodes(Some(NodeKind::Config), false);
    for (ino, key_opt, _) in inodes {
        let Some(k) = key_opt else { continue };
        if k == BACKUP_MANIFEST_KEY || k == TRUST_SEALS_KEY || k == TRUST_SECRET_KEY {
            continue;
        }
        let rec = db.get(ino.node_id).map_err(|e| e.to_string())?;
        if let Ok(mut s) = String::from_utf8(rec.payload.clone()) {
            if let Some(plain_slice) = s.trim().strip_prefix(PORTABLE_SECRET_PREFIX) {
                let enc = protect_secret(plain_slice)?;
                db.put(
                    WriteRequest::new(NodeKind::Config, enc.into_bytes())
                        .with_key(k)
                        .with_importance(ino.importance)
                        .with_pinned(ino.flags.contains(NodeFlags::PINNED)),
                )
                .map_err(|e| e.to_string())?;
                secure_zero(unsafe { s.as_bytes_mut() });
                updated += 1;
            }
        }
    }
    Ok(updated)
}

fn resolve_backup_destination(opts: &BackupOptions) -> Result<PathBuf, String> {
    if let Some(ref d) = opts.destination {
        return Ok(d.clone());
    }
    if opts.allow_prompt && io::stdin().is_terminal() {
        eprintln!(
            "[WARN] LibreDB backups are stored UNENCRYPTED (portable plaintext format) for cross-system recovery."
        );
        eprint!("Enter target directory path for UNENCRYPTED LibreDB backup: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read backup destination from terminal: {e}"))?;
        let trimmed = line.trim().trim_matches('"').trim_matches('\'');
        if trimmed.is_empty() {
            return Err("Backup aborted: empty destination path.".to_owned());
        }
        return Ok(PathBuf::from(trimmed));
    }
    Err(
        "Missing backup destination path. Pass <destination_dir> (note: backups are stored UNENCRYPTED for cross-system recovery)."
            .to_owned(),
    )
}

fn validate_safe_backup_destination(dest: &Path, ws_roots: &[&Path]) -> Result<(), String> {
    let norm = normalize_workspace_key(dest);
    if norm == ".git" || norm.ends_with("/.git") || norm.contains("/.git/") {
        return Err(format!(
            "Refusing to write unencrypted backups inside a '.git' directory ('{}').",
            dest.display()
        ));
    }
    if norm == ".agents" || norm.ends_with("/.agents") || norm.contains("/.agents/") {
        return Err(format!(
            "Refusing to write backup inside an active '.agents' directory ('{}'). Choose an external or dedicated backup folder.",
            dest.display()
        ));
    }
    for ws in ws_roots {
        let ws_norm = normalize_workspace_key(ws);
        if norm == ws_norm || norm.starts_with(&format!("{ws_norm}/")) {
            return Err(format!(
                "Refusing to store UNENCRYPTED backup inside workspace repository '{}': choose a folder outside Git working trees (e.g. a local Backup drive or NAS).",
                ws.display()
            ));
        }
    }
    Ok(())
}

fn ensure_backup_gitignore(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create backup directory '{}': {e}", dir.display()))?;
    set_private_dir_permissions(dir);
    let gi = dir.join(".gitignore");
    if !gi.exists() {
        fs::write(&gi, "*\n")
            .map_err(|e| format!("Failed to write '{}': {e}", gi.display()))?;
        set_private_file_permissions(&gi);
    }
    Ok(())
}

fn export_single_db_to_file(
    src_db: &LibreDb,
    dst_file: &Path,
    scope: BackupScope,
    source_label: &str,
    telemetry_only: bool,
) -> Result<(BackupManifest, usize), String> {
    src_db
        .verify_integrity()
        .map_err(|e| format!("Source database failed CRC32 integrity verification: {e}"))?;
    let parent = dst_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("Invalid backup file target '{}'", dst_file.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create directory '{}': {e}", parent.display()))?;
    set_private_dir_permissions(parent);

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let staging = parent.join(format!(
        ".staging_backup_{}_{}.ldb",
        std::process::id(),
        nonce
    ));
    let _ = fs::remove_file(&staging);
    let mut staging_guard = StagingFileGuard::new(staging.clone());

    let (nodes, decrypted) = collect_exported_nodes(
        src_db,
        (!telemetry_only).then_some(scope),
        SecretTransform::DecryptToPortablePlain,
        telemetry_only,
    )?;

    let manifest = {
        let dst_db = Arc::new(
            LibreDb::open(&staging)
                .map_err(|e| format!("Failed to create staging backup DB: {e}"))?,
        );
        set_private_file_permissions(&staging);
        replace_db_from_nodes_in_place(&dst_db, nodes, false, !telemetry_only)?;
        let m = stamp_backup_manifest(&dst_db, scope, source_label)?;
        let verified = has_valid_portable_backup_manifest(&dst_db, Some(scope))?;
        if verified.is_none() {
            return Err("Backup manifest self-check failed after staging".to_owned());
        }
        m
    };

    if dst_file.exists() {
        let _ = fs::remove_file(dst_file);
    }
    fs::rename(&staging, dst_file).map_err(|e| {
        format!(
            "Failed to finalize backup database '{}': {e}",
            dst_file.display()
        )
    })?;
    staging_guard.disarm();
    set_private_file_permissions(dst_file);
    Ok((manifest, decrypted))
}

fn locate_chat_source_dbs(cid: &str) -> Vec<PathBuf> {
    let mut found: Vec<(SystemTime, PathBuf)> = Vec::new();
    let conv_dir = crate::hooks::resolve_brain_conv_dir(cid);
    let eph_name = ephemeral_workspace_ldb_filename(&conv_dir);
    if let Ok(entries) = fs::read_dir(std::env::temp_dir()) {
        for ent in entries.flatten() {
            let fname = ent.file_name();
            if fname
                .to_str()
                .is_some_and(|n| n.starts_with("libredb_mcp_eph_"))
            {
                let cand = ent.path().join(&eph_name);
                if cand.is_file() {
                    let mtime = cand
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(UNIX_EPOCH);
                    found.push((mtime, cand));
                }
            }
        }
    }
    let legacy = conv_dir.join(".agents").join("memory.ldb");
    if legacy.is_file() {
        let mtime = legacy
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH);
        found.push((mtime, legacy));
    }
    found.sort_by_key(|(ts, _)| *ts);
    found.into_iter().map(|(_, p)| p).collect()
}

pub fn execute_backup_command(opts: &BackupOptions) -> Result<BackupReport, String> {
    if opts.cid.is_some() && (opts.instance || opts.all) {
        return Err("Cannot combine '--cid' with '--instance' or '--all' in 'backup'.".to_owned());
    }

    let dest = resolve_backup_destination(opts)?;
    let gdb_opt = crate::hooks::open_global_ldb_checked(opts.global_path.as_deref())?;
    let global_path = opts
        .global_path
        .clone()
        .unwrap_or_else(crate::hooks::default_global_ldb_path);

    let mut total_secrets = 0usize;
    let mut total_capsules = 0usize;
    let mut index = BackupIndex {
        format: BACKUP_FORMAT_V1.to_owned(),
        scope: if opts.all {
            "all".to_owned()
        } else if opts.instance {
            "instance".to_owned()
        } else if opts.cid.is_some() {
            "chat".to_owned()
        } else {
            "project".to_owned()
        },
        exported_at_unix_s: current_unix_s(),
        source_host: current_host_label(),
        unencrypted_warning: format!(
            "[WARN] Backup files in '{}' are stored UNENCRYPTED (portable plaintext format) for cross-system recovery. Keep only on trusted media.",
            dest.display()
        ),
        instance_db: None,
        telemetry_db: None,
        chat_db: None,
        projects: Vec::new(),
    };

    if let Some(ref cid) = opts.cid {
        let trimmed_cid = cid.trim();
        validate_safe_backup_destination(&dest, &[])?;
        let mut dbs = locate_chat_source_dbs(trimmed_cid);
        if dbs.is_empty() {
            if let Some(ref proj_dir) = opts.project_dir {
                let (candidate, ws_opt) = if proj_dir.is_file() {
                    (proj_dir.clone(), workspace_root_from_ldb_path(proj_dir))
                } else {
                    let ws_root = crate::hooks::find_workspace_root(proj_dir)
                        .unwrap_or_else(|| proj_dir.clone());
                    (ws_root.join(".agents").join("memory.ldb"), Some(ws_root))
                };
                if candidate.is_file() {
                    if let Some(ref ws_root) = ws_opt {
                        let Some(ref gdb) = gdb_opt else {
                            return Err(format!(
                                "Refusing to back up project database '{}' without an initialized customizations.ldb trust anchor at '{}'.",
                                candidate.display(),
                                global_path.display()
                            ));
                        };
                        if !is_workspace_memory_trusted(Some(gdb), ws_root) {
                            return Err(diagnose_untrusted_workspace_db(Some(gdb), ws_root));
                        }
                    }
                    dbs.push(candidate);
                }
            }
        }
        if dbs.is_empty() {
            return Err(format!(
                "No session or local memory database found for conversation ID '{trimmed_cid}'."
            ));
        }
        let target_dir = if dest.extension().and_then(|e| e.to_str()) == Some("ldb") {
            return Err("Chat backup destination must be a directory path.".to_owned());
        } else {
            ensure_backup_gitignore(&dest)?;
            dest.join(format!("chat_{}", sanitize_slug(trimmed_cid)))
        };
        fs::create_dir_all(&target_dir).map_err(|e| e.to_string())?;
        set_private_dir_permissions(&target_dir);
        let out_ldb = target_dir.join("memory.ldb");
        if dbs.len() == 1 {
            let src = LibreDb::open(&dbs[0]).map_err(|e| e.to_string())?;
            let (m, dec) = export_single_db_to_file(
                &src,
                &out_ldb,
                BackupScope::Chat,
                trimmed_cid,
                false,
            )?;
            total_secrets += dec;
            total_capsules += m.capsule_count;
        } else {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let staging = target_dir.join(format!(
                ".staging_backup_{}_{}.ldb",
                std::process::id(),
                nonce
            ));
            let _ = fs::remove_file(&staging);
            let mut staging_guard = StagingFileGuard::new(staging.clone());
            let m_count = {
                let temp_merged = Arc::new(LibreDb::open(&staging).map_err(|e| e.to_string())?);
                set_private_file_permissions(&staging);
                for p in &dbs {
                    let sdb = LibreDb::open(p).map_err(|e| e.to_string())?;
                    sdb.verify_integrity().map_err(|e| e.to_string())?;
                    let (nodes, dec) = collect_exported_nodes(
                        &sdb,
                        Some(BackupScope::Chat),
                        SecretTransform::DecryptToPortablePlain,
                        false,
                    )?;
                    total_secrets += dec;
                    merge_nodes_additive(&temp_merged, nodes, false)?;
                }
                let m = stamp_backup_manifest(&temp_merged, BackupScope::Chat, trimmed_cid)?;
                if has_valid_portable_backup_manifest(&temp_merged, Some(BackupScope::Chat))?
                    .is_none()
                {
                    return Err(
                        "Multi-DB chat backup manifest self-check failed after staging".to_owned(),
                    );
                }
                m.capsule_count
            };
            if out_ldb.exists() {
                let _ = fs::remove_file(&out_ldb);
            }
            fs::rename(&staging, &out_ldb).map_err(|e| {
                format!(
                    "Failed to finalize chat backup '{}': {e}",
                    out_ldb.display()
                )
            })?;
            staging_guard.disarm();
            set_private_file_permissions(&out_ldb);
            total_capsules += m_count;
        }
        index.chat_db = Some(format!("chat_{}/memory.ldb", sanitize_slug(trimmed_cid)));
        let idx_file = dest.join("backup_index.json");
        fs::write(
            &idx_file,
            serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        set_private_file_permissions(&idx_file);
        return Ok(BackupReport {
            destination: dest.display().to_string(),
            scope: "chat".to_owned(),
            unencrypted_warning: index.unencrypted_warning,
            instance_exported: false,
            telemetry_exported: false,
            chat_exported: true,
            projects_exported: Vec::new(),
            secrets_decrypted: total_secrets,
            total_capsules,
        });
    }

    if opts.instance || opts.all {
        let Some(ref gdb) = gdb_opt else {
            return Err(format!(
                "Cannot export instance backup: global customizations.ldb not found at '{}'.",
                global_path.display()
            ));
        };
        let mut protected_ws: Vec<PathBuf> = Vec::new();
        if let Ok(workspaces) = list_trusted_workspaces(gdb) {
            for (_, raw_p) in workspaces {
                protected_ws.push(PathBuf::from(raw_p));
            }
        }
        let ws_refs: Vec<&Path> = protected_ws.iter().map(PathBuf::as_path).collect();
        validate_safe_backup_destination(&dest, &ws_refs)?;
        ensure_backup_gitignore(&dest)?;

        let inst_dir = dest.join("instance");
        let inst_ldb = inst_dir.join("customizations.ldb");
        let (inst_m, dec) = export_single_db_to_file(
            gdb,
            &inst_ldb,
            BackupScope::Instance,
            "customizations.ldb",
            false,
        )?;
        total_secrets += dec;
        total_capsules += inst_m.capsule_count;
        index.instance_db = Some("instance/customizations.ldb".to_owned());

        let tel_src = global_path
            .parent()
            .map(|p| p.join("telemetry.ldb"))
            .unwrap_or_default();
        let mut telemetry_exported = false;
        if tel_src.is_file() {
            let tel_db = LibreDb::open(&tel_src).map_err(|e| e.to_string())?;
            let tel_out = inst_dir.join("telemetry.ldb");
            let (_, t_dec) = export_single_db_to_file(
                &tel_db,
                &tel_out,
                BackupScope::Instance,
                "telemetry.ldb",
                true,
            )?;
            total_secrets += t_dec;
            telemetry_exported = true;
            index.telemetry_db = Some("instance/telemetry.ldb".to_owned());
        }

        if opts.all {
            let projects_dir = dest.join("projects");
            fs::create_dir_all(&projects_dir).map_err(|e| e.to_string())?;
            set_private_dir_permissions(&projects_dir);
            let mut seen_slugs = HashSet::new();
            for (_, raw_ws) in list_trusted_workspaces(gdb)? {
                let ws_root = PathBuf::from(raw_ws.trim());
                let ws_ldb = ws_root.join(".agents").join("memory.ldb");
                if !ws_root.is_dir() || !ws_ldb.is_file() {
                    continue;
                }
                if !is_workspace_memory_trusted(Some(gdb), &ws_root) {
                    return Err(format!(
                        "Refusing to include untrusted or tampered workspace '{}' in '--all' backup.",
                        ws_root.display()
                    ));
                }
                let mut slug = project_backup_slug(&ws_root);
                while !seen_slugs.insert(slug.clone()) {
                    slug.push('_');
                }
                let rel_ldb = format!("projects/{slug}/memory.ldb");
                let out_ldb = dest.join(&rel_ldb);
                let src_pdb = LibreDb::open(&ws_ldb).map_err(|e| e.to_string())?;
                let label = strip_verbatim_prefix(&ws_root).to_string_lossy().into_owned();
                let (pm, pdec) = export_single_db_to_file(
                    &src_pdb,
                    &out_ldb,
                    BackupScope::Project,
                    &label,
                    false,
                )?;
                total_secrets += pdec;
                total_capsules += pm.capsule_count;
                index.projects.push(BackupProjectEntry {
                    slug,
                    original_path: label,
                    relative_ldb_path: rel_ldb,
                    capsule_count: pm.capsule_count,
                    content_sha256: pm.content_sha256,
                });
            }
        }

        let idx_file = dest.join("backup_index.json");
        fs::write(
            &idx_file,
            serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("Failed to write backup_index.json: {e}"))?;
        set_private_file_permissions(&idx_file);

        return Ok(BackupReport {
            destination: dest.display().to_string(),
            scope: index.scope,
            unencrypted_warning: index.unencrypted_warning,
            instance_exported: true,
            telemetry_exported,
            chat_exported: false,
            projects_exported: index.projects,
            secrets_decrypted: total_secrets,
            total_capsules,
        });
    }

    // Default: single project backup.
    let raw_proj = opts
        .project_dir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| "Unable to determine project directory for backup.".to_owned())?;
    let ws_root = crate::hooks::find_workspace_root(&raw_proj).unwrap_or(raw_proj);
    if is_private_brain_workspace(&ws_root) {
        return Err(
            "Private Antigravity brain directory cannot be backed up as a project. Pass '--cid <id>' to back up a standalone chat, or '--project <dir>' for a project."
                .to_owned(),
        );
    }
    let ws_ldb = ws_root.join(".agents").join("memory.ldb");
    if !ws_ldb.is_file() {
        return Err(format!(
            "No project database found at '{}'.",
            ws_ldb.display()
        ));
    }
    let Some(ref gdb) = gdb_opt else {
        return Err(format!(
            "Refusing to back up workspace '{}' without an initialized customizations.ldb trust anchor at '{}'. Run 'libredb trust \"{}\"' first or inspect read-only via '/libredb read \"{}\"'",
            ws_root.display(),
            global_path.display(),
            ws_root.display(),
            ws_ldb.display()
        ));
    };
    if !is_workspace_memory_trusted(Some(gdb), &ws_root) {
        return Err(diagnose_untrusted_workspace_db(Some(gdb), &ws_root));
    }
    validate_safe_backup_destination(&dest, &[&ws_root])?;

    let is_explicit_file = dest
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ldb"));
    let slug = project_backup_slug(&ws_root);
    let (index_dir, out_ldb, rel_ldb) = if is_explicit_file {
        let p = dest.parent().unwrap_or_else(|| Path::new("."));
        ensure_backup_gitignore(p)?;
        let fname = dest
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("memory.ldb")
            .to_owned();
        (p.to_path_buf(), dest.clone(), fname)
    } else {
        ensure_backup_gitignore(&dest)?;
        let fname = format!("{slug}_memory.ldb");
        (dest.clone(), dest.join(&fname), fname)
    };

    let src_pdb = LibreDb::open(&ws_ldb).map_err(|e| e.to_string())?;
    let label = strip_verbatim_prefix(&ws_root).to_string_lossy().into_owned();
    let (pm, pdec) =
        export_single_db_to_file(&src_pdb, &out_ldb, BackupScope::Project, &label, false)?;
    total_secrets += pdec;
    total_capsules += pm.capsule_count;
    let entry = BackupProjectEntry {
        slug,
        original_path: label,
        relative_ldb_path: rel_ldb,
        capsule_count: pm.capsule_count,
        content_sha256: pm.content_sha256,
    };
    index.projects.push(entry.clone());
    let info_file = index_dir.join(if is_explicit_file {
        "backup_project_info.json"
    } else {
        "backup_index.json"
    });
    fs::write(
        &info_file,
        serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    set_private_file_permissions(&info_file);

    Ok(BackupReport {
        destination: dest.display().to_string(),
        scope: "project".to_owned(),
        unencrypted_warning: index.unencrypted_warning,
        instance_exported: false,
        telemetry_exported: false,
        chat_exported: false,
        projects_exported: vec![entry],
        secrets_decrypted: total_secrets,
        total_capsules,
    })
}

fn require_valid_backup_file(path: &Path, expected_scope: BackupScope) -> Result<(LibreDb, BackupManifest), String> {
    if !path.is_file() {
        return Err(format!("Backup database file '{}' does not exist.", path.display()));
    }
    let db = LibreDb::open(path).map_err(|e| {
        format!(
            "Failed to open backup database '{}': {e}",
            path.display()
        )
    })?;
    db.verify_integrity().map_err(|e| {
        format!(
            "Backup database '{}' failed CRC32 integrity verification: {e}",
            path.display()
        )
    })?;
    let Some(manifest) = has_valid_portable_backup_manifest(&db, Some(expected_scope))? else {
        return Err(format!(
            "Refusing to restore '{}': database was NOT exported via '/libredb backup' ('libredb backup'), so it has no valid sys::backup_manifest. Export cleanly via '/libredb backup' on the source system, or inspect it read-only at your own risk via '/libredb read \"{}\"'",
            path.display(),
            path.display()
        ));
    };
    Ok((db, manifest))
}

fn pre_restore_backup_file(target: &Path) -> Result<Option<String>, String> {
    if !target.is_file() {
        return Ok(None);
    }
    let bak = target.with_extension("ldb.pre_restore.bak");
    fs::copy(target, &bak).map_err(|e| {
        format!(
            "Failed to create pre-restore safety copy '{}': {e}",
            bak.display()
        )
    })?;
    set_private_file_permissions(&bak);
    Ok(Some(bak.display().to_string()))
}

fn restore_project_ldb_from_backup_file(
    global_db: &LibreDb,
    src_file: &Path,
    ws_root: &Path,
) -> Result<(usize, Option<String>), String> {
    if fs::symlink_metadata(ws_root).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "Refusing to restore into symlinked workspace directory '{}'.",
            ws_root.display()
        ));
    }
    if is_private_brain_workspace(ws_root) {
        return Err("Refusing to restore a project database inside Antigravity's private brain folder.".to_owned());
    }
    if is_forbidden_mcp_workspace_root(ws_root) {
        return Err(format!(
            "Refusing to restore project database into forbidden root '{}'.",
            ws_root.display()
        ));
    }
    let (src_db, _) = require_valid_backup_file(src_file, BackupScope::Project)?;
    let _ws_lock = super::WorkspaceTrustLockGuard::acquire(global_db, ws_root)?;
    check_global_trust_sync(global_db)?;

    let target_ldb = ws_root.join(".agents").join("memory.ldb");
    if let Some(p) = target_ldb.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let pre_bak = pre_restore_backup_file(&target_ldb)?;

    let (nodes, reencrypted) = collect_exported_nodes(
        &src_db,
        Some(BackupScope::Project),
        SecretTransform::EncryptPortablePlainToLocalVault,
        false,
    )?;

    let dst_db = Arc::new(LibreDb::open(&target_ldb).map_err(|e| e.to_string())?);
    replace_db_from_nodes_in_place(&dst_db, nodes, false, true)?;
    deprecate_config_if_present(&dst_db, BACKUP_MANIFEST_KEY)?;
    seal_workspace_memory_inner(global_db, dst_db.as_ref(), ws_root, false, None)?;
    Ok((reencrypted, pre_bak))
}

pub(super) fn resolve_single_project_backup_file(source: &Path) -> Result<PathBuf, String> {
    if source.is_file() {
        return Ok(source.to_path_buf());
    }
    if !source.is_dir() {
        return Err(format!("Backup source '{}' does not exist.", source.display()));
    }
    let direct = source.join("memory.ldb");
    if direct.is_file() {
        return Ok(direct);
    }
    let idx_path = source.join("backup_index.json");
    if idx_path.is_file() {
        if let Ok(bytes) = fs::read(&idx_path) {
            if let Ok(idx) = serde_json::from_slice::<BackupIndex>(&bytes) {
                let rel_opt = if let Some(ref cdb) = idx.chat_db {
                    (idx.projects.is_empty()).then_some(cdb.as_str())
                } else if idx.projects.len() == 1 {
                    Some(idx.projects[0].relative_ldb_path.as_str())
                } else {
                    None
                };
                if let Some(rel) = rel_opt {
                    let p = Path::new(rel);
                    let safe_rel = !p.is_absolute()
                        && p.components().all(|c| {
                            matches!(
                                c,
                                std::path::Component::Normal(_) | std::path::Component::CurDir
                            )
                        });
                    if safe_rel {
                        let candidate = source.join(p);
                        if candidate.is_file() {
                            return Ok(candidate);
                        }
                    }
                }
            }
        }
    }
    let mut matches = Vec::new();
    if let Ok(entries) = fs::read_dir(source) {
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_file()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.ends_with("_memory.ldb"))
            {
                matches.push(p);
            }
        }
    }
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    Err(format!(
        "Could not uniquely locate a project backup '.ldb' file inside '{}'. Pass the explicit '.ldb' file path.",
        source.display()
    ))
}

fn restore_instance_dbs_from_backup(
    source_root_or_file: &Path,
    global_path_override: Option<&Path>,
) -> Result<(usize, bool, Vec<String>), String> {
    let inst_src_file = if source_root_or_file.is_file() {
        source_root_or_file.to_path_buf()
    } else {
        let nested = source_root_or_file.join("instance").join("customizations.ldb");
        if nested.is_file() {
            nested
        } else {
            source_root_or_file.join("customizations.ldb")
        }
    };

    let (src_db, _) = require_valid_backup_file(&inst_src_file, BackupScope::Instance)?;
    let target_global = global_path_override
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::hooks::default_global_ldb_path);

    let mut baks = Vec::new();
    if let Some(bak) = pre_restore_backup_file(&target_global)? {
        baks.push(bak);
    }
    let dst_gdb = crate::hooks::open_global_ldb(Some(&target_global))?;
    let _ = ensure_trust_anchor_secret(&dst_gdb)?;

    let (nodes, reencrypted) = collect_exported_nodes(
        &src_db,
        Some(BackupScope::Instance),
        SecretTransform::EncryptPortablePlainToLocalVault,
        false,
    )?;
    replace_db_from_nodes_in_place(&dst_gdb, nodes, true, true)?;
    deprecate_config_if_present(&dst_gdb, BACKUP_MANIFEST_KEY)?;

    // Telemetry restore (if exported alongside customizations.ldb).
    let mut telemetry_restored = false;
    let tel_src = inst_src_file
        .parent()
        .map(|p| p.join("telemetry.ldb"))
        .unwrap_or_default();
    if tel_src.is_file() {
        if let Ok((tel_src_db, _)) = require_valid_backup_file(&tel_src, BackupScope::Instance) {
            if let Some(tel_dst_path) = target_global.parent().map(|p| p.join("telemetry.ldb")) {
                if let Some(tbak) = pre_restore_backup_file(&tel_dst_path)? {
                    baks.push(tbak);
                }
                let tel_dst_db = Arc::new(LibreDb::open(&tel_dst_path).map_err(|e| e.to_string())?);
                let (t_nodes, _) = collect_exported_nodes(
                    &tel_src_db,
                    None,
                    SecretTransform::KeepUnchanged,
                    true,
                )?;
                replace_db_from_nodes_in_place(&tel_dst_db, t_nodes, false, false)?;
                telemetry_restored = true;
            }
        }
    }

    Ok((reencrypted, telemetry_restored, baks))
}

pub fn execute_restore_command(opts: &RestoreOptions) -> Result<RestoreReport, String> {
    let global_path = opts
        .global_path
        .clone()
        .unwrap_or_else(crate::hooks::default_global_ldb_path);

    if opts.instance || opts.all {
        let (mut total_secrets, telemetry_restored, mut backup_files_created) =
            restore_instance_dbs_from_backup(&opts.source, Some(&global_path))?;
        let gdb = crate::hooks::open_global_ldb(Some(&global_path))?;
        let mut projects_restored = Vec::new();
        let mut projects_skipped = Vec::new();

        if opts.all {
            let idx_path = if opts.source.is_dir() {
                opts.source.join("backup_index.json")
            } else {
                opts.source
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.join("backup_index.json"))
                    .unwrap_or_default()
            };
            if idx_path.is_file() {
                let raw = fs::read(&idx_path).map_err(|e| e.to_string())?;
                let index: BackupIndex = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                let base_dir = idx_path.parent().unwrap_or_else(|| Path::new("."));
                for entry in index.projects {
                    let rel_p = Path::new(&entry.relative_ldb_path);
                    let safe_rel = !rel_p.is_absolute()
                        && rel_p.components().all(|c| {
                            matches!(
                                c,
                                std::path::Component::Normal(_) | std::path::Component::CurDir
                            )
                        });
                    let src_file = base_dir.join(rel_p);
                    let target_dir = PathBuf::from(&entry.original_path);
                    let src_symlink = fs::symlink_metadata(&src_file)
                        .is_ok_and(|m| m.file_type().is_symlink());
                    let target_symlink = fs::symlink_metadata(&target_dir)
                        .is_ok_and(|m| m.file_type().is_symlink());
                    if !safe_rel
                        || src_symlink
                        || target_symlink
                        || is_private_brain_workspace(&target_dir)
                        || is_forbidden_mcp_workspace_root(&target_dir)
                    {
                        projects_skipped.push(entry);
                        continue;
                    }
                    if target_dir.is_dir() && src_file.is_file() {
                        let (dec, bak_opt) =
                            restore_project_ldb_from_backup_file(&gdb, &src_file, &target_dir)?;
                        total_secrets += dec;
                        if let Some(b) = bak_opt {
                            backup_files_created.push(b);
                        }
                        projects_restored.push(target_dir.display().to_string());
                    } else {
                        projects_skipped.push(entry);
                    }
                }
            }
        }

        return Ok(RestoreReport {
            source: opts.source.display().to_string(),
            scope: if opts.all { "all" } else { "instance" }.to_owned(),
            instance_restored: true,
            telemetry_restored,
            projects_restored,
            projects_skipped_missing_dir: projects_skipped,
            secrets_reencrypted: total_secrets,
            backup_files_created,
        });
    }

    let raw_proj = opts
        .project_dir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| "Unable to determine target project directory for restore.".to_owned())?;
    let ws_root = crate::hooks::find_workspace_root(&raw_proj).unwrap_or(raw_proj);
    let src_file = resolve_single_project_backup_file(&opts.source)?;
    let gdb = crate::hooks::open_global_ldb(Some(&global_path))?;
    let (secrets_reencrypted, pre_bak) =
        restore_project_ldb_from_backup_file(&gdb, &src_file, &ws_root)?;

    Ok(RestoreReport {
        source: src_file.display().to_string(),
        scope: "project".to_owned(),
        instance_restored: false,
        telemetry_restored: false,
        projects_restored: vec![ws_root.display().to_string()],
        projects_skipped_missing_dir: Vec::new(),
        secrets_reencrypted,
        backup_files_created: pre_bak.into_iter().collect(),
    })
}

fn try_relocate_moved_workspace_seal(
    global_db: &LibreDb,
    proj_db: &LibreDb,
    new_ws_root: &Path,
    explicit_old_path: Option<&Path>,
) -> Result<Option<String>, String> {
    check_global_trust_sync(global_db)?;
    let Ok(seal_rec) = proj_db.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) else {
        return Ok(None);
    };
    let seals_txt = String::from_utf8_lossy(&seal_rec.payload);
    let (content_digest, _) = compute_cognitive_content_digest(proj_db)?;
    let mut secret = ensure_trust_anchor_secret(global_db)?;

    let new_norm = normalize_workspace_key(new_ws_root);
    let mut candidates: Vec<(String, String)> = Vec::new();
    if let Some(old_p) = explicit_old_path {
        candidates.push((
            normalize_workspace_key(old_p),
            old_p.to_string_lossy().into_owned(),
        ));
    } else {
        for (old_norm, old_display) in list_trusted_workspaces(global_db)? {
            candidates.push((old_norm, old_display));
        }
    }

    let mut matched_old: Option<String> = None;
    for (cand_norm, cand_display) in candidates {
        if verify_and_extract_host_seal_rev(&secret, &cand_norm, &content_digest, &seals_txt)
            .is_some()
        {
            matched_old = Some(cand_display);
            break;
        }
    }
    secure_zero(&mut secret);

    let Some(old_display) = matched_old else {
        return Ok(None);
    };
    seal_workspace_memory(global_db, proj_db, new_ws_root)?;
    let old_norm = normalize_workspace_key(Path::new(&old_display));
    if old_norm != new_norm {
        let _ = revoke_workspace_trust(global_db, Path::new(&old_display));
    }
    Ok(Some(old_display))
}

fn copy_chat_artifacts_to_project(conv_dir: &Path, target_ws: &Path, cid: &str) -> usize {
    let Ok(entries) = fs::read_dir(conv_dir) else {
        return 0;
    };
    let dst_dir = target_ws
        .join("docs")
        .join(format!("migrated_{}", sanitize_slug(cid)));
    let mut copied = 0usize;
    for ent in entries.flatten() {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(
            ext.to_ascii_lowercase().as_str(),
            "md" | "html" | "htm" | "txt" | "pdf" | "json"
        ) {
            continue;
        }
        if copied == 0 && fs::create_dir_all(&dst_dir).is_err() {
            return 0;
        }
        if let Some(fname) = p.file_name() {
            if fs::copy(&p, dst_dir.join(fname)).is_ok() {
                copied += 1;
            }
        }
    }
    copied
}

pub fn execute_migrate_command(opts: &MigrateOptions) -> Result<MigrateReport, String> {
    let global_path = opts
        .global_path
        .clone()
        .unwrap_or_else(crate::hooks::default_global_ldb_path);
    let gdb = crate::hooks::open_global_ldb(Some(&global_path))?;

    let raw_target = opts
        .target_project
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| "Unable to resolve target project directory for migrate.".to_owned())?;
    let target_ws = crate::hooks::find_workspace_root(&raw_target).unwrap_or(raw_target);
    if is_private_brain_workspace(&target_ws) {
        return Err(
            "Target for 'migrate' must be a real project workspace, not a private Antigravity brain directory."
                .to_owned(),
        );
    }

    // Mode A: Single chat (--cid) -> Project merge.
    if let Some(ref raw_cid) = opts.cid {
        let cid = raw_cid.trim();
        let mut sources = locate_chat_source_dbs(cid);
        if let Some(ref explicit_src) = opts.source {
            let f = resolve_single_project_backup_file(explicit_src)?;
            if !sources.contains(&f) {
                sources.push(f);
            }
        }
        if sources.is_empty() {
            return Err(format!(
                "No session database or backup found for chat '--cid {cid}'."
            ));
        }
        fs::create_dir_all(target_ws.join(".agents")).map_err(|e| e.to_string())?;
        let target_ldb = target_ws.join(".agents").join("memory.ldb");
        let _ws_lock = super::WorkspaceTrustLockGuard::acquire(&gdb, &target_ws)?;
        if target_ldb.is_file()
            && !is_workspace_memory_trusted(Some(&gdb), &target_ws)
        {
            return Err(format!(
                "Target workspace '{}' exists on disk but is untrusted; verify it before migrating chat memory into it.",
                target_ws.display()
            ));
        }

        let dst_db = Arc::new(LibreDb::open(&target_ldb).map_err(|e| e.to_string())?);
        let mut nodes_merged = 0usize;
        let mut synapses_merged = 0usize;
        let mut skipped_older = 0usize;
        let mut used = Vec::new();
        let mut legacy_cleaned = false;
        let conv_dir = crate::hooks::resolve_brain_conv_dir(cid);
        let legacy_path = conv_dir.join(".agents").join("memory.ldb");

        for src_p in sources {
            let sdb = LibreDb::open(&src_p).map_err(|e| e.to_string())?;
            sdb.verify_integrity().map_err(|e| e.to_string())?;
            if src_p.extension().is_some_and(|e| e == "ldb")
                && opts.source.as_ref().is_some_and(|s| s == &src_p || src_p.starts_with(s))
                && has_valid_portable_backup_manifest(&sdb, Some(BackupScope::Chat))?.is_none()
            {
                return Err(format!(
                    "Refusing to migrate external chat backup '{}': missing sys::backup_manifest (not exported via '/libredb backup').",
                    src_p.display()
                ));
            }
            let (nodes, _) = collect_exported_nodes(
                &sdb,
                Some(BackupScope::Chat),
                SecretTransform::EncryptPortablePlainToLocalVault,
                false,
            )?;
            let (nm, sm, sk) = merge_nodes_additive(&dst_db, nodes, false)?;
            nodes_merged += nm;
            synapses_merged += sm;
            skipped_older += sk;
            used.push(src_p.display().to_string());
        }
        seal_workspace_memory_inner(&gdb, dst_db.as_ref(), &target_ws, false, None)?;
        if legacy_path.is_file() {
            if let Some(legacy_agents) = legacy_path.parent() {
                let _ = fs::remove_dir_all(legacy_agents);
                legacy_cleaned = true;
            }
        }
        let artifacts_copied = if opts.include_artifacts {
            copy_chat_artifacts_to_project(&conv_dir, &target_ws, cid)
        } else {
            0
        };
        return Ok(MigrateReport {
            mode: "chat_to_project".to_owned(),
            target_project: target_ws.display().to_string(),
            sources_used: used,
            nodes_merged,
            synapses_merged,
            nodes_skipped_older: skipped_older,
            artifacts_copied,
            relocated_from: None,
            legacy_brain_db_cleaned: legacy_cleaned,
        });
    }

    // Mode B: Additive merge from explicit backup/trusted local source -> target_ws.
    if let Some(ref src_arg) = opts.source {
        let src_file = if src_arg.is_dir() && src_arg.join(".agents").join("memory.ldb").is_file() {
            src_arg.join(".agents").join("memory.ldb")
        } else {
            resolve_single_project_backup_file(src_arg)?
        };
        let src_db = LibreDb::open(&src_file).map_err(|e| e.to_string())?;
        src_db.verify_integrity().map_err(|e| e.to_string())?;

        let is_backup = has_valid_portable_backup_manifest(&src_db, Some(BackupScope::Project))?.is_some();
        let is_trusted_local = src_arg.is_dir() && is_workspace_memory_trusted(Some(&gdb), src_arg);
        if !is_backup && !is_trusted_local {
            return Err(format!(
                "Refusing to migrate '{}': source is neither a valid '/libredb backup' export nor a trusted workspace on this host. Export it first with '/libredb backup' or inspect read-only via '/libredb read \"{}\"'",
                src_file.display(),
                src_file.display()
            ));
        }

        fs::create_dir_all(target_ws.join(".agents")).map_err(|e| e.to_string())?;
        let target_ldb = target_ws.join(".agents").join("memory.ldb");
        let _ws_lock = super::WorkspaceTrustLockGuard::acquire(&gdb, &target_ws)?;
        if target_ldb.is_file() && !is_workspace_memory_trusted(Some(&gdb), &target_ws) {
            return Err(format!(
                "Target workspace '{}' exists on disk but failed trust verification.",
                target_ws.display()
            ));
        }
        let dst_db = Arc::new(LibreDb::open(&target_ldb).map_err(|e| e.to_string())?);
        let (nodes, _) = collect_exported_nodes(
            &src_db,
            Some(BackupScope::Project),
            SecretTransform::EncryptPortablePlainToLocalVault,
            false,
        )?;
        let (nodes_merged, synapses_merged, nodes_skipped_older) =
            merge_nodes_additive(&dst_db, nodes, false)?;
        seal_workspace_memory_inner(&gdb, dst_db.as_ref(), &target_ws, false, None)?;
        return Ok(MigrateReport {
            mode: "additive_merge".to_owned(),
            target_project: target_ws.display().to_string(),
            sources_used: vec![src_file.display().to_string()],
            nodes_merged,
            synapses_merged,
            nodes_skipped_older,
            artifacts_copied: 0,
            relocated_from: None,
            legacy_brain_db_cleaned: false,
        });
    }

    // Mode C: Relocate moved/renamed workspace folder on same host.
    let target_ldb = target_ws.join(".agents").join("memory.ldb");
    if !target_ldb.is_file() {
        return Err(format!(
            "Nothing to migrate at '{}': pass '--cid <id>' or '<source_path>', or ensure '.agents/memory.ldb' exists in the moved folder.",
            target_ws.display()
        ));
    }
    let pdb = LibreDb::open(&target_ldb).map_err(|e| e.to_string())?;
    if let Some(old_path) =
        try_relocate_moved_workspace_seal(&gdb, &pdb, &target_ws, opts.from_path.as_deref())?
    {
        return Ok(MigrateReport {
            mode: "relocate_moved_workspace".to_owned(),
            target_project: target_ws.display().to_string(),
            sources_used: vec![target_ldb.display().to_string()],
            nodes_merged: 0,
            synapses_merged: 0,
            nodes_skipped_older: 0,
            artifacts_copied: 0,
            relocated_from: Some(old_path),
            legacy_brain_db_cleaned: false,
        });
    }

    if has_valid_portable_backup_manifest(&pdb, Some(BackupScope::Project))?.is_some() {
        let arc_pdb = Arc::new(pdb);
        adopt_portable_backup_in_place(&gdb, &arc_pdb, &target_ws)?;
        return Ok(MigrateReport {
            mode: "adopt_portable_backup".to_owned(),
            target_project: target_ws.display().to_string(),
            sources_used: vec![target_ldb.display().to_string()],
            nodes_merged: 0,
            synapses_merged: 0,
            nodes_skipped_older: 0,
            artifacts_copied: 0,
            relocated_from: None,
            legacy_brain_db_cleaned: false,
        });
    }

    Err(format!(
        "Cannot migrate '{}': database was not sealed by this host's trust anchor and does not contain a valid '/libredb backup' manifest. Export properly via '/libredb backup', or inspect read-only at your own risk via '/libredb read \"{}\"'",
        target_ldb.display(),
        target_ldb.display()
    ))
}

fn workspace_root_from_ldb_path(db_path: &Path) -> Option<PathBuf> {
    let fname = db_path.file_name()?.to_str()?;
    if !fname.eq_ignore_ascii_case("memory.ldb") {
        return None;
    }
    let parent = db_path.parent()?;
    if parent
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case(".agents"))
    {
        parent.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

fn inspect_single_ldb_read_only(
    ldb_path: &Path,
    gdb_opt: Option<&LibreDb>,
    query_low: Option<&str>,
    show_secrets: bool,
) -> Result<ReadLdbFileReport, String> {
    if !ldb_path.is_file() {
        return Err(format!("Database file '{}' does not exist.", ldb_path.display()));
    }
    let file_bytes = fs::metadata(ldb_path).map(|m| m.len()).unwrap_or(0);
    let db = LibreDb::open(ldb_path).map_err(|e| e.to_string())?;
    let crc_integrity_ok = db.verify_integrity().is_ok();

    let (provenance_status, provenance_detail, backup_manifest) =
        match has_valid_portable_backup_manifest(&db, None) {
            Ok(Some(m)) => (
                "PORTABLE_BACKUP".to_owned(),
                format!(
                    "Valid '/libredb backup' archive (scope={:?}, host={}, capsules={}).",
                    m.scope, m.source_host, m.capsule_count
                ),
                Some(m),
            ),
            Err(tamper_err) => (
                "INVALID_OR_TAMPERED_BACKUP_MANIFEST".to_owned(),
                format!("Backup manifest failed verification: {tamper_err}"),
                None,
            ),
            Ok(None) => {
                let mut local_trusted_ws: Option<String> = None;
                if let Some(gdb) = gdb_opt {
                    if let Ok(rec) = db.get_by_key(NodeKind::Config, TRUST_SEALS_KEY) {
                        let seals_txt = String::from_utf8_lossy(&rec.payload);
                        if let Ok((digest, _)) = compute_cognitive_content_digest(&db) {
                            if let Ok(mut secret) = ensure_trust_anchor_secret(gdb) {
                                if let Some(ws_root) = workspace_root_from_ldb_path(ldb_path) {
                                    let norm = normalize_workspace_key(&ws_root);
                                    if verify_and_extract_host_seal_rev(
                                        &secret,
                                        &norm,
                                        &digest,
                                        &seals_txt,
                                    )
                                    .is_some()
                                    {
                                        local_trusted_ws = Some(ws_root.display().to_string());
                                    }
                                }
                                secure_zero(&mut secret);
                            }
                        }
                    }
                }
                if let Some(ws) = local_trusted_ws {
                    (
                        "TRUSTED_LOCAL_DB".to_owned(),
                        format!("Valid local HMAC-SHA256 v4 seal bound to '{ws}'."),
                        None,
                    )
                } else {
                    (
                        "UNVERIFIED_FOREIGN_OR_RAW_DB".to_owned(),
                        "WARNING: Database was NOT created via '/libredb backup' and carries no valid local host seal. Cannot be restored or trusted directly; inspecting content read-only at your own risk.".to_owned(),
                        None,
                    )
                }
            }
        };

    let mut kind_counts: BTreeMap<String, usize> = BTreeMap::new();
    let inodes = db.list_inodes(None, false);
    let mut active_nodes = 0usize;
    let mut inspect_rows: Vec<(libredb_core::Inode, Option<String>)> = Vec::new();
    for (ino, key_opt, _) in inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        active_nodes += 1;
        *kind_counts
            .entry(ino.kind.as_str().to_owned())
            .or_insert(0) += 1;
        if matches!(
            ino.kind,
            NodeKind::Symbol | NodeKind::QuotaEvent | NodeKind::TranscriptCursor | NodeKind::WorkingSet
        ) {
            continue;
        }
        if key_opt.as_deref() == Some("sys::index_snapshot") {
            continue;
        }
        inspect_rows.push((ino, key_opt));
    }
    let fetch_ids: Vec<u64> = inspect_rows.iter().map(|(i, _)| i.node_id).collect();
    let mut by_id: HashMap<u64, Vec<u8>> = HashMap::new();
    if !fetch_ids.is_empty() {
        let (recs, _) = db.get_many_coalesced(&fetch_ids).map_err(|e| e.to_string())?;
        for r in recs {
            by_id.insert(r.node_id, r.payload);
        }
    }

    let mut matched_entries = Vec::new();
    for (ino, key_opt) in inspect_rows {
        let raw_bytes = by_id.remove(&ino.node_id).unwrap_or_default();
        let raw_text = String::from_utf8_lossy(&raw_bytes);
        let display_payload = if !show_secrets
            && (is_ciphertext_envelope(&raw_text)
                || raw_text.trim().starts_with(PORTABLE_SECRET_PREFIX))
        {
            "[REDACTED_SECRET (pass --show-secrets to reveal)]".to_owned()
        } else {
            let trimmed = raw_text.trim();
            if trimmed.len() > 280 {
                let mut end = 280;
                while end > 0 && !trimmed.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &trimmed[..end])
            } else {
                trimmed.to_owned()
            }
        };

        if let Some(q) = query_low {
            let key_hit = key_opt
                .as_deref()
                .is_some_and(|k| k.to_ascii_lowercase().contains(q));
            let val_hit = display_payload.to_ascii_lowercase().contains(q);
            let kind_hit = ino.kind.as_str().to_ascii_lowercase().contains(q);
            if !key_hit && !val_hit && !kind_hit {
                continue;
            }
        }
        if matched_entries.len() < 120 {
            matched_entries.push(ReadLdbEntry {
                kind: ino.kind.as_str().to_owned(),
                key: key_opt,
                importance: ino.importance,
                pinned: ino.flags.contains(NodeFlags::PINNED),
                token_count: ino.token_count,
                payload_preview: display_payload,
            });
        }
    }

    Ok(ReadLdbFileReport {
        path: ldb_path.display().to_string(),
        file_bytes,
        crc_integrity_ok,
        provenance_status,
        provenance_detail,
        backup_manifest,
        active_nodes,
        kind_counts,
        matched_entries,
    })
}

fn collect_ldb_files_in_dir(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 4 || out.len() >= 64 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                collect_ldb_files_in_dir(&p, out, depth + 1);
            } else if meta.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("ldb"))
            {
                out.push(p);
            }
        }
    }
}

pub fn execute_read_ldb_command(opts: &ReadLdbOptions) -> Result<ReadLdbReport, String> {
    let gdb_opt = crate::hooks::open_global_ldb_checked(opts.global_path.as_deref())
        .ok()
        .flatten();
    let q_low = opts
        .query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase);

    let mut backup_index: Option<BackupIndex> = None;
    let mut target_files = Vec::new();
    if opts.target.is_file() {
        target_files.push(opts.target.clone());
    } else if opts.target.is_dir() {
        let idx_file = opts.target.join("backup_index.json");
        if idx_file.is_file() {
            if let Ok(raw) = fs::read(&idx_file) {
                backup_index = serde_json::from_slice(&raw).ok();
            }
        }
        let ws_mem = opts.target.join(".agents").join("memory.ldb");
        if ws_mem.is_file() && !idx_file.is_file() {
            target_files.push(ws_mem);
        } else {
            collect_ldb_files_in_dir(&opts.target, &mut target_files, 0);
        }
    } else {
        return Err(format!(
            "Target path '{}' does not exist.",
            opts.target.display()
        ));
    }

    if target_files.is_empty() {
        return Err(format!(
            "No '.ldb' database files found under '{}'.",
            opts.target.display()
        ));
    }

    let mut files = Vec::with_capacity(target_files.len());
    for f in &target_files {
        files.push(inspect_single_ldb_read_only(
            f,
            gdb_opt.as_deref(),
            q_low.as_deref(),
            opts.show_secrets,
        )?);
    }

    Ok(ReadLdbReport {
        target: opts.target.display().to_string(),
        own_risk_warning: "[WARN: OWN-RISK READ-ONLY INSPECTION] Target databases were inspected strictly read-only without importing trust, executing hooks, or validating unsealed third-party payloads.".to_owned(),
        backup_index,
        files,
    })
}

pub(crate) fn format_read_ldb_report(rep: &ReadLdbReport) -> String {
    let mut out = String::new();
    out.push_str("=== LibreDB Own-Risk Read-Only Inspection ===\n");
    out.push_str(&format!("{}\n", rep.own_risk_warning));
    out.push_str(&format!("Target: {}\n", rep.target));
    if let Some(ref idx) = rep.backup_index {
        out.push_str(&format!(
            "Backup Index: format={} scope={} source_host={} projects={}\n",
            idx.format,
            idx.scope,
            idx.source_host,
            idx.projects.len()
        ));
    }
    for f in &rep.files {
        out.push_str(&format!(
            "\n--- {} ({} bytes, crc_ok={}) ---\n",
            f.path, f.file_bytes, f.crc_integrity_ok
        ));
        out.push_str(&format!(
            "Provenance: {} | {}\n",
            f.provenance_status, f.provenance_detail
        ));
        if !f.kind_counts.is_empty() {
            let counts_s: Vec<String> = f
                .kind_counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            out.push_str(&format!(
                "Active Nodes ({}): {}\n",
                f.active_nodes,
                counts_s.join(", ")
            ));
        }
        for e in &f.matched_entries {
            let key_lbl = e.key.as_deref().unwrap_or("<unkeyed>");
            out.push_str(&format!(
                "  [{}] {} (imp={}, tok={}): {}\n",
                e.kind, key_lbl, e.importance, e.token_count, e.payload_preview
            ));
        }
    }
    out
}

/// Checks if a database file at `ldb_path` has a corrupted, missing, or non-portable seal when
/// workspace trust failed, producing a clear user-facing diagnostic distinguishing raw copies
/// without `/libredb backup` from tampered/rolled-back seals.
pub fn diagnose_untrusted_workspace_db(global_db: Option<&LibreDb>, ws_root: &Path) -> String {
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    if !ldb_path.is_file() {
        return format!(
            "Workspace memory at '{}' is untrusted or missing (.agents/memory.ldb deleted after prior seal). Restore from backup or run 'libredb trust --reinit-lost \"{}\"' if intentionally re-initializing.",
            ldb_path.display(),
            ws_root.display()
        );
    }
    if is_git_index_tracking_agents_db(ws_root) {
        return format!(
            "Workspace memory at '{}' is tracked inside '.git/index' and quarantined against repository poisoning. Run 'libredb trust \"{}\"' only if you explicitly created and trust this database.",
            ldb_path.display(),
            ws_root.display()
        );
    }
    if has_internet_mark_of_the_web(&ldb_path) {
        return format!(
            "Workspace memory at '{}' carries a Windows Internet Mark-of-the-Web (Zone.Identifier ZoneId=3/4) and was quarantined instead of auto-adopted. Inspect read-only at your own risk via '/libredb read \"{}\"' or restore explicitly with '/libredb restore \"{}\" --project \"{}\"' if you downloaded and trust this archive.",
            ldb_path.display(),
            ldb_path.display(),
            ldb_path.display(),
            ws_root.display()
        );
    }
    if let Some(gdb) = global_db {
        if let Ok(Some((proj_rev, global_rev))) =
            super::seals::detect_workspace_seal_rollback(gdb, ws_root)
        {
            return format!(
                "Workspace memory at '{}' carries older seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (rollback detected). Use '/libredb restore' or run 'libredb trust --accept-rollback \"{}\"' if intentionally rolling back.",
                ldb_path.display(),
                ws_root.display()
            );
        }
    }
    match LibreDb::open(&ldb_path) {
        Err(e) => format!(
            "Workspace memory at '{}' cannot be opened or is corrupted ({e}). Inspect or restore a valid '/libredb backup'.",
            ldb_path.display()
        ),
        Ok(pdb) => match has_valid_portable_backup_manifest(&pdb, Some(BackupScope::Project)) {
            Err(manifest_err) => format!(
                "Workspace memory at '{}' failed portable backup manifest verification ({manifest_err}). Re-export cleanly with '/libredb backup' or inspect read-only at your own risk via '/libredb read \"{}\"'",
                ldb_path.display(),
                ldb_path.display()
            ),
            Ok(Some(_)) => format!(
                "Workspace memory at '{}' contains a portable '/libredb backup' archive but could not be auto-adopted (target workspace was previously sealed on this host or global customizations.ldb is absent). Use '/libredb restore \"{}\" --project \"{}\"' to adopt it safely.",
                ldb_path.display(),
                ldb_path.display(),
                ws_root.display()
            ),
            Ok(None) => format!(
                "Workspace memory at '{}' was not created via '/libredb backup' ('libredb backup'): foreign, missing, or modified host seal without a valid sys::backup_manifest. Export it cleanly via '/libredb backup' on the source machine, run 'libredb migrate --project \"{}\"' if this local folder was renamed on the same host, run 'libredb trust \"{}\"' if intentionally sealing locally, or inspect its contents read-only at your own risk via '/libredb read \"{}\"'",
                ldb_path.display(),
                ws_root.display(),
                ws_root.display(),
                ldb_path.display()
            ),
        },
    }
}
