//! Multi-threaded incremental workspace graph (`WorkspaceGraph`):
//! - Binary-safe directory scanner (skips NUL-byte binaries and build folders like `target/`),
//! - Parallel `FileSkeleton` extraction with 64-bit content-hash skip,
//! - Automatic `Calls` synapse wiring across workspace symbols,
//! - Automatic `Governs` / `CausedBy` causal wiring between `Decision`/`Task` nodes and `Symbol` nodes,
//! - `impact` blast-radius query and surgical `fim_slice` windowing.

use crate::skeleton::{FileSkeleton, SKELETON_HASH_SEED, SKELETON_KEY_PREFIX};
use libredb_core::crc::hash_key;
use libredb_core::{
    EdgeKind, LibreDb, LibreDbError, NodeKind, PreparedWrite, Result, Synapse, WriteRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Internal non-sealed cache key storing `(len, mtime_ns, content_hash)` per workspace file
/// plus governance fingerprint for `< 2 ms` `racy-git`-safe incremental skip.
pub const WORKSPACE_GRAPH_STATE_KEY: &str = "sys::workspace_graph_state";
/// Ephemeral `WorkingSet` key prefix staging `PreToolUse` edits until disk bytes match `expected_post_hash`.
pub const TENTATIVE_EDIT_PREFIX: &str = "tentative_edit::";
pub use crate::learning::{
    record_search_miss_cue, record_search_miss_cue_with_source, MissCueSource, PendingMissCue,
    SymbolCueBridgeBook, MAX_PENDING_MISS_CUES, MISS_CUE_TTL_NS, PENDING_MISS_CUES_KEY,
    SYMBOL_CUE_BRIDGES_KEY,
};
use crate::learning::{
    compose_tiers_with_bridges, diff_symbol_bodies, learn_from_verified_edit,
    note_bulk_scan_skipped, prune_deleted_file_symbols_from_bridges, prune_stale_error_pitfalls,
    BridgeScorer, EditEvidence, EditOrigin, MAX_INDEX_SCAN_LEARN_FILES,
};
/// Maximum number of source files allowed in a single Git commit for co-change coupling learning.
pub const MAX_COCHANGE_COMMIT_FILES: usize = 12;

/// Bumped to `5` in v1.4.0 so the first scan after upgrade re-extracts skeletons lacking body hashes.
const WORKSPACE_GRAPH_STATE_VERSION: u32 = 5;
const RACY_SUBSEC_WINDOW_NS: u128 = 50_000_000;
const RACY_COARSE_WINDOW_NS: u128 = 2_000_000_000;

/// Statistically verified Git co-change coupling partner for a source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoChangePartner {
    pub rel_path: String,
    pub shared_commits: u32,
    pub source_commits: u32,
    pub confidence_pct: u8,
    pub lift_x100: u32,
    pub newman_score_x100: u32,
}

/// Unverified `PreToolUse` edit staged in `NodeKind::WorkingSet` without mutating live `Symbol`
/// or `skeleton::*` contracts until disk bytes are verified against `expected_post_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TentativeFileEdit {
    pub rel_path: String,
    pub pre_edit_hash: Option<u64>,
    pub expected_post_hash: u64,
    pub raw_tokens: u64,
    pub created_ns: u128,
    pub post_skeleton: FileSkeleton,
    #[serde(default)]
    pub touched_symbol_keys: Vec<String>,
    #[serde(default)]
    pub added_body_tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedFileStat {
    len: u64,
    mtime_ns: u128,
    content_hash: u64,
    is_binary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkspaceGraphState {
    version: u32,
    skeleton_seed: u8,
    indexed_at_ns: u128,
    scan_root_key: String,
    exclusions_sorted: Vec<String>,
    gov_fingerprint: u64,
    #[serde(default)]
    git_head_oid: String,
    #[serde(default)]
    co_change_map: BTreeMap<String, Vec<CoChangePartner>>,
    files_scanned: usize,
    binary_files_skipped: usize,
    symbols_indexed: usize,
    call_synapses_wired: usize,
    governance_synapses_wired: usize,
    files: BTreeMap<String, CachedFileStat>,
}

/// Summary returned after indexing or refreshing a source workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceIndexReport {
    pub files_scanned: usize,
    pub files_unchanged_cached: usize,
    pub files_reindexed: usize,
    pub binary_files_skipped: usize,
    pub symbols_indexed: usize,
    pub call_synapses_wired: usize,
    pub governance_synapses_wired: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fast_path_hit: bool,
}

/// Ultra-compact 1-line symbol location match returned by `locate_symbols` (`< 0.5 ms`, zero edge walk).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolLocationMatch {
    pub query: String,
    pub node_id: u64,
    pub symbol_key: String,
    pub file_path: String,
    pub symbol_name: String,
    pub qualified_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub descriptor: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub signature: String,
    pub contract: String,
}

/// Specification for a single slice inside a batched `fim` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimSliceRequest {
    pub target: String,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default = "default_fim_pad")]
    pub pad: usize,
}

fn default_fim_pad() -> usize {
    12
}

/// Blast-radius impact and causal governance report for a located symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolImpactReport {
    pub node_id: u64,
    pub symbol_key: String,
    pub contract: String,
    /// Total incoming caller count before output bounding.
    #[serde(default)]
    pub total_callers: usize,
    /// Symbols in the workspace that call or reference this symbol (bounded for context hygiene).
    pub callers: Vec<String>,
    /// Concrete types or methods that implement, extend, or override this interface/trait/method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implementors: Vec<String>,
    /// Total outgoing callee/dependency count before output bounding.
    #[serde(default)]
    pub total_callees: usize,
    /// Symbols that this symbol calls or depends on (bounded for context hygiene).
    pub callees: Vec<String>,
    /// Architectural `Decision` or `Task` capsules governing why this symbol exists.
    pub governing_decisions: Vec<String>,
    /// Statistically verified Git co-change partner files (`Conf >= 55%`, `Lift >= 1.8`, top 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub co_changed_files: Vec<String>,
}

/// Surgical Fill-in-the-Middle (`FIM`) code slice enriched with blast-radius and causal context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimSliceBundle {
    pub file_label: String,
    pub target_symbol: Option<String>,
    pub window_start_line: usize,
    pub window_end_line: usize,
    pub total_file_lines: usize,
    pub slice_text: String,
    pub callers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implementors: Vec<String>,
    pub governing_decisions: Vec<String>,
}

impl FimSliceBundle {
    pub fn format_compact(&self) -> String {
        let sym_lbl = self.target_symbol.as_deref().unwrap_or("<line-window>");
        let mut out = format!(
            "=== FIM SLICE: {} :: {} [L{}-L{} of L{}] ===\n",
            self.file_label,
            sym_lbl,
            self.window_start_line,
            self.window_end_line,
            self.total_file_lines
        );
        if !self.governing_decisions.is_empty() {
            out.push_str("Governing Decisions:\n");
            for d in &self.governing_decisions {
                out.push_str(&format!("  * {d}\n"));
            }
        }
        if !self.implementors.is_empty() {
            out.push_str(&format!("Implementors ({}):\n", self.implementors.len()));
            for imp in self.implementors.iter().take(8) {
                out.push_str(&format!("  <= {imp}\n"));
            }
        }
        if !self.callers.is_empty() {
            out.push_str(&format!("Blast-Radius Callers ({}):\n", self.callers.len()));
            for c in self.callers.iter().take(10) {
                out.push_str(&format!("  <- {c}\n"));
            }
        }
        out.push_str("--- Code Window ---\n");
        out.push_str(&self.slice_text);
        if !self.slice_text.ends_with('\n') {
            out.push('\n');
        }
        out
    }
}

fn file_mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

pub(crate) fn current_unix_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

fn compute_governance_fingerprint(db: &LibreDb) -> u64 {
    let mut buf = Vec::new();
    for kind in [NodeKind::Decision, NodeKind::Task] {
        let mut inodes = db.list_inodes(Some(kind), false);
        inodes.sort_unstable_by_key(|(i, _, _)| i.node_id);
        for (ino, _, _) in inodes {
            buf.extend_from_slice(&ino.node_id.to_le_bytes());
            buf.extend_from_slice(&ino.updated_ns.to_le_bytes());
        }
    }
    hash_key(211, &buf)
}

fn is_safe_workspace_rel_key(rel_path: &str) -> bool {
    if rel_path.is_empty()
        || rel_path.contains(':')
        || rel_path.starts_with('/')
        || rel_path.starts_with('\\')
        || rel_path.contains('\\')
        || rel_path.bytes().any(|b| b < 0x20)
    {
        return false;
    }
    rel_path
        .split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn normalize_safe_workspace_rel_path(ws_root: &Path, target_file: &Path) -> Option<String> {
    let rel = target_file
        .strip_prefix(ws_root)
        .ok()
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .or_else(|| {
            let root_canon = std::fs::canonicalize(ws_root).ok()?;
            let parent_canon = std::fs::canonicalize(target_file.parent()?).ok()?;
            if let Ok(sym_meta) = std::fs::symlink_metadata(target_file) {
                if sym_meta.file_type().is_symlink() {
                    return None;
                }
            }
            let joined = parent_canon.join(target_file.file_name()?);
            joined
                .strip_prefix(&root_canon)
                .ok()
                .map(|r| r.to_string_lossy().replace('\\', "/"))
        })?;
    is_safe_workspace_rel_key(&rel).then_some(rel)
}

fn infer_agents_ws_root(db: &LibreDb) -> Option<PathBuf> {
    let db_path = db.path()?;
    let agents_dir = db_path.parent()?;
    if agents_dir.file_name().and_then(|n| n.to_str()) == Some(".agents") {
        agents_dir.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

pub(crate) fn strip_line_disambiguator(sym_key: &str) -> &str {
    if let Some((head, tail)) = sym_key.rsplit_once("@L") {
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return head;
        }
    }
    sym_key
}

fn apply_skeleton_symbols_atomic(
    db: &LibreDb,
    rel_path: &str,
    new_skel: &FileSkeleton,
    extra_deprecate_keys: &[(NodeKind, &str)],
) -> Result<usize> {
    let skel_key = format!("{SKELETON_KEY_PREFIX}{rel_path}");
    let file_prefix = format!("{rel_path}::");

    // Capture existing symbol IDs & outgoing synapses for `rel_path` (preserving signature keys
    // such as `@(I)Z` directly and line-disambiguated `@L...` keys by declaration ordinal).
    let mut old_by_ord: HashMap<(String, usize), Vec<Synapse>> = HashMap::new();
    let mut old_ord_counts: HashMap<String, usize> = HashMap::new();
    let mut existing_file_syms: Vec<(u64, String)> = Vec::new();
    for (ino, key_opt, syns) in db.list_inodes(Some(NodeKind::Symbol), false) {
        if let Some(full_k) = key_opt {
            if full_k.starts_with(&file_prefix) {
                let base_k = strip_line_disambiguator(&full_k).to_owned();
                let ord = *old_ord_counts
                    .entry(base_k.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(0);
                let kept_syns: Vec<Synapse> = syns
                    .into_iter()
                    .filter(|s| {
                        matches!(
                            s.kind,
                            EdgeKind::Calls | EdgeKind::DependsOn | EdgeKind::CausedBy
                        )
                    })
                    .collect();
                old_by_ord.insert((base_k, ord), kept_syns);
                existing_file_syms.push((ino.node_id, full_k));
            }
        }
    }

    let mut prepared: Vec<PreparedWrite> = Vec::with_capacity(1 + new_skel.symbols.len());
    let skel_bytes = serde_json::to_vec(new_skel)
        .map_err(|_| LibreDbError::CorruptFormat("skeleton serialize"))?;
    prepared.push(db.prepare(
        WriteRequest::new(NodeKind::WorkingSet, skel_bytes)
            .with_key(skel_key)
            .with_importance(190),
        0,
    )?);

    let sym_keys = compute_file_symbol_keys(rel_path, new_skel);
    let mut new_key_set: HashSet<String> = HashSet::with_capacity(sym_keys.len());
    let mut new_ord_counts: HashMap<String, usize> = HashMap::new();

    for (slot_i, (sym_idx, sym_key)) in sym_keys.into_iter().enumerate() {
        let sym = &new_skel.symbols[sym_idx];
        let qname = sym.qualified_name();
        let doc_part = if sym.doc_summary.is_empty() {
            String::new()
        } else {
            format!(" // {}", sym.doc_summary)
        };
        let body = format!(
            "{rel_path} :: {qname} [L{}-L{}] ({}) {}{doc_part}",
            sym.start_line, sym.end_line, sym.kind, sym.signature
        );
        let base_k = strip_line_disambiguator(&sym_key).to_owned();
        let ord = *new_ord_counts
            .entry(base_k.clone())
            .and_modify(|c| *c += 1)
            .or_insert(0);
        let prior_syns = old_by_ord.remove(&(base_k, ord)).unwrap_or_default();
        new_key_set.insert(sym_key.clone());
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Symbol, body.into_bytes())
                .with_key(sym_key)
                .with_importance(180)
                .with_synapses(prior_syns),
            slot_i + 1,
        )?);
    }

    let sym_count = new_key_set.len();
    let stale_ids: Vec<u64> = existing_file_syms
        .into_iter()
        .filter_map(|(nid, k)| (!new_key_set.contains(&k)).then_some(nid))
        .collect();

    let mut deprecate_keys: Vec<(NodeKind, &str)> =
        Vec::with_capacity(1 + extra_deprecate_keys.len());
    if let Ok(st_rec) = db.get_by_key(NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY) {
        if let Ok(mut st) = serde_json::from_slice::<WorkspaceGraphState>(&st_rec.payload) {
            st.version = 0;
            st.files.remove(rel_path);
            if let Ok(st_bytes) = serde_json::to_vec(&st) {
                let next_slot = prepared.len();
                prepared.push(db.prepare(
                    WriteRequest::new(NodeKind::Generic, st_bytes)
                        .with_key(WORKSPACE_GRAPH_STATE_KEY)
                        .with_importance(64),
                    next_slot,
                )?);
            } else {
                deprecate_keys.push((NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY));
            }
        } else {
            deprecate_keys.push((NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY));
        }
    }
    deprecate_keys.extend_from_slice(extra_deprecate_keys);

    let _ = db.commit_batch_with_tombstones(&prepared, &stale_ids, &deprecate_keys)?;
    if !stale_ids.is_empty() {
        let live_stripped: HashSet<String> = new_key_set
            .iter()
            .map(|k| strip_line_disambiguator(k).to_owned())
            .collect();
        prune_deleted_file_symbols_from_bridges(db, rel_path, &live_stripped);
    }
    let _ = db.maybe_auto_compact();
    Ok(sym_count)
}

/// Loads the last verified `skeleton::<rel_path>` snapshot (the pre-edit baseline for symbol diffs).
fn load_cached_skeleton(db: &LibreDb, rel_path: &str) -> Option<FileSkeleton> {
    let rec = db
        .get_by_key(NodeKind::WorkingSet, &format!("{SKELETON_KEY_PREFIX}{rel_path}"))
        .ok()?;
    serde_json::from_slice::<FileSkeleton>(&rec.payload).ok()
}

/// Stages a predicted `PreToolUse` edit under `tentative_edit::<rel_path>` (`NodeKind::WorkingSet`)
/// **without** mutating live `skeleton::<rel_path>` or `NodeKind::Symbol` nodes until disk bytes
/// are verified against `expected_post_hash`. Also reconciles any previously staged tentative edits
/// first, returning `(staged_now, prior_promoted_files, prior_avoided_tokens)`.
pub fn stage_tentative_file_edit(
    db: &LibreDb,
    ws_root: &Path,
    target_file: &Path,
    pre_edit_hash: Option<u64>,
    post_edit_bytes: &[u8],
    raw_tokens: u64,
) -> Result<(bool, usize, u64)> {
    let (promoted_prior, saved_prior) = reconcile_tentative_edits(db, ws_root)?;
    if post_edit_bytes.len() > crate::skeleton::MAX_SKELETON_FILE_BYTES as usize {
        return Ok((false, promoted_prior, saved_prior));
    }
    let probe_len = post_edit_bytes.len().min(2048);
    if post_edit_bytes[..probe_len].contains(&0u8) {
        return Ok((false, promoted_prior, saved_prior));
    }
    let Some(rel_path) = normalize_safe_workspace_rel_path(ws_root, target_file) else {
        return Ok((false, promoted_prior, saved_prior));
    };

    let expected_post_hash = hash_key(SKELETON_HASH_SEED, post_edit_bytes);
    if pre_edit_hash == Some(expected_post_hash) {
        return Ok((false, promoted_prior, saved_prior));
    }

    let old_disk_bytes = crate::skeleton::read_bounded_source_file(target_file).ok();
    let post_skeleton = FileSkeleton::extract_from_bytes(rel_path.clone(), post_edit_bytes);
    // Exact pre-edit baseline: the bytes currently on disk (`None` = file is being created).
    let old_skeleton = old_disk_bytes
        .as_deref()
        .map(|b| FileSkeleton::extract_from_bytes(rel_path.clone(), b));
    let touched_symbol_keys = diff_symbol_bodies(&rel_path, old_skeleton.as_ref(), &post_skeleton);
    let added_body_tokens = crate::skeleton::diff_symbol_body_tokens(
        &rel_path,
        old_disk_bytes.as_deref(),
        old_skeleton.as_ref(),
        post_edit_bytes,
        &post_skeleton,
        &touched_symbol_keys,
    );
    let tentative = TentativeFileEdit {
        rel_path: rel_path.clone(),
        pre_edit_hash,
        expected_post_hash,
        raw_tokens,
        created_ns: current_unix_ns(),
        post_skeleton,
        touched_symbol_keys,
        added_body_tokens,
    };
    let payload = serde_json::to_vec(&tentative)
        .map_err(|_| LibreDbError::CorruptFormat("tentative edit serialize"))?;
    db.put(
        WriteRequest::new(NodeKind::WorkingSet, payload)
            .with_key(format!("{TENTATIVE_EDIT_PREFIX}{rel_path}"))
            .with_importance(120),
    )?;
    Ok((true, promoted_prior, saved_prior))
}

/// Verifies any active `tentative_edit::<rel_path>` records against the actual file bytes on disk:
/// - If disk bytes match `expected_post_hash`, promotes `post_skeleton` + shifted `Symbol` contracts
///   in one single ACID `DeltaEnvelope` (`commit_batch_with_tombstones`).
/// - If disk bytes still match `pre_edit_hash` (failed/aborted IDE write) or the file does not exist,
///   discards `tentative_edit::<rel_path>` immediately while leaving live `Symbol` contracts untouched.
/// - If disk bytes changed to a different content hash, syncs live `Symbol` contracts from verified disk bytes.
pub fn reconcile_tentative_edits(db: &LibreDb, ws_root: &Path) -> Result<(usize, u64)> {
    let tentative_keys: Vec<(u64, String)> = db
        .list_inodes(Some(NodeKind::WorkingSet), false)
        .into_iter()
        .filter_map(|(ino, key_opt, _)| {
            let k = key_opt?;
            k.starts_with(TENTATIVE_EDIT_PREFIX).then_some((ino.node_id, k))
        })
        .collect();
    if tentative_keys.is_empty() {
        return Ok((0, 0));
    }

    let mut promoted_files = 0usize;
    let mut avoided_tokens = 0u64;

    for (nid, t_key) in tentative_keys {
        let Ok(rec) = db.get(nid) else {
            continue;
        };
        let Ok(tentative) = serde_json::from_slice::<TentativeFileEdit>(&rec.payload) else {
            let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
            continue;
        };
        if !is_safe_workspace_rel_key(&tentative.rel_path) {
            let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
            continue;
        };
        let candidate_path = ws_root.join(&tentative.rel_path);
        let confirmed_rel = normalize_safe_workspace_rel_path(ws_root, &candidate_path);
        if confirmed_rel.as_deref() != Some(tentative.rel_path.as_str()) {
            let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
            continue;
        }

        match crate::skeleton::read_bounded_source_file(&candidate_path) {
            Ok(disk_bytes) => {
                let disk_hash = hash_key(SKELETON_HASH_SEED, &disk_bytes);
                if disk_hash == tentative.expected_post_hash {
                    // `touched_symbol_keys` was computed at staging time against the exact pre-edit
                    // disk bytes; staging time (`created_ns`) is the causal edit timestamp.
                    let touched = tentative.touched_symbol_keys.clone();
                    let added_body_tokens = tentative.added_body_tokens.clone();
                    apply_skeleton_symbols_atomic(
                        db,
                        &tentative.rel_path,
                        &tentative.post_skeleton,
                        &[(NodeKind::WorkingSet, t_key.as_str())],
                    )?;
                    let _ = learn_from_verified_edit(
                        db,
                        &EditEvidence {
                            rel_path: tentative.rel_path.clone(),
                            edit_ns: tentative.created_ns,
                            touched,
                            added_body_tokens,
                            origin: EditOrigin::Hook,
                        },
                    );
                    promoted_files += 1;
                    avoided_tokens = avoided_tokens.saturating_add(tentative.raw_tokens);
                } else if Some(disk_hash) == tentative.pre_edit_hash {
                    // Tool write failed or was aborted: discard tentative edit, keep live symbols intact.
                    let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
                } else {
                    // External modification occurred: sync from actual verified disk bytes & clear tentative record.
                    let probe_len = disk_bytes.len().min(2048);
                    if !disk_bytes[..probe_len].contains(&0u8) {
                        let actual_skel =
                            FileSkeleton::extract_from_bytes(tentative.rel_path.clone(), &disk_bytes);
                        let baseline = load_cached_skeleton(db, &tentative.rel_path);
                        let touched = baseline
                            .as_ref()
                            .map(|old| diff_symbol_bodies(&tentative.rel_path, Some(old), &actual_skel))
                            .unwrap_or_default();
                        let added_body_tokens = crate::skeleton::diff_symbol_body_tokens(
                            &tentative.rel_path,
                            None,
                            baseline.as_ref(),
                            &disk_bytes,
                            &actual_skel,
                            &touched,
                        );
                        let edit_ns = std::fs::symlink_metadata(&candidate_path)
                            .map(|m| file_mtime_ns(&m))
                            .unwrap_or_else(|_| current_unix_ns());
                        apply_skeleton_symbols_atomic(
                            db,
                            &tentative.rel_path,
                            &actual_skel,
                            &[(NodeKind::WorkingSet, t_key.as_str())],
                        )?;
                        let _ = learn_from_verified_edit(
                            db,
                            &EditEvidence {
                                rel_path: tentative.rel_path.clone(),
                                edit_ns,
                                touched,
                                added_body_tokens,
                                origin: EditOrigin::DiskSync,
                            },
                        );
                    } else {
                        let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
                    }
                }
            }
            Err(_) => {
                // Target file absent (e.g. aborted file creation) or unreadable: discard tentative edit.
                let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
            }
        }
    }

    let _ = db.maybe_auto_compact();
    Ok((promoted_files, avoided_tokens))
}

/// Updates `skeleton::<rel_path>` (`NodeKind::WorkingSet`) and all `NodeKind::Symbol` `[Lstart-Lend]`
/// contracts for a single verified source file in **one single ACID `DeltaEnvelope`**
/// (`commit_batch_with_tombstones` + inline/overflow `WriteRequest::with_synapses`, `0` partial state).
pub fn sync_single_file_symbols(
    db: &LibreDb,
    ws_root: &Path,
    target_file: &Path,
    post_edit_bytes: &[u8],
) -> Result<usize> {
    if post_edit_bytes.len() > crate::skeleton::MAX_SKELETON_FILE_BYTES as usize {
        return Ok(0);
    }
    let probe_len = post_edit_bytes.len().min(2048);
    if post_edit_bytes[..probe_len].contains(&0u8) {
        return Ok(0);
    }

    let Some(rel_path) = normalize_safe_workspace_rel_path(ws_root, target_file) else {
        return Ok(0);
    };

    let skel_key = format!("{SKELETON_KEY_PREFIX}{rel_path}");
    let t_key = format!("{TENTATIVE_EDIT_PREFIX}{rel_path}");
    let new_hash = hash_key(SKELETON_HASH_SEED, post_edit_bytes);
    let mut baseline: Option<FileSkeleton> = None;
    if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &skel_key) {
        if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
            if cached.content_hash == new_hash {
                let _ = db.deprecate_key(NodeKind::WorkingSet, &t_key);
                return Ok(0);
            }
            baseline = Some(cached);
        }
    }

    let new_skel = FileSkeleton::extract_from_bytes(rel_path.clone(), post_edit_bytes);
    let touched = baseline
        .as_ref()
        .map(|old| diff_symbol_bodies(&rel_path, Some(old), &new_skel))
        .unwrap_or_default();
    let added_body_tokens = crate::skeleton::diff_symbol_body_tokens(
        &rel_path,
        None,
        baseline.as_ref(),
        post_edit_bytes,
        &new_skel,
        &touched,
    );
    let count = apply_skeleton_symbols_atomic(
        db,
        &rel_path,
        &new_skel,
        &[(NodeKind::WorkingSet, t_key.as_str())],
    )?;
    let _ = learn_from_verified_edit(
        db,
        &EditEvidence {
            rel_path,
            edit_ns: current_unix_ns(),
            touched,
            added_body_tokens,
            origin: EditOrigin::DiskSync,
        },
    );
    Ok(count)
}

/// Incrementally indexes all non-binary source files under `root` into `db`, wiring both
/// code call-graph synapses (`Calls`) and causal architecture synapses (`Decision <-> Symbol`).
pub fn index_workspace(db: &LibreDb, root: &Path, force: bool) -> Result<WorkspaceIndexReport> {
    index_workspace_with_exclusions(db, root, force, &[])
}

/// Incrementally indexes all non-binary source files under `root` into `db`, skipping nested
/// child cognitive workspaces (any subdirectory strictly below `root` that contains its own
/// `.agents` directory or matches one of `excluded_subroots`).
pub fn index_workspace_with_exclusions(
    db: &LibreDb,
    root: &Path,
    force: bool,
    excluded_subroots: &[PathBuf],
) -> Result<WorkspaceIndexReport> {
    let _ = reconcile_tentative_edits(db, root);
    let scan_cfg = WorkspaceScanConfig::from_db_and_root(db, root, excluded_subroots);
    let mut source_files = Vec::new();
    let mut walk_binary_skipped = 0usize;
    collect_source_files(root, root, &scan_cfg, &mut source_files, &mut walk_binary_skipped)?;

    let scan_root_key = normalize_scan_boundary_key(root);
    let mut exclusions_sorted: Vec<String> = scan_cfg.excluded_subroots.iter().cloned().collect();
    exclusions_sorted.sort();
    let gov_fp = compute_governance_fingerprint(db);
    let current_git_head = resolve_git_head_oid_fast(root);
    let scan_started_ns = current_unix_ns();
    let prev_state_opt: Option<WorkspaceGraphState> = db
        .get_by_key(NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<WorkspaceGraphState>(&rec.payload).ok());

    // `racy-git`-safe fast-path (Git `is_racy_timestamp` clean/smudge design):
    // Verify `symlink_metadata` `(len, mtime_ns)` on every candidate file. Any file whose `mtime_ns`
    // fell inside the OS clock granularity window (`50 ms` on sub-second NTFS/ext4/APFS, `2 s` on
    // coarse integer-second filesystems) relative to `state.indexed_at_ns` is re-hashed via `FNV-1a`
    // to catch sub-millisecond same-size edits; once `scan_started_ns` has safely advanced past all
    // smudged `mtime_ns` values, `state.indexed_at_ns` is un-smudged once so all subsequent warm
    // `index` / `impact` / `fim` calls complete in `< 2 ms` with `0` file opens and `0` DB writes!
    if !force {
        if let Some(ref prev_state) = prev_state_opt {
            let mut state = prev_state.clone();
            if state.version == WORKSPACE_GRAPH_STATE_VERSION
                && state.skeleton_seed == SKELETON_HASH_SEED
                && state.scan_root_key == scan_root_key
                && state.exclusions_sorted == exclusions_sorted
                && state.gov_fingerprint == gov_fp
                && state.git_head_oid == current_git_head
            {
                let mut all_clean = true;
                let mut verified_count = 0usize;
                let mut any_smudged_checked = false;
                let mut can_unsmudge_all = true;

                for (abs_path, rel_path) in &source_files {
                    let Ok(sym_meta) = std::fs::symlink_metadata(abs_path) else {
                        all_clean = false;
                        break;
                    };
                    if sym_meta.file_type().is_symlink()
                        || !sym_meta.is_file()
                        || sym_meta.len() > scan_cfg.max_file_bytes as u64
                    {
                        continue;
                    }
                    let Some(cached_stat) = state.files.get(rel_path) else {
                        all_clean = false;
                        break;
                    };
                    let mtime_ns = file_mtime_ns(&sym_meta);
                    if cached_stat.len != sym_meta.len() || cached_stat.mtime_ns != mtime_ns {
                        all_clean = false;
                        break;
                    };
                    let racy_win = if mtime_ns == 0 || mtime_ns % 1_000_000_000 == 0 {
                        RACY_COARSE_WINDOW_NS
                    } else {
                        RACY_SUBSEC_WINDOW_NS
                    };
                    let smudged = mtime_ns == 0
                        || state.indexed_at_ns.saturating_sub(mtime_ns) <= racy_win;
                    if smudged {
                        any_smudged_checked = true;
                        let Ok(raw_bytes) = std::fs::read(abs_path) else {
                            all_clean = false;
                            break;
                        };
                        if hash_key(SKELETON_HASH_SEED, &raw_bytes) != cached_stat.content_hash {
                            all_clean = false;
                            break;
                        }
                        if mtime_ns == 0
                            || scan_started_ns.saturating_sub(mtime_ns) <= racy_win
                        {
                            can_unsmudge_all = false;
                        }
                    }
                    verified_count += 1;
                }
                if all_clean && verified_count == state.files.len() {
                    if any_smudged_checked && can_unsmudge_all {
                        state.indexed_at_ns = scan_started_ns;
                        if let Ok(state_bytes) = serde_json::to_vec(&state) {
                            let _ = db.put(
                                WriteRequest::new(NodeKind::Generic, state_bytes)
                                    .with_key(WORKSPACE_GRAPH_STATE_KEY)
                                    .with_importance(64),
                            );
                        }
                    }
                    return Ok(WorkspaceIndexReport {
                        files_scanned: state.files_scanned,
                        files_unchanged_cached: state.files_scanned,
                        files_reindexed: 0,
                        binary_files_skipped: walk_binary_skipped + state.binary_files_skipped,
                        symbols_indexed: state.symbols_indexed,
                        call_synapses_wired: state.call_synapses_wired,
                        governance_synapses_wired: state.governance_synapses_wired,
                        fast_path_hit: true,
                    });
                }
            }
        }
    }

    let mut binary_probe_skipped = 0usize;
    let mut unchanged = 0usize;
    let mut reindexed = 0usize;
    let mut next_file_stats: BTreeMap<String, CachedFileStat> = BTreeMap::new();

    struct ParsedFile {
        rel_path: String,
        skeleton: FileSkeleton,
    }

    let mut changed_files: Vec<ParsedFile> = Vec::new();
    let mut all_skeletons: Vec<(String, FileSkeleton, Option<String>)> = Vec::new();
    // `(rel_path, last verified skeleton, file mtime_ns)` for files whose content changed on disk
    // outside the `PreToolUse` hook (terminal tools, scripts, editors without hooks).
    let mut learn_candidates: Vec<(String, FileSkeleton, u128)> = Vec::new();

    for (abs_path, rel_path) in source_files {
        let Ok(sym_meta) = std::fs::symlink_metadata(&abs_path) else {
            continue;
        };
        if sym_meta.file_type().is_symlink()
            || !sym_meta.is_file()
            || sym_meta.len() > scan_cfg.max_file_bytes as u64
        {
            continue;
        }
        let mtime_ns = file_mtime_ns(&sym_meta);
        let raw_bytes = match std::fs::read(&abs_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if raw_bytes.len() > scan_cfg.max_file_bytes {
            continue;
        }
        let current_hash = hash_key(SKELETON_HASH_SEED, &raw_bytes);
        // Universal binary file guard: any file containing a NUL byte in its first 2 KB is binary!
        let probe_len = raw_bytes.len().min(2048);
        if raw_bytes[..probe_len].contains(&0u8) {
            binary_probe_skipped += 1;
            next_file_stats.insert(
                rel_path,
                CachedFileStat {
                    len: raw_bytes.len() as u64,
                    mtime_ns,
                    content_hash: current_hash,
                    is_binary: true,
                },
            );
            continue;
        }

        next_file_stats.insert(
            rel_path.clone(),
            CachedFileStat {
                len: raw_bytes.len() as u64,
                mtime_ns,
                content_hash: current_hash,
                is_binary: false,
            },
        );
        let skel_key = format!("{SKELETON_KEY_PREFIX}{rel_path}");
        let mut prior_skel: Option<FileSkeleton> = None;

        if !force {
            if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &skel_key) {
                if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                    // Skeletons persisted before v1.4.0 lack per-symbol body hashes: re-extract them
                    // once (no learning event, because the file content itself is unchanged).
                    let has_body_hashes = cached.symbols.iter().all(|s| s.body_hash != 0);
                    if cached.content_hash == current_hash && has_body_hashes {
                        unchanged += 1;
                        let text = String::from_utf8_lossy(&raw_bytes).into_owned();
                        all_skeletons.push((rel_path, cached, Some(text)));
                        continue;
                    }
                    if cached.content_hash != current_hash {
                        prior_skel = Some(cached);
                    }
                }
            }
        }

        let raw_text = String::from_utf8_lossy(&raw_bytes).into_owned();
        let skel = FileSkeleton::extract_from_bytes(rel_path.clone(), &raw_bytes);
        reindexed += 1;
        if let Some(old_skel) = prior_skel {
            learn_candidates.push((rel_path.clone(), old_skel, mtime_ns));
        }
        all_skeletons.push((rel_path.clone(), skel.clone(), Some(raw_text)));
        changed_files.push(ParsedFile {
            rel_path,
            skeleton: skel,
        });
    }

    let binary_skipped = walk_binary_skipped + binary_probe_skipped;

    let files_scanned = unchanged + reindexed;

    let live_rel_paths: HashSet<&str> = all_skeletons
        .iter()
        .map(|(rel, _, _)| rel.as_str())
        .collect();
    let changed_rel_paths: HashSet<&str> = changed_files
        .iter()
        .map(|pf| pf.rel_path.as_str())
        .collect();

    // Prepare batched writes for all modified skeletons and their qualified symbol contracts.
    let mut prepared: Vec<PreparedWrite> = Vec::new();
    let mut new_sym_keys_for_changed: HashSet<String> = HashSet::new();

    for (idx, pf) in changed_files.iter().enumerate() {
        let skel_bytes = serde_json::to_vec(&pf.skeleton)
            .map_err(|_| LibreDbError::CorruptFormat("skeleton serialize"))?;
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::WorkingSet, skel_bytes)
                .with_key(format!("{SKELETON_KEY_PREFIX}{}", pf.rel_path))
                .with_importance(190),
            idx,
        )?);

        for (sym_idx, sym_key) in compute_file_symbol_keys(&pf.rel_path, &pf.skeleton) {
            let sym = &pf.skeleton.symbols[sym_idx];
            let qname = sym.qualified_name();
            let doc_part = if sym.doc_summary.is_empty() {
                String::new()
            } else {
                format!(" // {}", sym.doc_summary)
            };
            let body = format!(
                "{} :: {} [L{}-L{}] ({}) {}{}",
                pf.rel_path, qname, sym.start_line, sym.end_line, sym.kind, sym.signature, doc_part
            );
            new_sym_keys_for_changed.insert(sym_key.clone());
            prepared.push(db.prepare(
                WriteRequest::new(NodeKind::Symbol, body.into_bytes())
                    .with_key(sym_key)
                    .with_importance(180),
                idx,
            )?);
        }
    }

    // Tombstone stale `Symbol` and `skeleton::*` Inodes from deleted files or renamed/deleted symbols
    // inside reindexed files so orphan symbols never linger in `list_inodes` or `impact` queries.
    let mut stale_ids: Vec<u64> = Vec::new();
    for (ino, key_opt, _) in db.list_inodes(Some(NodeKind::Symbol), false) {
        if let Some(ref full_k) = key_opt {
            if let Some((file_part, _)) = full_k.split_once("::") {
                if !live_rel_paths.contains(file_part)
                    || (changed_rel_paths.contains(file_part)
                        && !new_sym_keys_for_changed.contains(full_k))
                {
                    stale_ids.push(ino.node_id);
                }
            }
        }
    }
    for (ino, key_opt, _) in db.list_inodes(Some(NodeKind::WorkingSet), false) {
        if let Some(ref k) = key_opt {
            if let Some(rel) = k.strip_prefix(SKELETON_KEY_PREFIX) {
                if !live_rel_paths.contains(rel) {
                    stale_ids.push(ino.node_id);
                }
            }
        }
    }
    let had_stale_tombstones = !stale_ids.is_empty();
    if had_stale_tombstones {
        db.deprecate_nodes(&stale_ids)?;
    }

    if !prepared.is_empty() {
        db.commit_batch(&prepared)?;
    }

    // Learn from targeted external edits only: never on the first index of a workspace and never
    // when a scan sees a bulk change (checkout, pull, formatter run across many files).
    if prev_state_opt.is_some() && !learn_candidates.is_empty() {
        if learn_candidates.len() <= MAX_INDEX_SCAN_LEARN_FILES {
            for (rel, old_skel, mtime) in &learn_candidates {
                if let Some(pf) = changed_files.iter().find(|pf| &pf.rel_path == rel) {
                    let touched = diff_symbol_bodies(rel, Some(old_skel), &pf.skeleton);
                    let new_text_bytes = all_skeletons
                        .iter()
                        .find(|(r, _, _)| r == rel)
                        .and_then(|(_, _, t)| t.as_deref())
                        .map(str::as_bytes)
                        .unwrap_or(&[]);
                    let added_body_tokens = crate::skeleton::diff_symbol_body_tokens(
                        rel,
                        None,
                        Some(old_skel),
                        new_text_bytes,
                        &pf.skeleton,
                        &touched,
                    );
                    let _ = learn_from_verified_edit(
                        db,
                        &EditEvidence {
                            rel_path: rel.clone(),
                            edit_ns: *mtime,
                            touched,
                            added_body_tokens,
                            origin: EditOrigin::IndexScan,
                        },
                    );
                }
            }
        } else {
            note_bulk_scan_skipped(db);
        }
    }

    // Build structural lookup tables of all active `NodeKind::Symbol` nodes (zero hardcoded stopwords):
    // - `by_qualified_name`: `Type::method -> Vec<(node_id, full_key)>` (exact container-qualified match)
    // - `by_method_name`: `method -> Vec<(node_id, full_key)>` (container member methods only)
    // - `by_free_name`: `name -> Vec<(node_id, full_key)>` (top-level free functions, types, tables)
    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
    let symbols_indexed = sym_inodes.len();
    let mut by_qualified_name: HashMap<String, Vec<(u64, String)>> = HashMap::new();
    let mut by_method_name: HashMap<String, Vec<(u64, String)>> = HashMap::new();
    let mut by_free_name: HashMap<String, Vec<(u64, String)>> = HashMap::new();
    let mut by_full_key: HashMap<String, u64> = HashMap::new();
    let mut active_sym_ids: Vec<u64> = Vec::with_capacity(sym_inodes.len());

    for (ino, key_opt, _) in &sym_inodes {
        active_sym_ids.push(ino.node_id);
        if let Some(ref full_k) = key_opt {
            by_full_key.insert(full_k.clone(), ino.node_id);
            if let Some((_, sym_part)) = full_k.split_once("::") {
                let clean_sym = sym_part.split('@').next().unwrap_or(sym_part);
                if let Some((_, method_short)) = clean_sym.rsplit_once("::") {
                    by_qualified_name
                        .entry(clean_sym.to_owned())
                        .or_default()
                        .push((ino.node_id, full_k.clone()));
                    if method_short.len() >= 3 {
                        by_method_name
                            .entry(method_short.to_owned())
                            .or_default()
                            .push((ino.node_id, full_k.clone()));
                    }
                } else if clean_sym.len() >= 3 {
                    by_free_name
                        .entry(clean_sym.to_owned())
                        .or_default()
                        .push((ino.node_id, full_k.clone()));
                }
            }
        }
    }

    let mut by_dalvik_descriptor: HashMap<String, Vec<u64>> = HashMap::new();
    for (rel_path, skel, _) in &all_skeletons {
        for (sym_idx, full_k) in compute_file_symbol_keys(rel_path, skel) {
            if let Some(&nid) = by_full_key.get(&full_k) {
                if let Some(ref desc) = skel.symbols[sym_idx].descriptor {
                    by_dalvik_descriptor.entry(desc.clone()).or_default().push(nid);
                }
            }
        }
    }

    // Compute unsupervised corpus Document Frequency (`DF`) across workspace files so ubiquitous
    // stdlib/utility identifiers in ANY programming or human language attenuate automatically
    // without a single hardcoded stopword!
    let mut receiver_call_df: HashMap<String, usize> = HashMap::new();
    let mut bare_call_df: HashMap<String, usize> = HashMap::new();
    let mut prose_token_df: HashMap<String, usize> = HashMap::new();
    let mut type_supertypes: HashMap<String, Vec<String>> = HashMap::new();
    for (_, skel, text_opt) in &all_skeletons {
        for sym in &skel.symbols {
            if !sym.supertypes.is_empty() {
                let owner_type = if sym.kind == "impl" {
                    sym.name
                        .rsplit_once(" for ")
                        .map(|(_, t)| t.trim().to_owned())
                        .unwrap_or_else(|| sym.name.clone())
                } else {
                    sym.name.clone()
                };
                let entry = type_supertypes.entry(owner_type).or_default();
                for sup in &sym.supertypes {
                    if !entry.iter().any(|x| x == sup) {
                        entry.push(sup.clone());
                    }
                }
            }
        }
        let Some(ref text) = text_opt else { continue };
        let file_sites = extract_call_sites(text, None);
        for m in file_sites.receiver_methods {
            *receiver_call_df.entry(m).or_insert(0) += 1;
        }
        for b in file_sites.bare_calls_and_types {
            *bare_call_df.entry(b).or_insert(0) += 1;
        }
        for tok in extract_code_identifiers(text) {
            *prose_token_df.entry(tok).or_insert(0) += 1;
        }
    }

    let mut edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    let existing_call_edges: usize = sym_inodes
        .iter()
        .map(|(_, _, syns)| {
            syns.iter()
                .filter(|s| matches!(s.kind, EdgeKind::Calls | EdgeKind::DependsOn))
                .count()
        })
        .sum();
    let need_call_pass =
        force || !changed_files.is_empty() || had_stale_tombstones || existing_call_edges == 0;
    let mut call_edges = 0usize;

    // 1. Wire `CallerSymbol --[Calls]--> CalleeSymbol` and DI/Inheritance `Impl --[DependsOn]--> Interface`!
    if need_call_pass {
        for (rel_path, skel, text_opt) in &all_skeletons {
            let Some(ref text) = text_opt else { continue };
            let file_idents = extract_code_identifiers(text);
            let lines: Vec<&str> = text.lines().collect();
            for (sym_idx, src_key) in compute_file_symbol_keys(rel_path, skel) {
                let sym = &skel.symbols[sym_idx];
                let Some(&src_id) = by_full_key.get(&src_key) else {
                    continue;
                };
                let mut seen_dep_targets: HashSet<u64> = HashSet::new();

                // 1a. Type-level supertypes / implemented interfaces / traits (`DependsOn`)
                let empty_sups: Vec<String> = Vec::new();
                let all_sups = if matches!(
                    sym.kind.as_str(),
                    "class" | "struct" | "enum" | "trait" | "interface" | "record" | "protocol" | "object"
                ) {
                    type_supertypes.get(&sym.name).unwrap_or(&sym.supertypes)
                } else {
                    &empty_sups
                };
                for sup in all_sups {
                    let dalvik_sup_key = format!("L{sup};");
                    if let Some(sup_ids) = by_dalvik_descriptor.get(&dalvik_sup_key) {
                        for &sup_id in sup_ids {
                            if sup_id != src_id && seen_dep_targets.insert(sup_id) {
                                edges.push((src_id, EdgeKind::DependsOn, sup_id, 230));
                                call_edges += 1;
                            }
                        }
                    } else if let Some(sup_targets) =
                        by_free_name.get(sup).or_else(|| by_qualified_name.get(sup))
                    {
                        for &(sup_id, _) in sup_targets {
                            if sup_id != src_id && seen_dep_targets.insert(sup_id) {
                                edges.push((src_id, EdgeKind::DependsOn, sup_id, 230));
                                call_edges += 1;
                            }
                        }
                    }
                }

                // 1b. Method-level DI / virtual override link (`ImplType::m --[DependsOn]--> Interface::m`)
                if matches!(
                    sym.kind.as_str(),
                    "fn" | "fun" | "func" | "function" | "method" | "def" | "async def"
                ) {
                    if let Some(ref cont) = sym.container {
                        if let Some(member_sig) = sym
                            .descriptor
                            .as_deref()
                            .and_then(|d| d.split_once(";->").map(|(_, ms)| ms))
                        {
                            for sup in collect_supertype_chain(cont, &type_supertypes, 3) {
                                let sup_desc = format!("L{sup};->{member_sig}");
                                if let Some(sup_mids) = by_dalvik_descriptor.get(&sup_desc) {
                                    for &sup_mid in sup_mids {
                                        if sup_mid != src_id && seen_dep_targets.insert(sup_mid) {
                                            edges.push((src_id, EdgeKind::DependsOn, sup_mid, 228));
                                            call_edges += 1;
                                        }
                                    }
                                }
                            }
                        } else if let Some(sups) = type_supertypes.get(cont) {
                            for sup in sups {
                                let sup_method_q = format!("{sup}::{}", sym.name);
                                if let Some(sup_mtargets) = by_qualified_name.get(&sup_method_q) {
                                    for &(sup_mid, _) in sup_mtargets {
                                        if sup_mid != src_id && seen_dep_targets.insert(sup_mid) {
                                            edges.push((src_id, EdgeKind::DependsOn, sup_mid, 228));
                                            call_edges += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let start_i = sym.start_line.saturating_sub(1);
                let end_i = sym.end_line.min(lines.len());
                if start_i >= end_i {
                    continue;
                }
                // Exclude lines owned by nested child symbols (e.g. methods inside a `class` or `trait`)
                // so enclosing containers never duplicate the outgoing calls of their member methods.
                let body_slice: String = lines[start_i..end_i]
                    .iter()
                    .enumerate()
                    .filter_map(|(offset, &ln)| {
                        let line_no = start_i + offset + 1;
                        let in_child = skel.symbols.iter().any(|other| {
                            other.kind != "impl"
                                && other.start_line > sym.start_line
                                && other.end_line <= sym.end_line
                                && line_no >= other.start_line
                                && line_no <= other.end_line
                        });
                        if in_child {
                            None
                        } else {
                            Some(ln)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let mut seen_targets: HashSet<u64> = HashSet::new();
                let own_qname = sym.qualified_name();
                let sites = extract_call_sites(&body_slice, sym.container.as_deref());

                // Stage A0: Exact Dalvik / Smali member & type descriptors (`L<pkg/Cls>;-><member><sig>`, `L<pkg/Cls>;`)
                // with 3-hop `type_supertypes` virtual/interface inheritance and zero cross-package or overload mixing!
                for dcall in sites.dalvik_exact_calls {
                    if sym.descriptor.as_deref() == Some(dcall.as_str()) {
                        continue;
                    }
                    let mut resolved = false;
                    if let Some(targets) = by_dalvik_descriptor.get(&dcall) {
                        resolved = true;
                        for &dst_id in targets {
                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 224));
                                call_edges += 1;
                            }
                        }
                    }
                    if !resolved {
                        if let Some((lhs_cls, member_sig)) = dcall.split_once(";->") {
                            let recv_cls = lhs_cls.trim_start_matches('L');
                            for sup in collect_supertype_chain(recv_cls, &type_supertypes, 3) {
                                let sup_desc = format!("L{sup};->{member_sig}");
                                if let Some(targets) = by_dalvik_descriptor.get(&sup_desc) {
                                    for &dst_id in targets {
                                        if dst_id != src_id && seen_targets.insert(dst_id) {
                                            edges.push((src_id, EdgeKind::Calls, dst_id, 218));
                                            call_edges += 1;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                for dtref in sites.dalvik_type_refs {
                    if sym.descriptor.as_deref() == Some(dtref.as_str()) {
                        continue;
                    }
                    if let Some(targets) = by_dalvik_descriptor.get(&dtref) {
                        for &dst_id in targets {
                            if dst_id != src_id
                                && !seen_dep_targets.contains(&dst_id)
                                && seen_targets.insert(dst_id)
                            {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 202));
                                call_edges += 1;
                            }
                        }
                    }
                }

                // Stage A: Exact qualified calls (`Type::method`, `Type.method`, `Self::method`)
                // plus 2-hop supertype/interface method resolution when Dalvik/OO bytecode invokes an inherited method
                // via the subclass static descriptor (`Lci/Sub;->m(` where `m` is declared on `Base`).
                for qcall in sites.qualified_calls {
                    if qcall == own_qname {
                        continue;
                    }
                    let mut resolved = false;
                    if let Some(targets) = by_qualified_name.get(&qcall) {
                        resolved = true;
                        for &(dst_id, _) in targets {
                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 220));
                                call_edges += 1;
                            }
                        }
                    }
                    if !resolved {
                        if let Some((recv_cls, m_name)) = qcall.rsplit_once("::") {
                            if let Some(sups_1) = type_supertypes.get(recv_cls) {
                                for sup1 in sups_1 {
                                    let sup1_q = format!("{sup1}::{m_name}");
                                    if let Some(targets) = by_qualified_name.get(&sup1_q) {
                                        for &(dst_id, _) in targets {
                                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                                edges.push((src_id, EdgeKind::Calls, dst_id, 215));
                                                call_edges += 1;
                                            }
                                        }
                                    } else if let Some(sups_2) = type_supertypes.get(sup1) {
                                        for sup2 in sups_2 {
                                            let sup2_q = format!("{sup2}::{m_name}");
                                            if let Some(targets) = by_qualified_name.get(&sup2_q) {
                                                for &(dst_id, _) in targets {
                                                    if dst_id != src_id && seen_targets.insert(dst_id) {
                                                        edges.push((src_id, EdgeKind::Calls, dst_id, 212));
                                                        call_edges += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Stage B1: Dynamic receiver method calls (`expr.method(`) - resolved when unambiguous in the
                // workspace (`targets.len() == 1`) OR disambiguated by an injected/imported interface/type name
                // present in `file_idents` (`@Inject OrderApprovalPort`, `private gateway: PaymentGateway`, etc.).
                for mcall in sites.receiver_methods {
                    if mcall == sym.name && sym.container.is_none() {
                        continue;
                    }
                    if let Some(targets) = by_method_name.get(&mcall) {
                        let df = receiver_call_df.get(&mcall).copied().unwrap_or(0);
                        let is_salient = files_scanned < 6 || df.saturating_mul(4) <= files_scanned;
                        if targets.len() == 1 && is_salient {
                            let (dst_id, _) = targets[0];
                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 205));
                                call_edges += 1;
                            }
                        } else if targets.len() > 1 && targets.len() <= 6 && is_salient {
                            let di_matched: Vec<u64> = targets
                                .iter()
                                .filter_map(|&(dst_id, ref fk)| {
                                    let (_, sym_part) = fk.split_once("::")?;
                                    let clean = sym_part.split('@').next().unwrap_or(sym_part);
                                    let (cont_type, _) = clean.rsplit_once("::")?;
                                    if sym.container.as_deref() != Some(cont_type)
                                        && file_idents.contains(cont_type)
                                    {
                                        Some(dst_id)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            if !di_matched.is_empty() && di_matched.len() <= 2 {
                                for dst_id in di_matched {
                                    if dst_id != src_id && seen_targets.insert(dst_id) {
                                        edges.push((src_id, EdgeKind::Calls, dst_id, 212));
                                        call_edges += 1;
                                    }
                                }
                            }
                        }
                    }
                }

                // Stage B2: Bare calls (`func(`, `macro!(`), `UpperCamel` type references, and same-container calls.
                let file_prefix = format!("{rel_path}::");
                for ident in sites.bare_calls_and_types {
                    if ident == sym.name || ident == own_qname {
                        continue;
                    }
                    // Implicit `this` / same-container call in OO languages (C++, Java, C#, Kotlin)
                    if let Some(ref cont) = sym.container {
                        let same_cont_q = format!("{cont}::{ident}");
                        if let Some(targets) = by_qualified_name.get(&same_cont_q) {
                            for &(dst_id, _) in targets {
                                if dst_id != src_id && seen_targets.insert(dst_id) {
                                    edges.push((src_id, EdgeKind::Calls, dst_id, 210));
                                    call_edges += 1;
                                }
                            }
                        }
                    }
                    if let Some(targets) = by_free_name.get(&ident) {
                        let df = bare_call_df.get(&ident).copied().unwrap_or(0);
                        if files_scanned >= 6 && targets.len() > 1 && df.saturating_mul(2) > files_scanned {
                            continue;
                        }
                        let has_same_file = targets.iter().any(|(_, fk)| fk.starts_with(&file_prefix));
                        if targets.len() > 3 && !has_same_file {
                            continue;
                        }
                        for &(dst_id, ref fk) in targets {
                            if targets.len() > 3 && !fk.starts_with(&file_prefix) {
                                continue;
                            }
                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 200));
                                call_edges += 1;
                            }
                        }
                    }
                }
            }
        }
    } else {
        call_edges = existing_call_edges;
    }

    // 2. Wire `Decision / Task --[Governs]--> Symbol` & `Symbol --[CausedBy]--> Decision` automatically!
    let mut gov_edges = 0usize;
    let mut active_gov_ids: Vec<u64> = Vec::new();
    let mut gov_out_edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    for kind in [NodeKind::Decision, NodeKind::Task] {
        let gov_inodes = db.list_inodes(Some(kind), false);
        let gov_ids: Vec<u64> = gov_inodes.iter().map(|(i, _, _)| i.node_id).collect();
        active_gov_ids.extend_from_slice(&gov_ids);
        let (gov_recs, _) = db.get_many_coalesced(&gov_ids)?;
        for rec in gov_recs {
            let text = String::from_utf8_lossy(&rec.payload);
            let mut seen_gov_syms: HashSet<u64> = HashSet::new();
            for qcall in extract_call_sites(&text, None).qualified_calls {
                if let Some(targets) = by_qualified_name.get(&qcall) {
                    for &(sym_id, _) in targets {
                        if seen_gov_syms.insert(sym_id) {
                            gov_out_edges.push((rec.node_id, EdgeKind::Governs, sym_id, 245));
                            edges.push((sym_id, EdgeKind::CausedBy, rec.node_id, 235));
                            gov_edges += 2;
                        }
                    }
                }
            }
            for ident in extract_code_identifiers(&text) {
                if ident.len() < 4 {
                    continue;
                }
                let df = prose_token_df.get(&ident).copied().unwrap_or(0);
                let is_salient = files_scanned < 6 || df.saturating_mul(3) <= files_scanned;
                if let Some(targets) = by_free_name.get(&ident) {
                    if targets.len() <= 3 && (targets.len() == 1 || is_salient) {
                        for &(sym_id, _) in targets {
                            if seen_gov_syms.insert(sym_id) {
                                gov_out_edges.push((rec.node_id, EdgeKind::Governs, sym_id, 240));
                                edges.push((sym_id, EdgeKind::CausedBy, rec.node_id, 230));
                                gov_edges += 2;
                            }
                        }
                    }
                }
                if is_salient {
                    if let Some(mtargets) = by_method_name.get(&ident) {
                        if mtargets.len() == 1 {
                            let (sym_id, _) = mtargets[0];
                            if seen_gov_syms.insert(sym_id) {
                                gov_out_edges.push((rec.node_id, EdgeKind::Governs, sym_id, 238));
                                edges.push((sym_id, EdgeKind::CausedBy, rec.node_id, 228));
                                gov_edges += 2;
                            }
                        }
                    }
                }
            }
        }
    }

    if need_call_pass {
        db.sync_edges_for_kinds(
            &active_sym_ids,
            &[EdgeKind::Calls, EdgeKind::DependsOn, EdgeKind::CausedBy],
            &edges,
        )?;
    } else {
        db.sync_edges_for_kinds(&active_sym_ids, &[EdgeKind::CausedBy], &edges)?;
    }
    db.sync_edges_scoped(
        &active_gov_ids,
        &[EdgeKind::Governs],
        Some(&[NodeKind::Symbol]),
        &gov_out_edges,
    )?;

    prune_stale_symbol_cue_bridges(db, &live_rel_paths, &by_full_key);

    // Physically deprecate falsified grounded reflexes ONLY on unsealed workspaces. Sealed workspaces
    // carry `sys::trust_seals` inside this very `.agents/memory.ldb`, and `NodeKind::Rule` is part of
    // the `hmac-sha256:v4` digest, so read/index paths must never mutate it there; `ReflexEngine::load`
    // already suppresses falsified reflexes at runtime without any write.
    if db.get_by_key(NodeKind::Config, "sys::trust_seals").is_err() {
        let mut live_anchor_syms: HashSet<String> = HashSet::new();
        for full_k in by_full_key.keys() {
            let stripped = strip_line_disambiguator(full_k);
            live_anchor_syms.insert(stripped.to_owned());
            if let Some((_, sym_part)) = stripped.split_once("::") {
                let clean_sym = sym_part.split('@').next().unwrap_or(sym_part);
                live_anchor_syms.insert(clean_sym.to_owned());
                if let Some((_, short_name)) = clean_sym.rsplit_once("::") {
                    live_anchor_syms.insert(short_name.to_owned());
                }
            }
        }
        let _ = crate::reflex::ReflexEngine::reconcile_grounded_reflexes(
            db,
            &live_rel_paths,
            &live_anchor_syms,
        );
    }

    let co_change_map = if !current_git_head.is_empty() {
        let can_reuse = !force
            && prev_state_opt
                .as_ref()
                .is_some_and(|ps| ps.git_head_oid == current_git_head);
        if can_reuse {
            let mut reused = prev_state_opt
                .as_ref()
                .map(|ps| ps.co_change_map.clone())
                .unwrap_or_default();
            reused.retain(|k, partners| {
                if !live_rel_paths.contains(k.as_str()) {
                    return false;
                }
                partners.retain(|p| live_rel_paths.contains(p.rel_path.as_str()));
                !partners.is_empty()
            });
            reused
        } else {
            compute_git_co_change_couplings(root, &live_rel_paths)
        }
    } else {
        BTreeMap::new()
    };

    let graph_state = WorkspaceGraphState {
        version: WORKSPACE_GRAPH_STATE_VERSION,
        skeleton_seed: SKELETON_HASH_SEED,
        indexed_at_ns: scan_started_ns,
        scan_root_key,
        exclusions_sorted,
        gov_fingerprint: gov_fp,
        git_head_oid: current_git_head,
        co_change_map,
        files_scanned,
        binary_files_skipped: binary_probe_skipped,
        symbols_indexed,
        call_synapses_wired: call_edges,
        governance_synapses_wired: gov_edges,
        files: next_file_stats,
    };
    if let Ok(state_bytes) = serde_json::to_vec(&graph_state) {
        let _ = db.put(
            WriteRequest::new(NodeKind::Generic, state_bytes)
                .with_key(WORKSPACE_GRAPH_STATE_KEY)
                .with_importance(64),
        );
    }
    let _ = db.maybe_auto_compact();

    Ok(WorkspaceIndexReport {
        files_scanned,
        files_unchanged_cached: unchanged,
        files_reindexed: reindexed,
        binary_files_skipped: binary_skipped,
        symbols_indexed,
        call_synapses_wired: call_edges,
        governance_synapses_wired: gov_edges,
        fast_path_hit: false,
    })
}

fn prune_stale_symbol_cue_bridges(
    db: &LibreDb,
    live_rel_paths: &HashSet<&str>,
    by_full_key: &HashMap<String, u64>,
) {
    let mut live_stripped: HashSet<String> = HashSet::with_capacity(by_full_key.len());
    for full_k in by_full_key.keys() {
        live_stripped.insert(strip_line_disambiguator(full_k).to_owned());
    }
    let _ = db.transact_key(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut book) = serde_json::from_slice::<SymbolCueBridgeBook>(&rec.payload) else {
            return Ok(None);
        };
        let mut modified = false;
        book.bridges.retain(|_, list| {
            let before = list.len();
            list.retain(|(sym_k, _)| {
                let stripped = strip_line_disambiguator(sym_k);
                let file_ok = stripped
                    .split_once("::")
                    .is_some_and(|(fp, _)| live_rel_paths.contains(fp));
                file_ok && (live_stripped.contains(stripped) || by_full_key.contains_key(sym_k))
            });
            if list.len() != before {
                modified = true;
            }
            !list.is_empty()
        });
        if !modified {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("symbol cue bridges serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });
    prune_stale_error_pitfalls(db, live_rel_paths, &live_stripped);
}

fn resolve_git_head_oid_fast(root: &Path) -> String {
    let git_dir = root.join(".git");
    if !git_dir.is_dir() {
        return String::new();
    }
    let head_path = git_dir.join("HEAD");
    let Ok(head_raw) = std::fs::read_to_string(&head_path) else {
        return String::new();
    };
    let head_trim = head_raw.trim();
    if let Some(ref_rel) = head_trim.strip_prefix("ref:") {
        let ref_rel = ref_rel.trim();
        if ref_rel.contains("..") || ref_rel.starts_with('/') || ref_rel.starts_with('\\') {
            return String::new();
        }
        let ref_file = git_dir.join(ref_rel);
        if let Ok(oid) = std::fs::read_to_string(&ref_file) {
            let t = oid.trim();
            if t.len() >= 40 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
                return t.to_ascii_lowercase();
            }
        }
        let packed = git_dir.join("packed-refs");
        if let Ok(packed_raw) = std::fs::read_to_string(&packed) {
            for line in packed_raw.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') || l.starts_with('^') {
                    continue;
                }
                if let Some((oid, rname)) = l.split_once(' ') {
                    if rname.trim() == ref_rel
                        && oid.len() >= 40
                        && oid.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return oid.to_ascii_lowercase();
                    }
                }
            }
        }
        String::new()
    } else if head_trim.len() >= 40 && head_trim.bytes().all(|b| b.is_ascii_hexdigit()) {
        head_trim.to_ascii_lowercase()
    } else {
        String::new()
    }
}

fn is_doc_or_meta_cochange_excluded(rel_path: &str) -> bool {
    let fname = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let low = fname.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "readme.md" | "changelog.md" | "license" | "license.md" | ".gitignore"
    )
}

fn compute_git_co_change_couplings(
    root: &Path,
    live_rel_paths: &HashSet<&str>,
) -> BTreeMap<String, Vec<CoChangePartner>> {
    if !root.join(".git").is_dir() || live_rel_paths.len() < 2 {
        return BTreeMap::new();
    }
    let output = std::process::Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "safe.directory=*",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotepath=false",
            "log",
            "-n",
            "128",
            "--name-only",
            "--pretty=format:__COMMIT__%H",
        ])
        .output();
    let Ok(out) = output else {
        return BTreeMap::new();
    };
    if !out.status.success() {
        return BTreeMap::new();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut valid_commits: Vec<Vec<String>> = Vec::new();
    let mut current_files: Vec<String> = Vec::new();
    let mut raw_non_meta_count: usize = 0;

    let mut flush_commit = |files: &mut Vec<String>, raw_cnt: &mut usize| {
        if *raw_cnt == 0 && files.is_empty() {
            return;
        }
        files.sort();
        files.dedup();
        if *raw_cnt >= 2
            && *raw_cnt <= MAX_COCHANGE_COMMIT_FILES
            && files.len() >= 2
            && files.len() <= MAX_COCHANGE_COMMIT_FILES
        {
            valid_commits.push(std::mem::take(files));
        } else {
            files.clear();
        }
        *raw_cnt = 0;
    };

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("__COMMIT__") {
            flush_commit(&mut current_files, &mut raw_non_meta_count);
            continue;
        }
        let norm = line.replace('\\', "/");
        if !is_doc_or_meta_cochange_excluded(&norm) {
            raw_non_meta_count += 1;
            if live_rel_paths.contains(norm.as_str()) {
                current_files.push(norm);
            }
        }
    }
    flush_commit(&mut current_files, &mut raw_non_meta_count);

    let m_valid = valid_commits.len();
    if m_valid < 2 {
        return BTreeMap::new();
    }

    let mut file_commits: HashMap<String, u32> = HashMap::new();
    let mut pair_stats: HashMap<(String, String), (u32, f64)> = HashMap::new();

    for c_files in &valid_commits {
        let m = c_files.len();
        let newman_w = 1.0 / ((m - 1) as f64);
        for f in c_files {
            *file_commits.entry(f.clone()).or_insert(0) += 1;
        }
        for i in 0..m {
            for j in (i + 1)..m {
                let a = &c_files[i];
                let b = &c_files[j];
                let entry_ab = pair_stats
                    .entry((a.clone(), b.clone()))
                    .or_insert((0, 0.0));
                entry_ab.0 += 1;
                entry_ab.1 += newman_w;
                let entry_ba = pair_stats
                    .entry((b.clone(), a.clone()))
                    .or_insert((0, 0.0));
                entry_ba.0 += 1;
                entry_ba.1 += newman_w;
            }
        }
    }

    let mut result: BTreeMap<String, Vec<CoChangePartner>> = BTreeMap::new();
    for ((src, dst), (shared, newman_sum)) in pair_stats {
        let src_c = file_commits.get(&src).copied().unwrap_or(0);
        let dst_c = file_commits.get(&dst).copied().unwrap_or(0);
        if src_c == 0 || dst_c == 0 {
            continue;
        }
        let min_shared = if m_valid <= 8 && shared == src_c { 2 } else { 3 };
        if shared < min_shared {
            continue;
        }
        let conf_ab = (shared as f64) / (src_c as f64);
        let conf_ba = (shared as f64) / (dst_c as f64);
        if conf_ab < 0.55 {
            continue;
        }
        let lift = ((shared as f64) * (m_valid as f64)) / ((src_c as f64) * (dst_c as f64));
        let high_mutual_coupling = conf_ab >= 0.75 && conf_ba >= 0.75 && shared >= 3;
        if lift < 1.80 && !high_mutual_coupling {
            continue;
        }
        let partner = CoChangePartner {
            rel_path: dst,
            shared_commits: shared,
            source_commits: src_c,
            confidence_pct: (conf_ab * 100.0).round().clamp(1.0, 100.0) as u8,
            lift_x100: (lift * 100.0).round() as u32,
            newman_score_x100: (newman_sum * 100.0).round() as u32,
        };
        result.entry(src).or_default().push(partner);
    }

    for partners in result.values_mut() {
        partners.sort_by(|a, b| {
            let sa = (a.confidence_pct as u64) * (a.newman_score_x100 as u64);
            let sb = (b.confidence_pct as u64) * (b.newman_score_x100 as u64);
            sb.cmp(&sa).then_with(|| a.rel_path.cmp(&b.rel_path))
        });
        partners.truncate(3);
    }

    result
}

fn compact_contract_ref(contract: &str) -> &str {
    if let Some(close_paren_idx) = contract.find(") ") {
        contract[..=close_paren_idx].trim()
    } else {
        contract.trim()
    }
}

/// Maximum number of symbols allowed in a single batched `locate` or `impact` call.
pub const MAX_BATCH_SYMBOL_QUERIES: usize = 64;
/// Maximum number of slice specs allowed in a single batched `fim` call.
pub const MAX_BATCH_FIM_SLICES: usize = 32;
/// Maximum matches emitted per query in `locate_symbols`.
pub const MAX_LOCATE_MATCHES_PER_QUERY: usize = 16;

fn normalize_symbol_query_parts(symbol_query: &str) -> Option<(String, Option<String>, bool)> {
    let raw_q = symbol_query.trim().trim_start_matches("::");
    if raw_q.is_empty() {
        return None;
    }
    let mut sig_filter: Option<String> = None;
    let normalized_q: String = if let Some((before, after_semi)) = raw_q.split_once(";->") {
        let cls = before.trim_start_matches('L').trim_end_matches(';');
        let m = if let Some(sig_idx) = after_semi.find(['(', ':']) {
            sig_filter = Some(after_semi[sig_idx..].to_owned());
            &after_semi[..sig_idx]
        } else {
            after_semi
        };
        format!("{cls}::{m}")
    } else if raw_q.starts_with('L') && raw_q.ends_with(';') && raw_q.len() > 2 {
        raw_q[1..raw_q.len() - 1].to_owned()
    } else if raw_q.contains("::") && raw_q.contains('(') {
        let idx = raw_q.find('(').unwrap_or(raw_q.len());
        sig_filter = Some(raw_q[idx..].to_owned());
        raw_q[..idx].to_owned()
    } else if raw_q.contains("->") {
        raw_q.replace("->", "::")
    } else if raw_q.contains('.')
        && !raw_q.ends_with(".rs")
        && !raw_q.ends_with(".smali")
        && !raw_q.contains('/')
    {
        raw_q.replace('.', "::")
    } else {
        raw_q.to_owned()
    };
    let is_qualified = normalized_q.contains("::");
    Some((normalized_q, sig_filter, is_qualified))
}

fn parse_symbol_location_from_contract(
    query: &str,
    node_id: u64,
    sym_key: &str,
    contract: &str,
) -> SymbolLocationMatch {
    let stripped_key = strip_line_disambiguator(sym_key);
    let (file_part, raw_sym_part) = stripped_key.split_once("::").unwrap_or(("", stripped_key));
    let (qname, key_sig_opt) = match raw_sym_part.split_once('@') {
        Some((sp, tail)) if tail.starts_with('(') || tail.starts_with(':') => (sp, Some(tail)),
        Some((sp, _)) => (sp, None),
        None => (raw_sym_part, None),
    };
    let short_name = qname
        .rsplit_once("::")
        .map_or_else(|| qname.rsplit('/').next().unwrap_or(qname), |(_, m)| m);
    let descriptor = if let Some(sig) = key_sig_opt {
        if let Some((cls, member)) = qname.rsplit_once("::") {
            format!("L{cls};->{member}{sig}")
        } else {
            String::new()
        }
    } else if file_part.ends_with(".smali") && !qname.contains("::") {
        format!("L{qname};")
    } else {
        String::new()
    };

    let mut start_line = 1usize;
    let mut end_line = 1usize;
    let mut kind = String::from("symbol");
    let mut signature = String::new();

    if let Some(l_idx) = contract.find(" [L") {
        let after_l = &contract[l_idx + 3..];
        if let Some(close_br) = after_l.find(']') {
            let span_str = &after_l[..close_br];
            if let Some((s_str, e_str)) = span_str.split_once("-L") {
                start_line = s_str.parse::<usize>().unwrap_or(1);
                end_line = e_str.parse::<usize>().unwrap_or(start_line);
            }
            let after_br = after_l[close_br + 1..].trim_start();
            if let Some(after_open_paren) = after_br.strip_prefix('(') {
                if let Some(close_paren) = after_open_paren.find(')') {
                    kind = after_open_paren[..close_paren].trim().to_owned();
                    let rest = after_open_paren[close_paren + 1..].trim();
                    signature = rest.split(" // ").next().unwrap_or(rest).trim().to_owned();
                }
            }
        }
    }

    SymbolLocationMatch {
        query: query.to_owned(),
        node_id,
        symbol_key: sym_key.to_owned(),
        file_path: file_part.to_owned(),
        symbol_name: short_name.to_owned(),
        qualified_name: qname.to_owned(),
        descriptor,
        kind,
        start_line,
        end_line,
        signature,
        contract: contract.trim().to_owned(),
    }
}

/// Fast (`< 0.5 ms`) single-pass symbol coordinate lookup (`[Lstart-Lend]`) for `1..=64` symbol queries
/// without traversing caller/callee/governance graph edges.
pub fn locate_symbols(db: &LibreDb, queries: &[String]) -> Result<Vec<SymbolLocationMatch>> {
    if let Some(ws_root) = infer_agents_ws_root(db) {
        let _ = reconcile_tentative_edits(db, &ws_root);
    }
    let mut clean_queries: Vec<String> = Vec::new();
    for q in queries {
        let t = q.trim();
        if !t.is_empty() && !clean_queries.iter().any(|existing| existing == t) {
            clean_queries.push(t.to_owned());
            if clean_queries.len() >= MAX_BATCH_SYMBOL_QUERIES {
                break;
            }
        }
    }
    if clean_queries.is_empty() {
        return Ok(Vec::new());
    }

    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
    let mut out = Vec::new();
    let bridge_scorer = BridgeScorer::from_symbol_inodes(db, &sym_inodes);
    let full_key_by_id: HashMap<u64, String> = sym_inodes
        .iter()
        .filter_map(|(i, k, _)| Some((i.node_id, k.clone()?)))
        .collect();

    for raw_query in &clean_queries {
        let Some((normalized_q, sig_filter, is_qualified_query)) =
            normalize_symbol_query_parts(raw_query)
        else {
            continue;
        };
        let q_low = normalized_q.to_lowercase();
        let mut tier1_exact: Vec<(u64, String)> = Vec::new();
        let mut tier2_ci: Vec<(u64, String)> = Vec::new();
        let mut tier3_substr: Vec<(u64, String)> = Vec::new();

        for (ino, key_opt, _) in &sym_inodes {
            let Some(ref full_k) = key_opt else { continue };
            let stripped_k = strip_line_disambiguator(full_k);
            let Some((_, raw_sym_part)) = stripped_k.split_once("::") else {
                continue;
            };
            let (sym_part, key_sig_opt) = match raw_sym_part.split_once('@') {
                Some((sp, tail)) if tail.starts_with('(') || tail.starts_with(':') => {
                    (sp, Some(tail))
                }
                Some((sp, _)) => (sp, None),
                None => (raw_sym_part, None),
            };
            if let Some(ref req_sig) = sig_filter {
                if key_sig_opt != Some(req_sig.as_str()) {
                    continue;
                }
            }
            let short_name = sym_part
                .rsplit_once("::")
                .map_or_else(|| sym_part.rsplit('/').next().unwrap_or(sym_part), |(_, m)| m);

            if is_qualified_query {
                let ns_suffix = format!("::{normalized_q}");
                let pkg_suffix = format!("/{normalized_q}");
                if sym_part == normalized_q
                    || sym_part.ends_with(&ns_suffix)
                    || sym_part.ends_with(&pkg_suffix)
                {
                    tier1_exact.push((ino.node_id, full_k.clone()));
                } else {
                    let sym_low = sym_part.to_lowercase();
                    let ns_suffix_low = format!("::{q_low}");
                    let pkg_suffix_low = format!("/{q_low}");
                    if sym_low == q_low
                        || sym_low.ends_with(&ns_suffix_low)
                        || sym_low.ends_with(&pkg_suffix_low)
                    {
                        tier2_ci.push((ino.node_id, full_k.clone()));
                    } else if q_low.len() >= 4 && sym_low.contains(&q_low) {
                        tier3_substr.push((ino.node_id, full_k.clone()));
                    }
                }
            } else if short_name == normalized_q || sym_part == normalized_q {
                tier1_exact.push((ino.node_id, full_k.clone()));
            } else if short_name.eq_ignore_ascii_case(&normalized_q)
                || sym_part.eq_ignore_ascii_case(&normalized_q)
            {
                tier2_ci.push((ino.node_id, full_k.clone()));
            } else if (normalized_q.contains('/') || normalized_q.contains('.'))
                && stripped_k
                    .split_once("::")
                    .is_some_and(|(fp, _)| fp.eq_ignore_ascii_case(&normalized_q))
            {
                tier1_exact.push((ino.node_id, full_k.clone()));
            } else if q_low.len() >= 3 && sym_part.to_lowercase().contains(&q_low) {
                tier3_substr.push((ino.node_id, full_k.clone()));
            }
        }

        tier1_exact.sort_by(|a, b| a.1.cmp(&b.1));
        tier2_ci.sort_by(|a, b| a.1.cmp(&b.1));
        tier3_substr.sort_by(|a, b| a.1.cmp(&b.1));
        let mut matched_ids = compose_tiers_with_bridges(
            db,
            raw_query,
            tier1_exact,
            tier2_ci,
            tier3_substr,
            bridge_scorer.as_ref(),
            &full_key_by_id,
            MissCueSource::Locate,
        );
        matched_ids.truncate(MAX_LOCATE_MATCHES_PER_QUERY);

        let req_ids: Vec<u64> = matched_ids.iter().map(|(id, _)| *id).collect();
        let (recs, _) = db.get_many_coalesced(&req_ids)?;
        for ((nid, sym_key), rec) in matched_ids.into_iter().zip(recs.into_iter()) {
            let contract = String::from_utf8_lossy(&rec.payload);
            out.push(parse_symbol_location_from_contract(
                raw_query,
                nid,
                &sym_key,
                &contract,
            ));
        }
    }

    Ok(out)
}

/// Renders ultra-compact 1-line `[Lstart-Lend]` symbol locations.
pub fn format_locate_compact(queries: &[String], matches: &[SymbolLocationMatch]) -> String {
    let q_label = if queries.len() == 1 {
        queries[0].clone()
    } else {
        format!("{} queries", queries.len())
    };
    if matches.is_empty() {
        return format!("=== LOCATE: {q_label} (0 symbols matched) ===\n");
    }
    let mut out = format!(
        "=== LOCATE: {} ({} symbol{} matched) ===\n",
        q_label,
        matches.len(),
        if matches.len() == 1 { "" } else { "s" }
    );
    for m in matches {
        if queries.len() > 1 {
            out.push_str(&format!("* [{}] {}\n", m.query, m.contract));
        } else {
            out.push_str(&format!("* {}\n", m.contract));
        }
    }
    out
}

/// Evaluates `query_symbol_impact` across `1..=64` symbols in a single batch call.
pub fn query_symbols_impact_batch(
    db: &LibreDb,
    symbols: &[String],
) -> Result<Vec<(String, Vec<SymbolImpactReport>)>> {
    if let Some(ws_root) = infer_agents_ws_root(db) {
        let _ = reconcile_tentative_edits(db, &ws_root);
    }
    let mut clean: Vec<String> = Vec::new();
    for s in symbols {
        let t = s.trim();
        if !t.is_empty() && !clean.iter().any(|existing| existing == t) {
            clean.push(t.to_owned());
            if clean.len() >= MAX_BATCH_SYMBOL_QUERIES {
                break;
            }
        }
    }
    let mut out = Vec::with_capacity(clean.len());
    for q in clean {
        let reps = query_symbol_impact(db, &q)?;
        out.push((q, reps));
    }
    Ok(out)
}

/// Renders batched `impact` reports into a single compact markdown block.
pub fn format_impact_batch_compact(batches: &[(String, Vec<SymbolImpactReport>)]) -> String {
    if batches.len() == 1 {
        return format_impact_compact(&batches[0].0, &batches[0].1);
    }
    let total_matches: usize = batches.iter().map(|(_, r)| r.len()).sum();
    let mut out = format!(
        "=== BATCH IMPACT: {} queries ({} total symbol{} matched) ===\n",
        batches.len(),
        total_matches,
        if total_matches == 1 { "" } else { "s" }
    );
    for (q, reps) in batches {
        out.push_str(&format_impact_compact(q, reps));
    }
    out
}

/// Renders multiple `FimSliceBundle` slices into a single compact response block.
pub fn format_fim_batch_compact(bundles: &[FimSliceBundle]) -> String {
    if bundles.len() == 1 {
        return bundles[0].format_compact();
    }
    let mut out = format!("=== BATCH FIM SLICES ({} slices) ===\n", bundles.len());
    for b in bundles {
        out.push_str(&b.format_compact());
    }
    out
}

/// Renders a token-minimal structural blast-radius summary (`80-90%` smaller than pretty JSON).
pub fn format_impact_compact(symbol_query: &str, reports: &[SymbolImpactReport]) -> String {
    if reports.is_empty() {
        return format!("=== IMPACT: {symbol_query} (0 symbols matched) ===\n");
    }
    let mut out = format!(
        "=== IMPACT: {} ({} symbol{} matched) ===\n",
        symbol_query,
        reports.len(),
        if reports.len() == 1 { "" } else { "s" }
    );
    for rep in reports.iter().take(10) {
        out.push_str(&format!("* {}\n", rep.contract.trim()));
        if !rep.governing_decisions.is_empty() {
            out.push_str("  Decisions:\n");
            for d in rep.governing_decisions.iter().take(4) {
                out.push_str(&format!("    ! {d}\n"));
            }
        }
        if !rep.implementors.is_empty() {
            out.push_str(&format!("  Implementors ({}):\n", rep.implementors.len()));
            for imp in rep.implementors.iter().take(8) {
                out.push_str(&format!("    <= {}\n", compact_contract_ref(imp)));
            }
        }
        if rep.total_callers > 0 {
            let shown = rep.callers.len().min(10);
            if rep.total_callers > shown {
                out.push_str(&format!("  Callers ({} total, top {}):\n", rep.total_callers, shown));
            } else {
                out.push_str(&format!("  Callers ({}):\n", rep.total_callers));
            }
            for c in rep.callers.iter().take(shown) {
                out.push_str(&format!("    <- {}\n", compact_contract_ref(c)));
            }
        }
        if rep.total_callees > 0 {
            let shown = rep.callees.len().min(8);
            if rep.total_callees > shown {
                out.push_str(&format!("  Callees ({} total, top {}):\n", rep.total_callees, shown));
            } else {
                out.push_str(&format!("  Callees ({}):\n", rep.total_callees));
            }
            for c in rep.callees.iter().take(shown) {
                out.push_str(&format!("    -> {}\n", compact_contract_ref(c)));
            }
        }
        if !rep.co_changed_files.is_empty() {
            out.push_str(&format!("  Co-Changed files ({}):\n", rep.co_changed_files.len()));
            for cf in rep.co_changed_files.iter().take(3) {
                out.push_str(&format!("    <-> {cf}\n"));
            }
        }
    }
    out
}

/// Locates symbols matching `symbol_query` and computes their bidirectional blast-radius (`callers`,
/// `implementors`, `callees`) plus governing architectural `Decision`/`Task` capsules in `O(N_symbols)` RAM time.
pub fn query_symbol_impact(db: &LibreDb, symbol_query: &str) -> Result<Vec<SymbolImpactReport>> {
    if let Some(ws_root) = infer_agents_ws_root(db) {
        let _ = reconcile_tentative_edits(db, &ws_root);
    }
    let raw_q = symbol_query.trim().trim_start_matches("::");
    if raw_q.is_empty() {
        return Ok(Vec::new());
    }
    // Preserve full Dalvik package/class paths and optional overload signatures (`(I)Z`, `:I`)
    // while keeping `Cls.m` / `Cls->m` / `p0::b` queries ergonomic:
    let mut sig_filter: Option<String> = None;
    let normalized_q: String = if let Some((before, after_semi)) = raw_q.split_once(";->") {
        let cls = before.trim_start_matches('L').trim_end_matches(';');
        let m = if let Some(sig_idx) = after_semi.find(['(', ':']) {
            sig_filter = Some(after_semi[sig_idx..].to_owned());
            &after_semi[..sig_idx]
        } else {
            after_semi
        };
        format!("{cls}::{m}")
    } else if raw_q.starts_with('L') && raw_q.ends_with(';') && raw_q.len() > 2 {
        raw_q[1..raw_q.len() - 1].to_owned()
    } else if raw_q.contains("::") && raw_q.contains('(') {
        let idx = raw_q.find('(').unwrap_or(raw_q.len());
        sig_filter = Some(raw_q[idx..].to_owned());
        raw_q[..idx].to_owned()
    } else if raw_q.contains("->") {
        raw_q.replace("->", "::")
    } else if raw_q.contains('.') && !raw_q.ends_with(".rs") && !raw_q.ends_with(".smali") && !raw_q.contains('/') {
        raw_q.replace('.', "::")
    } else {
        raw_q.to_owned()
    };
    let q_low = normalized_q.to_lowercase();
    let is_qualified_query = normalized_q.contains("::");

    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);

    // Build reverse `Calls` and `DependsOn` lookups in-memory (`0` disk I/O!).
    let mut reverse_calls: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut reverse_deps: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut tier1_exact: Vec<(u64, String)> = Vec::new();
    let mut tier2_ci: Vec<(u64, String)> = Vec::new();
    let mut tier3_substr: Vec<(u64, String)> = Vec::new();

    for (ino, key_opt, syns) in &sym_inodes {
        for syn in syns {
            if syn.kind == EdgeKind::Calls {
                reverse_calls.entry(syn.target_id).or_default().push(ino.node_id);
            } else if syn.kind == EdgeKind::DependsOn {
                reverse_deps.entry(syn.target_id).or_default().push(ino.node_id);
            }
        }

        let Some(ref full_k) = key_opt else { continue };
        let Some((file_part, raw_sym_part)) = full_k.split_once("::") else { continue };
        let (sym_part, key_sig_opt) = match raw_sym_part.split_once('@') {
            Some((sp, tail)) if tail.starts_with('(') || tail.starts_with(':') => (sp, Some(tail)),
            Some((sp, _)) => (sp, None),
            None => (raw_sym_part, None),
        };
        if let Some(ref req_sig) = sig_filter {
            if key_sig_opt != Some(req_sig.as_str()) {
                continue;
            }
        }
        let short_name = sym_part
            .rsplit_once("::")
            .map_or_else(|| sym_part.rsplit('/').next().unwrap_or(sym_part), |(_, m)| m);

        if is_qualified_query {
            let ns_suffix = format!("::{normalized_q}");
            let pkg_suffix = format!("/{normalized_q}");
            if sym_part == normalized_q
                || sym_part.ends_with(&ns_suffix)
                || sym_part.ends_with(&pkg_suffix)
            {
                tier1_exact.push((ino.node_id, full_k.clone()));
            } else {
                let sym_low = sym_part.to_lowercase();
                let ns_suffix_low = format!("::{q_low}");
                let pkg_suffix_low = format!("/{q_low}");
                if sym_low == q_low
                    || sym_low.ends_with(&ns_suffix_low)
                    || sym_low.ends_with(&pkg_suffix_low)
                {
                    tier2_ci.push((ino.node_id, full_k.clone()));
                } else if q_low.len() >= 4 && sym_low.contains(&q_low) {
                    tier3_substr.push((ino.node_id, full_k.clone()));
                }
            }
        } else if short_name == normalized_q || sym_part == normalized_q {
            tier1_exact.push((ino.node_id, full_k.clone()));
        } else if short_name.eq_ignore_ascii_case(&normalized_q)
            || sym_part.eq_ignore_ascii_case(&normalized_q)
        {
            tier2_ci.push((ino.node_id, full_k.clone()));
        } else if (normalized_q.contains('/') || normalized_q.contains('.'))
            && file_part.eq_ignore_ascii_case(&normalized_q)
        {
            tier1_exact.push((ino.node_id, full_k.clone()));
        } else if q_low.len() >= 3 && sym_part.to_lowercase().contains(&q_low) {
            // Never match against `file_part` so short queries (`"a"`, `"i4"`) never pull unrelated files!
            tier3_substr.push((ino.node_id, full_k.clone()));
        }
    }

    // Rank ambiguous matches (e.g. R8 short method `"a"` across 80 classes) by incoming caller fan-in
    // descending so the highest-impact call-graph hubs always surface first!
    let fan_in_order = |(id_a, k_a): &(u64, String), (id_b, k_b): &(u64, String)| {
        let ca = reverse_calls.get(id_a).map_or(0, Vec::len)
            + reverse_deps.get(id_a).map_or(0, Vec::len);
        let cb = reverse_calls.get(id_b).map_or(0, Vec::len)
            + reverse_deps.get(id_b).map_or(0, Vec::len);
        cb.cmp(&ca).then_with(|| k_a.cmp(k_b))
    };
    tier1_exact.sort_by(fan_in_order);
    tier2_ci.sort_by(fan_in_order);
    tier3_substr.sort_by(fan_in_order);
    let bridge_scorer = BridgeScorer::from_symbol_inodes(db, &sym_inodes);
    let full_key_by_id: HashMap<u64, String> = sym_inodes
        .iter()
        .filter_map(|(i, k, _)| Some((i.node_id, k.clone()?)))
        .collect();
    let matched_ids = compose_tiers_with_bridges(
        db,
        raw_q,
        tier1_exact,
        tier2_ci,
        tier3_substr,
        bridge_scorer.as_ref(),
        &full_key_by_id,
        MissCueSource::Impact,
    );

    let co_change_map: BTreeMap<String, Vec<CoChangePartner>> = db
        .get_by_key(NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<WorkspaceGraphState>(&rec.payload).ok())
        .map(|st| st.co_change_map)
        .unwrap_or_default();

    const MAX_SERIALIZED_CALLERS: usize = 20;
    const MAX_SERIALIZED_CALLEES: usize = 12;

    let mut reports = Vec::new();
    for (nid, sym_key) in matched_ids.into_iter().take(12) {
        let rec = db.get(nid)?;
        let contract = String::from_utf8_lossy(&rec.payload).into_owned();

        let mut caller_ids = reverse_calls.get(&nid).cloned().unwrap_or_default();
        let is_member_method = sym_key.matches("::").count() >= 2;
        if is_member_method {
            // Propagate DI callers across implemented interface/trait methods (`Caller -> Interface::m <- Impl::m`)
            for syn in &rec.synapses {
                if syn.kind == EdgeKind::DependsOn {
                    if let Some(iface_callers) = reverse_calls.get(&syn.target_id) {
                        for &cid in iface_callers {
                            if cid != nid && !caller_ids.contains(&cid) {
                                caller_ids.push(cid);
                            }
                        }
                    }
                }
            }
        }

        let total_callers = caller_ids.len();
        caller_ids.truncate(MAX_SERIALIZED_CALLERS);
        let (caller_recs, _) = db.get_many_coalesced(&caller_ids)?;
        let callers: Vec<String> = caller_recs
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
            .collect();

        let mut imp_ids = reverse_deps.get(&nid).cloned().unwrap_or_default();
        imp_ids.truncate(MAX_SERIALIZED_CALLERS);
        let (imp_recs, _) = db.get_many_coalesced(&imp_ids)?;
        let implementors: Vec<String> = imp_recs
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
            .collect();

        let mut callee_ids = Vec::new();
        let mut gov_ids = Vec::new();
        for syn in &rec.synapses {
            match syn.kind {
                EdgeKind::Calls | EdgeKind::DependsOn | EdgeKind::Imports => {
                    callee_ids.push(syn.target_id);
                }
                EdgeKind::CausedBy | EdgeKind::Governs => {
                    gov_ids.push(syn.target_id);
                }
                _ => {}
            }
        }

        let total_callees = callee_ids.len();
        callee_ids.truncate(MAX_SERIALIZED_CALLEES);
        let (callee_recs, _) = db.get_many_coalesced(&callee_ids)?;
        let callees: Vec<String> = callee_recs
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
            .collect();

        let (gov_recs, _) = db.get_many_coalesced(&gov_ids)?;
        let governing_decisions: Vec<String> = gov_recs
            .into_iter()
            .map(|r| {
                let txt = String::from_utf8_lossy(&r.payload);
                txt.lines().take(2).collect::<Vec<_>>().join(" | ")
            })
            .collect();

        let mut co_changed_files = Vec::new();
        if let Some((sym_file, _)) = sym_key.split_once("::") {
            if let Some(partners) = co_change_map.get(sym_file) {
                for p in partners.iter().take(3) {
                    let p_prefix = format!("{} ::", p.rel_path);
                    let already_linked = callers.iter().any(|c| c.starts_with(&p_prefix))
                        || callees.iter().any(|c| c.starts_with(&p_prefix))
                        || implementors.iter().any(|c| c.starts_with(&p_prefix));
                    if !already_linked {
                        co_changed_files.push(format!(
                            "{} ({}%, {}/{} commits)",
                            p.rel_path, p.confidence_pct, p.shared_commits, p.source_commits
                        ));
                    }
                }
            }
        }

        reports.push(SymbolImpactReport {
            node_id: nid,
            symbol_key: sym_key,
            contract,
            total_callers,
            callers,
            implementors,
            total_callees,
            callees,
            governing_decisions,
            co_changed_files,
        });
    }

    Ok(reports)
}

/// Extracts a minimal Fill-in-the-Middle (`FIM`) edit slice around `symbol_name` (or `center_line`),
/// automatically attaching blast-radius callers and governing architectural decisions!
pub fn extract_fim_slice(
    db: &LibreDb,
    file_path: &Path,
    symbol_name: Option<&str>,
    center_line: Option<usize>,
    context_pad: usize,
) -> Result<FimSliceBundle> {
    if let Some(ws_root) = infer_agents_ws_root(db) {
        let _ = reconcile_tentative_edits(db, &ws_root);
    }
    let raw_bytes = crate::skeleton::read_bounded_source_file(file_path)?;
    let text = String::from_utf8_lossy(&raw_bytes);
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let label = file_path.to_string_lossy().replace('\\', "/");

    let (skel, _) = FileSkeleton::index_or_get_cached_bytes(db, label.clone(), &raw_bytes)?;

    let (win_start, win_end, matched_sym, matched_impact_query) = if let Some(sym_q) = symbol_name {
        let q_low = sym_q.to_lowercase();
        let pkg_suffix_low = format!("/{q_low}");
        let found = skel
            .symbols
            .iter()
            .find(|s| {
                let qn_low = s.qualified_name().to_lowercase();
                s.descriptor
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(sym_q))
                    || qn_low == q_low
                    || qn_low.ends_with(&pkg_suffix_low)
                    || s.name.to_lowercase() == q_low
            })
            .or_else(|| {
                skel.symbols.iter().find(|s| {
                    s.descriptor
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(&q_low))
                        || s.qualified_name().to_lowercase().contains(&q_low)
                        || s.name.to_lowercase().contains(&q_low)
                })
            })
            .ok_or_else(|| LibreDbError::KeyNotFound {
                kind: NodeKind::Symbol,
                key: sym_q.to_owned(),
            })?;
        let s = found.start_line.saturating_sub(context_pad).max(1);
        let e = (found.end_line + context_pad).min(total_lines.max(1));
        let qname = found.qualified_name();
        let imp_q = found
            .descriptor
            .clone()
            .unwrap_or_else(|| format!("::{qname}"));
        (s, e, Some(qname), Some(imp_q))
    } else if let Some(ln) = center_line {
        let c = ln.clamp(1, total_lines.max(1));
        let s = c.saturating_sub(context_pad).max(1);
        let e = (c + context_pad).min(total_lines.max(1));
        (s, e, None, None)
    } else {
        (1, total_lines.min(50).max(1), None, None)
    };

    let mut numbered = String::new();
    if total_lines > 0 && win_start <= win_end {
        for ln in win_start..=win_end {
            numbered.push_str(&format!("{ln:>5}: {}\n", lines[ln - 1]));
        }
    }

    let mut callers = Vec::new();
    let mut implementors = Vec::new();
    let mut governing = Vec::new();
    if let Some(ref scoped_q) = matched_impact_query {
        if let Ok(impacts) = query_symbol_impact(db, scoped_q) {
            let best = impacts
                .iter()
                .find(|r| label.ends_with(r.symbol_key.split_once("::").map_or("", |(f, _)| f)))
                .cloned()
                .or_else(|| impacts.into_iter().next());
            if let Some(first) = best {
                callers = first.callers;
                implementors = first.implementors;
                governing = first.governing_decisions;
            }
        }
    }

    Ok(FimSliceBundle {
        file_label: label,
        target_symbol: matched_sym,
        window_start_line: win_start,
        window_end_line: win_end,
        total_file_lines: total_lines,
        slice_text: numbered,
        callers,
        implementors,
        governing_decisions: governing,
    })
}

struct WorkspaceScanConfig {
    extra_extensions: Vec<String>,
    ignore_dirs: HashSet<String>,
    excluded_subroots: HashSet<String>,
    max_file_bytes: usize,
}

fn normalize_scan_boundary_key(p: &Path) -> String {
    let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = canon.to_string_lossy().replace('\\', "/");
    let stripped = s.strip_prefix("//?/").unwrap_or(&s);
    let trimmed = if stripped.len() > 1 {
        stripped.trim_end_matches('/')
    } else {
        stripped
    };
    #[cfg(windows)]
    {
        trimmed.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        trimmed.to_owned()
    }
}

impl WorkspaceScanConfig {
    fn from_db_and_root(db: &LibreDb, root: &Path, excluded_paths: &[PathBuf]) -> Self {
        let root_key = normalize_scan_boundary_key(root);
        let excluded_subroots: HashSet<String> = excluded_paths
            .iter()
            .map(|p| normalize_scan_boundary_key(p))
            .filter(|k| !k.is_empty() && k != &root_key)
            .collect();
        let mut ignore_dirs: HashSet<String> = [
            ".git",
            ".agents",
            "target",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            "out",
            "__pycache__",
            ".pytest_cache",
            ".idea",
            ".vscode",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();

        // Autonomously learn directory ignore rules from the workspace's own `.gitignore`!
        if let Ok(gitignore) = std::fs::read_to_string(root.join(".gitignore")) {
            for line in gitignore.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') || t.starts_with('!') || t.contains('*') {
                    continue;
                }
                let clean = t.trim_matches('/');
                if !clean.is_empty() && !clean.contains('/') && (t.ends_with('/') || root.join(clean).is_dir()) {
                    ignore_dirs.insert(clean.to_ascii_lowercase());
                }
            }
        }

        // Apply runtime-configurable overrides from `NodeKind::Config` (`index:ignore_dirs`, `index:extra_extensions`, `index:max_file_bytes`).
        if let Ok(rec) = db.get_by_key(NodeKind::Config, "index:ignore_dirs") {
            for item in String::from_utf8_lossy(&rec.payload).split([',', ';', '\n']) {
                let d = item.trim().trim_matches('/').to_ascii_lowercase();
                if !d.is_empty() {
                    ignore_dirs.insert(d);
                }
            }
        }

        let mut extra_extensions = Vec::new();
        if let Ok(rec) = db.get_by_key(NodeKind::Config, "index:extra_extensions") {
            for item in String::from_utf8_lossy(&rec.payload).split([',', ';', ' ', '\n']) {
                let e = item.trim().to_ascii_lowercase();
                if !e.is_empty() {
                    extra_extensions.push(if e.starts_with('.') { e } else { format!(".{e}") });
                }
            }
        }

        let max_file_bytes = db
            .get_by_key(NodeKind::Config, "index:max_file_bytes")
            .ok()
            .and_then(|r| String::from_utf8_lossy(&r.payload).trim().parse::<usize>().ok())
            .unwrap_or(4 * 1024 * 1024)
            .min(crate::skeleton::MAX_SKELETON_FILE_BYTES as usize);

        Self {
            extra_extensions,
            ignore_dirs,
            excluded_subroots,
            max_file_bytes,
        }
    }
}

fn collect_source_files(
    root: &Path,
    curr: &Path,
    cfg: &WorkspaceScanConfig,
    out: &mut Vec<(PathBuf, String)>,
    binary_skipped: &mut usize,
) -> Result<()> {
    let entries = match std::fs::read_dir(curr) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        // Never follow file or directory symlinks during workspace indexing so repository symlinks
        // cannot escape the workspace boundary or ingest external credential/dotenv files.
        if ft.is_symlink() {
            continue;
        }
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let low = name.to_ascii_lowercase();

        if ft.is_dir() {
            if cfg.ignore_dirs.contains(&low)
                || matches!(low.as_str(), ".ssh" | ".gnupg" | ".aws" | ".azure" | ".kube")
            {
                continue;
            }
            // Never cross into nested child cognitive workspaces during a parent scan:
            // any subdirectory strictly below `root` with its own `.agents` directory or an
            // explicit server-registered workspace boundary owns an isolated cognitive brain.
            if p != root {
                if p.join(".agents").is_dir() {
                    continue;
                }
                if !cfg.excluded_subroots.is_empty()
                    && cfg.excluded_subroots.contains(&normalize_scan_boundary_key(&p))
                {
                    continue;
                }
            }
            collect_source_files(root, &p, cfg, out, binary_skipped)?;
        } else if ft.is_file() {
            if is_sensitive_filename(&low) {
                continue;
            }
            if is_known_source_extension(&low)
                || cfg.extra_extensions.iter().any(|ext| low.ends_with(ext))
            {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((p, rel));
            } else if is_known_binary_extension(&low) {
                *binary_skipped += 1;
            }
        }
    }
    Ok(())
}

fn is_sensitive_filename(low: &str) -> bool {
    if low == ".env"
        || (low.starts_with(".env.")
            && !low.ends_with(".example")
            && !low.ends_with(".sample")
            && !low.ends_with(".template")
            && !low.ends_with(".dist"))
    {
        return true;
    }
    low.ends_with(".credential.xml")
        || low.ends_with(".pem")
        || low.ends_with(".p12")
        || low.ends_with(".pfx")
        || low.ends_with(".jks")
        || low.ends_with(".kdbx")
        || matches!(
            low,
            ".vault.key" | ".netrc" | "_netrc" | ".git-credentials" | "id_rsa" | "id_ed25519" | "id_ecdsa"
        )
}

fn is_known_source_extension(low: &str) -> bool {
    if low.ends_with(".min.js") || low.ends_with(".min.css") {
        return false;
    }
    let fname = low.rsplit(['/', '\\']).next().unwrap_or(low);
    if matches!(fname, "makefile" | "gnumakefile" | "justfile" | "cmakelists.txt") {
        return true;
    }
    [
        ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
        ".dart", ".go", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".java", ".kt",
        ".kts", ".swift", ".smali", ".asm", ".s", ".inc", ".dis", ".ps1", ".psm1", ".sql", ".sh",
        ".bash", ".zsh", ".rb", ".php", ".lua", ".zig", ".scala", ".groovy", ".gradle", ".proto",
        ".ex", ".exs", ".erl", ".gleam", ".nim", ".jl", ".r", ".tf", ".hcl", ".nix", ".cmake",
        ".mk", ".wgsl", ".glsl", ".hlsl",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

fn is_known_binary_extension(low: &str) -> bool {
    [
        ".exe", ".dll", ".pyd", ".so", ".dylib", ".rlib", ".rmeta", ".pdb", ".obj", ".o", ".ldb",
        ".db", ".db-wal", ".db-shm", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".zip",
        ".7z", ".gz", ".xz", ".zst", ".whl", ".apk", ".aab", ".dex", ".arsc", ".flat", ".class",
        ".jar", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".ogg", ".wav",
    ]
    .iter()
    .any(|ext| low.ends_with(ext))
}

/// Centralized check for whether `dir` contains a recognized project or decompiled workspace marker.
pub fn has_project_root_marker(dir: &Path) -> bool {
    const MARKERS: &[&str] = &[
        ".agents",
        ".git",
        "Cargo.toml",
        "pyproject.toml",
        "package.json",
        "pubspec.yaml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "AndroidManifest.xml",
        "apktool.yml",
        "CMakeLists.txt",
        "Makefile",
        "composer.json",
        "Gemfile",
        "mix.exs",
    ];
    if MARKERS.iter().any(|m| dir.join(m).exists()) {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten().take(64) {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".sln") || name.ends_with(".csproj") {
                return true;
            }
        }
    }
    false
}

fn extract_code_identifiers(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut curr = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            curr.push(ch);
        } else {
            if curr.len() >= 3 && !curr.chars().next().unwrap().is_ascii_digit() {
                set.insert(curr.clone());
            }
            curr.clear();
        }
    }
    if curr.len() >= 3 && !curr.chars().next().unwrap().is_ascii_digit() {
        set.insert(curr);
    }
    set
}

fn collect_supertype_chain(
    start_type: &str,
    type_supertypes: &HashMap<String, Vec<String>>,
    max_hops: usize,
) -> Vec<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    visited.insert(start_type.to_owned());
    queue.push_back((start_type.to_owned(), 0));
    while let Some((curr, depth)) = queue.pop_front() {
        if depth >= max_hops {
            continue;
        }
        if let Some(sups) = type_supertypes.get(&curr) {
            for sup in sups {
                if visited.insert(sup.clone()) {
                    out.push(sup.clone());
                    queue.push_back((sup.clone(), depth + 1));
                }
            }
        }
    }
    out
}

pub(crate) fn compute_file_symbol_keys(rel_path: &str, skel: &FileSkeleton) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(skel.symbols.len());
    let mut seen_keys: HashSet<String> = HashSet::with_capacity(skel.symbols.len());
    for (idx, sym) in skel.symbols.iter().enumerate() {
        if sym.kind == "impl" {
            continue;
        }
        let qname = sym.qualified_name();
        let member_sig = sym
            .descriptor
            .as_deref()
            .and_then(|d| d.split_once(";->"))
            .and_then(|(_, m)| m.find(['(', ':']).map(|sig_idx| &m[sig_idx..]));
        let base_key = if let Some(sig) = member_sig {
            format!("{rel_path}::{qname}@{sig}")
        } else {
            format!("{rel_path}::{qname}")
        };
        let unique_key = if seen_keys.insert(base_key.clone()) {
            base_key
        } else {
            let disamb = format!("{base_key}@L{}", sym.start_line);
            seen_keys.insert(disamb.clone());
            disamb
        };
        out.push((idx, unique_key));
    }
    out
}

struct CallSiteBuckets {
    dalvik_exact_calls: HashSet<String>,
    dalvik_type_refs: HashSet<String>,
    qualified_calls: HashSet<String>,
    receiver_methods: HashSet<String>,
    bare_calls_and_types: HashSet<String>,
}

fn scan_dalvik_type_descriptor_end(bytes: &[u8], mut idx: usize) -> Option<usize> {
    let n = bytes.len();
    while idx < n && bytes[idx] == b'[' {
        idx += 1;
    }
    if idx >= n {
        return None;
    }
    match bytes[idx] {
        b'V' | b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => Some(idx + 1),
        b'L' => {
            let mut k = idx + 1;
            while k < n
                && (bytes[k].is_ascii_alphanumeric()
                    || matches!(bytes[k], b'/' | b'_' | b'$' | b'-'))
            {
                k += 1;
            }
            if k > idx + 1 && k < n && bytes[k] == b';' {
                Some(k + 1)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Language-agnostic syntactic call-site classifier with zero hardcoded stopwords:
/// 0. `dalvik_exact_calls` & `dalvik_type_refs`: exact `L<pkg/Cls>;-><member><sig>` and `L<pkg/Cls>;`
///    descriptors without stripping package paths or collapsing method overloads.
/// 1. `qualified_calls`: `UpperType::method`, `UpperType.method`, `Self::method`, `self.method(`, `this.method(`
///    (never leaked into unqualified buckets, so `Vec::new()` or `File::open()` never collide with user methods).
/// 2. `receiver_methods`: `expr.method(` on runtime variables or chained expressions.
/// 3. `bare_calls_and_types`: standalone `func(`, `macro!(`, or `UpperCamel` type references not preceded by `.` or `::`.
fn extract_call_sites(text: &str, self_container: Option<&str>) -> CallSiteBuckets {
    let mut dalvik_exact_calls = HashSet::new();
    let mut dalvik_type_refs = HashSet::new();
    let mut qualified_calls = HashSet::new();
    let mut receiver_methods = HashSet::new();
    let mut bare_calls_and_types = HashSet::new();

    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;

    while i < n {
        // 1. Skip `//` line comments
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // 2. Skip `/* ... */` block comments
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        // 3. Skip `#` comments (Smali, Python, Shell, Ruby, Makefile), preserving Rust `#[attr]` / `#![attr]`
        if bytes[i] == b'#' && (i + 1 >= n || (bytes[i + 1] != b'[' && bytes[i + 1] != b'!')) {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // 4. Skip `--` comments (SQL, Lua) when preceded by start-of-file or whitespace (never C `x--`)
        if i + 1 < n
            && bytes[i] == b'-'
            && bytes[i + 1] == b'-'
            && (i == 0 || bytes[i - 1].is_ascii_whitespace())
        {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // 5. Skip string literals (`"..."`) so error strings and SQL/JSON text do not synthesize call edges!
        if bytes[i] == b'"' {
            i += 1;
            while i < n {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(n);
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // 6. Dalvik / Smali exact descriptors: `L<pkg/Cls>;-><method>(<args>)<ret>`, `L<pkg/Cls>;-><field>:<type>`,
        // and standalone `L<pkg/Cls>;` type references. Preserves full package path and overload descriptor!
        if bytes[i] == b'L'
            && (i == 0 || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_'))
        {
            let mut k = i + 1;
            while k < n
                && (bytes[k].is_ascii_alphanumeric()
                    || matches!(bytes[k], b'/' | b'_' | b'$' | b'-'))
            {
                k += 1;
            }
            if k > i + 1 && k < n && bytes[k] == b';' {
                let cls_desc = &text[i..=k];
                if k + 3 < n && bytes[k + 1] == b'-' && bytes[k + 2] == b'>' {
                    dalvik_type_refs.insert(cls_desc.to_owned());
                    let m_start = k + 3;
                    if bytes[m_start] == b'<' {
                        let mut m_end = m_start + 1;
                        while m_end < n && bytes[m_end] != b'>' && bytes[m_end] != b'\n' {
                            m_end += 1;
                        }
                        if m_end + 1 < n && bytes[m_end] == b'>' && bytes[m_end + 1] == b'(' {
                            let member_name = &text[m_start..=m_end];
                            let mut p = m_end + 2;
                            while p < n
                                && bytes[p] != b')'
                                && bytes[p] != b'\n'
                                && bytes[p] != b'\r'
                                && bytes[p] != b' '
                            {
                                p += 1;
                            }
                            if p < n && bytes[p] == b')' {
                                if let Some(sig_end) = scan_dalvik_type_descriptor_end(bytes, p + 1)
                                {
                                    if member_name == "<init>" {
                                        dalvik_exact_calls.insert(text[i..sig_end].to_owned());
                                    }
                                    i = sig_end;
                                    continue;
                                }
                            }
                        }
                        i = (m_end + 1).min(n);
                        continue;
                    }
                    let mut m_end = m_start;
                    while m_end < n
                        && (bytes[m_end].is_ascii_alphanumeric()
                            || matches!(bytes[m_end], b'_' | b'$' | b'-'))
                    {
                        m_end += 1;
                    }
                    if m_end > m_start && m_end < n && bytes[m_end] == b'(' {
                        let mut p = m_end + 1;
                        while p < n
                            && bytes[p] != b')'
                            && bytes[p] != b'\n'
                            && bytes[p] != b'\r'
                            && bytes[p] != b' '
                        {
                            p += 1;
                        }
                        if p < n && bytes[p] == b')' {
                            if let Some(sig_end) = scan_dalvik_type_descriptor_end(bytes, p + 1) {
                                dalvik_exact_calls.insert(text[i..sig_end].to_owned());
                                i = sig_end;
                                continue;
                            }
                        }
                    } else if m_end > m_start && m_end < n && bytes[m_end] == b':' {
                        if let Some(sig_end) = scan_dalvik_type_descriptor_end(bytes, m_end + 1) {
                            dalvik_exact_calls.insert(text[i..sig_end].to_owned());
                            let field_type = text[m_end + 1..sig_end].trim_start_matches('[');
                            if field_type.starts_with('L') && field_type.ends_with(';') {
                                dalvik_type_refs.insert(field_type.to_owned());
                            }
                            i = sig_end;
                            continue;
                        }
                    }
                } else if text[i + 1..k].contains('/') {
                    dalvik_type_refs.insert(cls_desc.to_owned());
                    i = k + 1;
                    continue;
                }
            }
        }

        let preceded_by_access = (i >= 1 && (bytes[i - 1] == b'.' || bytes[i - 1] == b':'))
            || (i >= 2 && bytes[i - 2] == b'-' && bytes[i - 1] == b'>');

        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let s1 = i;
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let lhs = &text[s1..i];

            // Check if `lhs` is followed by `::`, `->`, `.`, or Lua/Smalltalk `:` call
            let sep_info: Option<(usize, u8)> = if i + 1 < n && bytes[i] == b':' && bytes[i + 1] == b':' {
                Some((i + 2, b':'))
            } else if i + 1 < n && bytes[i] == b'-' && bytes[i + 1] == b'>' {
                Some((i + 2, b'>'))
            } else if i < n && bytes[i] == b'.' {
                Some((i + 1, b'.'))
            } else if i + 1 < n && bytes[i] == b':' && bytes[i + 1] != b':' && bytes[i + 1].is_ascii_alphabetic() {
                Some((i + 1, b':'))
            } else {
                None
            };

            if let Some((sep_end, sep_kind)) = sep_info {
                if sep_end < n && (bytes[sep_end].is_ascii_alphabetic() || bytes[sep_end] == b'_') {
                    let mut j = sep_end + 1;
                    while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                        j += 1;
                    }
                    let rhs = &text[sep_end..j];
                    let has_call_paren = has_following_call_paren(bytes, j);
                    // Single `:` (`x: Foo` vs Lua `obj:method(`) requires `(` unless it was `::`!
                    let single_colon_not_call =
                        sep_end == i + 1 && bytes[i] == b':' && !has_call_paren;

                    if !single_colon_not_call {
                        let resolved_owner: Option<(&str, bool)> = if lhs == "Self" {
                            self_container.map(|c| (c, false))
                        } else if matches!(lhs, "self" | "this") {
                            self_container.map(|c| (c, true))
                        } else if lhs.len() >= 1 && lhs.as_bytes()[0].is_ascii_uppercase() {
                            Some((lhs, false))
                        } else {
                            None
                        };

                        if let Some((owner_type, req_paren)) = resolved_owner {
                            if owner_type.len() >= 3 && !preceded_by_access {
                                bare_calls_and_types.insert(owner_type.to_owned());
                            }
                            if (!rhs.is_empty() && has_call_paren)
                                || (rhs.len() >= 2 && !req_paren)
                            {
                                qualified_calls.insert(format!("{owner_type}::{rhs}"));
                            }
                            if j < n
                                && (bytes[j] == b'.'
                                    || (j + 1 < n && bytes[j] == b':' && bytes[j + 1] == b':')
                                    || (j + 1 < n && bytes[j] == b'-' && bytes[j + 1] == b'>'))
                            {
                                i = sep_end;
                            } else {
                                i = j;
                            }
                            continue;
                        } else if matches!(sep_kind, b'.' | b'>' | b':')
                            && has_call_paren
                            && rhs.len() >= 3
                        {
                            // Lowercase receiver call (`var.method(`, `ptr->method(`, `obj:method(`):
                            receiver_methods.insert(rhs.to_owned());
                            if j < n
                                && (bytes[j] == b'.'
                                    || (j + 1 < n && bytes[j] == b'-' && bytes[j + 1] == b'>'))
                            {
                                i = sep_end;
                            } else {
                                i = j;
                            }
                            continue;
                        }
                    }
                }
            }

            // Chained method call after `).method(` or `?.method(` where `preceded_by_access` is true:
            if preceded_by_access {
                if i >= 1 && lhs.len() >= 3 && has_following_call_paren(bytes, i) {
                    // Only treat `.method(` as a receiver method, not `mod::func(` (which is a module-qualified free call!)
                    let is_dot_or_arrow = (s1 >= 1 && bytes[s1 - 1] == b'.')
                        || (s1 >= 2 && bytes[s1 - 2] == b'-' && bytes[s1 - 1] == b'>');
                    if is_dot_or_arrow {
                        receiver_methods.insert(lhs.to_owned());
                    } else {
                        bare_calls_and_types.insert(lhs.to_owned());
                    }
                }
                continue;
            }

            // Standalone identifier (not preceded by `.` or `::`):
            if lhs.len() >= 3 {
                let is_upper_type = lhs.as_bytes()[0].is_ascii_uppercase()
                    && lhs.bytes().any(|b| b.is_ascii_lowercase());
                let is_call = has_following_call_paren(bytes, i);
                if is_call || is_upper_type {
                    bare_calls_and_types.insert(lhs.to_owned());
                }
            }
        } else {
            i += 1;
        }
    }

    CallSiteBuckets {
        dalvik_exact_calls,
        dalvik_type_refs,
        qualified_calls,
        receiver_methods,
        bare_calls_and_types,
    }
}

#[inline]
fn has_following_call_paren(bytes: &[u8], mut idx: usize) -> bool {
    let n = bytes.len();
    while idx < n && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    if idx >= n {
        return false;
    }
    if bytes[idx] == b'(' {
        return true;
    }
    if bytes[idx] == b'!' && idx + 1 < n && (bytes[idx + 1] == b'(' || bytes[idx + 1] == b'[') {
        return true;
    }
    // Turbofish / generic call: `foo::<T>(` or `foo<T>(`
    if idx + 2 < n && bytes[idx] == b':' && bytes[idx + 1] == b':' && bytes[idx + 2] == b'<' {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_di_interfaces_and_implementations_wire_bidirectional_impact() {
        let tmp = std::env::temp_dir().join(format!("libredb_di_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();

        // 1. Java / Quarkus DI: Interface + @ApplicationScoped impl + @Inject REST resource
        std::fs::write(
            tmp.join("src/OrderApprovalPort.java"),
            r#"package com.acme.orders;
public interface OrderApprovalPort {
    String approveOrder(String orderId);
}
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("src/OrderApprovalService.java"),
            r#"package com.acme.orders;
@ApplicationScoped
public class OrderApprovalService implements OrderApprovalPort {
    @Override
    public String approveOrder(String orderId) {
        return "APPROVED:" + orderId;
    }
}
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("src/OrderResource.java"),
            r#"package com.acme.orders;
public class OrderResource {
    @Inject OrderApprovalPort approvalPort;
    public String submitOrder(String id) {
        return approvalPort.approveOrder(id);
    }
}
"#,
        )
        .unwrap();

        // 2. Angular / TypeScript DI: Interface + @Injectable service + @Component consumer
        std::fs::write(
            tmp.join("src/payment.gateway.ts"),
            r#"export interface PaymentGateway {
    chargeCard(cents: number): Promise<boolean>;
}
@Injectable({ providedIn: 'root' })
export class StripePaymentGateway implements PaymentGateway {
    async chargeCard(cents: number): Promise<boolean> {
        return cents > 0;
    }
}
export class CheckoutComponent {
    constructor(private readonly gateway: PaymentGateway) {}
    async payNow(total: number): Promise<boolean> {
        return await this.gateway.chargeCard(total);
    }
}
"#,
        )
        .unwrap();

        // 3. C# / .NET Primary Constructor DI: IOrderRepository + SqlOrderRepository
        std::fs::write(
            tmp.join("src/OrderRepository.cs"),
            r#"namespace Acme.Orders;
public interface IOrderRepository {
    Task<bool> PersistApprovalAsync(Guid id);
}
public sealed class SqlOrderRepository(IDbConnection db) : BaseRepository, IOrderRepository {
    public async Task<bool> PersistApprovalAsync(Guid id) {
        return true;
    }
}
"#,
        )
        .unwrap();

        let db = LibreDb::open(tmp.join("mem.ldb")).unwrap();
        let rep = index_workspace(&db, &tmp, true).unwrap();
        assert_eq!(rep.files_scanned, 5);

        // Verify Java/Quarkus interface impact: shows OrderApprovalService as implementor & OrderResource::submitOrder as caller!
        let port_method = query_symbol_impact(&db, "OrderApprovalPort::approveOrder").unwrap();
        assert_eq!(port_method.len(), 1);
        assert!(port_method[0]
            .implementors
            .iter()
            .any(|s| s.contains("OrderApprovalService::approveOrder")));
        assert!(port_method[0]
            .callers
            .iter()
            .any(|s| s.contains("OrderResource::submitOrder")));

        // Verify concrete Java implementation inherits DI caller blast-radius (`OrderResource::submitOrder`)!
        let impl_method = query_symbol_impact(&db, "OrderApprovalService::approveOrder").unwrap();
        assert_eq!(impl_method.len(), 1);
        assert!(impl_method[0]
            .callers
            .iter()
            .any(|s| s.contains("OrderResource::submitOrder")));

        // Verify Angular/TypeScript DI interface + concrete implementation impact
        let ts_iface = query_symbol_impact(&db, "PaymentGateway::chargeCard").unwrap();
        assert_eq!(ts_iface.len(), 1);
        assert!(ts_iface[0]
            .implementors
            .iter()
            .any(|s| s.contains("StripePaymentGateway::chargeCard")));
        assert!(ts_iface[0]
            .callers
            .iter()
            .any(|s| s.contains("CheckoutComponent::payNow")));

        // Verify C#/.NET interface -> implementation resolution
        let cs_iface = query_symbol_impact(&db, "IOrderRepository::PersistApprovalAsync").unwrap();
        assert_eq!(cs_iface.len(), 1);
        assert!(cs_iface[0]
            .implementors
            .iter()
            .any(|s| s.contains("SqlOrderRepository::PersistApprovalAsync")));

        drop(db);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn smali_dalvik_call_graph_and_r8_short_methods() {
        let tmp = std::env::temp_dir().join(format!("libredb_smali_cg_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("smali_classes3/ci")).unwrap();
        std::fs::create_dir_all(tmp.join("smali/com/acme")).unwrap();

        std::fs::write(
            tmp.join("smali_classes3/ci/p0.smali"),
            r#".class public interface abstract Lci/p0;
.super Ljava/lang/Object;
.method public abstract b(I)Z
.end method
"#,
        )
        .unwrap();

        std::fs::write(
            tmp.join("smali_classes3/ci/p1.smali"),
            r#".class public Lci/p1;
.super Ljava/lang/Object;
.implements Lci/p0;
.method public final l(Landroid/content/Context;)Z
    .registers 3
    # Comment mentioning Lci/p0;->b(I)Z must be ignored
    const/4 v0, 0x1
    return v0
.end method
.method public b(I)Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
"#,
        )
        .unwrap();

        std::fs::write(
            tmp.join("smali_classes3/ci/j4.smali"),
            r#".class public final Lci/j4;
.super Lci/p1;
.field public c:Lci/p0;
.method public final checkLicense(Landroid/content/Context;)Z
    .registers 4
    iget-object v0, p0, Lci/j4;->c:Lci/p0;
    invoke-interface {v0, p1}, Lci/p0;->b(I)Z
    invoke-virtual {p0, p1}, Lci/j4;->l(Landroid/content/Context;)Z
    move-result v1
    return v1
.end method
"#,
        )
        .unwrap();

        std::fs::write(
            tmp.join("smali/com/acme/AlphaScreen.smali"),
            r#".class public final Lcom/acme/AlphaScreen;
.super Ljava/lang/Object;
.method public final renderView()V
    .registers 1
    return-void
.end method
"#,
        )
        .unwrap();

        let db = LibreDb::open(tmp.join(".agents_mem.ldb")).unwrap();
        let rep = index_workspace(&db, &tmp, true).unwrap();
        assert_eq!(rep.files_scanned, 4);
        assert!(rep.call_synapses_wired >= 3);

        // 1. Inherited Dalvik call `Lci/j4;->l(` resolves to superclass `p1::l`!
        let p1_l = query_symbol_impact(&db, "p1::l").unwrap();
        assert_eq!(p1_l.len(), 1);
        assert_eq!(p1_l[0].total_callers, 1);
        assert!(p1_l[0]
            .callers
            .iter()
            .any(|c| c.contains("j4::checkLicense")));

        // 2. Interface Dalvik call `Lci/p0;->b(` resolves on both interface `p0::b` AND implementor `p1::b`!
        let p1_b = query_symbol_impact(&db, "p1::b").unwrap();
        assert_eq!(p1_b.len(), 1);
        assert!(p1_b[0]
            .callers
            .iter()
            .any(|c| c.contains("j4::checkLicense")));

        // 3. Querying 1-char `"a"` MUST NOT match `AlphaScreen` or `smali/...` file-path letters!
        let bogus_a = query_symbol_impact(&db, "a").unwrap();
        assert!(
            bogus_a.is_empty(),
            "Short query 'a' must never match file-path substrings: {bogus_a:?}"
        );

        let compact = format_impact_compact("p1::l", &p1_l);
        assert!(compact.contains("=== IMPACT: p1::l (1 symbol matched) ==="));
        assert!(compact.contains("j4::checkLicense"));

        drop(db);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn smali_cross_package_same_short_name_and_method_overloads_never_collide() {
        let tmp =
            std::env::temp_dir().join(format!("libredb_smali_precision_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("smali/com/alpha")).unwrap();
        std::fs::create_dir_all(tmp.join("smali/com/beta")).unwrap();

        std::fs::write(
            tmp.join("smali/com/alpha/p0.smali"),
            r#".class public Lcom/alpha/p0;
.super Ljava/lang/Object;
.method public b(I)Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
.method public b(Ljava/lang/String;)V
    .registers 2
    return-void
.end method
"#,
        )
        .unwrap();

        std::fs::write(
            tmp.join("smali/com/beta/p0.smali"),
            r#".class public Lcom/beta/p0;
.super Ljava/lang/Object;
.method public b(I)Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
"#,
        )
        .unwrap();

        std::fs::write(
            tmp.join("smali/com/alpha/Caller.smali"),
            r#".class public final Lcom/alpha/Caller;
.super Ljava/lang/Object;
.method public static runCheck(Lcom/alpha/p0;)Z
    .registers 3
    const/4 v0, 0x7
    invoke-virtual {p0, v0}, Lcom/alpha/p0;->b(I)Z
    move-result v1
    return v1
.end method
"#,
        )
        .unwrap();

        let db = LibreDb::open(tmp.join("precision.ldb")).unwrap();
        let rep = index_workspace(&db, &tmp, true).unwrap();
        assert_eq!(rep.files_scanned, 3);

        // 1. Exact target `Lcom/alpha/p0;->b(I)Z` MUST have `Lcom/alpha/Caller;->runCheck` as its sole caller!
        let alpha_int = query_symbol_impact(&db, "Lcom/alpha/p0;->b(I)Z").unwrap();
        assert_eq!(alpha_int.len(), 1);
        assert_eq!(alpha_int[0].total_callers, 1);
        assert!(alpha_int[0]
            .callers
            .iter()
            .any(|c| c.contains("com/alpha/Caller::runCheck")));

        // 2. Sibling overload `Lcom/alpha/p0;->b(Ljava/lang/String;)V` MUST have 0 callers!
        let alpha_str = query_symbol_impact(&db, "Lcom/alpha/p0;->b(Ljava/lang/String;)V").unwrap();
        assert_eq!(alpha_str.len(), 1);
        assert_eq!(
            alpha_str[0].total_callers, 0,
            "Unreferenced overload b(Ljava/lang/String;)V must have 0 callers: {:?}",
            alpha_str[0].callers
        );

        // 3. Cross-package `Lcom/beta/p0;->b(I)Z` with identical short class name `p0` and signature `b(I)Z` MUST have 0 callers!
        let beta_int = query_symbol_impact(&db, "Lcom/beta/p0;->b(I)Z").unwrap();
        assert_eq!(beta_int.len(), 1);
        assert_eq!(
            beta_int[0].total_callers, 0,
            "Cross-package Lcom/beta/p0;->b(I)Z must never inherit Lcom/alpha/p0 callers: {:?}",
            beta_int[0].callers
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tentative_edit_discards_aborted_write_and_atomically_promotes_verified_write() {
        let tmp =
            std::env::temp_dir().join(format!("libredb_tentative_edit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::create_dir_all(tmp.join(".agents")).unwrap();

        let target = tmp.join("src/lib.rs");
        let orig_src = b"pub fn verify_token() -> bool {\n    true\n}\n";
        std::fs::write(&target, orig_src).unwrap();

        let db = LibreDb::open(tmp.join(".agents/memory.ldb")).unwrap();
        index_workspace(&db, &tmp, true).unwrap();

        let pre_hash = hash_key(SKELETON_HASH_SEED, orig_src);
        let predicted_post =
            b"// header 1\n// header 2\n// header 3\npub fn verify_token() -> bool {\n    true\n}\n";

        // Case A: Stage `PreToolUse` tentative edit, then simulate an ABORTED/FAILED IDE write (file stays unchanged on disk).
        let (staged, _, _) = stage_tentative_file_edit(
            &db,
            &tmp,
            &target,
            Some(pre_hash),
            predicted_post,
            120,
        )
        .unwrap();
        assert!(staged);

        // Immediate `query_symbol_impact` (without full workspace reindex!) MUST reconcile against disk,
        // discard the unexecuted tentative edit, and report original `[L1-L3]`!
        let after_abort = query_symbol_impact(&db, "verify_token").unwrap();
        assert_eq!(after_abort.len(), 1);
        assert!(
            after_abort[0].contract.contains("[L1-L3]"),
            "Aborted IDE write must never pollute live symbol graph: {}",
            after_abort[0].contract
        );
        assert!(
            db.get_by_key(NodeKind::WorkingSet, "tentative_edit::src/lib.rs")
                .is_err(),
            "Discarded tentative edit must be tombstoned immediately"
        );

        // Case B: Stage `PreToolUse` tentative edit, then perform the actual IDE file write to disk!
        let (staged2, _, _) = stage_tentative_file_edit(
            &db,
            &tmp,
            &target,
            Some(pre_hash),
            predicted_post,
            120,
        )
        .unwrap();
        assert!(staged2);
        std::fs::write(&target, predicted_post).unwrap();

        // Immediate `query_symbol_impact` reconciles against verified disk bytes and promotes `[L4-L6]` in 1 envelope!
        let seq_before = db.stats().unwrap().commit_seq;
        let after_commit = query_symbol_impact(&db, "verify_token").unwrap();
        let seq_after = db.stats().unwrap().commit_seq;
        assert_eq!(
            seq_after - seq_before,
            1,
            "Verified tentative promotion must execute in exactly 1 atomic commit_seq step"
        );
        assert!(
            after_commit[0].contract.contains("[L4-L6]"),
            "Verified edit must promote shifted [L4-L6] span: {}",
            after_commit[0].contract
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn workspace_index_racy_git_fast_path_and_immediate_mutation_detection() {
        let tmp = std::env::temp_dir().join(format!("libredb_racy_idx_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();

        let f_a = tmp.join("src/alpha.rs");
        let f_b = tmp.join("src/beta.rs");
        std::fs::write(&f_a, "pub fn compute_val() -> i32 {\n    10\n}\n").unwrap();
        std::fs::write(&f_b, "pub fn caller_fn() -> i32 {\n    compute_val()\n}\n").unwrap();

        let db = LibreDb::open(tmp.join("idx.ldb")).unwrap();
        let r1 = index_workspace(&db, &tmp, false).unwrap();
        assert_eq!(r1.files_reindexed, 2);

        // Warm scan hits `sys::workspace_graph_state` with 0 reindexed files
        let r2 = index_workspace(&db, &tmp, false).unwrap();
        assert_eq!(r2.files_reindexed, 0);
        assert_eq!(r2.files_unchanged_cached, 2);

        // Immediate sub-millisecond same-byte-length overwrite inside the 2s `racy-git` window MUST be detected!
        std::fs::write(&f_a, "pub fn renamed_val() -> i32 {\n    10\n}\n").unwrap();
        let r3 = index_workspace(&db, &tmp, false).unwrap();
        assert_eq!(
            r3.files_reindexed, 1,
            "Same-length racy overwrite must never serve stale graph state"
        );
        assert!(!query_symbol_impact(&db, "renamed_val").unwrap().is_empty());
        assert!(query_symbol_impact(&db, "compute_val").unwrap().is_empty());

        // Single-file symbol line-shift updates `[Lstart-Lend]` spans in one batch without touching source file
        let shifted = b"// line 1\n// line 2\n// line 3\npub fn renamed_val() -> i32 {\n    10\n}\n";
        let updated_cnt = sync_single_file_symbols(&db, &tmp, &f_a, shifted).unwrap();
        assert_eq!(updated_cnt, 1);
        let imp = query_symbol_impact(&db, "renamed_val").unwrap();
        assert!(
            imp[0].contract.contains("[L4-L6]"),
            "Symbol span must shift immediately to [L4-L6]: {}",
            imp[0].contract
        );

        // File deletion MUST be detected immediately and tombstone orphan symbols
        std::fs::remove_file(&f_a).unwrap();
        let _r4 = index_workspace(&db, &tmp, false).unwrap();
        assert!(
            query_symbol_impact(&db, "renamed_val").unwrap().is_empty(),
            "Deleted file symbols must be tombstoned on next scan"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
