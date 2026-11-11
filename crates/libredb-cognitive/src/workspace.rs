//! Multi-threaded incremental workspace graph (`WorkspaceGraph`):
//! - Binary-safe directory scanner (skips NUL-byte binaries and build folders like `target/`),
//! - Parallel `FileSkeleton` extraction with 64-bit content-hash skip,
//! - Automatic `Calls` synapse wiring across workspace symbols,
//! - Automatic `Governs` / `CausedBy` causal wiring between `Decision`/`Task` nodes and `Symbol` nodes,
//! - `impact` blast-radius query and surgical `fim_slice` windowing.

use crate::skeleton::{FileSkeleton, SKELETON_HASH_SEED, SKELETON_KEY_PREFIX};
use libredb_core::crc::hash_key;
use libredb_core::{EdgeKind, LibreDb, LibreDbError, NodeKind, PreparedWrite, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Internal non-sealed cache key storing `(len, mtime_ns, content_hash)` per workspace file
/// plus governance fingerprint for `< 2 ms` `racy-git`-safe incremental skip.
pub const WORKSPACE_GRAPH_STATE_KEY: &str = "sys::workspace_graph_state";
const WORKSPACE_GRAPH_STATE_VERSION: u32 = 2;
const RACY_SUBSEC_WINDOW_NS: u128 = 50_000_000;
const RACY_COARSE_WINDOW_NS: u128 = 2_000_000_000;

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

fn current_unix_ns() -> u128 {
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

/// Updates `skeleton::<rel_path>` (`NodeKind::WorkingSet`) and all `NodeKind::Symbol` `[Lstart-Lend]`
/// contracts for a single edited source file in one atomic `commit_batch` (`< 2 ms`, `0` source-file
/// disk writes, `0` mutation of `hmac-sha256:v4` sealed cognitive nodes).
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

    let rel_path = target_file
        .strip_prefix(ws_root)
        .ok()
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .or_else(|| {
            let root_canon = std::fs::canonicalize(ws_root).ok()?;
            let parent_canon = std::fs::canonicalize(target_file.parent()?).ok()?;
            let joined = parent_canon.join(target_file.file_name()?);
            joined
                .strip_prefix(&root_canon)
                .ok()
                .map(|r| r.to_string_lossy().replace('\\', "/"))
        })
        .unwrap_or_else(|| target_file.to_string_lossy().replace('\\', "/"));
    if rel_path.is_empty() || rel_path.starts_with("..") {
        return Ok(0);
    }

    let skel_key = format!("{SKELETON_KEY_PREFIX}{rel_path}");
    let new_hash = hash_key(SKELETON_HASH_SEED, post_edit_bytes);
    if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &skel_key) {
        if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
            if cached.content_hash == new_hash {
                return Ok(0);
            }
        }
    }

    let new_skel = FileSkeleton::extract_from_bytes(rel_path.clone(), post_edit_bytes);
    let file_prefix = format!("{rel_path}::");

    // Capture existing symbol IDs & outgoing synapses for `rel_path` (keyed by `(base_sym, ordinal)`)
    // so even overloaded methods keep their outgoing `Calls`/`DependsOn`/`CausedBy` edges across shifts.
    let mut old_by_ord: HashMap<(String, usize), Vec<libredb_core::Synapse>> = HashMap::new();
    let mut old_ord_counts: HashMap<String, usize> = HashMap::new();
    let mut existing_file_syms: Vec<(u64, String)> = Vec::new();
    for (ino, key_opt, syns) in db.list_inodes(Some(NodeKind::Symbol), false) {
        if let Some(full_k) = key_opt {
            if full_k.starts_with(&file_prefix) {
                let base_k = full_k.split('@').next().unwrap_or("").to_owned();
                let ord = *old_ord_counts.entry(base_k.clone()).and_modify(|c| *c += 1).or_insert(0);
                old_by_ord.insert((base_k, ord), syns);
                existing_file_syms.push((ino.node_id, full_k));
            }
        }
    }

    let mut prepared: Vec<PreparedWrite> = Vec::with_capacity(1 + new_skel.symbols.len());
    let skel_bytes = serde_json::to_vec(&new_skel)
        .map_err(|_| LibreDbError::CorruptFormat("skeleton serialize"))?;
    prepared.push(db.prepare(
        WriteRequest::new(NodeKind::WorkingSet, skel_bytes)
            .with_key(skel_key)
            .with_importance(190),
        0,
    )?);

    let sym_keys = compute_file_symbol_keys(&rel_path, &new_skel);
    let mut new_key_set: HashSet<String> = HashSet::with_capacity(sym_keys.len());
    let mut new_ord_counts: HashMap<String, usize> = HashMap::new();
    let mut preserved_synapses_per_slot: Vec<Vec<libredb_core::Synapse>> =
        Vec::with_capacity(sym_keys.len());

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
        let base_k = sym_key.split('@').next().unwrap_or(&sym_key).to_owned();
        let ord = *new_ord_counts.entry(base_k.clone()).and_modify(|c| *c += 1).or_insert(0);
        let prior_syns = old_by_ord.remove(&(base_k, ord)).unwrap_or_default();
        preserved_synapses_per_slot.push(prior_syns);
        new_key_set.insert(sym_key.clone());
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Symbol, body.into_bytes())
                .with_key(sym_key)
                .with_importance(180),
            slot_i + 1,
        )?);
    }

    let stale_ids: Vec<u64> = existing_file_syms
        .into_iter()
        .filter_map(|(nid, k)| (!new_key_set.contains(&k)).then_some(nid))
        .collect();
    if !stale_ids.is_empty() {
        db.deprecate_nodes(&stale_ids)?;
    }

    let committed_ids = db.commit_batch(&prepared)?;
    let updated_sym_count = committed_ids.len().saturating_sub(1);

    // Re-attach preserved outgoing synapses (`Calls`, `DependsOn`, `CausedBy`) to the new symbol IDs.
    let mut restored_edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    for (slot_i, syns) in preserved_synapses_per_slot.into_iter().enumerate() {
        if let Some(&new_id) = committed_ids.get(slot_i + 1) {
            for s in syns {
                if matches!(s.kind, EdgeKind::Calls | EdgeKind::DependsOn | EdgeKind::CausedBy) {
                    restored_edges.push((new_id, s.kind, s.target_id, s.weight));
                }
            }
        }
    }
    if !restored_edges.is_empty() {
        db.link_batch(&restored_edges)?;
    }

    // Invalidate `sys::workspace_graph_state` so the next workspace-wide `impact`/`fim` refreshes
    // inter-file call edges cleanly while single-file symbol `[Lstart-Lend]` spans are already exact.
    let _ = db.deprecate_key(NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY);

    Ok(updated_sym_count)
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
    let scan_cfg = WorkspaceScanConfig::from_db_and_root(db, root, excluded_subroots);
    let mut source_files = Vec::new();
    let mut walk_binary_skipped = 0usize;
    collect_source_files(root, root, &scan_cfg, &mut source_files, &mut walk_binary_skipped)?;

    let scan_root_key = normalize_scan_boundary_key(root);
    let mut exclusions_sorted: Vec<String> = scan_cfg.excluded_subroots.iter().cloned().collect();
    exclusions_sorted.sort();
    let gov_fp = compute_governance_fingerprint(db);
    let scan_started_ns = current_unix_ns();

    // `racy-git`-safe fast-path (Git `is_racy_timestamp` clean/smudge design):
    // Verify `symlink_metadata` `(len, mtime_ns)` on every candidate file. Any file whose `mtime_ns`
    // fell inside the OS clock granularity window (`50 ms` on sub-second NTFS/ext4/APFS, `2 s` on
    // coarse integer-second filesystems) relative to `state.indexed_at_ns` is re-hashed via `FNV-1a`
    // to catch sub-millisecond same-size edits; once `scan_started_ns` has safely advanced past all
    // smudged `mtime_ns` values, `state.indexed_at_ns` is un-smudged once so all subsequent warm
    // `index` / `impact` / `fim` calls complete in `< 2 ms` with `0` file opens and `0` DB writes!
    if !force {
        if let Ok(state_rec) = db.get_by_key(NodeKind::Generic, WORKSPACE_GRAPH_STATE_KEY) {
            if let Ok(mut state) = serde_json::from_slice::<WorkspaceGraphState>(&state_rec.payload) {
                if state.version == WORKSPACE_GRAPH_STATE_VERSION
                    && state.skeleton_seed == SKELETON_HASH_SEED
                    && state.scan_root_key == scan_root_key
                    && state.exclusions_sorted == exclusions_sorted
                    && state.gov_fingerprint == gov_fp
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
                        }
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

        if !force {
            if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &skel_key) {
                if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                    if cached.content_hash == current_hash {
                        unchanged += 1;
                        let text = String::from_utf8_lossy(&raw_bytes).into_owned();
                        all_skeletons.push((rel_path, cached, Some(text)));
                        continue;
                    }
                }
            }
        }

        let raw_text = String::from_utf8_lossy(&raw_bytes).into_owned();
        let skel = FileSkeleton::extract_from_bytes(rel_path.clone(), &raw_bytes);
        reindexed += 1;
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
                    if let Some(sup_targets) =
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
                        if let Some(sups) = type_supertypes.get(cont) {
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

                // Stage A: Exact qualified calls (`Type::method`, `Type.method`, `Lpkg/Cls;->method(`, `Self::method`)
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

    let graph_state = WorkspaceGraphState {
        version: WORKSPACE_GRAPH_STATE_VERSION,
        skeleton_seed: SKELETON_HASH_SEED,
        indexed_at_ns: scan_started_ns,
        scan_root_key,
        exclusions_sorted,
        gov_fingerprint: gov_fp,
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

fn compact_contract_ref(contract: &str) -> &str {
    if let Some(close_paren_idx) = contract.find(") ") {
        contract[..=close_paren_idx].trim()
    } else {
        contract.trim()
    }
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
    }
    out
}

/// Locates symbols matching `symbol_query` and computes their bidirectional blast-radius (`callers`,
/// `implementors`, `callees`) plus governing architectural `Decision`/`Task` capsules in `O(N_symbols)` RAM time.
pub fn query_symbol_impact(db: &LibreDb, symbol_query: &str) -> Result<Vec<SymbolImpactReport>> {
    let raw_q = symbol_query.trim().trim_start_matches("::");
    if raw_q.is_empty() {
        return Ok(Vec::new());
    }
    // Normalize `Cls.m` / `Cls->m` / `Lpkg/Cls;->m` into canonical `Cls::m` when qualified:
    let normalized_q: String = if let Some((_, after_semi)) = raw_q.split_once(";->") {
        let before = raw_q.split(";->").next().unwrap_or("");
        let cls = before.trim_start_matches('L').rsplit('/').next().unwrap_or(before);
        let m = after_semi.split(['(', ':']).next().unwrap_or(after_semi);
        format!("{cls}::{m}")
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
        let Some((_, raw_sym_part)) = full_k.split_once("::") else { continue };
        let sym_part = raw_sym_part.split('@').next().unwrap_or(raw_sym_part);
        let short_name = sym_part.rsplit_once("::").map_or(sym_part, |(_, m)| m);

        if is_qualified_query {
            let suffix = format!("::{normalized_q}");
            if sym_part == normalized_q || sym_part.ends_with(&suffix) {
                tier1_exact.push((ino.node_id, full_k.clone()));
            } else {
                let sym_low = sym_part.to_lowercase();
                let suffix_low = format!("::{q_low}");
                if sym_low == q_low || sym_low.ends_with(&suffix_low) {
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
        } else if q_low.len() >= 3 && sym_part.to_lowercase().contains(&q_low) {
            // Never match against `file_part` so short queries (`"a"`, `"i4"`) never pull unrelated files!
            tier3_substr.push((ino.node_id, full_k.clone()));
        }
    }

    let mut matched_ids = if !tier1_exact.is_empty() {
        tier1_exact
    } else if !tier2_ci.is_empty() {
        tier2_ci
    } else {
        tier3_substr
    };

    // Rank ambiguous matches (e.g. R8 short method `"a"` across 80 classes) by incoming caller fan-in
    // descending so the highest-impact call-graph hubs always surface first!
    matched_ids.sort_by(|(id_a, k_a), (id_b, k_b)| {
        let ca = reverse_calls.get(id_a).map_or(0, Vec::len)
            + reverse_deps.get(id_a).map_or(0, Vec::len);
        let cb = reverse_calls.get(id_b).map_or(0, Vec::len)
            + reverse_deps.get(id_b).map_or(0, Vec::len);
        cb.cmp(&ca).then_with(|| k_a.cmp(k_b))
    });

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
    let raw_bytes = crate::skeleton::read_bounded_source_file(file_path)?;
    let text = String::from_utf8_lossy(&raw_bytes);
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let label = file_path.to_string_lossy().replace('\\', "/");

    let (skel, _) = FileSkeleton::index_or_get_cached_bytes(db, label.clone(), &raw_bytes)?;

    let (win_start, win_end, matched_sym) = if let Some(sym_q) = symbol_name {
        let q_low = sym_q.to_lowercase();
        let found = skel
            .symbols
            .iter()
            .find(|s| s.qualified_name().to_lowercase() == q_low || s.name.to_lowercase() == q_low)
            .or_else(|| {
                skel.symbols.iter().find(|s| {
                    s.qualified_name().to_lowercase().contains(&q_low)
                        || s.name.to_lowercase().contains(&q_low)
                })
            })
            .ok_or_else(|| LibreDbError::KeyNotFound {
                kind: NodeKind::Symbol,
                key: sym_q.to_owned(),
            })?;
        let s = found.start_line.saturating_sub(context_pad).max(1);
        let e = (found.end_line + context_pad).min(total_lines.max(1));
        (s, e, Some(found.qualified_name()))
    } else if let Some(ln) = center_line {
        let c = ln.clamp(1, total_lines.max(1));
        let s = c.saturating_sub(context_pad).max(1);
        let e = (c + context_pad).min(total_lines.max(1));
        (s, e, None)
    } else {
        (1, total_lines.min(50).max(1), None)
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
    if let Some(ref sname) = matched_sym {
        let scoped_q = format!("::{sname}");
        if let Ok(impacts) = query_symbol_impact(db, &scoped_q) {
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

fn compute_file_symbol_keys(rel_path: &str, skel: &FileSkeleton) -> Vec<(usize, String)> {
    let mut out = Vec::with_capacity(skel.symbols.len());
    let mut seen_keys: HashSet<String> = HashSet::with_capacity(skel.symbols.len());
    for (idx, sym) in skel.symbols.iter().enumerate() {
        if sym.kind == "impl" {
            continue;
        }
        let qname = sym.qualified_name();
        let base_key = format!("{rel_path}::{qname}");
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
    qualified_calls: HashSet<String>,
    receiver_methods: HashSet<String>,
    bare_calls_and_types: HashSet<String>,
}

/// Language-agnostic syntactic call-site classifier with zero hardcoded stopwords:
/// 1. `qualified_calls`: `UpperType::method`, `UpperType.method`, `Self::method`, `self.method(`, `this.method(`
///    (never leaked into unqualified buckets, so `Vec::new()` or `File::open()` never collide with user methods).
/// 2. `receiver_methods`: `expr.method(` on runtime variables or chained expressions.
/// 3. `bare_calls_and_types`: standalone `func(`, `macro!(`, or `UpperCamel` type references not preceded by `.` or `::`.
fn extract_call_sites(text: &str, self_container: Option<&str>) -> CallSiteBuckets {
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

        // 6. Dalvik / Smali member descriptors: `L<pkg/Cls>;-><method>(` or `L<pkg/Cls>;-><field>:`
        // Supports obfuscated lowercase R8 class names (`p1`, `j4`, `i4`) and 1-char member names (`l`, `a`, `b`)!
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
            if k > i + 1
                && k + 3 < n
                && bytes[k] == b';'
                && bytes[k + 1] == b'-'
                && bytes[k + 2] == b'>'
            {
                let desc = &text[i + 1..k];
                let cls_short = desc.rsplit('/').next().unwrap_or(desc);
                let m_start = k + 3;
                if bytes[m_start] == b'<' {
                    // `<init>` or `<clinit>`: advance past closing `>` without polluting method call graph
                    let mut m_end = m_start + 1;
                    while m_end < n && bytes[m_end] != b'>' && bytes[m_end] != b'\n' {
                        m_end += 1;
                    }
                    if cls_short.len() >= 2 {
                        bare_calls_and_types.insert(cls_short.to_owned());
                    }
                    i = (m_end + 1).min(n);
                    continue;
                }
                let mut m_end = m_start;
                while m_end < n
                    && (bytes[m_end].is_ascii_alphanumeric()
                        || bytes[m_end] == b'_'
                        || bytes[m_end] == b'$')
                {
                    m_end += 1;
                }
                if m_end > m_start && m_end < n && (bytes[m_end] == b'(' || bytes[m_end] == b':') {
                    let member = &text[m_start..m_end];
                    if !cls_short.is_empty() && !member.is_empty() {
                        qualified_calls.insert(format!("{cls_short}::{member}"));
                        if cls_short.len() >= 2 {
                            bare_calls_and_types.insert(cls_short.to_owned());
                        }
                    }
                    i = m_end;
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
