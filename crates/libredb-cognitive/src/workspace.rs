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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
}

/// Blast-radius impact and causal governance report for a located symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolImpactReport {
    pub node_id: u64,
    pub symbol_key: String,
    pub contract: String,
    /// Symbols in the workspace that call or reference this symbol.
    pub callers: Vec<String>,
    /// Symbols that this symbol calls or depends on.
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

/// Incrementally indexes all non-binary source files under `root` into `db`, wiring both
/// code call-graph synapses (`Calls`) and causal architecture synapses (`Decision <-> Symbol`).
pub fn index_workspace(db: &LibreDb, root: &Path, force: bool) -> Result<WorkspaceIndexReport> {
    let scan_cfg = WorkspaceScanConfig::from_db_and_root(db, root);
    let mut source_files = Vec::new();
    let mut binary_skipped = 0usize;
    collect_source_files(root, root, &scan_cfg, &mut source_files, &mut binary_skipped)?;

    let mut unchanged = 0usize;
    let mut reindexed = 0usize;

    struct ParsedFile {
        rel_path: String,
        skeleton: FileSkeleton,
    }

    let mut changed_files: Vec<ParsedFile> = Vec::new();
    let mut all_skeletons: Vec<(String, FileSkeleton, Option<String>)> = Vec::new();

    for (abs_path, rel_path) in source_files {
        let raw_bytes = match std::fs::read(&abs_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if raw_bytes.len() > scan_cfg.max_file_bytes {
            continue;
        }
        // Universal binary file guard: any file containing a NUL byte in its first 2 KB is binary!
        let probe_len = raw_bytes.len().min(2048);
        if raw_bytes[..probe_len].contains(&0u8) {
            binary_skipped += 1;
            continue;
        }

        let current_hash = hash_key(SKELETON_HASH_SEED, &raw_bytes);
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
        let skel = FileSkeleton::extract(rel_path.clone(), &raw_text);
        reindexed += 1;
        all_skeletons.push((rel_path.clone(), skel.clone(), Some(raw_text)));
        changed_files.push(ParsedFile {
            rel_path,
            skeleton: skel,
        });
    }

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
    for (_, _, text_opt) in &all_skeletons {
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
        .map(|(_, _, syns)| syns.iter().filter(|s| s.kind == EdgeKind::Calls).count())
        .sum();
    let need_call_pass =
        force || !changed_files.is_empty() || had_stale_tombstones || existing_call_edges == 0;
    let mut call_edges = 0usize;

    // 1. Wire `CallerSymbol --[Calls]--> CalleeSymbol` across workspace files!
    if need_call_pass {
        for (rel_path, skel, text_opt) in &all_skeletons {
            let Some(ref text) = text_opt else { continue };
            let lines: Vec<&str> = text.lines().collect();
            for (sym_idx, src_key) in compute_file_symbol_keys(rel_path, skel) {
                let sym = &skel.symbols[sym_idx];
                let Some(&src_id) = by_full_key.get(&src_key) else {
                    continue;
                };
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

                // Stage A: Exact qualified calls (`Type::method`, `Type.method`, `Self::method`, `self.method(`)
                for qcall in sites.qualified_calls {
                    if qcall == own_qname {
                        continue;
                    }
                    if let Some(targets) = by_qualified_name.get(&qcall) {
                        for &(dst_id, _) in targets {
                            if dst_id != src_id && seen_targets.insert(dst_id) {
                                edges.push((src_id, EdgeKind::Calls, dst_id, 220));
                                call_edges += 1;
                            }
                        }
                    }
                }

                // Stage B1: Dynamic receiver method calls (`expr.method(`) - resolved when unambiguous in the
                // workspace (`targets.len() == 1`) and salient by corpus Document Frequency (`<= 25%` of files).
                for mcall in sites.receiver_methods {
                    if mcall == sym.name {
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
                            edges.push((rec.node_id, EdgeKind::Governs, sym_id, 245));
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
                                edges.push((rec.node_id, EdgeKind::Governs, sym_id, 240));
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
                                edges.push((rec.node_id, EdgeKind::Governs, sym_id, 238));
                                edges.push((sym_id, EdgeKind::CausedBy, rec.node_id, 228));
                                gov_edges += 2;
                            }
                        }
                    }
                }
            }
        }
    }

    let mut scoped_sources = active_sym_ids;
    scoped_sources.extend_from_slice(&active_gov_ids);
    if need_call_pass {
        db.sync_edges_for_kinds(
            &scoped_sources,
            &[EdgeKind::Calls, EdgeKind::Governs, EdgeKind::CausedBy],
            &edges,
        )?;
    } else {
        db.sync_edges_for_kinds(
            &scoped_sources,
            &[EdgeKind::Governs, EdgeKind::CausedBy],
            &edges,
        )?;
    }

    Ok(WorkspaceIndexReport {
        files_scanned,
        files_unchanged_cached: unchanged,
        files_reindexed: reindexed,
        binary_files_skipped: binary_skipped,
        symbols_indexed,
        call_synapses_wired: call_edges,
        governance_synapses_wired: gov_edges,
    })
}

/// Locates symbols matching `symbol_query` and computes their bidirectional blast-radius (`callers`,
/// `callees`) plus any governing architectural `Decision`/`Task` capsules in `O(N_symbols)` RAM time.
pub fn query_symbol_impact(db: &LibreDb, symbol_query: &str) -> Result<Vec<SymbolImpactReport>> {
    let q_low = symbol_query.to_lowercase();
    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);

    // Build reverse `Calls` lookup (`callee_id -> Vec<caller_id>`) from in-memory Inode synapses (`0` disk I/O!).
    let mut reverse_calls: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut matched_ids: Vec<(u64, String)> = Vec::new();

    for (ino, key_opt, syns) in &sym_inodes {
        let k = key_opt.clone().unwrap_or_default();
        if k.to_lowercase().contains(&q_low) {
            matched_ids.push((ino.node_id, k));
        }
        for syn in syns {
            if syn.kind == EdgeKind::Calls {
                reverse_calls.entry(syn.target_id).or_default().push(ino.node_id);
            }
        }
    }

    let mut reports = Vec::new();
    for (nid, sym_key) in matched_ids.into_iter().take(15) {
        let rec = db.get(nid)?;
        let contract = String::from_utf8_lossy(&rec.payload).into_owned();

        let caller_ids = reverse_calls.get(&nid).cloned().unwrap_or_default();
        let (caller_recs, _) = db.get_many_coalesced(&caller_ids)?;
        let callers: Vec<String> = caller_recs
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
            callers,
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
    let raw_bytes = std::fs::read(file_path).map_err(|e| {
        LibreDbError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", file_path.display()),
        ))
    })?;
    let text = String::from_utf8_lossy(&raw_bytes);
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let label = file_path.to_string_lossy().replace('\\', "/");

    let (skel, _) = FileSkeleton::index_or_get_cached(db, file_path, Some(&label))?;

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
        governing_decisions: governing,
    })
}

struct WorkspaceScanConfig {
    extra_extensions: Vec<String>,
    ignore_dirs: HashSet<String>,
    max_file_bytes: usize,
}

impl WorkspaceScanConfig {
    fn from_db_and_root(db: &LibreDb, root: &Path) -> Self {
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
            .unwrap_or(4 * 1024 * 1024);

        Self {
            extra_extensions,
            ignore_dirs,
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
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let low = name.to_ascii_lowercase();

        if p.is_dir() {
            if cfg.ignore_dirs.contains(&low) {
                continue;
            }
            collect_source_files(root, &p, cfg, out, binary_skipped)?;
        } else if p.is_file() {
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
        // Skip line comments (`//`) so prose words inside comments never synthesize call edges!
        if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Skip string literals (`"..."`) so error strings and SQL/JSON text do not synthesize call edges!
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

        let preceded_by_access = (i >= 1 && bytes[i - 1] == b'.')
            || (i >= 2 && bytes[i - 2] == b':' && bytes[i - 1] == b':')
            || (i >= 2 && bytes[i - 2] == b'-' && bytes[i - 1] == b'>');

        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let s1 = i;
            i += 1;
            while i < n && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let lhs = &text[s1..i];

            // Check if `lhs` is followed by `::`, `.`, or `->`
            let sep_info: Option<(usize, u8)> = if i + 1 < n && bytes[i] == b':' && bytes[i + 1] == b':' {
                Some((i + 2, b':'))
            } else if i + 1 < n && bytes[i] == b'-' && bytes[i + 1] == b'>' {
                Some((i + 2, b'.'))
            } else if i < n && bytes[i] == b'.' {
                Some((i + 1, b'.'))
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

                    let resolved_owner: Option<(&str, bool)> = if lhs == "Self" {
                        self_container.map(|c| (c, false))
                    } else if matches!(lhs, "self" | "this") {
                        self_container.map(|c| (c, true))
                    } else if lhs.len() >= 2 && lhs.as_bytes()[0].is_ascii_uppercase() {
                        Some((lhs, false))
                    } else {
                        None
                    };

                    if let Some((owner_type, req_paren)) = resolved_owner {
                        if owner_type.len() >= 3 && !preceded_by_access {
                            bare_calls_and_types.insert(owner_type.to_owned());
                        }
                        if rhs.len() >= 2 && (!req_paren || has_call_paren) {
                            qualified_calls.insert(format!("{owner_type}::{rhs}"));
                        }
                        // Advance to `sep_end` ONLY if `rhs` itself chains another `::` or `.` (e.g. `Mod::Type::method`);
                        // otherwise advance completely past `rhs` (`j`) so `rhs` is NEVER re-scanned as a bare identifier!
                        if j < n && (bytes[j] == b'.' || (j + 1 < n && bytes[j] == b':' && bytes[j + 1] == b':')) {
                            i = sep_end;
                        } else {
                            i = j;
                        }
                        continue;
                    } else if sep_kind == b'.' && has_call_paren && rhs.len() >= 3 {
                        // Lowercase receiver call (`var.method(`): record in `receiver_methods`!
                        receiver_methods.insert(rhs.to_owned());
                        if j < n && bytes[j] == b'.' {
                            i = sep_end;
                        } else {
                            i = j;
                        }
                        continue;
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
