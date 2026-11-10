//! Multi-threaded incremental workspace graph (`WorkspaceGraph`):
//! - Binary-safe directory scanner (skips NUL-byte binaries and build folders like `target/`),
//! - Parallel `FileSkeleton` extraction with 64-bit content-hash skip,
//! - Automatic `Calls` synapse wiring across workspace symbols,
//! - Automatic `Governs` / `CausedBy` causal wiring between `Decision`/`Task` nodes and `Symbol` nodes,
//! - `impact` blast-radius query and surgical `fim_slice` windowing.

use crate::skeleton::{FileSkeleton, SKELETON_KEY_PREFIX};
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
    let mut source_files = Vec::new();
    let mut binary_skipped = 0usize;
    collect_source_files(root, root, &mut source_files, &mut binary_skipped)?;

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
        // Universal binary file guard: any file containing a NUL byte in its first 2 KB is binary!
        let probe_len = raw_bytes.len().min(2048);
        if raw_bytes[..probe_len].contains(&0u8) {
            binary_skipped += 1;
            continue;
        }

        let current_hash = hash_key(99, &raw_bytes);
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

    // Prepare batched writes for all modified skeletons and their symbol contracts.
    let mut prepared: Vec<PreparedWrite> = Vec::new();
    for (idx, pf) in changed_files.iter().enumerate() {
        let skel_bytes = serde_json::to_vec(&pf.skeleton)
            .map_err(|_| LibreDbError::CorruptFormat("skeleton serialize"))?;
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::WorkingSet, skel_bytes)
                .with_key(format!("{SKELETON_KEY_PREFIX}{}", pf.rel_path))
                .with_importance(190),
            idx,
        )?);

        for sym in &pf.skeleton.symbols {
            let sym_key = format!("{}::{}", pf.rel_path, sym.name);
            let doc_part = if sym.doc_summary.is_empty() {
                String::new()
            } else {
                format!(" // {}", sym.doc_summary)
            };
            let body = format!(
                "{} [L{}-L{}] ({}) {}{}",
                pf.rel_path, sym.start_line, sym.end_line, sym.kind, sym.signature, doc_part
            );
            prepared.push(db.prepare(
                WriteRequest::new(NodeKind::Symbol, body.into_bytes())
                    .with_key(sym_key)
                    .with_importance(180),
                idx,
            )?);
        }
    }

    if !prepared.is_empty() {
        db.commit_batch(&prepared)?;
    }

    // Build lookup of all active `NodeKind::Symbol` nodes (`short_name -> Vec<(node_id, rel_path)>`).
    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
    let symbols_indexed = sym_inodes.len();
    let mut by_short_name: HashMap<String, Vec<(u64, String)>> = HashMap::new();
    let mut by_full_key: HashMap<String, u64> = HashMap::new();

    for (ino, key_opt, _) in &sym_inodes {
        if let Some(ref full_k) = key_opt {
            by_full_key.insert(full_k.clone(), ino.node_id);
            if let Some((_, short)) = full_k.rsplit_once("::") {
                if short.len() >= 3 {
                    by_short_name
                        .entry(short.to_owned())
                        .or_default()
                        .push((ino.node_id, full_k.clone()));
                }
            }
        }
    }

    let mut edges: Vec<(u64, EdgeKind, u64, u8)> = Vec::new();
    let existing_call_edges: usize = sym_inodes
        .iter()
        .map(|(_, _, syns)| syns.iter().filter(|s| s.kind == EdgeKind::Calls).count())
        .sum();
    let need_call_pass = force || !changed_files.is_empty() || existing_call_edges == 0;
    let mut call_edges = 0usize;

    // 1. Wire `CallerSymbol --[Calls]--> CalleeSymbol` across workspace files!
    if need_call_pass {
        for (rel_path, skel, text_opt) in &all_skeletons {
            let Some(ref text) = text_opt else { continue };
            let lines: Vec<&str> = text.lines().collect();
            for sym in &skel.symbols {
                let src_key = format!("{rel_path}::{}", sym.name);
                let Some(&src_id) = by_full_key.get(&src_key) else {
                    continue;
                };
                let start_i = sym.start_line.saturating_sub(1);
                let end_i = sym.end_line.min(lines.len());
                if start_i >= end_i {
                    continue;
                }
                let body_slice = lines[start_i..end_i].join("\n");
                let mut seen_targets: HashSet<u64> = HashSet::new();

                for ident in extract_code_identifiers(&body_slice) {
                    if ident == sym.name {
                        continue;
                    }
                    if let Some(targets) = by_short_name.get(&ident) {
                        for &(dst_id, _) in targets {
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
    for kind in [NodeKind::Decision, NodeKind::Task] {
        let gov_inodes = db.list_inodes(Some(kind), false);
        let gov_ids: Vec<u64> = gov_inodes.iter().map(|(i, _, _)| i.node_id).collect();
        let (gov_recs, _) = db.get_many_coalesced(&gov_ids)?;
        for rec in gov_recs {
            let text = String::from_utf8_lossy(&rec.payload);
            for ident in extract_code_identifiers(&text) {
                if ident.len() < 4 {
                    continue;
                }
                if let Some(targets) = by_short_name.get(&ident) {
                    for &(sym_id, _) in targets {
                        edges.push((rec.node_id, EdgeKind::Governs, sym_id, 240));
                        edges.push((sym_id, EdgeKind::CausedBy, rec.node_id, 230));
                        gov_edges += 2;
                    }
                }
            }
        }
    }

    if !edges.is_empty() {
        db.link_batch(&edges)?;
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
    let raw_bytes = std::fs::read(file_path)?;
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
            .find(|s| s.name.to_lowercase() == q_low)
            .or_else(|| skel.symbols.iter().find(|s| s.name.to_lowercase().contains(&q_low)))
            .ok_or_else(|| LibreDbError::KeyNotFound {
                kind: NodeKind::Symbol,
                key: sym_q.to_owned(),
            })?;
        let s = found.start_line.saturating_sub(context_pad).max(1);
        let e = (found.end_line + context_pad).min(total_lines.max(1));
        (s, e, Some(found.name.clone()))
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
        if let Ok(impacts) = query_symbol_impact(db, sname) {
            if let Some(first) = impacts.into_iter().next() {
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

fn collect_source_files(
    root: &Path,
    curr: &Path,
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
            if matches!(
                low.as_str(),
                ".git"
                    | ".agents"
                    | "target"
                    | "node_modules"
                    | ".venv"
                    | "venv"
                    | "dist"
                    | "build"
                    | "out"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".idea"
                    | ".vscode"
            ) {
                continue;
            }
            collect_source_files(root, &p, out, binary_skipped)?;
        } else if p.is_file() {
            if is_known_source_extension(&low) {
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
    [
        ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".dart", ".go", ".c", ".h",
        ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".java", ".kt", ".kts", ".swift", ".smali",
        ".asm", ".s", ".inc", ".dis", ".ps1", ".psm1", ".sql", ".sh", ".bash", ".zsh", ".rb",
        ".php", ".lua", ".zig", ".scala", ".groovy", ".gradle", ".proto",
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
