//! O(1) Transcript Compaction Epoch Detector (`detect_transcript_epoch`) and Atomic Episodic
//! Task/Fact/Decision/Handoff Board (`MemoryBoard`).

use libredb_core::{EdgeKind, LibreDb, LibreDbError, NodeKind, PreparedWrite, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Incremental cursor tracking `transcript.jsonl` byte offsets and `/compact` epochs inside `.ldb`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscriptEpochState {
    pub conversation_id: String,
    pub last_byte_offset: u64,
    pub checkpoint_count: u32,
    /// `1 + checkpoint_count` - increments automatically whenever Antigravity compacts context!
    pub active_epoch: u32,
}

/// Returns true if a single JSONL line from `transcript.jsonl` represents a genuine
/// Antigravity context compaction checkpoint (`"type": "CHECKPOINT"` or a `USER_INPUT`
/// step whose `content` begins with the context summary header), ignoring any mentions
/// of those strings inside model thinking, tool call arguments, or `read_file` outputs.
pub fn is_compaction_checkpoint_line(line: &str) -> bool {
    let summary_tag = concat!("<CONTEXT", "_SUMMARY>");
    if !line.contains("CHECKPOINT") && !line.contains(summary_tag) {
        return false;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
        let step_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if step_type == "CHECKPOINT" {
            return true;
        }
        if step_type == "USER_INPUT" {
            if let Some(content) = val.get("content").and_then(|v| v.as_str()) {
                if content.trim_start().starts_with(summary_tag) {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

/// Inspects an Antigravity `transcript.jsonl` incrementally from `last_byte_offset` (`O(delta_bytes)`!)
/// to detect `/compact` checkpoints automatically without false positives from tool outputs or thinking.
pub fn sync_transcript_epoch(
    db: &LibreDb,
    conversation_id: &str,
    transcript_jsonl: &Path,
) -> Result<u32> {
    let cursor_key = format!("sys::transcript_epoch::{conversation_id}");
    let mut state = match db.get_by_key(NodeKind::TranscriptCursor, &cursor_key) {
        Ok(rec) => serde_json::from_slice::<TranscriptEpochState>(&rec.payload)
            .map_err(|_| LibreDbError::CorruptFormat("corrupt transcript_epoch json"))?,
        Err(LibreDbError::KeyNotFound { .. }) => TranscriptEpochState {
            conversation_id: conversation_id.to_owned(),
            last_byte_offset: 0,
            checkpoint_count: 0,
            active_epoch: 1,
        },
        Err(other) => return Err(other),
    };

    if !transcript_jsonl.exists() {
        return Ok(state.active_epoch.max(1));
    }

    let mut file = File::open(transcript_jsonl)?;
    let file_len = file.metadata()?.len();
    if file_len < state.last_byte_offset {
        // Transcript was truncated/recreated; reset offset safely.
        state.last_byte_offset = 0;
        state.checkpoint_count = 0;
    }

    if file_len == state.last_byte_offset {
        return Ok(state.active_epoch.max(1));
    }

    file.seek(SeekFrom::Start(state.last_byte_offset))?;
    let mut delta_bytes = Vec::with_capacity((file_len - state.last_byte_offset) as usize);
    file.read_to_end(&mut delta_bytes)?;
    let delta_str = String::from_utf8_lossy(&delta_bytes);

    let mut added_checkpoints = 0u32;
    for line in delta_str.lines() {
        if is_compaction_checkpoint_line(line) {
            added_checkpoints += 1;
        }
    }

    state.last_byte_offset = file_len;
    state.checkpoint_count += added_checkpoints;
    state.active_epoch = 1 + state.checkpoint_count;

    if let Ok(encoded) = serde_json::to_vec(&state) {
        db.put(
            WriteRequest::new(NodeKind::TranscriptCursor, encoded)
                .with_key(cursor_key)
                .with_importance(32),
        )?;
    }

    Ok(state.active_epoch)
}

/// Structured task record stored natively as `NodeKind::Task`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCapsule {
    pub title: String,
    pub status: String,
    pub priority: String,
    pub notes: String,
}

/// Input specification for a single atomic `execute_batch` call (`< 2 ms` single `fsync`).
#[derive(Debug, Clone, Default)]
pub struct AtomicBatchSpec {
    /// `(key, value)` facts (`Supersedes` prior value automatically).
    pub facts: Vec<(String, String)>,
    /// `(title, rationale_body)` architectural decisions (`Pinned` + auto-governs matching symbols).
    pub decisions: Vec<(String, String)>,
    /// `(task_key, title, status, priority)` task upserts.
    pub tasks: Vec<(String, String, String, String)>,
    /// Optional milestone snapshot summary.
    pub snapshot: Option<String>,
}

/// Summary returned after committing an `AtomicBatchSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicBatchReport {
    pub nodes_committed: usize,
    pub assigned_node_ids: Vec<u64>,
    pub governance_edges_wired: usize,
}

/// Commits multiple facts, decisions, tasks, and snapshots in ONE atomic `fsync` transaction
/// and automatically wires `Governs` synapses from new decisions/tasks to matching code symbols!
pub fn execute_atomic_batch(db: &LibreDb, spec: &AtomicBatchSpec) -> Result<AtomicBatchReport> {
    let mut prepared: Vec<PreparedWrite> = Vec::new();
    let mut decision_indices: Vec<(usize, String)> = Vec::new();

    for (k, v) in &spec.facts {
        let idx = prepared.len();
        let body = format!("{k} = {v}");
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Fact, body.into_bytes())
                .with_key(k.clone())
                .with_importance(200),
            idx,
        )?);
    }

    for (title, body) in &spec.decisions {
        let idx = prepared.len();
        let full = format!("[Decision: {title}]\n{body}");
        decision_indices.push((idx, full.clone()));
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Decision, full.into_bytes())
                .with_key(title.clone())
                .with_importance(235)
                .with_pinned(true),
            idx,
        )?);
    }

    for (tkey, title, status, prio) in &spec.tasks {
        let idx = prepared.len();
        let formatted = format!("[Task {tkey} | {status} | {prio}]: {title}");
        decision_indices.push((idx, formatted.clone()));
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Task, formatted.into_bytes())
                .with_key(format!("task::{tkey}"))
                .with_importance(210),
            idx,
        )?);
    }

    if let Some(ref snap_txt) = spec.snapshot {
        let idx = prepared.len();
        prepared.push(db.prepare(
            WriteRequest::new(NodeKind::Snapshot, snap_txt.as_bytes().to_vec())
                .with_importance(175),
            idx,
        )?);
    }

    if prepared.is_empty() {
        return Ok(AtomicBatchReport {
            nodes_committed: 0,
            assigned_node_ids: Vec::new(),
            governance_edges_wired: 0,
        });
    }

    let ids = db.commit_batch(&prepared)?;

    // Auto-wire `Decision/Task --[Governs]--> Symbol` against existing workspace symbols!
    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
    let mut edges = Vec::new();
    if !sym_inodes.is_empty() && !decision_indices.is_empty() {
        for (b_idx, text) in &decision_indices {
            let gov_id = ids[*b_idx];
            let text_low = text.to_lowercase();
            for (s_ino, s_key_opt, _) in &sym_inodes {
                if let Some(ref sk) = s_key_opt {
                    if let Some((_, short_name)) = sk.rsplit_once("::") {
                        if short_name.len() >= 4 && text_low.contains(&short_name.to_lowercase()) {
                            edges.push((gov_id, EdgeKind::Governs, s_ino.node_id, 240));
                            edges.push((s_ino.node_id, EdgeKind::CausedBy, gov_id, 230));
                        }
                    }
                }
            }
        }
    }

    let gov_cnt = if edges.is_empty() {
        0
    } else {
        db.link_batch(&edges)?
    };
    let _ = db.maybe_auto_compact();

    Ok(AtomicBatchReport {
        nodes_committed: ids.len(),
        assigned_node_ids: ids,
        governance_edges_wired: gov_cnt,
    })
}

/// Creates a compact, deterministic subagent handoff capsule (`Delegates -> Task`) containing only
/// active facts and governing architectural decisions without transcript bloat.
pub fn create_subagent_handoff(
    db: &LibreDb,
    handoff_id: &str,
    task_key: &str,
    target_role: &str,
    instructions: &str,
) -> Result<(u64, String)> {
    let task_rec = db.get_by_key(NodeKind::Task, &format!("task::{task_key}"))?;
    let task_text = String::from_utf8_lossy(&task_rec.payload);

    let fact_inodes = db.list_inodes(Some(NodeKind::Fact), false);
    let recent_fact_ids: Vec<u64> = fact_inodes
        .iter()
        .rev()
        .take(6)
        .map(|(i, _, _)| i.node_id)
        .collect();
    let (fact_recs, _) = db.get_many_coalesced(&recent_fact_ids)?;

    let dec_inodes = db.list_inodes(Some(NodeKind::Decision), false);
    let recent_dec_ids: Vec<u64> = dec_inodes
        .iter()
        .rev()
        .take(4)
        .map(|(i, _, _)| i.node_id)
        .collect();
    let (dec_recs, _) = db.get_many_coalesced(&recent_dec_ids)?;

    let mut block = format!(
        "=== SUBAGENT HANDOFF: {handoff_id} -> [{target_role}] ===\nActive Task: {task_text}\nInstructions: {instructions}\n"
    );
    if !fact_recs.is_empty() {
        block.push_str("Active Facts:\n");
        for f in &fact_recs {
            block.push_str(&format!("  * {}\n", String::from_utf8_lossy(&f.payload)));
        }
    }
    if !dec_recs.is_empty() {
        block.push_str("Architectural Invariants:\n");
        for d in &dec_recs {
            let one_line = String::from_utf8_lossy(&d.payload)
                .lines()
                .collect::<Vec<_>>()
                .join(" | ");
            block.push_str(&format!("  * {one_line}\n"));
        }
    }

    let h_id = db.put(
        WriteRequest::new(NodeKind::Handoff, block.as_bytes().to_vec())
            .with_key(handoff_id.to_owned())
            .with_importance(205)
            .with_synapses(vec![libredb_core::Synapse::new(
                EdgeKind::Delegates,
                240,
                task_rec.node_id,
            )
            .map_err(|e| LibreDbError::NodeIdOverflow(match e {
                LibreDbError::NodeIdOverflow(v) => v,
                _ => 0,
            }))?]),
    )?;

    Ok((h_id, block))
}
