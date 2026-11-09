//! `libredb-cognitive`: Antigravity's unified cognitive memory & token-conservation engine.
//!
//! Orchestrates:
//! 1. `ReflexEngine` (proactive situational pitfall triggers),
//! 2. `HybridIndex` (stemmed BM25 + 3-gram subwords + bilingual concept bridges),
//! 3. `Inode` Spreading Activation (associative 2-hop graph expansion in RAM),
//! 4. `SessionState` (`Zero-Repeat Delta` per `(conversation_id, epoch)` eliminating duplicate output),
//! 5. `FileSkeleton` (`95-99%` hash-cached code contract compression).

pub mod reflex;
pub mod session;
pub mod skeleton;

pub use reflex::{detect_workspace_markers, FiredReflex, ReflexEngine, ReflexRule};
pub use session::SessionState;
pub use skeleton::{FileSkeleton, SectionSpan, SymbolContract};

use libredb_core::{EdgeKind, LibreDb, NodeFlags, NodeKind, Result};
use libredb_index::HybridIndex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

/// Input query to `CognitiveEngine::pulse`.
#[derive(Debug, Clone)]
pub struct PulseRequest {
    pub query: String,
    pub workspace_dir: Option<PathBuf>,
    pub conversation_id: Option<String>,
    pub epoch: u32,
    pub token_budget: u32,
    pub error_context: Option<String>,
}

impl PulseRequest {
    pub fn new(query: impl Into<String>, token_budget: u32) -> Self {
        Self {
            query: query.into(),
            workspace_dir: None,
            conversation_id: None,
            epoch: 1,
            token_budget,
            error_context: None,
        }
    }
}

/// Freshly hydrated knowledge item delivered in a `PulseResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveredCapsule {
    pub node_id: u64,
    pub kind: NodeKind,
    pub key: Option<String>,
    pub generation: u32,
    pub token_count: u32,
    pub score: f64,
    pub content: String,
}

/// Complete, token-budgeted, session-deduplicated context package produced in a single `pulse` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseResponse {
    pub fired_reflexes: Vec<FiredReflex>,
    pub capsules: Vec<DeliveredCapsule>,
    /// Compact `6-token` delta references for items suppressed because the active session already has them.
    pub already_in_context_stubs: Vec<String>,
    pub tokens_emitted: u32,
    pub tokens_saved_by_delta: u32,
    pub coalesced_io_reads: usize,
}

impl PulseResponse {
    /// Formats the complete `PulseResponse` as a zero-fluff prompt/CLI block.
    pub fn format_compact(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "=== LIBREDB PULSE ({}/{} tok emitted | {} tok saved via Zero-Repeat Delta | {} I/O reads) ===",
            self.tokens_emitted,
            self.tokens_emitted + self.tokens_saved_by_delta,
            self.tokens_saved_by_delta,
            self.coalesced_io_reads
        ));

        for rf in &self.fired_reflexes {
            lines.push(rf.directive.clone());
        }

        if !self.already_in_context_stubs.is_empty() {
            lines.push(format!(
                "[Zero-Repeat Delta]: {}",
                self.already_in_context_stubs.join(" | ")
            ));
        }

        for cap in &self.capsules {
            let k_lbl = cap.key.as_deref().unwrap_or("-");
            lines.push(format!(
                "--- [#{} {}:{} gen={} ~{} tok] ---\n{}",
                cap.node_id,
                cap.kind.as_str(),
                k_lbl,
                cap.generation,
                cap.token_count,
                cap.content.trim()
            ));
        }
        lines.join("\n")
    }
}

/// High-level cognitive facade over `LibreDb`, `HybridIndex`, and `ReflexEngine`.
pub struct CognitiveEngine {
    db: Arc<LibreDb>,
    index: HybridIndex,
    reflexes: ReflexEngine,
}

impl CognitiveEngine {
    pub fn open_db(db: Arc<LibreDb>) -> Result<Self> {
        let index = HybridIndex::build_from_db(&db)?;
        let reflexes = ReflexEngine::load(&db)?;
        Ok(Self {
            db,
            index,
            reflexes,
        })
    }

    pub fn db(&self) -> &Arc<LibreDb> {
        &self.db
    }

    /// Re-synchronizes the in-memory `HybridIndex` and `ReflexEngine` after bulk writes/imports.
    pub fn refresh_indices(&mut self) -> Result<()> {
        self.index = HybridIndex::build_from_db(&self.db)?;
        self.reflexes = ReflexEngine::load(&self.db)?;
        Ok(())
    }

    /// Learns a persistent cross-lingual or conceptual Hebbian association between `cue_phrase`
    /// (in any human language or domain vocabulary) and `target_node_ids`.
    pub fn reinforce_association(
        &mut self,
        cue_phrase: &str,
        target_node_ids: &[u64],
    ) -> Result<usize> {
        self.index
            .reinforce_association(&self.db, cue_phrase, target_node_ids)
    }

    /// Executes a one-shot associative `pulse`:
    /// 1. Fires matching `ReflexEngine` pitfalls,
    /// 2. Seeds initial candidates via `HybridIndex` (`BM25 + 3-grams + concept bridges`),
    /// 3. Propagates 2-hop spreading activation across `Inode` synapses in RAM (`0` disk I/O),
    /// 4. Applies `SessionState` Zero-Repeat Delta filtering (`conversation_id` + `epoch`),
    /// 5. Packs unseen/updated winners strictly within `token_budget` and fetches via coalesced I/O.
    pub fn pulse(&self, req: &PulseRequest) -> Result<PulseResponse> {
        let mut used_tokens = 0u32;
        let mut saved_by_delta = 0u32;
        let mut stubs = Vec::new();

        let mut session = if let Some(ref cid) = req.conversation_id {
            Some(SessionState::load_or_init(&self.db, cid, req.epoch)?)
        } else {
            None
        };

        // 1. Evaluate situational Reflexes first (highest-ROI mistake prevention!).
        let raw_reflexes = self.reflexes.evaluate(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
        );
        let mut fired_reflexes = Vec::new();
        for rf in raw_reflexes {
            let tracking_id = rf.node_id;
            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(tracking_id, rf.generation) {
                    let stub_tok = 5u32;
                    sess.record_suppression(rf.token_count, stub_tok);
                    saved_by_delta += rf.token_count.saturating_sub(stub_tok);
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    stubs.push(format!("reflex:{} unchanged", rf.id));
                    continue;
                }
                sess.mark_delivered(tracking_id, rf.generation);
            }
            if used_tokens.saturating_add(rf.token_count) <= req.token_budget {
                used_tokens += rf.token_count;
                fired_reflexes.push(rf);
            }
        }

        // 2. Hybrid lexical + concept-bridge + trigram seed search (exclude internal cursors/quotas).
        let searchable_kinds = [
            NodeKind::Rule,
            NodeKind::Skill,
            NodeKind::SkillSection,
            NodeKind::Decision,
            NodeKind::Fact,
            NodeKind::Task,
            NodeKind::Symbol,
            NodeKind::WorkingSet,
            NodeKind::Snapshot,
            NodeKind::Handoff,
        ];
        let lexical_hits = self.index.search(&req.query, Some(&searchable_kinds), 24);

        // 3. Spreading activation over in-memory Inode headers (`0` payload reads!).
        let inode_list = self.db.list_inodes(None, false);
        let inode_map: HashMap<u64, (libredb_core::Inode, Option<String>, Vec<libredb_core::Synapse>)> =
            inode_list
                .into_iter()
                .map(|(ino, k, syns)| (ino.node_id, (ino, k, syns)))
                .collect();

        let mut energy_map: HashMap<u64, f64> = HashMap::new();
        let mut queue: VecDeque<(u64, usize, f64)> = VecDeque::new();

        for hit in &lexical_hits {
            energy_map.insert(hit.node_id, hit.score);
            queue.push_back((hit.node_id, 0, hit.score));
        }

        while let Some((curr_id, hop, energy)) = queue.pop_front() {
            if hop >= 2 || energy < 0.25 {
                continue;
            }
            if let Some((_, _, syns)) = inode_map.get(&curr_id) {
                for syn in syns {
                    if syn.kind == EdgeKind::Supersedes {
                        continue;
                    }
                    let next_e = energy * (syn.weight as f64 / 255.0) * 0.55;
                    if next_e >= 0.25 {
                        if let Some((target_ino, _, _)) = inode_map.get(&syn.target_id) {
                            if target_ino.flags.is_live_active()
                                && searchable_kinds.contains(&target_ino.kind)
                            {
                                let slot = energy_map.entry(syn.target_id).or_insert(0.0);
                                if next_e > *slot {
                                    *slot = next_e;
                                    queue.push_back((syn.target_id, hop + 1, next_e));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut ranked: Vec<(u64, f64)> = energy_map.into_iter().collect();
        ranked.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        // Suppress low-relevance tail filler: only consider candidates scoring >= 35% of peak score!
        let peak_score = ranked.first().map_or(0.0, |x| x.1);
        let relevance_floor = (peak_score * 0.35).max(0.80);
        ranked.retain(|&(_, sc)| sc >= relevance_floor);

        // 4. Session Zero-Repeat Delta filtering + token-budget knapsack packing!
        let mut to_hydrate: Vec<(u64, f64)> = Vec::new();
        for (nid, score) in ranked {
            let Some((ino, key_opt, _)) = inode_map.get(&nid) else {
                continue;
            };
            if ino.flags.contains(NodeFlags::TOMBSTONE) || ino.flags.contains(NodeFlags::SUPERSEDED) {
                continue;
            }

            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(nid, ino.generation) {
                    let stub_tok = 6u32;
                    if ino.token_count > stub_tok {
                        sess.record_suppression(ino.token_count, stub_tok);
                        saved_by_delta += ino.token_count - stub_tok;
                    }
                    let k_short = key_opt.as_deref().unwrap_or("-");
                    stubs.push(format!("#{} {}:{} gen={}", nid, ino.kind.as_str(), k_short, ino.generation));
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    continue;
                }
            }

            let tok = ino.token_count.max(1);
            if used_tokens.saturating_add(tok) <= req.token_budget
                || (to_hydrate.is_empty() && fired_reflexes.is_empty() && tok <= req.token_budget)
            {
                used_tokens += tok;
                to_hydrate.push((nid, score));
                if let Some(ref mut sess) = session {
                    sess.mark_delivered(nid, ino.generation);
                }
            }
        }

        // 5. Hydrate ONLY the unseen/updated winning capsules in one coalesced extent read!
        let hydrate_ids: Vec<u64> = to_hydrate.iter().map(|&(id, _)| id).collect();
        let (records, io_reads) = self.db.get_many_coalesced(&hydrate_ids)?;

        let mut capsules = Vec::with_capacity(records.len());
        for (rec, (_, score)) in records.into_iter().zip(to_hydrate.into_iter()) {
            let key = inode_map.get(&rec.node_id).and_then(|(_, k, _)| k.clone());
            capsules.push(DeliveredCapsule {
                node_id: rec.node_id,
                kind: rec.kind,
                key,
                generation: rec.generation,
                token_count: rec.token_count,
                score,
                content: String::from_utf8_lossy(&rec.payload).into_owned(),
            });
        }

        if let Some(ref sess) = session {
            sess.save(&self.db)?;
        }

        Ok(PulseResponse {
            fired_reflexes,
            capsules,
            already_in_context_stubs: stubs,
            tokens_emitted: used_tokens,
            tokens_saved_by_delta: saved_by_delta,
            coalesced_io_reads: io_reads,
        })
    }
}
