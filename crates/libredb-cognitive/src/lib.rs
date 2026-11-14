//! `libredb-cognitive`: Antigravity's unified cognitive memory & token-conservation engine.
//!
//! Orchestrates:
//! 1. `ReflexEngine` (proactive situational pitfall triggers),
//! 2. `HybridIndex` (language-agnostic BM25 + IDF-weighted Unicode 3-grams + Hebbian concept bridges),
//! 3. `Inode` Spreading Activation (associative 2-hop graph expansion in RAM),
//! 4. `SessionState` (`Zero-Repeat Delta` per `(conversation_id, epoch)` eliminating duplicate output),
//! 5. `FileSkeleton` (`95-99%` hash-cached code contract compression).

pub mod guardrail;
pub mod learning;
pub mod overlay;
pub mod reflex;
pub mod session;
pub mod skeleton;
pub mod transcript;
pub mod workspace;

pub use guardrail::{
    audit_workspace_guardrails, audit_workspace_guardrails_with_prefixes,
    check_command_guardrails, check_text_guardrails, check_text_guardrails_with_mode,
    check_text_guardrails_with_options, is_sensitive_staged_file, is_test_or_scratch_path,
    GuardrailAuditReport, GuardrailViolation,
};
pub use learning::{
    format_learning_report, is_banal_syntax_error, learn_explicit_error_resolution,
    learning_state_report, record_error_cue, record_search_miss_cue_with_source,
    ErrorPitfallBook, LearnedPitfallEntry, LearningCounters, LearningStateReport, MissCueSource,
    PendingErrorCue, ACTIVE_PITFALL_MIN_CONFIDENCE, ERROR_PITFALL_BOOK_KEY, PENDING_ERROR_CUES_KEY,
};
pub use overlay::OverlayBrain;
pub use reflex::{
    compute_smoothed_utility, detect_workspace_markers, FiredReflex, ReflexEngine, ReflexRule,
    ReflexStatus, ReflexUtilityBook, ReflexUtilityStats, REFLEX_UTILITY_BOOK_KEY,
};
pub use session::SessionState;
pub use skeleton::{
    diff_symbol_body_tokens, extract_ordered_symbol_body_tokens, extract_symbol_body_tokens,
    FileSkeleton, SectionSpan, SymbolContract,
};
pub use transcript::{
    create_subagent_handoff, execute_atomic_batch, is_compaction_checkpoint_line,
    sync_transcript_epoch, AtomicBatchReport, AtomicBatchSpec, TaskCapsule, TranscriptEpochState,
};
pub use workspace::{
    extract_fim_slice, format_fim_batch_compact, format_impact_batch_compact,
    format_impact_compact, format_locate_compact, has_project_root_marker, index_workspace,
    index_workspace_with_exclusions, locate_symbols, query_symbol_impact,
    query_symbols_impact_batch, reconcile_tentative_edits, record_search_miss_cue,
    stage_tentative_file_edit, sync_single_file_symbols, CoChangePartner, FimSliceBundle,
    FimSliceRequest, PendingMissCue, SymbolCueBridgeBook, SymbolImpactReport, SymbolLocationMatch,
    TentativeFileEdit, WorkspaceIndexReport, MAX_BATCH_FIM_SLICES, MAX_BATCH_SYMBOL_QUERIES,
    MAX_LOCATE_MATCHES_PER_QUERY, PENDING_MISS_CUES_KEY, SYMBOL_CUE_BRIDGES_KEY,
    TENTATIVE_EDIT_PREFIX,
};

use libredb_core::{EdgeKind, LibreDb, NodeFlags, NodeKind, Result};
use libredb_index::HybridIndex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

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
            if rf.directive.starts_with("[REFLEX") {
                lines.push(rf.directive.clone());
            } else {
                lines.push(format!("[REFLEX {}]: {}", rf.id, rf.directive));
            }
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

/// Lightweight RAM-only scored candidate produced before touching any payload extents on disk.
#[derive(Debug, Clone)]
pub struct ScoredInodeCandidate {
    pub node_id: u64,
    pub kind: NodeKind,
    pub key: Option<String>,
    pub generation: u32,
    pub token_count: u32,
    pub score: f64,
    /// `true` if the candidate was surfaced by a calibrated learned bridge (`BridgeScorer`), which
    /// carries its own absolute acceptance threshold and is exempt from relative peak floors.
    pub via_bridge: bool,
}

/// Ranked `NodeKind::SkillSection` capsule returned by `CognitiveEngine::slice_skill_sections`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSectionSliceMatch {
    pub node_id: u64,
    pub key: String,
    pub skill_name: String,
    pub section_title: String,
    pub score: f64,
    pub token_count: u32,
    pub full_skill_tokens: u32,
    pub content: String,
}

/// High-level cognitive facade over `LibreDb`, `HybridIndex`, and `ReflexEngine`.
pub struct CognitiveEngine {
    db: Arc<LibreDb>,
    index: HybridIndex,
    reflexes: ReflexEngine,
    bridge_scorer: OnceLock<Option<learning::BridgeScorer>>,
}

impl CognitiveEngine {
    pub fn open_db(db: Arc<LibreDb>) -> Result<Self> {
        let index = HybridIndex::load_or_build(&db)?;
        let reflexes = ReflexEngine::load(&db)?;
        Ok(Self {
            db,
            index,
            reflexes,
            bridge_scorer: OnceLock::new(),
        })
    }

    pub fn db(&self) -> &Arc<LibreDb> {
        &self.db
    }

    /// Learned situational reflexes of this layer (used by `OverlayBrain` for cross-layer anchors).
    pub fn reflex_engine(&self) -> &ReflexEngine {
        &self.reflexes
    }

    /// Re-synchronizes the in-memory `HybridIndex` and `ReflexEngine` incrementally after writes.
    pub fn refresh_indices(&mut self) -> Result<()> {
        self.index.reconcile_in_ram(&self.db)?;
        self.reflexes = ReflexEngine::load(&self.db)?;
        self.bridge_scorer = OnceLock::new();
        Ok(())
    }

    /// Persists the compiled inverted index snapshot inside `.ldb` for sub-5ms cold CLI startup.
    pub fn save_index_snapshot(&mut self) -> Result<u64> {
        self.index.save_snapshot(&self.db)
    }

    /// Evaluates learned situational reflexes in RAM (`0` disk I/O).
    pub fn evaluate_reflexes(
        &self,
        workspace_dir: Option<&std::path::Path>,
        query: &str,
        error_context: Option<&str>,
    ) -> Vec<FiredReflex> {
        self.reflexes.evaluate(workspace_dir, query, error_context)
    }

    /// Computes ranked `Inode` candidates via `HybridIndex` + 2-hop synapse spreading activation
    /// **100% in RAM (`0` payload disk reads, `O(K)` hash lookups!)** so `SessionState` (`Zero-Repeat Delta`)
    /// can filter already-delivered items before touching a single payload byte on disk!
    pub fn score_candidates_in_ram(&self, query: &str) -> Vec<ScoredInodeCandidate> {
        let searchable_kinds = [
            NodeKind::Rule,
            NodeKind::Skill,
            NodeKind::SkillSection,
            NodeKind::Decision,
            NodeKind::Fact,
            NodeKind::Task,
            NodeKind::TaskVerification,
            NodeKind::Symbol,
            NodeKind::WorkingSet,
            NodeKind::Snapshot,
            NodeKind::CompactionCheckpoint,
            NodeKind::Handoff,
        ];
        let mut lexical_hits = self.index.search(query, Some(&searchable_kinds), 24);
        if lexical_hits.is_empty() {
            // Fallback for pure code-symbol queries when no prose capsule matched:
            // match active `NodeKind::Symbol` keys directly in RAM (`0` disk I/O, `0` index bloat).
            let q_tokens = libredb_index::segment_universal_tokens(query);
            for (sym_id, sym_score) in self.db.match_active_keys_by_kind(NodeKind::Symbol, &q_tokens, 8) {
                lexical_hits.push(libredb_index::SearchHit {
                    node_id: sym_id,
                    kind: NodeKind::Symbol,
                    key: None,
                    score: sym_score,
                    matched_features: Vec::new(),
                });
            }
        }
        // Learned `Search-Miss -> Verified-Edit` bridges form an independent, always-on channel on a
        // calibrated absolute scale, so weak 3-gram noise hits can never mask them.
        let mut bridged_ids: HashSet<u64> = HashSet::new();
        if let Some(scorer) = self
            .bridge_scorer
            .get_or_init(|| learning::BridgeScorer::load(&self.db))
        {
            for (sym_id, bridge_score) in scorer.score_query(query).into_iter().take(8) {
                bridged_ids.insert(sym_id);
                if let Some(hit) = lexical_hits.iter_mut().find(|h| h.node_id == sym_id) {
                    hit.score = hit.score.max(bridge_score);
                } else {
                    lexical_hits.push(libredb_index::SearchHit {
                        node_id: sym_id,
                        kind: NodeKind::Symbol,
                        key: None,
                        score: bridge_score,
                        matched_features: Vec::new(),
                    });
                }
            }
        }
        if lexical_hits.is_empty() {
            return Vec::new();
        }

        let mut meta_cache: HashMap<
            u64,
            (
                libredb_core::Inode,
                Option<String>,
                Vec<libredb_core::Synapse>,
            ),
        > = HashMap::with_capacity(64);
        let mut energy_map: HashMap<u64, f64> = HashMap::with_capacity(64);
        let mut queue: VecDeque<(u64, usize, f64)> = VecDeque::with_capacity(64);

        for hit in &lexical_hits {
            if let Some(meta) = self.db.get_inode_meta(hit.node_id) {
                meta_cache.insert(hit.node_id, meta);
                energy_map.insert(hit.node_id, hit.score);
                queue.push_back((hit.node_id, 0, hit.score));
            }
        }

        while let Some((curr_id, hop, energy)) = queue.pop_front() {
            if hop >= 2 || energy < 0.25 {
                continue;
            }
            let syns = match meta_cache.get(&curr_id) {
                Some((_, _, s)) => s.clone(),
                None => continue,
            };
            let d_out = syns
                .iter()
                .filter(|s| s.kind != EdgeKind::Supersedes)
                .count() as f64;
            let fan_denom = 1.0 + 0.35 * (1.0 + d_out).ln();

            for syn in syns {
                if syn.kind == EdgeKind::Supersedes {
                    continue;
                }
                let edge_alpha = match syn.kind {
                    EdgeKind::Governs | EdgeKind::CausedBy | EdgeKind::Verifies => 0.65,
                    EdgeKind::Calls | EdgeKind::DependsOn | EdgeKind::Inherits => 0.50,
                    EdgeKind::RelatedTo | EdgeKind::HasSection | EdgeKind::UsesSkill => 0.45,
                    _ => 0.35,
                };
                let next_e = energy * (syn.weight as f64 / 255.0) * (edge_alpha / fan_denom);
                if next_e >= 0.25 {
                    if !meta_cache.contains_key(&syn.target_id) {
                        if let Some(m) = self.db.get_inode_meta(syn.target_id) {
                            meta_cache.insert(syn.target_id, m);
                        }
                    }
                    if let Some((target_ino, _, _)) = meta_cache.get(&syn.target_id) {
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

        let mut out: Vec<ScoredInodeCandidate> = energy_map
            .into_iter()
            .filter_map(|(nid, score)| {
                let (ino, key_opt, _) = meta_cache.get(&nid)?;
                if ino.flags.contains(NodeFlags::TOMBSTONE)
                    || ino.flags.contains(NodeFlags::SUPERSEDED)
                {
                    return None;
                }
                let kind_mult = memory_kind_priority_multiplier(ino.kind, ino.flags);
                Some(ScoredInodeCandidate {
                    node_id: nid,
                    kind: ino.kind,
                    key: key_opt.clone(),
                    generation: ino.generation,
                    token_count: ino.token_count.max(1),
                    score: score * kind_mult,
                    via_bridge: bridged_ids.contains(&nid),
                })
            })
            .collect();

        out.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });

        let peak_score = out.first().map_or(0.0, |x| x.score);
        let relevance_floor = (peak_score * 0.35).max(0.80);
        out.retain(|c| c.score >= relevance_floor || c.via_bridge);
        out
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
    /// 2. Scores `Inode` candidates via `HybridIndex` + 2-hop spreading activation in RAM (`0` disk I/O),
    /// 3. Applies `SessionState` Zero-Repeat Delta filtering (`conversation_id` + `epoch`),
    /// 4. Packs unseen/updated winners strictly within `token_budget` and fetches via coalesced I/O.
    pub fn pulse(&self, req: &PulseRequest) -> Result<PulseResponse> {
        let mut used_tokens = 0u32;
        let mut saved_by_delta = 0u32;
        let mut stubs = Vec::new();

        let mut session = if let Some(ref cid) = req.conversation_id {
            Some(SessionState::load_or_init(&self.db, cid, req.epoch)?)
        } else {
            None
        };
        let mut session_dirty = false;

        // 1. Evaluate situational Reflexes first (highest-ROI mistake prevention!) and capture any
        // non-banal observed error context into the procedural error-recovery cue buffer without
        // self-refuting an active `pitfall::` reflex that is being recalled here.
        let raw_reflexes = self.reflexes.evaluate(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
        );
        let pitfall_recalled = raw_reflexes.iter().any(|r| r.id.starts_with("pitfall::"));
        if !pitfall_recalled {
            if let Some(err_str) = req
                .error_context
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let _ = learning::record_error_cue(&self.db, err_str, None);
            }
        }
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
                session_dirty = true;
            }
            if used_tokens.saturating_add(rf.token_count) <= req.token_budget {
                used_tokens += rf.token_count;
                fired_reflexes.push(rf);
            }
        }

        // 2. Score candidates 100% in RAM (`0` payload disk reads!).
        let ranked = self.score_candidates_in_ram(&req.query);
        if ranked.is_empty() && fired_reflexes.is_empty() {
            let _ = learning::record_search_miss_cue_with_source(
                &self.db,
                &req.query,
                learning::MissCueSource::Pulse,
            );
        }

        // 3. Session Zero-Repeat Delta filtering + token-budget knapsack packing!
        let mut to_hydrate: Vec<ScoredInodeCandidate> = Vec::new();
        for cand in ranked {
            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(cand.node_id, cand.generation) {
                    let stub_tok = 6u32;
                    if cand.token_count > stub_tok {
                        sess.record_suppression(cand.token_count, stub_tok);
                        saved_by_delta += cand.token_count - stub_tok;
                    }
                    let k_short = cand.key.as_deref().unwrap_or("-");
                    stubs.push(format!(
                        "#{} {}:{} gen={}",
                        cand.node_id,
                        cand.kind.as_str(),
                        k_short,
                        cand.generation
                    ));
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    continue;
                }
            }

            let tok = cand.token_count.max(1);
            if used_tokens.saturating_add(tok) <= req.token_budget
                || (to_hydrate.is_empty() && fired_reflexes.is_empty() && tok <= req.token_budget)
            {
                used_tokens += tok;
                if let Some(ref mut sess) = session {
                    sess.mark_delivered(cand.node_id, cand.generation);
                    session_dirty = true;
                }
                to_hydrate.push(cand);
            }
        }

        // 4. Hydrate ONLY the unseen/updated winning capsules in one coalesced extent read!
        let hydrate_ids: Vec<u64> = to_hydrate.iter().map(|c| c.node_id).collect();
        let (records, io_reads) = self.db.get_many_coalesced(&hydrate_ids)?;

        let mut capsules = Vec::with_capacity(records.len());
        for (rec, cand) in records.into_iter().zip(to_hydrate.into_iter()) {
            capsules.push(DeliveredCapsule {
                node_id: rec.node_id,
                kind: rec.kind,
                key: cand.key,
                generation: rec.generation,
                token_count: rec.token_count,
                score: cand.score,
                content: String::from_utf8_lossy(&rec.payload).into_owned(),
            });
        }

        if session_dirty {
            if let Some(ref sess) = session {
                sess.save(&self.db)?;
            }
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

    /// Ranks active `NodeKind::SkillSection` capsules via `HybridIndex` (`BM25` + Unicode 3-grams)
    /// and optional `skill_filter`, returning the top `top_k` micro-sections with parent skill token baselines.
    pub fn slice_skill_sections(
        &self,
        query: &str,
        skill_filter: Option<&str>,
        top_k: usize,
    ) -> Result<Vec<SkillSectionSliceMatch>> {
        let cap = top_k.clamp(1, 16);
        let prefix_low = skill_filter.map(|s| format!("{}::", s.trim().to_ascii_lowercase()));
        let mut hits = self
            .index
            .search(query, Some(&[NodeKind::SkillSection]), (cap * 6).max(24));

        if let Some(ref pfx) = prefix_low {
            hits.retain(|h| {
                h.key
                    .as_deref()
                    .is_some_and(|k| k.to_ascii_lowercase().starts_with(pfx))
            });
        }

        if hits.is_empty() {
            let q_low = query.trim().to_ascii_lowercase();
            if !q_low.is_empty() {
                for (ino, k_opt, _) in self.db.list_inodes(Some(NodeKind::SkillSection), false) {
                    if let Some(k) = k_opt {
                        let kl = k.to_ascii_lowercase();
                        if let Some(ref pfx) = prefix_low {
                            if !kl.starts_with(pfx) {
                                continue;
                            }
                        }
                        if kl.contains(&q_low) {
                            hits.push(libredb_index::SearchHit {
                                node_id: ino.node_id,
                                kind: NodeKind::SkillSection,
                                key: Some(k),
                                score: 1.0,
                                matched_features: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        hits.truncate(cap);
        if hits.is_empty() {
            return Ok(Vec::new());
        }

        let ids: Vec<u64> = hits.iter().map(|h| h.node_id).collect();
        let (recs, _) = self.db.get_many_coalesced(&ids)?;
        let mut full_tok_cache: HashMap<String, u32> = HashMap::new();
        let mut out = Vec::with_capacity(recs.len());

        for (hit, rec) in hits.into_iter().zip(recs.into_iter()) {
            let key = hit.key.unwrap_or_else(|| format!("node_{}", rec.node_id));
            let (skill_name, section_title) = key
                .split_once("::")
                .map(|(s, t)| (s.to_owned(), t.to_owned()))
                .unwrap_or_else(|| (key.clone(), String::new()));
            let full_skill_tokens = *full_tok_cache
                .entry(skill_name.clone())
                .or_insert_with(|| {
                    self.db
                        .get_by_key(NodeKind::Generic, &format!("skill_full::{skill_name}"))
                        .map(|r| r.token_count.max(((r.payload.len() + 3) / 4) as u32))
                        .unwrap_or(rec.token_count)
                });
            out.push(SkillSectionSliceMatch {
                node_id: rec.node_id,
                key,
                skill_name,
                section_title,
                score: hit.score,
                token_count: rec.token_count.max(1),
                full_skill_tokens,
                content: String::from_utf8_lossy(&rec.payload).into_owned(),
            });
        }

        Ok(out)
    }
}

#[inline]
fn memory_kind_priority_multiplier(kind: NodeKind, flags: NodeFlags) -> f64 {
    let pinned = flags.contains(NodeFlags::PINNED);
    match kind {
        NodeKind::Rule
        | NodeKind::Decision
        | NodeKind::Fact
        | NodeKind::SkillSection
        | NodeKind::Task => {
            if pinned {
                1.08
            } else {
                1.00
            }
        }
        NodeKind::Symbol | NodeKind::Skill | NodeKind::TaskVerification => 0.95,
        NodeKind::Snapshot
        | NodeKind::CompactionCheckpoint
        | NodeKind::Handoff
        | NodeKind::WorkingSet => {
            if pinned {
                1.00
            } else {
                0.78
            }
        }
        _ => 0.90,
    }
}
