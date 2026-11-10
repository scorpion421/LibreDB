//! `OverlayBrain`: Unified dual-layer cognitive memory mounting a global base layer
//! (`customizations.ldb`) underneath a writable project layer (`memory.ldb`).
//!
//! Scores `Inode` candidates across both layers **100% in RAM** and filters via `SessionState`
//! (`Zero-Repeat Delta`) *before* touching disk extents - so already-seen items incur **zero I/O reads**!

use crate::{
    CognitiveEngine, DeliveredCapsule, FiredReflex, PulseRequest, PulseResponse,
    ScoredInodeCandidate, SessionState,
};
use libredb_core::{LibreDb, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const GLOBAL_LAYER_TAG: u64 = 1u64 << 47;

/// Dual-layer cognitive facade uniting global system memory and local workspace memory.
pub struct OverlayBrain {
    global: Option<CognitiveEngine>,
    project: CognitiveEngine,
    last_global_seq: AtomicU64,
    last_project_seq: AtomicU64,
}

impl OverlayBrain {
    pub fn open(global_db: Option<Arc<LibreDb>>, project_db: Arc<LibreDb>) -> Result<Self> {
        if let Some(ref gdb) = global_db {
            gdb.sync_from_disk_if_changed()?;
        }
        project_db.sync_from_disk_if_changed()?;
        let last_global_seq = match &global_db {
            Some(gdb) => gdb.stats()?.commit_seq,
            None => 0,
        };
        let last_project_seq = project_db.stats()?.commit_seq;
        let global = match global_db {
            Some(gdb) => Some(CognitiveEngine::open_db(gdb)?),
            None => None,
        };
        let project = CognitiveEngine::open_db(project_db)?;
        Ok(Self {
            global,
            project,
            last_global_seq: AtomicU64::new(last_global_seq),
            last_project_seq: AtomicU64::new(last_project_seq),
        })
    }

    pub fn project_db(&self) -> &Arc<LibreDb> {
        self.project.db()
    }

    /// Refreshes indices across threads and OS processes if on-disk or in-memory `commit_seq` changed.
    pub fn refresh_if_needed(&mut self) -> Result<()> {
        if let Some(ref mut g) = self.global {
            g.db().sync_from_disk_if_changed()?;
            let g_seq = g.db().stats()?.commit_seq;
            if g_seq != self.last_global_seq.load(Ordering::Relaxed) {
                g.refresh_indices()?;
                self.last_global_seq.store(g_seq, Ordering::Relaxed);
            }
        }
        self.project.db().sync_from_disk_if_changed()?;
        let p_seq = self.project.db().stats()?.commit_seq;
        if p_seq != self.last_project_seq.load(Ordering::Relaxed) {
            self.project.refresh_indices()?;
            self.last_project_seq.store(p_seq, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Executes a federated, session-deduplicated `pulse` across both Project and Global layers.
    ///
    /// - Candidate scoring and `Zero-Repeat Delta` deduplication run **entirely in RAM (`0` disk reads)**,
    /// - Only unseen/updated winning `NodeId`s are hydrated via coalesced extent reads,
    /// - `SessionState` is persisted to disk **only if new nodes were actually delivered**!
    pub fn pulse(&self, req: &PulseRequest) -> Result<PulseResponse> {
        if self.global.is_none() {
            return self.project.pulse(req);
        }
        let global_eng = self.global.as_ref().unwrap();

        let mut session = if let Some(ref cid) = req.conversation_id {
            Some(SessionState::load_or_init(self.project.db(), cid, req.epoch)?)
        } else {
            None
        };
        let mut session_dirty = false;

        let mut used_tokens = 0u32;
        let mut saved_by_delta = 0u32;
        let mut stubs = Vec::new();
        let mut fired_reflexes: Vec<FiredReflex> = Vec::new();

        // 1. Evaluate reflexes across both layers in RAM (`0` disk reads).
        let proj_rf = self.project.evaluate_reflexes(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
        );
        let glob_rf = global_eng.evaluate_reflexes(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
        );

        for (is_global, rf) in proj_rf
            .into_iter()
            .map(|r| (false, r))
            .chain(glob_rf.into_iter().map(|r| (true, r)))
        {
            let ns_id = if is_global {
                GLOBAL_LAYER_TAG | rf.node_id
            } else {
                rf.node_id
            };
            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(ns_id, rf.generation) {
                    let stub_tok = 5u32;
                    sess.record_suppression(rf.token_count, stub_tok);
                    saved_by_delta += rf.token_count.saturating_sub(stub_tok);
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    stubs.push(format!("reflex:{} unchanged", rf.id));
                    continue;
                }
                sess.mark_delivered(ns_id, rf.generation);
                session_dirty = true;
            }
            if used_tokens.saturating_add(rf.token_count) <= req.token_budget {
                used_tokens += rf.token_count;
                fired_reflexes.push(rf);
            }
        }

        // 2. Score candidates across both layers 100% in RAM (`0` payload disk I/O!).
        let proj_cands = self.project.score_candidates_in_ram(&req.query);
        let glob_cands = global_eng.score_candidates_in_ram(&req.query);

        let mut merged: Vec<(bool, ScoredInodeCandidate)> =
            Vec::with_capacity(proj_cands.len() + glob_cands.len());
        for mut c in proj_cands {
            c.score *= 1.15;
            merged.push((false, c));
        }
        for c in glob_cands {
            merged.push((true, c));
        }
        merged.sort_by(|a, b| {
            b.1.score
                .partial_cmp(&a.1.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.node_id.cmp(&b.1.node_id))
        });

        let peak = merged.first().map_or(0.0, |x| x.1.score);
        let floor = (peak * 0.35).max(0.80);

        // 3. Filter via `SessionState` BEFORE hydrating any extents from disk!
        let mut to_fetch_proj: Vec<ScoredInodeCandidate> = Vec::new();
        let mut to_fetch_glob: Vec<ScoredInodeCandidate> = Vec::new();
        // Preserve display rank order `(is_global, local_idx)`
        let mut order_plan: Vec<(bool, usize)> = Vec::new();

        for (is_global, cand) in merged {
            if cand.score < floor {
                continue;
            }
            let ns_id = if is_global {
                GLOBAL_LAYER_TAG | cand.node_id
            } else {
                cand.node_id
            };
            let layer_prefix = if is_global { "global" } else { "proj" };

            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(ns_id, cand.generation) {
                    let stub_tok = 6u32;
                    if cand.token_count > stub_tok {
                        sess.record_suppression(cand.token_count, stub_tok);
                        saved_by_delta += cand.token_count - stub_tok;
                    }
                    let k_lbl = cand.key.as_deref().unwrap_or("-");
                    stubs.push(format!(
                        "{}#{} {}:{} gen={}",
                        layer_prefix,
                        cand.node_id,
                        cand.kind.as_str(),
                        k_lbl,
                        cand.generation
                    ));
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    continue;
                }
            }

            let tok = cand.token_count.max(1);
            if used_tokens.saturating_add(tok) <= req.token_budget
                || (order_plan.is_empty() && fired_reflexes.is_empty() && tok <= req.token_budget)
            {
                used_tokens += tok;
                if let Some(ref mut sess) = session {
                    sess.mark_delivered(ns_id, cand.generation);
                    session_dirty = true;
                }
                if is_global {
                    let idx = to_fetch_glob.len();
                    to_fetch_glob.push(cand);
                    order_plan.push((true, idx));
                } else {
                    let idx = to_fetch_proj.len();
                    to_fetch_proj.push(cand);
                    order_plan.push((false, idx));
                }
            }
        }

        // 4. Hydrate ONLY unseen winning capsules via coalesced extent reads (`0` reads if all were in context!).
        let proj_ids: Vec<u64> = to_fetch_proj.iter().map(|c| c.node_id).collect();
        let glob_ids: Vec<u64> = to_fetch_glob.iter().map(|c| c.node_id).collect();

        let (proj_recs, proj_io) = self.project.db().get_many_coalesced(&proj_ids)?;
        let (glob_recs, glob_io) = global_eng.db().get_many_coalesced(&glob_ids)?;

        let mut selected = Vec::with_capacity(order_plan.len());
        for (is_global, idx) in order_plan {
            if is_global {
                let cand = &to_fetch_glob[idx];
                let rec = &glob_recs[idx];
                let key = Some(match &cand.key {
                    Some(k) => format!("global::{k}"),
                    None => "global".to_owned(),
                });
                selected.push(DeliveredCapsule {
                    node_id: rec.node_id,
                    kind: rec.kind,
                    key,
                    generation: rec.generation,
                    token_count: rec.token_count,
                    score: cand.score,
                    content: String::from_utf8_lossy(&rec.payload).into_owned(),
                });
            } else {
                let cand = &to_fetch_proj[idx];
                let rec = &proj_recs[idx];
                let key = Some(match &cand.key {
                    Some(k) => format!("proj::{k}"),
                    None => "proj".to_owned(),
                });
                selected.push(DeliveredCapsule {
                    node_id: rec.node_id,
                    kind: rec.kind,
                    key,
                    generation: rec.generation,
                    token_count: rec.token_count,
                    score: cand.score,
                    content: String::from_utf8_lossy(&rec.payload).into_owned(),
                });
            }
        }

        // Only write `SessionState` to disk if `delivered_generations` actually gained a new item!
        if session_dirty {
            if let Some(ref sess) = session {
                let prev_seq = self.last_project_seq.load(Ordering::Relaxed);
                sess.save(self.project.db())?;
                let after_seq = self.project.db().stats()?.commit_seq;
                if after_seq == prev_seq + 1 {
                    self.last_project_seq.store(after_seq, Ordering::Relaxed);
                }
            }
        }

        Ok(PulseResponse {
            fired_reflexes,
            capsules: selected,
            already_in_context_stubs: stubs,
            tokens_emitted: used_tokens,
            tokens_saved_by_delta: saved_by_delta,
            coalesced_io_reads: proj_io + glob_io,
        })
    }
}
