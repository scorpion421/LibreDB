//! `OverlayBrain`: Unified dual-layer cognitive memory mounting a global base layer
//! (`customizations.ldb`) underneath a writable project layer (`memory.ldb`).
//!
//! Queries both layers simultaneously in a single `< 5 ms` pass while maintaining isolated
//! `SessionState` (`Zero-Repeat Delta`) namespaces so global and project `NodeId`s never collide.

use crate::{
    CognitiveEngine, DeliveredCapsule, FiredReflex, PulseRequest, PulseResponse, SessionState,
};
use libredb_core::{LibreDb, Result};
use std::sync::Arc;

const GLOBAL_LAYER_TAG: u64 = 1u64 << 47;

/// Dual-layer cognitive facade uniting global system memory and local workspace memory.
pub struct OverlayBrain {
    global: Option<CognitiveEngine>,
    project: CognitiveEngine,
    last_global_seq: u64,
    last_project_seq: u64,
}

impl OverlayBrain {
    pub fn open(global_db: Option<Arc<LibreDb>>, project_db: Arc<LibreDb>) -> Result<Self> {
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
            last_global_seq,
            last_project_seq,
        })
    }

    /// Refreshes indices only if `commit_seq` changed since last check (`< 1 microsecond` when clean!).
    pub fn refresh_if_needed(&mut self) -> Result<()> {
        if let Some(ref mut g) = self.global {
            let g_seq = g.db().stats()?.commit_seq;
            if g_seq != self.last_global_seq {
                g.refresh_indices()?;
                self.last_global_seq = g_seq;
            }
        }
        let p_seq = self.project.db().stats()?.commit_seq;
        if p_seq != self.last_project_seq {
            self.project.refresh_indices()?;
            self.last_project_seq = p_seq;
        }
        Ok(())
    }

    /// Executes a federated, session-deduplicated `pulse` across both Project and Global layers,
    /// persisting `SessionState` inside the writable `project` database.
    pub fn pulse(&self, req: &PulseRequest) -> Result<PulseResponse> {
        if self.global.is_none() {
            return self.project.pulse(req);
        }
        let global_eng = self.global.as_ref().unwrap();

        // Run stateless candidate gathering on both layers (with `conversation_id = None`),
        // then apply unified `SessionState` Zero-Repeat Delta filtering & budget packing across the union!
        let mut raw_req = req.clone();
        raw_req.conversation_id = None;
        raw_req.token_budget = req.token_budget.saturating_mul(2).max(1200);

        let proj_raw = self.project.pulse(&raw_req)?;
        let glob_raw = global_eng.pulse(&raw_req)?;

        let mut session = if let Some(ref cid) = req.conversation_id {
            Some(SessionState::load_or_init(self.project.db(), cid, req.epoch)?)
        } else {
            None
        };

        let mut used_tokens = 0u32;
        let mut saved_by_delta = 0u32;
        let mut stubs = Vec::new();
        let mut fired_reflexes: Vec<FiredReflex> = Vec::new();

        // 1. Merge project + global reflexes (project reflexes first).
        for (is_global, rf) in proj_raw
            .fired_reflexes
            .into_iter()
            .map(|r| (false, r))
            .chain(glob_raw.fired_reflexes.into_iter().map(|r| (true, r)))
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
            }
            if used_tokens.saturating_add(rf.token_count) <= req.token_budget {
                used_tokens += rf.token_count;
                fired_reflexes.push(rf);
            }
        }

        // 2. Merge and rank capsules across both layers (boost local project context slightly by `1.15x`
        //    so concrete project facts/decisions take priority over generic global docs at equal score).
        let mut merged_caps: Vec<(bool, DeliveredCapsule)> = Vec::with_capacity(
            proj_raw.capsules.len() + glob_raw.capsules.len(),
        );
        for mut c in proj_raw.capsules {
            c.score *= 1.15;
            merged_caps.push((false, c));
        }
        for c in glob_raw.capsules {
            merged_caps.push((true, c));
        }
        merged_caps.sort_by(|a, b| {
            b.1.score
                .partial_cmp(&a.1.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let peak = merged_caps.first().map_or(0.0, |x| x.1.score);
        let floor = (peak * 0.35).max(0.80);

        let mut selected: Vec<DeliveredCapsule> = Vec::new();
        for (is_global, mut cap) in merged_caps {
            if cap.score < floor {
                continue;
            }
            let ns_id = if is_global {
                GLOBAL_LAYER_TAG | cap.node_id
            } else {
                cap.node_id
            };
            let layer_prefix = if is_global { "global" } else { "proj" };

            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(ns_id, cap.generation) {
                    let stub_tok = 6u32;
                    if cap.token_count > stub_tok {
                        sess.record_suppression(cap.token_count, stub_tok);
                        saved_by_delta += cap.token_count - stub_tok;
                    }
                    let k_lbl = cap.key.as_deref().unwrap_or("-");
                    stubs.push(format!(
                        "{}#{} {}:{} gen={}",
                        layer_prefix,
                        cap.node_id,
                        cap.kind.as_str(),
                        k_lbl,
                        cap.generation
                    ));
                    used_tokens = used_tokens.saturating_add(stub_tok);
                    continue;
                }
            }

            let tok = cap.token_count.max(1);
            if used_tokens.saturating_add(tok) <= req.token_budget
                || (selected.is_empty() && fired_reflexes.is_empty() && tok <= req.token_budget)
            {
                used_tokens += tok;
                if let Some(ref mut sess) = session {
                    sess.mark_delivered(ns_id, cap.generation);
                }
                cap.key = Some(match cap.key {
                    Some(k) => format!("{layer_prefix}::{k}"),
                    None => layer_prefix.to_owned(),
                });
                selected.push(cap);
            }
        }

        if let Some(ref sess) = session {
            sess.save(self.project.db())?;
        }

        Ok(PulseResponse {
            fired_reflexes,
            capsules: selected,
            already_in_context_stubs: stubs,
            tokens_emitted: used_tokens,
            tokens_saved_by_delta: saved_by_delta,
            coalesced_io_reads: proj_raw.coalesced_io_reads + glob_raw.coalesced_io_reads,
        })
    }
}
