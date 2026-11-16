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

        // 1. Evaluate reflexes across both layers in RAM (`0` disk reads), and record any
        //    unmatched non-banal error into `sys::pending_error_cues` without refuting a pitfall
        //    that is actively being recalled on this `pulse` query.
        let proj_rf = self.project.evaluate_reflexes(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
        );
        let project_reflex_fired = !proj_rf.is_empty();
        let pitfall_recalled = proj_rf.iter().any(|r| r.id.starts_with("pitfall::"));
        if !pitfall_recalled {
            if let Some(err_str) = req
                .error_context
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let recorded = crate::learning::record_error_cue(self.project.db(), err_str, None)
                    .unwrap_or(false);
                if recorded {
                    if let Ok(st) = self.project.db().stats() {
                        self.last_project_seq.store(st.commit_seq, Ordering::Relaxed);
                    }
                }
            }
        }
        let glob_rf = global_eng.reflex_engine().evaluate_with_anchor_context(
            req.workspace_dir.as_deref(),
            &req.query,
            req.error_context.as_deref(),
            Some(self.project.reflex_engine()),
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
        let mut glob_cands = global_eng.score_candidates_in_ram(&req.query);

        // Only the project layer decides whether a query was a workspace miss: generic global
        // rule/skill matches must never mask an unresolved project-specific concept.
        if proj_cands.is_empty() && !project_reflex_fired {
            let recorded = crate::learning::record_search_miss_cue_with_source(
                self.project.db(),
                &req.query,
                crate::learning::MissCueSource::Pulse,
            )
            .unwrap_or(false);
            if recorded {
                if let Ok(st) = self.project.db().stats() {
                    self.last_project_seq.store(st.commit_seq, Ordering::Relaxed);
                }
            }
        }

        // Attenuate global skill hits belonging to an unrelated framework stack when workspace
        // markers establish the active project stack and the query did not ask for that stack.
        let ws_markers = req
            .workspace_dir
            .as_deref()
            .map(crate::reflex::detect_workspace_markers)
            .unwrap_or_default();
        let query_low = req.query.to_ascii_lowercase();
        for c in &mut glob_cands {
            c.score *= foreign_skill_stack_multiplier(
                c.kind,
                c.key.as_deref(),
                &query_low,
                &ws_markers,
            );
        }
        let glob_peak = glob_cands.iter().map(|c| c.score).fold(0.0_f64, f64::max);
        let glob_floor = (glob_peak * 0.35).max(0.80);
        glob_cands.retain(|c| c.score >= glob_floor || c.via_bridge);

        // Normalize project BM25 scores onto the global corpus scale so a large global store
        // (high IDF) never starves project-local capsules (lower IDF) before budget reservation.
        let proj_raw_peak = proj_cands.iter().map(|c| c.score).fold(0.0_f64, f64::max);
        let idf_parity_scale = if proj_raw_peak > 0.0 && glob_peak > proj_raw_peak {
            (glob_peak / proj_raw_peak).clamp(1.0, 3.5)
        } else {
            1.0
        };
        let proj_scaled_peak = proj_raw_peak * idf_parity_scale * 1.15;
        let proj_floor = (proj_scaled_peak * 0.35).max(0.80);

        let mut merged: Vec<(bool, ScoredInodeCandidate)> =
            Vec::with_capacity(proj_cands.len() + glob_cands.len());
        for mut c in proj_cands {
            c.score *= idf_parity_scale * 1.15;
            if c.score >= proj_floor || c.via_bridge {
                merged.push((false, c));
            }
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

        // 3. Filter via `SessionState` BEFORE hydrating any extents from disk!
        let mut to_fetch_proj: Vec<ScoredInodeCandidate> = Vec::new();
        let mut to_fetch_glob: Vec<ScoredInodeCandidate> = Vec::new();
        // Preserve display rank order `(is_global, local_idx)`
        let mut order_plan: Vec<(bool, usize)> = Vec::new();

        // Phase 3a: Apply Zero-Repeat Delta stubs first so fresh budget reflects freed tokens,
        // and collect remaining eligible candidates in descending relevance order.
        let mut fresh: Vec<(bool, ScoredInodeCandidate)> = Vec::new();
        for (is_global, cand) in merged {
            let ns_id = if is_global {
                GLOBAL_LAYER_TAG | cand.node_id
            } else {
                cand.node_id
            };
            let layer_prefix = if is_global { "global" } else { "proj" };

            if let Some(ref mut sess) = session {
                if sess.is_already_in_context(ns_id, cand.generation) {
                    let stub_tok = 6u32;
                    sess.record_suppression(cand.token_count, stub_tok);
                    saved_by_delta += cand.token_count.saturating_sub(stub_tok);
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
            fresh.push((is_global, cand));
        }

        // Phase 3b: Reserve at least 50% of remaining token budget for local project memories
        // (`!is_global`) so global skill hits cannot crowd out project facts and decisions.
        let remaining_after_stubs = req.token_budget.saturating_sub(used_tokens);
        let local_quota = (remaining_after_stubs + 1) / 2;
        let first_local_cap = ((remaining_after_stubs * 3) / 5).max(local_quota);
        let mut local_reserved_tok = 0u32;
        let mut picked = vec![false; fresh.len()];

        for (idx, (is_global, cand)) in fresh.iter().enumerate() {
            if *is_global {
                continue;
            }
            let tok = cand.token_count.max(1);
            let fits_quota = local_reserved_tok.saturating_add(tok) <= local_quota
                || (local_reserved_tok == 0 && tok <= first_local_cap);
            if fits_quota && used_tokens.saturating_add(tok) <= req.token_budget {
                picked[idx] = true;
                local_reserved_tok = local_reserved_tok.saturating_add(tok);
                used_tokens = used_tokens.saturating_add(tok);
            }
        }

        // Phase 3c: Fill remaining budget across all unselected candidates in original score order.
        let mut any_picked = picked.iter().any(|&p| p);
        for (idx, (_, cand)) in fresh.iter().enumerate() {
            if picked[idx] {
                continue;
            }
            let tok = cand.token_count.max(1);
            if used_tokens.saturating_add(tok) <= req.token_budget
                || (!any_picked && fired_reflexes.is_empty() && tok <= req.token_budget)
            {
                picked[idx] = true;
                any_picked = true;
                used_tokens = used_tokens.saturating_add(tok);
            }
        }

        // Phase 3d: Emit selected items in their original descending relevance rank order.
        for (selected_flag, (is_global, cand)) in picked.into_iter().zip(fresh.into_iter()) {
            if !selected_flag {
                continue;
            }
            let ns_id = if is_global {
                GLOBAL_LAYER_TAG | cand.node_id
            } else {
                cand.node_id
            };
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

        // 4. Hydrate ONLY unseen winning capsules via coalesced extent reads (`0` reads if all were in context!).
        let proj_ids: Vec<u64> = to_fetch_proj.iter().map(|c| c.node_id).collect();
        let glob_ids: Vec<u64> = to_fetch_glob.iter().map(|c| c.node_id).collect();

        let (proj_recs, proj_io) = self.project.db().get_many_coalesced(&proj_ids)?;
        let (glob_recs, glob_io) = global_eng.db().get_many_coalesced(&glob_ids)?;
        let mut proj_map: std::collections::HashMap<u64, _> =
            proj_recs.into_iter().map(|r| (r.node_id, r)).collect();
        let mut glob_map: std::collections::HashMap<u64, _> =
            glob_recs.into_iter().map(|r| (r.node_id, r)).collect();

        let mut selected = Vec::with_capacity(order_plan.len());
        for (is_global, idx) in order_plan {
            let (prefix, cand, rec_opt) = if is_global {
                let c = &to_fetch_glob[idx];
                ("global", c, glob_map.remove(&c.node_id))
            } else {
                let c = &to_fetch_proj[idx];
                ("proj", c, proj_map.remove(&c.node_id))
            };
            let Some(rec) = rec_opt else {
                continue;
            };
            let key = Some(match &cand.key {
                Some(k) => format!("{prefix}::{k}"),
                None => prefix.to_owned(),
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

        // Only write `SessionState` to disk if `delivered_generations` actually gained a new item!
        if session_dirty {
            if let Some(ref sess) = session {
                sess.save(self.project.db())?;
                let after_seq = self.project.db().stats()?.commit_seq;
                self.last_project_seq.store(after_seq, Ordering::Relaxed);
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

/// Attenuates global skill hits belonging to an unrelated framework stack when workspace markers
/// establish the active project stack and the query did not ask for that stack.
fn foreign_skill_stack_multiplier(
    kind: libredb_core::NodeKind,
    key_opt: Option<&str>,
    query_low: &str,
    ws_markers: &[String],
) -> f64 {
    if !matches!(
        kind,
        libredb_core::NodeKind::Skill | libredb_core::NodeKind::SkillSection
    ) || ws_markers.is_empty()
    {
        return 1.0;
    }
    let Some(raw_key) = key_opt else {
        return 1.0;
    };
    let skill_name = raw_key
        .split_once("::")
        .map_or(raw_key, |(head, _)| head)
        .trim()
        .to_ascii_lowercase();
    let has_exact_tok = |hay: &str, needle: &str| {
        hay.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|tok| tok == needle)
    };
    let marker_has = |needles: &[&str]| {
        ws_markers
            .iter()
            .any(|m| needles.iter().any(|n| m == n || m.contains(n)))
    };

    if skill_name.contains("flutter")
        || has_exact_tok(&skill_name, "dart")
        || skill_name.starts_with("dart-")
        || skill_name.starts_with("dart_")
    {
        let q_wants = query_low.contains("flutter") || has_exact_tok(query_low, "dart");
        let ws_uses = marker_has(&["pubspec.yaml", "pubspec.lock", ".dart_tool", ".flutter"]);
        if !q_wants && !ws_uses {
            return 0.25;
        }
    }

    if skill_name.starts_with("chrome-extension") || skill_name.contains("chrome_extension") {
        let q_wants = query_low.contains("chrome") && query_low.contains("extension");
        let ws_uses = marker_has(&["manifest.json"]);
        if !q_wants && !ws_uses {
            return 0.25;
        }
    }

    if skill_name.starts_with("android") || has_exact_tok(&skill_name, "android") {
        let q_wants = query_low.contains("android")
            || query_low.contains("kotlin")
            || query_low.contains("gradle");
        let ws_uses = marker_has(&[
            "androidmanifest.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradlew",
        ]);
        if !q_wants && !ws_uses {
            return 0.25;
        }
    }

    if skill_name.starts_with("apple-hig") || skill_name.starts_with("xcode") {
        let q_wants = query_low.contains("apple")
            || has_exact_tok(query_low, "ios")
            || query_low.contains("ipados")
            || query_low.contains("macos")
            || query_low.contains("swift")
            || query_low.contains("uikit")
            || query_low.contains("appkit")
            || query_low.contains("xcode")
            || has_exact_tok(query_low, "iphone")
            || has_exact_tok(query_low, "ipad");
        let ws_uses = marker_has(&[
            ".xcodeproj",
            ".xcworkspace",
            "package.swift",
            "podfile",
            "info.plist",
            "project.pbxproj",
        ]);
        if !q_wants && !ws_uses {
            return 0.25;
        }
    }

    if skill_name.starts_with("linux-desktop-hig") {
        let q_wants = query_low.contains("linux")
            || query_low.contains("gnome")
            || has_exact_tok(query_low, "kde")
            || query_low.contains("libadwaita")
            || query_low.contains("adwaita")
            || has_exact_tok(query_low, "gtk")
            || query_low.contains("gtk4")
            || query_low.contains("kirigami")
            || query_low.contains("breeze")
            || has_exact_tok(query_low, "qt")
            || query_low.contains("qt6")
            || has_exact_tok(query_low, "qml")
            || query_low.contains("wayland")
            || query_low.contains("flatpak");
        let ws_uses = marker_has(&[
            "meson.build",
            "cmakelists.txt",
            "flatpak",
            ".desktop",
            "org.gnome",
            "org.kde",
        ]);
        if !q_wants && !ws_uses {
            return 0.25;
        }
    }

    if skill_name.starts_with("windows-app-design") {
        let q_wants = query_low.contains("windows")
            || query_low.contains("winui")
            || query_low.contains("fluent")
            || has_exact_tok(query_low, "wpf")
            || has_exact_tok(query_low, "egui")
            || query_low.contains("eframe")
            || query_low.contains("xaml")
            || query_low.contains("tauri");
        let ws_has_windows = marker_has(&[".sln", ".csproj", ".vcxproj", "appxmanifest.xml"])
            || (marker_has(&["cargo.toml"])
                && !marker_has(&[
                    ".xcodeproj",
                    ".xcworkspace",
                    "package.swift",
                    "androidmanifest.xml",
                    "build.gradle",
                    "meson.build",
                    "flatpak",
                ]));
        let ws_is_other_platform = marker_has(&[
            ".xcodeproj",
            ".xcworkspace",
            "package.swift",
            "podfile",
            "androidmanifest.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "pubspec.yaml",
            "meson.build",
            "flatpak",
        ]);
        if !q_wants && ws_is_other_platform && !ws_has_windows {
            return 0.25;
        }
    }

    1.0
}
