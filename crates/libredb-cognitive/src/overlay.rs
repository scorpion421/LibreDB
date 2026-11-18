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
    same_as_global: bool,
    learning_enabled: bool,
    last_global_seq: AtomicU64,
    last_project_seq: AtomicU64,
}

impl OverlayBrain {
    pub fn open(global_db: Option<Arc<LibreDb>>, project_db: Arc<LibreDb>) -> Result<Self> {
        let same_as_global = global_db.as_ref().is_some_and(|gdb| {
            Arc::ptr_eq(gdb, &project_db)
                || match (gdb.path(), project_db.path()) {
                    (Some(gp), Some(pp)) => {
                        gp == pp
                            || (std::fs::canonicalize(gp).ok().is_some()
                                && std::fs::canonicalize(gp).ok()
                                    == std::fs::canonicalize(pp).ok())
                    }
                    _ => false,
                }
        });
        if let Some(ref gdb) = global_db {
            gdb.sync_from_disk_if_changed()?;
        }
        if !same_as_global {
            project_db.sync_from_disk_if_changed()?;
        }
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
            same_as_global,
            learning_enabled: true,
            last_global_seq: AtomicU64::new(last_global_seq),
            last_project_seq: AtomicU64::new(last_project_seq),
        })
    }

    /// Controls whether `OverlayBrain::pulse` records pending error/miss cues into `project_db`.
    /// Quarantined and shared fallback stores set this to `false` to prevent cross-session bleed.
    pub fn set_learning_enabled(&mut self, enabled: bool) {
        self.learning_enabled = enabled;
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
        let proj_rf = if self.same_as_global {
            Vec::new()
        } else {
            self.project.evaluate_reflexes(
                req.workspace_dir.as_deref(),
                &req.query,
                req.error_context.as_deref(),
            )
        };
        let project_reflex_fired = !proj_rf.is_empty();
        let pitfall_recalled = proj_rf.iter().any(|r| r.id.starts_with("pitfall::"));
        if self.learning_enabled && !self.same_as_global && !pitfall_recalled {
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
            if self.same_as_global {
                None
            } else {
                Some(self.project.reflex_engine())
            },
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
        let proj_cands = if self.same_as_global {
            Vec::new()
        } else {
            self.project.score_candidates_in_ram(&req.query)
        };
        let mut glob_cands = global_eng.score_candidates_in_ram(&req.query);

        // Only the project layer decides whether a query was a workspace miss: generic global
        // rule/skill matches must never mask an unresolved project-specific concept.
        if self.learning_enabled && !self.same_as_global && proj_cands.is_empty() && !project_reflex_fired {
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
        let mut query_specific_tokens: Vec<String> = Vec::new();
        for tok in libredb_index::segment_universal_tokens(&req.query) {
            if !is_generic_skill_collision_token(&tok) && !query_specific_tokens.contains(&tok) {
                query_specific_tokens.push(tok);
            }
        }
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
        glob_cands.retain(|c| {
            (c.score >= glob_floor
                && global_skill_passes_specificity_gate(
                    c,
                    &query_specific_tokens,
                    &query_low,
                    &ws_markers,
                ))
                || c.via_bridge
        });

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

        // Phase 3c: Fill remaining budget across unselected high-signal candidates in score order.
        let fill_skill_floor = (glob_peak * 0.55).max(1.35);
        let mut any_picked = picked.iter().any(|&p| p);
        for (idx, (is_global, cand)) in fresh.iter().enumerate() {
            if picked[idx] {
                continue;
            }
            if *is_global
                && (any_picked || !fired_reflexes.is_empty())
                && matches!(
                    cand.kind,
                    libredb_core::NodeKind::Skill | libredb_core::NodeKind::SkillSection
                )
                && !cand.via_bridge
                && cand.score < fill_skill_floor
                && cand.matched_term_count < 2
            {
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
fn has_exact_alpha_tok(hay: &str, needle: &str) -> bool {
    hay.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == needle)
}

fn marker_matches_any(ws_markers: &[String], needles: &[&str]) -> bool {
    ws_markers
        .iter()
        .any(|m| needles.iter().any(|n| m == n || m.contains(n)))
}

pub(crate) fn is_generic_skill_collision_token(tok: &str) -> bool {
    matches!(
        tok,
        "http"
            | "https"
            | "url"
            | "urls"
            | "uri"
            | "server"
            | "servers"
            | "client"
            | "clients"
            | "endpoint"
            | "endpoints"
            | "host"
            | "hosts"
            | "port"
            | "ports"
            | "local"
            | "localhost"
            | "remote"
            | "api"
            | "apis"
            | "sdk"
            | "sdks"
            | "cli"
            | "app"
            | "apps"
            | "application"
            | "service"
            | "services"
            | "system"
            | "systems"
            | "tool"
            | "tools"
            | "config"
            | "configs"
            | "configuration"
            | "setting"
            | "settings"
            | "option"
            | "options"
            | "default"
            | "defaults"
            | "env"
            | "file"
            | "files"
            | "folder"
            | "folders"
            | "dir"
            | "directory"
            | "path"
            | "paths"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "xml"
            | "text"
            | "string"
            | "strings"
            | "value"
            | "values"
            | "data"
            | "type"
            | "types"
            | "name"
            | "names"
            | "key"
            | "keys"
            | "list"
            | "lists"
            | "code"
            | "example"
            | "examples"
            | "sample"
            | "guide"
            | "guides"
            | "doc"
            | "docs"
            | "overview"
            | "basics"
            | "readme"
            | "user"
            | "users"
            | "error"
            | "errors"
            | "warning"
            | "status"
            | "info"
            | "log"
            | "logs"
            | "check"
            | "checks"
            | "test"
            | "tests"
            | "testing"
            | "debug"
            | "run"
            | "running"
            | "start"
            | "stop"
            | "use"
            | "using"
            | "used"
            | "allow"
            | "allows"
            | "deny"
            | "enable"
            | "enabled"
            | "disable"
            | "disabled"
            | "set"
            | "get"
            | "add"
            | "create"
            | "update"
            | "install"
            | "build"
            | "deploy"
            | "setup"
            | "manage"
            | "managed"
            | "query"
            | "search"
            | "read"
            | "write"
            | "open"
            | "close"
            | "connect"
            | "connection"
            | "request"
            | "response"
            | "header"
            | "headers"
            | "bearer"
            | "english"
            | "german"
            | "bitte"
            | "frage"
            | "hier"
            | "sind"
            | "und"
            | "oder"
            | "der"
            | "die"
            | "das"
            | "mit"
            | "von"
            | "auf"
            | "ist"
            | "the"
            | "and"
            | "for"
            | "with"
            | "from"
            | "how"
            | "where"
            | "what"
            | "when"
            | "why"
    )
}

fn is_ui_design_skill(skill_name: &str) -> bool {
    matches!(
        skill_name,
        "windows-app-design" | "android-app-design" | "apple-hig-design" | "linux-desktop-hig-design"
    )
}

fn query_has_ui_design_intent(query_low: &str) -> bool {
    const UNAMBIGUOUS_UI_TOKENS: &[&str] = &[
        "ui",
        "ux",
        "gui",
        "hig",
        "wpf",
        "egui",
        "eframe",
        "winui",
        "fluent",
        "xaml",
        "tauri",
        "maui",
        "avalonia",
        "winappsdk",
        "mica",
        "acrylic",
        "segoe",
        "material",
        "compose",
        "jetpack",
        "swiftui",
        "uikit",
        "appkit",
        "libadwaita",
        "adwaita",
        "gtk",
        "gtk4",
        "kirigami",
        "breeze",
        "qt",
        "qt6",
        "qml",
        "a11y",
        "aria",
        "dpi",
        "epx",
        "toolbar",
        "sidebar",
        "tabview",
        "splitview",
        "insets",
        "touch target",
        "dark mode",
        "light mode",
        "voiceover",
        "talkback",
        "screen reader",
        "screenreader",
        "widget",
        "widgets",
        "theming",
        "palette",
        "typography",
        "windows-app-design",
        "android-app-design",
        "apple-hig-design",
        "linux-desktop-hig-design",
    ];
    if UNAMBIGUOUS_UI_TOKENS
        .iter()
        .any(|tok| crate::reflex::reflex_keyword_matches(query_low, tok))
    {
        return true;
    }
    const CONTEXTUAL_UI_WORDS: &[&str] =
        &["design", "layout", "theme", "font", "contrast", "navigation"];
    const UI_SURFACE_CONTEXT_TOKENS: &[&str] = &[
        "windows", "android", "apple", "ios", "ipados", "macos", "linux", "gnome", "kde",
        "desktop", "mobile", "app", "apps", "window", "screen", "button", "card", "dialog",
        "sheet", "menu", "form", "icon",
    ];
    let has_ui_word = CONTEXTUAL_UI_WORDS
        .iter()
        .any(|w| crate::reflex::reflex_keyword_matches(query_low, w));
    has_ui_word
        && UI_SURFACE_CONTEXT_TOKENS
            .iter()
            .any(|ctx| crate::reflex::reflex_keyword_matches(query_low, ctx))
}

#[derive(Clone, Copy)]
enum SkillPattern {
    Exact(&'static str),
    Prefix(&'static str),
    Contains(&'static str),
    ExactToken(&'static str),
}

impl SkillPattern {
    fn matches(self, skill_name: &str) -> bool {
        match self {
            Self::Exact(s) => skill_name == s,
            Self::Prefix(s) => skill_name.starts_with(s),
            Self::Contains(s) => skill_name.contains(s),
            Self::ExactToken(s) => has_exact_alpha_tok(skill_name, s),
        }
    }
}

struct SkillDomainRule {
    skills: &'static [SkillPattern],
    query_terms: &'static [&'static str],
    require_all_query_terms: bool,
    ws_markers: &'static [&'static str],
    allows_stack_match: bool,
    requires_ui_intent_for_stack: bool,
}

const OTHER_UI_PLATFORM_MARKERS: &[&str] = &[
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
];

const SKILL_DOMAIN_RULES: &[SkillDomainRule] = &[
    SkillDomainRule {
        skills: &[
            SkillPattern::Exact("plugin"),
            SkillPattern::Exact("run-workflow"),
            SkillPattern::Exact("ui-plugin-navigation"),
            SkillPattern::Exact("migrate-workflows"),
            SkillPattern::Exact("migrate-agent-settings"),
            SkillPattern::Exact("workflow-skill-creator"),
            SkillPattern::Exact("permissioned-github"),
            SkillPattern::Exact("automation"),
            SkillPattern::Exact("generative_ui"),
            SkillPattern::Prefix("agy-"),
            SkillPattern::Prefix("gemini-"),
            SkillPattern::Contains("antigravity"),
        ],
        query_terms: &[
            "antigravity",
            "agy",
            "gemini",
            "mcp",
            "subagent",
            "subagents",
            "plugin",
            "plugins",
            "workflow",
            "workflows",
            "skill",
            "skills",
        ],
        require_all_query_terms: false,
        ws_markers: &[],
        allows_stack_match: false,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Exact("chrome-devtools"),
            SkillPattern::Exact("debug-optimize-lcp"),
            SkillPattern::Exact("memory-leak-debugging"),
            SkillPattern::Exact("modern-web-guidance"),
            SkillPattern::Exact("troubleshooting"),
        ],
        query_terms: &[
            "chrome",
            "devtools",
            "browser",
            "lcp",
            "web vitals",
            "heap",
            "html",
            "css",
            "javascript",
            "dom",
            "frontend",
            "troubleshoot",
            "troubleshooting",
        ],
        require_all_query_terms: false,
        ws_markers: &["package.json"],
        allows_stack_match: false,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Exact("predictingthepast"),
            SkillPattern::Exact("pymol"),
            SkillPattern::Exact("string-database"),
            SkillPattern::Prefix("alphafold"),
            SkillPattern::Prefix("alphagenome"),
            SkillPattern::Prefix("chembl"),
            SkillPattern::Prefix("clinical-trials"),
            SkillPattern::Prefix("clinvar"),
            SkillPattern::Prefix("dbsnp"),
            SkillPattern::Prefix("embl-"),
            SkillPattern::Prefix("encode-"),
            SkillPattern::Prefix("ensembl"),
            SkillPattern::Prefix("foldseek"),
            SkillPattern::Prefix("gnomad"),
            SkillPattern::Prefix("gtex"),
            SkillPattern::Prefix("human-protein"),
            SkillPattern::Prefix("interpro"),
            SkillPattern::Prefix("jaspar"),
            SkillPattern::Prefix("literature-search-"),
            SkillPattern::Prefix("ncbi-"),
            SkillPattern::Prefix("openfda"),
            SkillPattern::Prefix("opentargets"),
            SkillPattern::Prefix("pdb-"),
            SkillPattern::Prefix("protein-"),
            SkillPattern::Prefix("pubchem"),
            SkillPattern::Prefix("pubmed"),
            SkillPattern::Prefix("quickgo"),
            SkillPattern::Prefix("reactome"),
            SkillPattern::Prefix("ucsc-"),
            SkillPattern::Prefix("unibind"),
            SkillPattern::Prefix("uniprot"),
        ],
        query_terms: &[
            "protein",
            "proteins",
            "gene",
            "genes",
            "variant",
            "variants",
            "genome",
            "genomic",
            "alphafold",
            "alphagenome",
            "pubmed",
            "pubchem",
            "uniprot",
            "chembl",
            "clinvar",
            "ensembl",
            "arxiv",
            "biorxiv",
            "molecule",
            "molecules",
            "clinical",
            "pdb",
            "dna",
            "rna",
            "pymol",
        ],
        require_all_query_terms: false,
        ws_markers: &[],
        allows_stack_match: false,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Contains("flutter"),
            SkillPattern::ExactToken("dart"),
            SkillPattern::Prefix("dart-"),
            SkillPattern::Prefix("dart_"),
        ],
        query_terms: &["flutter", "dart"],
        require_all_query_terms: false,
        ws_markers: &["pubspec.yaml", "pubspec.lock", ".dart_tool", ".flutter"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Prefix("chrome-extension"),
            SkillPattern::Contains("chrome_extension"),
        ],
        query_terms: &["chrome", "extension"],
        require_all_query_terms: true,
        ws_markers: &["manifest.json"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Prefix("android"),
            SkillPattern::ExactToken("android"),
        ],
        query_terms: &["android", "kotlin", "gradle", "compose", "talkback"],
        require_all_query_terms: false,
        ws_markers: &[
            "androidmanifest.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradlew",
        ],
        allows_stack_match: true,
        requires_ui_intent_for_stack: true,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Prefix("apple-hig"),
            SkillPattern::Prefix("xcode"),
        ],
        query_terms: &[
            "apple",
            "ios",
            "ipados",
            "macos",
            "swift",
            "swiftui",
            "uikit",
            "appkit",
            "xcode",
            "iphone",
            "ipad",
            "voiceover",
        ],
        require_all_query_terms: false,
        ws_markers: &[
            ".xcodeproj",
            ".xcworkspace",
            "package.swift",
            "podfile",
            "info.plist",
            "project.pbxproj",
        ],
        allows_stack_match: true,
        requires_ui_intent_for_stack: true,
    },
    SkillDomainRule {
        skills: &[SkillPattern::Prefix("linux-desktop-hig")],
        query_terms: &[
            "linux",
            "gnome",
            "kde",
            "libadwaita",
            "adwaita",
            "gtk",
            "gtk4",
            "kirigami",
            "breeze",
            "qt",
            "qt6",
            "qml",
            "wayland",
            "flatpak",
        ],
        require_all_query_terms: false,
        ws_markers: &[
            "meson.build",
            "cmakelists.txt",
            "flatpak",
            ".desktop",
            "org.gnome",
            "org.kde",
        ],
        allows_stack_match: true,
        requires_ui_intent_for_stack: true,
    },
    SkillDomainRule {
        skills: &[SkillPattern::Prefix("windows-app-design")],
        query_terms: &[
            "windows", "winui", "fluent", "wpf", "egui", "eframe", "xaml", "tauri",
        ],
        require_all_query_terms: false,
        ws_markers: &[".sln", ".csproj", ".vcxproj", "appxmanifest.xml"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: true,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Contains("firebase"),
            SkillPattern::Contains("firestore"),
        ],
        query_terms: &["firebase", "firestore"],
        require_all_query_terms: false,
        ws_markers: &["firebase.json", ".firebaserc"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Prefix("gcp"),
            SkillPattern::Contains("gcp"),
            SkillPattern::Contains("airflow"),
            SkillPattern::Contains("bigquery"),
        ],
        query_terms: &["gcp", "airflow", "bigquery", "google cloud", "dataflow"],
        require_all_query_terms: false,
        ws_markers: &["airflow.cfg", "dags"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Contains("databricks"),
            SkillPattern::Contains("lakehouse"),
            SkillPattern::Contains("snowflake"),
        ],
        query_terms: &[
            "databricks",
            "lakehouse",
            "snowflake",
            "unity catalog",
            "iceberg",
            "delta lake",
        ],
        require_all_query_terms: false,
        ws_markers: &["databricks.yml", "dbt_project.yml"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[SkillPattern::ExactToken("a11y")],
        query_terms: &[
            "a11y",
            "accessibility",
            "wcag",
            "aria",
            "screenreader",
            "screen reader",
            "talkback",
            "voiceover",
        ],
        require_all_query_terms: false,
        ws_markers: &["package.json", "pubspec.yaml", "androidmanifest.xml"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Contains("react"),
            SkillPattern::Contains("nextjs"),
            SkillPattern::Contains("next-js"),
            SkillPattern::ExactToken("vue"),
            SkillPattern::Contains("angular"),
            SkillPattern::Contains("tailwind"),
        ],
        query_terms: &["react", "nextjs", "next.js", "vue", "angular", "tailwind"],
        require_all_query_terms: false,
        ws_markers: &[
            "package.json",
            "next.config",
            "vite.config",
            "angular.json",
            "tailwind.config",
        ],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
    SkillDomainRule {
        skills: &[
            SkillPattern::Contains("kubernetes"),
            SkillPattern::ExactToken("k8s"),
            SkillPattern::ExactToken("helm"),
            SkillPattern::Contains("terraform"),
        ],
        query_terms: &["kubernetes", "k8s", "helm", "terraform"],
        require_all_query_terms: false,
        ws_markers: &[".tf", "chart.yaml", "kustomization.yaml", "helmfile.yaml"],
        allows_stack_match: true,
        requires_ui_intent_for_stack: false,
    },
];

fn rule_query_matches(rule: &SkillDomainRule, query_low: &str) -> bool {
    if rule.require_all_query_terms {
        rule.query_terms
            .iter()
            .all(|t| crate::reflex::reflex_keyword_matches(query_low, t))
    } else {
        rule.query_terms
            .iter()
            .any(|t| crate::reflex::reflex_keyword_matches(query_low, t))
    }
}

fn find_matching_domain_rule(skill_name: &str) -> Option<&'static SkillDomainRule> {
    SKILL_DOMAIN_RULES
        .iter()
        .find(|rule| rule.skills.iter().any(|p| p.matches(skill_name)))
}

fn skill_matches_active_workspace_stack(
    skill_name: &str,
    query_low: &str,
    ws_markers: &[String],
) -> bool {
    if ws_markers.is_empty() || skill_name.is_empty() {
        return false;
    }
    let Some(rule) = find_matching_domain_rule(skill_name) else {
        return false;
    };
    if !rule.allows_stack_match || rule.ws_markers.is_empty() {
        return false;
    }
    if rule.requires_ui_intent_for_stack
        && is_ui_design_skill(skill_name)
        && !query_has_ui_design_intent(query_low)
    {
        return false;
    }
    marker_matches_any(ws_markers, rule.ws_markers)
}

fn skill_distinctively_named_in_query(skill_name: &str, query_low: &str) -> bool {
    if skill_name.is_empty() {
        return false;
    }
    skill_name
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|tok| {
            tok.len() >= 3
                && !matches!(
                    *tok,
                    "design"
                        | "skill"
                        | "guide"
                        | "app"
                        | "basics"
                        | "build"
                        | "catalog"
                        | "managed"
                        | "windows"
                        | "linux"
                        | "desktop"
                        | "server"
                        | "system"
                        | "admin"
                        | "data"
                        | "loss"
                        | "prevention"
                        | "accidental"
                        | "security"
                        | "database"
                        | "search"
                        | "python"
                        | "modern"
                        | "web"
                        | "debug"
                        | "debugging"
                        | "memory"
                        | "workflow"
                        | "workflows"
                        | "plugin"
                        | "run"
                        | "migrate"
                        | "automation"
                        | "troubleshooting"
                        | "building"
                        | "managing"
                        | "enforcing"
                        | "discovering"
                        | "clinical"
                        | "human"
                        | "string"
                        | "literature"
                        | "protein"
                        | "single"
                        | "variant"
                        | "analysis"
                        | "score"
                        | "fetch"
                        | "setup"
                        | "use"
                        | "add"
                        | "fix"
                        | "write"
                        | "collect"
                        | "generate"
                        | "resolve"
                        | "implement"
                        | "apply"
                        | "architecture"
                        | "best"
                        | "practices"
                        | "responsive"
                        | "layout"
                        | "declarative"
                        | "routing"
                        | "localization"
                        | "http"
                        | "package"
                        | "unit"
                        | "test"
                        | "widget"
                        | "integration"
                        | "runtime"
                        | "errors"
                        | "static"
                        | "coverage"
                        | "mocks"
                        | "primary"
                        | "constructors"
                        | "pattern"
                        | "matching"
                        | "documentation"
                        | "cli"
                        | "api"
                        | "dev"
                        | "live"
                        | "interactions"
                        | "platform"
                )
        })
        .any(|tok| has_exact_alpha_tok(query_low, tok))
}

fn global_skill_passes_specificity_gate(
    c: &crate::ScoredInodeCandidate,
    query_specific_tokens: &[String],
    query_low: &str,
    ws_markers: &[String],
) -> bool {
    if c.via_bridge
        || !matches!(
            c.kind,
            libredb_core::NodeKind::Skill | libredb_core::NodeKind::SkillSection
        )
    {
        return true;
    }
    let cand_specific_matched = c
        .matched_query_tokens
        .iter()
        .filter(|t| !is_generic_skill_collision_token(t.as_str()))
        .count();
    if cand_specific_matched == 0 {
        return false;
    }
    let raw_key = c.key.as_deref().unwrap_or("");
    let skill_name = raw_key
        .split_once("::")
        .map_or(raw_key, |(head, _)| head)
        .trim()
        .to_ascii_lowercase();
    if is_ui_design_skill(&skill_name) && !query_has_ui_design_intent(query_low) {
        return false;
    }
    if skill_matches_active_workspace_stack(&skill_name, query_low, ws_markers) {
        return c.score >= 1.00;
    }
    if skill_distinctively_named_in_query(&skill_name, query_low) {
        if query_specific_tokens.len() <= 2 {
            return c.score >= 1.00;
        }
        return cand_specific_matched >= 2 && c.score >= 1.10;
    }
    let required_specific = ((query_specific_tokens.len() + 3) / 4).max(2);
    cand_specific_matched >= required_specific && c.score >= 1.35
}

fn foreign_skill_stack_multiplier(
    kind: libredb_core::NodeKind,
    key_opt: Option<&str>,
    query_low: &str,
    ws_markers: &[String],
) -> f64 {
    if !matches!(
        kind,
        libredb_core::NodeKind::Skill | libredb_core::NodeKind::SkillSection
    ) {
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

    if is_ui_design_skill(&skill_name) && !query_has_ui_design_intent(query_low) {
        return 0.25;
    }

    let Some(rule) = find_matching_domain_rule(&skill_name) else {
        return 1.0;
    };
    let q_wants = rule_query_matches(rule, query_low);
    if skill_name.starts_with("windows-app-design") {
        if ws_markers.is_empty() {
            return 1.0;
        }
        let ws_has_windows = marker_matches_any(ws_markers, rule.ws_markers);
        let ws_is_other = marker_matches_any(ws_markers, OTHER_UI_PLATFORM_MARKERS);
        return if !q_wants && ws_is_other && !ws_has_windows {
            0.25
        } else {
            1.0
        };
    }

    let ws_uses = !rule.ws_markers.is_empty() && marker_matches_any(ws_markers, rule.ws_markers);
    if !q_wants && !ws_uses {
        0.25
    } else {
        1.0
    }
}
