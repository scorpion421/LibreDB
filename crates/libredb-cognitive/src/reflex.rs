//! Data-driven Situational Pitfall & Experience Reflex Engine (`ReflexEngine`).
//!
//! Zero hardcoded rules: every `ReflexRule` is learned from experience and persisted inside
//! `LibreDb` (`NodeKind::Rule` with key `reflex::<id>`). When `pulse` runs, matching reflexes
//! fire proactively (`< 0.05 ms`) before execution to prevent costly error-recovery turns.
//!
//! Code-grounded reflexes (`code_anchors`) are falsifiable: if every anchor vanished from the indexed
//! workspace the reflex is suppressed at runtime, and if an anchored symbol's signature changed since
//! the reflex was learned (`anchor_contracts`), it fires with an explicit verification marker.

use libredb_core::crc::{count_tokens_exact, hash_key};
use libredb_core::{LibreDb, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const REFLEX_KEY_PREFIX: &str = "reflex::";
/// Empirical outcome utility statistics per reflex ID (`NodeKind::Generic`, seal-neutral).
pub const REFLEX_UTILITY_BOOK_KEY: &str = "sys::reflex_utility_book";
const ANCHOR_CONTRACT_HASH_SEED: u8 = 0xA7;
const PITFALL_SYNTH_NODE_TAG: u64 = 1u64 << 46;
const PITFALL_SYNTH_HASH_SEED: u8 = 0xE2;
const DEFAULT_BASE_UTILITY: f64 = 0.75;

/// Empirical pass/fail tracking for a reflex ID, persisted in `sys::reflex_utility_book`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflexUtilityStats {
    #[serde(default)]
    pub successes: u32,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_updated_ns: u128,
}

/// Map of `reflex_id -> ReflexUtilityStats` stored inside `NodeKind::Generic`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReflexUtilityBook {
    #[serde(default)]
    pub stats: std::collections::BTreeMap<String, ReflexUtilityStats>,
}

/// Computes Laplace-smoothed empirical utility in `[0.05, 0.99]`:
/// `Utility(r) = (2.0 * u0 + successes) / (2.0 + successes + failures)`.
pub fn compute_smoothed_utility(
    base_utility: Option<f64>,
    stats: Option<&ReflexUtilityStats>,
) -> f64 {
    let u0 = base_utility.unwrap_or(DEFAULT_BASE_UTILITY).clamp(0.10, 0.99);
    let (s, f) = stats
        .map(|st| (f64::from(st.successes), f64::from(st.failures)))
        .unwrap_or((0.0, 0.0));
    ((2.0 * u0 + s) / (2.0 + s + f)).clamp(0.05, 0.99)
}

/// Structured situational trigger persisted inside `LibreDb` (`NodeKind::Rule` with `reflex::` key).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReflexRule {
    pub id: String,
    /// Matches if empty OR any tag matches detected workspace markers (`cargo.toml`, `pyproject.toml`, etc.) or query.
    #[serde(default)]
    pub stack_any: Vec<String>,
    /// Matches if empty OR any substring appears in the active task/command/query.
    #[serde(default)]
    pub action_any: Vec<String>,
    /// Matches if empty OR any substring appears in workspace path or observed error output.
    #[serde(default)]
    pub env_or_error_any: Vec<String>,
    /// Optional specialized conjunctive context tags: ALL tags must appear in the combined context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_tags: Vec<String>,
    /// Optional IDs of older reflexes overridden in matching contexts when this reflex remains viable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
    /// Optional prior base utility in `[0.10, 0.99]` (defaults to `0.75`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_utility: Option<f64>,
    /// Concise actionable warning (`15-40` tokens) injected into `pulse` output.
    pub directive: String,
    /// Optional code-graph anchors (`rel_path`, `rel_path::sym`, `Type::method`, or `sym_name`).
    /// When non-empty, the reflex is grounded in the workspace code graph: if all anchored files
    /// and symbols vanish from the workspace, the reflex is suppressed (falsified).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_anchors: Vec<String>,
    /// Deprecated since v1.4.0 (never populated); retained only for payload compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_contract_hash: Option<u64>,
    /// Signature hashes `(anchor, hash)` of anchored symbols captured at learning time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_contracts: Vec<(String, u64)>,
}

/// Fired reflex surfaced at the top of a `PulseResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredReflex {
    pub id: String,
    pub node_id: u64,
    pub generation: u32,
    pub token_count: u32,
    pub directive: String,
    /// Situational ranking score (`Spec(r, C) * Utility(r) * DriftMult`).
    #[serde(default)]
    pub score: f64,
    /// Older reflex IDs suppressed in this context by situational superseding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded_ids: Vec<String>,
}

/// Runtime classification of a learned reflex (`libredb learning`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexStatus {
    pub id: String,
    /// `active`, `drift` (anchored signature changed), or `falsified` (all anchors vanished).
    pub status: String,
    pub anchors: Vec<String>,
    /// Current Laplace-smoothed empirical utility in `[0.05, 0.99]`.
    #[serde(default)]
    pub utility: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleState {
    Active,
    Drift,
    Falsified,
}

type LiveAnchorSets = (HashSet<String>, HashSet<String>);
type SymbolInodes = Vec<(libredb_core::Inode, Option<String>, Vec<libredb_core::Synapse>)>;

/// Evaluates persisted learned reflexes against live workspace/action/error context.
#[derive(Default)]
pub struct ReflexEngine {
    rules: Vec<(u64, u32, ReflexRule, bool)>,
    /// Live workspace anchor sets of this layer (`None` if the layer has no indexed code graph).
    live_sets: Option<LiveAnchorSets>,
    utility_book: ReflexUtilityBook,
}

impl ReflexEngine {
    /// Loads ONLY cryptographically sealable `NodeKind::Rule` reflexes (`reflex::*`) plus numeric
    /// empirical utility counters (`sys::reflex_utility_book`). Used by `PreInvocation` hydration so
    /// unsealed `NodeKind::Generic` pitfall directives never enter `<SYSTEM_MESSAGE>`.
    pub fn load_sealed_only(db: &LibreDb) -> Result<Self> {
        let parsed = load_reflex_rules(db)?;
        let utility_book = load_utility_book(db);
        let (live_sets, classified) = classify_rules(db, parsed);
        let rules = classified
            .into_iter()
            .filter(|(_, _, _, st)| *st != RuleState::Falsified)
            .map(|(nid, gen, rule, st)| (nid, gen, rule, st == RuleState::Drift))
            .collect();
        Ok(Self {
            rules,
            live_sets,
            utility_book,
        })
    }

    /// Loads all learned `ReflexRule` capsules AND matured learned error pitfalls (`confidence >= 0.75`)
    /// from `db` (`0` hardcoded rules), suppressing code-grounded reflexes whose anchored files/symbols
    /// no longer exist in an indexed workspace and flagging reflexes whose anchored signatures drifted.
    pub fn load(db: &LibreDb) -> Result<Self> {
        let mut parsed = load_reflex_rules(db)?;
        for entry in crate::learning::load_matured_pitfalls(db) {
            let synth_nid = PITFALL_SYNTH_NODE_TAG
                | (hash_key(PITFALL_SYNTH_HASH_SEED, entry.id.as_bytes()) & (PITFALL_SYNTH_NODE_TAG - 1));
            let gen = entry.occurrences.max(1);
            let rule = entry.to_reflex_rule();
            parsed.push((synth_nid, gen, rule));
        }
        let utility_book = load_utility_book(db);
        let (live_sets, classified) = classify_rules(db, parsed);
        let rules = classified
            .into_iter()
            .filter(|(_, _, _, st)| *st != RuleState::Falsified)
            .map(|(nid, gen, rule, st)| (nid, gen, rule, st == RuleState::Drift))
            .collect();
        Ok(Self {
            rules,
            live_sets,
            utility_book,
        })
    }

    /// Returns the runtime status of every learned reflex in `db` (`0` writes).
    pub fn describe_all(db: &LibreDb) -> Vec<ReflexStatus> {
        let Ok(parsed) = load_reflex_rules(db) else {
            return Vec::new();
        };
        let utility_book = load_utility_book(db);
        let (_, classified) = classify_rules(db, parsed);
        let mut out: Vec<ReflexStatus> = classified
            .into_iter()
            .map(|(_, _, rule, st)| {
                let utility =
                    compute_smoothed_utility(rule.base_utility, utility_book.stats.get(&rule.id));
                ReflexStatus {
                    id: rule.id,
                    status: match st {
                        RuleState::Active => "active",
                        RuleState::Drift => "drift",
                        RuleState::Falsified => "falsified",
                    }
                    .to_owned(),
                    anchors: rule.code_anchors,
                    utility,
                    context_tags: rule.context_tags,
                    supersedes: rule.supersedes,
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Atomically records an empirical execution outcome (`success` or `failure`) for `reflex_id`
    /// in `sys::reflex_utility_book` (`NodeKind::Generic`, seal-neutral) and returns the updated
    /// smoothed utility in `[0.05, 0.99]`.
    pub fn record_reflex_outcome(db: &LibreDb, reflex_id: &str, success: bool) -> Result<f64> {
        let id_clean = reflex_id.trim();
        if id_clean.is_empty() {
            return Err(libredb_core::LibreDbError::CorruptFormat("empty reflex_id"));
        }
        let base_util = load_reflex_rules(db)
            .ok()
            .and_then(|v| {
                v.into_iter()
                    .find(|(_, _, r)| r.id == id_clean)
                    .map(|(_, _, r)| (r.base_utility, !r.supersedes.is_empty()))
            });
        let base_u0 = base_util.and_then(|(u, _)| u);
        let has_supersedes = base_util.is_some_and(|(_, has)| has);
        let now_ns = crate::workspace::current_unix_ns();
        let mut old_util = DEFAULT_BASE_UTILITY;
        let mut new_util = DEFAULT_BASE_UTILITY;

        db.transact_key(NodeKind::Generic, REFLEX_UTILITY_BOOK_KEY, |existing| {
            let mut book: ReflexUtilityBook = existing
                .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
                .unwrap_or_default();
            let entry = book.stats.entry(id_clean.to_owned()).or_default();
            old_util = compute_smoothed_utility(base_u0, Some(entry));
            if success {
                entry.successes = entry.successes.saturating_add(1);
            } else {
                entry.failures = entry.failures.saturating_add(1);
            }
            entry.last_updated_ns = now_ns;
            new_util = compute_smoothed_utility(base_u0, Some(entry));
            let bytes = serde_json::to_vec(&book)
                .map_err(|_| libredb_core::LibreDbError::CorruptFormat("reflex utility json serialize"))?;
            Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
        })?;

        if !success && has_supersedes && old_util >= 0.60 && new_util < 0.60 {
            crate::learning::note_method_supersede(db);
        }
        Ok(new_util)
    }

    /// Reconciles all active code-grounded `ReflexRule` capsules against the live workspace
    /// symbol and file sets. Any reflex with non-empty `code_anchors` whose anchors have all
    /// vanished from the workspace is deprecated (`SUPERSEDED`) so zombie warnings never linger.
    /// Callers must only invoke this on unsealed workspaces or inside seal-guarded write paths.
    /// Returns the number of falsified reflexes deprecated.
    pub fn reconcile_grounded_reflexes(
        db: &LibreDb,
        live_rel_paths: &HashSet<&str>,
        live_symbols: &HashSet<String>,
    ) -> Result<usize> {
        let live_files_owned: HashSet<String> =
            live_rel_paths.iter().map(|s| (*s).to_owned()).collect();
        let mut stale_reflex_ids: Vec<u64> = Vec::new();
        for (nid, _, rule) in load_reflex_rules(db)? {
            if !rule.code_anchors.is_empty()
                && !reflex_matches_live_anchors(&rule, &live_files_owned, live_symbols)
            {
                stale_reflex_ids.push(nid);
            }
        }
        if !stale_reflex_ids.is_empty() {
            db.deprecate_nodes(&stale_reflex_ids)?;
        }
        Ok(stale_reflex_ids.len())
    }

    /// Persists or updates a learned situational reflex inside `db`, capturing signature hashes of
    /// all anchors that resolve to live symbols (`anchor_contracts`) for later drift detection.
    pub fn learn_reflex(db: &LibreDb, rule: &ReflexRule) -> Result<u64> {
        let mut stored = rule.clone();
        stored.anchor_contract_hash = None;
        if !stored.code_anchors.is_empty() && stored.anchor_contracts.is_empty() {
            let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
            stored.anchor_contracts = stored
                .code_anchors
                .iter()
                .filter_map(|a| {
                    let norm = normalize_anchor(a)?;
                    let h = current_anchor_contract_hash(db, &sym_inodes, &norm)?;
                    Some((norm, h))
                })
                .collect();
        }
        let key = format!("{REFLEX_KEY_PREFIX}{}", stored.id);
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| libredb_core::LibreDbError::CorruptFormat("reflex json serialize"))?;
        db.put(
            WriteRequest::new(NodeKind::Rule, bytes)
                .with_key(key)
                .with_importance(240)
                .with_pinned(true),
        )
    }

    /// Convenience wrapper around `learn_reflex` accepting explicit situational superseding & utility fields.
    #[allow(clippy::too_many_arguments)]
    pub fn learn_reflex_with_options(
        db: &LibreDb,
        id: &str,
        stack_any: Vec<String>,
        action_any: Vec<String>,
        env_or_error_any: Vec<String>,
        context_tags: Vec<String>,
        supersedes: Vec<String>,
        base_utility: Option<f64>,
        directive: &str,
        code_anchors: Vec<String>,
    ) -> Result<u64> {
        let rule = ReflexRule {
            id: id.to_owned(),
            stack_any,
            action_any,
            env_or_error_any,
            context_tags,
            supersedes,
            base_utility: base_utility.map(|u| u.clamp(0.10, 0.99)),
            directive: directive.to_owned(),
            code_anchors,
            ..Default::default()
        };
        Self::learn_reflex(db, &rule)
    }

    /// Evaluates all learned reflexes against `(workspace_dir, query, error_context)`.
    pub fn evaluate(
        &self,
        workspace_dir: Option<&Path>,
        query: &str,
        error_context: Option<&str>,
    ) -> Vec<FiredReflex> {
        self.evaluate_with_anchor_context(workspace_dir, query, error_context, None)
    }

    /// Like `evaluate`, but validates code-anchored reflexes of a layer without its own code graph
    /// (e.g. global `customizations.ldb`) against `anchor_context`'s live workspace anchors,
    /// scores each candidate by `Spec(r, C) * Utility(r)`, and suppresses superseded general rules
    /// when a higher-scoring specialized rule applies.
    pub fn evaluate_with_anchor_context(
        &self,
        workspace_dir: Option<&Path>,
        query: &str,
        error_context: Option<&str>,
        anchor_context: Option<&ReflexEngine>,
    ) -> Vec<FiredReflex> {
        if self.rules.is_empty() {
            return Vec::new();
        }

        let markers = workspace_dir.map(detect_workspace_markers).unwrap_or_default();
        let ws_low = workspace_dir
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let q_low = query.to_lowercase();
        let err_low = error_context.unwrap_or("").to_lowercase();
        let markers_joined = markers.join(" ");
        let env_combined = format!("{ws_low} {markers_joined} {err_low} {q_low}");
        let foreign_sets = if self.live_sets.is_none() {
            anchor_context.and_then(|c| c.live_sets.as_ref())
        } else {
            None
        };

        struct Candidate<'a> {
            nid: u64,
            gen: u32,
            rule: &'a ReflexRule,
            drifted: bool,
            spec: f64,
            score: f64,
            norm_anchors: std::collections::BTreeSet<String>,
            norm_actions: std::collections::BTreeSet<String>,
            superseded_ids: Vec<String>,
        }

        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        for (nid, gen, rule, drifted) in &self.rules {
            if rule.stack_any.is_empty()
                && rule.action_any.is_empty()
                && rule.env_or_error_any.is_empty()
                && rule.context_tags.is_empty()
            {
                continue;
            }
            if !rule.code_anchors.is_empty() {
                if let Some((files, syms)) = foreign_sets {
                    if !reflex_matches_live_anchors(rule, files, syms) {
                        continue;
                    }
                }
            }

            let stack_ok = rule.stack_any.is_empty()
                || rule.stack_any.iter().any(|s| {
                    let sl = s.to_lowercase();
                    markers.iter().any(|m| m.contains(&sl)) || q_low.contains(&sl)
                });
            if !stack_ok {
                continue;
            }

            let action_matched = !rule.action_any.is_empty()
                && rule.action_any.iter().any(|a| {
                    let al = a.to_lowercase();
                    q_low.contains(&al) || err_low.contains(&al)
                });
            // Learned error pitfalls fire on direct error recurrence regardless of which CLI/build
            // verb (`build`, `test`, `pulse`) surfaced the error, reserving `action_any` for pure proactive runs.
            let pitfall_error_override = rule.id.starts_with("pitfall::")
                && !err_low.is_empty()
                && rule
                    .env_or_error_any
                    .iter()
                    .any(|e| err_low.contains(&e.to_lowercase()));
            let action_ok = rule.action_any.is_empty() || action_matched || pitfall_error_override;
            if !action_ok {
                continue;
            }

            let env_ok = rule.env_or_error_any.is_empty()
                || rule
                    .env_or_error_any
                    .iter()
                    .any(|e| env_combined.contains(&e.to_lowercase()));
            if !env_ok {
                continue;
            }

            let context_ok = rule.context_tags.is_empty()
                || rule
                    .context_tags
                    .iter()
                    .all(|ct| env_combined.contains(&ct.to_lowercase()));
            if !context_ok {
                continue;
            }

            let m_stack = if rule.stack_any.is_empty() { 0.0 } else { 1.0 };
            let m_action = if action_matched { 1.0 } else { 0.0 };
            let m_env = if rule.env_or_error_any.is_empty() {
                0.0
            } else {
                1.0
            };
            let m_anchor = if rule.code_anchors.is_empty() { 0.0 } else { 1.0 };
            let spec = 1.0
                + 0.15 * (m_stack + m_action + m_env)
                + 0.25 * m_anchor
                + 0.35 * (rule.context_tags.len() as f64);
            let utility =
                compute_smoothed_utility(rule.base_utility, self.utility_book.stats.get(&rule.id));
            let drift_mult = if *drifted { 0.70 } else { 1.00 };
            let score = spec * utility * drift_mult;

            let norm_anchors = rule
                .code_anchors
                .iter()
                .map(|a| a.trim().replace('\\', "/").to_lowercase())
                .filter(|a| !a.is_empty())
                .collect();
            let norm_actions = rule
                .action_any
                .iter()
                .map(|a| a.trim().to_lowercase())
                .filter(|a| !a.is_empty())
                .collect();

            candidates.push(Candidate {
                nid: *nid,
                gen: *gen,
                rule,
                drifted: *drifted,
                spec,
                score,
                norm_anchors,
                norm_actions,
                superseded_ids: Vec::new(),
            });
        }

        // Situational superseding: specialized or empirically superior rules suppress older rivals
        // in overlapping contexts unless empirical failures eroded the newer rule below 0.80 * old.
        let n = candidates.len();
        let mut suppressed = vec![false; n];
        for i in 0..n {
            if candidates[i].drifted {
                continue;
            }
            for j in 0..n {
                if i == j {
                    continue;
                }
                let explicit_supersede = candidates[i]
                    .rule
                    .supersedes
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&candidates[j].rule.id))
                    && candidates[i].score + 1e-9 >= 0.80 * candidates[j].score;

                let implicit_rival = !candidates[i].norm_anchors.is_empty()
                    && candidates[i].norm_anchors == candidates[j].norm_anchors
                    && !candidates[i].norm_actions.is_empty()
                    && candidates[i].norm_actions == candidates[j].norm_actions
                    && candidates[i].spec + 1e-9 >= candidates[j].spec
                    && candidates[i].score >= candidates[j].score + 0.15;

                if explicit_supersede || implicit_rival {
                    suppressed[j] = true;
                    let sup_id = candidates[j].rule.id.clone();
                    if !candidates[i].superseded_ids.contains(&sup_id) {
                        candidates[i].superseded_ids.push(sup_id);
                    }
                }
            }
        }

        let mut fired = Vec::new();
        for (idx, mut cand) in candidates.into_iter().enumerate() {
            if suppressed[idx] {
                continue;
            }
            cand.superseded_ids.sort();
            let directive = if cand.drifted {
                format!(
                    "[REFLEX {} (anchor contract changed; verify)]: {}",
                    cand.rule.id, cand.rule.directive
                )
            } else {
                cand.rule.directive.clone()
            };
            let tok = count_tokens_exact(directive.as_bytes());
            fired.push(FiredReflex {
                id: cand.rule.id.clone(),
                node_id: cand.nid,
                generation: cand.gen,
                token_count: tok,
                directive,
                score: cand.score,
                superseded_ids: cand.superseded_ids,
            });
        }
        fired.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        fired
    }
}

fn load_utility_book(db: &LibreDb) -> ReflexUtilityBook {
    db.get_by_key(NodeKind::Generic, REFLEX_UTILITY_BOOK_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<ReflexUtilityBook>(&rec.payload).ok())
        .unwrap_or_default()
}

fn load_reflex_rules(db: &LibreDb) -> Result<Vec<(u64, u32, ReflexRule)>> {
    let fetch_ids: Vec<u64> = db
        .list_inodes(Some(NodeKind::Rule), false)
        .iter()
        .filter_map(|(ino, key, _)| {
            key.as_deref()?
                .starts_with(REFLEX_KEY_PREFIX)
                .then_some(ino.node_id)
        })
        .collect();
    if fetch_ids.is_empty() {
        return Ok(Vec::new());
    }
    let (records, _) = db.get_many_coalesced(&fetch_ids)?;
    Ok(records
        .into_iter()
        .filter_map(|rec| {
            serde_json::from_slice::<ReflexRule>(&rec.payload)
                .ok()
                .map(|parsed| (rec.node_id, rec.generation, parsed))
        })
        .collect())
}

fn classify_rules(
    db: &LibreDb,
    parsed: Vec<(u64, u32, ReflexRule)>,
) -> (Option<LiveAnchorSets>, Vec<(u64, u32, ReflexRule, RuleState)>) {
    let any_anchored = parsed.iter().any(|(_, _, r)| !r.code_anchors.is_empty());
    let live_sets = if any_anchored {
        collect_live_workspace_anchor_sets(db)
    } else {
        None
    };
    let sym_inodes: SymbolInodes = if live_sets.is_some()
        && parsed.iter().any(|(_, _, r)| !r.anchor_contracts.is_empty())
    {
        db.list_inodes(Some(NodeKind::Symbol), false)
    } else {
        Vec::new()
    };
    let classified = parsed
        .into_iter()
        .map(|(nid, gen, rule)| {
            let state = match live_sets {
                Some((ref files, ref syms)) if !rule.code_anchors.is_empty() => {
                    if !reflex_matches_live_anchors(&rule, files, syms) {
                        RuleState::Falsified
                    } else if rule.anchor_contracts.iter().any(|(anchor, learned)| {
                        current_anchor_contract_hash(db, &sym_inodes, anchor)
                            .is_some_and(|now| now != *learned)
                    }) {
                        RuleState::Drift
                    } else {
                        RuleState::Active
                    }
                }
                _ => RuleState::Active,
            };
            (nid, gen, rule, state)
        })
        .collect();
    (live_sets, classified)
}

fn normalize_anchor(raw: &str) -> Option<String> {
    let norm = raw.trim().replace('\\', "/");
    (!norm.is_empty()).then_some(norm)
}

/// Resolves `anchor` to the lexicographically first matching live symbol and hashes its contract
/// signature (`(kind) signature`, excluding line span and doc summary).
fn current_anchor_contract_hash(
    db: &LibreDb,
    sym_inodes: &SymbolInodes,
    anchor: &str,
) -> Option<u64> {
    let mut best: Option<(String, u64)> = None;
    for (ino, key_opt, _) in sym_inodes {
        let Some(full_k) = key_opt.as_deref() else {
            continue;
        };
        let stripped = crate::workspace::strip_line_disambiguator(full_k);
        let matched = stripped == anchor
            || stripped.split_once("::").is_some_and(|(_, sym_part)| {
                let clean = sym_part.split('@').next().unwrap_or(sym_part);
                clean == anchor
                    || clean.rsplit_once("::").is_some_and(|(_, short)| short == anchor)
                    || anchor
                        .split_once("::")
                        .is_some_and(|(_, anchor_sym)| anchor_sym == clean)
            });
        if matched && best.as_ref().map_or(true, |(bk, _)| stripped < bk.as_str()) {
            best = Some((stripped.to_owned(), ino.node_id));
        }
    }
    let (_, nid) = best?;
    let rec = db.get(nid).ok()?;
    let text = String::from_utf8_lossy(&rec.payload);
    let after_span = text.split_once("] ").map_or(text.as_ref(), |(_, rest)| rest);
    let signature = after_span.split(" // ").next().unwrap_or(after_span).trim();
    Some(hash_key(ANCHOR_CONTRACT_HASH_SEED, signature.as_bytes()))
}

/// Collects lowercase filenames present at the root of `dir` as language-agnostic workspace markers
/// (e.g. `"cargo.toml"`, `"pyproject.toml"`, `"package.json"`, `".git"` - zero hardcoded stack taxonomy).
pub fn detect_workspace_markers(dir: &Path) -> Vec<String> {
    let mut markers = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten().take(128) {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            markers.push(name);
        }
    }
    markers
}

fn collect_live_workspace_anchor_sets(db: &LibreDb) -> Option<LiveAnchorSets> {
    let sym_inodes = db.list_inodes(Some(NodeKind::Symbol), false);
    let has_graph_state = db
        .get_by_key(NodeKind::Generic, crate::workspace::WORKSPACE_GRAPH_STATE_KEY)
        .is_ok();
    if sym_inodes.is_empty() && !has_graph_state {
        return None;
    }
    let mut live_files: HashSet<String> = HashSet::new();
    let mut live_syms: HashSet<String> = HashSet::new();
    for (_, key_opt, _) in sym_inodes {
        let Some(full_k) = key_opt else { continue };
        let stripped = full_k
            .rsplit_once("@L")
            .map_or(full_k.as_str(), |(h, _)| h);
        live_syms.insert(stripped.to_owned());
        if let Some((file_part, sym_part)) = stripped.split_once("::") {
            live_files.insert(file_part.to_owned());
            let clean_sym = sym_part.split('@').next().unwrap_or(sym_part);
            live_syms.insert(clean_sym.to_owned());
            if let Some((_, short_name)) = clean_sym.rsplit_once("::") {
                live_syms.insert(short_name.to_owned());
            }
        }
    }
    for (_, key_opt, _) in db.list_inodes(Some(NodeKind::WorkingSet), false) {
        if let Some(k) = key_opt {
            if let Some(rel) = k.strip_prefix(crate::skeleton::SKELETON_KEY_PREFIX) {
                live_files.insert(rel.to_owned());
            }
        }
    }
    Some((live_files, live_syms))
}

pub(crate) fn reflex_matches_live_anchors(
    rule: &ReflexRule,
    live_files: &HashSet<String>,
    live_syms: &HashSet<String>,
) -> bool {
    if rule.code_anchors.is_empty() {
        return true;
    }
    rule.code_anchors.iter().any(|raw_anchor| {
        let norm = raw_anchor.trim().replace('\\', "/");
        if norm.is_empty() {
            return false;
        }
        if live_files.contains(&norm) || live_syms.contains(&norm) {
            return true;
        }
        if let Some((_, sym_part)) = norm.split_once("::") {
            if live_syms.contains(sym_part) {
                return true;
            }
        }
        false
    })
}
