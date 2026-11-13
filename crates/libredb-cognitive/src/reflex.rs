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
const ANCHOR_CONTRACT_HASH_SEED: u8 = 0xA7;

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
}

/// Runtime classification of a learned reflex (`libredb learning`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexStatus {
    pub id: String,
    /// `active`, `drift` (anchored signature changed), or `falsified` (all anchors vanished).
    pub status: String,
    pub anchors: Vec<String>,
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
}

impl ReflexEngine {
    /// Loads all learned `ReflexRule` capsules purely from `db` (`0` hardcoded rules),
    /// suppressing code-grounded reflexes whose anchored files/symbols no longer exist in an indexed
    /// workspace and flagging reflexes whose anchored signatures drifted.
    pub fn load(db: &LibreDb) -> Result<Self> {
        let parsed = load_reflex_rules(db)?;
        let (live_sets, classified) = classify_rules(db, parsed);
        let rules = classified
            .into_iter()
            .filter(|(_, _, _, st)| *st != RuleState::Falsified)
            .map(|(nid, gen, rule, st)| (nid, gen, rule, st == RuleState::Drift))
            .collect();
        Ok(Self { rules, live_sets })
    }

    /// Returns the runtime status of every learned reflex in `db` (`0` writes).
    pub fn describe_all(db: &LibreDb) -> Vec<ReflexStatus> {
        let Ok(parsed) = load_reflex_rules(db) else {
            return Vec::new();
        };
        let (_, classified) = classify_rules(db, parsed);
        let mut out: Vec<ReflexStatus> = classified
            .into_iter()
            .map(|(_, _, rule, st)| ReflexStatus {
                id: rule.id,
                status: match st {
                    RuleState::Active => "active",
                    RuleState::Drift => "drift",
                    RuleState::Falsified => "falsified",
                }
                .to_owned(),
                anchors: rule.code_anchors,
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
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
    /// (e.g. global `customizations.ldb`) against `anchor_context`'s live workspace anchors.
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
        let env_combined = format!("{ws_low} {err_low} {q_low}");
        let foreign_sets = if self.live_sets.is_none() {
            anchor_context.and_then(|c| c.live_sets.as_ref())
        } else {
            None
        };

        let mut fired = Vec::new();
        for (nid, gen, rule, drifted) in &self.rules {
            if rule.stack_any.is_empty()
                && rule.action_any.is_empty()
                && rule.env_or_error_any.is_empty()
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

            let action_ok = rule.action_any.is_empty()
                || rule.action_any.iter().any(|a| {
                    let al = a.to_lowercase();
                    q_low.contains(&al) || err_low.contains(&al)
                });

            let env_ok = rule.env_or_error_any.is_empty()
                || rule
                    .env_or_error_any
                    .iter()
                    .any(|e| env_combined.contains(&e.to_lowercase()));

            if stack_ok && action_ok && env_ok {
                let directive = if *drifted {
                    format!(
                        "[REFLEX {} (anchor contract changed; verify)]: {}",
                        rule.id, rule.directive
                    )
                } else {
                    rule.directive.clone()
                };
                let tok = count_tokens_exact(directive.as_bytes());
                fired.push(FiredReflex {
                    id: rule.id.clone(),
                    node_id: *nid,
                    generation: *gen,
                    token_count: tok,
                    directive,
                });
            }
        }
        fired
    }
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
