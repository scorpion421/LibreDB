//! Data-driven Situational Pitfall & Experience Reflex Engine (`ReflexEngine`).
//!
//! Zero hardcoded rules: every `ReflexRule` is learned from experience and persisted inside
//! `LibreDb` (`NodeKind::Rule` with key `reflex::<id>`). When `pulse` runs, matching reflexes
//! fire proactively (`< 0.05 ms`) before execution to prevent costly error-recovery turns.

use libredb_core::crc::count_tokens_exact;
use libredb_core::{LibreDb, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const REFLEX_KEY_PREFIX: &str = "reflex::";

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
    /// and symbols vanish from the workspace, the reflex is automatically falsified (deprecated).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_anchors: Vec<String>,
    /// Optional FNV-1a hash of the anchored symbol signature/contract at learning time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_contract_hash: Option<u64>,
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

/// Evaluates persisted learned reflexes against live workspace/action/error context.
#[derive(Default)]
pub struct ReflexEngine {
    rules: Vec<(u64, u32, ReflexRule)>,
}

impl ReflexEngine {
    /// Loads all learned `ReflexRule` capsules purely from `db` (`0` hardcoded rules),
    /// automatically filtering out code-grounded reflexes whose anchored files/symbols no longer
    /// exist in an indexed workspace.
    pub fn load(db: &LibreDb) -> Result<Self> {
        let mut engine = Self::default();
        let rule_inodes = db.list_inodes(Some(NodeKind::Rule), false);
        let fetch_ids: Vec<u64> = rule_inodes
            .iter()
            .filter_map(|(ino, key, _)| {
                let k = key.as_deref()?;
                if k.starts_with(REFLEX_KEY_PREFIX) {
                    Some(ino.node_id)
                } else {
                    None
                }
            })
            .collect();

        if fetch_ids.is_empty() {
            return Ok(engine);
        }

        let (records, _) = db.get_many_coalesced(&fetch_ids)?;
        let mut parsed_rules = Vec::with_capacity(records.len());
        let mut any_anchored = false;
        for rec in records {
            if let Ok(parsed) = serde_json::from_slice::<ReflexRule>(&rec.payload) {
                if !parsed.code_anchors.is_empty() {
                    any_anchored = true;
                }
                parsed_rules.push((rec.node_id, rec.generation, parsed));
            }
        }

        let live_sets_opt = if any_anchored {
            collect_live_workspace_anchor_sets(db)
        } else {
            None
        };

        for (nid, gen, parsed) in parsed_rules {
            if !parsed.code_anchors.is_empty() {
                if let Some((ref live_files, ref live_syms)) = live_sets_opt {
                    if !reflex_matches_live_anchors(&parsed, live_files, live_syms) {
                        continue;
                    }
                }
            }
            engine.rules.push((nid, gen, parsed));
        }
        Ok(engine)
    }

    /// Reconciles all active code-grounded `ReflexRule` capsules against the live workspace
    /// symbol and file sets. Any reflex with non-empty `code_anchors` whose anchors have all
    /// vanished from the workspace is deprecated (`SUPERSEDED`) so zombie warnings never linger.
    /// Returns the number of falsified reflexes deprecated.
    pub fn reconcile_grounded_reflexes(
        db: &LibreDb,
        live_rel_paths: &HashSet<&str>,
        live_symbols: &HashSet<String>,
    ) -> Result<usize> {
        let rule_inodes = db.list_inodes(Some(NodeKind::Rule), false);
        let fetch_ids: Vec<u64> = rule_inodes
            .iter()
            .filter_map(|(ino, key, _)| {
                let k = key.as_deref()?;
                k.starts_with(REFLEX_KEY_PREFIX).then_some(ino.node_id)
            })
            .collect();
        if fetch_ids.is_empty() {
            return Ok(0);
        }

        let live_files_owned: HashSet<String> =
            live_rel_paths.iter().map(|s| (*s).to_owned()).collect();
        let (records, _) = db.get_many_coalesced(&fetch_ids)?;
        let mut stale_reflex_ids: Vec<u64> = Vec::new();
        for rec in records {
            if let Ok(parsed) = serde_json::from_slice::<ReflexRule>(&rec.payload) {
                if !parsed.code_anchors.is_empty()
                    && !reflex_matches_live_anchors(&parsed, &live_files_owned, live_symbols)
                {
                    stale_reflex_ids.push(rec.node_id);
                }
            }
        }
        if !stale_reflex_ids.is_empty() {
            db.deprecate_nodes(&stale_reflex_ids)?;
        }
        Ok(stale_reflex_ids.len())
    }

    /// Persists or updates a learned situational reflex inside `db`.
    pub fn learn_reflex(db: &LibreDb, rule: &ReflexRule) -> Result<u64> {
        let key = format!("{REFLEX_KEY_PREFIX}{}", rule.id);
        let bytes = serde_json::to_vec(rule)
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

        let mut fired = Vec::new();
        for (nid, gen, rule) in &self.rules {
            if rule.stack_any.is_empty()
                && rule.action_any.is_empty()
                && rule.env_or_error_any.is_empty()
            {
                continue;
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
                let tok = count_tokens_exact(rule.directive.as_bytes());
                fired.push(FiredReflex {
                    id: rule.id.clone(),
                    node_id: *nid,
                    generation: *gen,
                    token_count: tok,
                    directive: rule.directive.clone(),
                });
            }
        }
        fired
    }
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

fn collect_live_workspace_anchor_sets(db: &LibreDb) -> Option<(HashSet<String>, HashSet<String>)> {
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
