//! Data-driven Situational Pitfall & Experience Reflex Engine (`ReflexEngine`).
//!
//! Zero hardcoded rules: every `ReflexRule` is learned from experience and persisted inside
//! `LibreDb` (`NodeKind::Rule` with key `reflex::<id>`). When `pulse` runs, matching reflexes
//! fire proactively (`< 0.05 ms`) before execution to prevent costly error-recovery turns.

use libredb_core::crc::count_tokens_exact;
use libredb_core::{LibreDb, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const REFLEX_KEY_PREFIX: &str = "reflex::";

/// Structured situational trigger persisted inside `LibreDb` (`NodeKind::Rule` with `reflex::` key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexRule {
    pub id: String,
    /// Matches if empty OR any tag matches detected workspace markers (`cargo.toml`, `pyproject.toml`, etc.) or query.
    pub stack_any: Vec<String>,
    /// Matches if empty OR any substring appears in the active task/command/query.
    pub action_any: Vec<String>,
    /// Matches if empty OR any substring appears in workspace path or observed error output.
    pub env_or_error_any: Vec<String>,
    /// Concise actionable warning (`15-40` tokens) injected into `pulse` output.
    pub directive: String,
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
    /// Loads all learned `ReflexRule` capsules purely from `db` (`0` hardcoded rules).
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

        let (records, _) = db.get_many_coalesced(&fetch_ids)?;
        for rec in records {
            if let Ok(parsed) = serde_json::from_slice::<ReflexRule>(&rec.payload) {
                engine.rules.push((rec.node_id, rec.generation, parsed));
            }
        }
        Ok(engine)
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
