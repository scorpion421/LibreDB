//! Session Zero-Repeat Delta Delivery (`SessionLedger`).
//!
//! Tracks exactly which `(node_id -> generation)` pairs have already been injected into a given
//! `(conversation_id, compaction_epoch)` context window. Prevents duplicate rules, skills, facts,
//! and file skeletons from being emitted twice in the same session while automatically re-emitting
//! mutated nodes (`generation > seen_generation`) or re-hydrating after `/compact` (`epoch + 1`).

use libredb_core::{LibreDb, LibreDbError, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Persisted per-conversation state stored as a `NodeKind::TranscriptCursor` capsule inside `.ldb`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub conversation_id: String,
    pub active_epoch: u32,
    /// Maps `node_id -> last_delivered_generation` within `active_epoch`.
    pub delivered_generations: HashMap<u64, u32>,
    pub cumulative_tokens_saved: u64,
    pub duplicate_hits_suppressed: u64,
}

impl SessionState {
    pub fn new(conversation_id: impl Into<String>, active_epoch: u32) -> Self {
        Self {
            conversation_id: conversation_id.into(),
            active_epoch,
            delivered_generations: HashMap::new(),
            cumulative_tokens_saved: 0,
            duplicate_hits_suppressed: 0,
        }
    }

    /// Loads session state for `conversation_id` from `db`. If `current_epoch > stored.active_epoch`
    /// (for example after `/compact`), automatically clears `delivered_generations` for clean re-hydration!
    pub fn load_or_init(db: &LibreDb, conversation_id: &str, current_epoch: u32) -> Result<Self> {
        let storage_key = format!("session_delta::{conversation_id}");
        match db.get_by_key(NodeKind::TranscriptCursor, &storage_key) {
            Ok(rec) => {
                let mut parsed: SessionState = serde_json::from_slice(&rec.payload)
                    .unwrap_or_else(|_| SessionState::new(conversation_id, current_epoch));
                if current_epoch != parsed.active_epoch {
                    parsed.active_epoch = current_epoch;
                    parsed.delivered_generations.clear();
                }
                Ok(parsed)
            }
            Err(LibreDbError::KeyNotFound { .. }) => {
                Ok(SessionState::new(conversation_id, current_epoch))
            }
            Err(other) => Err(other),
        }
    }

    /// Returns true if `(node_id, generation)` is already present verbatim in the active session window.
    #[inline]
    pub fn is_already_in_context(&self, node_id: u64, generation: u32) -> bool {
        self.delivered_generations
            .get(&node_id)
            .copied()
            .is_some_and(|seen_gen| seen_gen >= generation)
    }

    /// Records that `(node_id, generation)` has now been delivered in full to the LLM context.
    #[inline]
    pub fn mark_delivered(&mut self, node_id: u64, generation: u32) {
        self.delivered_generations.insert(node_id, generation);
    }

    /// Records a suppressed duplicate delivery and adds `saved_tokens` to session telemetry.
    #[inline]
    pub fn record_suppression(&mut self, full_tokens: u32, stub_tokens: u32) {
        self.duplicate_hits_suppressed += 1;
        self.cumulative_tokens_saved += full_tokens.saturating_sub(stub_tokens) as u64;
    }

    /// Persists the updated `SessionState` atomically back into `db`.
    pub fn save(&self, db: &LibreDb) -> Result<u64> {
        let storage_key = format!("session_delta::{}", self.conversation_id);
        let bytes = serde_json::to_vec(self)
            .map_err(|e| LibreDbError::CorruptFormat(if e.is_io() { "session io" } else { "session json" }))?;
        db.put(
            WriteRequest::new(NodeKind::TranscriptCursor, bytes)
                .with_key(storage_key)
                .with_importance(64),
        )
    }
}
