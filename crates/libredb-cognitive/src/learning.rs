//! Closed-loop causal learning (`Search-Miss -> Verified-Edit`) for LibreDB workspaces.
//!
//! 1. **Miss recording** with source tagging (`locate`, `impact`, `pulse`), executed atomically via
//!    `LibreDb::transact_key` so concurrent hook and MCP processes never lose updates.
//! 2. **Precise symbol diffs** (`diff_symbol_bodies`) based on whitespace-insensitive per-symbol body
//!    hashes instead of whole-file prefix/suffix guessing.
//! 3. **Causal binding**: a cue recorded at `t_miss` binds only to edits with `t_edit >= t_miss`, within
//!    one multi-file episode (`120 s`, `<= 3` files, `<= 8` symbols).
//! 4. **Calibrated bridge scoring** (`BridgeScorer`): specificity-weighted query coverage times learned
//!    confidence on an absolute scale (`>= 0.80` accepted everywhere).
//! 5. **Read-only learning report** for `libredb learning`.
//!
//! All learning state lives in unsealed `NodeKind::Generic` capsules (`sys::*`) that are never hydrated
//! into prompts and never participate in workspace trust seals.

use crate::reflex::{ReflexEngine, ReflexStatus};
use crate::skeleton::{FileSkeleton, SymbolContract};
use crate::workspace::{compute_file_symbol_keys, current_unix_ns, strip_line_disambiguator};
use libredb_core::{LibreDb, LibreDbError, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Internal ring-buffer key storing recent unresolved queries awaiting a verified edit.
pub const PENDING_MISS_CUES_KEY: &str = "sys::pending_miss_cues";
/// Internal causal symbol-alias bridge key mapping `cue_token -> Vec<(symbol_key, weight)>`.
pub const SYMBOL_CUE_BRIDGES_KEY: &str = "sys::symbol_cue_bridges";
/// Internal ring-buffer key storing non-banal observed errors awaiting a structural fix edit.
pub const PENDING_ERROR_CUES_KEY: &str = "sys::pending_error_cues";
/// Internal procedural error-recovery pitfall book (`NodeKind::Generic`, seal-neutral).
pub const ERROR_PITFALL_BOOK_KEY: &str = "sys::error_pitfall_book";
/// Minimum confidence required for a learned pitfall entry to fire proactively in `ReflexEngine`.
pub const ACTIVE_PITFALL_MIN_CONFIDENCE: f64 = 0.75;
/// Maximum pending error cues retained in `sys::pending_error_cues`.
pub const MAX_PENDING_ERROR_CUES: usize = 32;
/// Maximum learned error pitfalls retained in `sys::error_pitfall_book`.
pub const MAX_LEARNED_PITFALLS: usize = 128;
const PITFALL_ID_HASH_SEED: u8 = 0xE1;
/// Internal learning counters (`misses_recorded`, `bindings_learned`, ...).
pub const LEARNING_COUNTERS_KEY: &str = "sys::learning_counters";
/// Maximum pending search-miss cues retained in `sys::pending_miss_cues`.
pub const MAX_PENDING_MISS_CUES: usize = 8;
/// Expiration window (`30 minutes`) for binding a search miss cue to a verified edit.
pub const MISS_CUE_TTL_NS: u128 = 30 * 60 * 1_000_000_000;
/// Multi-file episode window (`120 s`, measured in edit time) after the first binding of a cue.
pub const CUE_EPISODE_WINDOW_NS: u128 = 120 * 1_000_000_000;
/// Maximum distinct files a single cue may bind to (broader changes are refactorings).
pub const MAX_CUE_BOUND_FILES: usize = 3;
/// Maximum distinct symbols a single cue may bind to across all files.
pub const MAX_CUE_BOUND_SYMBOLS: usize = 8;
/// Maximum modified symbols per single edit that still count as a targeted change.
pub const MAX_TOUCHED_PER_EDIT: usize = 6;
/// Maximum changed files per index scan that still count as targeted external edits.
pub const MAX_INDEX_SCAN_LEARN_FILES: usize = 3;
/// Maximum cue tokens retained in `sys::symbol_cue_bridges`.
pub const MAX_BRIDGE_BOOK_TOKENS: usize = 512;
/// Maximum symbol targets per cue token.
pub const MAX_TARGETS_PER_CUE_TOKEN: usize = 8;
/// Absolute acceptance threshold for bridge scores in `locate`, `impact`, and `pulse`.
pub const BRIDGE_MIN_SCORE: f64 = 0.80;
/// Scale factor mapping `coverage x confidence` onto the retrieval score axis.
pub const BRIDGE_SCORE_SCALE: f64 = 2.0;
/// Minimum token specificity required to store a non-identifier cue token as its own bridge.
pub const MIN_BIND_TOKEN_SPECIFICITY: f64 = 0.20;
const BRIDGE_REINFORCE_RETAIN: f64 = 0.40;

/// Origin of a recorded search miss; determines the initial bridge weight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MissCueSource {
    /// Explicit symbol search (`locate`).
    #[default]
    Locate,
    /// Explicit blast-radius query (`impact`).
    Impact,
    /// Prose memory query (`pulse`); weaker evidence.
    Pulse,
}

impl MissCueSource {
    pub fn initial_weight(self) -> f64 {
        match self {
            Self::Locate | Self::Impact => 0.60,
            Self::Pulse => 0.45,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locate => "locate",
            Self::Impact => "impact",
            Self::Pulse => "pulse",
        }
    }
}

/// Pending unresolved query awaiting a causally later verified code edit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMissCue {
    pub raw_query: String,
    pub tokens: Vec<String>,
    pub recorded_at_ns: u128,
    #[serde(default)]
    pub source: MissCueSource,
    /// Edit timestamp of the first binding (opens the multi-file episode window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_bound_edit_ns: Option<u128>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bound_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bound_symbols: Vec<String>,
}

/// Persisted causal bridge mapping learned query cue tokens to workspace `symbol_key` strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolCueBridgeBook {
    pub bridges: BTreeMap<String, Vec<(String, f64)>>,
}

/// Pending non-banal error observed during execution awaiting a structural fix edit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingErrorCue {
    pub fingerprint_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub error_tokens: Vec<String>,
    pub raw_excerpt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_hint: Option<String>,
    pub recorded_at_ns: u128,
}

/// Verified procedural error-recovery entry persisted inside `sys::error_pitfall_book`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LearnedPitfallEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub trigger_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_tokens: Vec<String>,
    pub directive: String,
    pub confidence: f64,
    pub occurrences: u32,
    pub last_learned_ns: u128,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

impl LearnedPitfallEntry {
    /// Converts a matured error-recovery pitfall into a runtime `ReflexRule` so `ReflexEngine`
    /// can fire it proactively during subsequent similar tasks/errors.
    pub fn to_reflex_rule(&self) -> crate::reflex::ReflexRule {
        let mut triggers = self.trigger_tokens.clone();
        for sym in &self.affected_symbols {
            if let Some((_, sym_part)) = sym.split_once("::") {
                let short = sym_part.split('@').next().unwrap_or(sym_part);
                if short.len() >= 4 && !triggers.iter().any(|t| t.eq_ignore_ascii_case(short)) {
                    triggers.push(short.to_owned());
                }
            }
        }
        crate::reflex::ReflexRule {
            id: format!("pitfall::{}", self.id),
            stack_any: Vec::new(),
            action_any: self.action_tokens.clone(),
            env_or_error_any: triggers,
            context_tags: Vec::new(),
            supersedes: self
                .supersedes
                .iter()
                .map(|s| {
                    if s.starts_with("pitfall::") {
                        s.clone()
                    } else {
                        format!("pitfall::{s}")
                    }
                })
                .collect(),
            base_utility: Some(self.confidence.clamp(0.10, 0.99)),
            directive: self.directive.clone(),
            code_anchors: self.affected_symbols.clone(),
            anchor_contract_hash: None,
            anchor_contracts: Vec::new(),
        }
    }
}

/// Persisted procedural error-recovery knowledge (`NodeKind::Generic`, seal-neutral).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorPitfallBook {
    #[serde(default)]
    pub pitfalls: BTreeMap<String, LearnedPitfallEntry>,
}

/// Cumulative learning counters persisted in `sys::learning_counters`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearningCounters {
    #[serde(default)]
    pub misses_recorded: u64,
    #[serde(default)]
    pub bindings_learned: u64,
    #[serde(default)]
    pub broad_edits_skipped: u64,
    #[serde(default)]
    pub bulk_scans_skipped: u64,
    #[serde(default)]
    pub error_cues_recorded: u64,
    #[serde(default)]
    pub trivial_errors_filtered: u64,
    #[serde(default)]
    pub pitfalls_learned: u64,
    #[serde(default)]
    pub failed_fixes_refuted: u64,
    #[serde(default)]
    pub method_supersedes_applied: u64,
}

/// Where a verified edit was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditOrigin {
    Hook,
    DiskSync,
    IndexScan,
}

/// Verified edit evidence fed into `learn_from_verified_edit`.
#[derive(Debug, Clone)]
pub(crate) struct EditEvidence {
    pub rel_path: String,
    /// Hook: `TentativeFileEdit.created_ns`; disk sync and index scans: file `mtime_ns`.
    pub edit_ns: u128,
    /// Stripped symbol keys whose bodies actually changed (`diff_symbol_bodies`).
    pub touched: Vec<String>,
    /// Newly added non-punctuation identifier/code tokens across `touched` symbols.
    /// Empty when the edit only touched `;`, `,`, `)`, comments, or whitespace.
    pub added_body_tokens: Vec<String>,
    #[allow(dead_code)]
    pub origin: EditOrigin,
}

// ---------------------------------------------------------------------------------------------
// Cue tokens
// ---------------------------------------------------------------------------------------------

/// Extracts bounded cue tokens (`<= 8`) from a raw query: universal segments (`>= 3` chars, not
/// purely numeric) plus the whole identifier when the query contains no whitespace.
pub(crate) fn extract_cue_tokens(raw_query: &str) -> Vec<String> {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() || trimmed.len() > 160 || trimmed.contains('/') || trimmed.contains('\\') {
        return Vec::new();
    }
    let mut tokens: Vec<String> = Vec::new();
    for t in libredb_index::segment_universal_tokens(trimmed) {
        if t.chars().count() >= 3 && !t.chars().all(|c| c.is_ascii_digit()) && !tokens.contains(&t) {
            tokens.push(t);
        }
    }
    if let Some(whole) = whole_identifier(trimmed) {
        if !tokens.contains(&whole) {
            tokens.insert(0, whole);
        }
    }
    tokens.truncate(8);
    tokens
}

fn whole_identifier(raw_query: &str) -> Option<String> {
    let w = raw_query.trim().trim_start_matches("::").to_lowercase();
    (w.len() >= 3 && !w.contains(char::is_whitespace)).then_some(w)
}

// ---------------------------------------------------------------------------------------------
// Miss recording
// ---------------------------------------------------------------------------------------------

/// Records an unresolved query from `locate` (default source) in `sys::pending_miss_cues`.
pub fn record_search_miss_cue(db: &LibreDb, raw_query: &str) -> Result<bool> {
    record_search_miss_cue_with_source(db, raw_query, MissCueSource::Locate)
}

/// Records an unresolved query with an explicit source atomically (`transact_key`).
/// Re-recording an already pending cue refreshes its timestamp (or re-opens a previously bound
/// episode when the same query STILL misses later, enabling Noisy-OR reinforcement on retry).
pub fn record_search_miss_cue_with_source(
    db: &LibreDb,
    raw_query: &str,
    source: MissCueSource,
) -> Result<bool> {
    let tokens = extract_cue_tokens(raw_query);
    if tokens.is_empty() {
        return Ok(false);
    }
    let now_ns = current_unix_ns();
    let trimmed = raw_query.trim().to_owned();
    let mut count_as_miss = false;
    db.transact_key(NodeKind::Generic, PENDING_MISS_CUES_KEY, |existing| {
        let mut cues: Vec<PendingMissCue> = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        cues.retain(|c| {
            !is_cue_retired(c, now_ns, now_ns)
                && !(c.first_bound_edit_ns.is_some() && !c.raw_query.eq_ignore_ascii_case(&trimmed))
        });
        if let Some(existing_cue) = cues
            .iter_mut()
            .find(|c| c.raw_query.eq_ignore_ascii_case(&trimmed))
        {
            if let Some(fb) = existing_cue.first_bound_edit_ns {
                if now_ns < fb {
                    return Ok(None);
                }
                existing_cue.first_bound_edit_ns = None;
                existing_cue.bound_files.clear();
                existing_cue.bound_symbols.clear();
                count_as_miss = true;
            }
            existing_cue.recorded_at_ns = now_ns;
            existing_cue.source = source;
        } else {
            cues.push(PendingMissCue {
                raw_query: trimmed.clone(),
                tokens: tokens.clone(),
                recorded_at_ns: now_ns,
                source,
                first_bound_edit_ns: None,
                bound_files: Vec::new(),
                bound_symbols: Vec::new(),
            });
            count_as_miss = true;
        }
        if cues.len() > MAX_PENDING_MISS_CUES {
            let drop_n = cues.len() - MAX_PENDING_MISS_CUES;
            cues.drain(0..drop_n);
        }
        let bytes = serde_json::to_vec(&cues)
            .map_err(|_| LibreDbError::CorruptFormat("pending miss cues serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
    })?;
    if count_as_miss {
        bump_learning_counters(db, |c| c.misses_recorded += 1);
    }
    Ok(true)
}

// ---------------------------------------------------------------------------------------------
// Procedural error-recovery & 2-stage banality filter (Stage 1: lex/pattern, Stage 2: AST diff)
// ---------------------------------------------------------------------------------------------

const SYNTAX_SLIP_PATTERNS: &[&str] = &[
    "expected ';'",
    "expected ','",
    "expected ')'",
    "expected '}'",
    "expected ']'",
    "unclosed delimiter",
    "unexpected token",
    "unexpected end of input",
    "unexpected eof",
    "missing semicolon",
    "trailing comma",
    "unterminated string",
];

const ERROR_BOILERPLATE_WORDS: &[&str] = &[
    "error", "warning", "note", "help", "cannot", "could", "find", "found", "expected",
    "unexpected", "this", "that", "with", "from", "into", "have", "here", "line", "column",
    "near", "before", "after", "eof", "end", "input", "value", "variable", "scope",
    "syntax", "syntaxerror", "parse", "parser", "token", "delimiter", "unclosed", "missing",
    "semicolon", "colon", "comma", "brace", "bracket", "paren", "parenthesis", "trailing",
    "quote", "unterminated", "character", "indent", "indentation", "whitespace", "mismatched",
    "mismatch", "expression", "statement", "declaration", "identifier", "type", "types",
];

fn extract_error_code(text: &str) -> Option<String> {
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if raw.len() >= 4 && raw.len() <= 8 {
            let bytes = raw.as_bytes();
            let alpha_prefix = bytes.iter().take_while(|b| b.is_ascii_uppercase()).count();
            let digit_suffix = bytes[alpha_prefix..]
                .iter()
                .filter(|b| b.is_ascii_digit())
                .count();
            if (1..=3).contains(&alpha_prefix)
                && digit_suffix >= 3
                && alpha_prefix + digit_suffix == bytes.len()
            {
                return Some(raw.to_ascii_lowercase());
            }
        }
    }
    None
}

fn is_error_boilerplate(tok: &str) -> bool {
    ERROR_BOILERPLATE_WORDS.contains(&tok)
}

/// Extracts `(optional_error_code, ordered_meaningful_tokens, deterministic_fingerprint_id)`
/// from raw error diagnostic text.
fn extract_error_signature(error_text: &str) -> (Option<String>, Vec<String>, String) {
    let error_code = extract_error_code(error_text);
    let mut tokens: Vec<String> = Vec::new();
    let mut push_unique = |tok: String| {
        if !tok.is_empty() && !tokens.contains(&tok) {
            tokens.push(tok);
        }
    };

    if let Some(ref ec) = error_code {
        push_unique(ec.clone());
    }

    // Preserve compound identifiers (`workspace_scope_root`, `CamelCaseId`) ahead of split subtokens.
    for ident in error_text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if ident.len() < 4 {
            continue;
        }
        let has_alpha = ident.chars().any(|c| c.is_ascii_alphabetic());
        if !has_alpha {
            continue;
        }
        let low = ident.to_ascii_lowercase();
        if error_code.as_deref() == Some(low.as_str()) || is_error_boilerplate(&low) {
            continue;
        }
        if ident.contains('_') || ident.chars().any(|c| c.is_ascii_uppercase()) {
            push_unique(low);
        }
    }

    for sub in libredb_index::segment_universal_tokens(error_text) {
        if sub.chars().count() < 4 || sub.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if is_error_boilerplate(&sub) {
            continue;
        }
        push_unique(sub);
    }

    tokens.truncate(6);
    let basis = tokens.join("|");
    let h = libredb_core::crc::hash_key(PITFALL_ID_HASH_SEED, basis.as_bytes()) as u32;
    let fp = match error_code.as_deref() {
        Some(ec) => format!("{ec}_{h:08x}"),
        None => format!("pitfall_{h:08x}"),
    };
    (error_code, tokens, fp)
}

/// Stage 1 of the 2-stage Banality Filter: returns `true` when `error_text` is empty, too short,
/// or represents a trivial punctuation/delimiter/typo syntax slip carrying zero transferable
/// architectural or scoping signal.
pub fn is_banal_syntax_error(error_text: &str) -> bool {
    let trimmed = error_text.trim();
    if trimmed.len() < 6 {
        return true;
    }
    let lc = trimmed.to_ascii_lowercase();
    let (code_opt, specific_tokens, _) = extract_error_signature(trimmed);
    if code_opt.is_none() && specific_tokens.is_empty() {
        return true;
    }
    let has_compound_ident = specific_tokens.iter().any(|t| t.contains('_'));
    if code_opt.is_none()
        && SYNTAX_SLIP_PATTERNS.iter().any(|p| lc.contains(p))
        && !has_compound_ident
        && specific_tokens.len() <= 1
    {
        return true;
    }
    false
}

fn compact_error_excerpt(error_text: &str) -> String {
    let single_line = error_text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let mut out = String::with_capacity(single_line.len().min(96));
    for ch in single_line.chars().take(96) {
        out.push(ch);
    }
    out
}

/// Stages a non-banal observed error into `sys::pending_error_cues` (`NodeKind::Generic`,
/// seal-neutral). Banal syntax/delimiter slips are rejected at Stage 1 and counted in
/// `LearningCounters.trivial_errors_filtered`.
pub fn record_error_cue(
    db: &LibreDb,
    error_text: &str,
    action_hint: Option<&str>,
) -> Result<bool> {
    if is_banal_syntax_error(error_text) {
        bump_learning_counters(db, |c| c.trivial_errors_filtered += 1);
        return Ok(false);
    }
    let (error_code, error_tokens, fingerprint_id) = extract_error_signature(error_text);
    if error_code.is_none() && error_tokens.is_empty() {
        bump_learning_counters(db, |c| c.trivial_errors_filtered += 1);
        return Ok(false);
    }
    let now_ns = current_unix_ns();
    let excerpt = compact_error_excerpt(error_text);
    let hint_clean = action_hint
        .map(str::trim)
        .filter(|h| !h.is_empty() && h.len() <= 80)
        .map(ToOwned::to_owned);
    let mut counted = false;

    db.transact_key(NodeKind::Generic, PENDING_ERROR_CUES_KEY, |existing| {
        let mut cues: Vec<PendingErrorCue> = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        cues.retain(|c| now_ns.saturating_sub(c.recorded_at_ns) <= MISS_CUE_TTL_NS);
        if let Some(prev) = cues.iter_mut().find(|c| c.fingerprint_id == fingerprint_id) {
            prev.recorded_at_ns = now_ns;
            if hint_clean.is_some() {
                prev.action_hint = hint_clean.clone();
            }
        } else {
            cues.push(PendingErrorCue {
                fingerprint_id: fingerprint_id.clone(),
                error_code: error_code.clone(),
                error_tokens: error_tokens.clone(),
                raw_excerpt: excerpt.clone(),
                action_hint: hint_clean.clone(),
                recorded_at_ns: now_ns,
            });
            counted = true;
        }
        if cues.len() > MAX_PENDING_ERROR_CUES {
            let drop_n = cues.len() - MAX_PENDING_ERROR_CUES;
            cues.drain(0..drop_n);
        }
        let bytes = serde_json::to_vec(&cues)
            .map_err(|_| LibreDbError::CorruptFormat("pending error cues serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
    })?;

    let mut refuted_prior_fix = false;
    let _ = db.transact_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut book) = serde_json::from_slice::<ErrorPitfallBook>(&rec.payload) else {
            return Ok(None);
        };
        let Some(cur) = book.pitfalls.get_mut(&fingerprint_id) else {
            return Ok(None);
        };
        cur.confidence = (cur.confidence * 0.55).clamp(0.10, 0.98);
        cur.last_learned_ns = now_ns;
        refuted_prior_fix = true;
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("error pitfall book serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });

    if counted || refuted_prior_fix {
        bump_learning_counters(db, |c| {
            if counted {
                c.error_cues_recorded += 1;
            }
            if refuted_prior_fix {
                c.failed_fixes_refuted = c.failed_fixes_refuted.saturating_add(1);
            }
        });
    }
    Ok(true)
}

/// Extracts up to `8` meaningful resolution tokens from prose `fix_directive` text without
/// enforcing the short symbol-query length/path restrictions of `extract_cue_tokens`.
fn extract_fix_directive_tokens(directive: &str) -> Vec<String> {
    let trimmed = directive.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut push_unique = |tok: String| {
        if !tok.is_empty() && !tokens.contains(&tok) {
            tokens.push(tok);
        }
    };
    for ident in trimmed.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if ident.len() < 4 || !ident.chars().any(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let low = ident.to_ascii_lowercase();
        if is_error_boilerplate(&low) {
            continue;
        }
        if ident.contains('_') || ident.chars().any(|c| c.is_ascii_uppercase()) {
            push_unique(low);
        }
    }
    for sub in libredb_index::segment_universal_tokens(trimmed) {
        if sub.chars().count() < 3 || sub.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if is_error_boilerplate(&sub) {
            continue;
        }
        push_unique(sub);
    }
    tokens.truncate(8);
    tokens
}

/// Explicitly records a verified `(error_text -> fix_directive)` resolution (via CLI/MCP) in
/// `sys::error_pitfall_book` after passing the Stage 1 banality filter.
pub fn learn_explicit_error_resolution(
    db: &LibreDb,
    error_text: &str,
    fix_directive: &str,
    action_hint: Option<&str>,
    symbols: &[String],
    supersedes: &[String],
) -> Result<Option<LearnedPitfallEntry>> {
    if is_banal_syntax_error(error_text) {
        bump_learning_counters(db, |c| c.trivial_errors_filtered += 1);
        return Ok(None);
    }
    let fix_tokens = extract_fix_directive_tokens(fix_directive);
    if fix_tokens.is_empty() {
        bump_learning_counters(db, |c| c.trivial_errors_filtered += 1);
        return Ok(None);
    }
    let (error_code, error_tokens, fingerprint_id) = extract_error_signature(error_text);
    if error_code.is_none() && error_tokens.is_empty() {
        bump_learning_counters(db, |c| c.trivial_errors_filtered += 1);
        return Ok(None);
    }
    let now_ns = current_unix_ns();
    let action_tokens: Vec<String> = action_hint
        .map(extract_cue_tokens)
        .unwrap_or_default()
        .into_iter()
        .take(4)
        .collect();
    let affected_symbols: Vec<String> = symbols
        .iter()
        .map(|s| s.trim().replace('\\', "/"))
        .filter(|s| !s.is_empty())
        .collect();
    let supersedes_clean: Vec<String> = supersedes
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    let mut stored_entry: Option<LearnedPitfallEntry> = None;
    let mut supersedes_applied = 0u64;
    db.transact_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY, |existing| {
        let mut book: ErrorPitfallBook = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        for old_id in &supersedes_clean {
            let key_no_pfx = old_id.strip_prefix("pitfall::").unwrap_or(old_id);
            if let Some(old_entry) = book.pitfalls.get_mut(key_no_pfx) {
                old_entry.confidence = (old_entry.confidence * 0.65).clamp(0.10, 0.98);
                supersedes_applied += 1;
            }
        }
        let entry = book
            .pitfalls
            .entry(fingerprint_id.clone())
            .and_modify(|cur| {
                if cur.directive != fix_directive.trim() {
                    cur.directive = fix_directive.trim().to_owned();
                    supersedes_applied += 1;
                }
                cur.resolution_tokens = fix_tokens.clone();
                if !affected_symbols.is_empty() {
                    cur.affected_symbols = affected_symbols.clone();
                }
                for sp in &supersedes_clean {
                    if !cur.supersedes.contains(sp) {
                        cur.supersedes.push(sp.clone());
                    }
                }
                cur.confidence = (1.0 - (1.0 - cur.confidence) * 0.40).clamp(0.10, 0.98);
                cur.occurrences = cur.occurrences.saturating_add(1);
                cur.last_learned_ns = now_ns;
            })
            .or_insert_with(|| LearnedPitfallEntry {
                id: fingerprint_id.clone(),
                error_code: error_code.clone(),
                trigger_tokens: error_tokens.clone(),
                action_tokens: action_tokens.clone(),
                affected_symbols: affected_symbols.clone(),
                resolution_tokens: fix_tokens.clone(),
                directive: fix_directive.trim().to_owned(),
                confidence: 0.85,
                occurrences: 1,
                last_learned_ns: now_ns,
                supersedes: supersedes_clean.clone(),
            })
            .clone();
        stored_entry = Some(entry);
        evict_pitfall_book_overflow(&mut book);
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("error pitfall book serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    })?;

    // Retire matching pending error cue if staged earlier.
    let _ = db.transact_key(NodeKind::Generic, PENDING_ERROR_CUES_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut cues) = serde_json::from_slice::<Vec<PendingErrorCue>>(&rec.payload) else {
            return Ok(None);
        };
        let before = cues.len();
        cues.retain(|c| c.fingerprint_id != fingerprint_id);
        if cues.len() == before {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&cues)
            .map_err(|_| LibreDbError::CorruptFormat("pending error cues serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
    });

    bump_learning_counters(db, |c| {
        c.pitfalls_learned += 1;
        c.method_supersedes_applied += supersedes_applied + u64::from(!supersedes_clean.is_empty());
    });
    Ok(stored_entry)
}

pub(crate) fn load_matured_pitfalls(db: &LibreDb) -> Vec<LearnedPitfallEntry> {
    db.get_by_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<ErrorPitfallBook>(&rec.payload).ok())
        .map(|b| {
            b.pitfalls
                .into_values()
                .filter(|p| p.confidence >= ACTIVE_PITFALL_MIN_CONFIDENCE)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn note_method_supersede(db: &LibreDb) {
    bump_learning_counters(db, |c| c.method_supersedes_applied += 1);
}

fn evict_pitfall_book_overflow(book: &mut ErrorPitfallBook) {
    while book.pitfalls.len() > MAX_LEARNED_PITFALLS {
        let victim = book
            .pitfalls
            .iter()
            .min_by(|a, b| {
                a.1.confidence
                    .partial_cmp(&b.1.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.1.last_learned_ns.cmp(&b.1.last_learned_ns))
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                book.pitfalls.remove(&k);
            }
            None => break,
        }
    }
}

fn bump_learning_counters(db: &LibreDb, apply: impl FnOnce(&mut LearningCounters)) {
    let _ = db.transact_key(NodeKind::Generic, LEARNING_COUNTERS_KEY, |existing| {
        let mut counters: LearningCounters = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        apply(&mut counters);
        let bytes = serde_json::to_vec(&counters)
            .map_err(|_| LibreDbError::CorruptFormat("learning counters serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(16)))
    });
}

// ---------------------------------------------------------------------------------------------
// Precise symbol diffs
// ---------------------------------------------------------------------------------------------

/// Returns the stripped symbol keys of `new` whose bodies changed relative to `old`.
///
/// Symbols are matched by `(qualified_name, ordinal)` so overloads stay distinct and line shifts are
/// irrelevant. A symbol counts as modified if it is new or its whitespace-insensitive `body_hash`
/// (or signature) differs. Legacy skeletons without body hashes fall back to signature, doc, and
/// span comparison. `old == None` means the file did not exist before: every symbol is new.
pub(crate) fn diff_symbol_bodies(
    rel_path: &str,
    old: Option<&FileSkeleton>,
    new: &FileSkeleton,
) -> Vec<String> {
    let new_keys = compute_file_symbol_keys(rel_path, new);
    let mut touched: Vec<String> = Vec::new();
    let mut push_unique = |k: &str| {
        let stripped = strip_line_disambiguator(k).to_owned();
        if !touched.contains(&stripped) {
            touched.push(stripped);
        }
    };
    let Some(old_skel) = old else {
        for (_, k) in &new_keys {
            push_unique(k);
        }
        return touched;
    };

    let mut old_groups: HashMap<String, Vec<&SymbolContract>> = HashMap::new();
    for s in &old_skel.symbols {
        if s.kind == "impl" {
            continue;
        }
        old_groups.entry(s.qualified_name()).or_default().push(s);
    }
    let mut ordinals: HashMap<String, usize> = HashMap::new();
    for (idx, key) in &new_keys {
        let s = &new.symbols[*idx];
        let qn = s.qualified_name();
        let ord = {
            let slot = ordinals.entry(qn.clone()).or_insert(0);
            let cur = *slot;
            *slot += 1;
            cur
        };
        let changed = match old_groups.get(&qn).and_then(|v| v.get(ord)) {
            Some(o) if o.body_hash != 0 && s.body_hash != 0 => {
                o.body_hash != s.body_hash || o.signature != s.signature
            }
            Some(o) => {
                o.signature != s.signature
                    || o.doc_summary != s.doc_summary
                    || o.end_line.saturating_sub(o.start_line) != s.end_line.saturating_sub(s.start_line)
            }
            None => true,
        };
        if changed {
            push_unique(key);
        }
    }
    touched
}

// ---------------------------------------------------------------------------------------------
// Symbol vocabulary and specificity
// ---------------------------------------------------------------------------------------------

/// Live symbol vocabulary: stripped key lookup plus per-token document frequency over symbol names.
pub(crate) struct SymbolVocabulary {
    n_symbols: u32,
    token_df: HashMap<String, u32>,
    key_to_node: HashMap<String, u64>,
}

impl SymbolVocabulary {
    pub(crate) fn from_symbol_keys<'a>(entries: impl Iterator<Item = (u64, &'a str)>) -> Self {
        let mut vocab = Self {
            n_symbols: 0,
            token_df: HashMap::new(),
            key_to_node: HashMap::new(),
        };
        for (nid, full_k) in entries {
            let stripped = strip_line_disambiguator(full_k);
            vocab.key_to_node.entry(stripped.to_owned()).or_insert(nid);
            let sym_part = stripped.split_once("::").map_or(stripped, |(_, s)| s);
            let clean = sym_part.split('@').next().unwrap_or(sym_part);
            let toks: HashSet<String> = libredb_index::segment_universal_tokens(clean)
                .into_iter()
                .collect();
            for t in toks {
                *vocab.token_df.entry(t).or_insert(0) += 1;
            }
            vocab.n_symbols += 1;
        }
        vocab
    }

    pub(crate) fn from_db(db: &LibreDb) -> Self {
        let inodes = db.list_inodes(Some(NodeKind::Symbol), false);
        Self::from_symbol_keys(
            inodes
                .iter()
                .filter_map(|(ino, k, _)| k.as_deref().map(|key| (ino.node_id, key))),
        )
    }

    /// Normalized inverse document frequency of `token` among symbol names plus learned fan-out:
    /// `ln(1 + N / (1 + df)) / ln(1 + N)`, clamped to `[0.05, 1.0]`.
    pub(crate) fn specificity(&self, token: &str, bridge_fanout: u32) -> f64 {
        let n = f64::from(self.n_symbols.max(1));
        let df = self.token_df.get(token).copied().unwrap_or(0) + bridge_fanout.saturating_sub(1);
        let denom = (1.0 + n).ln();
        if denom <= f64::EPSILON {
            return 1.0;
        }
        ((1.0 + n / (1.0 + f64::from(df))).ln() / denom).clamp(0.05, 1.0)
    }
}

// ---------------------------------------------------------------------------------------------
// Bridge scoring
// ---------------------------------------------------------------------------------------------

pub(crate) fn load_bridge_book(db: &LibreDb) -> Option<SymbolCueBridgeBook> {
    let rec = db.get_by_key(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY).ok()?;
    serde_json::from_slice::<SymbolCueBridgeBook>(&rec.payload)
        .ok()
        .filter(|b| !b.bridges.is_empty())
}

/// Calibrated bridge scorer:
/// `score(s) = 2.0 * sum_{t in M(s)} spec(t) * w(t, s) / sum_{t in T} spec(t)`,
/// i.e. `2.0 x coverage x confidence`. Accepted only if `score >= 0.80`.
pub(crate) struct BridgeScorer {
    book: SymbolCueBridgeBook,
    vocab: SymbolVocabulary,
}

impl BridgeScorer {
    pub(crate) fn load(db: &LibreDb) -> Option<Self> {
        let book = load_bridge_book(db)?;
        Some(Self {
            book,
            vocab: SymbolVocabulary::from_db(db),
        })
    }

    pub(crate) fn from_symbol_inodes(
        db: &LibreDb,
        sym_inodes: &[(libredb_core::Inode, Option<String>, Vec<libredb_core::Synapse>)],
    ) -> Option<Self> {
        let book = load_bridge_book(db)?;
        let vocab = SymbolVocabulary::from_symbol_keys(
            sym_inodes
                .iter()
                .filter_map(|(ino, k, _)| k.as_deref().map(|key| (ino.node_id, key))),
        );
        Some(Self { book, vocab })
    }

    /// Returns `(symbol_node_id, score)` pairs with `score >= BRIDGE_MIN_SCORE`, best first.
    pub(crate) fn score_query(&self, raw_query: &str) -> Vec<(u64, f64)> {
        let tokens = extract_cue_tokens(raw_query);
        if tokens.is_empty() {
            return Vec::new();
        }
        let specs: Vec<f64> = tokens
            .iter()
            .map(|t| {
                let fanout = self.book.bridges.get(t).map_or(0, |l| l.len() as u32);
                self.vocab.specificity(t, fanout)
            })
            .collect();
        let sum_spec: f64 = specs.iter().sum();
        if sum_spec <= f64::EPSILON {
            return Vec::new();
        }
        let mut acc: HashMap<&str, f64> = HashMap::new();
        for (t, s) in tokens.iter().zip(specs.iter()) {
            if let Some(targets) = self.book.bridges.get(t) {
                for (k, w) in targets {
                    *acc.entry(k.as_str()).or_insert(0.0) += s * w;
                }
            }
        }
        let mut hits: Vec<(u64, &str, f64)> = acc
            .into_iter()
            .filter_map(|(k, v)| {
                let score = BRIDGE_SCORE_SCALE * v / sum_spec;
                if score + 1e-9 < BRIDGE_MIN_SCORE {
                    return None;
                }
                let nid = *self.vocab.key_to_node.get(k)?;
                Some((nid, k, score))
            })
            .collect();
        hits.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(b.1))
        });
        hits.into_iter().map(|(id, _, sc)| (id, sc)).collect()
    }
}

/// Shared tier resolution for `locate` and `impact`:
/// exact (tier 1) > case-insensitive (tier 2) > confident learned bridges > substring (tier 3).
/// Direct Tier-1/Tier-2 hits stay first while non-duplicate confident bridges join slots `2..K`.
/// Records a miss whenever neither tier 1, tier 2, nor a confident bridge matched, even if weak
/// substring hits exist (they are still returned).
pub(crate) fn compose_tiers_with_bridges(
    db: &LibreDb,
    raw_query: &str,
    tier1: Vec<(u64, String)>,
    tier2: Vec<(u64, String)>,
    tier3: Vec<(u64, String)>,
    scorer: Option<&BridgeScorer>,
    full_key_by_id: &HashMap<u64, String>,
    source: MissCueSource,
) -> Vec<(u64, String)> {
    let bridged: Vec<(u64, String)> = scorer
        .map(|s| s.score_query(raw_query))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(id, _)| full_key_by_id.get(&id).map(|k| (id, k.clone())))
        .collect();
    if !tier1.is_empty() || !tier2.is_empty() {
        let mut out = if !tier1.is_empty() { tier1 } else { tier2 };
        for b in bridged {
            if !out.iter().any(|(id, _)| *id == b.0) {
                out.push(b);
            }
        }
        return out;
    }
    if bridged.is_empty() {
        let _ = record_search_miss_cue_with_source(db, raw_query, source);
        return tier3;
    }
    let mut out = bridged;
    for t in tier3 {
        if !out.iter().any(|(id, _)| *id == t.0) {
            out.push(t);
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Causal binding
// ---------------------------------------------------------------------------------------------

fn is_cue_retired(c: &PendingMissCue, edit_ns: u128, now_ns: u128) -> bool {
    now_ns.saturating_sub(c.recorded_at_ns) > MISS_CUE_TTL_NS
        || c
            .first_bound_edit_ns
            .is_some_and(|fb| edit_ns.saturating_sub(fb) > CUE_EPISODE_WINDOW_NS)
        || c.bound_files.len() >= MAX_CUE_BOUND_FILES
        || c.bound_symbols.len() >= MAX_CUE_BOUND_SYMBOLS
}

fn is_cue_causally_bindable(c: &PendingMissCue, edit_ns: u128) -> bool {
    c.recorded_at_ns <= edit_ns && edit_ns - c.recorded_at_ns <= MISS_CUE_TTL_NS
}

struct CueBinding {
    tokens: Vec<String>,
    whole: Option<String>,
    source: MissCueSource,
    symbols: Vec<String>,
}

/// Binds all causally eligible pending miss cues and error cues to the symbols modified by a
/// verified edit. Returns the number of learned symbol bridges + error pitfalls created/updated.
pub(crate) fn learn_from_verified_edit(db: &LibreDb, ev: &EditEvidence) -> usize {
    if ev.touched.is_empty() {
        return 0;
    }
    let has_miss_cues = db.get_by_key(NodeKind::Generic, PENDING_MISS_CUES_KEY).is_ok();
    let has_error_cues = db.get_by_key(NodeKind::Generic, PENDING_ERROR_CUES_KEY).is_ok();
    if !has_miss_cues && !has_error_cues {
        return 0;
    }
    if ev.touched.len() > MAX_TOUCHED_PER_EDIT {
        bump_learning_counters(db, |c| c.broad_edits_skipped += 1);
        return 0;
    }

    let mut total_learned = 0usize;

    if has_miss_cues {
        let mut bindings: Vec<CueBinding> = Vec::new();
        let pending_tx = db.transact_key(NodeKind::Generic, PENDING_MISS_CUES_KEY, |existing| {
            let Some(rec) = existing else {
                return Ok(None);
            };
            let Ok(mut cues) = serde_json::from_slice::<Vec<PendingMissCue>>(&rec.payload) else {
                return Ok(None);
            };
            let now_ns = current_unix_ns();
            let before = cues.len();
            cues.retain(|c| !is_cue_retired(c, ev.edit_ns, now_ns));
            let mut changed = cues.len() != before;
            for c in &mut cues {
                if !is_cue_causally_bindable(c, ev.edit_ns) {
                    continue;
                }
                let new_syms: Vec<String> = ev
                    .touched
                    .iter()
                    .filter(|s| !c.bound_symbols.contains(s))
                    .cloned()
                    .collect();
                if new_syms.is_empty() {
                    continue;
                }
                let new_file = !c.bound_files.contains(&ev.rel_path);
                if c.bound_files.len() + usize::from(new_file) > MAX_CUE_BOUND_FILES
                    || c.bound_symbols.len() + new_syms.len() > MAX_CUE_BOUND_SYMBOLS
                {
                    continue;
                }
                c.first_bound_edit_ns.get_or_insert(ev.edit_ns);
                if new_file {
                    c.bound_files.push(ev.rel_path.clone());
                }
                c.bound_symbols.extend(new_syms.iter().cloned());
                bindings.push(CueBinding {
                    tokens: c.tokens.clone(),
                    whole: whole_identifier(&c.raw_query),
                    source: c.source,
                    symbols: new_syms,
                });
                changed = true;
            }
            if !changed {
                return Ok(None);
            }
            let bytes = serde_json::to_vec(&cues)
                .map_err(|_| LibreDbError::CorruptFormat("pending miss cues serialize"))?;
            Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
        });

        if pending_tx.is_ok() && !bindings.is_empty() {
            let vocab = SymbolVocabulary::from_db(db);
            let mut updated_links = 0usize;
            let bridge_tx = db.transact_key(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY, |existing| {
                let mut book: SymbolCueBridgeBook = existing
                    .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
                    .unwrap_or_default();
                for b in &bindings {
                    let init_w = b.source.initial_weight();
                    for tok in &b.tokens {
                        let is_whole = b.whole.as_deref() == Some(tok.as_str());
                        let fanout = book.bridges.get(tok).map_or(0, |l| l.len() as u32);
                        if !is_whole && vocab.specificity(tok, fanout) < MIN_BIND_TOKEN_SPECIFICITY {
                            continue;
                        }
                        let list = book.bridges.entry(tok.clone()).or_default();
                        for sym_k in &b.symbols {
                            if let Some(existing_link) = list.iter_mut().find(|(k, _)| k == sym_k) {
                                existing_link.1 = (1.0 - (1.0 - existing_link.1) * BRIDGE_REINFORCE_RETAIN)
                                    .clamp(0.10, 0.95);
                            } else {
                                list.push((sym_k.clone(), init_w));
                            }
                            updated_links += 1;
                        }
                        list.sort_by(|a, b| {
                            b.1.partial_cmp(&a.1)
                                .unwrap_or(std::cmp::Ordering::Equal)
                                .then_with(|| a.0.cmp(&b.0))
                        });
                        list.truncate(MAX_TARGETS_PER_CUE_TOKEN);
                    }
                }
                evict_bridge_book_overflow(&mut book);
                if updated_links == 0 {
                    return Ok(None);
                }
                let bytes = serde_json::to_vec(&book)
                    .map_err(|_| LibreDbError::CorruptFormat("symbol cue bridges serialize"))?;
                Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
            });
            if bridge_tx.is_ok() && updated_links > 0 {
                let n = bindings.len() as u64;
                bump_learning_counters(db, |c| c.bindings_learned += n);
                total_learned += updated_links;
            }
        }
    }

    if has_error_cues {
        total_learned += bind_error_cues_for_edit(db, ev);
    }

    total_learned
}

fn bind_error_cues_for_edit(db: &LibreDb, ev: &EditEvidence) -> usize {
    let mut causal_errors: Vec<PendingErrorCue> = Vec::new();
    let tx = db.transact_key(NodeKind::Generic, PENDING_ERROR_CUES_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(cues) = serde_json::from_slice::<Vec<PendingErrorCue>>(&rec.payload) else {
            return Ok(None);
        };
        let now_ns = current_unix_ns();
        let before = cues.len();
        let mut remaining = Vec::with_capacity(cues.len());
        for c in cues {
            if now_ns.saturating_sub(c.recorded_at_ns) > MISS_CUE_TTL_NS {
                continue;
            }
            if c.recorded_at_ns <= ev.edit_ns {
                causal_errors.push(c);
            } else {
                remaining.push(c);
            }
        }
        if causal_errors.is_empty() && remaining.len() == before {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&remaining)
            .map_err(|_| LibreDbError::CorruptFormat("pending error cues serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
    });
    if tx.is_err() || causal_errors.is_empty() {
        return 0;
    }

    // Stage 2 Banality Filter: if the verified edit introduced zero meaningful body tokens
    // (only `;`, `,`, `)`, comments, or formatting changed), retire these cues cleanly.
    if ev.added_body_tokens.is_empty() {
        let filtered_n = causal_errors.len() as u64;
        bump_learning_counters(db, |c| c.trivial_errors_filtered += filtered_n);
        return 0;
    }

    let now_ns = current_unix_ns();
    let mut learned_count = 0usize;
    let mut supersedes_applied = 0u64;
    let book_tx = db.transact_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY, |existing| {
        let mut book: ErrorPitfallBook = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        for cue in &causal_errors {
            let mut supersedes_for_cue: Vec<String> = Vec::new();
            for (old_id, old_p) in book.pitfalls.iter_mut() {
                if old_id == &cue.fingerprint_id {
                    continue;
                }
                let shares_symbol = old_p
                    .affected_symbols
                    .iter()
                    .any(|s| ev.touched.contains(s));
                let shares_trigger = old_p
                    .trigger_tokens
                    .iter()
                    .any(|t| cue.error_tokens.contains(t));
                if shares_symbol && shares_trigger && old_p.resolution_tokens != ev.added_body_tokens {
                    old_p.confidence = (old_p.confidence * 0.65).clamp(0.10, 0.98);
                    supersedes_for_cue.push(old_id.clone());
                    supersedes_applied += 1;
                }
            }

            let directive = format!(
                "Avoid repeat error ({}) in [{}]: apply verified fix tokens [{}].",
                cue.raw_excerpt,
                ev.touched.join(", "),
                ev.added_body_tokens.join(", ")
            );
            let action_tokens = cue
                .action_hint
                .as_deref()
                .map(extract_cue_tokens)
                .unwrap_or_default()
                .into_iter()
                .filter(|t| t.len() >= 3)
                .take(4)
                .collect::<Vec<_>>();

            match book.pitfalls.get_mut(&cue.fingerprint_id) {
                Some(cur) => {
                    let was_refuted = cur.confidence < ACTIVE_PITFALL_MIN_CONFIDENCE;
                    if (was_refuted || !cur.resolution_tokens.is_empty())
                        && cur.resolution_tokens != ev.added_body_tokens
                    {
                        supersedes_applied += 1;
                    }
                    cur.resolution_tokens = ev.added_body_tokens.clone();
                    cur.affected_symbols = ev.touched.clone();
                    cur.directive = directive;
                    for sp in &supersedes_for_cue {
                        if !cur.supersedes.contains(sp) {
                            cur.supersedes.push(sp.clone());
                        }
                    }
                    let recovered = (1.0 - (1.0 - cur.confidence) * 0.50).clamp(0.10, 0.98);
                    cur.confidence = if was_refuted {
                        recovered.max(0.80)
                    } else {
                        recovered
                    };
                    cur.occurrences = cur.occurrences.saturating_add(1);
                    cur.last_learned_ns = now_ns;
                }
                None => {
                    book.pitfalls.insert(
                        cue.fingerprint_id.clone(),
                        LearnedPitfallEntry {
                            id: cue.fingerprint_id.clone(),
                            error_code: cue.error_code.clone(),
                            trigger_tokens: cue.error_tokens.clone(),
                            action_tokens,
                            affected_symbols: ev.touched.clone(),
                            resolution_tokens: ev.added_body_tokens.clone(),
                            directive,
                            confidence: 0.80,
                            occurrences: 1,
                            last_learned_ns: now_ns,
                            supersedes: supersedes_for_cue,
                        },
                    );
                }
            }
            learned_count += 1;
        }
        evict_pitfall_book_overflow(&mut book);
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("error pitfall book serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });

    if book_tx.is_ok() && learned_count > 0 {
        let added = learned_count as u64;
        bump_learning_counters(db, |c| {
            c.pitfalls_learned += added;
            c.method_supersedes_applied += supersedes_applied;
        });
        return learned_count;
    }
    0
}

/// Records that an index scan skipped learning because too many files changed at once.
pub(crate) fn note_bulk_scan_skipped(db: &LibreDb) {
    if db.get_by_key(NodeKind::Generic, PENDING_MISS_CUES_KEY).is_ok() {
        bump_learning_counters(db, |c| c.bulk_scans_skipped += 1);
    }
}

fn evict_bridge_book_overflow(book: &mut SymbolCueBridgeBook) {
    while book.bridges.len() > MAX_BRIDGE_BOOK_TOKENS {
        let victim = book
            .bridges
            .iter()
            .map(|(tok, list)| {
                let max_w = list.iter().map(|(_, w)| *w).fold(0.0_f64, f64::max);
                (tok.clone(), max_w)
            })
            .min_by(|a, b| {
                a.1.partial_cmp(&b.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(&b.0))
            })
            .map(|(tok, _)| tok);
        match victim {
            Some(tok) => {
                book.bridges.remove(&tok);
            }
            None => break,
        }
    }
}

/// Removes bridge links pointing to symbols deleted from `rel_path` during a single-file sync.
pub(crate) fn prune_deleted_file_symbols_from_bridges(
    db: &LibreDb,
    rel_path: &str,
    live_stripped_keys_in_file: &HashSet<String>,
) {
    let prefix = format!("{rel_path}::");
    let _ = db.transact_key(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut book) = serde_json::from_slice::<SymbolCueBridgeBook>(&rec.payload) else {
            return Ok(None);
        };
        let mut modified = false;
        book.bridges.retain(|_, list| {
            let before = list.len();
            list.retain(|(sym_k, _)| {
                let stripped = strip_line_disambiguator(sym_k);
                !stripped.starts_with(&prefix) || live_stripped_keys_in_file.contains(stripped)
            });
            if list.len() != before {
                modified = true;
            }
            !list.is_empty()
        });
        if !modified {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("symbol cue bridges serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });
    prune_deleted_file_symbols_from_pitfalls(db, rel_path, live_stripped_keys_in_file);
}

fn prune_deleted_file_symbols_from_pitfalls(
    db: &LibreDb,
    rel_path: &str,
    live_stripped_keys_in_file: &HashSet<String>,
) {
    let prefix = format!("{rel_path}::");
    let _ = db.transact_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut book) = serde_json::from_slice::<ErrorPitfallBook>(&rec.payload) else {
            return Ok(None);
        };
        let mut modified = false;
        book.pitfalls.retain(|_, p| {
            if p.affected_symbols.is_empty() {
                return true;
            }
            let before = p.affected_symbols.len();
            p.affected_symbols.retain(|sym_k| {
                let stripped = strip_line_disambiguator(sym_k);
                !stripped.starts_with(&prefix) || live_stripped_keys_in_file.contains(stripped)
            });
            if p.affected_symbols.len() != before {
                modified = true;
            }
            !p.affected_symbols.is_empty()
        });
        if !modified {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("error pitfall book serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });
}

/// Removes pitfall entries pointing to files/symbols that vanished during an index scan.
pub(crate) fn prune_stale_error_pitfalls(
    db: &LibreDb,
    live_rel_paths: &HashSet<&str>,
    live_stripped: &HashSet<String>,
) {
    let _ = db.transact_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY, |existing| {
        let Some(rec) = existing else {
            return Ok(None);
        };
        let Ok(mut book) = serde_json::from_slice::<ErrorPitfallBook>(&rec.payload) else {
            return Ok(None);
        };
        let mut modified = false;
        book.pitfalls.retain(|_, p| {
            if p.affected_symbols.is_empty() {
                return true;
            }
            let before = p.affected_symbols.len();
            p.affected_symbols.retain(|sym_k| {
                let stripped = strip_line_disambiguator(sym_k);
                let file_ok = stripped
                    .split_once("::")
                    .is_some_and(|(fp, _)| live_rel_paths.contains(fp));
                file_ok && (live_stripped.contains(stripped) || live_stripped.contains(sym_k))
            });
            if p.affected_symbols.len() != before {
                modified = true;
            }
            !p.affected_symbols.is_empty()
        });
        if !modified {
            return Ok(None);
        }
        let bytes = serde_json::to_vec(&book)
            .map_err(|_| LibreDbError::CorruptFormat("error pitfall book serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(64)))
    });
}

// ---------------------------------------------------------------------------------------------
// Learning state report (`libredb learning`)
// ---------------------------------------------------------------------------------------------

/// Summary of one learned cue token.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeSummary {
    pub token: String,
    pub targets: Vec<(String, f64)>,
}

/// Read-only snapshot of the workspace learning state.
#[derive(Debug, Clone, Serialize)]
pub struct LearningStateReport {
    pub pending_cues: Vec<PendingMissCue>,
    pub pending_errors: Vec<PendingErrorCue>,
    pub learned_pitfalls: Vec<LearnedPitfallEntry>,
    pub bridge_token_count: usize,
    pub top_bridges: Vec<BridgeSummary>,
    pub reflexes: Vec<ReflexStatus>,
    pub counters: LearningCounters,
}

/// Builds a read-only learning state report (`0` writes).
pub fn learning_state_report(db: &LibreDb, top_n: usize) -> LearningStateReport {
    let now_ns = current_unix_ns();
    let pending_cues: Vec<PendingMissCue> = db
        .get_by_key(NodeKind::Generic, PENDING_MISS_CUES_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<Vec<PendingMissCue>>(&rec.payload).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !is_cue_retired(c, now_ns, now_ns))
        .collect();
    let pending_errors: Vec<PendingErrorCue> = db
        .get_by_key(NodeKind::Generic, PENDING_ERROR_CUES_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<Vec<PendingErrorCue>>(&rec.payload).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|c| now_ns.saturating_sub(c.recorded_at_ns) <= MISS_CUE_TTL_NS)
        .collect();
    let mut learned_pitfalls: Vec<LearnedPitfallEntry> = db
        .get_by_key(NodeKind::Generic, ERROR_PITFALL_BOOK_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice::<ErrorPitfallBook>(&rec.payload).ok())
        .map(|b| b.pitfalls.into_values().collect())
        .unwrap_or_default();
    learned_pitfalls.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    let vocab = SymbolVocabulary::from_db(db);
    let book = load_bridge_book(db).unwrap_or_default();
    let mut ranked: Vec<BridgeSummary> = book
        .bridges
        .iter()
        .filter_map(|(tok, list)| {
            let live_targets: Vec<(String, f64)> = list
                .iter()
                .filter(|(k, _)| vocab.key_to_node.contains_key(strip_line_disambiguator(k)))
                .cloned()
                .collect();
            (!live_targets.is_empty()).then(|| BridgeSummary {
                token: tok.clone(),
                targets: live_targets,
            })
        })
        .collect();
    let live_token_count = ranked.len();
    ranked.sort_by(|a, b| {
        let wa = a.targets.first().map_or(0.0, |t| t.1);
        let wb = b.targets.first().map_or(0.0, |t| t.1);
        wb.partial_cmp(&wa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.token.cmp(&b.token))
    });
    ranked.truncate(top_n);
    let counters: LearningCounters = db
        .get_by_key(NodeKind::Generic, LEARNING_COUNTERS_KEY)
        .ok()
        .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
        .unwrap_or_default();
    LearningStateReport {
        pending_cues,
        pending_errors,
        learned_pitfalls,
        bridge_token_count: live_token_count,
        top_bridges: ranked,
        reflexes: ReflexEngine::describe_all(db),
        counters,
    }
}

/// Formats a `LearningStateReport` as a compact CLI block.
pub fn format_learning_report(rep: &LearningStateReport) -> String {
    let now_ns = current_unix_ns();
    let mut lines = vec!["=== LIBREDB LEARNING STATE ===".to_owned()];
    lines.push(format!(
        "Pending miss cues ({}/{MAX_PENDING_MISS_CUES}, TTL 30 min):",
        rep.pending_cues.len()
    ));
    if rep.pending_cues.is_empty() {
        lines.push("  (none)".to_owned());
    }
    for c in &rep.pending_cues {
        let age_s = now_ns.saturating_sub(c.recorded_at_ns) / 1_000_000_000;
        let bound = if c.bound_files.is_empty() {
            "unbound".to_owned()
        } else {
            format!(
                "bound: {} ({} sym)",
                c.bound_files.join(", "),
                c.bound_symbols.len()
            )
        };
        lines.push(format!(
            "  * \"{}\" [{}, {}s ago, {bound}]",
            c.raw_query,
            c.source.as_str(),
            age_s
        ));
    }
    lines.push(format!(
        "Symbol cue bridges ({} tokens, {MAX_BRIDGE_BOOK_TOKENS} max):",
        rep.bridge_token_count
    ));
    if rep.top_bridges.is_empty() {
        lines.push("  (none)".to_owned());
    }
    for b in &rep.top_bridges {
        let targets: Vec<String> = b
            .targets
            .iter()
            .map(|(k, w)| format!("{k} ({w:.2})"))
            .collect();
        lines.push(format!("  * {} -> {}", b.token, targets.join(", ")));
    }
    let active = rep.reflexes.iter().filter(|r| r.status == "active").count();
    let falsified = rep.reflexes.iter().filter(|r| r.status == "falsified").count();
    let drift = rep.reflexes.iter().filter(|r| r.status == "drift").count();
    lines.push(format!(
        "Pending error cues ({}/{MAX_PENDING_ERROR_CUES}, TTL 30 min):",
        rep.pending_errors.len()
    ));
    if rep.pending_errors.is_empty() {
        lines.push("  (none)".to_owned());
    }
    for e in &rep.pending_errors {
        let age_s = now_ns.saturating_sub(e.recorded_at_ns) / 1_000_000_000;
        lines.push(format!(
            "  * [{}] \"{}\" ({}s ago)",
            e.fingerprint_id, e.raw_excerpt, age_s
        ));
    }
    lines.push(format!(
        "Learned error pitfalls ({} stored, {} active >= {ACTIVE_PITFALL_MIN_CONFIDENCE:.2}):",
        rep.learned_pitfalls.len(),
        rep.learned_pitfalls
            .iter()
            .filter(|p| p.confidence >= ACTIVE_PITFALL_MIN_CONFIDENCE)
            .count()
    ));
    if rep.learned_pitfalls.is_empty() {
        lines.push("  (none)".to_owned());
    }
    for p in rep.learned_pitfalls.iter().take(12) {
        let syms = if p.affected_symbols.is_empty() {
            "-".to_owned()
        } else {
            p.affected_symbols.join(", ")
        };
        let sup = if p.supersedes.is_empty() {
            String::new()
        } else {
            format!(" | supersedes [{}]", p.supersedes.join(", "))
        };
        lines.push(format!(
            "  * [{}] conf={:.2} n={} ({}) -> {}{sup}",
            p.id, p.confidence, p.occurrences, syms, p.directive
        ));
    }
    lines.push(format!(
        "Reflexes ({active} active, {falsified} falsified, {drift} contract drift):"
    ));
    for r in &rep.reflexes {
        let anchors = if r.anchors.is_empty() {
            String::new()
        } else {
            format!(" -> {}", r.anchors.join(", "))
        };
        let ctx = if r.context_tags.is_empty() {
            String::new()
        } else {
            format!(" ctx=[{}]", r.context_tags.join(","))
        };
        let sup = if r.supersedes.is_empty() {
            String::new()
        } else {
            format!(" supersedes=[{}]", r.supersedes.join(","))
        };
        lines.push(format!(
            "  * [{}] {} (util={:.2}){ctx}{sup}{anchors}",
            r.status, r.id, r.utility
        ));
    }
    lines.push(format!(
        "Counters: misses {}, bindings {}, broad edits skipped {}, bulk scans skipped {}, error cues {}, trivial filtered {}, pitfalls {}, refuted {}, supersedes {}",
        rep.counters.misses_recorded,
        rep.counters.bindings_learned,
        rep.counters.broad_edits_skipped,
        rep.counters.bulk_scans_skipped,
        rep.counters.error_cues_recorded,
        rep.counters.trivial_errors_filtered,
        rep.counters.pitfalls_learned,
        rep.counters.failed_fixes_refuted,
        rep.counters.method_supersedes_applied
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cue(recorded: u128) -> PendingMissCue {
        PendingMissCue {
            raw_query: "probe".to_owned(),
            tokens: vec!["probe".to_owned()],
            recorded_at_ns: recorded,
            source: MissCueSource::Locate,
            first_bound_edit_ns: None,
            bound_files: Vec::new(),
            bound_symbols: Vec::new(),
        }
    }

    #[test]
    fn causality_rejects_edits_before_the_miss() {
        let c = cue(1_000);
        assert!(!is_cue_causally_bindable(&c, 999));
        assert!(is_cue_causally_bindable(&c, 1_000));
        assert!(is_cue_causally_bindable(&c, 5_000));
        assert!(!is_cue_causally_bindable(&c, 1_000 + MISS_CUE_TTL_NS + 1));
    }

    #[test]
    fn episode_window_retires_cue_after_120_seconds_of_edit_time() {
        let now = current_unix_ns();
        let mut c = cue(now);
        c.first_bound_edit_ns = Some(now);
        c.bound_files = vec!["a.rs".to_owned()];
        assert!(!is_cue_retired(&c, now + CUE_EPISODE_WINDOW_NS, now));
        assert!(is_cue_retired(&c, now + CUE_EPISODE_WINDOW_NS + 1, now));
    }

    #[test]
    fn budgets_retire_cue() {
        let now = current_unix_ns();
        let mut c = cue(now);
        c.bound_files = vec!["a".into(), "b".into(), "c".into()];
        assert!(is_cue_retired(&c, now, now));
        let mut c2 = cue(now);
        c2.bound_symbols = (0..MAX_CUE_BOUND_SYMBOLS).map(|i| format!("s{i}")).collect();
        assert!(is_cue_retired(&c2, now, now));
    }

    #[test]
    fn specificity_attenuates_frequent_tokens() {
        let keys = [
            (1u64, "a.rs::get_config"),
            (2, "a.rs::get_value"),
            (3, "a.rs::get_item"),
            (4, "b.rs::quorum_lease"),
        ];
        let vocab = SymbolVocabulary::from_symbol_keys(keys.iter().map(|(i, k)| (*i, *k)));
        let rare = vocab.specificity("quorum", 0);
        let common = vocab.specificity("get", 0);
        let unseen = vocab.specificity("zzz", 0);
        assert!(unseen >= rare && rare > common, "unseen={unseen} rare={rare} common={common}");
        assert!((unseen - 1.0).abs() < 1e-9);
    }

    #[test]
    fn worked_examples_match_plan() {
        // Exact repeat of a 3-token query after one observation: 2.0 * 0.60 = 1.20.
        let mut book = SymbolCueBridgeBook::default();
        for t in ["validate", "token", "signature"] {
            book.bridges
                .insert(t.to_owned(), vec![("e.rs::target".to_owned(), 0.60)]);
        }
        let keys = [(7u64, "e.rs::target"), (8, "e.rs::other")];
        let scorer = BridgeScorer {
            book,
            vocab: SymbolVocabulary::from_symbol_keys(keys.iter().map(|(i, k)| (*i, *k))),
        };
        let exact = scorer.score_query("validate token signature");
        assert_eq!(exact.len(), 1);
        assert!((exact[0].1 - 1.20).abs() < 1e-9, "{exact:?}");
        // Unrelated query sharing one token is rejected.
        assert!(scorer.score_query("refresh token cache").is_empty());
    }
}
