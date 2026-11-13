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
/// Re-recording an already pending, still unbound query refreshes its timestamp; a query that is
/// already bound inside an open episode is left untouched (no duplicate evidence).
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
    let mut inserted = false;
    db.transact_key(NodeKind::Generic, PENDING_MISS_CUES_KEY, |existing| {
        let mut cues: Vec<PendingMissCue> = existing
            .and_then(|rec| serde_json::from_slice(&rec.payload).ok())
            .unwrap_or_default();
        cues.retain(|c| now_ns.saturating_sub(c.recorded_at_ns) <= MISS_CUE_TTL_NS);
        if let Some(existing_cue) = cues
            .iter_mut()
            .find(|c| c.raw_query.eq_ignore_ascii_case(&trimmed))
        {
            if existing_cue.first_bound_edit_ns.is_some() {
                return Ok(None);
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
            inserted = true;
        }
        if cues.len() > MAX_PENDING_MISS_CUES {
            let drop_n = cues.len() - MAX_PENDING_MISS_CUES;
            cues.drain(0..drop_n);
        }
        let bytes = serde_json::to_vec(&cues)
            .map_err(|_| LibreDbError::CorruptFormat("pending miss cues serialize"))?;
        Ok(Some(WriteRequest::new(NodeKind::Generic, bytes).with_importance(32)))
    })?;
    if inserted {
        bump_learning_counters(db, |c| c.misses_recorded += 1);
    }
    Ok(true)
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
        let df = self.token_df.get(token).copied().unwrap_or(0) + bridge_fanout;
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
    if !tier1.is_empty() {
        return tier1;
    }
    if !tier2.is_empty() {
        return tier2;
    }
    let bridged: Vec<(u64, String)> = scorer
        .map(|s| s.score_query(raw_query))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(id, _)| full_key_by_id.get(&id).map(|k| (id, k.clone())))
        .collect();
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

/// Binds all causally eligible pending cues to the symbols modified by a verified edit.
/// Returns the number of `(token, symbol)` bridge links created or reinforced.
pub(crate) fn learn_from_verified_edit(db: &LibreDb, ev: &EditEvidence) -> usize {
    if ev.touched.is_empty() {
        return 0;
    }
    if db.get_by_key(NodeKind::Generic, PENDING_MISS_CUES_KEY).is_err() {
        return 0;
    }
    if ev.touched.len() > MAX_TOUCHED_PER_EDIT {
        bump_learning_counters(db, |c| c.broad_edits_skipped += 1);
        return 0;
    }

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
    if pending_tx.is_err() || bindings.is_empty() {
        return 0;
    }

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
                        existing_link.1 =
                            (1.0 - (1.0 - existing_link.1) * BRIDGE_REINFORCE_RETAIN).clamp(0.10, 0.95);
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
    if bridge_tx.is_err() {
        return 0;
    }
    if updated_links > 0 {
        let n = bindings.len() as u64;
        bump_learning_counters(db, |c| c.bindings_learned += n);
    }
    updated_links
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
        .filter(|c| now_ns.saturating_sub(c.recorded_at_ns) <= MISS_CUE_TTL_NS)
        .collect();
    let book = load_bridge_book(db).unwrap_or_default();
    let mut ranked: Vec<BridgeSummary> = book
        .bridges
        .iter()
        .map(|(tok, list)| BridgeSummary {
            token: tok.clone(),
            targets: list.clone(),
        })
        .collect();
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
        bridge_token_count: book.bridges.len(),
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
        "Reflexes ({active} active, {falsified} falsified, {drift} contract drift):"
    ));
    for r in &rep.reflexes {
        let anchors = if r.anchors.is_empty() {
            String::new()
        } else {
            format!(" -> {}", r.anchors.join(", "))
        };
        lines.push(format!("  * [{}] {}{anchors}", r.status, r.id));
    }
    lines.push(format!(
        "Counters: misses {}, bindings {}, broad edits skipped {}, bulk scans skipped {}",
        rep.counters.misses_recorded,
        rep.counters.bindings_learned,
        rep.counters.broad_edits_skipped,
        rep.counters.bulk_scans_skipped
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
