//! Built-in token-consumption and savings telemetry (`libredb savings` / `libredb report`).
//!
//! Combines three clearly separated accounting views without touching cognitive trust seals:
//! 1. Live numeric event counters recorded atomically in `~/.gemini/libredb/telemetry.ldb` via
//!    cross-process-locked `LibreDb::transact_key` (`day::<ymd>` + per-workspace `ws_day::<hash>::<ymd>`),
//! 2. Bounded single-pass streaming inspection of local `Antigravity` conversation transcripts
//!    (`~/.gemini/antigravity/brain/<cid>/.system_generated/logs/transcript.jsonl`), enforcing
//!    `MAX_TRANSCRIPT_LINE_BYTES` (`8 MiB`) *during* chunked reading plus scan count/byte budgets, and
//! 3. Genuine provider-reported billing usage (`input_tokens`, `cache_read_tokens`, `output_tokens`)
//!    recorded on `PLANNER_RESPONSE` steps when present in transcripts.

use libredb_core::crc::{count_tokens_exact, hash_key};
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum lookback window (`10` years) accepted by `libredb savings --days` and MCP `savings`.
pub const MAX_SAVINGS_DAYS: u64 = 3_660;
/// Maximum single JSONL line length (`8 MiB`) buffered in RAM; longer lines are drained in-place.
pub const MAX_TRANSCRIPT_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of conversation transcripts inspected in a single `savings` invocation.
pub const MAX_TRANSCRIPTS_SCANNED: usize = 512;
/// Maximum cumulative transcript bytes read across a single `savings` invocation (`512 MiB`).
pub const MAX_TOTAL_TRANSCRIPT_SCAN_BYTES: u64 = 512 * 1024 * 1024;

static TELEMETRY_SUPPRESSED: AtomicBool = AtomicBool::new(false);

pub fn set_telemetry_suppressed(suppressed: bool) {
    TELEMETRY_SUPPRESSED.store(suppressed, Ordering::Relaxed);
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavingsMetrics {
    pub skeleton_calls: u64,
    pub skeleton_zero_repeat_hits: u64,
    pub skeleton_baseline_tokens: u64,
    pub skeleton_emitted_tokens: u64,

    pub fim_calls: u64,
    pub fim_baseline_tokens: u64,
    pub fim_emitted_tokens: u64,

    pub impact_calls: u64,
    pub impact_baseline_tokens: u64,
    pub impact_emitted_tokens: u64,

    pub pulse_calls: u64,
    pub pulse_baseline_tokens: u64,
    pub pulse_emitted_tokens: u64,

    pub skill_slice_calls: u64,
    pub skill_baseline_tokens: u64,
    pub skill_emitted_tokens: u64,

    pub hook_hydrated_turns: u64,
    pub hook_dedup_skipped_turns: u64,
    pub hook_symbol_shifts: u64,
    pub hook_baseline_tokens: u64,
    pub hook_emitted_tokens: u64,
}

impl SavingsMetrics {
    pub fn add_assign(&mut self, rhs: &Self) {
        self.skeleton_calls = self.skeleton_calls.saturating_add(rhs.skeleton_calls);
        self.skeleton_zero_repeat_hits = self
            .skeleton_zero_repeat_hits
            .saturating_add(rhs.skeleton_zero_repeat_hits);
        self.skeleton_baseline_tokens = self
            .skeleton_baseline_tokens
            .saturating_add(rhs.skeleton_baseline_tokens);
        self.skeleton_emitted_tokens = self
            .skeleton_emitted_tokens
            .saturating_add(rhs.skeleton_emitted_tokens);

        self.fim_calls = self.fim_calls.saturating_add(rhs.fim_calls);
        self.fim_baseline_tokens = self.fim_baseline_tokens.saturating_add(rhs.fim_baseline_tokens);
        self.fim_emitted_tokens = self.fim_emitted_tokens.saturating_add(rhs.fim_emitted_tokens);

        self.impact_calls = self.impact_calls.saturating_add(rhs.impact_calls);
        self.impact_baseline_tokens = self
            .impact_baseline_tokens
            .saturating_add(rhs.impact_baseline_tokens);
        self.impact_emitted_tokens = self
            .impact_emitted_tokens
            .saturating_add(rhs.impact_emitted_tokens);

        self.pulse_calls = self.pulse_calls.saturating_add(rhs.pulse_calls);
        self.pulse_baseline_tokens = self
            .pulse_baseline_tokens
            .saturating_add(rhs.pulse_baseline_tokens);
        self.pulse_emitted_tokens = self
            .pulse_emitted_tokens
            .saturating_add(rhs.pulse_emitted_tokens);

        self.skill_slice_calls = self.skill_slice_calls.saturating_add(rhs.skill_slice_calls);
        self.skill_baseline_tokens = self
            .skill_baseline_tokens
            .saturating_add(rhs.skill_baseline_tokens);
        self.skill_emitted_tokens = self
            .skill_emitted_tokens
            .saturating_add(rhs.skill_emitted_tokens);

        self.hook_hydrated_turns = self.hook_hydrated_turns.saturating_add(rhs.hook_hydrated_turns);
        self.hook_dedup_skipped_turns = self
            .hook_dedup_skipped_turns
            .saturating_add(rhs.hook_dedup_skipped_turns);
        self.hook_symbol_shifts = self.hook_symbol_shifts.saturating_add(rhs.hook_symbol_shifts);
        self.hook_baseline_tokens = self
            .hook_baseline_tokens
            .saturating_add(rhs.hook_baseline_tokens);
        self.hook_emitted_tokens = self.hook_emitted_tokens.saturating_add(rhs.hook_emitted_tokens);
    }

    pub fn max_merge(&self, rhs: &Self) -> Self {
        Self {
            skeleton_calls: self.skeleton_calls.max(rhs.skeleton_calls),
            skeleton_zero_repeat_hits: self
                .skeleton_zero_repeat_hits
                .max(rhs.skeleton_zero_repeat_hits),
            skeleton_baseline_tokens: self
                .skeleton_baseline_tokens
                .max(rhs.skeleton_baseline_tokens),
            skeleton_emitted_tokens: self
                .skeleton_emitted_tokens
                .max(rhs.skeleton_emitted_tokens),

            fim_calls: self.fim_calls.max(rhs.fim_calls),
            fim_baseline_tokens: self.fim_baseline_tokens.max(rhs.fim_baseline_tokens),
            fim_emitted_tokens: self.fim_emitted_tokens.max(rhs.fim_emitted_tokens),

            impact_calls: self.impact_calls.max(rhs.impact_calls),
            impact_baseline_tokens: self.impact_baseline_tokens.max(rhs.impact_baseline_tokens),
            impact_emitted_tokens: self.impact_emitted_tokens.max(rhs.impact_emitted_tokens),

            pulse_calls: self.pulse_calls.max(rhs.pulse_calls),
            pulse_baseline_tokens: self.pulse_baseline_tokens.max(rhs.pulse_baseline_tokens),
            pulse_emitted_tokens: self.pulse_emitted_tokens.max(rhs.pulse_emitted_tokens),

            skill_slice_calls: self.skill_slice_calls.max(rhs.skill_slice_calls),
            skill_baseline_tokens: self.skill_baseline_tokens.max(rhs.skill_baseline_tokens),
            skill_emitted_tokens: self.skill_emitted_tokens.max(rhs.skill_emitted_tokens),

            hook_hydrated_turns: self.hook_hydrated_turns.max(rhs.hook_hydrated_turns),
            hook_dedup_skipped_turns: self
                .hook_dedup_skipped_turns
                .max(rhs.hook_dedup_skipped_turns),
            hook_symbol_shifts: self.hook_symbol_shifts.max(rhs.hook_symbol_shifts),
            hook_baseline_tokens: self.hook_baseline_tokens.max(rhs.hook_baseline_tokens),
            hook_emitted_tokens: self.hook_emitted_tokens.max(rhs.hook_emitted_tokens),
        }
    }

    pub fn total_baseline_tokens(&self) -> u64 {
        self.skeleton_baseline_tokens
            .saturating_add(self.fim_baseline_tokens)
            .saturating_add(self.impact_baseline_tokens)
            .saturating_add(self.pulse_baseline_tokens)
            .saturating_add(self.skill_baseline_tokens)
            .saturating_add(self.hook_baseline_tokens)
    }

    pub fn total_emitted_tokens(&self) -> u64 {
        self.skeleton_emitted_tokens
            .saturating_add(self.fim_emitted_tokens)
            .saturating_add(self.impact_emitted_tokens)
            .saturating_add(self.pulse_emitted_tokens)
            .saturating_add(self.skill_emitted_tokens)
            .saturating_add(self.hook_emitted_tokens)
    }

    pub fn net_tokens_saved(&self) -> u64 {
        self.total_baseline_tokens()
            .saturating_sub(self.total_emitted_tokens())
    }

    pub fn savings_pct(&self) -> f64 {
        let base = self.total_baseline_tokens();
        if base == 0 {
            0.0
        } else {
            (self.net_tokens_saved() as f64 / base as f64) * 100.0
        }
    }
}

/// Genuine LLM provider billing counters extracted from `PLANNER_RESPONSE` transcript steps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReportedUsage {
    pub planner_steps: u64,
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub output_tokens: u64,
}

impl ProviderReportedUsage {
    pub fn add_assign(&mut self, rhs: &Self) {
        self.planner_steps = self.planner_steps.saturating_add(rhs.planner_steps);
        self.input_tokens = self.input_tokens.saturating_add(rhs.input_tokens);
        self.cache_read_tokens = self.cache_read_tokens.saturating_add(rhs.cache_read_tokens);
        self.output_tokens = self.output_tokens.saturating_add(rhs.output_tokens);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavingsReport {
    pub scope_label: String,
    pub token_estimation_method: String,
    pub conversations_analyzed: usize,
    pub transcripts_scanned: usize,
    pub scan_truncated: bool,
    pub active_days: usize,
    /// Backwards-compatible alias for `estimated_counterfactual_tokens`.
    pub without_libredb_tokens: u64,
    /// Backwards-compatible alias for `observed_libredb_tokens_approx`.
    pub with_libredb_tokens: u64,
    /// Backwards-compatible alias for `estimated_tokens_avoided`.
    pub net_tokens_saved: u64,
    pub observed_libredb_tokens_approx: u64,
    pub estimated_counterfactual_tokens: u64,
    pub estimated_tokens_avoided: u64,
    pub savings_percent: f64,
    pub compression_factor: f64,
    pub metrics: SavingsMetrics,
    pub ledger_only_metrics: SavingsMetrics,
    pub transcript_only_metrics: SavingsMetrics,
    pub provider_reported_usage: ProviderReportedUsage,
    pub per_day: BTreeMap<String, SavingsMetrics>,
}

#[derive(Debug, Clone, Copy)]
pub enum TelemetryEvent {
    Skeleton {
        zero_repeat_hits: u64,
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    Fim {
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    Impact {
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    Pulse {
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    SkillSlice {
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    HookHydration {
        dedup_skipped: bool,
        baseline_tokens: u64,
        emitted_tokens: u64,
    },
    HookSymbolShift {
        reread_tokens_avoided: u64,
    },
}

impl TelemetryEvent {
    fn to_metrics_delta(self) -> SavingsMetrics {
        let mut delta = SavingsMetrics::default();
        match self {
            TelemetryEvent::Skeleton {
                zero_repeat_hits,
                baseline_tokens,
                emitted_tokens,
            } => {
                delta.skeleton_calls = 1;
                delta.skeleton_zero_repeat_hits = zero_repeat_hits;
                delta.skeleton_baseline_tokens = baseline_tokens.max(emitted_tokens);
                delta.skeleton_emitted_tokens = emitted_tokens;
            }
            TelemetryEvent::Fim {
                baseline_tokens,
                emitted_tokens,
            } => {
                delta.fim_calls = 1;
                delta.fim_baseline_tokens = baseline_tokens.max(emitted_tokens);
                delta.fim_emitted_tokens = emitted_tokens;
            }
            TelemetryEvent::Impact {
                baseline_tokens,
                emitted_tokens,
            } => {
                delta.impact_calls = 1;
                delta.impact_baseline_tokens = baseline_tokens.max(emitted_tokens);
                delta.impact_emitted_tokens = emitted_tokens;
            }
            TelemetryEvent::Pulse {
                baseline_tokens,
                emitted_tokens,
            } => {
                delta.pulse_calls = 1;
                delta.pulse_baseline_tokens = baseline_tokens.max(emitted_tokens);
                delta.pulse_emitted_tokens = emitted_tokens;
            }
            TelemetryEvent::SkillSlice {
                baseline_tokens,
                emitted_tokens,
            } => {
                delta.skill_slice_calls = 1;
                delta.skill_baseline_tokens = baseline_tokens.max(emitted_tokens);
                delta.skill_emitted_tokens = emitted_tokens;
            }
            TelemetryEvent::HookHydration {
                dedup_skipped,
                baseline_tokens,
                emitted_tokens,
            } => {
                if dedup_skipped {
                    delta.hook_dedup_skipped_turns = 1;
                    delta.hook_baseline_tokens = baseline_tokens;
                } else {
                    delta.hook_hydrated_turns = 1;
                    delta.hook_baseline_tokens = baseline_tokens.max(emitted_tokens);
                    delta.hook_emitted_tokens = emitted_tokens;
                }
            }
            TelemetryEvent::HookSymbolShift {
                reread_tokens_avoided,
            } => {
                delta.hook_symbol_shifts = 1;
                delta.hook_baseline_tokens = reread_tokens_avoided;
            }
        }
        delta
    }
}

fn default_telemetry_ldb_path() -> Option<PathBuf> {
    if TELEMETRY_SUPPRESSED.load(Ordering::Relaxed)
        || env::var_os("LIBREDB_DISABLE_TELEMETRY").is_some()
    {
        return None;
    }
    if let Some(custom_p) = env::var_os("LIBREDB_TELEMETRY_PATH") {
        let pb = PathBuf::from(custom_p);
        if !pb.as_os_str().is_empty() {
            return Some(pb);
        }
    }
    let home = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME"))?;
    let libre_dir = PathBuf::from(home).join(".gemini").join("libredb");
    if !libre_dir.is_dir() {
        return None;
    }
    Some(libre_dir.join("telemetry.ldb"))
}

pub fn current_utc_date_ymd() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    unix_secs_to_ymd(secs)
}

/// Howard Hinnant civil-from-days algorithm (exact Gregorian `YYYY-MM-DD` without external crates).
pub fn unix_secs_to_ymd(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// `O(1)` ISO-8601 `YYYY-MM-DD` range filter (zero `HashSet` allocation regardless of `days`).
#[derive(Debug, Clone)]
struct DateWindow {
    min_ymd: String,
    max_ymd: String,
}

impl DateWindow {
    fn from_options(today_only: bool, days_opt: Option<u32>) -> Option<Self> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let span = if today_only { Some(1u32) } else { days_opt }?;
        let clamped_days = (span.max(1) as u64).min(MAX_SAVINGS_DAYS) as i64;
        let min_secs = now_secs.saturating_sub((clamped_days - 1) * 86_400);
        let max_secs = if today_only {
            now_secs.saturating_add(7_200)
        } else {
            now_secs.saturating_add(86_400)
        };
        Some(Self {
            min_ymd: unix_secs_to_ymd(min_secs),
            max_ymd: unix_secs_to_ymd(max_secs),
        })
    }

    #[inline]
    fn contains_ymd(&self, ymd: &str) -> bool {
        ymd.len() == 10
            && ymd.as_bytes()[4] == b'-'
            && ymd.as_bytes()[7] == b'-'
            && ymd >= self.min_ymd.as_str()
            && ymd <= self.max_ymd.as_str()
    }
}

pub fn workspace_ledger_prefix(ws_root: &Path) -> String {
    let norm = crate::security::normalize_workspace_key(ws_root);
    let h = hash_key(173, norm.as_bytes());
    format!("ws_day::{h:016x}::")
}

/// Best-effort, non-failing numeric telemetry append into `~/.gemini/libredb/telemetry.ldb`.
#[cfg(test)]
pub fn record_event(_ev: TelemetryEvent) {}

/// Best-effort, non-failing numeric telemetry append into `~/.gemini/libredb/telemetry.ldb`.
#[cfg(not(test))]
pub fn record_event(ev: TelemetryEvent) {
    let Some(path) = default_telemetry_ldb_path() else {
        return;
    };
    record_event_at(&path, &current_utc_date_ymd(), ev);
}

#[cfg(test)]
pub fn record_workspace_event(_ws_root: &Path, _ev: TelemetryEvent) {}

#[cfg(not(test))]
pub fn record_workspace_event(ws_root: &Path, ev: TelemetryEvent) {
    let Some(path) = default_telemetry_ldb_path() else {
        return;
    };
    record_workspace_event_at(&path, &current_utc_date_ymd(), Some(ws_root), ev);
}

#[cfg(not(test))]
pub fn record_event_at(telemetry_ldb: &Path, ymd: &str, ev: TelemetryEvent) {
    record_workspace_event_at(telemetry_ldb, ymd, None, ev);
}

/// Cross-process-atomic telemetry counter increment backed by `LibreDb::transact_key`
/// (`commit_lock` + OS `IpcWriteGuard` + `sync_from_disk_if_changed`), preventing lost updates
/// when concurrent CLI/hook/MCP processes write to `telemetry.ldb` simultaneously.
pub fn record_workspace_event_at(
    telemetry_ldb: &Path,
    ymd: &str,
    ws_root: Option<&Path>,
    ev: TelemetryEvent,
) {
    let Ok(db) = LibreDb::open(telemetry_ldb) else {
        return;
    };
    let delta = ev.to_metrics_delta();
    let day_key = format!("day::{ymd}");
    let _ = db.transact_key(NodeKind::Generic, &day_key, |existing| {
        let mut bucket = existing
            .and_then(|rec| serde_json::from_slice::<SavingsMetrics>(&rec.payload).ok())
            .unwrap_or_default();
        bucket.add_assign(&delta);
        let bytes = serde_json::to_vec(&bucket).unwrap_or_default();
        Ok(Some(
            WriteRequest::new(NodeKind::Generic, bytes)
                .with_key(day_key.clone())
                .with_importance(64),
        ))
    });

    if let Some(ws) = ws_root {
        let ws_key = format!("{}{ymd}", workspace_ledger_prefix(ws));
        let _ = db.transact_key(NodeKind::Generic, &ws_key, |existing| {
            let mut bucket = existing
                .and_then(|rec| serde_json::from_slice::<SavingsMetrics>(&rec.payload).ok())
                .unwrap_or_default();
            bucket.add_assign(&delta);
            let bytes = serde_json::to_vec(&bucket).unwrap_or_default();
            Ok(Some(
                WriteRequest::new(NodeKind::Generic, bytes)
                    .with_key(ws_key.clone())
                    .with_importance(64),
            ))
        });
    }

    if let Ok(st) = db.stats() {
        if st.superseded_nodes >= 128 {
            let _ = db.maybe_auto_compact();
        }
    }
}

pub struct SavingsQueryOptions<'a> {
    pub today_only: bool,
    pub days: Option<u32>,
    pub cid_filter: Option<&'a str>,
    pub project_filter: Option<&'a Path>,
    pub custom_brain_dir: Option<&'a Path>,
    pub custom_telemetry_ldb: Option<&'a Path>,
}

pub fn build_savings_report(opts: &SavingsQueryOptions<'_>) -> SavingsReport {
    let date_window = DateWindow::from_options(opts.today_only, opts.days);
    let mut ledger_by_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();

    if opts.cid_filter.is_none() {
        let tel_path_opt = opts
            .custom_telemetry_ldb
            .map(Path::to_path_buf)
            .or_else(default_telemetry_ldb_path);
        if let Some(tel_p) = tel_path_opt {
            if tel_p.is_file() {
                if let Ok(db) = LibreDb::open(&tel_p) {
                    let key_prefix = opts
                        .project_filter
                        .map(workspace_ledger_prefix)
                        .unwrap_or_else(|| "day::".to_owned());
                    for (ino, k_opt, _) in db.list_inodes(Some(NodeKind::Generic), false) {
                        let Some(k) = k_opt else { continue };
                        let Some(ymd) = k.strip_prefix(&key_prefix) else {
                            continue;
                        };
                        if let Some(ref win) = date_window {
                            if !win.contains_ymd(ymd) {
                                continue;
                            }
                        }
                        if let Ok(rec) = db.get(ino.node_id) {
                            if let Ok(m) = serde_json::from_slice::<SavingsMetrics>(&rec.payload) {
                                ledger_by_day.insert(ymd.to_owned(), m);
                            }
                        }
                    }
                }
            }
        }
    }

    let scan_out = scan_transcripts_by_day(
        opts.custom_brain_dir,
        date_window.as_ref(),
        opts.cid_filter,
        opts.project_filter,
    );

    let mut ledger_only = SavingsMetrics::default();
    for m in ledger_by_day.values() {
        ledger_only.add_assign(m);
    }
    let mut transcript_only = SavingsMetrics::default();
    for m in scan_out.by_day.values() {
        transcript_only.add_assign(m);
    }

    let mut all_days: HashSet<String> = ledger_by_day.keys().cloned().collect();
    all_days.extend(scan_out.by_day.keys().cloned());
    let mut per_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();
    let mut combined = SavingsMetrics::default();

    for day in all_days {
        let merged = match (ledger_by_day.get(&day), scan_out.by_day.get(&day)) {
            (Some(a), Some(b)) => a.max_merge(b),
            (Some(a), None) => a.clone(),
            (None, Some(b)) => b.clone(),
            (None, None) => SavingsMetrics::default(),
        };
        combined.add_assign(&merged);
        per_day.insert(day, merged);
    }

    let counterfactual_tok = combined.total_baseline_tokens();
    let observed_tok = combined.total_emitted_tokens();
    let avoided_tok = combined.net_tokens_saved();
    let pct = combined.savings_pct();
    let factor = if observed_tok > 0 && counterfactual_tok > 0 {
        counterfactual_tok as f64 / observed_tok as f64
    } else {
        1.0
    };

    let scope_label = if let Some(cid) = opts.cid_filter {
        format!("conversation:{cid}")
    } else if let Some(p) = opts.project_filter {
        if opts.today_only {
            format!("project:{} (today {})", p.display(), current_utc_date_ymd())
        } else if let Some(d) = opts.days {
            format!("project:{} (last {d} days)", p.display())
        } else {
            format!("project:{}", p.display())
        }
    } else if opts.today_only {
        format!("today ({})", current_utc_date_ymd())
    } else if let Some(d) = opts.days {
        format!("last {d} days")
    } else {
        "all recorded sessions".to_owned()
    };

    SavingsReport {
        scope_label,
        token_estimation_method:
            "observed_utf8_bytes_div_4_vs_modeled_counterfactual_plus_provider_usage".to_owned(),
        conversations_analyzed: scan_out.convs_matched,
        transcripts_scanned: scan_out.transcripts_scanned,
        scan_truncated: scan_out.scan_truncated,
        active_days: per_day.len(),
        without_libredb_tokens: counterfactual_tok,
        with_libredb_tokens: observed_tok,
        net_tokens_saved: avoided_tok,
        observed_libredb_tokens_approx: observed_tok,
        estimated_counterfactual_tokens: counterfactual_tok,
        estimated_tokens_avoided: avoided_tok,
        savings_percent: (pct * 10.0).round() / 10.0,
        compression_factor: (factor * 100.0).round() / 100.0,
        metrics: combined,
        ledger_only_metrics: ledger_only,
        transcript_only_metrics: transcript_only,
        provider_reported_usage: scan_out.provider_usage,
        per_day,
    }
}

struct TranscriptScanOutcome {
    by_day: BTreeMap<String, SavingsMetrics>,
    provider_usage: ProviderReportedUsage,
    convs_matched: usize,
    transcripts_scanned: usize,
    scan_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedLineStatus {
    Eof,
    Line(u64),
    OversizedSkipped(u64),
}

/// Reads at most `max_bytes` of a single JSONL line using chunked `fill_buf`/`consume`.
/// If a line exceeds `max_bytes` (e.g., a newline-less multi-hundred-MiB blob), immediately
/// clears `buf` and drains the remainder of that line in-place with **zero further heap growth**.
pub fn read_bounded_jsonl_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<BoundedLineStatus> {
    buf.clear();
    let mut total_bytes: u64 = 0;
    let mut oversized = false;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if total_bytes == 0 {
                Ok(BoundedLineStatus::Eof)
            } else if oversized {
                buf.clear();
                Ok(BoundedLineStatus::OversizedSkipped(total_bytes))
            } else {
                Ok(BoundedLineStatus::Line(total_bytes))
            };
        }

        if let Some(nl_pos) = available.iter().position(|&b| b == b'\n') {
            let consume_len = nl_pos + 1;
            total_bytes = total_bytes.saturating_add(consume_len as u64);
            if !oversized {
                if buf.len().saturating_add(nl_pos) <= max_bytes {
                    buf.extend_from_slice(&available[..nl_pos]);
                } else {
                    oversized = true;
                    buf.clear();
                }
            }
            reader.consume(consume_len);
            return if oversized {
                Ok(BoundedLineStatus::OversizedSkipped(total_bytes))
            } else {
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                Ok(BoundedLineStatus::Line(total_bytes))
            };
        } else {
            let chunk_len = available.len();
            total_bytes = total_bytes.saturating_add(chunk_len as u64);
            if !oversized {
                if buf.len().saturating_add(chunk_len) <= max_bytes {
                    buf.extend_from_slice(available);
                } else {
                    oversized = true;
                    buf.clear();
                }
            }
            reader.consume(chunk_len);
        }
    }
}

fn scan_transcripts_by_day(
    custom_brain_dir: Option<&Path>,
    date_window: Option<&DateWindow>,
    cid_filter: Option<&str>,
    project_filter: Option<&Path>,
) -> TranscriptScanOutcome {
    let mut out = TranscriptScanOutcome {
        by_day: BTreeMap::new(),
        provider_usage: ProviderReportedUsage::default(),
        convs_matched: 0,
        transcripts_scanned: 0,
        scan_truncated: false,
    };

    let brain_root = match custom_brain_dir {
        Some(p) => p.to_path_buf(),
        None => {
            let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) else {
                return out;
            };
            PathBuf::from(home)
                .join(".gemini")
                .join("antigravity")
                .join("brain")
        }
    };
    if !brain_root.is_dir() {
        return out;
    }

    let proj_needles: Option<(Vec<u8>, Vec<u8>)> = project_filter.map(|p| {
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let raw = canon.to_string_lossy();
        let clean = raw
            .strip_prefix(r"\\?\")
            .unwrap_or(&raw)
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let bs = clean.replace('/', "\\");
        (clean.into_bytes(), bs.into_bytes())
    });

    let Ok(entries) = std::fs::read_dir(&brain_root) else {
        return out;
    };

    let mut candidates: Vec<(u128, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let cid_name = entry.file_name().to_string_lossy().into_owned();
        if let Some(cf) = cid_filter {
            if !cid_name.starts_with(cf) {
                continue;
            }
        }
        let t_path = entry
            .path()
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl");
        let Ok(meta) = std::fs::symlink_metadata(&t_path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        candidates.push((mtime_ns, t_path));
    }

    // Scan newest transcripts first so bounded budgets always prioritize recent activity.
    candidates.sort_by(|a, b| b.0.cmp(&a.0));

    let mut cumulative_bytes: u64 = 0;
    for (_, t_path) in candidates {
        if out.transcripts_scanned >= MAX_TRANSCRIPTS_SCANNED
            || cumulative_bytes >= MAX_TOTAL_TRANSCRIPT_SCAN_BYTES
        {
            out.scan_truncated = true;
            break;
        }
        out.transcripts_scanned += 1;
        let remaining_budget = MAX_TOTAL_TRANSCRIPT_SCAN_BYTES.saturating_sub(cumulative_bytes);
        let (matched, bytes_read, hit_budget_cap) = parse_single_transcript(
            &t_path,
            date_window,
            proj_needles.as_ref(),
            remaining_budget,
            &mut out.by_day,
            &mut out.provider_usage,
        );
        cumulative_bytes = cumulative_bytes.saturating_add(bytes_read);
        if hit_budget_cap {
            out.scan_truncated = true;
        }
        if matched {
            out.convs_matched += 1;
        }
    }

    out
}

/// Zero-allocation case-insensitive workspace path boundary check (`needle` must not be followed
/// by an identifier/path-segment continuation byte, preventing `/repo/app` from matching `/repo/app2`).
fn line_mentions_workspace_bytes(line: &[u8], needle_slash: &[u8], needle_bs: &[u8]) -> bool {
    contains_path_boundary_ci(line, needle_slash) || contains_path_boundary_ci(line, needle_bs)
}

fn contains_path_boundary_ci(haystack: &[u8], needle_low: &[u8]) -> bool {
    if needle_low.is_empty() || haystack.len() < needle_low.len() {
        return false;
    }
    let max_start = haystack.len() - needle_low.len();
    for start in 0..=max_start {
        if haystack[start].to_ascii_lowercase() != needle_low[0] {
            continue;
        }
        if haystack[start..start + needle_low.len()]
            .iter()
            .zip(needle_low.iter())
            .all(|(&h, &n)| h.to_ascii_lowercase() == n)
        {
            let end = start + needle_low.len();
            let boundary_ok = if end >= haystack.len() {
                true
            } else {
                matches!(
                    haystack[end],
                    b'/' | b'\\' | b'"' | b'\'' | b' ' | b'\t' | b'\r' | b'\n' | b')' | b']' | b'}' | b',' | b';'
                )
            };
            if boundary_ok {
                return true;
            }
        }
    }
    false
}

fn extract_u64_field(obj: &Value, keys: &[&str]) -> Option<u64> {
    for &k in keys {
        if let Some(n) = obj.get(k).and_then(Value::as_u64) {
            return Some(n);
        }
        for sub in ["usage", "token_usage", "usageMetadata", "tokenUsage"] {
            if let Some(n) = obj.get(sub).and_then(|u| u.get(k)).and_then(Value::as_u64) {
                return Some(n);
            }
        }
    }
    None
}

fn parse_single_transcript(
    t_path: &Path,
    date_window: Option<&DateWindow>,
    proj_needles: Option<&(Vec<u8>, Vec<u8>)>,
    max_file_scan_bytes: u64,
    by_day: &mut BTreeMap<String, SavingsMetrics>,
    provider_usage: &mut ProviderReportedUsage,
) -> (bool, u64, bool) {
    let Ok(file) = File::open(t_path) else {
        return (false, 0, false);
    };
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut raw_buf: Vec<u8> = Vec::with_capacity(16 * 1024);

    let mut touches_proj = proj_needles.is_none();
    let mut local_by_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();
    let mut local_provider = ProviderReportedUsage::default();
    let mut matched_any_step = false;
    let mut active_hydration_tok_in_epoch: Option<(String, u64)> = None;
    let mut bytes_consumed: u64 = 0;
    let mut hit_budget = false;

    loop {
        if bytes_consumed >= max_file_scan_bytes {
            hit_budget = true;
            break;
        }
        match read_bounded_jsonl_line(&mut reader, &mut raw_buf, MAX_TRANSCRIPT_LINE_BYTES) {
            Ok(BoundedLineStatus::Eof) => break,
            Ok(BoundedLineStatus::OversizedSkipped(n)) => {
                bytes_consumed = bytes_consumed.saturating_add(n);
                continue;
            }
            Ok(BoundedLineStatus::Line(n)) => {
                bytes_consumed = bytes_consumed.saturating_add(n);
            }
            Err(_) => break,
        }

        if !touches_proj {
            if let Some((ref ns, ref nbs)) = proj_needles {
                if line_mentions_workspace_bytes(&raw_buf, ns, nbs) {
                    touches_proj = true;
                }
            }
        }

        let Ok(line_str) = std::str::from_utf8(&raw_buf) else {
            continue;
        };
        let trimmed = line_str.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let created_at = val.get("created_at").and_then(Value::as_str).unwrap_or("");
        let ymd = if created_at.len() >= 10 {
            &created_at[..10]
        } else {
            continue;
        };
        let date_in_scope = date_window.map_or(true, |win| win.contains_ymd(ymd));

        let step_type = val.get("type").and_then(Value::as_str).unwrap_or("");
        let content = val.get("content").and_then(Value::as_str).unwrap_or("");

        if date_in_scope && step_type == "PLANNER_RESPONSE" {
            let in_tok = extract_u64_field(&val, &["input_tokens", "prompt_tokens", "promptTokenCount"]);
            let cache_tok = extract_u64_field(
                &val,
                &[
                    "cache_read_tokens",
                    "cached_tokens",
                    "cached_content_token_count",
                    "cachedContentTokenCount",
                ],
            );
            let out_tok = extract_u64_field(
                &val,
                &["output_tokens", "completion_tokens", "candidates_token_count", "candidatesTokenCount"],
            );
            if in_tok.is_some() || cache_tok.is_some() || out_tok.is_some() {
                local_provider.planner_steps += 1;
                local_provider.input_tokens = local_provider
                    .input_tokens
                    .saturating_add(in_tok.unwrap_or(0));
                local_provider.cache_read_tokens = local_provider
                    .cache_read_tokens
                    .saturating_add(cache_tok.unwrap_or(0));
                local_provider.output_tokens = local_provider
                    .output_tokens
                    .saturating_add(out_tok.unwrap_or(0));
            }
        }

        if content.contains("<CONTEXT_SUMMARY>") {
            active_hydration_tok_in_epoch = None;
        }

        // Track PreInvocation hydration vs subsequent Zero-Repeat epoch deduplication across USER_INPUT turns
        if content.contains("=== PROJECT MEMORY CONTEXT (LibreDB .agents/memory.ldb) ===")
            || content.contains("=== PROJECT MEMORY CONTEXT (SkillsDB")
        {
            if let Some(idx) = content.find("=== PROJECT MEMORY CONTEXT") {
                let block = &content[idx..];
                let end_idx = block.find("</SYSTEM_MESSAGE>").unwrap_or(block.len());
                let hyd_tok = (count_tokens_exact(&block.as_bytes()[..end_idx]) as u64).max(80);
                active_hydration_tok_in_epoch = Some((ymd.to_owned(), hyd_tok));
                if date_in_scope {
                    matched_any_step = true;
                    let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                    bucket.hook_hydrated_turns += 1;
                    bucket.hook_emitted_tokens += hyd_tok;
                    bucket.hook_baseline_tokens += hyd_tok.max(850);
                }
            }
        } else if step_type == "USER_INPUT" {
            if let Some((_, hyd_tok)) = active_hydration_tok_in_epoch {
                if date_in_scope {
                    matched_any_step = true;
                    let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                    bucket.hook_dedup_skipped_turns += 1;
                    bucket.hook_baseline_tokens += hyd_tok;
                }
            }
        }

        if !date_in_scope {
            continue;
        }

        if !content.is_empty() {
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("=== SKELETON: ") {
                    if let Some((raw_t, skel_t)) = parse_skeleton_header_tokens(rest) {
                        matched_any_step = true;
                        let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                        bucket.skeleton_calls += 1;
                        bucket.skeleton_baseline_tokens += raw_t.max(skel_t);
                        bucket.skeleton_emitted_tokens += skel_t;
                    }
                } else if let Some(rest) = line
                    .strip_prefix("=== [Zero-Repeat Skeleton]: ")
                    .or_else(|| line.strip_prefix("[Zero-Repeat Skeleton]: "))
                {
                    let est_raw = parse_total_lines_marker(rest)
                        .map(|l| (l.saturating_mul(9)).max(120))
                        .unwrap_or(1_200);
                    matched_any_step = true;
                    let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                    bucket.skeleton_calls += 1;
                    bucket.skeleton_zero_repeat_hits += 1;
                    bucket.skeleton_baseline_tokens += est_raw;
                    bucket.skeleton_emitted_tokens += 55;
                } else if let Some(rest) = line.strip_prefix("=== FIM SLICE: ") {
                    let total_lines = rest
                        .split(" of L")
                        .nth(1)
                        .and_then(|s| s.split(']').next())
                        .and_then(|n| n.parse::<u64>().ok())
                        .unwrap_or(250);
                    let em_tok = (count_tokens_exact(content.as_bytes()) as u64).max(40);
                    let raw_est = (total_lines.saturating_mul(9)).max(em_tok);
                    matched_any_step = true;
                    let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                    bucket.fim_calls += 1;
                    bucket.fim_baseline_tokens += raw_est;
                    bucket.fim_emitted_tokens += em_tok;
                } else if let Some(rest) = line.strip_prefix("=== IMPACT: ") {
                    let _ = rest;
                    let em_tok = (count_tokens_exact(content.as_bytes()) as u64).max(30);
                    matched_any_step = true;
                    let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                    bucket.impact_calls += 1;
                    bucket.impact_baseline_tokens += (em_tok.saturating_mul(5)).max(2_400);
                    bucket.impact_emitted_tokens += em_tok;
                } else if let Some(rest) = line.strip_prefix("=== LIBREDB PULSE (") {
                    if let Some((em_t, total_t)) = parse_pulse_header_tokens(rest) {
                        matched_any_step = true;
                        let bucket = local_by_day.entry(ymd.to_owned()).or_default();
                        bucket.pulse_calls += 1;
                        bucket.pulse_emitted_tokens += em_t;
                        bucket.pulse_baseline_tokens += total_t.max(em_t + 350);
                    }
                }
            }
        }

        // CLI `get-skill --section` progressive disclosure calls in `tool_calls`
        if trimmed.contains("get-skill") && trimmed.contains("--section") {
            matched_any_step = true;
            let bucket = local_by_day.entry(ymd.to_owned()).or_default();
            bucket.skill_slice_calls += 1;
            bucket.skill_baseline_tokens += 2_200;
            bucket.skill_emitted_tokens += 320;
        }
    }

    if !touches_proj {
        return (false, bytes_consumed, hit_budget);
    }

    for (day, m) in local_by_day {
        by_day.entry(day).or_default().add_assign(&m);
    }
    if matched_any_step || proj_needles.is_none() || local_provider.planner_steps > 0 {
        provider_usage.add_assign(&local_provider);
    }

    (matched_any_step, bytes_consumed, hit_budget)
}

fn parse_skeleton_header_tokens(rest: &str) -> Option<(u64, u64)> {
    let (_, after_tilde) = rest.split_once(", ~")?;
    let (raw_s, after_arrow) = after_tilde.split_once(" -> ~")?;
    let skel_s = after_arrow.split_whitespace().next()?;
    let raw_t = raw_s.trim().parse::<u64>().ok()?;
    let skel_t = skel_s.trim().parse::<u64>().ok()?;
    Some((raw_t, skel_t))
}

fn parse_total_lines_marker(rest: &str) -> Option<u64> {
    let (_, after_l1) = rest.split_once("L1-L")?;
    let num_s: String = after_l1.chars().take_while(char::is_ascii_digit).collect();
    num_s.parse::<u64>().ok()
}

fn parse_pulse_header_tokens(rest: &str) -> Option<(u64, u64)> {
    let first_tok = rest.split_whitespace().next()?;
    let (em_s, tot_s) = first_tok.split_once('/')?;
    Some((em_s.parse().ok()?, tot_s.parse().ok()?))
}

pub fn format_savings_report(rep: &SavingsReport) -> String {
    let m = &rep.metrics;
    let mut out = String::new();
    out.push_str(&format!(
        "=== LibreDB Token Consumption & Counterfactual Savings Report [{}] ===\n",
        rep.scope_label
    ));
    out.push_str(&format!(
        "Analyzed scope: {} active day(s), {} matched conversation(s) ({} transcript(s) scanned{}) + live telemetry ledger\n",
        rep.active_days,
        rep.conversations_analyzed,
        rep.transcripts_scanned,
        if rep.scan_truncated { ", bounded cap reached" } else { "" }
    ));
    out.push_str(
        "Accounting basis: LibreDB output uses ~UTF-8 bytes/4; baseline is a modeled without-DB counterfactual.\n\n",
    );
    out.push_str(&format!(
        "{:<38} {:>8} {:>15} {:>15} {:>15} {:>8}\n",
        "Subsystem", "Calls", "Est. Baseline", "LibreDB (~B/4)", "Est. Avoided", "Ratio"
    ));
    out.push_str(&format!("{}\n", "-".repeat(104)));

    let rows = [
        (
            format!(
                "Code Skeletons ({} Zero-Repeat)",
                m.skeleton_zero_repeat_hits
            ),
            m.skeleton_calls,
            m.skeleton_baseline_tokens,
            m.skeleton_emitted_tokens,
        ),
        (
            "Surgical FIM Slices".to_owned(),
            m.fim_calls,
            m.fim_baseline_tokens,
            m.fim_emitted_tokens,
        ),
        (
            "Call-Graph Impact".to_owned(),
            m.impact_calls,
            m.impact_baseline_tokens,
            m.impact_emitted_tokens,
        ),
        (
            "Cognitive Pulse & Delta Dedup".to_owned(),
            m.pulse_calls,
            m.pulse_baseline_tokens,
            m.pulse_emitted_tokens,
        ),
        (
            "Progressive Skill Slicing".to_owned(),
            m.skill_slice_calls,
            m.skill_baseline_tokens,
            m.skill_emitted_tokens,
        ),
        (
            format!(
                "Hooks ({} dedup, {} sym shifts)",
                m.hook_dedup_skipped_turns, m.hook_symbol_shifts
            ),
            m.hook_hydrated_turns
                .saturating_add(m.hook_dedup_skipped_turns)
                .saturating_add(m.hook_symbol_shifts),
            m.hook_baseline_tokens,
            m.hook_emitted_tokens,
        ),
    ];

    for (name, calls, base, em) in rows {
        let sav = base.saturating_sub(em);
        let pct = if base > 0 {
            (sav as f64 / base as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "{:<38} {:>8} {:>11} tok {:>11} tok {:>11} tok {:>6.1}%\n",
            name, calls, base, em, sav, pct
        ));
    }

    out.push_str(&format!("{}\n", "-".repeat(104)));
    out.push_str(&format!(
        "{:<38} {:>8} {:>11} tok {:>11} tok {:>11} tok {:>6.1}% ({:.2}x)\n",
        "TOTAL (max-merged per day)",
        "-",
        rep.estimated_counterfactual_tokens,
        rep.observed_libredb_tokens_approx,
        rep.estimated_tokens_avoided,
        rep.savings_percent,
        rep.compression_factor
    ));
    out.push_str(&format!(
        "Source attribution: ledger={} avoided tok | transcripts={} avoided tok | max-merged={} avoided tok\n",
        rep.ledger_only_metrics.net_tokens_saved(),
        rep.transcript_only_metrics.net_tokens_saved(),
        rep.estimated_tokens_avoided
    ));
    let p = &rep.provider_reported_usage;
    if p.planner_steps > 0 {
        out.push_str(&format!(
            "Provider-reported usage ({} planner steps): input={} tok, cache_read={} tok, output={} tok\n",
            p.planner_steps, p.input_tokens, p.cache_read_tokens, p.output_tokens
        ));
    } else {
        out.push_str("Provider-reported usage: none recorded in scanned transcripts\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn telemetry_ledger_and_transcript_merge_with_provider_usage_and_workspace_isolation() {
        let tmp = env::temp_dir().join(format!("libredb_tel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let ws_a = tmp.join("ws_alpha");
        let ws_b = tmp.join("ws_beta");
        std::fs::create_dir_all(&ws_a).unwrap();
        std::fs::create_dir_all(&ws_b).unwrap();

        let brain_dir = tmp.join("brain");
        let cid_logs = brain_dir
            .join("cid-1234")
            .join(".system_generated")
            .join("logs");
        std::fs::create_dir_all(&cid_logs).unwrap();

        let ws_a_slash = ws_a.to_string_lossy().replace('\\', "/");
        let transcript = cid_logs.join("transcript.jsonl");
        std::fs::write(
            &transcript,
            format!(
                concat!(
                    r#"{{"created_at":"2026-11-11T10:00:00Z","type":"USER_INPUT","content":"<SYSTEM_MESSAGE>\n=== PROJECT MEMORY CONTEXT (LibreDB .agents/memory.ldb) ===\nGit Telemetry: branch 'master' @ 833e9fd\nWorkspace: {}\n</SYSTEM_MESSAGE>"}}"#, "\n",
                    r#"{{"created_at":"2026-11-11T10:01:00Z","type":"TOOL_RESPONSE","content":"=== SKELETON: src/main.rs (rust, L1-L2600, ~28931 -> ~496 tok, -98.3%) ===\nContracts:\n"}}"#, "\n",
                    r#"{{"created_at":"2026-11-11T10:02:00Z","type":"TOOL_RESPONSE","content":"=== [Zero-Repeat Skeleton]: src/main.rs (unchanged in session, hash=abc, L1-L2600, 42 contracts, saved ~28915 tok) ==="}}"#, "\n",
                    r#"{{"created_at":"2026-11-11T10:02:30Z","type":"PLANNER_RESPONSE","input_tokens":4200,"cache_read_tokens":3100,"output_tokens":380,"content":"ok"}}"#, "\n",
                    r#"{{"created_at":"2026-11-11T10:03:00Z","type":"USER_INPUT","content":"next turn deduplicated"}}"#, "\n"
                ),
                ws_a_slash
            ),
        )
        .unwrap();

        let tel_ldb = tmp.join("telemetry.ldb");
        record_workspace_event_at(
            &tel_ldb,
            "2026-11-11",
            Some(&ws_a),
            TelemetryEvent::Skeleton {
                zero_repeat_hits: 0,
                baseline_tokens: 28_931,
                emitted_tokens: 496,
            },
        );

        let rep = build_savings_report(&SavingsQueryOptions {
            today_only: false,
            days: None,
            cid_filter: None,
            project_filter: Some(&ws_a),
            custom_brain_dir: Some(&brain_dir),
            custom_telemetry_ldb: Some(&tel_ldb),
        });
        assert_eq!(rep.conversations_analyzed, 1);
        assert_eq!(rep.metrics.skeleton_calls, 2);
        assert_eq!(rep.metrics.skeleton_zero_repeat_hits, 1);
        assert_eq!(rep.metrics.hook_dedup_skipped_turns, 1);
        assert_eq!(rep.provider_reported_usage.planner_steps, 1);
        assert_eq!(rep.provider_reported_usage.input_tokens, 4_200);
        assert_eq!(rep.provider_reported_usage.cache_read_tokens, 3_100);
        assert_eq!(rep.provider_reported_usage.output_tokens, 380);
        assert!(rep.estimated_tokens_avoided > 50_000);

        // Querying isolated Workspace B must return 0 leaked metrics from Workspace A!
        let rep_b = build_savings_report(&SavingsQueryOptions {
            today_only: false,
            days: None,
            cid_filter: None,
            project_filter: Some(&ws_b),
            custom_brain_dir: Some(&brain_dir),
            custom_telemetry_ldb: Some(&tel_ldb),
        });
        assert_eq!(rep_b.conversations_analyzed, 0);
        assert_eq!(rep_b.estimated_tokens_avoided, 0);
        assert_eq!(rep_b.provider_reported_usage.planner_steps, 0);

        let formatted = format_savings_report(&rep);
        assert!(formatted.contains("Provider-reported usage (1 planner steps)"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bounded_jsonl_reader_skips_oversized_newlineless_line_without_buffer_growth() {
        let mut stream = Vec::with_capacity(10 * 1024 * 1024 + 512);
        stream.extend(std::iter::repeat(b'x').take(10 * 1024 * 1024));
        stream.push(b'\n');
        stream.extend_from_slice(br#"{"created_at":"2026-11-11T10:00:00Z","type":"USER_INPUT","content":"ok"}"#);
        stream.push(b'\n');

        let mut reader = BufReader::with_capacity(64 * 1024, Cursor::new(stream));
        let mut buf = Vec::new();
        let s1 = read_bounded_jsonl_line(&mut reader, &mut buf, MAX_TRANSCRIPT_LINE_BYTES).unwrap();
        assert!(matches!(s1, BoundedLineStatus::OversizedSkipped(n) if n > 10 * 1024 * 1024));
        assert!(buf.is_empty());
        assert!(buf.capacity() <= MAX_TRANSCRIPT_LINE_BYTES + 64 * 1024);

        let s2 = read_bounded_jsonl_line(&mut reader, &mut buf, MAX_TRANSCRIPT_LINE_BYTES).unwrap();
        assert!(matches!(s2, BoundedLineStatus::Line(_)));
        assert!(std::str::from_utf8(&buf).unwrap().contains("\"USER_INPUT\""));
    }
}
