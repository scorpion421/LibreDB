//! Built-in token-consumption and savings telemetry (`libredb savings` / `libredb report`).
//!
//! Combines two complementary, zero-seal-impact data sources without double-counting:
//! 1. Live numeric event counters recorded in `~/.gemini/libredb/telemetry.ldb` (strictly numeric,
//!    never touching `.agents/memory.ldb` or `customizations.ldb` trust seals), and
//! 2. Bounded read-only inspection of local `Antigravity` conversation transcripts
//!    (`~/.gemini/antigravity/brain/<cid>/.system_generated/logs/transcript.jsonl`), enabling
//!    immediate retroactive reporting (`--today`, `--days <n>`, `--cid <id>`, `--project <dir>`).

use libredb_core::crc::count_tokens_exact;
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRANSCRIPT_LINE_BYTES: usize = 8 * 1024 * 1024;
static TELEMETRY_SUPPRESSED: AtomicBool = AtomicBool::new(false);

pub fn set_telemetry_suppressed(suppressed: bool) {
    TELEMETRY_SUPPRESSED.store(suppressed, Ordering::Relaxed);
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavingsReport {
    pub scope_label: String,
    pub conversations_analyzed: usize,
    pub active_days: usize,
    pub without_libredb_tokens: u64,
    pub with_libredb_tokens: u64,
    pub net_tokens_saved: u64,
    pub savings_percent: f64,
    pub compression_factor: f64,
    pub metrics: SavingsMetrics,
    pub per_day: BTreeMap<String, SavingsMetrics>,
}

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

fn default_telemetry_ldb_path() -> Option<PathBuf> {
    if TELEMETRY_SUPPRESSED.load(Ordering::Relaxed)
        || env::var_os("LIBREDB_DISABLE_TELEMETRY").is_some()
    {
        return None;
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

fn allowed_date_set(today_only: bool, days_opt: Option<u32>) -> Option<HashSet<String>> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let span = if today_only {
        Some(1u32)
    } else {
        days_opt
    }?;
    let mut out = HashSet::new();
    // Include +1 day slack for local UTC+1/+2 midnight boundaries when `--today` is used:
    for back in 0..span.max(1) {
        let day_secs = now_secs - (back as i64) * 86_400;
        out.insert(unix_secs_to_ymd(day_secs));
    }
    if today_only {
        out.insert(unix_secs_to_ymd(now_secs + 7_200));
    }
    Some(out)
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

pub fn record_event_at(telemetry_ldb: &Path, ymd: &str, ev: TelemetryEvent) {
    let Ok(db) = LibreDb::open(telemetry_ldb) else {
        return;
    };
    let day_key = format!("day::{ymd}");
    let mut bucket = db
        .get_by_key(NodeKind::Generic, &day_key)
        .ok()
        .and_then(|r| serde_json::from_slice::<SavingsMetrics>(&r.payload).ok())
        .unwrap_or_default();

    let mut delta = SavingsMetrics::default();
    match ev {
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

    bucket.add_assign(&delta);
    if let Ok(bytes) = serde_json::to_vec(&bucket) {
        let _ = db.put(
            WriteRequest::new(NodeKind::Generic, bytes)
                .with_key(day_key)
                .with_importance(64),
        );
    }
    let _ = db.maybe_auto_compact();
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
    let allowed_dates = allowed_date_set(opts.today_only, opts.days);
    let mut ledger_by_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();

    if opts.cid_filter.is_none() && opts.project_filter.is_none() {
        let tel_path_opt = opts
            .custom_telemetry_ldb
            .map(Path::to_path_buf)
            .or_else(default_telemetry_ldb_path);
        if let Some(tel_p) = tel_path_opt {
            if tel_p.is_file() {
                if let Ok(db) = LibreDb::open(&tel_p) {
                    for (ino, k_opt, _) in db.list_inodes(Some(NodeKind::Generic), false) {
                        let Some(k) = k_opt else { continue };
                        let Some(ymd) = k.strip_prefix("day::") else { continue };
                        if let Some(ref set) = allowed_dates {
                            if !set.contains(ymd) {
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

    let (transcript_by_day, convs_matched) = scan_transcripts_by_day(
        opts.custom_brain_dir,
        allowed_dates.as_ref(),
        opts.cid_filter,
        opts.project_filter,
    );

    let mut all_days: HashSet<String> = ledger_by_day.keys().cloned().collect();
    all_days.extend(transcript_by_day.keys().cloned());
    let mut per_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();
    let mut combined = SavingsMetrics::default();

    for day in all_days {
        let merged = match (ledger_by_day.get(&day), transcript_by_day.get(&day)) {
            (Some(a), Some(b)) => a.max_merge(b),
            (Some(a), None) => a.clone(),
            (None, Some(b)) => b.clone(),
            (None, None) => SavingsMetrics::default(),
        };
        combined.add_assign(&merged);
        per_day.insert(day, merged);
    }

    let without_tok = combined.total_baseline_tokens();
    let with_tok = combined.total_emitted_tokens();
    let saved = combined.net_tokens_saved();
    let pct = combined.savings_pct();
    let factor = if with_tok > 0 && without_tok > 0 {
        without_tok as f64 / with_tok as f64
    } else {
        1.0
    };

    let scope_label = if let Some(cid) = opts.cid_filter {
        format!("conversation:{cid}")
    } else if opts.today_only {
        format!("today ({})", current_utc_date_ymd())
    } else if let Some(d) = opts.days {
        format!("last {d} days")
    } else if let Some(p) = opts.project_filter {
        format!("project:{}", p.display())
    } else {
        "all recorded sessions".to_owned()
    };

    SavingsReport {
        scope_label,
        conversations_analyzed: convs_matched,
        active_days: per_day.len(),
        without_libredb_tokens: without_tok,
        with_libredb_tokens: with_tok,
        net_tokens_saved: saved,
        savings_percent: (pct * 10.0).round() / 10.0,
        compression_factor: (factor * 100.0).round() / 100.0,
        metrics: combined,
        per_day,
    }
}

fn scan_transcripts_by_day(
    custom_brain_dir: Option<&Path>,
    allowed_dates: Option<&HashSet<String>>,
    cid_filter: Option<&str>,
    project_filter: Option<&Path>,
) -> (BTreeMap<String, SavingsMetrics>, usize) {
    let mut by_day: BTreeMap<String, SavingsMetrics> = BTreeMap::new();
    let mut convs_matched = 0usize;

    let brain_root = match custom_brain_dir {
        Some(p) => p.to_path_buf(),
        None => {
            let Some(home) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) else {
                return (by_day, 0);
            };
            PathBuf::from(home)
                .join(".gemini")
                .join("antigravity")
                .join("brain")
        }
    };
    if !brain_root.is_dir() {
        return (by_day, 0);
    }

    let proj_needle = project_filter.map(|p| {
        p.to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    });

    let Ok(entries) = std::fs::read_dir(&brain_root) else {
        return (by_day, 0);
    };

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

        if parse_single_transcript(&t_path, allowed_dates, proj_needle.as_deref(), &mut by_day) {
            convs_matched += 1;
        }
    }

    (by_day, convs_matched)
}

fn parse_single_transcript(
    t_path: &Path,
    allowed_dates: Option<&HashSet<String>>,
    proj_needle: Option<&str>,
    by_day: &mut BTreeMap<String, SavingsMetrics>,
) -> bool {
    let Ok(file) = File::open(t_path) else {
        return false;
    };
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();

    // If a `--project` filter is active, check in a fast first pass whether this transcript touches it.
    if let Some(needle) = proj_needle {
        let needle_bs = needle.replace('/', "\\");
        let mut touches_proj = false;
        loop {
            line_buf.clear();
            let Ok(n) = reader.read_line(&mut line_buf) else {
                break;
            };
            if n == 0 {
                break;
            }
            if line_buf.len() <= MAX_TRANSCRIPT_LINE_BYTES {
                let low = line_buf.to_ascii_lowercase();
                if low.contains(needle) || low.contains(&needle_bs) {
                    touches_proj = true;
                    break;
                }
            }
        }
        if !touches_proj {
            return false;
        }
        let Ok(reopened) = File::open(t_path) else {
            return false;
        };
        reader = BufReader::new(reopened);
    }

    let mut matched_any_step = false;
    let mut active_hydration_tok_in_epoch: Option<(String, u64)> = None;

    loop {
        line_buf.clear();
        let Ok(n) = reader.read_line(&mut line_buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        if line_buf.len() > MAX_TRANSCRIPT_LINE_BYTES {
            continue;
        }

        let Ok(val) = serde_json::from_str::<Value>(line_buf.trim()) else {
            continue;
        };
        let created_at = val.get("created_at").and_then(Value::as_str).unwrap_or("");
        let ymd = if created_at.len() >= 10 {
            &created_at[..10]
        } else {
            continue;
        };
        let date_in_scope = allowed_dates.map_or(true, |set| set.contains(ymd));

        let step_type = val.get("type").and_then(Value::as_str).unwrap_or("");
        let content = val.get("content").and_then(Value::as_str).unwrap_or("");

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
                    let bucket = by_day.entry(ymd.to_owned()).or_default();
                    bucket.hook_hydrated_turns += 1;
                    bucket.hook_emitted_tokens += hyd_tok;
                    bucket.hook_baseline_tokens += hyd_tok.max(850);
                }
            }
        } else if step_type == "USER_INPUT" {
            if let Some((_, hyd_tok)) = active_hydration_tok_in_epoch {
                if date_in_scope {
                    matched_any_step = true;
                    let bucket = by_day.entry(ymd.to_owned()).or_default();
                    bucket.hook_dedup_skipped_turns += 1;
                    bucket.hook_baseline_tokens += hyd_tok;
                }
            }
        }

        if !date_in_scope || content.is_empty() {
            continue;
        }

        // 1. Skeleton headers: `=== SKELETON: <file> (<lang>, L1-L<N>, ~<raw> -> ~<skel> tok`
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("=== SKELETON: ") {
                if let Some((raw_t, skel_t)) = parse_skeleton_header_tokens(rest) {
                    matched_any_step = true;
                    let bucket = by_day.entry(ymd.to_owned()).or_default();
                    bucket.skeleton_calls += 1;
                    bucket.skeleton_baseline_tokens += raw_t.max(skel_t);
                    bucket.skeleton_emitted_tokens += skel_t;
                }
            } else if let Some(rest) = line.strip_prefix("[Zero-Repeat Skeleton]: ") {
                let est_raw = parse_total_lines_marker(rest)
                    .map(|l| (l.saturating_mul(9)).max(120))
                    .unwrap_or(1_200);
                matched_any_step = true;
                let bucket = by_day.entry(ymd.to_owned()).or_default();
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
                let bucket = by_day.entry(ymd.to_owned()).or_default();
                bucket.fim_calls += 1;
                bucket.fim_baseline_tokens += raw_est;
                bucket.fim_emitted_tokens += em_tok;
            } else if let Some(rest) = line.strip_prefix("=== IMPACT: ") {
                let _ = rest;
                let em_tok = (count_tokens_exact(content.as_bytes()) as u64).max(30);
                matched_any_step = true;
                let bucket = by_day.entry(ymd.to_owned()).or_default();
                bucket.impact_calls += 1;
                bucket.impact_baseline_tokens += (em_tok.saturating_mul(5)).max(2_400);
                bucket.impact_emitted_tokens += em_tok;
            } else if let Some(rest) = line.strip_prefix("=== LIBREDB PULSE (") {
                if let Some((em_t, total_t)) = parse_pulse_header_tokens(rest) {
                    matched_any_step = true;
                    let bucket = by_day.entry(ymd.to_owned()).or_default();
                    bucket.pulse_calls += 1;
                    bucket.pulse_emitted_tokens += em_t;
                    bucket.pulse_baseline_tokens += total_t.max(em_t + 350);
                }
            }
        }

        // CLI `get-skill --section` progressive disclosure calls in `tool_calls`
        if line_buf.contains("get-skill") && line_buf.contains("--section") {
            matched_any_step = true;
            let bucket = by_day.entry(ymd.to_owned()).or_default();
            bucket.skill_slice_calls += 1;
            bucket.skill_baseline_tokens += 2_200;
            bucket.skill_emitted_tokens += 320;
        }
    }

    matched_any_step
}

fn parse_skeleton_header_tokens(rest: &str) -> Option<(u64, u64)> {
    // Format: `<file> (<lang>, L1-L<N>, ~28931 -> ~496 tok, -98.3%) ===`
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
    // Format: `420/1180 tok emitted | 760 tok saved via Zero-Repeat Delta | ...`
    let first_tok = rest.split_whitespace().next()?;
    let (em_s, tot_s) = first_tok.split_once('/')?;
    Some((em_s.parse().ok()?, tot_s.parse().ok()?))
}

pub fn format_savings_report(rep: &SavingsReport) -> String {
    let m = &rep.metrics;
    let mut out = String::new();
    out.push_str(&format!(
        "=== LibreDB Token Consumption & Savings Report [{}] ===\n",
        rep.scope_label
    ));
    out.push_str(&format!(
        "Analyzed scope: {} active day(s), {} conversation transcript(s) + live telemetry ledger\n\n",
        rep.active_days, rep.conversations_analyzed
    ));
    out.push_str(&format!(
        "{:<38} {:>8} {:>14} {:>14} {:>14} {:>8}\n",
        "Subsystem", "Calls", "Without DB", "With LibreDB", "Saved", "Saving"
    ));
    out.push_str(&format!("{}\n", "-".repeat(100)));

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
            "{:<38} {:>8} {:>10} tok {:>10} tok {:>10} tok {:>6.1}%\n",
            name, calls, base, em, sav, pct
        ));
    }

    out.push_str(&format!("{}\n", "-".repeat(100)));
    out.push_str(&format!(
        "{:<38} {:>8} {:>10} tok {:>10} tok {:>10} tok {:>6.1}% ({:.2}x)\n",
        "TOTAL",
        "-",
        rep.without_libredb_tokens,
        rep.with_libredb_tokens,
        rep.net_tokens_saved,
        rep.savings_percent,
        rep.compression_factor
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_ledger_and_transcript_merge_without_double_counting() {
        let tmp = env::temp_dir().join(format!("libredb_tel_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let brain_dir = tmp.join("brain");
        let cid_logs = brain_dir
            .join("cid-1234")
            .join(".system_generated")
            .join("logs");
        std::fs::create_dir_all(&cid_logs).unwrap();

        let transcript = cid_logs.join("transcript.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                r#"{"created_at":"2026-11-11T10:00:00Z","type":"USER_INPUT","content":"<SYSTEM_MESSAGE>\n=== PROJECT MEMORY CONTEXT (LibreDB .agents/memory.ldb) ===\nGit Telemetry: branch 'master' @ 833e9fd\n  * active_version = 1.1.0\n</SYSTEM_MESSAGE>"}"#, "\n",
                r#"{"created_at":"2026-11-11T10:01:00Z","type":"TOOL_RESPONSE","content":"=== SKELETON: src/main.rs (rust, L1-L2600, ~28931 -> ~496 tok, -98.3%) ===\nContracts:\n"}"#, "\n",
                r#"{"created_at":"2026-11-11T10:02:00Z","type":"TOOL_RESPONSE","content":"[Zero-Repeat Skeleton]: src/main.rs (unchanged in session, hash=abc, L1-L2600, 42 contracts)"}"#, "\n",
                r#"{"created_at":"2026-11-11T10:03:00Z","type":"USER_INPUT","content":"next turn deduplicated"}"#, "\n"
            ),
        )
        .unwrap();

        let tel_ldb = tmp.join("telemetry.ldb");
        record_event_at(
            &tel_ldb,
            "2026-11-11",
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
            project_filter: None,
            custom_brain_dir: Some(&brain_dir),
            custom_telemetry_ldb: Some(&tel_ldb),
        });
        assert_eq!(rep.conversations_analyzed, 1);
        assert_eq!(rep.metrics.skeleton_calls, 2);
        assert_eq!(rep.metrics.skeleton_zero_repeat_hits, 1);
        assert_eq!(rep.metrics.hook_dedup_skipped_turns, 1);
        assert!(rep.net_tokens_saved > 50_000);
        let formatted = format_savings_report(&rep);
        assert!(formatted.contains("TOTAL"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
