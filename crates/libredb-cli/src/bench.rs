//! Native built-in benchmarks and security/feature verification suites (`libredb bench`):
//! 1. Storage kernel concurrency & compaction microbenchmark (`--suite kernel`, default when no workspace/full flag),
//! 2. End-to-end 6-stage token-economy, latency, and `v4`-seal benchmark (`--suite full` or `--workspace <dir>`),
//!    reproducing the `C1..C6` methodology natively in compiled Rust without external scripts,
//! 3. Built-in `v1.1.1` security & feature verification routine (`--suite audit`), deterministically
//!    validating workspace `savings` authorization, DoS bounds, tentative edit promotion, exact Dalvik
//!    call-graph identity, atomic telemetry, 3-tier token accounting, `BM25` priority hydration,
//!    `racy-git` restored-timestamp detection, and `hmac-sha256:v4` trust seals (`A1..A9`).

use crate::hooks::{evaluate_pre_invocation_payload, evaluate_pre_tool_payload};
use crate::mcp::{handle_rpc_method, McpServerState};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// Standard UTF-8 `~4 bytes/token` metric matching `hooks.rs`, `tools.rs`, and historical
/// `AntiGraviton` / `LibreDB` head-to-head benchmark transcripts (`1:1` unit parity).
#[inline]
fn utf8_tokens(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        0
    } else {
        ((bytes.len() as u64) + 3) / 4
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelBenchReport {
    pub nodes: usize,
    pub threads: usize,
    pub prepare_ms: f64,
    pub prepare_nodes_per_sec: f64,
    pub commit_fsync_ms: f64,
    pub commit_nodes_per_sec: f64,
    pub concurrent_read_ms: f64,
    pub reads_per_sec: f64,
    pub compact_verify_ms: f64,
    pub bytes_before_compact: u64,
    pub bytes_after_compact: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskScoreRow {
    pub task_id: String,
    pub title: String,
    pub naive_without_db_tokens: u64,
    pub grep_without_db_tokens: u64,
    pub with_libredb_tokens: u64,
    pub libredb_ms: f64,
    pub verification_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullEconomyBenchReport {
    pub corpus_label: String,
    pub token_estimation_method: String,
    pub files_count: usize,
    pub total_lines: usize,
    pub total_bytes: u64,
    pub corpus_raw_tokens: u64,
    pub indexed_symbols: usize,
    pub indexed_call_edges: usize,
    pub cold_index_ms: f64,
    pub warm_index_ms: f64,
    pub tasks: Vec<TaskScoreRow>,
    pub total_naive_without_db_tokens: u64,
    pub total_grep_without_db_tokens: u64,
    pub total_with_libredb_tokens: u64,
    pub saved_vs_naive_tokens: u64,
    pub saved_vs_naive_percent: f64,
    pub saved_vs_grep_tokens: u64,
    pub saved_vs_grep_percent: f64,
    pub v4_seal_verified_after_bench: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckRow {
    pub check_id: String,
    pub title: String,
    pub passed: bool,
    pub elapsed_ms: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSuiteReport {
    pub suite: String,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub total_ms: f64,
    pub checks: Vec<AuditCheckRow>,
}

pub struct EconomyBenchOptions<'a> {
    pub workspace_source: Option<&'a Path>,
    pub path_filters: Vec<String>,
    pub ext_filters: Vec<String>,
    pub max_files: usize,
    pub as_json: bool,
}

struct TempSandboxGuard(PathBuf);

impl Drop for TempSandboxGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run_kernel_microbench(
    total_nodes: usize,
    threads: usize,
    as_json: bool,
) -> Result<KernelBenchReport, Box<dyn std::error::Error>> {
    let threads = threads.max(1);
    let tmp_path: PathBuf =
        env::temp_dir().join(format!("libredb_bench_{}.tmp.ldb", process::id()));
    let _ = fs::remove_file(&tmp_path);

    let db = Arc::new(LibreDb::open(&tmp_path)?);
    let per_thread = (total_nodes / threads).max(1);

    let t_prep = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let db_ref = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let mut batch = Vec::with_capacity(per_thread);
            for j in 0..per_thread {
                let idx = tid * per_thread + j;
                let text = format!(
                    "## Skill section #{idx}\nDeterministic architectural guidance for concurrent worker lane {tid} item {j} with repeatable compressible tokens."
                );
                let req = WriteRequest::new(NodeKind::SkillSection, text.into_bytes())
                    .with_key(format!("sec_{idx}"));
                batch.push(db_ref.prepare(req, tid).expect("prepare succeeded"));
            }
            batch
        }));
    }

    let mut all_prepared = Vec::with_capacity(per_thread * threads);
    for h in handles {
        all_prepared.extend(h.join().expect("worker joined"));
    }
    let prep_ms = t_prep.elapsed().as_secs_f64() * 1000.0;

    let t_commit = Instant::now();
    let ids = db.commit_batch(&all_prepared)?;
    let commit_ms = t_commit.elapsed().as_secs_f64() * 1000.0;

    let ids_arc = Arc::new(ids);
    let t_read = Instant::now();
    let mut r_handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let db_ref = Arc::clone(&db);
        let ids_ref = Arc::clone(&ids_arc);
        r_handles.push(thread::spawn(move || {
            let start = tid * per_thread;
            for &nid in &ids_ref[start..start + per_thread] {
                let rec = db_ref.get(nid).expect("read succeeded");
                assert!(!rec.payload.is_empty());
            }
        }));
    }
    for rh in r_handles {
        rh.join().expect("reader joined");
    }
    let read_ms = t_read.elapsed().as_secs_f64() * 1000.0;

    let t_comp = Instant::now();
    let comp = db.compact_with_gravity()?;
    let comp_ms = t_comp.elapsed().as_secs_f64() * 1000.0;

    let st = db.verify_integrity()?;
    drop(db);
    let _ = fs::remove_file(&tmp_path);

    let actual_n = ids_arc.len();
    let rep = KernelBenchReport {
        nodes: actual_n,
        threads,
        prepare_ms: round2(prep_ms),
        prepare_nodes_per_sec: (actual_n as f64 / (prep_ms / 1000.0).max(1e-6)).round(),
        commit_fsync_ms: round2(commit_ms),
        commit_nodes_per_sec: (actual_n as f64 / (commit_ms / 1000.0).max(1e-6)).round(),
        concurrent_read_ms: round2(read_ms),
        reads_per_sec: (actual_n as f64 / (read_ms / 1000.0).max(1e-6)).round(),
        compact_verify_ms: round2(comp_ms),
        bytes_before_compact: comp.bytes_before,
        bytes_after_compact: st.file_bytes,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        println!("=== LibreDB Kernel Benchmark ({actual_n} nodes across {threads} threads) ===");
        println!(
            "  Parallel prepare ({threads} lanes): {:>8.2} ms ({:.0} nodes/sec)",
            rep.prepare_ms, rep.prepare_nodes_per_sec
        );
        println!(
            "  Atomic batch commit + fsync:   {:>8.2} ms ({:.0} nodes/sec)",
            rep.commit_fsync_ms, rep.commit_nodes_per_sec
        );
        println!(
            "  Concurrent {threads}-thread reads:  {:>8.2} ms ({:.0} reads/sec)",
            rep.concurrent_read_ms, rep.reads_per_sec
        );
        println!(
            "  Gravity compaction + verify:   {:>8.2} ms ({} -> {} bytes)",
            rep.compact_verify_ms, rep.bytes_before_compact, rep.bytes_after_compact
        );
    }
    Ok(rep)
}

pub fn run_full_economy_bench(
    opts: &EconomyBenchOptions<'_>,
) -> Result<FullEconomyBenchReport, Box<dyn std::error::Error>> {
    // Isolate telemetry during benchmark execution so synthetic runs never skew real user savings!
    crate::telemetry::set_telemetry_suppressed(true);

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Stage benchmark sandbox outside `%TEMP%` / `/tmp` so `PreToolUse` and `PreInvocation`
    // (`is_protected_profile_dir`) exercise real production workspace hook paths identically.
    let sbx_base = crate::hooks::user_home_dir()
        .join(".cache")
        .join("libredb_bench");
    fs::create_dir_all(&sbx_base)?;
    let sbx_root = sbx_base.join(format!("run_{}_{}", process::id(), nonce));
    let _guard = TempSandboxGuard(sbx_root.clone());
    let ws_dir = sbx_root.join("workspace");
    fs::create_dir_all(ws_dir.join(".git/refs/heads"))?;
    fs::write(ws_dir.join(".git/HEAD"), "ref: refs/heads/master\n")?;
    fs::write(
        ws_dir.join(".git/refs/heads/master"),
        "1100000000000000000000000000000000000000\n",
    )?;

    let (corpus_label, staged_files) = if let Some(src_ws) = opts.workspace_source {
        let files = stage_real_workspace_files(
            src_ws,
            &ws_dir,
            &opts.path_filters,
            &opts.ext_filters,
            opts.max_files.max(1),
        )?;
        if files.is_empty() {
            return Err(format!(
                "No matching non-binary source files found under '{}'",
                src_ws.display()
            )
            .into());
        }
        (format!("workspace:{}", src_ws.display()), files)
    } else {
        let files = stage_synthetic_polyglot_corpus(&ws_dir)?;
        ("synthetic-polyglot-r8-di-corpus".to_owned(), files)
    };

    let mut total_lines = 0usize;
    let mut total_bytes = 0u64;
    let mut corpus_raw_tokens = 0u64;
    let mut largest_file: Option<(PathBuf, usize, u64)> = None;
    for fp in &staged_files {
        let bytes = fs::read(fp)?;
        let lines_cnt = bytes.iter().filter(|&&b| b == b'\n').count() + 1;
        let tok = utf8_tokens(&bytes);
        total_lines += lines_cnt;
        total_bytes += bytes.len() as u64;
        corpus_raw_tokens += tok;
        if largest_file.as_ref().map_or(true, |(_, l, _)| lines_cnt > *l) {
            largest_file = Some((fp.clone(), lines_cnt, tok));
        }
    }

    // Initialize isolated global `customizations.ldb` + seed multi-section skill for C6 + trust workspace
    let global_ldb = sbx_root.join("customizations_bench.ldb");
    {
        let gdb = Arc::new(LibreDb::open(&global_ldb)?);
        seed_bench_skill(&gdb)?;
        let proj_ldb = ws_dir.join(".agents").join("memory.ldb");
        fs::create_dir_all(proj_ldb.parent().unwrap())?;
        let pdb = LibreDb::open(&proj_ldb)?;
        crate::security::seal_workspace_memory(&gdb, &pdb, &ws_dir)?;
        let norm = crate::security::normalize_workspace_key(&ws_dir);
        gdb.put(
            WriteRequest::new(NodeKind::Config, b"allowed".to_vec())
                .with_key(format!("trust:allowed::{norm}"))
                .with_importance(240)
                .with_pinned(true),
        )?;
        let mut cog = libredb_cognitive::CognitiveEngine::open_db(Arc::clone(&gdb))?;
        cog.save_index_snapshot()?;
    }

    let mut mcp_state =
        McpServerState::new_with_workspace_root(None, Some(&global_ldb), Some(&ws_dir))?;
    let ws_str = ws_dir.to_string_lossy().to_string();

    // =========================================================================
    // C1: Structural Workspace Mapping (Cold + Warm `racy-git` Fast-Path)
    // =========================================================================
    let t_c1 = Instant::now();
    let c1_val = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "target": ws_str, "cwd": ws_str }
        }),
        &mut mcp_state,
    )?;
    let cold_index_ms = t_c1.elapsed().as_secs_f64() * 1000.0;
    let c1_text = extract_mcp_text(&c1_val);
    let c1_rep: libredb_cognitive::WorkspaceIndexReport = serde_json::from_str(&c1_text)?;
    let c1_tokens = utf8_tokens(c1_text.as_bytes());

    // Ensure >55 ms elapsed since staging so call #1 un-smudges any same-tick timestamps, then measure true warm fast-path:
    if cold_index_ms < 60.0 {
        thread::sleep(std::time::Duration::from_millis(60));
    }
    let _ = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "target": ws_str, "cwd": ws_str }
        }),
        &mut mcp_state,
    )?;
    let t_warm = Instant::now();
    let _ = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "target": ws_str, "cwd": ws_str }
        }),
        &mut mcp_state,
    )?;
    let warm_index_ms = t_warm.elapsed().as_secs_f64() * 1000.0;

    let c1_grep_tokens = (staged_files.len() as u64).saturating_mul(165).max(c1_tokens);

    // Discover top called symbols and medium/large callable symbols from the indexed graph for C2 & C3
    let (top_call_targets, slice_targets) = {
        let pdb = LibreDb::open(ws_dir.join(".agents/memory.ldb"))?;
        select_bench_targets(&pdb, &ws_dir)
    };

    // =========================================================================
    // C2: Call-Graph & Blast-Radius Impact (Up to 10 Top Hub Symbols)
    // =========================================================================
    let t_c2 = Instant::now();
    let mut c2_tokens = 0u64;
    let mut c2_callers_resolved = 0usize;
    for q_sym in &top_call_targets {
        let resp = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": { "action": "impact", "target": q_sym, "cwd": ws_str }
            }),
            &mut mcp_state,
        )?;
        let txt = extract_mcp_text(&resp);
        c2_tokens += utf8_tokens(txt.as_bytes());
        c2_callers_resolved += txt.lines().filter(|l| l.trim_start().starts_with("<- ")).count();
    }
    let c2_ms = t_c2.elapsed().as_secs_f64() * 1000.0;
    let c2_grep_tokens = ((top_call_targets.len() as u64)
        .saturating_mul((corpus_raw_tokens / 12).clamp(600, 9_800)))
    .max(c2_tokens);

    // =========================================================================
    // C3: Surgical FIM Slicing + Session Zero-Repeat Skeleton Deduplication
    // =========================================================================
    let t_c3 = Instant::now();
    let mut c3_tokens = 0u64;
    let mut c3_without_db_tokens = 0u64;
    for (file_p, sym_name, file_raw_tok) in &slice_targets {
        let f_str = file_p.to_string_lossy().to_string();
        let resp = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "fim",
                    "target": f_str,
                    "symbol": sym_name,
                    "pad": 0,
                    "cwd": ws_str
                }
            }),
            &mut mcp_state,
        )?;
        let txt = extract_mcp_text(&resp);
        c3_tokens += utf8_tokens(txt.as_bytes());
        c3_without_db_tokens += *file_raw_tok;
    }

    let mut zr_note = String::from("0 files");
    if let Some((ref big_p, _, big_raw_tok)) = largest_file {
        let big_s = big_p.to_string_lossy().to_string();
        let r1 = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": { "action": "skeleton", "target": big_s, "cid": "bench-cid", "cwd": ws_str }
            }),
            &mut mcp_state,
        )?;
        let r2 = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": { "action": "skeleton", "target": big_s, "cid": "bench-cid", "cwd": ws_str }
            }),
            &mut mcp_state,
        )?;
        let t1 = utf8_tokens(extract_mcp_text(&r1).as_bytes());
        let t2_txt = extract_mcp_text(&r2);
        let t2 = utf8_tokens(t2_txt.as_bytes());
        zr_note = format!(
            "{} sliced; Zero-Repeat {}->{}->{} tok (dedup={})",
            slice_targets.len(),
            big_raw_tok,
            t1,
            t2,
            t2_txt.contains("[Zero-Repeat Skeleton]")
        );
    }
    let c3_ms = t_c3.elapsed().as_secs_f64() * 1000.0;
    let c3_without_db_tokens = c3_without_db_tokens.max(c3_tokens);

    // =========================================================================
    // C4: Multi-Epoch Compaction & BM25-Assisted PreInvocation Hydration (<= 450 tok)
    // =========================================================================
    let mut facts_obj = serde_json::Map::new();
    facts_obj.insert(
        "early_anchor_fact_01".to_owned(),
        Value::String("Billing gate primeValidatorToken resides in Lci/j4;->checkLicense".to_owned()),
    );
    for idx in 2..=26 {
        facts_obj.insert(
            format!("bench_metric_fact_{idx:02}"),
            Value::String(format!(
                "Subsystem {idx:02} verified deterministic throughput across concurrent worker lanes with zero regressions."
            )),
        );
    }
    let mut decisions_obj = serde_json::Map::new();
    for idx in 1..=4 {
        decisions_obj.insert(
            format!("arch_decision_{idx:02}"),
            Value::String(format!(
                "Enforce strict cryptographic workspace isolation, bounded memory allocation, and zero-polling reactive execution across layer {idx}. {}",
                "Detailed rationale sentence preserved in database for full pulse recall. ".repeat(5)
            )),
        );
    }
    let _ = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_memorize",
            "arguments": {
                "cwd": ws_str,
                "facts": facts_obj,
                "decisions": decisions_obj,
                "snapshot": "Milestone v1.1.0 benchmark baseline ready."
            }
        }),
        &mut mcp_state,
    )?;

    // Drop `mcp_state` handle briefly or keep compatible readers while hooks run
    let transcript_path = sbx_root.join("transcript.jsonl");
    fs::write(
        &transcript_path,
        r#"{"created_at":"2026-11-11T12:00:00Z","type":"USER_INPUT","content":"start"}"#,
    )?;
    let t_c4 = Instant::now();
    let mut c4_tokens = 0u64;
    let mut c4_injections = 0usize;
    let mut c4_early_bm25_recalled = false;
    let mut c4_max_single_turn_tokens = 0u64;

    for step in 0..11 {
        if step > 0 && step % 2 == 0 {
            let mut f = fs::OpenOptions::new().append(true).open(&transcript_path)?;
            use std::io::Write;
            writeln!(
                f,
                r#"{{"created_at":"2026-11-11T12:0{step}:00Z","type":"USER_INPUT","content":"<CONTEXT_SUMMARY>compacted epoch {step}</CONTEXT_SUMMARY>"}}"#
            )?;
        }
        let hook_out = evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "bench-c4-cid",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_str],
                "prompt": "Check primeValidatorToken in Lci/j4 billing gate"
            }),
            Some(&global_ldb),
        )?;
        if let Some(arr) = hook_out.get("injectSteps").and_then(Value::as_array) {
            if !arr.is_empty() {
                c4_injections += 1;
                let msg = arr[0]
                    .pointer("/systemMessage/systemMessage")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let tok = utf8_tokens(msg.as_bytes());
                c4_tokens += tok;
                c4_max_single_turn_tokens = c4_max_single_turn_tokens.max(tok);
                if msg.contains("primeValidatorToken") {
                    c4_early_bm25_recalled = true;
                }
            }
        }
    }
    let c4_ms = t_c4.elapsed().as_secs_f64() * 1000.0;
    let c4_naive_tokens = (11u64 * 1_850).max(c4_tokens);

    // =========================================================================
    // C5: Live PreToolUse In-RAM `[Lstart-Lend]` Symbol Shift (10 Edits) + v4 Seal Check
    // =========================================================================
    let edit_target = slice_targets
        .first()
        .map(|(p, _, _)| p.clone())
        .or_else(|| staged_files.first().cloned())
        .unwrap();
    let edit_rel = edit_target
        .strip_prefix(&ws_dir)
        .unwrap_or(&edit_target)
        .to_string_lossy()
        .replace('\\', "/");
    let orig_disk = fs::read_to_string(&edit_target).unwrap_or_default();
    let edit_file_raw_tok = utf8_tokens(orig_disk.as_bytes()).max(200);
    // Record baseline last-symbol start line in `.agents/memory.ldb` BEFORE any PreToolUse edit:
    let baseline_sym_line: Option<(String, usize)> = {
        let pdb = LibreDb::open(ws_dir.join(".agents/memory.ldb"))?;
        let sym_prefix = format!("{edit_rel}::");
        let mut best: Option<(String, usize)> = None;
        for (ino, k_opt, _) in pdb.list_inodes(Some(NodeKind::Symbol), false) {
            let Some(k) = k_opt else { continue };
            if !k.starts_with(&sym_prefix) {
                continue;
            }
            if let Ok(rec) = pdb.get(ino.node_id) {
                let txt = String::from_utf8_lossy(&rec.payload);
                if let Some(after_l) = txt.split("[L").nth(1) {
                    if let Some(start_str) = after_l.split('-').next() {
                        if let Ok(st_ln) = start_str.parse::<usize>() {
                            if best.as_ref().map_or(true, |(_, prev)| st_ln > *prev) {
                                best = Some((k, st_ln));
                            }
                        }
                    }
                }
            }
        }
        best
    };
    let mut aborted_guard_ok = false;
    let mut shifted_ok = 0usize;
    let t_c5 = Instant::now();
    if let Some(first_nl) = orig_disk.find('\n') {
        let first_line = &orig_disk[..=first_nl];
        // Step 0: Verify aborted edit never leaves phantom line-shifts in live `Symbol` contracts!
        let abort_dec = evaluate_pre_tool_payload(
            &json!({
                "toolName": "edit_file",
                "toolArgs": {
                    "Path": edit_target.to_string_lossy().to_string(),
                    "Target": first_line,
                    "Replacement": format!("// aborted_edit_1\n// aborted_edit_2\n{first_line}")
                }
            }),
            Some(&global_ldb),
        );
        if abort_dec.get("decision").and_then(Value::as_str) == Some("allow") {
            let pdb = LibreDb::open(ws_dir.join(".agents/memory.ldb"))?;
            let _ = libredb_cognitive::reconcile_tentative_edits(&pdb, &ws_dir);
            aborted_guard_ok = if let Some((ref sym_k, base_start)) = baseline_sym_line {
                pdb.get_by_key(NodeKind::Symbol, sym_k)
                    .ok()
                    .map(|r| {
                        String::from_utf8_lossy(&r.payload).contains(&format!("[L{base_start}-"))
                    })
                    .unwrap_or(false)
            } else {
                true
            };
        }

        let mut cur_disk = orig_disk.clone();
        for edit_i in 1..=10 {
            let replacement = format!("// bench_shift_{edit_i}\n{first_line}");
            let dec = evaluate_pre_tool_payload(
                &json!({
                    "toolName": "edit_file",
                    "toolArgs": {
                        "Path": edit_target.to_string_lossy().to_string(),
                        "Target": first_line,
                        "Replacement": replacement
                    }
                }),
                Some(&global_ldb),
            );
            if dec.get("decision").and_then(Value::as_str) == Some("allow") {
                let disk_after_hook = fs::read_to_string(&edit_target).unwrap_or_default();
                let pre_unchanged = if let Some((ref sym_k, base_start)) = baseline_sym_line {
                    let pdb = LibreDb::open(ws_dir.join(".agents/memory.ldb"))?;
                    pdb.get_by_key(NodeKind::Symbol, sym_k)
                        .ok()
                        .map(|r| {
                            String::from_utf8_lossy(&r.payload)
                                .contains(&format!("[L{}-", base_start + (edit_i - 1)))
                        })
                        .unwrap_or(false)
                } else {
                    true
                };
                if disk_after_hook == cur_disk && pre_unchanged {
                    cur_disk = cur_disk.replacen(first_line, &replacement, 1);
                    fs::write(&edit_target, &cur_disk)?;
                    let pdb = LibreDb::open(ws_dir.join(".agents/memory.ldb"))?;
                    let _ = libredb_cognitive::reconcile_tentative_edits(&pdb, &ws_dir);
                    let db_shifted = if let Some((ref sym_k, base_start)) = baseline_sym_line {
                        pdb.get_by_key(NodeKind::Symbol, sym_k)
                            .ok()
                            .map(|r| {
                                String::from_utf8_lossy(&r.payload)
                                    .contains(&format!("[L{}-", base_start + edit_i))
                            })
                            .unwrap_or(false)
                    } else {
                        true
                    };
                    if db_shifted {
                        shifted_ok += 1;
                    }
                }
            }
        }
    }
    let c5_ms = t_c5.elapsed().as_secs_f64() * 1000.0;
    let c5_reread_without_db = edit_file_raw_tok.saturating_mul(10);

    // =========================================================================
    // C6: Progressive Skill Slicing & Zero-Repeat Federated `libredb_pulse`
    // =========================================================================
    let t_c6 = Instant::now();
    let p1 = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_pulse",
            "arguments": {
                "query": "Zero-Repeat Skeleton FIM code graph",
                "cwd": ws_str,
                "cid": "bench-c6-cid",
                "budget": 450
            }
        }),
        &mut mcp_state,
    )?;
    let p2 = handle_rpc_method(
        "tools/call",
        &json!({
            "name": "libredb_pulse",
            "arguments": {
                "query": "Zero-Repeat Skeleton FIM code graph",
                "cwd": ws_str,
                "cid": "bench-c6-cid",
                "budget": 450
            }
        }),
        &mut mcp_state,
    )?;
    let c6_ms = t_c6.elapsed().as_secs_f64() * 1000.0;
    let p1_tok = utf8_tokens(extract_mcp_text(&p1).as_bytes());
    let p2_tok = utf8_tokens(extract_mcp_text(&p2).as_bytes());
    let c6_tokens = p1_tok + p2_tok;
    let c6_without_db = 3_633u64 * 2;

    let v4_seal_ok = {
        let gdb = LibreDb::open(&global_ldb)?;
        crate::security::is_workspace_memory_trusted(Some(&gdb), &ws_dir)
    };
    drop(mcp_state);

    let tasks = vec![
        TaskScoreRow {
            task_id: "C1".to_owned(),
            title: format!("Structural workspace map ({} files)", staged_files.len()),
            naive_without_db_tokens: corpus_raw_tokens,
            grep_without_db_tokens: c1_grep_tokens,
            with_libredb_tokens: c1_tokens,
            libredb_ms: round2(c1_ms_display(cold_index_ms)),
            verification_note: format!(
                "{} syms, {} edges (warm {:.2} ms)",
                c1_rep.symbols_indexed, c1_rep.call_synapses_wired, warm_index_ms
            ),
        },
        TaskScoreRow {
            task_id: "C2".to_owned(),
            title: format!("Call-graph impact ({} hub queries)", top_call_targets.len()),
            naive_without_db_tokens: c2_grep_tokens.saturating_mul(2),
            grep_without_db_tokens: c2_grep_tokens,
            with_libredb_tokens: c2_tokens,
            libredb_ms: round2(c2_ms),
            verification_note: format!("{c2_callers_resolved} caller links surfaced"),
        },
        TaskScoreRow {
            task_id: "C3".to_owned(),
            title: format!("Surgical FIM slices ({} targets)", slice_targets.len()),
            naive_without_db_tokens: c3_without_db_tokens,
            grep_without_db_tokens: c3_without_db_tokens,
            with_libredb_tokens: c3_tokens,
            libredb_ms: round2(c3_ms),
            verification_note: zr_note,
        },
        TaskScoreRow {
            task_id: "C4".to_owned(),
            title: "Compaction + BM25 hydration (11 turns, 6 epochs)".to_owned(),
            naive_without_db_tokens: c4_naive_tokens,
            grep_without_db_tokens: 2_200u64.max(c4_tokens),
            with_libredb_tokens: c4_tokens,
            libredb_ms: round2(c4_ms),
            verification_note: format!(
                "{c4_injections}/11 injected, max {c4_max_single_turn_tokens} tok/turn, BM25={c4_early_bm25_recalled}"
            ),
        },
        TaskScoreRow {
            task_id: "C5".to_owned(),
            title: "Verified tentative symbol shift (10 edits)".to_owned(),
            naive_without_db_tokens: c5_reread_without_db,
            grep_without_db_tokens: c5_reread_without_db,
            with_libredb_tokens: 0,
            libredb_ms: round2(c5_ms),
            verification_note: format!(
                "abort_safe={aborted_guard_ok}, {shifted_ok}/10 ACID shifts, v4_seal={v4_seal_ok}"
            ),
        },
        TaskScoreRow {
            task_id: "C6".to_owned(),
            title: "Progressive skill slice + 2-turn federated pulse".to_owned(),
            naive_without_db_tokens: c6_without_db,
            grep_without_db_tokens: 3_633,
            with_libredb_tokens: c6_tokens,
            libredb_ms: round2(c6_ms),
            verification_note: format!("Turn1={p1_tok} tok -> Turn2={p2_tok} tok (Zero-Repeat)"),
        },
    ];

    let total_naive: u64 = tasks.iter().map(|r| r.naive_without_db_tokens).sum();
    let total_grep: u64 = tasks.iter().map(|r| r.grep_without_db_tokens).sum();
    let total_ldb: u64 = tasks.iter().map(|r| r.with_libredb_tokens).sum();
    let saved_naive = total_naive.saturating_sub(total_ldb);
    let saved_grep = total_grep.saturating_sub(total_ldb);
    let pct_naive = if total_naive > 0 {
        (saved_naive as f64 / total_naive as f64) * 100.0
    } else {
        0.0
    };
    let pct_grep = if total_grep > 0 {
        (saved_grep as f64 / total_grep as f64) * 100.0
    } else {
        0.0
    };

    let report = FullEconomyBenchReport {
        corpus_label,
        token_estimation_method:
            "observed_utf8_bytes_div_4_vs_modeled_counterfactuals".to_owned(),
        files_count: staged_files.len(),
        total_lines,
        total_bytes,
        corpus_raw_tokens,
        indexed_symbols: c1_rep.symbols_indexed,
        indexed_call_edges: c1_rep.call_synapses_wired,
        cold_index_ms: round2(cold_index_ms),
        warm_index_ms: round2(warm_index_ms),
        tasks,
        total_naive_without_db_tokens: total_naive,
        total_grep_without_db_tokens: total_grep,
        total_with_libredb_tokens: total_ldb,
        saved_vs_naive_tokens: saved_naive,
        saved_vs_naive_percent: round2(pct_naive),
        saved_vs_grep_tokens: saved_grep,
        saved_vs_grep_percent: round2(pct_grep),
        v4_seal_verified_after_bench: v4_seal_ok,
    };

    if opts.as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_economy_bench_table(&report);
    }
    Ok(report)
}

#[inline]
fn c1_ms_display(ms: f64) -> f64 {
    ms
}

fn print_economy_bench_table(rep: &FullEconomyBenchReport) {
    println!(
        "=== LibreDB Native Token-Economy & Graph Benchmark [{}] ===",
        rep.corpus_label
    );
    println!(
        "Corpus: {} files | {} lines | {} bytes (~{} raw UTF-8/4 tokens) | {} symbols | {} call/DI edges",
        rep.files_count,
        rep.total_lines,
        rep.total_bytes,
        rep.corpus_raw_tokens,
        rep.indexed_symbols,
        rep.indexed_call_edges
    );
    println!(
        "Accounting: LibreDB (~UTF-8 B/4 observed payload) vs. Est. Naive / Est. Grep modeled counterfactuals"
    );
    println!(
        "Index speed: {:.2} ms cold -> {:.2} ms warm cached | HMAC-SHA256 v4 seal intact: {}\n",
        rep.cold_index_ms, rep.warm_index_ms, rep.v4_seal_verified_after_bench
    );
    println!(
        "{:<4} {:<44} {:>12} {:>12} {:>14} {:>9}  {}",
        "ID", "Task", "Est. Naive", "Est. Grep", "LibreDB (~B/4)", "Time", "Verification"
    );
    println!("{}", "-".repeat(126));
    for r in &rep.tasks {
        println!(
            "{:<4} {:<44} {:>12} {:>12} {:>14} {:>7.2}ms  {}",
            r.task_id,
            r.title,
            r.naive_without_db_tokens,
            r.grep_without_db_tokens,
            r.with_libredb_tokens,
            r.libredb_ms,
            r.verification_note
        );
    }
    println!("{}", "-".repeat(126));
    println!(
        "{:<4} {:<44} {:>12} {:>12} {:>14}",
        "SUM",
        "Total Context Consumption",
        rep.total_naive_without_db_tokens,
        rep.total_grep_without_db_tokens,
        rep.total_with_libredb_tokens
    );
    println!(
        "Est. Avoided vs. Naive Full Reads: {} tokens (-{:.2}%)",
        rep.saved_vs_naive_tokens, rep.saved_vs_naive_percent
    );
    println!(
        "Est. Avoided vs. Manual Grep/Scan: {} tokens (-{:.2}%)",
        rep.saved_vs_grep_tokens, rep.saved_vs_grep_percent
    );
}

fn stage_real_workspace_files(
    src_root: &Path,
    dst_root: &Path,
    path_filters: &[String],
    ext_filters: &[String],
    max_files: usize,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    collect_real_candidates(src_root, src_root, path_filters, ext_filters, &mut candidates)?;
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    let mut staged = Vec::new();
    for (rel, src_p) in candidates.into_iter().take(max_files) {
        let bytes = fs::read(&src_p)?;
        let probe = bytes.len().min(2048);
        if bytes[..probe].contains(&0u8) {
            continue;
        }
        let dst_p = dst_root.join(&rel);
        if let Some(par) = dst_p.parent() {
            fs::create_dir_all(par)?;
        }
        fs::write(&dst_p, &bytes)?;
        staged.push(dst_p);
    }
    Ok(staged)
}

fn collect_real_candidates(
    root: &Path,
    curr: &Path,
    path_filters: &[String],
    ext_filters: &[String],
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(entries) = fs::read_dir(curr) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let low = name.to_ascii_lowercase();
        let p = entry.path();
        if ft.is_dir() {
            if matches!(
                low.as_str(),
                ".git" | ".agents" | "target" | "node_modules" | "dist" | "build" | ".venv" | "venv"
            ) {
                continue;
            }
            collect_real_candidates(root, &p, path_filters, ext_filters, out)?;
        } else if ft.is_file() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() == 0 || meta.len() > 4 * 1024 * 1024 {
                continue;
            }
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let rel_low = rel.to_ascii_lowercase();
            if !ext_filters.is_empty()
                && !ext_filters.iter().any(|e| {
                    let clean = e.trim_start_matches('.').to_ascii_lowercase();
                    rel_low.ends_with(&format!(".{clean}"))
                })
            {
                continue;
            }
            if !path_filters.is_empty()
                && !path_filters
                    .iter()
                    .any(|f| rel_low.contains(&f.replace('\\', "/").to_ascii_lowercase()))
            {
                continue;
            }
            out.push((rel, p));
        }
    }
    Ok(())
}

fn stage_synthetic_polyglot_corpus(dst_root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let smali_dir = dst_root.join("smali_classes3/ci");
    let rust_dir = dst_root.join("src");
    fs::create_dir_all(&smali_dir)?;
    fs::create_dir_all(&rust_dir)?;

    // Core R8 interface + base class
    let p0 = smali_dir.join("p0.smali");
    fs::write(
        &p0,
        ".class public interface abstract Lci/p0;\n.super Ljava/lang/Object;\n.method public abstract b(I)Z\n.end method\n",
    )?;
    out.push(p0);

    let p1 = smali_dir.join("p1.smali");
    let mut p1_body = String::from(
        ".class public Lci/p1;\n.super Ljava/lang/Object;\n.implements Lci/p0;\n.method public final l(Landroid/content/Context;)Z\n    .registers 4\n",
    );
    for r in 0..45 {
        p1_body.push_str(&format!("    const/16 v0, 0x{r:x}\n"));
    }
    p1_body.push_str("    return v0\n.end method\n.method public b(I)Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method\n");
    fs::write(&p1, p1_body)?;
    out.push(p1);

    // 18 multi-method R8 Smali feature classes invoking `Lci/p1;->l(` and `Lci/p0;->b(`
    for idx in 1..=18 {
        let fp = smali_dir.join(format!("j{idx}.smali"));
        let mut s = format!(
            ".class public final Lci/j{idx};\n.super Lci/p1;\n.method public final verifyGate{idx}(Landroid/content/Context;)Z\n    .registers 5\n    invoke-virtual {{p0, p1}}, Lci/j{idx};->l(Landroid/content/Context;)Z\n    invoke-interface {{p0, v0}}, Lci/p0;->b(I)Z\n"
        );
        for ln in 0..34 {
            s.push_str(&format!("    nop # gate check {ln} in class j{idx}\n"));
        }
        s.push_str("    move-result v1\n    return v1\n.end method\n");
        for helper in 1..=5 {
            s.push_str(&format!(
                ".method private helperStage{helper}_{idx}(I)I\n    .registers 3\n"
            ));
            for ln in 0..38 {
                s.push_str(&format!(
                    "    add-int/lit8 p1, p1, 0x1 # auxiliary bytecode line {ln}\n"
                ));
            }
            s.push_str("    return p1\n.end method\n");
        }
        fs::write(&fp, s)?;
        out.push(fp);
    }

    // 4 multi-function Rust modules with cross-module calls
    let lib_rs = rust_dir.join("engine.rs");
    let mut eng = String::from(
        "pub struct SealVerifier;\nimpl SealVerifier {\n    pub fn check_digest(buf: &[u8]) -> bool {\n",
    );
    for ln in 0..38 {
        eng.push_str(&format!("        let _step_{ln} = buf.len().wrapping_add({ln});\n"));
    }
    eng.push_str("        !buf.is_empty()\n    }\n");
    for aux in 1..=4 {
        eng.push_str(&format!("    pub fn audit_slot_{aux}(slot: usize) -> usize {{\n"));
        for ln in 0..36 {
            eng.push_str(&format!("        let _v_{ln} = slot.wrapping_mul({ln} + 1);\n"));
        }
        eng.push_str("        slot\n    }\n");
    }
    eng.push_str("}\n");
    fs::write(&lib_rs, eng)?;
    out.push(lib_rs);

    for idx in 1..=3 {
        let rp = rust_dir.join(format!("worker_{idx}.rs"));
        let mut body = format!(
            "use crate::engine::SealVerifier;\npub fn run_worker_{idx}(payload: &[u8]) -> bool {{\n    let ok = SealVerifier::check_digest(payload);\n"
        );
        for ln in 0..36 {
            body.push_str(&format!("    let _acc_{ln} = payload.len() + {ln};\n"));
        }
        body.push_str("    ok\n}\n");
        for aux in 1..=4 {
            body.push_str(&format!("pub fn stage_helper_{idx}_{aux}(n: usize) -> usize {{\n"));
            for ln in 0..36 {
                body.push_str(&format!("    let _s_{ln} = n.wrapping_add({ln});\n"));
            }
            body.push_str("    n\n}\n");
        }
        fs::write(&rp, body)?;
        out.push(rp);
    }

    Ok(out)
}

fn select_bench_targets(
    pdb: &LibreDb,
    ws_dir: &Path,
) -> (Vec<String>, Vec<(PathBuf, String, u64)>) {
    let inodes = pdb.list_inodes(Some(NodeKind::Symbol), false);
    let mut reverse_fan_in: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (_, _, syns) in &inodes {
        for s in syns {
            if matches!(s.kind, EdgeKind::Calls | EdgeKind::DependsOn) {
                *reverse_fan_in.entry(s.target_id).or_insert(0) += 1;
            }
        }
    }

    let mut ranked_hubs: Vec<(usize, String)> = Vec::new();
    let mut seen_queries: HashSet<String> = HashSet::new();
    for (ino, k_opt, _) in &inodes {
        let Some(ref fk) = k_opt else { continue };
        let Some((_, sym_part)) = fk.split_once("::") else { continue };
        let clean_q = sym_part.split('@').next().unwrap_or(sym_part).to_owned();
        let fan = reverse_fan_in.get(&ino.node_id).copied().unwrap_or(0);
        if fan > 0 && seen_queries.insert(clean_q.clone()) {
            ranked_hubs.push((fan, clean_q));
        }
    }
    ranked_hubs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut top_queries: Vec<String> = ranked_hubs.into_iter().take(10).map(|(_, q)| q).collect();
    if top_queries.is_empty() {
        for (_, k_opt, _) in inodes.iter().take(5) {
            if let Some(ref fk) = k_opt {
                if let Some((_, sp)) = fk.split_once("::") {
                    top_queries.push(sp.split('@').next().unwrap_or(sp).to_owned());
                }
            }
        }
    }

    // Select up to 20 distinct files with callable methods in `[30..=180]` lines (`1:1` parity with
    // the 250-Smali APK reference benchmark, falling back to `[8..=180]` on small repos).
    let mut slice_candidates: Vec<(usize, PathBuf, String, u64)> = Vec::new();
    let mut seen_files: HashSet<String> = HashSet::new();
    for min_span in [30usize, 8usize] {
        for (_, k_opt, _) in pdb.list_inodes(Some(NodeKind::WorkingSet), false) {
            let Some(k) = k_opt else { continue };
            let Some(rel) = k.strip_prefix("skeleton::") else { continue };
            if seen_files.contains(rel) {
                continue;
            }
            let Ok(rec) = pdb.get_by_key(NodeKind::WorkingSet, &k) else { continue };
            let Ok(skel) = serde_json::from_slice::<libredb_cognitive::FileSkeleton>(&rec.payload) else {
                continue;
            };
            if let Some(best_sym) = skel
                .symbols
                .iter()
                .filter(|s| {
                    let span = s.end_line.saturating_sub(s.start_line) + 1;
                    span >= min_span
                        && span <= 180
                        && !matches!(
                            s.kind.as_str(),
                            "class" | "struct" | "module" | "interface" | "trait" | "impl"
                        )
                        && !matches!(s.name.as_str(), "<init>" | "<clinit>")
                })
                .max_by_key(|s| s.end_line.saturating_sub(s.start_line))
            {
                let full_p = ws_dir.join(rel);
                let raw_utf8_tok = fs::read(&full_p)
                    .map(|b| utf8_tokens(&b))
                    .unwrap_or(skel.raw_tokens as u64);
                if seen_files.insert(rel.to_owned()) {
                    let span = best_sym.end_line.saturating_sub(best_sym.start_line) + 1;
                    slice_candidates.push((
                        span,
                        full_p,
                        best_sym.qualified_name(),
                        raw_utf8_tok,
                    ));
                }
            }
        }
        if slice_candidates.len() >= 20 {
            break;
        }
    }
    slice_candidates.sort_by(|a, b| b.0.cmp(&a.0));
    let slice_targets: Vec<(PathBuf, String, u64)> = slice_candidates
        .into_iter()
        .take(20)
        .map(|(_, p, s, rt)| (p, s, rt))
        .collect();

    (top_queries, slice_targets)
}

fn seed_bench_skill(gdb: &LibreDb) -> Result<(), Box<dyn std::error::Error>> {
    let s1 = "[libredb > MCP Code Graph]\n## MCP Code Graph\nUse libredb_code with Zero-Repeat Skeleton, surgical FIM code slices, and compact call-graph impact.";
    let s2 = "[libredb > Security Vault]\n## Security Vault\nAll tokens are encrypted via OS DPAPI or RFC 8439 ChaCha20-Poly1305 AEAD. ".repeat(18);
    let id_root = gdb.put(
        WriteRequest::new(
            NodeKind::Skill,
            b"[Skill: libredb | plugin=libredb]\nPrimary cognitive memory and code graph".to_vec(),
        )
        .with_key("libredb")
        .with_importance(210),
    )?;
    let id_s1 = gdb.put(
        WriteRequest::new(NodeKind::SkillSection, s1.as_bytes().to_vec())
            .with_key("libredb::MCP Code Graph")
            .with_importance(200),
    )?;
    let id_s2 = gdb.put(
        WriteRequest::new(NodeKind::SkillSection, s2.into_bytes())
            .with_key("libredb::Security Vault")
            .with_importance(190),
    )?;
    gdb.link_batch(&[
        (id_root, EdgeKind::HasSection, id_s1, 240),
        (id_root, EdgeKind::HasSection, id_s2, 240),
    ])?;
    Ok(())
}

fn extract_mcp_text(val: &Value) -> String {
    val.pointer("/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

#[inline]
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Executes the built-in `v1.1.1` security & feature verification routine (`libredb bench --suite audit`).
/// Validates all 9 core invariants (`A1..A9`) in an isolated sandbox and returns `Err` on any failure.
pub fn run_feature_and_security_audit(
    as_json: bool,
) -> Result<AuditSuiteReport, Box<dyn std::error::Error>> {
    crate::telemetry::set_telemetry_suppressed(true);
    let suite_start = Instant::now();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let sbx_base = crate::hooks::user_home_dir()
        .join(".cache")
        .join("libredb_audit");
    fs::create_dir_all(&sbx_base)?;
    let sbx_root = sbx_base.join(format!("audit_{}_{}", process::id(), nonce));
    let _guard = TempSandboxGuard(sbx_root.clone());

    let mut checks: Vec<AuditCheckRow> = Vec::with_capacity(9);

    let mut run_check = |id: &str,
                         title: &str,
                         f: &mut dyn FnMut() -> Result<String, String>| {
        let t0 = Instant::now();
        match f() {
            Ok(detail) => checks.push(AuditCheckRow {
                check_id: id.to_owned(),
                title: title.to_owned(),
                passed: true,
                elapsed_ms: round2(t0.elapsed().as_secs_f64() * 1000.0),
                detail,
            }),
            Err(err) => checks.push(AuditCheckRow {
                check_id: id.to_owned(),
                title: title.to_owned(),
                passed: false,
                elapsed_ms: round2(t0.elapsed().as_secs_f64() * 1000.0),
                detail: format!("FAIL: {err}"),
            }),
        }
    };

    let global_ldb = sbx_root.join("customizations.ldb");
    let ws_a = sbx_root.join("ws_alpha");
    let ws_b = sbx_root.join("ws_beta");
    fs::create_dir_all(ws_a.join(".agents"))?;
    fs::create_dir_all(ws_a.join(".git"))?;
    fs::create_dir_all(ws_b.join(".agents"))?;
    fs::create_dir_all(ws_b.join(".git"))?;
    {
        let gdb = LibreDb::open(&global_ldb)?;
        seed_bench_skill(&gdb)?;
        let pdb_a = LibreDb::open(ws_a.join(".agents/memory.ldb"))?;
        crate::security::seal_workspace_memory(&gdb, &pdb_a, &ws_a)?;
    }

    // A1: MCP `savings` workspace authorization & boundary isolation
    run_check(
        "A1",
        "MCP savings workspace authorization & isolation",
        &mut || {
            let ws_a_ldb = ws_a.join(".agents/memory.ldb");
            let mut mcp_a = McpServerState::new_with_workspace_root(
                Some(&ws_a_ldb),
                Some(&global_ldb),
                Some(&ws_a),
            )?;
            let cross_res = handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "savings",
                        "cwd": ws_b.to_string_lossy().to_string()
                    }
                }),
                &mut mcp_a,
            );
            if cross_res.is_ok() {
                return Err("Cross-workspace savings call for ws_beta was not rejected".to_owned());
            }
            let wildcard_res = handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "savings",
                        "cwd": "*"
                    }
                }),
                &mut mcp_a,
            );
            if wildcard_res.is_ok() {
                return Err("Global wildcard cwd='*' savings call was not rejected".to_owned());
            }
            let own_res = handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "savings",
                        "format": "json"
                    }
                }),
                &mut mcp_a,
            )?;
            let parsed: Value = serde_json::from_str(&extract_mcp_text(&own_res))
                .map_err(|e| format!("invalid JSON: {e}"))?;
            let scope = parsed
                .get("scope_label")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !scope.starts_with("project:") || !scope.contains("ws_alpha") {
                return Err(format!(
                    "Omitted cwd did not stay scoped to ws_alpha; got scope_label='{scope}'"
                ));
            }
            Ok("ws_beta denied, cwd='*' denied, omitted cwd scoped strictly to ws_alpha".to_owned())
        },
    );

    // A2: `savings` resource-exhaustion bounds (`days` cap + streaming `<= 8 MiB` JSONL reader)
    run_check(
        "A2",
        "Savings DoS bounds (days cap & 8 MiB streaming JSONL)",
        &mut || {
            let ws_a_ldb = ws_a.join(".agents/memory.ldb");
            let mut mcp_a = McpServerState::new_with_workspace_root(
                Some(&ws_a_ldb),
                Some(&global_ldb),
                Some(&ws_a),
            )?;
            let huge_days = handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "savings",
                        "days": 1_000_000_000u64
                    }
                }),
                &mut mcp_a,
            );
            if huge_days.is_ok() {
                return Err("days=1_000_000_000 was not rejected".to_owned());
            }

            let over_len = crate::telemetry::MAX_TRANSCRIPT_LINE_BYTES + 512 * 1024;
            let mut stream_bytes = vec![b'x'; over_len];
            stream_bytes.push(b'\n');
            let valid_tail = b"{\"type\":\"USER_INPUT\",\"content\":\"ok\"}\n";
            stream_bytes.extend_from_slice(valid_tail);

            let mut reader = std::io::BufReader::with_capacity(64 * 1024, &stream_bytes[..]);
            let mut line_buf = Vec::new();
            let first = crate::telemetry::read_bounded_jsonl_line(
                &mut reader,
                &mut line_buf,
                crate::telemetry::MAX_TRANSCRIPT_LINE_BYTES,
            )
            .map_err(|e| e.to_string())?;
            if !matches!(first, crate::telemetry::BoundedLineStatus::OversizedSkipped(_))
                || !line_buf.is_empty()
            {
                return Err(format!("Oversized JSONL line was not drained safely: {first:?}"));
            }
            let second = crate::telemetry::read_bounded_jsonl_line(
                &mut reader,
                &mut line_buf,
                crate::telemetry::MAX_TRANSCRIPT_LINE_BYTES,
            )
            .map_err(|e| e.to_string())?;
            if !matches!(second, crate::telemetry::BoundedLineStatus::Line(_))
                || !std::str::from_utf8(&line_buf)
                    .unwrap_or("")
                    .contains("USER_INPUT")
            {
                return Err("Valid JSONL line after oversized line was not recovered".to_owned());
            }
            Ok(format!(
                "days>{} rejected; {:.1} MiB newline-less line drained in-place",
                crate::telemetry::MAX_SAVINGS_DAYS,
                over_len as f64 / (1024.0 * 1024.0)
            ))
        },
    );

    // A3: Tentative `PreToolUse` edit staging & single-`DeltaEnvelope` ACID promotion
    run_check(
        "A3",
        "Tentative PreToolUse staging & atomic ACID promotion",
        &mut || {
            let ws_t = sbx_root.join("ws_tentative");
            fs::create_dir_all(ws_t.join(".agents")).map_err(|e| e.to_string())?;
            fs::create_dir_all(ws_t.join(".git")).map_err(|e| e.to_string())?;
            fs::create_dir_all(ws_t.join("src")).map_err(|e| e.to_string())?;
            let src_p = ws_t.join("src/lib.rs");
            let init_src = "pub fn alpha() -> u32 {\n    1\n}\n\npub fn omega() -> u32 {\n    alpha() + 1\n}\n";
            fs::write(&src_p, init_src).map_err(|e| e.to_string())?;
            let ldb_t = ws_t.join(".agents/memory.ldb");
            {
                let gdb = LibreDb::open(&global_ldb).map_err(|e| e.to_string())?;
                let pdb = LibreDb::open(&ldb_t).map_err(|e| e.to_string())?;
                libredb_cognitive::index_workspace(&pdb, &ws_t, true).map_err(|e| e.to_string())?;
                crate::security::seal_workspace_memory(&gdb, &pdb, &ws_t)?;
            }

            // 1. Aborted IDE write: PreToolUse runs, disk stays untouched, immediate query keeps [L5-L7].
            let abort_payload = json!({
                "toolName": "edit_file",
                "toolArgs": {
                    "Path": src_p.to_string_lossy().to_string(),
                    "Target": "pub fn alpha() -> u32 {\n    1\n}",
                    "Replacement": "pub fn alpha() -> u32 {\n    let _a = 1;\n    let _b = 2;\n    1\n}"
                }
            });
            let _ = evaluate_pre_tool_payload(&abort_payload, Some(&global_ldb));
            {
                let pdb = LibreDb::open(&ldb_t).map_err(|e| e.to_string())?;
                let pre_sym = pdb
                    .get_by_key(NodeKind::Symbol, "src/lib.rs::omega")
                    .map_err(|e| e.to_string())?;
                if !String::from_utf8_lossy(&pre_sym.payload).contains("[L5-L7]") {
                    return Err("Live Symbol mutated BEFORE disk write!".to_owned());
                }
                let imp =
                    libredb_cognitive::query_symbol_impact(&pdb, "omega").map_err(|e| e.to_string())?;
                if imp.is_empty() || !imp[0].contract.contains("[L5-L7]") {
                    return Err(format!(
                        "Aborted edit shifted omega contract: {:?}",
                        imp.first().map(|r| &r.contract)
                    ));
                }
            }

            // 2. Verified IDE write: PreToolUse -> fs::write -> 1-commit_seq ACID promotion to [L7-L9].
            let _ = evaluate_pre_tool_payload(&abort_payload, Some(&global_ldb));
            let post_src = "pub fn alpha() -> u32 {\n    let _a = 1;\n    let _b = 2;\n    1\n}\n\npub fn omega() -> u32 {\n    alpha() + 1\n}\n";
            fs::write(&src_p, post_src).map_err(|e| e.to_string())?;
            let pdb = LibreDb::open(&ldb_t).map_err(|e| e.to_string())?;
            let seq_before = pdb.stats().map_err(|e| e.to_string())?.commit_seq;
            let (promoted, _) =
                libredb_cognitive::reconcile_tentative_edits(&pdb, &ws_t).map_err(|e| e.to_string())?;
            let seq_after = pdb.stats().map_err(|e| e.to_string())?.commit_seq;
            let imp2 =
                libredb_cognitive::query_symbol_impact(&pdb, "omega").map_err(|e| e.to_string())?;
            if promoted != 1
                || seq_after != seq_before + 1
                || imp2.is_empty()
                || !imp2[0].contract.contains("[L7-L9]")
            {
                return Err(format!(
                    "Expected promoted=1 in 1 commit_seq to [L7-L9]; got promoted={promoted}, seq {seq_before}->{seq_after}, contract={:?}",
                    imp2.first().map(|r| &r.contract)
                ));
            }
            Ok("aborted write=0 phantom shift; verified write promoted in 1 ACID commit".to_owned())
        },
    );

    // A4: Exact Dalvik/Smali package & method-descriptor call-graph precision & recall
    run_check(
        "A4",
        "Dalvik/Smali exact package & overload call-graph identity",
        &mut || {
            let ws_s = sbx_root.join("ws_smali");
            fs::create_dir_all(ws_s.join("smali/com/alpha"))
                .and_then(|_| fs::create_dir_all(ws_s.join("smali/com/beta")))
                .and_then(|_| fs::create_dir_all(ws_s.join("smali/com/app")))
                .and_then(|_| fs::create_dir_all(ws_s.join(".agents")))
                .map_err(|e| e.to_string())?;
            fs::write(
                ws_s.join("smali/com/alpha/Base.smali"),
                ".class public Lcom/alpha/Base;\n.super Ljava/lang/Object;\n.method public baseGate()Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method\n",
            )
            .map_err(|e| e.to_string())?;
            fs::write(
                ws_s.join("smali/com/alpha/p0.smali"),
                ".class public Lcom/alpha/p0;\n.super Lcom/alpha/Base;\n.method public b(I)Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method\n.method public b(Ljava/lang/String;)V\n    .registers 2\n    return-void\n.end method\n",
            )
            .map_err(|e| e.to_string())?;
            fs::write(
                ws_s.join("smali/com/beta/p0.smali"),
                ".class public Lcom/beta/p0;\n.super Ljava/lang/Object;\n.method public b(I)Z\n    .registers 2\n    const/4 v0, 0x0\n    return v0\n.end method\n",
            )
            .map_err(|e| e.to_string())?;
            fs::write(
                ws_s.join("smali/com/app/Caller.smali"),
                ".class public final Lcom/app/Caller;\n.super Ljava/lang/Object;\n.method public static run(Lcom/alpha/p0;)Z\n    .registers 3\n    const/4 v0, 0x7\n    invoke-virtual {p0, v0}, Lcom/alpha/p0;->b(I)Z\n    invoke-virtual {p0}, Lcom/alpha/p0;->baseGate()Z\n    move-result v1\n    return v1\n.end method\n",
            )
            .map_err(|e| e.to_string())?;

            let pdb = LibreDb::open(ws_s.join(".agents/memory.ldb")).map_err(|e| e.to_string())?;
            libredb_cognitive::index_workspace(&pdb, &ws_s, true).map_err(|e| e.to_string())?;

            let alpha_i = libredb_cognitive::query_symbol_impact(&pdb, "Lcom/alpha/p0;->b(I)Z")
                .map_err(|e| e.to_string())?;
            let alpha_s = libredb_cognitive::query_symbol_impact(
                &pdb,
                "Lcom/alpha/p0;->b(Ljava/lang/String;)V",
            )
            .map_err(|e| e.to_string())?;
            let beta_i = libredb_cognitive::query_symbol_impact(&pdb, "Lcom/beta/p0;->b(I)Z")
                .map_err(|e| e.to_string())?;
            let base_g = libredb_cognitive::query_symbol_impact(&pdb, "Lcom/alpha/Base;->baseGate()Z")
                .map_err(|e| e.to_string())?;

            let c_alpha_i: usize = alpha_i.iter().map(|r| r.total_callers).sum();
            let c_alpha_s: usize = alpha_s.iter().map(|r| r.total_callers).sum();
            let c_beta_i: usize = beta_i.iter().map(|r| r.total_callers).sum();
            let c_base_g: usize = base_g.iter().map(|r| r.total_callers).sum();

            if c_alpha_i != 1 || c_alpha_s != 0 || c_beta_i != 0 || c_base_g != 1 {
                return Err(format!(
                    "Precision/recall mismatch: alpha_b(I)={c_alpha_i}, alpha_b(Str)={c_alpha_s}, beta_b(I)={c_beta_i}, baseGate={c_base_g}"
                ));
            }
            Ok("precision=100%, recall=100% (0 cross-pkg or overload collisions)".to_owned())
        },
    );

    // A5: Concurrent `telemetry.ldb` `transact_key` integrity (8 threads x 25 increments = 200)
    run_check(
        "A5",
        "Concurrent telemetry.ldb transact_key update integrity",
        &mut || {
            let tel_ldb = sbx_root.join("telemetry_concurrent.ldb");
            let mut handles = Vec::with_capacity(8);
            for _ in 0..8 {
                let p = tel_ldb.clone();
                let ws = ws_a.clone();
                handles.push(thread::spawn(move || {
                    for _ in 0..25 {
                        crate::telemetry::record_workspace_event_at(
                            &p,
                            "2026-11-11",
                            Some(&ws),
                            crate::telemetry::TelemetryEvent::Fim {
                                baseline_tokens: 100,
                                emitted_tokens: 15,
                            },
                        );
                    }
                }));
            }
            for h in handles {
                h.join().map_err(|_| "worker panicked".to_owned())?;
            }
            let rep_ws = crate::telemetry::build_savings_report(
                &crate::telemetry::SavingsQueryOptions {
                    today_only: false,
                    days: None,
                    cid_filter: None,
                    project_filter: Some(&ws_a),
                    custom_brain_dir: Some(&sbx_root.join("empty_brain")),
                    custom_telemetry_ldb: Some(&tel_ldb),
                },
            );
            let db = LibreDb::open(&tel_ldb).map_err(|e| e.to_string())?;
            db.verify_integrity().map_err(|e| e.to_string())?;
            if rep_ws.ledger_only_metrics.fim_calls != 200
                || rep_ws.ledger_only_metrics.fim_baseline_tokens != 20_000
                || rep_ws.ledger_only_metrics.fim_emitted_tokens != 3_000
            {
                return Err(format!(
                    "Lost updates detected: fim_calls={} (expected 200)",
                    rep_ws.ledger_only_metrics.fim_calls
                ));
            }
            Ok("200/200 concurrent increments preserved, 0 lost updates".to_owned())
        },
    );

    // A6: 3-tier token reporting & `PLANNER_RESPONSE` provider usage attribution
    run_check(
        "A6",
        "3-tier token accounting & provider usage extraction",
        &mut || {
            let brain_dir = sbx_root.join("brain_a6");
            let logs_dir = brain_dir
                .join("cid-a6")
                .join(".system_generated")
                .join("logs");
            fs::create_dir_all(&logs_dir).map_err(|e| e.to_string())?;
            let tel_ldb = sbx_root.join("telemetry_a6.ldb");
            crate::telemetry::record_workspace_event_at(
                &tel_ldb,
                "2026-11-11",
                Some(&ws_a),
                crate::telemetry::TelemetryEvent::SkillSlice {
                    baseline_tokens: 900,
                    emitted_tokens: 120,
                },
            );
            let ws_slash = ws_a.to_string_lossy().replace('\\', "/");
            let jsonl = format!(
                "{{\"created_at\":\"2026-11-11T10:00:00Z\",\"type\":\"PLANNER_RESPONSE\",\"usageMetadata\":{{\"promptTokenCount\":4200,\"cachedContentTokenCount\":3100,\"candidatesTokenCount\":380}},\"tool_calls\":[{{\"name\":\"mcp_libredb_libredb-mcp_libredb_code\",\"arguments\":{{\"action\":\"fim\",\"cwd\":\"{ws_slash}\"}}}}]}}\n\
                 {{\"created_at\":\"2026-11-11T10:00:01Z\",\"type\":\"TOOL_RESPONSE\",\"content\":\"=== FIM SLICE: src/a.rs :: x [L10-L20 of L200] ===\\nfn x() {{}}\"}}\n"
            );
            fs::write(logs_dir.join("transcript.jsonl"), jsonl).map_err(|e| e.to_string())?;

            let rep = crate::telemetry::build_savings_report(
                &crate::telemetry::SavingsQueryOptions {
                    today_only: false,
                    days: None,
                    cid_filter: None,
                    project_filter: Some(&ws_a),
                    custom_brain_dir: Some(&brain_dir),
                    custom_telemetry_ldb: Some(&tel_ldb),
                },
            );
            if rep.ledger_only_metrics.skill_slice_calls != 1
                || rep.transcript_only_metrics.fim_calls != 1
                || rep.provider_reported_usage.planner_steps != 1
                || rep.provider_reported_usage.input_tokens != 4_200
                || rep.provider_reported_usage.cache_read_tokens != 3_100
                || rep.provider_reported_usage.output_tokens != 380
            {
                return Err(format!(
                    "Unexpected 3-tier report: ledger={:?}, transcript={:?}, provider={:?}",
                    rep.ledger_only_metrics, rep.transcript_only_metrics, rep.provider_reported_usage
                ));
            }
            Ok("ledger_only, transcript_only, max_merge & provider usage separated".to_owned())
        },
    );

    // A7: Priority-budgeted `BM25` `Decision` & `Fact` hydration under `> 10 KB` saturation
    run_check(
        "A7",
        "Priority-budgeted BM25 Decision & Fact hydration (<= 1,800 B)",
        &mut || {
            let ws_h = sbx_root.join("ws_hydrate");
            fs::create_dir_all(ws_h.join(".agents")).map_err(|e| e.to_string())?;
            let pdb = Arc::new(
                LibreDb::open(ws_h.join(".agents/memory.ldb")).map_err(|e| e.to_string())?,
            );
            for t in 1..=8 {
                pdb.put(
                    WriteRequest::new(
                        NodeKind::Task,
                        format!(
                            "[Task: task_{t}] | in_progress | high | Detailed task item #{t} with operational notes and padding"
                        )
                        .into_bytes(),
                    )
                    .with_key(format!("task_{t}")),
                )
                .map_err(|e| e.to_string())?;
            }
            pdb.put(
                WriteRequest::new(
                    NodeKind::Fact,
                    b"anchor_fact_quorum = Raft lease quorum uses monotonic hardware ticks".to_vec(),
                )
                .with_key("anchor_fact_quorum"),
            )
            .map_err(|e| e.to_string())?;
            for i in 2..=30 {
                pdb.put(
                    WriteRequest::new(
                        NodeKind::Fact,
                        format!(
                            "filler_fact_{i:02} = Verbose historical observation #{i} padding out naive byte limits across turns"
                        )
                        .into_bytes(),
                    )
                    .with_key(format!("filler_fact_{i:02}")),
                )
                .map_err(|e| e.to_string())?;
            }
            pdb.put(
                WriteRequest::new(
                    NodeKind::Decision,
                    b"[Decision: anchor_dec_quorum] Enforce monotonic Raft lease quorum ticks across failover epochs".to_vec(),
                )
                .with_key("anchor_dec_quorum"),
            )
            .map_err(|e| e.to_string())?;
            for d in 2..=8 {
                pdb.put(
                    WriteRequest::new(
                        NodeKind::Decision,
                        format!(
                            "[Decision: filler_dec_{d}] Long historical narrative #{d}: {}",
                            "subsystem migration details and rationale ".repeat(10)
                        )
                        .into_bytes(),
                    )
                    .with_key(format!("filler_dec_{d}")),
                )
                .map_err(|e| e.to_string())?;
            }
            let mut cog =
                libredb_cognitive::CognitiveEngine::open_db(Arc::clone(&pdb)).map_err(|e| e.to_string())?;
            cog.save_index_snapshot().map_err(|e| e.to_string())?;
            let gdb = LibreDb::open(&global_ldb).map_err(|e| e.to_string())?;
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_h)?;

            let out = evaluate_pre_invocation_payload(
                &json!({
                    "conversationId": "audit-a7-cid",
                    "workspacePaths": [ws_h.to_string_lossy().to_string()],
                    "prompt": "How does monotonic Raft lease quorum failover work?"
                }),
                Some(&global_ldb),
            )
            .map_err(|e| e.to_string())?;
            let msg = out["injectSteps"][0]["systemMessage"]["systemMessage"]
                .as_str()
                .unwrap_or("");
            if msg.is_empty()
                || msg.len() > 1_800
                || !msg.contains("anchor_fact_quorum")
                || !msg.contains("anchor_dec_quorum")
            {
                return Err(format!(
                    "BM25 hydration failed invariants (len={}): {msg}",
                    msg.len()
                ));
            }
            Ok(format!(
                "{} B <= 1,800 B; both BM25 Decision #1 & Fact #1 retained",
                msg.len()
            ))
        },
    );

    // A8: `racy-git` same-length & restored-timestamp mutation detection
    run_check(
        "A8",
        "Racy-git same-length & restored-timestamp detection",
        &mut || {
            let ws_r = sbx_root.join("ws_racy");
            fs::create_dir_all(ws_r.join("src")).map_err(|e| e.to_string())?;
            fs::create_dir_all(ws_r.join(".agents")).map_err(|e| e.to_string())?;
            let rf = ws_r.join("src/racy.rs");
            fs::write(&rf, "pub fn gate_a() -> u32 { 1 }\n").map_err(|e| e.to_string())?;
            let orig_mtime = fs::metadata(&rf)
                .and_then(|m| m.modified())
                .map_err(|e| e.to_string())?;

            let pdb = LibreDb::open(ws_r.join(".agents/memory.ldb")).map_err(|e| e.to_string())?;
            libredb_cognitive::index_workspace(&pdb, &ws_r, false).map_err(|e| e.to_string())?;

            // Case 1: Same byte length + explicitly restored identical `mtime` inside smudged window
            fs::write(&rf, "pub fn gate_b() -> u32 { 1 }\n").map_err(|e| e.to_string())?;
            if let Ok(f) = fs::File::options().write(true).open(&rf) {
                let _ = f.set_modified(orig_mtime);
            }
            let rep1 =
                libredb_cognitive::index_workspace(&pdb, &ws_r, false).map_err(|e| e.to_string())?;
            let imp_b =
                libredb_cognitive::query_symbol_impact(&pdb, "gate_b").map_err(|e| e.to_string())?;
            if rep1.files_reindexed != 1 || imp_b.is_empty() {
                return Err(format!(
                    "Smudged same-mtime mutation missed: reindexed={}",
                    rep1.files_reindexed
                ));
            }

            // Case 2: Archive/backup restore to an older historical timestamp (`orig_mtime - 3600s`)
            fs::write(&rf, "pub fn gate_c() -> u32 { 1 }\n").map_err(|e| e.to_string())?;
            if let Some(older) = orig_mtime.checked_sub(std::time::Duration::from_secs(3_600)) {
                if let Ok(f) = fs::File::options().write(true).open(&rf) {
                    let _ = f.set_modified(older);
                }
            }
            let rep2 =
                libredb_cognitive::index_workspace(&pdb, &ws_r, false).map_err(|e| e.to_string())?;
            let imp_c =
                libredb_cognitive::query_symbol_impact(&pdb, "gate_c").map_err(|e| e.to_string())?;
            if rep2.files_reindexed != 1 || imp_c.is_empty() {
                return Err(format!(
                    "Restored historical mtime mutation missed: reindexed={}",
                    rep2.files_reindexed
                ));
            }
            Ok("smudged same-mtime & backdated archive-restore edits both detected".to_owned())
        },
    );

    // A9: `hmac-sha256:v4` workspace trust seal preservation across index, edits, and pulse
    run_check(
        "A9",
        "HMAC-SHA256 v4 workspace trust seal preservation",
        &mut || {
            let gdb = LibreDb::open(&global_ldb).map_err(|e| e.to_string())?;
            let ok_a = crate::security::is_workspace_memory_trusted(Some(&gdb), &ws_a);
            let ok_t = crate::security::is_workspace_memory_trusted(
                Some(&gdb),
                &sbx_root.join("ws_tentative"),
            );
            let ok_h = crate::security::is_workspace_memory_trusted(
                Some(&gdb),
                &sbx_root.join("ws_hydrate"),
            );
            if !ok_a || !ok_t || !ok_h {
                return Err(format!(
                    "v4 seal broken: ws_alpha={ok_a}, ws_tentative={ok_t}, ws_hydrate={ok_h}"
                ));
            }
            Ok("all 3 sealed workspaces verified intact after mutations & queries".to_owned())
        },
    );

    let passed = checks.iter().filter(|c| c.passed).count();
    let failed = checks.len().saturating_sub(passed);
    let report = AuditSuiteReport {
        suite: "v1.1.1-feature-and-security-audit".to_owned(),
        total_checks: checks.len(),
        passed_checks: passed,
        failed_checks: failed,
        total_ms: round2(suite_start.elapsed().as_secs_f64() * 1000.0),
        checks,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "=== LibreDB Feature & Security Verification Suite [{}] ===",
            report.suite
        );
        println!(
            "{:<4} {:<6} {:<52} {:>8}  {}",
            "ID", "Status", "Verification Check", "Time", "Result"
        );
        println!("{}", "-".repeat(122));
        for c in &report.checks {
            println!(
                "{:<4} {:<6} {:<52} {:>6.2}ms  {}",
                c.check_id,
                if c.passed { "PASS" } else { "FAIL" },
                c.title,
                c.elapsed_ms,
                c.detail
            );
        }
        println!("{}", "-".repeat(122));
        println!(
            "Summary: {}/{} passed, {} failed in {:.2} ms",
            report.passed_checks, report.total_checks, report.failed_checks, report.total_ms
        );
    }

    if failed > 0 {
        return Err(format!(
            "Verification suite failed ({failed}/{} checks failed)",
            report.total_checks
        )
        .into());
    }
    Ok(report)
}
