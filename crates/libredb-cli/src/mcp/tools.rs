//! MCP tool dispatch (`libredb_pulse`, `libredb_code`, `libredb_memorize`, and legacy aliases)
//! including fail-closed `SessionState` loading and explicit in-RAM Zero-Repeat degradation on
//! storage write failures.

use super::authz::{default_libredb_home, infer_antigravity_transcript_path};
use super::{canonical_brain_cache_key, McpServerState};
use crate::hooks::{open_global_ldb, user_home_dir};
use crate::telemetry::{
    build_savings_report, format_savings_report, record_event, record_workspace_event,
    SavingsQueryOptions, TelemetryEvent, MAX_SAVINGS_DAYS,
};
use libredb_bridge::import_sqlite_readonly;
use libredb_cognitive::skeleton::{
    read_bounded_source_file, SKELETON_HASH_SEED, SKELETON_KEY_PREFIX,
};
use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, format_fim_batch_compact,
    format_impact_batch_compact, format_impact_compact, format_locate_compact, locate_symbols,
    query_symbol_impact, query_symbols_impact_batch, reconcile_tentative_edits,
    sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton, FimSliceRequest,
    PulseRequest, ReflexEngine, ReflexRule, SessionState, MAX_BATCH_FIM_SLICES,
    MAX_BATCH_SYMBOL_QUERIES,
};
use libredb_core::crc::hash_key;
use libredb_core::{LibreDb, LibreDbError, NodeKind, PreparedWrite, WriteRequest};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[inline]
fn is_degradable_db_write_error(err: &LibreDbError) -> bool {
    matches!(err, LibreDbError::Io(_) | LibreDbError::SimulatedPowerLoss(_))
}

/// Extracts hash-cached `FileSkeleton`s and updates per-`cid` `SessionState` with strict error
/// semantics:
/// - Source file read errors, symlink violations, and DB read/format corruptions (`CorruptFormat`,
///   `ChecksumMismatch`, corrupt `session_delta::<cid>` JSON) ALWAYS fail closed (`Err`).
/// - Storage write errors (`LibreDbError::Io` / `LibreDbError::SimulatedPowerLoss`) during skeleton
///   cache commits or `sess.save(&proj_db)` NEVER fail silently: the server retains the updated
///   `SessionState` in bounded RAM (`state.ram_session_fallback`) so subsequent turns in the same
///   session still suppress duplicate skeleton tokens, and appends an explicit `[WARN: ...]` line.
fn execute_skeleton_with_zero_repeat(
    state: &mut McpServerState,
    proj_db: &Arc<LibreDb>,
    ws_root: &Path,
    requested_paths: &[PathBuf],
    sym_filter: Option<&str>,
    force: bool,
    cid_arg: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok((promoted, avoided_tok)) = reconcile_tentative_edits(proj_db, ws_root) {
        if promoted > 0 {
            record_workspace_event(
                ws_root,
                TelemetryEvent::HookSymbolShift {
                    reread_tokens_avoided: avoided_tok,
                },
            );
        }
    }
    let mut skeletons: Vec<FileSkeleton> = Vec::with_capacity(requested_paths.len());
    let mut pending_cache_writes: Vec<PreparedWrite> = Vec::new();
    let mut degraded_write_err: Option<String> = None;

    for (idx, path) in requested_paths.iter().enumerate() {
        let raw_bytes = read_bounded_source_file(path)?;
        let current_hash = hash_key(SKELETON_HASH_SEED, &raw_bytes);
        let label = path.to_string_lossy().replace('\\', "/");
        let cache_key = format!("{SKELETON_KEY_PREFIX}{label}");

        match proj_db.get_by_key(NodeKind::WorkingSet, &cache_key) {
            Ok(rec) => {
                if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                    if cached.content_hash == current_hash {
                        skeletons.push(cached);
                        continue;
                    }
                }
            }
            Err(LibreDbError::KeyNotFound { .. }) => {}
            Err(other) => return Err(other.into()),
        }

        let skel = FileSkeleton::extract_from_bytes(label, &raw_bytes);
        let encoded = serde_json::to_vec(&skel)
            .map_err(|_| LibreDbError::CorruptFormat("skeleton json serialize"))?;
        let prep = proj_db.prepare(
            WriteRequest::new(NodeKind::WorkingSet, encoded)
                .with_key(cache_key)
                .with_importance(200),
            idx,
        )?;
        pending_cache_writes.push(prep);
        skeletons.push(skel);
    }

    if !pending_cache_writes.is_empty() {
        match proj_db.commit_batch(&pending_cache_writes) {
            Ok(_) => {
                let _ = proj_db.maybe_auto_compact();
            }
            Err(e) if is_degradable_db_write_error(&e) => {
                degraded_write_err.get_or_insert_with(|| e.to_string());
            }
            Err(e) => return Err(e.into()),
        }
    }

    let brain_cache_key = proj_db
        .path()
        .map(canonical_brain_cache_key)
        .unwrap_or_else(|| crate::security::normalize_workspace_key(ws_root));

    let mut session_opt: Option<(String, SessionState)> = if let Some(cid) = cid_arg
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut epoch = 1u32;
        if let Some(tp) = infer_antigravity_transcript_path(cid) {
            if tp.exists() {
                match sync_transcript_epoch(proj_db, cid, &tp) {
                    Ok(ep) => epoch = ep,
                    Err(e) if is_degradable_db_write_error(&e) => {
                        degraded_write_err.get_or_insert_with(|| e.to_string());
                    }
                    Err(other) => return Err(other.into()),
                }
            }
        }
        // Fail closed on genuine DB read/corruption errors (`?` instead of `.ok()`):
        let mut sess = SessionState::load_or_init(proj_db, cid, epoch)?;
        let ram_key = (brain_cache_key.clone(), cid.to_owned());
        if let Some(ram_sess) = state.ram_session_fallback.get(&ram_key) {
            if ram_sess.active_epoch == epoch {
                for (lbl, hash) in &ram_sess.delivered_skeletons {
                    sess.delivered_skeletons.insert(lbl.clone(), *hash);
                }
                for (nid, gen) in &ram_sess.delivered_generations {
                    let entry = sess.delivered_generations.entry(*nid).or_insert(*gen);
                    if *gen > *entry {
                        *entry = *gen;
                    }
                }
                sess.cumulative_tokens_saved =
                    sess.cumulative_tokens_saved.max(ram_sess.cumulative_tokens_saved);
                sess.duplicate_hits_suppressed =
                    sess.duplicate_hits_suppressed.max(ram_sess.duplicate_hits_suppressed);
            }
        }
        Some((cid.to_owned(), sess))
    } else {
        None
    };

    let mut out_blocks: Vec<String> = Vec::with_capacity(skeletons.len() + 1);
    let mut session_dirty = false;
    let mut zr_hits = 0u64;
    let mut baseline_raw_tokens = 0u64;
    let mut emitted_tokens = 0u64;

    for skel in skeletons {
        baseline_raw_tokens = baseline_raw_tokens.saturating_add(skel.raw_tokens as u64);
        if !force && sym_filter.is_none() {
            if let Some((_, ref mut sess)) = session_opt {
                if sess.is_skeleton_in_context(&skel.file_label, skel.content_hash) {
                    sess.record_suppression(skel.raw_tokens, 16);
                    session_dirty = true;
                    zr_hits += 1;
                    emitted_tokens = emitted_tokens.saturating_add(16);
                    out_blocks.push(format!(
                        "=== [Zero-Repeat Skeleton]: {} (unchanged in session, hash={:016x}, L1-L{}, {} contracts, saved ~{} tok) ===\n",
                        skel.file_label,
                        skel.content_hash,
                        skel.total_lines,
                        skel.symbols.len(),
                        skel.raw_tokens.saturating_sub(16)
                    ));
                    continue;
                }
                sess.mark_skeleton_delivered(skel.file_label.clone(), skel.content_hash);
                session_dirty = true;
            }
        }
        let rendered = skel.render_compact(sym_filter, sym_filter.is_some());
        emitted_tokens = emitted_tokens.saturating_add(((rendered.len() + 3) / 4) as u64);
        out_blocks.push(rendered);
    }

    record_workspace_event(
        ws_root,
        TelemetryEvent::Skeleton {
            zero_repeat_hits: zr_hits,
            baseline_tokens: baseline_raw_tokens.max(emitted_tokens),
            emitted_tokens,
        },
    );

    if session_dirty {
        if let Some((cid, sess)) = session_opt {
            let ram_key = (brain_cache_key, cid);
            match sess.save(proj_db) {
                Ok(_) => {
                    state.ram_session_fallback.remove(&ram_key);
                }
                Err(e) if is_degradable_db_write_error(&e) => {
                    degraded_write_err = Some(e.to_string());
                    state.insert_ram_session_bounded(ram_key, sess);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    if let Some(err_msg) = degraded_write_err {
        out_blocks.push(format!(
            "[WARN: Zero-Repeat persistence degraded to in-RAM session mode; disk save failed: {err_msg}]"
        ));
    }

    Ok(out_blocks.join("\n"))
}

pub(super) fn dispatch_tool(
    name: &str,
    args: &Value,
    state: &mut McpServerState,
) -> Result<String, Box<dyn std::error::Error>> {
    let cwd_hint = args
        .get("cwd")
        .and_then(Value::as_str)
        .or_else(|| args.get("file_path").and_then(Value::as_str))
        .or_else(|| args.get("target").and_then(Value::as_str));
    let cid_arg = args.get("cid").and_then(Value::as_str);

    match name {
        "libredb_pulse" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let budget = args.get("budget").and_then(Value::as_u64).unwrap_or(600) as u32;
            let mut req = PulseRequest::new(query, budget);
            let requested_ws_dir = args
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .or_else(|| state.pinned_workspace_root.clone());
            if let Some(err) = args.get("error").and_then(Value::as_str) {
                req.error_context = Some(err.to_owned());
            }

            let q_key = canonical_brain_cache_key(
                &default_libredb_home().join("quarantined_workspace.ldb"),
            );
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
            let is_quarantined = brain
                .project_db()
                .path()
                .is_some_and(|p| canonical_brain_cache_key(p) == q_key);
            if !is_quarantined {
                req.workspace_dir = requested_ws_dir;
            }
            if let Some(cid) = cid_arg {
                req.conversation_id = Some(cid.to_owned());
                let tp_opt = infer_antigravity_transcript_path(cid);
                if let Some(tp) = tp_opt {
                    if tp.exists() {
                        req.epoch = sync_transcript_epoch(brain.project_db(), cid, &tp)?;
                    }
                }
            }

            let resp = brain.pulse(&req)?;
            let formatted = resp.format_compact();
            let emitted_tok = ((formatted.len() + 3) / 4) as u64;
            let baseline_tok = emitted_tok
                .saturating_add(resp.tokens_saved_by_delta as u64)
                .max((resp.tokens_emitted + resp.tokens_saved_by_delta) as u64);
            record_event(TelemetryEvent::Pulse {
                baseline_tokens: baseline_tok,
                emitted_tokens: emitted_tok,
            });
            Ok(formatted)
        }
        "libredb_code" => {
            let action = args
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("skeleton");
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);
            let target_opt = args.get("target").and_then(Value::as_str);
            if action == "savings" {
                let days_opt: Option<u32> = match args.get("days") {
                    None | Some(Value::Null) => None,
                    Some(v) => {
                        let Some(raw_d) = v.as_u64() else {
                            return Err(format!(
                                "Invalid 'days' parameter: expected integer in 0..={MAX_SAVINGS_DAYS}"
                            )
                            .into());
                        };
                        if raw_d > MAX_SAVINGS_DAYS {
                            return Err(format!(
                                "Requested 'days' ({raw_d}) exceeds maximum allowed window ({MAX_SAVINGS_DAYS} days)"
                            )
                            .into());
                        }
                        Some(raw_d as u32)
                    }
                };

                // Enforce the exact same server-side workspace authorization boundary as all other
                // `libredb_code` actions (`resolve_authorized_code_workspace` + quarantine check),
                // unless an unpinned host explicitly opted into `mcp:allow_global_savings=true` with `cwd="*"`.
                let proj_filter: Option<PathBuf> = if raw_cwd_arg.map(str::trim) == Some("*") {
                    state.sync_global_db_or_purge()?;
                    if state.pinned_workspace_root.is_some()
                        || !crate::security::load_bool_config(
                            state.global_db.as_deref(),
                            None,
                            "mcp:allow_global_savings",
                            false,
                        )
                    {
                        return Err(
                            "LibreDB MCP access denied: global cross-workspace savings ('cwd=\"*\"') is disabled by policy; pass an authorized workspace 'cwd' or use the local 'libredb savings' CLI."
                                .into(),
                        );
                    }
                    None
                } else {
                    let (ws_root, _containment_root) = state.resolve_authorized_code_workspace(
                        raw_cwd_arg,
                        target_opt,
                        true,
                    )?;
                    let ws_root_str = ws_root.to_string_lossy().into_owned();
                    let proj_db = {
                        let brain = state.resolve_brain_mut(Some(&ws_root_str), cid_arg, false)?;
                        Arc::clone(brain.project_db())
                    };
                    if state.is_quarantined_db(&proj_db) {
                        return Err(format!(
                            "LibreDB MCP access denied: workspace '{}' is quarantined; run 'libredb trust' in a terminal first.",
                            ws_root.display()
                        )
                        .into());
                    }
                    Some(ws_root)
                };

                let opts = SavingsQueryOptions {
                    today_only: days_opt == Some(0),
                    days: days_opt.filter(|&d| d > 0),
                    cid_filter: cid_arg,
                    project_filter: proj_filter.as_deref(),
                    custom_brain_dir: None,
                    custom_telemetry_ldb: None,
                };
                let rep = build_savings_report(&opts);
                let want_json = args
                    .get("format")
                    .and_then(Value::as_str)
                    .is_some_and(|f| f.eq_ignore_ascii_case("json"));
                return if want_json {
                    Ok(serde_json::to_string_pretty(&rep)?)
                } else {
                    Ok(format_savings_report(&rep))
                };
            }
            let files_arr: Vec<String> = args
                .get("files")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let symbols_arr: Vec<String> = args
                .get("symbols")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;
            let slices_arr: Vec<FimSliceRequest> = match args.get("slices") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(arr)) => {
                    let mut parsed = Vec::with_capacity(arr.len());
                    for item in arr {
                        let t = item
                            .get("target")
                            .or_else(|| item.get("file"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or("Each item in 'slices' must specify a non-empty 'target' file path")?;
                        let s = item
                            .get("symbol")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                            .map(ToOwned::to_owned);
                        let l = item.get("line").and_then(Value::as_u64).map(|n| n as usize);
                        let p = item
                            .get("pad")
                            .and_then(Value::as_u64)
                            .map_or(pad, |n| n as usize);
                        parsed.push(FimSliceRequest {
                            target: t.to_owned(),
                            symbol: s,
                            line: l,
                            pad: p,
                        });
                    }
                    parsed
                }
                Some(_) => return Err("Invalid 'slices' parameter: expected array of slice objects".into()),
            };
            let first_file_hint = target_opt
                .or_else(|| files_arr.first().map(String::as_str))
                .or_else(|| slices_arr.first().map(|s| s.target.as_str()));
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
            let want_json = args
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|f| f.eq_ignore_ascii_case("json"));

            let (ws_root, containment_root) = state.resolve_authorized_code_workspace(
                raw_cwd_arg,
                first_file_hint,
                matches!(action, "impact" | "locate"),
            )?;
            let ws_root_str = ws_root.to_string_lossy().into_owned();
            let proj_db = {
                let brain = state.resolve_brain_mut(Some(&ws_root_str), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            if state.is_quarantined_db(&proj_db) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace '{}' is quarantined; run 'libredb trust' in a terminal first.",
                    ws_root.display()
                )
                .into());
            }
            let protected_paths = state.custom_protected_paths(Some(&proj_db));
            let resolve_rel = |raw_p: &str| -> PathBuf {
                let tp = Path::new(raw_p);
                if tp.is_relative() {
                    containment_root.join(tp)
                } else {
                    tp.to_path_buf()
                }
            };
            let check_target_access = |p: &Path| -> Result<(), String> {
                if let Some(err) = crate::security::check_mcp_read_path_policy(p, &protected_paths)
                {
                    return Err(err);
                }
                if let Some(err) =
                    crate::security::check_mcp_workspace_containment(p, &containment_root)
                {
                    return Err(err);
                }
                if let Some(err) = crate::security::check_mcp_workspace_containment(p, &ws_root) {
                    return Err(err);
                }
                Ok(())
            };
            let collect_symbol_queries = || -> Result<Vec<String>, String> {
                let mut queries: Vec<String> = Vec::new();
                let mut push_unique = |raw: &str| {
                    let t = raw.trim();
                    if !t.is_empty() && !queries.iter().any(|q| q == t) {
                        queries.push(t.to_owned());
                    }
                };
                if let Some(t) = target_opt {
                    if symbols_arr.is_empty() && t.contains(',') && !t.contains('(') {
                        for part in t.split(',') {
                            push_unique(part);
                        }
                    } else {
                        push_unique(t);
                    }
                }
                if let Some(s) = sym {
                    push_unique(s);
                }
                for s in &symbols_arr {
                    push_unique(s);
                }
                if queries.is_empty() {
                    return Err(format!(
                        "Missing 'target' or 'symbols' for action='{action}'"
                    ));
                }
                if queries.len() > MAX_BATCH_SYMBOL_QUERIES {
                    return Err(format!(
                        "Requested symbol batch ({}) exceeds maximum allowed ({MAX_BATCH_SYMBOL_QUERIES})",
                        queries.len()
                    ));
                }
                Ok(queries)
            };

            match action {
                "skeleton" => {
                    let mut requested_paths: Vec<PathBuf> = Vec::new();
                    if let Some(t) = target_opt {
                        if !t.trim().is_empty() {
                            requested_paths.push(resolve_rel(t));
                        }
                    }
                    for f in &files_arr {
                        let rp = resolve_rel(f);
                        if !requested_paths.contains(&rp) {
                            requested_paths.push(rp);
                        }
                    }
                    if requested_paths.is_empty() {
                        return Err("Missing 'target' or 'files' for action='skeleton'".into());
                    }
                    for rp in &requested_paths {
                        check_target_access(rp)?;
                        state.verify_target_belongs_to_workspace(rp, &ws_root)?;
                    }
                    execute_skeleton_with_zero_repeat(
                        state,
                        &proj_db,
                        &ws_root,
                        &requested_paths,
                        sym,
                        force,
                        cid_arg,
                    )
                }
                "locate" => {
                    let queries = collect_symbol_queries()?;
                    check_target_access(&ws_root)?;
                    state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &ws_root,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;
                    let matches = locate_symbols(&proj_db, &queries)?;
                    let rendered = if want_json {
                        serde_json::to_string_pretty(&matches)?
                    } else {
                        format_locate_compact(&queries, &matches)
                    };
                    let emitted_tok = ((rendered.len() + 3) / 4) as u64;
                    let baseline_tok = ((matches.len().max(queries.len()) * 140)
                        .max(rendered.len() / 4)) as u64;
                    record_workspace_event(
                        &ws_root,
                        TelemetryEvent::Impact {
                            baseline_tokens: baseline_tok.max(emitted_tok),
                            emitted_tokens: emitted_tok,
                        },
                    );
                    Ok(rendered)
                }
                "impact" => {
                    let queries = collect_symbol_queries()?;
                    check_target_access(&ws_root)?;
                    state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &ws_root,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;
                    let (rendered, total_refs) = if queries.len() == 1 {
                        let reports = query_symbol_impact(&proj_db, &queries[0])?;
                        let refs: usize = reports
                            .iter()
                            .map(|r| r.total_callers.max(r.callers.len()))
                            .sum();
                        let txt = if want_json {
                            serde_json::to_string_pretty(&reports)?
                        } else {
                            format_impact_compact(&queries[0], &reports)
                        };
                        (txt, refs)
                    } else {
                        let batches = query_symbols_impact_batch(&proj_db, &queries)?;
                        let refs: usize = batches
                            .iter()
                            .flat_map(|(_, reps)| reps.iter())
                            .map(|r| r.total_callers.max(r.callers.len()))
                            .sum();
                        let txt = if want_json {
                            let json_batches: Vec<Value> = batches
                                .iter()
                                .map(|(q, reps)| {
                                    serde_json::json!({
                                        "query": q,
                                        "reports": reps,
                                    })
                                })
                                .collect();
                            serde_json::to_string_pretty(&json_batches)?
                        } else {
                            format_impact_batch_compact(&batches)
                        };
                        (txt, refs)
                    };
                    let emitted_tok = ((rendered.len() + 3) / 4) as u64;
                    let baseline_grep_tok = ((total_refs.max(queries.len()) * 180)
                        .max(rendered.len() / 4)) as u64;
                    record_workspace_event(
                        &ws_root,
                        TelemetryEvent::Impact {
                            baseline_tokens: baseline_grep_tok.max(emitted_tok),
                            emitted_tokens: emitted_tok,
                        },
                    );
                    Ok(rendered)
                }
                "fim" => {
                    let mut requests: Vec<FimSliceRequest> = Vec::new();
                    if !slices_arr.is_empty() {
                        requests.extend(slices_arr);
                    } else if !symbols_arr.is_empty() {
                        let target = target_opt
                            .or_else(|| files_arr.first().map(String::as_str))
                            .ok_or("Missing 'target' file path for batched 'symbols' in action='fim'")?;
                        for s in &symbols_arr {
                            requests.push(FimSliceRequest {
                                target: target.to_owned(),
                                symbol: Some(s.clone()),
                                line: None,
                                pad,
                            });
                        }
                    } else {
                        let target = target_opt.ok_or("Missing target")?;
                        requests.push(FimSliceRequest {
                            target: target.to_owned(),
                            symbol: sym.map(ToOwned::to_owned),
                            line,
                            pad,
                        });
                    }
                    if requests.len() > MAX_BATCH_FIM_SLICES {
                        return Err(format!(
                            "Requested FIM slice batch ({}) exceeds maximum allowed ({MAX_BATCH_FIM_SLICES})",
                            requests.len()
                        )
                        .into());
                    }

                    check_target_access(&ws_root)?;
                    let mut resolved_requests: Vec<(PathBuf, FimSliceRequest)> =
                        Vec::with_capacity(requests.len());
                    for req in requests {
                        let rp = resolve_rel(&req.target);
                        check_target_access(&rp)?;
                        state.verify_target_belongs_to_workspace(&rp, &ws_root)?;
                        resolved_requests.push((rp, req));
                    }

                    state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &ws_root,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;

                    let mut bundles = Vec::with_capacity(resolved_requests.len());
                    let mut unique_files: std::collections::HashSet<PathBuf> =
                        std::collections::HashSet::new();
                    let mut raw_file_tok_sum = 0u64;

                    for (rp, req) in &resolved_requests {
                        let bundle = extract_fim_slice(
                            &proj_db,
                            rp,
                            req.symbol.as_deref(),
                            req.line,
                            req.pad,
                        )?;
                        if unique_files.insert(rp.clone()) {
                            let file_tok = std::fs::metadata(rp)
                                .map(|m| (m.len().saturating_add(3)) / 4)
                                .unwrap_or(0);
                            raw_file_tok_sum = raw_file_tok_sum.saturating_add(file_tok);
                        }
                        bundles.push(bundle);
                    }

                    let rendered = if want_json {
                        if bundles.len() == 1 {
                            serde_json::to_string_pretty(&bundles[0])?
                        } else {
                            serde_json::to_string_pretty(&bundles)?
                        }
                    } else {
                        format_fim_batch_compact(&bundles)
                    };
                    let emitted_tok = ((rendered.len() + 3) / 4) as u64;
                    record_workspace_event(
                        &ws_root,
                        TelemetryEvent::Fim {
                            baseline_tokens: raw_file_tok_sum.max(emitted_tok),
                            emitted_tokens: emitted_tok,
                        },
                    );
                    Ok(rendered)
                }
                "index" => {
                    let target = target_opt.ok_or("Missing target")?;
                    let resolved_target = resolve_rel(target);
                    check_target_access(&resolved_target)?;
                    state.verify_target_belongs_to_workspace(&resolved_target, &ws_root)?;
                    let rep = state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &resolved_target,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;
                    Ok(serde_json::to_string_pretty(&rep)?)
                }
                other => Err(format!("Unsupported libredb_code action '{other}'").into()),
            }
        }
        "libredb_memorize" | "libredb_batch" => {
            let mut outputs: Vec<String> = Vec::new();

            if args.get("sync_central_sqlite").and_then(Value::as_bool) == Some(true) {
                state.sync_global_db_or_purge()?;
                let allow_sync = crate::security::load_bool_config(
                    state.global_db.as_deref(),
                    None,
                    "mcp:allow_central_sqlite_sync",
                    false,
                );
                if !allow_sync {
                    return Err(
                        "Refusing unapproved MCP import of legacy customizations.db into global customizations.ldb ('sync_central_sqlite' is disabled by default). Run 'libredb modernize-global --migrate-legacy' in a terminal, or explicitly enable 'libredb config set mcp:allow_central_sqlite_sync true'."
                            .into(),
                    );
                }
                let central_sqlite = user_home_dir()
                    .join(".gemini")
                    .join("database")
                    .join("customizations.db");
                if let Some(ref gp) = state.global_path.clone() {
                    if central_sqlite.exists() {
                        let gdb = open_global_ldb(Some(gp))?;
                        let sum = import_sqlite_readonly(&central_sqlite, &gdb, "central")?;
                        let mut cog = CognitiveEngine::open_db(gdb)?;
                        cog.save_index_snapshot()?;
                        state.reload_global_db()?;
                        outputs.push(format!(
                            "Synced {} central capsules + {} synapses from customizations.db",
                            sum.cognitive_capsules_created, sum.synapses_wired
                        ));
                    }
                }
            }

            let (ws_write_lock, ws_root_to_seal, proj_db) = {
                let (lock_opt, ws_opt, brain) =
                    state.resolve_brain_with_seal_target(cwd_hint, cid_arg, true)?;
                (lock_opt, ws_opt, Arc::clone(brain.project_db()))
            };

            let mut spec = AtomicBatchSpec::default();
            if let Some(fmap) = args.get("facts").and_then(Value::as_object) {
                for (k, v) in fmap {
                    spec.facts.push((
                        k.clone(),
                        v.as_str()
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    ));
                }
            }
            if let Some(dmap) = args.get("decisions").and_then(Value::as_object) {
                for (k, v) in dmap {
                    spec.decisions.push((
                        k.clone(),
                        v.as_str()
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    ));
                }
            }
            if let Some(tarr) = args.get("tasks").and_then(Value::as_array) {
                for t in tarr {
                    if let (Some(k), Some(title)) = (
                        t.get("key").and_then(Value::as_str),
                        t.get("title").and_then(Value::as_str),
                    ) {
                        let st = t.get("status").and_then(Value::as_str).unwrap_or("pending");
                        let pr = t.get("priority").and_then(Value::as_str).unwrap_or("med");
                        spec.tasks.push((
                            k.to_owned(),
                            title.to_owned(),
                            st.to_owned(),
                            pr.to_owned(),
                        ));
                    }
                }
            }
            if let Some(snap) = args.get("snapshot").and_then(Value::as_str) {
                spec.snapshot = Some(snap.to_owned());
            }
            if !spec.facts.is_empty()
                || !spec.decisions.is_empty()
                || !spec.tasks.is_empty()
                || spec.snapshot.is_some()
            {
                let rep = execute_atomic_batch(&proj_db, &spec)?;
                outputs.push(format!(
                    "Committed {} capsules ({} governance edges)",
                    rep.nodes_committed, rep.governance_edges_wired
                ));
            }

            if let Some(la) = args.get("learn_assoc").and_then(Value::as_object) {
                if let Some(cue) = la.get("cue").and_then(Value::as_str) {
                    let ids: Vec<u64> = la
                        .get("target_ids")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_u64).collect())
                        .unwrap_or_default();
                    let mut cog = CognitiveEngine::open_db(Arc::clone(&proj_db))?;
                    let cnt = cog.reinforce_association(cue, &ids)?;
                    cog.save_index_snapshot()?;
                    outputs.push(format!("Reinforced {cnt} Hebbian synapses for '{cue}'"));
                }
            }

            if let Some(lr) = args.get("learn_reflex").and_then(Value::as_object) {
                if let (Some(id), Some(dir)) = (
                    lr.get("id").and_then(Value::as_str),
                    lr.get("directive").and_then(Value::as_str),
                ) {
                    let parse_arr = |k: &str| -> Vec<String> {
                        lr.get(k)
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(Value::as_str)
                                    .map(ToOwned::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    let rule = ReflexRule {
                        id: id.to_owned(),
                        stack_any: parse_arr("stack"),
                        action_any: parse_arr("action"),
                        env_or_error_any: parse_arr("env"),
                        directive: dir.to_owned(),
                        code_anchors: parse_arr("anchors"),
                        ..Default::default()
                    };
                    let nid = ReflexEngine::learn_reflex(&proj_db, &rule)?;
                    outputs.push(format!("Learned reflex '{id}' (#{nid})"));
                }
            }

            let _ = proj_db.maybe_auto_compact();
            let seal_res =
                state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db);
            drop(ws_write_lock);
            seal_res?;
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
            brain.refresh_if_needed()?;
            if outputs.is_empty() {
                Ok("No mutations requested.".to_owned())
            } else {
                Ok(outputs.join(" | "))
            }
        }
        // Backwards-compatible legacy aliases:
        "libredb_skeleton" => {
            let fp = args
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or("Missing file_path")?;
            let flt = args.get("filter").and_then(Value::as_str);
            let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);
            let (ws_root, containment_root) =
                state.resolve_authorized_code_workspace(raw_cwd_arg, Some(fp), false)?;
            let resolved_fp = if Path::new(fp).is_relative() {
                containment_root.join(fp)
            } else {
                PathBuf::from(fp)
            };
            let ws_root_str = ws_root.to_string_lossy().into_owned();
            let proj_db = {
                let brain = state.resolve_brain_mut(Some(&ws_root_str), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            if state.is_quarantined_db(&proj_db) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace '{}' is quarantined; run 'libredb trust' in a terminal first.",
                    ws_root.display()
                )
                .into());
            }
            let protected = state.custom_protected_paths(Some(&proj_db));
            if let Some(err) = crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
            {
                return Err(err.into());
            }
            if let Some(err) =
                crate::security::check_mcp_workspace_containment(&resolved_fp, &containment_root)
            {
                return Err(err.into());
            }
            if let Some(err) =
                crate::security::check_mcp_workspace_containment(&resolved_fp, &ws_root)
            {
                return Err(err.into());
            }
            state.verify_target_belongs_to_workspace(&resolved_fp, &ws_root)?;
            execute_skeleton_with_zero_repeat(
                state,
                &proj_db,
                &ws_root,
                &[resolved_fp],
                flt,
                force,
                cid_arg,
            )
        }
        "libredb_impact" => {
            let sym = args
                .get("symbol")
                .and_then(Value::as_str)
                .ok_or("Missing symbol")?;
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);
            let (ws_root, _) = state.resolve_authorized_code_workspace(raw_cwd_arg, None, true)?;
            let ws_root_str = ws_root.to_string_lossy().into_owned();
            let proj_db = {
                let brain = state.resolve_brain_mut(Some(&ws_root_str), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            if state.is_quarantined_db(&proj_db) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace '{}' is quarantined; run 'libredb trust' in a terminal first.",
                    ws_root.display()
                )
                .into());
            }
            let reports = query_symbol_impact(&proj_db, sym)?;
            Ok(serde_json::to_string_pretty(&reports)?)
        }
        "libredb_fim" => {
            let fp = args
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or("Missing file_path")?;
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);
            let (ws_root, containment_root) =
                state.resolve_authorized_code_workspace(raw_cwd_arg, Some(fp), false)?;
            let resolved_fp = if Path::new(fp).is_relative() {
                containment_root.join(fp)
            } else {
                PathBuf::from(fp)
            };
            let ws_root_str = ws_root.to_string_lossy().into_owned();
            let proj_db = {
                let brain = state.resolve_brain_mut(Some(&ws_root_str), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            if state.is_quarantined_db(&proj_db) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace '{}' is quarantined; run 'libredb trust' in a terminal first.",
                    ws_root.display()
                )
                .into());
            }
            let protected = state.custom_protected_paths(Some(&proj_db));
            if let Some(err) = crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
            {
                return Err(err.into());
            }
            if let Some(err) =
                crate::security::check_mcp_workspace_containment(&resolved_fp, &containment_root)
            {
                return Err(err.into());
            }
            if let Some(err) =
                crate::security::check_mcp_workspace_containment(&resolved_fp, &ws_root)
            {
                return Err(err.into());
            }
            state.verify_target_belongs_to_workspace(&resolved_fp, &ws_root)?;
            let bundle = extract_fim_slice(&proj_db, &resolved_fp, sym, line, pad)?;
            Ok(bundle.format_compact())
        }
        "libredb_handoff" => {
            let hid = args
                .get("handoff_id")
                .and_then(Value::as_str)
                .ok_or("Missing handoff_id")?;
            let tkey = args
                .get("task_key")
                .and_then(Value::as_str)
                .ok_or("Missing task_key")?;
            let role = args
                .get("role")
                .and_then(Value::as_str)
                .ok_or("Missing role")?;
            let notes = args.get("instructions").and_then(Value::as_str).unwrap_or("");
            let (ws_write_lock, ws_root_to_seal, proj_db) = {
                let (lock_opt, ws_opt, brain) =
                    state.resolve_brain_with_seal_target(cwd_hint, cid_arg, true)?;
                (lock_opt, ws_opt, Arc::clone(brain.project_db()))
            };
            let (_, block) = create_subagent_handoff(&proj_db, hid, tkey, role, notes)?;
            let _ = proj_db.maybe_auto_compact();
            let seal_res =
                state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db);
            drop(ws_write_lock);
            seal_res?;
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
            brain.refresh_if_needed()?;
            Ok(block)
        }
        other => Err(format!("Unknown tool '{other}'").into()),
    }
}
