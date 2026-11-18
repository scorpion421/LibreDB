//! MCP tool dispatch (`libredb_pulse`, `libredb_code`, `libredb_memorize`, and legacy aliases)
//! including fail-closed `SessionState` loading and explicit in-RAM Zero-Repeat degradation on
//! storage write failures.

use super::authz::{default_libredb_home, infer_antigravity_transcript_path};
use super::{canonical_brain_cache_key, McpServerState};
use crate::telemetry::{
    build_savings_report, format_savings_report, record_event, record_workspace_event,
    SavingsQueryOptions, TelemetryEvent, MAX_SAVINGS_DAYS,
};
use libredb_cognitive::skeleton::{
    read_bounded_source_file, SKELETON_HASH_SEED, SKELETON_KEY_PREFIX,
};
use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, format_fim_batch_compact,
    format_grep_report_compact, format_impact_batch_compact, format_impact_compact,
    format_locate_compact, grep_workspace, locate_symbols, normalize_workspace_display_label,
    query_symbol_impact, query_symbols_impact_batch, reconcile_tentative_edits,
    sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton, FimSliceRequest,
    PulseRequest, ReflexEngine, ReflexRule, SessionState, WorkspaceGrepOptions,
    MAX_BATCH_FIM_SLICES, MAX_BATCH_SYMBOL_QUERIES,
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
        let label = normalize_workspace_display_label(Some(ws_root), path);
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
                .or_else(|| state.pinned_workspace_root.clone())
                .filter(|ws| !crate::security::is_private_brain_workspace(ws));
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
            if matches!(action, "backup" | "restore" | "migrate" | "read") {
                state.sync_global_db_or_purge()?;
                let want_json = args
                    .get("format")
                    .and_then(Value::as_str)
                    .is_some_and(|f| f.eq_ignore_ascii_case("json"));
                let instance_flag = args.get("instance").and_then(Value::as_bool).unwrap_or(false);
                let all_flag = args.get("all").and_then(Value::as_bool).unwrap_or(false);

                if let Some(ref pin_root) = state.pinned_workspace_root {
                    if instance_flag || all_flag {
                        return Err(
                            "LibreDB MCP access denied: 'instance' and 'all' backup/restore operations are disabled on workspace-pinned MCP servers; run the local 'libredb' CLI instead."
                                .into(),
                        );
                    }
                    if let Some(raw_c) = raw_cwd_arg.filter(|s| !s.trim().is_empty()) {
                        let c_path = Path::new(raw_c);
                        let abs_c = if c_path.is_relative() {
                            pin_root.join(c_path)
                        } else {
                            c_path.to_path_buf()
                        };
                        let canon_c = crate::security::canonicalize_with_missing_tail(&abs_c)
                            .unwrap_or(abs_c);
                        if let Some(err) =
                            crate::security::check_mcp_workspace_containment(&canon_c, pin_root)
                        {
                            return Err(err.into());
                        }
                    }
                }

                match action {
                    "backup" => {
                        let base_dir = raw_cwd_arg
                            .filter(|s| !s.trim().is_empty())
                            .map(PathBuf::from)
                            .or_else(|| state.pinned_workspace_root.clone());
                        let dest = args
                            .get("destination")
                            .and_then(Value::as_str)
                            .or(target_opt)
                            .filter(|s| !s.trim().is_empty())
                            .map(|raw| {
                                let p = Path::new(raw);
                                if p.is_relative() {
                                    base_dir
                                        .as_deref()
                                        .unwrap_or(&state.default_project_path)
                                        .join(p)
                                } else {
                                    p.to_path_buf()
                                }
                            });
                        if let Some(ref d) = dest {
                            if let Some(err) = crate::security::check_mcp_read_path_policy(d, &[]) {
                                return Err(err.into());
                            }
                        }
                        let opts = crate::security::BackupOptions {
                            destination: dest,
                            project_dir: base_dir,
                            cid: cid_arg.map(str::to_owned),
                            instance: instance_flag,
                            all: all_flag,
                            global_path: state.global_path.clone(),
                            allow_prompt: false,
                        };
                        let rep = crate::security::execute_backup_command(&opts)?;
                        return if want_json {
                            Ok(serde_json::to_string_pretty(&rep)?)
                        } else {
                            Ok(format!(
                                "[WARN] {}\n[OK] Portable {} backup written to '{}' (instance={}, telemetry={}, chat={}, projects={}, decrypted_secrets={}, total_capsules={})",
                                rep.unencrypted_warning,
                                rep.scope,
                                rep.destination,
                                rep.instance_exported,
                                rep.telemetry_exported,
                                rep.chat_exported,
                                rep.projects_exported.len(),
                                rep.secrets_decrypted,
                                rep.total_capsules
                            ))
                        };
                    }
                    "restore" => {
                        let raw_src = args
                            .get("source")
                            .and_then(Value::as_str)
                            .or(target_opt)
                            .filter(|s| !s.trim().is_empty())
                            .ok_or("Missing 'source' backup path for action='restore'")?;
                        let base_dir = raw_cwd_arg
                            .filter(|s| !s.trim().is_empty())
                            .map(PathBuf::from)
                            .or_else(|| state.pinned_workspace_root.clone());
                        let src_path = {
                            let p = Path::new(raw_src);
                            if p.is_relative() {
                                base_dir
                                    .as_deref()
                                    .unwrap_or(&state.default_project_path)
                                    .join(p)
                            } else {
                                p.to_path_buf()
                            }
                        };
                        if let Some(err) =
                            crate::security::check_mcp_read_path_policy(&src_path, &[])
                        {
                            return Err(err.into());
                        }
                        let opts = crate::security::RestoreOptions {
                            source: src_path,
                            project_dir: base_dir,
                            instance: instance_flag,
                            all: all_flag,
                            global_path: state.global_path.clone(),
                        };
                        let rep = crate::security::execute_restore_command(&opts)?;
                        state.brains.clear();
                        state.ram_session_fallback.clear();
                        state.sync_global_db_or_purge()?;
                        return if want_json {
                            Ok(serde_json::to_string_pretty(&rep)?)
                        } else {
                            Ok(format!(
                                "[OK] Restored {} backup from '{}' (instance={}, telemetry={}, projects_restored={}, skipped_missing={}, reencrypted_secrets={})",
                                rep.scope,
                                rep.source,
                                rep.instance_restored,
                                rep.telemetry_restored,
                                rep.projects_restored.len(),
                                rep.projects_skipped_missing_dir.len(),
                                rep.secrets_reencrypted
                            ))
                        };
                    }
                    "migrate" => {
                        let target_project = raw_cwd_arg
                            .filter(|s| !s.trim().is_empty())
                            .map(PathBuf::from)
                            .or_else(|| state.pinned_workspace_root.clone());
                        let base_dir = target_project
                            .as_deref()
                            .unwrap_or(&state.default_project_path);
                        let source = args
                            .get("source")
                            .and_then(Value::as_str)
                            .or(target_opt)
                            .filter(|s| !s.trim().is_empty())
                            .map(|raw| {
                                let p = Path::new(raw);
                                if p.is_relative() {
                                    base_dir.join(p)
                                } else {
                                    p.to_path_buf()
                                }
                            });
                        if let Some(ref sp) = source {
                            if let Some(err) = crate::security::check_mcp_read_path_policy(sp, &[])
                            {
                                return Err(err.into());
                            }
                        }
                        let from_path = args
                            .get("from_path")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .map(PathBuf::from);
                        let include_artifacts = args
                            .get("include_artifacts")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let opts = crate::security::MigrateOptions {
                            source,
                            cid: cid_arg.map(str::to_owned),
                            target_project,
                            from_path,
                            include_artifacts,
                            global_path: state.global_path.clone(),
                        };
                        let rep = crate::security::execute_migrate_command(&opts)?;
                        state.brains.clear();
                        state.ram_session_fallback.clear();
                        state.sync_global_db_or_purge()?;
                        return if want_json {
                            Ok(serde_json::to_string_pretty(&rep)?)
                        } else {
                            Ok(format!(
                                "[OK] Migration ({}) completed for '{}' (nodes_merged={}, synapses_merged={}, skipped_older={}, artifacts_copied={}, legacy_cleaned={})",
                                rep.mode,
                                rep.target_project,
                                rep.nodes_merged,
                                rep.synapses_merged,
                                rep.nodes_skipped_older,
                                rep.artifacts_copied,
                                rep.legacy_brain_db_cleaned
                            ))
                        };
                    }
                    "read" => {
                        let raw_target = target_opt
                            .or_else(|| args.get("source").and_then(Value::as_str))
                            .filter(|s| !s.trim().is_empty())
                            .ok_or("Missing 'target' path or directory for action='read'")?;
                        let base_dir = state
                            .pinned_workspace_root
                            .as_deref()
                            .unwrap_or(&state.default_project_path);
                        let resolved_target = {
                            let p = Path::new(raw_target);
                            if p.is_relative() {
                                base_dir.join(p)
                            } else {
                                p.to_path_buf()
                            }
                        };
                        if let Some(err) =
                            crate::security::check_mcp_read_path_policy(&resolved_target, &[])
                        {
                            return Err(err.into());
                        }
                        let show_secrets = args
                            .get("show_secrets")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if let Some(ref pin_root) = state.pinned_workspace_root {
                            let canon_t = crate::security::canonicalize_with_missing_tail(
                                &resolved_target,
                            )
                            .unwrap_or_else(|| resolved_target.clone());
                            if let Some(err) =
                                crate::security::check_mcp_workspace_containment(&canon_t, pin_root)
                            {
                                return Err(err.into());
                            }
                            if show_secrets {
                                return Err(
                                    "LibreDB MCP access denied: 'show_secrets' is disabled on workspace-pinned MCP servers."
                                        .into(),
                                );
                            }
                        }
                        let opts = crate::security::ReadLdbOptions {
                            target: resolved_target,
                            query: args
                                .get("query")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            show_secrets,
                            global_path: state.global_path.clone(),
                        };
                        let rep = crate::security::execute_read_ldb_command(&opts)?;
                        return if want_json {
                            Ok(serde_json::to_string_pretty(&rep)?)
                        } else {
                            Ok(crate::security::format_read_ldb_report(&rep))
                        };
                    }
                    _ => {}
                }
            }
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
            let first_file_hint = if action == "grep" {
                args.get("subpath")
                    .and_then(Value::as_str)
                    .or_else(|| files_arr.first().map(String::as_str))
            } else {
                target_opt
                    .or_else(|| files_arr.first().map(String::as_str))
                    .or_else(|| slices_arr.first().map(|s| s.target.as_str()))
            };
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
            let want_json = args
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|f| f.eq_ignore_ascii_case("json"));

            let allow_ws_infer = matches!(action, "impact" | "locate" | "grep")
                || (action == "fim"
                    && first_file_hint.is_none()
                    && (sym.is_some() || !symbols_arr.is_empty()));
            let (ws_root, containment_root) = state.resolve_authorized_code_workspace(
                raw_cwd_arg,
                first_file_hint,
                allow_ws_infer,
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
                    check_target_access(&ws_root)?;
                    let mut requests: Vec<FimSliceRequest> = Vec::new();
                    let resolved_explicit: Vec<(PathBuf, FimSliceRequest)>;

                    if !slices_arr.is_empty() {
                        requests.extend(slices_arr);
                    } else if !symbols_arr.is_empty() {
                        if let Some(target) = target_opt.or_else(|| files_arr.first().map(String::as_str)) {
                            for s in &symbols_arr {
                                requests.push(FimSliceRequest {
                                    target: target.to_owned(),
                                    symbol: Some(s.clone()),
                                    line: None,
                                    pad,
                                });
                            }
                        }
                    } else if let Some(target) = target_opt {
                        let mut final_target = target.to_owned();
                        let mut final_line = line;
                        if final_line.is_none() && sym.is_none() {
                            let (stripped, line_suffix) = crate::split_path_and_line_suffix(target);
                            if let Some(ln) = line_suffix {
                                if !resolve_rel(target).exists() {
                                    final_target = stripped.to_owned();
                                    final_line = Some(ln);
                                }
                            }
                        }
                        requests.push(FimSliceRequest {
                            target: final_target,
                            symbol: sym.map(ToOwned::to_owned),
                            line: final_line,
                            pad,
                        });
                    } else if sym.is_none() {
                        return Err("Missing 'target' file path or 'symbol'/'symbols' query for action='fim'".into());
                    }

                    if requests.is_empty() {
                        // File-less symbol resolution across workspace code graph
                        state.run_locked_workspace_index(
                            &proj_db,
                            &ws_root,
                            &ws_root,
                            Some(&ws_root_str),
                            cid_arg,
                        )?;
                        let queries: Vec<String> = if !symbols_arr.is_empty() {
                            symbols_arr.clone()
                        } else if let Some(s) = sym {
                            vec![s.to_owned()]
                        } else {
                            Vec::new()
                        };
                        if queries.len() > MAX_BATCH_SYMBOL_QUERIES {
                            return Err(format!(
                                "Requested FIM symbol batch ({}) exceeds maximum allowed ({MAX_BATCH_SYMBOL_QUERIES})",
                                queries.len()
                            )
                            .into());
                        }
                        let located = locate_symbols(&proj_db, &queries)?;
                        if located.is_empty() {
                            return Err(format!(
                                "No symbol matched {:?} in workspace '{}'",
                                queries,
                                ws_root.display()
                            )
                            .into());
                        }
                        let cap = if queries.len() == 1 { 4 } else { MAX_BATCH_FIM_SLICES };
                        let mut seen_keys: std::collections::HashSet<(PathBuf, String)> =
                            std::collections::HashSet::new();
                        let mut auto_resolved: Vec<(PathBuf, FimSliceRequest)> = Vec::new();
                        for m in &located {
                            if auto_resolved.len() >= cap {
                                break;
                            }
                            let rp = resolve_rel(&m.file_path);
                            check_target_access(&rp)?;
                            state.verify_target_belongs_to_workspace(&rp, &ws_root)?;
                            if seen_keys.insert((rp.clone(), m.qualified_name.clone())) {
                                auto_resolved.push((
                                    rp,
                                    FimSliceRequest {
                                        target: m.file_path.clone(),
                                        symbol: Some(m.qualified_name.clone()),
                                        line: None,
                                        pad,
                                    },
                                ));
                            }
                        }
                        resolved_explicit = auto_resolved;
                    } else {
                        if requests.len() > MAX_BATCH_FIM_SLICES {
                            return Err(format!(
                                "Requested FIM slice batch ({}) exceeds maximum allowed ({MAX_BATCH_FIM_SLICES})",
                                requests.len()
                            )
                            .into());
                        }
                        let mut manual_resolved: Vec<(PathBuf, FimSliceRequest)> =
                            Vec::with_capacity(requests.len());
                        for mut req in requests {
                            if req.line.is_none() && req.symbol.is_none() {
                                let (stripped, line_suffix) =
                                    crate::split_path_and_line_suffix(&req.target);
                                if let Some(ln) = line_suffix {
                                    if !resolve_rel(&req.target).exists() {
                                        req.target = stripped.to_owned();
                                        req.line = Some(ln);
                                    }
                                }
                            }
                            let rp = resolve_rel(&req.target);
                            check_target_access(&rp)?;
                            state.verify_target_belongs_to_workspace(&rp, &ws_root)?;
                            manual_resolved.push((rp, req));
                        }
                        state.run_locked_workspace_index(
                            &proj_db,
                            &ws_root,
                            &ws_root,
                            Some(&ws_root_str),
                            cid_arg,
                        )?;
                        resolved_explicit = manual_resolved;
                    }

                    let mut bundles = Vec::with_capacity(resolved_explicit.len());
                    let mut unique_files: std::collections::HashSet<PathBuf> =
                        std::collections::HashSet::new();
                    let mut raw_file_tok_sum = 0u64;

                    for (rp, req) in &resolved_explicit {
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
                "grep" => {
                    check_target_access(&ws_root)?;
                    let pattern = target_opt
                        .or(sym)
                        .ok_or("Missing 'target' search pattern for action='grep'")?;
                    let sub_rp = if let Some(sub) = args
                        .get("subpath")
                        .and_then(Value::as_str)
                        .or_else(|| files_arr.first().map(String::as_str))
                    {
                        let rp = resolve_rel(sub);
                        check_target_access(&rp)?;
                        state.verify_target_belongs_to_workspace(&rp, &ws_root)?;
                        Some(rp)
                    } else {
                        None
                    };
                    let ext_list: Vec<String> = args
                        .get("extensions")
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    let opts = WorkspaceGrepOptions {
                        fixed_strings: args
                            .get("fixed_strings")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        ignore_case: args
                            .get("ignore_case")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        word_boundary: args
                            .get("word_boundary")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        max_matches: args
                            .get("max_matches")
                            .and_then(Value::as_u64)
                            .unwrap_or(80) as usize,
                        context_lines: args
                            .get("context")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as usize,
                        extensions: ext_list,
                        include_symbols: true,
                    };
                    let mut report = grep_workspace(
                        &ws_root,
                        sub_rp.as_deref(),
                        pattern,
                        Some(&proj_db),
                        &opts,
                    )?;
                    let prev_len = report.matches.len();
                    report.matches.retain(|m| {
                        let rp = resolve_rel(&m.file_path);
                        check_target_access(&rp).is_ok()
                            && state.verify_target_belongs_to_workspace(&rp, &ws_root).is_ok()
                    });
                    if report.matches.len() != prev_len {
                        let uniq: std::collections::HashSet<&str> = report
                            .matches
                            .iter()
                            .map(|m| m.file_path.as_str())
                            .collect();
                        report.files_matched = uniq.len();
                        report.total_matches = report.matches.len();
                    }
                    let rendered = if want_json {
                        serde_json::to_string_pretty(&report)?
                    } else {
                        format_grep_report_compact(&report)
                    };
                    let emitted_tok = ((rendered.len() + 3) / 4) as u64;
                    let baseline_tok = ((report.files_matched.max(1) * 320)
                        .max(report.files_searched * 18)) as u64;
                    record_workspace_event(
                        &ws_root,
                        TelemetryEvent::Impact {
                            baseline_tokens: baseline_tok.max(emitted_tok),
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
                if let (Some(id), Some(outcome)) = (
                    lr.get("id").and_then(Value::as_str),
                    lr.get("outcome").and_then(Value::as_str),
                ) {
                    let success = match outcome.trim().to_ascii_lowercase().as_str() {
                        "pass" | "success" | "ok" | "true" => true,
                        "fail" | "failure" | "err" | "false" => false,
                        other => {
                            return Err(format!(
                                "Unsupported learn_reflex.outcome '{other}' (expected pass/fail)"
                            )
                            .into())
                        }
                    };
                    let new_util = ReflexEngine::record_reflex_outcome(&proj_db, id, success)?;
                    outputs.push(format!(
                        "Recorded {} outcome for reflex '{id}' (utility={new_util:.2})",
                        if success { "pass" } else { "fail" }
                    ));
                } else if let (Some(id), Some(dir)) = (
                    lr.get("id").and_then(Value::as_str),
                    lr.get("directive").and_then(Value::as_str),
                ) {
                    let rule = ReflexRule {
                        id: id.to_owned(),
                        stack_any: parse_arr("stack"),
                        action_any: parse_arr("action"),
                        env_or_error_any: parse_arr("env"),
                        context_tags: parse_arr("context_tags"),
                        supersedes: parse_arr("supersedes"),
                        base_utility: lr
                            .get("base_utility")
                            .and_then(Value::as_f64)
                            .map(|u| u.clamp(0.10, 0.99)),
                        directive: dir.to_owned(),
                        code_anchors: parse_arr("anchors"),
                        ..Default::default()
                    };
                    let nid = ReflexEngine::learn_reflex(&proj_db, &rule)?;
                    outputs.push(format!("Learned reflex '{id}' (#{nid})"));
                }
            }

            if let Some(le) = args.get("learn_error").and_then(Value::as_object) {
                if let (Some(err_txt), Some(fix_dir)) = (
                    le.get("error_text").and_then(Value::as_str),
                    le.get("fix_directive").and_then(Value::as_str),
                ) {
                    let parse_le_arr = |k: &str| -> Vec<String> {
                        le.get(k)
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(Value::as_str)
                                    .map(ToOwned::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    let action_hint = le.get("action_hint").and_then(Value::as_str);
                    let syms = parse_le_arr("symbols");
                    let sup = parse_le_arr("supersedes");
                    match libredb_cognitive::learn_explicit_error_resolution(
                        &proj_db,
                        err_txt,
                        fix_dir,
                        action_hint,
                        &syms,
                        &sup,
                    )? {
                        Some(entry) => {
                            outputs.push(format!(
                                "Learned error recovery pitfall '{}' (conf={:.2})",
                                entry.id, entry.confidence
                            ));
                        }
                        None => {
                            outputs.push("Filtered banal syntax slip at Stage 1 gate".to_owned());
                        }
                    }
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
