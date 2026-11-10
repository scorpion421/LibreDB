//! Native sub-millisecond Antigravity lifecycle hooks (`PreInvocation` and `PreToolUse`)
//! with silent background `SQLite -> LibreDB` auto-migration on first workspace/chat touch.

use libredb_bridge::open_or_auto_migrate;
use libredb_cognitive::{
    check_command_guardrails, check_text_guardrails, has_project_root_marker,
    is_compaction_checkpoint_line, is_test_or_scratch_path, sync_transcript_epoch, CognitiveEngine,
};
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde_json::{json, Value};
use std::env;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn default_global_ldb_path() -> PathBuf {
    user_home_dir()
        .join(".gemini")
        .join("libredb")
        .join("customizations.ldb")
}

pub fn default_central_sqlite_path() -> PathBuf {
    user_home_dir()
        .join(".gemini")
        .join("database")
        .join("customizations.db")
}

pub fn open_global_ldb(override_path: Option<&Path>) -> Result<Arc<LibreDb>, String> {
    let target = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_global_ldb_path);
    let central_sql = default_central_sqlite_path();
    let (db, migrated) = open_or_auto_migrate(&target, Some(&central_sql), "central")
        .map_err(|e| e.to_string())?;
    if migrated.is_some() {
        if let Ok(mut cog) = CognitiveEngine::open_db(Arc::clone(&db)) {
            let _ = cog.save_index_snapshot();
        }
    }
    Ok(db)
}

pub fn open_project_ldb_silent(ldb_path: &Path) -> Result<(Arc<LibreDb>, bool), String> {
    let (db, migrated) =
        open_or_auto_migrate(ldb_path, None, "project").map_err(|e| e.to_string())?;
    let did_migrate = migrated.is_some();
    if did_migrate {
        if let Ok(mut cog) = CognitiveEngine::open_db(Arc::clone(&db)) {
            let _ = cog.save_index_snapshot();
        }
    }
    Ok((db, did_migrate))
}

/// Handles Antigravity `PreToolUse` JSON hook from `stdin` (`< 1.5 ms`).
pub fn run_pre_tool_hook(_global_ldb_opt: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    let _ = io::stdin().read_to_string(&mut raw);
    let payload: Value = serde_json::from_str(raw.trim()).unwrap_or_else(|_| json!({}));

    let (tool_name, args) = extract_pre_tool_name_and_args(&payload);

    // 0. Subagent Model Enforcer (Rule 5 & Rule 7): automatically route read-only `research`
    // subagents to `Model="flash"` so they never burn `Argon High` / `Claude` code-gen quota.
    if tool_name == "invoke_subagent" {
        let type_name = args
            .get("TypeName")
            .or_else(|| args.get("typeName"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if type_name.eq_ignore_ascii_case("research") {
            let model_str = args
                .get("Model")
                .or_else(|| args.get("model"))
                .and_then(Value::as_str)
                .unwrap_or("inherit");
            if !model_str.eq_ignore_ascii_case("flash")
                && !model_str.eq_ignore_ascii_case("flash_lite")
            {
                emit_json(&json!({
                    "decision": "allow",
                    "overwrite": { "Model": "flash" }
                }))?;
                return Ok(());
            }
        }
    }

    // 1. Shell command guardrails + automatic WaitMsBeforeAsync upgrade to 10000ms
    let cmd_opt = args
        .get("CommandLine")
        .or_else(|| args.get("command"))
        .and_then(Value::as_str);

    if let Some(cmd_line) = cmd_opt {
        if let Some(v) = check_command_guardrails(cmd_line) {
            emit_json(&json!({
                "decision": "deny",
                "reason": format!("LibreDB Guardrail Blocked Command ({}): {}", v.rule, v.message)
            }))?;
            return Ok(());
        }

        // Subagent Firewall: block >= 4 consecutive exploratory shell searches in main context
        if is_exploratory_search_cmd(cmd_line) {
            if let Some((cid, t_path)) = resolve_cid_and_transcript(&payload) {
                if !cid.is_empty() && t_path.is_file() && count_recent_exploratory_streak(&t_path) >= 4 {
                    emit_json(&json!({
                        "decision": "deny",
                        "reason": "LibreDB Subagent Firewall (Rule 5): 4+ consecutive exploratory shell search commands executed in main context. Delegate open multi-file searching to invoke_subagent(TypeName='research', Model='flash') or use libredb_code(action='skeleton'|'fim'|'impact')."
                    }))?;
                    return Ok(());
                }
            }
        }

        let is_daemon = args.get("IsDaemon").and_then(Value::as_bool).unwrap_or(false);
        if !is_daemon {
            if let Some(wait_val) = args.get("WaitMsBeforeAsync") {
                if let Some(w_i64) = wait_val.as_i64() {
                    if w_i64 > 0 && w_i64 < 10_000 {
                        emit_json(&json!({
                            "decision": "allow",
                            "overwrite": { "WaitMsBeforeAsync": 10000 }
                        }))?;
                        return Ok(());
                    }
                } else if let Some(w_str) = wait_val.as_str() {
                    if let Ok(w_i64) = w_str.parse::<i64>() {
                        if w_i64 > 0 && w_i64 < 10_000 {
                            emit_json(&json!({
                                "decision": "allow",
                                "overwrite": { "WaitMsBeforeAsync": "10000" }
                            }))?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    // 2. File write/edit guardrails + silent WorkingSet tracking in .agents/memory.ldb
    let target_file = args
        .get("Path")
        .or_else(|| args.get("TargetFile"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("<tool_input>");

    let is_write_or_edit = matches!(
        tool_name,
        "write_file"
            | "edit_file"
            | "write_to_file"
            | "replace_file_content"
            | "multi_replace_file_content"
    ) || args.get("Content").is_some()
        || args.get("Replacement").is_some()
        || args.get("ReplacementChunks").is_some();

    if is_write_or_edit {
        if !is_test_or_scratch_path(target_file) {
            let mut texts_to_check: Vec<&str> = Vec::new();
            for k in [
                "Content",
                "Replacement",
                "CodeContent",
                "ReplacementContent",
                "content",
                "replacement",
                "new_string",
            ] {
                if let Some(s) = args.get(k).and_then(Value::as_str) {
                    texts_to_check.push(s);
                }
            }
            if let Some(chunks) = args.get("ReplacementChunks").and_then(Value::as_array) {
                for ch in chunks {
                    if let Some(s) = ch
                        .get("ReplacementContent")
                        .or_else(|| ch.get("Replacement"))
                        .and_then(Value::as_str)
                    {
                        texts_to_check.push(s);
                    }
                }
            }

            for txt in texts_to_check {
                let violations = check_text_guardrails(txt, target_file);
                if let Some(first_crit) = violations.into_iter().find(|v| v.severity == "CRITICAL")
                {
                    emit_json(&json!({
                        "decision": "deny",
                        "reason": format!(
                            "LibreDB Guardrail Blocked Code Modification ({}): {} In snippet: '{}'",
                            first_crit.rule, first_crit.message, first_crit.snippet
                        )
                    }))?;
                    return Ok(());
                }
            }
        }

        if target_file != "<tool_input>" && !is_test_or_scratch_path(target_file) {
            let target_path = Path::new(target_file);
            if matches!(
                tool_name,
                "edit_file" | "replace_file_content" | "multi_replace_file_content"
            ) {
                normalize_file_crlf_and_bom_before_edit(target_path);
            }
            let _ = record_working_set_edit(target_path);
        }
    }

    emit_json(&json!({ "decision": "allow" }))?;
    Ok(())
}

/// Handles Antigravity `PreInvocation` JSON hook from `stdin` (`< 2.5 ms` warm, `< 30 ms` on first-time SQLite auto-port).
pub fn run_pre_invocation_hook(
    global_ldb_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    let _ = io::stdin().read_to_string(&mut raw);
    let payload: Value = serde_json::from_str(raw.trim()).unwrap_or_else(|_| json!({}));

    let (cid_opt, transcript_opt) = match resolve_cid_and_transcript(&payload) {
        Some((c, tp)) => (Some(c), Some(tp)),
        None => (None, None),
    };

    let ws_root = resolve_hook_workspace(&payload, transcript_opt.as_deref());
    let target_ldb: Option<PathBuf> = if let Some(ref root) = ws_root {
        Some(root.join(".agents").join("memory.ldb"))
    } else if let Some(ref cid) = cid_opt {
        let brain_agents = user_home_dir()
            .join(".gemini")
            .join("antigravity")
            .join("brain")
            .join(cid)
            .join(".agents");
        let cand_ldb = brain_agents.join("memory.ldb");
        let cand_db = brain_agents.join("memory.db");
        if cand_ldb.exists() || cand_db.exists() {
            Some(cand_ldb)
        } else {
            None
        }
    } else {
        None
    };

    let Some(mem_ldb_path) = target_ldb else {
        emit_json(&json!({ "injectSteps": [] }))?;
        return Ok(());
    };

    // If neither `.agents/memory.ldb` nor `.agents/memory.db` exists yet in this folder, wait until
    // the agent or workspace actually creates project memory rather than polluting random folders.
    let mem_db_sibling = mem_ldb_path.with_extension("db");
    if !mem_ldb_path.exists() && !mem_db_sibling.exists() {
        emit_json(&json!({ "injectSteps": [] }))?;
        return Ok(());
    }

    let Ok((proj_db, _did_migrate)) = open_project_ldb_silent(&mem_ldb_path) else {
        emit_json(&json!({ "injectSteps": [] }))?;
        return Ok(());
    };

    let mut epoch = 1u32;
    if let (Some(ref cid), Some(ref tp)) = (&cid_opt, &transcript_opt) {
        if tp.is_file() {
            epoch = sync_transcript_epoch(&proj_db, cid, tp).unwrap_or(1);
        }
    }

    let ws_key = ws_root
        .as_ref()
        .map(|p| {
            p.to_string_lossy()
                .replace('\\', "/")
                .trim_end_matches('/')
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|| "__chat__".to_owned());
    let dedup_token = format!("{ws_key}@ep={epoch}");

    let mut had_prior_cursor = false;
    if let Some(ref cid) = cid_opt {
        let proj_cur_key = format!("sys::pre_inv_dedup::{cid}");
        if let Ok(cur_rec) = proj_db.get_by_key(NodeKind::TranscriptCursor, &proj_cur_key) {
            had_prior_cursor = true;
            if let Ok(cur_json) = serde_json::from_slice::<Value>(&cur_rec.payload) {
                if cur_json.get("dedup_token").and_then(Value::as_str) == Some(dedup_token.as_str())
                {
                    emit_json(&json!({ "injectSteps": [] }))?;
                    return Ok(());
                }
            }
        }
        let next_cur = json!({
            "conversation_id": cid,
            "epoch_count": epoch,
            "dedup_token": dedup_token,
            "inferred_workspace": ws_key,
        });
        if let Ok(bytes) = serde_json::to_vec(&next_cur) {
            let _ = proj_db.put(
                WriteRequest::new(NodeKind::TranscriptCursor, bytes)
                    .with_key(proj_cur_key)
                    .with_importance(64),
            );
        }
    }

    // Only touch global `customizations.ldb` on the first turn in a workspace (or when an explicit
    // `--db` override is passed) so routine turns never contend on or dirty `customizations.ldb`.
    if !had_prior_cursor || global_ldb_opt.is_some() {
        if let Some(ref root) = ws_root {
            if !is_protected_profile_dir(root) {
                if let Some(name) = root.file_name().and_then(|n| n.to_str()) {
                    if let Ok(global_db) = open_global_ldb(global_ldb_opt) {
                        let ws_cfg_key = format!("workspace:{name}");
                        let root_str = root.to_string_lossy().into_owned();
                        let already_same = global_db
                            .get_by_key(NodeKind::Config, &ws_cfg_key)
                            .map(|r| r.payload == root_str.as_bytes())
                            .unwrap_or(false);
                        if !already_same {
                            let _ = global_db.put(
                                WriteRequest::new(NodeKind::Config, root_str.into_bytes())
                                    .with_key(ws_cfg_key)
                                    .with_importance(170),
                            );
                        }
                    }
                }
            }
        }
    }

    let context_block = build_project_memory_hydration(&proj_db, ws_root.as_deref());
    if context_block.is_empty() {
        emit_json(&json!({ "injectSteps": [] }))?;
    } else {
        emit_json(&json!({
            "injectSteps": [{
                "ephemeralMessage": context_block
            }]
        }))?;
    }
    Ok(())
}

fn build_project_memory_hydration(proj_db: &LibreDb, ws_root: Option<&Path>) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(root) = ws_root {
        if let Some(git_line) = collect_git_telemetry_line(root) {
            lines.push(git_line);
        }
    }

    let inodes = proj_db.list_inodes(None, false);
    let mut task_ids: Vec<u64> = Vec::new();
    let mut handoff_ids: Vec<u64> = Vec::new();
    let mut decision_ids: Vec<u64> = Vec::new();
    let mut fact_ids: Vec<(u64, u64)> = Vec::new();

    for (ino, _, _) in &inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        match ino.kind {
            NodeKind::Task => task_ids.push(ino.node_id),
            NodeKind::Handoff => handoff_ids.push(ino.node_id),
            NodeKind::Decision => decision_ids.push(ino.node_id),
            NodeKind::Fact => fact_ids.push((ino.updated_ns, ino.node_id)),
            _ => {}
        }
    }

    // Open tasks (skip completed/done/closed/cancelled)
    if !task_ids.is_empty() {
        task_ids.sort_unstable();
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&task_ids) {
            let open_tasks: Vec<String> = recs
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
                .filter(|t| {
                    let low = t.to_ascii_lowercase();
                    !low.contains(" completed ")
                        && !low.contains("| done |")
                        && !low.contains("| completed |")
                        && !low.contains("| closed |")
                        && !low.contains("| cancelled |")
                })
                .take(5)
                .collect();
            if !open_tasks.is_empty() {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push("Active Task Board:".to_owned());
                for t in open_tasks {
                    let first = t.lines().next().unwrap_or(&t);
                    lines.push(format!("  * {first}"));
                }
            }
        }
    }

    // Pending handoffs
    if !handoff_ids.is_empty() {
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&handoff_ids) {
            let pending: Vec<String> = recs
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
                .filter(|h| h.contains("(pending)"))
                .take(3)
                .collect();
            if !pending.is_empty() {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push("Pending Subagent Handoffs:".to_owned());
                for h in pending {
                    let first = h.lines().next().unwrap_or(&h);
                    lines.push(format!("  * {first}"));
                }
            }
        }
    }

    // Most recent 12 active facts
    if !fact_ids.is_empty() {
        fact_ids.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let top_fids: Vec<u64> = fact_ids.into_iter().take(12).map(|(_, id)| id).collect();
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&top_fids) {
            if !recs.is_empty() {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push("Project Facts (.agents/memory.ldb):".to_owned());
                for r in recs {
                    let txt = String::from_utf8_lossy(&r.payload);
                    lines.push(format!("  * {}", txt.trim()));
                }
            }
        }
    }

    // Active architectural decisions (up to 5)
    if !decision_ids.is_empty() {
        decision_ids.sort_by(|a, b| b.cmp(a));
        decision_ids.truncate(5);
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&decision_ids) {
            if !recs.is_empty() {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push("Active Architectural Decisions:".to_owned());
                for r in recs {
                    let txt = String::from_utf8_lossy(&r.payload);
                    let flat = txt.lines().collect::<Vec<_>>().join(" ");
                    lines.push(format!("  * {}", flat.trim()));
                }
            }
        }
    }

    // Latest snapshot or compaction checkpoint
    if let Ok(snap) = proj_db.get_by_key(NodeKind::Snapshot, "latest_snapshot") {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Latest Milestone Snapshot:".to_owned());
        for sl in String::from_utf8_lossy(&snap.payload).lines().take(5) {
            lines.push(format!("  {sl}"));
        }
    } else if let Ok(cp) = proj_db.get_by_key(NodeKind::CompactionCheckpoint, "latest_compaction") {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Latest Compaction Checkpoint:".to_owned());
        for cl in String::from_utf8_lossy(&cp.payload).lines().take(3) {
            lines.push(format!("  {cl}"));
        }
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!(
            "=== PROJECT MEMORY CONTEXT (LibreDB .agents/memory.ldb) ===\n{}",
            lines.join("\n")
        )
    }
}

fn collect_git_telemetry_line(root: &Path) -> Option<String> {
    let git_dir = root.join(".git");
    let head_raw = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head_trimmed = head_raw.trim();
    if let Some(ref_rel) = head_trimmed.strip_prefix("ref: ") {
        let ref_rel = ref_rel.trim();
        let branch = ref_rel
            .strip_prefix("refs/heads/")
            .unwrap_or(ref_rel)
            .to_owned();
        let ref_file = git_dir.join(ref_rel);
        let short_hash = if let Ok(hash_raw) = std::fs::read_to_string(&ref_file) {
            hash_raw.trim().chars().take(7).collect::<String>()
        } else if let Ok(packed) = std::fs::read_to_string(git_dir.join("packed-refs")) {
            packed
                .lines()
                .find_map(|l| {
                    let l = l.trim();
                    if l.starts_with('#') || l.starts_with('^') {
                        return None;
                    }
                    let mut parts = l.split_whitespace();
                    let h = parts.next()?;
                    let r = parts.next()?;
                    if r == ref_rel {
                        Some(h.chars().take(7).collect::<String>())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "unborn".to_owned())
        } else {
            "unborn".to_owned()
        };
        Some(format!("Git Telemetry: branch '{branch}' @ {short_hash}"))
    } else {
        let short_hash: String = head_trimmed.chars().take(7).collect();
        if short_hash.is_empty() {
            None
        } else {
            Some(format!("Git Telemetry: branch 'HEAD' @ {short_hash}"))
        }
    }
}

fn record_working_set_edit(target_file: &Path) -> Result<(), String> {
    let Some(root) = find_workspace_root(target_file) else {
        return Ok(());
    };
    let ldb_path = root.join(".agents").join("memory.ldb");
    let db_sibling = ldb_path.with_extension("db");
    if !ldb_path.exists() && !db_sibling.exists() {
        return Ok(());
    }
    let (proj_db, _) = open_project_ldb_silent(&ldb_path)?;
    let rel_key = target_file
        .strip_prefix(&root)
        .unwrap_or(target_file)
        .to_string_lossy()
        .replace('\\', "/");

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);

    let mut prev_edits = 0u64;
    if let Ok(r) = proj_db.get_by_key(NodeKind::WorkingSet, &rel_key) {
        // Coalesce rapid consecutive edits to the same file within 60 seconds to avoid delta-log spam.
        if now_ns.saturating_sub(r.updated_ns) < 60_000_000_000 {
            return Ok(());
        }
        let s = String::from_utf8_lossy(&r.payload);
        prev_edits = s
            .split("edits=")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
    }
    let next_edits = prev_edits + 1;
    let body = format!("[WorkingSet edits={next_edits}] {rel_key}");
    proj_db
        .put(
            WriteRequest::new(NodeKind::WorkingSet, body.into_bytes())
                .with_key(rel_key)
                .with_importance(180),
        )
        .map_err(|e| e.to_string())?;
    let _ = proj_db.maybe_auto_compact();
    Ok(())
}

fn normalize_file_crlf_and_bom_before_edit(path: &Path) {
    if !path.is_file() {
        return;
    }
    let Ok(raw) = std::fs::read(path) else {
        return;
    };
    let probe = raw.len().min(4096);
    if raw[..probe].contains(&0u8) {
        return;
    }
    let has_bom = raw.starts_with(&[0xEF, 0xBB, 0xBF]);
    let body = if has_bom { &raw[3..] } else { &raw[..] };
    let has_crlf = body.windows(2).any(|w| w == b"\r\n");
    if !has_bom && !has_crlf {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let normalized = text.replace("\r\n", "\n");
    let _ = std::fs::write(path, normalized.as_bytes());
}

fn resolve_hook_workspace(payload: &Value, transcript_opt: Option<&Path>) -> Option<PathBuf> {
    if let Some(arr) = payload.get("workspacePaths").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                let p = PathBuf::from(s);
                if p.is_dir() && !is_protected_profile_dir(&p) {
                    if let Some(root) = find_workspace_root(&p) {
                        if !is_protected_profile_dir(&root) {
                            return Some(root);
                        }
                    }
                    return Some(p);
                }
            }
        }
    }
    if let Some(tp) = transcript_opt {
        if let Some(inferred) = infer_workspace_from_transcript(tp) {
            return Some(inferred);
        }
    }
    None
}

fn infer_workspace_from_transcript(transcript_path: &Path) -> Option<PathBuf> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(transcript_path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let read_len = len.min(65_536);
    let offset = len - read_len;
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; read_len as usize];
    f.read_exact(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);

    for line in text.lines().rev().take(40) {
        for key in ["\"Path\":", "\"TargetFile\":", "\"cwd\":", "\"SearchPath\":", "\"DirectoryPath\":"] {
            let mut rest = line;
            while let Some(pos) = rest.find(key) {
                rest = &rest[pos + key.len()..];
                let trimmed = rest.trim_start();
                if let Some(after_quote) = trimmed.strip_prefix('"') {
                    if let Some(end_q) = after_quote.find('"') {
                        let raw_p = after_quote[..end_q].replace("\\\\", "\\");
                        let candidate = PathBuf::from(&raw_p);
                        if candidate.exists() && !is_protected_profile_dir(&candidate) {
                            if let Some(root) = find_workspace_root(&candidate) {
                                if !is_protected_profile_dir(&root) {
                                    return Some(root);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let dir = if start.is_file() {
        start.parent()?
    } else {
        start
    };
    if is_protected_profile_dir(dir) {
        return None;
    }
    let mut curr = Some(dir);
    while let Some(c) = curr {
        if c.parent().is_none() || is_protected_profile_dir(c) {
            break;
        }
        if has_project_root_marker(c) {
            return Some(c.to_path_buf());
        }
        curr = c.parent();
    }
    None
}

pub fn is_protected_profile_dir(p: &Path) -> bool {
    let low = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    let trimmed = low.trim_end_matches('\\');

    let home_trim = user_home_dir()
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_owned();
    let temp_trim = env::temp_dir()
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_owned();

    let temp_prefix = format!("{temp_trim}\\");
    if trimmed == home_trim || trimmed == temp_trim || low.starts_with(&temp_prefix) {
        return true;
    }

    // Allow dedicated Antigravity scratch workspaces (`~/.gemini/antigravity/scratch/<project>`)
    let scratch_prefix = format!("{home_trim}\\.gemini\\antigravity\\scratch\\");
    if low.starts_with(&scratch_prefix) && trimmed.len() > scratch_prefix.trim_end_matches('\\').len() {
        return false;
    }

    trimmed == format!("{home_trim}\\appdata")
        || trimmed == format!("{home_trim}\\appdata\\local")
        || trimmed == format!("{home_trim}\\appdata\\roaming")
        || low.contains("\\appdata\\local\\temp\\")
        || trimmed.ends_with("\\appdata\\local\\temp")
        || low.contains("\\.gemini\\")
        || trimmed.ends_with("\\.gemini")
        || low.contains("\\appdata\\local\\programs")
        || low.contains("\\appdata\\local\\antigravity")
        || low.contains("\\appdata\\roaming\\antigravity")
        || low.contains("\\windows\\")
        || trimmed.ends_with("\\windows")
        || low.contains("\\program files")
}

fn resolve_cid_and_transcript(payload: &Value) -> Option<(String, PathBuf)> {
    let cid = payload
        .get("conversationId")
        .or_else(|| payload.get("cid"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains('\\'))?;
    if let Some(tp_str) = payload
        .get("transcriptPath")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some((cid.to_owned(), PathBuf::from(tp_str)));
    }
    let brain_base = payload
        .get("brainDir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home_dir().join(".gemini").join("antigravity").join("brain"));
    let t_path = brain_base
        .join(cid)
        .join(".system_generated")
        .join("logs")
        .join("transcript.jsonl");
    Some((cid.to_owned(), t_path))
}

fn is_exploratory_search_cmd(cmd: &str) -> bool {
    let low = cmd.trim().to_ascii_lowercase();
    low.starts_with("select-string ")
        || low.starts_with("grep ")
        || low.starts_with("rg ")
        || low.starts_with("findstr ")
        || low.contains("| select-string ")
        || (low.starts_with("get-childitem ") && low.contains("-recurse"))
}

fn count_recent_exploratory_streak(transcript_path: &Path) -> usize {
    use std::io::{Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(transcript_path) else {
        return 0;
    };
    let Ok(meta) = f.metadata() else {
        return 0;
    };
    let fsize = meta.len();
    if fsize == 0 {
        return 0;
    }
    let read_len = fsize.min(131_072);
    let offset = fsize - read_len;
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return 0;
    }
    let mut buf = vec![0u8; read_len as usize];
    if f.read_exact(&mut buf).is_err() {
        return 0;
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if offset > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let mut streak = 0usize;
    for line in lines.into_iter().rev().take(30) {
        if line.contains("\"USER_INPUT\"")
            || line.contains("\"USER_EXPLICIT\"")
            || line.contains("\"invoke_subagent\"")
            || is_compaction_checkpoint_line(line)
        {
            break;
        }
        if line.contains("\"PLANNER_RESPONSE\"") && line.contains("\"run_command\"") {
            if let Ok(obj) = serde_json::from_str::<Value>(line) {
                let mut had_run = false;
                let mut had_exp = false;
                if let Some(tcs) = obj.get("tool_calls").and_then(Value::as_array) {
                    for tc in tcs {
                        let nm = tc
                            .get("name")
                            .or_else(|| tc.get("function").and_then(|f| f.get("name")))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if nm == "run_command" {
                            had_run = true;
                            let prev_cmd = tc
                                .get("args")
                                .or_else(|| tc.get("arguments"))
                                .and_then(|a| a.get("CommandLine"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            if is_exploratory_search_cmd(prev_cmd) {
                                had_exp = true;
                            }
                        }
                    }
                }
                if had_run {
                    if had_exp {
                        streak += 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    streak
}

fn emit_json(val: &Value) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{val}")?;
    out.flush()
}

pub fn user_home_dir() -> PathBuf {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
}

fn extract_pre_tool_name_and_args(payload: &Value) -> (&str, &Value) {
    let tc = payload
        .get("toolCall")
        .or_else(|| payload.get("tool_call"))
        .unwrap_or(payload);

    let tool_name = tc
        .get("toolName")
        .or_else(|| tc.get("tool"))
        .or_else(|| tc.get("name"))
        .or_else(|| payload.get("toolName"))
        .or_else(|| payload.get("tool"))
        .or_else(|| payload.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let args = tc
        .get("toolInput")
        .or_else(|| tc.get("parameters"))
        .or_else(|| tc.get("arguments"))
        .or_else(|| tc.get("args"))
        .or_else(|| payload.get("toolInput"))
        .or_else(|| payload.get("parameters"))
        .or_else(|| payload.get("arguments"))
        .or_else(|| payload.get("args"))
        .unwrap_or(tc);

    (tool_name, args)
}

#[cfg(test)]
mod tests {
    use super::extract_pre_tool_name_and_args;
    use serde_json::json;

    #[test]
    fn extract_pre_tool_unwraps_nested_tool_call_and_flat_payloads() {
        let nested = json!({
            "conversationId": "06c3256c-1245-4193-9a93-a7f106e123f4",
            "toolCall": {
                "name": "invoke_subagent",
                "args": {
                    "TypeName": "research",
                    "Model": "inherit"
                }
            }
        });
        let (name_n, args_n) = extract_pre_tool_name_and_args(&nested);
        assert_eq!(name_n, "invoke_subagent");
        assert_eq!(args_n.get("TypeName").and_then(|v| v.as_str()), Some("research"));

        let flat = json!({
            "toolName": "run_command",
            "toolInput": {
                "CommandLine": "cargo test",
                "WaitMsBeforeAsync": 5000
            }
        });
        let (name_f, args_f) = extract_pre_tool_name_and_args(&flat);
        assert_eq!(name_f, "run_command");
        assert_eq!(args_f.get("WaitMsBeforeAsync").and_then(|v| v.as_i64()), Some(5000));
    }
}
