//! Native sub-millisecond Antigravity lifecycle hooks (`PreInvocation` and `PreToolUse`)
//! with silent background `SQLite -> LibreDB` auto-migration on first workspace/chat touch.

use libredb_bridge::open_or_auto_migrate;
use libredb_cognitive::{
    check_command_guardrails, check_text_guardrails_with_options, has_project_root_marker,
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

const MIN_VALID_LDB_BYTES: u64 = 8192;
const MAX_HOOK_STDIN_BYTES: u64 = 16 * 1024 * 1024;

fn read_bounded_hook_stdin() -> io::Result<(String, bool)> {
    let mut buf = Vec::with_capacity(4096);
    io::stdin()
        .take(MAX_HOOK_STDIN_BYTES + 1)
        .read_to_end(&mut buf)?;
    if (buf.len() as u64) > MAX_HOOK_STDIN_BYTES {
        buf.truncate(MAX_HOOK_STDIN_BYTES as usize);
        Ok((String::from_utf8_lossy(&buf).into_owned(), true))
    } else {
        Ok((String::from_utf8_lossy(&buf).into_owned(), false))
    }
}

pub fn open_global_ldb(override_path: Option<&Path>) -> Result<Arc<LibreDb>, String> {
    let target = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_global_ldb_path);
    match std::fs::symlink_metadata(&target) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to open symlinked global customizations.ldb at '{}'",
                    target.display()
                ));
            }
            if !meta.is_file() || meta.len() < MIN_VALID_LDB_BYTES {
                return Err(format!(
                    "Existing global customizations.ldb at '{}' is truncated or invalid (length {} bytes < {MIN_VALID_LDB_BYTES}); refusing to auto-reinitialize",
                    target.display(),
                    meta.len()
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = target.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
        }
        Err(e) => {
            return Err(format!(
                "Failed to inspect global customizations.ldb metadata at '{}': {e}",
                target.display()
            ));
        }
    }
    // Never implicitly import legacy `~/.gemini/database/customizations.db` on cold CLI opens;
    // legacy SQLite migration requires explicit `--migrate-legacy` or `libredb import-sqlite`.
    let (db, _) = open_or_auto_migrate(&target, None, "central").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
    }
    Ok(db)
}

/// Opens `customizations.ldb` when present on disk, returning `Ok(None)` ONLY when the file genuinely
/// does not exist (`ErrorKind::NotFound`), and returning `Err` if `customizations.ldb` exists (or
/// cannot be inspected) yet is symlinked, truncated (`< 8192` bytes), or fails `LibreDb::open`.
/// Prevents a corrupted or 0-byte truncated `customizations.ldb` from masquerading as an unconfigured host.
pub fn open_global_ldb_checked(override_path: Option<&Path>) -> Result<Option<Arc<LibreDb>>, String> {
    let target = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_global_ldb_path);
    match std::fs::symlink_metadata(&target) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to open symlinked global customizations.ldb at '{}'",
                    target.display()
                ));
            }
            if !meta.is_file() || meta.len() < MIN_VALID_LDB_BYTES {
                return Err(format!(
                    "Existing global customizations.ldb at '{}' is truncated or invalid (length {} bytes < {MIN_VALID_LDB_BYTES}); refusing to auto-reinitialize",
                    target.display(),
                    meta.len()
                ));
            }
            LibreDb::open(&target)
                .map(|db| Some(Arc::new(db)))
                .map_err(|e| {
                    format!(
                        "Failed to open existing global customizations.ldb at '{}': {e}",
                        target.display()
                    )
                })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Failed to inspect global customizations.ldb metadata at '{}': {e}",
            target.display()
        )),
    }
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
pub fn run_pre_tool_hook(global_ldb_opt: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let (raw, exceeded) = match read_bounded_hook_stdin() {
        Ok(pair) => pair,
        Err(e) => {
            emit_json(&json!({
                "decision": "deny",
                "reason": format!("LibreDB PreToolUse failed to read hook stdin: {e}")
            }))?;
            return Ok(());
        }
    };
    if exceeded {
        emit_json(&json!({
            "decision": "deny",
            "reason": "LibreDB PreToolUse hook payload exceeded 16 MiB safety limit."
        }))?;
        return Ok(());
    }
    let trimmed = raw.trim();
    let payload: Value = if trimmed.is_empty() {
        json!({})
    } else {
        match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                emit_json(&json!({
                    "decision": "deny",
                    "reason": format!("LibreDB PreToolUse rejected malformed JSON payload: {e}")
                }))?;
                return Ok(());
            }
        }
    };

    let response = evaluate_pre_tool_payload(&payload, global_ldb_opt);
    emit_json(&response)?;
    Ok(())
}

/// Pure, directly unit-testable `PreToolUse` evaluator enforcing fail-closed behavior whenever
/// `customizations.ldb` exists on disk yet is corrupted, truncated, or symlinked.
pub(crate) fn evaluate_pre_tool_payload(payload: &Value, global_ldb_opt: Option<&Path>) -> Value {
    let (tool_name, args) = extract_pre_tool_name_and_args(payload);
    let mut global_db_cache: Option<Result<Option<Arc<LibreDb>>, String>> = None;
    let mut get_global_db_checked = || -> Result<Option<Arc<LibreDb>>, String> {
        global_db_cache
            .get_or_insert_with(|| open_global_ldb_checked(global_ldb_opt))
            .clone()
    };

    // 0. Opt-in Subagent Model Router (`hook:subagent_flash_routing = true`): off by default on
    // enterprise-neutral installations so corporate agent configurations keep their chosen models.
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
            let gdb_opt = get_global_db_checked().ok().flatten();
            if !model_str.eq_ignore_ascii_case("flash")
                && !model_str.eq_ignore_ascii_case("flash_lite")
                && crate::security::load_bool_config(
                    gdb_opt.as_deref(),
                    None,
                    "hook:subagent_flash_routing",
                    false,
                )
            {
                return json!({
                    "decision": "allow",
                    "overwrite": { "Model": "flash" }
                });
            }
        }
    }

    // 1. Shell command security guardrails + opt-in exploratory search streak firewall
    let cmd_opt = args
        .get("CommandLine")
        .or_else(|| args.get("command"))
        .and_then(Value::as_str);

    if let Some(cmd_line) = cmd_opt {
        if let Some(v) = check_command_guardrails(cmd_line) {
            return json!({
                "decision": "deny",
                "reason": format!("LibreDB Guardrail Blocked Command ({}): {}", v.rule, v.message)
            });
        }

        let gdb_opt = match get_global_db_checked() {
            Ok(opt) => opt,
            Err(err) => {
                return json!({
                    "decision": "deny",
                    "reason": format!(
                        "LibreDB PreToolUse failed closed because global customizations.ldb could not be verified: {err}"
                    )
                });
            }
        };
        if let Some(ref gdb) = gdb_opt {
            if let Err(err) = crate::security::check_global_trust_sync(gdb) {
                return json!({
                    "decision": "deny",
                    "reason": format!(
                        "LibreDB PreToolUse failed closed because global customizations.ldb could not synchronize: {err}"
                    )
                });
            }
        }

        // Opt-in Subagent Firewall (`hook:exploratory_firewall = true`, off by default on neutral installs)
        if is_exploratory_search_cmd(cmd_line)
            && crate::security::load_bool_config(
                gdb_opt.as_deref(),
                None,
                "hook:exploratory_firewall",
                false,
            )
        {
            if let Some((cid, t_path)) = resolve_cid_and_transcript(payload) {
                if !cid.is_empty() && t_path.is_file() && count_recent_exploratory_streak(&t_path) >= 4 {
                    return json!({
                        "decision": "deny",
                        "reason": "LibreDB Subagent Firewall (Rule 5): 4+ consecutive exploratory shell search commands executed in main context. Delegate open multi-file searching to invoke_subagent(TypeName='research', Model='flash') or use libredb_code(action='skeleton'|'fim'|'impact')."
                    });
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
        .or_else(|| args.get("target_file"))
        .or_else(|| args.get("filename"))
        .and_then(Value::as_str)
        .unwrap_or("<tool_input>");

    let is_explicit_write_tool = matches!(
        tool_name,
        "write_file"
            | "edit_file"
            | "write_to_file"
            | "replace_file_content"
            | "multi_replace_file_content"
            | "delete_file"
            | "remove_file"
            | "rename_file"
            | "move_file"
    );
    let is_write_or_edit = is_explicit_write_tool
        || args.get("Content").is_some()
        || args.get("Replacement").is_some()
        || args.get("ReplacementChunks").is_some()
        || args.get("CodeContent").is_some()
        || args.get("ReplacementContent").is_some()
        || args.get("content").is_some()
        || args.get("replacement").is_some()
        || args.get("new_string").is_some();

    if is_write_or_edit {
        if is_explicit_write_tool && target_file == "<tool_input>" {
            return json!({
                "decision": "deny",
                "reason": "LibreDB Control-Plane Guardrail Blocked Write: missing target file path in write/edit tool invocation."
            });
        }
        let global_db_ro = match get_global_db_checked() {
            Ok(opt) => opt,
            Err(err) => {
                return json!({
                    "decision": "deny",
                    "reason": format!(
                        "LibreDB Control-Plane Guardrail failed closed because global customizations.ldb could not be verified: {err}"
                    )
                });
            }
        };
        if let Some(ref gdb) = global_db_ro {
            if let Err(err) = crate::security::check_global_trust_sync(gdb) {
                return json!({
                    "decision": "deny",
                    "reason": format!(
                        "LibreDB Control-Plane Guardrail failed closed because global customizations.ldb could not synchronize: {err}"
                    )
                });
            }
        }
        let proj_db_ro = if target_file != "<tool_input>" {
            find_workspace_root(Path::new(target_file)).and_then(|root| {
                if crate::security::is_workspace_memory_trusted(global_db_ro.as_deref(), &root) {
                    let ldb_p = root.join(".agents").join("memory.ldb");
                    ldb_p.is_file().then(|| LibreDb::open(&ldb_p).ok()).flatten()
                } else {
                    None
                }
            })
        } else {
            None
        };

        if target_file != "<tool_input>" {
            let custom_protected = crate::security::load_config_list(
                global_db_ro.as_deref(),
                proj_db_ro.as_ref(),
                "guardrail:protected_paths",
            );
            let hook_ws = resolve_hook_workspace(payload, None).or_else(|| env::current_dir().ok());
            if let Some(reason) = crate::security::check_tool_write_path_policy_with_base(
                target_file,
                hook_ws.as_deref(),
                &custom_protected,
            ) {
                return json!({
                    "decision": "deny",
                    "reason": format!("LibreDB Control-Plane Guardrail Blocked Write: {reason}")
                });
            }
        }

        if !is_test_or_scratch_path(target_file) {
            let custom_prefixes = crate::security::load_config_list(
                global_db_ro.as_deref(),
                proj_db_ro.as_ref(),
                "guardrail:secret_prefixes",
            );
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

            let enforce_style = crate::security::load_bool_config(
                global_db_ro.as_deref(),
                proj_db_ro.as_ref(),
                "guardrail:style_rules",
                false,
            );
            let is_full_file = matches!(tool_name, "write_file" | "write_to_file")
                && args.get("Append").and_then(Value::as_bool) != Some(true);
            for txt in texts_to_check {
                let violations = check_text_guardrails_with_options(
                    txt,
                    target_file,
                    is_full_file,
                    &custom_prefixes,
                );
                if let Some(first_crit) = violations.into_iter().find(|v| {
                    v.severity == "CRITICAL"
                        && (enforce_style
                            || !matches!(v.rule.as_str(), "no-em-en-dash" | "no-emojis"))
                }) {
                    return json!({
                        "decision": "deny",
                        "reason": format!(
                            "LibreDB Guardrail Blocked Code Modification ({}): {} In snippet: '{}'",
                            first_crit.rule, first_crit.message, first_crit.snippet
                        )
                    });
                }
            }
        }

        if target_file != "<tool_input>" && !is_test_or_scratch_path(target_file) {
            let target_path = Path::new(target_file);
            let _ = record_working_set_edit(target_path, global_db_ro.as_deref());
        }
    }

    json!({ "decision": "allow" })
}

/// Handles Antigravity `PreInvocation` JSON hook from `stdin` (`< 2.5 ms` warm, `< 30 ms` on first-time SQLite auto-port).
pub fn run_pre_invocation_hook(
    global_ldb_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok((raw, exceeded)) = read_bounded_hook_stdin() else {
        emit_json(&json!({ "injectSteps": [] }))?;
        return Ok(());
    };
    if exceeded {
        emit_json(&json!({ "injectSteps": [] }))?;
        return Ok(());
    }
    let payload: Value = serde_json::from_str(raw.trim()).unwrap_or_else(|_| json!({}));
    let response = evaluate_pre_invocation_payload(&payload, global_ldb_opt)?;
    emit_json(&response)?;
    Ok(())
}

/// Pure, directly unit-testable `PreInvocation` evaluator enforcing fail-closed workspace trust
/// both before opening `.agents/memory.*` and immediately after any legacy SQLite `.db -> .ldb` migration.
pub(crate) fn evaluate_pre_invocation_payload(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (cid_opt, transcript_opt) = match resolve_cid_and_transcript(payload) {
        Some((c, tp)) => (Some(c), Some(tp)),
        None => (None, None),
    };

    let ws_root = resolve_hook_workspace(payload, transcript_opt.as_deref());
    let target_ldb: Option<PathBuf> = if let Some(ref root) = ws_root {
        Some(root.join(".agents").join("memory.ldb"))
    } else if let Some(ref cid) = cid_opt {
        let brain_agents = resolve_brain_conv_dir(cid).join(".agents");
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
        return Ok(json!({ "injectSteps": [] }));
    };

    // If neither `.agents/memory.ldb` nor `.agents/memory.db` exists yet in this folder, wait until
    // the agent or workspace actually creates project memory rather than polluting random folders.
    let mem_db_sibling = mem_ldb_path.with_extension("db");
    if !mem_ldb_path.exists() && !mem_db_sibling.exists() {
        return Ok(json!({ "injectSteps": [] }));
    }

    // Cryptographic workspace trust check BEFORE opening `.ldb` or migrating any C SQLite `.db` file!
    // Prevents cloned repositories carrying poisoned `.agents/memory.*` payloads from injecting
    // `<SYSTEM_MESSAGE>` prompt overrides or triggering untrusted SQLite deserialization, and fails
    // closed immediately if an existing `customizations.ldb` is corrupted/unreadable on disk.
    if let Some(ref root) = ws_root {
        let Ok(global_db_ro) = open_global_ldb_checked(global_ldb_opt) else {
            return Ok(json!({ "injectSteps": [] }));
        };
        if !crate::security::is_workspace_memory_trusted(global_db_ro.as_deref(), root) {
            return Ok(json!({ "injectSteps": [] }));
        }
    }

    let Ok((proj_db, did_migrate)) = open_project_ldb_silent(&mem_ldb_path) else {
        return Ok(json!({ "injectSteps": [] }));
    };

    // Strict fail-closed post-migration sealing: if an authorized legacy `.agents/memory.db` was just
    // migrated into `.agents/memory.ldb`, it MUST be cryptographically sealed with `hmac-sha256:v4:r<rev>:`
    // BEFORE recording any dedup cursor or reading/injecting a single capsule from `proj_db`.
    // If sealing fails for any reason, emit ONLY the quarantine diagnostic and zero project content.
    if did_migrate {
        if let Some(ref root) = ws_root {
            if !crate::security::is_private_brain_workspace(root) {
                let seal_outcome: Result<(), String> = if is_protected_profile_dir(root) {
                    Err("workspace resolves to a protected profile directory".to_owned())
                } else {
                    match open_global_ldb_checked(global_ldb_opt) {
                        Ok(Some(global_db)) => crate::security::seal_workspace_memory(
                            &global_db, &proj_db, root,
                        )
                        .map(|()| {
                            let norm = crate::security::normalize_workspace_key(root);
                            let ws_cfg_key = crate::security::workspace_id_config_key(&norm);
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
                        }),
                        Ok(None) => Err("global customizations.ldb is unavailable".to_owned()),
                        Err(e) => Err(e),
                    }
                };

                if let Err(err) = seal_outcome {
                    eprintln!(
                        "[WARN] LibreDB post-migration seal failed for '{}': {err}",
                        root.display()
                    );
                    let diag = format!(
                        "[WARN] Quarantined migrated workspace '{}': post-migration hmac-sha256:v4 workspace seal failed ({err}); project memory context suppressed.",
                        root.display()
                    );
                    return Ok(json!({
                        "injectSteps": [{
                            "systemMessage": {
                                "systemMessage": diag
                            }
                        }]
                    }));
                }
            }
        }
    }

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
                    return Ok(json!({ "injectSteps": [] }));
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

    // Record workspace discovery metadata in `customizations.ldb` on first session touch without
    // ever re-sealing an existing `.ldb` file automatically.
    if !did_migrate && (!had_prior_cursor || global_ldb_opt.is_some()) {
        if let Some(ref root) = ws_root {
            if !is_protected_profile_dir(root) {
                if let Ok(Some(global_db)) = open_global_ldb_checked(global_ldb_opt) {
                    let norm = crate::security::normalize_workspace_key(root);
                    let ws_cfg_key = crate::security::workspace_id_config_key(&norm);
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

    let context_block = build_project_memory_hydration(&proj_db, ws_root.as_deref());
    if context_block.is_empty() {
        Ok(json!({ "injectSteps": [] }))
    } else {
        Ok(json!({
            "injectSteps": [{
                "systemMessage": {
                    "systemMessage": context_block
                }
            }]
        }))
    }
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
    let head_path = git_dir.join("HEAD");
    let head_meta = std::fs::symlink_metadata(&head_path).ok()?;
    if head_meta.file_type().is_symlink() || !head_meta.is_file() || head_meta.len() > 4096 {
        return None;
    }
    let head_raw = std::fs::read_to_string(&head_path).ok()?;
    let head_trimmed = head_raw.trim();
    if let Some(ref_rel) = head_trimmed.strip_prefix("ref: ") {
        let ref_rel = ref_rel.trim();
        let raw_branch = ref_rel.strip_prefix("refs/heads/").unwrap_or(ref_rel);
        let branch = crate::security::sanitize_git_ref_for_prompt(raw_branch);
        let valid_ref_rel = ref_rel.starts_with("refs/")
            && !ref_rel.contains("..")
            && !ref_rel.contains('\\')
            && !ref_rel.contains(':')
            && !ref_rel.bytes().any(|b| b < 0x20);
        let ref_file = git_dir.join(ref_rel);
        let ref_file_ok = valid_ref_rel
            && std::fs::symlink_metadata(&ref_file)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.is_file() && m.len() <= 256);
        let packed_path = git_dir.join("packed-refs");
        let packed_ok = valid_ref_rel
            && std::fs::symlink_metadata(&packed_path).is_ok_and(|m| {
                !m.file_type().is_symlink() && m.is_file() && m.len() <= 4 * 1024 * 1024
            });
        let short_hash = if ref_file_ok {
            std::fs::read_to_string(&ref_file)
                .ok()
                .map(|hash_raw| {
                    hash_raw
                        .trim()
                        .chars()
                        .filter(char::is_ascii_hexdigit)
                        .take(7)
                        .collect::<String>()
                })
                .unwrap_or_else(|| "unborn".to_owned())
        } else if packed_ok {
            std::fs::read_to_string(&packed_path)
                .ok()
                .and_then(|packed| {
                    packed.lines().find_map(|l| {
                        let l = l.trim();
                        if l.starts_with('#') || l.starts_with('^') {
                            return None;
                        }
                        let mut parts = l.split_whitespace();
                        let h = parts.next()?;
                        let r = parts.next()?;
                        if r == ref_rel {
                            Some(
                                h.chars()
                                    .filter(char::is_ascii_hexdigit)
                                    .take(7)
                                    .collect::<String>(),
                            )
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| "unborn".to_owned())
        } else {
            "unborn".to_owned()
        };
        let safe_hash = if short_hash.is_empty() {
            "unborn"
        } else {
            &short_hash
        };
        Some(format!("Git Telemetry: branch '{branch}' @ {safe_hash}"))
    } else {
        let short_hash: String = head_trimmed
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(7)
            .collect();
        if short_hash.is_empty() {
            None
        } else {
            Some(format!("Git Telemetry: branch 'HEAD' @ {short_hash}"))
        }
    }
}

fn record_working_set_edit(target_file: &Path, global_db: Option<&LibreDb>) -> Result<(), String> {
    let Some(root) = find_workspace_root(target_file) else {
        return Ok(());
    };
    let ldb_path = root.join(".agents").join("memory.ldb");
    let db_sibling = ldb_path.with_extension("db");
    if !ldb_path.exists() && !db_sibling.exists() {
        return Ok(());
    }
    if !crate::security::is_workspace_memory_trusted(global_db, &root) {
        return Ok(());
    }
    let (proj_db, did_migrate) = open_project_ldb_silent(&ldb_path)?;
    if did_migrate && !crate::security::is_private_brain_workspace(&root) {
        let gdb = global_db.ok_or_else(|| {
            "global customizations.ldb is required to seal migrated workspace".to_owned()
        })?;
        crate::security::seal_workspace_memory(gdb, &proj_db, &root)?;
    }
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

    // Allow dedicated Antigravity scratch workspaces (`~/.gemini/antigravity*/scratch/<project>`)
    for prod in ["antigravity", "antigravity-ide", "antigravity-cli"] {
        let scratch_prefix = format!("{home_trim}\\.gemini\\{prod}\\scratch\\");
        if low.starts_with(&scratch_prefix)
            && trimmed.len() > scratch_prefix.trim_end_matches('\\').len()
        {
            return false;
        }
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
        || low.starts_with("\\etc\\")
        || trimmed == "\\etc"
        || low.starts_with("\\usr\\")
        || trimmed == "\\usr"
        || low.starts_with("\\proc\\")
        || trimmed == "\\proc"
        || low.starts_with("\\sys\\")
        || trimmed == "\\sys"
        || low.starts_with("\\dev\\")
        || trimmed == "\\dev"
        || low.starts_with("\\run\\")
        || trimmed == "\\run"
        || low.starts_with("\\var\\tmp\\")
        || trimmed == "\\var\\tmp"
}

/// Resolves `<appDataDir>/brain/<cid>` across Antigravity 2.0 (`antigravity`),
/// Antigravity IDE (`antigravity-ide`), and Antigravity CLI (`antigravity-cli`).
pub fn resolve_brain_conv_dir(cid: &str) -> PathBuf {
    let gemini = user_home_dir().join(".gemini");
    for prod in ["antigravity", "antigravity-ide", "antigravity-cli"] {
        let cand = gemini.join(prod).join("brain").join(cid);
        if cand.is_dir() {
            return cand;
        }
    }
    gemini.join("antigravity").join("brain").join(cid)
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
    let conv_dir = payload
        .get("artifactDirectoryPath")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| {
            payload
                .get("brainDir")
                .and_then(Value::as_str)
                .map(|b| PathBuf::from(b).join(cid))
        })
        .unwrap_or_else(|| resolve_brain_conv_dir(cid));
    let t_path = conv_dir
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
        .or_else(|| tc.get("tool_name"))
        .or_else(|| tc.get("tool"))
        .or_else(|| tc.get("name"))
        .or_else(|| payload.get("toolName"))
        .or_else(|| payload.get("tool_name"))
        .or_else(|| payload.get("tool"))
        .or_else(|| payload.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");

    let args = tc
        .get("toolInput")
        .or_else(|| tc.get("toolArgs"))
        .or_else(|| tc.get("tool_args"))
        .or_else(|| tc.get("parameters"))
        .or_else(|| tc.get("arguments"))
        .or_else(|| tc.get("args"))
        .or_else(|| tc.get("input"))
        .or_else(|| payload.get("toolInput"))
        .or_else(|| payload.get("toolArgs"))
        .or_else(|| payload.get("tool_args"))
        .or_else(|| payload.get("parameters"))
        .or_else(|| payload.get("arguments"))
        .or_else(|| payload.get("args"))
        .or_else(|| payload.get("input"))
        .unwrap_or(tc);

    (tool_name, args)
}

#[cfg(test)]
mod tests {
    use super::extract_pre_tool_name_and_args;
    use serde_json::json;
    use std::fs;

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

    #[test]
    fn failed_post_migration_seal_fails_closed_and_injects_zero_project_memory() {
        use super::evaluate_pre_invocation_payload;
        use libredb_core::{LibreDb, NodeKind, WriteRequest};
        use std::fs;

        let base_target = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "test_pre_inv_mig_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
        let _ = fs::remove_dir_all(&base_target);
        let ws_repo = base_target.join("legacy_mig_repo");
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        fs::write(ws_repo.join("Cargo.toml"), b"[package]\nname = \"demo\"\n").unwrap();

        // 1. Seed a real legacy `.agents/memory.db` SQLite store containing sensitive project memory:
        let legacy_sqlite = ws_repo.join(".agents").join("memory.db");
        {
            let conn = rusqlite::Connection::open(&legacy_sqlite).unwrap();
            conn.execute_batch(
                "CREATE TABLE fact_history (id INTEGER PRIMARY KEY, key TEXT NOT NULL, old_value TEXT, new_value TEXT NOT NULL);
                 INSERT INTO fact_history (key, old_value, new_value) VALUES ('secret_key', NULL, 'SECRET_MIGRATED_FACT_MUST_NOT_LEAK');
                 CREATE TABLE project_decisions (id INTEGER PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, category TEXT, is_active INTEGER NOT NULL DEFAULT 1);
                 INSERT INTO project_decisions (title, content, category, is_active) VALUES ('secret_arch', 'SECRET_MIGRATED_DECISION_MUST_NOT_LEAK', 'security', 1);",
            )
            .unwrap();
        }
        assert!(!ws_repo.join(".agents").join("memory.ldb").exists());

        // 2. Authorize `ws_repo` in an isolated `customizations.ldb`, then corrupt `sys::trust_anchor_secret`
        //    so pre-migration path authorization succeeds (`!ldb_path.is_file() && path_authorized`),
        //    SQLite -> `.ldb` migration succeeds (`did_migrate == true`), and `seal_workspace_memory` FAILS!
        let global_ldb_path = base_target.join("customizations.ldb");
        {
            let gdb = LibreDb::open(&global_ldb_path).unwrap();
            gdb.put(
                WriteRequest::new(
                    NodeKind::Config,
                    ws_repo.to_string_lossy().as_bytes().to_vec(),
                )
                .with_key("workspace:legacy_mig_repo"),
            )
            .unwrap();
            gdb.put(
                WriteRequest::new(NodeKind::Config, b"corrupt-non-hex-secret".to_vec())
                    .with_key("sys::trust_anchor_secret"),
            )
            .unwrap();
        }

        let payload = json!({
            "conversationId": "conv-mig-fail-closed-test",
            "workspacePaths": [ws_repo.to_string_lossy().to_string()]
        });

        let out1 = evaluate_pre_invocation_payload(&payload, Some(&global_ldb_path)).unwrap();
        let out1_str = serde_json::to_string(&out1).unwrap();

        // Migration ran (`.agents/memory.ldb` now exists and holds the ported capsules on disk),
        // `[WARN]` diagnostic WAS emitted, and ZERO project memory capsules or headers were injected!
        let ported_ldb = LibreDb::open(ws_repo.join(".agents").join("memory.ldb")).unwrap();
        assert!(ported_ldb.get_by_key(NodeKind::Fact, "secret_key").is_ok());
        drop(ported_ldb);

        assert!(
            out1_str.contains("[WARN] Quarantined migrated workspace"),
            "Expected fail-closed diagnostic warning, got: {out1_str}"
        );
        assert!(
            !out1_str.contains("SECRET_MIGRATED_FACT_MUST_NOT_LEAK"),
            "Migrated Fact leaked despite post-migration seal failure: {out1_str}"
        );
        assert!(
            !out1_str.contains("SECRET_MIGRATED_DECISION_MUST_NOT_LEAK"),
            "Migrated Decision leaked despite post-migration seal failure: {out1_str}"
        );
        assert!(
            !out1_str.contains("PROJECT MEMORY CONTEXT"),
            "Project memory context header must not be emitted on seal failure: {out1_str}"
        );

        // Subsequent invocation sees unsealed `.agents/memory.ldb` and fails closed before opening:
        let out2 = evaluate_pre_invocation_payload(&payload, Some(&global_ldb_path)).unwrap();
        assert_eq!(out2, json!({ "injectSteps": [] }));

        let _ = fs::remove_dir_all(&base_target);
    }

    #[test]
    fn pre_tool_use_fails_closed_when_customizations_ldb_is_corrupted_and_blocks_missing_write_path() {
        let tmp = std::env::temp_dir().join(format!(
            "libredb_pre_tool_fail_closed_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(&tmp).unwrap();
        let corrupt_global = tmp.join("customizations.ldb");
        fs::write(&corrupt_global, b"truncated_corrupt_header").unwrap();

        let cmd_payload = json!({
            "toolName": "run_command",
            "toolArgs": { "CommandLine": "echo hello" }
        });
        let cmd_out = super::evaluate_pre_tool_payload(&cmd_payload, Some(&corrupt_global));
        assert_eq!(
            cmd_out.get("decision").and_then(serde_json::Value::as_str),
            Some("deny"),
            "run_command MUST fail closed when customizations.ldb is corrupted: {cmd_out}"
        );

        let write_payload = json!({
            "toolName": "write_file",
            "toolArgs": { "Path": tmp.join("src.rs").to_string_lossy().to_string(), "Content": "fn main() {}\n" }
        });
        let write_out = super::evaluate_pre_tool_payload(&write_payload, Some(&corrupt_global));
        assert_eq!(
            write_out.get("decision").and_then(serde_json::Value::as_str),
            Some("deny"),
            "write_file MUST fail closed when customizations.ldb is corrupted: {write_out}"
        );

        let missing_path_write = json!({
            "toolName": "write_file",
            "toolArgs": { "Content": "fn sneaky() {}\n" }
        });
        let missing_out = super::evaluate_pre_tool_payload(&missing_path_write, None);
        assert_eq!(
            missing_out.get("decision").and_then(serde_json::Value::as_str),
            Some("deny"),
            "write_file omitting Path MUST be denied fail-closed: {missing_out}"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn git_telemetry_blocks_dotdot_ref_traversal() {
        let tmp = std::env::temp_dir().join(format!(
            "libredb_git_telemetry_traversal_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let repo = tmp.join("sub").join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        let secret_outside = tmp.join("outside_hex_secret");
        fs::write(&secret_outside, "deadbeefcafe1234\n").unwrap();
        fs::write(
            repo.join(".git").join("HEAD"),
            "ref: ../../outside_hex_secret\n",
        )
        .unwrap();

        let line = super::collect_git_telemetry_line(&repo).unwrap();
        assert!(
            !line.contains("deadbee"),
            "collect_git_telemetry_line MUST NEVER read files via '..' ref traversal: {line}"
        );
        assert!(line.ends_with("@ unborn"), "Unexpected telemetry line: {line}");

        let _ = fs::remove_dir_all(&tmp);
    }
}
