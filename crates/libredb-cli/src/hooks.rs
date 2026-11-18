//! Native sub-millisecond Antigravity lifecycle hooks (`PreInvocation` and `PreToolUse`)
//! powered by single-file pure-Rust `LibreDB` storage and optional in-memory `MCP` coordination.

use libredb_cognitive::{
    check_command_guardrails, check_text_guardrails_with_options, has_project_root_marker,
    is_compaction_checkpoint_line, is_test_or_scratch_path, sync_transcript_epoch,
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
    let db = Arc::new(LibreDb::open(&target).map_err(|e| e.to_string())?);
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

pub fn open_project_ldb_silent(ldb_path: &Path) -> Result<Arc<LibreDb>, String> {
    LibreDb::open(ldb_path).map(Arc::new).map_err(|e| e.to_string())
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

    let response = crate::ipc::try_invoke_ipc_hook("pre_tool", global_ldb_opt, &payload)
        .unwrap_or_else(|| evaluate_pre_tool_payload(&payload, global_ldb_opt));
    emit_json(&response)?;
    Ok(())
}

/// Pure, directly unit-testable `PreToolUse` evaluator enforcing fail-closed behavior whenever
/// `customizations.ldb` exists on disk yet is corrupted, truncated, or symlinked.
pub(crate) fn evaluate_pre_tool_payload(payload: &Value, global_ldb_opt: Option<&Path>) -> Value {
    evaluate_pre_tool_payload_inner(payload, global_ldb_opt, None)
}

/// In-RAM IPC variant of `PreToolUse` reusing `McpServerState`'s open `global_db` and cached
/// workspace brains without reopening `.ldb` files from disk.
pub(crate) fn evaluate_pre_tool_payload_with_ram_state(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
    ram_state: &mut crate::mcp::McpServerState,
) -> Value {
    evaluate_pre_tool_payload_inner(payload, global_ldb_opt, Some(ram_state))
}

fn evaluate_pre_tool_payload_inner(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
    mut ram_state: Option<&mut crate::mcp::McpServerState>,
) -> Value {
    let (tool_name, args) = extract_pre_tool_name_and_args(payload);
    let ram_synced_global = ram_state.is_some();
    let mut global_db_cache: Option<Result<Option<Arc<LibreDb>>, String>> =
        ram_state.as_deref_mut().map(|st| {
            st.sync_global_db_or_purge()
                .map(|()| st.global_db.clone())
        });
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
        if !ram_synced_global {
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
        if !ram_synced_global {
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
        }
        let trusted_ws = if target_file != "<tool_input>" {
            find_workspace_root(Path::new(target_file)).and_then(|root| {
                if let Some(ref mut st) = ram_state {
                    if let Some(cached_pdb) = st.lookup_or_cache_trusted_workspace_db(&root) {
                        return Some((root, Some(cached_pdb)));
                    }
                }
                if crate::security::is_workspace_memory_trusted(global_db_ro.as_deref(), &root) {
                    let ldb_p = root.join(".agents").join("memory.ldb");
                    let opened = ldb_p
                        .is_file()
                        .then(|| LibreDb::open(&ldb_p).ok().map(Arc::new))
                        .flatten();
                    Some((root, opened))
                } else {
                    None
                }
            })
        } else {
            None
        };
        let proj_db_ro = trusted_ws.as_ref().and_then(|(_, db_opt)| db_opt.as_deref());

        if target_file != "<tool_input>" {
            let custom_protected = crate::security::load_config_list(
                global_db_ro.as_deref(),
                proj_db_ro,
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
            if crate::security::load_bool_config(
                global_db_ro.as_deref(),
                proj_db_ro,
                "guardrail:multi_edit_guard",
                true,
            ) {
                if let Some(reason) = check_ambiguous_multi_edit_hazard(
                    Path::new(target_file),
                    target_file,
                    tool_name,
                    &args,
                ) {
                    return json!({
                        "decision": "deny",
                        "reason": reason
                    });
                }
            }
        }

        if !is_test_or_scratch_path(target_file) {
            let custom_prefixes = crate::security::load_config_list(
                global_db_ro.as_deref(),
                proj_db_ro,
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
                proj_db_ro,
                "guardrail:style_rules",
                false,
            );
            let is_full_file = matches!(tool_name, "write_file" | "write_to_file")
                && args.get("Append").and_then(Value::as_bool) != Some(true);
            for txt in texts_to_check {
                let mut violations = check_text_guardrails_with_options(
                    txt,
                    target_file,
                    is_full_file,
                    &custom_prefixes,
                );
                if enforce_style {
                    violations.extend(libredb_cognitive::check_german_prose_style(
                        txt,
                        target_file,
                    ));
                }
                if let Some(first_crit) = violations.into_iter().find(|v| {
                    v.severity == "CRITICAL"
                        && (enforce_style
                            || !matches!(
                                v.rule.as_str(),
                                "no-em-en-dash"
                                    | "no-emojis"
                                    | "german-ascii-umlaut"
                                    | "german-deppenbindestrich"
                            ))
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
            if let Some((ref ws_root, ref preopened_db)) = trusted_ws {
                let target_path = Path::new(target_file);
                let cid_transcript = resolve_cid_and_transcript(payload);
                let _ = record_working_set_edit(
                    ws_root,
                    preopened_db.clone(),
                    target_path,
                    tool_name,
                    &args,
                    global_db_ro.as_deref(),
                    cid_transcript.as_ref().map(|(c, p)| (c.as_str(), p.as_path())),
                );
            }
        }
    }

    json!({ "decision": "allow" })
}

/// Handles Antigravity `PreInvocation` JSON hook from `stdin` (`< 2 ms` warm, `< 0.5 ms` via IPC).
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
    let response = if let Some(ipc_resp) =
        crate::ipc::try_invoke_ipc_hook("pre_invocation", global_ldb_opt, &payload)
    {
        ipc_resp
    } else {
        evaluate_pre_invocation_payload(&payload, global_ldb_opt)?
    };
    emit_json(&response)?;
    Ok(())
}

/// Pure, directly unit-testable `PreInvocation` evaluator enforcing fail-closed workspace trust
/// before opening `.agents/memory.ldb`.
pub(crate) fn evaluate_pre_invocation_payload(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
) -> Result<Value, Box<dyn std::error::Error>> {
    evaluate_pre_invocation_payload_inner(payload, global_ldb_opt, None)
}

/// In-RAM IPC variant of `PreInvocation` reusing `McpServerState`'s open `global_db` and cached
/// workspace brains without reopening `.ldb` files from disk on every turn.
pub(crate) fn evaluate_pre_invocation_payload_with_ram_state(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
    ram_state: &mut crate::mcp::McpServerState,
) -> Result<Value, Box<dyn std::error::Error>> {
    evaluate_pre_invocation_payload_inner(payload, global_ldb_opt, Some(ram_state))
}

fn evaluate_pre_invocation_payload_inner(
    payload: &Value,
    global_ldb_opt: Option<&Path>,
    mut ram_state: Option<&mut crate::mcp::McpServerState>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (cid_opt, transcript_opt) = match resolve_cid_and_transcript(payload) {
        Some((c, tp)) => (Some(c), Some(tp)),
        None => (None, None),
    };

    let ws_root = resolve_hook_workspace(payload, transcript_opt.as_deref())
        .filter(|root| !crate::security::is_private_brain_workspace(root));
    let target_ldb: Option<PathBuf> = ws_root
        .as_ref()
        .map(|root| root.join(".agents").join("memory.ldb"));

    let Some(mem_ldb_path) = target_ldb else {
        return Ok(json!({ "injectSteps": [] }));
    };

    // If `.agents/memory.ldb` does not exist yet in this folder, wait until the agent or
    // workspace actually creates project memory rather than polluting random folders.
    if !mem_ldb_path.is_file() {
        return Ok(json!({ "injectSteps": [] }));
    }

    let mut cached_gdb_opt: Option<Option<Arc<LibreDb>>> = if let Some(ref mut st) = ram_state {
        if st.sync_global_db_or_purge().is_err() {
            return Ok(json!({ "injectSteps": [] }));
        }
        Some(st.global_db.clone())
    } else {
        None
    };
    let mut ensure_global_db = || -> Result<Option<Arc<LibreDb>>, String> {
        if let Some(ref opt) = cached_gdb_opt {
            return Ok(opt.clone());
        }
        let opened = open_global_ldb_checked(global_ldb_opt)?;
        cached_gdb_opt = Some(opened.clone());
        Ok(opened)
    };

    // Cryptographic workspace trust check BEFORE opening `.agents/memory.ldb`!
    // Prevents cloned repositories carrying poisoned `.agents/memory.ldb` payloads from injecting
    // `<SYSTEM_MESSAGE>` prompt overrides, and fails closed immediately if an existing
    // `customizations.ldb` is corrupted/unreadable on disk.
    let proj_db: Arc<LibreDb> =
        if let (Some(ref mut st), Some(ref root)) = (ram_state.as_deref_mut(), &ws_root) {
            let Some(pdb) = st.lookup_or_cache_trusted_workspace_db(root) else {
                return Ok(json!({ "injectSteps": [] }));
            };
            pdb
        } else {
            if let Some(ref root) = ws_root {
                let Ok(global_db_ro) = ensure_global_db() else {
                    return Ok(json!({ "injectSteps": [] }));
                };
                if !crate::security::is_workspace_memory_trusted(global_db_ro.as_deref(), root) {
                    return Ok(json!({ "injectSteps": [] }));
                }
            }
            let Ok(pdb) = open_project_ldb_silent(&mem_ldb_path) else {
                return Ok(json!({ "injectSteps": [] }));
            };
            pdb
        };

    if let Some(ref root) = ws_root {
        if let Ok((promoted, saved_tok)) =
            libredb_cognitive::reconcile_tentative_edits(&proj_db, root)
        {
            if promoted > 0 {
                crate::telemetry::record_workspace_event(
                    root,
                    crate::telemetry::TelemetryEvent::HookSymbolShift {
                        reread_tokens_avoided: saved_tok,
                    },
                );
            }
        }
    }

    let harvested_errors = if let (Some(ref cid), Some(ref tp)) = (&cid_opt, &transcript_opt) {
        if tp.is_file() {
            harvest_recent_transcript_errors(&proj_db, cid, tp, true)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let error_hint = harvested_errors.first().map(String::as_str);
    let has_sealed_reflex_for_error = error_hint
        .filter(|h| !h.trim().is_empty())
        .and_then(|err_s| {
            libredb_cognitive::ReflexEngine::load_sealed_only(&proj_db)
                .ok()
                .map(|rx| !rx.evaluate(ws_root.as_deref(), err_s, Some(err_s)).is_empty())
        })
        .unwrap_or(false);

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
                if !has_sealed_reflex_for_error
                    && cur_json.get("dedup_token").and_then(Value::as_str)
                        == Some(dedup_token.as_str())
                {
                    let evt = crate::telemetry::TelemetryEvent::HookHydration {
                        dedup_skipped: true,
                        baseline_tokens: 420,
                        emitted_tokens: 0,
                    };
                    if let Some(ref root) = ws_root {
                        crate::telemetry::record_workspace_event(root, evt);
                    } else {
                        crate::telemetry::record_event(evt);
                    }
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
    if !had_prior_cursor || global_ldb_opt.is_some() {
        if let Some(ref root) = ws_root {
            if !is_protected_profile_dir(root) {
                if let Ok(Some(global_db)) = ensure_global_db() {
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

    const STYLE_INVARIANT: &str = "Style Invariant: Informal German ('Du'), natural umlauts (never ae/oe/ue), closed German Komposita (zero Deppenbindestriche), zero em/en-dashes or emojis, 100% ASCII English in code/commits.";
    let gdb_opt = ensure_global_db().ok().flatten();
    let enforce_style = crate::security::load_bool_config(
        gdb_opt.as_deref(),
        Some(&proj_db),
        "guardrail:style_rules",
        false,
    );
    let hydration_cap = if enforce_style {
        MAX_PRE_INVOCATION_BYTES.saturating_sub(STYLE_INVARIANT.len() + 1)
    } else {
        MAX_PRE_INVOCATION_BYTES
    };
    let prompt_hint = extract_prompt_hint(payload, transcript_opt.as_deref());
    let (mut context_block, naive_baseline_bytes) = build_project_memory_hydration_with_cap(
        &proj_db,
        ws_root.as_deref(),
        prompt_hint.as_deref(),
        error_hint,
        hydration_cap,
    );
    if enforce_style
        && !context_block.is_empty()
        && context_block.len() + STYLE_INVARIANT.len() + 1 <= MAX_PRE_INVOCATION_BYTES
    {
        context_block.push('\n');
        context_block.push_str(STYLE_INVARIANT);
    }
    if context_block.is_empty() {
        Ok(json!({ "injectSteps": [] }))
    } else {
        let emitted_tok = ((context_block.len() + 3) / 4) as u64;
        let baseline_tok = ((naive_baseline_bytes + 3) / 4) as u64;
        let evt = crate::telemetry::TelemetryEvent::HookHydration {
            dedup_skipped: false,
            baseline_tokens: baseline_tok.max(emitted_tok),
            emitted_tokens: emitted_tok,
        };
        if let Some(ref root) = ws_root {
            crate::telemetry::record_workspace_event(root, evt);
        } else {
            crate::telemetry::record_event(evt);
        }
        Ok(json!({
            "injectSteps": [{
                "systemMessage": {
                    "systemMessage": context_block
                }
            }]
        }))
    }
}

const MAX_PRE_INVOCATION_BYTES: usize = 1_800;
/// Maximum learned reflex directives injected by `PreInvocation` per turn.
const MAX_PRE_INVOCATION_REFLEXES: usize = 2;

fn truncate_utf8_clean(s: &str, max_chars: usize) -> (&str, bool) {
    match s.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => (s[..byte_idx].trim_end(), true),
        None => (s, false),
    }
}

fn strip_tag_block(mut text: String, open_tag: &str, close_tag: &str) -> String {
    while let Some(start) = text.find(open_tag) {
        if let Some(rel_end) = text[start + open_tag.len()..].find(close_tag) {
            let end = start + open_tag.len() + rel_end + close_tag.len();
            text.replace_range(start..end, " ");
        } else {
            text.truncate(start);
            break;
        }
    }
    text
}

fn sanitize_prompt_hint_text(raw: &str) -> Option<String> {
    if let Some(u_start) = raw.find("<USER_REQUEST>") {
        let after = &raw[u_start + "<USER_REQUEST>".len()..];
        let inner = match after.find("</USER_REQUEST>") {
            Some(u_end) => &after[..u_end],
            None => after,
        };
        let t = inner.trim();
        if !t.is_empty() {
            let (head, _) = truncate_utf8_clean(t, 512);
            return Some(head.to_owned());
        }
    }
    let mut cleaned = raw.to_owned();
    for (o, c) in [
        ("<SYSTEM_MESSAGE>", "</SYSTEM_MESSAGE>"),
        ("<EPHEMERAL_MESSAGE>", "</EPHEMERAL_MESSAGE>"),
        ("< EPHEMERAL_MESSAGE >", "</ EPHEMERAL_MESSAGE >"),
        ("<ADDITIONAL_METADATA>", "</ADDITIONAL_METADATA>"),
        ("<CONTEXT_SUMMARY>", "</CONTEXT_SUMMARY>"),
    ] {
        cleaned = strip_tag_block(cleaned, o, c);
    }
    let trimmed = cleaned
        .replace("<USER_REQUEST>", " ")
        .replace("</USER_REQUEST>", " ");
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        None
    } else {
        let (head, _) = truncate_utf8_clean(trimmed, 512);
        Some(head.to_owned())
    }
}

pub fn extract_prompt_hint(payload: &Value, transcript_opt: Option<&Path>) -> Option<String> {
    const HINT_KEYS: &[&str] = &[
        "lastUserInput",
        "last_user_input",
        "prompt",
        "Prompt",
        "userPrompt",
        "userMessage",
        "query",
        "message",
        "Message",
        "input",
        "task",
        "instruction",
        "objective",
        "brief",
        "description",
    ];
    for key in HINT_KEYS {
        if let Some(raw) = payload.get(*key).and_then(Value::as_str) {
            if let Some(clean) = sanitize_prompt_hint_text(raw) {
                return Some(clean);
            }
        }
    }
    for container_key in ["toolArgs", "arguments", "request", "params", "subagent"] {
        if let Some(sub_obj) = payload.get(container_key) {
            for key in HINT_KEYS {
                if let Some(raw) = sub_obj.get(*key).and_then(Value::as_str) {
                    if let Some(clean) = sanitize_prompt_hint_text(raw) {
                        return Some(clean);
                    }
                }
            }
        }
    }

    let tp = transcript_opt?;
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(tp).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let read_len = len.min(16_384);
    f.seek(SeekFrom::Start(len - read_len)).ok()?;
    let mut buf = vec![0u8; read_len as usize];
    f.read_exact(&mut buf).ok()?;
    let tail = String::from_utf8_lossy(&buf);
    let recent_lines: Vec<&str> = tail
        .lines()
        .rev()
        .take(16)
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .collect();

    // Pass 1: Standard `USER_INPUT` step with non-empty sanitized user/task text
    for line in &recent_lines {
        if !line.contains("USER_INPUT") {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v.get("type").and_then(Value::as_str) == Some("USER_INPUT") {
                if let Some(c) = v.get("content").and_then(Value::as_str) {
                    if let Some(clean) = sanitize_prompt_hint_text(c) {
                        return Some(clean);
                    }
                }
            }
        }
    }

    // Pass 2: Subagent / swarm dispatch fallback (inspect `tool_calls` arguments or initial subagent prompt)
    for line in &recent_lines {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(tcalls) = v.get("tool_calls").and_then(Value::as_array) {
            for tc in tcalls {
                for arg_container in [
                    tc.get("arguments"),
                    tc.get("args"),
                    tc.get("input"),
                    Some(tc),
                ]
                .into_iter()
                .flatten()
                {
                    for key in ["Prompt", "prompt", "brief", "task", "Message", "query"] {
                        if let Some(raw) = arg_container.get(key).and_then(Value::as_str) {
                            if let Some(clean) = sanitize_prompt_hint_text(raw) {
                                return Some(clean);
                            }
                        }
                    }
                }
            }
        }
        let step_idx = v.get("step_index").and_then(Value::as_u64).unwrap_or(99);
        let src = v.get("source").and_then(Value::as_str).unwrap_or("");
        if step_idx <= 2 || matches!(src, "USER_EXPLICIT" | "SYSTEM" | "AGENT") {
            if let Some(c) = v.get("content").and_then(Value::as_str) {
                if let Some(clean) = sanitize_prompt_hint_text(c) {
                    return Some(clean);
                }
            }
        }
    }
    None
}

/// Builds a priority-budgeted (`<= 450`-token / `1,800`-byte), `BM25`-assisted `<SYSTEM_MESSAGE>`
/// strictly from `hmac-sha256:v4`-sealed cognitive capsules (`Task`, `Handoff`, `Fact`, `Decision`,
/// `Snapshot`, `CompactionCheckpoint`).
///
/// Priority reservation guarantees that `BM25`-matched `Decision` and `Fact` capsules are never
/// evicted by verbose tasks, handoffs, or recency filler. Unsealed `WorkingSet` and `Symbol` nodes
/// are NEVER read here.
fn build_project_memory_hydration_with_cap(
    proj_db: &LibreDb,
    ws_root: Option<&Path>,
    prompt_hint: Option<&str>,
    error_hint: Option<&str>,
    max_bytes: usize,
) -> (String, usize) {
    let mut naive_baseline_bytes = 64usize;
    let mut git_line_opt = ws_root.and_then(collect_git_telemetry_line);
    if let Some(ref g) = git_line_opt {
        naive_baseline_bytes += g.len() + 1;
    }

    let inodes = proj_db.list_inodes(None, false);
    let mut task_ids: Vec<u64> = Vec::new();
    let mut handoff_ids: Vec<u64> = Vec::new();
    let mut decision_ids: Vec<u64> = Vec::new();
    let mut fact_ids: Vec<(u64, u64)> = Vec::new();
    let mut active_symbol_count: usize = 0;

    for (ino, _, _) in &inodes {
        if !ino.flags.is_live_active() {
            continue;
        }
        match ino.kind {
            NodeKind::Task => {
                naive_baseline_bytes += (ino.token_count as usize) * 4;
                task_ids.push(ino.node_id);
            }
            NodeKind::Handoff => {
                naive_baseline_bytes += (ino.token_count as usize) * 4;
                handoff_ids.push(ino.node_id);
            }
            NodeKind::Decision => {
                naive_baseline_bytes += (ino.token_count as usize) * 4;
                decision_ids.push(ino.node_id);
            }
            NodeKind::Fact => {
                naive_baseline_bytes += (ino.token_count as usize) * 4;
                fact_ids.push((ino.updated_ns, ino.node_id));
            }
            // Security invariant: NEVER hydrate WorkingSet, Symbol, Generic, or TranscriptCursor payloads;
            // only surface a compact integer readiness summary for live Symbol inodes when > 0.
            NodeKind::Symbol => {
                active_symbol_count += 1;
            }
            _ => {}
        }
    }

    if active_symbol_count > 0 {
        let sym_word = if active_symbol_count == 1 {
            "symbol"
        } else {
            "symbols"
        };
        let graph_line = format!(
            "Code Graph: {active_symbol_count} {sym_word} indexed (use 'libredb locate <sym>', 'libredb fim --symbol <sym>', 'libredb grep <pat>')"
        );
        naive_baseline_bytes += graph_line.len() + 1;
        git_line_opt = Some(match git_line_opt {
            Some(g) => format!("{g}\n{graph_line}"),
            None => graph_line,
        });
    }

    // Tier 1 (with Git/Code Graph): learned situational reflexes matching the current prompt or newly
    // harvested error diagnostic. `load_sealed_only` loads exclusively `NodeKind::Rule` capsules
    // covered by the `hmac-sha256:v4` workspace seal, so unsealed `NodeKind::Generic` text can
    // never enter `<SYSTEM_MESSAGE>`.
    let reflex_query_owned: String = [
        prompt_hint.map(str::trim).filter(|s| !s.is_empty()),
        error_hint.map(str::trim).filter(|s| !s.is_empty()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n");
    if !reflex_query_owned.is_empty() {
        if let Ok(rx) = libredb_cognitive::ReflexEngine::load_sealed_only(proj_db) {
            let err_arg: String = error_hint
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().take(256).collect())
                .unwrap_or_else(|| reflex_query_owned.chars().take(256).collect());
            let fired = rx.evaluate(ws_root, &reflex_query_owned, Some(&err_arg));
            if !fired.is_empty() {
                let mut block = vec!["Learned Reflexes:".to_owned()];
                for rf in fired.iter().take(MAX_PRE_INVOCATION_REFLEXES) {
                    let flat = rf.directive.lines().collect::<Vec<_>>().join(" ");
                    let (short, cut) = truncate_utf8_clean(flat.trim(), 160);
                    let ellipsis = if cut { "..." } else { "" };
                    if short.starts_with("[REFLEX") {
                        block.push(format!("  * {short}{ellipsis}"));
                    } else {
                        block.push(format!("  * [{}] {short}{ellipsis}", rf.id));
                    }
                }
                let reflex_block = block.join("\n");
                naive_baseline_bytes += reflex_block.len() + 1;
                git_line_opt = Some(match git_line_opt {
                    Some(g) => format!("{g}\n\n{reflex_block}"),
                    None => reflex_block,
                });
            }
        }
    }

    let bm25_opt = prompt_hint
        .map(str::trim)
        .filter(|q| !q.is_empty() && (!fact_ids.is_empty() || !decision_ids.is_empty()))
        .and_then(|q| {
            libredb_index::HybridIndex::load_or_build(proj_db)
                .ok()
                .map(|idx| (q, idx))
        });

    // Collect candidate lines per section, separating BM25-priority items from recency/status items.
    let total_decs = decision_ids.len();
    let mut bm25_dec_lines: Vec<String> = Vec::new();
    let mut recency_dec_lines: Vec<String> = Vec::new();
    if !decision_ids.is_empty() {
        decision_ids.sort_by(|a, b| b.cmp(a));
        let live_dec_set: std::collections::HashSet<u64> = decision_ids.iter().copied().collect();
        let mut bm25_dids: Vec<u64> = Vec::with_capacity(2);
        if let Some((q, ref idx)) = bm25_opt {
            for hit in idx.search(q, Some(&[NodeKind::Decision]), 4) {
                if live_dec_set.contains(&hit.node_id) && !bm25_dids.contains(&hit.node_id) {
                    bm25_dids.push(hit.node_id);
                    if bm25_dids.len() >= 2 {
                        break;
                    }
                }
            }
        }
        let mut all_dids = bm25_dids.clone();
        for &did in &decision_ids {
            if all_dids.len() >= 3 {
                break;
            }
            if !all_dids.contains(&did) {
                all_dids.push(did);
            }
        }
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&all_dids) {
            let rec_map: std::collections::HashMap<u64, _> =
                recs.into_iter().map(|r| (r.node_id, r)).collect();
            for did in &all_dids {
                if let Some(r) = rec_map.get(did) {
                    let txt = String::from_utf8_lossy(&r.payload);
                    let flat = txt.lines().collect::<Vec<_>>().join(" ");
                    let (short, cut) = truncate_utf8_clean(flat.trim(), 150);
                    let formatted = if cut {
                        format!("  * {short}... [#{} via libredb_pulse]", r.node_id)
                    } else {
                        format!("  * {short}")
                    };
                    if bm25_dids.contains(did) {
                        bm25_dec_lines.push(formatted);
                    } else {
                        recency_dec_lines.push(formatted);
                    }
                }
            }
        }
    }

    let total_facts = fact_ids.len();
    let mut bm25_fact_lines: Vec<String> = Vec::new();
    let mut recency_fact_lines: Vec<String> = Vec::new();
    if !fact_ids.is_empty() {
        fact_ids.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let live_fact_set: std::collections::HashSet<u64> =
            fact_ids.iter().map(|&(_, id)| id).collect();
        let mut bm25_fids: Vec<u64> = Vec::with_capacity(2);
        if let Some((q, ref idx)) = bm25_opt {
            for hit in idx.search(q, Some(&[NodeKind::Fact]), 4) {
                if live_fact_set.contains(&hit.node_id) && !bm25_fids.contains(&hit.node_id) {
                    bm25_fids.push(hit.node_id);
                    if bm25_fids.len() >= 2 {
                        break;
                    }
                }
            }
        }
        let target_fact_cap = if bm25_fids.is_empty() { 5 } else { 6 };
        let mut all_fids = bm25_fids.clone();
        for &(_, id) in &fact_ids {
            if all_fids.len() >= target_fact_cap {
                break;
            }
            if !all_fids.contains(&id) {
                all_fids.push(id);
            }
        }
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&all_fids) {
            let rec_map: std::collections::HashMap<u64, _> =
                recs.into_iter().map(|r| (r.node_id, r)).collect();
            for fid in &all_fids {
                if let Some(r) = rec_map.get(fid) {
                    let txt = String::from_utf8_lossy(&r.payload);
                    let flat = txt.lines().collect::<Vec<_>>().join(" ");
                    let (short, cut) = truncate_utf8_clean(flat.trim(), 140);
                    let formatted = if cut {
                        format!("  * {short}... [#{}]", r.node_id)
                    } else {
                        format!("  * {short}")
                    };
                    if bm25_fids.contains(fid) {
                        bm25_fact_lines.push(formatted);
                    } else {
                        recency_fact_lines.push(formatted);
                    }
                }
            }
        }
    }

    let mut open_task_lines: Vec<String> = Vec::new();
    let mut omitted_open_tasks = false;
    if !task_ids.is_empty() {
        task_ids.sort_unstable();
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&task_ids) {
            let all_open: Vec<String> = recs
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
                .collect();
            omitted_open_tasks = all_open.len() > 3;
            for t in all_open.into_iter().take(3) {
                let first = t.lines().next().unwrap_or(&t).trim();
                let (short, cut) = truncate_utf8_clean(first, 115);
                open_task_lines.push(format!("  * {short}{}", if cut { "..." } else { "" }));
            }
        }
    }

    let mut handoff_lines: Vec<String> = Vec::new();
    if !handoff_ids.is_empty() {
        if let Ok((recs, _)) = proj_db.get_many_coalesced(&handoff_ids) {
            for h in recs
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
                .filter(|h| h.contains("(pending)"))
                .take(2)
            {
                let first = h.lines().next().unwrap_or(&h).trim();
                let (short, cut) = truncate_utf8_clean(first, 115);
                handoff_lines.push(format!("  * {short}{}", if cut { "..." } else { "" }));
            }
        }
    }

    let mut snap_header: Option<&'static str> = None;
    let mut snap_lines: Vec<String> = Vec::new();
    if let Ok(snap) = proj_db.get_by_key(NodeKind::Snapshot, "latest_snapshot") {
        naive_baseline_bytes += snap.payload.len();
        snap_header = Some("Latest Milestone Snapshot:");
        for sl in String::from_utf8_lossy(&snap.payload).lines().take(3) {
            let (short, cut) = truncate_utf8_clean(sl.trim(), 130);
            snap_lines.push(format!("  {short}{}", if cut { "..." } else { "" }));
        }
    } else if let Ok(cp) = proj_db.get_by_key(NodeKind::CompactionCheckpoint, "latest_compaction") {
        naive_baseline_bytes += cp.payload.len();
        snap_header = Some("Latest Compaction Checkpoint:");
        for cl in String::from_utf8_lossy(&cp.payload).lines().take(3) {
            let (short, cut) = truncate_utf8_clean(cl.trim(), 130);
            snap_lines.push(format!("  {short}{}", if cut { "..." } else { "" }));
        }
    }

    let header = "=== PROJECT MEMORY CONTEXT (LibreDB .agents/memory.ldb) ===";
    let footer_notice = "  ... [capped at 450 tok; query details via libredb_pulse]";

    let mut chosen_tasks: Vec<String> = Vec::new();
    let mut chosen_handoffs: Vec<String> = Vec::new();
    let mut chosen_facts: Vec<String> = Vec::new();
    let mut chosen_decs: Vec<String> = Vec::new();
    let mut chosen_snap: Vec<String> = Vec::new();
    let mut omitted = omitted_open_tasks;

    let render_hydration = |git: &Option<String>,
                            tasks: &[String],
                            handoffs: &[String],
                            facts: &[String],
                            decs: &[String],
                            snap_hdr: Option<&str>,
                            snaps: &[String],
                            with_footer: bool|
     -> String {
        let mut secs: Vec<Vec<String>> = Vec::new();
        if let Some(ref g) = git {
            secs.push(vec![g.clone()]);
        }
        if !tasks.is_empty() {
            let mut s = vec!["Active Task Board:".to_owned()];
            s.extend_from_slice(tasks);
            secs.push(s);
        }
        if !handoffs.is_empty() {
            let mut s = vec!["Pending Subagent Handoffs:".to_owned()];
            s.extend_from_slice(handoffs);
            secs.push(s);
        }
        if !facts.is_empty() {
            let hdr = if total_facts > facts.len() {
                format!(
                    "Project Facts ({} of {total_facts} active; full via libredb_pulse):",
                    facts.len()
                )
            } else {
                "Project Facts (.agents/memory.ldb):".to_owned()
            };
            let mut s = vec![hdr];
            s.extend_from_slice(facts);
            secs.push(s);
        }
        if !decs.is_empty() {
            let hdr = if total_decs > decs.len() {
                format!(
                    "Active Architectural Decisions ({} of {total_decs}; full via libredb_pulse):",
                    decs.len()
                )
            } else {
                "Active Architectural Decisions:".to_owned()
            };
            let mut s = vec![hdr];
            s.extend_from_slice(decs);
            secs.push(s);
        }
        if let Some(sh) = snap_hdr {
            if !snaps.is_empty() {
                let mut s = vec![sh.to_owned()];
                s.extend_from_slice(snaps);
                secs.push(s);
            }
        }
        if secs.is_empty() {
            return String::new();
        }
        let mut out = String::with_capacity(max_bytes);
        out.push_str(header);
        for (idx, sec) in secs.iter().enumerate() {
            if idx > 0 {
                out.push('\n');
            }
            for line in sec {
                out.push('\n');
                out.push_str(line);
            }
        }
        if with_footer {
            out.push('\n');
            out.push_str(footer_notice);
        }
        out
    };

    // Tier 2 (after Git): Lock in BM25-matched Decisions and BM25-matched Facts FIRST so they can NEVER be evicted!
    for d in bm25_dec_lines {
        chosen_decs.push(d);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_decs.pop();
            omitted = true;
        }
    }
    for f in bm25_fact_lines {
        chosen_facts.push(f);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_facts.pop();
            omitted = true;
        }
    }

    // Tier 3: Open Tasks & Pending Handoffs
    for t in open_task_lines {
        chosen_tasks.push(t);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_tasks.pop();
            omitted = true;
        }
    }
    for h in handoff_lines {
        chosen_handoffs.push(h);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_handoffs.pop();
            omitted = true;
        }
    }

    // Tier 4: Remaining newest Decisions, newest Facts, and Latest Snapshot / Compaction Checkpoint
    for d in recency_dec_lines {
        chosen_decs.push(d);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_decs.pop();
            omitted = true;
        }
    }
    for f in recency_fact_lines {
        chosen_facts.push(f);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_facts.pop();
            omitted = true;
        }
    }
    for s in snap_lines {
        chosen_snap.push(s);
        if render_hydration(
            &git_line_opt,
            &chosen_tasks,
            &chosen_handoffs,
            &chosen_facts,
            &chosen_decs,
            snap_header,
            &chosen_snap,
            true,
        )
        .len()
            > max_bytes
        {
            chosen_snap.pop();
            omitted = true;
        }
    }

    let out = render_hydration(
        &git_line_opt,
        &chosen_tasks,
        &chosen_handoffs,
        &chosen_facts,
        &chosen_decs,
        snap_header,
        &chosen_snap,
        omitted,
    );
    if out.is_empty() {
        return (String::new(), 0);
    }

    (out, naive_baseline_bytes.max(128))
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

const MAX_SIMULATED_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

fn align_replacement_line_endings(
    cur: &str,
    file_uses_crlf: bool,
    target_raw: &str,
    repl_raw: &str,
) -> Option<(String, String)> {
    if target_raw.is_empty() {
        return None;
    }
    if cur.contains(target_raw) {
        Some((target_raw.to_owned(), repl_raw.to_owned()))
    } else if file_uses_crlf && !target_raw.contains("\r\n") && target_raw.contains('\n') {
        let t = target_raw.replace('\n', "\r\n");
        let r = if repl_raw.contains("\r\n") {
            repl_raw.to_owned()
        } else {
            repl_raw.replace('\n', "\r\n")
        };
        Some((t, r))
    } else if !file_uses_crlf && target_raw.contains("\r\n") {
        Some((
            target_raw.replace("\r\n", "\n"),
            repl_raw.replace("\r\n", "\n"),
        ))
    } else {
        None
    }
}

fn line_window_byte_range(
    cur: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Option<(usize, usize)> {
    let (Some(sl), Some(el)) = (start_line, end_line) else {
        return None;
    };
    if sl < 1 || el < sl {
        return None;
    }
    let mut cur_line = 1usize;
    let mut span_start: Option<usize> = if sl == 1 { Some(0) } else { None };
    let mut span_end: Option<usize> = None;
    for (idx, b) in cur.bytes().enumerate() {
        if b == b'\n' {
            if cur_line == el && span_end.is_none() {
                span_end = Some(idx + 1);
                break;
            }
            cur_line += 1;
            if cur_line == sl && span_start.is_none() {
                span_start = Some(idx + 1);
            }
        }
    }
    let s_idx = span_start.unwrap_or(0);
    let e_idx = span_end.unwrap_or(cur.len()).max(s_idx);
    Some((s_idx, e_idx))
}

fn is_symbol_or_test_decl_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with("//") || t.starts_with("/*") || t.starts_with("# ") {
        return false;
    }
    if t.starts_with("#[test]")
        || t.starts_with("#[tokio::test")
        || t.starts_with("#[rstest")
    {
        return true;
    }
    const DECL_PREFIXES: &[&str] = &[
        "fn ",
        "pub fn ",
        "pub(crate) fn ",
        "pub(super) fn ",
        "async fn ",
        "pub async fn ",
        "struct ",
        "pub struct ",
        "pub(crate) struct ",
        "enum ",
        "pub enum ",
        "trait ",
        "pub trait ",
        "impl ",
        "impl<",
        "mod ",
        "pub mod ",
        "def ",
        "async def ",
        "class ",
        "function ",
        "async function ",
        "export function ",
        "export async function ",
        "export class ",
        "func ",
    ];
    DECL_PREFIXES.iter().any(|p| t.starts_with(p))
}

fn check_multi_edit_pair(
    cur: &str,
    file_uses_crlf: bool,
    display_file: &str,
    target_raw: &str,
    repl_raw: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Option<String> {
    let (target_eff, _) = align_replacement_line_endings(cur, file_uses_crlf, target_raw, repl_raw)?;
    let (base_off, win_end) = line_window_byte_range(cur, start_line, end_line).unwrap_or((0, cur.len()));
    let window = &cur[base_off..win_end];
    let hit_offsets: Vec<usize> = window
        .match_indices(&target_eff)
        .map(|(rel, _)| base_off + rel)
        .collect();
    if hit_offsets.len() <= 1 {
        return None;
    }

    let target_decls = target_raw
        .lines()
        .filter(|l| is_symbol_or_test_decl_line(l))
        .count();
    let repl_decls = repl_raw
        .lines()
        .filter(|l| is_symbol_or_test_decl_line(l))
        .count();
    let target_lines = target_raw.lines().count().max(1);
    let repl_lines = repl_raw.lines().count();
    let large_brace_append = repl_lines >= target_lines + 8
        && target_lines <= 4
        && target_raw.trim_end().ends_with('}');

    if repl_decls > target_decls || large_brace_append {
        let mut line_labels: Vec<String> = hit_offsets
            .iter()
            .take(8)
            .map(|&off| {
                let ln = cur[..off].bytes().filter(|&b| b == b'\n').count() + 1;
                format!("L{ln}")
            })
            .collect();
        if hit_offsets.len() > 8 {
            line_labels.push("...".to_owned());
        }
        return Some(format!(
            "LibreDB Ambiguous Multi-Edit Guard Blocked Write: Target matched {} locations in '{}' ({}) while Replacement introduces new symbol/test declarations or appends a large block onto a non-unique closing-brace anchor, which would duplicate code {} times. Include 1-2 unique surrounding lines in Target so the edit modifies only the intended site.",
            hit_offsets.len(),
            display_file,
            line_labels.join(", "),
            hit_offsets.len()
        ));
    }
    None
}

fn check_ambiguous_multi_edit_hazard(
    target_file: &Path,
    display_file: &str,
    tool_name: &str,
    args: &Value,
) -> Option<String> {
    if !matches!(
        tool_name,
        "edit_file" | "replace_file_content" | "multi_replace_file_content"
    ) {
        return None;
    }
    let meta = std::fs::symlink_metadata(target_file).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_SIMULATED_SOURCE_BYTES
    {
        return None;
    }
    let raw_bytes = std::fs::read(target_file).ok()?;
    let cur = std::str::from_utf8(&raw_bytes).ok()?;
    let file_uses_crlf = cur.contains("\r\n");

    if tool_name == "multi_replace_file_content" {
        let chunks = args.get("ReplacementChunks")?.as_array()?;
        for ch in chunks {
            let allow_mult = ch
                .get("AllowMultiple")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !allow_mult {
                continue;
            }
            let Some(target_str) = ch
                .get("TargetContent")
                .or_else(|| ch.get("Target"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some(repl_str) = ch
                .get("ReplacementContent")
                .or_else(|| ch.get("Replacement"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let sl = ch
                .get("StartLine")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let el = ch
                .get("EndLine")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            if let Some(reason) = check_multi_edit_pair(
                cur,
                file_uses_crlf,
                display_file,
                target_str,
                repl_str,
                sl,
                el,
            ) {
                return Some(reason);
            }
        }
        return None;
    }

    let replace_all = tool_name == "edit_file"
        || args
            .get("AllowMultiple")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if !replace_all {
        return None;
    }
    let target_str = args
        .get("Target")
        .or_else(|| args.get("TargetContent"))
        .or_else(|| args.get("old_string"))
        .or_else(|| args.get("target"))
        .and_then(Value::as_str)?;
    let repl_str = args
        .get("Replacement")
        .or_else(|| args.get("ReplacementContent"))
        .or_else(|| args.get("new_string"))
        .or_else(|| args.get("replacement"))
        .and_then(Value::as_str)?;
    let sl = args
        .get("StartLine")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let el = args
        .get("EndLine")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    check_multi_edit_pair(
        cur,
        file_uses_crlf,
        display_file,
        target_str,
        repl_str,
        sl,
        el,
    )
}

fn apply_in_ram_replacement(
    cur: &str,
    file_uses_crlf: bool,
    target_raw: &str,
    repl_raw: &str,
    replace_all: bool,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Option<String> {
    let (target_eff, repl_eff) =
        align_replacement_line_endings(cur, file_uses_crlf, target_raw, repl_raw)?;

    if let Some((s_idx, e_idx)) = line_window_byte_range(cur, start_line, end_line) {
        let window = &cur[s_idx..e_idx];
        if window.contains(&target_eff) {
            let updated_win = if replace_all {
                window.replace(&target_eff, &repl_eff)
            } else {
                if window.matches(&target_eff).count() != 1 {
                    return None;
                }
                window.replacen(&target_eff, &repl_eff, 1)
            };
            let mut rebuilt =
                String::with_capacity(cur.len().saturating_sub(window.len()) + updated_win.len());
            rebuilt.push_str(&cur[..s_idx]);
            rebuilt.push_str(&updated_win);
            rebuilt.push_str(&cur[e_idx..]);
            return Some(rebuilt);
        }
    }

    let count = cur.matches(&target_eff).count();
    if count == 0 {
        return None;
    }
    if replace_all {
        Some(cur.replace(&target_eff, &repl_eff))
    } else if count == 1 {
        Some(cur.replacen(&target_eff, &repl_eff, 1))
    } else {
        None
    }
}

/// Pure in-RAM simulation of a pending IDE write/edit tool call.
/// Never touches `target_file` on disk and preserves native `CRLF`/`LF` line endings so
/// `FNV-1a` (`SKELETON_HASH_SEED`) matches the exact bytes the IDE tool writes to disk.
fn simulate_post_edit_bytes(
    target_file: &Path,
    tool_name: &str,
    args: &Value,
) -> Option<(Option<u64>, Vec<u8>, u64)> {
    match tool_name {
        "write_file" | "write_to_file" => {
            let content = args
                .get("Content")
                .or_else(|| args.get("CodeContent"))
                .or_else(|| args.get("content"))
                .and_then(Value::as_str)?;
            if content.len() as u64 > MAX_SIMULATED_SOURCE_BYTES {
                return None;
            }
            let is_append = args
                .get("Append")
                .or_else(|| args.get("append"))
                .and_then(Value::as_bool)
                == Some(true);
            let mut pre_hash = None;
            if let Ok(meta) = std::fs::symlink_metadata(target_file) {
                if meta.file_type().is_symlink()
                    || !meta.is_file()
                    || meta.len() > MAX_SIMULATED_SOURCE_BYTES
                {
                    return None;
                }
                let mut buf = std::fs::read(target_file).ok()?;
                pre_hash = Some(libredb_core::crc::hash_key(
                    libredb_cognitive::skeleton::SKELETON_HASH_SEED,
                    &buf,
                ));
                if is_append {
                    if (buf.len() as u64).saturating_add(content.len() as u64)
                        > MAX_SIMULATED_SOURCE_BYTES
                    {
                        return None;
                    }
                    buf.extend_from_slice(content.as_bytes());
                    let raw_tok = ((buf.len() + 3) / 4) as u64;
                    return Some((pre_hash, buf, raw_tok));
                }
            }
            let bytes = content.as_bytes().to_vec();
            let raw_tok = ((bytes.len() + 3) / 4) as u64;
            Some((pre_hash, bytes, raw_tok))
        }
        "edit_file" | "replace_file_content" => {
            let meta = std::fs::symlink_metadata(target_file).ok()?;
            if meta.file_type().is_symlink()
                || !meta.is_file()
                || meta.len() > MAX_SIMULATED_SOURCE_BYTES
            {
                return None;
            }
            let raw_bytes = std::fs::read(target_file).ok()?;
            let pre_hash = Some(libredb_core::crc::hash_key(
                libredb_cognitive::skeleton::SKELETON_HASH_SEED,
                &raw_bytes,
            ));
            let cur = std::str::from_utf8(&raw_bytes).ok()?;
            let file_uses_crlf = cur.contains("\r\n");
            let target_str = args
                .get("Target")
                .or_else(|| args.get("TargetContent"))
                .or_else(|| args.get("old_string"))
                .or_else(|| args.get("target"))
                .and_then(Value::as_str)?;
            let repl_str = args
                .get("Replacement")
                .or_else(|| args.get("ReplacementContent"))
                .or_else(|| args.get("new_string"))
                .or_else(|| args.get("replacement"))
                .and_then(Value::as_str)?;
            let replace_all = tool_name == "edit_file"
                || args
                    .get("AllowMultiple")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let start_line = args
                .get("StartLine")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let end_line = args
                .get("EndLine")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let updated = apply_in_ram_replacement(
                cur,
                file_uses_crlf,
                target_str,
                repl_str,
                replace_all,
                start_line,
                end_line,
            )?;
            let post_bytes = updated.into_bytes();
            let raw_tok = ((post_bytes.len() + 3) / 4) as u64;
            Some((pre_hash, post_bytes, raw_tok))
        }
        "multi_replace_file_content" => {
            let meta = std::fs::symlink_metadata(target_file).ok()?;
            if meta.file_type().is_symlink()
                || !meta.is_file()
                || meta.len() > MAX_SIMULATED_SOURCE_BYTES
            {
                return None;
            }
            let raw_bytes = std::fs::read(target_file).ok()?;
            let pre_hash = Some(libredb_core::crc::hash_key(
                libredb_cognitive::skeleton::SKELETON_HASH_SEED,
                &raw_bytes,
            ));
            let mut cur = std::str::from_utf8(&raw_bytes).ok()?.to_owned();
            let file_uses_crlf = cur.contains("\r\n");
            let chunks = args.get("ReplacementChunks")?.as_array()?;
            if chunks.is_empty() {
                return None;
            }
            let mut ordered: Vec<&Value> = chunks.iter().collect();
            if ordered
                .iter()
                .all(|c| c.get("StartLine").and_then(Value::as_u64).is_some())
            {
                ordered.sort_by(|a, b| {
                    let sa = a.get("StartLine").and_then(Value::as_u64).unwrap_or(0);
                    let sb = b.get("StartLine").and_then(Value::as_u64).unwrap_or(0);
                    sb.cmp(&sa)
                });
            }
            for ch in ordered {
                let target_str = ch
                    .get("TargetContent")
                    .or_else(|| ch.get("Target"))
                    .and_then(Value::as_str)?;
                let repl_str = ch
                    .get("ReplacementContent")
                    .or_else(|| ch.get("Replacement"))
                    .and_then(Value::as_str)?;
                let allow_mult = ch
                    .get("AllowMultiple")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let sl = ch
                    .get("StartLine")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize);
                let el = ch
                    .get("EndLine")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize);
                cur = apply_in_ram_replacement(
                    &cur,
                    file_uses_crlf,
                    target_str,
                    repl_str,
                    allow_mult,
                    sl,
                    el,
                )?;
            }
            let post_bytes = cur.into_bytes();
            let raw_tok = ((post_bytes.len() + 3) / 4) as u64;
            Some((pre_hash, post_bytes, raw_tok))
        }
        _ => None,
    }
}

fn record_working_set_edit(
    ws_root: &Path,
    preopened_db: Option<Arc<LibreDb>>,
    target_file: &Path,
    tool_name: &str,
    args: &Value,
    global_db: Option<&LibreDb>,
    cid_transcript: Option<(&str, &Path)>,
) -> Result<(), String> {
    if crate::security::is_private_brain_workspace(ws_root) {
        return Ok(());
    }
    let ldb_path = ws_root.join(".agents").join("memory.ldb");
    let db_sibling = ldb_path.with_extension("db");
    if preopened_db.is_none() && !ldb_path.exists() && !db_sibling.exists() {
        return Ok(());
    }
    let is_net = preopened_db
        .as_ref()
        .is_some_and(|db| db.is_network_share())
        || libredb_core::io::detect_network_path(&ldb_path);
    let _ws_lock = match global_db.filter(|_| !crate::security::is_private_brain_workspace(ws_root)) {
        Some(gdb) => {
            if is_net {
                let Some(guard) = crate::security::WorkspaceTrustLockGuard::try_acquire_bounded(
                    gdb, ws_root, 250,
                )?
                else {
                    return Ok(());
                };
                Some(guard)
            } else {
                Some(crate::security::WorkspaceTrustLockGuard::acquire(
                    gdb, ws_root,
                )?)
            }
        }
        None => None,
    };
    let proj_db = match preopened_db {
        Some(db) => {
            let _ = db.sync_from_disk_if_changed();
            db
        }
        None => open_project_ldb_silent(&ldb_path)?,
    };

    let _deferred = proj_db
        .is_network_share()
        .then(|| proj_db.begin_deferred_sync());

    // Harvest any unseen non-banal transcript/task errors BEFORE staging the edit so
    // error cue timestamps causally precede the staged TentativeFileEdit (`edit_ns >= recorded_at_ns`).
    if let Some((cid, tp)) = cid_transcript {
        if tp.is_file() {
            let _ =
                harvest_recent_transcript_errors(&proj_db, cid, tp, !proj_db.is_network_share());
        }
    }

    // Stage tentative predicted edit in `WorkingSet` (`tentative_edit::<rel>`) without mutating
    // live `NodeKind::Symbol` contracts until actual disk bytes are verified on subsequent access.
    if let Some((pre_hash, post_bytes, raw_tok)) =
        simulate_post_edit_bytes(target_file, tool_name, args)
    {
        if let Ok((_, promoted_prior, saved_prior)) =
            libredb_cognitive::stage_tentative_file_edit(
                &proj_db,
                ws_root,
                target_file,
                pre_hash,
                &post_bytes,
                raw_tok,
            )
        {
            if promoted_prior > 0 {
                crate::telemetry::record_workspace_event(
                    ws_root,
                    crate::telemetry::TelemetryEvent::HookSymbolShift {
                        reread_tokens_avoided: saved_prior,
                    },
                );
            }
        }
    } else if !proj_db.is_network_share() {
        if let Ok((promoted_prior, saved_prior)) =
            libredb_cognitive::reconcile_tentative_edits(&proj_db, ws_root)
        {
            if promoted_prior > 0 {
                crate::telemetry::record_workspace_event(
                    ws_root,
                    crate::telemetry::TelemetryEvent::HookSymbolShift {
                        reread_tokens_avoided: saved_prior,
                    },
                );
            }
        }
    }

    let rel_key = target_file
        .strip_prefix(ws_root)
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
    if !proj_db.is_network_share() {
        let _ = proj_db.maybe_auto_compact();
    }
    Ok(())
}

/// Reads the trailing `<= max_bytes` of `path`, discarding the truncated leading line when seeking
/// past offset `0`.
fn read_file_tail_lines(path: &Path, max_bytes: u64) -> Option<Vec<String>> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let read_len = len.min(max_bytes);
    let offset = len - read_len;
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; read_len as usize];
    f.read_exact(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
    if offset > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    Some(lines)
}

fn strip_ci_log_prefix(raw_line: &str) -> &str {
    let after_step = if let Some(pos) = raw_line.find("\tUNKNOWN STEP\t") {
        &raw_line[pos + "\tUNKNOWN STEP\t".len()..]
    } else {
        raw_line
    };
    let trimmed = after_step.trim_start();
    if let Some((first_tok, rest)) = trimmed.split_once(' ') {
        if first_tok.starts_with("20")
            && first_tok.ends_with('Z')
            && first_tok.contains('T')
            && first_tok.len() >= 20
        {
            return rest;
        }
    }
    after_step
}

fn is_numbered_source_line(t: &str) -> bool {
    t.split_once(": ")
        .is_some_and(|(num, _)| !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()))
}

/// Extracts up to `4` deduplicated error/panic diagnostic lines from command or CI log text while
/// ignoring numbered source-code listings (`"631: ..."`).
pub(crate) fn extract_error_diagnostics_from_command_output(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let push_unique = |out: &mut Vec<String>, cand: String| {
        if !cand.is_empty() && !out.contains(&cand) && out.len() < 4 {
            out.push(cand);
        }
    };

    for i in 0..lines.len() {
        if out.len() >= 4 {
            break;
        }
        let t = strip_ci_log_prefix(lines[i]).trim();
        if t.is_empty()
            || is_numbered_source_line(t)
            || t.starts_with("Task Description:")
            || t.starts_with("CommandLine:")
            || t.starts_with("\"CommandLine\"")
            || t.starts_with(".\\")
            || t.starts_with("./")
            || t.contains("learn-error ")
        {
            continue;
        }
        if (t.starts_with("thread '") || t.starts_with("panicked at "))
            && t.contains("panicked at ")
        {
            let mut next_msg = None;
            for j in (i + 1)..=(i + 2).min(lines.len().saturating_sub(1)) {
                let nt = strip_ci_log_prefix(lines[j]).trim();
                if nt.is_empty()
                    || is_numbered_source_line(nt)
                    || nt.starts_with("note: ")
                    || nt.starts_with("thread '")
                    || nt.starts_with("---")
                    || nt == "failures:"
                {
                    continue;
                }
                next_msg = Some(nt);
                break;
            }
            let combined = match next_msg {
                Some(nt) => format!("{t} {nt}"),
                None => t.to_owned(),
            };
            push_unique(&mut out, combined);
            continue;
        }

        let is_short_compiler_err = (t.contains(": error[E")
            || t.contains(": error: ")
            || t.contains("): error TS"))
            && libredb_cognitive::extract_error_file_hint(t).is_some();
        let is_compiler_or_runtime_err = (is_short_compiler_err
            || t.starts_with("error[E")
            || ((t.starts_with("error: ") || t.starts_with("Error: "))
                && !t.starts_with("error: test failed, to rerun")
                && !t.contains("0 errors"))
            || t.starts_with("SyntaxError:")
            || t.starts_with("TypeError:")
            || t.starts_with("ReferenceError:")
            || t.starts_with("AssertionError:")
            || t.starts_with("ImportError:"))
            && !libredb_cognitive::is_non_causal_error_noise(t);
        if is_compiler_or_runtime_err {
            push_unique(&mut out, t.to_owned());
        }
    }
    out
}

/// Resolves local `file:///` task log URIs strictly contained in the conversation's non-symlink
/// `.system_generated/tasks` sibling directory.
fn collect_contained_task_log_paths(content: &str, transcript_path: &Path) -> Vec<PathBuf> {
    let Some(sys_gen_dir) = transcript_path.parent().and_then(|p| p.parent()) else {
        return Vec::new();
    };
    let tasks_dir = sys_gen_dir.join("tasks");
    if std::fs::symlink_metadata(&tasks_dir)
        .map_or(true, |m| m.file_type().is_symlink() || !m.is_dir())
    {
        return Vec::new();
    }
    let Ok(canon_tasks) = std::fs::canonicalize(&tasks_dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut rest = content;
    while let Some(pos) = rest.find("file:///") {
        let after_scheme = &rest[pos + "file:///".len()..];
        let uri_end = after_scheme
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '>' | ')' | ']'))
            .unwrap_or(after_scheme.len());
        let raw_path_part = &after_scheme[..uri_end];
        rest = &after_scheme[uri_end..];

        let raw_os = if raw_path_part.as_bytes().get(1) == Some(&b':') {
            raw_path_part.to_owned()
        } else {
            format!("/{raw_path_part}")
        };
        let norm_forward = raw_os.replace('\\', "/");
        if !norm_forward.contains(".system_generated/tasks/task-")
            || !norm_forward.ends_with(".log")
        {
            continue;
        }
        let cand = PathBuf::from(&raw_os);
        let Some(fname) = cand.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !fname.starts_with("task-") || !fname.ends_with(".log") {
            continue;
        }
        if std::fs::symlink_metadata(&cand)
            .map_or(true, |m| m.file_type().is_symlink() || !m.is_file())
        {
            continue;
        }
        if let Some(parent) = cand.parent() {
            if std::fs::canonicalize(parent).ok().as_ref() == Some(&canon_tasks)
                && !out.contains(&cand)
            {
                out.push(cand);
            }
        }
    }
    out
}

/// Incrementally harvests non-banal errors and panics from the trailing window of `transcript_path`
/// (plus strictly contained `.system_generated/tasks/task-*.log` files) into `sys::pending_error_cues`
/// using seal-neutral `NodeKind::TranscriptCursor` (`sys::error_harvest_cursor::{cid}`).
/// Returns the error diagnostic strings newly recorded during this scan.
fn harvest_recent_transcript_errors(
    proj_db: &LibreDb,
    cid: &str,
    transcript_path: &Path,
    persist_cursor_when_empty: bool,
) -> Vec<String> {
    let Some(lines) = read_file_tail_lines(transcript_path, 65_536) else {
        return Vec::new();
    };
    let cursor_key = format!("sys::error_harvest_cursor::{cid}");
    let last_step_index = proj_db
        .get_by_key(NodeKind::TranscriptCursor, &cursor_key)
        .ok()
        .and_then(|rec| serde_json::from_slice::<Value>(&rec.payload).ok())
        .and_then(|v| v.get("last_step_index").and_then(Value::as_u64))
        .unwrap_or(0);

    let start_idx = lines
        .iter()
        .rposition(|l| is_compaction_checkpoint_line(l))
        .map_or(0, |k| k + 1);
    let mut max_step_index = last_step_index;
    let mut queued_cues: Vec<(String, &'static str)> = Vec::new();
    let mut enqueue = |msg: String, hint: &'static str| {
        if !msg.is_empty()
            && !queued_cues.iter().any(|(m, _)| m == &msg)
            && queued_cues.len() < 4
        {
            queued_cues.push((msg, hint));
        }
    };

    for line in &lines[start_idx..] {
        let Ok(obj) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let step_idx = obj.get("step_index").and_then(Value::as_u64).unwrap_or(0);
        if step_idx > 0 && step_idx <= last_step_index {
            continue;
        }
        max_step_index = max_step_index.max(step_idx);

        // Source A: explicit error parameters inside planner MCP/pulse calls.
        if obj.get("type").and_then(Value::as_str) == Some("PLANNER_RESPONSE") {
            if let Some(tcs) = obj.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    let raw_args = tc
                        .get("args")
                        .or_else(|| tc.get("arguments"))
                        .unwrap_or(&Value::Null);
                    let inner = raw_args.get("Arguments").unwrap_or(raw_args);
                    let err_opt = inner
                        .get("error")
                        .and_then(Value::as_str)
                        .or_else(|| {
                            inner
                                .get("learn_error")
                                .and_then(|le| le.get("error"))
                                .and_then(Value::as_str)
                        });
                    if let Some(err_s) = err_opt.map(str::trim).filter(|s| !s.is_empty()) {
                        enqueue(err_s.to_owned(), "pulse");
                    }
                }
            }
        }

        // Source B: compiler errors, runtime errors, and test panics from command/task logs.
        let content = obj.get("content").and_then(Value::as_str).unwrap_or("");
        let is_read_file_view = content.contains("\nShowing lines ")
            && !content.contains("UNKNOWN STEP")
            && !content.contains("Command exited with code ")
            && !content.contains("Command output:")
            && !content.contains("Log output:");
        if !is_read_file_view
            && (content.contains("Command output:")
                || content.contains("Log output:")
                || content.contains("Command exited with code ")
                || content.contains("panicked at ")
                || content.contains("error[E")
                || content.contains("Task logs are available at: "))
        {
            for diag in extract_error_diagnostics_from_command_output(content) {
                enqueue(diag, "hook-transcript");
            }
            for log_path in collect_contained_task_log_paths(content, transcript_path) {
                if let Some(log_lines) = read_file_tail_lines(&log_path, 16_384) {
                    let joined = log_lines.join("\n");
                    for diag in extract_error_diagnostics_from_command_output(&joined) {
                        enqueue(diag, "hook-transcript");
                    }
                }
            }
        }
    }

    let mut newly_recorded = Vec::new();
    for (diag, hint) in queued_cues {
        if libredb_cognitive::record_error_cue(proj_db, &diag, Some(hint)).unwrap_or(false) {
            newly_recorded.push(diag);
        }
    }
    if max_step_index > last_step_index
        && (!newly_recorded.is_empty() || persist_cursor_when_empty)
    {
        let cur_json = json!({ "last_step_index": max_step_index });
        if let Ok(bytes) = serde_json::to_vec(&cur_json) {
            let _ = proj_db.put(
                WriteRequest::new(NodeKind::TranscriptCursor, bytes)
                    .with_key(cursor_key)
                    .with_importance(32),
            );
        }
    }
    newly_recorded
}

fn resolve_hook_workspace(payload: &Value, transcript_opt: Option<&Path>) -> Option<PathBuf> {
    if let Some(arr) = payload.get("workspacePaths").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                let p = PathBuf::from(s);
                if p.is_dir()
                    && !is_protected_profile_dir(&p)
                    && !crate::security::is_private_brain_workspace(&p)
                {
                    if let Some(root) = find_workspace_root(&p) {
                        if !is_protected_profile_dir(&root)
                            && !crate::security::is_private_brain_workspace(&root)
                        {
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
                        if candidate.exists()
                            && !is_protected_profile_dir(&candidate)
                            && !crate::security::is_private_brain_workspace(&candidate)
                        {
                            if let Some(root) = find_workspace_root(&candidate) {
                                if !is_protected_profile_dir(&root)
                                    && !crate::security::is_private_brain_workspace(&root)
                                {
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
    if is_protected_profile_dir(dir) || crate::security::is_private_brain_workspace(dir) {
        return None;
    }
    let mut fallback_marker: Option<PathBuf> = None;
    let mut curr = Some(dir);
    while let Some(c) = curr {
        if c.parent().is_none()
            || is_protected_profile_dir(c)
            || crate::security::is_private_brain_workspace(c)
            || c.file_name().and_then(|s| s.to_str()) == Some("target")
        {
            break;
        }
        // Prefer an initialized `.agents` memory database first, then the `.git`
        // repository boundary, so nested workspace sub-crates resolve to the repo root.
        if c.join(".agents").join("memory.ldb").exists() {
            return Some(c.to_path_buf());
        }
        if c.join(".git").exists() {
            return Some(c.to_path_buf());
        }
        if has_project_root_marker(c) {
            fallback_marker = Some(c.to_path_buf());
        }
        curr = c.parent();
    }
    fallback_marker
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

    #[test]
    fn pre_tool_use_shifts_symbol_spans_in_ram_while_preserving_v4_hmac_seal() {
        use super::{LibreDb, NodeKind, Value, WriteRequest};
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "libredb_hook_shift_prod_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
        let ws_repo = base_dir.join("prod_workspace");
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        fs::create_dir_all(ws_repo.join(".git")).unwrap();
        fs::create_dir_all(ws_repo.join("src")).unwrap();

        let src_file = ws_repo.join("src").join("engine.rs");
        let initial_crlf = "pub fn alpha() -> u32 {\r\n    1\r\n}\r\n\r\npub fn omega(x: u32) -> u32 {\r\n    alpha() + x\r\n}\r\n";
        fs::write(&src_file, initial_crlf.as_bytes()).unwrap();

        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(&proj_ldb).unwrap();
            pdb.put(
                WriteRequest::new(NodeKind::Fact, b"core_mode = strict".to_vec())
                    .with_key("core_mode"),
            )
            .unwrap();
            libredb_cognitive::index_workspace(&pdb, &ws_repo, true).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        // 0. First verify aborted/failed tool write safety: `PreToolUse` stages `tentative_edit`
        // WITHOUT mutating live `NodeKind::Symbol`, and an immediate query when disk bytes stayed
        // unchanged discards the tentative edit cleanly with zero phantom line shift!
        let aborted_payload = json!({
            "toolName": "edit_file",
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "toolArgs": {
                "Path": src_file.to_string_lossy().to_string(),
                "Target": "pub fn alpha() -> u32 {\n    1\n}",
                "Replacement": "pub fn alpha() -> u32 {\n    let _aborted_a = 1;\n    let _aborted_b = 2;\n    1\n}"
            }
        });
        let aborted_out = super::evaluate_pre_tool_payload(&aborted_payload, Some(&global_path));
        assert_eq!(aborted_out.get("decision").and_then(Value::as_str), Some("allow"));
        {
            let pdb = LibreDb::open(&proj_ldb).unwrap();
            assert!(
                pdb.get_by_key(NodeKind::WorkingSet, "tentative_edit::src/engine.rs")
                    .is_ok(),
                "Expected tentative_edit::src/engine.rs to be staged before disk write"
            );
            let sym_before = pdb
                .get_by_key(NodeKind::Symbol, "src/engine.rs::omega")
                .unwrap();
            assert!(
                String::from_utf8_lossy(&sym_before.payload).contains("[L5-L7]"),
                "Live Symbol MUST NOT shift before disk write succeeds"
            );
            // Query without writing to disk (simulating aborted IDE edit):
            let impact = libredb_cognitive::query_symbol_impact(&pdb, "omega").unwrap();
            assert!(
                impact[0].contract.contains("[L5-L7]"),
                "Expected [L5-L7] after aborted write, got: {}",
                impact[0].contract
            );
            assert!(
                pdb.get_by_key(NodeKind::WorkingSet, "tentative_edit::src/engine.rs")
                    .is_err(),
                "Aborted tentative edit MUST be discarded on query"
            );
        }

        // Now simulate 10 sequential verified edits via `PreToolUse` -> IDE `fs::write` -> query,
        // verifying: (a) live Symbol never shifts prematurely before `fs::write`, (b) CRLF is preserved,
        // (c) `omega` symbol span promotes atomically right after `fs::write`, and (d) `v4` seal stays valid!
        let mut cur_content = initial_crlf.to_owned();
        for step in 1..=10usize {
            let old_fn = if step == 1 {
                "pub fn alpha() -> u32 {\r\n    1\r\n}".to_owned()
            } else {
                let mut prev = String::from("pub fn alpha() -> u32 {\r\n");
                for k in 1..step {
                    prev.push_str(&format!("    let _pad_{k} = {k}u32;\r\n"));
                }
                prev.push_str("    1\r\n}");
                prev
            };
            let mut next_fn = String::from("pub fn alpha() -> u32 {\r\n");
            for k in 1..=step {
                next_fn.push_str(&format!("    let _pad_{k} = {k}u32;\r\n"));
            }
            next_fn.push_str("    1\r\n}");

            // Pass LF snippets in toolArgs (as LLMs do) while the file on disk uses CRLF:
            let edit_payload = json!({
                "toolName": "edit_file",
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "toolArgs": {
                    "Path": src_file.to_string_lossy().to_string(),
                    "Target": old_fn.replace("\r\n", "\n"),
                    "Replacement": next_fn.replace("\r\n", "\n")
                }
            });
            let out = super::evaluate_pre_tool_payload(&edit_payload, Some(&global_path));
            assert_eq!(out.get("decision").and_then(Value::as_str), Some("allow"));

            // Verify `PreToolUse` NEVER modified `src_file` on disk OR prematurely shifted live Symbol:
            let on_disk_before_ide = fs::read_to_string(&src_file).unwrap();
            assert_eq!(on_disk_before_ide, cur_content);
            {
                let pdb_pre = LibreDb::open(&proj_ldb).unwrap();
                let pre_sym = pdb_pre
                    .get_by_key(NodeKind::Symbol, "src/engine.rs::omega")
                    .unwrap();
                let prev_start = 5 + (step - 1);
                let prev_end = 7 + (step - 1);
                assert!(
                    String::from_utf8_lossy(&pre_sym.payload)
                        .contains(&format!("[L{prev_start}-L{prev_end}]")),
                    "Step {step}: live Symbol shifted before disk write!"
                );
            }

            // Simulate the IDE writing the post-edit CRLF bytes to disk:
            cur_content = cur_content.replacen(&old_fn, &next_fn, 1);
            assert!(cur_content.contains("\r\n"));
            fs::write(&src_file, cur_content.as_bytes()).unwrap();

            // Immediately query without running a full workspace reindex: tentative edit reconciles & promotes!
            let pdb = LibreDb::open(&proj_ldb).unwrap();
            let impact = libredb_cognitive::query_symbol_impact(&pdb, "omega").unwrap();
            let expected_start = 5 + step;
            let expected_end = 7 + step;
            assert!(
                impact[0]
                    .contract
                    .contains(&format!("[L{expected_start}-L{expected_end}]")),
                "Step {step}: expected promoted omega at L{expected_start}-L{expected_end}, got: {}",
                impact[0].contract
            );
        }

        // Security invariant: `hmac-sha256:v4` workspace trust seal MUST still verify cleanly,
        // AND `PreInvocation` MUST NEVER inject `WorkingSet` or `Symbol` content!
        let gdb = LibreDb::open(&global_path).unwrap();
        assert!(crate::security::is_workspace_memory_trusted(
            Some(&gdb),
            &ws_repo
        ));

        let pre_inv = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-shift-seal-check",
                "workspacePaths": [ws_repo.to_string_lossy().to_string()]
            }),
            Some(&global_path),
        )
        .unwrap();
        let pre_inv_str = serde_json::to_string(&pre_inv).unwrap();
        assert!(pre_inv_str.contains("core_mode = strict"));
        assert!(
            !pre_inv_str.contains("omega") && !pre_inv_str.contains("WorkingSet"),
            "Unsealed Symbol/WorkingSet nodes MUST NEVER appear in PreInvocation <SYSTEM_MESSAGE>: {pre_inv_str}"
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn pre_invocation_bm25_recalls_early_fact_within_450_token_cap() {
        use super::{LibreDb, NodeKind, WriteRequest};
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "libredb_pre_inv_bm25_cap_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = std::sync::Arc::new(LibreDb::open(&proj_ldb).unwrap());
            // Saturate tasks (`8` verbose open tasks) so naive sequential hydration would consume > 600 bytes up front:
            for t in 1..=8 {
                let task_body = format!(
                    "[Task: saturate_task_{t}] | in_progress | high | Long operational checklist item #{t} with detailed substeps and verification paths across modules"
                );
                pdb.put(
                    WriteRequest::new(NodeKind::Task, task_body.into_bytes())
                        .with_key(format!("saturate_task_{t}")),
                )
                .unwrap();
            }
            // Fact #1 (oldest): unique early architectural fact that used to be pushed out by recency cap!
            pdb.put(
                WriteRequest::new(
                    NodeKind::Fact,
                    b"early_anchor_fact = Dalvik R8 descriptor resolution uses two-hop supertype table".to_vec(),
                )
                .with_key("early_anchor_fact"),
            )
            .unwrap();
            for i in 2..=30 {
                let filler = format!(
                    "filler_metric_{i:02} = Synthetic historical benchmark observation number {i} with verbose telemetry numbers and padding text to exceed naive budgets"
                );
                pdb.put(
                    WriteRequest::new(NodeKind::Fact, filler.into_bytes())
                        .with_key(format!("filler_metric_{i:02}")),
                )
                .unwrap();
            }
            // Decision #1 (oldest): unique query-relevant architectural decision that MUST NOT be evicted by tasks/facts!
            pdb.put(
                WriteRequest::new(
                    NodeKind::Decision,
                    b"[Decision: early_dalvik_supertype_decision] Enforce exact Dalvik R8 supertype descriptor resolution and method-signature disambiguation across call edges".to_vec(),
                )
                .with_key("early_dalvik_supertype_decision"),
            )
            .unwrap();
            for d in 2..=8 {
                let verbose_dec = format!(
                    "[Decision: verbose_arch_dec_{d}] Long historical architectural narrative #{d}: {}",
                    "detailed design rationale and migration notes across subsystems ".repeat(12)
                );
                pdb.put(
                    WriteRequest::new(NodeKind::Decision, verbose_dec.into_bytes())
                        .with_key(format!("verbose_arch_dec_{d}")),
                )
                .unwrap();
            }
            let mut cog = libredb_cognitive::CognitiveEngine::open_db(std::sync::Arc::clone(&pdb)).unwrap();
            cog.save_index_snapshot().unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        let payload = json!({
            "conversationId": "conv-bm25-cap-check",
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "prompt": "How does Dalvik R8 supertype descriptor resolution work?"
        });
        let out = super::evaluate_pre_invocation_payload(&payload, Some(&global_path)).unwrap();
        let sys_msg = out["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .expect("Expected hydrated systemMessage");

        assert!(
            sys_msg.len() <= super::MAX_PRE_INVOCATION_BYTES,
            "Hydrated PreInvocation message exceeded 1,800-byte (~450-token) cap: {} bytes\n{sys_msg}",
            sys_msg.len()
        );
        assert!(
            sys_msg.contains("early_anchor_fact"),
            "BM25-assisted PreInvocation failed to recall Fact #1 ('early_anchor_fact') from 30 facts:\n{sys_msg}"
        );
        assert!(
            sys_msg.contains("early_dalvik_supertype_decision"),
            "BM25-assisted PreInvocation failed to protect Decision #1 ('early_dalvik_supertype_decision') from eviction under task/fact saturation:\n{sys_msg}"
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    /// S16 (v1.4.0): `PreInvocation` proactively injects learned reflexes matching the prompt
    /// (sealed `NodeKind::Rule` capsules) within the 1,800-byte budget, and nothing otherwise.
    #[test]
    fn pre_invocation_injects_only_matching_learned_reflexes() {
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "libredb_preinv_reflex_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();
            let pdb = std::sync::Arc::new(libredb_core::LibreDb::open(&proj_ldb).unwrap());
            pdb.put(
                libredb_core::WriteRequest::new(
                    libredb_core::NodeKind::Fact,
                    b"db_engine = PostgreSQL 16 with logical replication".to_vec(),
                )
                .with_key("db_engine"),
            )
            .unwrap();
            libredb_cognitive::ReflexEngine::learn_reflex(
                &pdb,
                &libredb_cognitive::ReflexRule {
                    id: "migration-lock-guard".to_owned(),
                    action_any: vec!["migration".to_owned()],
                    directive: "Run schema migrations only while holding the advisory lock.".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        let hit_payload = json!({
            "conversationId": "conv-reflex-hit",
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "prompt": "Please write the migration for the users table"
        });
        let out = super::evaluate_pre_invocation_payload(&hit_payload, Some(&global_path)).unwrap();
        let sys_msg = out["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .expect("Expected hydrated systemMessage");
        assert!(sys_msg.len() <= super::MAX_PRE_INVOCATION_BYTES);
        assert!(
            sys_msg.contains("Learned Reflexes:") && sys_msg.contains("migration-lock-guard"),
            "Matching reflex must be injected proactively:\n{sys_msg}"
        );

        let miss_payload = json!({
            "conversationId": "conv-reflex-miss",
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "prompt": "Update the README badges"
        });
        let out2 = super::evaluate_pre_invocation_payload(&miss_payload, Some(&global_path)).unwrap();
        let sys_msg2 = out2["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .unwrap_or("");
        assert!(
            !sys_msg2.contains("migration-lock-guard"),
            "Non-matching prompt must not inject the reflex:\n{sys_msg2}"
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn pre_tool_use_harvests_transcript_command_errors_and_binds_verified_edit_into_pitfall_book() {
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "libredb_hook_err_harvest_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join("src")).unwrap();
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        fs::write(
            ws_repo.join("Cargo.toml"),
            "[package]\nname = \"err_harvest\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let src_path = ws_repo.join("src").join("lib.rs");
        let orig_src = "pub fn hard_kill_os_process() {\n    drop_stdin();\n}\n";
        fs::write(&src_path, orig_src).unwrap();

        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();
            let pdb = std::sync::Arc::new(libredb_core::LibreDb::open(&proj_ldb).unwrap());
            libredb_cognitive::index_workspace(&pdb, &ws_repo, false).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        let logs_dir = base_dir.join(".system_generated").join("logs");
        let tasks_dir = base_dir.join(".system_generated").join("tasks");
        fs::create_dir_all(&logs_dir).unwrap();
        fs::create_dir_all(&tasks_dir).unwrap();
        let transcript_path = logs_dir.join("transcript.jsonl");
        let task_log_path = tasks_dir.join("task-42.log");
        fs::write(
            &task_log_path,
            "running 1 test\ntest e2e_sigkill ... FAILED\n",
        )
        .unwrap();
        let task_uri = format!(
            "file:///{}",
            task_log_path
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches('/')
        );

        let lines = [
            json!({
                "step_index": 1,
                "type": "GENERIC",
                "content": "Created At: 2026-11-14T10:00:00Z\nShowing lines 1-20 of 20\n10: error: expected ';', found '}'\n"
            })
            .to_string(),
            json!({
                "step_index": 2,
                "type": "GENERIC",
                "content": "Command output:\nerror: expected ';', found '}'\n"
            })
            .to_string(),
            json!({
                "step_index": 3,
                "type": "GENERIC",
                "content": format!(
                    "Task logs are available at: {task_uri}\nCommand output:\nTask Description: .\\target\\release\\libredb.exe learn-error \"thread 'x' panicked at y:1:1\"\nthread 'e2e_sigkill' panicked at crates/foo.rs:275:5:\nReal OS SIGKILL MUST bypass Drop!\n"
                )
            })
            .to_string(),
        ];
        fs::write(&transcript_path, format!("{}\n", lines.join("\n"))).unwrap();

        let new_src = "pub fn hard_kill_os_process() {\n    let keep_stdin_open_until_killed = stdin_take();\n    kill_and_wait(keep_stdin_open_until_killed);\n}\n";
        let pre_tool_payload = json!({
            "conversationId": "conv-hook-err-harvest",
            "transcriptPath": transcript_path.to_string_lossy().to_string(),
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "toolName": "edit_file",
            "toolArgs": {
                "Path": src_path.to_string_lossy().to_string(),
                "Target": "drop_stdin();",
                "Replacement": "let keep_stdin_open_until_killed = stdin_take();\n    kill_and_wait(keep_stdin_open_until_killed);"
            }
        });
        let pre_tool_out =
            super::evaluate_pre_tool_payload(&pre_tool_payload, Some(&global_path));
        assert_eq!(pre_tool_out["decision"], "allow");

        let rep_mid = {
            let pdb_mid = libredb_core::LibreDb::open(&proj_ldb).unwrap();
            libredb_cognitive::learning_state_report(&pdb_mid, 10)
        };
        assert!(
            rep_mid.counters.trivial_errors_filtered >= 1,
            "Banal ';' slip in command output must be Stage-1 filtered: {:?}",
            rep_mid.counters
        );
        assert_eq!(
            rep_mid.pending_errors.len(),
            1,
            "Expected exactly 1 harvested non-banal panic cue (and read_file ignored): {:?}",
            rep_mid.pending_errors
        );
        let cues_before_second_pass = rep_mid.counters.error_cues_recorded;

        // Apply the verified edit to disk, then invoke PreInvocation to reconcile and bind.
        fs::write(&src_path, new_src).unwrap();
        let pre_inv_payload = json!({
            "conversationId": "conv-hook-err-harvest",
            "transcriptPath": transcript_path.to_string_lossy().to_string(),
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "prompt": "Check the test result"
        });
        let _ = super::evaluate_pre_invocation_payload(&pre_inv_payload, Some(&global_path))
            .unwrap();

        let rep_after = {
            let pdb_after = libredb_core::LibreDb::open(&proj_ldb).unwrap();
            libredb_cognitive::learning_state_report(&pdb_after, 10)
        };
        assert_eq!(
            rep_after.counters.pitfalls_learned, 1,
            "Verified structural fix must bind the harvested transcript panic cue into error_pitfall_book: {:?}",
            rep_after
        );
        assert_eq!(rep_after.learned_pitfalls.len(), 1);
        assert!(
            rep_after.learned_pitfalls[0]
                .resolution_tokens
                .iter()
                .any(|t| t == "keep_stdin_open_until_killed"),
            "Expected structural fix token 'keep_stdin_open_until_killed' in pitfall resolution_tokens: {:?}",
            rep_after.learned_pitfalls[0]
        );

        // Re-running PreInvocation must not re-harvest already processed transcript steps and
        // must keep the workspace hmac-sha256:v4 trust seal valid.
        let pre_inv_payload_2 = json!({
            "conversationId": "conv-hook-err-harvest",
            "transcriptPath": transcript_path.to_string_lossy().to_string(),
            "workspacePaths": [ws_repo.to_string_lossy().to_string()],
            "prompt": "Another prompt"
        });
        let _ = super::evaluate_pre_invocation_payload(&pre_inv_payload_2, Some(&global_path))
            .unwrap();
        let rep_recheck = {
            let pdb_recheck = libredb_core::LibreDb::open(&proj_ldb).unwrap();
            libredb_cognitive::learning_state_report(&pdb_recheck, 10)
        };
        assert_eq!(
            rep_recheck.counters.error_cues_recorded, cues_before_second_pass,
            "Already-harvested transcript steps must not be re-recorded"
        );
        let trusted_after = {
            let gdb_recheck = libredb_core::LibreDb::open(&global_path).unwrap();
            crate::security::is_workspace_memory_trusted(Some(&gdb_recheck), &ws_repo)
        };
        assert!(
            trusted_after,
            "Transcript error harvesting and pitfall learning must preserve hmac-sha256:v4 trust seal"
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn pre_invocation_refutes_failed_tentative_fix_and_hydrates_sealed_error_reflex() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_refute_hook_test_{}_{}", std::process::id(), nanos));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join("src")).unwrap();
        fs::write(
            ws_repo.join("Cargo.toml"),
            "[package]\nname = \"refute_hook\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let src_path = ws_repo.join("src").join("lib.rs");
        let orig_src = "pub fn clone_lease_token(tok: &str) -> String {\n    tok.to_owned()\n}\n\npub fn renew_session(lease_token: String) -> usize {\n    lease_token.len()\n}\n";
        fs::write(&src_path, orig_src).unwrap();

        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();
            let pdb = std::sync::Arc::new(libredb_core::LibreDb::open(&proj_ldb).unwrap());
            libredb_cognitive::index_workspace(&pdb, &ws_repo, false).unwrap();
            let rx_rule = libredb_cognitive::ReflexRule {
                id: "seal-borrow-lease-token".to_owned(),
                env_or_error_any: vec!["E0382".to_owned(), "lease_token".to_owned()],
                directive: "Borrow-check fix: call clone_lease_token before renewing session.".to_owned(),
                code_anchors: vec!["src/lib.rs::renew_session".to_owned()],
                ..Default::default()
            };
            libredb_cognitive::ReflexEngine::learn_reflex(&pdb, &rx_rule).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        let logs_dir = base_dir.join(".system_generated").join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        let transcript_path = logs_dir.join("transcript.jsonl");
        let err_line = json!({
            "step_index": 1,
            "type": "GENERIC",
            "content": "Command output:\nerror[E0382]: borrow of moved value 'lease_token' in renew_session\n"
        })
        .to_string();
        fs::write(&transcript_path, format!("{err_line}\n")).unwrap();

        // Turn 1: initial PreInvocation hydrates workspace and records pre_inv_dedup for @ep=1.
        let inv1 = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-hook-refute",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "prompt": "Fix the lease_token borrow error in renew_session"
            }),
            Some(&global_path),
        )
        .unwrap();
        assert!(!inv1["injectSteps"].as_array().unwrap().is_empty());

        // Turn 1 tool: stage and write an ineffective edit (`bad_attempt()`).
        let bad_src = orig_src.replace(
            "    lease_token.len()\n",
            "    let bad_attempt = lease_token.len();\n    bad_attempt\n",
        );
        let pt1 = super::evaluate_pre_tool_payload(
            &json!({
                "conversationId": "conv-hook-refute",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "toolName": "edit_file",
                "toolArgs": {
                    "Path": src_path.to_string_lossy().to_string(),
                    "Target": "    lease_token.len()",
                    "Replacement": "    let bad_attempt = lease_token.len();\n    bad_attempt"
                }
            }),
            Some(&global_path),
        );
        assert_eq!(pt1["decision"], "allow");
        fs::write(&src_path, &bad_src).unwrap();

        // Post-edit build fails again with the exact same error at step_index 2.
        let err_line_2 = json!({
            "step_index": 2,
            "type": "GENERIC",
            "content": "Command output:\nerror[E0382]: borrow of moved value 'lease_token' in renew_session\n"
        })
        .to_string();
        fs::write(&transcript_path, format!("{err_line}\n{err_line_2}\n")).unwrap();

        // Turn 2: PreInvocation reconciles bad_src first, then harvests step 2 -> refutes failed fix
        // AND bypasses pre_inv_dedup to surface the sealed reflex!
        let inv2 = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-hook-refute",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "prompt": "Continue checking the build"
            }),
            Some(&global_path),
        )
        .unwrap();
        let msg2 = inv2["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .unwrap_or("");
        assert!(
            msg2.contains("seal-borrow-lease-token"),
            "Expected PreInvocation to bypass dedup and hydrate sealed reflex on newly harvested error:\n{msg2}"
        );

        let rep_refuted = {
            let pdb = libredb_core::LibreDb::open(&proj_ldb).unwrap();
            libredb_cognitive::learning_state_report(&pdb, 10)
        };
        assert_eq!(rep_refuted.counters.failed_fixes_refuted, 1);
        assert_eq!(rep_refuted.learned_pitfalls.len(), 1);
        assert!(
            rep_refuted.learned_pitfalls[0].confidence < libredb_cognitive::ACTIVE_PITFALL_MIN_CONFIDENCE,
            "Refuted fix must drop below active threshold: {:?}",
            rep_refuted.learned_pitfalls[0]
        );

        // Turn 2 tool + Turn 3: apply the verified fix (`clone_lease_token`).
        let good_src = bad_src.replace(
            "    let bad_attempt = lease_token.len();\n    bad_attempt\n",
            "    clone_lease_token(&lease_token).len()\n",
        );
        let pt2 = super::evaluate_pre_tool_payload(
            &json!({
                "conversationId": "conv-hook-refute",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "toolName": "edit_file",
                "toolArgs": {
                    "Path": src_path.to_string_lossy().to_string(),
                    "Target": "    let bad_attempt = lease_token.len();\n    bad_attempt",
                    "Replacement": "    clone_lease_token(&lease_token).len()"
                }
            }),
            Some(&global_path),
        );
        assert_eq!(pt2["decision"], "allow");
        fs::write(&src_path, &good_src).unwrap();

        let _ = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-hook-refute",
                "transcriptPath": transcript_path.to_string_lossy().to_string(),
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "prompt": "Verify fix landed"
            }),
            Some(&global_path),
        )
        .unwrap();

        let rep_fixed = {
            let pdb = libredb_core::LibreDb::open(&proj_ldb).unwrap();
            libredb_cognitive::learning_state_report(&pdb, 10)
        };
        assert!(
            rep_fixed.learned_pitfalls[0].confidence >= libredb_cognitive::ACTIVE_PITFALL_MIN_CONFIDENCE,
            "Verified fix after refutation must recover active confidence: {:?}",
            rep_fixed.learned_pitfalls[0]
        );
        assert!(
            rep_fixed.learned_pitfalls[0]
                .resolution_tokens
                .iter()
                .any(|t| t == "clone_lease_token"),
            "Expected clone_lease_token in updated pitfall: {:?}",
            rep_fixed.learned_pitfalls[0]
        );
        assert!(rep_fixed.counters.method_supersedes_applied >= 1);

        let trusted_after = {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();
            crate::security::is_workspace_memory_trusted(Some(&gdb), &ws_repo)
        };
        assert!(trusted_after, "Workspace seal must remain valid after refutation and recovery");

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn find_workspace_root_prefers_memory_and_git_root_over_subcrate_cargo_toml() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_root_res_{}_{}", std::process::id(), nanos));

        // Case 1: Cargo workspace with `.agents/memory.ldb` and `.git` at root, nested sub-crate Cargo.toml.
        let repo_a = base_dir.join("repo_a");
        let sub_a = repo_a.join("crates").join("ws4w-core").join("src");
        fs::create_dir_all(&sub_a).unwrap();
        fs::create_dir_all(repo_a.join(".git")).unwrap();
        fs::write(repo_a.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/ws4w-core\"]\n").unwrap();
        fs::write(repo_a.join("crates").join("ws4w-core").join("Cargo.toml"), "[package]\nname = \"ws4w-core\"\n").unwrap();
        let nested_file = sub_a.join("firewall.rs");
        fs::write(&nested_file, "pub fn check() {}\n").unwrap();

        // Even before `.agents/memory.ldb` is created, `.git` boundary beats inner `Cargo.toml`.
        assert_eq!(super::find_workspace_root(&nested_file), Some(repo_a.clone()));

        // Once `.agents/memory.ldb` exists at root, it resolves directly to root.
        fs::create_dir_all(repo_a.join(".agents")).unwrap();
        {
            let _ = libredb_core::LibreDb::open(&repo_a.join(".agents").join("memory.ldb")).unwrap();
        }
        assert_eq!(super::find_workspace_root(&nested_file), Some(repo_a.clone()));

        // Case 2: Pure Cargo workspace without `.git` or `.agents/` stops cleanly at `target` boundary.
        let repo_b = base_dir.join("repo_b");
        let sub_b = repo_b.join("crates").join("sub").join("src");
        fs::create_dir_all(&sub_b).unwrap();
        fs::write(repo_b.join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(repo_b.join("crates").join("sub").join("Cargo.toml"), "[package]\nname = \"sub\"\n").unwrap();
        let file_b = sub_b.join("lib.rs");
        fs::write(&file_b, "").unwrap();
        assert_eq!(super::find_workspace_root(&file_b), Some(repo_b));

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn extract_error_diagnostics_parses_short_cargo_and_drops_summary_noise() {
        let output = "\
error: could not compile `ws4w-core` (lib) due to 12 previous errors\n\
Error: Unknown 'git-init' flag '--help'. Check CLI help.\n\
crates/ws4w-core/src/lib.rs:10:5: error: unclosed delimiter\n\
crates/ws4w-core/src/firewall.rs:42:13: error[E0425]: cannot find value `netfw_policy` in this scope\n\
src/app.ts(18,7): error TS2345: Argument of type 'string' is not assignable.\n";
        let diags = super::extract_error_diagnostics_from_command_output(output);
        assert_eq!(diags.len(), 2, "Expected only genuine causal errors: {diags:?}");
        assert!(diags[0].contains("E0425"));
        assert!(diags[1].contains("TS2345"));
    }

    #[test]
    fn pre_invocation_injects_style_invariant_within_byte_budget() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_style_inv_{}_{}", std::process::id(), nanos));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join("src")).unwrap();
        fs::write(ws_repo.join("Cargo.toml"), "[package]\nname = \"style_inv\"\nversion = \"0.1.0\"\n").unwrap();
        fs::write(ws_repo.join("src").join("lib.rs"), "pub fn ping() -> u32 { 1 }\n").unwrap();

        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();
            let _ = gdb.put(
                libredb_core::WriteRequest::new(libredb_core::NodeKind::Config, b"true".to_vec())
                    .with_key("guardrail:style_rules"),
            );
            let pdb = std::sync::Arc::new(libredb_core::LibreDb::open(&proj_ldb).unwrap());
            pdb.put(
                libredb_core::WriteRequest::new(
                    libredb_core::NodeKind::Fact,
                    b"Ping service responds on port 8080".to_vec(),
                )
                .with_key("ping_port"),
            )
            .unwrap();
            libredb_cognitive::index_workspace(&pdb, &ws_repo, false).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        let res = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-style-inv",
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "prompt": "Check ping implementation"
            }),
            Some(&global_path),
        )
        .unwrap();
        let serialized = res.to_string();
        assert!(
            serialized.contains("Style Invariant:"),
            "Expected compact Style Invariant line when guardrail:style_rules=true: {serialized}"
        );
        let injected = res["injectSteps"][0]["content"]
            .as_str()
            .or_else(|| res["injectSteps"][0]["text"].as_str())
            .unwrap_or("");
        assert!(
            injected.len() <= 2100,
            "Injected PreInvocation block exceeded compact ceiling ({} bytes)",
            injected.len()
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn pre_invocation_surfaces_code_graph_readiness_when_symbols_indexed() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_cg_hint_{}_{}", std::process::id(), nanos));
        let ws_repo = base_dir.join("repo");
        fs::create_dir_all(ws_repo.join("src")).unwrap();
        fs::write(
            ws_repo.join("Cargo.toml"),
            "[package]\nname = \"cg_hint\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            ws_repo.join("src").join("lib.rs"),
            "pub fn alpha_fn() -> u32 { 1 }\npub fn beta_fn() -> u32 { alpha_fn() + 1 }\n",
        )
        .unwrap();

        let global_path = base_dir.join("customizations.ldb");
        let proj_ldb = ws_repo.join(".agents").join("memory.ldb");
        let empty_repo = base_dir.join("empty_repo");
        fs::create_dir_all(&empty_repo).unwrap();
        let empty_ldb = empty_repo.join(".agents").join("memory.ldb");
        {
            let gdb = libredb_core::LibreDb::open(&global_path).unwrap();

            let pdb = std::sync::Arc::new(libredb_core::LibreDb::open(&proj_ldb).unwrap());
            libredb_cognitive::index_workspace(&pdb, &ws_repo, false).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();

            let epdb = std::sync::Arc::new(libredb_core::LibreDb::open(&empty_ldb).unwrap());
            epdb.put(
                libredb_core::WriteRequest::new(libredb_core::NodeKind::Fact, b"empty".to_vec())
                    .with_key("k"),
            )
            .unwrap();
            crate::security::seal_workspace_memory(&gdb, &epdb, &empty_repo).unwrap();
        }

        let res_sym = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-cg-sym",
                "workspacePaths": [ws_repo.to_string_lossy().to_string()],
                "prompt": "Check alpha_fn"
            }),
            Some(&global_path),
        )
        .unwrap();
        let ser_sym = res_sym.to_string();
        assert!(
            ser_sym.contains("Code Graph: 2 symbols indexed")
                && ser_sym.contains("libredb locate")
                && ser_sym.contains("libredb fim --symbol")
                && ser_sym.contains("libredb grep"),
            "Expected compact Code Graph readiness line when Symbol inodes > 0: {ser_sym}"
        );

        let res_empty = super::evaluate_pre_invocation_payload(
            &json!({
                "conversationId": "conv-cg-empty",
                "workspacePaths": [empty_repo.to_string_lossy().to_string()],
                "prompt": "Check empty"
            }),
            Some(&global_path),
        )
        .unwrap();
        assert!(
            !res_empty.to_string().contains("Code Graph:"),
            "Must omit Code Graph line when 0 Symbol inodes exist: {res_empty}"
        );

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn pre_tool_use_blocks_ambiguous_multi_match_symbol_duplication_and_allows_benign_renames() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_multi_edit_{}_{}", std::process::id(), nanos));
        fs::create_dir_all(&base_dir).unwrap();
        let global_path = base_dir.join("customizations.ldb");
        {
            let _gdb = libredb_core::LibreDb::open(&global_path).unwrap();
        }
        let target_rs = base_dir.join("tests.rs");
        let sample = "\
#[test]
fn case_one() {
    drop(state);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn case_two() {
    drop(state);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn case_three() {
    drop(state);
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn unique_end() {
    let sentinel = 999;
}
";
        fs::write(&target_rs, sample).unwrap();

        // 1. Ambiguous 3-site anchor appending a new #[test] MUST be blocked with exact line numbers!
        let dup_deny = super::evaluate_pre_tool_payload(
            &json!({
                "toolName": "edit_file",
                "toolInput": {
                    "Path": target_rs.to_string_lossy(),
                    "Target": "    drop(state);\n    let _ = fs::remove_dir_all(&tmp);\n}",
                    "Replacement": "    drop(state);\n    let _ = fs::remove_dir_all(&tmp);\n}\n\n#[test]\nfn dup_case() {\n    assert!(true);\n}"
                }
            }),
            Some(&global_path),
        );
        assert_eq!(dup_deny["decision"], "deny", "Multi-site test insertion must be blocked: {dup_deny}");
        let reason = dup_deny["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("3 locations")
                && reason.contains("L3")
                && reason.contains("L9")
                && reason.contains("L15"),
            "Deny message should report exact duplicate anchor lines: {reason}"
        );

        // 2. Benign multi-site identifier/text replacement (0 new declarations) MUST remain allowed!
        let rename_allow = super::evaluate_pre_tool_payload(
            &json!({
                "toolName": "edit_file",
                "toolInput": {
                    "Path": target_rs.to_string_lossy(),
                    "Target": "remove_dir_all(&tmp)",
                    "Replacement": "remove_dir_all(&work_dir)"
                }
            }),
            Some(&global_path),
        );
        assert_eq!(rename_allow["decision"], "allow", "Benign rename across multiple sites must be allowed: {rename_allow}");

        // 3. Single-site unique anchor appending a new #[test] MUST remain allowed!
        let unique_allow = super::evaluate_pre_tool_payload(
            &json!({
                "toolName": "edit_file",
                "toolInput": {
                    "Path": target_rs.to_string_lossy(),
                    "Target": "fn unique_end() {\n    let sentinel = 999;\n}",
                    "Replacement": "fn unique_end() {\n    let sentinel = 999;\n}\n\n#[test]\nfn next_unique_test() {\n    assert_eq!(1, 1);\n}"
                }
            }),
            Some(&global_path),
        );
        assert_eq!(unique_allow["decision"], "allow", "Unique anchor test append must be allowed: {unique_allow}");

        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn extract_prompt_hint_prefers_last_user_input_without_touching_transcript() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_prompt_hint_{}_{}", std::process::id(), nanos));
        fs::create_dir_all(&base_dir).unwrap();
        let transcript = base_dir.join("transcript.jsonl");
        fs::write(
            &transcript,
            "{\"type\":\"USER_INPUT\",\"content\":\"stale transcript prompt\"}\n",
        )
        .unwrap();

        let camel_payload = json!({
            "lastUserInput": "<SYSTEM_MESSAGE>hidden</SYSTEM_MESSAGE>\n<USER_REQUEST>Fix canonical installer path</USER_REQUEST>"
        });
        assert_eq!(
            super::extract_prompt_hint(&camel_payload, Some(&transcript)),
            Some("Fix canonical installer path".to_owned())
        );

        let snake_payload = json!({
            "last_user_input": "Check snake case last_user_input field"
        });
        assert_eq!(
            super::extract_prompt_hint(&snake_payload, Some(&transcript)),
            Some("Check snake case last_user_input field".to_owned())
        );

        let _ = fs::remove_dir_all(&base_dir);
    }
}
