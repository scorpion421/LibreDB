//! Multi-workspace, low-prompt-footprint Model Context Protocol (`MCP`) JSON-RPC 2.0 server.
//!
//! Design highlights for Antigravity:
//! 1. **78% Smaller Tool Schema Overhead:** Exposes 3 consolidated, surgical tools (`libredb_pulse`,
//!    `libredb_code`, `libredb_memorize`) in `tools/list` so per-turn system-prompt declaration cost
//!    stays minimal (`~240 tokens`), while keeping legacy granular tool names working in `tools/call`.
//! 2. **Dynamic Per-Workspace Brain Cache:** Resolves `<workspace_root>/.agents/memory.ldb` on the
//!    fly from `cwd` or `target` and caches hot `OverlayBrain` instances in RAM across workspaces.
//! 3. **Hands-Free `/compact` Detection:** Automatically locates Antigravity's `transcript.jsonl`
//!    from `cid` (`~/.gemini/antigravity/brain/<cid>/.system_generated/logs/transcript.jsonl`).

use crate::hooks::{is_protected_profile_dir, open_global_ldb, open_project_ldb_silent};
use libredb_bridge::import_sqlite_readonly;
use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, index_workspace,
    query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton,
    OverlayBrain, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::LibreDb;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct McpServerState {
    default_project_path: PathBuf,
    global_path: Option<PathBuf>,
    global_db: Option<Arc<LibreDb>>,
    brains: HashMap<PathBuf, OverlayBrain>,
}

impl McpServerState {
    pub fn new(default_project_path: Option<&Path>, global_path: Option<&Path>) -> Result<Self, String> {
        let fallback_proj = match default_project_path {
            Some(p) => p.to_path_buf(),
            None => default_libredb_home().join("default_memory.ldb"),
        };
        let global_path_buf = global_path.map(Path::to_path_buf);
        let global_db = match global_path {
            Some(gp) => Some(open_global_ldb(Some(gp))?),
            None => None,
        };

        Ok(Self {
            default_project_path: fallback_proj,
            global_path: global_path_buf,
            global_db,
            brains: HashMap::new(),
        })
    }

    fn resolve_brain_mut(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
    ) -> Result<&mut OverlayBrain, String> {
        let db_path = match hint_path {
            Some(raw) if !raw.trim().is_empty() => {
                resolve_workspace_ldb_path(Path::new(raw.trim()), &self.default_project_path)
            }
            _ => match cid_opt.and_then(infer_chat_memory_ldb_path) {
                Some(chat_ldb) => chat_ldb,
                None => self.default_project_path.clone(),
            },
        };

        if !self.brains.contains_key(&db_path) {
            let (proj_db, _) = open_project_ldb_silent(&db_path)?;
            let brain =
                OverlayBrain::open(self.global_db.clone(), proj_db).map_err(|e| e.to_string())?;
            self.brains.insert(db_path.clone(), brain);
        }

        let brain = self.brains.get_mut(&db_path).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok(brain)
    }

    fn reload_global_db(&mut self) -> Result<(), String> {
        if let Some(ref gp) = self.global_path {
            let gdb = Arc::new(LibreDb::open(gp).map_err(|e| e.to_string())?);
            self.global_db = Some(gdb);
            self.brains.clear();
        }
        Ok(())
    }
}

pub fn run_mcp_stdio_server(
    default_project_db: Option<&Path>,
    global_db_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = McpServerState::new(default_project_db, global_db_path)?;

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                writeln!(stdout, "{err_resp}")?;
                stdout.flush()?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        if id.is_none() {
            continue;
        }
        let req_id = id.unwrap();

        let response = match handle_rpc_method(method, &params, &mut state) {
            Ok(result_val) => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result_val
            }),
            Err(err_msg) => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": { "code": -32000, "message": err_msg }
            }),
        };

        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }

    Ok(())
}

pub fn handle_rpc_method(
    method: &str,
    params: &Value,
    state: &mut McpServerState,
) -> Result<Value, String> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "libredb-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "libredb_pulse",
                    "description": "One-shot dual-layer recall (global + workspace .agents/memory.ldb) with Zero-Repeat Delta deduplication, proactive pitfall reflexes, and auto /compact epoch sync.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Concept, symbol, or task query" },
                            "cwd": { "type": "string", "description": "Active workspace directory" },
                            "cid": { "type": "string", "description": "Conversation ID for Zero-Repeat Delta & auto /compact sync" },
                            "budget": { "type": "integer", "default": 600 },
                            "error": { "type": "string", "description": "Optional error text to trigger pitfall reflexes" }
                        },
                        "required": ["query"]
                    }
                },
                {
                    "name": "libredb_code",
                    "description": "Zero-bloat source code graph: 'skeleton' (-95% file map), 'impact' (callers + governing decisions), 'fim' (surgical edit slice + callers + decisions), or 'index' (scan workspace).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string", "enum": ["skeleton", "impact", "fim", "index"] },
                            "target": { "type": "string", "description": "File path, workspace directory, or symbol query" },
                            "cwd": { "type": "string" },
                            "symbol": { "type": "string", "description": "Symbol filter or FIM target" },
                            "line": { "type": "integer" },
                            "pad": { "type": "integer", "default": 12 }
                        },
                        "required": ["action", "target"]
                    }
                },
                {
                    "name": "libredb_memorize",
                    "description": "Atomically persists workspace facts, decisions (auto-linked to code symbols), tasks, snapshots, handoffs, language-agnostic Hebbian bridges, or situational reflexes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cwd": { "type": "string" },
                            "cid": { "type": "string" },
                            "facts": { "type": "object" },
                            "decisions": { "type": "object" },
                            "tasks": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "key": { "type": "string" },
                                        "title": { "type": "string" },
                                        "status": { "type": "string" },
                                        "priority": { "type": "string" }
                                    },
                                    "required": ["key", "title"]
                                }
                            },
                            "snapshot": { "type": "string" },
                            "learn_assoc": {
                                "type": "object",
                                "properties": {
                                    "cue": { "type": "string" },
                                    "target_ids": { "type": "array", "items": { "type": "integer" } }
                                }
                            },
                            "learn_reflex": {
                                "type": "object",
                                "properties": {
                                    "id": { "type": "string" },
                                    "directive": { "type": "string" },
                                    "stack": { "type": "array", "items": { "type": "string" } },
                                    "action": { "type": "array", "items": { "type": "string" } },
                                    "env": { "type": "array", "items": { "type": "string" } }
                                }
                            },
                            "sync_central_sqlite": { "type": "boolean" }
                        }
                    }
                }
            ]
        })),
        "tools/call" => {
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or("Missing tool name")?;
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let text_out = dispatch_tool(tool_name, &args, state).map_err(|e| e.to_string())?;
            Ok(json!({
                "content": [{ "type": "text", "text": text_out }]
            }))
        }
        other => Err(format!("Unsupported RPC method '{other}'")),
    }
}

fn dispatch_tool(
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
            if let Some(d) = args.get("cwd").and_then(Value::as_str) {
                req.workspace_dir = Some(PathBuf::from(d));
            }
            if let Some(err) = args.get("error").and_then(Value::as_str) {
                req.error_context = Some(err.to_owned());
            }

            let brain = state.resolve_brain_mut(cwd_hint, cid_arg)?;
            if let Some(cid) = cid_arg {
                req.conversation_id = Some(cid.to_owned());
                let tp_opt = args
                    .get("transcript_path")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| infer_antigravity_transcript_path(cid));
                if let Some(tp) = tp_opt {
                    if tp.exists() {
                        req.epoch = sync_transcript_epoch(brain.project_db(), cid, &tp)?;
                    }
                }
            }

            let resp = brain.pulse(&req)?;
            Ok(resp.format_compact())
        }
        "libredb_code" => {
            let action = args.get("action").and_then(Value::as_str).unwrap_or("skeleton");
            let target = args.get("target").and_then(Value::as_str).ok_or("Missing target")?;
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;

            let brain = state.resolve_brain_mut(cwd_hint.or(Some(target)), cid_arg)?;
            let proj_db = Arc::clone(brain.project_db());

            match action {
                "skeleton" => {
                    let (skel, _) = FileSkeleton::index_or_get_cached(&proj_db, Path::new(target), None)?;
                    Ok(skel.render_compact(sym, sym.is_some()))
                }
                "impact" => {
                    let reports = query_symbol_impact(&proj_db, target)?;
                    Ok(serde_json::to_string_pretty(&reports)?)
                }
                "fim" => {
                    let bundle = extract_fim_slice(&proj_db, Path::new(target), sym, line, pad)?;
                    Ok(bundle.format_compact())
                }
                "index" => {
                    let rep = index_workspace(&proj_db, Path::new(target), false)?;
                    let mut cog = CognitiveEngine::open_db(proj_db)?;
                    cog.save_index_snapshot()?;
                    brain.refresh_if_needed()?;
                    Ok(serde_json::to_string_pretty(&rep)?)
                }
                other => Err(format!("Unsupported libredb_code action '{other}'").into()),
            }
        }
        "libredb_memorize" | "libredb_batch" => {
            let mut outputs: Vec<String> = Vec::new();

            if args.get("sync_central_sqlite").and_then(Value::as_bool) == Some(true) {
                let central_sqlite = user_home_dir().join(".gemini").join("database").join("customizations.db");
                if let Some(ref gp) = state.global_path.clone() {
                    if central_sqlite.exists() {
                        let gdb = Arc::new(LibreDb::open(gp)?);
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

            let brain = state.resolve_brain_mut(cwd_hint, cid_arg)?;
            let proj_db = Arc::clone(brain.project_db());

            let mut spec = AtomicBatchSpec::default();
            if let Some(fmap) = args.get("facts").and_then(Value::as_object) {
                for (k, v) in fmap {
                    spec.facts.push((
                        k.clone(),
                        v.as_str().map(ToOwned::to_owned).unwrap_or_else(|| v.to_string()),
                    ));
                }
            }
            if let Some(dmap) = args.get("decisions").and_then(Value::as_object) {
                for (k, v) in dmap {
                    spec.decisions.push((
                        k.clone(),
                        v.as_str().map(ToOwned::to_owned).unwrap_or_else(|| v.to_string()),
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
                            .map(|a| a.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect())
                            .unwrap_or_default()
                    };
                    let rule = ReflexRule {
                        id: id.to_owned(),
                        stack_any: parse_arr("stack"),
                        action_any: parse_arr("action"),
                        env_or_error_any: parse_arr("env"),
                        directive: dir.to_owned(),
                    };
                    let nid = ReflexEngine::learn_reflex(&proj_db, &rule)?;
                    outputs.push(format!("Learned reflex '{id}' (#{nid})"));
                }
            }

            brain.refresh_if_needed()?;
            if outputs.is_empty() {
                Ok("No mutations requested.".to_owned())
            } else {
                Ok(outputs.join(" | "))
            }
        }
        // Backwards-compatible legacy aliases:
        "libredb_skeleton" => {
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
            let flt = args.get("filter").and_then(Value::as_str);
            let brain = state.resolve_brain_mut(Some(fp), cid_arg)?;
            let (skel, _) = FileSkeleton::index_or_get_cached(brain.project_db(), Path::new(fp), None)?;
            Ok(skel.render_compact(flt, flt.is_some()))
        }
        "libredb_impact" => {
            let sym = args.get("symbol").and_then(Value::as_str).ok_or("Missing symbol")?;
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg)?;
            let reports = query_symbol_impact(brain.project_db(), sym)?;
            Ok(serde_json::to_string_pretty(&reports)?)
        }
        "libredb_fim" => {
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;
            let brain = state.resolve_brain_mut(Some(fp), cid_arg)?;
            let bundle = extract_fim_slice(brain.project_db(), Path::new(fp), sym, line, pad)?;
            Ok(bundle.format_compact())
        }
        "libredb_handoff" => {
            let hid = args.get("handoff_id").and_then(Value::as_str).ok_or("Missing handoff_id")?;
            let tkey = args.get("task_key").and_then(Value::as_str).ok_or("Missing task_key")?;
            let role = args.get("role").and_then(Value::as_str).ok_or("Missing role")?;
            let notes = args.get("instructions").and_then(Value::as_str).unwrap_or("");
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg)?;
            let (_, block) = create_subagent_handoff(brain.project_db(), hid, tkey, role, notes)?;
            Ok(block)
        }
        other => Err(format!("Unknown tool '{other}'").into()),
    }
}

fn user_home_dir() -> PathBuf {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir)
}

fn default_libredb_home() -> PathBuf {
    user_home_dir().join(".gemini").join("libredb")
}

fn infer_chat_memory_ldb_path(cid: &str) -> Option<PathBuf> {
    if cid.trim().is_empty() || cid.contains('/') || cid.contains('\\') {
        return None;
    }
    let brain_dir = user_home_dir()
        .join(".gemini")
        .join("antigravity")
        .join("brain")
        .join(cid.trim());
    if brain_dir.is_dir() {
        Some(brain_dir.join(".agents").join("memory.ldb"))
    } else {
        None
    }
}

fn infer_antigravity_transcript_path(cid: &str) -> Option<PathBuf> {
    if cid.trim().is_empty() || cid.contains('/') || cid.contains('\\') {
        return None;
    }
    Some(
        user_home_dir()
            .join(".gemini")
            .join("antigravity")
            .join("brain")
            .join(cid)
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl"),
    )
}

fn resolve_workspace_ldb_path(probe: &Path, fallback: &Path) -> PathBuf {
    if probe.extension().and_then(|e| e.to_str()) == Some("ldb") {
        return probe.to_path_buf();
    }
    let start_dir = if probe.is_file() {
        probe.parent().unwrap_or(probe)
    } else {
        probe
    };

    if is_protected_profile_dir(start_dir) {
        return fallback.to_path_buf();
    }

    let markers = [
        ".git",
        ".agents",
        "Cargo.toml",
        "pyproject.toml",
        "package.json",
        "pubspec.yaml",
        "go.mod",
        "pom.xml",
    ];

    let mut curr_opt = Some(start_dir);
    while let Some(curr) = curr_opt {
        if curr.parent().is_none() || is_protected_profile_dir(curr) {
            break;
        }
        if markers.iter().any(|m| curr.join(m).exists()) {
            return curr.join(".agents").join("memory.ldb");
        }
        curr_opt = curr.parent();
    }

    if start_dir.exists() && start_dir.parent().is_some() {
        start_dir.join(".agents").join("memory.ldb")
    } else {
        fallback.to_path_buf()
    }
}
