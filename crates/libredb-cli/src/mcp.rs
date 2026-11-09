//! Native Model Context Protocol (`MCP`) JSON-RPC 2.0 server over `stdio`.
//!
//! Keeps `OverlayBrain` (`HybridIndex`, `ReflexEngine`, and `Inode` graph) warm in RAM so
//! Antigravity tool invocations execute in `< 0.5 ms` with zero shell or Python startup latency.

use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, index_workspace,
    query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton,
    OverlayBrain, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::LibreDb;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn run_mcp_stdio_server(
    project_db_path: &Path,
    global_db_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let proj_db = Arc::new(LibreDb::open(project_db_path)?);
    let glob_db = match global_db_path {
        Some(gp) => Some(Arc::new(LibreDb::open(gp)?)),
        None => None,
    };
    let mut brain = OverlayBrain::open(glob_db.clone(), Arc::clone(&proj_db))?;

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

        // Notifications (no `id`) require no response frame.
        if id.is_none() {
            continue;
        }
        let req_id = id.unwrap();

        let response =
            match handle_rpc_method(method, &params, &proj_db, glob_db.as_ref(), &mut brain) {
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
    proj_db: &Arc<LibreDb>,
    glob_db: Option<&Arc<LibreDb>>,
    brain: &mut OverlayBrain,
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
                    "description": "One-shot session-deduplicated associative recall across global and project memory within an exact token budget.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" },
                            "budget": { "type": "integer", "default": 800 },
                            "cid": { "type": "string" },
                            "transcript_path": { "type": "string" },
                            "cwd": { "type": "string" },
                            "error": { "type": "string" }
                        },
                        "required": ["query"]
                    }
                },
                {
                    "name": "libredb_skeleton",
                    "description": "Extracts or serves a 95%+ compressed, hash-cached symbol contract and [Lstart-Lend] map for a source file.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": { "type": "string" },
                            "filter": { "type": "string" }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "libredb_impact",
                    "description": "Computes blast-radius callers, callees, and governing architectural decisions for a symbol.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "symbol": { "type": "string" } },
                        "required": ["symbol"]
                    }
                },
                {
                    "name": "libredb_fim",
                    "description": "Extracts a surgical Fill-in-the-Middle edit window around a symbol or line with blast-radius and governing decisions.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": { "type": "string" },
                            "symbol": { "type": "string" },
                            "line": { "type": "integer" },
                            "pad": { "type": "integer", "default": 12 }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "libredb_batch",
                    "description": "Atomically persists facts, decisions, tasks, and milestone snapshots in one fsync and auto-wires Governs synapses.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "facts": { "type": "object" },
                            "decisions": { "type": "object" },
                            "snapshot": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "libredb_handoff",
                    "description": "Builds a deterministic zero-bloat subagent delegation bundle linked to a task.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "handoff_id": { "type": "string" },
                            "task_key": { "type": "string" },
                            "role": { "type": "string" },
                            "instructions": { "type": "string" }
                        },
                        "required": ["handoff_id", "task_key", "role"]
                    }
                },
                {
                    "name": "libredb_learn_assoc",
                    "description": "Reinforces a language-agnostic Hebbian concept bridge from any phrasing/script to target NodeIds.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "cue_phrase": { "type": "string" },
                            "target_ids": { "type": "array", "items": { "type": "integer" } }
                        },
                        "required": ["cue_phrase", "target_ids"]
                    }
                },
                {
                    "name": "libredb_learn_reflex",
                    "description": "Persists a situational pitfall reflex triggered automatically before matching commands.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "directive": { "type": "string" },
                            "stack": { "type": "array", "items": { "type": "string" } },
                            "action": { "type": "array", "items": { "type": "string" } },
                            "env": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["id", "directive"]
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
            let text_out = dispatch_tool(tool_name, &args, proj_db, glob_db, brain)
                .map_err(|e| e.to_string())?;
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
    proj_db: &Arc<LibreDb>,
    _glob_db: Option<&Arc<LibreDb>>,
    brain: &mut OverlayBrain,
) -> Result<String, Box<dyn std::error::Error>> {
    match name {
        "libredb_pulse" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let budget = args.get("budget").and_then(Value::as_u64).unwrap_or(800) as u32;
            let mut req = PulseRequest::new(query, budget);
            if let Some(cid) = args.get("cid").and_then(Value::as_str) {
                req.conversation_id = Some(cid.to_owned());
                if let Some(tp) = args.get("transcript_path").and_then(Value::as_str) {
                    req.epoch = sync_transcript_epoch(proj_db, cid, Path::new(tp))?;
                }
            }
            if let Some(cwd) = args.get("cwd").and_then(Value::as_str) {
                req.workspace_dir = Some(PathBuf::from(cwd));
            }
            if let Some(err) = args.get("error").and_then(Value::as_str) {
                req.error_context = Some(err.to_owned());
            }
            brain.refresh_if_needed()?;
            let resp = brain.pulse(&req)?;
            Ok(resp.format_compact())
        }
        "libredb_skeleton" => {
            let fp = args
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or("Missing file_path")?;
            let flt = args.get("filter").and_then(Value::as_str);
            let (skel, _) = FileSkeleton::index_or_get_cached(proj_db, Path::new(fp), None)?;
            Ok(skel.render_compact(flt, flt.is_some()))
        }
        "libredb_impact" => {
            let sym = args
                .get("symbol")
                .and_then(Value::as_str)
                .ok_or("Missing symbol")?;
            let reports = query_symbol_impact(proj_db, sym)?;
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
            let bundle = extract_fim_slice(proj_db, Path::new(fp), sym, line, pad)?;
            Ok(bundle.format_compact())
        }
        "libredb_batch" => {
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
            if let Some(snap) = args.get("snapshot").and_then(Value::as_str) {
                spec.snapshot = Some(snap.to_owned());
            }
            let rep = execute_atomic_batch(proj_db, &spec)?;
            let _ = index_workspace; // keep symbol link reachable
            Ok(serde_json::to_string_pretty(&rep)?)
        }
        "libredb_handoff" => {
            let hid = args.get("handoff_id").and_then(Value::as_str).ok_or("Missing handoff_id")?;
            let tkey = args.get("task_key").and_then(Value::as_str).ok_or("Missing task_key")?;
            let role = args.get("role").and_then(Value::as_str).ok_or("Missing role")?;
            let notes = args.get("instructions").and_then(Value::as_str).unwrap_or("");
            let (_, block) = create_subagent_handoff(proj_db, hid, tkey, role, notes)?;
            Ok(block)
        }
        "libredb_learn_assoc" => {
            let cue = args.get("cue_phrase").and_then(Value::as_str).ok_or("Missing cue_phrase")?;
            let ids: Vec<u64> = args
                .get("target_ids")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default();
            let mut cog = CognitiveEngine::open_db(Arc::clone(proj_db))?;
            let cnt = cog.reinforce_association(cue, &ids)?;
            Ok(format!("Reinforced {cnt} Hebbian synapses"))
        }
        "libredb_learn_reflex" => {
            let id = args.get("id").and_then(Value::as_str).ok_or("Missing id")?;
            let dir = args.get("directive").and_then(Value::as_str).ok_or("Missing directive")?;
            let parse_arr = |k: &str| -> Vec<String> {
                args.get(k)
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
            let nid = ReflexEngine::learn_reflex(proj_db, &rule)?;
            Ok(format!("Learned reflex '{id}' as node #{nid}"))
        }
        other => Err(format!("Unknown tool '{other}'").into()),
    }
}
