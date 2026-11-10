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

use crate::hooks::{
    default_global_ldb_path, find_workspace_root, is_protected_profile_dir, open_global_ldb,
    open_global_ldb_if_exists, open_project_ldb_silent, resolve_brain_conv_dir, user_home_dir,
};
use libredb_bridge::import_sqlite_readonly;
use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, index_workspace,
    query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton,
    OverlayBrain, PulseRequest, ReflexEngine, ReflexRule, SessionState,
};
use libredb_core::LibreDb;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct McpServerState {
    default_project_path: PathBuf,
    global_path: Option<PathBuf>,
    global_db: Option<Arc<LibreDb>>,
    /// Keyed by `canonical_brain_cache_key(db_path)` so relative paths, `..` segments, symlinks,
    /// and Windows casing variants always address and evict the exact same cached `OverlayBrain`.
    brains: HashMap<String, OverlayBrain>,
}

pub(crate) fn canonical_brain_cache_key(db_path: &Path) -> String {
    let abs = if db_path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(db_path))
            .unwrap_or_else(|_| db_path.to_path_buf())
    } else {
        db_path.to_path_buf()
    };
    crate::security::normalize_workspace_key(&abs)
}

impl McpServerState {
    pub fn new(default_project_path: Option<&Path>, global_path: Option<&Path>) -> Result<Self, String> {
        let fallback_proj = match default_project_path {
            Some(p) => p.to_path_buf(),
            None => default_libredb_home().join("default_memory.ldb"),
        };
        let global_path_buf = global_path
            .map(Path::to_path_buf)
            .or_else(|| {
                let def = default_global_ldb_path();
                def.is_file().then_some(def)
            });
        let global_db = match global_path {
            Some(gp) => Some(open_global_ldb(Some(gp))?),
            None => open_global_ldb_if_exists(None),
        };

        Ok(Self {
            default_project_path: fallback_proj,
            global_path: global_path_buf,
            global_db,
            brains: HashMap::new(),
        })
    }

    fn custom_protected_paths(&self, proj_db: Option<&LibreDb>) -> Vec<String> {
        crate::security::load_config_list(
            self.global_db.as_deref(),
            proj_db,
            "guardrail:protected_paths",
        )
    }

    fn seal_project_db_if_authorized(
        &mut self,
        ws_root_opt: Option<&Path>,
        proj_db: &LibreDb,
    ) -> Result<(), String> {
        if let (Some(ref gdb), Some(ws_root)) = (&self.global_db, ws_root_opt) {
            if let Err(err) = crate::security::seal_workspace_memory(gdb, proj_db, ws_root) {
                let cache_key =
                    canonical_brain_cache_key(&ws_root.join(".agents").join("memory.ldb"));
                self.brains.remove(&cache_key);
                return Err(format!(
                    "Workspace mutation succeeded, but updating hmac-sha256:v3 trust seal for '{}' failed: {err}",
                    ws_root.display()
                ));
            }
        }
        Ok(())
    }

    fn resolve_brain_with_seal_target(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<(Option<PathBuf>, &mut OverlayBrain), String> {
        let candidate_path = match hint_path {
            Some(raw) if !raw.trim().is_empty() => {
                resolve_workspace_ldb_path(Path::new(raw.trim()), &self.default_project_path)
            }
            _ => match cid_opt.and_then(infer_chat_memory_ldb_path) {
                Some(chat_ldb) => chat_ldb,
                None => self.default_project_path.clone(),
            },
        };
        let candidate_cache_key = canonical_brain_cache_key(&candidate_path);

        let mut ws_root_to_seal: Option<PathBuf> = None;
        let (mut db_path, mut cache_key) =
            if let Some(ws_root) = workspace_root_from_agents_ldb(&candidate_path) {
                if crate::security::is_workspace_memory_trusted(self.global_db.as_deref(), &ws_root)
                {
                    if is_explicit_memorize {
                        ws_root_to_seal = Some(ws_root);
                    }
                    (candidate_path, candidate_cache_key)
                } else {
                    // Evict any cached OverlayBrain via canonical key so relative/symlink/casing variants are purged too.
                    self.brains.remove(&candidate_cache_key);
                    if is_explicit_memorize {
                        return Err(format!(
                            "Workspace memory at '{}' is quarantined because a pre-existing unsealed, tampered, or Git-tracked .agents database was detected. Run 'libredb trust \"{}\"' in a terminal if you trust this repository.",
                            candidate_path.display(),
                            ws_root.display()
                        ));
                    }
                    let q_path = default_libredb_home().join("quarantined_workspace.ldb");
                    let q_key = canonical_brain_cache_key(&q_path);
                    (q_path, q_key)
                }
            } else {
                (candidate_path, candidate_cache_key)
            };

        if !self.brains.contains_key(&cache_key) {
            let (proj_db, did_migrate) = open_project_ldb_silent(&db_path)?;
            let mut ready_db = Some(proj_db);
            if did_migrate {
                if let Some(mig_ws) = workspace_root_from_agents_ldb(&db_path) {
                    if !crate::security::is_private_brain_workspace(&mig_ws) {
                        let seal_res = if is_protected_profile_dir(&mig_ws) {
                            Err("workspace resolves to a protected profile directory".to_owned())
                        } else if let Some(ref gdb) = self.global_db {
                            crate::security::seal_workspace_memory(
                                gdb,
                                ready_db.as_ref().unwrap(),
                                &mig_ws,
                            )
                        } else {
                            Err("global customizations.ldb is unavailable".to_owned())
                        };
                        if let Err(err) = seal_res {
                            ready_db = None;
                            if is_explicit_memorize {
                                return Err(format!(
                                    "Post-migration hmac-sha256:v3 workspace seal failed for '{}': {err}",
                                    mig_ws.display()
                                ));
                            }
                            ws_root_to_seal = None;
                            db_path = default_libredb_home().join("quarantined_workspace.ldb");
                            cache_key = canonical_brain_cache_key(&db_path);
                            if !self.brains.contains_key(&cache_key) {
                                let (q_db, _) = open_project_ldb_silent(&db_path)?;
                                let q_brain = OverlayBrain::open(self.global_db.clone(), q_db)
                                    .map_err(|e| e.to_string())?;
                                self.brains.insert(cache_key.clone(), q_brain);
                            }
                        }
                    }
                }
            }
            if let Some(valid_db) = ready_db {
                let brain = OverlayBrain::open(self.global_db.clone(), valid_db)
                    .map_err(|e| e.to_string())?;
                self.brains.insert(cache_key.clone(), brain);
            }
        }

        let brain = self.brains.get_mut(&cache_key).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok((ws_root_to_seal, brain))
    }

    fn resolve_brain_mut(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<&mut OverlayBrain, String> {
        let (_, brain) =
            self.resolve_brain_with_seal_target(hint_path, cid_opt, is_explicit_memorize)?;
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
                    "description": "Zero-bloat source code graph: 'skeleton' (-95% file map, supports single 'target' or batch 'files'), 'impact' (callers + governing decisions), 'fim' (surgical edit slice + callers + decisions), or 'index' (scan workspace).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string", "enum": ["skeleton", "impact", "fim", "index"] },
                            "target": { "type": "string", "description": "File path, workspace directory, or symbol query" },
                            "files": { "type": "array", "items": { "type": "string" }, "description": "Optional batch of file paths for action='skeleton' (single fsync)" },
                            "cwd": { "type": "string" },
                            "cid": { "type": "string", "description": "Optional conversation ID for Zero-Repeat Skeleton deduplication" },
                            "force": { "type": "boolean", "description": "Force full skeleton emission even if unchanged in session" },
                            "symbol": { "type": "string", "description": "Symbol filter or FIM target" },
                            "line": { "type": "integer" },
                            "pad": { "type": "integer", "default": 12 }
                        },
                        "required": ["action"]
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

            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
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
            let target_opt = args.get("target").and_then(Value::as_str);
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
            let first_file_hint = target_opt.or_else(|| files_arr.first().map(String::as_str));
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;
            let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);

            let proj_db = {
                let brain =
                    state.resolve_brain_mut(cwd_hint.or(first_file_hint), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            let protected_paths = state.custom_protected_paths(Some(&proj_db));
            let resolve_rel = |raw_p: &str| -> PathBuf {
                let tp = Path::new(raw_p);
                if tp.is_relative() {
                    if let Some(c) = args.get("cwd").and_then(Value::as_str) {
                        if !c.trim().is_empty() {
                            return Path::new(c.trim()).join(tp);
                        }
                    }
                }
                tp.to_path_buf()
            };

            let ws_root: Option<PathBuf> = args
                .get("cwd")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .filter(|p| p.is_dir());

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
                        if let Some(err) =
                            crate::security::check_mcp_read_path_policy(rp, &protected_paths)
                        {
                            return Err(err.into());
                        }
                    }

                    let items: Vec<(&Path, Option<&str>)> = requested_paths
                        .iter()
                        .map(|p| (p.as_path(), None))
                        .collect();
                    let skeletons = FileSkeleton::index_or_get_cached_batch(&proj_db, &items)?;

                    let mut session_opt: Option<SessionState> = if let Some(cid) = cid_arg {
                        let mut epoch = 1u32;
                        if let Some(tp) = infer_antigravity_transcript_path(cid) {
                            if tp.exists() {
                                epoch = sync_transcript_epoch(&proj_db, cid, &tp).unwrap_or(1);
                            }
                        }
                        SessionState::load_or_init(&proj_db, cid, epoch).ok()
                    } else {
                        None
                    };

                    let mut out_blocks: Vec<String> = Vec::with_capacity(skeletons.len());
                    let mut session_dirty = false;

                    for (skel, _) in skeletons {
                        if !force && sym.is_none() {
                            if let Some(ref mut sess) = session_opt {
                                if sess.is_skeleton_in_context(&skel.file_label, skel.content_hash) {
                                    sess.record_suppression(skel.raw_tokens, 16);
                                    session_dirty = true;
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
                        out_blocks.push(skel.render_compact(sym, sym.is_some()));
                    }

                    if session_dirty {
                        if let Some(ref sess) = session_opt {
                            let _ = sess.save(&proj_db);
                        }
                    }

                    Ok(out_blocks.join("\n"))
                }
                "impact" => {
                    let target = target_opt.ok_or("Missing target")?;
                    if let Some(ref root) = ws_root {
                        if crate::security::check_mcp_read_path_policy(root, &protected_paths)
                            .is_none()
                        {
                            if let Ok(rep) = index_workspace(&proj_db, root, false) {
                                if rep.files_reindexed > 0 {
                                    if let Ok(mut cog) =
                                        CognitiveEngine::open_db(Arc::clone(&proj_db))
                                    {
                                        let _ = cog.save_index_snapshot();
                                    }
                                    if let Ok(brain) = state.resolve_brain_mut(
                                        cwd_hint.or(first_file_hint),
                                        cid_arg,
                                        false,
                                    ) {
                                        let _ = brain.refresh_if_needed();
                                    }
                                }
                            }
                        }
                    }
                    let reports = query_symbol_impact(&proj_db, target)?;
                    Ok(serde_json::to_string_pretty(&reports)?)
                }
                "fim" => {
                    let target = target_opt.ok_or("Missing target")?;
                    let resolved_target = resolve_rel(target);
                    if let Some(err) = crate::security::check_mcp_read_path_policy(
                        &resolved_target,
                        &protected_paths,
                    ) {
                        return Err(err.into());
                    }
                    if let Some(ref root) = ws_root {
                        if crate::security::check_mcp_read_path_policy(root, &protected_paths)
                            .is_none()
                        {
                            if let Ok(rep) = index_workspace(&proj_db, root, false) {
                                if rep.files_reindexed > 0 {
                                    if let Ok(mut cog) =
                                        CognitiveEngine::open_db(Arc::clone(&proj_db))
                                    {
                                        let _ = cog.save_index_snapshot();
                                    }
                                    if let Ok(brain) = state.resolve_brain_mut(
                                        cwd_hint.or(first_file_hint),
                                        cid_arg,
                                        false,
                                    ) {
                                        let _ = brain.refresh_if_needed();
                                    }
                                }
                            }
                        }
                    }
                    let bundle = extract_fim_slice(&proj_db, &resolved_target, sym, line, pad)?;
                    Ok(bundle.format_compact())
                }
                "index" => {
                    let target = target_opt.ok_or("Missing target")?;
                    let resolved_target = resolve_rel(target);
                    if let Some(err) = crate::security::check_mcp_read_path_policy(
                        &resolved_target,
                        &protected_paths,
                    ) {
                        return Err(err.into());
                    }
                    let rep = index_workspace(&proj_db, &resolved_target, false)?;
                    let mut cog = CognitiveEngine::open_db(proj_db)?;
                    cog.save_index_snapshot()?;
                    let brain =
                        state.resolve_brain_mut(cwd_hint.or(first_file_hint), cid_arg, false)?;
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

            let (ws_root_to_seal, proj_db) = {
                let (ws_opt, brain) =
                    state.resolve_brain_with_seal_target(cwd_hint, cid_arg, true)?;
                (ws_opt, Arc::clone(brain.project_db()))
            };

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

            state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db)?;
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
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
            let flt = args.get("filter").and_then(Value::as_str);
            let resolved_fp = if Path::new(fp).is_relative() {
                args.get("cwd")
                    .and_then(Value::as_str)
                    .filter(|c| !c.trim().is_empty())
                    .map(|c| Path::new(c.trim()).join(fp))
                    .unwrap_or_else(|| PathBuf::from(fp))
            } else {
                PathBuf::from(fp)
            };
            let proj_db = {
                let brain = state.resolve_brain_mut(cwd_hint.or(Some(fp)), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            let protected = state.custom_protected_paths(Some(&proj_db));
            if let Some(err) =
                crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
            {
                return Err(err.into());
            }
            let (skel, _) = FileSkeleton::index_or_get_cached(&proj_db, &resolved_fp, None)?;
            Ok(skel.render_compact(flt, flt.is_some()))
        }
        "libredb_impact" => {
            let sym = args.get("symbol").and_then(Value::as_str).ok_or("Missing symbol")?;
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
            let reports = query_symbol_impact(brain.project_db(), sym)?;
            Ok(serde_json::to_string_pretty(&reports)?)
        }
        "libredb_fim" => {
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
            let sym = args.get("symbol").and_then(Value::as_str);
            let line = args.get("line").and_then(Value::as_u64).map(|n| n as usize);
            let pad = args.get("pad").and_then(Value::as_u64).unwrap_or(12) as usize;
            let resolved_fp = if Path::new(fp).is_relative() {
                args.get("cwd")
                    .and_then(Value::as_str)
                    .filter(|c| !c.trim().is_empty())
                    .map(|c| Path::new(c.trim()).join(fp))
                    .unwrap_or_else(|| PathBuf::from(fp))
            } else {
                PathBuf::from(fp)
            };
            let proj_db = {
                let brain = state.resolve_brain_mut(cwd_hint.or(Some(fp)), cid_arg, false)?;
                Arc::clone(brain.project_db())
            };
            let protected = state.custom_protected_paths(Some(&proj_db));
            if let Some(err) =
                crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
            {
                return Err(err.into());
            }
            let bundle = extract_fim_slice(&proj_db, &resolved_fp, sym, line, pad)?;
            Ok(bundle.format_compact())
        }
        "libredb_handoff" => {
            let hid = args.get("handoff_id").and_then(Value::as_str).ok_or("Missing handoff_id")?;
            let tkey = args.get("task_key").and_then(Value::as_str).ok_or("Missing task_key")?;
            let role = args.get("role").and_then(Value::as_str).ok_or("Missing role")?;
            let notes = args.get("instructions").and_then(Value::as_str).unwrap_or("");
            let (ws_root_to_seal, proj_db) = {
                let (ws_opt, brain) =
                    state.resolve_brain_with_seal_target(cwd_hint, cid_arg, true)?;
                (ws_opt, Arc::clone(brain.project_db()))
            };
            let (_, block) = create_subagent_handoff(&proj_db, hid, tkey, role, notes)?;
            state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db)?;
            let brain = state.resolve_brain_mut(cwd_hint, cid_arg, false)?;
            brain.refresh_if_needed()?;
            Ok(block)
        }
        other => Err(format!("Unknown tool '{other}'").into()),
    }
}

fn default_libredb_home() -> PathBuf {
    user_home_dir().join(".gemini").join("libredb")
}

fn workspace_root_from_agents_ldb(db_path: &Path) -> Option<PathBuf> {
    let joined = if db_path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(db_path))
            .unwrap_or_else(|_| db_path.to_path_buf())
    } else {
        db_path.to_path_buf()
    };
    let resolved = crate::security::canonicalize_with_missing_tail(&joined).unwrap_or(joined);
    let parent = resolved.parent()?;
    if parent.file_name().and_then(|n| n.to_str()) == Some(".agents") {
        parent.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf)
    } else {
        None
    }
}

fn infer_chat_memory_ldb_path(cid: &str) -> Option<PathBuf> {
    if cid.trim().is_empty() || cid.contains('/') || cid.contains('\\') {
        return None;
    }
    let brain_dir = resolve_brain_conv_dir(cid.trim());
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
        resolve_brain_conv_dir(cid.trim())
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

    if let Some(root) = find_workspace_root(start_dir) {
        return root.join(".agents").join("memory.ldb");
    }

    if start_dir.exists() && start_dir.parent().is_some() {
        start_dir.join(".agents").join("memory.ldb")
    } else {
        fallback.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_brain_cache_key, McpServerState};
    use libredb_core::{LibreDb, NodeKind, WriteRequest};
    use std::fs;

    #[test]
    fn relative_and_absolute_paths_share_canonical_cache_key_and_evict_on_seal_failure() {
        let base_target = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "test_mcp_cache_key_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
        let _ = fs::remove_dir_all(&base_target);
        let ws_repo = base_target.join("mcp_repo");
        fs::create_dir_all(ws_repo.join(".agents")).unwrap();
        fs::create_dir_all(ws_repo.join("sub")).unwrap();

        let global_path = base_target.join("customizations.ldb");
        let abs_ldb = ws_repo.join(".agents").join("memory.ldb");
        let dotdot_ldb = ws_repo.join("sub").join("..").join(".agents").join("memory.ldb");

        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(&abs_ldb).unwrap();
            pdb.put(WriteRequest::new(NodeKind::Fact, b"k=1".to_vec()).with_key("k"))
                .unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_repo).unwrap();
        }

        // Verify relative (from CWD), `sub/..`, and clean absolute paths produce the exact same cache key:
        let cwd = std::env::current_dir().unwrap();
        if let Some(rel_from_cwd) = abs_ldb.strip_prefix(&cwd).ok() {
            assert_eq!(
                canonical_brain_cache_key(rel_from_cwd),
                canonical_brain_cache_key(&abs_ldb)
            );
        }
        assert_eq!(
            canonical_brain_cache_key(&dotdot_ldb),
            canonical_brain_cache_key(&abs_ldb)
        );

        let mut state =
            McpServerState::new(Some(&base_target.join("fallback.ldb")), Some(&global_path))
                .unwrap();

        // Populate cache via `sub/../.agents/memory.ldb` non-canonical path:
        let hint_non_canon = dotdot_ldb.to_string_lossy().to_string();
        let (ws_seal_opt, brain) = state
            .resolve_brain_with_seal_target(Some(&hint_non_canon), None, true)
            .unwrap();
        assert!(ws_seal_opt.is_some());
        let proj_arc = std::sync::Arc::clone(brain.project_db());
        assert_eq!(state.brains.len(), 1);

        // Corrupt the global trust secret so `seal_project_db_if_authorized` fails after mutation,
        // and verify the entry cached under `sub/../.agents/memory.ldb` IS evicted via `ws_root`:
        state
            .global_db
            .as_ref()
            .unwrap()
            .put(
                WriteRequest::new(NodeKind::Config, b"corrupt-non-hex".to_vec())
                    .with_key("sys::trust_anchor_secret"),
            )
            .unwrap();
        let err = state
            .seal_project_db_if_authorized(ws_seal_opt.as_deref(), &proj_arc)
            .expect_err("Expected seal failure on corrupted secret");
        assert!(err.contains("updating hmac-sha256:v3 trust seal"));
        assert!(
            state.brains.is_empty(),
            "Cached OverlayBrain must be evicted even when opened via non-canonical/relative path"
        );

        drop(proj_arc);
        drop(state);
        let _ = fs::remove_dir_all(&base_target);
    }
}
