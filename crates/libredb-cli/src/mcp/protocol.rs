//! JSON-RPC 2.0 stream transport, `initialize` root discovery, and dynamic `roots/list` sync.

use super::tools::dispatch_tool;
use super::{
    canonical_brain_cache_key, read_bounded_jsonrpc_line, BoundedLineRead, McpServerState,
    MAX_MCP_LINE_BYTES,
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn percent_decode_utf8(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            let b = ((hi << 4) | lo) as u8;
            if b == 0 {
                return None;
            }
            out.push(b);
            i += 3;
        } else {
            if bytes[i] == 0 {
                return None;
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

pub(crate) fn parse_file_uri_or_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path_str = if let Some(rest) = trimmed.strip_prefix("file://") {
        let after_host = rest.strip_prefix("localhost").unwrap_or(rest);
        let decoded = percent_decode_utf8(after_host)?;
        let b = decoded.as_bytes();
        if b.len() >= 3 && b[0] == b'/' && b[1].is_ascii_alphabetic() && b[2] == b':' {
            decoded[1..].to_owned()
        } else {
            decoded
        }
    } else if trimmed.contains("://") {
        return None;
    } else {
        trimmed.to_owned()
    };
    let p = PathBuf::from(path_str);
    let canon = crate::security::canonicalize_with_missing_tail(&p).unwrap_or(p);
    if canon.is_dir() && !crate::security::is_forbidden_mcp_workspace_root(&canon) {
        Some(canon)
    } else {
        None
    }
}

pub(super) fn has_explicit_root_fields(val: &Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    obj.contains_key("roots")
        || obj.contains_key("workspaceFolders")
        || obj.contains_key("rootUri")
        || obj.contains_key("rootPath")
}

pub(super) fn extract_workspace_roots_from_value(val: &Value) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for key in ["rootUri", "rootPath"] {
        if let Some(s) = val.get(key).and_then(Value::as_str) {
            if let Some(p) = parse_file_uri_or_path(s) {
                candidates.push(p);
            }
        }
    }
    for arr_key in ["workspaceFolders", "roots"] {
        if let Some(arr) = val.get(arr_key).and_then(Value::as_array) {
            for item in arr {
                if let Some(u) = item
                    .get("uri")
                    .or_else(|| item.get("path"))
                    .and_then(Value::as_str)
                {
                    if let Some(p) = parse_file_uri_or_path(u) {
                        candidates.push(p);
                    }
                }
            }
        }
    }
    candidates
}

impl McpServerState {
    pub(crate) fn replace_client_workspace_roots(&mut self, candidates: Vec<PathBuf>) {
        let mut next_roots: Vec<PathBuf> = Vec::new();
        for cand in candidates {
            if let Some(ref pin) = self.pinned_workspace_root {
                if crate::security::check_mcp_workspace_containment(&cand, pin).is_some() {
                    continue;
                }
            }
            let cand_norm = crate::security::normalize_workspace_key(&cand);
            if !next_roots
                .iter()
                .any(|existing| crate::security::normalize_workspace_key(existing) == cand_norm)
            {
                next_roots.push(cand);
            }
        }

        let old_roots_snapshot = self.client_workspace_roots.clone();
        for old_root in &old_roots_snapshot {
            let old_norm = crate::security::normalize_workspace_key(old_root);
            let still_present = next_roots
                .iter()
                .any(|nr| crate::security::normalize_workspace_key(nr) == old_norm);
            if !still_present {
                let old_ldb = old_root.join(".agents").join("memory.ldb");
                let old_ldb_key = canonical_brain_cache_key(&old_ldb);
                self.brains.remove(&old_ldb_key);
                self.clear_ram_sessions_for_cache_key(&old_ldb_key);
                if let Some(ref dir) = self.ephemeral_dir {
                    let eph_file =
                        dir.join(crate::security::ephemeral_workspace_ldb_filename(old_root));
                    let eph_key = canonical_brain_cache_key(&eph_file);
                    self.brains.remove(&eph_key);
                    self.clear_ram_sessions_for_cache_key(&eph_key);
                    let _ = std::fs::remove_file(&eph_file);
                }
                let stale_keys: Vec<String> = self
                    .brains
                    .iter()
                    .filter_map(|(k, b)| {
                        let p = b.project_db().path()?;
                        let in_old =
                            crate::security::check_mcp_workspace_containment(p, old_root).is_none();
                        let in_next = next_roots
                            .iter()
                            .any(|nr| {
                                crate::security::check_mcp_workspace_containment(p, nr).is_none()
                            });
                        (in_old && !in_next).then(|| k.clone())
                    })
                    .collect();
                for sk in stale_keys {
                    self.brains.remove(&sk);
                    self.clear_ram_sessions_for_cache_key(&sk);
                }
            }
        }

        self.client_workspace_roots = next_roots;
    }

    pub(crate) fn register_initialize_roots(&mut self, params: &Value) {
        self.client_supports_roots = params
            .get("capabilities")
            .and_then(|c| c.get("roots"))
            .is_some();
        self.pending_roots_request_id = None;
        self.client_roots_refresh_pending = false;
        let candidates = extract_workspace_roots_from_value(params);
        self.replace_client_workspace_roots(candidates);
    }

    pub(super) fn issue_roots_list_request(&mut self) -> Value {
        self.next_server_req_seq = self.next_server_req_seq.saturating_add(1);
        let req_id = format!("libredb-roots-{}", self.next_server_req_seq);
        self.pending_roots_request_id = Some(req_id.clone());
        json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "roots/list",
            "params": {}
        })
    }
}

/// Processes a newline-delimited JSON-RPC 2.0 MCP stream, handling requests, client notifications
/// (`notifications/initialized`, `notifications/roots/list_changed`), and client responses to
/// server-initiated `roots/list` refreshes.
pub fn process_mcp_stream<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    state: &mut McpServerState,
) -> io::Result<()> {
    loop {
        let line = match read_bounded_jsonrpc_line(reader, MAX_MCP_LINE_BYTES) {
            Ok(BoundedLineRead::Eof) => break,
            Ok(BoundedLineRead::Oversized) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": "Parse error: JSON-RPC line exceeded 16 MiB limit" }
                });
                writeln!(writer, "{err_resp}")?;
                writer.flush()?;
                continue;
            }
            Ok(BoundedLineRead::Line(l)) => l,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                writeln!(writer, "{err_resp}")?;
                writer.flush()?;
                continue;
            }
        };
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
                writeln!(writer, "{err_resp}")?;
                writer.flush()?;
                continue;
            }
        };

        // Handle JSON-RPC responses from the MCP host client to server-initiated `roots/list` queries:
        if req.get("method").is_none() {
            if let (Some(resp_id), Some(expected_id)) = (
                req.get("id").and_then(Value::as_str),
                state.pending_roots_request_id.as_deref(),
            ) {
                if resp_id == expected_id {
                    state.pending_roots_request_id = None;
                    state.client_roots_refresh_pending = false;
                    if let Some(result_obj) = req.get("result") {
                        let updated = extract_workspace_roots_from_value(result_obj);
                        state.replace_client_workspace_roots(updated);
                    } else {
                        state.replace_client_workspace_roots(Vec::new());
                    }
                }
            }
            continue;
        }

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        // Handle JSON-RPC notifications (no `id` member):
        if id.is_none() {
            match method {
                "notifications/roots/list_changed" => {
                    state.client_supports_roots = true;
                    if has_explicit_root_fields(&params) {
                        state.pending_roots_request_id = None;
                        state.client_roots_refresh_pending = false;
                        let updated = extract_workspace_roots_from_value(&params);
                        state.replace_client_workspace_roots(updated);
                    } else {
                        // Suspend client-root authorization fail-closed immediately while preserving
                        // cached `OverlayBrain`s, `SessionState`s, and ephemeral `.ldb` files for
                        // workspaces that remain open when the `roots/list` response arrives.
                        state.client_roots_refresh_pending = true;
                        let roots_req = state.issue_roots_list_request();
                        writeln!(writer, "{roots_req}")?;
                        writer.flush()?;
                    }
                }
                "notifications/initialized" => {
                    if state.client_supports_roots
                        && state.client_workspace_roots.is_empty()
                        && state.pending_roots_request_id.is_none()
                    {
                        state.client_roots_refresh_pending = true;
                        let roots_req = state.issue_roots_list_request();
                        writeln!(writer, "{roots_req}")?;
                        writer.flush()?;
                    }
                }
                _ => {}
            }
            continue;
        }
        let req_id = id.unwrap();

        let response = match handle_rpc_method(method, &params, state) {
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

        writeln!(writer, "{response}")?;
        writer.flush()?;
    }

    Ok(())
}

pub fn handle_rpc_method(
    method: &str,
    params: &Value,
    state: &mut McpServerState,
) -> Result<Value, String> {
    match method {
        "initialize" => {
            state.register_initialize_roots(params);
            Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "libredb-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }))
        }
        "notifications/roots/list_changed" => {
            if has_explicit_root_fields(params) {
                state.pending_roots_request_id = None;
                let updated = extract_workspace_roots_from_value(params);
                state.replace_client_workspace_roots(updated);
            } else {
                state.replace_client_workspace_roots(Vec::new());
            }
            Ok(json!({}))
        }
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
