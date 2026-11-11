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
    default_global_ldb_path, find_workspace_root, open_global_ldb, open_global_ldb_checked,
    open_project_ldb_silent, resolve_brain_conv_dir, user_home_dir,
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

const MAX_CACHED_BRAINS: usize = 16;
const MAX_MCP_LINE_BYTES: usize = 16 * 1024 * 1024;

pub struct McpServerState {
    default_project_path: PathBuf,
    global_path: Option<PathBuf>,
    global_db: Option<Arc<LibreDb>>,
    /// Optional hard workspace root pinned at server launch (`--workspace-root`,
    /// `LIBREDB_MCP_WORKSPACE_ROOT`, or `--project <ws>/.agents/memory.ldb`). When set, all
    /// MCP workspace and file operations are strictly confined within this directory regardless
    /// of caller-supplied `cwd` or other entries in `customizations.ldb`.
    pinned_workspace_root: Option<PathBuf>,
    /// Workspace roots reported by the trusted MCP host client during `initialize` or updated
    /// dynamically via `notifications/roots/list_changed` -> `roots/list`. Never controllable by tool calls.
    client_workspace_roots: Vec<PathBuf>,
    /// True if the MCP host client advertised `capabilities.roots` during `initialize`.
    client_supports_roots: bool,
    /// Monotonic counter for server-initiated `roots/list` JSON-RPC queries.
    next_server_req_seq: u64,
    /// In-flight server-to-client `roots/list` request ID awaiting a JSON-RPC response on stdin.
    pending_roots_request_id: Option<String>,
    /// Keyed by `canonical_brain_cache_key(db_path)` so relative paths, `..` segments, symlinks,
    /// and Windows casing variants always address and evict the exact same cached `OverlayBrain`.
    brains: HashMap<String, OverlayBrain>,
    /// Lazy CSPRNG `0700` private directory holding ephemeral `.ldb` brains for clean workspaces
    /// opened before `.agents/memory.ldb` exists or when `customizations.ldb` is absent, ensuring
    /// read/code MCP tools never materialize unsealed `.agents/memory.ldb` files inside repos.
    ephemeral_dir: Option<PathBuf>,
    /// Exclusive kernel file lock on `<ephemeral_dir>/.owner.lock` held for the lifetime of this
    /// server so crashed (`SIGKILL`) directories can be reaped without touching active sessions.
    ephemeral_lock: Option<libredb_core::OsFileBackend>,
}

impl Drop for McpServerState {
    fn drop(&mut self) {
        self.brains.clear();
        if let Some(lock_backend) = self.ephemeral_lock.take() {
            let _ = lock_backend.unlock_exclusive();
            drop(lock_backend);
        }
        if let Some(dir) = self.ephemeral_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn insert_brain_bounded(
    brains: &mut HashMap<String, OverlayBrain>,
    key: String,
    brain: OverlayBrain,
) {
    if !brains.contains_key(&key) && brains.len() >= MAX_CACHED_BRAINS {
        if let Some(victim) = brains.keys().next().cloned() {
            brains.remove(&victim);
        }
    }
    brains.insert(key, brain);
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BoundedLineRead {
    Line(String),
    Oversized,
    Eof,
}

/// Reads a single `\n`-delimited JSON-RPC line with a hard upper bound of `max_bytes`,
/// draining the remainder of any oversized line in fixed chunks without unbounded heap allocation.
pub(crate) fn read_bounded_jsonrpc_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<BoundedLineRead> {
    let mut out: Vec<u8> = Vec::new();
    let mut oversized = false;

    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            if out.is_empty() && !oversized {
                return Ok(BoundedLineRead::Eof);
            }
            if oversized {
                return Ok(BoundedLineRead::Oversized);
            }
            return String::from_utf8(out)
                .map(BoundedLineRead::Line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }

        if let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
            if !oversized {
                if out.len() + nl_pos > max_bytes {
                    oversized = true;
                    out.clear();
                } else {
                    out.extend_from_slice(&buf[..nl_pos]);
                }
            }
            reader.consume(nl_pos + 1);
            if oversized {
                return Ok(BoundedLineRead::Oversized);
            }
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return String::from_utf8(out)
                .map(BoundedLineRead::Line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }

        let avail = buf.len();
        if !oversized {
            if out.len() + avail > max_bytes {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(buf);
            }
        }
        reader.consume(avail);
    }
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

fn validate_pinned_workspace_root(raw_root: &Path) -> Result<PathBuf, String> {
    if let Ok(sym_meta) = std::fs::symlink_metadata(raw_root) {
        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing symlinked '--workspace-root' path '{}'",
                raw_root.display()
            ));
        }
    }
    let abs = if raw_root.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(raw_root))
            .unwrap_or_else(|_| raw_root.to_path_buf())
    } else {
        raw_root.to_path_buf()
    };
    let canon = crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs);
    if !canon.is_dir() {
        return Err(format!(
            "Pinned MCP '--workspace-root' '{}' does not exist or is not a directory",
            raw_root.display()
        ));
    }
    if crate::security::is_forbidden_mcp_workspace_root(&canon) {
        return Err(format!(
            "Refusing overly broad or control-plane '--workspace-root' '{}'",
            raw_root.display()
        ));
    }
    Ok(canon)
}

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

/// Resolves the canonical owning workspace root whose `.seal_locks/ws_<hash>.lock` serializes all
/// mutations to `proj_db`. Always prefers the parent workspace of `<ws_root>/.agents/memory.ldb`
/// over any subdirectory `fallback_dir` so subdirectory `index`, `impact`, `fim`, and `memorize`
/// contend on the exact same lock identity.
pub(crate) fn resolve_canonical_workspace_lock_root(
    proj_db: &LibreDb,
    authorized_ws_root: &Path,
) -> PathBuf {
    if let Some(db_path) = proj_db.path() {
        if let Some(ws_root) = workspace_root_from_agents_ldb(db_path) {
            return ws_root;
        }
    }
    let abs = if authorized_ws_root.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(authorized_ws_root))
            .unwrap_or_else(|_| authorized_ws_root.to_path_buf())
    } else {
        authorized_ws_root.to_path_buf()
    };
    crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs)
}

fn find_owning_repo_or_agents_ancestor(start_dir: &Path) -> Option<PathBuf> {
    let mut curr = Some(start_dir);
    while let Some(c) = curr {
        if crate::security::is_forbidden_mcp_workspace_root(c) {
            break;
        }
        if c.join(".agents").is_dir() || c.join(".git").exists() {
            return Some(c.to_path_buf());
        }
        curr = c.parent();
    }
    None
}

impl McpServerState {
    #[cfg(test)]
    pub fn new(
        default_project_path: Option<&Path>,
        global_path: Option<&Path>,
    ) -> Result<Self, String> {
        Self::new_with_workspace_root(default_project_path, global_path, None)
    }

    pub fn new_with_workspace_root(
        default_project_path: Option<&Path>,
        global_path: Option<&Path>,
        workspace_root: Option<&Path>,
    ) -> Result<Self, String> {
        let pinned_workspace_root = match workspace_root {
            Some(ws) => Some(validate_pinned_workspace_root(ws)?),
            None => default_project_path
                .and_then(workspace_root_from_agents_ldb)
                .filter(|ws| {
                    !crate::security::is_private_brain_workspace(ws)
                        && !crate::security::is_forbidden_mcp_workspace_root(ws)
                        && ws.is_dir()
                }),
        };
        let fallback_proj = match default_project_path {
            Some(p) => p.to_path_buf(),
            None => match pinned_workspace_root {
                Some(ref pin) => pin.join(".agents").join("memory.ldb"),
                None => default_libredb_home().join("default_memory.ldb"),
            },
        };
        let global_path_buf = global_path
            .map(Path::to_path_buf)
            .or_else(|| {
                let def = default_global_ldb_path();
                def.is_file().then_some(def)
            });
        let _ = crate::security::reap_abandoned_ephemeral_dirs("libredb_mcp_eph");
        let global_db = open_global_ldb_checked(global_path)?;

        Ok(Self {
            default_project_path: fallback_proj,
            global_path: global_path_buf,
            global_db,
            pinned_workspace_root,
            client_workspace_roots: Vec::new(),
            client_supports_roots: false,
            next_server_req_seq: 0,
            pending_roots_request_id: None,
            brains: HashMap::new(),
            ephemeral_dir: None,
            ephemeral_lock: None,
        })
    }

    #[cfg(test)]
    fn simulate_hard_crash_for_test(mut self) -> Option<PathBuf> {
        self.brains.clear();
        if let Some(lock_backend) = self.ephemeral_lock.take() {
            let _ = lock_backend.unlock_exclusive();
            drop(lock_backend);
        }
        // Take `ephemeral_dir` before `Drop` runs so `remove_dir_all` is skipped, faithfully
        // reproducing OS kernel file-descriptor teardown after `SIGKILL` / `TerminateProcess`.
        self.ephemeral_dir.take()
    }

    fn ephemeral_workspace_ldb_path(&mut self, ws_root: &Path) -> Result<PathBuf, String> {
        if self.ephemeral_dir.is_none() {
            let (dir, lock_backend) =
                crate::security::create_private_ephemeral_dir("libredb_mcp_eph")?;
            self.ephemeral_dir = Some(dir);
            self.ephemeral_lock = Some(lock_backend);
        }
        let dir = self.ephemeral_dir.as_ref().unwrap();
        Ok(dir.join(crate::security::ephemeral_workspace_ldb_filename(ws_root)))
    }

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

        for old_root in &self.client_workspace_roots {
            let old_norm = crate::security::normalize_workspace_key(old_root);
            let still_present = next_roots
                .iter()
                .any(|nr| crate::security::normalize_workspace_key(nr) == old_norm);
            if !still_present {
                let old_ldb = old_root.join(".agents").join("memory.ldb");
                self.brains.remove(&canonical_brain_cache_key(&old_ldb));
                if let Some(ref dir) = self.ephemeral_dir {
                    let eph_file = dir.join(crate::security::ephemeral_workspace_ldb_filename(old_root));
                    self.brains.remove(&canonical_brain_cache_key(&eph_file));
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
                            .any(|nr| crate::security::check_mcp_workspace_containment(p, nr).is_none());
                        (in_old && !in_next).then(|| k.clone())
                    })
                    .collect();
                for sk in stale_keys {
                    self.brains.remove(&sk);
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
        let candidates = extract_workspace_roots_from_value(params);
        self.replace_client_workspace_roots(candidates);
    }

    fn issue_roots_list_request(&mut self) -> Value {
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

    fn sync_global_db_or_purge(&mut self) -> Result<(), String> {
        if let Some(ref gdb) = self.global_db {
            if let Err(sync_err) = crate::security::check_global_trust_sync(gdb) {
                self.brains.clear();
                return Err(sync_err);
            }
        } else if let Some(ref gp) = self.global_path {
            match open_global_ldb_checked(Some(gp)) {
                Ok(Some(gdb)) => {
                    self.brains.clear();
                    self.global_db = Some(gdb);
                }
                Ok(None) => {}
                Err(err) => {
                    self.brains.clear();
                    return Err(err);
                }
            }
        } else {
            match open_global_ldb_checked(None) {
                Ok(Some(gdb)) => {
                    self.brains.clear();
                    self.global_path = Some(default_global_ldb_path());
                    self.global_db = Some(gdb);
                }
                Ok(None) => {}
                Err(err) => {
                    self.brains.clear();
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Validates `candidate_dir` against server-side workspace boundaries (`pinned_workspace_root`,
    /// MCP `initialize` / `roots/list` `client_workspace_roots`, or `customizations.ldb` trusted
    /// workspaces) and returns the MOST SPECIFIC (deepest) canonical authorized workspace root.
    /// Never depends on client root registration order and never falls back to self-declared `cwd`.
    fn authorize_mcp_workspace_path(
        &mut self,
        candidate_dir: &Path,
        allow_private_brain: bool,
    ) -> Result<PathBuf, String> {
        self.sync_global_db_or_purge()?;
        let abs = if candidate_dir.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(candidate_dir))
                .unwrap_or_else(|_| candidate_dir.to_path_buf())
        } else {
            candidate_dir.to_path_buf()
        };
        let canon = crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs);
        if allow_private_brain && crate::security::is_private_brain_workspace(&canon) {
            return Ok(canon);
        }
        if crate::security::is_forbidden_mcp_workspace_root(&canon) {
            return Err(format!(
                "LibreDB MCP access denied: '{}' is a forbidden root or control-plane directory",
                candidate_dir.display()
            ));
        }
        if !canon.is_dir() {
            return Err(format!(
                "LibreDB MCP access denied: workspace directory '{}' does not exist",
                candidate_dir.display()
            ));
        }

        let mut candidates_by_specificity: Vec<PathBuf> = Vec::new();

        // 1. Hard server pin (`--workspace-root`, `LIBREDB_MCP_WORKSPACE_ROOT`, or `--project`):
        //    Enforces a strict outer containment boundary on `canon` before considering nested roots.
        if let Some(ref pin_root) = self.pinned_workspace_root {
            if let Some(err) = crate::security::check_mcp_workspace_containment(&canon, pin_root) {
                return Err(err);
            }
            if !crate::security::is_workspace_memory_trusted(self.global_db.as_deref(), pin_root) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                    pin_root.display(),
                    pin_root.display()
                ));
            }
            candidates_by_specificity.push(pin_root.clone());
        }

        // 2. Trusted MCP host client roots (`initialize` / `roots/list`):
        //    Always select the deepest containing workspace root (`max_by_key`), never `.iter().find()`.
        if let Some(deepest_client_root) = self
            .client_workspace_roots
            .iter()
            .filter(|cr| crate::security::check_mcp_workspace_containment(&canon, cr).is_none())
            .max_by_key(|cr| crate::security::normalize_workspace_key(cr).len())
            .cloned()
        {
            candidates_by_specificity.push(deepest_client_root);
        }

        // 3. Server-side `customizations.ldb` explicitly authorized workspaces:
        //    Walking upward from `canon` yields the deepest explicitly authorized workspace first.
        if let Some(ref gdb) = self.global_db {
            let mut cur = Some(canon.as_path());
            while let Some(anc) = cur {
                if crate::security::is_forbidden_mcp_workspace_root(anc) {
                    break;
                }
                if crate::security::is_workspace_path_authorized_synced(gdb, anc) {
                    candidates_by_specificity.push(anc.to_path_buf());
                    break;
                }
                cur = anc.parent();
            }
        }

        if let Some(selected_root) = candidates_by_specificity
            .into_iter()
            .max_by_key(|p| crate::security::normalize_workspace_key(p).len())
        {
            if !crate::security::is_workspace_memory_trusted(
                self.global_db.as_deref(),
                &selected_root,
            ) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                    selected_root.display(),
                    selected_root.display()
                ));
            }
            return Ok(selected_root);
        }

        // 4. Optional administrator opt-out (`mcp:allow_untrusted_workspaces = true` in `customizations.ldb`):
        if let Some(ref gdb) = self.global_db {
            if crate::security::is_mcp_untrusted_workspaces_allowed(gdb) {
                let inferred_root = find_owning_repo_or_agents_ancestor(&canon)
                    .or_else(|| find_workspace_root(&canon))
                    .unwrap_or_else(|| canon.clone());
                if crate::security::is_forbidden_mcp_workspace_root(&inferred_root) {
                    return Err(format!(
                        "LibreDB MCP access denied: '{}' is a forbidden workspace root",
                        candidate_dir.display()
                    ));
                }
                if !crate::security::is_workspace_memory_trusted(Some(gdb), &inferred_root) {
                    return Err(format!(
                        "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                        inferred_root.display(),
                        inferred_root.display()
                    ));
                }
                return Ok(inferred_root);
            }
            return Err(format!(
                "LibreDB MCP access denied: workspace '{}' is not authorized on the server (neither pinned via '--workspace-root', declared in MCP 'initialize' roots, nor trusted in customizations.ldb). Run 'libredb trust \"{}\"' in a terminal if you trust this workspace.",
                candidate_dir.display(),
                canon.display()
            ));
        }

        Err(format!(
            "LibreDB MCP access denied: workspace '{}' has no server-side authorization (global customizations.ldb is absent and neither '--workspace-root' nor MCP 'initialize' workspaceFolders was configured). Start 'libredb mcp --workspace-root \"{}\"', configure MCP 'initialize' roots, or run 'libredb init' and 'libredb trust \"{}\"'.",
            candidate_dir.display(),
            canon.display(),
            canon.display()
        ))
    }

    /// Resolves `(ws_root, containment_root)` for `libredb_code` and legacy code tools, failing
    /// closed whenever `cwd` is invalid, missing without a server-known workspace, or unauthorized.
    fn resolve_authorized_code_workspace(
        &mut self,
        raw_cwd_opt: Option<&str>,
        target_hint_opt: Option<&str>,
        allow_symbol_only: bool,
    ) -> Result<(PathBuf, PathBuf), String> {
        self.sync_global_db_or_purge()?;
        if let Some(raw_cwd) = raw_cwd_opt.map(str::trim).filter(|s| !s.is_empty()) {
            let cwd_p = Path::new(raw_cwd);
            let cwd_abs = if cwd_p.is_relative() {
                std::env::current_dir()
                    .map(|c| c.join(cwd_p))
                    .unwrap_or_else(|_| cwd_p.to_path_buf())
            } else {
                cwd_p.to_path_buf()
            };
            let cwd_canon =
                crate::security::canonicalize_with_missing_tail(&cwd_abs).unwrap_or(cwd_abs);
            if !cwd_canon.is_dir() {
                return Err(format!(
                    "LibreDB MCP access denied: 'cwd' ('{raw_cwd}') does not exist or is not a directory"
                ));
            }
            if crate::security::is_forbidden_mcp_workspace_root(&cwd_canon) {
                return Err(format!(
                    "LibreDB MCP access denied: 'cwd' ('{raw_cwd}') is an invalid or overly broad workspace root"
                ));
            }
            let ws_root = self.authorize_mcp_workspace_path(&cwd_canon, false)?;
            if let Some(err) = crate::security::check_mcp_workspace_containment(&cwd_canon, &ws_root)
            {
                return Err(err);
            }
            return Ok((ws_root, cwd_canon));
        }

        if let Some(pin_root) = self.pinned_workspace_root.clone() {
            let ws_root = self.authorize_mcp_workspace_path(&pin_root, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if self.client_workspace_roots.len() == 1
            && (allow_symbol_only
                || target_hint_opt.is_some_and(|h| Path::new(h.trim()).is_relative()))
        {
            let cr = self.client_workspace_roots[0].clone();
            let ws_root = self.authorize_mcp_workspace_path(&cr, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if !allow_symbol_only {
            let Some(hint) = target_hint_opt.map(str::trim).filter(|s| !s.is_empty()) else {
                return Err(
                    "LibreDB MCP access denied: missing target and 'cwd' workspace root".to_owned(),
                );
            };
            let hint_p = Path::new(hint);
            if hint_p.is_relative() {
                return Err(
                    "LibreDB MCP access denied: 'cwd' is required for relative target paths when server is not pinned via '--workspace-root'"
                        .to_owned(),
                );
            }
            if self.global_db.is_none() && self.client_workspace_roots.is_empty() {
                return Err(
                    "LibreDB MCP access denied: omitting 'cwd' is not permitted when neither customizations.ldb nor '--workspace-root' is configured"
                        .to_owned(),
                );
            }
            let hint_canon = crate::security::canonicalize_with_missing_tail(hint_p)
                .unwrap_or_else(|| hint_p.to_path_buf());
            let probe_dir = if hint_canon.is_dir() {
                hint_canon.as_path()
            } else {
                hint_canon
                    .parent()
                    .ok_or_else(|| "LibreDB MCP access denied: invalid target path".to_owned())?
            };
            let ws_root = self.authorize_mcp_workspace_path(probe_dir, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if let Some(def_ws) = workspace_root_from_agents_ldb(&self.default_project_path) {
            let ws_root = self.authorize_mcp_workspace_path(&def_ws, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        Err(
            "LibreDB MCP access denied: 'cwd' is required for symbol impact queries when server is not pinned via '--workspace-root'"
                .to_owned(),
        )
    }

    fn is_quarantined_db(&self, proj_db: &LibreDb) -> bool {
        let Some(p) = proj_db.path() else {
            return false;
        };
        let q_path = default_libredb_home().join("quarantined_workspace.ldb");
        canonical_brain_cache_key(p) == canonical_brain_cache_key(&q_path)
    }

    /// Acquires `WorkspaceTrustLockGuard` on the canonical owning workspace root (never swallowing
    /// lock failures via `.ok()`), runs `index_workspace`, updates the cognitive index snapshot,
    /// and refreshes the cached `OverlayBrain`.
    fn run_locked_workspace_index(
        &mut self,
        proj_db: &Arc<LibreDb>,
        ws_root: &Path,
        scan_dir: &Path,
        brain_hint: Option<&str>,
        cid_opt: Option<&str>,
    ) -> Result<libredb_cognitive::WorkspaceIndexReport, String> {
        if self.is_quarantined_db(proj_db) {
            return Err(format!(
                "Refusing to index '{}' because workspace memory is quarantined; run 'libredb trust' in a terminal first.",
                scan_dir.display()
            ));
        }
        let lock_root = resolve_canonical_workspace_lock_root(proj_db, ws_root);
        let _idx_lock = match self
            .global_db
            .as_deref()
            .filter(|_| !crate::security::is_private_brain_workspace(&lock_root))
        {
            Some(gdb) => Some(crate::security::WorkspaceTrustLockGuard::acquire(
                gdb, &lock_root,
            )?),
            None => None,
        };
        let rep = index_workspace(proj_db, scan_dir, false).map_err(|e| e.to_string())?;
        let mut cog = CognitiveEngine::open_db(Arc::clone(proj_db)).map_err(|e| e.to_string())?;
        cog.save_index_snapshot().map_err(|e| e.to_string())?;
        drop(_idx_lock);
        let brain = self.resolve_brain_mut(brain_hint, cid_opt, false)?;
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok(rep)
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
                    "Workspace mutation succeeded, but updating hmac-sha256:v4 trust seal for '{}' failed: {err}",
                    ws_root.display()
                ));
            }
        }
        Ok(())
    }

    fn is_global_customizations_target(&self, candidate_key: &str) -> bool {
        if candidate_key.ends_with("/.gemini/libredb/customizations.ldb") {
            return true;
        }
        if let Some(ref gp) = self.global_path {
            if canonical_brain_cache_key(gp) == candidate_key {
                return true;
            }
        }
        false
    }

    fn open_quarantined_brain(&mut self) -> Result<&mut OverlayBrain, String> {
        let q_path = default_libredb_home().join("quarantined_workspace.ldb");
        let q_key = canonical_brain_cache_key(&q_path);
        if !self.brains.contains_key(&q_key) {
            let (q_db, _) = open_project_ldb_silent(&q_path)?;
            let q_brain = OverlayBrain::open(self.global_db.clone(), q_db)
                .map_err(|e| e.to_string())?;
            insert_brain_bounded(&mut self.brains, q_key.clone(), q_brain);
        }
        let brain = self.brains.get_mut(&q_key).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok(brain)
    }

    fn resolve_brain_with_seal_target(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<
        (
            Option<crate::security::WorkspaceTrustLockGuard>,
            Option<PathBuf>,
            &mut OverlayBrain,
        ),
        String,
    > {
        // Synchronize `customizations.ldb` from disk BEFORE trusting any cached `OverlayBrain` or
        // evaluating workspace seals; fail closed and purge RAM brains on any global DB corruption.
        self.sync_global_db_or_purge()?;

        let explicit_hint = hint_path.map(str::trim).filter(|s| !s.is_empty());
        if let Some(ref pin_root) = self.pinned_workspace_root {
            if let Some(raw) = explicit_hint {
                if let Some(err) =
                    crate::security::check_mcp_workspace_containment(Path::new(raw), pin_root)
                {
                    return Err(err);
                }
            }
        }

        let candidate_path = match explicit_hint {
            Some(raw) => match resolve_explicit_hint_ldb_path(Path::new(raw)) {
                Ok(p) => p,
                Err(err) => {
                    if is_explicit_memorize {
                        return Err(err);
                    }
                    let brain = self.open_quarantined_brain()?;
                    return Ok((None, None, brain));
                }
            },
            None => {
                if let Some(ref pin) = self.pinned_workspace_root {
                    pin.join(".agents").join("memory.ldb")
                } else if self.client_workspace_roots.len() == 1 {
                    self.client_workspace_roots[0]
                        .join(".agents")
                        .join("memory.ldb")
                } else if let Some(chat_ldb) = cid_opt.and_then(infer_chat_memory_ldb_path) {
                    chat_ldb
                } else {
                    self.default_project_path.clone()
                }
            }
        };
        let candidate_cache_key = canonical_brain_cache_key(&candidate_path);

        if self.is_global_customizations_target(&candidate_cache_key) {
            if is_explicit_memorize {
                return Err(
                    "Refusing to mutate global customizations.ldb via workspace MCP tools; use 'libredb config' or 'libredb trust'."
                        .to_owned(),
                );
            }
            let brain = self.open_quarantined_brain()?;
            return Ok((None, None, brain));
        }

        let mut ws_write_lock: Option<crate::security::WorkspaceTrustLockGuard> = None;
        let mut ws_root_to_seal: Option<PathBuf> = None;
        let (mut db_path, mut cache_key) =
            if let Some(ws_root) = workspace_root_from_agents_ldb(&candidate_path) {
                if crate::security::is_private_brain_workspace(&ws_root) {
                    (candidate_path, candidate_cache_key)
                } else {
                    match self.authorize_mcp_workspace_path(&ws_root, false) {
                        Ok(auth_root) => {
                            let auth_ldb = auth_root.join(".agents").join("memory.ldb");
                            let auth_cache_key = canonical_brain_cache_key(&auth_ldb);
                            if self.global_db.is_none() {
                                if is_explicit_memorize {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    return Err(format!(
                                        "LibreDB MCP access denied: persisting workspace memory in '{}' via libredb_memorize requires an initialized global customizations.ldb trust store; run 'libredb init' and 'libredb trust \"{}\"' in a terminal.",
                                        auth_root.display(),
                                        auth_root.display()
                                    ));
                                }
                                if crate::security::is_workspace_memory_trusted(None, &auth_root) {
                                    let eph_path = self.ephemeral_workspace_ldb_path(&auth_root)?;
                                    let eph_key = canonical_brain_cache_key(&eph_path);
                                    (eph_path, eph_key)
                                } else {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    let q_path =
                                        default_libredb_home().join("quarantined_workspace.ldb");
                                    let q_key = canonical_brain_cache_key(&q_path);
                                    (q_path, q_key)
                                }
                            } else {
                                let has_disk_memory =
                                    auth_ldb.is_file() || auth_ldb.with_extension("db").exists();
                                let needs_mig_lock =
                                    !auth_ldb.is_file() && auth_ldb.with_extension("db").exists();
                                if is_explicit_memorize || needs_mig_lock {
                                    if let Some(ref gdb) = self.global_db {
                                        ws_write_lock = Some(
                                            crate::security::WorkspaceTrustLockGuard::acquire(
                                                gdb, &auth_root,
                                            )?,
                                        );
                                    }
                                }
                                let allow_readonly_sqlite_mig = !needs_mig_lock
                                    || is_explicit_memorize
                                    || self.global_db.as_deref().is_some_and(|gdb| {
                                        let norm =
                                            crate::security::normalize_workspace_key(&auth_root);
                                        gdb.get_by_key(
                                            libredb_core::NodeKind::Config,
                                            &format!("trust:allowed::{norm}"),
                                        )
                                        .is_ok()
                                    });
                                if allow_readonly_sqlite_mig
                                    && crate::security::is_workspace_memory_trusted(
                                        self.global_db.as_deref(),
                                        &auth_root,
                                    )
                                {
                                    if !is_explicit_memorize && !has_disk_memory {
                                        let eph_path =
                                            self.ephemeral_workspace_ldb_path(&auth_root)?;
                                        let eph_key = canonical_brain_cache_key(&eph_path);
                                        (eph_path, eph_key)
                                    } else {
                                        if is_explicit_memorize {
                                            if let Some(ref dir) = self.ephemeral_dir {
                                                let eph_path = dir.join(
                                                    crate::security::ephemeral_workspace_ldb_filename(
                                                        &auth_root,
                                                    ),
                                                );
                                                let eph_key = canonical_brain_cache_key(&eph_path);
                                                self.brains.remove(&eph_key);
                                            }
                                            ws_root_to_seal = Some(auth_root);
                                        }
                                        (auth_ldb, auth_cache_key)
                                    }
                                } else {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    if is_explicit_memorize {
                                        return Err(format!(
                                            "Workspace memory at '{}' is quarantined because a pre-existing unsealed, tampered, rolled-back, or Git-tracked .agents database was detected. Run 'libredb trust \"{}\"' (or '--reinit-lost' / '--accept-rollback' if recovering) in a terminal if you trust this repository.",
                                            auth_ldb.display(),
                                            auth_root.display()
                                        ));
                                    }
                                    ws_write_lock = None;
                                    let q_path =
                                        default_libredb_home().join("quarantined_workspace.ldb");
                                    let q_key = canonical_brain_cache_key(&q_path);
                                    (q_path, q_key)
                                }
                            }
                        }
                        Err(auth_err) => {
                            // Evict any cached OverlayBrain via canonical key and never create `.agents/memory.ldb`
                            // inside unauthorized or quarantined workspaces.
                            self.brains.remove(&candidate_cache_key);
                            if is_explicit_memorize || self.global_db.is_none() {
                                return Err(auth_err);
                            }
                            let q_path = default_libredb_home().join("quarantined_workspace.ldb");
                            let q_key = canonical_brain_cache_key(&q_path);
                            (q_path, q_key)
                        }
                    }
                }
            } else if explicit_hint.is_some() {
                if is_explicit_memorize {
                    return Err(format!(
                        "Refusing to mutate arbitrary non-workspace .ldb file '{}' via MCP; pass an authorized workspace directory in 'cwd'.",
                        candidate_path.display()
                    ));
                }
                let q_path = default_libredb_home().join("quarantined_workspace.ldb");
                let q_key = canonical_brain_cache_key(&q_path);
                (q_path, q_key)
            } else if is_explicit_memorize {
                return Err(
                    "LibreDB MCP access denied: 'cwd' (authorized workspace directory) or 'cid' (conversation ID) is required for libredb_memorize when server is not pinned via '--workspace-root'."
                        .to_owned(),
                );
            } else {
                (candidate_path, candidate_cache_key)
            };

        if !self.brains.contains_key(&cache_key) {
            let (proj_db, did_migrate) = open_project_ldb_silent(&db_path)?;
            let mut ready_db = Some(proj_db);
            if did_migrate {
                if let Some(mig_ws) = workspace_root_from_agents_ldb(&db_path) {
                    if !crate::security::is_private_brain_workspace(&mig_ws) {
                        let seal_res =
                            if crate::security::is_forbidden_mcp_workspace_root(&mig_ws) {
                                Err("workspace resolves to a forbidden root or control-plane directory".to_owned())
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
                                    "Post-migration hmac-sha256:v4 workspace seal failed for '{}': {err}",
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
                                insert_brain_bounded(&mut self.brains, cache_key.clone(), q_brain);
                            }
                        }
                    }
                }
            }
            if let Some(valid_db) = ready_db {
                let brain = OverlayBrain::open(self.global_db.clone(), valid_db)
                    .map_err(|e| e.to_string())?;
                insert_brain_bounded(&mut self.brains, cache_key.clone(), brain);
            }
        }

        let brain = self.brains.get_mut(&cache_key).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok((ws_write_lock, ws_root_to_seal, brain))
    }

    fn resolve_brain_mut(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<&mut OverlayBrain, String> {
        let (_, _, brain) =
            self.resolve_brain_with_seal_target(hint_path, cid_opt, is_explicit_memorize)?;
        Ok(brain)
    }

    fn reload_global_db(&mut self) -> Result<(), String> {
        if let Some(ref gp) = self.global_path {
            match open_global_ldb_checked(Some(gp)) {
                Ok(Some(gdb)) => {
                    self.global_db = Some(gdb);
                    self.brains.clear();
                }
                Ok(None) => {
                    self.global_db = None;
                    self.brains.clear();
                }
                Err(err) => {
                    self.brains.clear();
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

pub fn run_mcp_stdio_server_with_workspace_root(
    default_project_db: Option<&Path>,
    global_db_path: Option<&Path>,
    workspace_root: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let env_ws = std::env::var_os("LIBREDB_MCP_WORKSPACE_ROOT")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let effective_ws = workspace_root.or(env_ws.as_deref());
    let mut state =
        McpServerState::new_with_workspace_root(default_project_db, global_db_path, effective_ws)?;

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = io::stdout();
    process_mcp_stream(&mut reader, &mut stdout, &mut state)?;
    Ok(())
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
                        let updated = extract_workspace_roots_from_value(&params);
                        state.replace_client_workspace_roots(updated);
                    } else {
                        // Fail closed immediately for any closed workspace while querying fresh `roots/list`.
                        state.replace_client_workspace_roots(Vec::new());
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

fn has_explicit_root_fields(val: &Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    obj.contains_key("roots")
        || obj.contains_key("workspaceFolders")
        || obj.contains_key("rootUri")
        || obj.contains_key("rootPath")
}

fn extract_workspace_roots_from_value(val: &Value) -> Vec<PathBuf> {
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
            let requested_ws_dir = args
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .or_else(|| state.pinned_workspace_root.clone());
            if let Some(err) = args.get("error").and_then(Value::as_str) {
                req.error_context = Some(err.to_owned());
            }

            let q_key =
                canonical_brain_cache_key(&default_libredb_home().join("quarantined_workspace.ldb"));
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
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);

            let (ws_root, containment_root) = state.resolve_authorized_code_workspace(
                raw_cwd_arg,
                first_file_hint,
                action == "impact",
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
                    check_target_access(&ws_root)?;
                    state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &ws_root,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;
                    let reports = query_symbol_impact(&proj_db, target)?;
                    Ok(serde_json::to_string_pretty(&reports)?)
                }
                "fim" => {
                    let target = target_opt.ok_or("Missing target")?;
                    let resolved_target = resolve_rel(target);
                    check_target_access(&resolved_target)?;
                    check_target_access(&ws_root)?;
                    state.run_locked_workspace_index(
                        &proj_db,
                        &ws_root,
                        &ws_root,
                        Some(&ws_root_str),
                        cid_arg,
                    )?;
                    let bundle = extract_fim_slice(&proj_db, &resolved_target, sym, line, pad)?;
                    Ok(bundle.format_compact())
                }
                "index" => {
                    let target = target_opt.ok_or("Missing target")?;
                    let resolved_target = resolve_rel(target);
                    check_target_access(&resolved_target)?;
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
                let central_sqlite = user_home_dir().join(".gemini").join("database").join("customizations.db");
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

            let seal_res = state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db);
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
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
            let flt = args.get("filter").and_then(Value::as_str);
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
            if let Some(err) =
                crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
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
            let (skel, _) = FileSkeleton::index_or_get_cached(&proj_db, &resolved_fp, None)?;
            Ok(skel.render_compact(flt, flt.is_some()))
        }
        "libredb_impact" => {
            let sym = args.get("symbol").and_then(Value::as_str).ok_or("Missing symbol")?;
            let raw_cwd_arg = args.get("cwd").and_then(Value::as_str);
            let (ws_root, _) =
                state.resolve_authorized_code_workspace(raw_cwd_arg, None, true)?;
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
            let fp = args.get("file_path").and_then(Value::as_str).ok_or("Missing file_path")?;
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
            if let Some(err) =
                crate::security::check_mcp_read_path_policy(&resolved_fp, &protected)
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
            let bundle = extract_fim_slice(&proj_db, &resolved_fp, sym, line, pad)?;
            Ok(bundle.format_compact())
        }
        "libredb_handoff" => {
            let hid = args.get("handoff_id").and_then(Value::as_str).ok_or("Missing handoff_id")?;
            let tkey = args.get("task_key").and_then(Value::as_str).ok_or("Missing task_key")?;
            let role = args.get("role").and_then(Value::as_str).ok_or("Missing role")?;
            let notes = args.get("instructions").and_then(Value::as_str).unwrap_or("");
            let (ws_write_lock, ws_root_to_seal, proj_db) = {
                let (lock_opt, ws_opt, brain) =
                    state.resolve_brain_with_seal_target(cwd_hint, cid_arg, true)?;
                (lock_opt, ws_opt, Arc::clone(brain.project_db()))
            };
            let (_, block) = create_subagent_handoff(&proj_db, hid, tkey, role, notes)?;
            let seal_res = state.seal_project_db_if_authorized(ws_root_to_seal.as_deref(), &proj_db);
            drop(ws_write_lock);
            seal_res?;
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
    let fname = resolved.file_name()?.to_str()?;
    if !fname.eq_ignore_ascii_case("memory.ldb") {
        return None;
    }
    let parent = resolved.parent()?;
    if parent
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case(".agents"))
    {
        parent
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
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

fn resolve_explicit_hint_ldb_path(probe: &Path) -> Result<PathBuf, String> {
    if probe
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ldb"))
    {
        return Ok(probe.to_path_buf());
    }
    let joined = if probe.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(probe))
            .unwrap_or_else(|_| probe.to_path_buf())
    } else {
        probe.to_path_buf()
    };
    if !joined.exists() {
        return Err(format!(
            "LibreDB MCP access denied: workspace path '{}' does not exist",
            probe.display()
        ));
    }
    let start_dir = if joined.is_file() {
        joined.parent().unwrap_or(&joined)
    } else {
        &joined
    };
    if crate::security::is_forbidden_mcp_workspace_root(start_dir) {
        return Err(format!(
            "LibreDB MCP access denied: '{}' is a forbidden root or control-plane directory",
            probe.display()
        ));
    }
    if crate::security::is_private_brain_workspace(start_dir) {
        if let Some(repo_anc) = find_owning_repo_or_agents_ancestor(start_dir) {
            return Ok(repo_anc.join(".agents").join("memory.ldb"));
        }
    }
    Ok(start_dir.join(".agents").join("memory.ldb"))
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
        let (ws_write_lock, ws_seal_opt, brain) = state
            .resolve_brain_with_seal_target(Some(&hint_non_canon), None, true)
            .unwrap();
        assert!(ws_seal_opt.is_some());
        let proj_arc = std::sync::Arc::clone(brain.project_db());
        drop(ws_write_lock);
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
        assert!(err.contains("updating hmac-sha256:v4 trust seal"));
        assert!(
            state.brains.is_empty(),
            "Cached OverlayBrain must be evicted even when opened via non-canonical/relative path"
        );

        drop(proj_arc);
        drop(state);
        let _ = fs::remove_dir_all(&base_target);
    }

    #[test]
    fn bounded_jsonrpc_reader_and_mcp_workspace_containment_and_customizations_guard() {
        use super::{
            handle_rpc_method, read_bounded_jsonrpc_line, BoundedLineRead,
        };
        use serde_json::json;
        use std::io::Cursor;

        // 1. Oversized JSON-RPC line must be drained safely without unbounded allocation,
        //    leaving the next valid JSON-RPC line intact on the stream!
        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&vec![b'A'; 1024]);
        stream_bytes.push(b'\n');
        stream_bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let mut cursor = Cursor::new(stream_bytes);
        assert_eq!(
            read_bounded_jsonrpc_line(&mut cursor, 256).unwrap(),
            BoundedLineRead::Oversized
        );
        assert_eq!(
            read_bounded_jsonrpc_line(&mut cursor, 256).unwrap(),
            BoundedLineRead::Line("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}".to_owned())
        );
        assert_eq!(
            read_bounded_jsonrpc_line(&mut cursor, 256).unwrap(),
            BoundedLineRead::Eof
        );

        // 2. `libredb_code` MUST reject paths escaping outside `cwd` AND `libredb_memorize`
        //    MUST reject targeting `customizations.ldb`!
        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_containment_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let ws_dir = tmp.join("workspace");
        let outside_dir = tmp.join("outside");
        fs::create_dir_all(ws_dir.join(".agents")).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_rs = outside_dir.join("secret_algo.rs");
        fs::write(&outside_rs, "pub fn top_secret() {}\n").unwrap();

        let global_path = tmp.join("customizations.ldb");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(ws_dir.join(".agents").join("memory.ldb")).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_dir).unwrap();
        }

        let mut state =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&global_path)).unwrap();

        let escape_res = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": ws_dir.to_string_lossy().to_string(),
                    "target": "../outside/secret_algo.rs"
                }
            }),
            &mut state,
        );
        assert!(
            escape_res.is_err(),
            "libredb_code MUST reject '../outside/secret_algo.rs' escaping outside cwd!"
        );

        let global_mut_res = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": global_path.to_string_lossy().to_string(),
                    "facts": { "evil": "1" }
                }
            }),
            &mut state,
        );
        assert!(
            global_mut_res.is_err(),
            "libredb_memorize MUST refuse mutating customizations.ldb!"
        );

        drop(state);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_sync_central_sqlite_is_blocked_by_default_and_never_overwrites_trust_keys() {
        use super::handle_rpc_method;
        use libredb_bridge::import_sqlite_readonly;
        use serde_json::json;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_central_sync_guard_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let ws_dir = tmp.join("workspace");
        fs::create_dir_all(ws_dir.join(".agents")).unwrap();
        let global_path = tmp.join("customizations.ldb");
        let poisoned_sql = tmp.join("poisoned_customizations.db");

        let original_secret: Vec<u8>;
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(ws_dir.join(".agents").join("memory.ldb")).unwrap();
            pdb.put(WriteRequest::new(NodeKind::Fact, b"ok=1".to_vec()).with_key("ok"))
                .unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_dir).unwrap();
            original_secret = gdb
                .get_by_key(NodeKind::Config, "sys::trust_anchor_secret")
                .unwrap()
                .payload;
        }

        // Craft a malicious SQLite customizations.db attempting to forge trust:* and sys::* keys:
        {
            let conn = rusqlite::Connection::open(&poisoned_sql).unwrap();
            conn.execute_batch(
                "CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO runtime_config (key, value) VALUES
                   ('sys::trust_anchor_secret', '0000000000000000000000000000000000000000000000000000000000000000'),
                   ('trust:allowed::/evil/rogue', '1'),
                   ('trust:seal_rev::/evil/rogue', '99'),
                   ('workspace:evil', '/evil/rogue'),
                   ('workspace_id::0123456789abcdef', '/evil/rogue'),
                   ('ui:theme', 'solarized');",
            )
            .unwrap();
        }

        // 1. MCP `libredb_memorize(sync_central_sqlite=true)` MUST fail closed by default:
        let mut state =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&global_path)).unwrap();
        let err = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": ws_dir.to_string_lossy().to_string(),
                    "sync_central_sqlite": true
                }
            }),
            &mut state,
        )
        .expect_err("sync_central_sqlite=true MUST be rejected unless mcp:allow_central_sqlite_sync is enabled");
        assert!(err.contains("mcp:allow_central_sqlite_sync"));
        drop(state);

        // 2. Even if an operator runs `import_sqlite_readonly` into `customizations.ldb`,
        //    reserved `sys::*`, `trust:*`, `workspace:*`, and `workspace_id::*` keys MUST NEVER overwrite
        //    existing trust state or grant rogue workspace authorization:
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            import_sqlite_readonly(&poisoned_sql, &gdb, "central").unwrap();

            assert_eq!(
                gdb.get_by_key(NodeKind::Config, "sys::trust_anchor_secret")
                    .unwrap()
                    .payload,
                original_secret,
                "SQLite import MUST NEVER overwrite sys::trust_anchor_secret!"
            );
            assert!(
                crate::security::is_workspace_memory_trusted(Some(&gdb), &ws_dir),
                "Existing sealed workspace MUST remain trusted after SQLite import!"
            );
            for forbidden in [
                "trust:allowed::/evil/rogue",
                "trust:seal_rev::/evil/rogue",
                "workspace:evil",
                "workspace_id::0123456789abcdef",
            ] {
                assert!(
                    gdb.get_by_key(NodeKind::Config, forbidden).is_err(),
                    "Reserved Config key '{forbidden}' MUST NOT be imported from SQLite!"
                );
            }
            assert_eq!(
                gdb.get_by_key(NodeKind::Config, "ui:theme")
                    .unwrap()
                    .payload,
                b"solarized"
            );
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_code_indexing_propagates_lock_failures_and_uses_canonical_workspace_lock_for_subdirs() {
        use super::{handle_rpc_method, resolve_canonical_workspace_lock_root};
        use serde_json::json;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_lock_disciplined_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let ws_dir = tmp.join("mono_repo");
        let sub_crate = ws_dir.join("crates").join("sub");
        fs::create_dir_all(ws_dir.join(".agents")).unwrap();
        fs::create_dir_all(sub_crate.join("src")).unwrap();
        let sub_rs = sub_crate.join("src").join("lib.rs");
        fs::write(
            &sub_rs,
            "pub fn compute_widget() -> u32 { 42 }\npub fn caller_fn() -> u32 { compute_widget() }\n",
        )
        .unwrap();

        let global_path = tmp.join("customizations.ldb");
        let pdb_path = ws_dir.join(".agents").join("memory.ldb");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(&pdb_path).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws_dir).unwrap();

            // 1. Subdirectory `crates/sub` MUST resolve to the exact same canonical workspace lockfile as `ws_dir`:
            let resolved_lock_root = resolve_canonical_workspace_lock_root(&pdb, &sub_crate);
            let root_lock =
                crate::security::workspace_trust_lock_path_for_root(&gdb, &ws_dir).unwrap();
            let sub_lock =
                crate::security::workspace_trust_lock_path_for_root(&gdb, &resolved_lock_root)
                    .unwrap();
            assert_eq!(
                sub_lock, root_lock,
                "Subdirectory indexing MUST acquire the owning workspace root lockfile, not a separate subdir lock!"
            );
        }

        // 2. Holding `WorkspaceTrustLockGuard` on `ws_dir` in thread A MUST serialize `libredb_code(action=index, target=crates/sub)` in thread B:
        let gdb_holder = Arc::new(LibreDb::open(&global_path).unwrap());
        let holder_released = Arc::new(AtomicBool::new(false));
        let (locked_tx, locked_rx) = mpsc::channel();
        let gdb_for_thread = Arc::clone(&gdb_holder);
        let ws_for_thread = ws_dir.clone();
        let released_for_thread = Arc::clone(&holder_released);
        let lock_thread = thread::spawn(move || {
            let guard =
                crate::security::WorkspaceTrustLockGuard::acquire(&gdb_for_thread, &ws_for_thread)
                    .unwrap();
            locked_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(120));
            released_for_thread.store(true, Ordering::SeqCst);
            drop(guard);
        });
        locked_rx.recv().unwrap();

        let mut state =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&global_path)).unwrap();
        let idx_res = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "index",
                    "cwd": ws_dir.to_string_lossy().to_string(),
                    "target": "crates/sub"
                }
            }),
            &mut state,
        )
        .unwrap();
        assert!(
            holder_released.load(Ordering::SeqCst),
            "Subdirectory index MUST wait for the workspace-root WorkspaceTrustLockGuard before mutating memory.ldb!"
        );
        lock_thread.join().unwrap();
        let idx_text = idx_res["content"][0]["text"].as_str().unwrap_or("");
        assert!(idx_text.contains("\"symbols_indexed\": 2"));
        drop(state);
        drop(gdb_holder);

        // 3. When `WorkspaceTrustLockGuard::acquire` fails (e.g. obstructed lockfile), ALL THREE
        //    indexing paths (`impact`, `fim`, and `index`) MUST return `Err` and leave `0` symbols written:
        let fail_ws = tmp.join("fail_repo");
        fs::create_dir_all(fail_ws.join(".agents")).unwrap();
        let fail_rs = fail_ws.join("mod_a.rs");
        fs::write(&fail_rs, "pub fn blocked_fn() -> usize { 7 }\n").unwrap();
        let fail_pdb_path = fail_ws.join(".agents").join("memory.ldb");
        let lock_file_to_obstruct = {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(&fail_pdb_path).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &fail_ws).unwrap();
            crate::security::workspace_trust_lock_path_for_root(&gdb, &fail_ws).unwrap()
        };
        let _ = fs::remove_file(&lock_file_to_obstruct);
        fs::create_dir_all(&lock_file_to_obstruct).unwrap();

        let mut fail_state =
            McpServerState::new(Some(&tmp.join("default2.ldb")), Some(&global_path)).unwrap();
        for payload in [
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "impact",
                    "cwd": fail_ws.to_string_lossy().to_string(),
                    "target": "blocked_fn"
                }
            }),
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "fim",
                    "cwd": fail_ws.to_string_lossy().to_string(),
                    "target": "mod_a.rs",
                    "symbol": "blocked_fn"
                }
            }),
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "index",
                    "cwd": fail_ws.to_string_lossy().to_string(),
                    "target": "."
                }
            }),
        ] {
            let res = handle_rpc_method("tools/call", &payload, &mut fail_state);
            assert!(
                res.is_err(),
                "libredb_code MUST fail closed instead of indexing unlocked when WorkspaceTrustLockGuard::acquire fails: {payload}"
            );
        }
        drop(fail_state);

        let check_pdb = LibreDb::open(&fail_pdb_path).unwrap();
        assert_eq!(
            check_pdb.list_inodes(Some(NodeKind::Symbol), false).len(),
            0,
            "Failed lock acquisition MUST prevent unlocked Symbol writes into .agents/memory.ldb!"
        );
        drop(check_pdb);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_enforces_server_side_workspace_authorization_non_optional_containment_and_pinned_roots() {
        use super::handle_rpc_method;
        use serde_json::json;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_ws_authz_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let trusted_ws = tmp.join("trusted_ws");
        let second_trusted_ws = tmp.join("second_trusted_ws");
        let untrusted_ws = tmp.join("untrusted_ws");
        let ide_init_ws = tmp.join("ide_init_ws");
        for d in [&trusted_ws, &second_trusted_ws, &untrusted_ws, &ide_init_ws] {
            fs::create_dir_all(d.join("src")).unwrap();
        }
        fs::create_dir_all(trusted_ws.join(".agents")).unwrap();
        fs::create_dir_all(second_trusted_ws.join(".agents")).unwrap();

        let trusted_rs = trusted_ws.join("src").join("ok.rs");
        let second_rs = second_trusted_ws.join("src").join("second.rs");
        let untrusted_rs = untrusted_ws.join("src").join("secret.rs");
        let ide_rs = ide_init_ws.join("src").join("ide_mod.rs");
        fs::write(&trusted_rs, "pub fn alpha_ok() {}\n").unwrap();
        fs::write(&second_rs, "pub fn beta_ok() {}\n").unwrap();
        fs::write(&untrusted_rs, "pub fn stolen_secret() {}\n").unwrap();
        fs::write(&ide_rs, "pub fn ide_symbol() {}\n").unwrap();

        let global_path = tmp.join("customizations.ldb");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb1 = LibreDb::open(trusted_ws.join(".agents").join("memory.ldb")).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb1, &trusted_ws).unwrap();
            let pdb2 =
                LibreDb::open(second_trusted_ws.join(".agents").join("memory.ldb")).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb2, &second_trusted_ws).unwrap();
        }

        let mut state =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&global_path)).unwrap();

        // (a) Omitting `cwd` MUST still enforce containment + server-side workspace authorization:
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "target": untrusted_rs.to_string_lossy().to_string()
                    }
                }),
                &mut state,
            )
            .is_err(),
            "Omitting cwd MUST NOT allow reading files in an unauthorized workspace!"
        );

        // (b) Omitting `cwd` on an authorized workspace file succeeds, while mixing files from two
        //     distinct authorized workspaces in one omitted-cwd `files` batch is rejected by containment:
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "target": trusted_rs.to_string_lossy().to_string()
                    }
                }),
                &mut state,
            )
            .is_ok()
        );
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "files": [
                            trusted_rs.to_string_lossy().to_string(),
                            second_rs.to_string_lossy().to_string()
                        ]
                    }
                }),
                &mut state,
            )
            .is_err(),
            "Omitting cwd MUST bind batch containment to a single workspace root!"
        );

        // (c) Forging `cwd` to an unauthorized folder, non-existent folder, or `/` MUST fail closed:
        for bad_args in [
            json!({
                "action": "skeleton",
                "cwd": untrusted_ws.to_string_lossy().to_string(),
                "target": "src/secret.rs"
            }),
            json!({
                "action": "skeleton",
                "cwd": tmp.join("does_not_exist_dir").to_string_lossy().to_string(),
                "target": trusted_rs.to_string_lossy().to_string()
            }),
            json!({
                "action": "skeleton",
                "cwd": "/",
                "target": trusted_rs.to_string_lossy().to_string()
            }),
        ] {
            assert!(
                handle_rpc_method(
                    "tools/call",
                    &json!({
                        "name": "libredb_code",
                        "arguments": bad_args
                    }),
                    &mut state,
                )
                .is_err(),
                "Forged or non-existent cwd MUST be rejected: {bad_args}"
            );
        }

        // (d) Forging `cwd = untrusted_ws`, an arbitrary non-workspace `.ldb` file, or omitting `cwd`
        //     in `libredb_memorize` MUST be rejected and MUST NOT create `.agents/memory.ldb`:
        for bad_mem in [
            json!({
                "cwd": untrusted_ws.to_string_lossy().to_string(),
                "facts": { "planted": "1" }
            }),
            json!({
                "cwd": tmp.join("arbitrary_outside.ldb").to_string_lossy().to_string(),
                "facts": { "planted": "1" }
            }),
            json!({
                "facts": { "unscoped": "1" }
            }),
        ] {
            assert!(
                handle_rpc_method(
                    "tools/call",
                    &json!({
                        "name": "libredb_memorize",
                        "arguments": bad_mem
                    }),
                    &mut state,
                )
                .is_err(),
                "Unauthorized or unscoped libredb_memorize MUST fail closed: {bad_mem}"
            );
        }
        assert!(
            !untrusted_ws.join(".agents").join("memory.ldb").exists(),
            "Unauthorized libredb_memorize MUST NOT create .agents/memory.ldb on disk!"
        );
        assert!(
            !tmp.join("arbitrary_outside.ldb").exists(),
            "Arbitrary .ldb libredb_memorize MUST NOT create database files on disk!"
        );

        // (e) Host-provided MCP `initialize` `workspaceFolders` authorizes the IDE-opened workspace:
        let ide_uri = format!(
            "file:///{}",
            ide_init_ws
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches('/')
        );
        handle_rpc_method(
            "initialize",
            &json!({
                "workspaceFolders": [{ "uri": ide_uri, "name": "ide_init_ws" }]
            }),
            &mut state,
        )
        .unwrap();
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "cwd": ide_init_ws.to_string_lossy().to_string(),
                        "target": "src/ide_mod.rs"
                    }
                }),
                &mut state,
            )
            .is_ok()
        );
        drop(state);

        // (f) Server-pinned `--workspace-root` (`new_with_workspace_root`) strictly isolates the MCP
        //     session to `trusted_ws`, rejecting even `second_trusted_ws` (which IS in customizations.ldb):
        let mut pinned_state = McpServerState::new_with_workspace_root(
            Some(&tmp.join("default_pinned.ldb")),
            Some(&global_path),
            Some(&trusted_ws),
        )
        .unwrap();
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "target": "src/ok.rs"
                    }
                }),
                &mut pinned_state,
            )
            .is_ok(),
            "Pinned workspace root MUST allow omitted-cwd relative targets inside the pinned workspace!"
        );
        for cross_ws_call in [
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": second_trusted_ws.to_string_lossy().to_string(),
                    "target": "src/second.rs"
                }
            }),
            json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": second_trusted_ws.to_string_lossy().to_string(),
                    "facts": { "cross": "blocked" }
                }
            }),
            json!({
                "name": "libredb_pulse",
                "arguments": {
                    "query": "status",
                    "cwd": second_trusted_ws.to_string_lossy().to_string()
                }
            }),
        ] {
            assert!(
                handle_rpc_method("tools/call", &cross_ws_call, &mut pinned_state).is_err(),
                "Server-pinned --workspace-root MUST block all cross-workspace MCP calls: {cross_ws_call}"
            );
        }

        drop(pinned_state);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_sqlite_import_never_activates_security_switches_or_authorizes_untrusted_workspaces() {
        use super::handle_rpc_method;
        use libredb_bridge::import_sqlite_readonly;
        use serde_json::json;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_sql_policy_switches_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let trusted_ws = tmp.join("trusted_ws");
        let untrusted_ws = tmp.join("untrusted_ws");
        fs::create_dir_all(trusted_ws.join(".agents")).unwrap();
        fs::create_dir_all(trusted_ws.join("src")).unwrap();
        fs::create_dir_all(untrusted_ws.join("src")).unwrap();
        fs::write(trusted_ws.join("src").join("ok.rs"), "pub fn ok_fn() {}\n").unwrap();
        fs::write(
            untrusted_ws.join("src").join("secret.rs"),
            "pub fn hidden_fn() {}\n",
        )
        .unwrap();

        let global_path = tmp.join("customizations.ldb");
        let poisoned_sql = tmp.join("poisoned_switches.db");
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb = LibreDb::open(trusted_ws.join(".agents").join("memory.ldb")).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &trusted_ws).unwrap();
        }

        // Craft a SQLite `runtime_config` attempting to enable `mcp:allow_untrusted_workspaces`,
        // `mcp:allow_central_sqlite_sync`, `gitea_allow_insecure_http`, and `guardrail:allow_staged_files`:
        {
            let conn = rusqlite::Connection::open(&poisoned_sql).unwrap();
            conn.execute_batch(
                "CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO runtime_config (key, value) VALUES
                   ('mcp:allow_untrusted_workspaces', 'true'),
                   ('MCP:allow_central_sqlite_sync', 'true'),
                   ('gitea_allow_insecure_http', 'true'),
                   ('guardrail:allow_staged_files', '.env,secrets.json'),
                   ('ui:accent', 'emerald');",
            )
            .unwrap();
        }

        {
            let gdb = LibreDb::open(&global_path).unwrap();
            import_sqlite_readonly(&poisoned_sql, &gdb, "central").unwrap();

            for blocked_switch in [
                "mcp:allow_untrusted_workspaces",
                "mcp:allow_central_sqlite_sync",
                "MCP:allow_central_sqlite_sync",
                "gitea_allow_insecure_http",
                "guardrail:allow_staged_files",
            ] {
                assert!(
                    gdb.get_by_key(NodeKind::Config, blocked_switch).is_err(),
                    "Privileged security switch '{blocked_switch}' MUST NOT materialize from SQLite import!"
                );
            }
            assert!(
                !crate::security::is_mcp_workspace_authorized_in_global(&gdb, &untrusted_ws),
                "Untrusted workspace MUST NOT become MCP-authorized after importing SQLite runtime_config!"
            );
        }

        let mut state =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&global_path)).unwrap();

        // Untrusted workspace MUST still be rejected across `libredb_code` and `libredb_memorize`,
        // and `sync_central_sqlite=true` MUST remain disabled:
        for rejected_call in [
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": untrusted_ws.to_string_lossy().to_string(),
                    "target": "src/secret.rs"
                }
            }),
            json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": untrusted_ws.to_string_lossy().to_string(),
                    "facts": { "pwn": "1" }
                }
            }),
            json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": trusted_ws.to_string_lossy().to_string(),
                    "sync_central_sqlite": true
                }
            }),
        ] {
            assert!(
                handle_rpc_method("tools/call", &rejected_call, &mut state).is_err(),
                "SQLite-imported security switches MUST NOT weaken MCP enforcement: {rejected_call}"
            );
        }

        drop(state);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_without_global_db_rejects_unregistered_cwd_and_keeps_pinned_or_init_roots_consistent() {
        use super::handle_rpc_method;
        use serde_json::json;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_standalone_authz_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let rogue_ws = tmp.join("rogue_ws");
        let pinned_ws = tmp.join("pinned_ws");
        let init_ws = tmp.join("init_ws");
        let preseeded_ws = tmp.join("preseeded_ws");
        for d in [&rogue_ws, &pinned_ws, &init_ws, &preseeded_ws] {
            fs::create_dir_all(d.join("src")).unwrap();
        }
        fs::write(rogue_ws.join("src").join("rogue.rs"), "pub fn rogue() {}\n").unwrap();
        fs::write(
            pinned_ws.join("src").join("pinned.rs"),
            "pub fn pinned_target() -> usize { 1 }\npub fn pinned_caller() -> usize { pinned_target() }\n",
        )
        .unwrap();
        fs::write(
            init_ws.join("src").join("init.rs"),
            "pub fn init_fn() -> bool { true }\n",
        )
        .unwrap();
        fs::write(
            preseeded_ws.join("src").join("bad.rs"),
            "pub fn unverified() {}\n",
        )
        .unwrap();
        // Plant an unsealed `.agents/memory.ldb` inside `preseeded_ws` to simulate a cloned repository:
        fs::create_dir_all(preseeded_ws.join(".agents")).unwrap();
        {
            let planted = LibreDb::open(preseeded_ws.join(".agents").join("memory.ldb")).unwrap();
            planted
                .put(WriteRequest::new(NodeKind::Fact, b"trap=1".to_vec()).with_key("trap"))
                .unwrap();
        }

        let missing_global = tmp.join("nonexistent_customizations.ldb");

        // 1. Unconfigured standalone server (no `customizations.ldb`, no `--workspace-root`, no `initialize` roots):
        //    MUST keep `global_db == None`, MUST NOT create `customizations.ldb`, and MUST reject self-declared `cwd` on Call 1!
        let mut unconfigured =
            McpServerState::new(Some(&tmp.join("default.ldb")), Some(&missing_global)).unwrap();
        assert!(unconfigured.global_db.is_none());
        assert!(
            !missing_global.exists(),
            "McpServerState MUST NOT create an empty customizations.ldb when global DB does not exist!"
        );
        for unauth_call in [
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": rogue_ws.to_string_lossy().to_string(),
                    "target": "src/rogue.rs"
                }
            }),
            json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": rogue_ws.to_string_lossy().to_string(),
                    "facts": { "a": "b" }
                }
            }),
            json!({
                "name": "libredb_pulse",
                "arguments": {
                    "query": "rules",
                    "cwd": rogue_ws.to_string_lossy().to_string()
                }
            }),
        ] {
            assert!(
                handle_rpc_method("tools/call", &unauth_call, &mut unconfigured).is_err(),
                "Standalone MCP server without server-side workspace registration MUST reject self-declared cwd on Call 1: {unauth_call}"
            );
        }
        assert!(!rogue_ws.join(".agents").join("memory.ldb").exists());

        // 2. Host-provided MCP `initialize` `workspaceFolders` without `customizations.ldb`:
        //    - Rejects `preseeded_ws` (which contains an unverified `.agents/memory.ldb`) even if listed in `initialize`!
        //    - Allows `init_ws` consistently across Call 1, Call 2, and post-cache-eviction Call 3 without creating `.agents/memory.ldb`!
        //    - Rejects `libredb_memorize` until `customizations.ldb` is initialized!
        let init_uri = format!(
            "file:///{}",
            init_ws
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches('/')
        );
        let preseeded_uri = format!(
            "file:///{}",
            preseeded_ws
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches('/')
        );
        handle_rpc_method(
            "initialize",
            &json!({
                "workspaceFolders": [
                    { "uri": init_uri, "name": "init_ws" },
                    { "uri": preseeded_uri, "name": "preseeded_ws" }
                ]
            }),
            &mut unconfigured,
        )
        .unwrap();

        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "cwd": preseeded_ws.to_string_lossy().to_string(),
                        "target": "src/bad.rs"
                    }
                }),
                &mut unconfigured,
            )
            .is_err(),
            "Pre-existing unsealed .agents/memory.ldb MUST be rejected on Call 1 even when global_db is None!"
        );

        for round in 1..=3 {
            if round == 3 {
                unconfigured.brains.clear();
            }
            assert!(
                handle_rpc_method(
                    "tools/call",
                    &json!({
                        "name": "libredb_code",
                        "arguments": {
                            "action": "skeleton",
                            "cwd": init_ws.to_string_lossy().to_string(),
                            "target": "src/init.rs"
                        }
                    }),
                    &mut unconfigured,
                )
                .is_ok(),
                "MCP initialize workspace MUST succeed identically on round {round} without Call-1 vs Call-2 drift!"
            );
        }
        assert!(
            !init_ws.join(".agents").join("memory.ldb").exists(),
            "Read/code MCP tools MUST NOT create unsealed .agents/memory.ldb inside clean workspaces!"
        );
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_memorize",
                    "arguments": {
                        "cwd": init_ws.to_string_lossy().to_string(),
                        "facts": { "persist": "denied_without_global_trust" }
                    }
                }),
                &mut unconfigured,
            )
            .is_err(),
            "libredb_memorize MUST fail closed when global customizations.ldb is absent!"
        );
        assert!(!init_ws.join(".agents").join("memory.ldb").exists());
        let eph_dir_init = unconfigured.ephemeral_dir.clone();
        drop(unconfigured);
        if let Some(d) = eph_dir_init {
            assert!(
                !d.exists(),
                "Ephemeral MCP brain directory MUST be removed on McpServerState drop!"
            );
        }

        // 3. Server-pinned `--workspace-root` without `customizations.ldb`:
        //    Succeeds consistently across `skeleton`, `impact` (indexing), `pulse`, and post-eviction `skeleton`
        //    while keeping `pinned_ws/.agents/memory.ldb` completely absent on disk!
        let mut pinned_no_global = McpServerState::new_with_workspace_root(
            None,
            Some(&missing_global),
            Some(&pinned_ws),
        )
        .unwrap();
        assert!(pinned_no_global.global_db.is_none());
        for ok_call in [
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/pinned.rs"
                }
            }),
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "impact",
                    "target": "pinned_target"
                }
            }),
            json!({
                "name": "libredb_pulse",
                "arguments": {
                    "query": "pinned_target"
                }
            }),
        ] {
            assert!(
                handle_rpc_method("tools/call", &ok_call, &mut pinned_no_global).is_ok(),
                "Pinned workspace without customizations.ldb MUST succeed consistently: {ok_call}"
            );
        }
        pinned_no_global.brains.clear();
        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "skeleton",
                        "target": "src/pinned.rs"
                    }
                }),
                &mut pinned_no_global,
            )
            .is_ok(),
            "Pinned workspace without customizations.ldb MUST still succeed after brain cache eviction!"
        );
        assert!(
            !pinned_ws.join(".agents").join("memory.ldb").exists(),
            "Pinned workspace without customizations.ldb MUST NOT leave unsealed .agents/memory.ldb on disk!"
        );
        drop(pinned_no_global);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_nested_workspaces_always_select_most_specific_cognitive_brain_regardless_of_order() {
        use super::handle_rpc_method;
        use libredb_cognitive::CognitiveEngine;
        use serde_json::json;
        use std::sync::Arc;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_nested_ws_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let main_ws = tmp.join("Projects").join("Main");
        let sub_ws = main_ws.join("Subproject");
        let clean_sub_ws = main_ws.join("CleanSub");
        fs::create_dir_all(main_ws.join(".git")).unwrap();
        fs::create_dir_all(main_ws.join(".agents")).unwrap();
        fs::create_dir_all(main_ws.join("src")).unwrap();
        fs::create_dir_all(sub_ws.join(".agents")).unwrap();
        fs::create_dir_all(sub_ws.join("src")).unwrap();
        fs::create_dir_all(clean_sub_ws.join("src")).unwrap();

        fs::write(
            main_ws.join("src").join("main_mod.rs"),
            "pub fn parent_main_entry() {}\n",
        )
        .unwrap();
        fs::write(
            sub_ws.join("src").join("sub_mod.rs"),
            "pub fn child_sub_entry() {}\n",
        )
        .unwrap();
        fs::write(
            clean_sub_ws.join("src").join("clean_mod.rs"),
            "pub fn clean_nested_entry() {}\n",
        )
        .unwrap();

        let global_path = tmp.join("customizations.ldb");
        let main_ldb = main_ws.join(".agents").join("memory.ldb");
        let sub_ldb = sub_ws.join(".agents").join("memory.ldb");

        {
            let gdb = LibreDb::open(&global_path).unwrap();

            let pdb_main = Arc::new(LibreDb::open(&main_ldb).unwrap());
            pdb_main
                .put(
                    WriteRequest::new(NodeKind::Fact, b"ws_role = parent_main_marker".to_vec())
                        .with_key("ws_role"),
                )
                .unwrap();
            let mut cog_main = CognitiveEngine::open_db(Arc::clone(&pdb_main)).unwrap();
            cog_main.save_index_snapshot().unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb_main, &main_ws).unwrap();

            let pdb_sub = Arc::new(LibreDb::open(&sub_ldb).unwrap());
            pdb_sub
                .put(
                    WriteRequest::new(NodeKind::Fact, b"ws_role = child_sub_marker".to_vec())
                        .with_key("ws_role"),
                )
                .unwrap();
            let mut cog_sub = CognitiveEngine::open_db(Arc::clone(&pdb_sub)).unwrap();
            cog_sub.save_index_snapshot().unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb_sub, &sub_ws).unwrap();
        }

        let to_file_uri = |p: &std::path::Path| -> String {
            format!(
                "file:///{}",
                p.to_string_lossy()
                    .replace('\\', "/")
                    .trim_start_matches('/')
            )
        };
        let main_uri = to_file_uri(&main_ws);
        let sub_uri = to_file_uri(&sub_ws);
        let clean_sub_uri = to_file_uri(&clean_sub_ws);

        // 1. Register `[Main, Main/Subproject]` (parent FIRST, child SECOND) - previously `.iter().find`
        //    returned `Main` instead of `Main/Subproject`!
        let mut state_parent_first = McpServerState::new_with_workspace_root(
            None,
            Some(&global_path),
            None,
        )
        .unwrap();
        handle_rpc_method(
            "initialize",
            &json!({
                "workspaceFolders": [
                    { "uri": main_uri, "name": "Main" },
                    { "uri": sub_uri, "name": "Subproject" }
                ]
            }),
            &mut state_parent_first,
        )
        .unwrap();

        let sub_pulse = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_pulse",
                "arguments": {
                    "query": "ws_role",
                    "cwd": sub_ws.to_string_lossy().to_string()
                }
            }),
            &mut state_parent_first,
        )
        .unwrap();
        let sub_pulse_txt = sub_pulse["content"][0]["text"].as_str().unwrap();
        assert!(
            sub_pulse_txt.contains("child_sub_marker")
                && !sub_pulse_txt.contains("parent_main_marker"),
            "Nested Subproject pulse MUST read child_sub_marker from Subproject, never parent_main_marker: {sub_pulse_txt}"
        );

        handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "index",
                    "cwd": sub_ws.to_string_lossy().to_string(),
                    "target": "."
                }
            }),
            &mut state_parent_first,
        )
        .unwrap();

        // Indexing `Subproject` MUST populate `Subproject/.agents/memory.ldb` and leave `Main/.agents/memory.ldb` untouched:
        {
            let pdb_main = LibreDb::open(&main_ldb).unwrap();
            let pdb_sub = LibreDb::open(&sub_ldb).unwrap();
            assert!(
                pdb_main.list_inodes(Some(NodeKind::Symbol), false).is_empty(),
                "Indexing nested Subproject MUST NOT write Symbol nodes into parent Main/.agents/memory.ldb!"
            );
            assert!(
                !pdb_sub.list_inodes(Some(NodeKind::Symbol), false).is_empty(),
                "Indexing nested Subproject MUST write Symbol nodes into Subproject/.agents/memory.ldb!"
            );
        }

        // Memorizing from a subdirectory (`Main/Subproject/src`) MUST persist and seal into
        // `Main/Subproject/.agents/memory.ldb` (neither `Main` nor `Main/Subproject/src/.agents`):
        handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_memorize",
                "arguments": {
                    "cwd": sub_ws.join("src").to_string_lossy().to_string(),
                    "facts": { "nested_write_scope": "strictly_child_subproject" }
                }
            }),
            &mut state_parent_first,
        )
        .unwrap();
        assert!(
            !sub_ws.join("src").join(".agents").exists(),
            "Memorizing from Subproject/src MUST NOT create Subproject/src/.agents!"
        );
        {
            let gdb = LibreDb::open(&global_path).unwrap();
            let pdb_main = LibreDb::open(&main_ldb).unwrap();
            let pdb_sub = LibreDb::open(&sub_ldb).unwrap();
            assert!(pdb_main.get_by_key(NodeKind::Fact, "nested_write_scope").is_err());
            assert!(pdb_sub.get_by_key(NodeKind::Fact, "nested_write_scope").is_ok());
            assert!(crate::security::is_workspace_memory_trusted(Some(&gdb), &main_ws));
            assert!(crate::security::is_workspace_memory_trusted(Some(&gdb), &sub_ws));
        }

        // Omitted-`cwd` absolute target inside `Subproject` MUST also resolve to `Subproject`:
        let skel_res = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": sub_ws.join("src").join("sub_mod.rs").to_string_lossy().to_string()
                }
            }),
            &mut state_parent_first,
        )
        .unwrap();
        assert!(skel_res["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("child_sub_entry"));
        drop(state_parent_first);

        // 2. Reverse registration order `[Main/Subproject, Main]` AND cross-source nesting
        //    `[Main, Main/CleanSub]` (where `CleanSub` has NO `.agents` and NO `.git` inside `Main`'s `.git` tree):
        let mut state_child_first = McpServerState::new_with_workspace_root(
            None,
            Some(&global_path),
            None,
        )
        .unwrap();
        handle_rpc_method(
            "initialize",
            &json!({
                "workspaceFolders": [
                    { "uri": sub_uri, "name": "Subproject" },
                    { "uri": main_uri, "name": "Main" },
                    { "uri": clean_sub_uri, "name": "CleanSub" }
                ]
            }),
            &mut state_child_first,
        )
        .unwrap();

        let main_pulse = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_pulse",
                "arguments": {
                    "query": "ws_role",
                    "cwd": main_ws.to_string_lossy().to_string()
                }
            }),
            &mut state_child_first,
        )
        .unwrap();
        let main_pulse_txt = main_pulse["content"][0]["text"].as_str().unwrap();
        assert!(
            main_pulse_txt.contains("parent_main_marker")
                && !main_pulse_txt.contains("child_sub_marker"),
            "Parent Main pulse MUST read parent_main_marker, never child_sub_marker: {main_pulse_txt}"
        );

        handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "index",
                    "cwd": clean_sub_ws.to_string_lossy().to_string(),
                    "target": "."
                }
            }),
            &mut state_child_first,
        )
        .unwrap();
        assert!(
            !clean_sub_ws.join(".agents").join("memory.ldb").exists(),
            "Clean nested workspace without .agents MUST use ephemeral brain without creating .agents/memory.ldb!"
        );
        {
            let pdb_main = LibreDb::open(&main_ldb).unwrap();
            assert!(
                pdb_main.list_inodes(Some(NodeKind::Symbol), false).is_empty(),
                "Indexing clean nested CleanSub MUST NOT walk up into parent Main/.agents/memory.ldb!"
            );
        }

        drop(state_child_first);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_stream_refreshes_client_roots_on_list_changed_and_revokes_closed_workspaces() {
        use super::process_mcp_stream;
        use serde_json::{json, Value};
        use std::io::Cursor;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_dynamic_roots_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let missing_global = tmp.join("nonexistent_customizations.ldb");
        let ws_a = tmp.join("ws_alpha");
        let ws_b = tmp.join("ws_beta");
        fs::create_dir_all(ws_a.join("src")).unwrap();
        fs::create_dir_all(ws_b.join("src")).unwrap();
        fs::write(ws_a.join("src").join("alpha.rs"), "pub fn alpha_fn() {}\n").unwrap();
        fs::write(ws_b.join("src").join("beta.rs"), "pub fn beta_fn() {}\n").unwrap();

        let to_file_uri = |p: &std::path::Path| -> String {
            format!(
                "file:///{}",
                p.to_string_lossy()
                    .replace('\\', "/")
                    .trim_start_matches('/')
            )
        };
        let uri_a = to_file_uri(&ws_a);
        let uri_b = to_file_uri(&ws_b);

        let mut state =
            McpServerState::new_with_workspace_root(None, Some(&missing_global), None).unwrap();

        let run_frames = |st: &mut McpServerState, frames: &[Value]| -> Vec<Value> {
            let mut input_bytes = Vec::new();
            for f in frames {
                input_bytes.extend_from_slice(f.to_string().as_bytes());
                input_bytes.push(b'\n');
            }
            let mut reader = Cursor::new(input_bytes);
            let mut out_bytes = Vec::new();
            process_mcp_stream(&mut reader, &mut out_bytes, st).unwrap();
            String::from_utf8(out_bytes)
                .unwrap()
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str::<Value>(l).unwrap())
                .collect()
        };

        // Phase 1: MCP `2024-11-05` client declares `capabilities.roots` without inline `workspaceFolders`,
        // followed by `notifications/initialized` -> server MUST emit `roots/list` (`id = "libredb-roots-1"`):
        let out_p1 = run_frames(
            &mut state,
            &[
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "roots": { "listChanged": true } }
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                }),
            ],
        );
        assert_eq!(out_p1.len(), 2);
        assert_eq!(out_p1[0]["id"], json!(1));
        assert!(out_p1[0].get("result").is_some());
        assert_eq!(out_p1[1]["method"], json!("roots/list"));
        assert_eq!(out_p1[1]["id"], json!("libredb-roots-1"));

        // Phase 2: Client responds with `[ws_a]` -> `ws_a` succeeds (opening ephemeral `.ldb`), `ws_b` is denied:
        let out_p2 = run_frames(
            &mut state,
            &[
                json!({
                    "jsonrpc": "2.0",
                    "id": "libredb-roots-1",
                    "result": {
                        "roots": [{ "uri": uri_a, "name": "ws_alpha" }]
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "libredb_pulse",
                        "arguments": {
                            "query": "alpha",
                            "cwd": ws_a.to_string_lossy().to_string()
                        }
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "libredb_code",
                        "arguments": {
                            "action": "skeleton",
                            "cwd": ws_b.to_string_lossy().to_string(),
                            "target": "src/beta.rs"
                        }
                    }
                }),
            ],
        );
        assert_eq!(out_p2.len(), 2);
        assert_eq!(out_p2[0]["id"], json!(2));
        assert!(out_p2[0].get("result").is_some(), "Authorized ws_a MUST succeed: {:?}", out_p2[0]);
        assert_eq!(out_p2[1]["id"], json!(3));
        assert!(out_p2[1].get("error").is_some(), "Unauthorized ws_b MUST fail closed: {:?}", out_p2[1]);

        let eph_a_file = state
            .ephemeral_dir
            .as_ref()
            .unwrap()
            .join(crate::security::ephemeral_workspace_ldb_filename(&ws_a));
        assert!(eph_a_file.is_file(), "Ephemeral .ldb for ws_a must exist while ws_a is active");

        // Phase 3: Client sends `notifications/roots/list_changed` AND immediately pipelines a `tools/call`
        // on closed `ws_a` BEFORE replying to `libredb-roots-2` -> server MUST revoke `ws_a` immediately
        // (fail-closed), delete `eph_a_file`, emit `libredb-roots-2`, and reject the pipelined `ws_a` call!
        let out_p3 = run_frames(
            &mut state,
            &[
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/roots/list_changed"
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "libredb_pulse",
                        "arguments": {
                            "query": "alpha",
                            "cwd": ws_a.to_string_lossy().to_string()
                        }
                    }
                }),
            ],
        );
        assert_eq!(out_p3.len(), 2);
        assert_eq!(out_p3[0]["method"], json!("roots/list"));
        assert_eq!(out_p3[0]["id"], json!("libredb-roots-2"));
        assert_eq!(out_p3[1]["id"], json!(4));
        assert!(
            out_p3[1].get("error").is_some(),
            "Closed workspace ws_a MUST be revoked immediately on notifications/roots/list_changed!"
        );
        assert!(
            !eph_a_file.exists(),
            "Ephemeral .ldb file for revoked ws_a MUST be deleted on root eviction!"
        );

        // Phase 4: Client replies to `libredb-roots-2` with `[ws_b]` -> `ws_a` remains denied, `ws_b` now succeeds!
        let out_p4 = run_frames(
            &mut state,
            &[
                json!({
                    "jsonrpc": "2.0",
                    "id": "libredb-roots-2",
                    "result": {
                        "roots": [{ "uri": uri_b, "name": "ws_beta" }]
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "libredb_code",
                        "arguments": {
                            "action": "skeleton",
                            "cwd": ws_a.to_string_lossy().to_string(),
                            "target": "src/alpha.rs"
                        }
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "libredb_code",
                        "arguments": {
                            "action": "skeleton",
                            "cwd": ws_b.to_string_lossy().to_string(),
                            "target": "src/beta.rs"
                        }
                    }
                }),
            ],
        );
        assert_eq!(out_p4.len(), 2);
        assert_eq!(out_p4[0]["id"], json!(5));
        assert!(out_p4[0].get("error").is_some(), "Closed ws_a MUST stay denied after switching to ws_b");
        assert_eq!(out_p4[1]["id"], json!(6));
        assert!(
            out_p4[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("beta_fn"),
            "Newly added ws_b MUST succeed after roots/list refresh: {:?}",
            out_p4[1]
        );

        drop(state);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn mcp_reaps_orphaned_ephemeral_dbs_from_crashed_processes_without_touching_live_sessions() {
        use super::handle_rpc_method;
        use serde_json::json;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_mcp_eph_reaper_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let missing_global = tmp.join("nonexistent_customizations.ldb");
        let ws_live = tmp.join("ws_live");
        let ws_crashed = tmp.join("ws_crashed");
        fs::create_dir_all(ws_live.join("src")).unwrap();
        fs::create_dir_all(ws_crashed.join("src")).unwrap();
        fs::write(ws_live.join("src").join("live.rs"), "pub fn live_fn() {}\n").unwrap();
        fs::write(
            ws_crashed.join("src").join("crashed.rs"),
            "pub fn crashed_fn() {}\n",
        )
        .unwrap();

        let mut state_live = McpServerState::new_with_workspace_root(
            None,
            Some(&missing_global),
            Some(&ws_live),
        )
        .unwrap();
        let mut state_crashed = McpServerState::new_with_workspace_root(
            None,
            Some(&missing_global),
            Some(&ws_crashed),
        )
        .unwrap();

        handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_pulse",
                "arguments": { "query": "live_fn" }
            }),
            &mut state_live,
        )
        .unwrap();
        handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_pulse",
                "arguments": { "query": "crashed_fn" }
            }),
            &mut state_crashed,
        )
        .unwrap();

        let live_dir = state_live.ephemeral_dir.clone().unwrap();
        let leaked_dir = state_crashed
            .simulate_hard_crash_for_test()
            .expect("Expected ephemeral directory on crashed MCP state");
        assert!(live_dir.exists());
        assert!(
            leaked_dir.exists(),
            "Simulated SIGKILL/TerminateProcess MUST leave orphaned ephemeral dir on disk prior to reaping"
        );

        // Starting a new MCP server (while `state_live` is still running and holding `.owner.lock`)
        // MUST reap `leaked_dir` and MUST NOT disturb `live_dir`!
        let state_reaper = McpServerState::new_with_workspace_root(
            None,
            Some(&missing_global),
            Some(&ws_live),
        )
        .unwrap();
        assert!(
            !leaked_dir.exists(),
            "Abandoned ephemeral directory from crashed MCP server MUST be reaped on startup!"
        );
        assert!(
            live_dir.exists(),
            "Live MCP server's locked ephemeral directory MUST NEVER be deleted by concurrent reaper!"
        );

        assert!(
            handle_rpc_method(
                "tools/call",
                &json!({
                    "name": "libredb_code",
                    "arguments": {
                        "action": "impact",
                        "target": "live_fn"
                    }
                }),
                &mut state_live,
            )
            .is_ok(),
            "Live MCP session MUST continue operating cleanly after concurrent ephemeral reaping!"
        );

        drop(state_reaper);
        drop(state_live);
        assert!(
            !live_dir.exists(),
            "Live MCP session MUST still clean up its own ephemeral directory on normal Drop!"
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
