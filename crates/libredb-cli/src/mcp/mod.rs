//! Multi-workspace, low-prompt-footprint Model Context Protocol (`MCP`) JSON-RPC 2.0 server.
//!
//! Modular architecture (`v1.0.0`):
//! - `mod.rs`: `McpServerState` lifecycle, bounded JSON-RPC framing, and in-RAM `SessionState`
//!   continuity fallback on transient/simulated disk write errors.
//! - `protocol.rs`: JSON-RPC 2.0 stream transport, `initialize` root discovery, and dynamic
//!   `notifications/roots/list_changed` / `roots/list` synchronization.
//! - `authz.rs`: Server-side workspace authorization, nested workspace boundary isolation,
//!   ephemeral `0700` `.ldb` brain routing, and `WorkspaceTrustLockGuard` seal orchestration.
//! - `tools.rs`: `libredb_pulse`, `libredb_code`, `libredb_memorize`, and legacy tool aliases.

mod authz;
mod protocol;
mod tools;
#[cfg(test)]
mod tests;

pub use protocol::process_mcp_stream;
pub(crate) use protocol::handle_rpc_method;

use crate::hooks::{default_global_ldb_path, open_global_ldb_checked};
use authz::{default_libredb_home, validate_pinned_workspace_root, workspace_root_from_agents_ldb};
use libredb_cognitive::{OverlayBrain, SessionState};
use libredb_core::LibreDb;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) const MAX_CACHED_BRAINS: usize = 16;
pub(super) const MAX_RAM_SESSIONS: usize = 64;
pub(super) const MAX_MCP_LINE_BYTES: usize = 16 * 1024 * 1024;

pub struct McpServerState {
    pub(super) default_project_path: PathBuf,
    pub(super) global_path: Option<PathBuf>,
    pub(super) global_db: Option<Arc<LibreDb>>,
    /// Optional hard workspace root pinned at server launch (`--workspace-root`,
    /// `LIBREDB_MCP_WORKSPACE_ROOT`, or `--project <ws>/.agents/memory.ldb`). When set, all
    /// MCP workspace and file operations are strictly confined within this directory regardless
    /// of caller-supplied `cwd` or other entries in `customizations.ldb`.
    pub(super) pinned_workspace_root: Option<PathBuf>,
    /// Workspace roots reported by the trusted MCP host client during `initialize` or updated
    /// dynamically via `notifications/roots/list_changed` -> `roots/list`. Never controllable by tool calls.
    pub(super) client_workspace_roots: Vec<PathBuf>,
    /// True if the MCP host client advertised `capabilities.roots` during `initialize`.
    pub(super) client_supports_roots: bool,
    /// True while a `notifications/roots/list_changed` (or post-`initialize`) `roots/list` query
    /// is in flight: suspends client-root authorization fail-closed immediately while preserving
    /// cached `OverlayBrain`s and ephemeral `.ldb` session state for surviving roots until the
    /// updated root list arrives and is diffed.
    pub(super) client_roots_refresh_pending: bool,
    /// Monotonic counter for server-initiated `roots/list` JSON-RPC queries.
    pub(super) next_server_req_seq: u64,
    /// In-flight server-to-client `roots/list` request ID awaiting a JSON-RPC response on stdin.
    pub(super) pending_roots_request_id: Option<String>,
    /// Keyed by `canonical_brain_cache_key(db_path)` so relative paths, `..` segments, symlinks,
    /// and Windows casing variants always address and evict the exact same cached `OverlayBrain`.
    pub(super) brains: HashMap<String, OverlayBrain>,
    /// Bounded in-RAM `SessionState` fallback (`(brain_cache_key, cid) -> SessionState`) activated
    /// only when saving `SessionState` hits an OS/storage write error (`Io` / `SimulatedPowerLoss`),
    /// preserving Zero-Repeat deduplication within the active session while surfacing an explicit warning.
    pub(super) ram_session_fallback: HashMap<(String, String), SessionState>,
    /// Lazy CSPRNG `0700` private directory holding ephemeral `.ldb` brains for clean workspaces
    /// opened before `.agents/memory.ldb` exists or when `customizations.ldb` is absent, ensuring
    /// read/code MCP tools never materialize unsealed `.agents/memory.ldb` files inside repos.
    pub(super) ephemeral_dir: Option<PathBuf>,
    /// Exclusive kernel file lock on `<ephemeral_dir>/.owner.lock` held for the lifetime of this
    /// server so crashed (`SIGKILL`) directories can be reaped without touching active sessions.
    pub(super) ephemeral_lock: Option<libredb_core::OsFileBackend>,
}

impl Drop for McpServerState {
    fn drop(&mut self) {
        self.brains.clear();
        self.ram_session_fallback.clear();
        if let Some(lock_backend) = self.ephemeral_lock.take() {
            let _ = lock_backend.unlock_exclusive();
            drop(lock_backend);
        }
        if let Some(dir) = self.ephemeral_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

pub(super) fn insert_brain_bounded(
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
            client_roots_refresh_pending: false,
            next_server_req_seq: 0,
            pending_roots_request_id: None,
            brains: HashMap::new(),
            ram_session_fallback: HashMap::new(),
            ephemeral_dir: None,
            ephemeral_lock: None,
        })
    }

    #[cfg(test)]
    pub(super) fn simulate_hard_crash_for_test(mut self) -> Option<PathBuf> {
        self.brains.clear();
        self.ram_session_fallback.clear();
        if let Some(lock_backend) = self.ephemeral_lock.take() {
            let _ = lock_backend.unlock_exclusive();
            drop(lock_backend);
        }
        // Take `ephemeral_dir` before `Drop` runs so `remove_dir_all` is skipped, faithfully
        // reproducing OS kernel file-descriptor teardown after `SIGKILL` / `TerminateProcess`.
        self.ephemeral_dir.take()
    }

    pub(super) fn insert_ram_session_bounded(&mut self, key: (String, String), sess: SessionState) {
        if !self.ram_session_fallback.contains_key(&key)
            && self.ram_session_fallback.len() >= MAX_RAM_SESSIONS
        {
            if let Some(victim) = self.ram_session_fallback.keys().next().cloned() {
                self.ram_session_fallback.remove(&victim);
            }
        }
        self.ram_session_fallback.insert(key, sess);
    }

    pub(super) fn clear_ram_sessions_for_cache_key(&mut self, brain_key: &str) {
        self.ram_session_fallback.retain(|(bk, _), _| bk != brain_key);
    }

    pub(super) fn sync_global_db_or_purge(&mut self) -> Result<(), String> {
        if let Some(ref gdb) = self.global_db {
            if let Err(sync_err) = crate::security::check_global_trust_sync(gdb) {
                self.brains.clear();
                self.ram_session_fallback.clear();
                return Err(sync_err);
            }
        } else if let Some(ref gp) = self.global_path {
            match open_global_ldb_checked(Some(gp)) {
                Ok(Some(gdb)) => {
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                    self.global_db = Some(gdb);
                }
                Ok(None) => {}
                Err(err) => {
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                    return Err(err);
                }
            }
        } else {
            match open_global_ldb_checked(None) {
                Ok(Some(gdb)) => {
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                    self.global_path = Some(default_global_ldb_path());
                    self.global_db = Some(gdb);
                }
                Ok(None) => {}
                Err(err) => {
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub(super) fn reload_global_db(&mut self) -> Result<(), String> {
        if let Some(ref gp) = self.global_path {
            match open_global_ldb_checked(Some(gp)) {
                Ok(Some(gdb)) => {
                    self.global_db = Some(gdb);
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                }
                Ok(None) => {
                    self.global_db = None;
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                }
                Err(err) => {
                    self.brains.clear();
                    self.ram_session_fallback.clear();
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub(super) fn custom_protected_paths(&self, proj_db: Option<&LibreDb>) -> Vec<String> {
        crate::security::load_config_list(
            self.global_db.as_deref(),
            proj_db,
            "guardrail:protected_paths",
        )
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
