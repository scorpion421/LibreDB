//! Cross-platform local in-memory IPC coordinator bridging short-lived lifecycle hooks
//! (`hook-pre-tool`, `hook-pre-invocation`) directly into the running `libredb mcp-serve` process.
//!
//! - Windows: local Named Pipe (`\\.\pipe\libredb-ipc-v1-<24hex>`) with `PIPE_REJECT_REMOTE_CLIENTS`
//!   and default user DACL (no drivers, no admin elevation, and no SMB/network I/O).
//! - Unix (Linux/macOS): `0600` Unix Domain Socket guarded by an advisory file lock.

use crate::hooks::{
    default_global_ldb_path, evaluate_pre_invocation_payload_with_ram_state,
    evaluate_pre_tool_payload_with_ram_state,
};
use crate::mcp::{read_bounded_jsonrpc_line, BoundedLineRead, McpServerState, MAX_MCP_LINE_BYTES};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const LOCK_TRY_TIMEOUT_MS: u64 = 400;

fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn effective_global_ldb_path(global_ldb_opt: Option<&Path>) -> PathBuf {
    let raw = global_ldb_opt
        .map(Path::to_path_buf)
        .unwrap_or_else(default_global_ldb_path);
    if raw.is_relative() {
        std::env::current_dir()
            .map(|c| c.join(&raw))
            .unwrap_or(raw)
    } else {
        raw
    }
}

/// Computes the deterministic 24-hex endpoint identifier bound to `customizations.ldb`.
pub fn control_plane_endpoint_id(global_ldb_opt: Option<&Path>) -> String {
    let abs = effective_global_ldb_path(global_ldb_opt);
    let norm = crate::security::normalize_workspace_key(&abs);
    let mut h = Sha256::new();
    h.update(b"LibreDB::ControlPlaneIpc::v1\0");
    h.update(norm.as_bytes());
    let digest = h.finalize();
    hex_encode_lower(&digest[..12])
}

#[cfg(windows)]
fn endpoint_address(global_ldb_opt: Option<&Path>) -> String {
    let id = control_plane_endpoint_id(global_ldb_opt);
    format!(r"\\.\pipe\libredb-ipc-v1-{id}")
}

#[cfg(unix)]
fn endpoint_address(global_ldb_opt: Option<&Path>) -> PathBuf {
    let id = control_plane_endpoint_id(global_ldb_opt);
    let abs = effective_global_ldb_path(global_ldb_opt);
    if let Some(parent) = abs.parent().filter(|p| !p.as_os_str().is_empty()) {
        let cand = parent.join(format!(".ipc_{id}.sock"));
        if cand.as_os_str().len() <= 96 {
            return cand;
        }
    }
    std::env::temp_dir().join(format!("libredb-ipc-{id}.sock"))
}

fn handle_ipc_line(
    raw_line: &str,
    global_ldb_default: &Option<PathBuf>,
    state: &Arc<Mutex<McpServerState>>,
    served_count: &Arc<AtomicU64>,
) -> Value {
    let Ok(req) = serde_json::from_str::<Value>(raw_line.trim()) else {
        return json!({ "ok": false, "fallback": true });
    };
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    let payload = req.get("payload").unwrap_or(&Value::Null);
    let req_gdb = req
        .get("global_ldb")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let eff_gdb = req_gdb.as_deref().or(global_ldb_default.as_deref());

    let Some(mut st) = state.try_lock_for(Duration::from_millis(LOCK_TRY_TIMEOUT_MS)) else {
        return json!({ "ok": false, "fallback": true });
    };

    match op {
        "pre_tool" => {
            let response = evaluate_pre_tool_payload_with_ram_state(payload, eff_gdb, &mut st);
            served_count.fetch_add(1, Ordering::AcqRel);
            json!({ "ok": true, "response": response })
        }
        "pre_invocation" => {
            match evaluate_pre_invocation_payload_with_ram_state(payload, eff_gdb, &mut st) {
                Ok(response) => {
                    served_count.fetch_add(1, Ordering::AcqRel);
                    json!({ "ok": true, "response": response })
                }
                Err(_) => json!({ "ok": false, "fallback": true }),
            }
        }
        _ => json!({ "ok": false, "fallback": true }),
    }
}

fn serve_connected_stream<R: io::Read, W: io::Write>(
    reader_stream: R,
    mut writer_stream: W,
    global_ldb_default: &Option<PathBuf>,
    state: &Arc<Mutex<McpServerState>>,
    served_count: &Arc<AtomicU64>,
) {
    let mut reader = BufReader::new(reader_stream);
    let req_line = match read_bounded_jsonrpc_line(&mut reader, MAX_MCP_LINE_BYTES) {
        Ok(BoundedLineRead::Line(l)) if !l.trim().is_empty() => l,
        _ => return,
    };
    drop(reader);

    let resp = handle_ipc_line(&req_line, global_ldb_default, state, served_count);
    if let Ok(mut out) = serde_json::to_string(&resp) {
        out.push('\n');
        let _ = writer_stream.write_all(out.as_bytes());
        let _ = writer_stream.flush();
    }
}

fn exchange_client_line<R: io::Read, W: io::Write>(
    reader_stream: R,
    mut writer_stream: W,
    request_line: &str,
) -> Option<Value> {
    writer_stream.write_all(request_line.as_bytes()).ok()?;
    writer_stream.flush().ok()?;
    let mut reader = BufReader::new(reader_stream);
    let line = match read_bounded_jsonrpc_line(&mut reader, MAX_MCP_LINE_BYTES).ok()? {
        BoundedLineRead::Line(l) => l,
        BoundedLineRead::Oversized | BoundedLineRead::Eof => return None,
    };
    let resp: Value = serde_json::from_str(line.trim()).ok()?;
    if resp.get("ok").and_then(Value::as_bool) == Some(true) {
        resp.get("response").cloned()
    } else {
        None
    }
}

#[cfg(windows)]
mod win_pipe {
    use core::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const PIPE_BUF_BYTES: u32 = 65_536;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            lp_name: *const u16,
            dw_open_mode: u32,
            dw_pipe_mode: u32,
            n_max_instances: u32,
            n_out_buffer_size: u32,
            n_in_buffer_size: u32,
            n_default_time_out: u32,
            lp_security_attributes: *mut c_void,
        ) -> RawHandle;

        fn ConnectNamedPipe(h_named_pipe: RawHandle, lp_overlapped: *mut c_void) -> i32;
        fn WaitNamedPipeW(lp_named_pipe_name: *const u16, n_time_out: u32) -> i32;
        fn GetLastError() -> u32;
    }

    pub(super) fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub(super) fn create_pipe_instance(wide_name: &[u16], first_instance: bool) -> io::Result<File> {
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first_instance {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let raw = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF_BYTES,
                PIPE_BUF_BYTES,
                0,
                core::ptr::null_mut(),
            )
        };
        if raw.is_null() || (raw as isize) == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(raw) })
    }

    pub(super) fn accept_loop(
        wide_name: Vec<u16>,
        mut cur_pipe: File,
        stop: Arc<AtomicBool>,
        global_ldb_default: Option<PathBuf>,
        state: Arc<parking_lot::Mutex<crate::mcp::McpServerState>>,
        served_count: Arc<AtomicU64>,
    ) {
        while !stop.load(Ordering::Acquire) {
            let ok = unsafe { ConnectNamedPipe(cur_pipe.as_raw_handle(), core::ptr::null_mut()) };
            if ok == 0 {
                let err = unsafe { GetLastError() } as i32;
                if err != ERROR_PIPE_CONNECTED {
                    drop(cur_pipe);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match create_pipe_instance(&wide_name, false) {
                        Ok(next) => {
                            cur_pipe = next;
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            }

            if stop.load(Ordering::Acquire) {
                drop(cur_pipe);
                break;
            }

            let next_opt = create_pipe_instance(&wide_name, false).ok();
            let g = global_ldb_default.clone();
            let s = Arc::clone(&state);
            let c = Arc::clone(&served_count);
            let connected_pipe = cur_pipe;
            std::thread::spawn(move || {
                super::serve_connected_stream(&connected_pipe, &connected_pipe, &g, &s, &c);
                drop(connected_pipe);
            });

            match next_opt {
                Some(next) => cur_pipe = next,
                None => break,
            }
        }
    }

    pub(super) fn connect_client(pipe_name: &str, max_wait: Duration) -> Option<File> {
        let wide = to_wide_null(pipe_name);
        let deadline = Instant::now() + max_wait;
        loop {
            match OpenOptions::new().read(true).write(true).open(pipe_name) {
                Ok(f) => return Some(f),
                Err(e) => {
                    let code = e.raw_os_error().unwrap_or(0);
                    if e.kind() == io::ErrorKind::NotFound || code == ERROR_FILE_NOT_FOUND {
                        return None;
                    }
                    if code != ERROR_PIPE_BUSY || Instant::now() >= deadline {
                        return None;
                    }
                    let rem_ms = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .clamp(1, 50) as u32;
                    let waited = unsafe { WaitNamedPipeW(wide.as_ptr(), rem_ms) };
                    if waited == 0 {
                        let wait_err = unsafe { GetLastError() } as i32;
                        if wait_err == ERROR_FILE_NOT_FOUND || Instant::now() >= deadline {
                            return None;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }
}

/// Background IPC listener hosted inside `libredb mcp-serve` serving `hook-pre-tool` and
/// `hook-pre-invocation` directly from the in-RAM `McpServerState`.
pub struct McpIpcServer {
    #[cfg(windows)]
    endpoint: String,
    #[cfg(unix)]
    endpoint: PathBuf,
    #[cfg(unix)]
    _lock_guard: libredb_core::OsFileBackend,
    stop: Arc<AtomicBool>,
    served_count: Arc<AtomicU64>,
    listener: Option<JoinHandle<()>>,
}

impl McpIpcServer {
    /// Starts the local IPC endpoint bound to `global_ldb_opt`.
    /// Returns `None` without error if another active `libredb mcp-serve` instance already owns
    /// the endpoint (for example, when multiple Antigravity windows run concurrently).
    pub fn start(
        global_ldb_opt: Option<&Path>,
        state: Arc<Mutex<McpServerState>>,
    ) -> Option<Self> {
        let global_ldb_default = global_ldb_opt.map(Path::to_path_buf);
        let stop = Arc::new(AtomicBool::new(false));
        let served_count = Arc::new(AtomicU64::new(0));

        #[cfg(windows)]
        {
            let endpoint = endpoint_address(global_ldb_opt);
            let wide = win_pipe::to_wide_null(&endpoint);
            let first_pipe = win_pipe::create_pipe_instance(&wide, true).ok()?;
            let stop_bg = Arc::clone(&stop);
            let served_bg = Arc::clone(&served_count);
            let listener = std::thread::spawn(move || {
                win_pipe::accept_loop(
                    wide,
                    first_pipe,
                    stop_bg,
                    global_ldb_default,
                    state,
                    served_bg,
                );
            });
            Some(Self {
                endpoint,
                stop,
                served_count,
                listener: Some(listener),
            })
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use std::os::unix::net::UnixListener;

            let endpoint = endpoint_address(global_ldb_opt);
            if let Some(parent) = endpoint.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            let lock_path = endpoint.with_extension("lock");
            let lock_guard = libredb_core::OsFileBackend::open(&lock_path).ok()?;
            if lock_guard.try_lock_write_region().ok() != Some(true) {
                return None;
            }
            let _ = std::fs::remove_file(&endpoint);
            let listener_sock = UnixListener::bind(&endpoint).ok()?;
            let _ = std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600));

            let stop_bg = Arc::clone(&stop);
            let served_bg = Arc::clone(&served_count);
            let listener = std::thread::spawn(move || {
                for incoming in listener_sock.incoming() {
                    if stop_bg.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = incoming else {
                        break;
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(2_000)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(2_000)));
                    let g = global_ldb_default.clone();
                    let s = Arc::clone(&state);
                    let c = Arc::clone(&served_bg);
                    std::thread::spawn(move || {
                        serve_connected_stream(&stream, &stream, &g, &s, &c);
                    });
                }
            });
            Some(Self {
                endpoint,
                _lock_guard: lock_guard,
                stop,
                served_count,
                listener: Some(listener),
            })
        }
    }

    /// Returns the number of hook requests served in-RAM by this IPC coordinator.
    #[allow(dead_code)]
    pub fn served_count(&self) -> u64 {
        self.served_count.load(Ordering::Acquire)
    }
}

impl Drop for McpIpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(windows)]
        {
            let _ = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.endpoint);
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::net::UnixStream::connect(&self.endpoint);
        }
        if let Some(jh) = self.listener.take() {
            let _ = jh.join();
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.endpoint);
            let _ = self._lock_guard.unlock_exclusive();
        }
    }
}

/// Attempts to evaluate a lifecycle hook via an active `libredb mcp-serve` in-memory coordinator.
/// Returns `None` within microseconds if no coordinator is running or busy so the hook falls
/// back seamlessly to direct in-process `.ldb` evaluation.
pub fn try_invoke_ipc_hook(op: &str, global_ldb_opt: Option<&Path>, payload: &Value) -> Option<Value> {
    let req = json!({
        "op": op,
        "global_ldb": global_ldb_opt.map(|p| p.to_string_lossy().into_owned()),
        "payload": payload,
    });
    let mut req_line = serde_json::to_string(&req).ok()?;
    req_line.push('\n');
    if req_line.len() > MAX_MCP_LINE_BYTES {
        return None;
    }

    #[cfg(windows)]
    {
        let endpoint = endpoint_address(global_ldb_opt);
        let pipe = win_pipe::connect_client(&endpoint, Duration::from_millis(150))?;
        exchange_client_line(&pipe, &pipe, &req_line)
    }

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let endpoint = endpoint_address(global_ldb_opt);
        let stream = UnixStream::connect(&endpoint).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(2_000)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(2_000)));
        exchange_client_line(&stream, &stream, &req_line)
    }
}
