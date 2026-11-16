//! Cross-platform local in-memory IPC coordinator bridging short-lived lifecycle hooks
//! (`hook-pre-tool`, `hook-pre-invocation`) directly into the running `libredb mcp-serve` process.
//!
//! - Windows: local Named Pipe (`\\.\pipe\libredb-ipc-v1-<24hex>`) with `PIPE_REJECT_REMOTE_CLIENTS`,
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, protected owner/SYSTEM/Administrators SDDL DACL, and client
//!   pipe-owner SID verification (no drivers, no admin elevation, and no SMB/network I/O).
//! - Unix (Linux/macOS): `0600` Unix Domain Socket inside a verified `0700` user-owned directory
//!   guarded by an advisory file lock.

use crate::hooks::{
    default_global_ldb_path, evaluate_pre_invocation_payload_with_ram_state,
    evaluate_pre_tool_payload_with_ram_state,
};
use crate::mcp::{read_bounded_jsonrpc_line, BoundedLineRead, McpServerState, MAX_MCP_LINE_BYTES};
use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

const LOCK_TRY_TIMEOUT_MS: u64 = 400;
const MAX_CONCURRENT_IPC_WORKERS: usize = 16;

struct WorkerSlotGuard(Arc<AtomicUsize>);

impl Drop for WorkerSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_worker_slot(counter: &Arc<AtomicUsize>) -> Option<WorkerSlotGuard> {
    loop {
        let cur = counter.load(Ordering::Acquire);
        if cur >= MAX_CONCURRENT_IPC_WORKERS {
            return None;
        }
        if counter
            .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(WorkerSlotGuard(Arc::clone(counter)));
        }
    }
}

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
fn current_euid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(unix)]
fn endpoint_address(global_ldb_opt: Option<&Path>) -> PathBuf {
    let id = control_plane_endpoint_id(global_ldb_opt);
    let abs = effective_global_ldb_path(global_ldb_opt);
    if let Some(parent) = abs.parent().filter(|p| !p.as_os_str().is_empty()) {
        let cand = parent.join(".ipc").join(format!("ipc_{id}.sock"));
        if cand.as_os_str().len() <= 96 {
            return cand;
        }
    }
    std::env::temp_dir()
        .join(format!("libredb-ipc-{}", current_euid()))
        .join(format!("ipc_{id}.sock"))
}

#[cfg(unix)]
fn verify_or_create_private_ipc_dir(dir: &Path, create: bool) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if create && fs::symlink_metadata(dir).is_err() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPC directory is not a regular directory",
        ));
    }
    if meta.uid() != current_euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPC directory is not owned by the current user",
        ));
    }
    if (meta.mode() & 0o077) != 0 {
        if !create {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "IPC directory permissions are too permissive",
            ));
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let recheck = fs::symlink_metadata(dir)?;
        if !recheck.is_dir()
            || recheck.file_type().is_symlink()
            || recheck.uid() != current_euid()
            || (recheck.mode() & 0o077) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Failed to enforce 0700 permissions on IPC directory",
            ));
        }
    }
    Ok(())
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
    if let Some(ref p) = req_gdb {
        let expected = crate::security::normalize_workspace_key(&effective_global_ldb_path(
            global_ldb_default.as_deref(),
        ));
        let requested =
            crate::security::normalize_workspace_key(&effective_global_ldb_path(Some(p)));
        if requested != expected {
            return json!({ "ok": false, "fallback": true });
        }
    }
    let eff_gdb = global_ldb_default.as_deref();

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
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_INFO_CLASS: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const SE_KERNEL_OBJECT: u32 = 6;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_ANONYMOUS: u32 = 0x0000_0000;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

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
        fn GetCurrentProcess() -> RawHandle;
        fn CloseHandle(h_object: RawHandle) -> i32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: RawHandle,
            desired_access: u32,
            token_handle: *mut RawHandle,
        ) -> i32;

        fn GetTokenInformation(
            token_handle: RawHandle,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;

        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;

        fn GetSecurityInfo(
            handle: RawHandle,
            object_type: u32,
            security_info: u32,
            ppsid_owner: *mut *mut c_void,
            ppsid_group: *mut *mut c_void,
            pp_dacl: *mut *mut c_void,
            pp_sacl: *mut *mut c_void,
            pp_security_descriptor: *mut *mut c_void,
        ) -> u32;
    }

    struct WinHandle(RawHandle);

    impl Drop for WinHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && (self.0 as isize) != -1 {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalMem(*mut c_void);

    impl Drop for LocalMem {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    pub(super) fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn sid_ptr_to_string(sid: *const c_void) -> io::Result<String> {
        if sid.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
        }
        let mut wide_sid: *mut u16 = core::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut wide_sid) };
        if ok == 0 || wide_sid.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _mem = LocalMem(wide_sid as *mut c_void);
        let mut len = 0usize;
        while len < 256 && unsafe { *wide_sid.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { core::slice::from_raw_parts(wide_sid, len) };
        Ok(String::from_utf16_lossy(slice))
    }

    fn current_user_sid_string() -> io::Result<String> {
        let mut tok: RawHandle = core::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let _tok_guard = WinHandle(tok);

        let mut needed: u32 = 0;
        unsafe {
            GetTokenInformation(
                tok,
                TOKEN_USER_INFO_CLASS,
                core::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed < core::mem::size_of::<*const c_void>() as u32 {
            return Err(io::Error::last_os_error());
        }
        // 8-byte aligned storage matching `TOKEN_USER` ABI on both 32-bit and 64-bit Windows.
        let word_count = (needed as usize).div_ceil(core::mem::size_of::<u64>());
        let mut aligned_buf = vec![0u64; word_count];
        let buf_bytes = (aligned_buf.len() * core::mem::size_of::<u64>()) as u32;
        let ok2 = unsafe {
            GetTokenInformation(
                tok,
                TOKEN_USER_INFO_CLASS,
                aligned_buf.as_mut_ptr() as *mut c_void,
                buf_bytes,
                &mut needed,
            )
        };
        if ok2 == 0 {
            return Err(io::Error::last_os_error());
        }
        let user_sid_ptr = unsafe { *(aligned_buf.as_ptr() as *const *const c_void) };
        sid_ptr_to_string(user_sid_ptr)
    }

    fn build_owner_only_sd() -> io::Result<LocalMem> {
        let user_sid = current_user_sid_string()?;
        // Protected DACL granting full pipe access only to current user, LocalSystem, and Administrators.
        let sddl = format!("D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)(A;;GA;;;BA)");
        let wide_sddl = to_wide_null(&sddl);
        let mut sd_ptr: *mut c_void = core::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 || sd_ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalMem(sd_ptr))
    }

    fn verify_pipe_owner(pipe_file: &File, expected_user_sid: &str) -> bool {
        let mut owner_sid: *mut c_void = core::ptr::null_mut();
        let mut sd_ptr: *mut c_void = core::ptr::null_mut();
        let rc = unsafe {
            GetSecurityInfo(
                pipe_file.as_raw_handle(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner_sid,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sd_ptr,
            )
        };
        if rc != 0 || sd_ptr.is_null() {
            if !sd_ptr.is_null() {
                drop(LocalMem(sd_ptr));
            }
            return false;
        }
        let _sd_guard = LocalMem(sd_ptr);
        let Ok(owner) = sid_ptr_to_string(owner_sid) else {
            return false;
        };
        owner == expected_user_sid || owner == "S-1-5-32-544" || owner == "S-1-5-18"
    }

    pub(super) fn create_pipe_instance(wide_name: &[u16], first_instance: bool) -> io::Result<File> {
        let sd = build_owner_only_sd()?;
        let mut sa = SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd.0,
            b_inherit_handle: 0,
        };
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
                &mut sa as *mut SecurityAttributes as *mut c_void,
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
        active_workers: Arc<AtomicUsize>,
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
            let connected_pipe = cur_pipe;
            if let Some(slot) = super::try_acquire_worker_slot(&active_workers) {
                let g = global_ldb_default.clone();
                let s = Arc::clone(&state);
                let c = Arc::clone(&served_count);
                std::thread::spawn(move || {
                    let _slot = slot;
                    super::serve_connected_stream(&connected_pipe, &connected_pipe, &g, &s, &c);
                    drop(connected_pipe);
                });
            } else {
                drop(connected_pipe);
            }

            match next_opt {
                Some(next) => cur_pipe = next,
                None => break,
            }
        }
    }

    pub(super) fn connect_client(pipe_name: &str, max_wait: Duration) -> Option<File> {
        let expected_sid = current_user_sid_string().ok()?;
        let wide = to_wide_null(pipe_name);
        let deadline = Instant::now() + max_wait;
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS)
                .open(pipe_name)
            {
                Ok(f) => {
                    if verify_pipe_owner(&f, &expected_sid) {
                        return Some(f);
                    }
                    return None;
                }
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
        let active_workers = Arc::new(AtomicUsize::new(0));

        #[cfg(windows)]
        {
            let endpoint = endpoint_address(global_ldb_opt);
            let wide = win_pipe::to_wide_null(&endpoint);
            let first_pipe = win_pipe::create_pipe_instance(&wide, true).ok()?;
            let stop_bg = Arc::clone(&stop);
            let served_bg = Arc::clone(&served_count);
            let workers_bg = Arc::clone(&active_workers);
            let listener = std::thread::spawn(move || {
                win_pipe::accept_loop(
                    wide,
                    first_pipe,
                    stop_bg,
                    global_ldb_default,
                    state,
                    served_bg,
                    workers_bg,
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
            let parent = endpoint
                .parent()
                .filter(|p| !p.as_os_str().is_empty())?;
            verify_or_create_private_ipc_dir(parent, true).ok()?;

            let lock_path = endpoint.with_extension("lock");
            if fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
                return None;
            }
            let lock_guard = libredb_core::OsFileBackend::open(&lock_path).ok()?;
            if lock_guard.try_lock_write_region().ok() != Some(true) {
                return None;
            }
            let _ = std::fs::remove_file(&endpoint);
            let listener_sock = UnixListener::bind(&endpoint).ok()?;
            let _ = std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600));

            let stop_bg = Arc::clone(&stop);
            let served_bg = Arc::clone(&served_count);
            let workers_bg = Arc::clone(&active_workers);
            let listener = std::thread::spawn(move || {
                for incoming in listener_sock.incoming() {
                    if stop_bg.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = incoming else {
                        break;
                    };
                    let Some(slot) = try_acquire_worker_slot(&workers_bg) else {
                        drop(stream);
                        continue;
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(2_000)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(2_000)));
                    let g = global_ldb_default.clone();
                    let s = Arc::clone(&state);
                    let c = Arc::clone(&served_bg);
                    std::thread::spawn(move || {
                        let _slot = slot;
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
        let parent = endpoint.parent()?;
        verify_or_create_private_ipc_dir(parent, false).ok()?;
        let stream = UnixStream::connect(&endpoint).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(2_000)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(2_000)));
        exchange_client_line(&stream, &stream, &req_line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libredb_core::LibreDb;

    #[test]
    fn ipc_server_serves_pinned_hook_and_rejects_mismatched_global_db_path() {
        let base_target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("test_ipc_hardening_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base_target);
        let ws = base_target.join("ws");
        std::fs::create_dir_all(ws.join(".agents")).unwrap();
        let gdb_path = base_target.join("customizations.ldb");
        let pdb_path = ws.join(".agents").join("memory.ldb");
        {
            let gdb = LibreDb::open(&gdb_path).unwrap();
            let pdb = LibreDb::open(&pdb_path).unwrap();
            crate::security::seal_workspace_memory(&gdb, &pdb, &ws).unwrap();
        }

        let state = Arc::new(Mutex::new(
            McpServerState::new(Some(&pdb_path), Some(&gdb_path)).unwrap(),
        ));
        let srv = McpIpcServer::start(Some(&gdb_path), Arc::clone(&state))
            .expect("IPC server must bind with protected ACL/directory");

        let payload = json!({
            "conversationId": "ipc-test-cid",
            "cwd": ws.to_string_lossy(),
            "prompt": "inspect status"
        });

        let ok_resp = try_invoke_ipc_hook("pre_invocation", Some(&gdb_path), &payload)
            .expect("IPC client should communicate over owner-verified endpoint");
        assert!(ok_resp.get("injectSteps").is_some());
        assert_eq!(srv.served_count(), 1);

        // Passing a foreign global_ldb path on the wire must fail closed without invoking hooks.
        let spoofed_gdb = base_target.join("evil_customizations.ldb");
        let rejected = handle_ipc_line(
            &serde_json::to_string(&json!({
                "op": "pre_invocation",
                "global_ldb": spoofed_gdb.to_string_lossy(),
                "payload": payload,
            }))
            .unwrap(),
            &Some(gdb_path),
            &state,
            &srv.served_count,
        );
        assert_eq!(rejected.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(rejected.get("fallback").and_then(Value::as_bool), Some(true));
        assert_eq!(srv.served_count(), 1);

        drop(srv);
        drop(state);
        let _ = std::fs::remove_dir_all(&base_target);
    }
}
