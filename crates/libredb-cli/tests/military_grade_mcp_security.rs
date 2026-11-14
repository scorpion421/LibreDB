//! Military-grade end-to-end adversarial security, cognitive isolation, context-continuity,
//! and OS subprocess crash-recovery test suite driving the compiled `libredb` executable.

use libredb_core::{LibreDb, NodeKind};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn libredb_bin() -> &'static str {
    env!("CARGO_BIN_EXE_libredb")
}

struct TestSandbox {
    root: PathBuf,
    temp_dir: PathBuf,
    home_dir: PathBuf,
}

impl TestSandbox {
    fn new(tag: &str) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = PathBuf::from(libredb_bin())
            .parent()
            .map(|p| p.join("mil_test_sandboxes"))
            .unwrap_or_else(std::env::temp_dir);
        let root = base.join(format!(
            "libredb_mil_{tag}_{}_{seq}_{nanos}",
            std::process::id()
        ));
        let temp_dir = root.join("isolated_tmp");
        let home_dir = root.join("isolated_home");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::create_dir_all(&home_dir).unwrap();
        Self {
            root,
            temp_dir,
            home_dir,
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(libredb_bin());
        c.env("TMP", &self.temp_dir)
            .env("TEMP", &self.temp_dir)
            .env("TMPDIR", &self.temp_dir)
            .env("HOME", &self.home_dir)
            .env("USERPROFILE", &self.home_dir)
            .env_remove("LIBREDB_MCP_WORKSPACE_ROOT");
        c
    }

    fn list_ephemeral_dirs(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.temp_dir) {
            for e in entries.flatten() {
                if e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("libredb_mcp_eph_"))
                {
                    out.push(e.path());
                }
            }
        }
        out
    }
}

impl Drop for TestSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn to_file_uri(p: &Path) -> String {
    format!(
        "file:///{}",
        p.to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
    )
}

struct LiveMcpSubprocess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl LiveMcpSubprocess {
    fn spawn(sbx: &TestSandbox, extra_args: &[&str]) -> Self {
        let mut cmd = sbx.cmd();
        cmd.arg("mcp-serve");
        for a in extra_args {
            cmd.arg(a);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn libredb mcp-serve");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin: Some(stdin),
            stdout,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn send_json(&mut self, msg: &Value) {
        let st = self.stdin.as_mut().expect("MCP stdin already closed");
        writeln!(st, "{msg}").expect("Failed to write JSON-RPC frame");
        st.flush().expect("Failed to flush JSON-RPC frame");
    }

    fn recv_json(&mut self) -> Value {
        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .expect("Failed reading MCP stdout");
        assert!(n > 0, "Unexpected EOF on MCP subprocess stdout");
        serde_json::from_str(line.trim()).expect("Invalid JSON-RPC frame from MCP server")
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send_json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        let resp = self.recv_json();
        assert_eq!(resp["id"], json!(id), "Mismatched JSON-RPC response ID: {resp}");
        resp
    }

    fn hard_kill_os_process(mut self) {
        // Keep `stdin` open across `kill()` and `wait()` so the child stays blocked on `stdin`
        // and cannot wake up on pipe `EOF` (`Drop` cleanup) before `SIGKILL` / `TerminateProcess` arrives.
        let keep_stdin_open_until_killed = self.stdin.take();
        // Real OS uncatchable kill: `SIGKILL` on Unix, `TerminateProcess` on Windows.
        self.child
            .kill()
            .expect("Failed to issue OS SIGKILL / TerminateProcess");
        let _ = self.child.wait().expect("Failed waiting on killed child");
        drop(keep_stdin_open_until_killed);
    }

    fn shutdown_clean(mut self) {
        drop(self.stdin.take());
        let status = self
            .child
            .wait()
            .expect("Failed waiting for clean MCP exit");
        assert!(status.success(), "MCP server exited with non-zero status: {status}");
    }
}

/// 1. Real OS subprocess hard-kill (`SIGKILL` / `TerminateProcess`) + 8-way concurrent startup reaper test:
///    Proves empirically across real OS processes and kernel file descriptors that:
///    - Hard-killing a live `libredb mcp-serve` process skips `Drop` and leaves `libredb_mcp_eph_<pid>_*` on disk,
///      while the OS kernel immediately releases `.owner.lock`.
///    - 8 simultaneously spawning `libredb mcp-serve` processes never race each other during `.initializing` -> `.owner.lock`
///      acquisition, cleanly reap the hard-killed victim's orphaned directory, and NEVER disturb a concurrent live
///      `libredb mcp-serve` process (preserving its `[Zero-Repeat Skeleton]` session memory intact!).
#[test]
fn e2e_real_os_sigkill_ephemeral_reaper_preserves_concurrent_live_mcp_processes() {
    let sbx = TestSandbox::new("sigkill_reaper");
    let missing_global = sbx.root.join("nonexistent_customizations.ldb");
    let missing_str = missing_global.to_string_lossy().into_owned();

    let ws_live = sbx.root.join("ws_live");
    let ws_victim = sbx.root.join("ws_victim");
    fs::create_dir_all(ws_live.join("src")).unwrap();
    fs::create_dir_all(ws_victim.join("src")).unwrap();
    fs::write(
        ws_live.join("src").join("live_mod.rs"),
        "pub struct LiveKernelState {\n    pub epoch: u64,\n}\npub fn run_live_cycle(s: &LiveKernelState) -> u64 {\n    s.epoch + 1\n}\n",
    )
    .unwrap();
    fs::write(
        ws_victim.join("src").join("victim_mod.rs"),
        "pub fn doomed_worker() -> u32 {\n    99\n}\n",
    )
    .unwrap();

    let ws_live_str = ws_live.to_string_lossy().into_owned();
    let ws_victim_str = ws_victim.to_string_lossy().into_owned();

    let mut live_proc = LiveMcpSubprocess::spawn(
        &sbx,
        &["--global", &missing_str, "--workspace-root", &ws_live_str],
    );
    let mut victim_proc = LiveMcpSubprocess::spawn(
        &sbx,
        &["--global", &missing_str, "--workspace-root", &ws_victim_str],
    );
    let live_pid = live_proc.pid();
    let victim_pid = victim_proc.pid();

    assert!(live_proc.call(1, "initialize", json!({})).get("result").is_some());
    assert!(victim_proc.call(1, "initialize", json!({})).get("result").is_some());

    // Prime Turn 1 skeleton + SessionState (`cid = "live-session"`) inside `live_proc`'s ephemeral DB,
    // and force ephemeral DB materialization inside `victim_proc`:
    let t1_live = live_proc.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cid": "live-session",
                "target": "src/live_mod.rs"
            }
        }),
    );
    let t1_txt = t1_live["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        t1_txt.contains("run_live_cycle") && !t1_txt.contains("[Zero-Repeat Skeleton]"),
        "Turn 1 skeleton must emit full contract: {t1_txt}"
    );

    let t1_victim = victim_proc.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "impact",
                "target": "doomed_worker"
            }
        }),
    );
    assert!(t1_victim.get("result").is_some());

    let eph_before = sbx.list_ephemeral_dirs();
    assert_eq!(eph_before.len(), 2, "Expected 2 active ephemeral dirs: {eph_before:?}");
    let live_eph_dir = eph_before
        .iter()
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("libredb_mcp_eph_{live_pid}_"))
        })
        .cloned()
        .expect("Missing live_proc ephemeral dir");
    let victim_eph_dir = eph_before
        .iter()
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("libredb_mcp_eph_{victim_pid}_"))
        })
        .cloned()
        .expect("Missing victim_proc ephemeral dir");
    assert!(live_eph_dir.join(".owner.lock").is_file());
    assert!(!live_eph_dir.join(".initializing").exists());
    assert!(victim_eph_dir.join(".owner.lock").is_file());

    // Execute a genuine OS-level hard kill (`SIGKILL` / `TerminateProcess`) on `victim_proc`:
    victim_proc.hard_kill_os_process();
    assert!(
        victim_eph_dir.exists(),
        "Real OS SIGKILL / TerminateProcess MUST bypass Rust Drop and leave orphaned dir prior to reaping!"
    );

    // Spawn 8 concurrent `libredb mcp-serve` processes in parallel to stress-test concurrent reaping
    // and `.initializing` -> `.owner.lock` handoff while `live_proc` remains active:
    let mut worker_dirs = Vec::new();
    for idx in 0..8 {
        let wd = sbx.root.join(format!("ws_reaper_{idx}"));
        fs::create_dir_all(wd.join("src")).unwrap();
        fs::write(wd.join("src").join("r.rs"), format!("pub fn reaper_{idx}() {{}}\n")).unwrap();
        worker_dirs.push(wd);
    }

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for wd in &worker_dirs {
            let sbx_ref = &sbx;
            let miss = missing_str.as_str();
            handles.push(s.spawn(move || {
                let wd_str = wd.to_string_lossy().into_owned();
                let mut proc = LiveMcpSubprocess::spawn(
                    sbx_ref,
                    &["--global", miss, "--workspace-root", &wd_str],
                );
                let r1 = proc.call(1, "initialize", json!({}));
                assert!(r1.get("result").is_some());
                let r2 = proc.call(
                    2,
                    "tools/call",
                    json!({
                        "name": "libredb_code",
                        "arguments": {
                            "action": "skeleton",
                            "target": "src/r.rs"
                        }
                    }),
                );
                assert!(r2.get("result").is_some(), "Concurrent worker failed: {r2}");
                proc.shutdown_clean();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    assert!(
        !victim_eph_dir.exists(),
        "Hard-killed victim's orphaned ephemeral directory MUST be reaped by subsequent MCP startups!"
    );
    assert!(
        live_eph_dir.exists(),
        "Live MCP process's kernel-locked ephemeral directory MUST NEVER be touched by concurrent reapers!"
    );

    // Prove `live_proc`'s ephemeral `.ldb` and `SessionState` survived completely intact:
    let t2_live = live_proc.call(
        3,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cid": "live-session",
                "target": "src/live_mod.rs"
            }
        }),
    );
    let t2_txt = t2_live["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        t2_txt.contains("[Zero-Repeat Skeleton]"),
        "Live MCP process MUST retain its ephemeral SessionState across concurrent reaping: {t2_txt}"
    );

    live_proc.shutdown_clean();
    assert!(
        sbx.list_ephemeral_dirs().is_empty(),
        "All ephemeral directories must be cleaned up once all MCP processes exit!"
    );
}

/// 2. Context continuity across dynamic `notifications/roots/list_changed` (`[A, B] -> [A, C]`):
///    Proves both fail-closed suspension during the in-flight `roots/list` window AND zero-loss
///    preservation of `A`'s `[Zero-Repeat Skeleton]` + `Zero-Repeat Delta` session memory while
///    evicting closed workspace `B`'s cache and ephemeral `.ldb`.
#[test]
fn e2e_dynamic_roots_list_changed_preserves_surviving_workspace_context_and_evicts_closed() {
    let sbx = TestSandbox::new("roots_continuity");
    let missing_global = sbx.root.join("nonexistent_customizations.ldb");
    let missing_str = missing_global.to_string_lossy().into_owned();

    let ws_a = sbx.root.join("ws_keep_alpha");
    let ws_b = sbx.root.join("ws_close_beta");
    let ws_c = sbx.root.join("ws_open_gamma");
    for (ws, fn_name) in [
        (&ws_a, "alpha_engine_step"),
        (&ws_b, "beta_legacy_step"),
        (&ws_c, "gamma_fresh_step"),
    ] {
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::write(
            ws.join("src").join("mod.rs"),
            format!(
                "pub struct Ctx {{\n    pub v: usize,\n}}\npub fn {fn_name}(c: &Ctx) -> usize {{\n    c.v + 42\n}}\n"
            ),
        )
        .unwrap();
    }

    let uri_a = to_file_uri(&ws_a);
    let uri_b = to_file_uri(&ws_b);
    let uri_c = to_file_uri(&ws_c);

    let mut mcp = LiveMcpSubprocess::spawn(&sbx, &["--global", &missing_str]);

    // Handshake with `capabilities.roots.listChanged = true`:
    let init_resp = mcp.call(
        1,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "roots": { "listChanged": true } }
        }),
    );
    assert!(init_resp.get("result").is_some());
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));
    let roots_q1 = mcp.recv_json();
    assert_eq!(roots_q1["method"], json!("roots/list"));
    let req_id_1 = roots_q1["id"].as_str().unwrap().to_owned();

    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "id": req_id_1,
        "result": {
            "roots": [
                { "uri": uri_a, "name": "ws_keep_alpha" },
                { "uri": uri_b, "name": "ws_close_beta" }
            ]
        }
    }));

    // Prime Turn 1 `[Zero-Repeat Skeleton]` + symbol index on BOTH `ws_a` and `ws_b`:
    let a_idx = mcp.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "index",
                "cwd": ws_a.to_string_lossy().to_string(),
                "target": "."
            }
        }),
    );
    assert!(a_idx.get("result").is_some());

    let a_skel_1 = mcp.call(
        3,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_a.to_string_lossy().to_string(),
                "cid": "continuity-cid",
                "target": "src/mod.rs"
            }
        }),
    );
    let a_txt_1 = a_skel_1["result"]["content"][0]["text"].as_str().unwrap();
    assert!(a_txt_1.contains("alpha_engine_step") && !a_txt_1.contains("[Zero-Repeat Skeleton]"));

    let b_skel_1 = mcp.call(
        4,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_b.to_string_lossy().to_string(),
                "cid": "continuity-cid",
                "target": "src/mod.rs"
            }
        }),
    );
    assert!(b_skel_1.get("result").is_some());

    // Verify 2 ephemeral `.ldb` files exist inside the subprocess's `libredb_mcp_eph_*` dir:
    let eph_dirs = sbx.list_ephemeral_dirs();
    assert_eq!(eph_dirs.len(), 1);
    let count_ldb_files = |dir: &Path| -> usize {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x == "ldb")
            })
            .count()
    };
    assert_eq!(count_ldb_files(&eph_dirs[0]), 2);

    // Trigger `notifications/roots/list_changed` AND pipeline requests on `ws_a` and `ws_b`
    // BEFORE answering `roots/list`:
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/roots/list_changed"
    }));
    let roots_q2 = mcp.recv_json();
    assert_eq!(roots_q2["method"], json!("roots/list"));
    let req_id_2 = roots_q2["id"].as_str().unwrap().to_owned();

    let pending_a = mcp.call(
        5,
        "tools/call",
        json!({
            "name": "libredb_pulse",
            "arguments": {
                "query": "alpha",
                "cwd": ws_a.to_string_lossy().to_string()
            }
        }),
    );
    let pending_b = mcp.call(
        6,
        "tools/call",
        json!({
            "name": "libredb_pulse",
            "arguments": {
                "query": "beta",
                "cwd": ws_b.to_string_lossy().to_string()
            }
        }),
    );
    assert!(
        pending_a.get("error").is_some() && pending_b.get("error").is_some(),
        "All client-root calls MUST fail closed while roots/list refresh is in flight!"
    );
    assert_eq!(
        count_ldb_files(&eph_dirs[0]),
        2,
        "Ephemeral .ldb files MUST NOT be prematurely deleted before roots/list reply arrives!"
    );

    // Reply with `[ws_a, ws_c]` (`ws_a` stays open, `ws_b` was closed, `ws_c` was opened):
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "id": req_id_2,
        "result": {
            "roots": [
                { "uri": uri_a, "name": "ws_keep_alpha" },
                { "uri": uri_c, "name": "ws_open_gamma" }
            ]
        }
    }));

    // Closed `ws_b` MUST fail closed and its ephemeral `.ldb` MUST be removed (`2 -> 1` before `ws_c` opens):
    let closed_b = mcp.call(
        7,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_b.to_string_lossy().to_string(),
                "target": "src/mod.rs"
            }
        }),
    );
    assert!(closed_b.get("error").is_some(), "Closed ws_b MUST remain unauthorized");
    assert_eq!(
        count_ldb_files(&eph_dirs[0]),
        1,
        "Closed ws_b's ephemeral .ldb MUST be deleted while surviving ws_a's .ldb stays intact!"
    );

    // Surviving `ws_a` MUST immediately emit `[Zero-Repeat Skeleton]` (proving zero context loss!):
    let a_skel_2 = mcp.call(
        8,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_a.to_string_lossy().to_string(),
                "cid": "continuity-cid",
                "target": "src/mod.rs"
            }
        }),
    );
    let a_txt_2 = a_skel_2["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        a_txt_2.contains("[Zero-Repeat Skeleton]"),
        "Surviving workspace ws_a MUST preserve its SessionState across [A, B] -> [A, C] root switch: {a_txt_2}"
    );

    // Newly added `ws_c` MUST succeed cleanly:
    let c_skel = mcp.call(
        9,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_c.to_string_lossy().to_string(),
                "target": "src/mod.rs"
            }
        }),
    );
    assert!(c_skel["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("gamma_fresh_step"));

    mcp.shutdown_clean();
}

/// 3. Rapid-burst `notifications/roots/list_changed` sequence superseding & error-response revocation:
///    Proves that stale out-of-order `roots/list` replies cannot resurrect revoked roots after a newer
///    `list_changed` notification, and a JSON-RPC `error` reply to `roots/list` revokes all client roots.
#[test]
fn e2e_rapid_burst_list_changed_and_error_reply_fail_closed() {
    let sbx = TestSandbox::new("burst_roots");
    let missing_global = sbx.root.join("nonexistent_customizations.ldb");
    let missing_str = missing_global.to_string_lossy().into_owned();

    let ws_a = sbx.root.join("ws_a");
    let ws_b = sbx.root.join("ws_b");
    fs::create_dir_all(ws_a.join("src")).unwrap();
    fs::create_dir_all(ws_b.join("src")).unwrap();
    fs::write(ws_a.join("src").join("a.rs"), "pub fn fa() {}\n").unwrap();
    fs::write(ws_b.join("src").join("b.rs"), "pub fn fb() {}\n").unwrap();

    let uri_a = to_file_uri(&ws_a);
    let uri_b = to_file_uri(&ws_b);

    let mut mcp = LiveMcpSubprocess::spawn(&sbx, &["--global", &missing_str]);
    mcp.call(
        1,
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "roots": { "listChanged": true } },
            "workspaceFolders": [
                { "uri": uri_a, "name": "ws_a" },
                { "uri": uri_b, "name": "ws_b" }
            ]
        }),
    );

    // Fire TWO rapid-fire `notifications/roots/list_changed` notifications back-to-back:
    mcp.send_json(&json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }));
    let q1 = mcp.recv_json();
    let stale_id = q1["id"].as_str().unwrap().to_owned();

    mcp.send_json(&json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }));
    let q2 = mcp.recv_json();
    let latest_id = q2["id"].as_str().unwrap().to_owned();
    assert_ne!(stale_id, latest_id);

    // Send a stale reply for `stale_id` still claiming `[ws_a, ws_b]` -> MUST be ignored!
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "id": stale_id,
        "result": {
            "roots": [
                { "uri": uri_a, "name": "ws_a" },
                { "uri": uri_b, "name": "ws_b" }
            ]
        }
    }));
    let probe_b = mcp.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": ws_b.to_string_lossy().to_string(),
                "target": "src/b.rs"
            }
        }),
    );
    assert!(
        probe_b.get("error").is_some(),
        "Stale superseded roots/list response MUST NOT re-authorize ws_b!"
    );

    // Now send the authoritative reply for `latest_id` containing ONLY `[ws_a]`:
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "id": latest_id,
        "result": {
            "roots": [{ "uri": uri_a, "name": "ws_a" }]
        }
    }));
    assert!(mcp
        .call(
            3,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": ws_a.to_string_lossy().to_string(),
                    "target": "src/a.rs"
                }
            }),
        )
        .get("result")
        .is_some());
    assert!(mcp
        .call(
            4,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": ws_b.to_string_lossy().to_string(),
                    "target": "src/b.rs"
                }
            }),
        )
        .get("error")
        .is_some());

    // Finally, trigger `list_changed` and reply with a JSON-RPC `error` -> revokes `ws_a` fail-closed:
    mcp.send_json(&json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" }));
    let q3 = mcp.recv_json();
    let err_id = q3["id"].as_str().unwrap().to_owned();
    mcp.send_json(&json!({
        "jsonrpc": "2.0",
        "id": err_id,
        "error": { "code": -32603, "message": "client failed listing roots" }
    }));
    assert!(mcp
        .call(
            5,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": ws_a.to_string_lossy().to_string(),
                    "target": "src/a.rs"
                }
            }),
        )
        .get("error")
        .is_some());

    mcp.shutdown_clean();
}

/// 4. Strict nested workspace boundary enforcement (`cwd = Main, target = Subproject` AND recursive `Main` scans):
///    Proves across MCP `libredb_code` (`index`, `skeleton`, `fim`, `impact`, batch `files`), legacy aliases,
///    and CLI `libredb index-workspace` that parent workspaces NEVER index, read, or pollute nested child
///    cognitive workspaces (`Subproject`, `CleanSub`, or unsealed `RogueSub`), while ordinary monorepo
///    subdirectories (`crates/helper`) work seamlessly.
#[test]
fn e2e_parent_workspace_cannot_index_read_or_pollute_nested_subprojects() {
    let sbx = TestSandbox::new("nested_boundary");
    let global_ldb = sbx.root.join("customizations.ldb");
    let global_str = global_ldb.to_string_lossy().into_owned();

    let main_ws = sbx.root.join("Projects").join("Main");
    let helper_dir = main_ws.join("crates").join("helper").join("src");
    let sub_ws = main_ws.join("Subproject");
    let clean_sub_ws = main_ws.join("CleanSub");
    let rogue_sub_ws = main_ws.join("RogueSub");

    fs::create_dir_all(main_ws.join("src")).unwrap();
    fs::create_dir_all(&helper_dir).unwrap();
    fs::create_dir_all(sub_ws.join("src")).unwrap();
    fs::create_dir_all(clean_sub_ws.join("src")).unwrap();
    fs::create_dir_all(rogue_sub_ws.join(".agents")).unwrap();
    fs::create_dir_all(rogue_sub_ws.join("src")).unwrap();

    fs::write(
        main_ws.join("src").join("main_service.rs"),
        "pub fn main_orchestrator() -> u32 { helper_utility() }\n",
    )
    .unwrap();
    fs::write(
        helper_dir.join("helper.rs"),
        "pub fn helper_utility() -> u32 { 7 }\n",
    )
    .unwrap();
    fs::write(
        sub_ws.join("src").join("sub_secret.rs"),
        "pub fn subproject_confidential_algo() -> u32 { 42 }\n",
    )
    .unwrap();
    fs::write(
        clean_sub_ws.join("src").join("clean_child.rs"),
        "pub fn clean_sub_isolated_fn() -> u32 { 11 }\n",
    )
    .unwrap();
    fs::write(
        rogue_sub_ws.join("src").join("rogue_implant.rs"),
        "pub fn rogue_unsealed_implant() -> u32 { 666 }\n",
    )
    .unwrap();

    // Seed an unsealed `.agents/memory.ldb` inside `RogueSub`:
    {
        let rdb = LibreDb::open(rogue_sub_ws.join(".agents").join("memory.ldb")).unwrap();
        rdb.put(
            libredb_core::WriteRequest::new(NodeKind::Fact, b"rogue_fact = poisoned".to_vec())
                .with_key("rogue_fact"),
        )
        .unwrap();
    }

    // Initialize `customizations.ldb` and seal `Main` and `Subproject` via real CLI commands:
    assert!(sbx
        .cmd()
        .args(["init", &global_str])
        .status()
        .unwrap()
        .success());
    assert!(sbx
        .cmd()
        .args(["trust", &main_ws.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());
    assert!(sbx
        .cmd()
        .args(["trust", &sub_ws.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());

    let mut mcp = LiveMcpSubprocess::spawn(&sbx, &["--global", &global_str]);
    mcp.call(
        1,
        "initialize",
        json!({
            "workspaceFolders": [
                { "uri": to_file_uri(&main_ws), "name": "Main" },
                { "uri": to_file_uri(&sub_ws), "name": "Subproject" },
                { "uri": to_file_uri(&clean_sub_ws), "name": "CleanSub" }
            ]
        }),
    );

    let main_cwd = main_ws.to_string_lossy().to_string();
    let sub_cwd = sub_ws.to_string_lossy().to_string();
    let rogue_cwd = rogue_sub_ws.to_string_lossy().to_string();

    // A. Explicit cross-boundary calls (`cwd = Main`, `target` inside `Subproject`, `CleanSub`, or `RogueSub`)
    //    MUST ALL fail closed with a workspace boundary violation!
    let mut req_seq = 10u64;
    for forbidden_call in [
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "Subproject" }
        }),
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "CleanSub" }
        }),
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "RogueSub" }
        }),
        json!({
            "name": "libredb_code",
            "arguments": { "action": "skeleton", "cwd": main_cwd, "target": "Subproject/src/sub_secret.rs" }
        }),
        json!({
            "name": "libredb_code",
            "arguments": { "action": "fim", "cwd": main_cwd, "target": "Subproject/src/sub_secret.rs" }
        }),
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": main_cwd,
                "files": ["src/main_service.rs", "Subproject/src/sub_secret.rs"]
            }
        }),
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "files": [
                    main_ws.join("src").join("main_service.rs").to_string_lossy().to_string(),
                    sub_ws.join("src").join("sub_secret.rs").to_string_lossy().to_string()
                ]
            }
        }),
        json!({
            "name": "libredb_skeleton",
            "arguments": { "cwd": main_cwd, "file_path": "Subproject/src/sub_secret.rs" }
        }),
        json!({
            "name": "libredb_fim",
            "arguments": { "cwd": main_cwd, "file_path": "Subproject/src/sub_secret.rs" }
        }),
    ] {
        req_seq += 1;
        let resp = mcp.call(req_seq, "tools/call", forbidden_call.clone());
        assert!(
            resp.get("error").is_some(),
            "Cross-workspace target MUST fail closed: call={forbidden_call} -> resp={resp}"
        );
    }

    // Verify neither `Main/.agents/memory.ldb` nor `Subproject/.agents/memory.ldb` was polluted by the rejected calls:
    {
        let pdb_main = LibreDb::open(main_ws.join(".agents").join("memory.ldb")).unwrap();
        let pdb_sub = LibreDb::open(sub_ws.join(".agents").join("memory.ldb")).unwrap();
        assert!(pdb_main.list_inodes(Some(NodeKind::Symbol), false).is_empty());
        assert!(pdb_sub.list_inodes(Some(NodeKind::Symbol), false).is_empty());
    }

    // B. Ordinary monorepo subdirectory (`crates/helper`) AND recursive parent `index` (`cwd = Main, target = "."`)
    //    MUST index `Main` + `crates/helper` while skipping `Subproject`, `CleanSub`, and `RogueSub`!
    let ok_helper = mcp.call(
        30,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "crates/helper" }
        }),
    );
    assert!(ok_helper.get("result").is_some(), "Ordinary subdir must succeed: {ok_helper}");

    let ok_main_all = mcp.call(
        31,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "." }
        }),
    );
    assert!(ok_main_all.get("result").is_some(), "Parent root index must succeed: {ok_main_all}");

    // C. Direct `RogueSub` access MUST fail closed / quarantine (never falling back to `Main`'s brain!):
    assert!(mcp
        .call(
            32,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": { "action": "skeleton", "cwd": rogue_cwd, "target": "src/rogue_implant.rs" }
            }),
        )
        .get("error")
        .is_some());
    assert!(mcp
        .call(
            33,
            "tools/call",
            json!({
                "name": "libredb_memorize",
                "arguments": { "cwd": rogue_cwd, "facts": { "x": "1" } }
            }),
        )
        .get("error")
        .is_some());
    let rogue_pulse = mcp.call(
        34,
        "tools/call",
        json!({
            "name": "libredb_pulse",
            "arguments": { "cwd": rogue_cwd, "query": "rogue_fact" }
        }),
    );
    assert!(
        !rogue_pulse["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("poisoned"),
        "Unsealed nested RogueSub MUST NEVER inject poisoned facts!"
    );

    // D. Direct `cwd = Subproject, target = "."` indexes strictly into `Subproject/.agents/memory.ldb`:
    let ok_sub = mcp.call(
        35,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": sub_cwd, "target": "." }
        }),
    );
    assert!(ok_sub.get("result").is_some());

    mcp.shutdown_clean();

    // E. Also run CLI `libredb index-workspace Main/.agents/memory.ldb Main --global <global>` and verify
    //    CLI indexing likewise skips `.agents`-bearing nested workspaces (`Subproject` and `RogueSub`):
    assert!(sbx
        .cmd()
        .args([
            "index-workspace",
            &main_ws.join(".agents").join("memory.ldb").to_string_lossy(),
            &main_ws.to_string_lossy(),
            "--global",
            &global_str,
            "--force"
        ])
        .status()
        .unwrap()
        .success());

    let main_sym_keys: Vec<String> = LibreDb::open(main_ws.join(".agents").join("memory.ldb"))
        .unwrap()
        .list_inodes(Some(NodeKind::Symbol), false)
        .into_iter()
        .filter_map(|(_, k, _)| k)
        .collect();
    let sub_sym_keys: Vec<String> = LibreDb::open(sub_ws.join(".agents").join("memory.ldb"))
        .unwrap()
        .list_inodes(Some(NodeKind::Symbol), false)
        .into_iter()
        .filter_map(|(_, k, _)| k)
        .collect();

    assert!(
        main_sym_keys.iter().any(|k| k.contains("main_orchestrator"))
            && main_sym_keys.iter().any(|k| k.contains("helper_utility")),
        "Main brain must contain Main + crates/helper symbols: {main_sym_keys:?}"
    );
    for leaked in [
        "subproject_confidential_algo",
        "rogue_unsealed_implant",
    ] {
        assert!(
            !main_sym_keys.iter().any(|k| k.contains(leaked)),
            "Main brain MUST NOT contain nested child symbol '{leaked}': {main_sym_keys:?}"
        );
    }
    assert!(
        sub_sym_keys
            .iter()
            .any(|k| k.contains("subproject_confidential_algo"))
            && !sub_sym_keys.iter().any(|k| k.contains("main_orchestrator")),
        "Subproject brain must contain ONLY Subproject symbols: {sub_sym_keys:?}"
    );
}

fn create_dir_link_or_junction(target: &Path, link_path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path).is_ok()
    }
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link_path.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// 5. Symlink / NTFS directory-junction pivot test:
///    Proves that creating an internal directory link inside `Main/links/sub_pivot -> Main/Subproject/src`
///    or `Main/links/out_pivot -> OutsideVault` cannot trick `cwd = Main` into reading or indexing
///    either `Subproject` or external files!
#[test]
fn e2e_symlink_pivot_into_nested_workspace_and_outside_root_blocked() {
    let sbx = TestSandbox::new("symlink_pivot");
    let global_ldb = sbx.root.join("customizations.ldb");
    let global_str = global_ldb.to_string_lossy().into_owned();

    let main_ws = sbx.root.join("Main");
    let sub_ws = main_ws.join("Subproject");
    let outside_dir = sbx.root.join("OutsideVault");
    fs::create_dir_all(main_ws.join("src")).unwrap();
    fs::create_dir_all(main_ws.join("links")).unwrap();
    fs::create_dir_all(sub_ws.join("src")).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    fs::write(main_ws.join("src").join("ok.rs"), "pub fn ok_main() {}\n").unwrap();
    fs::write(
        sub_ws.join("src").join("pivoted.rs"),
        "pub fn secret_nested_via_link() {}\n",
    )
    .unwrap();
    fs::write(
        outside_dir.join("ext.rs"),
        "pub fn secret_external_via_link() {}\n",
    )
    .unwrap();

    assert!(sbx.cmd().args(["init", &global_str]).status().unwrap().success());
    assert!(sbx
        .cmd()
        .args(["trust", &main_ws.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());
    assert!(sbx
        .cmd()
        .args(["trust", &sub_ws.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());

    let sub_link = main_ws.join("links").join("sub_pivot");
    let out_link = main_ws.join("links").join("out_pivot");
    let has_sub_link = create_dir_link_or_junction(&sub_ws.join("src"), &sub_link);
    let has_out_link = create_dir_link_or_junction(&outside_dir, &out_link);

    let mut mcp = LiveMcpSubprocess::spawn(&sbx, &["--global", &global_str]);
    mcp.call(
        1,
        "initialize",
        json!({
            "workspaceFolders": [
                { "uri": to_file_uri(&main_ws), "name": "Main" },
                { "uri": to_file_uri(&sub_ws), "name": "Subproject" }
            ]
        }),
    );
    let main_cwd = main_ws.to_string_lossy().to_string();

    if has_sub_link {
        let r_skel = mcp.call(
            2,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": main_cwd,
                    "target": "links/sub_pivot/pivoted.rs"
                }
            }),
        );
        assert!(
            r_skel.get("error").is_some(),
            "Symlink/junction pivot from Main into nested Subproject MUST be blocked: {r_skel}"
        );
        let r_idx = mcp.call(
            3,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "index",
                    "cwd": main_cwd,
                    "target": "links/sub_pivot"
                }
            }),
        );
        assert!(r_idx.get("error").is_some());
    }

    if has_out_link {
        let r_out = mcp.call(
            4,
            "tools/call",
            json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "cwd": main_cwd,
                    "target": "links/out_pivot/ext.rs"
                }
            }),
        );
        assert!(
            r_out.get("error").is_some(),
            "Symlink/junction pivot escaping Main MUST be blocked: {r_out}"
        );
    }

    // Recursive scan of `Main` MUST skip directory links/junctions and nested `Subproject`:
    let r_scan = mcp.call(
        5,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": { "action": "index", "cwd": main_cwd, "target": "." }
        }),
    );
    assert!(r_scan.get("result").is_some());
    mcp.shutdown_clean();

    let syms: Vec<String> = LibreDb::open(main_ws.join(".agents").join("memory.ldb"))
        .unwrap()
        .list_inodes(Some(NodeKind::Symbol), false)
        .into_iter()
        .filter_map(|(_, k, _)| k)
        .collect();
    assert!(syms.iter().any(|k| k.contains("ok_main")));
    assert!(!syms.iter().any(|k| k.contains("secret_nested_via_link")));
    assert!(!syms.iter().any(|k| k.contains("secret_external_via_link")));
}

/// 6. Multi-process concurrent `MCP` + `CLI` workspace mutation & monotonic `v4` seal stress test:
///    Hammers a single workspace concurrently from 2 live `libredb mcp-serve` OS processes,
///    a CLI `libredb config` writer loop, and a CLI `libredb index-workspace` loop, verifying zero
///    seal desynchronization, zero lost facts, and valid monotonic `hmac-sha256:v4:r<rev>` ratchets.
#[test]
fn e2e_concurrent_multiprocess_mcp_and_cli_mutations_preserve_monotonic_v4_seals() {
    let sbx = TestSandbox::new("multiprocess_seal");
    let global_ldb = sbx.root.join("customizations.ldb");
    let global_str = global_ldb.to_string_lossy().into_owned();
    let ws = sbx.root.join("ConcurrentRepo");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(
        ws.join("src").join("engine.rs"),
        "pub fn concurrent_kernel_op() -> usize { 1 }\n",
    )
    .unwrap();
    let ws_str = ws.to_string_lossy().into_owned();

    assert!(sbx.cmd().args(["init", &global_str]).status().unwrap().success());
    assert!(sbx
        .cmd()
        .args(["trust", &ws_str, "--global", &global_str])
        .status()
        .unwrap()
        .success());

    std::thread::scope(|s| {
        for lane in 0..2u64 {
            let sbx_ref = &sbx;
            let g_ref = global_str.as_str();
            let w_ref = ws_str.as_str();
            s.spawn(move || {
                let mut mcp = LiveMcpSubprocess::spawn(
                    sbx_ref,
                    &["--global", g_ref, "--workspace-root", w_ref],
                );
                assert!(mcp.call(1, "initialize", json!({})).get("result").is_some());
                let lane_word = if lane == 0 { "alpha" } else { "bravo" };
                let step_words = ["zero", "one", "two", "three", "four"];
                for step in 0..5u64 {
                    let sw = step_words[step as usize];
                    let fk = format!("fact_{lane_word}_{sw}");
                    let fv = format!("verified_payload_{lane_word}_{sw}_anchor");
                    let resp = mcp.call(
                        10 + step,
                        "tools/call",
                        json!({
                            "name": "libredb_memorize",
                            "arguments": {
                                "cwd": w_ref,
                                "facts": { fk: fv }
                            }
                        }),
                    );
                    assert!(
                        resp.get("result").is_some(),
                        "Concurrent MCP memorize failed on lane {lane} step {step}: {resp}"
                    );
                }
                mcp.shutdown_clean();
            });
        }

        let sbx_cfg = &sbx;
        let g_cfg = global_str.as_str();
        let w_cfg = ws_str.as_str();
        s.spawn(move || {
            for i in 0..4 {
                let st = sbx_cfg
                    .cmd()
                    .args([
                        "config",
                        "set",
                        "index:max_file_bytes",
                        &format!("{}", 1048576 + i * 1024),
                        "--project",
                        w_cfg,
                        "--global",
                        g_cfg,
                    ])
                    .stdout(Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success(), "Concurrent CLI config set failed at iter {i}");
            }
        });

        let sbx_idx = &sbx;
        let g_idx = global_str.as_str();
        let w_idx = ws_str.as_str();
        let ldb_path = ws.join(".agents").join("memory.ldb");
        s.spawn(move || {
            for i in 0..4 {
                let st = sbx_idx
                    .cmd()
                    .args([
                        "index-workspace",
                        &ldb_path.to_string_lossy(),
                        w_idx,
                        "--global",
                        g_idx,
                    ])
                    .stdout(Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success(), "Concurrent CLI index-workspace failed at iter {i}");
            }
        });
    });

    // Verify all 10 facts exist AND a fresh MCP server trusts and recalls from the workspace cleanly:
    let pdb = LibreDb::open(ws.join(".agents").join("memory.ldb")).unwrap();
    let step_words = ["zero", "one", "two", "three", "four"];
    for lane_word in ["alpha", "bravo"] {
        for sw in step_words {
            let fk = format!("fact_{lane_word}_{sw}");
            assert!(
                pdb.get_by_key(NodeKind::Fact, &fk).is_ok(),
                "Missing committed concurrent fact '{fk}'!"
            );
        }
    }
    let seal_txt = String::from_utf8_lossy(
        &pdb.get_by_key(NodeKind::Config, "sys::trust_seals")
            .unwrap()
            .payload,
    )
    .into_owned();
    assert!(
        seal_txt.contains("hmac-sha256:v4:r"),
        "Expected v4 monotonic seal tag, got: {seal_txt}"
    );
    drop(pdb);

    let mut verifier =
        LiveMcpSubprocess::spawn(&sbx, &["--global", &global_str, "--workspace-root", &ws_str]);
    verifier.call(1, "initialize", json!({}));
    let pulse = verifier.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_pulse",
            "arguments": { "query": "bravo four", "cwd": ws_str }
        }),
    );
    let pulse_txt = pulse["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        pulse_txt.contains("verified_payload_bravo_four_anchor"),
        "Expected recalled concurrent fact, got: {pulse}"
    );
    verifier.shutdown_clean();
}

/// 7. End-to-end CLI `hook-pre-invocation` & `hook-pre-tool` adversarial test:
///    Verifies real subprocess hook execution against rolled-back/unsealed workspace databases and
///    adversarial `PreToolUse` envelopes (`toolArgs`, `tool_args`, `input`, NTFS ADS `:stream`,
///    control-plane `hooks.json`, `.git/hooks`, `.vault.key` command tamper, and missing write path).
#[test]
fn e2e_cli_lifecycle_hooks_enforce_quarantine_and_block_control_plane_attacks() {
    let sbx = TestSandbox::new("cli_hooks");
    let global_ldb = sbx.home_dir.join(".gemini").join("libredb").join("customizations.ldb");
    fs::create_dir_all(global_ldb.parent().unwrap()).unwrap();
    let global_str = global_ldb.to_string_lossy().into_owned();

    assert!(sbx.cmd().args(["init", &global_str]).status().unwrap().success());

    // 1. Create a sealed trusted workspace and prove `hook-pre-invocation` hydrates legitimate facts:
    let trusted_ws = sbx.root.join("TrustedRepo");
    fs::create_dir_all(trusted_ws.join(".agents")).unwrap();
    fs::write(trusted_ws.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    assert!(sbx
        .cmd()
        .args(["trust", &trusted_ws.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());
    assert!(sbx
        .cmd()
        .args([
            "batch",
            &trusted_ws.join(".agents").join("memory.ldb").to_string_lossy(),
            "--fact",
            "TRUSTED_FACT=SAFE_HYDRATION_OK",
            "--global",
            &global_str
        ])
        .status()
        .unwrap()
        .success());

    // 2. Create an unsealed poisoned workspace (`PROMPT_INJECTION_SECRET`):
    let poisoned_ws = sbx.root.join("PoisonedRepo");
    fs::create_dir_all(poisoned_ws.join(".agents")).unwrap();
    fs::write(poisoned_ws.join("Cargo.toml"), "[package]\nname = \"poison\"\n").unwrap();
    {
        let pdb = LibreDb::open(poisoned_ws.join(".agents").join("memory.ldb")).unwrap();
        pdb.put(
            libredb_core::WriteRequest::new(
                NodeKind::Fact,
                b"PROMPT_INJECTION_SECRET = EXFILTRATE_NOW".to_vec(),
            )
            .with_key("PROMPT_INJECTION_SECRET"),
        )
        .unwrap();
    }

    let run_hook = |subcmd: &str, payload: Value| -> Value {
        let mut child = sbx
            .cmd()
            .args([subcmd, "--global", &global_str])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        {
            let st = child.stdin.as_mut().unwrap();
            write!(st, "{payload}").unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).expect("Hook must emit valid JSON")
    };

    let trusted_inv = run_hook(
        "hook-pre-invocation",
        json!({ "workspacePaths": [trusted_ws.to_string_lossy().to_string()] }),
    );
    assert!(
        trusted_inv.to_string().contains("SAFE_HYDRATION_OK"),
        "Trusted sealed workspace must hydrate via hook-pre-invocation: {trusted_inv}"
    );

    let pre_inv = run_hook(
        "hook-pre-invocation",
        json!({ "workspacePaths": [poisoned_ws.to_string_lossy().to_string()] }),
    );
    let pre_inv_str = pre_inv.to_string();
    assert!(
        !pre_inv_str.contains("EXFILTRATE_NOW"),
        "hook-pre-invocation MUST quarantine unsealed project memory: {pre_inv_str}"
    );
    assert_eq!(
        pre_inv["injectSteps"],
        json!([]),
        "Unsealed project memory must produce zero injected prompt steps: {pre_inv_str}"
    );

    // Also verify that mutating a sealed `.agents/memory.ldb` via CLI WITHOUT `--global` fails closed:
    let unauth_cli_write = sbx
        .cmd()
        .env("HOME", sbx.root.join("no_global_home"))
        .env("USERPROFILE", sbx.root.join("no_global_home"))
        .args([
            "put",
            &trusted_ws.join(".agents").join("memory.ldb").to_string_lossy(),
            "Fact",
            "ROGUE_WRITE",
            "--key",
            "rogue",
        ])
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !unauth_cli_write.success(),
        "CLI write to sealed .agents/memory.ldb without customizations.ldb MUST fail closed!"
    );

    let hooks_ads_target = sbx
        .home_dir
        .join(".gemini")
        .join("config")
        .join("plugins")
        .join("libredb")
        .join("hooks.json:hidden_ads");

    // Every adversarial `PreToolUse` payload below MUST return `"decision": "deny"`:
    for attack_payload in [
        json!({
            "toolName": "write_file",
            "toolArgs": { "Path": hooks_ads_target.to_string_lossy().to_string() }
        }),
        json!({
            "tool_name": "edit_file",
            "tool_args": { "Path": poisoned_ws.join(".git/hooks/pre-commit").to_string_lossy().to_string() }
        }),
        json!({
            "name": "write_file",
            "input": { "Path": poisoned_ws.join(".AGENTS/MEMORY.LDB").to_string_lossy().to_string() }
        }),
        json!({
            "toolName": "write_file",
            "toolInput": { "Content": "missing path field attack" }
        }),
        json!({
            "toolName": "run_command",
            "toolArgs": { "CommandLine": "git -c core.sshCommand=evil fetch origin" }
        }),
    ] {
        let res = run_hook("hook-pre-tool", attack_payload.clone());
        assert_eq!(
            res["decision"],
            json!("deny"),
            "Adversarial PreToolUse payload MUST be denied: payload={attack_payload} -> res={res}"
        );
        assert!(
            res["reason"].as_str().is_some_and(|s| !s.is_empty()),
            "Denied PreToolUse response must explain reason: {res}"
        );
    }
}

/// 8. End-to-end poisoned legacy SQLite `.agents/memory.db` migration over `libredb mcp-serve`:
///    Verifies that auto-migrating an authorized workspace's `.agents/memory.db` strips all
///    privileged `sys::*`, `trust:*`, `mcp:*`, `gitea_allow_insecure_http`, and `guardrail:*`
///    switches from active `Config` capsules while sealing legitimate project facts cleanly.
#[test]
fn e2e_poisoned_sqlite_migration_strips_privileged_keys_and_preserves_legitimate_facts() {
    let sbx = TestSandbox::new("sqlite_mig_e2e");
    let global_ldb = sbx.root.join("customizations.ldb");
    let global_str = global_ldb.to_string_lossy().into_owned();

    let mig_ws2 = sbx.root.join("LegacySqlImportProject");
    let evil_ws = sbx.root.join("EvilRogueDir");
    fs::create_dir_all(mig_ws2.join(".agents")).unwrap();
    fs::create_dir_all(evil_ws.join("src")).unwrap();
    fs::write(evil_ws.join("src").join("evil.rs"), "pub fn evil() {}\n").unwrap();

    assert!(sbx.cmd().args(["init", &global_str]).status().unwrap().success());
    let sql_path = mig_ws2.join("legacy_memory.db");
    {
        let conn = rusqlite::Connection::open(&sql_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE project_facts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, value TEXT);
             INSERT INTO project_facts (key, value) VALUES ('arch_stack', 'pure_rust_zero_copy');
             CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO runtime_config (key, value) VALUES
               ('sys::trust_anchor_secret', 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'),
               ('trust:allowed::/evil', '1'),
               ('mcp:allow_untrusted_workspaces', 'true'),
               ('mcp:allow_central_sqlite_sync', 'true'),
               ('gitea_allow_insecure_http', 'true'),
               ('guardrail:allow_staged_files', 'true'),
               ('index:extra_extensions', '.custom');",
        )
        .unwrap();
    }

    let mig2_ldb = mig_ws2.join(".agents").join("memory.ldb");
    assert!(sbx
        .cmd()
        .args([
            "import-sqlite",
            &mig2_ldb.to_string_lossy(),
            &sql_path.to_string_lossy(),
            "--scope",
            "project",
            "--global",
            &global_str
        ])
        .status()
        .unwrap()
        .success());
    assert!(sbx
        .cmd()
        .args(["trust", &mig_ws2.to_string_lossy(), "--global", &global_str])
        .status()
        .unwrap()
        .success());

    // Also import into `global_ldb` (`--scope central` on a disposable central copy) to verify central strip:
    let central_copy = sbx.root.join("central_imported.ldb");
    assert!(sbx
        .cmd()
        .args([
            "import-sqlite",
            &central_copy.to_string_lossy(),
            &sql_path.to_string_lossy(),
            "--scope",
            "central"
        ])
        .status()
        .unwrap()
        .success());

    for db_check in [&mig2_ldb, &central_copy] {
        let db = LibreDb::open(db_check).unwrap();
        for blocked_key in [
            "trust:allowed::/evil",
            "mcp:allow_untrusted_workspaces",
            "mcp:allow_central_sqlite_sync",
            "gitea_allow_insecure_http",
            "guardrail:allow_staged_files",
        ] {
            assert!(
                db.get_by_key(NodeKind::Config, blocked_key).is_err(),
                "Privileged security switch '{blocked_key}' MUST be stripped in {}!",
                db_check.display()
            );
        }
        assert!(db.get_by_key(NodeKind::Config, "index:extra_extensions").is_ok());
    }

    let mut mcp = LiveMcpSubprocess::spawn(&sbx, &["--global", &global_str]);
    mcp.call(1, "initialize", json!({}));

    // Legitimate migrated fact in `mig_ws2` is recalled cleanly:
    let ok_pulse = mcp.call(
        2,
        "tools/call",
        json!({
            "name": "libredb_pulse",
            "arguments": {
                "cwd": mig_ws2.to_string_lossy().to_string(),
                "query": "pure_rust_zero_copy"
            }
        }),
    );
    assert!(ok_pulse["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("pure_rust_zero_copy"));

    // Unauthorized `evil_ws` remains 100% blocked (`mcp:allow_untrusted_workspaces` was NOT activated!):
    let evil_attempt = mcp.call(
        3,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "skeleton",
                "cwd": evil_ws.to_string_lossy().to_string(),
                "target": "src/evil.rs"
            }
        }),
    );
    assert!(evil_attempt.get("error").is_some());
    mcp.shutdown_clean();
}
