//! End-to-end integration and multi-process security verification suite for `LibreDB v1.1.1`.
//!
//! Exercises the compiled `libredb` binary across real OS processes and JSON-RPC 2.0 stdio streams:
//! 1. `libredb bench --suite audit --json` (all 9 live verification checks `A1..A9`),
//! 2. `libredb mcp-serve` stdio authorization for `libredb_code(action="savings")` (`ws_alpha` vs `ws_beta`,
//!    `cwd="*"` denial, omitted `cwd` scoping, and `days > 3660` rejection),
//! 3. True 4-process OS concurrency (`4 x 15 = 60` real child processes) incrementing a shared
//!    `telemetry.ldb` via `LibreDb::transact_key` with `0` lost updates.

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fresh_sandbox(tag: &str) -> TempDirGuard {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join(format!("v111_{tag}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&base).expect("create sandbox");
    TempDirGuard(base)
}

#[test]
fn built_in_audit_suite_cli_passes_all_9_checks() {
    let bin = env!("CARGO_BIN_EXE_libredb");
    let out = Command::new(bin)
        .args(["bench", "--suite", "audit", "--json"])
        .output()
        .expect("run libredb bench --suite audit --json");

    assert!(
        out.status.success(),
        "libredb bench --suite audit failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let rep: Value = serde_json::from_slice(&out.stdout).expect("valid audit JSON");
    assert_eq!(rep.get("total_checks").and_then(Value::as_u64), Some(12));
    assert_eq!(rep.get("passed_checks").and_then(Value::as_u64), Some(12));
    assert_eq!(rep.get("failed_checks").and_then(Value::as_u64), Some(0));

    let checks = rep
        .get("checks")
        .and_then(Value::as_array)
        .expect("checks array");
    for (idx, expected_id) in [
        "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            checks[idx].get("check_id").and_then(Value::as_str),
            Some(*expected_id)
        );
        assert_eq!(
            checks[idx].get("passed").and_then(Value::as_bool),
            Some(true),
            "Audit check {expected_id} failed: {:?}",
            checks[idx]
        );
    }
}

#[test]
fn mcp_stdio_savings_enforces_workspace_boundary_and_days_limit() {
    let sbx = fresh_sandbox("mcp_savings_authz");
    let bin = env!("CARGO_BIN_EXE_libredb");

    let fake_home = sbx.0.join("home");
    fs::create_dir_all(fake_home.join(".gemini/libredb")).unwrap();
    let global_ldb = fake_home.join(".gemini/libredb/customizations.ldb");

    let ws_a = sbx.0.join("workspace_alpha");
    let ws_b = sbx.0.join("workspace_beta");
    fs::create_dir_all(ws_a.join(".git")).unwrap();
    fs::create_dir_all(ws_b.join(".git")).unwrap();

    // Trust `ws_a` in isolated `global_ldb`:
    let trust_status = Command::new(bin)
        .args([
            "trust",
            &ws_a.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .expect("trust ws_a");
    assert!(trust_status.success());

    let mut child = Command::new(bin)
        .args([
            "mcp-serve",
            "--global",
            &global_ldb.to_string_lossy(),
            "--workspace-root",
            &ws_a.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-serve");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    let mut rpc = |id: u64, method: &str, params: Value| -> Value {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).expect("valid JSON-RPC response")
    };

    let init_resp = rpc(1, "initialize", json!({ "capabilities": {} }));
    assert!(init_resp.get("result").is_some());

    // 1. Cross-workspace `cwd = ws_b` MUST fail closed:
    let cross = rpc(
        2,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "savings",
                "cwd": ws_b.to_string_lossy().to_string()
            }
        }),
    );
    assert!(
        cross.get("error").is_some(),
        "Expected JSON-RPC error when querying ws_beta from ws_alpha-pinned server: {cross}"
    );

    // 2. Global wildcard `cwd = "*"` MUST fail closed on pinned server:
    let wild = rpc(
        3,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "savings",
                "cwd": "*"
            }
        }),
    );
    assert!(
        wild.get("error").is_some(),
        "Expected JSON-RPC error for cwd='*' on pinned server: {wild}"
    );

    // 3. Unbounded `days = 1_000_000_000` MUST fail closed:
    let huge_days = rpc(
        4,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "savings",
                "days": 1_000_000_000u64
            }
        }),
    );
    assert!(
        huge_days.get("error").is_some(),
        "Expected JSON-RPC error for excessive days=1_000_000_000: {huge_days}"
    );

    // 4. Omitted `cwd` MUST stay strictly scoped to `workspace_alpha`:
    let own = rpc(
        5,
        "tools/call",
        json!({
            "name": "libredb_code",
            "arguments": {
                "action": "savings",
                "format": "json"
            }
        }),
    );
    let text = own
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("savings JSON payload");
    let rep: Value = serde_json::from_str(text).unwrap();
    let scope = rep
        .get("scope_label")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        scope.starts_with("project:") && scope.contains("workspace_alpha"),
        "Expected project-scoped savings report for workspace_alpha, got: {scope}"
    );

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn four_concurrent_os_processes_increment_telemetry_ldb_without_lost_updates() {
    let sbx = fresh_sandbox("multiprocess_telemetry");
    let bin = env!("CARGO_BIN_EXE_libredb");

    let fake_home = sbx.0.join("home");
    fs::create_dir_all(fake_home.join(".gemini/libredb")).unwrap();
    let global_ldb = fake_home.join(".gemini/libredb/customizations.ldb");
    let tel_ldb = sbx.0.join("shared_telemetry.ldb");

    let skill_md = sbx.0.join("SKILL.md");
    fs::write(
        &skill_md,
        "---\nname: audit_skill\ndescription: Multi-process telemetry test skill\n---\n\n# Audit skill\n\n## Core rules\nEnforce cross-process atomic transact_key updates on telemetry.ldb.\n\n## Extended guide\nPadding text so full baseline exceeds single section slice. ".to_owned()
            + &"Extra guide line for baseline ratio. ".repeat(25),
    )
    .unwrap();

    let sync_out = Command::new(bin)
        .args([
            "sync-skill",
            &skill_md.to_string_lossy(),
            "--name",
            "audit_skill",
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .expect("sync-skill");
    assert!(
        sync_out.status.success(),
        "sync-skill failed: {}",
        String::from_utf8_lossy(&sync_out.stderr)
    );

    // Spawn 4 concurrent threads, each launching 15 real OS `libredb get-skill --section` child processes (`60` total).
    let mut handles = Vec::new();
    for _ in 0..4 {
        let bin_str = bin.to_owned();
        let gdb_p = global_ldb.clone();
        let tel_p = tel_ldb.clone();
        let home_p = fake_home.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..15 {
                let out = Command::new(&bin_str)
                    .args([
                        "get-skill",
                        "audit_skill",
                        "--section",
                        "Core rules",
                        "--global",
                        &gdb_p.to_string_lossy(),
                    ])
                    .env("LIBREDB_TELEMETRY_PATH", &tel_p)
                    .env("USERPROFILE", &home_p)
                    .env("HOME", &home_p)
                    .output()
                    .expect("get-skill child");
                assert!(
                    out.status.success(),
                    "get-skill child failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread joined");
    }

    // Verify binary CRC32C & superblock integrity of `shared_telemetry.ldb`:
    let ver = Command::new(bin)
        .args(["verify", &tel_ldb.to_string_lossy()])
        .output()
        .expect("verify telemetry.ldb");
    assert!(
        ver.status.success(),
        "telemetry.ldb integrity check failed: {}",
        String::from_utf8_lossy(&ver.stderr)
    );

    // Query `savings --today --json` against `shared_telemetry.ldb`: must equal exact `60` calls!
    let sav = Command::new(bin)
        .args(["savings", "--today", "--json"])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .expect("savings --today --json");
    assert!(sav.status.success());
    let rep: Value = serde_json::from_slice(&sav.stdout).expect("savings JSON");
    assert_eq!(
        rep.pointer("/ledger_only_metrics/skill_slice_calls")
            .and_then(Value::as_u64),
        Some(60),
        "Expected exact 60 multi-process skill_slice_calls with 0 lost updates, got: {rep}"
    );

    // Also verify CLI rejects unbounded `--days 1000000000`:
    let bad_days = Command::new(bin)
        .args(["savings", "--days", "1000000000"])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .output()
        .expect("savings huge days");
    assert!(!bad_days.status.success());
}

#[test]
fn v120_mcp_batched_locate_impact_fim_and_zero_boilerplate_cli_work() {
    let sbx = fresh_sandbox("v120_batch_and_cli");
    let bin = env!("CARGO_BIN_EXE_libredb");

    let fake_home = sbx.0.join("home");
    fs::create_dir_all(fake_home.join(".gemini/libredb")).unwrap();
    let global_ldb = fake_home.join(".gemini/libredb/customizations.ldb");
    let tel_ldb = sbx.0.join("v120_telemetry.ldb");

    let ws = sbx.0.join("workspace_main");
    let outside_ws = sbx.0.join("workspace_outside");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::create_dir_all(outside_ws.join("src")).unwrap();
    fs::write(
        ws.join("src/lib.rs"),
        "pub fn first_fn(a: i32) -> i32 {\n    second_fn(a) + 1\n}\n\npub fn second_fn(b: i32) -> i32 {\n    b * 3\n}\n",
    )
    .unwrap();
    fs::write(outside_ws.join("src/secret.rs"), "pub fn secret_fn() {}\n").unwrap();

    // Trust `ws` and seed a fact + skill in `global_ldb`:
    assert!(Command::new(bin)
        .args([
            "trust",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy()
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .unwrap()
        .success());

    assert!(Command::new(bin)
        .args([
            "batch",
            &ws.join(".agents/memory.ldb").to_string_lossy(),
            "--fact",
            "v120_arch=batched_mcp_and_zero_boilerplate_cli",
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .unwrap()
        .success());

    // 1. Zero-boilerplate `libredb pulse "<query>" --cwd <ws>` (omitting `<db.ldb>`):
    let pulse_out = Command::new(bin)
        .args([
            "pulse",
            "batched_mcp_and_zero_boilerplate_cli",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .expect("zero-boilerplate pulse");
    assert!(
        pulse_out.status.success(),
        "zero-boilerplate pulse failed: {}",
        String::from_utf8_lossy(&pulse_out.stderr)
    );
    let pulse_stdout = String::from_utf8_lossy(&pulse_out.stdout);
    assert!(
        pulse_stdout.contains("v120_arch = batched_mcp_and_zero_boilerplate_cli"),
        "Expected fact in pulse output, got: {pulse_stdout}"
    );

    // 2. MCP stdio server: batched `locate`, batched `impact`, batched `fim`, and containment check on `slices`
    let mut child = Command::new(bin)
        .args([
            "mcp-serve",
            "--workspace-root",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-serve");

    let mut stdin = child.stdin.take().expect("mcp stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("mcp stdout"));

    let mut rpc = |id: u64, args: Value| -> Value {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "libredb_code",
                "arguments": args
            }
        });
        writeln!(stdin, "{req}").expect("write rpc");
        stdin.flush().expect("flush rpc");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read rpc");
        serde_json::from_str(&line).expect("valid rpc json")
    };

    // 2a. Batched `locate`
    let loc_resp = rpc(
        1,
        json!({
            "action": "locate",
            "symbols": ["first_fn", "second_fn"],
            "format": "json"
        }),
    );
    let loc_txt = loc_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("locate json text");
    let loc_arr: Vec<Value> = serde_json::from_str(loc_txt).expect("parse locate json");
    assert_eq!(loc_arr.len(), 2);

    // 2b. Batched `impact`
    let imp_resp = rpc(
        2,
        json!({
            "action": "impact",
            "symbols": ["first_fn", "second_fn"]
        }),
    );
    let imp_txt = imp_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("impact text");
    assert!(imp_txt.contains("=== BATCH IMPACT: 2 queries"));
    assert!(imp_txt.contains("first_fn"));
    assert!(imp_txt.contains("second_fn"));

    // 2c. Batched `fim` via `slices`
    let fim_resp = rpc(
        3,
        json!({
            "action": "fim",
            "slices": [
                { "target": "src/lib.rs", "symbol": "first_fn", "pad": 2 },
                { "target": "src/lib.rs", "symbol": "second_fn", "pad": 2 }
            ]
        }),
    );
    let fim_txt = fim_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("fim text");
    assert!(fim_txt.contains("=== BATCH FIM SLICES (2 slices) ==="));

    // 2d. Security containment: a batched `fim` request containing an out-of-workspace slice MUST fail closed!
    let bad_fim = rpc(
        4,
        json!({
            "action": "fim",
            "slices": [
                { "target": "src/lib.rs", "symbol": "first_fn" },
                { "target": outside_ws.join("src/secret.rs").to_string_lossy(), "symbol": "secret_fn" }
            ]
        }),
    );
    assert!(
        bad_fim.get("error").is_some(),
        "Expected MCP containment denial when any slice escapes workspace, got: {bad_fim}"
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();

    // 3. Zero-boilerplate CLI `libredb locate first_fn second_fn --cwd <ws>`
    let cli_loc = Command::new(bin)
        .args([
            "locate",
            "first_fn",
            "second_fn",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .expect("cli locate");
    assert!(
        cli_loc.status.success(),
        "cli locate failed: {}",
        String::from_utf8_lossy(&cli_loc.stderr)
    );
    let cli_loc_out = String::from_utf8_lossy(&cli_loc.stdout);
    assert!(cli_loc_out.contains("first_fn") && cli_loc_out.contains("second_fn"));
}

#[test]
fn v130_closed_loop_search_bridge_git_cochange_and_falsifiable_reflexes_work() {
    let sbx = fresh_sandbox("v130_closed_loop");
    let bin = env!("CARGO_BIN_EXE_libredb");

    let fake_home = sbx.0.join("home");
    fs::create_dir_all(fake_home.join(".gemini/libredb")).unwrap();
    let global_ldb = fake_home.join(".gemini/libredb/customizations.ldb");
    let tel_ldb = sbx.0.join("v130_telemetry.ldb");

    let ws = sbx.0.join("ws_causal");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"ws_causal\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let auth_rs = ws.join("src/auth.rs");
    let session_rs = ws.join("src/session.rs");
    let legacy_rs = ws.join("src/legacy_v1.rs");

    fs::write(
        &auth_rs,
        "pub fn verify_hmac_seal(nonce: u64) -> bool {\n    nonce > 10\n}\n\npub fn unrelated_helper() -> u32 {\n    99\n}\n",
    )
    .unwrap();
    fs::write(
        &session_rs,
        "pub fn open_sealed_session(nonce: u64) -> bool {\n    nonce == 42\n}\n",
    )
    .unwrap();
    fs::write(&legacy_rs, "pub fn old_v1_shim() {}\n").unwrap();

    // Initialize git history with 3 focused co-change commits between `src/auth.rs` and `src/session.rs`:
    let run_git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(&ws)
            .args(["-c", "safe.directory=*"])
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@local.dev")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@local.dev")
            .output()
            .expect("git command");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run_git(&["init", "-q"]);
    for rev in 1..=3 {
        fs::write(
            &auth_rs,
            format!(
                "pub fn verify_hmac_seal(nonce: u64) -> bool {{\n    nonce > {rev}\n}}\n\npub fn unrelated_helper() -> u32 {{\n    99\n}}\n"
            ),
        )
        .unwrap();
        fs::write(
            &session_rs,
            format!("pub fn open_sealed_session(nonce: u64) -> bool {{\n    nonce == {rev}\n}}\n"),
        )
        .unwrap();
        run_git(&["add", "src/auth.rs", "src/session.rs"]);
        run_git(&["commit", "-q", "-m", &format!("cochange {rev}")]);
    }

    // Trust workspace and learn a grounded reflex anchored to `src/legacy_v1.rs`:
    assert!(Command::new(bin)
        .args([
            "trust",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy()
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .unwrap()
        .success());

    let db_path = ws.join(".agents/memory.ldb");
    assert!(Command::new(bin)
        .args([
            "learn-reflex",
            &db_path.to_string_lossy(),
            "legacy-v1-guard",
            "Always update old_v1_shim in src/legacy_v1.rs when refactoring.",
            "--stack",
            "rust",
            "--action",
            "shim",
            "--anchor",
            "src/legacy_v1.rs",
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .unwrap()
        .success());

    // 1. Verify grounded reflex fires while `src/legacy_v1.rs` exists:
    let p_active = Command::new(bin)
        .args([
            "pulse",
            "rust shim",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    let p_active_txt = String::from_utf8_lossy(&p_active.stdout);
    assert!(
        p_active_txt.contains("legacy-v1-guard"),
        "Expected grounded reflex while anchor exists, got: {p_active_txt}"
    );

    // 2. Trigger a search miss on `zero_knowledge_ticket` via `locate`:
    let miss_out = Command::new(bin)
        .args([
            "locate",
            "zero_knowledge_ticket",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&miss_out.stdout).contains("0 symbols matched"),
        "Expected initial search miss, got: {}",
        String::from_utf8_lossy(&miss_out.stdout)
    );

    // 3. Simulate `PreToolUse` (`edit_file` on `src/auth.rs` modifying `verify_hmac_seal`) + disk write:
    let new_auth = "pub fn verify_hmac_seal(nonce: u64) -> bool {\n    let checked = nonce > 5;\n    checked\n}\n\npub fn unrelated_helper() -> u32 {\n    99\n}\n";
    let mut hook_child = Command::new(bin)
        .args([
            "hook-pre-tool",
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let hook_payload = json!({
        "toolName": "write_file",
        "toolArgs": {
            "Path": auth_rs.to_string_lossy().to_string(),
            "Content": new_auth
        }
    });
    writeln!(hook_child.stdin.take().unwrap(), "{hook_payload}").unwrap();
    let _ = hook_child.wait_with_output().unwrap();
    fs::write(&auth_rs, new_auth).unwrap();

    // 4. Now repeat `locate zero_knowledge_ticket` -> `reconcile_tentative_edits` promotes edit & binds cue to `verify_hmac_seal`!
    let hit_out = Command::new(bin)
        .args([
            "locate",
            "zero_knowledge_ticket",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    let hit_txt = String::from_utf8_lossy(&hit_out.stdout);
    assert!(
        hit_txt.contains("verify_hmac_seal") && !hit_txt.contains("unrelated_helper"),
        "Expected Search-Miss -> Verified-Edit bridge to resolve verify_hmac_seal, got: {hit_txt}"
    );

    // 5. Verify `impact verify_hmac_seal` surfaces `src/session.rs` in `Co-changed files (git Lift)`:
    let imp_out = Command::new(bin)
        .args([
            "impact",
            "verify_hmac_seal",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    let imp_txt = String::from_utf8_lossy(&imp_out.stdout);
    assert!(
        imp_txt.contains("Co-changed files (git Lift)") && imp_txt.contains("src/session.rs"),
        "Expected git co-change partner src/session.rs in impact output, got: {imp_txt}"
    );

    // 6. Delete `src/legacy_v1.rs`, re-index, and verify grounded reflex `legacy-v1-guard` is suppressed!
    fs::remove_file(&legacy_rs).unwrap();
    assert!(Command::new(bin)
        .args([
            "index-workspace",
            &db_path.to_string_lossy(),
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .status()
        .unwrap()
        .success());

    let p_after = Command::new(bin)
        .args([
            "pulse",
            "rust shim",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
        ])
        .env("LIBREDB_TELEMETRY_PATH", &tel_ldb)
        .env("USERPROFILE", &fake_home)
        .env("HOME", &fake_home)
        .output()
        .unwrap();
    let p_after_txt = String::from_utf8_lossy(&p_after.stdout);
    assert!(
        !p_after_txt.contains("legacy-v1-guard"),
        "Expected falsified grounded reflex to be suppressed after src/legacy_v1.rs removal, got: {p_after_txt}"
    );
}
