//! End-to-end learning regression checks for `LibreDB v1.4.0` across real OS processes
//! (`libredb` CLI, `mcp-serve` JSON-RPC stdio, sealed workspaces).

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
        .join(format!("v140_{tag}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&base).expect("create sandbox");
    TempDirGuard(base)
}

fn run_cli(bin: &str, home: &Path, tel: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(args)
        .env("LIBREDB_TELEMETRY_PATH", tel)
        .env("USERPROFILE", home)
        .env("HOME", home)
        .output()
        .expect("run libredb")
}

/// S3: A sealed workspace with a code-anchored reflex must stay trusted after the anchor file is
/// deleted and the workspace is re-indexed through every read path (MCP `locate`/`impact`/`index`,
/// CLI `locate`/`impact`). The falsified reflex must be suppressed at runtime.
#[test]
fn s03_sealed_workspace_stays_trusted_after_anchor_falsification() {
    let sbx = fresh_sandbox("s03_seal");
    let bin = env!("CARGO_BIN_EXE_libredb");
    let home = sbx.0.join("home");
    fs::create_dir_all(home.join(".gemini/libredb")).unwrap();
    let global = home.join(".gemini/libredb/customizations.ldb");
    let tel = sbx.0.join("tel.ldb");
    let ws = sbx.0.join("ws_sealed");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(ws.join("Cargo.toml"), "[package]\nname = \"ws_sealed\"\nversion = \"0.1.0\"\n").unwrap();
    fs::write(ws.join("src/main.rs"), "pub fn main_entry() -> u32 {\n    7\n}\n").unwrap();
    fs::write(ws.join("src/legacy.rs"), "pub fn legacy_shim() {}\n").unwrap();
    let g = global.to_string_lossy().to_string();
    let w = ws.to_string_lossy().to_string();
    let db = ws.join(".agents/memory.ldb").to_string_lossy().to_string();

    assert!(run_cli(bin, &home, &tel, &["trust", &w, "--global", &g]).status.success());
    assert!(run_cli(
        bin,
        &home,
        &tel,
        &["batch", &db, "--fact", "seal_probe=sealed workspace probe fact", "--global", &g]
    )
    .status
    .success());
    let learn = run_cli(
        bin,
        &home,
        &tel,
        &[
            "learn-reflex", &db, "legacy-guard", "Keep legacy_shim in sync.", "--action", "shim",
            "--anchor", "src/legacy.rs", "--global", &g,
        ],
    );
    assert!(learn.status.success(), "{}", String::from_utf8_lossy(&learn.stderr));
    let idx = run_cli(bin, &home, &tel, &["index-workspace", &db, &w, "--global", &g]);
    assert!(idx.status.success(), "{}", String::from_utf8_lossy(&idx.stderr));

    fs::remove_file(ws.join("src/legacy.rs")).unwrap();

    // MCP read paths (each runs `run_locked_workspace_index` without resealing):
    let mut child = Command::new(bin)
        .args(["mcp-serve", "--workspace-root", &w, "--global", &g])
        .env("LIBREDB_TELEMETRY_PATH", &tel)
        .env("USERPROFILE", &home)
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-serve");
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut rpc = |id: u64, args: Value| -> Value {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "libredb_code", "arguments": args}});
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).expect("valid JSON-RPC response")
    };
    for (id, args) in [
        (1, json!({"action": "locate", "target": "main_entry"})),
        (2, json!({"action": "impact", "target": "main_entry"})),
        (3, json!({"action": "index", "target": "."})),
    ] {
        let resp = rpc(id, args);
        assert!(resp.get("error").is_none(), "MCP read path failed: {resp}");
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();

    for args in [
        vec!["locate", "main_entry", "--cwd", &w, "--global", &g],
        vec!["impact", "main_entry", "--cwd", &w, "--global", &g],
    ] {
        let out = run_cli(bin, &home, &tel, &args);
        assert!(
            out.status.success(),
            "CLI {:?} failed after anchor falsification: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let pulse = run_cli(bin, &home, &tel, &["pulse", "shim probe", "--cwd", &w, "--global", &g]);
    let txt = String::from_utf8_lossy(&pulse.stdout);
    assert!(
        pulse.status.success(),
        "Workspace must remain trusted (no quarantine) after read paths: {}",
        String::from_utf8_lossy(&pulse.stderr)
    );
    assert!(!txt.contains("legacy-guard"), "Falsified reflex must be suppressed: {txt}");
}

#[test]
fn learning_cli_reports_cues_bridges_reflex_status_and_counters() {
    let sbx = fresh_sandbox("learning_cli");
    let bin = env!("CARGO_BIN_EXE_libredb");
    let home = sbx.0.join("home");
    fs::create_dir_all(home.join(".gemini/libredb")).unwrap();
    let global = home.join(".gemini/libredb/customizations.ldb");
    let tel = sbx.0.join("tel.ldb");
    let ws = sbx.0.join("ws_learn");
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(ws.join("Cargo.toml"), "[package]\nname = \"ws_learn\"\nversion = \"0.1.0\"\n")
        .unwrap();
    let lib_rs = ws.join("src/lib.rs");
    fs::write(
        &lib_rs,
        "pub fn dispatch_order(limit: usize) -> usize {\n    limit + 1\n}\n",
    )
    .unwrap();
    let g = global.to_string_lossy().to_string();
    let w = ws.to_string_lossy().to_string();
    let db = ws.join(".agents/memory.ldb").to_string_lossy().to_string();

    assert!(run_cli(bin, &home, &tel, &["init", &g]).status.success());
    assert!(run_cli(bin, &home, &tel, &["trust", &w, "--global", &g]).status.success());
    let idx1 = run_cli(bin, &home, &tel, &["index-workspace", &db, &w, "--global", &g]);
    assert!(idx1.status.success(), "{}", String::from_utf8_lossy(&idx1.stderr));

    let miss = run_cli(
        bin,
        &home,
        &tel,
        &["pulse", "throttling backpressure gate", "--cwd", &w, "--global", &g],
    );
    assert!(miss.status.success(), "{}", String::from_utf8_lossy(&miss.stderr));

    std::thread::sleep(std::time::Duration::from_millis(25));
    fs::write(
        &lib_rs,
        "pub fn dispatch_order(limit: usize) -> usize {\n    limit + 2\n}\n",
    )
    .unwrap();
    let idx2 = run_cli(bin, &home, &tel, &["index-workspace", &db, &w, "--global", &g]);
    assert!(idx2.status.success(), "{}", String::from_utf8_lossy(&idx2.stderr));

    let learn = run_cli(
        bin,
        &home,
        &tel,
        &[
            "learn-reflex",
            &db,
            "order-guard",
            "Check dispatch_order limit before changing arithmetic.",
            "--action",
            "dispatch",
            "--anchor",
            "src/lib.rs::dispatch_order",
            "--global",
            &g,
        ],
    );
    assert!(learn.status.success(), "{}", String::from_utf8_lossy(&learn.stderr));

    std::thread::sleep(std::time::Duration::from_millis(25));
    fs::write(
        &lib_rs,
        "pub fn dispatch_order(limit: usize, strict: bool) -> usize {\n    if strict { limit + 2 } else { limit }\n}\n",
    )
    .unwrap();
    let idx3 = run_cli(bin, &home, &tel, &["index-workspace", &db, &w, "--global", &g]);
    assert!(idx3.status.success(), "{}", String::from_utf8_lossy(&idx3.stderr));

    let json_out = run_cli(bin, &home, &tel, &["learning", "--cwd", &w, "--global", &g, "--json"]);
    assert!(
        json_out.status.success(),
        "libredb learning --json failed: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&json_out.stdout).expect("valid learning JSON");
    assert!(
        parsed["counters"]["misses_recorded"].as_u64().unwrap_or(0) >= 1,
        "expected misses_recorded >= 1: {parsed}"
    );
    assert!(
        parsed["counters"]["bindings_learned"].as_u64().unwrap_or(0) >= 1,
        "expected bindings_learned >= 1: {parsed}"
    );
    let bridges = parsed["top_bridges"].as_array().expect("top_bridges array");
    assert!(!bridges.is_empty(), "expected non-empty top_bridges: {parsed}");
    let points_to_dispatch = bridges.iter().any(|b| {
        b["targets"].as_array().is_some_and(|targets| {
            targets.iter().any(|t| {
                t.as_array()
                    .and_then(|pair| pair.first())
                    .and_then(|s| s.as_str())
                    .is_some_and(|k| k.contains("src/lib.rs::dispatch_order"))
            })
        })
    });
    assert!(points_to_dispatch, "expected bridge targeting src/lib.rs::dispatch_order: {parsed}");
    let reflexes = parsed["reflexes"].as_array().expect("reflexes array");
    let order_guard = reflexes
        .iter()
        .find(|r| r["id"].as_str() == Some("order-guard"))
        .expect("order-guard reflex present");
    assert_eq!(
        order_guard["status"].as_str(),
        Some("drift"),
        "expected anchor contract drift status: {order_guard}"
    );

    let txt_out = run_cli(bin, &home, &tel, &["learning", "--cwd", &w, "--global", &g]);
    assert!(
        txt_out.status.success(),
        "libredb learning failed: {}",
        String::from_utf8_lossy(&txt_out.stderr)
    );
    let txt = String::from_utf8_lossy(&txt_out.stdout);
    assert!(txt.contains("=== LIBREDB LEARNING STATE ==="), "{txt}");
    assert!(txt.contains("Symbol cue bridges"), "{txt}");
    assert!(txt.contains("Reflexes ("), "{txt}");
    assert!(txt.contains("Counters:"), "{txt}");
}

#[test]
fn learning_verify_and_bench_suite_prove_causal_learning_without_placebo_leaks() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "libredb_learn_verify_e2e_{}_{nonce}",
        std::process::id()
    ));
    let ws = root.join("ws");
    let global_ldb = root.join("global.ldb");
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"e2e_verify_ws\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    for (i, name) in ["alpha_pipeline", "beta_router", "gamma_store", "delta_sham"]
        .iter()
        .enumerate()
    {
        std::fs::write(
            ws.join(format!("src/m{i}.rs")),
            format!(
                "pub fn {name}(val: u64) -> u64 {{\n    let acc = val + {i};\n    acc * 3\n}}\n"
            ),
        )
        .unwrap();
    }

    let bin = env!("CARGO_BIN_EXE_libredb");

    let verify_out = std::process::Command::new(bin)
        .args([
            "learning",
            "--verify",
            "--cwd",
            &ws.to_string_lossy(),
            "--global",
            &global_ldb.to_string_lossy(),
            "--json",
        ])
        .output()
        .expect("run libredb learning --verify");
    assert!(
        verify_out.status.success(),
        "learning --verify failed: {}\n{}",
        String::from_utf8_lossy(&verify_out.stderr),
        String::from_utf8_lossy(&verify_out.stdout)
    );
    let rep: serde_json::Value = serde_json::from_slice(&verify_out.stdout)
        .expect("parse learning --verify JSON");
    assert_eq!(rep["verdict"].as_str(), Some("VERIFIED_CAUSAL_LEARNING"), "{rep}");
    assert_eq!(rep["passed_stages"].as_u64(), Some(13), "{rep}");
    assert_eq!(rep["failed_stages"].as_u64(), Some(0), "{rep}");
    assert_eq!(rep["placebo_false_bindings"].as_u64(), Some(0), "{rep}");
    assert_eq!(rep["dead_bridges_retained"].as_u64(), Some(0), "{rep}");
    assert!(
        rep["causal_mrr_lift"].as_f64().unwrap_or(0.0) >= 0.99,
        "expected causal_mrr_lift >= 0.99: {rep}"
    );

    let bench_out = std::process::Command::new(bin)
        .args([
            "bench",
            "--suite",
            "learning",
            "--workspace",
            &ws.to_string_lossy(),
            "--json",
        ])
        .output()
        .expect("run libredb bench --suite learning");
    assert!(
        bench_out.status.success(),
        "bench --suite learning failed: {}\n{}",
        String::from_utf8_lossy(&bench_out.stderr),
        String::from_utf8_lossy(&bench_out.stdout)
    );
    let brep: serde_json::Value = serde_json::from_slice(&bench_out.stdout)
        .expect("parse bench --suite learning JSON");
    assert_eq!(brep["verdict"].as_str(), Some("VERIFIED_CAUSAL_LEARNING"), "{brep}");
    assert_eq!(brep["passed_stages"].as_u64(), Some(13), "{brep}");
    assert_eq!(brep["failed_stages"].as_u64(), Some(0), "{brep}");
    assert_eq!(brep["placebo_false_bindings"].as_u64(), Some(0), "{brep}");

    // Verify CLI learn-error, banal rejection, and learn-reflex --context/--supersedes/--outcome end-to-end
    let g_cli = global_ldb.to_string_lossy().to_string();
    let db_cli = ws.join(".agents/memory.ldb").to_string_lossy().to_string();
    assert!(std::process::Command::new(bin)
        .args(["trust", &ws.to_string_lossy(), "--global", &g_cli])
        .output()
        .expect("trust ws")
        .status
        .success());
    let banal_cli = std::process::Command::new(bin)
        .args([
            "learn-error",
            &db_cli,
            "error: expected ';', found '}'",
            "Add missing semicolon",
            "--global",
            &g_cli,
        ])
        .output()
        .expect("learn-error banal");
    assert!(banal_cli.status.success());
    assert!(
        String::from_utf8_lossy(&banal_cli.stdout).contains("Filtered banal syntax slip"),
        "{}",
        String::from_utf8_lossy(&banal_cli.stdout)
    );
    let real_cli = std::process::Command::new(bin)
        .args([
            "learn-error",
            &db_cli,
            "error[E0425]: cannot find value 'tx_budget_limit' in this scope",
            "Thread tx_budget_limit through execute_plan",
            "--symbols",
            "src/m0.rs::alpha_pipeline",
            "--global",
            &g_cli,
        ])
        .output()
        .expect("learn-error real");
    assert!(real_cli.status.success());
    assert!(
        String::from_utf8_lossy(&real_cli.stdout).contains("Learned error-recovery pitfall"),
        "{}",
        String::from_utf8_lossy(&real_cli.stdout)
    );
    let sup_cli = std::process::Command::new(bin)
        .args([
            "learn-reflex",
            &db_cli,
            "v15-ctx-rule",
            "Use v15 specialized context method.",
            "--action",
            "refactor",
            "--context",
            "inplace,strict",
            "--supersedes",
            "v15-old-rule",
            "--utility",
            "0.85",
            "--global",
            &g_cli,
        ])
        .output()
        .expect("learn-reflex with options");
    assert!(sup_cli.status.success(), "{}", String::from_utf8_lossy(&sup_cli.stderr));
    let out_cli = std::process::Command::new(bin)
        .args(["learn-reflex", &db_cli, "v15-ctx-rule", "--outcome", "fail", "--global", &g_cli])
        .output()
        .expect("learn-reflex outcome fail");
    assert!(out_cli.status.success(), "{}", String::from_utf8_lossy(&out_cli.stderr));
    assert!(
        String::from_utf8_lossy(&out_cli.stdout).contains("Recorded fail outcome"),
        "{}",
        String::from_utf8_lossy(&out_cli.stdout)
    );

    let _ = std::fs::remove_dir_all(&root);
}
