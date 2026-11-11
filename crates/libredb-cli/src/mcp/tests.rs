use super::{canonical_brain_cache_key, handle_rpc_method, process_mcp_stream, McpServerState};
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
        use handle_rpc_method;
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
        use super::authz::resolve_canonical_workspace_lock_root;
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
        use handle_rpc_method;
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
        use handle_rpc_method;
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
        use handle_rpc_method;
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
        use handle_rpc_method;
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
        use process_mcp_stream;
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
        // on `ws_a` BEFORE replying to `libredb-roots-2` -> server MUST suspend client roots immediately
        // (fail-closed) while preserving `eph_a_file` until `roots/list` confirms whether `ws_a` was closed!
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
            "Client workspace ws_a MUST fail closed while roots/list refresh is pending!"
        );
        assert!(
            eph_a_file.is_file(),
            "Ephemeral .ldb for ws_a MUST be preserved during pending roots/list refresh until removal is confirmed!"
        );

        // Phase 4: Client replies to `libredb-roots-2` with `[ws_b]` -> `ws_a` is now confirmed removed
        // (its ephemeral `.ldb` is deleted and calls stay denied), while `ws_b` succeeds!
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
        assert!(
            !eph_a_file.exists(),
            "Ephemeral .ldb file for confirmed-closed ws_a MUST be deleted once roots/list excludes ws_a!"
        );
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
        use handle_rpc_method;
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

    struct ToggleFaultBackend {
        inner: libredb_core::OsFileBackend,
        fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,
        fail_reads: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl libredb_core::StorageBackend for ToggleFaultBackend {
        fn len(&self) -> libredb_core::Result<u64> {
            self.inner.len()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> libredb_core::Result<()> {
            if offset >= 8192 && self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(libredb_core::LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "simulated storage read failure",
                )));
            }
            self.inner.read_at(offset, buf)
        }

        fn read_ops_count(&self) -> u64 {
            self.inner.read_ops_count()
        }

        fn write_ops_count(&self) -> u64 {
            self.inner.write_ops_count()
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> libredb_core::Result<()> {
            if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(libredb_core::LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "simulated disk full during SessionState save",
                )));
            }
            self.inner.write_at(offset, buf)
        }

        fn sync_data(&self) -> libredb_core::Result<()> {
            if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(libredb_core::LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "simulated fsync failure during SessionState save",
                )));
            }
            self.inner.sync_data()
        }

        fn set_len(&self, new_len: u64) -> libredb_core::Result<()> {
            if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(libredb_core::LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "simulated set_len failure",
                )));
            }
            self.inner.set_len(new_len)
        }

        fn lock_write_region(&self) -> libredb_core::Result<()> {
            self.inner.lock_write_region()
        }

        fn unlock_write_region(&self) -> libredb_core::Result<()> {
            self.inner.unlock_write_region()
        }
    }

    #[test]
    fn mcp_skeleton_handles_simulated_session_write_failures_and_propagates_corrupt_session_loads() {
        use serde_json::json;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let tmp = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "test_mcp_zero_repeat_fault_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
        let _ = fs::remove_dir_all(&tmp);
        let ws = tmp.join("ws_fault");
        fs::create_dir_all(ws.join("src")).unwrap();
        let src_file = ws.join("src").join("engine_demo.rs");
        fs::write(
            &src_file,
            "pub struct ZeroRepeatDemo {\n    pub count: u64,\n}\n\npub fn compute_demo_value(x: u64) -> u64 {\n    x.saturating_add(42)\n}\n",
        )
        .unwrap();

        let missing_global = tmp.join("no_global.ldb");
        let mut state = McpServerState::new_with_workspace_root(
            None,
            Some(&missing_global),
            Some(&ws),
        )
        .unwrap();

        // Mount a fault-injecting StorageBackend for the workspace's ephemeral `.ldb` brain:
        let eph_ldb_path = state.ephemeral_workspace_ldb_path(&ws).unwrap();
        let cache_key = canonical_brain_cache_key(&eph_ldb_path);
        let fail_writes = Arc::new(AtomicBool::new(false));
        let fail_reads = Arc::new(AtomicBool::new(false));

        // Pre-initialize valid LIBREDB1 superblocks before arming `fail_writes`:
        let inner_backend = libredb_core::OsFileBackend::open(&eph_ldb_path).unwrap();
        let fault_backend = Arc::new(ToggleFaultBackend {
            inner: inner_backend,
            fail_writes: Arc::clone(&fail_writes),
            fail_reads: Arc::clone(&fail_reads),
        });
        let fault_db = Arc::new(
            LibreDb::open_with_backend_and_path(fault_backend, &eph_ldb_path).unwrap(),
        );
        let fault_brain = libredb_cognitive::OverlayBrain::open(None, Arc::clone(&fault_db)).unwrap();
        state.brains.insert(cache_key.clone(), fault_brain);

        // 1. Arm simulated storage write failure (`ENOSPC` / `StorageFull`):
        //    Turn 1 MUST NOT silently discard `sess.save(&proj_db)`; it must emit the explicit
        //    degraded-persistence warning AND populate bounded in-RAM session state!
        fail_writes.store(true, Ordering::SeqCst);
        let turn1 = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/engine_demo.rs",
                    "cid": "conv-write-fault-1"
                }
            }),
            &mut state,
        )
        .expect("Turn 1 skeleton under write fault must degrade gracefully to in-RAM session mode");
        let turn1_txt = turn1["content"][0]["text"].as_str().unwrap();
        assert!(
            turn1_txt.contains("compute_demo_value"),
            "Turn 1 must still deliver full contract skeleton: {turn1_txt}"
        );
        assert!(
            turn1_txt.contains("[WARN: Zero-Repeat persistence degraded to in-RAM session mode"),
            "Turn 1 must surface explicit Zero-Repeat write-failure warning instead of swallowing `let _ = sess.save`: {turn1_txt}"
        );

        // Confirm `session_delta::conv-write-fault-1` was indeed NOT persisted to disk:
        assert!(
            fault_db
                .get_by_key(
                    NodeKind::TranscriptCursor,
                    "session_delta::conv-write-fault-1"
                )
                .is_err(),
            "Disk DB must not contain session_delta while writes are failing"
        );

        // 2. Turn 2 (still under write failure in the same MCP session) MUST STILL suppress
        //    duplicate skeleton tokens via `ram_session_fallback` (zero wasted context tokens!):
        let turn2 = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/engine_demo.rs",
                    "cid": "conv-write-fault-1"
                }
            }),
            &mut state,
        )
        .unwrap();
        let turn2_txt = turn2["content"][0]["text"].as_str().unwrap();
        assert!(
            turn2_txt.contains("[Zero-Repeat Skeleton]"),
            "Turn 2 must suppress duplicate skeleton via in-RAM fallback even when disk save failed: {turn2_txt}"
        );
        assert!(
            turn2_txt.contains("[WARN: Zero-Repeat persistence degraded to in-RAM session mode"),
            "Turn 2 must continue reporting degraded persistence while disk writes fail: {turn2_txt}"
        );

        // Legacy `libredb_skeleton` alias must share the exact same session continuity:
        let alias_turn = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_skeleton",
                "arguments": {
                    "file_path": "src/engine_demo.rs",
                    "cid": "conv-write-fault-1"
                }
            }),
            &mut state,
        )
        .unwrap();
        let alias_txt = alias_turn["content"][0]["text"].as_str().unwrap();
        assert!(
            alias_txt.contains("[Zero-Repeat Skeleton]"),
            "Legacy libredb_skeleton must also honor Zero-Repeat SessionState: {alias_txt}"
        );

        // 3. Recover disk writes: Turn 3 flushes the merged session to disk and clears the warning & RAM fallback!
        fail_writes.store(false, Ordering::SeqCst);
        let turn3 = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/engine_demo.rs",
                    "cid": "conv-write-fault-1"
                }
            }),
            &mut state,
        )
        .unwrap();
        let turn3_txt = turn3["content"][0]["text"].as_str().unwrap();
        assert!(turn3_txt.contains("[Zero-Repeat Skeleton]"));
        assert!(
            !turn3_txt.contains("[WARN: Zero-Repeat persistence degraded"),
            "Warning must clear once disk persistence succeeds: {turn3_txt}"
        );
        assert!(
            state.ram_session_fallback.is_empty(),
            "In-RAM fallback map must be cleared once disk save succeeds"
        );
        assert!(
            fault_db
                .get_by_key(
                    NodeKind::TranscriptCursor,
                    "session_delta::conv-write-fault-1"
                )
                .is_ok(),
            "Recovered disk save must persist session_delta capsule"
        );

        // 4. Corrupt `session_delta::<cid>` JSON (or storage read failure during `SessionState::load_or_init`)
        //    MUST fail closed (`Err`) instead of being silently swallowed via `.ok()`!
        fault_db
            .put(
                WriteRequest::new(NodeKind::TranscriptCursor, b"{corrupt_json!!!".to_vec())
                    .with_key("session_delta::conv-corrupt"),
            )
            .unwrap();
        let corrupt_err = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/engine_demo.rs",
                    "cid": "conv-corrupt"
                }
            }),
            &mut state,
        )
        .expect_err("Corrupt session_delta JSON must return an explicit error instead of `.ok()`");
        assert!(
            corrupt_err.contains("corrupt session_delta json"),
            "Unexpected error for corrupt session_delta: {corrupt_err}"
        );

        fail_reads.store(true, Ordering::SeqCst);
        let read_err = handle_rpc_method(
            "tools/call",
            &json!({
                "name": "libredb_code",
                "arguments": {
                    "action": "skeleton",
                    "target": "src/engine_demo.rs",
                    "cid": "conv-write-fault-1"
                }
            }),
            &mut state,
        )
        .expect_err("Storage read error during SessionState::load_or_init must fail closed");
        assert!(
            read_err.contains("simulated storage read failure"),
            "Unexpected error for storage read failure: {read_err}"
        );
        fail_reads.store(false, Ordering::SeqCst);

        drop(state);
        let _ = fs::remove_dir_all(&tmp);
    }
