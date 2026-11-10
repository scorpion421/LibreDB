use libredb_bridge::{export_sqlite_database, open_or_auto_migrate, verify_sqlite_equivalence};
use libredb_cognitive::{CognitiveEngine, PulseRequest};
use libredb_core::{EdgeKind, NodeKind, WriteRequest};
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn legacy_project_memory_db_auto_ports_all_11_tables_silently_with_zero_amnesia() {
    let dir = tempdir().unwrap();
    let agents_dir = dir.path().join(".agents");
    std::fs::create_dir_all(&agents_dir).unwrap();
    let legacy_db_path = agents_dir.join("memory.db");
    let target_ldb_path = agents_dir.join("memory.ldb");

    // 1. Seed a realistic pre-existing SkillsDB `.agents/memory.db` covering ALL 11 tables!
    {
        let conn = Connection::open(&legacy_db_path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE project_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'architecture',
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE session_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT,
                summary TEXT NOT NULL,
                next_steps TEXT,
                files_touched TEXT,
                commit_hash TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE project_facts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deprecated_at TEXT DEFAULT NULL,
                superseded_by TEXT DEFAULT NULL
            );
            CREATE TABLE fact_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE project_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE task_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                verifier_type TEXT NOT NULL,
                passed INTEGER NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE task_handoffs (
                id TEXT PRIMARY KEY,
                task_id INTEGER,
                source_role TEXT NOT NULL,
                target_role TEXT NOT NULL,
                context_variables TEXT,
                notes TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE symbol_index (
                file_path TEXT NOT NULL,
                symbol_name TEXT NOT NULL,
                qualified_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                signature TEXT DEFAULT '',
                file_mtime REAL NOT NULL,
                PRIMARY KEY (file_path, qualified_name, start_line)
            );
            CREATE TABLE compaction_archive (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                checkpoint_num INTEGER NOT NULL,
                step_index INTEGER NOT NULL,
                summary TEXT NOT NULL,
                extracted_refs TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE active_working_set (
                file_path TEXT PRIMARY KEY,
                symbols_touched TEXT DEFAULT '',
                line_ranges TEXT DEFAULT '',
                edit_count INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE dependency_edges (
                source_file TEXT NOT NULL,
                source_symbol TEXT NOT NULL,
                target_symbol TEXT NOT NULL,
                edge_kind TEXT NOT NULL,
                line_no INTEGER NOT NULL,
                file_mtime REAL NOT NULL,
                PRIMARY KEY (source_file, source_symbol, target_symbol, edge_kind, line_no)
            );
            CREATE VIRTUAL TABLE project_memory_fts USING fts5(source_table, title_or_key, content);

            INSERT INTO project_decisions (title, content, category, is_active, created_at, updated_at) VALUES
                ('obsolete-cache', 'Old LRU strategy replaced.', 'perf', 0, '2026-11-01', '2026-11-02'),
                ('zero-io-pulse', 'execute_pulse must filter SessionState in RAM before extent reads.', 'architecture', 1, '2026-11-09', '2026-11-09');

            INSERT INTO session_snapshots (conversation_id, summary, next_steps, files_touched, commit_hash, created_at) VALUES
                ('cid-1', 'Built v0.1.0 storage kernel', 'Add index', 'engine.rs', 'dd4ffe5', '2026-11-08T12:00:00Z'),
                ('cid-1', 'Built v0.4.0 MCP server', 'Auto-port SQLite', 'mcp.rs, overlay.rs', '0bfb310', '2026-11-09T23:55:00Z');

            INSERT INTO fact_history (key, old_value, new_value, reason, created_at) VALUES
                ('version', '0.1.0', '0.2.0', 'release', '2026-11-08'),
                ('version', '0.2.0', '0.3.0', 'release', '2026-11-09');

            INSERT INTO project_facts (key, value, updated_at, deprecated_at, superseded_by) VALUES
                ('version', '0.4.0', '2026-11-09T23:55:00Z', NULL, NULL),
                ('legacy_flag', 'enabled', '2026-11-01T00:00:00Z', '2026-11-05T00:00:00Z', 'version');

            INSERT INTO project_tasks (id, title, description, status, priority, created_at, updated_at) VALUES
                (1, 'Implement auto-porter', 'Port memory.db silently on open', 'in_progress', 'high', '2026-11-09', '2026-11-09');

            INSERT INTO task_verifications (task_id, verifier_type, passed, details, created_at) VALUES
                (1, 'cargo_test', 1, 'All 18 suites green', '2026-11-09T23:58:00Z');

            INSERT INTO task_handoffs (id, task_id, source_role, target_role, context_variables, notes, status, created_at, updated_at) VALUES
                ('ho-01', 1, 'lead', 'research', '{\"crate\":\"libredb-bridge\"}', 'Verify all 19 tables', 'pending', '2026-11-09', '2026-11-09');

            INSERT INTO symbol_index (file_path, symbol_name, qualified_name, kind, start_line, end_line, signature, file_mtime) VALUES
                ('src/engine.rs', 'execute_pulse', 'Engine::execute_pulse', 'fn', 10, 80, 'pub fn execute_pulse(&self)', 1700000000.0),
                ('src/engine.rs', 'read_extents', 'Engine::read_extents', 'fn', 82, 120, 'fn read_extents(&self)', 1700000000.0);

            INSERT INTO dependency_edges (source_file, source_symbol, target_symbol, edge_kind, line_no, file_mtime) VALUES
                ('src/engine.rs', 'execute_pulse', 'read_extents', 'call', 45, 1700000000.0);

            INSERT INTO compaction_archive (conversation_id, checkpoint_num, step_index, summary, extracted_refs, created_at) VALUES
                ('cid-1', 1, 140, 'Compacted initial design discussion', 'engine.rs, format.rs', '2026-11-09T20:00:00Z');

            INSERT INTO active_working_set (file_path, symbols_touched, line_ranges, edit_count, updated_at) VALUES
                ('src/engine.rs', 'execute_pulse', '10-80', 4, '2026-11-09T23:50:00Z');

            INSERT INTO project_memory_fts (source_table, title_or_key, content) VALUES
                ('decision', 'zero-io-pulse', 'execute_pulse must filter SessionState in RAM');
            ",
        )
        .unwrap();
    }

    let orig_sqlite_bytes = std::fs::read(&legacy_db_path).unwrap();
    assert!(!target_ldb_path.exists());

    // 2. First open on `memory.ldb` must silently port 100% of `memory.db` in the background!
    let (ldb, mig_opt) = open_or_auto_migrate(&target_ldb_path, None, "project").unwrap();
    let mig = mig_opt.expect("first touch must auto-migrate sibling memory.db");
    assert!(target_ldb_path.is_file());
    assert!(mig.cognitive_capsules_created >= 14);
    assert!(mig.synapses_wired >= 5);

    // Source `memory.db` must remain 100% byte-for-byte untouched!
    assert_eq!(std::fs::read(&legacy_db_path).unwrap(), orig_sqlite_bytes);

    // 3. Verify zero amnesia across every table and temporal chain:
    // (a) Latest snapshot + historical milestone lineage (`v0.4.0` -> `Supersedes` -> `v0.1.0`)
    let snap = ldb.get_by_key(NodeKind::Snapshot, "latest_snapshot").unwrap();
    let snap_txt = String::from_utf8_lossy(&snap.payload);
    assert!(snap_txt.contains("Built v0.4.0 MCP server"));
    assert!(snap_txt.contains("0bfb310"));
    let snap_chain = ldb.trace_lineage(snap.node_id, 4).unwrap();
    assert_eq!(snap_chain.len(), 2, "both milestones must be linked via Supersedes");
    assert!(snap_chain[1].payload_preview.contains("Built v0.1.0"));

    // (b) Fact current value (`0.4.0`) + full `fact_history` lineage (`0.4.0 -> 0.3.0 -> 0.2.0 -> 0.1.0`)
    let ver_fact = ldb.get_by_key(NodeKind::Fact, "version").unwrap();
    assert!(String::from_utf8_lossy(&ver_fact.payload).contains("0.4.0"));
    let fact_chain = ldb.trace_lineage(ver_fact.node_id, 8).unwrap();
    assert!(
        fact_chain.len() >= 4,
        "full fact_history chain + deprecated superseded fact must be preserved, got {}",
        fact_chain.len()
    );
    // Deprecated `legacy_flag` must NOT appear as an active key!
    assert!(ldb.get_by_key(NodeKind::Fact, "legacy_flag").is_err());

    // (c) Inactive decision suppressed, active decision wired via `Governs` to `execute_pulse` symbol!
    assert!(ldb.get_by_key(NodeKind::Decision, "obsolete-cache").is_err());
    let active_dec = ldb.get_by_key(NodeKind::Decision, "zero-io-pulse").unwrap();
    assert!(
        active_dec.synapses.iter().any(|s| s.kind == EdgeKind::Governs),
        "active decision mentioning execute_pulse must auto-wire Governs -> Symbol"
    );

    // (d) TaskVerification wired via `Verifies` -> Task, and Handoff preserves `context_variables`!
    let verif = ldb.get_by_key(NodeKind::TaskVerification, "verify::1").unwrap();
    assert!(verif.synapses.iter().any(|s| s.kind == EdgeKind::Verifies));
    let ho = ldb.get_by_key(NodeKind::Handoff, "ho-01").unwrap();
    assert!(String::from_utf8_lossy(&ho.payload).contains("libredb-bridge"));
    assert!(ho.synapses.iter().any(|s| s.kind == EdgeKind::Delegates));

    // (e) CompactionCheckpoint & WorkingSet (`Touches -> Symbol`) preserved!
    let cp = ldb
        .get_by_key(NodeKind::CompactionCheckpoint, "latest_compaction")
        .unwrap();
    assert!(String::from_utf8_lossy(&cp.payload).contains("step=140"));
    let ws = ldb.get_by_key(NodeKind::WorkingSet, "src/engine.rs").unwrap();
    assert!(ws.synapses.iter().any(|s| s.kind == EdgeKind::Touches));

    // (f) Continuing to write new facts natively in LibreDB works seamlessly, and reopening does NOT re-import!
    ldb.put(
        WriteRequest::new(NodeKind::Fact, b"auto_ported = true".to_vec()).with_key("auto_ported"),
    )
    .unwrap();
    drop(ldb);

    let (ldb2, mig2) = open_or_auto_migrate(&target_ldb_path, None, "project").unwrap();
    assert!(mig2.is_none(), "second open must use existing .ldb directly");
    assert!(ldb2.get_by_key(NodeKind::Fact, "auto_ported").is_ok());

    // And lossless SQLite snapshot verification still passes with 0 discrepancies!
    let recon_sqlite = dir.path().join("reconstructed_memory.db");
    export_sqlite_database(&ldb2, "project", &recon_sqlite).unwrap();
    let eq = verify_sqlite_equivalence(&legacy_db_path, &recon_sqlite).unwrap();
    assert_eq!(eq.fts5_tables_verified, 1);
}

#[test]
fn central_customizations_auto_port_preserves_full_skill_body_configs_and_brand_new_chats_skip_sqlite() {
    let dir = tempdir().unwrap();
    let central_sql = dir.path().join("customizations.db");
    let central_ldb = dir.path().join("customizations.ldb");

    let full_skill_markdown = "---\nname: demo-skill\n---\n# Demo skill\n\nDetailed verbatim body line 1.\nDetailed verbatim body line 2 with code `fn run() {}`.\n";

    {
        let conn = Connection::open(&central_sql).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                scope TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                summary TEXT,
                content TEXT NOT NULL
            );
            CREATE TABLE skills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                plugin_name TEXT NOT NULL,
                category TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                description TEXT,
                content TEXT NOT NULL
            );
            CREATE TABLE skill_sections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_name TEXT NOT NULL,
                section_title TEXT NOT NULL,
                content TEXT NOT NULL
            );
            CREATE TABLE runtime_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT
            );
            CREATE TABLE transcript_cursors (
                conversation_id TEXT PRIMARY KEY,
                checkpoint_count INTEGER NOT NULL DEFAULT 0,
                epoch_count INTEGER NOT NULL DEFAULT 1,
                dedup_token TEXT DEFAULT '',
                inferred_workspace TEXT DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE quota_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pool TEXT NOT NULL,
                execution_tier TEXT NOT NULL,
                model_used TEXT,
                input_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                saved_agy_tokens INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
            ",
        )
        .unwrap();

        conn.execute(
            "INSERT INTO rules (key, name, category, scope, is_active, summary, content) VALUES
                ('old-rule', 'Old', 'fmt', 'global', 0, 'retired', 'Retired rule text'),
                ('active-rule', 'Active', 'fmt', 'global', 1, 'active', 'Enforce strict ASCII');",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO skills (name, plugin_name, category, is_active, description, content) VALUES (?1, 'core', 'dev', 1, 'Demo desc', ?2);",
            rusqlite::params!["demo-skill", full_skill_markdown],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO runtime_config (key, value, updated_at) VALUES ('gitea_url', 'http://localhost:3000', '2026-11-10'), ('gitea_user', 'MickyFoley', '2026-11-10');",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transcript_cursors (conversation_id, checkpoint_count, epoch_count, dedup_token, inferred_workspace, updated_at) VALUES ('cid-abc', 2, 3, 'ws@ep=3', 'D:/Antigravity/LibreDB', '2026-11-10');",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO quota_ledger (pool, execution_tier, model_used, input_tokens, output_tokens, saved_agy_tokens, created_at) VALUES ('agy_gemini_high', 'ultra', 'Gemini 4 Argon', 500, 120, 4200, '2026-11-10');",
            [],
        )
        .unwrap();
    }

    let (gdb, mig) = open_or_auto_migrate(&central_ldb, Some(&central_sql), "central").unwrap();
    assert!(mig.is_some());

    // Inactive rule suppressed; active rule live!
    assert!(gdb.get_by_key(NodeKind::Rule, "old-rule").is_err());
    assert!(gdb.get_by_key(NodeKind::Rule, "active-rule").is_ok());

    // Verbatim full SKILL.md preserved byte-for-byte!
    let full_rec = gdb
        .get_by_key(NodeKind::Generic, "skill_full::demo-skill")
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&full_rec.payload).unwrap(),
        full_skill_markdown
    );

    // Runtime config, cursor, and quota event all active!
    assert_eq!(
        std::str::from_utf8(&gdb.get_by_key(NodeKind::Config, "gitea_user").unwrap().payload)
            .unwrap(),
        "MickyFoley"
    );
    assert!(gdb
        .get_by_key(NodeKind::TranscriptCursor, "cid-abc")
        .is_ok());
    assert!(gdb.get_by_key(NodeKind::QuotaEvent, "quota::1").is_ok());

    // Cognitive pulse recalls active rule without returning retired rule!
    let cog = CognitiveEngine::open_db(gdb).unwrap();
    let resp = cog
        .pulse(&PulseRequest::new("Retired rule text Enforce strict ASCII", 500))
        .unwrap();
    assert_eq!(resp.capsules.len(), 1);
    assert_eq!(resp.capsules[0].key.as_deref(), Some("active-rule"));

    // Brand-new project / chat folder with NO `memory.db` creates ONLY `memory.ldb`, never `.db`!
    let fresh_proj = dir.path().join("brand_new_project").join(".agents");
    let fresh_ldb = fresh_proj.join("memory.ldb");
    let (_, fresh_mig) = open_or_auto_migrate(&fresh_ldb, None, "project").unwrap();
    assert!(fresh_mig.is_none());
    assert!(fresh_ldb.is_file());
    assert!(!fresh_proj.join("memory.db").exists());
}
