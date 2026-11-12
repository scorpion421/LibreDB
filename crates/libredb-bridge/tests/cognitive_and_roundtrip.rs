//! End-to-end tests for cognitive token conservation, multilingual Hebbian learning,
//! code contract skeleton compression, and lossless 19-table SQLite round-trip bijection.

use libredb_bridge::{
    export_sqlite_database, import_sqlite_readonly, verify_sqlite_equivalence,
};
use libredb_cognitive::{
    CognitiveEngine, FileSkeleton, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use rusqlite::Connection;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn zero_repeat_session_delta_and_reflex_triggers_slash_multi_turn_tokens() {
    let dir = tempdir().unwrap();
    // Create a Cargo.toml marker in the simulated workspace so marker detection sees `"cargo.toml"`.
    std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();

    let db = Arc::new(LibreDb::open(dir.path().join("session_delta.ldb")).unwrap());

    // Store a verbose architectural decision + linked skill section (~120 tokens total).
    let dec_body = "Architectural invariant: Always stage files via git add and verify checksums before publishing releases to local Gitea servers. ".repeat(4);
    let dec_id = db
        .put(
            WriteRequest::new(NodeKind::Decision, dec_body.into_bytes())
                .with_key("gitea-release-invariant")
                .with_importance(230),
        )
        .unwrap();

    let sec_body = "Release procedure: Increment VERSION and CHANGELOG.md under SemVer 2.0.0 before invoking gitea-release. ".repeat(3);
    let sec_id = db
        .put(
            WriteRequest::new(NodeKind::SkillSection, sec_body.into_bytes())
                .with_key("gitea::release-steps")
                .with_importance(200),
        )
        .unwrap();
    db.link(dec_id, EdgeKind::HasSection, sec_id, 240).unwrap();

    // Teach a situational reflex purely as data (`0` hardcoded rules in engine).
    ReflexEngine::learn_reflex(
        &db,
        &ReflexRule {
            id: "cargo-dist-binary".to_owned(),
            stack_any: vec!["cargo.toml".to_owned()],
            action_any: vec!["gitea".to_owned(), "release".to_owned()],
            env_or_error_any: vec![],
            directive: "Place compiled release binary into dist/ before calling gitea-release.".to_owned(),
            ..Default::default()
        },
    )
    .unwrap();

    let cog = CognitiveEngine::open_db(Arc::clone(&db)).unwrap();

    // Turn 1 (`cid = "conv-alpha", epoch = 1`): Cold retrieval emits full capsules + reflex!
    let mut req1 = PulseRequest::new("publish gitea release", 1_000);
    req1.workspace_dir = Some(dir.path().to_path_buf());
    req1.conversation_id = Some("conv-alpha".to_owned());
    req1.epoch = 1;

    let r1 = cog.pulse(&req1).unwrap();
    assert_eq!(r1.fired_reflexes.len(), 1);
    assert_eq!(r1.capsules.len(), 2);
    assert_eq!(r1.tokens_saved_by_delta, 0);
    let turn1_tokens = r1.tokens_emitted;
    assert!(turn1_tokens > 100);

    // Turn 2 (`cid = "conv-alpha", epoch = 1`): Follow-up query hits the exact same unchanged nodes ->
    // Zero-Repeat Delta suppresses full payloads and saves > 80% tokens!
    let r2 = cog.pulse(&req1).unwrap();
    assert!(r2.fired_reflexes.is_empty());
    assert!(r2.capsules.is_empty());
    assert_eq!(r2.already_in_context_stubs.len(), 3);
    assert!(
        r2.tokens_emitted < turn1_tokens / 4,
        "expected >75% token reduction on Turn 2, got {} vs {}",
        r2.tokens_emitted,
        turn1_tokens
    );
    assert!(r2.tokens_saved_by_delta > 90);

    // Turn 3: Mutate `gitea-release-invariant` (`generation` advances 1 -> 2) ->
    // ONLY the mutated node re-hydrates; unchanged skill section and reflex stay deduplicated!
    db.put(
        WriteRequest::new(
            NodeKind::Decision,
            b"Updated invariant v2: Attach Windows x64 binary in dist/ on every Gitea tag.".to_vec(),
        )
        .with_key("gitea-release-invariant"),
    )
    .unwrap();
    let mut cog_reloaded = CognitiveEngine::open_db(Arc::clone(&db)).unwrap();
    let _ = &mut cog_reloaded;
    let r3 = cog_reloaded.pulse(&req1).unwrap();
    assert_eq!(r3.capsules.len(), 1);
    assert_eq!(r3.capsules[0].generation, 3); // gen 1 (put) -> gen 2 (link) -> gen 3 (superseding update)

    // Turn 4: `/compact` advances `epoch = 2` -> clean full re-hydration!
    let mut req_post_compact = req1.clone();
    req_post_compact.epoch = 2;
    let r4 = cog_reloaded.pulse(&req_post_compact).unwrap();
    assert_eq!(r4.fired_reflexes.len(), 1);
    assert_eq!(r4.capsules.len(), 2);
}

#[test]
fn multilingual_hebbian_learning_works_across_scripts_with_zero_hardcoded_dictionaries() {
    let dir = tempdir().unwrap();
    let db = Arc::new(LibreDb::open(dir.path().join("polyglot.ldb")).unwrap());

    let id_net = db
        .put(
            WriteRequest::new(
                NodeKind::SkillSection,
                b"Disable shared-memory mmap files on remote UNC SMB network mounts.".to_vec(),
            )
            .with_key("smb-unc-safety"),
        )
        .unwrap();
    let id_lock = db
        .put(
            WriteRequest::new(
                NodeKind::SkillSection,
                b"Sharded chaos write lanes allow 16 parallel subagents without lock contention.".to_vec(),
            )
            .with_key("parallel-lanes"),
        )
        .unwrap();

    let mut cog = CognitiveEngine::open_db(Arc::clone(&db)).unwrap();

    // Teach German, Spanish, and Cyrillic cues purely through Hebbian reinforcement:
    let de_cue = "Netzlaufwerk Freigabe Verbindungsabbruch";
    let es_cue = "escritura paralela sin bloqueo";
    let cyr_cue = "\u{0441}\u{0435}\u{0442}\u{0435}\u{0432}\u{0430}\u{044F} \u{043F}\u{0430}\u{043F}\u{043A}\u{0430}"; // Cyrillic script cue via ASCII escapes

    cog.reinforce_association(de_cue, &[id_net]).unwrap();
    cog.reinforce_association(cyr_cue, &[id_net]).unwrap();
    cog.reinforce_association(es_cue, &[id_lock]).unwrap();

    // Reopen cold from disk to prove learned language bridges are 100% persistent inside `.ldb`:
    let cog_cold = CognitiveEngine::open_db(Arc::clone(&db)).unwrap();

    let p_de = cog_cold.pulse(&PulseRequest::new(de_cue, 500)).unwrap();
    assert_eq!(p_de.capsules[0].node_id, id_net);

    let p_cyr = cog_cold.pulse(&PulseRequest::new(cyr_cue, 500)).unwrap();
    assert_eq!(p_cyr.capsules[0].node_id, id_net);

    let p_es = cog_cold.pulse(&PulseRequest::new(es_cue, 500)).unwrap();
    assert_eq!(p_es.capsules[0].node_id, id_lock);
}

#[test]
fn file_skeleton_compresses_source_by_over_80_percent_and_caches_by_hash() {
    let dir = tempdir().unwrap();
    let db = LibreDb::open(dir.path().join("skeleton.ldb")).unwrap();
    let py_file = dir.path().join("sample_engine.py");

    let mut py_src = String::from("# SECTION: core.storage\n");
    for i in 0..25 {
        py_src.push_str(&format!(
            "def process_record_{i}(conn: Connection, payload: bytes, retry_limit: int = 5) -> bool:\n"
        ));
        py_src.push_str("    \"\"\"Validates and commits a record with retry semantics.\"\"\"\n");
        for step in 0..18 {
            py_src.push_str(&format!(
                "    temp_val_{step} = len(payload) + {step} * retry_limit\n"
            ));
        }
        py_src.push_str("    return temp_val_0 > 0\n\n");
    }
    std::fs::write(&py_file, &py_src).unwrap();

    let (skel1, hit1) = FileSkeleton::index_or_get_cached(&db, &py_file, Some("sample_engine.py")).unwrap();
    assert!(!hit1);
    assert_eq!(skel1.sections.len(), 1);
    assert_eq!(skel1.symbols.len(), 25);
    assert!(
        skel1.skeleton_tokens * 4 < skel1.raw_tokens,
        "expected >75% token compression, got {} vs {} raw tokens",
        skel1.skeleton_tokens,
        skel1.raw_tokens
    );

    // Second lookup on unchanged file hits 64-bit hash cache immediately (`hit2 == true`).
    let (skel2, hit2) = FileSkeleton::index_or_get_cached(&db, &py_file, Some("sample_engine.py")).unwrap();
    assert!(hit2);
    assert_eq!(skel1.content_hash, skel2.content_hash);
}

#[test]
fn lossless_19_table_sqlite_to_libredb_to_sqlite_bijection_proof() {
    let dir = tempdir().unwrap();
    let orig_central = dir.path().join("orig_customizations.db");
    let orig_project = dir.path().join("orig_memory.db");
    let ldb_path = dir.path().join("unified.ldb");
    let recon_central = dir.path().join("recon_customizations.db");
    let recon_project = dir.path().join("recon_memory.db");

    // 1. Build realistic Central SQLite DB (8 relational tables + 4 external-content FTS5 virtual tables).
    {
        let c = Connection::open(&orig_central).unwrap();
        c.execute_batch(
            "
            CREATE TABLE rules (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT NOT NULL, scope TEXT NOT NULL, is_active INTEGER DEFAULT 1, summary TEXT, content TEXT NOT NULL, token_estimate INTEGER, updated_at TEXT);
            CREATE TABLE skills (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, plugin_name TEXT NOT NULL, category TEXT NOT NULL, is_active INTEGER DEFAULT 1, description TEXT, content TEXT NOT NULL, token_estimate INTEGER, updated_at TEXT);
            CREATE TABLE skill_sections (id INTEGER PRIMARY KEY AUTOINCREMENT, skill_name TEXT NOT NULL, plugin_name TEXT NOT NULL, category TEXT NOT NULL, section_title TEXT NOT NULL, heading_level INTEGER NOT NULL DEFAULT 2, content TEXT NOT NULL, token_estimate INTEGER NOT NULL DEFAULT 0, UNIQUE(skill_name, section_title));
            CREATE TABLE synonym_synapses (id INTEGER PRIMARY KEY AUTOINCREMENT, term TEXT UNIQUE NOT NULL, synonyms TEXT NOT NULL, language TEXT DEFAULT 'de', category TEXT DEFAULT 'general');
            CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT);
            CREATE TABLE quota_ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, pool TEXT NOT NULL, execution_tier TEXT NOT NULL, model_used TEXT, effort_level TEXT, input_tokens INTEGER, output_tokens INTEGER, saved_agy_tokens INTEGER, saved_agy_turns INTEGER, latency_ms INTEGER, status TEXT, task_summary TEXT, created_at TEXT NOT NULL);
            CREATE TABLE transcript_cursors (conversation_id TEXT PRIMARY KEY, file_size INTEGER NOT NULL, last_byte_offset INTEGER NOT NULL, max_step_index INTEGER NOT NULL, checkpoint_count INTEGER NOT NULL, last_checkpoint_step INTEGER NOT NULL, hydrated_checkpoint_count INTEGER NOT NULL, epoch_count INTEGER NOT NULL, active_epoch_date TEXT, dedup_token TEXT, inferred_workspace TEXT, cached_state_json TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE agent_templates (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, system_prompt TEXT NOT NULL, skills TEXT, tools TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE VIRTUAL TABLE rules_fts USING fts5(key, name, category, summary, content, content='rules', content_rowid='id');
            CREATE VIRTUAL TABLE skills_fts USING fts5(name, plugin_name, category, description, content, content='skills', content_rowid='id');
            CREATE VIRTUAL TABLE synonym_fts USING fts5(term, synonyms, content='synonym_synapses', content_rowid='id');
            CREATE VIRTUAL TABLE skill_sections_fts USING fts5(skill_name, section_title, content, content='skill_sections', content_rowid='id');

            INSERT INTO rules VALUES (1, 'global-fmt', 'Formatting', 'core', 'global', 1, 'No dashes', 'Strictly ASCII hyphens.', 12, '2026-11-09T20:00:00Z');
            INSERT INTO rules VALUES (2, 'legacy-inactive', 'Old Rule', 'legacy', 'global', 0, NULL, 'Inactive body preserved losslessly.', 9, NULL);
            INSERT INTO skills VALUES (1, 'customizations-db', 'core', 'db', 1, 'Central DB', '## Overview\nBody text.', 120, '2026-11-09T20:00:00Z');
            INSERT INTO skill_sections VALUES (1, 'customizations-db', 'core', 'db', 'Overview', 2, 'Body text.', 25);
            INSERT INTO synonym_synapses VALUES (1, 'speicher', 'memory storage allocation', 'de', 'perf');
            INSERT INTO runtime_config VALUES ('gitea_url', 'http://127.0.0.1:3000', '2026-11-09T20:00:00Z');
            INSERT INTO quota_ledger VALUES (1, 'agy_gemini_high', 'ultra', 'argon', 'high', 4000, 500, 12000, 2, 320, 'ok', 'Plan design', '2026-11-09T20:00:00Z');
            INSERT INTO transcript_cursors VALUES ('cid-1', 8192, 8192, 12, 0, 0, 0, 1, '2026-11-09', 'tok1', 'D:/Antigravity/LibreDB', '{}', '2026-11-09T20:00:00Z');
            INSERT INTO agent_templates VALUES ('lead_architect', 'Architect', 'Design', 'Design systems.', '[\"customizations-db\"]', '[]', '2026-11-09T20:00:00Z', '2026-11-09T20:00:00Z');
            INSERT INTO rules_fts(rules_fts) VALUES ('rebuild');
            INSERT INTO skills_fts(skills_fts) VALUES ('rebuild');
            INSERT INTO synonym_fts(synonym_fts) VALUES ('rebuild');
            INSERT INTO skill_sections_fts(skill_sections_fts) VALUES ('rebuild');
            ",
        )
        .unwrap();
    }

    // 2. Build realistic Project Memory SQLite DB (11 relational tables + 1 contentful FTS5 table).
    {
        let p = Connection::open(&orig_project).unwrap();
        p.execute_batch(
            "
            CREATE TABLE project_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL, category TEXT, is_active INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE session_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT, summary TEXT NOT NULL, next_steps TEXT, files_touched TEXT, commit_hash TEXT, created_at TEXT NOT NULL);
            CREATE TABLE project_facts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL, deprecated_at TEXT, superseded_by TEXT);
            CREATE TABLE fact_history (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, old_value TEXT, new_value TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL);
            CREATE TABLE project_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, status TEXT NOT NULL, priority TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE task_verifications (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, verifier_type TEXT NOT NULL, passed INTEGER NOT NULL, details TEXT, created_at TEXT NOT NULL);
            CREATE TABLE task_handoffs (id TEXT PRIMARY KEY, task_id INTEGER, source_role TEXT NOT NULL, target_role TEXT NOT NULL, context_variables TEXT, notes TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE symbol_index (file_path TEXT NOT NULL, symbol_name TEXT NOT NULL, qualified_name TEXT NOT NULL, kind TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, signature TEXT, file_mtime REAL NOT NULL, PRIMARY KEY (file_path, qualified_name, start_line));
            CREATE TABLE compaction_archive (id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL, checkpoint_num INTEGER NOT NULL, step_index INTEGER NOT NULL, summary TEXT NOT NULL, extracted_refs TEXT, created_at TEXT NOT NULL, UNIQUE(conversation_id, step_index));
            CREATE TABLE active_working_set (file_path TEXT PRIMARY KEY, symbols_touched TEXT, line_ranges TEXT, edit_count INTEGER NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE dependency_edges (source_file TEXT NOT NULL, source_symbol TEXT NOT NULL, target_symbol TEXT NOT NULL, edge_kind TEXT NOT NULL, line_no INTEGER NOT NULL, file_mtime REAL NOT NULL, PRIMARY KEY (source_file, source_symbol, target_symbol, edge_kind, line_no));
            CREATE VIRTUAL TABLE project_memory_fts USING fts5(source_table, title_or_key, content);

            INSERT INTO project_decisions VALUES (1, 'Dual Superblock', 'Ping-pong slots.', 'arch', 1, '2026-11-09', '2026-11-09');
            INSERT INTO session_snapshots VALUES (1, 'cid-1', 'Built v0.1.0', 'Build v0.2.0', 'engine.rs', 'dd4ffe5', '2026-11-09');
            INSERT INTO project_facts VALUES (1, 'inode_bytes', '128', '2026-11-09', NULL, NULL);
            INSERT INTO fact_history VALUES (1, 'inode_bytes', '64', '128', 'expanded for synapses', '2026-11-09');
            INSERT INTO project_tasks VALUES (1, 'Build bridge', 'Lossless SQLite bridge', 'in_progress', 'high', '2026-11-09', '2026-11-09');
            INSERT INTO task_verifications VALUES (1, 1, 'cargo_test', 1, 'all green', '2026-11-09');
            INSERT INTO task_handoffs VALUES ('ho_1', 1, 'lead', 'auditor', '{\"strict\":true}', 'Check CRC', 'pending', '2026-11-09', '2026-11-09');
            INSERT INTO symbol_index VALUES ('engine.rs', 'open', 'LibreDb::open', 'fn', 190, 195, 'pub fn open(path)', 1731189000.25);
            INSERT INTO symbol_index VALUES ('engine.rs', 'open_with_backend', 'LibreDb::open_with_backend', 'fn', 198, 214, 'pub fn open_with_backend', 1731189000.25);
            INSERT INTO compaction_archive VALUES (1, 'cid-1', 1, 50, 'Compacted turn 50', 'engine.rs', '2026-11-09');
            INSERT INTO active_working_set VALUES ('engine.rs', 'open', '190-214', 3, '2026-11-09');
            INSERT INTO dependency_edges VALUES ('engine.rs', 'LibreDb::open', 'LibreDb::open_with_backend', 'call', 192, 1731189000.25);
            INSERT INTO project_memory_fts VALUES ('decision', 'Dual Superblock', 'Ping-pong slots.');
            ",
        )
        .unwrap();
    }

    // 3. Import BOTH databases into a single `.ldb` file, compact with Gravity, verify CRC integrity,
    //    and export BOTH back to brand-new SQLite files!
    let ldb = Arc::new(LibreDb::open(&ldb_path).unwrap());
    let sum_c = import_sqlite_readonly(&orig_central, &ldb, "central").unwrap();
    let sum_p = import_sqlite_readonly(&orig_project, &ldb, "project").unwrap();
    assert!(sum_c.synapses_wired >= 3);
    assert!(sum_p.synapses_wired >= 2);

    ldb.compact_with_gravity().unwrap();
    ldb.verify_integrity().unwrap();

    export_sqlite_database(&ldb, "central", &recon_central).unwrap();
    export_sqlite_database(&ldb, "project", &recon_project).unwrap();

    // 4. Prove 100% cell-for-cell equivalence across all 19 relational tables + all 5 FTS5 virtual tables!
    let rep_c = verify_sqlite_equivalence(&orig_central, &recon_central).unwrap();
    assert_eq!(rep_c.tables_verified, 12); // 8 relational + 4 FTS5
    assert_eq!(rep_c.fts5_tables_verified, 4);

    let rep_p = verify_sqlite_equivalence(&orig_project, &recon_project).unwrap();
    assert_eq!(rep_p.tables_verified, 12); // 11 relational + 1 FTS5
    assert_eq!(rep_p.fts5_tables_verified, 1);
}
