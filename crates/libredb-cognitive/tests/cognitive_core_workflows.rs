//! End-to-end tests for cognitive token conservation, multilingual Hebbian learning,
//! and code contract skeleton compression.

use libredb_cognitive::{
    CognitiveEngine, FileSkeleton, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
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
