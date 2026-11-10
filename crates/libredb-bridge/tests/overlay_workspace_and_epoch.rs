//! Verification suite for `LibreDB v0.3.0`:
//! - Dual-layer `OverlayBrain` (`customizations.ldb` + `memory.ldb`) with cross-layer `Zero-Repeat Delta`,
//! - Binary-safe `index_workspace` + automatic `Calls` & `Decision -> Governs -> Symbol` wiring,
//! - `query_symbol_impact` blast-radius & `extract_fim_slice` surgical edit windows,
//! - Incremental `sync_transcript_epoch` `/compact` detection + `execute_atomic_batch` + `handoff`.

use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, index_workspace,
    query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, OverlayBrain,
    PulseRequest,
};
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn overlay_brain_merges_global_and_project_memory_without_id_collisions() {
    let dir = tempdir().unwrap();
    let global_db = Arc::new(LibreDb::open(dir.path().join("global.ldb")).unwrap());
    let project_db = Arc::new(LibreDb::open(dir.path().join("project.ldb")).unwrap());

    // Both DBs independently allocate `NodeId = 1`! OverlayBrain must isolate their session namespaces.
    let g_id = global_db
        .put(
            WriteRequest::new(
                NodeKind::Rule,
                "Global formatting rule: strictly use standard ASCII hyphens in Gitea release notes. "
                    .repeat(3)
                    .into_bytes(),
            )
            .with_key("global-gitea-fmt")
            .with_importance(220),
        )
        .unwrap();
    assert_eq!(g_id, 1);
    CognitiveEngine::open_db(Arc::clone(&global_db))
        .unwrap()
        .save_index_snapshot()
        .unwrap();

    let p_id = project_db
        .put(
            WriteRequest::new(
                NodeKind::Decision,
                "Project Gitea release target: attach Windows x64 binary into dist/ folder. "
                    .repeat(3)
                    .into_bytes(),
            )
            .with_key("proj-gitea-dist")
            .with_importance(230),
        )
        .unwrap();
    assert_eq!(p_id, 1);
    CognitiveEngine::open_db(Arc::clone(&project_db))
        .unwrap()
        .save_index_snapshot()
        .unwrap();

    let brain = OverlayBrain::open(Some(global_db), project_db).unwrap();

    let mut req = PulseRequest::new("Gitea release binary notes", 800);
    req.conversation_id = Some("overlay-conv-1".to_owned());
    req.epoch = 1;

    // Turn 1: Delivers BOTH `proj::proj-gitea-dist` and `global::global-gitea-fmt` despite both having `node_id == 1`!
    let r1 = brain.pulse(&req).unwrap();
    assert_eq!(r1.capsules.len(), 2);
    assert!(r1
        .capsules
        .iter()
        .any(|c| c.key.as_deref() == Some("proj::proj-gitea-dist")));
    assert!(r1
        .capsules
        .iter()
        .any(|c| c.key.as_deref() == Some("global::global-gitea-fmt")));

    // Turn 2: Both global#1 and proj#1 are suppressed via Zero-Repeat Delta in RAM (`0` I/O reads)!
    let r2 = brain.pulse(&req).unwrap();
    assert!(r2.capsules.is_empty());
    assert_eq!(r2.already_in_context_stubs.len(), 2);
    assert_eq!(r2.coalesced_io_reads, 0, "expected 0 payload disk reads on deduplicated Turn 2");
    assert!(r2.tokens_saved_by_delta > 20);
}

#[test]
fn workspace_indexer_skips_binaries_wires_calls_and_connects_governing_decisions_to_fim() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    let target_dir = dir.path().join("target");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&target_dir).unwrap();

    // Write a fake binary `.rlib` and an arbitrary file containing NUL bytes to prove binary immunity!
    std::fs::write(target_dir.join("fake.rlib"), b"\x00\xFF\xFEbinary_noise").unwrap();
    std::fs::write(src_dir.join("embedded_blob.rs"), b"fn bad()\x00\x01\x02").unwrap();

    std::fs::write(
        src_dir.join("storage.rs"),
        r#"/// Persists durable block frames with hardware checksums.
pub fn write_durable_frame(buf: &[u8]) -> bool {
    !buf.is_empty()
}
"#,
    )
    .unwrap();

    std::fs::write(
        src_dir.join("service.rs"),
        r#"/// Commits incoming batch records into storage.
pub fn commit_records(payload: &[u8]) -> bool {
    write_durable_frame(payload)
}
"#,
    )
    .unwrap();

    let db = LibreDb::open(dir.path().join("ws.ldb")).unwrap();

    // Record an architectural Decision mentioning `write_durable_frame` BEFORE indexing:
    let batch_spec = AtomicBatchSpec {
        facts: vec![("alignment".to_owned(), "4096".to_owned())],
        decisions: vec![(
            "Frame Durability".to_owned(),
            "Every write_durable_frame call must verify CRC32 before updating superblocks.".to_owned(),
        )],
        tasks: vec![(
            "t1".to_owned(),
            "Audit write_durable_frame error handling".to_owned(),
            "in_progress".to_owned(),
            "high".to_owned(),
        )],
        snapshot: Some("Initial storage service layout.".to_owned()),
    };
    execute_atomic_batch(&db, &batch_spec).unwrap();

    // Index workspace: skips `target/` and NUL-byte `embedded_blob.rs`, indexes 2 Rust files!
    let rep1 = index_workspace(&db, dir.path(), false).unwrap();
    assert_eq!(rep1.files_reindexed, 2);
    assert!(rep1.binary_files_skipped >= 1);
    assert!(rep1.call_synapses_wired >= 1);
    assert!(rep1.governance_synapses_wired >= 2);

    // Second incremental run touches 0 files (`files_unchanged_cached == 2`)!
    let rep2 = index_workspace(&db, dir.path(), false).unwrap();
    assert_eq!(rep2.files_unchanged_cached, 2);
    assert_eq!(rep2.files_reindexed, 0);

    // Query blast-radius impact on `write_durable_frame`: must report `commit_records` as caller
    // AND `"Frame Durability"` Decision as governing invariant!
    let impacts = query_symbol_impact(&db, "write_durable_frame").unwrap();
    assert_eq!(impacts.len(), 1);
    assert!(impacts[0]
        .callers
        .iter()
        .any(|c| c.contains("commit_records")));
    assert!(impacts[0]
        .governing_decisions
        .iter()
        .any(|g| g.contains("Frame Durability")));

    // Surgical FIM slice around `write_durable_frame` embeds both callers and governing decisions!
    let fim = extract_fim_slice(
        &db,
        &src_dir.join("storage.rs"),
        Some("write_durable_frame"),
        None,
        2,
    )
    .unwrap();
    let rendered = fim.format_compact();
    assert!(rendered.contains("Frame Durability"));
    assert!(rendered.contains("commit_records"));
    assert!(rendered.contains("pub fn write_durable_frame"));

    // Verify deterministic subagent handoff generation:
    let (_, handoff_md) =
        create_subagent_handoff(&db, "ho_01", "t1", "Security Auditor", "Verify torn writes")
            .unwrap();
    assert!(handoff_md.contains("Security Auditor"));
    assert!(handoff_md.contains("alignment = 4096"));
    assert!(handoff_md.contains("Frame Durability"));
}

#[test]
fn workspace_indexer_qualifies_impl_methods_resolves_stopword_calls_and_reconciles_deleted_edges() {
    let dir = tempdir().unwrap();
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    std::fs::write(
        src_dir.join("kernel.rs"),
        r#"pub struct KernelStore;

impl KernelStore {
    pub fn open(path: &str) -> Self {
        let _ = path;
        Self
    }

    pub fn encode(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

pub struct HeaderBlock;

impl HeaderBlock {
    pub fn encode(&self) -> [u8; 64] {
        [0u8; 64]
    }
}
"#,
    )
    .unwrap();

    std::fs::write(
        src_dir.join("client.rs"),
        r#"pub fn bootstrap_store() -> [u8; 32] {
    let ks = KernelStore::open("demo.ldb");
    ks.encode()
}

pub fn legacy_helper() -> u32 {
    7
}
"#,
    )
    .unwrap();

    let db = LibreDb::open(dir.path().join("qual.ldb")).unwrap();
    index_workspace(&db, dir.path(), false).unwrap();

    // 1. Both `KernelStore::encode` and `HeaderBlock::encode` coexist without overwriting each other!
    let enc_impacts = query_symbol_impact(&db, "::encode").unwrap();
    assert_eq!(enc_impacts.len(), 2);

    // 2. `KernelStore::open` resolves `bootstrap_store` via Stage A despite `open` being a stopword!
    let open_impacts = query_symbol_impact(&db, "KernelStore::open").unwrap();
    assert_eq!(open_impacts.len(), 1);
    assert_eq!(open_impacts[0].callers.len(), 1);
    assert!(open_impacts[0].callers[0].contains("bootstrap_store"));

    // 3. Remove `KernelStore::open` call from `bootstrap_store` and delete `legacy_helper`:
    // incremental re-index must tombstone `legacy_helper` AND remove the stale `Calls` synapse!
    std::fs::write(
        src_dir.join("client.rs"),
        r#"pub fn bootstrap_store() -> [u8; 32] {
    [1u8; 32]
}
"#,
    )
    .unwrap();

    index_workspace(&db, dir.path(), false).unwrap();
    assert!(
        query_symbol_impact(&db, "legacy_helper").unwrap().is_empty(),
        "deleted symbol must be tombstoned on incremental re-index"
    );
    let open_after = query_symbol_impact(&db, "KernelStore::open").unwrap();
    assert_eq!(open_after.len(), 1);
    assert!(
        open_after[0].callers.is_empty(),
        "removed call edge must be pruned by sync_edges_for_kinds"
    );
}

#[test]
fn transcript_tail_detector_automatically_advances_epoch_on_compaction() {
    let dir = tempdir().unwrap();
    let db = Arc::new(LibreDb::open(dir.path().join("epoch.ldb")).unwrap());
    let transcript = dir.path().join("transcript.jsonl");

    db.put(
        WriteRequest::new(
            NodeKind::Fact,
            b"critical_invariant = never lose context on compact".to_vec(),
        )
        .with_key("critical_invariant"),
    )
    .unwrap();
    CognitiveEngine::open_db(Arc::clone(&db))
        .unwrap()
        .save_index_snapshot()
        .unwrap();

    std::fs::write(
        &transcript,
        "{\"step_index\":1,\"type\":\"USER_INPUT\",\"content\":\"hello\"}\n",
    )
    .unwrap();

    let ep1 = sync_transcript_epoch(&db, "cid-live", &transcript).unwrap();
    assert_eq!(ep1, 1);

    let brain = OverlayBrain::open(None, Arc::clone(&db)).unwrap();
    let mut req = PulseRequest::new("critical invariant", 500);
    req.conversation_id = Some("cid-live".to_owned());
    req.epoch = ep1;

    // Turn 1 delivers full fact; Turn 2 suppresses it (epoch == 1).
    assert_eq!(brain.pulse(&req).unwrap().capsules.len(), 1);
    assert_eq!(brain.pulse(&req).unwrap().capsules.len(), 0);

    // Append a simulated `PLANNER_RESPONSE` mentioning "CHECKPOINT" and the summary tag in thinking/tool output:
    // this MUST NOT trigger a false `/compact` epoch increment!
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    let tag = concat!("<CONTEXT", "_SUMMARY>");
    writeln!(
        f,
        "{{\"step_index\":20,\"type\":\"PLANNER_RESPONSE\",\"thinking\":\"Checking \\\"CHECKPOINT\\\" and {tag} in transcript.rs\",\"content\":\"ok\"}}"
    )
    .unwrap();
    drop(f);

    let ep_still_1 = sync_transcript_epoch(&db, "cid-live", &transcript).unwrap();
    assert_eq!(
        ep_still_1, 1,
        "mentions of CHECKPOINT or summary tag inside PLANNER_RESPONSE must not bump epoch"
    );

    // Append a genuine `/compact` CHECKPOINT line to `transcript.jsonl`!
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap();
    writeln!(
        f,
        "{{\"step_index\":40,\"type\":\"CHECKPOINT\",\"content\":\"{tag}compacted\"}}"
    )
    .unwrap();
    drop(f);

    // `sync_transcript_epoch` reads ONLY the newly appended bytes, sees CHECKPOINT, and bumps epoch -> 2!
    let ep2 = sync_transcript_epoch(&db, "cid-live", &transcript).unwrap();
    assert_eq!(ep2, 2);

    req.epoch = ep2;
    // Post-compaction `pulse` automatically re-hydrates `critical_invariant`!
    assert_eq!(brain.pulse(&req).unwrap().capsules.len(), 1);
}
