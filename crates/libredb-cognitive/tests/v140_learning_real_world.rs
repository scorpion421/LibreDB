//! Real-world learning regression suite for `LibreDB v1.4.0`.
//!
//! Unlike the `v1.3.0` toy fixtures, every scenario here runs against a realistic workspace:
//! - a non-empty global layer (`OverlayBrain` with rules and skills),
//! - a populated project layer (facts and decisions sharing many Unicode 3-grams with the queries),
//! - a multi-symbol source file (`src/engine.rs` with 10 functions) plus helper files.
//!
//! Each test documents which defect (`B1`..`B11`) of the v1.4.0 plan it guards against.

use libredb_cognitive::skeleton::SKELETON_HASH_SEED;
use libredb_cognitive::{
    index_workspace, locate_symbols, query_symbol_impact, reconcile_tentative_edits,
    record_search_miss_cue, stage_tentative_file_edit, CognitiveEngine, OverlayBrain,
    PulseRequest, ReflexEngine, ReflexRule, PENDING_MISS_CUES_KEY, SYMBOL_CUE_BRIDGES_KEY,
};
use libredb_core::crc::hash_key;
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ENGINE_REL: &str = "src/engine.rs";
const TYPES_REL: &str = "src/types.rs";

struct Fixture {
    root: PathBuf,
    proj: Arc<LibreDb>,
    global: Arc<LibreDb>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn engine_fn(i: usize, body_add: &str) -> String {
    format!("pub fn compute_engine_step_{i}(x: u64) -> u64 {{\n    let y = x + {body_add};\n    y * 2\n}}\n\n")
}

fn engine_source_with(overrides: &[(usize, String)]) -> String {
    let mut out = String::new();
    for i in 0..10 {
        if let Some((_, custom)) = overrides.iter().find(|(idx, _)| *idx == i) {
            out.push_str(custom);
        } else {
            out.push_str(&engine_fn(i, &i.to_string()));
        }
    }
    out
}

fn fixture(tag: &str) -> Fixture {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir().join(format!(
        "libredb_v140_{tag}_{}_{nonce}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".agents")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"ws_learning\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(root.join(ENGINE_REL), engine_source_with(&[])).unwrap();
    std::fs::write(
        root.join(TYPES_REL),
        "pub struct LeaseConfig {\n    pub ttl: u64,\n}\n\npub fn default_lease_config() -> LeaseConfig {\n    LeaseConfig { ttl: 30 }\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/release.rs"),
        "pub fn release_handle(id: u64) -> bool {\n    id > 0\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/util_a.rs"),
        "pub fn util_alpha_value() -> u32 {\n    1\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/util_b.rs"),
        "pub fn util_beta_value() -> u32 {\n    2\n}\n",
    )
    .unwrap();

    let proj = Arc::new(LibreDb::open(root.join(".agents/memory.ldb")).unwrap());
    // Project noise: facts and decisions sharing many 3-grams with test queries
    // ("quorums", "releases", "tickets", "gateway", "warp", "validation") without exact query tokens.
    let noise_words = [
        "quorums of replicas confirm releases before tickets expire",
        "the gateway warps configuration state into protocol updates",
        "validation of signatures happens after cached refreshes",
        "release tickets are granted by quorums of operators",
        "warp drive gateway telemetry is aggregated per tick",
        "engine steps compute derived states and update caches",
        "configuration protocol version tokens are rotated weekly",
        "operators validate gateway tickets during the release window",
    ];
    for i in 0..30 {
        let body = format!(
            "noise_fact_{i:02} = {} (observation {i})",
            noise_words[i % noise_words.len()]
        );
        proj.put(
            WriteRequest::new(NodeKind::Fact, body.into_bytes()).with_key(format!("noise_fact_{i:02}")),
        )
        .unwrap();
    }
    for d in 0..10 {
        let body = format!(
            "[Decision: noise_decision_{d}] {} and keep the protocol stable",
            noise_words[(d * 3) % noise_words.len()]
        );
        proj.put(
            WriteRequest::new(NodeKind::Decision, body.into_bytes())
                .with_key(format!("noise_decision_{d}")),
        )
        .unwrap();
    }

    let global = Arc::new(LibreDb::open(root.join("global_customizations.ldb")).unwrap());
    for r in 0..20 {
        let body = format!(
            "Global rule {r}: always validate release tickets, keep gateway configuration consistent, and document protocol warps."
        );
        global
            .put(WriteRequest::new(NodeKind::Rule, body.into_bytes()).with_key(format!("global_rule_{r}")))
            .unwrap();
    }

    index_workspace(&proj, &root, false).unwrap();
    Fixture { root, proj, global }
}

fn hook_edit(fx: &Fixture, rel: &str, new_content: &str) {
    let target = fx.root.join(rel);
    let pre = std::fs::read(&target).unwrap();
    let pre_hash = hash_key(SKELETON_HASH_SEED, &pre);
    let (staged, _, _) = stage_tentative_file_edit(
        &fx.proj,
        &fx.root,
        &target,
        Some(pre_hash),
        new_content.as_bytes(),
        (new_content.len() / 4) as u64,
    )
    .unwrap();
    assert!(staged, "PreToolUse staging must succeed for {rel}");
    std::fs::write(&target, new_content).unwrap();
}

fn bridge_book(db: &LibreDb) -> Value {
    db.get_by_key(NodeKind::Generic, SYMBOL_CUE_BRIDGES_KEY)
        .ok()
        .and_then(|r| serde_json::from_slice::<Value>(&r.payload).ok())
        .unwrap_or(Value::Null)
}

fn bridge_targets(db: &LibreDb, token: &str) -> Vec<String> {
    bridge_book(db)
        .pointer(&format!("/bridges/{token}"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|pair| pair.get(0).and_then(Value::as_str).map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn pending_queries(db: &LibreDb) -> Vec<String> {
    db.get_by_key(NodeKind::Generic, PENDING_MISS_CUES_KEY)
        .ok()
        .and_then(|r| serde_json::from_slice::<Value>(&r.payload).ok())
        .and_then(|v| v.as_array().cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("raw_query").and_then(Value::as_str).map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn overlay_pulse(fx: &Fixture, query: &str) -> libredb_cognitive::PulseResponse {
    let brain = OverlayBrain::open(Some(Arc::clone(&fx.global)), Arc::clone(&fx.proj)).unwrap();
    let mut req = PulseRequest::new(query, 4000);
    req.workspace_dir = Some(fx.root.clone());
    brain.pulse(&req).unwrap()
}

fn pulse_mentions(resp: &libredb_cognitive::PulseResponse, needle: &str) -> bool {
    resp.capsules.iter().any(|c| c.content.contains(needle))
}

fn locate_names(db: &LibreDb, q: &str) -> Vec<String> {
    locate_symbols(db, &[q.to_owned()])
        .unwrap()
        .into_iter()
        .map(|m| m.qualified_name)
        .collect()
}

fn sym(name: &str) -> String {
    format!("{ENGINE_REL}::{name}")
}

// --- S1 (B1): Overlay pulse must record search misses ---------------------------------------
#[test]
fn s01_overlay_pulse_records_search_miss() {
    let fx = fixture("s01");
    let _ = overlay_pulse(&fx, "zyxquux_frobnicator");
    assert!(
        pending_queries(&fx.proj).iter().any(|q| q == "zyxquux_frobnicator"),
        "OverlayBrain::pulse must record a project-layer miss, pending: {:?}",
        pending_queries(&fx.proj)
    );
}

// --- S2 (B3): Learned bridge must survive 3-gram noise in overlay pulse --------------------
#[test]
fn s02_learned_bridge_survives_trigram_noise_in_overlay_pulse() {
    let fx = fixture("s02");
    assert!(locate_names(&fx.proj, "quorum_lease_ticket").is_empty());
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(7, engine_fn(7, "700"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert!(
        bridge_targets(&fx.proj, "quorum_lease_ticket").contains(&sym("compute_engine_step_7")),
        "precondition: bridge learned, book: {}",
        bridge_book(&fx.proj)
    );
    let resp = overlay_pulse(&fx, "quorum_lease_ticket");
    assert!(
        pulse_mentions(&resp, "compute_engine_step_7"),
        "Overlay pulse must deliver the bridged symbol despite noise, got: {}",
        resp.format_compact()
    );
}

// --- S5 (B5): Multi-site edit binds only the truly modified function ------------------------
#[test]
fn s05_multi_site_edit_binds_only_modified_function() {
    let fx = fixture("s05");
    assert!(locate_names(&fx.proj, "frobulate_widget").is_empty());
    let edited = format!(
        "use std::fmt;\n\n{}",
        engine_source_with(&[(9, engine_fn(9, "x * 9"))])
    );
    hook_edit(&fx, ENGINE_REL, &edited);
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert_eq!(
        bridge_targets(&fx.proj, "frobulate_widget"),
        vec![sym("compute_engine_step_9")],
        "book: {}",
        bridge_book(&fx.proj)
    );
}

// --- S6 (B5): Removing a blank separator line must not blame the next function -------------
#[test]
fn s06_blank_line_removal_blames_no_function() {
    let fx = fixture("s06");
    assert!(locate_names(&fx.proj, "snorkel_delta").is_empty());
    let original = engine_source_with(&[]);
    let anchor = engine_fn(4, "4");
    let squeezed = original.replacen(&anchor, anchor.trim_end_matches('\n'), 1)
        .replacen("}pub fn compute_engine_step_5", "}\npub fn compute_engine_step_5", 1);
    assert_ne!(squeezed, original);
    hook_edit(&fx, ENGINE_REL, &squeezed);
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert!(
        bridge_targets(&fx.proj, "snorkel_delta").is_empty(),
        "Whitespace-only separator change must not bind any symbol, book: {}",
        bridge_book(&fx.proj)
    );
}

// --- S7 (B5): Body-only edit detected in reconcile fallback (disk differs from prediction) -
#[test]
fn s07_body_only_edit_detected_in_reconcile_fallback() {
    let fx = fixture("s07");
    assert!(locate_names(&fx.proj, "gizmo_pivot").is_empty());
    let target = fx.root.join(ENGINE_REL);
    let pre = std::fs::read(&target).unwrap();
    let predicted = engine_source_with(&[(8, engine_fn(8, "888"))]);
    stage_tentative_file_edit(
        &fx.proj,
        &fx.root,
        &target,
        Some(hash_key(SKELETON_HASH_SEED, &pre)),
        predicted.as_bytes(),
        64,
    )
    .unwrap();
    // The actual write differs from the prediction: body-only change of step 2.
    std::fs::write(&target, engine_source_with(&[(2, engine_fn(2, "222"))])).unwrap();
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert_eq!(
        bridge_targets(&fx.proj, "gizmo_pivot"),
        vec![sym("compute_engine_step_2")],
        "book: {}",
        bridge_book(&fx.proj)
    );
}

// --- S8 (B5): Whitespace-only reformat binds nothing --------------------------------------
#[test]
fn s08_whitespace_reformat_binds_nothing() {
    let fx = fixture("s08");
    assert!(locate_names(&fx.proj, "plumbus_router").is_empty());
    let reformatted = engine_source_with(&[(
        1,
        "pub fn compute_engine_step_1(x: u64) -> u64 {\n    let  y  =  x  +  1;\n        y * 2\n}\n\n".to_owned(),
    )]);
    hook_edit(&fx, ENGINE_REL, &reformatted);
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert!(
        bridge_targets(&fx.proj, "plumbus_router").is_empty(),
        "Reformat must not bind, book: {}",
        bridge_book(&fx.proj)
    );
}

// --- S9 (B6): An edit staged before the miss must never consume it -------------------------
#[test]
fn s09_prior_edit_never_consumes_later_miss() {
    let fx = fixture("s09");
    hook_edit(
        &fx,
        TYPES_REL,
        "pub struct LeaseConfig {\n    pub ttl: u64,\n}\n\npub fn default_lease_config() -> LeaseConfig {\n    LeaseConfig { ttl: 60 }\n}\n",
    );
    // Miss recorded via a path that does not reconcile first (e.g. pulse):
    record_search_miss_cue(&fx.proj, "zorblax_engine").unwrap();
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(6, engine_fn(6, "606"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    let targets = bridge_targets(&fx.proj, "zorblax_engine");
    assert!(
        targets.contains(&sym("compute_engine_step_6"))
            && !targets.iter().any(|t| t.contains("default_lease_config")),
        "Cue must bind only to the causally later edit, got: {targets:?}"
    );
}

// --- S10 (B6): Multi-file change within one episode binds both files ----------------------
#[test]
fn s10_multi_file_episode_binds_both_files() {
    let fx = fixture("s10");
    assert!(locate_names(&fx.proj, "blorptastic_flow").is_empty());
    hook_edit(
        &fx,
        TYPES_REL,
        "pub struct LeaseConfig {\n    pub ttl: u64,\n}\n\npub fn default_lease_config() -> LeaseConfig {\n    LeaseConfig { ttl: 90 }\n}\n",
    );
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(3, engine_fn(3, "303"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    let targets = bridge_targets(&fx.proj, "blorptastic_flow");
    assert!(
        targets.contains(&sym("compute_engine_step_3"))
            && targets.iter().any(|t| t.contains("default_lease_config")),
        "Both files of one episode must be bound, got: {targets:?}"
    );
}

// --- S11 (B7): External disk edit is learned by index scan; bulk changes are not ---------
#[test]
fn s11_external_edit_learned_by_index_scan_but_bulk_ignored() {
    let fx = fixture("s11");
    assert!(locate_names(&fx.proj, "snarfblat_io").is_empty());
    std::fs::write(
        fx.root.join(ENGINE_REL),
        engine_source_with(&[(0, engine_fn(0, "1000"))]),
    )
    .unwrap();
    index_workspace(&fx.proj, &fx.root, false).unwrap();
    assert_eq!(
        bridge_targets(&fx.proj, "snarfblat_io"),
        vec![sym("compute_engine_step_0")],
        "book: {}",
        bridge_book(&fx.proj)
    );

    assert!(locate_names(&fx.proj, "glimmer_bulk").is_empty());
    std::fs::write(fx.root.join(ENGINE_REL), engine_source_with(&[(5, engine_fn(5, "55"))])).unwrap();
    std::fs::write(fx.root.join("src/release.rs"), "pub fn release_handle(id: u64) -> bool {\n    id > 1\n}\n").unwrap();
    std::fs::write(fx.root.join("src/util_a.rs"), "pub fn util_alpha_value() -> u32 {\n    11\n}\n").unwrap();
    std::fs::write(fx.root.join("src/util_b.rs"), "pub fn util_beta_value() -> u32 {\n    22\n}\n").unwrap();
    index_workspace(&fx.proj, &fx.root, false).unwrap();
    assert!(
        bridge_targets(&fx.proj, "glimmer_bulk").is_empty(),
        "Bulk change (> 3 files in one scan) must not be learned"
    );
}

// --- S12 (B4): Generic shared token must not pull an unrelated symbol ---------------------
#[test]
fn s12_generic_token_does_not_pull_unrelated_symbol() {
    let fx = fixture("s12");
    assert!(locate_names(&fx.proj, "validate token signature").is_empty());
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(5, engine_fn(5, "505"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    assert!(
        bridge_targets(&fx.proj, "signature").contains(&sym("compute_engine_step_5")),
        "precondition: bridge learned, book: {}",
        bridge_book(&fx.proj)
    );
    assert!(
        !locate_names(&fx.proj, "refresh token cache")
            .iter()
            .any(|n| n == "compute_engine_step_5"),
        "locate must not return the bridged symbol for an unrelated query"
    );
    assert!(
        !query_symbol_impact(&fx.proj, "refresh token cache")
            .unwrap()
            .iter()
            .any(|r| r.symbol_key.contains("compute_engine_step_5")),
        "impact must not return the bridged symbol for an unrelated query"
    );
    let resp = overlay_pulse(&fx, "refresh token cache");
    assert!(
        !pulse_mentions(&resp, "compute_engine_step_5"),
        "pulse must not return the bridged symbol for an unrelated query"
    );
    // The exact learned query still resolves:
    assert!(locate_names(&fx.proj, "validate token signature")
        .iter()
        .any(|n| n == "compute_engine_step_5"));
}

// --- S13 (B4): Single-token cue is usable in overlay pulse after one observation ---------
#[test]
fn s13_single_token_cue_usable_after_one_observation() {
    let fx = fixture("s13");
    assert!(locate_names(&fx.proj, "warpgate").is_empty());
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(4, engine_fn(4, "404"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    let resp = overlay_pulse(&fx, "warpgate");
    assert!(
        pulse_mentions(&resp, "compute_engine_step_4"),
        "Single-token learned cue must surface after one observation, got: {}",
        resp.format_compact()
    );
}

// --- S14 (B9): Weak substring hits must not suppress miss recording ----------------------
#[test]
fn s14_weak_substring_hit_still_records_miss_and_bridge_ranks_first() {
    let fx = fixture("s14");
    let first = locate_names(&fx.proj, "lease");
    assert!(!first.is_empty(), "precondition: tier-3 substring hits exist");
    assert!(
        pending_queries(&fx.proj).iter().any(|q| q == "lease"),
        "Miss must be recorded when only weak substring hits exist, pending: {:?}",
        pending_queries(&fx.proj)
    );
    hook_edit(&fx, ENGINE_REL, &engine_source_with(&[(8, engine_fn(8, "808"))]));
    reconcile_tentative_edits(&fx.proj, &fx.root).unwrap();
    let after = locate_names(&fx.proj, "lease");
    assert_eq!(
        after.first().map(String::as_str),
        Some("compute_engine_step_8"),
        "Confident bridge must rank before tier-3 substring hits, got: {after:?}"
    );
}

// --- S15 (B8): Concurrent miss recording loses no update ---------------------------------
#[test]
fn s15_concurrent_miss_recording_loses_no_update() {
    let fx = fixture("s15");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for t in 0..2 {
        let db = Arc::clone(&fx.proj);
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..4 {
                record_search_miss_cue(&db, &format!("concurrent_cue_t{t}_n{i}")).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let pending = pending_queries(&fx.proj);
    for t in 0..2 {
        for i in 0..4 {
            let q = format!("concurrent_cue_t{t}_n{i}");
            assert!(pending.contains(&q), "Lost concurrent cue {q}, pending: {pending:?}");
        }
    }
}

// --- S17 (B11): Anchor signature drift is surfaced on the reflex -------------------------
#[test]
fn s17_anchor_signature_drift_is_flagged() {
    let fx = fixture("s17");
    let rule = ReflexRule {
        id: "step2-guard".to_owned(),
        action_any: vec!["checkpoint".to_owned()],
        directive: "Keep compute_engine_step_2 overflow-safe.".to_owned(),
        code_anchors: vec!["compute_engine_step_2".to_owned()],
        ..Default::default()
    };
    ReflexEngine::learn_reflex(&fx.proj, &rule).unwrap();
    let before = CognitiveEngine::open_db(Arc::clone(&fx.proj))
        .unwrap()
        .evaluate_reflexes(Some(&fx.root), "checkpoint the engine", None);
    assert_eq!(before.len(), 1);
    assert!(!before[0].directive.contains("anchor contract changed"));

    std::fs::write(
        fx.root.join(ENGINE_REL),
        engine_source_with(&[(
            2,
            "pub fn compute_engine_step_2(x: u64, scale: u64) -> u64 {\n    let y = x + scale;\n    y * 2\n}\n\n".to_owned(),
        )]),
    )
    .unwrap();
    index_workspace(&fx.proj, &fx.root, false).unwrap();
    let after = CognitiveEngine::open_db(Arc::clone(&fx.proj))
        .unwrap()
        .evaluate_reflexes(Some(&fx.root), "checkpoint the engine", None);
    assert_eq!(after.len(), 1);
    assert!(
        after[0].directive.contains("anchor contract changed"),
        "Drifted anchor signature must be flagged, got: {}",
        after[0].directive
    );
}

// --- S18: v1.3.0 skeletons without body hashes are re-extracted once, without learning ---
#[test]
fn s18_legacy_skeletons_migrate_once_without_learning() {
    let fx = fixture("s18");
    record_search_miss_cue(&fx.proj, "legacy_migration_probe").unwrap();
    let book_before = bridge_book(&fx.proj);

    // Downgrade persisted state to the v1.3.0 shape.
    let skel_keys: Vec<String> = fx
        .proj
        .list_inodes(Some(NodeKind::WorkingSet), false)
        .into_iter()
        .filter_map(|(_, k, _)| k.filter(|k| k.starts_with("skeleton::")))
        .collect();
    for k in &skel_keys {
        let rec = fx.proj.get_by_key(NodeKind::WorkingSet, k).unwrap();
        let mut v: Value = serde_json::from_slice(&rec.payload).unwrap();
        if let Some(syms) = v.get_mut("symbols").and_then(Value::as_array_mut) {
            for s in syms {
                if let Some(obj) = s.as_object_mut() {
                    obj.remove("body_hash");
                }
            }
        }
        fx.proj
            .put(WriteRequest::new(NodeKind::WorkingSet, serde_json::to_vec(&v).unwrap()).with_key(k.clone()))
            .unwrap();
    }
    let st_rec = fx
        .proj
        .get_by_key(NodeKind::Generic, "sys::workspace_graph_state")
        .unwrap();
    let mut st: Value = serde_json::from_slice(&st_rec.payload).unwrap();
    st["version"] = Value::from(4u32);
    fx.proj
        .put(
            WriteRequest::new(NodeKind::Generic, serde_json::to_vec(&st).unwrap())
                .with_key("sys::workspace_graph_state"),
        )
        .unwrap();

    let rep = index_workspace(&fx.proj, &fx.root, false).unwrap();
    assert!(
        rep.files_reindexed >= 5,
        "Legacy skeletons must be re-extracted once, report: {rep:?}"
    );
    assert_eq!(
        bridge_book(&fx.proj),
        book_before,
        "Schema migration must never create learning events"
    );
    let rep2 = index_workspace(&fx.proj, &fx.root, false).unwrap();
    assert_eq!(rep2.files_reindexed, 0, "Migration must happen exactly once");
}

// --- S19 (v1.5.0): Procedural error-recovery learning, 2-stage banality filter, and superseding ---
#[test]
fn s19_v150_error_recovery_banality_and_situational_superseding() {
    use libredb_cognitive::{
        diff_symbol_body_tokens, is_banal_syntax_error, learn_explicit_error_resolution,
        learning_state_report, record_error_cue, FileSkeleton, PulseRequest, ReflexEngine,
    };

    assert!(is_banal_syntax_error("error: expected ';', found '}'"));
    assert!(is_banal_syntax_error("SyntaxError: unexpected token ')'"));
    assert!(!is_banal_syntax_error(
        "error[E0425]: cannot find value 'workspace_scope_root' in this scope"
    ));

    let fx = fixture("s19");
    let old_src = b"pub fn alpha_guard(x: i32) -> i32 {\n    x + 1\n}\n";
    let punct_src = b"pub fn alpha_guard(x: i32) -> i32 {\n    (x + 1);\n}\n";
    let old_sk = FileSkeleton::extract_from_bytes("src/g.rs", old_src);
    let punct_sk = FileSkeleton::extract_from_bytes("src/g.rs", punct_src);
    let touched = vec!["src/g.rs::alpha_guard".to_owned()];
    assert!(
        diff_symbol_body_tokens(
            "src/g.rs",
            Some(old_src),
            Some(&old_sk),
            punct_src,
            &punct_sk,
            &touched
        )
        .is_empty(),
        "Punctuation-only diff must yield zero newly introduced body tokens"
    );

    assert!(!record_error_cue(&fx.proj, "error: expected ';', found '}'", None).unwrap());
    assert!(record_error_cue(
        &fx.proj,
        "error[E0425]: cannot find value 'session_guard_token' in this scope",
        Some("check")
    )
    .unwrap());
    let learned = learn_explicit_error_resolution(
        &fx.proj,
        "error[E0425]: cannot find value 'session_guard_token' in this scope",
        "Bind session_guard_token from validate_session_scope before checking gates.",
        Some("check"),
        &["src/engine.rs::compute_engine_step_2".to_owned()],
        &[],
    )
    .unwrap();
    assert!(learned.is_some());

    let m1 = ReflexRule {
        id: "m1-general".to_owned(),
        stack_any: vec!["cargo.toml".to_owned()],
        action_any: vec!["migrate".to_owned()],
        directive: "Use general migration runner.".to_owned(),
        code_anchors: vec!["compute_engine_step_2".to_owned()],
        ..Default::default()
    };
    let m2 = ReflexRule {
        id: "m2-zero-downtime".to_owned(),
        stack_any: vec!["cargo.toml".to_owned()],
        action_any: vec!["migrate".to_owned()],
        context_tags: vec!["bluegreen".to_owned(), "sharded".to_owned()],
        supersedes: vec!["m1-general".to_owned()],
        directive: "Use sharded blue-green expansion migration protocol.".to_owned(),
        code_anchors: vec!["compute_engine_step_2".to_owned()],
        ..Default::default()
    };
    ReflexEngine::learn_reflex(&fx.proj, &m1).unwrap();
    ReflexEngine::learn_reflex(&fx.proj, &m2).unwrap();

    let rx = ReflexEngine::load(&fx.proj).unwrap();
    let gen_hit = rx.evaluate(Some(&fx.root), "migrate database", None);
    assert_eq!(gen_hit.len(), 1);
    assert_eq!(gen_hit[0].id, "m1-general");

    let spec_hit = rx.evaluate(Some(&fx.root), "migrate bluegreen sharded database", None);
    assert_eq!(spec_hit.len(), 1);
    assert_eq!(spec_hit[0].id, "m2-zero-downtime");
    assert_eq!(spec_hit[0].superseded_ids, vec!["m1-general".to_owned()]);

    for _ in 0..4 {
        ReflexEngine::record_reflex_outcome(&fx.proj, "m2-zero-downtime", false).unwrap();
    }
    let rx_fallback = ReflexEngine::load(&fx.proj).unwrap();
    let fb_hit = rx_fallback.evaluate(Some(&fx.root), "migrate bluegreen sharded database", None);
    assert_eq!(fb_hit[0].id, "m1-general");

    let mut req = PulseRequest::new("compute_engine_step_2", 1500);
    req.error_context = Some("E0425 session_guard_token".to_owned());
    let cog = CognitiveEngine::open_db(Arc::clone(&fx.proj)).unwrap();
    let resp = cog.pulse(&req).unwrap();
    assert!(resp.fired_reflexes.iter().any(|r| r.id.starts_with("pitfall::")));

    let rep = learning_state_report(&fx.proj, 10);
    assert!(rep.counters.trivial_errors_filtered >= 1);
    assert!(rep.counters.pitfalls_learned >= 1);
    assert!(rep.counters.method_supersedes_applied >= 1);
}

#[allow(dead_code)]
fn assert_path_exists(p: &Path) {
    assert!(p.exists(), "missing {}", p.display());
}
