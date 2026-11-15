use libredb_cognitive::{
    check_german_prose_style, extract_error_file_hint, index_workspace, is_banal_syntax_error,
    is_code_learning_eligible_path, learning_state_report, reconcile_tentative_edits,
    record_error_cue, stage_tentative_file_edit, OverlayBrain, PulseRequest,
};
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn temp_test_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join(format!("v161_{tag}_{}_{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn file_hint_and_banal_noise_filters_reject_summaries_and_dotfiles() {
    assert_eq!(
        extract_error_file_hint(
            "crates/ws4w-core/src/firewall.rs:42:13: error[E0425]: cannot find value `netfw_policy`"
        )
        .as_deref(),
        Some("crates/ws4w-core/src/firewall.rs")
    );
    assert_eq!(
        extract_error_file_hint(
            "C:\\proj\\crates\\ws4w-core\\src\\lib.rs:10:5: error[E0308]: mismatched types"
        )
        .as_deref(),
        Some("C:/proj/crates/ws4w-core/src/lib.rs")
    );
    assert_eq!(
        extract_error_file_hint("src/app.ts(18,7): error TS2345: Argument of type 'string'")
            .as_deref(),
        Some("src/app.ts")
    );
    assert_eq!(
        extract_error_file_hint("File \"src/worker.py\", line 42, in run").as_deref(),
        Some("src/worker.py")
    );
    assert_eq!(
        extract_error_file_hint(".gitignore:1:1: error: invalid pattern"),
        None
    );

    assert!(!is_code_learning_eligible_path(".gitignore"));
    assert!(!is_code_learning_eligible_path("README.md"));
    assert!(!is_code_learning_eligible_path("Cargo.lock"));
    assert!(!is_code_learning_eligible_path(".agents/memory.ldb"));
    assert!(is_code_learning_eligible_path("crates/ws4w-core/src/firewall.rs"));
    assert!(is_code_learning_eligible_path("Cargo.toml"));

    assert!(is_banal_syntax_error(
        "error: could not compile `ws4w-core` (lib) due to 12 previous errors"
    ));
    assert!(is_banal_syntax_error(
        "Error: Unknown 'git-init' flag '--help'. Check CLI help."
    ));
    assert!(is_banal_syntax_error(
        "crates/ws4w-core/src/lib.rs:10:5: error: unclosed delimiter"
    ));
    assert!(!is_banal_syntax_error(
        "crates/ws4w-core/src/firewall.rs:42:13: error[E0425]: cannot find value `netfw_policy`"
    ));
}

#[test]
fn gitignore_and_unrelated_files_do_not_consume_file_hinted_error_cues() {
    let base = temp_test_dir("cue_bind");
    let ws = base.join("ws");
    let src_dir = ws.join("crates").join("ws4w-core").join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(ws.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/ws4w-core\"]\n").unwrap();
    fs::write(
        ws.join("crates").join("ws4w-core").join("Cargo.toml"),
        "[package]\nname = \"ws4w-core\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let gitignore_path = ws.join(".gitignore");
    let other_path = src_dir.join("other.rs");
    let fw_path = src_dir.join("firewall.rs");
    fs::write(&gitignore_path, "# Ignore build output\ntarget/\n").unwrap();
    fs::write(&other_path, "pub fn helper() -> u32 {\n    1\n}\n").unwrap();
    let fw_orig = "pub fn apply_rule() -> u32 {\n    0\n}\n";
    fs::write(&fw_path, fw_orig).unwrap();

    let db = Arc::new(LibreDb::open(&ws.join(".agents").join("memory.ldb")).unwrap());
    index_workspace(&db, &ws, false).unwrap();

    let recorded = record_error_cue(
        &db,
        "crates/ws4w-core/src/firewall.rs:2:5: error[E0425]: cannot find value `netfw_policy` in this scope",
        None,
    )
    .unwrap();
    assert!(recorded, "Causal compiler error with file_hint must be recorded");
    let rep0 = learning_state_report(&db, 10);
    assert_eq!(rep0.pending_errors.len(), 1);
    assert_eq!(
        rep0.pending_errors[0].file_hint.as_deref(),
        Some("crates/ws4w-core/src/firewall.rs")
    );

    // Edit `.gitignore` first: must NEVER consume pending compiler cues.
    let gi_new = b"# Ignore build output\ntarget/\n*.log\n";
    let _ = stage_tentative_file_edit(&db, &ws, &gitignore_path, None, gi_new, 10).unwrap();
    fs::write(&gitignore_path, gi_new).unwrap();
    let _ = reconcile_tentative_edits(&db, &ws).unwrap();
    let rep1 = learning_state_report(&db, 10);
    assert_eq!(
        rep1.pending_errors.len(),
        1,
        ".gitignore must not consume pending error cues"
    );
    assert!(rep1.learned_pitfalls.is_empty());

    // Edit unrelated `other.rs`: `file_hint` must prevent cross-file cue theft.
    let other_new = b"pub fn helper() -> u32 {\n    42\n}\n";
    let _ = stage_tentative_file_edit(&db, &ws, &other_path, None, other_new, 10).unwrap();
    fs::write(&other_path, other_new).unwrap();
    let _ = reconcile_tentative_edits(&db, &ws).unwrap();
    let rep2 = learning_state_report(&db, 10);
    assert_eq!(
        rep2.pending_errors.len(),
        1,
        "Unrelated source file must not consume firewall.rs error cue"
    );
    assert!(rep2.learned_pitfalls.is_empty());

    // Edit the failing file `firewall.rs`: cue binds to `firewall.rs` and survives re-indexing.
    let fw_fix = b"pub fn build_netfw_policy() -> u32 { 7 }\n\npub fn apply_rule() -> u32 {\n    build_netfw_policy()\n}\n";
    let _ = stage_tentative_file_edit(&db, &ws, &fw_path, None, fw_fix, 20).unwrap();
    fs::write(&fw_path, fw_fix).unwrap();
    let _ = reconcile_tentative_edits(&db, &ws).unwrap();

    index_workspace(&db, &ws, false).unwrap();
    let rep3 = learning_state_report(&db, 10);
    assert!(
        rep3.pending_errors.is_empty(),
        "Matching file edit must consume pending cue: {:?}",
        rep3.pending_errors
    );
    assert_eq!(rep3.learned_pitfalls.len(), 1);
    let debug_pitfall = format!("{:?}", rep3.learned_pitfalls[0]);
    assert!(
        debug_pitfall.contains("firewall.rs"),
        "Pitfall must bind to firewall.rs, got: {debug_pitfall}"
    );
    assert!(!debug_pitfall.contains(".gitignore"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn overlay_pulse_reserves_budget_for_local_decisions_over_global_skills() {
    let base = temp_test_dir("overlay_quota");
    let gdb = Arc::new(LibreDb::open(&base.join("global.ldb")).unwrap());
    let pdb = Arc::new(LibreDb::open(&base.join("project.ldb")).unwrap());

    // Seed two heavy global SkillSection capsules (~340 tokens each) matching the query.
    let mut heavy_body_a = String::from("Global WireGuard firewall policy checklist:\n");
    let mut heavy_body_b = String::from("Global Windows firewall policy hardening checklist:\n");
    for i in 0..70 {
        heavy_body_a.push_str(&format!("Verify firewall network policy rule step_{i}. "));
        heavy_body_b.push_str(&format!("Audit firewall network policy adapter entry_{i}. "));
    }
    gdb.put(
        WriteRequest::new(NodeKind::SkillSection, heavy_body_a.into_bytes())
            .with_key("skill::firewall-guide::section-a")
            .with_importance(220),
    )
    .unwrap();
    gdb.put(
        WriteRequest::new(NodeKind::SkillSection, heavy_body_b.into_bytes())
            .with_key("skill::windows-guide::section-b")
            .with_importance(220),
    )
    .unwrap();

    // Seed project-local architectural Decision (~60 tokens) matching the query.
    pdb.put(
        WriteRequest::new(
            NodeKind::Decision,
            b"Use windows crate COM bindings for INetFwPolicy2 firewall network policy rules."
                .to_vec(),
        )
        .with_key("firewall_com_architecture")
        .with_importance(200),
    )
    .unwrap();

    let brain = OverlayBrain::open(Some(gdb), pdb).unwrap();
    let resp = brain
        .pulse(&PulseRequest::new("firewall network policy", 800))
        .unwrap();

    assert!(
        resp.tokens_emitted <= 800,
        "Emitted tokens {} exceeded 800 budget",
        resp.tokens_emitted
    );
    assert!(
        resp.capsules
            .iter()
            .any(|c| c.key.as_deref().is_some_and(|k| k.ends_with("firewall_com_architecture"))),
        "Local Decision must not be crowded out by global SkillSections: {:?}",
        resp.capsules
            .iter()
            .map(|c| (&c.kind, &c.key, c.token_count))
            .collect::<Vec<_>>()
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn check_german_prose_style_catches_violations_with_zero_english_false_positives() {
    let bad_german = format!(
        "Dieser {p1} war Wert, weil kein Benchmark das aufgedeckt {u1}. Wir {u2} ohne {p2} {u3}.",
        p1 = concat!("Pra", "xis-", "Test"),
        u1 = concat!("hae", "tte"),
        u2 = concat!("koe", "nnen"),
        p2 = concat!("Archi", "tektur-", "Wildwuchs"),
        u3 = concat!("loe", "sen"),
    );
    let violations = check_german_prose_style(&bad_german, "notes.md");
    assert!(
        violations.iter().any(|v| v.rule == "german-ascii-umlaut"),
        "Expected german-ascii-umlaut violation: {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.rule == "german-deppenbindestrich"),
        "Expected german-deppenbindestrich violation: {violations:?}"
    );

    let clean_german = format!(
        "Dieser Praxistest war Wert, weil er Fehler aufgedeckt {h} und wir Probleme ohne Wildwuchs {l}.",
        h = "h\u{00e4}tte",
        l = "l\u{00f6}sen",
    );
    let clean_v = check_german_prose_style(&clean_german, "notes.md");
    assert!(
        clean_v.is_empty(),
        "Clean German with real umlauts and joined Komposita should have 0 violations: {clean_v:?}"
    );

    let clean_english = "# Architecture Overview\n\n\
Zero-Repeat Delta and Fail-Closed Security return `true` values in read-only mode.\n\
User queues do not block UTF-8 parsing when code fences appear:\n\
```rust\nlet praxis_test_value = true;\n```\n";
    let en_v = check_german_prose_style(clean_english, "README.md");
    assert!(
        en_v.is_empty(),
        "English docs and code fences must produce 0 false positives: {en_v:?}"
    );
}
