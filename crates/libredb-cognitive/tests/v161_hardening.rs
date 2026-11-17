use libredb_cognitive::{
    check_german_prose_style, extract_error_file_hint, index_workspace, is_banal_syntax_error,
    is_code_learning_eligible_path, learning_state_report, reconcile_tentative_edits,
    record_error_cue, sanitize_learning_artifacts, stage_tentative_file_edit, CognitiveEngine,
    ErrorPitfallBook, LearnedPitfallEntry, OverlayBrain, PendingErrorCue, PulseRequest,
    ReflexEngine, ReflexRule, ERROR_PITFALL_BOOK_KEY, PENDING_ERROR_CUES_KEY,
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

#[test]
fn overlay_pulse_normalizes_cross_layer_idf_and_attenuates_foreign_stack_skills() {
    let dir = temp_test_dir("overlay_idf_stack");
    let proj_dir = dir.join("rust_proj");
    fs::create_dir_all(proj_dir.join("src")).unwrap();
    fs::create_dir_all(proj_dir.join(".agents")).unwrap();
    fs::write(
        proj_dir.join("Cargo.toml"),
        "[package]\nname = \"winui_app\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(proj_dir.join("src").join("ui.rs"), "pub fn render_main() {}\n").unwrap();

    let glob_db = Arc::new(LibreDb::open(dir.join("global.ldb")).unwrap());
    for idx in 0..55 {
        glob_db
            .put(
                WriteRequest::new(
                    NodeKind::Fact,
                    format!("Global background note {idx}: desktop ui layout window rendering guide")
                        .into_bytes(),
                )
                .with_key(format!("filler::{idx:02}"))
                .with_importance(64),
            )
            .unwrap();
    }
    glob_db
        .put(
            WriteRequest::new(
                NodeKind::Skill,
                b"Flutter desktop layout widgets architecture guide for Dart UI".to_vec(),
            )
            .with_key("flutter-layout")
            .with_importance(200),
        )
        .unwrap();
    glob_db
        .put(
            WriteRequest::new(
                NodeKind::SkillSection,
                b"Windows desktop Fluent design architecture layout using Flutter Scaffold".to_vec(),
            )
            .with_key("flutter-layout::Desktop Architecture")
            .with_importance(200),
        )
        .unwrap();
    for (sk_key, sk_body, sec_key, sec_body) in [
        (
            "android-app-design",
            "Native Android Material 3 UI design architecture layout for Jetpack Compose mobile",
            "android-app-design::Material 3 Surface",
            "Windows desktop and UI design architecture comparison with Material 3 edge-to-edge",
        ),
        (
            "apple-hig-design",
            "Native Apple HIG design architecture layout for iOS iPadOS and macOS SwiftUI",
            "apple-hig-design::macOS Split View",
            "Desktop UI Fluent and HIG architecture navigation layout for native apps",
        ),
        (
            "linux-desktop-hig-design",
            "Native Linux desktop HIG design architecture for GNOME Libadwaita and KDE Kirigami",
            "linux-desktop-hig-design::GNOME HeaderBar",
            "Desktop UI Fluent and HIG design architecture layout for GTK4 and Qt6",
        ),
    ] {
        glob_db
            .put(
                WriteRequest::new(NodeKind::Skill, sk_body.as_bytes().to_vec())
                    .with_key(sk_key)
                    .with_importance(200),
            )
            .unwrap();
        glob_db
            .put(
                WriteRequest::new(NodeKind::SkillSection, sec_body.as_bytes().to_vec())
                    .with_key(sec_key)
                    .with_importance(200),
            )
            .unwrap();
    }
    glob_db
        .put(
            WriteRequest::new(
                NodeKind::Skill,
                b"Native Microsoft Windows Fluent 2 UI design architecture for desktop apps".to_vec(),
            )
            .with_key("windows-app-design")
            .with_importance(200),
        )
        .unwrap();
    glob_db
        .put(
            WriteRequest::new(
                NodeKind::Decision,
                b"Windows UI Fluent 2 design architecture rule: Segoe UI Variable, crisp 4px corners, high contrast".to_vec(),
            )
            .with_key("rule::windows-fluent-app-design")
            .with_importance(220),
        )
        .unwrap();

    let proj_db = Arc::new(LibreDb::open(proj_dir.join(".agents").join("memory.ldb")).unwrap());
    proj_db
        .put(
            WriteRequest::new(
                NodeKind::Decision,
                b"Windows UI Fluent 2 design architecture decision for native WinUI 3 main shell".to_vec(),
            )
            .with_key("decision::ui_architecture")
            .with_importance(220),
        )
        .unwrap();
    proj_db
        .put(
            WriteRequest::new(
                NodeKind::Fact,
                b"WinUI 3 desktop design applies Fluent 2 surface layers".to_vec(),
            )
            .with_key("fact::ui_surface")
            .with_importance(160),
        )
        .unwrap();

    let brain = OverlayBrain::open(Some(Arc::clone(&glob_db)), Arc::clone(&proj_db)).unwrap();
    let mut req = PulseRequest::new("Windows UI Fluent 2 design architecture", 1800);
    req.workspace_dir = Some(proj_dir.clone());
    let resp = brain.pulse(&req).unwrap();

    let proj_keys: Vec<_> = resp
        .capsules
        .iter()
        .filter(|c| {
            c.key.as_deref().is_some_and(|k| {
                matches!(
                    k.strip_prefix("proj::").unwrap_or(k),
                    "decision::ui_architecture" | "fact::ui_surface"
                )
            })
        })
        .collect();
    assert!(
        !proj_keys.is_empty(),
        "Normalized cross-layer scoring must deliver project capsules despite a larger global corpus: {:?}",
        resp.capsules.iter().map(|c| (&c.key, c.score)).collect::<Vec<_>>()
    );

    let top_proj_score = proj_keys.iter().map(|c| c.score).fold(0.0_f64, f64::max);
    let max_foreign_score = resp
        .capsules
        .iter()
        .filter(|c| {
            c.key.as_deref().is_some_and(|k| {
                let tail = k.strip_prefix("global::").unwrap_or(k);
                tail.starts_with("flutter-layout")
                    || tail.starts_with("android-app-design")
                    || tail.starts_with("apple-hig-design")
                    || tail.starts_with("linux-desktop-hig-design")
            })
        })
        .map(|c| c.score)
        .fold(0.0_f64, f64::max);
    assert!(
        max_foreign_score == 0.0 || max_foreign_score < top_proj_score,
        "Foreign stack skills must be attenuated/suppressed in Cargo.toml workspace: proj={top_proj_score:.2}, foreign={max_foreign_score:.2}"
    );

    let mut flutter_req = PulseRequest::new("flutter desktop layout architecture", 1800);
    flutter_req.workspace_dir = Some(proj_dir.clone());
    flutter_req.epoch = 2;
    let flutter_resp = brain.pulse(&flutter_req).unwrap();
    assert!(
        flutter_resp.capsules.iter().any(|c| {
            c.key
                .as_deref()
                .is_some_and(|k| k.strip_prefix("global::").unwrap_or(k).starts_with("flutter-layout"))
        }),
        "Explicit query mentioning flutter must opt back in without foreign stack attenuation"
    );

    for (epoch, query, expected_prefix) in [
        (3u32, "android material compose layout architecture", "android-app-design"),
        (4u32, "apple hig macos swiftui design layout", "apple-hig-design"),
        (5u32, "linux gnome libadwaita kirigami design architecture", "linux-desktop-hig-design"),
    ] {
        let mut opt_in = PulseRequest::new(query, 1800);
        opt_in.workspace_dir = Some(proj_dir.clone());
        opt_in.epoch = epoch;
        let opt_resp = brain.pulse(&opt_in).unwrap();
        assert!(
            opt_resp.capsules.iter().any(|c| {
                c.key
                    .as_deref()
                    .is_some_and(|k| k.strip_prefix("global::").unwrap_or(k).starts_with(expected_prefix))
            }),
            "Explicit platform query '{query}' must surface '{expected_prefix}'"
        );
    }

    // Apple workspace markers (.xcodeproj) must keep apple-hig-design unattenuated and suppress windows-app-design.
    let apple_dir = dir.join("ios_app");
    fs::create_dir_all(apple_dir.join("MyApp.xcodeproj")).unwrap();
    let mut apple_ws_req = PulseRequest::new("UI design architecture layout", 1800);
    apple_ws_req.workspace_dir = Some(apple_dir);
    apple_ws_req.epoch = 6;
    let apple_ws_resp = brain.pulse(&apple_ws_req).unwrap();
    let apple_score = apple_ws_resp
        .capsules
        .iter()
        .filter(|c| {
            c.key
                .as_deref()
                .is_some_and(|k| k.strip_prefix("global::").unwrap_or(k).starts_with("apple-hig-design"))
        })
        .map(|c| c.score)
        .fold(0.0_f64, f64::max);
    let win_score_in_apple = apple_ws_resp
        .capsules
        .iter()
        .filter(|c| {
            c.key
                .as_deref()
                .is_some_and(|k| k.strip_prefix("global::").unwrap_or(k).starts_with("windows-app-design"))
        })
        .map(|c| c.score)
        .fold(0.0_f64, f64::max);
    assert!(
        apple_score > 0.0 && apple_score > win_score_in_apple,
        "In .xcodeproj workspace apple-hig-design ({apple_score:.2}) must outrank attenuated windows-app-design ({win_score_in_apple:.2})"
    );

    drop(brain);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn causal_error_binding_blocks_cli_noise_dead_code_neighbor_symbols_and_duplicates() {
    let dir = temp_test_dir("causal_guards");
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(dir.join(".agents")).unwrap();

    let initial_src = "\
pub fn draw_status_icon(active: bool) -> u32 {
    if active { 1 } else { 0 }
}

pub fn compute_metric_hash(seed: u64) -> u64 {
    seed.wrapping_mul(31)
}
";
    let src_file = src_dir.join("lib.rs");
    fs::write(&src_file, initial_src).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"guard_test\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let db = LibreDb::open(dir.join(".agents").join("memory.ldb")).unwrap();
    index_workspace(&db, &dir, false).unwrap();

    // 1. CLI flag/subcommand noise, OS lock/access errors, and dead_code/unused warnings are rejected.
    for noise in [
        "error: unexpected argument '--bogus' found\nUnknown flag '--bogus'\nFor more information, try '--help'",
        "Error: Unknown subcommand 'bogus'",
        "Access is denied. (os error 5)",
        "warning: function `draw_status_icon` is never used",
    ] {
        assert!(
            is_banal_syntax_error(noise),
            "Noise diagnostic should fail Stage 1 filter: {noise}"
        );
        assert!(
            !record_error_cue(&db, noise, Some("cargo test")).unwrap(),
            "record_error_cue must reject non-causal noise: {noise}"
        );
    }

    // 2. Guard C: neighbor-symbol isolation prevents unrelated edits in the same file from stealing cues.
    assert!(record_error_cue(
        &db,
        "src/lib.rs:2:5: error[E0425]: cannot find value `draw_status_icon` in this scope",
        Some("cargo check"),
    )
    .unwrap());
    let edited_neighbor = initial_src.replace("seed.wrapping_mul(31)", "seed.wrapping_mul(37)");
    stage_tentative_file_edit(&db, &dir, &src_file, None, edited_neighbor.as_bytes(), 12).unwrap();
    fs::write(&src_file, &edited_neighbor).unwrap();
    reconcile_tentative_edits(&db, &dir).unwrap();

    let rep_neighbor = learning_state_report(&db, 10);
    assert!(
        rep_neighbor.learned_pitfalls.is_empty(),
        "Editing compute_metric_hash must not consume an E0425 cue naming `draw_status_icon`: {:?}",
        rep_neighbor.learned_pitfalls
    );
    assert_eq!(
        rep_neighbor.pending_errors.len(),
        1,
        "Protected cue for `draw_status_icon` must remain pending after unrelated symbol edit"
    );

    // Editing the actual target symbol (`draw_status_icon`) consumes the pending E0425 cue.
    let edited_draw_once = edited_neighbor.replace(
        "pub fn draw_status_icon(active: bool) -> u32 {\n    if active { 1 } else { 0 }",
        "pub fn draw_status_icon(active: bool) -> u32 {\n    let icon_state = if active { 2 } else { 0 };\n    icon_state",
    );
    stage_tentative_file_edit(&db, &dir, &src_file, None, edited_draw_once.as_bytes(), 16).unwrap();
    fs::write(&src_file, &edited_draw_once).unwrap();
    reconcile_tentative_edits(&db, &dir).unwrap();
    let rep_once = learning_state_report(&db, 10);
    assert_eq!(
        rep_once.learned_pitfalls.len(),
        1,
        "Target edit on draw_status_icon must consume its E0425 cue: {:?}",
        rep_once.learned_pitfalls
    );

    // 3. Guard D: two co-occurring cues on a matching edit coalesce into a single coded pitfall.
    assert!(record_error_cue(
        &db,
        "error: wrong arity when calling draw_status_icon helper",
        Some("cargo check"),
    )
    .unwrap());
    assert!(record_error_cue(
        &db,
        "src/lib.rs:1:1: error[E0061]: this function takes 2 arguments but 1 argument was supplied",
        Some("cargo check"),
    )
    .unwrap());
    let edited_target = edited_draw_once.replace(
        "pub fn draw_status_icon(active: bool) -> u32 {\n    let icon_state = if active { 2 } else { 0 };\n    icon_state",
        "pub fn draw_status_icon(active: bool, force_redraw: bool) -> u32 {\n    if active || force_redraw { 1 } else { 0 }",
    );
    stage_tentative_file_edit(&db, &dir, &src_file, None, edited_target.as_bytes(), 16).unwrap();
    fs::write(&src_file, &edited_target).unwrap();
    reconcile_tentative_edits(&db, &dir).unwrap();

    let rep_coalesced = learning_state_report(&db, 10);
    assert_eq!(
        rep_coalesced.learned_pitfalls.len(),
        2,
        "Guard D must coalesce the two co-occurring Step 3 cues into 1 additional pitfall (2 total): {:?}",
        rep_coalesced.learned_pitfalls
    );
    assert!(
        rep_coalesced
            .learned_pitfalls
            .iter()
            .any(|p| p.error_code.as_deref() == Some("e0061")),
        "Guard D must prefer the file-hinted + error-coded E0061 cue over the generic fallback: {:?}",
        rep_coalesced.learned_pitfalls
    );

    // 4. sanitize_learning_artifacts cleans injected legacy noise cues, noise pitfalls, and duplicates.
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    db.put(
        WriteRequest::new(
            NodeKind::Generic,
            serde_json::to_vec(&vec![
                PendingErrorCue {
                    fingerprint_id: "cue_noise".to_owned(),
                    error_code: None,
                    error_tokens: vec!["access".to_owned(), "denied".to_owned()],
                    raw_excerpt: "Access is denied. (os error 5)".to_owned(),
                    action_hint: None,
                    file_hint: None,
                    recorded_at_ns: now_ns,
                },
                PendingErrorCue {
                    fingerprint_id: "cue_clean".to_owned(),
                    error_code: Some("e0308".to_owned()),
                    error_tokens: vec!["e0308".to_owned(), "compute_metric_hash".to_owned()],
                    raw_excerpt: "error[E0308]: mismatched types in compute_metric_hash".to_owned(),
                    action_hint: Some("cargo test".to_owned()),
                    file_hint: Some("src/lib.rs".to_owned()),
                    recorded_at_ns: now_ns,
                },
            ])
            .unwrap(),
        )
        .with_key(PENDING_ERROR_CUES_KEY),
    )
    .unwrap();

    let mut book = ErrorPitfallBook::default();
    book.pitfalls.insert(
        "pitfall_bogus_cli".to_owned(),
        LearnedPitfallEntry {
            id: "pitfall_bogus_cli".to_owned(),
            error_code: None,
            trigger_tokens: vec!["bogus".to_owned()],
            action_tokens: vec!["libredb".to_owned()],
            affected_symbols: vec!["src/lib.rs::compute_metric_hash".to_owned()],
            resolution_tokens: vec!["wrapping_mul".to_owned()],
            directive: "Avoid repeat error (Unknown flag '--bogus' in CLI) in [src/lib.rs::compute_metric_hash]: apply verified fix tokens [wrapping_mul].".to_owned(),
            confidence: 0.80,
            occurrences: 1,
            last_learned_ns: now_ns,
            supersedes: Vec::new(),
        },
    );
    book.pitfalls.insert(
        "pitfall_dup_uncoded".to_owned(),
        LearnedPitfallEntry {
            id: "pitfall_dup_uncoded".to_owned(),
            error_code: None,
            trigger_tokens: vec!["compute_metric_hash".to_owned()],
            action_tokens: Vec::new(),
            affected_symbols: vec!["src/lib.rs::compute_metric_hash".to_owned()],
            resolution_tokens: vec!["wrapping_add".to_owned()],
            directive: "Avoid repeat error (error: wrong arithmetic in compute_metric_hash) in [src/lib.rs::compute_metric_hash]: apply verified fix tokens [wrapping_add].".to_owned(),
            confidence: 0.80,
            occurrences: 1,
            last_learned_ns: now_ns,
            supersedes: Vec::new(),
        },
    );
    book.pitfalls.insert(
        "e0308_dup_coded".to_owned(),
        LearnedPitfallEntry {
            id: "e0308_dup_coded".to_owned(),
            error_code: Some("e0308".to_owned()),
            trigger_tokens: vec!["e0308".to_owned(), "compute_metric_hash".to_owned()],
            action_tokens: Vec::new(),
            affected_symbols: vec!["src/lib.rs::compute_metric_hash".to_owned()],
            resolution_tokens: vec!["wrapping_add".to_owned()],
            directive: "Avoid repeat error (error[E0308]: mismatched arithmetic in compute_metric_hash) in [src/lib.rs::compute_metric_hash]: apply verified fix tokens [wrapping_add].".to_owned(),
            confidence: 0.80,
            occurrences: 1,
            last_learned_ns: now_ns,
            supersedes: Vec::new(),
        },
    );
    db.put(
        WriteRequest::new(NodeKind::Generic, serde_json::to_vec(&book).unwrap())
            .with_key(ERROR_PITFALL_BOOK_KEY),
    )
    .unwrap();

    let (purged_cues, purged_pitfalls) = sanitize_learning_artifacts(&db).unwrap();
    assert_eq!(purged_cues, 1, "Must purge 1 os error 5 cue");
    assert_eq!(
        purged_pitfalls, 2,
        "Must purge 1 CLI-flag pitfall and 1 uncoded duplicate pitfall"
    );
    let rep_after = learning_state_report(&db, 10);
    assert_eq!(rep_after.pending_errors.len(), 1);
    assert_eq!(rep_after.pending_errors[0].fingerprint_id, "cue_clean");
    assert_eq!(rep_after.learned_pitfalls.len(), 1);
    assert_eq!(rep_after.learned_pitfalls[0].id, "e0308_dup_coded");

    drop(db);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn check_german_prose_style_skips_html_code_blocks_cli_flags_ps_cmdlets_and_wifi() {
    let clean_html = format!(
        "<!DOCTYPE html>\n\
<html lang=\"de\">\n\
<head>\n\
  <style>\n\
    .{css_hdr} {{ color: #222; }}\n\
  </style>\n\
  <script>\n\
    const AutoScroll = '{ps_script}';\n\
  </script>\n\
</head>\n\
<body>\n\
  <!-- {cmt_tag}: {u_word} {p_word} {ps_stop} -->\n\
  <p class=\"{attr_cls}\">Dieser Bericht pr{u_uml}ft das System, weil keine Fehler vorliegen.</p>\n\
  <p>Verbauter Adapter: <code>Intel {wifi_tok} 6E AX211 160MHz</code> ohne St{o_uml}rung.</p>\n\
  <p>Dienstbefehl: <code>{ps_stop} WinRM; {ps_set} WinRM -StartupType Disabled</code>.</p>\n\
  <p>Systemwartung: <code>DISM /Online {cli_clean} /RestoreHealth</code> abschlie{sz_ch}en.</p>\n\
  <pre><code>\n\
{ps_evt} -LogName System\n\
{ps_rst} -Force\n\
  </code></pre>\n\
  <p>Auch im Flie{sz_ch}text sind {wifi_tok}, {ps_stop}, {ps_set}, {cli_clean} und {cli_dry} erlaubt.</p>\n\
</body>\n\
</html>\n",
        css_hdr = concat!("Report", "-Header"),
        ps_script = concat!("Enable", "-Feature"),
        cmt_tag = concat!("Auto", "-Comment"),
        u_word = concat!("ue", "ber"),
        p_word = concat!("prue", "fen"),
        attr_cls = concat!("Auto", "-Box"),
        wifi_tok = concat!("Wi", "-Fi"),
        ps_stop = concat!("Stop", "-Service"),
        ps_set = concat!("Set", "-Service"),
        ps_evt = concat!("Get", "-WinEvent"),
        ps_rst = concat!("Restart", "-Computer"),
        cli_clean = concat!("/Cleanup", "-Image"),
        cli_dry = concat!("--Dry", "-Run"),
        u_uml = "\u{00fc}",
        o_uml = "\u{00f6}",
        sz_ch = "\u{00df}",
    );
    let clean_v = check_german_prose_style(&clean_html, "report.html");
    assert!(
        clean_v.is_empty(),
        "Valid German HTML report with code blocks, wireless LAN tokens, PowerShell cmdlets, and CLI switches must pass: {clean_v:?}"
    );

    let bad_html = format!(
        "<p>Dieser {bad_tok} muss erkannt werden, weil ein Deppenbindestrich vorliegt.</p>",
        bad_tok = concat!("Auto", "-", "Modus"),
    );
    let bad_v = check_german_prose_style(&bad_html, "report.html");
    assert_eq!(
        bad_v.len(),
        1,
        "Expected real German Deppenbindestrich outside <code> in HTML prose to be flagged: {bad_v:?}"
    );
    assert_eq!(bad_v[0].rule, "german-deppenbindestrich");

    let dual_ps_german = format!(
        "<p>Dieser {test_tok} ist nicht zul{a_uml}ssig.</p>",
        test_tok = concat!("Test", "-", "Laufzeit"),
        a_uml = "\u{00e4}",
    );
    let dual_v = check_german_prose_style(&dual_ps_german, "report.html");
    assert!(
        dual_v.iter().any(|v| v.rule == "german-deppenbindestrich"),
        "German compound noun with 'Test-' + German root must still be flagged: {dual_v:?}"
    );
}

#[test]
fn pulse_suppresses_single_word_global_skill_fillers_and_admin_ui_reflex_false_positives() {
    let base = temp_test_dir("pulse_v221_noise");
    let gdb = Arc::new(LibreDb::open(&base.join("global.ldb")).unwrap());
    let pdb = Arc::new(LibreDb::open(&base.join("project.ldb")).unwrap());

    gdb.put(
        WriteRequest::new(
            NodeKind::Rule,
            b"Always verify Winlogon, LogonUI, Credential Provider, and display driver event logs on Windows 11 25H2 systems.".to_vec(),
        )
        .with_key("local-admin")
        .with_importance(240),
    )
    .unwrap();

    for (key, body) in [
        (
            "flutter-build-responsive-layout::Layout Provider",
            "[flutter-build-responsive-layout > Layout Provider]\nUse MediaQuery and LayoutBuilder Provider widgets.",
        ),
        (
            "gcp-managed-airflow-migrations::Provider Policy",
            "[gcp-managed-airflow-migrations > Provider Policy]\nConfigure Airflow Provider Policy roles for GCP Composer.",
        ),
        (
            "firebase-auth-basics::Credential Provider",
            "[firebase-auth-basics > Credential Provider]\nConfigure OAuth Credential Provider in Firebase Console.",
        ),
        (
            "federate-lakehouse-catalog::Governance Policy",
            "[federate-lakehouse-catalog > Governance Policy]\nDatabricks Lakehouse Unity Catalog Provider setup.",
        ),
        (
            "a11y-debugging::Screen Report",
            "[a11y-debugging > Screen Report]\nInspect ARIA roles and Screen Report output.",
        ),
    ] {
        gdb.put(
            WriteRequest::new(NodeKind::SkillSection, body.as_bytes().to_vec())
                .with_key(key)
                .with_importance(210),
        )
        .unwrap();
    }

    ReflexEngine::learn_reflex(
        &gdb,
        &ReflexRule {
            id: "windows-fluent-app-design".to_owned(),
            stack_any: vec!["winui".to_owned(), "egui".to_owned(), "fluent 2".to_owned()],
            action_any: vec!["ui".to_owned(), "layout".to_owned(), "design".to_owned()],
            exclude_any: vec![
                "winlogon".to_owned(),
                "logonui".to_owned(),
                "credential provider".to_owned(),
                "taskmanager".to_owned(),
                "grafiktreiber".to_owned(),
            ],
            env_or_error_any: Vec::new(),
            directive: "Apply Fluent 2 / native UI guidelines cleanly.".to_owned(),
            ..Default::default()
        },
    )
    .unwrap();
    // Separate rule testing word-boundary matching for short/ambiguous tokens (`ui`, `window`)
    // without `exclude_any`: neither `"LogonUI"` (`"ui"`) nor `"Windows"` (`"window"`) may match.
    ReflexEngine::learn_reflex(
        &gdb,
        &ReflexRule {
            id: "word-boundary-ui-guard".to_owned(),
            stack_any: vec!["window".to_owned()],
            action_any: vec!["ui".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Window UI boundary rule.".to_owned(),
            ..Default::default()
        },
    )
    .unwrap();

    {
        let mut cog = CognitiveEngine::open_db(Arc::clone(&gdb)).unwrap();
        cog.save_index_snapshot().unwrap();
    }

    let brain = OverlayBrain::open(Some(gdb), pdb).unwrap();
    let admin_req = PulseRequest::new(
        "25H2 Windows 11 notebook Winlogon LogonUI Taskmanager Grafiktreiber Credential Provider",
        1200,
    );
    let admin_resp = brain.pulse(&admin_req).unwrap();

    assert!(
        !admin_resp
            .fired_reflexes
            .iter()
            .any(|r| r.id == "windows-fluent-app-design" || r.id == "word-boundary-ui-guard"),
        "OS diagnostic query must never trigger UI design reflexes: {:?}",
        admin_resp.fired_reflexes
    );
    let keys: Vec<String> = admin_resp
        .capsules
        .iter()
        .filter_map(|c| c.key.clone())
        .collect();
    assert!(
        keys.iter().any(|k| k == "global::local-admin"),
        "Expected matching admin rule 'global::local-admin' in capsules: {keys:?}"
    );
    for noisy_prefix in [
        "flutter-build-responsive-layout",
        "gcp-managed-airflow-migrations",
        "firebase-auth-basics",
        "federate-lakehouse-catalog",
        "a11y-debugging",
    ] {
        assert!(
            !keys
                .iter()
                .any(|k| k.strip_prefix("global::").unwrap_or(k).starts_with(noisy_prefix)),
            "Single-word unrelated global skill filler '{noisy_prefix}' must be suppressed: {keys:?}"
        );
    }

    // Genuine UI design query still fires the reflex cleanly.
    let mut ui_req = PulseRequest::new("Build a WinUI Fluent 2 toolbar UI layout", 1200);
    ui_req.conversation_id = Some("conv-ui-real".to_owned());
    let ui_resp = brain.pulse(&ui_req).unwrap();
    assert!(
        ui_resp
            .fired_reflexes
            .iter()
            .any(|r| r.id == "windows-fluent-app-design"),
        "Genuine UI design query must still fire windows-fluent-app-design: {:?}",
        ui_resp.fired_reflexes
    );

    // Explicit framework query still resolves the explicitly requested skill.
    let mut flutter_req = PulseRequest::new("flutter", 600);
    flutter_req.conversation_id = Some("conv-flutter".to_owned());
    let flutter_resp = brain.pulse(&flutter_req).unwrap();
    assert!(
        flutter_resp.capsules.iter().any(|c| {
            c.key.as_deref().is_some_and(|k| {
                k.strip_prefix("global::")
                    .unwrap_or(k)
                    .starts_with("flutter-build-responsive-layout")
            })
        }),
        "Explicit single-word skill query 'flutter' must still retrieve flutter skill: {:?}",
        flutter_resp.capsules
    );

    let _ = fs::remove_dir_all(&base);
}
