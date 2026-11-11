//! Command-line interface, lifecycle hooks, Gitea automation, and native MCP server for `LibreDB`.

mod cli_args;
mod gitea;
mod hooks;
mod mcp;
mod security;

use cli_args::CliSpec;

use libredb_bridge::{
    export_sqlite_database, import_sqlite_readonly, open_or_auto_migrate, verify_sqlite_equivalence,
};
use libredb_cognitive::{
    audit_workspace_guardrails_with_prefixes, create_subagent_handoff, execute_atomic_batch,
    extract_fim_slice, index_workspace_with_exclusions, query_symbol_impact, sync_transcript_epoch,
    AtomicBatchSpec, CognitiveEngine, FileSkeleton, OverlayBrain, PulseRequest, ReflexEngine,
    ReflexRule,
};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn print_usage() {
    println!(
        "LibreDB v{} - Tailored cognitive memory, workspace graph & MCP engine for Antigravity

Antigravity Cognitive & Code-Graph Commands:
  libredb pulse <db.ldb> <query> [--global <g.ldb>] [--cid <id>] [--transcript <t.jsonl>] [--epoch <n>] [--budget <tok>] [--cwd <dir>] [--err <msg>]
  libredb index-workspace <db.ldb> <workspace_dir> [--force]
  libredb skeleton <db.ldb> <source_file> [--filter <substr>]
  libredb impact <db.ldb> <symbol_query>
  libredb fim <db.ldb> <source_file> [--symbol <name> | --line <n>] [--pad <lines>]
  libredb batch <db.ldb> [--fact k=v]... [--decision Title::Body]... [--task key::title::status::prio]... [--snapshot <summary>]
  libredb handoff <db.ldb> <handoff_id> <task_key> <role> [--notes <text>]
  libredb learn-assoc <db.ldb> <cue_phrase> <target_id_1,target_id_2>
  libredb learn-reflex <db.ldb> <id> <directive> [--stack <s1,s2>] [--action <a1,a2>] [--env <e1,e2>]
  libredb get-skill <skill_name> [--section <title>] [--global <customizations.ldb>]
  libredb sync-skill <SKILL.md> [--name <skill_name>] [--global <customizations.ldb>]
  libredb list-rules [--global <customizations.ldb>]
  libredb list-skills [--global <customizations.ldb>]
  libredb list-reflexes [--global <customizations.ldb>]
  libredb modernize-global [--global <customizations.ldb>] [--skill-md <SKILL.md>] [--profile neutral|personal] [--migrate-legacy]
  libredb mcp-serve [<default_project.ldb>] [--global <customizations.ldb>] [--workspace-root <dir>]

Security, Trust & Universal Configuration Commands:
  libredb trust [<dir>] [--revoke] [--list] [--reinit-lost] [--accept-rollback] [--migrate-v3 [--confirm-metadata]] [--migrate-v2] [--if-clean] [--global <customizations.ldb>]
  libredb config <get|set|unset|list> [<key>] [<value>] [--project <dir>] [--global <customizations.ldb>]
  libredb guardrail check [--path <dir>] [--staged] [--strict]
  libredb hook-pre-tool [--global <customizations.ldb>]
  libredb hook-pre-invocation [--global <customizations.ldb>]
  libredb gitea-status [--global <customizations.ldb>]
  libredb gitea-config [--url <u>] [--user <usr>] [--token <tok> | --token-stdin] [--allow-insecure-http <bool>] [--register-helper]
  libredb gitea-credential-helper [get]
  libredb git-init | gitea-init [<dir>] [--name <repo>] [--use-existing] [--overwrite]
  libredb git-sync | gitea-sync [-m <msg>] [--project <dir>] [--remote <r>] [--all-remotes] [--github] [--releases] [--allow-unversioned]
  libredb git-release | gitea-release [vX.Y.Z] [--project <dir>] [--remote <r>] [--all-remotes] [--github]

Lossless 1:1 SQLite Bridge Commands:
  libredb import-sqlite <db.ldb> <source.db> [--scope central|project]
  libredb export-sqlite <db.ldb> <reconstructed.db> [--scope central|project]
  libredb verify-roundtrip <source.db> [--scope central|project]

Core Storage & Graph Commands:
  libredb init <db.ldb>
  libredb put <db.ldb> <kind> <payload> [--key <key>] [--importance <0..255>] [--pin]
  libredb get <db.ldb> <node_id>
  libredb get-key <db.ldb> <kind> <key>
  libredb link <db.ldb> <src_id> <edge_kind> <dst_id> [--weight <0..255>]
  libredb deprecate <db.ldb> <kind> <key>
  libredb trace <db.ldb> <node_id> [--depth <n>]
  libredb recall <db.ldb> <seed_id> [--hops <n>] [--budget <tokens>]
  libredb compact <db.ldb> [--prune]
  libredb stats <db.ldb> [--json]
  libredb verify <db.ldb>
  libredb bench [--nodes <n>] [--threads <t>]",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    run_with_args(&args)
}

fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }
    if args[0] == "--version" || args[0] == "-V" || args[0] == "version" {
        println!("libredb {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let sub_args = &args[1..];
    match args[0].as_str() {
        "mcp-serve" => {
            let cli = CliSpec::new(
                "mcp-serve",
                "libredb mcp-serve [<default_project.ldb>] [--global <customizations.ldb>] [--workspace-root <dir>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .values(&["--project", "--workspace-root"])
            .parse(sub_args)?;
            if cli.value("--project").is_some() && !cli.positionals.is_empty() {
                return Err(
                    "Cannot specify both positional <default_project.ldb> and '--project' in 'mcp-serve'"
                        .into(),
                );
            }
            let proj_path = cli
                .path_value("--project")
                .or_else(|| cli.positionals.first().map(PathBuf::from));
            let ws_root = cli.path_value("--workspace-root");
            mcp::run_mcp_stdio_server_with_workspace_root(
                proj_path.as_deref(),
                cli.global_deref(),
                ws_root.as_deref(),
            )?;
        }
        "hook-pre-tool" => {
            let cli = CliSpec::new(
                "hook-pre-tool",
                "libredb hook-pre-tool [--global <customizations.ldb>]",
            )
            .positionals(0, Some(0))
            .allow_global()
            .parse(sub_args)?;
            hooks::run_pre_tool_hook(cli.global_deref())?;
        }
        "hook-pre-invocation" => {
            let cli = CliSpec::new(
                "hook-pre-invocation",
                "libredb hook-pre-invocation [--global <customizations.ldb>]",
            )
            .positionals(0, Some(0))
            .allow_global()
            .parse(sub_args)?;
            hooks::run_pre_invocation_hook(cli.global_deref())?;
        }
        "guardrail" => {
            let cli = CliSpec::new(
                "guardrail",
                "libredb guardrail check [--path <dir>] [--staged] [--strict] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .switches(&["--staged", "--strict"])
            .values(&["--path"])
            .parse(sub_args)?;
            let sub = cli.positionals.first().map(String::as_str).unwrap_or("check");
            if sub != "check" {
                return Err(
                    "Usage: libredb guardrail check [--path <dir>] [--staged] [--strict]".into(),
                );
            }
            let dir = cli
                .path_value("--path")
                .map(Ok)
                .unwrap_or_else(env::current_dir)?;
            let staged = cli.has_switch("--staged");
            let strict = cli.has_switch("--strict");
            let gdb_res = hooks::open_global_ldb_checked(cli.global_deref());
            let gdb_opt = gdb_res.as_ref().ok().and_then(Clone::clone);
            let pdb_opt = if gdb_res.is_ok()
                && security::is_workspace_memory_trusted(gdb_opt.as_deref(), &dir)
            {
                let p = dir.join(".agents").join("memory.ldb");
                p.is_file().then(|| LibreDb::open(&p).ok()).flatten()
            } else {
                None
            };
            let custom_prefixes = security::load_config_list(
                gdb_opt.as_deref(),
                pdb_opt.as_ref(),
                "guardrail:secret_prefixes",
            );
            let rep = audit_workspace_guardrails_with_prefixes(&dir, staged, &custom_prefixes)?;
            if rep.passed(strict) {
                println!("=== LIBREDB GUARDRAIL AUDIT REPORT: [PASSED] ===");
                println!("  Files Checked:      {}", rep.files_checked);
                println!("  Violations Found:   0");
                println!("================================================");
            } else {
                println!("=== LIBREDB GUARDRAIL AUDIT REPORT: [FAILED] ===");
                println!("  Files Checked:      {}", rep.files_checked);
                println!("  Violations Found:   {}", rep.violations.len());
                for v in &rep.violations {
                    println!(
                        "  * [{}] {} ({}:L{}): {} -> '{}'",
                        v.severity, v.rule, v.file, v.line, v.message, v.snippet
                    );
                }
                println!("================================================");
                process::exit(1);
            }
        }
        "trust" => {
            let cli = CliSpec::new(
                "trust",
                "libredb trust [<dir>] [--revoke] [--list] [--reinit-lost] [--accept-rollback] [--migrate-v3 [--confirm-metadata]] [--migrate-v2] [--if-clean] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .switches(&[
                "--revoke",
                "--list",
                "--migrate-v2",
                "--migrate-v3",
                "--confirm-metadata",
                "--reinit-lost",
                "--accept-rollback",
                "--if-clean",
            ])
            .parse(sub_args)?;
            let dir_opt = cli.positionals.first().map(PathBuf::from);
            let revoke = cli.has_switch("--revoke");
            let list = cli.has_switch("--list");
            let migrate_v2 = cli.has_switch("--migrate-v2");
            let migrate_v3 = cli.has_switch("--migrate-v3");
            let confirm_metadata = cli.has_switch("--confirm-metadata");
            let reinit_lost = cli.has_switch("--reinit-lost");
            let accept_rollback = cli.has_switch("--accept-rollback");
            let if_clean = cli.has_switch("--if-clean");
            let gdb = hooks::open_global_ldb(cli.global_deref())?;
            if list {
                let items = security::list_trusted_workspaces(&gdb)?;
                println!("=== Trusted Workspaces ({}) ===", items.len());
                for (_, display_path) in items {
                    println!("  * {display_path}");
                }
            } else if migrate_v3 {
                if let Some(target_dir) = dir_opt {
                    let abs = std::fs::canonicalize(&target_dir).unwrap_or(target_dir);
                    let clean = gitea::strip_verbatim_prefix(&abs);
                    if security::migrate_workspace_seal_v3_to_v4(&gdb, &clean, confirm_metadata)? {
                        println!(
                            "[OK] Verified legacy v0.9.3 HMAC + Inode invariants and upgraded workspace '{}' to v4 metadata-bound seal",
                            clean.display()
                        );
                    } else {
                        println!(
                            "[OK] Workspace '{}' already carries a valid v4 metadata-bound trust seal",
                            clean.display()
                        );
                    }
                } else {
                    let mut migrated = 0usize;
                    let mut already_valid = 0usize;
                    let mut rejected = 0usize;
                    for (_, raw_ws) in security::list_trusted_workspaces(&gdb)? {
                        let ws_path = PathBuf::from(raw_ws.trim());
                        if !ws_path.is_dir()
                            || (!ws_path.join(".agents").join("memory.ldb").is_file()
                                && !security::has_prior_workspace_seal_marker(&gdb, &ws_path))
                        {
                            continue;
                        }
                        match security::migrate_workspace_seal_v3_to_v4(
                            &gdb,
                            &ws_path,
                            confirm_metadata,
                        ) {
                            Ok(true) => migrated += 1,
                            Ok(false) => already_valid += 1,
                            Err(msg) => {
                                rejected += 1;
                                eprintln!(
                                    "[WARN] Refused v3->v4 seal migration for '{}': {msg}",
                                    ws_path.display()
                                );
                            }
                        }
                    }
                    println!(
                        "[OK] Workspace v3->v4 seal migration summary: {migrated} upgraded, {already_valid} already v4, {rejected} rejected"
                    );
                    if rejected > 0 {
                        return Err(format!(
                            "{rejected} workspace(s) require inspection / '--confirm-metadata' or failed v3 HMAC verification and remain quarantined"
                        )
                        .into());
                    }
                }
            } else if migrate_v2 {
                if let Some(target_dir) = dir_opt {
                    let abs = std::fs::canonicalize(&target_dir).unwrap_or(target_dir);
                    let clean = gitea::strip_verbatim_prefix(&abs);
                    if security::migrate_workspace_seal_v2_to_v3(&gdb, &clean)? {
                        println!(
                            "[OK] Verified legacy v2 HMAC and upgraded workspace '{}' to content-bound v4 seal",
                            clean.display()
                        );
                    } else {
                        println!(
                            "[OK] Workspace '{}' already carries a valid content-bound v4 trust seal",
                            clean.display()
                        );
                    }
                } else {
                    let mut migrated = 0usize;
                    let mut already_valid = 0usize;
                    let mut rejected = 0usize;
                    for (_, raw_ws) in security::list_trusted_workspaces(&gdb)? {
                        let ws_path = PathBuf::from(raw_ws.trim());
                        if !ws_path.is_dir()
                            || (!ws_path.join(".agents").join("memory.ldb").is_file()
                                && !security::has_prior_workspace_seal_marker(&gdb, &ws_path))
                        {
                            continue;
                        }
                        match security::migrate_workspace_seal_v2_to_v3(&gdb, &ws_path) {
                            Ok(true) => migrated += 1,
                            Ok(false) => already_valid += 1,
                            Err(msg) => {
                                rejected += 1;
                                eprintln!("[WARN] Refused v2->v3 seal migration for '{}': {msg}", ws_path.display());
                            }
                        }
                    }
                    println!(
                        "[OK] Workspace v2->v4 seal migration summary: {migrated} upgraded, {already_valid} already v4, {rejected} rejected"
                    );
                    if rejected > 0 {
                        return Err(format!("{rejected} workspace(s) failed v2 HMAC verification and remain quarantined").into());
                    }
                }
            } else {
                security::check_global_trust_sync(&gdb)?;
                let target_dir = dir_opt.unwrap_or(env::current_dir()?);
                let abs = std::fs::canonicalize(&target_dir).unwrap_or(target_dir);
                let clean = gitea::strip_verbatim_prefix(&abs);
                if revoke {
                    security::revoke_workspace_trust(&gdb, &clean)?;
                    println!("[OK] Revoked workspace trust for '{}'", clean.display());
                } else if if_clean {
                    if security::is_workspace_memory_trusted(Some(&gdb), &clean) {
                        let ldb_path = clean.join(".agents").join("memory.ldb");
                        let (pdb, _) = hooks::open_project_ldb_silent(&ldb_path)?;
                        security::seal_workspace_memory(&gdb, &pdb, &clean)?;
                        println!(
                            "[OK] Trusted and cryptographically sealed clean workspace '{}'",
                            clean.display()
                        );
                    } else if security::is_unsealed_replacement_of_sealed_workspace(&gdb, &clean) {
                        println!(
                            "[WARN] Skipping automatic workspace trust for '{}': previously sealed .agents/memory.ldb is missing, unsealed, or rolled back to empty; restore from backup or run 'libredb trust --reinit-lost \"{}\"' if intentionally starting fresh.",
                            clean.display(),
                            clean.display()
                        );
                    } else if let Some((proj_rev, global_rev)) =
                        security::detect_workspace_seal_rollback(&gdb, &clean)?
                    {
                        println!(
                            "[WARN] Skipping automatic workspace trust for '{}': .agents/memory.ldb carries older seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (historical snapshot rollback detected); restore the latest database or run 'libredb trust --accept-rollback \"{}\"' if intentionally restoring a backup.",
                            clean.display(),
                            clean.display()
                        );
                    } else {
                        println!(
                            "[WARN] Skipping automatic workspace trust for '{}': pre-existing .agents database has an unverified or modified seal; inspect and run 'libredb trust \"{}\"' manually if trusted.",
                            clean.display(),
                            clean.display()
                        );
                    }
                } else if !reinit_lost
                    && security::is_unsealed_replacement_of_sealed_workspace(&gdb, &clean)
                {
                    return Err(format!(
                        "Workspace '{}' was previously sealed on this host, but .agents/memory.ldb is now missing, unsealed, or rolled back to empty. Restore .agents/memory.ldb from backup or pass '--reinit-lost' ('libredb trust --reinit-lost \"{}\"') to explicitly re-initialize workspace trust after database loss.",
                        clean.display(),
                        clean.display()
                    )
                    .into());
                } else if !accept_rollback && !reinit_lost {
                    if let Some((proj_rev, global_rev)) =
                        security::detect_workspace_seal_rollback(&gdb, &clean)?
                    {
                        return Err(format!(
                            "Workspace '{}' carries an older valid seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (historical snapshot rollback detected). Restore the latest .agents/memory.ldb or pass '--accept-rollback' ('libredb trust --accept-rollback \"{}\"') to explicitly adopt this older backup.",
                            clean.display(),
                            clean.display()
                        )
                        .into());
                    }
                    let ldb_path = clean.join(".agents").join("memory.ldb");
                    let (pdb, _) = hooks::open_project_ldb_silent(&ldb_path)?;
                    security::seal_workspace_memory(&gdb, &pdb, &clean)?;
                    println!(
                        "[OK] Trusted and cryptographically sealed workspace '{}'",
                        clean.display()
                    );
                } else {
                    let ldb_path = clean.join(".agents").join("memory.ldb");
                    let (pdb, _) = hooks::open_project_ldb_silent(&ldb_path)?;
                    security::seal_workspace_memory(&gdb, &pdb, &clean)?;
                    if reinit_lost {
                        println!(
                            "[OK] Re-initialized and cryptographically sealed workspace '{}' after database loss (--reinit-lost)",
                            clean.display()
                        );
                    } else if accept_rollback {
                        println!(
                            "[OK] Adopted backup snapshot and advanced monotonic seal revision for workspace '{}' (--accept-rollback)",
                            clean.display()
                        );
                    } else {
                        println!(
                            "[OK] Trusted and cryptographically sealed workspace '{}'",
                            clean.display()
                        );
                    }
                }
            }
        }
        "config" => {
            let cli = CliSpec::new(
                "config",
                "libredb config <get|set|unset|list> [<key>] [<value>] [--project <dir>] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(3))
            .raw_value_slots(&[2])
            .allow_global()
            .values(&["--project"])
            .parse(sub_args)?;
            let action = cli.positionals.first().map(String::as_str).unwrap_or("list");
            let positional = if cli.positionals.len() > 1 {
                &cli.positionals[1..]
            } else {
                &[]
            };
            let proj_dir = cli.path_value("--project");
            let gdb_for_proj_seal = if proj_dir.is_some() && matches!(action, "set" | "unset") {
                hooks::open_global_ldb_checked(cli.global_deref())?
            } else {
                None
            };
            let mut proj_seal_guard: Option<security::PreMutationSealGuard> = None;
            let db: Arc<LibreDb> = if let Some(ref pdir) = proj_dir {
                let abs = std::fs::canonicalize(pdir).unwrap_or_else(|_| pdir.clone());
                let clean = gitea::strip_verbatim_prefix(&abs);
                let ldb_p = clean.join(".agents").join("memory.ldb");
                if matches!(action, "set" | "unset") {
                    proj_seal_guard = Some(security::PreMutationSealGuard::verify_before_write(
                        gdb_for_proj_seal.as_deref(),
                        &ldb_p,
                    )?);
                }
                let (pdb, _) = hooks::open_project_ldb_silent(&ldb_p)?;
                pdb
            } else {
                hooks::open_global_ldb(cli.global_deref())?
            };
            let is_secret_key = |k: &str| -> bool {
                let low = k.to_ascii_lowercase();
                low.ends_with("token")
                    || low.contains("secret")
                    || low.contains("password")
                    || low.contains("api_key")
            };
            match action {
                "set" => {
                    if positional.len() != 2 {
                        return Err("Usage: libredb config set <key> <value> [--project <dir>] [--global <g.ldb>]".into());
                    }
                    let key = positional[0].trim();
                    if security::is_reserved_security_config_key(key) {
                        return Err(format!(
                            "Refusing to modify reserved security configuration key '{key}' via 'libredb config'; use 'libredb trust' to manage workspace trust."
                        )
                        .into());
                    }
                    let key_low = key.to_ascii_lowercase();
                    if proj_dir.is_some()
                        && (key_low.starts_with("mcp:") || key_low == "gitea_allow_insecure_http")
                    {
                        return Err(format!(
                            "Host-global security policy key '{key}' cannot be scoped to '--project'; omit '--project' to configure it in global customizations.ldb."
                        )
                        .into());
                    }
                    let val = &positional[1];
                    let stored = if is_secret_key(key) {
                        security::protect_secret(val.trim())?
                    } else {
                        val.clone()
                    };
                    db.put(
                        WriteRequest::new(NodeKind::Config, stored.into_bytes())
                            .with_key(key)
                            .with_importance(190),
                    )?;
                    if let Some(ref guard) = proj_seal_guard {
                        guard.reseal_after_write(gdb_for_proj_seal.as_deref(), &db)?;
                    }
                    println!(
                        "[OK] Updated config '{}'{}",
                        key,
                        if is_secret_key(key) {
                            " (OS vault encrypted)"
                        } else {
                            ""
                        }
                    );
                }
                "get" => {
                    if positional.len() != 1 {
                        return Err(
                            "Usage: libredb config get <key> [--project <dir>] [--global <g.ldb>]"
                                .into(),
                        );
                    }
                    let key = &positional[0];
                    let rec = db.get_by_key(NodeKind::Config, key)?;
                    let raw = String::from_utf8_lossy(&rec.payload);
                    if is_secret_key(key) || security::is_ciphertext_envelope(&raw) {
                        println!("<redacted:encrypted-in-os-vault>");
                    } else {
                        println!("{}", raw.trim());
                    }
                }
                "unset" => {
                    if positional.len() != 1 {
                        return Err("Usage: libredb config unset <key> [--project <dir>] [--global <g.ldb>]".into());
                    }
                    let key = positional[0].trim();
                    if security::is_reserved_security_config_key(key) {
                        return Err(format!(
                            "Refusing to remove reserved security configuration key '{key}' via 'libredb config'; use 'libredb trust --revoke' instead."
                        )
                        .into());
                    }
                    let key_low = key.to_ascii_lowercase();
                    if proj_dir.is_some()
                        && (key_low.starts_with("mcp:") || key_low == "gitea_allow_insecure_http")
                    {
                        return Err(format!(
                            "Host-global security policy key '{key}' cannot be scoped to '--project'; omit '--project' to remove it from global customizations.ldb."
                        )
                        .into());
                    }
                    if db.deprecate_key(NodeKind::Config, key)? {
                        if let Some(ref guard) = proj_seal_guard {
                            guard.reseal_after_write(gdb_for_proj_seal.as_deref(), &db)?;
                        }
                        println!("[OK] Removed config '{key}'");
                    } else {
                        println!("Config '{key}' not found");
                    }
                }
                "list" => {
                    if !positional.is_empty() {
                        return Err(
                            "Usage: libredb config list [--project <dir>] [--global <g.ldb>]"
                                .into(),
                        );
                    }
                    let mut rows: Vec<(String, String)> = Vec::new();
                    for (ino, k_opt, _) in db.list_inodes(Some(NodeKind::Config), false) {
                        let Some(k) = k_opt else { continue };
                        if k == "sys::trust_anchor_secret"
                            || k.starts_with("trust:sealed::")
                            || k.starts_with("trust:seal_rev::")
                            || k.starts_with("trust:nonempty_sealed::")
                            || k.starts_with("trust:v3_upgraded::")
                            || k.starts_with("trust:v4_upgraded::")
                        {
                            continue;
                        }
                        if let Ok(rec) = db.get(ino.node_id) {
                            let raw = String::from_utf8_lossy(&rec.payload).trim().to_owned();
                            let shown = if is_secret_key(&k) || security::is_ciphertext_envelope(&raw) {
                                "<redacted:encrypted-in-os-vault>".to_owned()
                            } else {
                                raw.lines().collect::<Vec<_>>().join(", ")
                            };
                            rows.push((k, shown));
                        }
                    }
                    rows.sort_by(|a, b| a.0.cmp(&b.0));
                    println!("=== Active Configuration ({}) ===", rows.len());
                    for (k, v) in rows {
                        println!("  * {k} = {v}");
                    }
                }
                other => return Err(format!("Unknown config action '{other}'. Expected get, set, unset, or list.").into()),
            }
        }
        "get-skill" => {
            let cli = CliSpec::new(
                "get-skill",
                "libredb get-skill <skill_name> [--section <title>] [--global <customizations.ldb>]",
            )
            .positionals(1, Some(1))
            .allow_global()
            .values(&["--section"])
            .parse(sub_args)?;
            let skill_name = &cli.positionals[0];
            let gdb = hooks::open_global_ldb(cli.global_deref())?;
            if let Some(sec_title) = cli.value("--section") {
                let exact_key = format!("{skill_name}::{sec_title}");
                if let Ok(rec) = gdb.get_by_key(NodeKind::SkillSection, &exact_key) {
                    println!("{}", String::from_utf8_lossy(&rec.payload));
                } else {
                    let prefix = format!("{skill_name}::").to_ascii_lowercase();
                    let sub_low = sec_title.to_ascii_lowercase();
                    let mut matched_id = None;
                    for (ino, k_opt, _) in gdb.list_inodes(Some(NodeKind::SkillSection), false) {
                        if let Some(k) = k_opt {
                            let kl = k.to_ascii_lowercase();
                            if kl.starts_with(&prefix) && kl.contains(&sub_low) {
                                matched_id = Some(ino.node_id);
                                break;
                            }
                        }
                    }
                    if let Some(nid) = matched_id {
                        let rec = gdb.get(nid)?;
                        println!("{}", String::from_utf8_lossy(&rec.payload));
                    } else {
                        return Err(format!("Section '{sec_title}' not found in skill '{skill_name}'").into());
                    }
                }
            } else if let Ok(full_rec) =
                gdb.get_by_key(NodeKind::Generic, &format!("skill_full::{skill_name}"))
            {
                println!("{}", String::from_utf8_lossy(&full_rec.payload));
            } else {
                let rec = gdb.get_by_key(NodeKind::Skill, skill_name)?;
                println!("{}", String::from_utf8_lossy(&rec.payload));
            }
        }
        "list-rules" => {
            let cli = CliSpec::new(
                "list-rules",
                "libredb list-rules [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .alias("--db", "--global")
            .parse(sub_args)?;
            let global_path = cli
                .global_path
                .clone()
                .or_else(|| cli.positionals.first().map(PathBuf::from));
            let gdb = hooks::open_global_ldb(global_path.as_deref())?;
            let mut inodes: Vec<_> = gdb
                .list_inodes(Some(NodeKind::Rule), false)
                .into_iter()
                .filter(|(_, k_opt, _)| !k_opt.as_deref().is_some_and(|k| k.starts_with("reflex::")))
                .collect();
            inodes.sort_by(|a, b| a.1.cmp(&b.1));
            println!("=== Active Rules ({}) ===", inodes.len());
            for (ino, k_opt, _) in inodes {
                let k = k_opt.unwrap_or_else(|| format!("node_{}", ino.node_id));
                let rec = gdb.get(ino.node_id)?;
                let txt = String::from_utf8_lossy(&rec.payload);
                let summary = txt
                    .lines()
                    .find(|l| l.starts_with("Summary:"))
                    .or_else(|| txt.lines().next())
                    .unwrap_or("");
                println!("  * [#{} {:<42} {:>4} tok] {}", ino.node_id, k, ino.token_count, summary);
            }
        }
        "list-skills" => {
            let cli = CliSpec::new(
                "list-skills",
                "libredb list-skills [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .alias("--db", "--global")
            .parse(sub_args)?;
            let global_path = cli
                .global_path
                .clone()
                .or_else(|| cli.positionals.first().map(PathBuf::from));
            let gdb = hooks::open_global_ldb(global_path.as_deref())?;
            let sec_inodes = gdb.list_inodes(Some(NodeKind::SkillSection), false);
            let mut skill_inodes = gdb.list_inodes(Some(NodeKind::Skill), false);
            skill_inodes.sort_by(|a, b| a.1.cmp(&b.1));
            println!(
                "=== Active Skills ({} skills, {} sections) ===",
                skill_inodes.len(),
                sec_inodes.len()
            );
            for (ino, k_opt, _) in skill_inodes {
                let sname = k_opt.unwrap_or_else(|| format!("node_{}", ino.node_id));
                let prefix = format!("{sname}::");
                let sec_cnt = sec_inodes
                    .iter()
                    .filter(|(_, sk_opt, _)| sk_opt.as_deref().is_some_and(|sk| sk.starts_with(&prefix)))
                    .count();
                let rec = gdb.get(ino.node_id)?;
                let txt = String::from_utf8_lossy(&rec.payload);
                let desc = txt.lines().nth(1).or_else(|| txt.lines().next()).unwrap_or("");
                println!(
                    "  * [#{} {:<28} {:>2} secs, {:>3} tok] {}",
                    ino.node_id, sname, sec_cnt, ino.token_count, desc
                );
            }
        }
        "list-reflexes" => {
            let cli = CliSpec::new(
                "list-reflexes",
                "libredb list-reflexes [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .alias("--db", "--global")
            .parse(sub_args)?;
            let global_path = cli
                .global_path
                .clone()
                .or_else(|| cli.positionals.first().map(PathBuf::from));
            let gdb = hooks::open_global_ldb(global_path.as_deref())?;
            let mut inodes: Vec<_> = gdb
                .list_inodes(Some(NodeKind::Rule), false)
                .into_iter()
                .filter(|(_, k_opt, _)| k_opt.as_deref().is_some_and(|k| k.starts_with("reflex::")))
                .collect();
            inodes.sort_by(|a, b| a.1.cmp(&b.1));
            println!("=== Active Situational Reflexes ({}) ===", inodes.len());
            for (ino, k_opt, _) in inodes {
                let k = k_opt.unwrap_or_else(|| format!("node_{}", ino.node_id));
                let rec = gdb.get(ino.node_id)?;
                if let Ok(r) = serde_json::from_slice::<ReflexRule>(&rec.payload) {
                    println!(
                        "  * [#{} {:<32}] stack={:?} action={:?} -> {}",
                        ino.node_id, r.id, r.stack_any, r.action_any, r.directive
                    );
                } else {
                    println!("  * [#{} {}] {}", ino.node_id, k, String::from_utf8_lossy(&rec.payload));
                }
            }
        }
        "sync-skill" => {
            let cli = CliSpec::new(
                "sync-skill",
                "libredb sync-skill <SKILL.md> [--name <skill_name>] [--global <customizations.ldb>]",
            )
            .positionals(1, Some(1))
            .allow_global()
            .values(&["--name"])
            .parse(sub_args)?;
            let md_path = PathBuf::from(&cli.positionals[0]);
            let gdb = hooks::open_global_ldb(cli.global_deref())?;
            let (sname, sec_cnt) = sync_skill_markdown(&gdb, &md_path, cli.value("--name"))?;
            let mut cog = CognitiveEngine::open_db(gdb)?;
            cog.save_index_snapshot()?;
            println!(
                "[OK] Synced skill '{sname}' ({sec_cnt} sections + full body) and updated index snapshot"
            );
        }
        "modernize-global" => {
            let cli = CliSpec::new(
                "modernize-global",
                "libredb modernize-global [--global <customizations.ldb>] [--skill-md <SKILL.md>] [--profile neutral|personal] [--migrate-legacy]",
            )
            .positionals(0, Some(0))
            .allow_global()
            .switches(&["--personal", "--migrate-legacy"])
            .alias("--personal-rules", "--personal")
            .values(&["--skill-md", "--profile"])
            .parse(sub_args)?;
            let mut personal = cli.has_switch("--personal");
            if let Some(prof) = cli.value("--profile") {
                match prof.trim().to_ascii_lowercase().as_str() {
                    "personal" => personal = true,
                    "neutral" => personal = false,
                    other => {
                        return Err(format!(
                            "Invalid --profile '{other}'; expected 'neutral' or 'personal'"
                        )
                        .into());
                    }
                }
            }
            let skill_md = cli.path_value("--skill-md");
            let migrate_legacy = cli.has_switch("--migrate-legacy");
            let target_global = cli
                .global_path
                .clone()
                .unwrap_or_else(hooks::default_global_ldb_path);
            if let Some(parent) = target_global.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let gdb = if migrate_legacy {
                let central_sql = hooks::default_central_sqlite_path();
                if !target_global.exists() && central_sql.is_file() {
                    open_or_auto_migrate(&target_global, Some(central_sql.as_path()), "central")?.0
                } else {
                    let existing_gdb = hooks::open_global_ldb(Some(&target_global))?;
                    if central_sql.is_file() {
                        import_sqlite_readonly(&central_sql, &existing_gdb, "central")?;
                    }
                    existing_gdb
                }
            } else {
                hooks::open_global_ldb(Some(&target_global))?
            };
            modernize_global_db(&gdb, skill_md.as_deref(), personal)?;
        }
        "gitea-credential-helper" => {
            let cli = CliSpec::new(
                "gitea-credential-helper",
                "libredb gitea-credential-helper [get] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .parse(sub_args)?;
            let action = cli.positionals.first().map(String::as_str).unwrap_or("get");
            gitea::cmd_gitea_credential_helper(action, cli.global_deref())?;
        }
        cmd @ ("gitea-status" | "git-status") => {
            let cli = CliSpec::new(cmd, "libredb gitea-status [--global <customizations.ldb>]")
                .positionals(0, Some(0))
                .allow_global()
                .parse(sub_args)?;
            gitea::cmd_gitea_status(cli.global_deref())?;
        }
        "gitea-config" => {
            let cli = CliSpec::new(
                "gitea-config",
                "libredb gitea-config [--url <u>] [--user <usr>] [--token <tok> | --token-stdin] [--allow-insecure-http <bool>] [--register-helper] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(0))
            .allow_global()
            .switches(&["--token-stdin", "--register-helper"])
            .values(&["--url", "--user", "--token"])
            .optional_bools(&["--allow-insecure-http"])
            .parse(sub_args)?;
            let mut token = cli.value("--token").map(ToOwned::to_owned);
            if cli.has_switch("--token-stdin") {
                let mut stdin_tok = String::new();
                std::io::stdin().read_to_string(&mut stdin_tok)?;
                token = Some(stdin_tok.trim_end_matches(['\r', '\n']).to_owned());
            }
            gitea::cmd_gitea_config(
                cli.global_deref(),
                cli.value("--url"),
                cli.value("--user"),
                token.as_deref(),
                cli.optional_bool("--allow-insecure-http"),
                cli.has_switch("--register-helper"),
            )?;
        }
        cmd @ ("gitea-init" | "git-init") => {
            let cli = CliSpec::new(
                cmd,
                "libredb git-init [<dir>] [--name <repo>] [--use-existing] [--overwrite] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .switches(&["--use-existing", "--overwrite"])
            .values(&["--name"])
            .parse(sub_args)?;
            let dir = cli
                .positionals
                .first()
                .map(PathBuf::from)
                .map(Ok)
                .unwrap_or_else(env::current_dir)?;
            gitea::cmd_gitea_init(
                &dir,
                cli.value("--name"),
                cli.has_switch("--use-existing"),
                cli.has_switch("--overwrite"),
                cli.global_deref(),
            )?;
        }
        cmd @ ("gitea-sync" | "git-sync") => {
            let cli = CliSpec::new(
                cmd,
                "libredb git-sync [-m <msg>] [--project <dir>] [--remote <r>] [--all-remotes] [--github] [--releases] [--allow-unversioned] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(0))
            .allow_global()
            .switches(&[
                "--all-remotes",
                "--github",
                "--releases",
                "--allow-unversioned",
            ])
            .values(&["--message", "--project", "--remote"])
            .alias("-m", "--message")
            .parse(sub_args)?;
            let dir = cli
                .path_value("--project")
                .map(Ok)
                .unwrap_or_else(env::current_dir)?;
            let msg = cli.value("--message").unwrap_or("Synchronize workspace");
            gitea::cmd_gitea_sync(
                &dir,
                msg,
                cli.has_switch("--releases"),
                cli.has_switch("--allow-unversioned"),
                cli.value("--remote"),
                cli.has_switch("--all-remotes"),
                cli.has_switch("--github"),
                cli.global_deref(),
            )?;
        }
        cmd @ ("gitea-release" | "git-release") => {
            let cli = CliSpec::new(
                cmd,
                "libredb git-release [vX.Y.Z] [--project <dir>] [--remote <r>] [--all-remotes] [--github] [--global <customizations.ldb>]",
            )
            .positionals(0, Some(1))
            .allow_global()
            .switches(&["--all-remotes", "--github"])
            .values(&["--project", "--remote"])
            .parse(sub_args)?;
            let dir = cli
                .path_value("--project")
                .map(Ok)
                .unwrap_or_else(env::current_dir)?;
            gitea::cmd_gitea_release(
                &dir,
                cli.positionals.first().map(String::as_str),
                cli.value("--remote"),
                cli.has_switch("--all-remotes"),
                cli.has_switch("--github"),
                cli.global_deref(),
            )?;
        }
        "pulse" => {
            let cli = CliSpec::new(
                "pulse",
                "libredb pulse <db.ldb> <query> [--global <g.ldb>] [--cid <id>] [--transcript <t.jsonl>] [--epoch <n>] [--budget <tok>] [--cwd <dir>] [--err <msg>]",
            )
            .positionals(2, Some(2))
            .raw_value_slots(&[1])
            .allow_global()
            .values(&[
                "--cid",
                "--transcript",
                "--epoch",
                "--budget",
                "--cwd",
                "--err",
            ])
            .parse(sub_args)?;
            let mut req = PulseRequest::new(&cli.positionals[1], 800);
            req.conversation_id = cli.value("--cid").map(ToOwned::to_owned);
            let transcript_path = cli.path_value("--transcript");
            if let Some(ep) = cli.parse_value::<u32>("--epoch")? {
                req.epoch = ep;
            }
            if let Some(b) = cli.parse_value::<u32>("--budget")? {
                req.token_budget = b;
            }
            req.workspace_dir = cli.path_value("--cwd");
            req.error_context = cli.value("--err").map(ToOwned::to_owned);

            let t0 = Instant::now();
            let proj_db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            if let (Some(ref cid), Some(ref tp)) = (&req.conversation_id, &transcript_path) {
                req.epoch = sync_transcript_epoch(&proj_db, cid, tp)?;
            }
            let glob_db = match cli.global_deref() {
                Some(gp) => Some(hooks::open_global_ldb(Some(gp))?),
                None => hooks::open_global_ldb_checked(None)?,
            };
            let brain = OverlayBrain::open(glob_db, proj_db)?;
            let resp = brain.pulse(&req)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!("{}", resp.format_compact());
            println!("[Completed in {elapsed_ms:.2} ms]");
        }
        "index-workspace" => {
            let cli = CliSpec::new(
                "index-workspace",
                "libredb index-workspace <db.ldb> <workspace_dir> [--force] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .switches(&["--force"])
            .parse(sub_args)?;
            let force = cli.has_switch("--force");
            let t0 = Instant::now();
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let ws_arg = Path::new(&cli.positionals[1]);
            let ws_canon = std::fs::canonicalize(ws_arg).unwrap_or_else(|_| ws_arg.to_path_buf());
            let ws_norm = security::normalize_workspace_key(&ws_canon);
            let ws_prefix = format!("{ws_norm}/");
            let mut excluded_children = Vec::new();
            if let Some(ref gdb) = gdb_opt {
                if let Ok(trusted) = security::list_trusted_workspaces(gdb) {
                    for (t_norm, raw_path) in trusted {
                        if t_norm != ws_norm && t_norm.starts_with(&ws_prefix) {
                            excluded_children.push(PathBuf::from(raw_path));
                        }
                    }
                }
            }
            let rep = index_workspace_with_exclusions(&db, ws_arg, force, &excluded_children)?;
            let mut cog = CognitiveEngine::open_db(Arc::clone(&db))?;
            cog.save_index_snapshot()?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "[OK] Indexed workspace '{}' in {:.2} ms: {} files scanned ({} cached, {} reindexed, {} binaries skipped) -> {} symbols, {} call edges, {} governance edges",
                cli.positionals[1],
                t0.elapsed().as_secs_f64() * 1000.0,
                rep.files_scanned,
                rep.files_unchanged_cached,
                rep.files_reindexed,
                rep.binary_files_skipped,
                rep.symbols_indexed,
                rep.call_synapses_wired,
                rep.governance_synapses_wired
            );
        }
        "skeleton" => {
            let cli = CliSpec::new(
                "skeleton",
                "libredb skeleton <db.ldb> <source_file> [--filter <substr>] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--filter"])
            .parse(sub_args)?;
            let filter = cli.value("--filter");
            let t0 = Instant::now();
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let src_path = Path::new(&cli.positionals[1]);
            let (skel, cache_hit) = FileSkeleton::index_or_get_cached(&db, src_path, None)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            print!("{}", skel.render_compact(filter, filter.is_some()));
            println!(
                "[Skeleton {} in {:.2} ms]",
                if cache_hit {
                    "served from hash-verified cache"
                } else {
                    "extracted & cached"
                },
                elapsed_ms
            );
        }
        "impact" => {
            let cli = CliSpec::new(
                "impact",
                "libredb impact <db.ldb> <symbol_query> [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .raw_value_slots(&[1])
            .allow_global()
            .parse(sub_args)?;
            let t0 = Instant::now();
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let reports = query_symbol_impact(&db, &cli.positionals[1])?;
            println!(
                "=== BLAST-RADIUS & CAUSAL IMPACT: '{}' ({} matches in {:.2} ms) ===",
                cli.positionals[1],
                reports.len(),
                t0.elapsed().as_secs_f64() * 1000.0
            );
            for r in reports {
                println!("\n* [#{}] {}", r.node_id, r.contract);
                for g in &r.governing_decisions {
                    println!("    [Governed by]:    {g}");
                }
                for imp in &r.implementors {
                    println!("    [Implemented by] <= {imp}");
                }
                for c in &r.callers {
                    println!("    [Called by]      <- {c}");
                }
                for d in &r.callees {
                    println!("    [Calls/Depends]  -> {d}");
                }
            }
        }
        "fim" => {
            let cli = CliSpec::new(
                "fim",
                "libredb fim <db.ldb> <source_file> [--symbol <name> | --line <n>] [--pad <lines>] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--symbol", "--line", "--pad"])
            .parse(sub_args)?;
            let line = cli.parse_value::<usize>("--line")?;
            let pad = cli.parse_value::<usize>("--pad")?.unwrap_or(12);
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let bundle = extract_fim_slice(
                &db,
                Path::new(&cli.positionals[1]),
                cli.value("--symbol"),
                line,
                pad,
            )?;
            print!("{}", bundle.format_compact());
        }
        "batch" => {
            let cli = CliSpec::new(
                "batch",
                "libredb batch <db.ldb> [--fact k=v] [--decision Title::Body] [--task key::title::status::prio] [--snapshot <text>] [--global <customizations.ldb>]",
            )
            .positionals(1, Some(1))
            .allow_global()
            .multi_values(&["--fact", "--decision", "--task"])
            .values(&["--snapshot"])
            .parse(sub_args)?;
            let mut spec = AtomicBatchSpec::default();
            for raw_f in cli.values_list("--fact") {
                let Some((k, v)) = raw_f.split_once('=') else {
                    return Err(format!(
                        "Invalid --fact '{raw_f}'; expected 'key=value' in 'batch'"
                    )
                    .into());
                };
                if k.trim().is_empty() {
                    return Err(format!("Invalid --fact '{raw_f}'; key cannot be empty").into());
                }
                spec.facts.push((k.trim().to_owned(), v.trim().to_owned()));
            }
            for raw_d in cli.values_list("--decision") {
                let Some((t, b)) = raw_d.split_once("::") else {
                    return Err(format!(
                        "Invalid --decision '{raw_d}'; expected 'Title::Body' in 'batch'"
                    )
                    .into());
                };
                if t.trim().is_empty() {
                    return Err(
                        format!("Invalid --decision '{raw_d}'; title cannot be empty").into(),
                    );
                }
                spec.decisions
                    .push((t.trim().to_owned(), b.trim().to_owned()));
            }
            for raw_t in cli.values_list("--task") {
                let parts: Vec<&str> = raw_t.splitn(4, "::").collect();
                if parts.len() != 4 || parts[0].trim().is_empty() {
                    return Err(format!(
                        "Invalid --task '{raw_t}'; expected 'key::title::status::prio' in 'batch'"
                    )
                    .into());
                }
                spec.tasks.push((
                    parts[0].trim().to_owned(),
                    parts[1].trim().to_owned(),
                    parts[2].trim().to_owned(),
                    parts[3].trim().to_owned(),
                ));
            }
            spec.snapshot = cli.value("--snapshot").map(ToOwned::to_owned);
            if spec.facts.is_empty()
                && spec.decisions.is_empty()
                && spec.tasks.is_empty()
                && spec.snapshot.is_none()
            {
                return Err(
                    "Usage: libredb batch <db.ldb> [--fact k=v] [--decision Title::Body] [--task key::title::status::prio] [--snapshot <text>]"
                        .into(),
                );
            }
            let t0 = Instant::now();
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let rep = execute_atomic_batch(&db, &spec)?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "[OK] Committed {} capsules and wired {} governance synapses in {:.2} ms (IDs: {:?})",
                rep.nodes_committed,
                rep.governance_edges_wired,
                t0.elapsed().as_secs_f64() * 1000.0,
                rep.assigned_node_ids
            );
        }
        "handoff" => {
            let cli = CliSpec::new(
                "handoff",
                "libredb handoff <db.ldb> <handoff_id> <task_key> <role> [--notes <text>] [--global <customizations.ldb>]",
            )
            .positionals(4, Some(4))
            .allow_global()
            .values(&["--notes"])
            .parse(sub_args)?;
            let notes = cli.value("--notes").unwrap_or("");
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let (_, block) = create_subagent_handoff(
                &db,
                &cli.positionals[1],
                &cli.positionals[2],
                &cli.positionals[3],
                notes,
            )?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            print!("{block}");
        }
        "learn-assoc" => {
            let cli = CliSpec::new(
                "learn-assoc",
                "libredb learn-assoc <db.ldb> <cue_phrase> <id1,id2,...> [--global <customizations.ldb>]",
            )
            .positionals(3, Some(3))
            .raw_value_slots(&[1])
            .allow_global()
            .parse(sub_args)?;
            let target_ids: Result<Vec<u64>, _> = cli.positionals[2]
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().parse::<u64>())
                .collect();
            let target_ids = target_ids?;
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let mut cog = CognitiveEngine::open_db(Arc::clone(&db))?;
            let edges = cog.reinforce_association(&cli.positionals[1], &target_ids)?;
            cog.save_index_snapshot()?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "Reinforced {} Hebbian concept synapses from '{}' -> {:?}",
                edges, cli.positionals[1], target_ids
            );
        }
        "learn-reflex" => {
            let cli = CliSpec::new(
                "learn-reflex",
                "libredb learn-reflex <db.ldb> <id> <directive> [--stack s] [--action a] [--env e] [--global <customizations.ldb>]",
            )
            .positionals(3, Some(3))
            .raw_value_slots(&[2])
            .allow_global()
            .values(&["--stack", "--action", "--env"])
            .parse(sub_args)?;
            let split_csv = |opt: Option<&str>| -> Vec<String> {
                opt.unwrap_or("")
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            let rule = ReflexRule {
                id: cli.positionals[1].clone(),
                stack_any: split_csv(cli.value("--stack")),
                action_any: split_csv(cli.value("--action")),
                env_or_error_any: split_csv(cli.value("--env")),
                directive: cli.positionals[2].clone(),
            };
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let nid = ReflexEngine::learn_reflex(&db, &rule)?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!("Learned situational reflex '{}' as node #{nid}", rule.id);
        }
        "import-sqlite" => {
            let cli = CliSpec::new(
                "import-sqlite",
                "libredb import-sqlite <db.ldb> <source.db> [--scope central|project] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--scope"])
            .parse(sub_args)?;
            let scope = cli.value("--scope").unwrap_or("central");
            let t0 = Instant::now();
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard = if scope == "central" {
                security::PreMutationSealGuard::verify_before_write_allow_fresh_global_import(
                    gdb_opt.as_deref(),
                    db_path,
                )?
            } else {
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?
            };
            let db = Arc::new(LibreDb::open(db_path)?);
            let sum = import_sqlite_readonly(Path::new(&cli.positionals[1]), &db, scope)?;
            // Pre-build and persist the inverted index snapshot BEFORE sealing so cold CLI `pulse` runs in <10 ms!
            let mut cog = CognitiveEngine::open_db(Arc::clone(&db))?;
            cog.save_index_snapshot()?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "[OK] Imported SQLite '{}' + saved persistent index snapshot in {:.2} ms: {} tables ({} rows) -> {} cognitive capsules + {} synapses",
                cli.positionals[1],
                t0.elapsed().as_secs_f64() * 1000.0,
                sum.tables_mirrored,
                sum.total_sqlite_rows,
                sum.cognitive_capsules_created,
                sum.synapses_wired
            );
        }
        "export-sqlite" => {
            let cli = CliSpec::new(
                "export-sqlite",
                "libredb export-sqlite <db.ldb> <reconstructed.db> [--scope central|project] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--scope"])
            .parse(sub_args)?;
            let scope = cli.value("--scope").unwrap_or("central");
            let t0 = Instant::now();
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let rows = export_sqlite_database(&db, scope, Path::new(&cli.positionals[1]))?;
            println!(
                "[OK] Reconstructed SQLite '{}' (scope={}, {} rows + FTS5 indexes) in {:.2} ms",
                cli.positionals[1],
                scope,
                rows,
                t0.elapsed().as_secs_f64() * 1000.0
            );
        }
        "verify-roundtrip" => {
            let cli = CliSpec::new(
                "verify-roundtrip",
                "libredb verify-roundtrip <source.db> [--scope central|project]",
            )
            .positionals(1, Some(1))
            .values(&["--scope"])
            .parse(sub_args)?;
            let scope = cli.value("--scope").unwrap_or("central");
            let src_path = Path::new(&cli.positionals[0]);
            let src_meta = std::fs::symlink_metadata(src_path)?;
            if src_meta.file_type().is_symlink() || !src_meta.file_type().is_file() {
                return Err(format!(
                    "Refusing symlink or non-regular source SQLite file '{}'",
                    src_path.display()
                )
                .into());
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let tmp_dir = env::temp_dir().join(format!(
                "libredb_roundtrip_{}_{stamp}",
                process::id()
            ));
            std::fs::create_dir(&tmp_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o700));
            }

            let copy_src = tmp_dir.join("source_snapshot.db");
            let temp_ldb = tmp_dir.join("bridge.tmp.ldb");
            let recon_db = tmp_dir.join("reconstructed.db");
            std::fs::copy(src_path, &copy_src)?;

            let t0 = Instant::now();
            let imp_sum;
            {
                let ldb = LibreDb::open(&temp_ldb)?;
                imp_sum = import_sqlite_readonly(&copy_src, &ldb, scope)?;
                ldb.compact_with_gravity()?;
                ldb.verify_integrity()?;
                export_sqlite_database(&ldb, scope, &recon_db)?;
            }
            let rep = verify_sqlite_equivalence(&copy_src, &recon_db)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            let _ = std::fs::remove_dir_all(&tmp_dir);

            println!("=== LOSSLESS 1:1 SQLITE <-> LIBREDB BIJECTION VERIFIED ===");
            println!("  Source snapshot:       {}", src_path.display());
            println!(
                "  Tables verified:       {} (including {} FTS5 virtual tables)",
                rep.tables_verified, rep.fts5_tables_verified
            );
            println!("  Exact rows verified:   {} (0 discrepancies)", rep.rows_verified);
            println!(
                "  Cognitive graph built: {} capsules + {} synapses",
                imp_sum.cognitive_capsules_created, imp_sum.synapses_wired
            );
            println!("  Canonical digest:      {}", rep.canonical_digest_hex);
            println!("  Total round-trip time: {:.2} ms", elapsed_ms);
        }
        "init" => {
            let cli = CliSpec::new(
                "init",
                "libredb init <db.ldb> [--global <customizations.ldb>]",
            )
            .positionals(1, Some(1))
            .allow_global()
            .parse(sub_args)?;
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let _seal_guard =
                security::PreMutationSealGuard::verify_before_write_allow_fresh_global_import(
                    gdb_opt.as_deref(),
                    db_path,
                )?;
            let db = LibreDb::open(db_path)?;
            let st = db.stats()?;
            println!(
                "Initialized LibreDB at '{}' ({} bytes, commit_seq={})",
                cli.positionals[0], st.file_bytes, st.commit_seq
            );
        }
        "put" => {
            let cli = CliSpec::new(
                "put",
                "libredb put <db.ldb> <kind> <payload> [--key <k>] [--importance <0..255>] [--pin] [--global <customizations.ldb>]",
            )
            .positionals(3, Some(3))
            .raw_value_slots(&[2])
            .allow_global()
            .switches(&["--pin"])
            .values(&["--key", "--importance"])
            .parse(sub_args)?;
            let kind = NodeKind::parse(&cli.positionals[1])
                .ok_or_else(|| format!("Unknown node kind '{}'", cli.positionals[1]))?;
            let mut req = WriteRequest::new(kind, cli.positionals[2].as_bytes().to_vec());
            let explicit_key = cli.value("--key").map(ToOwned::to_owned);
            if let Some(ref k) = explicit_key {
                req = req.with_key(k);
            }
            if let Some(imp) = cli.parse_value::<u8>("--importance")? {
                req = req.with_importance(imp);
            }
            if cli.has_switch("--pin") {
                req = req.with_pinned(true);
            }
            if kind == NodeKind::Config {
                if let Some(ref k) = explicit_key {
                    if security::is_admin_only_security_config_key(k) {
                        return Err(format!(
                            "Refusing to write reserved cryptographic/policy Config key '{k}' via 'libredb put'; use 'libredb trust' or 'libredb config' instead."
                        )
                        .into());
                    }
                }
            }

            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = LibreDb::open(db_path)?;
            let id = db.put(req)?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            let rec = db.get(id)?;
            println!(
                "Stored node #{} (kind={}, gen={}, tokens={}, bytes={})",
                id,
                rec.kind.as_str(),
                rec.generation,
                rec.token_count,
                rec.payload.len()
            );
        }
        "get" => {
            let cli = CliSpec::new(
                "get",
                "libredb get <db.ldb> <node_id> [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .parse(sub_args)?;
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let id: u64 = cli.positionals[1].parse()?;
            let rec = db.get(id)?;
            print_record(&rec);
        }
        "get-key" => {
            let cli = CliSpec::new(
                "get-key",
                "libredb get-key <db.ldb> <kind> <key> [--global <customizations.ldb>]",
            )
            .positionals(3, Some(3))
            .raw_value_slots(&[2])
            .allow_global()
            .parse(sub_args)?;
            let kind = NodeKind::parse(&cli.positionals[1])
                .ok_or_else(|| format!("Unknown node kind '{}'", cli.positionals[1]))?;
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let rec = db.get_by_key(kind, &cli.positionals[2])?;
            print_record(&rec);
        }
        "link" => {
            let cli = CliSpec::new(
                "link",
                "libredb link <db.ldb> <src_id> <edge_kind> <dst_id> [--weight <0..255>] [--global <customizations.ldb>]",
            )
            .positionals(4, Some(4))
            .allow_global()
            .values(&["--weight"])
            .parse(sub_args)?;
            let src_id: u64 = cli.positionals[1].parse()?;
            let edge_kind = EdgeKind::parse(&cli.positionals[2])
                .ok_or_else(|| format!("Unknown edge kind '{}'", cli.positionals[2]))?;
            let dst_id: u64 = cli.positionals[3].parse()?;
            let weight: u8 = cli.parse_value::<u8>("--weight")?.unwrap_or(200);
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = LibreDb::open(db_path)?;
            db.link(src_id, edge_kind, dst_id, weight)?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "Linked node #{} --[{} (w={})]--> node #{}",
                src_id,
                edge_kind.as_str(),
                weight,
                dst_id
            );
        }
        "deprecate" => {
            let cli = CliSpec::new(
                "deprecate",
                "libredb deprecate <db.ldb> <kind> <key> [--global <customizations.ldb>]",
            )
            .positionals(3, Some(3))
            .raw_value_slots(&[2])
            .allow_global()
            .parse(sub_args)?;
            let kind = NodeKind::parse(&cli.positionals[1])
                .ok_or_else(|| format!("Unknown node kind '{}'", cli.positionals[1]))?;
            if kind == NodeKind::Config
                && security::is_admin_only_security_config_key(&cli.positionals[2])
            {
                return Err(format!(
                    "Refusing to deprecate reserved cryptographic/policy Config key '{}' via 'libredb deprecate'; use 'libredb trust --revoke' or 'libredb config unset' instead.",
                    cli.positionals[2]
                )
                .into());
            }
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = LibreDb::open(db_path)?;
            let removed = db.deprecate_key(kind, &cli.positionals[2])?;
            if removed {
                seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
                println!(
                    "Deprecated active key '{}' ({})",
                    cli.positionals[2],
                    kind.as_str()
                );
            } else {
                println!(
                    "Key '{}' ({}) not found",
                    cli.positionals[2],
                    kind.as_str()
                );
            }
        }
        "trace" => {
            let cli = CliSpec::new(
                "trace",
                "libredb trace <db.ldb> <node_id> [--depth <n>] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--depth"])
            .parse(sub_args)?;
            let root_id: u64 = cli.positionals[1].parse()?;
            let depth: usize = cli.parse_value::<usize>("--depth")?.unwrap_or(8);
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let chain = db.trace_lineage(root_id, depth)?;
            println!(
                "Causal & temporal lineage from node #{root_id} ({} steps):",
                chain.len()
            );
            for item in chain {
                let edge_lbl = item.via_edge.map_or("root", |e| e.as_str());
                let state_lbl = if item.is_active { "ACTIVE" } else { "SUPERSEDED" };
                println!(
                    "  [d={} via {:<10}] #{} ({}, {}, {} tok): {}",
                    item.depth,
                    edge_lbl,
                    item.node_id,
                    item.kind.as_str(),
                    state_lbl,
                    item.token_count,
                    item.payload_preview
                );
            }
        }
        "recall" => {
            let cli = CliSpec::new(
                "recall",
                "libredb recall <db.ldb> <seed_id> [--hops <n>] [--budget <tokens>] [--global <customizations.ldb>]",
            )
            .positionals(2, Some(2))
            .allow_global()
            .values(&["--hops", "--budget"])
            .parse(sub_args)?;
            let seed_id: u64 = cli.positionals[1].parse()?;
            let hops: usize = cli.parse_value::<usize>("--hops")?.unwrap_or(2);
            let budget: u32 = cli.parse_value::<u32>("--budget")?.unwrap_or(800);
            let db =
                open_cli_verified_project_db(cli.global_deref(), Path::new(&cli.positionals[0]))?;
            let bundle = db.recall_within_budget(&[seed_id], hops, budget, false)?;
            println!(
                "Recall bundle: {} nodes, {}/{} tokens, {} coalesced I/O read(s)",
                bundle.records.len(),
                bundle.total_tokens,
                bundle.token_budget,
                bundle.coalesced_io_reads
            );
            for rec in &bundle.records {
                println!(
                    "  * #{} [{}] ({} tok): {}",
                    rec.node_id,
                    rec.kind.as_str(),
                    rec.token_count,
                    String::from_utf8_lossy(&rec.payload)
                );
            }
        }
        "compact" => {
            let cli = CliSpec::new(
                "compact",
                "libredb compact <db.ldb> [--prune] [--global <customizations.ldb>]",
            )
            .positionals(1, Some(1))
            .allow_global()
            .switches(&["--prune"])
            .parse(sub_args)?;
            let prune = cli.has_switch("--prune");
            let t0 = Instant::now();
            let db_path = Path::new(&cli.positionals[0]);
            let gdb_opt = hooks::open_global_ldb_checked(cli.global_deref())?;
            let seal_guard =
                security::PreMutationSealGuard::verify_before_write(gdb_opt.as_deref(), db_path)?;
            let db = Arc::new(LibreDb::open(db_path)?);
            let initial_bytes = db.stats()?.file_bytes;
            let mut cog = CognitiveEngine::open_db(Arc::clone(&db))?;
            cog.save_index_snapshot()?;
            let rep = db.compact_with_options(prune)?;
            seal_guard.reseal_after_write(gdb_opt.as_deref(), &db)?;
            println!(
                "Gravity compaction{} + index snapshot finished in {:.2} ms: {} -> {} bytes ({} hot nodes in {} locality groups, {} cold nodes archived)",
                if prune { " (--prune)" } else { "" },
                t0.elapsed().as_secs_f64() * 1000.0,
                initial_bytes,
                rep.bytes_after,
                rep.hot_nodes_packed,
                rep.locality_groups,
                rep.cold_nodes_archived
            );
        }
        "stats" => {
            let cli = CliSpec::new("stats", "libredb stats <db.ldb> [--json]")
                .positionals(0, Some(1))
                .switches(&["--json"])
                .values(&["--db"])
                .parse(sub_args)?;
            let db_path = cli
                .value("--db")
                .or_else(|| cli.positionals.first().map(String::as_str))
                .ok_or("Usage: libredb stats <db.ldb> [--json]")?;
            let db = LibreDb::open(db_path)?;
            let st = db.stats()?;
            if cli.has_switch("--json") {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                println!("=== LibreDB Statistics ===");
                println!("  File size:         {} bytes", st.file_bytes);
                println!("  Commit sequence:   {}", st.commit_seq);
                println!("  Compactions:       {}", st.compaction_count);
                println!("  Total inodes:      {}", st.total_inodes);
                println!("  Active nodes:      {}", st.active_nodes);
                println!("  Superseded nodes:  {}", st.superseded_nodes);
                println!("  Inline nodes:      {}", st.inline_nodes);
                println!("  LZ4 extents:       {}", st.compressed_nodes);
                println!("  Keyed entries:     {}", st.keyed_entries);
                println!("  Active LLM tokens: {}", st.total_tokens_active);
            }
        }
        "verify" => {
            let cli = CliSpec::new("verify", "libredb verify <db.ldb>")
                .positionals(1, Some(1))
                .parse(sub_args)?;
            let t0 = Instant::now();
            let db = LibreDb::open(&cli.positionals[0])?;
            let st = db.verify_integrity()?;
            println!(
                "[OK] Verified {} inodes and all extents in {:.2} ms ({} bytes, commit_seq={})",
                st.total_inodes,
                t0.elapsed().as_secs_f64() * 1000.0,
                st.file_bytes,
                st.commit_seq
            );
        }
        "bench" => {
            let cli = CliSpec::new("bench", "libredb bench [--nodes <n>] [--threads <t>]")
                .positionals(0, Some(0))
                .values(&["--nodes", "--threads"])
                .parse(sub_args)?;
            let total_nodes = cli.parse_value::<usize>("--nodes")?.unwrap_or(10_000);
            let threads = cli.parse_value::<usize>("--threads")?.unwrap_or(16);
            run_microbench(total_nodes, threads.max(1))?;
        }
        other => {
            return Err(format!("Unknown subcommand '{other}'. Run 'libredb --help'.").into());
        }
    }

    Ok(())
}

fn print_record(rec: &libredb_core::NodeRecord) {
    println!(
        "Node #{} [kind={}, active={}, gen={}, tokens={}, hits={}]",
        rec.node_id,
        rec.kind.as_str(),
        rec.flags.is_live_active(),
        rec.generation,
        rec.token_count,
        rec.access_count
    );
    if !rec.synapses.is_empty() {
        println!("Synapses ({}):", rec.synapses.len());
        for s in &rec.synapses {
            println!("  -> #{} ({}, weight={})", s.target_id, s.kind.as_str(), s.weight);
        }
    }
    println!(
        "Payload ({} bytes):\n{}",
        rec.payload.len(),
        String::from_utf8_lossy(&rec.payload)
    );
}

fn run_microbench(total_nodes: usize, threads: usize) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_path: PathBuf =
        env::temp_dir().join(format!("libredb_bench_{}.tmp.ldb", process::id()));
    let _ = std::fs::remove_file(&tmp_path);

    let db = Arc::new(LibreDb::open(&tmp_path)?);
    let per_thread = total_nodes / threads;

    let t_prep = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let db_ref = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            let mut batch = Vec::with_capacity(per_thread);
            for j in 0..per_thread {
                let idx = tid * per_thread + j;
                let text = format!(
                    "## Skill section #{idx}\nDeterministic architectural guidance for concurrent worker lane {tid} item {j} with repeatable compressible tokens."
                );
                let req = WriteRequest::new(NodeKind::SkillSection, text.into_bytes())
                    .with_key(format!("sec_{idx}"));
                batch.push(db_ref.prepare(req, tid).expect("prepare succeeded"));
            }
            batch
        }));
    }

    let mut all_prepared = Vec::with_capacity(per_thread * threads);
    for h in handles {
        all_prepared.extend(h.join().expect("worker joined"));
    }
    let prep_ms = t_prep.elapsed().as_secs_f64() * 1000.0;

    let t_commit = Instant::now();
    let ids = db.commit_batch(&all_prepared)?;
    let commit_ms = t_commit.elapsed().as_secs_f64() * 1000.0;

    let ids_arc = Arc::new(ids);
    let t_read = Instant::now();
    let mut r_handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let db_ref = Arc::clone(&db);
        let ids_ref = Arc::clone(&ids_arc);
        r_handles.push(thread::spawn(move || {
            let start = tid * per_thread;
            for &nid in &ids_ref[start..start + per_thread] {
                let rec = db_ref.get(nid).expect("read succeeded");
                assert!(!rec.payload.is_empty());
            }
        }));
    }
    for rh in r_handles {
        rh.join().expect("reader joined");
    }
    let read_ms = t_read.elapsed().as_secs_f64() * 1000.0;

    let t_comp = Instant::now();
    let comp = db.compact_with_gravity()?;
    let comp_ms = t_comp.elapsed().as_secs_f64() * 1000.0;

    let st = db.verify_integrity()?;
    let _ = std::fs::remove_file(&tmp_path);

    let actual_n = ids_arc.len();
    println!("=== LibreDB Kernel Benchmark ({actual_n} nodes across {threads} threads) ===");
    println!(
        "  Parallel prepare ({threads} lanes): {:>8.2} ms ({:.0} nodes/sec)",
        prep_ms,
        (actual_n as f64) / (prep_ms / 1000.0)
    );
    println!(
        "  Atomic batch commit + fsync:   {:>8.2} ms ({:.0} nodes/sec)",
        commit_ms,
        (actual_n as f64) / (commit_ms / 1000.0)
    );
    println!(
        "  Concurrent {threads}-thread reads:  {:>8.2} ms ({:.0} reads/sec)",
        read_ms,
        (actual_n as f64) / (read_ms / 1000.0)
    );
    println!(
        "  Gravity compaction + verify:   {:>8.2} ms ({} -> {} bytes)",
        comp_ms, comp.bytes_before, st.file_bytes
    );
    Ok(())
}

fn sync_skill_markdown(
    gdb: &Arc<LibreDb>,
    md_path: &Path,
    explicit_name: Option<&str>,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(md_path)?;
    let normalized = raw.replace("\r\n", "\n");
    let mut name_opt: Option<String> = explicit_name.map(ToOwned::to_owned);
    let mut desc = String::new();
    let mut body_start = 0usize;

    if let Some(after_open) = normalized.strip_prefix("---\n") {
        if let Some(end_idx) = after_open.find("\n---\n") {
            let fm = &after_open[..end_idx];
            body_start = 4 + end_idx + 5;
            let mut in_multiline_desc = false;
            for line in fm.lines() {
                if in_multiline_desc && (line.starts_with(' ') || line.starts_with('\t')) {
                    let cont = line.trim();
                    if !cont.is_empty() {
                        if !desc.is_empty() {
                            desc.push(' ');
                        }
                        desc.push_str(cont);
                    }
                    continue;
                }
                in_multiline_desc = false;
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if key == "name" && name_opt.is_none() && !val.is_empty() {
                        name_opt = Some(val.to_owned());
                    } else if key == "description" {
                        if matches!(val, "" | ">" | ">-" | "|" | "|-") {
                            in_multiline_desc = true;
                        } else {
                            desc = val.to_owned();
                        }
                    }
                }
            }
        }
    }

    let skill_name = name_opt.unwrap_or_else(|| {
        md_path
            .parent()
            .and_then(|p| p.file_name())
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    });
    if desc.is_empty() {
        desc = format!("Specialized Antigravity skill '{skill_name}'");
    }

    let body = &normalized[body_start..];
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut cur_title: Option<String> = None;
    let mut cur_buf = String::new();

    for line in body.lines() {
        if let Some(h2) = line.strip_prefix("## ").or_else(|| line.strip_prefix("### ")) {
            if let Some(prev_t) = cur_title.take() {
                let trimmed = cur_buf.trim().to_owned();
                if !trimmed.is_empty() {
                    sections.push((prev_t, trimmed));
                }
                cur_buf.clear();
            }
            cur_title = Some(h2.trim().to_owned());
            cur_buf.push_str(line);
            cur_buf.push('\n');
        } else if cur_title.is_some() {
            cur_buf.push_str(line);
            cur_buf.push('\n');
        }
    }
    if let Some(last_t) = cur_title.take() {
        let trimmed = cur_buf.trim().to_owned();
        if !trimmed.is_empty() {
            sections.push((last_t, trimmed));
        }
    }

    let sec_prefix = format!("{skill_name}::");
    let new_keys: std::collections::HashSet<String> = sections
        .iter()
        .map(|(t, _)| format!("{skill_name}::{t}"))
        .collect();
    for (_, k_opt, _) in gdb.list_inodes(Some(NodeKind::SkillSection), false) {
        if let Some(k) = k_opt {
            if k.starts_with(&sec_prefix) && !new_keys.contains(&k) {
                let _ = gdb.deprecate_key(NodeKind::SkillSection, &k);
            }
        }
    }

    let mut prepared = Vec::new();
    let summary_card = format!(
        "[Skill: {skill_name} | plugin={skill_name} | category={skill_name}]\n{desc}\n(Full length: {} chars)",
        normalized.len()
    );
    prepared.push(gdb.prepare(
        WriteRequest::new(NodeKind::Skill, summary_card.into_bytes())
            .with_key(&skill_name)
            .with_importance(210),
        0,
    )?);
    prepared.push(gdb.prepare(
        WriteRequest::new(NodeKind::Generic, normalized.clone().into_bytes())
            .with_key(format!("skill_full::{skill_name}"))
            .with_importance(120),
        1,
    )?);

    for (idx, (stitle, scontent)) in sections.iter().enumerate() {
        let sec_key = format!("{skill_name}::{stitle}");
        let sec_body = format!("[{skill_name} > {stitle}]\n{scontent}");
        prepared.push(gdb.prepare(
            WriteRequest::new(NodeKind::SkillSection, sec_body.into_bytes())
                .with_key(sec_key)
                .with_importance(195),
            idx + 2,
        )?);
    }

    let ids = gdb.commit_batch(&prepared)?;
    let skill_id = ids[0];
    let full_id = ids[1];
    let mut edges = vec![(skill_id, EdgeKind::HasSection, full_id, 250)];
    for &sec_id in &ids[2..] {
        edges.push((skill_id, EdgeKind::HasSection, sec_id, 240));
        edges.push((sec_id, EdgeKind::RelatedTo, skill_id, 240));
    }
    gdb.link_batch(&edges)?;

    Ok((skill_name, sections.len()))
}

fn modernize_global_db(
    gdb: &Arc<LibreDb>,
    skill_md_opt: Option<&Path>,
    personal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let t0 = Instant::now();
    let mut deprecated_legacy = 0usize;

    if gdb.deprecate_key(NodeKind::Skill, "customizations-db")? {
        deprecated_legacy += 1;
    }
    if gdb.deprecate_key(NodeKind::Generic, "skill_full::customizations-db")? {
        deprecated_legacy += 1;
    }
    if gdb.deprecate_key(NodeKind::Generic, "sqlite_mirror::central")? {
        deprecated_legacy += 1;
    }
    for (_, k_opt, _) in gdb.list_inodes(Some(NodeKind::SkillSection), false) {
        if let Some(k) = k_opt {
            if k.starts_with("customizations-db::")
                && gdb.deprecate_key(NodeKind::SkillSection, &k)?
            {
                deprecated_legacy += 1;
            }
        }
    }

    // Purge legacy SQLite telemetry bloat (`QuotaEvent` and `TranscriptCursor`) from global customizations.ldb
    let mut telemetry_ids: Vec<u64> = Vec::new();
    for kind in [NodeKind::QuotaEvent, NodeKind::TranscriptCursor] {
        for (ino, _, _) in gdb.list_inodes(Some(kind), false) {
            telemetry_ids.push(ino.node_id);
        }
    }
    if !telemetry_ids.is_empty() {
        deprecated_legacy += gdb.deprecate_nodes(&telemetry_ids)?;
    }

    let mut rules_updated = 0usize;
    if personal {
        let mut rule_writes = Vec::new();
        for (idx, (ino, k_opt, _)) in gdb
            .list_inodes(Some(NodeKind::Rule), false)
            .into_iter()
            .enumerate()
        {
            let Some(key) = k_opt else { continue };
            if key.starts_with("reflex::") {
                continue;
            }
            let rec = gdb.get(ino.node_id)?;
            let orig = String::from_utf8_lossy(&rec.payload).into_owned();
            let updated = orig
                .replace("skillsdb ", "libredb ")
                .replace("(skillsdb ", "(libredb ")
                .replace("`skillsdb`", "`libredb`")
                .replace("customizations-db", "libredb")
                .replace("customizations.db", "customizations.ldb")
                .replace("memory.db", "memory.ldb")
                .replace("SkillsDB", "LibreDB");
            if updated != orig {
                rule_writes.push(
                    gdb.prepare(
                        WriteRequest::new(NodeKind::Rule, updated.into_bytes())
                            .with_key(key)
                            .with_importance(230)
                            .with_pinned(true),
                        idx,
                    )?,
                );
                rules_updated += 1;
            }
        }
        if !rule_writes.is_empty() {
            gdb.commit_batch(&rule_writes)?;
        }
    } else {
        // Enterprise-neutral profile (`--profile neutral`, default): remove ONLY the exact personal
        // rule and the 7 exact personal author reflexes seeded by `--profile personal`, preserving 100%
        // of custom organization-defined rules (including any custom `rule:global::*` keys).
        if gdb.deprecate_key(NodeKind::Rule, "rule:global::candid-architectural-pushback")? {
            deprecated_legacy += 1;
        }
        for personal_reflex_id in [
            "rust-guardrail-staged",
            "candid-architectural-pushback",
            "semver-changelog-discipline",
            "anti-salami-code-slicing",
            "windows-soc-admin-audit",
            "formatting-and-language-boundary",
            "rust-gitea-dist",
        ] {
            if gdb.deprecate_key(NodeKind::Rule, &format!("reflex::{personal_reflex_id}"))? {
                deprecated_legacy += 1;
            }
        }
    }

    let default_skill_md = env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gemini")
        .join("config")
        .join("plugins")
        .join("libredb")
        .join("skills")
        .join("libredb")
        .join("SKILL.md");
    let skill_path = skill_md_opt
        .map(Path::to_path_buf)
        .unwrap_or(default_skill_md);
    let mut synced_sections = 0usize;
    if skill_path.is_file() {
        let (_, cnt) = sync_skill_markdown(gdb, &skill_path, Some("libredb"))?;
        synced_sections = cnt;
    }

    // Strictly technical, developer-agnostic engine safety reflexes (safe for all corporate & neutral users):
    let technical_reflexes = [
        ReflexRule {
            id: "windows-hooks-cmd-quoting".to_owned(),
            stack_any: vec!["windows".to_owned(), "hooks".to_owned(), "json".to_owned()],
            action_any: vec!["hook".to_owned(), "plugin".to_owned(), "deploy".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "On Windows, hooks.json commands run via cmd.exe /C: keep space-free %USERPROFILE%\\.gemini\\libredb\\bin\\libredb.exe unquoted, and wrap executable paths containing spaces in one pair of escaped double quotes (\\\"C:\\\\Path With Spaces\\\\libredb.exe\\\" <subcmd>).".to_owned(),
        },
        ReflexRule {
            id: "gitea-collision-and-github-guard".to_owned(),
            stack_any: vec!["git".to_owned(), "gitea".to_owned()],
            action_any: vec!["gitea-init".to_owned(), "gitea-sync".to_owned(), "gitea-release".to_owned(), "git-sync".to_owned(), "git-release".to_owned(), "push".to_owned()],
            env_or_error_any: vec!["GITEA REPOSITORY COLLISION".to_owned(), "UNVERSIONED WORKSPACE".to_owned(), "SEMVER IMMUTABILITY VIOLATION".to_owned()],
            directive: "Never hijack existing non-Gitea origin remotes or leak Gitea Basic Auth headers to external servers. Pause and ask user on [GITEA REPOSITORY COLLISION] or before --allow-unversioned.".to_owned(),
        },
        ReflexRule {
            id: "git-non-acl-safe-dir".to_owned(),
            stack_any: vec!["git".to_owned()],
            action_any: vec!["git".to_owned(), "gitea-init".to_owned()],
            env_or_error_any: vec!["dubious ownership".to_owned()],
            directive: "On non-ACL drives, run 'git config --global --add safe.directory <repo>' right after git init.".to_owned(),
        },
    ];

    // Maintainer's personal workflow & formatting reflexes (`--profile personal` ONLY):
    let personal_reflexes = [
        ReflexRule {
            id: "rust-guardrail-staged".to_owned(),
            stack_any: vec!["rust".to_owned(), "cargo".to_owned()],
            action_any: vec!["commit".to_owned(), "gitea".to_owned(), "release".to_owned(), "sync".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Ensure /target/ and /dist/ are in .gitignore and run 'libredb guardrail check --path <dir> --staged --strict' before committing.".to_owned(),
        },
        ReflexRule {
            id: "candid-architectural-pushback".to_owned(),
            stack_any: vec!["architecture".to_owned(), "design".to_owned(), "coding".to_owned(), "refactor".to_owned()],
            action_any: vec!["plan".to_owned(), "design".to_owned(), "build".to_owned(), "implement".to_owned(), "architecture".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Always give candid, unvarnished engineering feedback: if a proposed idea shoots past the target or introduces unnecessary complexity, say so directly and propose the cleaner alternative.".to_owned(),
        },
        ReflexRule {
            id: "semver-changelog-discipline".to_owned(),
            stack_any: vec!["semver".to_owned(), "changelog".to_owned(), "release".to_owned()],
            action_any: vec!["release".to_owned(), "tag".to_owned(), "version".to_owned(), "gitea-release".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Never overwrite an existing release tag in place; increment SemVer X.Y.Z, document under Keep a Changelog 1.1.0 in CHANGELOG.md, and attach deliverables from dist/ or releases/.".to_owned(),
        },
        ReflexRule {
            id: "anti-salami-code-slicing".to_owned(),
            stack_any: vec!["rust".to_owned(), "python".to_owned(), "typescript".to_owned(), "code".to_owned()],
            action_any: vec!["read".to_owned(), "inspect".to_owned(), "skeleton".to_owned(), "fim".to_owned(), "impact".to_owned(), "refactor".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Read files <=800 lines in one read_file call; for files >800 lines use libredb_code (action=skeleton, fim, or impact) before editing.".to_owned(),
        },
        ReflexRule {
            id: "windows-soc-admin-audit".to_owned(),
            stack_any: vec!["windows".to_owned(), "powershell".to_owned(), "admin".to_owned(), "wmi".to_owned(), "cim".to_owned()],
            action_any: vec!["elevate".to_owned(), "admin".to_owned(), "service".to_owned(), "schtasks".to_owned(), "firewall".to_owned()],
            env_or_error_any: vec!["Access is denied".to_owned(), "RunAs".to_owned()],
            directive: "Follow SOC transparent IT admin standard: log all 4 phases ([1/4 PRE-CHECK]..[4/4 POST-CHECK]) under C:\\IT_ADMIN_LOGS\\<USER>\\<TASK>\\<TARGET>\\<Date>\\<hh_mm_ss>\\ and never use C:\\Windows\\Temp or cmd.exe /c wrappers.".to_owned(),
        },
        ReflexRule {
            id: "formatting-and-language-boundary".to_owned(),
            stack_any: vec!["markdown".to_owned(), "docs".to_owned(), "commit".to_owned(), "ui".to_owned()],
            action_any: vec!["write".to_owned(), "edit".to_owned(), "commit".to_owned(), "readme".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Enforce strict output invariants: zero em-dashes/en-dashes, zero emojis, sentence case headings, informal German ('Du') in chat without Deppenbindestriche, and 100% ASCII English in code/comments/commits.".to_owned(),
        },
        ReflexRule {
            id: "rust-gitea-dist".to_owned(),
            stack_any: vec!["cargo.toml".to_owned(), "rust".to_owned()],
            action_any: vec!["gitea-release".to_owned(), "gitea-sync".to_owned()],
            env_or_error_any: Vec::new(),
            directive: "Copy compiled release deliverables into dist/ before running 'libredb gitea-release' so assets attach automatically.".to_owned(),
        },
    ];

    for r in &technical_reflexes {
        ReflexEngine::learn_reflex(gdb, r)?;
    }

    let mut active_reflex_count = technical_reflexes.len();
    if personal {
        for r in &personal_reflexes {
            ReflexEngine::learn_reflex(gdb, r)?;
        }
        active_reflex_count += personal_reflexes.len();

        let pushback_rule = "[Rule: candid-architectural-pushback | priority=100 | enforcement=CRITICAL]\nSummary: Candid engineering pushback without false politeness when coding ideas overshoot the target.\nWhenever a user idea or architectural direction shoots past the target, introduces unnecessary complexity, hardcodes a fragile assumption, or heads in the wrong technical direction, state directly and candidly that it is suboptimal and immediately propose the cleaner engineering alternative. Never hold back technical criticism out of personal consideration.";
        gdb.put(
            WriteRequest::new(NodeKind::Rule, pushback_rule.as_bytes().to_vec())
                .with_key("rule:global::candid-architectural-pushback")
                .with_importance(245)
                .with_pinned(true),
        )?;
    }

    // Transparently upgrade any legacy plaintext or POSIX `vault:v1:` `gitea_token` to OS vault (`dpapi:v1:` / `vault:v2:`)
    // BEFORE `--prune` compaction physically purges superseded extents from `customizations.ldb`!
    let _ = gitea::GiteaConfig::load(gdb);

    // Audit registered workspaces strictly read-only (`is_workspace_memory_trusted`): NEVER re-seal
    // unverified or offline-modified `.agents/memory.ldb` databases during global upgrades!
    let mut verified_workspaces = 0usize;
    let mut quarantined_workspaces = 0usize;
    for (_, raw_ws) in security::list_trusted_workspaces(gdb)? {
        let ws_path = PathBuf::from(raw_ws.trim());
        let ldb_p = ws_path.join(".agents").join("memory.ldb");
        if ws_path.is_dir()
            && (ldb_p.is_file() || security::has_prior_workspace_seal_marker(gdb, &ws_path))
        {
            if security::is_workspace_memory_trusted(Some(gdb), &ws_path) {
                verified_workspaces += 1;
            } else {
                quarantined_workspaces += 1;
                if security::is_unsealed_replacement_of_sealed_workspace(gdb, &ws_path) {
                    println!(
                        "[WARN] Quarantined workspace '{}': previously sealed .agents/memory.ldb is missing, unsealed, or rolled back to empty; restore from backup or run 'libredb trust --reinit-lost \"{}\"' to re-initialize.",
                        ws_path.display(),
                        ws_path.display()
                    );
                } else if let Some((proj_rev, global_rev)) =
                    security::detect_workspace_seal_rollback(gdb, &ws_path)?
                {
                    println!(
                        "[WARN] Quarantined workspace '{}': .agents/memory.ldb carries older seal revision r{proj_rev} while host customizations.ldb requires at least r{global_rev} (historical snapshot rollback detected); restore latest .agents/memory.ldb or run 'libredb trust --accept-rollback \"{}\"' to accept.",
                        ws_path.display(),
                        ws_path.display()
                    );
                } else if security::has_valid_legacy_v3_content_seal(gdb, &ws_path) {
                    println!(
                        "[WARN] Quarantined workspace '{}': .agents/memory.ldb carries a valid legacy v0.9.3 content seal (CognitiveContent::v3) without v4 metadata authentication; run 'libredb trust --migrate-v3 \"{}\"' (adding '--confirm-metadata' after reviewing unauthenticated metadata if prompted).",
                        ws_path.display(),
                        ws_path.display()
                    );
                } else {
                    println!(
                        "[WARN] Quarantined workspace '{}': .agents/memory.ldb has an unverified, legacy v2, or modified seal (run 'libredb trust --migrate-v2 \"{}\"' for v0.9.0 upgrades or 'libredb trust \"{}\"' after manual inspection).",
                        ws_path.display(),
                        ws_path.display(),
                        ws_path.display()
                    );
                }
            }
        }
    }

    let mut cog = CognitiveEngine::open_db(Arc::clone(gdb))?;
    cog.save_index_snapshot()?;
    let comp = gdb.compact_with_options(true)?;

    println!(
        "[OK] Modernized global LibreDB (profile={}) in {:.2} ms: {} legacy capsules deprecated, {} rules updated, {} libredb skill sections synced, {} reflexes active, {} workspaces verified ({} quarantined) ({} -> {} bytes)",
        if personal { "personal" } else { "neutral" },
        t0.elapsed().as_secs_f64() * 1000.0,
        deprecated_legacy,
        rules_updated,
        synced_sections,
        active_reflex_count,
        verified_workspaces,
        quarantined_workspaces,
        comp.bytes_before,
        comp.bytes_after
    );
    Ok(())
}

/// Verifies workspace trust BEFORE read-only CLI commands (`pulse`, `skeleton`, `impact`, `fim`)
/// open or auto-migrate a project `.agents/memory.ldb` (or legacy `.db`).
fn open_cli_verified_project_db(
    global_path_opt: Option<&Path>,
    db_path: &Path,
) -> Result<Arc<LibreDb>, Box<dyn std::error::Error>> {
    let gdb_opt = hooks::open_global_ldb_checked(global_path_opt)?;
    let joined_db = if db_path.is_relative() {
        env::current_dir()
            .map(|cwd| cwd.join(db_path))
            .unwrap_or_else(|_| db_path.to_path_buf())
    } else {
        db_path.to_path_buf()
    };
    let resolved_db = security::canonicalize_with_missing_tail(&joined_db).unwrap_or(joined_db);
    if let Some(parent) = resolved_db.parent() {
        let is_agents = parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(".agents"));
        let is_mem = resolved_db
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.eq_ignore_ascii_case("memory.ldb") || n.eq_ignore_ascii_case("memory.db")
            });
        if is_agents && is_mem {
            if let Some(ws_root) = parent.parent() {
                if security::is_private_brain_workspace(ws_root) {
                    let ldb_file = ws_root.join(".agents").join("memory.ldb");
                    let leg_sql = ws_root.join(".agents").join("memory.db");
                    let sql_opt = if !ldb_file.exists() && leg_sql.is_file() {
                        Some(leg_sql.as_path())
                    } else {
                        None
                    };
                    return Ok(open_or_auto_migrate(&ldb_file, sql_opt, "project")?.0);
                }
                let Some(ref gdb) = gdb_opt else {
                    return Err(format!(
                        "Refusing to read workspace memory '{}' without an initialized global customizations.ldb trust anchor; run 'libredb trust \"{}\"' first.",
                        db_path.display(),
                        ws_root.display()
                    )
                    .into());
                };
                let _ws_lock = security::WorkspaceTrustLockGuard::acquire(gdb, ws_root)?;
                let ldb_file = ws_root.join(".agents").join("memory.ldb");
                let leg_sql = ws_root.join(".agents").join("memory.db");
                if !ldb_file.exists() && leg_sql.is_file() {
                    let norm = security::normalize_workspace_key(ws_root);
                    if security::has_config_key_fail_closed(gdb, &format!("trust:revoked::{norm}"))?
                        || !security::has_config_key_fail_closed(
                            gdb,
                            &format!("trust:allowed::{norm}"),
                        )?
                        || security::has_prior_workspace_seal_marker(gdb, ws_root)
                        || security::is_git_index_tracking_agents_db(ws_root)
                    {
                        return Err(format!(
                            "Refusing automatic legacy SQLite migration for untrusted workspace '{}'; inspect .agents/memory.db and run 'libredb trust \"{}\"' if trusted.",
                            ws_root.display(),
                            ws_root.display()
                        )
                        .into());
                    }
                    let (migrated_db, did_mig) =
                        open_or_auto_migrate(&ldb_file, Some(leg_sql.as_path()), "project")?;
                    if did_mig.is_some() {
                        security::seal_workspace_memory(gdb, &migrated_db, ws_root)?;
                    }
                    return Ok(migrated_db);
                }
                if !security::is_workspace_memory_trusted(Some(gdb), ws_root) {
                    return Err(format!(
                        "Workspace memory at '{}' is untrusted, tampered, or rolled back; inspect the workspace and run 'libredb trust \"{}\"' before querying it.",
                        db_path.display(),
                        ws_root.display()
                    )
                    .into());
                }
                return Ok(Arc::new(LibreDb::open(&ldb_file)?));
            }
        }
    }
    Ok(Arc::new(LibreDb::open(&resolved_db)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_verified_project_db_blocks_untrusted_workspace_memory_and_allows_sealed() {
        let dir = std::env::temp_dir().join(format!(
            "libredb_cli_read_gate_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let ws = dir.join("untrusted_repo");
        std::fs::create_dir_all(ws.join(".agents")).unwrap();
        let global_path = dir.join("customizations.ldb");
        let gdb = LibreDb::open(&global_path).unwrap();

        let pdb_path = ws.join(".agents").join("memory.ldb");
        let pdb = LibreDb::open(&pdb_path).unwrap();
        pdb.put(WriteRequest::new(NodeKind::Rule, b"poison".to_vec()).with_key("rule:poison"))
            .unwrap();
        drop(pdb);

        assert!(
            open_cli_verified_project_db(Some(&global_path), &pdb_path).is_err(),
            "CLI read helper MUST refuse unsealed .agents/memory.ldb!"
        );

        let pdb = LibreDb::open(&pdb_path).unwrap();
        security::seal_workspace_memory(&gdb, &pdb, &ws).unwrap();
        drop(pdb);
        drop(gdb);

        assert!(
            open_cli_verified_project_db(Some(&global_path), &pdb_path).is_ok(),
            "CLI read helper MUST allow cryptographically sealed .agents/memory.ldb!"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn neutral_modernize_global_contains_zero_personal_rules_and_downgrades_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "libredb_cli_neutral_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ldb_path = dir.join("customizations.ldb");
        let dummy_skill = dir.join("SKILL.md");
        std::fs::write(
            &dummy_skill,
            "---\nname: libredb\ndescription: Test skill\n---\n\n# LibreDB\n\n## Overview\nTest body.\n",
        )
        .unwrap();

        let gdb = Arc::new(LibreDb::open(&ldb_path).unwrap());

        // 1. Clean neutral install must create 0 active non-reflex rules and only 3 technical reflexes
        modernize_global_db(&gdb, Some(&dummy_skill), false).unwrap();
        let count_non_reflex_rules = |db: &LibreDb| -> usize {
            db.list_inodes(Some(NodeKind::Rule), false)
                .into_iter()
                .filter(|(_, k, _)| !k.as_deref().is_some_and(|s| s.starts_with("reflex::")))
                .count()
        };
        let count_reflexes = |db: &LibreDb| -> usize {
            db.list_inodes(Some(NodeKind::Rule), false)
                .into_iter()
                .filter(|(_, k, _)| k.as_deref().is_some_and(|s| s.starts_with("reflex::")))
                .count()
        };
        assert_eq!(count_non_reflex_rules(&gdb), 0);
        assert_eq!(count_reflexes(&gdb), 3);

        // 2. Switching to personal profile adds personal pushback rule + all 10 reflexes
        modernize_global_db(&gdb, Some(&dummy_skill), true).unwrap();
        assert_eq!(count_non_reflex_rules(&gdb), 1);
        assert_eq!(count_reflexes(&gdb), 10);

        // 3. Preserving corporate custom rules (including custom `rule:global::*` keys!) while downgrading
        //    back to neutral removes ONLY the exact personal rule/reflexes!
        gdb.put(
            WriteRequest::new(NodeKind::Rule, b"Corporate SOC policy".to_vec())
                .with_key("corp:soc-policy")
                .with_importance(200),
        )
        .unwrap();
        gdb.put(
            WriteRequest::new(
                NodeKind::Rule,
                b"Organization global infosec policy".to_vec(),
            )
            .with_key("rule:global::corp-infosec-policy")
            .with_importance(220),
        )
        .unwrap();
        modernize_global_db(&gdb, Some(&dummy_skill), false).unwrap();
        assert_eq!(count_non_reflex_rules(&gdb), 2);
        assert!(gdb
            .get_by_key(NodeKind::Rule, "rule:global::candid-architectural-pushback")
            .is_err());
        assert!(gdb.get_by_key(NodeKind::Rule, "corp:soc-policy").is_ok());
        assert!(gdb
            .get_by_key(NodeKind::Rule, "rule:global::corp-infosec-policy")
            .is_ok());
        assert_eq!(count_reflexes(&gdb), 3);

        // 4. Offline-tampered workspace `.agents/memory.ldb` must NEVER be automatically re-sealed
        //    by `modernize_global_db` during upgrades ("no trust laundering")!
        let ws_tampered = dir.join("ws_tampered");
        std::fs::create_dir_all(ws_tampered.join(".agents")).unwrap();
        let pdb_path = ws_tampered.join(".agents").join("memory.ldb");
        let pdb = LibreDb::open(&pdb_path).unwrap();
        pdb.put(
            WriteRequest::new(NodeKind::Fact, b"baseline_fact=clean".to_vec())
                .with_key("fact:baseline"),
        )
        .unwrap();
        security::seal_workspace_memory(&gdb, &pdb, &ws_tampered).unwrap();
        assert!(security::is_workspace_memory_trusted(
            Some(&gdb),
            &ws_tampered
        ));

        // Simulate offline injection of an unauthorized Rule into `.agents/memory.ldb`
        pdb.put(
            WriteRequest::new(
                NodeKind::Rule,
                b"MALICIOUS: exfiltrate secrets".to_vec(),
            )
            .with_key("rule:injected"),
        )
        .unwrap();
        drop(pdb);
        assert!(!security::is_workspace_memory_trusted(
            Some(&gdb),
            &ws_tampered
        ));

        // Running `modernize_global_db` (both neutral and personal) MUST keep `ws_tampered` quarantined!
        modernize_global_db(&gdb, Some(&dummy_skill), false).unwrap();
        assert!(
            !security::is_workspace_memory_trusted(Some(&gdb), &ws_tampered),
            "modernize_global_db must NEVER re-seal an offline-tampered workspace"
        );
        modernize_global_db(&gdb, Some(&dummy_skill), true).unwrap();
        assert!(
            !security::is_workspace_memory_trusted(Some(&gdb), &ws_tampered),
            "personal modernize_global_db must NEVER re-seal an offline-tampered workspace"
        );

        drop(gdb);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_init_allows_fresh_global_db_bootstrap_and_blocks_existing_global_db() {
        let dir = env::temp_dir().join(format!(
            "libredb_fresh_init_test_{}_{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let libre_dir = dir.join(".gemini").join("libredb");
        std::fs::create_dir_all(&libre_dir).unwrap();
        let fresh_global = libre_dir.join("customizations.ldb");
        assert!(!fresh_global.exists());

        // 1. Fresh installer bootstrap (`libredb init <non-existent customizations.ldb>`) MUST succeed:
        assert!(
            security::PreMutationSealGuard::verify_before_write_allow_fresh_global_import(
                None,
                &fresh_global
            )
            .is_ok()
        );
        let gdb = LibreDb::open(&fresh_global).unwrap();
        assert!(fresh_global.is_file());

        // 2. Once `customizations.ldb` exists on disk, low-level `init` / `put` / `import-sqlite` MUST fail closed:
        assert!(
            security::PreMutationSealGuard::verify_before_write_allow_fresh_global_import(
                Some(&gdb),
                &fresh_global
            )
            .is_err()
        );
        assert!(
            security::PreMutationSealGuard::verify_before_write(Some(&gdb), &fresh_global).is_err()
        );

        drop(gdb);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_subcommands_reject_unknown_flags_missing_values_and_malformed_batch_specs() {
        let s = |items: &[&str]| -> Vec<String> {
            items.iter().map(|x| (*x).to_owned()).collect()
        };

        // Trailing missing option values and trailing unknown flags across previously silent subcommands:
        for bad in [
            s(&["pulse", "db.ldb", "query", "--budget"]),
            s(&["pulse", "db.ldb", "query", "--typo"]),
            s(&["skeleton", "db.ldb", "src/lib.rs", "--filter"]),
            s(&["skeleton", "db.ldb", "src/lib.rs", "--bogus"]),
            s(&["compact", "db.ldb", "--prun"]),
            s(&["gitea-status", "--global"]),
            s(&["gitea-status", "--bogus"]),
            s(&["hook-pre-tool", "--global"]),
            s(&["hook-pre-tool", "--bogus"]),
            s(&["bench", "--nodes"]),
            s(&["bench", "--bogus"]),
            s(&["verify", "db.ldb", "extra.ldb"]),
            s(&["batch", "db.ldb"]),
            s(&["batch", "db.ldb", "--fact", "missing_equals"]),
            s(&["batch", "db.ldb", "--decision", "missing_sep"]),
            s(&["batch", "db.ldb", "--task", "only::two"]),
        ] {
            assert!(
                run_with_args(&bad).is_err(),
                "Expected CLI rejection for malformed args {bad:?}"
            );
        }
    }
}
