//! Command-line interface, lifecycle hooks, Gitea automation, and native MCP server for `LibreDB`.

mod gitea;
mod hooks;
mod mcp;

use libredb_bridge::{
    export_sqlite_database, import_sqlite_readonly, open_or_auto_migrate, verify_sqlite_equivalence,
};
use libredb_cognitive::{
    audit_workspace_guardrails, create_subagent_handoff, execute_atomic_batch, extract_fim_slice,
    index_workspace, query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine,
    FileSkeleton, OverlayBrain, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use std::env;
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
  libredb mcp-serve [<default_project.ldb>] [--global <customizations.ldb>]

Native Antigravity Hooks, Guardrails & Gitea Automation:
  libredb guardrail check [--path <dir>] [--staged] [--strict]
  libredb hook-pre-tool [--global <customizations.ldb>]
  libredb hook-pre-invocation [--global <customizations.ldb>]
  libredb gitea-status [--global <customizations.ldb>]
  libredb gitea-config [--url <u>] [--user <usr>] [--token <tok>] [--register-helper]
  libredb gitea-credential-helper [get]
  libredb gitea-init [<dir>] [--name <repo>] [--use-existing] [--overwrite]
  libredb gitea-sync [-m <msg>] [--project <dir>] [--releases] [--allow-unversioned]
  libredb gitea-release [vX.Y.Z] [--project <dir>]

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
  libredb compact <db.ldb>
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
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "mcp-serve" => {
            let mut proj_path: Option<PathBuf> = None;
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--global" if i + 1 < args.len() => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--project" if i + 1 < args.len() => {
                        proj_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    positional if !positional.starts_with("--") && proj_path.is_none() => {
                        proj_path = Some(PathBuf::from(positional));
                        i += 1;
                    }
                    other => return Err(format!("Unknown mcp-serve argument '{other}'").into()),
                }
            }
            mcp::run_mcp_stdio_server(proj_path.as_deref(), global_path.as_deref())?;
        }
        "hook-pre-tool" => {
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i + 1 < args.len() {
                if args[i] == "--global" {
                    global_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            hooks::run_pre_tool_hook(global_path.as_deref())?;
        }
        "hook-pre-invocation" => {
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i + 1 < args.len() {
                if args[i] == "--global" {
                    global_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            hooks::run_pre_invocation_hook(global_path.as_deref())?;
        }
        "guardrail" => {
            let sub = args.get(1).map(String::as_str).unwrap_or("check");
            if sub != "check" {
                return Err("Usage: libredb guardrail check [--path <dir>] [--staged] [--strict]".into());
            }
            let mut dir = env::current_dir()?;
            let mut staged = false;
            let mut strict = false;
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--path" if i + 1 < args.len() => {
                        dir = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    "--staged" => {
                        staged = true;
                        i += 1;
                    }
                    "--strict" => {
                        strict = true;
                        i += 1;
                    }
                    other => return Err(format!("Unknown guardrail flag '{other}'").into()),
                }
            }
            let rep = audit_workspace_guardrails(&dir, staged)?;
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
        "get-skill" => {
            if args.len() < 2 {
                return Err("Usage: libredb get-skill <skill_name> [--section <title>] [--global <customizations.ldb>]".into());
            }
            let skill_name = &args[1];
            let mut section: Option<String> = None;
            let mut global_path: Option<PathBuf> = None;
            let mut i = 2usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--section" => {
                        section = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--global" => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }
            let gdb = hooks::open_global_ldb(global_path.as_deref())?;
            if let Some(sec_title) = section {
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
        "gitea-credential-helper" => {
            let action = args.get(1).map(String::as_str).unwrap_or("get");
            gitea::cmd_gitea_credential_helper(action, None)?;
        }
        "gitea-status" => {
            let mut global_path: Option<PathBuf> = None;
            if args.len() >= 3 && args[1] == "--global" {
                global_path = Some(PathBuf::from(&args[2]));
            }
            gitea::cmd_gitea_status(global_path.as_deref())?;
        }
        "gitea-config" => {
            let mut url: Option<String> = None;
            let mut user: Option<String> = None;
            let mut token: Option<String> = None;
            let mut global_path: Option<PathBuf> = None;
            let mut reg_helper = false;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--url" if i + 1 < args.len() => {
                        url = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--user" if i + 1 < args.len() => {
                        user = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--token" if i + 1 < args.len() => {
                        token = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--global" if i + 1 < args.len() => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--register-helper" => {
                        reg_helper = true;
                        i += 1;
                    }
                    other => return Err(format!("Unknown gitea-config flag '{other}'").into()),
                }
            }
            gitea::cmd_gitea_config(
                global_path.as_deref(),
                url.as_deref(),
                user.as_deref(),
                token.as_deref(),
                reg_helper,
            )?;
        }
        "gitea-init" => {
            let mut dir = env::current_dir()?;
            let mut name: Option<String> = None;
            let mut use_existing = false;
            let mut overwrite = false;
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--name" if i + 1 < args.len() => {
                        name = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--global" if i + 1 < args.len() => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--use-existing" => {
                        use_existing = true;
                        i += 1;
                    }
                    "--overwrite" => {
                        overwrite = true;
                        i += 1;
                    }
                    pos if !pos.starts_with("--") => {
                        dir = PathBuf::from(pos);
                        i += 1;
                    }
                    other => return Err(format!("Unknown gitea-init flag '{other}'").into()),
                }
            }
            gitea::cmd_gitea_init(&dir, name.as_deref(), use_existing, overwrite, global_path.as_deref())?;
        }
        "gitea-sync" => {
            let mut dir = env::current_dir()?;
            let mut msg = "Synchronize workspace".to_owned();
            let mut releases = false;
            let mut allow_unversioned = false;
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "-m" | "--message" if i + 1 < args.len() => {
                        msg = args[i + 1].clone();
                        i += 2;
                    }
                    "--project" if i + 1 < args.len() => {
                        dir = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    "--global" if i + 1 < args.len() => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--releases" => {
                        releases = true;
                        i += 1;
                    }
                    "--allow-unversioned" => {
                        allow_unversioned = true;
                        i += 1;
                    }
                    other => return Err(format!("Unknown gitea-sync flag '{other}'").into()),
                }
            }
            gitea::cmd_gitea_sync(&dir, &msg, releases, allow_unversioned, global_path.as_deref())?;
        }
        "gitea-release" => {
            let mut dir = env::current_dir()?;
            let mut tag: Option<String> = None;
            let mut global_path: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--project" if i + 1 < args.len() => {
                        dir = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    "--global" if i + 1 < args.len() => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    pos if !pos.starts_with("--") && tag.is_none() => {
                        tag = Some(pos.to_owned());
                        i += 1;
                    }
                    other => return Err(format!("Unknown gitea-release flag '{other}'").into()),
                }
            }
            gitea::cmd_gitea_release(&dir, tag.as_deref(), global_path.as_deref())?;
        }
        "pulse" => {
            if args.len() < 3 {
                return Err(
                    "Usage: libredb pulse <db.ldb> <query> [--global <g.ldb>] [--cid <id>] [--transcript <t.jsonl>] [--epoch <n>] [--budget <tok>] [--cwd <dir>] [--err <msg>]".into(),
                );
            }
            let mut req = PulseRequest::new(&args[2], 800);
            let mut global_path: Option<PathBuf> = None;
            let mut transcript_path: Option<PathBuf> = None;

            let mut i = 3usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--global" => {
                        global_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--cid" => {
                        req.conversation_id = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--transcript" => {
                        transcript_path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--epoch" => {
                        req.epoch = args[i + 1].parse()?;
                        i += 2;
                    }
                    "--budget" => {
                        req.token_budget = args[i + 1].parse()?;
                        i += 2;
                    }
                    "--cwd" => {
                        req.workspace_dir = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    "--err" => {
                        req.error_context = Some(args[i + 1].clone());
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }

            let t0 = Instant::now();
            let (proj_db, _) = open_or_auto_migrate(Path::new(&args[1]), None, "project")?;
            if let (Some(ref cid), Some(ref tp)) = (&req.conversation_id, &transcript_path) {
                req.epoch = sync_transcript_epoch(&proj_db, cid, tp)?;
            }
            let glob_db = match global_path {
                Some(gp) => Some(open_or_auto_migrate(&gp, None, "central")?.0),
                None => None,
            };
            let brain = OverlayBrain::open(glob_db, proj_db)?;
            let resp = brain.pulse(&req)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!("{}", resp.format_compact());
            println!("[Completed in {elapsed_ms:.2} ms]");
        }
        "index-workspace" => {
            if args.len() < 3 {
                return Err("Usage: libredb index-workspace <db.ldb> <workspace_dir> [--force]".into());
            }
            let force = args.get(3).map(String::as_str) == Some("--force");
            let t0 = Instant::now();
            let db = Arc::new(LibreDb::open(&args[1])?);
            let rep = index_workspace(&db, Path::new(&args[2]), force)?;
            let mut cog = CognitiveEngine::open_db(db)?;
            cog.save_index_snapshot()?;
            println!(
                "[OK] Indexed workspace '{}' in {:.2} ms: {} files scanned ({} cached, {} reindexed, {} binaries skipped) -> {} symbols, {} call edges, {} governance edges",
                args[2],
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
            if args.len() < 3 {
                return Err("Usage: libredb skeleton <db.ldb> <source_file> [--filter <substr>]".into());
            }
            let mut filter: Option<String> = None;
            if args.len() >= 5 && args[3] == "--filter" {
                filter = Some(args[4].clone());
            }
            let t0 = Instant::now();
            let db = LibreDb::open(&args[1])?;
            let src_path = Path::new(&args[2]);
            let (skel, cache_hit) = FileSkeleton::index_or_get_cached(&db, src_path, None)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            print!("{}", skel.render_compact(filter.as_deref(), filter.is_some()));
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
            if args.len() < 3 {
                return Err("Usage: libredb impact <db.ldb> <symbol_query>".into());
            }
            let t0 = Instant::now();
            let db = LibreDb::open(&args[1])?;
            let reports = query_symbol_impact(&db, &args[2])?;
            println!(
                "=== BLAST-RADIUS & CAUSAL IMPACT: '{}' ({} matches in {:.2} ms) ===",
                args[2],
                reports.len(),
                t0.elapsed().as_secs_f64() * 1000.0
            );
            for r in reports {
                println!("\n* [#{}] {}", r.node_id, r.contract);
                for g in &r.governing_decisions {
                    println!("    [Governed by]: {g}");
                }
                for c in &r.callers {
                    println!("    [Called by]  <- {c}");
                }
                for d in &r.callees {
                    println!("    [Calls]      -> {d}");
                }
            }
        }
        "fim" => {
            if args.len() < 3 {
                return Err("Usage: libredb fim <db.ldb> <source_file> [--symbol <name> | --line <n>] [--pad <lines>]".into());
            }
            let mut symbol: Option<String> = None;
            let mut line: Option<usize> = None;
            let mut pad = 12usize;
            let mut i = 3usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--symbol" => {
                        symbol = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--line" => {
                        line = Some(args[i + 1].parse()?);
                        i += 2;
                    }
                    "--pad" => {
                        pad = args[i + 1].parse()?;
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }
            let db = LibreDb::open(&args[1])?;
            let bundle =
                extract_fim_slice(&db, Path::new(&args[2]), symbol.as_deref(), line, pad)?;
            print!("{}", bundle.format_compact());
        }
        "batch" => {
            if args.len() < 3 {
                return Err("Usage: libredb batch <db.ldb> [--fact k=v] [--decision Title::Body] [--task key::title::status::prio] [--snapshot <text>]".into());
            }
            let mut spec = AtomicBatchSpec::default();
            let mut i = 2usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--fact" => {
                        if let Some((k, v)) = args[i + 1].split_once('=') {
                            spec.facts.push((k.trim().to_owned(), v.trim().to_owned()));
                        }
                        i += 2;
                    }
                    "--decision" => {
                        if let Some((t, b)) = args[i + 1].split_once("::") {
                            spec.decisions.push((t.trim().to_owned(), b.trim().to_owned()));
                        }
                        i += 2;
                    }
                    "--task" => {
                        let parts: Vec<&str> = args[i + 1].splitn(4, "::").collect();
                        if parts.len() == 4 {
                            spec.tasks.push((
                                parts[0].trim().to_owned(),
                                parts[1].trim().to_owned(),
                                parts[2].trim().to_owned(),
                                parts[3].trim().to_owned(),
                            ));
                        }
                        i += 2;
                    }
                    "--snapshot" => {
                        spec.snapshot = Some(args[i + 1].clone());
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }
            let t0 = Instant::now();
            let db = LibreDb::open(&args[1])?;
            let rep = execute_atomic_batch(&db, &spec)?;
            println!(
                "[OK] Committed {} capsules and wired {} governance synapses in {:.2} ms (IDs: {:?})",
                rep.nodes_committed,
                rep.governance_edges_wired,
                t0.elapsed().as_secs_f64() * 1000.0,
                rep.assigned_node_ids
            );
        }
        "handoff" => {
            if args.len() < 5 {
                return Err("Usage: libredb handoff <db.ldb> <handoff_id> <task_key> <role> [--notes <text>]".into());
            }
            let mut notes = "";
            if args.len() >= 7 && args[5] == "--notes" {
                notes = &args[6];
            }
            let db = LibreDb::open(&args[1])?;
            let (_, block) = create_subagent_handoff(&db, &args[2], &args[3], &args[4], notes)?;
            print!("{block}");
        }
        "learn-assoc" => {
            if args.len() < 4 {
                return Err("Usage: libredb learn-assoc <db.ldb> <cue_phrase> <id1,id2,...>".into());
            }
            let target_ids: Result<Vec<u64>, _> = args[3]
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().parse::<u64>())
                .collect();
            let target_ids = target_ids?;
            let db = Arc::new(LibreDb::open(&args[1])?);
            let mut cog = CognitiveEngine::open_db(db)?;
            let edges = cog.reinforce_association(&args[2], &target_ids)?;
            cog.save_index_snapshot()?;
            println!(
                "Reinforced {} Hebbian concept synapses from '{}' -> {:?}",
                edges, args[2], target_ids
            );
        }
        "learn-reflex" => {
            if args.len() < 4 {
                return Err("Usage: libredb learn-reflex <db.ldb> <id> <directive> [--stack s] [--action a] [--env e]".into());
            }
            let mut rule = ReflexRule {
                id: args[2].clone(),
                stack_any: Vec::new(),
                action_any: Vec::new(),
                env_or_error_any: Vec::new(),
                directive: args[3].clone(),
            };
            let mut i = 4usize;
            while i + 1 < args.len() {
                let items: Vec<String> = args[i + 1]
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                match args[i].as_str() {
                    "--stack" => rule.stack_any = items,
                    "--action" => rule.action_any = items,
                    "--env" => rule.env_or_error_any = items,
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
                i += 2;
            }
            let db = LibreDb::open(&args[1])?;
            let nid = ReflexEngine::learn_reflex(&db, &rule)?;
            println!("Learned situational reflex '{}' as node #{nid}", rule.id);
        }
        "import-sqlite" => {
            if args.len() < 3 {
                return Err("Usage: libredb import-sqlite <db.ldb> <source.db> [--scope central|project]".into());
            }
            let mut scope = "central";
            if args.len() >= 5 && args[3] == "--scope" {
                scope = &args[4];
            }
            let t0 = Instant::now();
            let db = Arc::new(LibreDb::open(&args[1])?);
            let sum = import_sqlite_readonly(Path::new(&args[2]), &db, scope)?;
            // Pre-build and persist the inverted index snapshot so cold CLI `pulse` runs in <10 ms!
            let mut cog = CognitiveEngine::open_db(db)?;
            cog.save_index_snapshot()?;
            println!(
                "[OK] Imported SQLite '{}' + saved persistent index snapshot in {:.2} ms: {} tables ({} rows) -> {} cognitive capsules + {} synapses",
                args[2],
                t0.elapsed().as_secs_f64() * 1000.0,
                sum.tables_mirrored,
                sum.total_sqlite_rows,
                sum.cognitive_capsules_created,
                sum.synapses_wired
            );
        }
        "export-sqlite" => {
            if args.len() < 3 {
                return Err("Usage: libredb export-sqlite <db.ldb> <reconstructed.db> [--scope central|project]".into());
            }
            let mut scope = "central";
            if args.len() >= 5 && args[3] == "--scope" {
                scope = &args[4];
            }
            let t0 = Instant::now();
            let db = LibreDb::open(&args[1])?;
            let rows = export_sqlite_database(&db, scope, Path::new(&args[2]))?;
            println!(
                "[OK] Reconstructed SQLite '{}' (scope={}, {} rows + FTS5 indexes) in {:.2} ms",
                args[2],
                scope,
                rows,
                t0.elapsed().as_secs_f64() * 1000.0
            );
        }
        "verify-roundtrip" => {
            if args.len() < 2 {
                return Err("Usage: libredb verify-roundtrip <source.db> [--scope central|project]".into());
            }
            let mut scope = "central";
            if args.len() >= 4 && args[2] == "--scope" {
                scope = &args[3];
            }
            let src_path = Path::new(&args[1]);
            let pid = process::id();
            let tmp_dir = env::temp_dir().join(format!("libredb_roundtrip_{pid}"));
            let _ = std::fs::remove_dir_all(&tmp_dir);
            std::fs::create_dir_all(&tmp_dir)?;

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
            if args.len() < 2 {
                return Err("Usage: libredb init <db.ldb>".into());
            }
            let db = LibreDb::open(&args[1])?;
            let st = db.stats()?;
            println!(
                "Initialized LibreDB at '{}' ({} bytes, commit_seq={})",
                args[1], st.file_bytes, st.commit_seq
            );
        }
        "put" => {
            if args.len() < 4 {
                return Err("Usage: libredb put <db.ldb> <kind> <payload> [--key <k>] [--importance <0..255>] [--pin]".into());
            }
            let kind = NodeKind::parse(&args[2])
                .ok_or_else(|| format!("Unknown node kind '{}'", args[2]))?;
            let mut req = WriteRequest::new(kind, args[3].as_bytes().to_vec());

            let mut i = 4usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--key" if i + 1 < args.len() => {
                        req = req.with_key(&args[i + 1]);
                        i += 2;
                    }
                    "--importance" if i + 1 < args.len() => {
                        req = req.with_importance(args[i + 1].parse()?);
                        i += 2;
                    }
                    "--pin" => {
                        req = req.with_pinned(true);
                        i += 1;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }

            let db = LibreDb::open(&args[1])?;
            let id = db.put(req)?;
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
            if args.len() < 3 {
                return Err("Usage: libredb get <db.ldb> <node_id>".into());
            }
            let db = LibreDb::open(&args[1])?;
            let id: u64 = args[2].parse()?;
            let rec = db.get(id)?;
            print_record(&rec);
        }
        "get-key" => {
            if args.len() < 4 {
                return Err("Usage: libredb get-key <db.ldb> <kind> <key>".into());
            }
            let kind = NodeKind::parse(&args[2])
                .ok_or_else(|| format!("Unknown node kind '{}'", args[2]))?;
            let db = LibreDb::open(&args[1])?;
            let rec = db.get_by_key(kind, &args[3])?;
            print_record(&rec);
        }
        "link" => {
            if args.len() < 5 {
                return Err("Usage: libredb link <db.ldb> <src_id> <edge_kind> <dst_id> [--weight <0..255>]".into());
            }
            let src_id: u64 = args[2].parse()?;
            let edge_kind = EdgeKind::parse(&args[3])
                .ok_or_else(|| format!("Unknown edge kind '{}'", args[3]))?;
            let dst_id: u64 = args[4].parse()?;
            let mut weight: u8 = 200;
            if args.len() >= 7 && args[5] == "--weight" {
                weight = args[6].parse()?;
            }
            let db = LibreDb::open(&args[1])?;
            db.link(src_id, edge_kind, dst_id, weight)?;
            println!(
                "Linked node #{} --[{} (w={})]--> node #{}",
                src_id,
                edge_kind.as_str(),
                weight,
                dst_id
            );
        }
        "deprecate" => {
            if args.len() < 4 {
                return Err("Usage: libredb deprecate <db.ldb> <kind> <key>".into());
            }
            let kind = NodeKind::parse(&args[2])
                .ok_or_else(|| format!("Unknown node kind '{}'", args[2]))?;
            let db = LibreDb::open(&args[1])?;
            let removed = db.deprecate_key(kind, &args[3])?;
            if removed {
                println!("Deprecated active key '{}' ({})", args[3], kind.as_str());
            } else {
                println!("Key '{}' ({}) not found", args[3], kind.as_str());
            }
        }
        "trace" => {
            if args.len() < 3 {
                return Err("Usage: libredb trace <db.ldb> <node_id> [--depth <n>]".into());
            }
            let root_id: u64 = args[2].parse()?;
            let mut depth = 8usize;
            if args.len() >= 5 && args[3] == "--depth" {
                depth = args[4].parse()?;
            }
            let db = LibreDb::open(&args[1])?;
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
            if args.len() < 3 {
                return Err("Usage: libredb recall <db.ldb> <seed_id> [--hops <n>] [--budget <tokens>]".into());
            }
            let seed_id: u64 = args[2].parse()?;
            let mut hops = 2usize;
            let mut budget = 800u32;
            let mut i = 3usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--hops" => {
                        hops = args[i + 1].parse()?;
                        i += 2;
                    }
                    "--budget" => {
                        budget = args[i + 1].parse()?;
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }
            let db = LibreDb::open(&args[1])?;
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
            if args.len() < 2 {
                return Err("Usage: libredb compact <db.ldb>".into());
            }
            let t0 = Instant::now();
            let db = Arc::new(LibreDb::open(&args[1])?);
            let mut cog = CognitiveEngine::open_db(Arc::clone(&db))?;
            cog.save_index_snapshot()?;
            let rep = db.compact_with_gravity()?;
            println!(
                "Gravity compaction + index snapshot finished in {:.2} ms: {} -> {} bytes ({} hot nodes in {} locality groups, {} cold nodes archived)",
                t0.elapsed().as_secs_f64() * 1000.0,
                rep.bytes_before,
                rep.bytes_after,
                rep.hot_nodes_packed,
                rep.locality_groups,
                rep.cold_nodes_archived
            );
        }
        "stats" => {
            if args.len() < 2 {
                return Err("Usage: libredb stats <db.ldb> [--json]".into());
            }
            let db = LibreDb::open(&args[1])?;
            let st = db.stats()?;
            if args.get(2).map(String::as_str) == Some("--json") {
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
            if args.len() < 2 {
                return Err("Usage: libredb verify <db.ldb>".into());
            }
            let t0 = Instant::now();
            let db = LibreDb::open(&args[1])?;
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
            let mut total_nodes = 10_000usize;
            let mut threads = 16usize;
            let mut i = 1usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--nodes" => {
                        total_nodes = args[i + 1].parse()?;
                        i += 2;
                    }
                    "--threads" => {
                        threads = args[i + 1].parse()?;
                        i += 2;
                    }
                    other => return Err(format!("Unknown flag '{other}'").into()),
                }
            }
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
