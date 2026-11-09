//! Command-line interface for `LibreDB v0.2.0`: cognitive `pulse`, `skeleton`, `reflex`,
//! lossless `SQLite` migration/verification, and storage diagnostics.

use libredb_bridge::{
    export_sqlite_database, import_sqlite_readonly, verify_sqlite_equivalence,
};
use libredb_cognitive::{
    CognitiveEngine, FileSkeleton, PulseRequest, ReflexEngine, ReflexRule,
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
        "LibreDB v{} - Cognitive LLM memory & token-conservation engine

Cognitive & Token-Conservation Commands:
  libredb pulse <db.ldb> <query> [--cid <conv_id>] [--epoch <n>] [--budget <tok>] [--cwd <dir>] [--err <msg>]
  libredb skeleton <db.ldb> <source_file> [--filter <substr>]
  libredb learn-assoc <db.ldb> <cue_phrase> <target_id_1,target_id_2>
  libredb learn-reflex <db.ldb> <id> <directive> [--stack <s1,s2>] [--action <a1,a2>] [--env <e1,e2>]

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
        "pulse" => {
            if args.len() < 3 {
                return Err(
                    "Usage: libredb pulse <db.ldb> <query> [--cid <id>] [--epoch <n>] [--budget <tok>] [--cwd <dir>] [--err <msg>]".into(),
                );
            }
            let mut req = PulseRequest::new(&args[2], 800);
            let mut i = 3usize;
            while i + 1 < args.len() {
                match args[i].as_str() {
                    "--cid" => {
                        req.conversation_id = Some(args[i + 1].clone());
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
            let db = Arc::new(LibreDb::open(&args[1])?);
            let cog = CognitiveEngine::open_db(db)?;
            let resp = cog.pulse(&req)?;
            let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!("{}", resp.format_compact());
            println!("[Completed in {elapsed_ms:.2} ms]");
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
                if cache_hit { "served from hash-verified cache" } else { "extracted & cached" },
                elapsed_ms
            );
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
            let db = LibreDb::open(&args[1])?;
            let sum = import_sqlite_readonly(Path::new(&args[2]), &db, scope)?;
            println!(
                "[OK] Imported SQLite '{}' (scope={}) in {:.2} ms: {} tables ({} rows) -> {} cognitive capsules + {} synapses",
                args[2],
                sum.scope,
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

            // Strictly copy source SQLite to temp first so original file is never locked or touched!
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
            println!("  Tables verified:       {} (including {} FTS5 virtual tables)", rep.tables_verified, rep.fts5_tables_verified);
            println!("  Exact rows verified:   {} (0 discrepancies)", rep.rows_verified);
            println!("  Cognitive graph built: {} capsules + {} synapses", imp_sum.cognitive_capsules_created, imp_sum.synapses_wired);
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
            println!("Causal & temporal lineage from node #{root_id} ({} steps):", chain.len());
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
            let db = LibreDb::open(&args[1])?;
            let t0 = Instant::now();
            let rep = db.compact_with_gravity()?;
            println!(
                "Gravity compaction finished in {:.2} ms: {} -> {} bytes ({} hot nodes in {} locality groups, {} cold nodes archived)",
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
