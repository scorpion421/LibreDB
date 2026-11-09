//! Command-line utility for inspecting, mutating, compacting, verifying, and benchmarking `.ldb` files.

use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use std::env;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn print_usage() {
    println!(
        "LibreDB v{} - Single-file cognitive chaos-extent-inode storage engine

Usage:
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
    println!("Payload ({} bytes):\n{}", rec.payload.len(), String::from_utf8_lossy(&rec.payload));
}

fn run_microbench(total_nodes: usize, threads: usize) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_path: PathBuf = env::temp_dir().join(format!("libredb_bench_{}.tmp.ldb", process::id()));
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

    // Concurrent 16-thread random reads
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
    println!("  Parallel prepare ({threads} lanes): {:>8.2} ms ({:.0} nodes/sec)", prep_ms, (actual_n as f64) / (prep_ms / 1000.0));
    println!("  Atomic batch commit + fsync:   {:>8.2} ms ({:.0} nodes/sec)", commit_ms, (actual_n as f64) / (commit_ms / 1000.0));
    println!("  Concurrent {threads}-thread reads:  {:>8.2} ms ({:.0} reads/sec)", read_ms, (actual_n as f64) / (read_ms / 1000.0));
    println!("  Gravity compaction + verify:   {:>8.2} ms ({} -> {} bytes)", comp_ms, comp.bytes_before, st.file_bytes);
    Ok(())
}
