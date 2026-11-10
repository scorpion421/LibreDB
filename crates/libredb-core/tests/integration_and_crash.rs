//! Integration, concurrency, gravity locality, and 10,000-cycle deterministic crash tests.

use libredb_core::{
    EdgeKind, FaultInjectingBackend, Inode, InodeStorage, LibreDb, LibreDbError, NodeFlags,
    NodeKind, Synapse, WriteRequest, INODE_SIZE,
};
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn inode_128_byte_wire_roundtrip_and_crc_tamper_detection() {
    let syn1 = Synapse::new(EdgeKind::HasSection, 240, 42).unwrap();
    let syn2 = Synapse::new(EdgeKind::Governs, 180, 999_999).unwrap();

    let mut inline_bytes = [0u8; 43];
    let sample = b"account_tier=ultra";
    inline_bytes[..sample.len()].copy_from_slice(sample);

    let inode = Inode {
        node_id: 7,
        kind: NodeKind::Fact,
        flags: NodeFlags(NodeFlags::ACTIVE | NodeFlags::INLINE_DATA | NodeFlags::PINNED),
        importance: 220,
        token_count: 5,
        created_ns: 1_700_000_000_000,
        updated_ns: 1_700_000_000_500,
        access_count: 19,
        generation: 3,
        key_hash: 0xDEAD_BEEF_CAFE_BABE,
        storage: InodeStorage::Inline {
            len: sample.len() as u8,
            bytes: inline_bytes,
        },
        inline_synapses: [Some(syn1), Some(syn2), None, None],
    };

    let mut raw = inode.encode();
    assert_eq!(raw.len(), INODE_SIZE);

    let decoded = Inode::decode(&raw).expect("clean decode");
    assert_eq!(decoded, inode);

    // Flip a single bit in byte 17 and ensure CRC32 rejects corruption immediately.
    raw[17] ^= 0x01;
    let err = Inode::decode(&raw).unwrap_err();
    assert!(matches!(err, LibreDbError::ChecksumMismatch { context: "inode", .. }));
}

#[test]
fn inline_payload_lz4_extent_and_overflow_synapses_persist_cleanly() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("storage_modes.ldb");

    let hub_id;
    let mut target_ids = Vec::new();

    {
        let db = LibreDb::open(&db_path).unwrap();

        // 1. Tiny config value (`<= 43 B`) stored directly inside the 128-byte Inode (`0` extent I/O).
        let cfg_id = db
            .put(WriteRequest::new(NodeKind::Config, b"mode=golden_ratio".to_vec()).with_key("router_mode"))
            .unwrap();
        let cfg = db.get(cfg_id).unwrap();
        assert!(cfg.flags.contains(NodeFlags::INLINE_DATA));
        assert_eq!(cfg.payload, b"mode=golden_ratio");

        // 2. Compressible skill markdown (`> 96 B`) stored as an LZ4-compressed extent.
        let large_md = "## Customizations database skill\n".repeat(40);
        hub_id = db
            .put(
                WriteRequest::new(NodeKind::Skill, large_md.as_bytes().to_vec())
                    .with_key("customizations-db")
                    .with_pinned(true),
            )
            .unwrap();

        let skill_rec = db.get(hub_id).unwrap();
        assert!(skill_rec.flags.contains(NodeFlags::COMPRESSED_LZ4));
        assert_eq!(skill_rec.payload, large_md.as_bytes());

        // 3. Attach 9 synapses (`> 4` inline capacity -> spills 5 into CRC-verified overflow extent).
        for idx in 0..9 {
            let sec_id = db
                .put(WriteRequest::new(
                    NodeKind::SkillSection,
                    format!("Section #{idx} body").into_bytes(),
                ))
                .unwrap();
            target_ids.push(sec_id);
            db.link(hub_id, EdgeKind::HasSection, sec_id, 200).unwrap();
        }
    }

    // Reopen from disk and verify all 9 synapses + compressed payload + inline config survive intact.
    let reopened = LibreDb::open(&db_path).unwrap();
    reopened.verify_integrity().unwrap();

    let cfg = reopened.get_by_key(NodeKind::Config, "router_mode").unwrap();
    assert_eq!(cfg.payload, b"mode=golden_ratio");

    let syns = reopened.neighbors(hub_id, Some(EdgeKind::HasSection)).unwrap();
    assert_eq!(syns.len(), 9);
    let recovered_targets: Vec<u64> = syns.iter().map(|s| s.target_id).collect();
    assert_eq!(recovered_targets, target_ids);
}

#[test]
fn temporal_superseding_and_causal_lineage_prevent_stale_contradictions() {
    let dir = tempdir().unwrap();
    let db = LibreDb::open(dir.path().join("temporal.ldb")).unwrap();

    // User moves cities three times over the year on the same logical key `city`.
    let id_munich = db
        .put(WriteRequest::new(NodeKind::Fact, b"User lives in Munich".to_vec()).with_key("city"))
        .unwrap();
    let id_hamburg = db
        .put(WriteRequest::new(NodeKind::Fact, b"User moved to Hamburg".to_vec()).with_key("city"))
        .unwrap();
    let id_berlin = db
        .put(WriteRequest::new(NodeKind::Fact, b"User moved to Berlin".to_vec()).with_key("city"))
        .unwrap();

    // Active lookup returns ONLY the current truth (Berlin, generation 3).
    let current = db.get_by_key(NodeKind::Fact, "city").unwrap();
    assert_eq!(current.node_id, id_berlin);
    assert_eq!(current.generation, 3);
    assert_eq!(current.payload, b"User moved to Berlin");
    assert!(current.flags.is_live_active());

    // Older nodes are automatically flagged `SUPERSEDED` (never polluting active recall).
    let old_m = db.get(id_munich).unwrap();
    assert!(old_m.flags.contains(NodeFlags::SUPERSEDED));
    assert!(!old_m.flags.is_live_active());

    // Causal lineage walk reconstructs the exact chronological chain: Berlin -> Hamburg -> Munich!
    let history = db.trace_lineage(id_berlin, 5).unwrap();
    let chain_ids: Vec<u64> = history.iter().map(|n| n.node_id).collect();
    assert_eq!(chain_ids, vec![id_berlin, id_hamburg, id_munich]);
    assert!(history[0].is_active);
    assert!(history[1].is_superseded);
    assert!(history[2].is_superseded);
}

#[test]
fn gravity_compaction_colocates_scattered_family_into_single_coalesced_read() {
    let dir = tempdir().unwrap();
    let db = LibreDb::open(dir.path().join("gravity.ldb")).unwrap();

    let parent_payload = "Parent architectural decision governing network safety and concurrency. ".repeat(6);
    let root_id = db
        .put(
            WriteRequest::new(NodeKind::Decision, parent_payload.into_bytes())
                .with_key("arch-net")
                .with_pinned(true)
                .with_importance(250),
        )
        .unwrap();

    let mut rng_state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut section_ids = Vec::new();

    for i in 0..6 {
        // Scatter 8 KB high-entropy incompressible spacers (> 4 KB gap) between linked family nodes!
        let mut varied_noise = vec![0u8; 8192];
        for byte in &mut varied_noise {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            *byte = (rng_state & 0xFF) as u8;
        }
        db.put(WriteRequest::new(NodeKind::Generic, varied_noise))
            .unwrap();

        let child_text = format!(
            "Linked symbol implementation #{i} enforcing network lease verification with detailed docstring body. "
        )
        .repeat(3);
        let cid = db
            .put(WriteRequest::new(NodeKind::Symbol, child_text.into_bytes()).with_importance(200))
            .unwrap();
        section_ids.push(cid);
        db.link(root_id, EdgeKind::Governs, cid, 240).unwrap();
    }

    // Before Gravity compaction: family extents are separated by > 5 KB noise blocks -> multiple I/O reads.
    let before_bundle = db.recall_within_budget(&[root_id], 2, 10_000, false).unwrap();
    assert_eq!(before_bundle.records.len(), 7);
    assert!(
        before_bundle.coalesced_io_reads >= 6,
        "expected scattered reads before gravity, got {}",
        before_bundle.coalesced_io_reads
    );

    // Run "sleep phase" Gravity compaction (`ext4` block-group style locality clustering).
    let report = db.compact_with_gravity().unwrap();
    assert!(report.hot_nodes_packed >= 7);
    db.verify_integrity().unwrap();

    // After Gravity compaction: all 7 linked family members sit back-to-back -> ONE single coalesced read!
    let after_bundle = db.recall_within_budget(&[root_id], 2, 10_000, false).unwrap();
    assert_eq!(after_bundle.records.len(), 7);
    assert_eq!(
        after_bundle.coalesced_io_reads, 1,
        "expected exactly 1 coalesced sequential read after gravity compaction"
    );
}

#[test]
fn token_budget_packer_strictly_honors_ceiling() {
    let dir = tempdir().unwrap();
    let db = LibreDb::open(dir.path().join("budget.ldb")).unwrap();

    let root = db
        .put(
            WriteRequest::new(
                NodeKind::Skill,
                b"Root skill overview with compact token footprint.".to_vec(),
            )
            .with_importance(255),
        )
        .unwrap();

    for i in 0..10 {
        let body = format!(
            "Detailed micro-skill slice #{i} explaining step-by-step diagnostics, flags, and verification rules."
        )
        .repeat(4);
        let child = db
            .put(WriteRequest::new(NodeKind::SkillSection, body.into_bytes()).with_importance(200 - i as u8))
            .unwrap();
        db.link(root, EdgeKind::HasSection, child, 220).unwrap();
    }

    let budget = 120u32;
    let bundle = db.recall_within_budget(&[root], 2, budget, false).unwrap();
    assert!(!bundle.records.is_empty());
    assert!(
        bundle.total_tokens <= budget,
        "total_tokens {} exceeded budget {}",
        bundle.total_tokens,
        budget
    );
}

#[test]
fn concurrent_16_thread_chaos_write_lanes_and_lock_free_readers() {
    let dir = tempdir().unwrap();
    let db = Arc::new(LibreDb::open(dir.path().join("concurrency.ldb")).unwrap());

    // Seed initial baseline nodes so concurrent readers always have live targets.
    for i in 0..32 {
        db.put(
            WriteRequest::new(NodeKind::Fact, format!("seed_val_{i}").into_bytes())
                .with_key(format!("seed_{i}")),
        )
        .unwrap();
    }

    let mut handles = Vec::new();

    // Spawn 16 writer threads (matching SkillsDB Ultra 16-worker concurrency) + 8 continuous reader threads!
    for tid in 0..16usize {
        let db_w = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for j in 0..50usize {
                let payload = format!(
                    "Subagent #{tid} learned finding #{j}: concurrent chaos write without SQLITE_BUSY."
                );
                let prep = db_w
                    .prepare(
                        WriteRequest::new(NodeKind::Fact, payload.into_bytes())
                            .with_key(format!("w_{tid}_{j}")),
                        tid,
                    )
                    .unwrap();
                db_w.commit_batch(&[prep]).unwrap();
            }
        }));
    }

    for rid in 0..8usize {
        let db_r = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for step in 0..120usize {
                let key = format!("seed_{}", (rid + step) % 32);
                let rec = db_r.get_by_key(NodeKind::Fact, &key).unwrap();
                assert!(rec.payload.starts_with(b"seed_val_"));
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked during concurrent storm");
    }

    // Verify all 16 lanes processed 50 writes each (800 new active + 32 seed = 832 active nodes).
    let lanes = db.lane_distribution();
    assert!(lanes.iter().all(|&c| c >= 50));

    let st = db.verify_integrity().unwrap();
    assert_eq!(st.active_nodes, 832);
}

#[test]
fn deterministic_10000_power_loss_and_torn_write_crash_simulation() {
    // Models continuous mutations, updates, links, deprecations, and Gravity compactions
    // while injecting 10,000 simulated power losses & partial torn writes at every write boundary!
    let backend = Arc::new(FaultInjectingBackend::new());
    let db = LibreDb::open_with_backend(Arc::clone(&backend) as Arc<_>).unwrap();

    // Seed an initial durable baseline.
    let mut committed_truth: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    for k in 0..8 {
        let key = format!("k_{k}");
        let val = format!("initial_value_for_{k}_with_padding_bytes").into_bytes();
        db.put(WriteRequest::new(NodeKind::Fact, val.clone()).with_key(&key))
            .unwrap();
        committed_truth.insert(key, val);
    }

    let mut simulated_crashes: usize = 0;
    let mut op_counter: usize = 0;

    while simulated_crashes < 10_000 {
        op_counter += 1;
        let base_image = backend.durable_crash_image();

        // Sweep across write countdowns `0..=4` and torn byte prefixes (`0`, `1`, `13`, `64`, `511`)
        // to hit delta writes, superblock Slot A, superblock Slot B, and two-phase compaction writes!
        for countdown in 0..=3u64 {
            for &torn_bytes in &[0usize, 1, 13, 64, 511] {
                if simulated_crashes >= 10_000 {
                    break;
                }
                let sim_disk = Arc::new(FaultInjectingBackend::from_durable_image(base_image.clone()));
                let sim_db = LibreDb::open_with_backend(Arc::clone(&sim_disk) as Arc<_>)
                    .expect("clean baseline image must open");

                sim_disk.arm_power_loss(countdown, torn_bytes);

                // Attempt either a keyed update, a multi-item batch, or a full Gravity compaction under fault!
                let key = format!("k_{}", op_counter % 8);
                let next_val = format!(
                    "updated_under_fault_op_{op_counter}_crash_{simulated_crashes}_payload_body"
                )
                .into_bytes();

                let op_result = if op_counter % 7 == 0 {
                    sim_db.compact_with_gravity().map(|_| ())
                } else {
                    sim_db
                        .put(WriteRequest::new(NodeKind::Fact, next_val.clone()).with_key(&key))
                        .map(|_| ())
                };

                // Reboot onto the durable post-crash disk image and verify ACID atomicity + CRC integrity!
                let crashed_platter = sim_disk.durable_crash_image();
                let reboot_disk = Arc::new(FaultInjectingBackend::from_durable_image(crashed_platter));
                let recovered_db = LibreDb::open_with_backend(Arc::clone(&reboot_disk) as Arc<_>)
                    .unwrap_or_else(|e| {
                        panic!(
                            "recovery failed on crash #{simulated_crashes} (countdown={countdown}, torn={torn_bytes}): {e}"
                        )
                    });

                recovered_db.verify_integrity().unwrap_or_else(|e| {
                    panic!("integrity check failed after crash #{simulated_crashes}: {e}")
                });

                // Every key must equal EITHER the pre-crash committed truth OR (if commit succeeded before fault) `next_val`!
                for (truth_k, truth_v) in &committed_truth {
                    let rec = recovered_db
                        .get_by_key(NodeKind::Fact, truth_k)
                        .expect("committed key must never vanish");
                    if truth_k == &key && op_counter % 7 != 0 {
                        assert!(
                            rec.payload == *truth_v || rec.payload == next_val,
                            "atomic violation on key {truth_k}"
                        );
                        if op_result.is_ok() {
                            assert_eq!(rec.payload, next_val);
                        }
                    } else {
                        assert_eq!(rec.payload, *truth_v);
                    }
                }

                simulated_crashes += 1;
            }
        }

        // Advance the real durable state cleanly so subsequent crash iterations exercise deeper histories & compactions!
        let live_key = format!("k_{}", op_counter % 8);
        let live_val = format!("committed_gen_{op_counter}_durable_payload_for_testing").into_bytes();
        db.put(WriteRequest::new(NodeKind::Fact, live_val.clone()).with_key(&live_key))
            .unwrap();
        committed_truth.insert(live_key, live_val);

        if op_counter % 12 == 0 {
            db.compact_with_gravity().unwrap();
        }
    }

    assert_eq!(simulated_crashes, 10_000);
}

#[test]
fn multi_handle_interleaved_ipc_commits_preserve_every_update_and_lock_free_reads() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ipc_concurrent.ldb");

    // Simulate Process A (`libredb-mcp` long-lived daemon) and Process B (`hook-pre-tool` / `CLI`)
    // holding independent `LibreDb` handles over the exact same OS file!
    let handle_mcp = LibreDb::open(&db_path).unwrap();
    let handle_hook = LibreDb::open(&db_path).unwrap();

    handle_mcp
        .put(WriteRequest::new(NodeKind::Fact, b"from_mcp_1".to_vec()).with_key("mcp_fact"))
        .unwrap();

    // Process B writes without Process A knowing in advance:
    handle_hook
        .put(
            WriteRequest::new(NodeKind::WorkingSet, b"src/main.rs".to_vec())
                .with_key("src/main.rs"),
        )
        .unwrap();

    // Now Process A writes again: must NOT overwrite Process B's delta frame at the old tail!
    handle_mcp
        .put(
            WriteRequest::new(NodeKind::Decision, b"ipc_safe_architecture".to_vec())
                .with_key("ipc_dec"),
        )
        .unwrap();

    // Both handles + a fresh verification handle must see ALL 3 capsules intact with valid CRCs!
    handle_hook.sync_from_disk_if_changed().unwrap();
    assert_eq!(
        handle_hook.get_by_key(NodeKind::Fact, "mcp_fact").unwrap().payload,
        b"from_mcp_1"
    );
    assert_eq!(
        handle_mcp
            .get_by_key(NodeKind::WorkingSet, "src/main.rs")
            .unwrap()
            .payload,
        b"src/main.rs"
    );
    assert_eq!(
        handle_hook
            .get_by_key(NodeKind::Decision, "ipc_dec")
            .unwrap()
            .payload,
        b"ipc_safe_architecture"
    );

    let verifier = LibreDb::open(&db_path).unwrap();
    verifier.verify_integrity().unwrap();
}

#[test]
fn compaction_garbage_collects_superseded_system_extents_and_keeps_1_hop_causal_history() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("gc_compaction.ldb");
    let db = LibreDb::open(&db_path).unwrap();

    // 1. Write 5 iterations of a large `sys::index_snapshot` (`NodeKind::Generic`) -> 4 superseded + 1 active
    let big_snap = vec![b'X'; 32_768];
    for _ in 0..5 {
        db.put(
            WriteRequest::new(NodeKind::Generic, big_snap.clone())
                .with_key("sys::index_snapshot")
                .with_importance(5),
        )
        .unwrap();
    }

    // 2. Write 3 generations of a `Decision` (`dec_1` -> `dec_2` -> `dec_3`):
    //    `dec_3` is active, `dec_2` is 1-hop predecessor (kept by default compaction), `dec_1` is 2-hop (purged!)
    let id_v1 = db
        .put(WriteRequest::new(NodeKind::Decision, b"v1_obsolete".to_vec()).with_key("arch_dec"))
        .unwrap();
    let id_v2 = db
        .put(WriteRequest::new(NodeKind::Decision, b"v2_prev".to_vec()).with_key("arch_dec"))
        .unwrap();
    let id_v3 = db
        .put(WriteRequest::new(NodeKind::Decision, b"v3_live".to_vec()).with_key("arch_dec"))
        .unwrap();

    let rep1 = db.compact_with_gravity().unwrap();
    assert_eq!(rep1.hot_nodes_packed, 2); // active `sys::index_snapshot` + active `dec_3`
    assert_eq!(rep1.cold_nodes_archived, 1); // ONLY 1-hop `dec_2` kept; all 4 old `sys::index_snapshot` + `dec_1` purged!
    assert!(db.get(id_v3).is_ok());
    assert!(db.get(id_v2).is_ok());
    assert!(db.get(id_v1).is_err());

    // 3. Full `--prune` (`compact_with_options(true)`) purges 100% of cold nodes:
    let rep2 = db.compact_with_options(true).unwrap();
    assert_eq!(rep2.hot_nodes_packed, 2);
    assert_eq!(rep2.cold_nodes_archived, 0);
    assert!(db.get(id_v2).is_err());
    db.verify_integrity().unwrap();
}
