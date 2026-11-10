//! Gravity locality planner (`ext4` block-group style co-location + cold archive segregation).

use crate::format::{EdgeKind, Inode, NodeFlags, NodeKind, Synapse, GRAVITY_BLOCK_GROUP_BYTES};
use std::collections::{HashMap, HashSet, VecDeque};

/// Deterministic physical layout plan computed during the "sleep phase" (`compact_with_gravity`).
#[derive(Debug, Default)]
pub struct GravityPlan {
    /// Active Inodes ordered so strongly linked families sit adjacent inside `64 KB` locality zones.
    pub hot_node_ids: Vec<u64>,
    /// Superseded or cold-archived Inodes segregated to the cold tail of the file.
    pub cold_node_ids: Vec<u64>,
    /// Number of `64 KB` locality block groups formed for active extents.
    pub locality_groups: usize,
}

#[inline]
fn is_causal_history_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Rule
            | NodeKind::Skill
            | NodeKind::SkillSection
            | NodeKind::Decision
            | NodeKind::Fact
            | NodeKind::Task
            | NodeKind::TaskVerification
            | NodeKind::Handoff
            | NodeKind::Snapshot
            | NodeKind::CompactionCheckpoint
    )
}

/// Computes the optimal physical extent write order and garbage-collects dead extents.
///
/// Design:
/// 1. Retains all live active Inodes in `hot_node_ids`.
/// 2. Garbage-collects all `TOMBSTONE` nodes, all superseded ephemeral/system/cache extents
///    (`Generic`, `WorkingSet`, `Symbol`, `QuotaEvent`, `TranscriptCursor`, `SynonymCluster`),
///    and any `2+` generation obsolete nodes. When `prune_all_cold` is false, retains `1-hop`
///    `EdgeKind::Supersedes` predecessors of live active knowledge capsules in `cold_node_ids`
///    for causal time-travel. When `prune_all_cold` is true, purges 100% of cold nodes.
/// 3. Builds an undirected affinity graph across active nodes from all structural synapses
///    (`HasSection`, `Governs`, `DependsOn`, `Calls`, `Verifies`, `Delegates`, `Touches`, etc.).
/// 4. Ranks anchor seeds by `(PINNED, structural_degree, importance, access_count)` and performs
///    bounded Breadth-First Locality Packing into `64 KB` (`GRAVITY_BLOCK_GROUP_BYTES`) windows.
pub fn compute_gravity_plan(
    inodes: &HashMap<u64, Inode>,
    all_synapses: &HashMap<u64, Vec<Synapse>>,
    prune_all_cold: bool,
) -> GravityPlan {
    let mut active_ids: Vec<u64> = Vec::new();
    let mut cold_ids: Vec<u64> = Vec::new();

    for (&id, inode) in inodes {
        if inode.flags.is_live_active() {
            active_ids.push(id);
        }
    }

    if !prune_all_cold {
        let mut protected_cold: HashSet<u64> = HashSet::new();
        for &src_id in &active_ids {
            if let Some(syns) = all_synapses.get(&src_id) {
                for syn in syns {
                    if syn.kind == EdgeKind::Supersedes {
                        if let Some(target_ino) = inodes.get(&syn.target_id) {
                            if !target_ino.flags.contains(NodeFlags::TOMBSTONE)
                                && !target_ino.flags.is_live_active()
                                && is_causal_history_kind(target_ino.kind)
                            {
                                protected_cold.insert(syn.target_id);
                            }
                        }
                    }
                }
            }
        }
        cold_ids.extend(protected_cold);
    }

    // Sort cold nodes deterministically by NodeId for reproducible binary output.
    cold_ids.sort_unstable();

    if active_ids.is_empty() {
        return GravityPlan {
            hot_node_ids: Vec::new(),
            cold_node_ids: cold_ids,
            locality_groups: 0,
        };
    }

    let active_set: HashSet<u64> = active_ids.iter().copied().collect();
    let mut adjacency: HashMap<u64, Vec<(u64, u8)>> = HashMap::with_capacity(active_ids.len());

    for &src_id in &active_ids {
        if let Some(syns) = all_synapses.get(&src_id) {
            for syn in syns {
                if syn.kind.has_gravity_pull() && active_set.contains(&syn.target_id) {
                    adjacency
                        .entry(src_id)
                        .or_default()
                        .push((syn.target_id, syn.weight));
                    adjacency
                        .entry(syn.target_id)
                        .or_default()
                        .push((src_id, syn.weight));
                }
            }
        }
    }

    // Sort each node's neighbor list by descending synapse weight, then ascending NodeId.
    for neighbors in adjacency.values_mut() {
        neighbors.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        neighbors.dedup_by_key(|x| x.0);
    }

    // Rank anchor candidates by cognitive gravity mass.
    active_ids.sort_unstable_by(|&a, &b| {
        let ia = &inodes[&a];
        let ib = &inodes[&b];
        let pin_a = ia.flags.contains(NodeFlags::PINNED);
        let pin_b = ib.flags.contains(NodeFlags::PINNED);
        let deg_a = adjacency.get(&a).map_or(0usize, Vec::len);
        let deg_b = adjacency.get(&b).map_or(0usize, Vec::len);

        pin_b
            .cmp(&pin_a)
            .then_with(|| deg_b.cmp(&deg_a))
            .then_with(|| ib.importance.cmp(&ia.importance))
            .then_with(|| ib.access_count.cmp(&ia.access_count))
            .then_with(|| a.cmp(&b))
    });

    let mut visited: HashSet<u64> = HashSet::with_capacity(active_ids.len());
    let mut hot_order: Vec<u64> = Vec::with_capacity(active_ids.len());
    let mut current_group_bytes: usize = 0;
    let mut locality_groups: usize = 1;
    let mut queue: VecDeque<u64> = VecDeque::new();

    for seed in active_ids {
        if visited.contains(&seed) {
            continue;
        }
        visited.insert(seed);
        queue.push_back(seed);

        while let Some(curr) = queue.pop_front() {
            let est_bytes = match inodes[&curr].storage {
                crate::format::InodeStorage::Inline { .. } => 0,
                crate::format::InodeStorage::Extent { stored_len, .. } => stored_len as usize,
            };

            if current_group_bytes > 0
                && current_group_bytes.saturating_add(est_bytes) > GRAVITY_BLOCK_GROUP_BYTES
            {
                locality_groups += 1;
                current_group_bytes = 0;
            }
            current_group_bytes = current_group_bytes.saturating_add(est_bytes);
            hot_order.push(curr);

            if let Some(neighbors) = adjacency.get(&curr) {
                for &(nb, _w) in neighbors {
                    if !visited.contains(&nb) {
                        visited.insert(nb);
                        queue.push_back(nb);
                    }
                }
            }
        }
    }

    GravityPlan {
        hot_node_ids: hot_order,
        cold_node_ids: cold_ids,
        locality_groups,
    }
}
