# LibreDB

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(10k%20crash%20sims)-brightgreen.svg)](crates/libredb-core/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.99%2B%20%7C%20LIBREDB1-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a local-first, zero-configuration, single-file cognitive database engine (`*.ldb`) written in Rust for long-term `LLM` memory. It combines `SQLite`'s single-file portability, `PostgreSQL`'s concurrent `MVCC` and strict typing discipline, logistics chaos-warehouse write lanes, and `ext4`-inspired fixed `128-byte` `Inodes` with `64 KB` Gravity locality groups.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

Conventional relational and vector databases force `LLM` memory systems to choose between single-writer bottlenecks (`SQLite_BUSY`), fragile multi-file network sidecars (`.db-wal` / `.db-shm`), or heavyweight server clusters lacking temporal truth and token awareness. `LibreDB` resolves these trade-offs directly inside a single self-healing binary file (`LIBREDB1`).

| Dimension | Traditional `SQLite` (`WAL` + `FTS5`) | `LibreDB` (`LIBREDB1` kernel) |
| :--- | :--- | :--- |
| **File footprint & `SMB` safety** | `3` files (`.db`, `.db-wal`, `.db-shm`); `.shm` breaks on `SMB` | **Single `.ldb` file** with ping-pong `CRC32C` superblocks |
| **Concurrent subagent writes** | Single global writer lock (`SQLITE_BUSY` retry loops) | **`16` sharded chaos preparation lanes** + lock-free `MVCC` reads |
| **Graph & impact traversal** | Multi-table `B-Tree` index joins across `19` isolated tables | **`O(1)` in-memory `128-byte` `Inode` array** with typed synapses |
| **Connected family read I/O** | Scattered `4 KB` page reads across separate table trees | **`64 KB` Gravity block groups** coalescing families into `1` read |
| **Temporal truth & `LLM` budget** | Manual history tables & heuristic `len / 4` token guesses | **Automatic `Supersedes` chains** + exact token-budgeted `recall` |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.85+` (`x86_64-pc-windows-msvc` or POSIX target)

### Build and verify

```powershell
cargo build --release
cargo test --release
```

### Quickstart example

```powershell
# 1. Initialize a single-file cognitive database
.\target\release\libredb.exe init memory.ldb

# 2. Store typed, keyed knowledge with automatic temporal superseding
.\target\release\libredb.exe put memory.ldb decision "Use ping-pong superblocks for SMB safety" --key smb-safety --pin
.\target\release\libredb.exe put memory.ldb symbol "fn recover_existing(backend: &dyn StorageBackend)" --key recover_existing

# 3. Wire a cognitive synapse (`Decision #1 --[governs]--> Symbol #2`)
.\target\release\libredb.exe link memory.ldb 1 governs 2 --weight 240

# 4. Recall connected context strictly within an LLM token budget
.\target\release\libredb.exe recall memory.ldb 1 --hops 2 --budget 400

# 5. Run "sleep phase" Gravity co-location and cryptographic scrub
.\target\release\libredb.exe compact memory.ldb
.\target\release\libredb.exe verify memory.ldb
```

## Usage and commands

| Command | Description |
| :--- | :--- |
| `libredb init <db.ldb>` | Initializes a fresh `LIBREDB1` database with dual `4 KB` superblocks |
| `libredb put <db.ldb> <kind> <payload> [--key <k>] [--pin]` | Writes an inline or `LZ4`-compressed capsule (`Supersedes` prior key automatically) |
| `libredb get <db.ldb> <node_id>` | Performs a lock-free `O(1)` `Inode` snapshot read by immutable `NodeId` |
| `libredb get-key <db.ldb> <kind> <key>` | Resolves the active version of `(kind, key)` in `O(1)` |
| `libredb link <db.ldb> <src> <edge_kind> <dst> [--weight <w>]` | Attaches a typed directed synapse (`governs`, `has_section`, `calls`, etc.) |
| `libredb deprecate <db.ldb> <kind> <key>` | Tombstones a stale fact/key so it never pollutes active `LLM` context |
| `libredb trace <db.ldb> <node_id> [--depth <n>]` | Walks `Supersedes`, `CausedBy`, and `Governs` edges to explain causal history |
| `libredb recall <db.ldb> <seed_id> [--hops <n>] [--budget <t>]` | Executes spreading-activation recall within a strict token ceiling |
| `libredb compact <db.ldb>` | Runs crash-proof two-phase disjoint-window Gravity compaction (`64 KB` locality groups) |
| `libredb stats <db.ldb> [--json]` | Displays live storage, compression, token, and I/O telemetry |
| `libredb verify <db.ldb>` | Verifies `CRC32C` checksums across all superblocks, `Inodes`, and extents |
| `libredb bench [--nodes <n>] [--threads <t>]` | Benchmarks `16`-lane parallel preparation, batch commits, reads, and compaction |

## Architecture and project structure

Each `.ldb` file begins with two `4 KB` ping-pong superblocks (`Slot A` at `0..4096`, `Slot B` at `4096..8192`). Small capsules (`<= 43 bytes` with `<= 4` synapses) reside directly inside their `128-byte` `Inode` (`0` payload seeks). Larger capsules are `LZ4`-compressed into contiguous extents with `CRC32C` verification. During `compact`, active connected `Inode` families are packed together into `64 KB` Gravity locality groups using a two-phase disjoint staging window (`T_stage >= max(tail, 8192 + Lc)`), guaranteeing 100% power-loss immunity without external `.wal` or `.shm` files.

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace configuration
|-- VERSION                                        # Semantic Version (0.1.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # AGPLv3 + Commons Clause license
|-- README.md                                      # 9-block standardized documentation
|-- crates/
    |-- libredb-core/                              # Core storage & cognitive kernel library
    |   |-- Cargo.toml
    |   |-- src/
    |   |   |-- lib.rs                             # Public API surface
    |   |   |-- error.rs                           # Typed error taxonomy
    |   |   |-- crc.rs                             # SIMD CRC32, deterministic hash, BPE token counter
    |   |   |-- format.rs                          # 128-byte Inode, Superblock, Synapse & frame codecs
    |   |   |-- io.rs                              # Positional OS file I/O & fault-injecting crash simulator
    |   |   |-- gravity.rs                         # 64 KB block-group BFS locality planner
    |   |   |-- engine.rs                          # 16-lane chaos writes, MVCC snapshots, recall & compaction
    |   |-- tests/
    |       |-- integration_and_crash.rs           # Concurrency, gravity & 10,000-fault power-loss suite
    |-- libredb-cli/                               # Standalone CLI & benchmark binary
        |-- Cargo.toml
        |-- src/
            |-- main.rs                            # CLI entrypoint (`libredb`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for full terms.
