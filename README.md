# LibreDB

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(10k%20crash%20%2B%2019--table%20bijection)-brightgreen.svg)](crates/libredb-bridge/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.99%2B%20%7C%20LIBREDB1-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a local-first, zero-configuration, single-file cognitive memory and token-conservation engine (`*.ldb`) written in Rust for `LLMs`. It pairs a crash-proof single-file `Inode`-extent kernel with session-aware `Zero-Repeat Delta` deduplication, hash-cached code contract skeletons, data-learned situational `Reflex` triggers, language-agnostic Hebbian concept learning, and a 100% lossless bidirectional `SQLite` bridge.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

Traditional `LLM` memory layers waste tens of thousands of prompt tokens per session by re-emitting identical context across turns, reading entire multi-thousand-line code files to inspect signatures, relying on hardcoded mono/bilingual synonym lists, and failing to surface situational tooling pitfalls before execution. `LibreDB v0.2.0` addresses every one of those token drains directly inside a single self-contained `.ldb` file.

| Capability | Legacy `SQLite` + `FTS5` workflow | `LibreDB v0.2.0` cognitive engine |
| :--- | :--- | :--- |
| **Multi-turn context repetition** | Re-emits identical rules/skills/facts on repeated queries | **`Zero-Repeat Delta` (`SessionState`)** suppresses seen generations (`>80%` saved) |
| **Large source file inspection** | Full/sliced `read_file` (`10,000-30,000` tokens) | **`FileSkeleton` (`64-bit` hash cache)** delivers `[Lstart-Lend]` contracts (`-95%+` tokens) |
| **Multilingual & domain recall** | Hardcoded stopword & synonym tables | **Zero hardcoded languages:** `IDF` Unicode `n-grams` + persistent **Hebbian learning** |
| **Operational mistake prevention** | Passive lookup only after hitting an error | **Data-learned `ReflexEngine`** fires `20-token` warnings proactively on context match |
| **Migration & rollback safety** | Locked into `19` relational + `5` `FTS5` tables | **Lossless `SQLite <-> LibreDB` bijection** verified cell-for-cell |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.85+` (`x86_64-pc-windows-msvc` or POSIX target)

### Build and test

```powershell
cargo test --release
cargo build --release
```

### Quickstart example

```powershell
# 1. Verify 100% lossless round-trip on a read-only copy of an existing SQLite DB
.\target\release\libredb.exe verify-roundtrip ~/.gemini/database/customizations.db --scope central

# 2. Import SQLite knowledge (read-only) into a single cognitive .ldb file
.\target\release\libredb.exe import-sqlite brain.ldb ~/.gemini/database/customizations.db --scope central

# 3. Extract a 95%+ compressed, hash-cached code contract skeleton
.\target\release\libredb.exe skeleton brain.ldb crates/libredb-core/src/engine.rs

# 4. Run a session-deduplicated, token-budgeted cognitive pulse (Turn 1 vs Turn 2 delta!)
.\target\release\libredb.exe pulse brain.ldb "gitea release" --cid session-42 --epoch 1 --budget 600
.\target\release\libredb.exe pulse brain.ldb "gitea release" --cid session-42 --epoch 1 --budget 600
```

## Usage and commands

| Command | Description |
| :--- | :--- |
| `libredb pulse <db.ldb> <query> [--cid <id>] [--epoch <n>] [--budget <t>]` | One-shot recall with `Reflex` triggers, spreading activation, and `Zero-Repeat Delta` |
| `libredb skeleton <db.ldb> <source_file> [--filter <s>]` | Extracts/caches compressed `[Lstart-Lend]` symbol contracts and section spans |
| `libredb learn-assoc <db.ldb> <cue_phrase> <id1,id2>` | Teaches a language-agnostic Hebbian concept bridge from any script/phrasing to target nodes |
| `libredb learn-reflex <db.ldb> <id> <directive> [--stack <s>] [--action <a>]` | Persists a data-driven situational pitfall warning triggered by workspace/action context |
| `libredb import-sqlite <db.ldb> <source.db> [--scope central\|project]` | Imports all `SkillsDB` SQLite tables read-only into cognitive capsules + lossless mirror |
| `libredb export-sqlite <db.ldb> <out.db> [--scope central\|project]` | Reconstructs an exact SQLite database including indexes and rebuilt `FTS5` virtual tables |
| `libredb verify-roundtrip <source.db> [--scope central\|project]` | Proves `100%` cell-by-cell `SQLite -> LibreDB -> SQLite` equivalence in `%TEMP%` |
| `libredb put / get / get-key / link / deprecate / trace / recall` | Direct `O(1)` `Inode`, temporal `Supersedes`, and synapse graph operations |
| `libredb compact / stats / verify / bench` | Crash-safe `64 KB` Gravity compaction, `CRC32` scrub, and `16`-thread benchmark |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (5 modular crates)
|-- VERSION                                        # Semantic Version (0.2.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # AGPLv3 + Commons Clause license
|-- README.md                                      # 9-block standardized documentation
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic BM25, Unicode n-grams & Hebbian concept learner
    |-- libredb-cognitive/                         # Session Zero-Repeat Delta, ReflexEngine, FileSkeleton & Pulse
    |-- libredb-bridge/                            # Lossless 19-table SQLite <-> LibreDB migrator & parity verifier
    |-- libredb-cli/                               # Standalone CLI & benchmark runner (`libredb`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for full terms.
