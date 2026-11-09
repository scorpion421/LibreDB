# LibreDB

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(17%20suites%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-bridge/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.99%2B%20%7C%20PyO3%20abi3%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a local-first, zero-configuration, single-file cognitive database and workspace memory engine (`*.ldb`) built in Rust specifically for `Antigravity` and `LLMs`. It unifies dual-layer global/project overlay memory, session-aware `Zero-Repeat Delta` token conservation, language-agnostic Hebbian concept learning, causal code-graph impact & surgical `FIM` slicing, native `MCP` stdio serving, in-process `PyO3` Python bindings, and a 100% lossless bidirectional `SQLite` bridge.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v0.3.0` (`Rust` + `PyO3` + `MCP`) |
| :--- | :--- | :--- |
| **Invocation & index startup** | `300-1500 ms` shell/Python startup + SQLite queries | **`< 0.5 ms` via `mcp-serve` / `PyO3`** (`< 15 ms` cold CLI via `sys::index_snapshot`) |
| **Multi-turn context bloat** | Re-emits identical rules, skills & facts on repeated calls | **`Zero-Repeat Delta` + auto `transcript.jsonl` `/compact` epoch sync** |
| **Source inspection & edits** | Full `read_file` scans + separate `symbol_index` / `decisions` | **Unified `fim` & `impact`** joining `[Lstart-Lend]` code, callers & governing decisions |
| **Language & concept recall** | Hardcoded stopword & bilingual synonym dictionaries | **100% language-agnostic `IDF` Unicode `n-grams` + persistent Hebbian learning** |
| **Global + project memory** | Disconnected `customizations.db` and `.agents/memory.db` files | **`OverlayBrain`** federating global and project `.ldb` layers in one call |
| **Migration & rollback safety** | Tied to `19` relational + `5` `FTS5` tables | **`223 ms` lossless cell-by-cell `SQLite <-> LibreDB` round-trip bijection** |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.85+` (`x86_64-pc-windows-msvc` or POSIX target)
- **Optional Python integration:** `Python 3.12+` (tested on `Python 3.14.5` via Stable ABI `abi3`)

### Build and verify

```powershell
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY = "1"
cargo test --release
cargo build --release
```

### Quickstart example

```powershell
# 1. Import global SQLite customizations into a pre-indexed global .ldb layer
.\target\release\libredb.exe import-sqlite global.ldb ~/.gemini/database/customizations.db --scope central

# 2. Index a code workspace and commit an architectural decision (auto-wires Governs -> Symbols!)
.\target\release\libredb.exe batch project.ldb --decision "Superblock Safety::recover_existing verifies CRC32 on both slots"
.\target\release\libredb.exe index-workspace project.ldb .

# 3. Inspect surgical FIM edit slice + blast-radius callers + governing decisions in one call
.\target\release\libredb.exe fim project.ldb crates/libredb-core/src/engine.rs --symbol recover_existing

# 4. Run dual-layer OverlayBrain pulse (or launch persistent zero-latency MCP stdio server)
.\target\release\libredb.exe pulse project.ldb "gitea release" --global global.ldb --cid conv-1 --budget 600
.\target\release\libredb.exe mcp-serve project.ldb --global global.ldb
```

## Usage and commands

| Command / interface | Description |
| :--- | :--- |
| `libredb pulse <proj.ldb> <q> [--global <g.ldb>] [--cid <c>] [--transcript <t>]` | Dual-layer associative recall with auto `/compact` epoch detection & `Zero-Repeat Delta` |
| `libredb index-workspace <db.ldb> <dir> [--force]` | Binary-safe incremental workspace scanner wiring `Calls` and `Decision -> Symbol` synapses |
| `libredb impact <db.ldb> <symbol>` | Returns symbol signature, blast-radius callers, callees, and governing `Decisions` |
| `libredb fim <db.ldb> <file> [--symbol <s> \| --line <n>]` | Extracts minimal edit window enriched with blast-radius callers and governing invariants |
| `libredb skeleton <db.ldb> <file> [--filter <s>]` | Extracts/serves `64-bit` hash-cached `[Lstart-Lend]` symbol contracts (`-92%+` tokens) |
| `libredb batch <db.ldb> [--fact k=v] [--decision T::B] [--task k::t::s::p]` | Single-`fsync` atomic episodic commit with automatic `Decision -> Symbol` wiring |
| `libredb handoff <db.ldb> <id> <task_key> <role> [--notes <n>]` | Generates deterministic, zero-bloat subagent delegation blocks |
| `libredb learn-assoc` / `libredb learn-reflex` | Persists language-agnostic Hebbian concept bridges and situational pitfall reflexes |
| `libredb mcp-serve <proj.ldb> [--global <g.ldb>]` | Runs a persistent `JSON-RPC 2.0` `MCP` server over `stdio` (`< 0.5 ms` per tool call) |
| `import libredb` (`PyO3` `libredb.Brain`) | Native in-process Python `abi3` extension exposing all cognitive & bridge methods |
| `libredb import-sqlite` / `export-sqlite` / `verify-roundtrip` | Lossless `19`-table + `5`-`FTS5` `SQLite <-> LibreDB` migration and parity verification |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (6 modular crates)
|-- VERSION                                        # Semantic Version (0.3.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # AGPLv3 + Commons Clause license
|-- README.md                                      # 9-block standardized documentation
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, Hebbian learner & persistent index snapshot
    |-- libredb-cognitive/                         # OverlayBrain, Session Delta, Reflexes, WorkspaceGraph, FIM & Transcript Epoch
    |-- libredb-bridge/                            # Lossless 19-table SQLite <-> LibreDB migrator & parity verifier
    |-- libredb-cli/                               # Standalone CLI & native JSON-RPC 2.0 MCP stdio server
    |-- libredb-py/                                # Native PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for full terms.
