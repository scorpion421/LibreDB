# LibreDB

[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(17%20suites%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-bridge/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.99%2B%20%7C%20PyO3%20abi3%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a local-first, zero-configuration, single-file cognitive database and multi-workspace `MCP` memory engine (`*.ldb`) built in Rust specifically for `Antigravity` and `LLMs`. It unifies dual-layer global/project overlay memory, zero-I/O RAM-first `Zero-Repeat Delta` context deduplication, language-agnostic Hebbian concept learning, causal code-graph impact & surgical `FIM` slicing, in-process `PyO3` Python bindings, and a 100% lossless bidirectional `SQLite` bridge.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v0.4.0` (`Rust` + `PyO3` + `MCP`) |
| :--- | :--- | :--- |
| **Invocation & Turn 2+ latency** | `300-1500 ms` shell/Python startup + SQLite queries | **`< 0.5 ms` warm `MCP` / `PyO3` (`0` disk I/O on deduplicated turns)** |
| **Multi-turn context bloat** | Re-emits identical rules, skills & facts on repeated calls | **RAM-first `Zero-Repeat Delta` + hands-free `cid` `/compact` sync** |
| **MCP tool schema overhead** | Verbose multi-tool prompt schemas (`> 1,100` tokens/turn) | **Consolidated 3-tool `MCP` schema (`libredb_pulse`, `libredb_code`, `libredb_memorize`, `-78%` tokens)** |
| **Source inspection & edits** | Full `read_file` scans + separate `symbol_index` / `decisions` | **Unified `fim` & `impact`** joining `[Lstart-Lend]` code, callers & governing decisions |
| **Language & concept recall** | Hardcoded stopword & bilingual synonym dictionaries | **100% language-agnostic `IDF` Unicode `n-grams` + persistent Hebbian learning** |
| **Migration & rollback safety** | Tied to `19` relational + `5` `FTS5` tables | **`223 ms` lossless cell-by-cell `SQLite <-> LibreDB` round-trip bijection** |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.85+` (`x86_64-pc-windows-msvc` or POSIX target)
- **Optional Python integration:** `Python 3.12+` (verified on `Python 3.14.5` via Stable ABI `abi3`)

### Build, verify, and deploy standalone Antigravity plugin

```powershell
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY = "1"
cargo test --release --workspace --exclude libredb-py
cargo build --release --workspace
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1
```

## Usage and commands

| Command / MCP tool | Description |
| :--- | :--- |
| `libredb_pulse` (`MCP`) / `libredb pulse` | Dual-layer associative recall with hands-free `/compact` sync & zero-I/O `Zero-Repeat Delta` |
| `libredb_code` (`MCP`) / `skeleton`, `impact`, `fim`, `index-workspace` | Binary-safe code graph joining `[Lstart-Lend]` slices, callers, and governing `Decisions` |
| `libredb_memorize` (`MCP`) / `batch`, `learn-assoc`, `learn-reflex` | Atomic multi-capsule commits, language-agnostic Hebbian learning, and pitfall reflexes |
| `libredb mcp-serve [--global <customizations.ldb>]` | Multi-workspace `JSON-RPC 2.0` `MCP` server resolving `<cwd>/.agents/memory.ldb` dynamically |
| `import libredb` (`PyO3` `libredb.Brain`) | Native in-process Python `abi3` extension exposing all cognitive & bridge methods |
| `libredb import-sqlite` / `export-sqlite` / `verify-roundtrip` | Lossless `19`-table + `5`-`FTS5` `SQLite <-> LibreDB` migration and parity verification |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (6 modular crates)
|-- VERSION                                        # Semantic Version (0.4.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # AGPLv3 + Commons Clause license
|-- README.md                                      # 9-block standardized documentation
|-- scripts/
|   |-- deploy_plugin.ps1                          # Zero-touch standalone Antigravity plugin installer
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, Hebbian learner & persistent index snapshot
    |-- libredb-cognitive/                         # OverlayBrain, Session Delta, Reflexes, WorkspaceGraph, FIM & Transcript Epoch
    |-- libredb-bridge/                            # Lossless 19-table SQLite <-> LibreDB migrator & parity verifier
    |-- libredb-cli/                               # Standalone CLI & multi-workspace JSON-RPC 2.0 MCP stdio server
    |-- libredb-py/                                # Native PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for full terms.
