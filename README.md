# LibreDB

[![Version](https://img.shields.io/badge/version-1.6.5-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(149%20tests%20%2B%2012%20audits%20%2B%2013%20learning%20checks%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-cli/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.89%2B%20%7C%20PyO3%20abi3%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a single-binary local memory database, code-graph indexer, and release automation tool built in Rust for `Antigravity` and `MCP`-compatible AI coding assistants. Instead of re-reading entire source files or losing project context across turns, it stores decisions, tasks, skills, and resolved bug patterns in a compact `.agents/memory.ldb` file, locates exact symbols and call dependencies on demand, and deduplicates session context automatically. It also encrypts repository credentials via OS keystores, seals workspace databases against tampering, checks staged commits against project guardrails, and publishes Git/Gitea releases with binary assets across Windows, Linux, and macOS.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v1.6.5` (`Rust` + `MCP` + `PyO3`) |
| :--- | :--- | :--- |
| **Hook response latency** | `350-500 ms` Python startup + `SQLite` WAL per edit or turn | **`< 2 ms` native hooks loading matching project decisions, facts, and coding rules** |
| **Multi-turn recall & I/O** | Repeated subprocess spawns and full-file re-reads | **RAM-cached session delta skipping already-shown context with zero extra disk reads** |
| **Security & credential storage** | Plaintext tokens and unverified local memory files | **OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), `HMAC-SHA256` database seals, and symlink checks** |
| **Code navigation & learning** | Blind file reads without call-graph awareness | **Symbol index across 25+ languages (`locate`, `skeleton`, `impact`, `fim`) with automatic fix learning** |
| **Diagnostics & releases** | External ad-hoc scripts for metrics and release uploads | **Built-in token-savings reports (`savings`), verification benchmarks (`bench`), and Git/Gitea release automation** |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.89+` (`cargo` + `rustc`, plus a standard C compiler `cc`/`gcc`/`clang` on Linux/macOS or MSVC on Windows for bundled `sqlite3.c` - zero external `-dev` libraries required)
- **Optional Python integration:** `Python 3.12+` (verified on `Python 3.14.5` via Stable ABI `abi3`, decoupled from default `CLI`/`MCP` builds)

### Linux and macOS (enterprise-neutral source build & plugin install)

```sh
make test
make install                  # Neutral default: 0 personal rules, no implicit legacy DB import
make install-mcp-only         # Pure MCP server mode (lifecycle hooks disabled)
make install-migrate-legacy   # Neutral install + explicit legacy customizations.db import
```

### Windows (PowerShell enterprise-neutral build & plugin install)

```powershell
cargo test --release
cargo build --release
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1                  # Neutral default
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1 -NoHooks         # Pure MCP server mode
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1 -MigrateLegacy   # Neutral + legacy SQLite import
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1 -Profile Personal # Maintainer profile
```

## Usage and commands

| Command / MCP tool | Description |
| :--- | :--- |
| `libredb_pulse` / `libredb pulse "<query>"` | Recalls relevant rules, skills, decisions, and tasks for the current workspace while suppressing duplicates already shown in the session |
| `libredb_code` / `locate`, `skeleton`, `impact`, `fim` | Searches symbol definitions, shows compact file outlines, traces affected callers, and reads surgical line ranges across 25+ languages |
| `libredb slice-skill` / `get-skill` | Finds and returns relevant sections from installed skills on demand instead of loading full manuals |
| `libredb learning [--verify]` / `savings` / `bench` | Inspects learned search bridges and error pitfalls, measures token savings across transcripts, and runs built-in audit and learning checks |
| `libredb_memorize` / `learn-reflex`, `learn-error` | Saves project facts, architectural decisions, tasks, snapshots, and verified bug-fix rules atomically |
| `libredb mcp-serve` / `guardrail check` | Starts the workspace-scoped MCP server or checks staged commits against formatting, style, and security rules |
| `libredb trust` / `libredb config` | Seals and verifies workspace memory databases (`HMAC-SHA256`) and manages global or per-project settings |
| `libredb git-init` / `git-sync` / `git-release` | Initializes repositories, pushes commits cleanly, creates Keep a Changelog releases on Gitea/GitHub, and attaches build artifacts |
| `libredb import-sqlite` / `export-sqlite` / `verify-roundtrip` | Migrates legacy `SQLite` memory stores losslessly to and from `.ldb` format and verifies data parity |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (5 default CLI/MCP crates + optional PyO3 crate)
|-- Makefile                                       # Zero-dependency POSIX/Linux/macOS source build & installer
|-- VERSION                                        # Semantic Version (1.6.5)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # Commons Clause v1.0 + full verbatim GNU AGPL v3.0 text
|-- README.md                                      # 9-block standardized documentation
|-- scripts/
|   |-- deploy_plugin.ps1                          # Windows PowerShell installer (-Profile Neutral|Personal, -NoHooks, -MigrateLegacy)
|   |-- deploy_plugin.sh                           # POSIX/Linux/macOS installer (--profile neutral|personal, --no-hooks, --migrate-legacy)
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, alphanumeric v5 tokens & Hebbian learner
    |-- libredb-cognitive/                         # OverlayBrain, Causal & Error-Recovery Learning, Situational Superseding, Guardrails & FIM
    |   |-- tests/v140_learning_real_world.rs      # 17 realistic causal learning, error-recovery, refutation & superseding tests
    |-- libredb-bridge/                            # Zero-amnesia 19-table SQLite migrator & parity verifier
    |-- libredb-cli/                               # Modular CLI, MCP Server, Telemetry/Benchmarks, DPAPI/ChaCha20-Poly1305 Vault & Gitea Suite
    |   |-- src/cli_args.rs                        # Deterministic zero-dependency CLI flag & positional parser (CliSpec)
    |   |-- src/design_skills.rs                   # Native platform UI design skills (Windows Fluent 2, Android Material 3, Apple HIG, KDE/GNOME HIG)
    |   |-- src/bench.rs                           # Native kernel, C1..C6 economy, A1..A12 audit & L1..L13 learning verification engine
    |   |-- src/telemetry.rs                       # Cross-process-atomic telemetry.ldb ledger + streaming 8 MiB transcript analyzer
    |   |-- src/mcp/                               # Modular MCP server (mod, protocol, authz, tools, tests)
    |   |-- src/security/                          # Modular security suite (mod, ephemeral, vault, seals, path_policy, tests)
    |   |-- src/hooks.rs                           # Sub-2ms subagent-aware priority BM25 + sealed reflex PreInvocation & PreToolUse hooks
    |   |-- src/gitea.rs                           # Provider-aware multi-remote Git, Gitea & GitHub release automation
    |   |-- tests/military_grade_mcp_security.rs   # Multi-process OS SIGKILL, root-refresh & boundary isolation E2E suite
    |   |-- tests/v111_feature_and_security_audit.rs # E2E MCP savings authz, batched locate/impact/fim, closed-loop causal learning & A1..A12 audit suite
    |   |-- tests/v140_learning_e2e.rs                 # E2E sealed workspace reflex drift, libredb learning --verify & L1..L13 verification suite
    |-- libredb-py/                                # Optional PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for the complete license terms.
