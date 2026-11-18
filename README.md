# LibreDB

[![Version](https://img.shields.io/badge/version-2.4.4-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(168%20tests%20%2B%2012%20audits%20%2B%2015%20learning%20checks%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-cli/tests/)
[![Tech Stack](https://img.shields.io/badge/pure%20rust-1.89%2B%20%7C%20zero%20C%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is a 100% pure-Rust, single-binary local memory database, code-graph indexer, and release automation tool built for `Antigravity` and `MCP`-compatible AI coding assistants. Instead of re-reading entire source files or losing project context across turns, it stores decisions, tasks, skills, and resolved bug patterns in a compact `.agents/memory.ldb` file, routes sub-millisecond lifecycle hooks through an in-memory `MCP` `IPC` coordinator with incremental `O(1)` tail-sync, locates exact symbols and call dependencies on demand, and deduplicates session context automatically. It also encrypts repository credentials via OS keystores, seals workspace databases against tampering, checks staged commits against project guardrails, and optionally publishes Git/Gitea releases (`git-automation` feature) across Windows, Linux, and macOS.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v2.4.4` (100% Pure `Rust` + `MCP` + `PyO3`) |
| :--- | :--- | :--- |
| **Hook response latency** | `350-500 ms` Python startup + `SQLite` WAL per edit or turn | **`< 0.5 ms` via the in-memory `MCP` `IPC` coordinator (`< 2 ms` direct fallback), loading matching rules and project memory without disk polling** |
| **Multi-turn recall & I/O** | Repeated subprocess spawns and full-file re-reads | **RAM-cached session delta and `O(1)` incremental tail-sync (`2` reads total on external updates), keeping turn 2+ recall instant even over network shares** |
| **Security & credential storage** | Plaintext tokens and unverified local memory files | **OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), monotonic `HMAC-SHA256` database seals, and symlink/junction path containment** |
| **Code navigation & learning** | Blind file reads without call-graph awareness | **Symbol index across 25+ languages (`locate`, `skeleton`, `impact`, file-less `fim --symbol`, symbol-annotated `grep`) with self-correcting fix learning and outcome verification** |
| **Diagnostics & releases** | External ad-hoc scripts for metrics and release uploads | **Built-in token-savings reports (`savings`), verification benchmarks (`bench`, `L1..L15` learning suite), and Git/Gitea release automation** |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.89+` (`cargo` + `rustc`, 100% pure Rust with zero C code, zero C compiler, and zero external `-dev` libraries required)
- **Optional Python integration:** `Python 3.12+` (verified on `Python 3.14.5` via Stable ABI `abi3`, decoupled from default `CLI`/`MCP` builds)

### Linux and macOS (enterprise-neutral source build & plugin install)

```sh
make test
make install                  # Neutral default: 0 personal rules installed
make install-mcp-only         # Pure MCP server mode (lifecycle hooks disabled)
make install-personal         # Maintainer profile (external skills + rules)
```

### Windows (PowerShell enterprise-neutral build & plugin install)

```powershell
cargo test --release
cargo build --release
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1                  # Neutral default
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1 -NoHooks         # Pure MCP server mode
pwsh -ExecutionPolicy Bypass -File .\scripts\deploy_plugin.ps1 -Profile Personal # Maintainer profile
```

## Usage and commands

| Command / MCP tool | Description |
| :--- | :--- |
| `libredb_pulse` / `libredb pulse "<query>"` | Recalls relevant rules, skills, decisions, and tasks for the current workspace while suppressing duplicates already shown in the session |
| `libredb_code` / `locate`, `skeleton`, `impact`, `fim`, `grep` | Searches symbols and patterns with enclosing contracts, shows compact file outlines, traces callers, and reads surgical symbol or `<file>:<line>` ranges |
| `libredb slice-skill` / `get-skill` / `sync-skill` | Syncs external `SKILL.md` guides and retrieves relevant sections on demand instead of loading full manuals |
| `libredb learning [--verify]` / `savings` / `bench` | Inspects learned search bridges and error pitfalls, runs `L1..L15` learning verification, measures transcript token savings, and runs built-in benchmarks |
| `libredb_memorize` / `learn-reflex`, `learn-error` | Saves project facts, architectural decisions, tasks, snapshots, and verified bug-fix rules atomically |
| `libredb mcp-serve` / `guardrail check` | Starts the workspace-scoped MCP server with in-memory hook IPC coordinator or checks staged commits against formatting, style, and security rules |
| `libredb trust` / `libredb config` / `status` | Seals and verifies workspace memory databases (`HMAC-SHA256`), manages global or per-project settings, and inspects database statistics |
| `libredb backup` / `restore` / `migrate` / `read` | Exports portable unencrypted backups (`--instance`, `--all`, `--cid`), restores with local re-encryption and automatic project-start adoption, migrates standalone chats or moved folders, and inspects `.ldb` files read-only |
| `libredb install` / `libredb update` | Deploys the complete plugin from any standalone release binary without source checkout or `cargo` (preserving custom AppLocker paths and profiles) and updates directly from GitHub Releases |
| `libredb git-init` / `git-sync` / `git-release` | Optional `git-automation` feature (enabled by default): pushes commits cleanly with multi-remote preflight checks, creates Keep a Changelog releases on Gitea/GitHub, and attaches matching binary assets |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Pure-Rust workspace (4 default CLI/MCP crates + optional PyO3 crate)
|-- Makefile                                       # Zero-dependency POSIX/Linux/macOS source build & installer
|-- VERSION                                        # Semantic Version (2.4.4)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # Commons Clause v1.0 + full verbatim Apache License 2.0 text
|-- README.md                                      # 9-block standardized documentation
|-- skills/                                        # External data-driven platform design guides synced via --skills-dir
|   |-- windows-app-design/SKILL.md                # Windows Fluent 2 and best-practices UI standard
|   |-- android-app-design/SKILL.md                # Android Material 3 and mobile UI standard
|   |-- apple-hig-design/SKILL.md                  # Apple iOS, iPadOS, and macOS Human Interface Guidelines
|   |-- linux-desktop-hig-design/SKILL.md          # GNOME Libadwaita and KDE Kirigami desktop HIG standard
|-- scripts/
|   |-- deploy_plugin.ps1                          # Windows PowerShell installer (-Profile Neutral|Personal, -NoHooks)
|   |-- deploy_plugin.sh                           # POSIX/Linux/macOS installer (--profile neutral|personal, --no-hooks)
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC, Tail-Sync)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, alphanumeric v5 tokens & Hebbian learner
    |-- libredb-cognitive/                         # OverlayBrain, Causal & Error-Recovery Learning, Situational Superseding, Guardrails & FIM
    |   |-- tests/cognitive_core_workflows.rs      # End-to-end session delta, multilingual Hebbian, and skeleton compression tests
    |   |-- tests/overlay_workspace_and_epoch.rs   # Dual-layer OverlayBrain, call-graph, and /compact epoch detection tests
    |   |-- tests/v140_learning_real_world.rs      # Realistic causal learning, error-recovery, refutation & superseding tests
    |-- libredb-cli/                               # Modular CLI, MCP Server, Telemetry/Benchmarks, DPAPI/ChaCha20-Poly1305 Vault & optional Gitea Suite
    |   |-- src/cli_args.rs                        # Deterministic zero-dependency CLI flag & positional parser (CliSpec)
    |   |-- src/installer.rs                       # Standalone pure-Rust plugin installer & GitHub Release self-updater (install, update)
    |   |-- src/bench.rs                           # Native kernel, C1..C6 economy, A1..A12 audit & L1..L15 learning verification engine
    |   |-- src/telemetry.rs                       # Cross-process-atomic telemetry.ldb ledger + streaming 8 MiB transcript analyzer
    |   |-- src/ipc.rs                             # Cross-platform in-memory MCP-to-hook IPC coordinator (Named Pipe / Unix Socket)
    |   |-- src/mcp/                               # Modular MCP server (mod, protocol, authz, tools, tests)
    |   |-- src/security/                          # Modular security suite (mod, ephemeral, vault, seals, path_policy, backup, tests)
    |   |-- src/hooks.rs                           # Sub-millisecond IPC-routed & direct-fallback PreInvocation & PreToolUse hooks
    |   |-- src/gitea.rs                           # Optional git-automation feature: Git, Gitea & GitHub release automation
    |   |-- tests/military_grade_mcp_security.rs   # Multi-process OS SIGKILL, root-refresh & boundary isolation E2E suite
    |   |-- tests/v111_feature_and_security_audit.rs # E2E MCP savings authz, batched locate/impact/fim, closed-loop causal learning & A1..A12 audit suite
    |   |-- tests/v140_learning_e2e.rs             # E2E sealed workspace reflex drift, libredb learning --verify & L1..L15 verification suite
    |-- libredb-py/                                # Optional PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **Apache License, Version 2.0 (Apache-2.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for the complete license terms.
