# LibreDB

[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(107%20tests%20%2B%2011%20audits%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-cli/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.89%2B%20%7C%20PyO3%20abi3%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is an enterprise-ready, local-first, zero-configuration, single-file cognitive database, token-economy analytics & benchmark suite, lifecycle hook engine, dynamic multi-remote Git/Gitea automation suite, and multi-workspace `MCP` memory substrate (`*.ldb`) built in Rust for `Antigravity` and `MCP`-compatible `LLM` clients. It replaces `SQLite` + Python memory overhead with zero-I/O RAM-first `Zero-Repeat Delta` deduplication, cross-process-serialized revision-and-metadata-bound `HMAC-SHA256` workspace trust seals (`libredb trust`, `hmac-sha256:v4:r<rev>:` with crash-consistent CAS anti-rollback and anti-deletion ratchets), standards-compliant OS/AEAD secret protection (Windows `DPAPI` / RFC 8439 `ChaCha20-Poly1305`), `< 2 ms` compiled `PreInvocation` (subagent-aware priority-budgeted `BM25` `<= 450`-token hydration) and `PreToolUse` (tentative-verified ACID symbol-span shifting + closed-loop `Search-Miss -> Verified-Edit` bridging) hooks, `< 5 us` local topology-inferred 25+ language exact Dalvik/DI code-graph (`locate`, batched `fim`, batched `impact` with Git co-change `Lift` mining, `skeleton`), falsifiable grounded reflexes, ACT-R hub fan damping, native 3-tier `libredb savings` & `libredb bench` (`--suite kernel|full|audit`) verification, and strictly neutral default installation across Windows, Linux, and macOS.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v1.3.0` (Pure `Rust` + `MCP` + `PyO3`) |
| :--- | :--- | :--- |
| **Lifecycle hook latency** | `350-500 ms` Python startup + `SQLite` WAL per edit/turn | **`< 2 ms` in-engine (subagent-aware priority `BM25` `<= 450`-tok `PreInvocation` + tentative ACID `PreToolUse` shift & miss-bridge)** |
| **Turn 2+ recall & I/O** | `300-1500 ms` subprocess + repeated full text output | **`0` disk I/O reads (`< 3 ms` warm `MCP` / `locate` / `fim` / `impact`) via RAM-first `Zero-Repeat Delta` & stat+hash cache** |
| **Cryptography & trust** | Plaintext DB tokens & unverified `.agents/memory.db` loads | **Windows `DPAPI` + RFC 8439 `ChaCha20-Poly1305` `AEAD` + monotonic `HMAC-SHA256` (`v4:r<rev>`)** |
| **Symlink-safe path policy** | Lexical-only path checks vulnerable to symlink aliases | **Canonicalized symlink/junction, NTFS ADS (`:stream`) & `..` containment across `MCP`, `CLI` & hooks** |
| **Topology & DI code graph** | Full `read_file` scans + blind to Dalvik/R8 & interfaces | **`< 5 us` structural topology + exact Dalvik/R8 + Git co-change `Lift` + closed-loop miss->edit bridges + batched `locate`/`fim`/`impact`** |
| **Built-in economy & audit** | External ad-hoc Python scripts required to measure savings | **Native 3-tier `libredb savings` (`report`) & `libredb bench --suite kernel\|full\|audit` (`C1..C6` + `A1..A11`, `--json`)** |

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
| `libredb_pulse` (`MCP`) / `libredb pulse [<db.ldb>] <query>` | Zero-boilerplate dual-layer associative recall with hands-free `/compact` sync & zero-I/O `Zero-Repeat Delta` |
| `libredb_code` (`MCP`) / `locate`, `skeleton`, `impact`, `fim`, `index-workspace` | Topology + Dalvik/R8 + `DI` + Git co-change `Lift` code graph supporting `< 0.5 ms` `locate`, closed-loop `Search-Miss -> Verified-Edit` bridging, batched `impact` (`symbols`) & `fim` (`slices`), `[Lstart-Lend]` slices, and `savings` |
| `libredb slice-skill <query>` / `get-skill [--section \| --query]` | Direct `BM25` + `HybridIndex` progressive-disclosure skill-section search across `customizations.ldb` |
| `libredb savings` (`report`) / `libredb bench` | Built-in 3-tier token-consumption & savings analytics (`--today`, `--days`, `--cid`, `--project`, `--json`) and `C1..C6` / `A1..A11` benchmark & security verification suite (`--suite kernel\|full\|audit`, `--workspace`) |
| `libredb_memorize` (`MCP`) / `batch`, `learn-assoc`, `learn-reflex [--anchor]` | Atomic multi-capsule commits, tasks, language-agnostic Hebbian learning, and grounded falsifiable reflexes |
| `libredb mcp-serve` / `hook-pre-invocation` / `hook-pre-tool` / `guardrail check` | Multi-workspace or `--workspace-root`-pinned `MCP` server, sub-2ms lifecycle hooks, symlink-resolved path protection & guardrail scanner |
| `libredb trust` / `libredb config` | Monotonic `HMAC-SHA256` (`v4:r<rev>`) workspace trust seals (`--accept-rollback`, `--reinit-lost`, `--migrate-v3`, `--migrate-v2`) & dynamic settings |
| `libredb git-init` / `git-sync` / `git-release` (aliases: `gitea-*`) | Provider-aware multi-remote Git, Keep a Changelog release, and binary asset automation |
| `libredb import-sqlite` / `export-sqlite` / `verify-roundtrip` | Explicit lossless `19`-table + `5`-`FTS5` `SQLite <-> LibreDB` migration and parity verification |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (5 default CLI/MCP crates + optional PyO3 crate)
|-- Makefile                                       # Zero-dependency POSIX/Linux/macOS source build & installer
|-- VERSION                                        # Semantic Version (1.3.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # Commons Clause v1.0 + full verbatim GNU AGPL v3.0 text
|-- README.md                                      # 9-block standardized documentation
|-- scripts/
|   |-- deploy_plugin.ps1                          # Windows PowerShell installer (-Profile Neutral|Personal, -NoHooks, -MigrateLegacy)
|   |-- deploy_plugin.sh                           # POSIX/Linux/macOS installer (--profile neutral|personal, --no-hooks, --migrate-legacy)
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, alphanumeric v5 tokens & Hebbian learner
    |-- libredb-cognitive/                         # OverlayBrain, Session Delta, Guardrails, Grounded Reflexes, Causal WorkspaceGraph & FIM
    |-- libredb-bridge/                            # Zero-amnesia 19-table SQLite migrator & parity verifier
    |-- libredb-cli/                               # Modular CLI, MCP Server, Telemetry/Benchmarks, DPAPI/ChaCha20-Poly1305 Vault & Gitea Suite
    |   |-- src/cli_args.rs                        # Deterministic zero-dependency CLI flag & positional parser (CliSpec)
    |   |-- src/bench.rs                           # Native kernel, C1..C6 economy & A1..A11 feature/security audit engine
    |   |-- src/telemetry.rs                       # Cross-process-atomic telemetry.ldb ledger + streaming 8 MiB transcript analyzer
    |   |-- src/mcp/                               # Modular MCP server (mod, protocol, authz, tools, tests)
    |   |-- src/security/                          # Modular security suite (mod, ephemeral, vault, seals, path_policy, tests)
    |   |-- src/hooks.rs                           # Sub-2ms subagent-aware priority BM25 PreInvocation & tentative PreToolUse hooks
    |   |-- src/gitea.rs                           # Provider-aware multi-remote Git, Gitea & GitHub release automation
    |   |-- tests/military_grade_mcp_security.rs   # Multi-process OS SIGKILL, root-refresh & boundary isolation E2E suite
    |   |-- tests/v111_feature_and_security_audit.rs # E2E MCP savings authz, batched locate/impact/fim, closed-loop causal learning & A1..A11 audit suite
    |-- libredb-py/                                # Optional PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for the complete license terms.
