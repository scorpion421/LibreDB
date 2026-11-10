# LibreDB

[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-passing%20(40%20tests%20%2B%2010k%20crash%20sims)-brightgreen.svg)](crates/libredb-bridge/tests/)
[![Tech Stack](https://img.shields.io/badge/rust-1.89%2B%20%7C%20PyO3%20abi3%20%7C%20MCP-orange.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20Commons%20Clause-purple.svg)](LICENSE)

`LibreDB` is an enterprise-ready, local-first, zero-configuration, single-file cognitive database, lifecycle hook engine, dynamic multi-remote Git/Gitea automation suite, and multi-workspace `MCP` memory substrate (`*.ldb`) built in Rust for `Antigravity` and `MCP`-compatible `LLM` clients. It replaces `SQLite` + Python memory overhead with zero-I/O RAM-first `Zero-Repeat Delta` deduplication, `HMAC-SHA256` workspace trust anchors (`libredb trust`), standards-compliant OS/AEAD secret protection (Windows `DPAPI` / RFC 8439 `ChaCha20-Poly1305`), `< 2 ms` in-engine compiled `PreInvocation`/`PreToolUse` hooks (`~2 ms` POSIX / `~20 ms` Windows PE spawn), 15+ language Dependency-Injection-aware (`DI`) causal code-graph `FIM` slicing, and enterprise-neutral installation across Windows, Linux, and macOS.

## Table of contents

- [Executive summary and impact](#executive-summary-and-impact)
- [Installation and quickstart](#installation-and-quickstart)
- [Usage and commands](#usage-and-commands)
- [Architecture and project structure](#architecture-and-project-structure)
- [Versioning and license](#versioning-and-license)

## Executive summary and impact

| Dimension | Legacy Python + `SQLite` (`SkillsDB`) | `LibreDB v0.9.0` (Pure `Rust` + `MCP` + `PyO3`) |
| :--- | :--- | :--- |
| **Lifecycle hook latency** | `350-500 ms` Python startup + `SQLite` WAL per edit/turn | **`< 2 ms` in-engine (`~2 ms` Linux / `~20 ms` Windows PE spawn, verified in CI)** |
| **Turn 2+ recall & I/O** | `300-1500 ms` subprocess + repeated full text output | **`0` disk I/O reads (`~3 ms` `MCP` / `PyO3`) via RAM-first `Zero-Repeat Delta`** |
| **Cryptography & trust** | Plaintext DB tokens & unverified `.agents/memory.db` loads | **Windows `DPAPI` + RFC 8439 `ChaCha20-Poly1305` `AEAD` + `HMAC-SHA256` (`libredb trust`)** |
| **Enterprise DI code graph** | Full `read_file` scans + blind to interfaces/`@Inject` | **15+ language `DI` interface-to-implementation `fim`, `impact` & batched `skeleton`** (Java/Quarkus, TS/Angular, C#/.NET, Rust, Python, SQL, PowerShell) |
| **Enterprise-neutral install** | Hardcoded personal workflow rules & forced Git identity | **Neutral default install (`0` personal rules, preserves `git config`) + opt-in `-NoHooks` / `-Profile Personal`** |
| **Guardrails & Git/Gitea DevOps** | `15,492`-line Python script + forced `origin` rewrites | **Binary-safe `< 0.5 ms` security guardrails + dynamic multi-remote Git/Gitea/GitHub sync** |

## Installation and quickstart

### Prerequisites

- **Rust toolchain:** `1.89+` (`cargo` + `rustc`, plus a standard C compiler `cc`/`gcc`/`clang` on Linux/macOS or MSVC on Windows for bundled `sqlite3.c` - zero external `-dev` libraries required)
- **Optional Python integration:** `Python 3.12+` (verified on `Python 3.14.5` via Stable ABI `abi3`, decoupled from default `CLI`/`MCP` builds)

### Linux and macOS (enterprise-neutral source build & plugin install)

```sh
make test
make install            # Neutral default: MCP + security hooks, no personal rules, preserves git user.name
make install-mcp-only   # Pure MCP server mode (lifecycle hooks disabled)
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
| `libredb_pulse` (`MCP`) / `libredb pulse` | Dual-layer associative recall with hands-free `/compact` sync & zero-I/O `Zero-Repeat Delta` |
| `libredb_code` (`MCP`) / `skeleton`, `impact`, `fim`, `index-workspace` | `DI`-aware code graph joining `[Lstart-Lend]` slices, interface `implementors`, callers, and `Decisions` |
| `libredb_memorize` (`MCP`) / `batch`, `learn-assoc`, `learn-reflex` | Atomic multi-capsule commits, tasks, language-agnostic Hebbian learning, and pitfall reflexes |
| `libredb hook-pre-invocation` / `hook-pre-tool` / `guardrail check` | Sub-2ms Antigravity lifecycle hooks, control-plane path protection & guardrail scanner |
| `libredb trust` / `libredb config` | `HMAC-SHA256` workspace trust seals (`sys::trust_seals`) & dynamic zero-hardcode settings |
| `libredb git-init` / `git-sync` / `git-release` (aliases: `gitea-*`) | Provider-aware multi-remote Git, Keep a Changelog release, and binary asset automation |
| `libredb import-sqlite` / `export-sqlite` / `verify-roundtrip` | Lossless `19`-table + `5`-`FTS5` `SQLite <-> LibreDB` migration and parity verification |

## Architecture and project structure

```text
LibreDB/
|-- Cargo.toml                                     # Rust workspace (5 default CLI/MCP crates + optional PyO3 crate)
|-- Makefile                                       # Zero-dependency POSIX/Linux/macOS source build & installer
|-- VERSION                                        # Semantic Version (0.9.0)
|-- CHANGELOG.md                                   # Keep a Changelog 1.1.0 release history
|-- LICENSE                                        # AGPLv3 + Commons Clause license
|-- README.md                                      # 9-block standardized documentation
|-- scripts/
|   |-- deploy_plugin.ps1                          # Windows PowerShell plugin installer (-Profile Neutral|Personal, -NoHooks)
|   |-- deploy_plugin.sh                           # POSIX/Linux/macOS plugin installer (--profile neutral|personal, --no-hooks)
|-- crates/
    |-- libredb-core/                              # Frozen single-file LIBREDB1 storage kernel (Inodes, Extents, MVCC)
    |-- libredb-index/                             # Language-agnostic IDF n-grams, Hebbian learner & persistent index snapshot
    |-- libredb-cognitive/                         # OverlayBrain, Session Delta, Guardrails, Reflexes, DI WorkspaceGraph & FIM
    |-- libredb-bridge/                            # Zero-amnesia 19-table silent SQLite auto-porter & parity verifier
    |-- libredb-cli/                               # CLI, Multi-Workspace MCP Server, DPAPI/ChaCha20-Poly1305 Vault & Gitea Suite
    |-- libredb-py/                                # Optional PyO3 abi3 Python extension (`libredb.pyd` / `.so`)
```

## Versioning and license

This project strictly follows [Semantic Versioning 2.0.0](https://semver.org/) and documents all releases in [CHANGELOG.md](CHANGELOG.md) according to [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

Licensed under **GNU Affero General Public License v3.0 (AGPL-3.0) with Commons Clause License Condition v1.0** - see [LICENSE](LICENSE) for full terms.
