# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-11-10

### Added

- Added CLI rule, skill, and reflex inspection and synchronization subcommands (`libredb list-rules`, `libredb list-skills`, `libredb list-reflexes`, `libredb sync-skill <SKILL.md>`, and `libredb modernize-global`) in `crates/libredb-cli/src/main.rs`.
- Added `libredb modernize-global` to cleanly deprecate legacy `customizations-db` skill capsules in `~/.gemini/libredb/customizations.ldb`, update active `NodeKind::Rule` directives from `skillsdb` to `libredb` (while preserving all `sqlite_row:*` 1:1 audit backups untouched), sync `SKILL.md` (`skill:libredb`), and seed `9` core procedural reflexes (`rust-guardrail-staged`, `windows-hooks-cmd-quoting`, `gitea-collision-and-github-guard`, `semver-changelog-discipline`, `anti-salami-code-slicing`, `windows-soc-admin-audit`, `formatting-and-language-boundary`, `rust-gitea-dist`, and `git-non-acl-safe-dir`).
- Added automatic incremental workspace code-graph refresh before `libredb_code` (`action="impact"` and `action="fim"`) and `libredb gitea-sync` so newly edited files and symbols are immediately reflected in blast-radius callers and governance edges without manual `index-workspace` invocations.

### Changed

- Made `LibreDb::link_batch` in `crates/libredb-core/src/engine.rs` zero-I/O idempotent when all target synapses on a node already exist with identical weights, eliminating redundant delta-envelope commits and `fsync` calls on unchanged graph edges.
- Optimized `index_workspace` in `crates/libredb-cognitive/src/workspace.rs` to skip full source-file identifier re-scanning when `files_reindexed == 0` and call edges are already wired, reducing warm incremental workspace checks to `< 2 ms` with `0` disk writes.
- Updated `scripts/deploy_plugin.ps1` to preserve live additions in `~/.gemini/libredb/customizations.ldb` across redeployments instead of re-importing from frozen `customizations.db` when `customizations.ldb` already exists.

## [0.5.3] - 2026-11-10

### Fixed

- Resolved relative `target` file paths against `cwd` inside `libredb_code` (`skeleton`, `fim`, `index`) in `crates/libredb-cli/src/mcp.rs` so relative workspace paths work identically to absolute paths.
- Added `--version` / `-V` CLI flag support and `--db <path>` flag parsing to `libredb stats` in `crates/libredb-cli/src/main.rs`.
- Added automatic termination of stale `libredb` MCP daemon processes during `scripts/deploy_plugin.ps1` upgrades so newly deployed binaries and open `.ldb` handles refresh immediately.

## [0.5.2] - 2026-11-10

### Fixed

- Fixed PowerShell string quote escaping in `scripts/deploy_plugin.ps1` when seeding the `windows-hooks-cmd-quoting` reflex capsule so automated binary and plugin deployment runs cleanly end-to-end.

## [0.5.1] - 2026-11-10

### Fixed

- Added zero-sidecar inter-process writer synchronization (`LockFileEx` high-offset byte lock on Windows / advisory `flock` on Unix) and automatic superblock reload (`LibreDb::sync_from_disk_if_changed`) across `commit_batch`, `link_batch`, `deprecate_key`, `compact_with_gravity`, and `OverlayBrain::refresh_if_needed`, ensuring concurrent OS processes (`libredb-mcp` daemon + `PreInvocation`/`PreToolUse` hooks + `CLI`) never clobber interleaved commits while keeping `0 .. file_len` `MVCC` reads `100%` lock-free.
- Replaced in-place `Remove-Item` deletion of live `.ldb` files in `scripts/deploy_plugin.ps1` with atomic staging + rename swaps, preventing Windows `NTFS` `DELETE_PENDING` (`os error 5`) errors when upgrading while background handles are open.

## [0.5.0] - 2026-11-10

### Added

- Silent, crash-safe background `SQLite -> LibreDB` auto-porter (`open_or_auto_migrate` in `libredb-bridge`) wired across `MCP` (`libredb-mcp`), lifecycle hooks, `CLI`, and `PyO3`: whenever an existing workspace (`<root>/.agents/memory.db`), chat (`<brain>/<cid>/.agents/memory.db`), or central store (`customizations.db`) is touched for the first time, `LibreDB` imports `100%` of its contents read-only into `.ldb` in the background (`0` bytes altered in `.db`), while brand-new chats and projects operate purely on `.ldb`.
- Complete `19`-table zero-amnesia cognitive hydration in `populate_cognitive_graph`:
  - Preserves `100%` verbatim `SKILL.md` bodies (`skill_full::<name>` + `libredb get-skill`), `runtime_config` (`NodeKind::Config`), `transcript_cursors`, and `quota_ledger` alongside active/historical `rules` and `skill_sections`.
  - Hydrates all `11` project memory tables including `session_snapshots` (chronological `Supersedes` milestone lineage), `fact_history` + `deprecated_at` / `superseded_by` temporal chains, `task_verifications` (`Verifies` synapses), `task_handoffs.context_variables`, `compaction_archive`, `active_working_set` (`Touches` synapses), automatic `Decision -> Governs -> Symbol` synapses, and unlimited `dependency_edges`.
- Pure-Rust binary-safe guardrail engine (`libredb-cognitive::guardrail` / `libredb guardrail check`) enforcing formatting invariants (`no-em-en-dash`, `no-emojis`, `no-vbscript`), SemVer tag immutability, zero-polling, and SOC-compliant remote execution rules in `< 0.5 ms` per file without scanning build binaries.
- Native compiled Rust Antigravity lifecycle hooks (`libredb hook-pre-invocation` and `libredb hook-pre-tool` in `< 2 ms`), replacing `400 ms` Python hook cold-starts while preserving epoch deduplication, `WaitMsBeforeAsync` auto-upgrades, Subagent Firewall checks, and `WorkingSet` tracking.
- Dependency-free native Rust Gitea workflow suite (`gitea-status`, `gitea-config`, `gitea-init`, `gitea-sync`, `gitea-release`, `gitea-credential-helper`) over `std::net::TcpStream` HTTP/1.1 with `[GITEA REPOSITORY COLLISION]` protection, transient Basic auth headers, Keep a Changelog 1.1.0 release syncing, and `multipart/form-data` binary asset uploads.
- Complete standalone Antigravity replacement bundle in `scripts/deploy_plugin.ps1` (`plugin.json`, `mcp_config.json`, `hooks.json`, `rules/AGENTS.md`, `skills/libredb/SKILL.md`, and `PATH` shim) allowing `customizations-db` to be cleanly toggled off for pure single-engine operation.

### Fixed

- Eliminated `O(N^2)` posting-list duplicate scans during bulk `HybridIndex` ingestion in `libredb-index`, accelerating initial index builds on `55,000+`-symbol repositories (`Android`, `Nova-Launcher`) by over an order of magnitude so first-touch hook auto-migration stays well inside the `5 s` hook budget.

## [0.4.0] - 2026-11-09

### Added

- Multi-workspace dynamic `MCP` stdio server (`McpServerState` in `libredb-cli::mcp`) resolving `<workspace>/.agents/memory.ldb` automatically from `cwd` / `target` and caching hot `OverlayBrain` instances per workspace in RAM.
- Consolidated 3-tool `MCP` surface (`libredb_pulse`, `libredb_code`, `libredb_memorize`) reducing per-turn system-prompt tool-schema token overhead by `78%` while retaining legacy tool-name dispatch compatibility.
- Automatic Antigravity `transcript.jsonl` path resolution from `cid` inside `libredb_pulse` for hands-free `/compact` epoch synchronization.
- Automated local deployment script (`scripts/deploy_plugin.ps1`) installing standalone `libredb.exe`, `libredb.pyd`, pre-indexed `customizations.ldb`, and the toggleable Antigravity plugin (`~/.gemini/config/plugins/libredb/`) without modifying `AntiGraviton`.

### Changed

- Refactored `OverlayBrain::pulse` and `CognitiveEngine::score_candidates_in_ram` to perform `BM25`, synapse spreading activation, and `SessionState` (`Zero-Repeat Delta`) deduplication `100%` in RAM before touching disk extents - reducing Turn 2+ deduplicated payload disk reads from `14` down to `0` (`sub-millisecond` warm latency).

## [0.3.0] - 2026-11-09

### Added

- Persistent single-extent inverted index snapshots (`sys::index_snapshot`) with incremental `Inode` generation delta reconciliation in `libredb-index`, cutting cold CLI `pulse` startup by an order of magnitude without re-tokenizing unchanged capsules.
- `OverlayBrain` in `libredb-cognitive::overlay` uniting a read-only global base layer (`customizations.ldb`) and a writable project layer (`memory.ldb`) in a single federated `pulse` with isolated `Zero-Repeat Delta` session namespaces.
- Binary-safe workspace graph engine (`libredb-cognitive::workspace`):
  - `index_workspace` (`libredb index-workspace`) skipping build directories (`target/`, `dist/`, `.venv/`) and `NUL`-byte binaries while extracting `64-bit` hash-cached `FileSkeleton`s.
  - Automatic cross-graph causal synapse wiring (`Caller --[Calls]--> Callee` and `Decision/Task --[Governs]--> Symbol`).
  - `query_symbol_impact` (`libredb impact`) and `extract_fim_slice` (`libredb fim`) combining surgical `[Lstart-Lend]` code slices with blast-radius callers and governing architectural decisions.
- Incremental binary tail `/compact` detector (`sync_transcript_epoch`), atomic multi-entity commits (`execute_atomic_batch` / `libredb batch`), and zero-bloat subagent delegation bundles (`create_subagent_handoff` / `libredb handoff`).
- Native `JSON-RPC 2.0` Model Context Protocol stdio server (`libredb mcp-serve`) keeping `OverlayBrain` hot in RAM for sub-millisecond tool calls with zero process startup overhead.
- Native `PyO3` (`abi3-py312` forward-compatible) Python extension crate (`libredb-py`, `import libredb`) exposing `libredb.Brain` directly in-process to Python `3.12 - 3.14+`.

## [0.2.0] - 2026-11-09

### Added

- `libredb-index`: Language-agnostic information-theoretic search engine combining `BM25` token scoring, unsupervised morphological `BM25` over Unicode character `n-grams` (with zero hardcoded stopword lists, stemmers, or language dictionaries), and persistent Hebbian co-activation concept learning (`reinforce_association` / `libredb learn-assoc`).
- `libredb-cognitive`:
  - `SessionState` (`Zero-Repeat Delta` filter per `(conversation_id, epoch)`) suppressing duplicate context deliveries across multi-turn sessions while automatically re-hydrating mutated generations or post-compaction epochs.
  - Purely data-driven `ReflexEngine` (`learn-reflex`) firing concise situational pitfall guardrails based on detected workspace markers, actions, and error substrings before execution.
  - `FileSkeleton` (`libredb skeleton`) extracting `64-bit` content-hash-cached module boundaries, `[Lstart-Lend]` spans, signatures, and docstrings (`85-98%` token compression over full file reads).
  - Unified one-shot `CognitiveEngine::pulse` (`libredb pulse`) integrating reflexes, hybrid search, 2-hop `Inode` spreading activation, session delta deduplication, and coalesced extent reads within a strict token budget.
- `libredb-bridge`: Lossless 1:1 bidirectional `SQLite <-> LibreDB` migrator and cryptographic bijection verifier (`import-sqlite`, `export-sqlite`, `verify-roundtrip`) supporting all 19 `SkillsDB` relational tables and all 5 `FTS5` virtual tables with zero source modifications.
- Lock-free `list_inodes`, `get_many_coalesced`, and `active_key_for` snapshot helpers in `libredb-core`.

## [0.1.0] - 2026-11-09

### Added

- Initial `libredb-core` storage kernel implementing the single-file `LIBREDB1` (`*.ldb`) binary format with ping-pong `CRC32C`-verified superblocks (`Slot A` and `Slot B`) for sidecar-free crash recovery on local `NVMe` and `SMB` network shares.
- Fixed `128-byte` cache-line-aligned `Inode` records supporting `O(1)` lookup by immutable `NodeId`, inline small payloads (`<= 43 bytes`), `LZ4`-compressed contiguous extents, exact token counts, temporal `Supersedes` chains, and `4` inline typed cognitive synapses (with overflow synapse extents for high-degree hubs).
- Sharded concurrent preparation lanes (`16` independent worker lanes) paired with lock-free `MVCC` snapshot readers using offset-explicit random `pread` / `seek_read` I/O without global read locks.
- Deterministic gravity compaction pass (`compact_with_gravity`) inspired by `ext4` block groups, co-locating strongly linked `Inode` families into contiguous `64 KB` locality zones while demoting superseded historical versions to a cold archive region.
- `libredb-cli` command-line utility (`init`, `put`, `get`, `link`, `neighbors`, `trace`, `compact`, `inspect`, `verify`, `bench`) for inspecting, testing, and benchmarking `.ldb` files.
- Comprehensive verification suite covering binary encoding invariants, `16`-thread concurrent read/write storms, and deterministic mid-write power-loss fault injection (`10,000` simulated crash points).
