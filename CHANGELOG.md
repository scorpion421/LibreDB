# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
