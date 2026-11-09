# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

### Added

- Initial `libredb-core` storage kernel implementing the single-file `LIBREDB1` (`*.ldb`) binary format with ping-pong `CRC32C`-verified superblocks (`Slot A` and `Slot B`) for sidecar-free crash recovery on local `NVMe` and `SMB` network shares.
- Fixed `128-byte` cache-line-aligned `Inode` records supporting `O(1)` lookup by immutable `NodeId`, inline small payloads (`<= 43 bytes`), `LZ4`-compressed contiguous extents, exact token counts, temporal `Supersedes` chains, and `4` inline typed cognitive synapses (with overflow synapse extents for high-degree hubs).
- Sharded concurrent preparation lanes (`16` independent worker lanes) paired with lock-free `MVCC` snapshot readers using offset-explicit random `pread` / `seek_read` I/O without global read locks.
- Deterministic gravity compaction pass (`compact_with_gravity`) inspired by `ext4` block groups, co-locating strongly linked `Inode` families into contiguous `64 KB` locality zones while demoting superseded historical versions to a cold archive region.
- `libredb-cli` command-line utility (`init`, `put`, `get`, `link`, `neighbors`, `trace`, `compact`, `inspect`, `verify`, `bench`) for inspecting, testing, and benchmarking `.ldb` files.
- Comprehensive verification suite covering binary encoding invariants, `16`-thread concurrent read/write storms, and deterministic mid-write power-loss fault injection (`10,000` simulated crash points).
