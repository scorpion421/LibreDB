# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.3] - 2026-11-10

### Fixed

- Propagated explicit `Result<(), String>` errors from `PreMutationSealGuard::reseal_after_write` (`crates/libredb-cli/src/security.rs`) and `McpServerState::seal_project_db_if_authorized` (`crates/libredb-cli/src/mcp.rs`) across all project-mutating `CLI` commands (`crates/libredb-cli/src/main.rs`) and `MCP` write tools (`libredb_memorize`, `libredb_handoff`, evicting any stale RAM `OverlayBrain` on failure), and surfaced post-migration `seal_workspace_memory` errors explicitly in `run_pre_invocation_hook` (`crates/libredb-cli/src/hooks.rs`), ensuring a failed `hmac-sha256:v3:` seal refresh after a successful write is reported immediately to the caller rather than silently ignored.

## [0.9.2] - 2026-11-10

### Added

- Added `--migrate-v2` and `--if-clean` flags to `libredb trust` (`migrate_workspace_seal_v2_to_v3` in `crates/libredb-cli/src/security.rs` and `crates/libredb-cli/src/main.rs`): `--migrate-v2` explicitly verifies a legacy `v0.9.0` `hmac-sha256:v2:` workspace HMAC against this host's `sys::trust_anchor_secret` (while rejecting downgrade attempts if a `slot:<id>=hmac-sha256:v3:` entry already exists and failed verification) before issuing a content-bound `hmac-sha256:v3:` seal, and `--if-clean` allows plugin installers (`scripts/deploy_plugin.ps1` and `scripts/deploy_plugin.sh`) to seal fresh or already-valid workspaces without ever auto-trusting a modified `.agents/memory.ldb`.

### Fixed

- Narrowed neutral-profile rule cleanup in `modernize_global_db` (`crates/libredb-cli/src/main.rs`) from the prefix wildcard `k.starts_with("rule:global::")` to the exact personal rule key `"rule:global::candid-architectural-pushback"` (plus the `7` exact personal reflex IDs), ensuring custom organization-defined global rules under the `rule:global::*` namespace survive `--profile neutral` upgrades and `Personal -> Neutral` switches untouched.

### Security

- Eliminated post-hoc workspace re-sealing ("trust laundering") across global upgrades, CLI mutations, lifecycle hooks, and `MCP` caching: `modernize_global_db` (`crates/libredb-cli/src/main.rs`) now audits registered workspaces strictly read-only via `is_workspace_memory_trusted` (quarantining and warning on modified or unverified `.agents/memory.ldb` files instead of calling `seal_workspace_memory`), all project-mutating CLI commands (`config set/unset --project`, `batch`, `handoff`, `learn-reflex`, `import-sqlite`, `put`, `deprecate`, `compact`) enforce a pre-mutation `PreMutationSealGuard::verify_before_write` check before touching disk, `run_pre_invocation_hook` (`crates/libredb-cli/src/hooks.rs`) seals strictly when `did_migrate == true`, and `McpServerState::resolve_brain_with_seal_target` (`crates/libredb-cli/src/mcp.rs`) evicts cached RAM `OverlayBrain` instances immediately on seal mismatch.

## [0.9.1] - 2026-11-10

### Added

- Added `--profile neutral|personal` and `--migrate-legacy` flags to `libredb modernize-global` (`crates/libredb-cli/src/main.rs`), `-MigrateLegacy` to `scripts/deploy_plugin.ps1`, `--migrate-legacy` to `scripts/deploy_plugin.sh`, and `install-migrate-legacy` to `Makefile`, decoupling legacy `~/.gemini/database/customizations.db` `SQLite` imports from default enterprise-neutral installations unless explicitly requested.
- Embedded the complete verbatim GNU Affero General Public License v3.0 (`AGPL-3.0`) text beneath the `Commons Clause` License Condition v1.0 header in `LICENSE`, and added hard CI assertions in `.github/workflows/ci.yml` verifying `Active Rules (0)` and `Active Situational Reflexes (3)` on neutral installs alongside upper-bound hook latency gates (`< 5.0 ms` median on Linux, `< 25.0 ms` median on Windows).

### Changed

- Made `modernize_global_db` in `crates/libredb-cli/src/main.rs` 100% developer-neutral by default (`--profile neutral`): neutral installations never seed `rule:global::candid-architectural-pushback` or personal formatting/German/admin/release reflexes, actively remove personal `rule:global::*` capsules, personal `AGENTS.md`, and personal `libredb config` toggles when downgrading an existing `Personal` installation to `Neutral` (while preserving custom corporate rules), and seed only `3` strictly technical engine-safety reflexes (`windows-hooks-cmd-quoting`, `gitea-collision-and-github-guard`, `git-non-acl-safe-dir`).
- Removed silent central `customizations.db` fallback auto-migration from `open_global_ldb_if_exists` and custom `--global <path>` overrides in `crates/libredb-cli/src/hooks.rs` so lifecycle hooks and `MCP` sessions never implicitly import legacy personal `SQLite` data into neutral environments.

### Security

- Added safe read-only `vault:v1:` -> `vault:v2:` POSIX credential migration (`legacy_v1_open_for_migration` and `is_ciphertext_envelope` in `crates/libredb-cli/src/security.rs`) so existing `v0.8.7`/`v0.8.8` `vault:v1:` tokens are decrypted and upgraded to RFC 8439 `ChaCha20-Poly1305` `vault:v2:` without ever treating unknown or cross-platform ciphertexts as plaintext or double-encrypting them, and hardened `load_or_create_posix_vault_key_at` (`create_new(true)`) and `ensure_trust_anchor_secret` so pre-existing `.vault.key` files and trust secrets are never overwritten on decode errors.
- Upgraded `check_mcp_read_path_policy` and `check_tool_write_path_policy_with_base` (`canonicalize_with_missing_tail` and `lexical_normalize_lower` in `crates/libredb-cli/src/security.rs`, wired across `hooks.rs` and `mcp.rs`) to canonicalize symlinks, Windows directory junctions, and `..` segments before policy evaluation, and hardened `collect_source_files` (`crates/libredb-cognitive/src/workspace.rs`) to skip file/directory symlinks and sensitive key/dotenv files (`.env`, `.env.*`, `.pem`, `.p12`, `.pfx`, `.jks`, `.kdbx`, `.vault.key`) during `index-workspace`.
- Upgraded workspace trust anchors from path-only `hmac-sha256:v2:` to content-authenticated `hmac-sha256:v3:` (`compute_cognitive_content_digest` and `compute_workspace_seal_v3` in `crates/libredb-cli/src/security.rs`, refreshed automatically after authorized `MCP` and `CLI` cognitive writes), binding the `HMAC-SHA256` seal to a deterministic `SHA-256` digest over all active cognitive capsules (`Rule`, `Skill`, `Decision`, `Fact`, `Task`, `Handoff`, `Snapshot`, `CompactionCheckpoint`, and `Config`) so offline tampering of `.agents/memory.ldb` invalidates trust immediately while keeping `WorkingSet` and `Symbol` cache updates zero-friction.

## [0.9.0] - 2026-11-10

### Added

- Added polyglot Dependency Injection (`DI`) and interface/trait inheritance resolution (`SymbolContract.supertypes`, `SKELETON_HASH_SEED = 109`, `extract_brace_supertypes`, `extract_python_supertypes`, `EdgeKind::DependsOn`, and `SymbolImpactReport.implementors`) across Java/Quarkus (`implements`/`extends` + `@Inject` interface calls), Angular/TypeScript (`implements` + constructor `DI`), C#/.NET (`:` base/interface lists + C# 12 primary constructors), Python (`Protocol`/`ABC` base classes), Kotlin, C++, Swift, and Rust (`impl Trait for Type`), propagating interface callers (`OrderResource::submitOrder -> OrderApprovalPort::approveOrder -> OrderApprovalService::approveOrder`) into concrete implementation `impact` and `fim` blast-radius slices.
- Added enterprise-neutral installation profiles (`-Profile Neutral|Personal` and `-NoHooks` in `scripts/deploy_plugin.ps1`; `--profile neutral|personal`, `--personal-rules`, and `--no-hooks` in `scripts/deploy_plugin.sh`; `install-personal`, `install-mcp-only`, and `bench` targets in `Makefile`), ensuring default installations never create or inject personal `rules/AGENTS.md` workflow directives onto corporate or evaluation workstations.
- Added automated storage kernel benchmarks (`libredb bench`) and `25`-iteration wall-clock `hook-pre-invocation` / `hook-pre-tool` latency measurements plus neutral-install `AGENTS.md` absence assertions to `.github/workflows/ci.yml` on both `ubuntu-latest` and `windows-latest`.

### Changed

- Made opinionated `PreToolUse` and `git-sync` workflow preferences opt-in via `libredb config` (`hook:subagent_flash_routing`, `hook:exploratory_firewall`, and `guardrail:style_rules` defaulting to `false` on neutral enterprise installs while enabled in `-Profile Personal`), keeping all security, path-protection, and secret-prevention guardrails active unconditionally.
- Updated `ensure_local_git_initialized` and `cmd_gitea_sync` (`git_has_configured_identity` in `crates/libredb-cli/src/gitea.rs`) to preserve the developer's configured Git `user.name` and `user.email` by default unless `git:author_name` / `git:author_email` overrides are explicitly set in `libredb config`.
- Aligned `Cargo.toml` and all six workspace crate manifests (`crates/*/Cargo.toml`) with `LICENSE` (`AGPL-3.0 + Commons Clause`) by replacing `license = "AGPL-3.0-only"` with `license-file = "LICENSE"` (`license-file.workspace = true`) and `repository = "https://github.com/scorpion421/LibreDB"`.

### Security

- Replaced all custom POSIX vault and workspace trust-seal primitives in `crates/libredb-cli/src/security.rs` (removing `xor_keystream` and `FNV-1a`/`SplitMix64` MACs) with standards-compliant RFC 8439 `ChaCha20-Poly1305` `AEAD` (`vault:v2:<nonce-hex>:<ciphertext+poly1305-tag-hex>`, cryptographically authenticating the `96-bit` `nonce`, domain-separated `AAD`, and ciphertext with a `128-bit` `Poly1305` tag alongside Windows `DPAPI`) and RFC 2104 `HMAC-SHA256` (`hmac-sha256:v2:<64-hex>`) for `sys::trust_seals`, hardened POSIX `.vault.key` against symlinks and loose permissions (`0600`), and added `1`-bit nonce, ciphertext, and tag tamper rejection unit tests.

## [0.8.8] - 2026-11-10

### Added

- Added first-class POSIX / Linux / macOS zero-dependency source build and plugin deployment workflow: root `Makefile` (`build`, `build-native`, `test`, `install`, `python`, `guardrail`, `uninstall`, `clean`, `help`), POSIX installer `scripts/deploy_plugin.sh` (atomic `mv -f` hot-swap binary updates, `test_safe_binary_dir` world-writable permission checks, `/bin/sh -c` hook verification, `~/.local/bin` + `~/.gemini` installation, and `modernize-global` + `trust` sealing), `.gitattributes` enforcing `LF` line endings on POSIX scripts and Makefiles, and cross-platform `.github/workflows/ci.yml` (`ubuntu-latest` + `windows-latest`).
- Added pure-Rust Linux network filesystem detection (`is_linux_network_mount` via `/proc/mounts` for `nfs`, `nfs4`, `cifs`, `smb3`, `smbfs`, `fuse.sshfs`, `9p`, `lustre`, `ceph`, and `glusterfs`) and bounded non-blocking `unix_lock::lock_with_timeout` (`file.try_lock()` with `1,500 ms` network / `3,000 ms` local exponential backoff) in `crates/libredb-core/src/io.rs`.
- Added native `Makefile` / `GNUmakefile` / `*.mk` target rule extraction (`extract_makefile_symbols`, `SKELETON_HASH_SEED = 108`) in `crates/libredb-cognitive/src/skeleton.rs` and `crates/libredb-cognitive/src/workspace.rs`.

### Changed

- Configured `default-members` in root `Cargo.toml` to decouple the optional `libredb-py` `cdylib` extension from default `cargo build --release` and `cargo test --release` invocations so Linux, macOS, and Windows hosts compile the full `libredb` CLI and `MCP` server with zero Python interpreter or header requirements (`make python` builds `libredb-py` explicitly).
- Updated `cmd_gitea_status` and `query_service_state` in `crates/libredb-cli/src/gitea.rs` for cross-platform operation (`systemctl is-active` / `--user` probing on Unix, Windows `sc.exe` restricted strictly to `#[cfg(windows)]` loopback services), and extended `is_protected_profile_dir` in `crates/libredb-cli/src/hooks.rs` to guard Unix system hierarchies (`/etc`, `/usr`, `/proc`, `/sys`, `/dev`, `/run`, `/var/tmp`).

## [0.8.7] - 2026-11-10

### Added

- Added zero-dependency OS credential vault (`protect_secret`, `unprotect_secret`, and `is_protected_secret` in `crates/libredb-cli/src/security.rs`) backed by Windows `DPAPI` (`CryptProtectData` / `CryptUnprotectData` + `SystemFunction036` CSPRNG + volatile memory scrubbing) and POSIX `0600` keyfiles, plus `--token-stdin` and `--allow-insecure-http` flags on `libredb gitea-config` with transparent plaintext-to-vault migration in `GiteaConfig::load` and `modernize-global`.
- Added autonomous cryptographic workspace trust anchors (`is_workspace_memory_trusted`, `seal_workspace_memory`, `revoke_workspace_trust`, and `is_git_index_tracking_agents_db` in `crates/libredb-cli/src/security.rs`) exposed via `libredb trust [<dir>] [--revoke] [--list]`, quarantining unsealed or Git-tracked `.agents/memory.*` databases from automatic `PreInvocation` `<SYSTEM_MESSAGE>` hydration and untrusted C `SQLite` deserialization.
- Added universal dynamic configuration (`libredb config <get|set|unset|list> [<key>] [<value>] [--project <dir>]` in `crates/libredb-cli/src/main.rs` and `WorkspaceScanConfig::from_db_and_root` in `crates/libredb-cognitive/src/workspace.rs`) supporting root `.gitignore` directory discovery and runtime overrides (`index:ignore_dirs`, `index:extra_extensions`, `index:max_file_bytes`, `guardrail:secret_prefixes`, `guardrail:protected_paths`, `guardrail:allow_staged_files`, and `gitea_allow_insecure_http`).

### Changed

- Replaced the hardcoded 75-word call-graph stopword list in `crates/libredb-cognitive/src/workspace.rs` with a 100% language-agnostic 3-tier syntactic (`Type::method` vs `.method(` vs bare `func(`) and unsupervised corpus Document-Frequency (`IDF`) call-site classifier (`extract_call_sites`), keeping zero hardcoded language or identifier dictionaries across the codebase.
- Upgraded `scripts/deploy_plugin.ps1` (`Test-SafeBinaryAcl`) to stage non-`%USERPROFILE%` drive hook binaries outside `target\` (`<DriveRoot>\.gemini\libredb\bin\libredb.exe`) only after verifying directory write ACLs exclude broad multi-user principals (`Everyone`, `Users`, `Authenticated Users`, `Domain Users`), preventing both `cargo clean` hook breakage and shared-drive binary hijacking.

### Fixed

- Fixed domain-prefix boundary matching in `GiteaConfig::is_gitea_remote_url` and dynamic loopback port matching (`extract_url_port`) in `crates/libredb-cli/src/gitea.rs` so subdomain prefix lookalikes (`git.corp.example.attacker.example`) never match `git.corp.example` and custom loopback Gitea ports work without hardcoded `:3000` assumptions.
- Fixed `find_matching_brace_end` in `crates/libredb-cognitive/src/skeleton.rs` (`SKELETON_HASH_SEED = 107`) to enforce strict per-character loop progress on `'\...` sequences longer than 10 characters and honor PowerShell/Shell/SQL quote-escaping and `#` / `<# ... #>` comment rules so PowerShell regexes (`'\\(...)'`) and trailing-backslash Windows paths (`"$env:USERPROFILE\bin\"`) never stall or misbalance function braces.

### Security

- Hardened `crates/libredb-cli/src/gitea.rs` against credential exfiltration and Git repository traps: verified `stdin` `protocol` + `host` in `cmd_gitea_credential_helper`, removed `curl --location` redirect auth forwarding, enforced `--proto =https` and zero-disk `-K -` `stdin` piping on `GET`/`DELETE` requests (`FILE_ATTRIBUTE_TEMPORARY` when `stdin` carries a body), blocked non-loopback cleartext `http://` token transmission by default, enforced `.git/info/exclude` (`/.agents/`, `*.tmp.ldb`, `*.credential.xml`) and `is_sensitive_staged_file` checks + `-c core.fsmonitor=false`, and gated `ensure_git_safe_dir` via `is_safe_auto_git_dir` (`CVE-2022-24765`).
- Enforced control-plane and credential path policies (`check_tool_write_path_policy` and `check_mcp_read_path_policy` in `crates/libredb-cli/src/security.rs`) across `PreToolUse` (`hooks.json`, `mcp_config.json`, `.git/hooks/*`, `.git/config`, `.ssh/*`, `credentials/*`) and `libredb-mcp` (`skeleton`, `fim`, `index`, blocking `.env` and credential stores), sanitized `.git/HEAD` branch names in `collect_git_telemetry_line`, and added `-EncodedCommand` obfuscation + 14-family secret-prefix + URL Basic-Auth leak detection in `crates/libredb-cognitive/src/guardrail.rs`.
- Added malformed-file OOM allocation bounds checks in `decode_metadata_frame` (`crates/libredb-core/src/format.rs`) and `read_inode_payload` / `read_coalesced_extents` / `read_overflow_synapses` (`MAX_EXTENT_PAYLOAD_BYTES` + EOF bounds in `crates/libredb-core/src/engine.rs`), plus `PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;` and `validate_safe_ddl_sql` in `crates/libredb-bridge/src/lib.rs`.

## [0.8.6] - 2026-11-10

### Added

- Added container-aware symbol qualification (`SymbolContract.container` and `SymbolContract::qualified_name()` in `crates/libredb-cognitive/src/skeleton.rs`, `SKELETON_HASH_SEED = 106`) across Rust (`impl Type` and `impl Trait for Type`), C++, Java, Kotlin, C#, Python, Go, and Smali, populating Stage A (`by_qualified_name`) and resolving `Self::method` and `self.method(` calls in `crates/libredb-cognitive/src/workspace.rs`.
- Added `LibreDb::sync_edges_for_kinds` in `crates/libredb-core/src/engine.rs` and incremental stale-symbol tombstoning in `crates/libredb-cognitive/src/workspace.rs` so deleted or renamed symbols and removed `Calls` / `Governs` / `CausedBy` synapses are cleanly reconciled on incremental re-indexing.
- Added multi-product `brain` directory discovery (`resolve_brain_conv_dir` across `antigravity`, `antigravity-ide`, and `antigravity-cli`) in `crates/libredb-cli/src/hooks.rs` and `crates/libredb-cli/src/mcp.rs`, space-safe `cmd.exe /c` path quoting in `scripts/deploy_plugin.ps1`, and `Gemini 4 Carbon` to the global model catalog in `AGENTS.md`.

### Changed

- Upgraded `HybridIndex` to `INDEX_FORMAT_VERSION = 4` (`purge_nodes_from_postings` in `crates/libredb-index/src/lib.rs`), purging dead `word_postings` and `ngram_postings` entries whenever Inodes are superseded or updated so `sys::index_snapshot` never accumulates historical posting bloat.
- Upgraded `PreInvocation` context injection in `crates/libredb-cli/src/hooks.rs` from deprecated `ephemeralMessage` to Antigravity 2.0 `{"systemMessage": {"systemMessage": ...}}`, and removed both `WaitMsBeforeAsync` argument rewrites and destructive pre-edit `CRLF`/UTF-8 BOM stripping from `PreToolUse`.

### Fixed

- Fixed `find_matching_brace_end` in `crates/libredb-cognitive/src/skeleton.rs` to track parentheses, `[T; N]` array-type brackets, Rust lifetimes (`'a`), raw strings (`r#"..."#`), character literals, and comments so Rust functions returning fixed-size arrays (`-> [u8; N]`) are never truncated at the array semicolon, and attached file paths to `std::fs::read` errors in `FileSkeleton` and `extract_fim_slice`.
- Fixed `PreToolUse` `CHANGELOG.md` snippet validation (`check_text_guardrails_with_mode` in `crates/libredb-cognitive/src/guardrail.rs`) so partial `edit_file` replacements on `CHANGELOG.md` do not falsely require line-1 `# Changelog` unless writing the full file.
- Fixed a first-touch initialization race in `LibreDb::open_with_backend` (protecting fresh file bootstrap under `IpcWriteGuard` and re-checking `backend.len()`), and hardened `LibreDb::get` and `LibreDb::get_many_coalesced` in `crates/libredb-core/src/engine.rs` to retry via `sync_from_disk_if_changed` on `UnexpectedEof` (`LibreDbError::Io`) without panicking if a cold node was pruned concurrently.
- Fixed `parse_http_response` in `crates/libredb-cli/src/gitea.rs` to skip interim `HTTP/1.1 100 Continue` header frames before decoding status codes and bodies.

### Security

- Eliminated plaintext token exposure on child process command lines (Windows Event 4688 / Sysmon Event ID 1) in `crates/libredb-cli/src/gitea.rs`: `configure_git_command_for_remote` now passes Gitea Basic Auth headers (plus `http.sslBackend=schannel` on Windows for `https://` Gitea remotes) exclusively via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_*` / `GIT_CONFIG_VALUE_*` environment variables, and `https_request_via_system_curl` passes `Authorization` headers via a zero-on-drop RAII `-K` config file (`EphemeralCurlConfig`) instead of `-H` CLI arguments.

## [0.8.5] - 2026-11-10

### Added

- Added transparent `https://` Gitea API support (`https_request_via_system_curl` in `crates/libredb-cli/src/gitea.rs`) delegating TLS requests to OS-native `curl` (`C:\Windows\System32\curl.exe` backed by Windows Schannel and the Active Directory GPO Enterprise Root CA store) while keeping zero-dependency `TcpStream` HTTP/1.1 for local `http://` endpoints.
- Added two-stage `EdgeKind::Calls` resolution in `crates/libredb-cognitive/src/workspace.rs` (`extract_qualified_calls` for exact `Type::method` / `Type.method` calls plus `is_trivial_call_stopword` and cross-file ambiguity filtering for bare identifiers), eliminating `~80%` of false-positive call edges caused by generic method names (`new`, `open`, `get`, `write`, `from`, `default`).

### Changed

- Upgraded `win_lock::lock_high_byte` in `crates/libredb-core/src/io.rs` from indefinite kernel blocking to `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY` with bounded exponential backoff (`1,500 ms` on SMB network shares, `3,000 ms` on local disk), ensuring lifecycle hooks fail open (`TimedOut`) instead of stalling if an SMB OpLock/lease on a mapped network drive (`Q:\`) transiently hangs.

## [0.8.4] - 2026-11-10

### Changed

- Added `$ReleaseExe` (`<workspace>\target\release\libredb.exe`) as the third fallback candidate in `$HookExeCandidates` in `scripts/deploy_plugin.ps1` so `< 2 ms` `PreInvocation` and `PreToolUse` hooks remain active via the project drive (`Q:\...`) even when Enterprise Active Directory `SRP` / `AppLocker` policies block `cmd.exe /c` execution inside `%USERPROFILE%`.
- Updated `run_pre_tool_hook` (`extract_pre_tool_name_and_args` in `crates/libredb-cli/src/hooks.rs`) to unwrap the Antigravity 2.0 nested `{"toolCall": {"name": "...", "args": {...}}}` wrapper alongside flat hook payloads.

## [0.8.3] - 2026-11-10

### Added

- Added automatic `Unblock-File` (`Zone.Identifier` removal) and a live `cmd.exe /c` execution probe in `scripts/deploy_plugin.ps1` before writing `hooks.json`, automatically setting `"enabled": false` when Enterprise Active Directory `AppLocker` or `SRP` policies block `cmd.exe /c` hook execution so `PreToolUse` never aborts tool calls.
- Added `no-hardcoded-hosts-or-domains` (`detect_hardcoded_internal_unc`) in `crates/libredb-cognitive/src/guardrail.rs` to block internal `.local` Active Directory UNC FQDNs in source and test files.

### Changed

- Updated `scripts/deploy_plugin.ps1` to deploy the native `libredb.exe` PE binary directly into `~/.gemini/antigravity/bin/libredb.exe` (and remove any legacy `libredb.cmd` batch wrapper), avoiding Enterprise Active Directory `AppLocker` / `SRP` batch-script blocks in user profile directories and eliminating `cmd.exe` subprocess startup overhead.
- Upgraded `detect_network_path` in `crates/libredb-core/src/io.rs` to detect mapped SMB network drives (`Q:\...` resolving to `\\?\UNC\...`) for SMB-safe `sync_all()` durability without misclassifying local `\\?\C:\...` verbatim paths.

### Fixed

- Fixed `strip_verbatim_prefix` in `crates/libredb-cli/src/gitea.rs` to check `\\?\UNC\` (case-insensitively) and rewrite it to `\\<server>\<share>\...` before falling back to `\\?\`, resolving `os error 267` when `std::fs::canonicalize` resolves a mapped SMB network drive (`Q:\...`) to `\\?\UNC\<server>\<share>\...`.

## [0.8.2] - 2026-11-10

### Changed

- Routed all project-scoped CLI subcommands (`index-workspace`, `skeleton`, `impact`, `fim`, `batch`, `handoff`, `learn-assoc`, `learn-reflex`, and `compact`) in `crates/libredb-cli/src/main.rs` through `open_project_ldb_silent` (`open_or_auto_migrate`), and upgraded `open_or_auto_migrate` in `crates/libredb-bridge/src/lib.rs` to automatically import a sibling `.db` file even if an empty (`total_inodes == 0`) `.ldb` file was previously initialized.
- Added a `60`-second per-file coalescing window and `maybe_auto_compact` call in `record_working_set_edit` (`crates/libredb-cli/src/hooks.rs`) so consecutive `PreToolUse` `edit_file` operations on the same file do not append redundant `WorkingSet` delta commits.

### Fixed

- Tightened `is_protected_profile_dir` and `run_pre_invocation_hook` in `crates/libredb-cli/src/hooks.rs` to block all subdirectories inside `$TEMP` (`low.starts_with(&format!("{temp_trim}\\"))` and `\appdata\local\temp\`) from registering `workspace:<name>` entries in global `customizations.ldb`.

## [0.8.1] - 2026-11-10

### Added

- Added `LibreDb::maybe_auto_compact` in `crates/libredb-core/src/engine.rs` (invoked automatically after `SessionState::save` and `execute_atomic_batch`) so uncompacted delta tails exceeding `1 MiB` (or `512 KiB` with `>= 32` superseded Inodes) self-compact in the background without manual CLI intervention.
- Added `is_compaction_checkpoint_line` in `crates/libredb-cognitive/src/transcript.rs` to parse candidate `transcript.jsonl` JSON lines and verify `"type" == "CHECKPOINT"` (or a `USER_INPUT` summary step) rather than matching raw substrings inside model thinking or `read_file` tool outputs.

### Changed

- Upgraded `compact_with_options(true)` (`libredb compact <db.ldb> --prune`) in `crates/libredb-core/src/engine.rs` and `populate_cognitive_graph` in `crates/libredb-bridge/src/lib.rs` to normalize symbol file paths (`\` -> `/`), use canonical 2-part symbol keys (`{file_path}::{qualified_name}`), and filter out unreferenced R8/ProGuard obfuscated or legacy 3-part line-numbered `NodeKind::Symbol` bloat on `> 500`-symbol tables while keeping `sqlite_mirror::*` 100% lossless prior to `--prune`.
- Upgraded `HybridIndex` (`INDEX_FORMAT_VERSION = 3`) in `crates/libredb-index/src/lib.rs` to retain 100% of `word_postings` across full document bodies while capping body character `3-gram` extraction to the first `16` unique tokens (`len >= 4`, max `12` 3-grams/token), shrinking `sys::index_snapshot` in `customizations.ldb` by over `60%`.
- Decoupled `run_pre_invocation_hook` (`crates/libredb-cli/src/hooks.rs`) from global `customizations.ldb` on routine turns by storing the per-conversation `PreInvocation` deduplication cursor (`sys::pre_inv_dedup::{cid}`) inside `.agents/memory.ldb`, replacing the two `git.exe` subprocesses in `collect_git_telemetry_line` with a pure-Rust `.git/HEAD` and `.git/refs` reader (`< 0.1 ms`), supporting `transcriptPath` in hook payloads, and filtering `| done |`, `| completed |`, `| closed |`, and `| cancelled |` tasks from the `Active Task Board`.

### Fixed

- Fixed `OverlayBrain::pulse` (`crates/libredb-cognitive/src/overlay.rs`) to unconditionally synchronize `last_project_seq` after `SessionState::save` (including when `maybe_auto_compact` advances `commit_seq` by `2`).

## [0.8.0] - 2026-11-10

### Added

- Added native assembly/disassembly (`.asm`, `.s`, `.inc`, `.dis` supporting MASM/NASM/GAS/IDA/Ghidra `PROC .. ENDP`, sections, and non-local labels) and Markdown (`.md`, `.markdown`, `.mdx` ATX `#`..`####` sections ignoring fenced code blocks) contract extractors in `crates/libredb-cognitive/src/skeleton.rs`.
- Added single-transaction multi-file batch skeleton extraction (`FileSkeleton::index_or_get_cached_batch` in `crates/libredb-cognitive/src/skeleton.rs`, `Brain.skeleton_batch` in `crates/libredb-py/src/lib.rs`, and `files: [...]` + session-aware `Zero-Repeat Skeleton` deduplication in `libredb_code` in `crates/libredb-cli/src/mcp.rs`), replacing per-file `fsync` commits with a single `commit_batch`.
- Added `LibreDb::compact_with_options(prune_all_cold: bool)` and `LibreDb::deprecate_nodes` in `crates/libredb-core/src/engine.rs`, exposed via `libredb compact <db.ldb> [--prune]` and `Brain.compact(prune=False)`.

### Changed

- Upgraded `compute_gravity_plan` (`crates/libredb-core/src/gravity.rs`) and `compact_with_options` (`crates/libredb-core/src/engine.rs`) to garbage-collect all superseded system, cache, symbol, and telemetry extents (`sys::index_snapshot`, `session::*`, `skeleton::*`, `Symbol`, `QuotaEvent`, `TranscriptCursor`) and `2+` generation obsolete nodes while retaining `1-hop` `EdgeKind::Supersedes` history for active knowledge capsules (`Rule`, `Skill`, `Decision`, `Fact`, `Task`), and stripping dangling synapses to pruned nodes.
- Added `is_indexable_cognitive_node` and `INDEX_FORMAT_VERSION = 2` in `crates/libredb-index/src/lib.rs` plus `LibreDb::match_active_keys_by_kind` in `crates/libredb-core/src/engine.rs` so non-prose nodes (`Symbol`, `QuotaEvent`, `TranscriptCursor`, `WorkingSet`, `Generic`) no longer bloat the `BM25` + `3-gram` `sys::index_snapshot`.
- Updated `modernize_global_db` (`crates/libredb-cli/src/main.rs`) to purge legacy SQLite `QuotaEvent`, `TranscriptCursor`, and `sqlite_mirror::central` bloat nodes and run `compact_with_options(true)`.

## [0.7.2] - 2026-11-10

### Changed

- Replaced full-table `list_inodes(None, false)` cloning inside `CognitiveEngine::score_candidates_in_ram` (`crates/libredb-cognitive/src/lib.rs`) with `O(1)` `LibreDb::get_inode_meta` (`crates/libredb-core/src/engine.rs`) hash lookups over the `<= 24` lexical seeds and their 2-hop neighbors, and replaced full disk snapshot reloads in `CognitiveEngine::refresh_indices` with in-RAM `HybridIndex::reconcile_in_ram` (`crates/libredb-index/src/lib.rs`) - cutting warm multi-turn `pulse` latency on `54,780`-node databases (`Nova-Launcher`) by `10x` (from `157 ms/turn` down to `5-16 ms/turn`).
- Excluded internal cache and mirror prefixes (`skeleton::`, `session::`, `sqlite_row:`) in `is_internal_system_key` (`crates/libredb-index/src/lib.rs`) and tracked `SessionState::save` sequence increments in `OverlayBrain::pulse` (`crates/libredb-cognitive/src/overlay.rs`) so `FileSkeleton` caching and session state updates never trigger redundant index reconciliations.

## [0.7.1] - 2026-11-10

### Fixed

- Added automatic cross-process `sync_from_disk_if_changed` snapshot reload inside `OverlayBrain::open` (`crates/libredb-cognitive/src/overlay.rs`) and transparent extent-read retry in `LibreDb::get` and `LibreDb::get_many_coalesced` (`crates/libredb-core/src/engine.rs`) when another OS process (such as `libredb modernize-global`) executes `compact_with_gravity()` while `libredb-mcp` holds an older in-memory `SnapshotState`.

## [0.7.0] - 2026-11-10

### Added

- Provider-aware, multi-remote Git and release engine in `crates/libredb-cli/src/gitea.rs` (`libredb git-sync` / `git-release` / `git-init` aliases alongside `gitea-*` with `--remote <name>`, `--all-remotes`, and `--github` flags):
  - Never hijacks or overwrites an existing non-Gitea `origin` remote (`https://github.com/...`, GitLab, or enterprise Git); links local Gitea as a dedicated `gitea` remote when `origin` already points elsewhere.
  - Pre-commit and pre-release SemVer 2.0.0 tag-SHA immutability verification (`resolve_git_tag_commit` vs. `HEAD`), blocking unversioned code modifications onto an already tagged release unless `--allow-unversioned` is explicitly confirmed.
  - Automatic GitHub release and deliverable asset synchronization via `gh release` when pushing to a GitHub remote (`--github` or `--all-remotes`).
- Full 12+ language polyglot contract skeleton parser in `crates/libredb-cognitive/src/skeleton.rs` and centralized `has_project_root_marker` in `crates/libredb-cognitive/src/workspace.rs`:
  - Added dedicated extractors for Android Smali bytecode (`.class`, `.field`, `.method .. .end method`), SQL DDL (`CREATE TABLE/VIEW/FUNCTION/PROCEDURE/TRIGGER/INDEX`), PowerShell (`function`, `filter`, `class`, `enum`), POSIX shell functions, Go receiver methods, and typed C/C++/C#/Java/Kotlin/Dart/Swift class methods.
  - Unified project root detection across `hooks.rs`, `mcp.rs`, and `workspace.rs` covering Android (`apktool.yml`, `AndroidManifest.xml`, `build.gradle(.kts)`), C/C++ (`CMakeLists.txt`, `Makefile`), and .NET (`*.sln`, `*.csproj`).
- Added Keep a Changelog 1.1.0 format and duplicate-version validation (`changelog-duplicate-version`, `keep-a-changelog-format`) and hardcoded secret/private-key leak detection (`no-hardcoded-secrets`) in `crates/libredb-cognitive/src/guardrail.rs`.
- Added live `transcript.jsonl` workspace path inference (`infer_workspace_from_transcript`), `PreToolUse` `invoke_subagent(TypeName="research") -> Model="flash"` quota enforcement, and automatic `CRLF -> LF` / UTF-8 BOM normalization before file edits in `crates/libredb-cli/src/hooks.rs`.
- Codified the permanent candid architectural pushback rule (`rule:global::candid-architectural-pushback` and `reflex::candid-architectural-pushback`) across `AGENTS.md` and `customizations.ldb`.

### Fixed

- Removed the early `if invocation_num > 1 { return }` guard in `run_pre_invocation_hook` (`crates/libredb-cli/src/hooks.rs`) that prevented `sync_transcript_epoch` from detecting mid-session `<CONTEXT_SUMMARY>` (`CHECKPOINT`) compactions when `invocationNum > 1`; per-epoch deduplication is handled exclusively by `dedup_token` (`<workspace>@ep=<epoch>`).

### Security

- Fixed a credential-routing flaw in `crates/libredb-cli/src/gitea.rs` (`GiteaConfig::git_auth_args_for_remote`): transient `Authorization: Basic` Gitea headers are now attached strictly when the target remote URL matches the configured local Gitea host, preventing local Gitea tokens from ever being sent to GitHub or external Git servers.

## [0.6.2] - 2026-11-10

### Fixed

- Updated `scripts/deploy_plugin.ps1` to hot-swap `libredb.exe` via `Install-BinaryHotSafe` (`Move-Item` to `.old`) without terminating the active `libredb-mcp` stdio process, and to run `libredb modernize-global` directly in-place on `customizations.ldb` using `LibreDB`'s IPC writer lock so live MCP sessions never disconnect during upgrades.

## [0.6.1] - 2026-11-10

### Fixed

- Fixed YAML frontmatter parsing in `sync_skill_markdown` (`crates/libredb-cli/src/main.rs`) to support folded and block multi-line `description:` scalars (`>-`, `>`, `|`, `|-`) so `skill:global::libredb` indexes its full summary text instead of the raw scalar marker.
- Updated `PulseResponse::format_compact` in `crates/libredb-cognitive/src/lib.rs` to automatically prefix fired reflex directives with `[REFLEX <id>]: ` when not already prefixed.

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
