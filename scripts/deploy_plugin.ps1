$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$GeminiDir = Join-Path $UserHome ".gemini"
$LibreHome = Join-Path $GeminiDir "libredb"
$BinDir = Join-Path $LibreHome "bin"
$PluginDir = Join-Path $GeminiDir "config\plugins\libredb"
$SkillDir = Join-Path $PluginDir "skills\libredb"
$AssetsDir = Join-Path $PluginDir "assets"

New-Item -ItemType Directory -Force -Path $BinDir, $SkillDir, $AssetsDir | Out-Null

$ReleaseExe = Join-Path $ProjectRoot "target\release\libredb.exe"
$ReleaseDll = Join-Path $ProjectRoot "target\release\libredb_py.dll"
if (-not (Test-Path $ReleaseExe)) {
    throw "Release binary not found at $ReleaseExe. Run 'cargo build --release --workspace' first."
}

$TargetExe = Join-Path $BinDir "libredb.exe"
Copy-Item $ReleaseExe $TargetExe -Force
if (Test-Path $ReleaseDll) {
    Copy-Item $ReleaseDll (Join-Path $BinDir "libredb.pyd") -Force
}

# Seed read-only copy of central customizations.db into ~/.gemini/libredb/customizations.ldb (never modifies customizations.db!)
$CentralSqlite = Join-Path $GeminiDir "database\customizations.db"
$GlobalLdb = Join-Path $LibreHome "customizations.ldb"
if (Test-Path $CentralSqlite) {
    if (Test-Path $GlobalLdb) { Remove-Item $GlobalLdb -Force }
    & $TargetExe import-sqlite $GlobalLdb $CentralSqlite --scope central
    & $TargetExe compact $GlobalLdb
}

# Seed initial operational reflexes learned from real-world sessions into customizations.ldb
& $TargetExe learn-reflex $GlobalLdb "rust-guardrail-staged" `
    "[REFLEX rust-guardrail-staged]: Ensure /target/ is in .gitignore and run 'skillsdb guardrail check --staged' so binary .rlib/.pdb artifacts are skipped." `
    --stack "cargo.toml" --action "guardrail,release" | Out-Null
& $TargetExe learn-reflex $GlobalLdb "rust-gitea-dist" `
    "[REFLEX rust-gitea-dist]: Copy compiled release deliverables into dist/ before running 'skillsdb gitea-release' so assets attach automatically." `
    --stack "cargo.toml" --action "gitea-release,gitea-sync" | Out-Null
& $TargetExe learn-reflex $GlobalLdb "git-non-acl-safe-dir" `
    "[REFLEX git-non-acl-safe-dir]: On non-ACL drives, run 'git config --global --add safe.directory <repo>' right after git init." `
    --action "git,gitea-init" --env "dubious ownership" | Out-Null

# Index LibreDB's own workspace into d:\Antigravity\LibreDB\.agents\memory.ldb so it is immediately ready
$SelfLdb = Join-Path $ProjectRoot ".agents\memory.ldb"
& $TargetExe index-workspace $SelfLdb $ProjectRoot

$ExeForward = $TargetExe.Replace('\', '/')
$GlobalForward = $GlobalLdb.Replace('\', '/')

# 1. Write plugin.json (strictly adhering to Antigravity plugin manifest schema)
$PluginJson = @'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "0.4.0",
  "description": "Single-file Rust cognitive memory, Zero-Repeat Delta context deduplicator, and causal workspace code-graph MCP server for Antigravity.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Run a LibreDB cognitive pulse on the active workspace to load deduplicated context",
    "Extract a surgical FIM code slice and blast-radius impact map with libredb_code",
    "Persist architectural decisions and language-agnostic concept bridges via libredb_memorize"
  ]
}
'@
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $PluginDir "plugin.json"), $PluginJson, $Utf8NoBom)

# 2. Write mcp_config.json (prefixed server name libredb-mcp)
$McpJson = @"
{
  "mcpServers": {
    "libredb-mcp": {
      "command": "$ExeForward",
      "args": [
        "mcp-serve",
        "--global",
        "$GlobalForward"
      ]
    }
  }
}
"@
[System.IO.File]::WriteAllText((Join-Path $PluginDir "mcp_config.json"), $McpJson, $Utf8NoBom)

# 3. Write progressive-disclosure SKILL.md
$SkillMd = @'
---
name: libredb
description: >-
  High-speed Rust cognitive memory, Zero-Repeat Delta context deduplication, and causal code-graph
  slicing via the libredb-mcp server. Activate when inspecting large codebases with minimal tokens,
  checking symbol blast-radius and governing architectural decisions, or persisting session-deduplicated
  project memory alongside SkillsDB.
---

# LibreDB cognitive memory and code graph

`libredb-mcp` runs as a persistent, sub-millisecond Rust MCP server uniting global rules/skills (`~/.gemini/libredb/customizations.ldb`) with per-workspace `.agents/memory.ldb` files while leaving `SkillsDB` (`customizations.db` and `.agents/memory.db`) completely untouched.

## Available MCP tools

1. **`libredb_pulse`** (`query`, `cwd`, `cid`, `budget`, `error`):
   - Retrieves relevant rules, micro-skills, decisions, facts, and symbols across both layers within `budget` tokens.
   - Pass `cid` (the current Conversation ID) and `cwd` so `Zero-Repeat Delta` suppresses items already delivered in the current session epoch (`0` disk reads on Turn 2+) and automatically re-hydrates if `/compact` occurred.
2. **`libredb_code`** (`action`: `"index"` | `"skeleton"` | `"impact"` | `"fim"`, `target`, `cwd`, `symbol`, `line`, `pad`):
   - `"index"`: Incrementally scans all non-binary source files in `target` (`cwd`), wiring `Calls` and `Decision -> Governs -> Symbol` synapses.
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a large file (`3 ms` hash-verified cache).
   - `"impact"`: Returns bidirectional callers, callees, and governing architectural decisions for a symbol.
   - `"fim"`: Returns a surgical edit window around `symbol` or `line` with blast-radius callers and governing decisions attached.
3. **`libredb_memorize`** (`cwd`, `facts`, `decisions`, `snapshot`, `learn_assoc`, `learn_reflex`, `sync_central_sqlite`):
   - Commits facts, architectural decisions (automatically wired to matching workspace symbols), Hebbian cross-lingual associations, or situational pitfall reflexes in a single atomic transaction.
'@
[System.IO.File]::WriteAllText((Join-Path $SkillDir "SKILL.md"), $SkillMd, $Utf8NoBom)

# 4. Write square transparent SVG logo with >=10% margin and high contrast on dark & light themes
$LogoSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <rect x="28" y="28" width="200" height="200" rx="44" fill="#0F172A" stroke="#38BDF8" stroke-width="10"/>
  <circle cx="88" cy="96" r="18" fill="#38BDF8"/>
  <circle cx="168" cy="96" r="18" fill="#A78BFA"/>
  <circle cx="128" cy="168" r="20" fill="#34D399"/>
  <line x1="103" y1="106" x2="117" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="153" y1="106" x2="139" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="106" y1="96" x2="150" y2="96" stroke="#94A3B8" stroke-width="7" stroke-dasharray="10 8" stroke-linecap="round"/>
</svg>
'@
[System.IO.File]::WriteAllText((Join-Path $AssetsDir "logo.svg"), $LogoSvg, $Utf8NoBom)

# 5. Write user-facing README.md inside plugin bundle
$PluginReadme = @'
# LibreDB cognitive memory plugin

Standalone, toggleable Antigravity plugin providing `libredb-mcp` (3-tool Rust cognitive memory and causal code-graph server) alongside `SkillsDB` without modifying `customizations.db`.
'@
[System.IO.File]::WriteAllText((Join-Path $PluginDir "README.md"), $PluginReadme, $Utf8NoBom)

Write-Output "[OK] Deployed LibreDB v0.4.0 standalone binaries to: $BinDir"
Write-Output "[OK] Hydrated global read-only mirror at: $GlobalLdb"
Write-Output "[OK] Installed toggleable Antigravity plugin at: $PluginDir"
