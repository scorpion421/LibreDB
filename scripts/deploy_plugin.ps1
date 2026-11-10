$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$GeminiDir = Join-Path $UserHome ".gemini"
$LibreHome = Join-Path $GeminiDir "libredb"
$BinDir = Join-Path $LibreHome "bin"
$PluginDir = Join-Path $GeminiDir "config\plugins\libredb"
$RulesDir = Join-Path $PluginDir "rules"
$SkillDir = Join-Path $PluginDir "skills\libredb"
$AssetsDir = Join-Path $PluginDir "assets"

New-Item -ItemType Directory -Force -Path $BinDir, $RulesDir, $SkillDir, $AssetsDir | Out-Null

$ReleaseExe = Join-Path $ProjectRoot "target\release\libredb.exe"
$ReleaseDll = Join-Path $ProjectRoot "target\release\libredb_py.dll"
if (-not (Test-Path $ReleaseExe)) {
    throw "Release binary not found at $ReleaseExe. Run 'cargo build --release --workspace' first."
}

function Install-BinaryHotSafe {
    param([string]$Src, [string]$Dst)
    if (Test-Path $Dst) {
        $OldPath = "$Dst.old"
        if (Test-Path $OldPath) {
            Remove-Item $OldPath -Force -ErrorAction SilentlyContinue
        }
        try {
            Copy-Item $Src $Dst -Force
            return
        } catch {
            Move-Item $Dst $OldPath -Force
        }
    }
    Copy-Item $Src $Dst -Force
}

$TargetExe = Join-Path $BinDir "libredb.exe"
Get-Process libredb -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 150
Install-BinaryHotSafe -Src $ReleaseExe -Dst $TargetExe
if (Test-Path $ReleaseDll) {
    Install-BinaryHotSafe -Src $ReleaseDll -Dst (Join-Path $BinDir "libredb.pyd")
}

# Install a lightweight `libredb.cmd` shim into the same user PATH directory as `skillsdb` (if writable inside USERPROFILE)
$SkillsDbCmd = Get-Command skillsdb -ErrorAction SilentlyContinue
if ($SkillsDbCmd -and $SkillsDbCmd.Source) {
    $ShimDir = Split-Path -Parent $SkillsDbCmd.Source
    if ($ShimDir.StartsWith($UserHome, [System.StringComparison]::OrdinalIgnoreCase)) {
        $ShimPath = Join-Path $ShimDir "libredb.cmd"
        $ShimBody = "@echo off`r`n`"$TargetExe`" %*`r`n"
        [System.IO.File]::WriteAllText($ShimPath, $ShimBody, [System.Text.Encoding]::ASCII)
        Write-Output "[OK] Installed PATH CLI shim at: $ShimPath"
    }
}

# Seed or update ~/.gemini/libredb/customizations.ldb without ever overwriting live additions from old SQLite
$CentralSqlite = Join-Path $GeminiDir "database\customizations.db"
$GlobalLdb = Join-Path $LibreHome "customizations.ldb"
$StagingLdb = "$GlobalLdb.staging"
if (Test-Path $StagingLdb) { Remove-Item $StagingLdb -Force }
if (Test-Path $GlobalLdb) {
    Copy-Item $GlobalLdb $StagingLdb -Force
} elseif (Test-Path $CentralSqlite) {
    & $TargetExe import-sqlite $StagingLdb $CentralSqlite --scope central
}

$ExeForward = $TargetExe.Replace('\', '/')
$GlobalForward = $GlobalLdb.Replace('\', '/')
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# 1. Write plugin.json (strictly adhering to Antigravity plugin manifest schema)
$PluginJson = @'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "0.6.1",
  "description": "Full Rust replacement for SQLite SkillsDB: single-file cognitive memory, silent SQLite auto-porter, sub-2ms hooks, guardrails, causal code graph, and local Gitea automation.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Run a LibreDB cognitive pulse on the active workspace to load deduplicated context",
    "Check local Gitea status and run a strict LibreDB guardrail audit on the workspace",
    "Extract a surgical FIM code slice and blast-radius impact map with libredb_code"
  ]
}
'@
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

# 3. Write hooks.json (native compiled <2ms Rust PreInvocation and PreToolUse hooks)
# Note: Never put inner quotes in Windows hooks.json commands because Go exec.Command("cmd", "/C", cmd)
# escapes quotes as \" which cmd.exe rejects; unquoted %USERPROFILE%\... executes natively.
$HooksJson = @'
{
  "libredb-autonomous-memory": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "%USERPROFILE%\\.gemini\\libredb\\bin\\libredb.exe hook-pre-invocation",
        "timeout": 5
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "%USERPROFILE%\\.gemini\\libredb\\bin\\libredb.exe hook-pre-tool",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
'@
[System.IO.File]::WriteAllText((Join-Path $PluginDir "hooks.json"), $HooksJson, $Utf8NoBom)

# 4. Write rules/AGENTS.md (preserving 100% of all 7 global user directives, powered natively by LibreDB)
$AgentsMd = @'
# Central LibreDB rules directive

All system rules, coding standards, administrative credentials, and skills are maintained in `~/.gemini/libredb/customizations.ldb` (with automatic silent 1:1 background migration from any pre-existing `.db` files). Adhere to these active global rules with HIGHEST PRIORITY:

1. **Global output formatting invariant (strict enforcement across all operations)**:
   - **No em-dashes or en-dashes**: Never output em-dashes (U+2014) or en-dashes (U+2013) in chat, markdown, code comments, commit messages, or artifacts. Use standard ASCII hyphens (`-`), colons (`:`), or parentheses.
   - **No emojis**: Never output emojis, smileys, or decorative Unicode symbols.
   - **Sentence case for headings and labels**: Use natural sentence case for headings, subheadings, and bold bullet labels (capitalize only the first word and proper nouns/acronyms like `GitHub`, `Gitea`, `LibreDB`, `SkillsDB`, `SQLite`, `JSONL`, `UTF-8`, `API`, `CLI`, `IDE`, `MCP`). Never use Title Case.

2. **Conversational communication and writing standards**:
   - Always use informal German ("Du" / "Dein" for the user, "wir" / "unser" for joint work; strictly NEVER formal "Sie" or plural "Ihr" / "Euer" / "Euch").
   - Use natural German spelling including umlauts (__UMLAUT_LIST__).
   - **German compound nouns (strictly no Deppenbindestriche)**: Always write German compound nouns (Komposita) as a single joined word (e.g., "Abteilungskontingent" never "Abteilungs-Kontingent", "Browsertool" never "Browser-Tool", "Tabwechsel" never "Tab-Wechsel", "Standardeinstellung" never "Standard-Einstellung", "Kontextkompaktierung" never "Kontext-Kompaktierung", "Subagentenisolation" never "Subagenten-Isolation", "Tokenreduktion" never "Token-Reduktion", "__TOKEN_OEKONOMIE__" never "__TOKEN_OEKONOMIE_BAD__").

3. **Coding and scripting standards (strict language separation, SemVer 2.0.0, and Keep a Changelog 1.1.0)**:
   - **Language boundary (zero exceptions)**: All code, comments, console outputs, logs, UI labels, buttons, dialogs, error strings, and commit messages MUST be in grammatically correct English (ASCII only). Never translate UI strings to German.
   - **Strict Semantic Versioning (SemVer 2.0.0) and Keep a Changelog 1.1.0**: Version projects according to https://semver.org/ (`MAJOR.MINOR.PATCH`) and https://keepachangelog.com/en/1.1.0/. Never overwrite an already published release version in place; increment the version, document changes in `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD` (`### Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`, `### Security`), and publish matching Git tags and Releases (`libredb gitea-sync -m "<msg>" --project "<dir>" --releases` and `libredb gitea-release vX.Y.Z --project "<dir>"`). Place built deliverable artifacts (`.apk`, `.aab`, `.exe`, `.msi`, `.xpi`, `.vsix`, `.whl`, `.jar`, `.zip`) in `dist/` or `releases/` so they attach automatically.
   - **Authoring & scripting hygiene**: Author commits as `Antigravity <antigravity@local.dev>`. Strictly no VBScript (`.vbs`, `cscript`, `wscript`).
   - **Standardized 9-block `README.md` blueprint**: (1) `# Title`, (2) clickable Shields.io badges (`Version` -> `CHANGELOG.md`, `Tests` -> `tests/`, tech stack, `License` -> `LICENSE` `AGPLv3 + Commons Clause`), (3) 1-3 sentence summary, (4) `## Table of contents`, (5) executive summary & impact table, (6) installation & quickstart, (7) usage & commands, (8) architecture & ASCII tree (`|--`), (9) SemVer 2.0.0 & license.

4. **Admin elevation and 100% transparent IT audit standard (`C:\IT_ADMIN_LOGS\<USERNAME>\<TASK>\<TARGET>\<Date>\<hh_mm_ss>\`)**:
   - Execute admin tasks directly if elevated, via optional DPAPI credentials (`~/.gemini/config/credentials/*.credential.xml`), or `Start-Process -Verb RunAs`.
   - **SOC-compliant transparent administration**: Never stage in `C:\Windows\Temp`, never use cryptic names or `cmd.exe /c` wrappers, never create remote services via `sc.exe \\`, and never hardcode usernames, hosts, or domains. After user approval, use `C:\IT_ADMIN_LOGS\<USERNAME>\<TASK>\<TARGET>\<Date>\<hh_mm_ss>\` and task folder `\IT_ADMIN_LOGS\<USERNAME>\` with a live-queried `AuditLog_<Target>_<Date>_<hh_mm_ss>.log` (`[1/4 PRE-CHECK]`, `[2/4..3/4 ACTION]`, `[4/4 POST-CHECK]`, `[CLEANUP]`).

5. **Turn-economy, diagnostic protocol, and context hygiene**:
   - **Anti-salami-slicing & symbol lookup**: Read files `<= 800 lines` in a single `read_file` call. For files `> 800 lines`, inspect exact contract spans and edit slices first via `libredb_code` (`action="skeleton"`, `"fim"`, or `"impact"` on `libredb-mcp`) and batch `read_file` calls in parallel.
   - **Subagent firewall**: Run targeted edits (1-3 files) and host/WMI/CIM admin commands directly in main context. Delegate open-ended codebase exploration (`>= 4` searches or `> 5` files) to a `research` subagent (`Model="flash"`).
   - **Cluster-fix, batching, and zero-polling**: Search for all occurrences of a bug class before rebuilding, chain `build && test && verify`, use `libredb_memorize` to combine facts, decisions, tasks, and snapshots in one atomic call, verify formatting via `libredb guardrail check --path "<dir>" --staged --strict`, and set `WaitMsBeforeAsync=10000` (never poll `manage_task status`). Append a brief note at the end of your response if an internal tool needed a workaround.

6. **Autonomous project memory, silent SQLite migration, Gitea sync, and knowledge protocol (pure Pull)**:
   - Persist facts, architectural decisions, tasks, snapshots, Hebbian associations, and situational reflexes in `.agents/memory.ldb` via `libredb_memorize` (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`). Any pre-existing `.agents/memory.db` in an older project or chat is automatically and silently migrated 1:1 into `.agents/memory.ldb` on first access, while new projects and chats use `.agents/memory.ldb` exclusively.
   - Recall deduplicated rules, domain micro-skills, decisions, and facts on demand via `libredb_pulse` (`query`, `cwd`, `cid`, `budget`) or `libredb get-skill <name> [--section "<Section>"]`.
   - **Gitea sync**: Use `libredb gitea-init "<dir>"`, `libredb gitea-sync -m "<msg>" --project "<dir>" [--releases]`, `libredb gitea-release [vX.Y.Z] --project "<dir>"`, and `libredb gitea-status`. Ask confirmation before `--allow-unversioned` ("Soll ich das wirklich ohne Versionierung hochladen?") and pause on `[GITEA REPOSITORY COLLISION]` (`--use-existing`, `--name`, or `--overwrite`). Format Gitea/GitHub URLs as clickable links `[Label](url)`.

7. **Model & concurrency catalog (pure Pull, zero background control plane)**:
   - Supports `ultra` (16 parallel reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, and `GPT-OSS 120B`. Keep 100% of code generation on `Gemini 4 Argon` or `Claude 5.5`; route only read-only `research` subagents to `Model="flash"`.
'@
$UmlautList = "$([char]0x00E4), $([char]0x00F6), $([char]0x00FC), $([char]0x00DF)"
$TokenOek = "Token$([char]0x00F6)konomie"
$TokenOekBad = "Token-$([char]0x00D6)konomie"
$AgentsMd = $AgentsMd.Replace("__UMLAUT_LIST__", $UmlautList).Replace("__TOKEN_OEKONOMIE__", $TokenOek).Replace("__TOKEN_OEKONOMIE_BAD__", $TokenOekBad)
[System.IO.File]::WriteAllText((Join-Path $RulesDir "AGENTS.md"), $AgentsMd, $Utf8NoBom)

# 5. Write progressive-disclosure SKILL.md
$SkillMd = @'
---
name: libredb
description: >-
  Primary Rust cognitive memory, silent SQLite auto-porter, Zero-Repeat Delta context deduplicator,
  guardrail scanner, causal code-graph slicer, and local Gitea release engine for Antigravity.
  Activate whenever recalling rules or skills, inspecting large files, persisting project memory,
  checking guardrails, or syncing repositories and releases to local Gitea.
---

# LibreDB cognitive memory, code graph, and Gitea suite

`LibreDB` unites global customizations (`~/.gemini/libredb/customizations.ldb`) and per-workspace/per-chat memory (`.agents/memory.ldb`) with native `< 2 ms` lifecycle hooks and zero-dependency Gitea automation. Pre-existing `.agents/memory.db` databases in older projects or chats are automatically migrated 1:1 into `.agents/memory.ldb` in the background on first touch; new projects and chats use `.agents/memory.ldb` exclusively.

## MCP tools (`libredb-mcp`)

1. **`libredb_pulse`** (`query`, `cwd`, `cid`, `budget`, `error`):
   - Retrieves relevant rules, micro-skills, decisions, facts, tasks, snapshots, and symbols across global + workspace layers within `budget` tokens.
   - Always pass `cid` (Conversation ID) and `cwd` so RAM-first `Zero-Repeat Delta` suppresses already-delivered items (`0` disk I/O reads on Turn 2+) and automatically re-hydrates after `/compact`.
2. **`libredb_code`** (`action`: `"index"` | `"skeleton"` | `"impact"` | `"fim"`, `target`, `cwd`, `symbol`, `line`, `pad`):
   - `"index"`: Incrementally scans all non-binary source files in `target`, wiring `Calls` and `Decision -> Governs -> Symbol` synapses.
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a large file (`> 800` lines).
   - `"impact"`: Returns bidirectional callers, callees, and governing architectural decisions for a symbol.
   - `"fim"`: Returns a surgical `[Lstart-Lend]` edit slice with blast-radius callers and governing decisions attached.
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `sync_central_sqlite`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, or situational pitfall reflexes.

## CLI commands (`libredb`)

- **Guardrails:** `libredb guardrail check --path "<dir>" [--staged] [--strict]`
- **Rules, skills & reflexes:**
  - `libredb get-skill <skill_name> [--section "<Section Title>"]`
  - `libredb sync-skill <SKILL.md> [--name <skill_name>]`
  - `libredb list-rules`, `libredb list-skills`, `libredb list-reflexes`
  - `libredb modernize-global`
- **Gitea workflow:**
  - `libredb gitea-status`
  - `libredb gitea-init "<dir>" [--name <repo>] [--use-existing] [--overwrite]`
  - `libredb gitea-sync -m "<commit message>" --project "<dir>" [--releases] [--allow-unversioned]`
  - `libredb gitea-release [vX.Y.Z] --project "<dir>"`
  - `libredb gitea-config [--url <u>] [--user <usr>] [--token <tok>] [--register-helper]`
'@
$SkillMdPath = Join-Path $SkillDir "SKILL.md"
[System.IO.File]::WriteAllText($SkillMdPath, $SkillMd, $Utf8NoBom)

# Modernize staging DB (deprecate legacy customizations-db skill, update rule texts to libredb, sync SKILL.md, seed 9 core reflexes, compact)
& $TargetExe modernize-global --global $StagingLdb --skill-md $SkillMdPath
Install-BinaryHotSafe -Src $StagingLdb -Dst $GlobalLdb
Remove-Item $StagingLdb -Force -ErrorAction SilentlyContinue

# Incrementally index LibreDB's own workspace into .agents/memory.ldb
$SelfLdb = Join-Path $ProjectRoot ".agents\memory.ldb"
try {
    & $TargetExe index-workspace $SelfLdb $ProjectRoot
} catch {
    Write-Output "[INFO] Workspace index skipped while older handle drains: $_"
}

# 6. Write square transparent SVG logo with >=10% margin and high contrast on dark & light themes
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

# 7. Write user-facing README.md inside plugin bundle
$PluginReadme = @'
# LibreDB cognitive memory plugin (v0.6.0)

Complete standalone Rust replacement for `AntiGraviton SkillsDB` (`customizations-db`):
- `libredb-mcp`: 3-tool multi-workspace cognitive memory & causal code-graph server with zero-I/O RAM session delta and automatic incremental workspace refresh.
- Silent background 1:1 auto-migration for any pre-existing `.agents/memory.db` in older projects or chats; pure `.ldb` operation for all new projects and chats.
- Native compiled `< 2 ms` `PreInvocation` and `PreToolUse` guardrail hooks (`hooks.json`).
- Global system directives (`rules/AGENTS.md`) and native local Gitea release automation (`libredb gitea-sync` / `gitea-release`).

To switch cleanly to pure single-engine operation, disable `AntiGraviton SkillsDB` (`customizations-db`) in Customizations and leave `LibreDB Cognitive Memory` (`libredb`) enabled.
'@
[System.IO.File]::WriteAllText((Join-Path $PluginDir "README.md"), $PluginReadme, $Utf8NoBom)

Write-Output "[OK] Deployed LibreDB v0.6.0 standalone binaries to: $BinDir"
Write-Output "[OK] Hydrated and modernized global 19-table store at: $GlobalLdb"
Write-Output "[OK] Installed complete Antigravity replacement plugin at: $PluginDir"
