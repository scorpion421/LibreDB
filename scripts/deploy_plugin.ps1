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
    Unblock-File -Path $Src -ErrorAction SilentlyContinue
    if (Test-Path $Dst) {
        $OldPath = "$Dst.old"
        if (Test-Path $OldPath) {
            Remove-Item $OldPath -Force -ErrorAction SilentlyContinue
        }
        try {
            Copy-Item $Src $Dst -Force
            Unblock-File -Path $Dst -ErrorAction SilentlyContinue
            return
        } catch {
            Move-Item $Dst $OldPath -Force
        }
    }
    Copy-Item $Src $Dst -Force
    Unblock-File -Path $Dst -ErrorAction SilentlyContinue
}

$TargetExe = Join-Path $BinDir "libredb.exe"
Install-BinaryHotSafe -Src $ReleaseExe -Dst $TargetExe
if (Test-Path $ReleaseDll) {
    Install-BinaryHotSafe -Src $ReleaseDll -Dst (Join-Path $BinDir "libredb.pyd")
}

# Install native `libredb.exe` PE binary directly into `~/.gemini/antigravity/bin` (and any user PATH shim dir)
# instead of a `.cmd` batch wrapper, avoiding Enterprise AppLocker/SRP script blocks and `cmd.exe` spawn overhead.
$TargetPathDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$DefaultAgyBin = Join-Path $GeminiDir "antigravity\bin"
[void]$TargetPathDirs.Add($DefaultAgyBin)
$SkillsDbCmd = Get-Command skillsdb -ErrorAction SilentlyContinue
if ($SkillsDbCmd -and $SkillsDbCmd.Source) {
    $ShimDir = Split-Path -Parent $SkillsDbCmd.Source
    if ($ShimDir.StartsWith($UserHome, [System.StringComparison]::OrdinalIgnoreCase)) {
        [void]$TargetPathDirs.Add($ShimDir)
    }
}
foreach ($PathDir in $TargetPathDirs) {
    New-Item -ItemType Directory -Force -Path $PathDir | Out-Null
    $LegacyCmdShim = Join-Path $PathDir "libredb.cmd"
    if (Test-Path $LegacyCmdShim) {
        Remove-Item $LegacyCmdShim -Force -ErrorAction SilentlyContinue
    }
    $DirectExePath = Join-Path $PathDir "libredb.exe"
    if (-not $DirectExePath.Equals($TargetExe, [System.StringComparison]::OrdinalIgnoreCase)) {
        Install-BinaryHotSafe -Src $ReleaseExe -Dst $DirectExePath
        Write-Output "[OK] Installed native PATH CLI binary at: $DirectExePath"
    }
}

# Seed ~/.gemini/libredb/customizations.ldb on first install; update in-place via transactional IPC lock afterwards
$CentralSqlite = Join-Path $GeminiDir "database\customizations.db"
$GlobalLdb = Join-Path $LibreHome "customizations.ldb"
if ((-not (Test-Path $GlobalLdb)) -and (Test-Path $CentralSqlite)) {
    & $TargetExe import-sqlite $GlobalLdb $CentralSqlite --scope central
}

$ExeForward = $TargetExe.Replace('\', '/')
$GlobalForward = $GlobalLdb.Replace('\', '/')
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# 1. Write plugin.json (strictly adhering to Antigravity plugin manifest schema)
$PluginJson = @'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "0.8.3",
  "description": "Full Rust replacement for SQLite SkillsDB: single-file cognitive memory, silent SQLite auto-porter, sub-2ms hooks, guardrails, 14-language causal code graph, and dynamic multi-remote Git/Gitea automation.",
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

# 3. Write hooks.json with Enterprise GPO / AppLocker & Zone.Identifier self-probe
# Note: Antigravity executes hooks via Go `exec.Command("cmd", "/C", cmd)`. On Enterprise AD workstations
# where AppLocker/SRP blocks `cmd.exe /c` from launching binaries in `%USERPROFILE%`, a failing PreToolUse
# hook would abort every tool call. We probe `cmd.exe /c` first and disable hooks automatically if blocked.
$HookExeCandidates = @(
    "%USERPROFILE%\.gemini\libredb\bin\libredb.exe",
    "%USERPROFILE%\.gemini\antigravity\bin\libredb.exe"
)
$VerifiedHookCmd = $null
foreach ($CandCmd in $HookExeCandidates) {
    try {
        $ProbeOut = "{}" | & $env:ComSpec /d /c "$CandCmd hook-pre-invocation" 2>$null
        if ($LASTEXITCODE -eq 0 -and ($ProbeOut -join "") -match "injectSteps") {
            $VerifiedHookCmd = $CandCmd
            break
        }
    } catch {
    }
}

if ($null -ne $VerifiedHookCmd) {
    $VerifiedEscaped = $VerifiedHookCmd.Replace('\', '\\')
    $HooksJson = @"
{
  "libredb-autonomous-memory": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "$VerifiedEscaped hook-pre-invocation",
        "timeout": 5
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|invoke_subagent|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "$VerifiedEscaped hook-pre-tool",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
"@
    [System.IO.File]::WriteAllText((Join-Path $PluginDir "hooks.json"), $HooksJson, $Utf8NoBom)
    Write-Output "[OK] Verified cmd.exe hook execution and enabled hooks.json via: $VerifiedHookCmd"
} else {
    $DisabledHooksJson = @'
{
  "libredb-autonomous-memory": {
    "enabled": false
  }
}
'@
    [System.IO.File]::WriteAllText((Join-Path $PluginDir "hooks.json"), $DisabledHooksJson, $Utf8NoBom)
    Write-Output "[WARN] Enterprise GPO/AppLocker blocked cmd.exe /c hook execution; set enabled=false in hooks.json so tool calls are never blocked."
}

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
   - **Candid architectural pushback (zero sugarcoating)**: When the user's idea or direction in a coding project shoots past the target, introduces unnecessary complexity, hardcodes a fragile pattern, or is technically suboptimal, tell the user directly that it is wrong or suboptimal and propose the better engineering approach immediately. Never hold back technical critique out of personal consideration.

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
   - **Dynamic Git & Gitea sync**: Use `libredb git-init "<dir>"` (`gitea-init`), `libredb git-sync -m "<msg>" --project "<dir>" [--remote <r>] [--all-remotes] [--github] [--releases]` (`gitea-sync`), `libredb git-release [vX.Y.Z] --project "<dir>" [--all-remotes] [--github]` (`gitea-release`), and `libredb gitea-status`. Existing non-Gitea `origin` remotes are never hijacked, and Gitea Basic Auth headers are sent exclusively to the configured Gitea host. Ask confirmation before `--allow-unversioned` ("Soll ich das wirklich ohne Versionierung hochladen?") and pause on `[GITEA REPOSITORY COLLISION]` (`--use-existing`, `--name`, or `--overwrite`). Format Gitea/GitHub URLs as clickable links `[Label](url)`.

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
2. **`libredb_code`** (`action`: `"index"` | `"skeleton"` | `"impact"` | `"fim"`, `target`, `files`, `cwd`, `cid`, `force`, `symbol`, `line`, `pad`):
   - `"index"`: Incrementally scans all non-binary source files in `target`, wiring `Calls` and `Decision -> Governs -> Symbol` synapses.
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a single `target` file or a multi-file batch (`files: [...]`) across 14+ languages (including `.smali`, `.asm`, and `.md`) with session-aware `[Zero-Repeat Skeleton]` deduplication (`cid`).
   - `"impact"`: Returns bidirectional callers, callees, and governing architectural decisions for a symbol.
   - `"fim"`: Returns a surgical `[Lstart-Lend]` edit slice with blast-radius callers and governing decisions attached.
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `sync_central_sqlite`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, or situational pitfall reflexes.

## CLI commands (`libredb`)

- **Guardrails:** `libredb guardrail check --path "<dir>" [--staged] [--strict]`
- **Compaction & GC:** `libredb compact <db.ldb> [--prune]`
- **Rules, skills & reflexes:**
  - `libredb get-skill <skill_name> [--section "<Section Title>"]`
  - `libredb sync-skill <SKILL.md> [--name <skill_name>]`
  - `libredb list-rules`, `libredb list-skills`, `libredb list-reflexes`
  - `libredb modernize-global`
- **Dynamic Git & Gitea workflow:**
  - `libredb gitea-status`
  - `libredb git-init "<dir>" [--name <repo>] [--use-existing] [--overwrite]` (alias: `gitea-init`)
  - `libredb git-sync -m "<commit message>" --project "<dir>" [--remote <r>] [--all-remotes] [--github] [--releases] [--allow-unversioned]` (alias: `gitea-sync`)
  - `libredb git-release [vX.Y.Z] --project "<dir>" [--remote <r>] [--all-remotes] [--github]` (alias: `gitea-release`)
  - `libredb gitea-config [--url <u>] [--user <usr>] [--token <tok>] [--register-helper]`
'@
$SkillMdPath = Join-Path $SkillDir "SKILL.md"
[System.IO.File]::WriteAllText($SkillMdPath, $SkillMd, $Utf8NoBom)

# Modernize global DB in-place via LibreDB IPC writer lock (zero handle invalidation for running MCP server)
& $TargetExe modernize-global --global $GlobalLdb --skill-md $SkillMdPath

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
# LibreDB cognitive memory plugin (v0.8.3)

Complete standalone Rust replacement for `AntiGraviton SkillsDB` (`customizations-db`):
- `libredb-mcp`: 3-tool multi-workspace cognitive memory & 14-language causal code-graph server with zero-I/O RAM session delta, `[Zero-Repeat Skeleton]` deduplication, and automatic incremental workspace refresh.
- Compaction garbage collection (`compact_with_options`, `maybe_auto_compact`) and `INDEX_FORMAT_VERSION = 3` selective cognitive `HybridIndex`.
- Silent background 1:1 auto-migration for any pre-existing `.agents/memory.db` in older projects or chats; pure `.ldb` operation for all new projects and chats.
- Native compiled `< 2 ms` `PreInvocation` and `PreToolUse` guardrail hooks (`hooks.json`) with post-compaction epoch hydration, live `transcript.jsonl` workspace inference, `research -> flash` subagent routing, and `CRLF`/BOM normalization.
- Global system directives (`rules/AGENTS.md`) and dynamic multi-remote Git/Gitea release automation (`libredb git-sync` / `git-release` & `gitea-sync` / `gitea-release`).

To switch cleanly to pure single-engine operation, disable `AntiGraviton SkillsDB` (`customizations-db`) in Customizations and leave `LibreDB Cognitive Memory` (`libredb`) enabled.
'@
[System.IO.File]::WriteAllText((Join-Path $PluginDir "README.md"), $PluginReadme, $Utf8NoBom)

# 8. Ensure "libredb": { "enabled": true } in ~/.gemini/config/config.json if present
$AgyConfigPath = Join-Path $GeminiDir "config\config.json"
if (Test-Path $AgyConfigPath) {
    try {
        $CfgObj = Get-Content $AgyConfigPath -Raw | ConvertFrom-Json
        if ($null -ne $CfgObj.plugins) {
            if ($null -eq $CfgObj.plugins.PSObject.Properties["libredb"]) {
                $CfgObj.plugins | Add-Member -NotePropertyName "libredb" -NotePropertyValue ([PSCustomObject]@{ enabled = $true })
            } else {
                $CfgObj.plugins.libredb.enabled = $true
            }
            $CfgJson = $CfgObj | ConvertTo-Json -Depth 20
            [System.IO.File]::WriteAllText($AgyConfigPath, $CfgJson, $Utf8NoBom)
        }
    } catch {
        Write-Output "[WARN] Could not auto-update config.json plugin state: $_"
    }
}

Write-Output "[OK] Deployed LibreDB v0.8.3 standalone binaries to: $BinDir"
Write-Output "[OK] Hydrated and modernized global 19-table store at: $GlobalLdb"
Write-Output "[OK] Installed complete Antigravity replacement plugin at: $PluginDir"
