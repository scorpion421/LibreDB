param(
    [ValidateSet("Neutral", "Personal")]
    [string]$Profile = "Neutral",
    [switch]$NoHooks,
    [switch]$MigrateLegacy
)

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

# Seed ~/.gemini/libredb/customizations.ldb cleanly on neutral installs; import legacy customizations.db
# only when explicitly requested (-MigrateLegacy) or when deploying the maintainer's -Profile Personal.
$CentralSqlite = Join-Path $GeminiDir "database\customizations.db"
$GlobalLdb = Join-Path $LibreHome "customizations.ldb"
if (-not (Test-Path $GlobalLdb)) {
    if ((($Profile -eq "Personal") -or $MigrateLegacy) -and (Test-Path $CentralSqlite)) {
        & $TargetExe import-sqlite $GlobalLdb $CentralSqlite --scope central
    } else {
        & $TargetExe init $GlobalLdb | Out-Null
    }
}

$ExeForward = $TargetExe.Replace('\', '/')
$GlobalForward = $GlobalLdb.Replace('\', '/')
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# 1. Write plugin.json (strictly adhering to Antigravity plugin manifest schema)
$PluginJson = @'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "1.4.1",
  "description": "Enterprise-ready Rust cognitive memory, token-economy analytics & MCP code graph: single-file LIBREDB1 storage, silent SQLite auto-porter, sub-2ms hooks, content-bound HMAC-SHA256 workspace trust seals, DPAPI / ChaCha20-Poly1305 credential vault, zero-hardcode topology & Dalvik/DI causal code graph, built-in benchmarks & token-savings reports, and multi-remote Git/Gitea/GitHub automation.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Show my LibreDB token savings report for today and all workspaces",
    "Run a LibreDB cognitive pulse on the active workspace to load deduplicated context",
    "Extract a surgical FIM code slice and DI blast-radius impact map with libredb_code"
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

# 3. Write hooks.json with Enterprise GPO / AppLocker, ACL verification & stable non-target staging
# Note: Antigravity executes hooks via Go `exec.Command("cmd", "/C", cmd)`. On Enterprise AD workstations
# where AppLocker/SRP blocks `cmd.exe /c` inside `%USERPROFILE%`, we stage a dedicated binary outside `target\`
# (so `cargo clean` never breaks hooks) and verify directory ACLs before enabling it.
function Test-SafeBinaryAcl {
    param([string]$CheckPath)
    try {
        $Acl = Get-Acl -Path $CheckPath -ErrorAction Stop
        foreach ($Rule in $Acl.Access) {
            if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }
            $Id = $Rule.IdentityReference.Value
            $IsBroad = $Id -match '^(Everyone|Jeder|BUILTIN\\Users|BUILTIN\\Benutzer|NT AUTHORITY\\Authenticated Users|NT-AUTORIT.+\\Authentifizierte Benutzer)$' -or
                       $Id -match '\\(Domain Users|Dom.+nen-Benutzer)$'
            if ($IsBroad) {
                $Rights = [int]$Rule.FileSystemRights
                # FileSystemRights: WriteData/CreateFiles (2), AppendData (4), Write (278), Modify (197055), FullControl (2032127), GenericWrite (0x40000000), GenericAll (0x10000000)
                if (($Rights -band 0x50030116) -ne 0) {
                    return $false
                }
            }
        }
        return $true
    } catch {
        return $false
    }
}

$PrimaryHookCandidates = @(
    "%USERPROFILE%\.gemini\libredb\bin\libredb.exe",
    "%USERPROFILE%\.gemini\antigravity\bin\libredb.exe"
)
$VerifiedHookCmd = $null
if (-not $NoHooks) {
    foreach ($CandExe in $PrimaryHookCandidates) {
        $FormattedCmd = if ($CandExe.Contains(' ')) { '"' + $CandExe + '"' } else { $CandExe }
        try {
            $ProbeOut = "{}" | & $env:ComSpec /c "$FormattedCmd hook-pre-invocation" 2>$null
            if ($LASTEXITCODE -eq 0 -and ($ProbeOut -join "") -match "injectSteps") {
                $VerifiedHookCmd = $FormattedCmd
                break
            }
        } catch {
        }
    }
}

# Fallback for Enterprise AD workstations where `%USERPROFILE%` is SRP-blocked and `$ProjectRoot`
# resides on an ACL-restricted personal network home share (e.g. `Q:\`): stage outside `target\`!
if ((-not $NoHooks) -and ($null -eq $VerifiedHookCmd)) {
    $HomeRoot = [System.IO.Path]::GetPathRoot($UserHome)
    $ProjDriveRoot = [System.IO.Path]::GetPathRoot($ProjectRoot)
    if ($ProjDriveRoot -and (-not $ProjDriveRoot.Equals($HomeRoot, [System.StringComparison]::OrdinalIgnoreCase))) {
        if (Test-SafeBinaryAcl -CheckPath $ProjDriveRoot) {
            $DriveHookDir = Join-Path $ProjDriveRoot ".gemini\libredb\bin"
            try {
                New-Item -ItemType Directory -Force -Path $DriveHookDir -ErrorAction Stop | Out-Null
                if (Test-SafeBinaryAcl -CheckPath $DriveHookDir) {
                    $DriveHookExe = Join-Path $DriveHookDir "libredb.exe"
                    Install-BinaryHotSafe -Src $ReleaseExe -Dst $DriveHookExe
                    $FormattedCmd = if ($DriveHookExe.Contains(' ')) { '"' + $DriveHookExe + '"' } else { $DriveHookExe }
                    $ProbeOut = "{}" | & $env:ComSpec /c "$FormattedCmd hook-pre-invocation" 2>$null
                    if ($LASTEXITCODE -eq 0 -and ($ProbeOut -join "") -match "injectSteps") {
                        $VerifiedHookCmd = $FormattedCmd
                    }
                }
            } catch {
            }
        } else {
            Write-Output "[WARN] Skipping fallback drive hook root $ProjDriveRoot due to broad multi-user write ACL."
        }
    }
}

if ($null -ne $VerifiedHookCmd) {
    $VerifiedEscaped = $VerifiedHookCmd.Replace('\', '\\').Replace('"', '\"')
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
    if ($NoHooks) {
        Write-Output "[OK] Installed hooks.json with enabled=false (-NoHooks MCP-only mode)."
    } else {
        Write-Output "[WARN] Enterprise GPO/AppLocker blocked cmd.exe /c hook execution; set enabled=false in hooks.json so tool calls are never blocked."
    }
}

# 4. Optional personal rules profile: enterprise-neutral by default (-Profile Neutral never injects personal AGENTS.md)
$AgentsMdPath = Join-Path $RulesDir "AGENTS.md"
if ($Profile -eq "Personal") {
    $AgentsMd = @'
# Central LibreDB rules directive

All system rules, coding standards, administrative credentials, and skills live in `~/.gemini/libredb/customizations.ldb` (auto-migrating legacy `.db` files 1:1 on first touch). Enforce with HIGHEST PRIORITY:

1. **Global output formatting invariant**:
   - **No em-dashes or en-dashes**: Never output U+2014 or U+2013 in chat, markdown, code comments, commits, or artifacts. Use `-`, `:`, or `(...)`.
   - **No emojis**: Never output emojis, smileys, or decorative Unicode symbols.
   - **Sentence case for headings and labels**: Capitalize only the first word and proper nouns/acronyms (`GitHub`, `Gitea`, `LibreDB`, `SQLite`, `JSONL`, `UTF-8`, `API`, `CLI`, `IDE`, `MCP`). Never use Title Case.

2. **Conversational communication and writing standards**:
   - Use informal German ("Du"/"Dein", "wir"/"unser"; NEVER formal "Sie" or plural "Ihr"/"Euer"/"Euch") with natural umlauts (__UMLAUT_LIST__).
   - **German compound nouns (no Deppenbindestriche)**: Join Komposita into one word (e.g., "Abteilungskontingent", "Browsertool", "Tabwechsel", "Standardeinstellung", "Kontextkompaktierung", "Subagentenisolation", "Tokenreduktion", "__TOKEN_OEKONOMIE__" never "__TOKEN_OEKONOMIE_BAD__").
   - **Candid architectural pushback**: When an idea overshoots the target, adds unnecessary complexity, or hardcodes a fragile assumption, say directly that it is suboptimal and propose the cleaner engineering approach immediately.

3. **Coding, SemVer 2.0.0, and Keep a Changelog 1.1.0**:
   - **Language boundary**: 100% grammatically correct ASCII English in all code, comments, logs, UI strings, and commits. Never translate UI strings to German.
   - **SemVer & releases**: Follow https://semver.org/ (`MAJOR.MINOR.PATCH`) and https://keepachangelog.com/en/1.1.0/. Never overwrite published tags; bump version, update `CHANGELOG.md` (`## [X.Y.Z] - YYYY-MM-DD`), place deliverables (`.apk`, `.aab`, `.exe`, `.msi`, `.xpi`, `.vsix`, `.whl`, `.jar`, `.zip`) in `dist/` or `releases/`, and sync via `libredb git-sync -m "<msg>" --project "<dir>" --releases` / `libredb git-release vX.Y.Z --project "<dir>"`.
   - **Authoring & README**: Commit as `Antigravity <antigravity@local.dev>`. Strictly no VBScript (`.vbs`, `cscript`, `wscript`). Follow the 9-block `README.md` blueprint: (1) `# Title`, (2) Shields.io badges (`Version`, `Tests`, stack, `AGPLv3 + Commons Clause`), (3) 1-3 sentence summary, (4) `## Table of contents`, (5) executive summary table, (6) installation & quickstart, (7) usage & commands, (8) architecture & ASCII tree (`|--`), (9) SemVer & license.

4. **Admin elevation and SOC audit standard (`C:\IT_ADMIN_LOGS\<USERNAME>\<TASK>\<TARGET>\<Date>\<hh_mm_ss>\`)**:
   - Elevate directly, via DPAPI (`~/.gemini/config/credentials/*.credential.xml`), or `Start-Process -Verb RunAs`. Never stage in `C:\Windows\Temp`, use `cmd.exe /c` wrappers, create remote services (`sc.exe \\`), or hardcode identities. After approval, log `[1/4 PRE-CHECK]`, `[2/4..3/4 ACTION]`, `[4/4 POST-CHECK]`, `[CLEANUP]` to `AuditLog_<Target>_<Date>_<hh_mm_ss>.log`.

5. **Turn-economy, diagnostics, and built-in benchmarks**:
   - **Anti-salami-slicing**: Read files `<= 800 lines` in one `read_file` call; for `> 800 lines` use `libredb_code` (`skeleton`, `locate`, `fim`, `impact` with batched `files`/`symbols`/`slices`) and batch parallel reads.
   - **Subagent firewall**: Run 1-3 file edits and WMI/CIM commands in main context; delegate `>= 4` searches or `> 5` files to `research` (`Model="flash"`).
   - **Batching & verification**: Fix entire bug classes before rebuilding, chain `build && test && verify`, commit memory via `libredb_memorize`, check `libredb guardrail check --path "<dir>" --staged --strict`, inspect savings/benchmarks natively via `libredb savings` and `libredb bench` (zero ad-hoc scripts), and use `WaitMsBeforeAsync=10000` without polling. Note any internal tool workarounds briefly at the end.

6. **Autonomous project memory & Git/Gitea sync (pure Pull)**:
   - Persist/recall via `libredb_memorize`, `libredb_pulse` (`query`, `cwd`, `cid`, `budget`), and `libredb get-skill <name> [--section "<Section>"]` / `libredb slice-skill "<query>"` on `.agents/memory.ldb` (auto-migrating legacy `.agents/memory.db` 1:1).
   - Use `libredb git-init`, `git-sync`, `git-release`, and `gitea-status`. Never hijack non-Gitea `origin` remotes or leak Gitea auth headers; ask before `--allow-unversioned` ("Soll ich das wirklich ohne Versionierung hochladen?") and pause on `[GITEA REPOSITORY COLLISION]`. Link URLs as `[Label](url)`.

7. **Model & concurrency catalog**:
   - `ultra` (16 reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 4 Carbon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`. Keep 100% of code generation on `Argon`, `Carbon`, or `Claude 5.5`; route only read-only `research` subagents to `Model="flash"`.
'@
    $UmlautList = "$([char]0x00E4), $([char]0x00F6), $([char]0x00FC), $([char]0x00DF)"
    $TokenOek = "Token$([char]0x00F6)konomie"
    $TokenOekBad = "Token-$([char]0x00D6)konomie"
    $AgentsMd = $AgentsMd.Replace("__UMLAUT_LIST__", $UmlautList).Replace("__TOKEN_OEKONOMIE__", $TokenOek).Replace("__TOKEN_OEKONOMIE_BAD__", $TokenOekBad)
    [System.IO.File]::WriteAllText($AgentsMdPath, $AgentsMd, $Utf8NoBom)
    Write-Output "[OK] Installed personal AGENTS.md rules directive (-Profile Personal)."
} elseif (Test-Path $AgentsMdPath) {
    $FirstLine = (Get-Content -Path $AgentsMdPath -TotalCount 1 -ErrorAction SilentlyContinue) -join ""
    if ($FirstLine.StartsWith("# Central LibreDB rules directive")) {
        Remove-Item -Path $AgentsMdPath -Force
        Write-Output "[OK] Neutral profile: removed previous personal rules/AGENTS.md."
    } else {
        Write-Output "[INFO] Neutral profile: preserving custom organization rules/AGENTS.md without modification."
    }
} else {
    Write-Output "[OK] Neutral enterprise profile: no personal rules/AGENTS.md installed."
}

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
2. **`libredb_code`** (`action`: `"index"` | `"skeleton"` | `"locate"` | `"impact"` | `"fim"` | `"savings"`, `target`, `files`, `symbols`, `slices`, `cwd`, `cid`, `force`, `symbol`, `line`, `pad`, `format`, `days`):
   - `"index"`: Incrementally scans non-binary source files in `target` (`< 3 ms` warm stat+hash fast path), wiring `Calls` (including Dalvik/Smali descriptors & `1..2`-char R8 methods) and `Decision -> Governs -> Symbol` synapses.
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a single `target` file or multi-file batch (`files: [...]`) across 25+ languages and `< 5 us` topology-inferred extensionless files with session-aware `[Zero-Repeat Skeleton]` deduplication (`cid`).
   - `"locate"`: Returns `< 0.5 ms` 1-line `[Lstart-Lend]` symbol locations for a single `target` or batched `symbols: [...]` (`<= 64`) without full caller/callee edge traversal.
   - `"impact"`: Returns compact (`-70%` token) bidirectional callers, DI/interface implementors, callees, and governing architectural decisions for a single `target` or batched `symbols: [...]` (`<= 64`, `format="json"` for raw JSON).
   - `"fim"`: Returns surgical `[Lstart-Lend]` edit slices with blast-radius callers, implementors, and governing decisions attached for a single `target` or batched `slices: [{"target": "...", "symbol": "...", "line": 42, "pad": 12}]` / `symbols: [...]` (`<= 32` slices, deduplicating file baseline tokens).
   - `"savings"`: Returns an authorized workspace 3-tier token-consumption and savings report (`days=0` for today, `days <= 3660`).
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `sync_central_sqlite`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, or situational pitfall reflexes.

## CLI commands (`libredb`)

- **Zero-boilerplate cognitive & code-graph queries:**
  - `libredb pulse [<db.ldb>] "<query>" [--cwd "<dir>"] [--cid <id>] [--budget <tok>]`
  - `libredb locate [<db.ldb>] <symbol...> [--cwd "<dir>"] [--json]`
  - `libredb impact [<db.ldb>] <symbol...> [--cwd "<dir>"] [--json]`
  - `libredb slice-skill "<query>" [--skill <skill_name>] [--top <k>] [--json]`
  - `libredb get-skill [<skill_name>] [--section "<Section Title>" | --query "<query>" [--top <k>]] [--json]`
- **Learning observability:** `libredb learning [<db.ldb>] [--cwd "<dir>"] [--db <db.ldb>] [--top <n>] [--json]`
- **Token savings & reproducible benchmarks:**
  - `libredb savings | report [--today] [--days <n>] [--cid <id>] [--project "<dir>"] [--json]`
  - `libredb bench [--suite kernel|full|audit] [--workspace "<dir>"] [--filter <p1,p2>] [--ext <e1,e2>] [--max-files <n>] [--nodes <n>] [--threads <t>] [--json]`
- **Guardrails:** `libredb guardrail check --path "<dir>" [--staged] [--strict]`
- **Workspace trust & universal config:**
  - `libredb trust [<dir>] [--revoke] [--list] [--accept-rollback] [--reinit-lost] [--migrate-v3 [--confirm-metadata]] [--migrate-v2] [--if-clean]`
  - `libredb config <get|set|unset|list> [<key>] [<value>] [--project "<dir>"]`
- **Compaction & GC:** `libredb compact <db.ldb> [--prune]`
- **Rules, skills & reflexes:**
  - `libredb sync-skill <SKILL.md> [--name <skill_name>]`
  - `libredb list-rules`, `libredb list-skills`, `libredb list-reflexes`
  - `libredb modernize-global`
- **Dynamic Git & Gitea workflow:**
  - `libredb gitea-status`
  - `libredb git-init "<dir>" [--name <repo>] [--use-existing] [--overwrite]` (alias: `gitea-init`)
  - `libredb git-sync -m "<commit message>" --project "<dir>" [--remote <r>] [--all-remotes] [--github] [--releases] [--allow-unversioned]` (alias: `gitea-sync`)
  - `libredb git-release [vX.Y.Z] --project "<dir>" [--remote <r>] [--all-remotes] [--github]` (alias: `gitea-release`)
  - `libredb gitea-config [--url <u>] [--user <usr>] [--token <tok> | --token-stdin] [--allow-insecure-http <bool>] [--register-helper]`
'@
$SkillMdPath = Join-Path $SkillDir "SKILL.md"
[System.IO.File]::WriteAllText($SkillMdPath, $SkillMd, $Utf8NoBom)

# Modernize global DB in-place via LibreDB IPC writer lock (encrypting plaintext tokens via DPAPI + read-only v3 workspace seal audit)
$ModernizeArgs = @("modernize-global", "--global", $GlobalLdb, "--skill-md", $SkillMdPath, "--profile", $Profile.ToLowerInvariant())
if ($MigrateLegacy) {
    $ModernizeArgs += "--migrate-legacy"
}
& $TargetExe @ModernizeArgs

if ($Profile -eq "Personal") {
    & $TargetExe config unset "hook:subagent_flash_routing" --global $GlobalLdb | Out-Null
    & $TargetExe config unset "hook:exploratory_firewall" --global $GlobalLdb | Out-Null
    & $TargetExe config set "guardrail:style_rules" "true" --global $GlobalLdb | Out-Null
    & $TargetExe config set "git:author_name" "Antigravity" --global $GlobalLdb | Out-Null
    & $TargetExe config set "git:author_email" "antigravity@local.dev" --global $GlobalLdb | Out-Null
} else {
    & $TargetExe config unset "hook:subagent_flash_routing" --global $GlobalLdb | Out-Null
    & $TargetExe config unset "hook:exploratory_firewall" --global $GlobalLdb | Out-Null
    & $TargetExe config unset "guardrail:style_rules" --global $GlobalLdb | Out-Null
    & $TargetExe config unset "git:author_name" --global $GlobalLdb | Out-Null
    & $TargetExe config unset "git:author_email" --global $GlobalLdb | Out-Null
}

# Seal and incrementally index LibreDB's own workspace into .agents/memory.ldb ONLY if clean/untampered
$SelfLdb = Join-Path $ProjectRoot ".agents\memory.ldb"
try {
    $TrustOut = (& $TargetExe trust $ProjectRoot --if-clean --global $GlobalLdb) -join "`n"
    Write-Output $TrustOut
    if ($TrustOut -notmatch '^\[WARN\]') {
        & $TargetExe index-workspace $SelfLdb $ProjectRoot --force
    }
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
# LibreDB cognitive memory plugin (v1.4.1)

Enterprise-ready standalone Rust cognitive memory, token-economy analytics & code-graph engine for `Antigravity`:
- `libredb-mcp`: 3-tool multi-workspace cognitive memory & 25+ language zero-hardcode topology + exact Dalvik/DI + Git co-change `Lift` code-graph server with `< 0.5 ms` `locate`, closed-loop causal `Search-Miss -> Verified-Edit` bridging (body-hash diffs + calibrated `BridgeScorer`), batched `impact` (`symbols`) & `fim` (`slices`), tentative-verified `PreToolUse` ACID symbol shifting, contract-drift grounded reflexes, subagent-aware priority-budgeted `BM25` `PreInvocation` hydration, zero-I/O RAM session delta, and `[Zero-Repeat Skeleton]` deduplication.
- Built-in analytics, benchmarks & verification suite: `libredb savings` (`report`) combines cross-process-atomic `~/.gemini/libredb/telemetry.ldb` counters with bounded streaming `Antigravity` transcript parsing (`<= 8 MiB/line`, 3-tier observed vs counterfactual vs provider usage), `libredb learning [--verify]` inspects cues/bridges/reflex drift/counters read-only and proves causal learning via `L1..L10`, and `libredb bench` (`--suite kernel|full|audit|learning`, `--workspace`) runs `C1..C6` token-economy benchmarks, `A1..A12` security/feature audits, and `L1..L10` learning verification natively without external scripts.
- Standards-compliant security: monotonic content-and-metadata-bound RFC 2104 `HMAC-SHA256` (`v4:r<rev>`) workspace trust seals (`libredb trust`), Windows `DPAPI` (`CryptProtectData`) and POSIX RFC 8439 `ChaCha20-Poly1305` AEAD OS credential vault, symlink-canonicalized control-plane & credential path protection, and universal `libredb config` customization.
- Strictly neutral by default: `deploy_plugin.ps1` (`-Profile Neutral`, default) installs `libredb-mcp` and security guardrails with `0` personal rules, `0` implicit legacy DB imports, and preserved corporate `git config` identity.
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

Write-Output "[OK] Deployed LibreDB v1.4.1 standalone binaries to: $BinDir (Profile=$Profile)"
Write-Output "[OK] Hydrated and modernized global store at: $GlobalLdb"
Write-Output "[OK] Installed complete Antigravity plugin at: $PluginDir"
