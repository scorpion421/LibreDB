param(
    [ValidateSet("Neutral", "Personal")]
    [string]$Profile = "Neutral",
    [switch]$NoHooks
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
    throw "Release binary not found at $ReleaseExe. Run 'cargo build --release' first."
}

function Install-BinaryHotSafe {
    param([string]$Src, [string]$Dst)
    Unblock-File -Path $Src -ErrorAction SilentlyContinue
    # Opportunistically sweep unlocked `.old` binaries deferred from prior live upgrades.
    Remove-Item "$Dst.old" -Force -ErrorAction SilentlyContinue
    $DstDir = Split-Path -Parent $Dst
    $DstLeaf = Split-Path -Leaf $Dst
    Get-ChildItem -LiteralPath $DstDir -Filter "$DstLeaf.*.old" -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
    if (Test-Path $Dst) {
        try {
            Copy-Item $Src $Dst -Force
            Unblock-File -Path $Dst -ErrorAction SilentlyContinue
            return
        } catch {
            $OldPath = "$Dst.$PID.$([Environment]::TickCount64).old"
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

# Seed ~/.gemini/libredb/customizations.ldb cleanly when absent.
$GlobalLdb = Join-Path $LibreHome "customizations.ldb"
if (-not (Test-Path $GlobalLdb)) {
    & $TargetExe init $GlobalLdb | Out-Null
}

$ExeForward = $TargetExe.Replace('\', '/')
$GlobalForward = $GlobalLdb.Replace('\', '/')
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# 1. Write plugin.json (strictly adhering to Antigravity plugin manifest schema)
$PluginJson = @'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "2.0.0",
  "description": "Persistent project memory, fast code-graph search, and token-savings engine for Antigravity. Routes sub-millisecond lifecycle hooks via an in-memory MCP IPC coordinator with O(1) tail-sync, locates functions and call dependencies without reading whole files, enforces workspace guardrails, and automates Git/Gitea releases.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Show how many tokens LibreDB saved today and across my projects",
    "Load the project context, active decisions, and open tasks for this workspace",
    "Find where a function is defined and check which callers are affected before editing"
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
            $Sid = $null
            try {
                if ($Rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $Sid = $Rule.IdentityReference.Value
                } else {
                    $Sid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
            } catch {
                $Sid = $Rule.IdentityReference.Value
            }
            $IsBroad = $Sid -match '^(S-1-1-0|S-1-2-0|S-1-5-11|S-1-5-32-545|S-1-5-32-546)$' -or
                       $Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$'
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
        "timeout": 15
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|invoke_subagent|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "$VerifiedEscaped hook-pre-tool",
            "timeout": 15
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

All system rules, coding standards, administrative credentials, and skills live in `~/.gemini/libredb/customizations.ldb` (pure Rust single-file `LIBREDB1` storage). Enforce with HIGHEST PRIORITY:

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
   - **Human-readable changelogs, release notes & overviews**: Write all `README.md` summaries, plugin overviews, `CHANGELOG.md` entries, and Git/Gitea release descriptions in clear, logical IT prose for human engineers and users. Explain what changed, why it matters, and how to use it in 1-2 concise sentences per bullet - never dump internal helper function names, storage keys, or run-on buzzword chains.
   - **Authoring & README**: Commit as `Antigravity <antigravity@local.dev>`. Strictly no VBScript (`.vbs`, `cscript`, `wscript`). Follow the 9-block `README.md` blueprint: (1) `# Title`, (2) Shields.io badges (`Version`, `Tests`, stack, `Apache 2.0 + Commons Clause`), (3) 1-3 sentence summary, (4) `## Table of contents`, (5) executive summary table, (6) installation & quickstart, (7) usage & commands, (8) architecture & ASCII tree (`|--`), (9) SemVer & license.

4. **Admin elevation and SOC audit standard (`C:\IT_ADMIN_LOGS\<USERNAME>\<TASK>\<TARGET>\<Date>\<hh_mm_ss>\`)**:
   - Elevate directly, via DPAPI (`~/.gemini/config/credentials/*.credential.xml`), or `Start-Process -Verb RunAs`. Never stage in `C:\Windows\Temp`, use `cmd.exe /c` wrappers, create remote services (`sc.exe \\`), or hardcode identities. After approval, log `[1/4 PRE-CHECK]`, `[2/4..3/4 ACTION]`, `[4/4 POST-CHECK]`, `[CLEANUP]` to `AuditLog_<Target>_<Date>_<hh_mm_ss>.log`.

5. **Turn-economy, diagnostics, and built-in benchmarks**:
   - **Anti-salami-slicing**: Read files `<= 800 lines` in one `read_file` call; for `> 800 lines` use `libredb_code` (`skeleton`, `locate`, `fim`, `impact` with batched `files`/`symbols`/`slices`) and batch parallel reads.
   - **Subagent firewall**: Run 1-3 file edits and WMI/CIM commands in main context; delegate `>= 4` searches or `> 5` files to `research` (`Model="flash"`).
   - **Batching & verification**: Fix entire bug classes before rebuilding, chain `build && test && verify`, commit memory via `libredb_memorize`, check `libredb guardrail check --path "<dir>" --staged --strict`, inspect savings/benchmarks natively via `libredb savings` and `libredb bench` (zero ad-hoc scripts), and use `WaitMsBeforeAsync=10000` without polling. Note any internal tool workarounds briefly at the end.

6. **Autonomous project memory & Git/Gitea sync (pure Pull)**:
   - Persist/recall via `libredb_memorize`, `libredb_pulse` (`query`, `cwd`, `cid`, `budget`), and `libredb get-skill <name> [--section "<Section>"]` / `libredb slice-skill "<query>"` on pure-Rust `.agents/memory.ldb`.
   - Use `libredb git-init`, `git-sync`, `git-release`, and `gitea-status`. Never hijack non-Gitea `origin` remotes or leak Gitea auth headers; ask before `--allow-unversioned` ("Soll ich das wirklich ohne Versionierung hochladen?") and pause on `[GITEA REPOSITORY COLLISION]`. Link URLs as `[Label](url)`.

7. **Model & concurrency catalog**:
   - `ultra` (16 reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 4 Carbon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`. Keep 100% of code generation on `Argon`, `Carbon`, or `Claude 5.5`; route only read-only `research` subagents to `Model="flash"`.

8. **Native cross-platform app design & anti-AI-slop UI standard (`Windows Fluent 2`, `Android Material 3`, `Apple HIG`, `KDE / GNOME HIG`)**:
   - Ban AI-slop aesthetics across ALL platforms and toolkits (`WinUI`, `WPF`, `egui`/`eframe`, `Tauri`, `Jetpack Compose`, `SwiftUI`/`UIKit`/`AppKit`, `GTK4`/`Libadwaita`, `Kirigami`/`Qt6`): zero neon purple/cyan/rainbow gradients, zero oversized pill-heavy `>= 16px` cards or glassmorphism blobs, zero gratuitous animations, zero heavy Bold-all-over text, and zero hardcoded palettes overriding system Light/Dark/High-Contrast themes.
   - **Windows (`Fluent 2`)** (`https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview`, `https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices`): `Segoe UI Variable` (`400`/`600` only), `8px`/`4px`/`2px` corner radii on a `4px` grid, neutral layered surfaces with `1px` borders, `Mica`/`Acrylic`, single system accent, `>= 4.5:1` contrast, `epx` DPI scaling, full keyboard + UI Automation focus (`libredb get-skill windows-app-design`).
   - **Android (`Material 3` / `Compose`)** (`https://developer.android.com/design/ui/`, `https://developer.android.com/design/ui/mobile`): `Roboto`/`Roboto Flex` in nonlinearly scaled `sp` (up to `200%`), `dynamicLightColorScheme`/`dynamicDarkColorScheme` tonal `surfaceContainer` tiers, M3 shape scale (`4dp`..`28dp`), mandatory `enableEdgeToEdge()` + `WindowInsets` (`safeDrawing`/`ime`), `>= 48dp` touch targets, adaptive `NavigationBar`/`NavigationRail`/`PermanentNavigationDrawer` + `ListDetailPaneScaffold`, predictive back, `TalkBack` (`libredb get-skill android-app-design`).
   - **Apple iOS/iPadOS & macOS (`Apple HIG`)** (`https://developer.apple.com/design/human-interface-guidelines`, `https://developer.apple.com/design/human-interface-guidelines/designing-for-ios`, `https://developer.apple.com/design/human-interface-guidelines/designing-for-macos`): `SF Pro` (`SF Mono`) + `Dynamic Type` & `SF Symbols`, semantic system colors + `Material`/`NSVisualEffectView` vibrancy (respecting `reduceTransparency`/`Contrast`), iOS `safeAreaInsets` + `44pt` touch targets + `3-5` bottom `TabView` + `.insetGrouped` `.continuous` squircles vs macOS `20-28pt` pointer density + `NavigationSplitView` sidebar + unified `toolbar` + Menu Bar `.commands` (`Cmd+,` Settings) + `VoiceOver` (`libredb get-skill apple-hig-design`).
   - **Linux Desktop (`GNOME Libadwaita` & `KDE Kirigami` HIG)** (`https://develop.kde.org/hig/`, `https://developer.gnome.org/hig/`, `https://developer.gnome.org/hig/principles.html`): GNOME `AdwToolbarView`/`AdwHeaderBar`, `AdwNavigationSplitView` + `AdwBreakpoint`, `.boxed-list` (`12px`/`6px` radii), `AdwToastOverlay`/`AdwStatusPage`, `AdwStyleManager` `@window_bg_color`/`@accent_bg_color`; KDE `Kirigami.ApplicationWindow`, `FormLayout`, `InlineMessage`, `Kirigami.Theme`/`KColorScheme` + `Kirigami.Units`, `xdg-desktop-portal` dark/accent, Wayland fractional scaling, `AT-SPI2` (`libredb get-skill linux-desktop-hig-design`).
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
  Persistent project memory, surgical code-graph search, token-savings analytics,
  guardrail scanner, and Git/Gitea release automation for Antigravity. Activate when
  recalling project context or skills, inspecting large files, saving architectural
  decisions, checking guardrails, or publishing releases.
---

# LibreDB cognitive memory, code graph, and Gitea suite

`LibreDB` gives `Antigravity` global customizations (`~/.gemini/libredb/customizations.ldb`) and per-workspace project memory (`.agents/memory.ldb`) with fast lifecycle hooks and built-in Git/Gitea release automation on a pure-Rust single-file `LIBREDB1` storage engine.

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
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `learn_error`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, situational pitfall reflexes, or error-recovery directives.

## CLI commands (`libredb`)

- **Zero-boilerplate cognitive & code-graph queries:**
  - `libredb pulse [<db.ldb>] "<query>" [--cwd "<dir>" | --project "<dir>"] [--cid <id>] [--budget <tok>] [--err <msg>]`
  - `libredb locate [<db.ldb>] <symbol...> [--cwd "<dir>" | --project "<dir>"] [--json]`
  - `libredb impact [<db.ldb>] <symbol...> [--cwd "<dir>" | --project "<dir>"] [--json]`
  - `libredb slice-skill "<query>" [--skill <skill_name>] [--top <k>] [--json]`
  - `libredb get-skill [<skill_name>] [--section "<Section Title>" | --query "<query>" [--top <k>]] [--json]`
- **Learning observability & verification:** `libredb learning [<db.ldb>] [--verify] [--cwd "<dir>" | --project "<dir>"] [--db <db.ldb>] [--top <n>] [--json]`
- **Token savings & reproducible benchmarks:**
  - `libredb savings | report [--today] [--days <n>] [--cid <id>] [--project "<dir>" | --cwd "<dir>"] [--json]`
  - `libredb bench [--suite kernel|full|audit|learning] [--workspace "<dir>" | --project "<dir>" | --cwd "<dir>"] [--filter <p1,p2>] [--ext <e1,e2>] [--max-files <n>] [--nodes <n>] [--threads <t>] [--json]`
- **Guardrails & database inspection:**
  - `libredb guardrail check --path "<dir>" [--staged] [--strict]`
  - `libredb status | stats [<db.ldb>] [--project "<dir>" | --cwd "<dir>"] [--json]`
- **Workspace trust & universal config:**
  - `libredb trust [<dir>] [--revoke] [--list] [--accept-rollback] [--reinit-lost] [--if-clean]`
  - `libredb config <get|set|unset|list> [<key>] [<value>] [--project "<dir>" | --cwd "<dir>"]`
- **Compaction & GC:** `libredb compact <db.ldb> [--prune]`
- **Rules, skills & reflexes:**
  - `libredb sync-skill <SKILL.md> [--name <skill_name>]`
  - `libredb list-rules`, `libredb list-skills`, `libredb list-reflexes`
  - `libredb modernize-global [--skills-dir "<dir>"] [--profile neutral|personal]`
- **Dynamic Git & Gitea workflow:**
  - `libredb gitea-status [--project "<dir>" | --cwd "<dir>"]`
  - `libredb git-init "<dir>" [--name <repo>] [--use-existing] [--overwrite]` (alias: `gitea-init`)
  - `libredb git-sync -m "<commit message>" --project "<dir>" [--remote <r>] [--all-remotes] [--github] [--releases] [--allow-unversioned]` (alias: `gitea-sync`)
  - `libredb git-release [vX.Y.Z] --project "<dir>" [--remote <r>] [--all-remotes] [--github]` (alias: `gitea-release`)
  - `libredb gitea-config [--url <u>] [--user <usr>] [--token <tok> | --token-stdin] [--allow-insecure-http <bool>] [--register-helper]`
'@
$SkillMdPath = Join-Path $SkillDir "SKILL.md"
[System.IO.File]::WriteAllText($SkillMdPath, $SkillMd, $Utf8NoBom)

# Modernize global DB in-place via LibreDB IPC writer lock (encrypting plaintext tokens via DPAPI + read-only v4 workspace seal audit)
$SkillsRepoDir = Join-Path $ProjectRoot "skills"
$ModernizeArgs = @("modernize-global", "--global", $GlobalLdb, "--skill-md", $SkillMdPath, "--skills-dir", $SkillsRepoDir, "--profile", $Profile.ToLowerInvariant())
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
# LibreDB cognitive memory plugin (v2.0.0)

`LibreDB` gives `Antigravity` persistent project memory, targeted code navigation, and automated release workflows in a single 100% pure-Rust binary:

- **Persistent project memory (`libredb_pulse`, `libredb_memorize`)**: Stores architectural decisions, project facts, open tasks, and global rules in a single `.agents/memory.ldb` file, synchronizing updates incrementally (`O(1)` tail-sync) and skipping entries already shown in the session.
- **In-memory hook coordinator (`libredb mcp-serve`)**: Runs `PreInvocation` and `PreToolUse` hooks directly against the live MCP server RAM over a local Named Pipe or Unix socket, avoiding duplicate file locks and timeouts on slow network drives while falling back transparently to disk.
- **Targeted code navigation (`libredb_code`)**: Indexes functions, classes, and call relationships across 25+ languages so the agent can jump directly to symbol definitions (`locate`), inspect file outlines (`skeleton`), check affected callers (`impact`), and read exact code slices (`fim`) instead of loading entire large files.
- **Self-correcting learning (`libredb learning --verify`)**: Remembers which code symbol solved a failed search and which fix resolved a compiler or test error, refutes wrong hints automatically across 15 verified stages (`L1..L15`), and surfaces accurate pitfalls when similar code is touched later.
- **Token-savings reports and verification (`libredb savings`, `libredb bench`)**: Tracks real token savings across sessions and workspaces and runs built-in performance and security audit suites.
- **Workspace security and Git/Gitea releases (`libredb trust`, `libredb guardrail`, `libredb git-sync`)**: Encrypts credentials via OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), seals workspace databases against tampering (`HMAC-SHA256`), checks staged commits against project guardrails, and publishes versioned Git/Gitea releases with binary deliverables.
- **Neutral default profile**: `deploy_plugin.ps1` (`-Profile Neutral`, default) installs the MCP server and security guardrails with zero personal rules and preserves existing Git identities.
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

Write-Output "[OK] Deployed LibreDB v2.0.0 standalone binaries to: $BinDir (Profile=$Profile)"
Write-Output "[OK] Hydrated and modernized global store at: $GlobalLdb"
Write-Output "[OK] Installed complete Antigravity plugin at: $PluginDir"
