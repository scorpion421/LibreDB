param(
    [ValidateSet("Neutral", "Personal")]
    [string]$Profile = "Neutral",
    [switch]$NoHooks,
    [string]$BinaryPath = "",
    [string]$FallbackDrive = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VersionFile = Join-Path $ProjectRoot "VERSION"
$LibreVersion = if (Test-Path $VersionFile) { (Get-Content -Raw $VersionFile).Trim() } else { "2.4.2" }
if (-not $LibreVersion) { $LibreVersion = "2.4.2" }
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$GeminiDir = Join-Path $UserHome ".gemini"
$LibreHome = Join-Path $GeminiDir "libredb"
$BinDir = Join-Path $LibreHome "bin"
$PluginDir = Join-Path $GeminiDir "config\plugins\libredb"
$RulesDir = Join-Path $PluginDir "rules"
$SkillDir = Join-Path $PluginDir "skills\libredb"
$AssetsDir = Join-Path $PluginDir "assets"

New-Item -ItemType Directory -Force -Path $BinDir, $RulesDir, $SkillDir, $AssetsDir | Out-Null

$ReleaseExe = if ($BinaryPath -and $BinaryPath.Trim()) {
    $BinaryPath.Trim()
} else {
    @(
        (Join-Path $ProjectRoot "target\release\libredb.exe"),
        (Join-Path $ProjectRoot "dist\libredb-v$LibreVersion-windows-x64.exe"),
        (Join-Path $ProjectRoot "dist\libredb.exe")
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
$ReleaseDll = Join-Path $ProjectRoot "target\release\libredb_py.dll"
if (-not (Test-Path -LiteralPath $ReleaseDll)) {
    $ReleaseDll = Join-Path $ProjectRoot "dist\libredb.pyd"
}
if ((-not $ReleaseExe) -or (-not (Test-Path -LiteralPath $ReleaseExe))) {
    throw "Release binary not found in target\release or dist\. Build with 'cargo build --release' or pass -BinaryPath <path> (or run 'libredb update')."
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

function Remove-StaleBinaryCopy {
    param([string]$TargetPath)
    $TargetDir = Split-Path -Parent $TargetPath
    $TargetLeaf = Split-Path -Leaf $TargetPath
    if (Test-Path -LiteralPath $TargetDir) {
        Remove-Item "$TargetPath.old" -Force -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath $TargetDir -Filter "$TargetLeaf.*.old" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        return
    }
    try {
        Remove-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
    } catch {
        try {
            $OldPath = "$TargetPath.$PID.$([Environment]::TickCount64).old"
            Move-Item -LiteralPath $TargetPath -Destination $OldPath -Force -ErrorAction Stop
            Remove-Item -LiteralPath $OldPath -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
}

function Ensure-UserPathContains {
    param([string]$DirToAdd)
    $CleanTarget = $DirToAdd.Trim().TrimEnd('\', '/')
    if (-not $CleanTarget) { return }
    $CurrentSessionHas = ($env:PATH -split ';') | Where-Object {
        $_.Trim().Trim('"').TrimEnd('\', '/').Equals($CleanTarget, [System.StringComparison]::OrdinalIgnoreCase)
    }
    if (-not $CurrentSessionHas) {
        $env:PATH = "$CleanTarget;$env:PATH"
    }
    try {
        $EnvKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
        try {
            $ExistingRaw = [string]$EnvKey.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $ValKind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            try {
                if ($EnvKey.GetValueNames() -contains "Path") {
                    $ExistingKind = $EnvKey.GetValueKind("Path")
                    if ($ExistingKind -eq [Microsoft.Win32.RegistryValueKind]::String -and -not $ExistingRaw.Contains('%')) {
                        $ValKind = [Microsoft.Win32.RegistryValueKind]::String
                    }
                }
            } catch {
            }
            $AlreadyPresent = $false
            foreach ($Part in ($ExistingRaw -split ';')) {
                $CleanPart = $Part.Trim().Trim('"').TrimEnd('\', '/')
                if (-not $CleanPart) { continue }
                $ExpandedPart = if ($UserHome -and $CleanPart -match '^(?i)%USERPROFILE%(.*)$') {
                    $UserHome.TrimEnd('\', '/') + $Matches[1]
                } else {
                    $CleanPart
                }
                if ($CleanPart.Equals($CleanTarget, [System.StringComparison]::OrdinalIgnoreCase) -or
                    $ExpandedPart.Equals($CleanTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $AlreadyPresent = $true
                    break
                }
            }
            if (-not $AlreadyPresent) {
                $TrimmedBase = $ExistingRaw.Trim().TrimEnd(';')
                $NewVal = if ($TrimmedBase) { "$TrimmedBase;$CleanTarget" } else { $CleanTarget }
                $EnvKey.SetValue("Path", $NewVal, $ValKind)
                if (-not ("LibreDbNativeWin32.UserEnv" -as [type])) {
                    Add-Type -Namespace LibreDbNativeWin32 -Name UserEnv -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@
                }
                $MsgRes = [System.UIntPtr]::Zero
                [void][LibreDbNativeWin32.UserEnv]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment", 0x0002, 1000, [ref]$MsgRes)
                Write-Output "[OK] Added canonical binary directory to user PATH: $CleanTarget"
            }
        } finally {
            $EnvKey.Close()
        }
    } catch {
        Write-Output "[WARN] Could not update HKCU\Environment\Path: $_"
    }
}

$TargetExe = Join-Path $BinDir "libredb.exe"
Install-BinaryHotSafe -Src $ReleaseExe -Dst $TargetExe
if (Test-Path $ReleaseDll) {
    Install-BinaryHotSafe -Src $ReleaseDll -Dst (Join-Path $BinDir "libredb.pyd")
}

Ensure-UserPathContains -DirToAdd $BinDir

# Remove legacy duplicate binary copies and batch shims so only `~/.gemini/libredb/bin/libredb.exe` exists locally.
$LegacyPathDirs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$DefaultAgyBin = Join-Path $GeminiDir "antigravity\bin"
[void]$LegacyPathDirs.Add($DefaultAgyBin)
$SkillsDbCmd = Get-Command skillsdb -ErrorAction SilentlyContinue
if ($SkillsDbCmd -and $SkillsDbCmd.Source) {
    $ShimDir = Split-Path -Parent $SkillsDbCmd.Source
    if ($ShimDir.StartsWith($UserHome, [System.StringComparison]::OrdinalIgnoreCase)) {
        [void]$LegacyPathDirs.Add($ShimDir)
    }
}
foreach ($PathDir in $LegacyPathDirs) {
    if ($PathDir.TrimEnd('\', '/').Equals($BinDir.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }
    Remove-StaleBinaryCopy -TargetPath (Join-Path $PathDir "libredb.cmd")
    Remove-StaleBinaryCopy -TargetPath (Join-Path $PathDir "libredb.exe")
}

function Test-RipgrepBinary {
    param([string]$ExePath)
    if ((-not $ExePath) -or (-not (Test-Path -LiteralPath $ExePath))) { return $false }
    try {
        $VerLines = @(& $ExePath --version 2>$null)
        return ($LASTEXITCODE -eq 0 -and $VerLines.Count -gt 0 -and $VerLines[0] -match '^ripgrep\s')
    } catch {
        return $false
    }
}

function Find-LocalRipgrep {
    param([string]$HostArch)
    $StaticPatterns = @(
        (Join-Path $UserHome ".cargo\bin\rg.exe"),
        (Join-Path $UserHome "scoop\apps\ripgrep\current\rg.exe"),
        (Join-Path $env:ProgramFiles "ripgrep*\rg.exe"),
        (Join-Path $env:ProgramFiles "Git\usr\bin\rg.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Microsoft VS Code*\resources\app\node_modules*\@vscode\ripgrep\bin\rg.exe"),
        (Join-Path $env:ProgramFiles "Microsoft VS Code*\resources\app\node_modules*\@vscode\ripgrep\bin\rg.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\antigravity*\resources\app\node_modules*\@vscode\ripgrep\bin\rg.exe")
    )
    $Candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($Pat in $StaticPatterns) {
        if (-not $Pat) { continue }
        Get-Item -Path $Pat -ErrorAction SilentlyContinue | ForEach-Object { [void]$Candidates.Add($_.FullName) }
    }
    $WinGetPkgs = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    if (Test-Path $WinGetPkgs) {
        Get-ChildItem -Path $WinGetPkgs -Filter "BurntSushi.ripgrep*" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                Get-ChildItem -Path $_.FullName -Filter "rg.exe" -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object { [void]$Candidates.Add($_.FullName) }
            }
    }
    $VsRoot = Join-Path $env:ProgramFiles "Microsoft Visual Studio"
    if (Test-Path $VsRoot) {
        Get-ChildItem -Path $VsRoot -Filter "rg.exe" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object { if ($_.FullName -match $HostArch) { 0 } else { 1 } } |
            ForEach-Object { [void]$Candidates.Add($_.FullName) }
    }
    foreach ($Cand in $Candidates) {
        if ($HostArch -eq "x64" -and $Cand -match '(^|[\\/])(win32-)?arm64([\\/]|$)') { continue }
        if ($HostArch -eq "arm64" -and $Cand -match '(^|[\\/])(win32-)?(x64|x86|amd64|ia32)([\\/]|$)') { continue }
        if (Test-RipgrepBinary -ExePath $Cand) {
            return $Cand
        }
    }
    return $null
}

$script:ProvisionedRg = $null

function Ensure-RipgrepOnPath {
    param([string]$DefaultBinDir)
    $DstRg = Join-Path $DefaultBinDir "rg.exe"
    $LegacyAgyRg = Join-Path $GeminiDir "antigravity\bin\rg.exe"
    if (Test-RipgrepBinary -ExePath $DstRg) {
        $script:ProvisionedRg = $DstRg
        Write-Output "[OK] Native ripgrep (rg.exe) verified at: $DstRg"
        return
    }
    if (Test-RipgrepBinary -ExePath $LegacyAgyRg) {
        $script:ProvisionedRg = $LegacyAgyRg
        Write-Output "[OK] Native ripgrep (rg.exe) verified at: $LegacyAgyRg"
        return
    }
    $ExistingRg = Get-Command rg -ErrorAction SilentlyContinue
    if ($ExistingRg -and $ExistingRg.Source -and (Test-RipgrepBinary -ExePath $ExistingRg.Source)) {
        $script:ProvisionedRg = $ExistingRg.Source
        Write-Output "[OK] Native ripgrep (rg) available on PATH: $($ExistingRg.Source)"
        return
    }
    $ArchRaw = if ($env:PROCESSOR_ARCHITECTURE) { $env:PROCESSOR_ARCHITECTURE.ToUpperInvariant() } else { "AMD64" }
    $HostArch = if ($ArchRaw -eq "ARM64") { "arm64" } else { "x64" }
    $FoundRg = Find-LocalRipgrep -HostArch $HostArch
    if ((-not $FoundRg) -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Output "[INFO] ripgrep (rg.exe) not found locally; trying winget user install..."
        try {
            & winget install --id BurntSushi.ripgrep.MSVC --exact --silent --accept-package-agreements --accept-source-agreements --scope user --disable-interactivity 2>$null | Out-Null
            $FoundRg = Find-LocalRipgrep -HostArch $HostArch
        } catch {
        }
    }
    if ($FoundRg) {
        if (-not $FoundRg.Equals($DstRg, [System.StringComparison]::OrdinalIgnoreCase)) {
            Install-BinaryHotSafe -Src $FoundRg -Dst $DstRg
        }
        $script:ProvisionedRg = $DstRg
        Write-Output "[OK] Provisioned native ripgrep (rg.exe) into PATH at: $DstRg"
        return
    }
    Write-Output "[INFO] ripgrep (rg.exe) not found locally and winget install unavailable."
}

Ensure-RipgrepOnPath -DefaultBinDir $BinDir

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
  "version": "__VERSION__",
  "description": "Persistent project memory, fast code-graph search, and token-savings engine for Antigravity. Routes sub-millisecond lifecycle hooks via an in-memory MCP IPC coordinator with O(1) tail-sync, locates functions and call dependencies without reading whole files, enforces workspace guardrails, and automates Git/Gitea releases.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Show how many tokens LibreDB saved today and across my projects",
    "Load the project context, active decisions, and open tasks for this workspace",
    "Find where a function is defined and check which callers are affected before editing"
  ]
}
'@.Replace("__VERSION__", $LibreVersion)
[System.IO.File]::WriteAllText((Join-Path $PluginDir "plugin.json"), $PluginJson, $Utf8NoBom)

# 2. Verify executable launch permission across Enterprise GPO / AppLocker & stage fallback outside target\ if needed.
# Note: Antigravity executes hooks via Go `exec.Command("cmd", "/C", cmd)` and MCP servers via Go `fork/exec`.
# On Enterprise AD workstations where AppLocker/SRP blocks unsigned binaries under `%USERPROFILE%`,
# we stage a dedicated binary outside `target\` on an ACL-restricted workspace drive (e.g. `Q:\`) and
# point both `mcp_config.json` and `hooks.json` to the verified executable while keeping `customizations.ldb` local.
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

$VerifiedHookCmd = $null
$VerifiedExePath = $null
$CanonicalHookToken = "%USERPROFILE%\.gemini\libredb\bin\libredb.exe"
$FormattedCanonicalCmd = if ($CanonicalHookToken.Contains(' ')) { '"' + $CanonicalHookToken + '"' } else { $CanonicalHookToken }
for ($attempt = 0; $attempt -lt 3; $attempt++) {
    if ($attempt -gt 0) {
        Start-Sleep -Milliseconds 350
    }
    try {
        $ProbeOut = "{}" | & $env:ComSpec /c "$FormattedCanonicalCmd hook-pre-invocation" 2>$null
        if ($LASTEXITCODE -eq 0 -and ($ProbeOut -join "") -match "injectSteps") {
            $VerifiedHookCmd = $FormattedCanonicalCmd
            $VerifiedExePath = $TargetExe
            break
        }
    } catch {
    }
}

# Explicit opt-in fallback ONLY via -FallbackDrive <dir> (never auto-derived from workspace or current_dir):
if (($null -eq $VerifiedHookCmd) -and $FallbackDrive -and $FallbackDrive.Trim()) {
    $FbRoot = $FallbackDrive.Trim()
    if (Test-SafeBinaryAcl -CheckPath $FbRoot) {
        $DriveHookDir = Join-Path $FbRoot ".gemini\libredb\bin"
        try {
            New-Item -ItemType Directory -Force -Path $DriveHookDir -ErrorAction Stop | Out-Null
            if (Test-SafeBinaryAcl -CheckPath $DriveHookDir) {
                $DriveHookExe = Join-Path $DriveHookDir "libredb.exe"
                Install-BinaryHotSafe -Src $ReleaseExe -Dst $DriveHookExe
                if ($ProvisionedRg -and (Test-Path $ProvisionedRg)) {
                    Install-BinaryHotSafe -Src $ProvisionedRg -Dst (Join-Path $DriveHookDir "rg.exe")
                }
                $FormattedCmd = if ($DriveHookExe.Contains(' ')) { '"' + $DriveHookExe + '"' } else { $DriveHookExe }
                $ProbeOut = "{}" | & $env:ComSpec /c "$FormattedCmd hook-pre-invocation" 2>$null
                if ($LASTEXITCODE -eq 0 -and ($ProbeOut -join "") -match "injectSteps") {
                    $VerifiedHookCmd = $FormattedCmd
                    $VerifiedExePath = $DriveHookExe
                }
            }
        } catch {
        }
    } else {
        Write-Output "[WARN] Skipping -FallbackDrive root $FbRoot due to broad multi-user write ACL."
    }
}

$McpExeForward = if ($VerifiedExePath) { $VerifiedExePath.Replace('\', '/') } else { $ExeForward }

# 3. Write mcp_config.json (prefixed server name libredb-mcp using SRP-verified executable path)
$McpJson = @"
{
  "mcpServers": {
    "libredb-mcp": {
      "command": "$McpExeForward",
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

# 4. Write hooks.json
if ((-not $NoHooks) -and ($null -ne $VerifiedHookCmd)) {
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
    Write-Output "[OK] Verified execution and enabled hooks/MCP via: $McpExeForward"
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
        Write-Output "[OK] Installed hooks.json with enabled=false (-NoHooks MCP-only mode; MCP command: $McpExeForward)."
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
   - **Anti-salami-slicing**: Read files `<= 800 lines` in one `read_file` call; for `> 800 lines` use `libredb_code` (`skeleton`, `locate`, `fim` including file-less `symbol`, `impact`, `grep` with batched `files`/`symbols`/`slices`) and batch parallel reads.
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
2. **`libredb_code`** (`action`: `"index"` | `"skeleton"` | `"locate"` | `"impact"` | `"fim"` | `"grep"` | `"savings"` | `"backup"` | `"restore"` | `"migrate"` | `"read"`, `target`, `destination`, `source`, `instance`, `all`, `from_path`, `include_artifacts`, `query`, `show_secrets`, `files`, `symbols`, `slices`, `cwd`, `subpath`, `cid`, `force`, `symbol`, `line`, `pad`, `ignore_case`, `fixed_strings`, `word_boundary`, `context`, `max_matches`, `extensions`, `format`, `days`):
   - `"index"`: Incrementally scans non-binary source files in `target` (`< 3 ms` warm stat+hash fast path), wiring `Calls` (including Dalvik/Smali descriptors & `1..2`-char R8 methods) and `Decision -> Governs -> Symbol` synapses.
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a single `target` file or multi-file batch (`files: [...]`) across 25+ languages and `< 5 us` topology-inferred extensionless files with session-aware `[Zero-Repeat Skeleton]` deduplication (`cid`).
   - `"locate"`: Returns `< 0.5 ms` 1-line `[Lstart-Lend]` symbol locations for a single `target` or batched `symbols: [...]` (`<= 64`) without full caller/callee edge traversal.
   - `"impact"`: Returns compact (`-70%` token) bidirectional callers, DI/interface implementors, callees, and governing architectural decisions for a single `target` or batched `symbols: [...]` (`<= 64`, `format="json"` for raw JSON).
   - `"fim"`: Returns surgical `[Lstart-Lend]` edit slices with blast-radius callers, implementors, and governing decisions attached for a file `target` (including `<path>:<line>` syntax), file-less workspace `symbol`/`symbols` lookup, or batched `slices` (`<= 32`).
   - `"grep"`: Pure-Rust `.gitignore`-aware, credential/binary-safe workspace text and pattern search annotated with enclosing `[kind name Lstart-Lend]` contracts (optional `subpath`, `ignore_case`, `fixed_strings`, `word_boundary`, `context`, `max_matches`, `extensions`).
   - `"savings"`: Returns an authorized workspace 3-tier token-consumption and savings report (`days=0` for today, `days <= 3660`).
   - `"backup"` / `"restore"` / `"migrate"` / `"read"`: Portable unencrypted export with `sys::backup_manifest` (`destination`, `instance`, `all`), integrity-verified local re-encryption and sealing (`source`, `instance`, `all`), standalone chat or moved-folder migration (`source`, `cid`, `from_path`, `include_artifacts`), and own-risk read-only inspection (`target`, `query`, `show_secrets`).
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `learn_error`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, situational pitfall reflexes, or error-recovery directives.

## CLI commands (`libredb`)

- **Self-update & standalone install (zero repo or cargo required):**
  - `libredb update [--check] [--force] [--version <vX.Y.Z>] [--repo <owner/repo>] [--profile neutral|personal] [--no-hooks] [--fallback-drive <dir>]` (aliases: `self-update`, `upgrade`)
  - `libredb install [<binary_path>] [--profile neutral|personal] [--no-hooks] [--fallback-drive <dir>]` (alias: `self-install`)
  - **Rule for plugin updates:** Always update or install LibreDB by running `libredb update` or `<binary> install` via `run_command`. NEVER call `edit_file` or `write_file` on `mcp_config.json`, `hooks.json`, `plugin.json`, or files inside `~/.gemini/libredb/` (`PreToolUse` blocks direct edits to control-plane files by design).
- **Zero-boilerplate cognitive & code-graph queries:**
  - `libredb pulse [<db.ldb>] "<query>" [--cwd "<dir>" | --project "<dir>"] [--cid <id>] [--budget <tok>] [--err <msg>]`
  - `libredb skeleton [<db.ldb>] <source_file...> [--filter <substr>] [--cwd "<dir>" | --project "<dir>"] [--cid <id>] [--force] [--json]`
  - `libredb locate [<db.ldb>] <symbol...> [--cwd "<dir>" | --project "<dir>"] [--json]`
  - `libredb impact [<db.ldb>] <symbol...> [--cwd "<dir>" | --project "<dir>"] [--json]`
  - `libredb fim [<db.ldb>] [<source_file[:line]>] [--symbol <name> | --line <n>] [--pad <lines>] [--cwd "<dir>" | --project "<dir>"] [--json]`
  - `libredb grep | search "<pattern>" [<path>] [--cwd "<dir>" | --project "<dir>"] [-i] [-F] [-w] [-C <lines>] [--ext <e1,e2>] [-m <max>] [--no-symbols] [--json]`
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
- **Portable backup, restore, migration & own-risk inspection:**
  - `libredb backup [<dest_dir>] [--project "<dir>" | --cwd "<dir>"] [--cid <id>] [--instance] [--all] [--json]` (alias: `backup-ldb`)
  - `libredb restore <source_path> [--project "<dir>" | --cwd "<dir>"] [--instance] [--all] [--json]` (alias: `restore-ldb`)
  - `libredb migrate [<source_path>] [--cid <id>] [--project "<dir>" | --cwd "<dir>"] [--from-path "<old_dir>"] [--include-artifacts] [--json]` (alias: `migrate-ldb`)
  - `libredb read <path_or_dir> [--query "<substr>"] [--show-secrets] [--json]` (alias: `read-ldb`)

## Portable backup & migration rules

- **Mandatory backup prompt & warning:** When the user invokes `/libredb backup` without specifying a destination folder, ALWAYS warn them clearly that exported `.ldb` files contain unencrypted `portable_plain:` secrets and ask where to store the backup before executing it.
- **Auto-adopt on new project start:** Dropping a backed-up project `memory.ldb` into a brand-new project's `.agents/memory.ldb` automatically verifies `sys::backup_manifest`, re-encrypts any secrets locally, deletes the manifest, and seals it with `hmac-sha256:v4` on first open.
- **Fail-closed raw copies:** Copying raw `.ldb` files without `/libredb backup` fails closed on host/path mismatch; use `/libredb read <path_or_dir>` for strictly read-only own-risk inspection without sealing or trust changes.
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
# LibreDB cognitive memory plugin (v__VERSION__)

`LibreDB` gives `Antigravity` persistent project memory, targeted code navigation, and automated release workflows in a single 100% pure-Rust binary:

- **Persistent project memory (`libredb_pulse`, `libredb_memorize`)**: Stores architectural decisions, project facts, open tasks, and global rules in a single `.agents/memory.ldb` file, synchronizing updates incrementally (`O(1)` tail-sync) and skipping entries already shown in the session.
- **In-memory hook coordinator (`libredb mcp-serve`)**: Runs `PreInvocation` and `PreToolUse` hooks directly against the live MCP server RAM over a local Named Pipe or Unix socket, avoiding duplicate file locks and timeouts on slow network drives while falling back transparently to disk.
- **Targeted code navigation (`libredb_code`)**: Indexes functions, classes, and call relationships across 25+ languages so the agent can jump directly to symbol definitions (`locate`), inspect file outlines (`skeleton`), check affected callers (`impact`), run symbol-annotated searches (`grep`), and read exact file-less or line-targeted slices (`fim`) instead of loading entire large files.
- **Self-correcting learning (`libredb learning --verify`)**: Remembers which code symbol solved a failed search and which fix resolved a compiler or test error, refutes wrong hints automatically across 15 verified stages (`L1..L15`), and surfaces accurate pitfalls when similar code is touched later.
- **Token-savings reports and verification (`libredb savings`, `libredb bench`)**: Tracks real token savings across sessions and workspaces and runs built-in performance and security audit suites.
- **Workspace security and Git/Gitea releases (`libredb trust`, `libredb guardrail`, `libredb git-sync`)**: Encrypts credentials via OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), seals workspace databases against tampering (`HMAC-SHA256`), checks staged commits against project guardrails, and publishes versioned Git/Gitea releases with binary deliverables.
- **Neutral default profile**: `deploy_plugin.ps1` (`-Profile Neutral`, default) installs the MCP server and security guardrails with zero personal rules and preserves existing Git identities.
'@.Replace("__VERSION__", $LibreVersion)
[System.IO.File]::WriteAllText((Join-Path $PluginDir "README.md"), $PluginReadme, $Utf8NoBom)

# 8. Ensure "libredb": { "enabled": true } in ~/.gemini/config/config.json if present
$AgyConfigPath = Join-Path $GeminiDir "config\config.json"
if (Test-Path $AgyConfigPath) {
    try {
        $CfgObj = Get-Content $AgyConfigPath -Raw | ConvertFrom-Json
        if ($null -ne $CfgObj.plugins) {
            $AlreadyEnabled = $false
            if ($null -ne $CfgObj.plugins.PSObject.Properties["libredb"]) {
                $AlreadyEnabled = ($CfgObj.plugins.libredb.enabled -eq $true)
            }
            if (-not $AlreadyEnabled) {
                if ($null -eq $CfgObj.plugins.PSObject.Properties["libredb"]) {
                    $CfgObj.plugins | Add-Member -NotePropertyName "libredb" -NotePropertyValue ([PSCustomObject]@{ enabled = $true })
                } else {
                    $CfgObj.plugins.libredb.enabled = $true
                }
                $CfgJson = $CfgObj | ConvertTo-Json -Depth 20
                [System.IO.File]::WriteAllText($AgyConfigPath, $CfgJson, $Utf8NoBom)
            }
        }
    } catch {
        Write-Output "[WARN] Could not auto-update config.json plugin state: $_"
    }
}

Write-Output "[OK] Deployed LibreDB v$LibreVersion standalone binaries to: $BinDir (Profile=$Profile)"
Write-Output "[OK] Hydrated and modernized global store at: $GlobalLdb"
Write-Output "[OK] Installed complete Antigravity plugin at: $PluginDir"
