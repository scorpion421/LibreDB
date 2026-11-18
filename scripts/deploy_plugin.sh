#!/bin/sh
# POSIX / Linux / macOS Antigravity plugin installer for LibreDB
# Enterprise-neutral by default (never installs personal rules unless requested).
set -eu

PROFILE="neutral"
NO_HOOKS=0
BINARY_PATH=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --personal-rules|--personal)
            PROFILE="personal"
            shift
            ;;
        --profile)
            PROFILE=$(printf '%s' "${2:-neutral}" | tr '[:upper:]' '[:lower:]')
            shift 2
            ;;
        --no-hooks)
            NO_HOOKS=1
            shift
            ;;
        --binary)
            BINARY_PATH="${2:-}"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./scripts/deploy_plugin.sh [--personal-rules | --profile neutral|personal] [--no-hooks] [--binary <path>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LIBRE_VERSION=$(tr -d ' \t\r\n' < "$PROJECT_ROOT/VERSION" 2>/dev/null || echo "2.4.2")
case "$LIBRE_VERSION" in
    ""|*[!0-9A-Za-z._+-]*) LIBRE_VERSION="2.4.2" ;;
esac
USER_HOME="${HOME:-$(pwd)}"
GEMINI_DIR="$USER_HOME/.gemini"
LIBRE_HOME="$GEMINI_DIR/libredb"
BIN_DIR="$LIBRE_HOME/bin"
PLUGIN_DIR="$GEMINI_DIR/config/plugins/libredb"
RULES_DIR="$PLUGIN_DIR/rules"
SKILL_DIR="$PLUGIN_DIR/skills/libredb"
ASSETS_DIR="$PLUGIN_DIR/assets"

mkdir -p "$BIN_DIR" "$RULES_DIR" "$SKILL_DIR" "$ASSETS_DIR"
chmod 700 "$LIBRE_HOME" 2>/dev/null || true

if [ -n "$BINARY_PATH" ]; then
    RELEASE_BIN="$BINARY_PATH"
elif [ -f "$PROJECT_ROOT/target/release/libredb" ]; then
    RELEASE_BIN="$PROJECT_ROOT/target/release/libredb"
elif [ -f "$PROJECT_ROOT/dist/libredb" ]; then
    RELEASE_BIN="$PROJECT_ROOT/dist/libredb"
else
    RELEASE_BIN="$PROJECT_ROOT/target/release/libredb"
    echo "[INFO] Release binary not found at $RELEASE_BIN or dist/libredb; compiling from source..."
    (cd "$PROJECT_ROOT" && cargo build --release)
fi
if [ ! -f "$RELEASE_BIN" ]; then
    echo "Release binary not found at $RELEASE_BIN." >&2
    exit 1
fi

# Atomic POSIX hot-swap install: copy to sibling temp file + chmod 0755 + mv -f
# Prevents ETXTBSY ("Text file busy") even while a live libredb mcp-serve process is running.
install_binary_hot_safe() {
    src="$1"
    dst="$2"
    tmp_dst="${dst}.tmp.$$"
    cp "$src" "$tmp_dst"
    chmod 0755 "$tmp_dst"
    mv -f "$tmp_dst" "$dst"
}

# Verify that a candidate hook directory is owned by current user/root and not world-writable without sticky bit.
test_safe_binary_dir() {
    check_dir="$1"
    [ -d "$check_dir" ] || return 1
    dir_uid=""
    if stat -c '%u' "$check_dir" >/dev/null 2>&1; then
        dir_uid=$(stat -c '%u' "$check_dir")
    elif stat -f '%u' "$check_dir" >/dev/null 2>&1; then
        dir_uid=$(stat -f '%u' "$check_dir")
    fi
    if [ -n "$dir_uid" ]; then
        current_uid=$(id -u)
        if [ "$dir_uid" -ne "$current_uid" ] && [ "$dir_uid" -ne 0 ]; then
            return 1
        fi
    fi
    perm_oct=""
    if stat -c '%a' "$check_dir" >/dev/null 2>&1; then
        perm_oct=$(stat -c '%a' "$check_dir")
    elif stat -f '%Lp' "$check_dir" >/dev/null 2>&1; then
        perm_oct=$(stat -f '%Lp' "$check_dir")
    fi
    if [ -n "$perm_oct" ]; then
        other_digit=$(printf '%s' "$perm_oct" | sed 's/.*\(.\)$/\1/')
        case "$other_digit" in
            2|3|6|7)
                # Reject world-writable directory unless sticky bit (1xxx) is set
                case "$perm_oct" in
                    1???|3???|5???|7???) ;;
                    *) return 1 ;;
                esac
                ;;
        esac
    fi
    return 0
}

TARGET_EXE="$BIN_DIR/libredb"
install_binary_hot_safe "$RELEASE_BIN" "$TARGET_EXE"

for py_lib in "$PROJECT_ROOT/target/release/liblibredb_py.so" "$PROJECT_ROOT/target/release/liblibredb_py.dylib"; do
    if [ -f "$py_lib" ]; then
        install_binary_hot_safe "$py_lib" "$BIN_DIR/libredb.so"
        break
    fi
done

# Remove legacy duplicate physical copies and expose canonical binary via atomic ~/.local/bin symlink
rm -f "$GEMINI_DIR/antigravity/bin/libredb" "$GEMINI_DIR/antigravity/bin/libredb.cmd"
LOCAL_BIN_DIR="$USER_HOME/.local/bin"
mkdir -p "$LOCAL_BIN_DIR"
chmod 755 "$LOCAL_BIN_DIR" 2>/dev/null || true
if [ "$LOCAL_BIN_DIR/libredb" != "$TARGET_EXE" ]; then
    ln -sf "$TARGET_EXE" "$LOCAL_BIN_DIR/.libredb.lnk.$$"
    mv -f "$LOCAL_BIN_DIR/.libredb.lnk.$$" "$LOCAL_BIN_DIR/libredb"
    echo "[OK] Linked canonical CLI binary into PATH at: $LOCAL_BIN_DIR/libredb -> $TARGET_EXE"
fi

# Provision ripgrep (rg) into canonical ~/.gemini/libredb/bin (+ ~/.local/bin symlink) if absent from standard PATH
RG_CANON_BIN="$BIN_DIR/rg"
RG_LEGACY_BIN="$GEMINI_DIR/antigravity/bin/rg"
if [ -x "$RG_CANON_BIN" ]; then
    rg_canon_ver=$("$RG_CANON_BIN" --version 2>/dev/null || true)
    case "$rg_canon_ver" in
        "ripgrep "*) echo "[OK] Native ripgrep (rg) verified at: $RG_CANON_BIN" ;;
    esac
elif [ -x "$RG_LEGACY_BIN" ]; then
    rg_agy_ver=$("$RG_LEGACY_BIN" --version 2>/dev/null || true)
    case "$rg_agy_ver" in
        "ripgrep "*) echo "[OK] Native ripgrep (rg) verified at: $RG_LEGACY_BIN" ;;
    esac
elif ! PATH="/usr/bin:/bin:$BIN_DIR:$LOCAL_BIN_DIR:$GEMINI_DIR/antigravity/bin" command -v rg >/dev/null 2>&1; then
    for rg_cand in /opt/homebrew/bin/rg /usr/local/bin/rg "$USER_HOME/.cargo/bin/rg" /usr/bin/rg; do
        if [ -x "$rg_cand" ]; then
            rg_ver=$("$rg_cand" --version 2>/dev/null || true)
            case "$rg_ver" in
                "ripgrep "*)
                    install_binary_hot_safe "$rg_cand" "$RG_CANON_BIN"
                    if [ "$LOCAL_BIN_DIR/rg" != "$RG_CANON_BIN" ] && [ ! -e "$LOCAL_BIN_DIR/rg" ]; then
                        ln -sf "$RG_CANON_BIN" "$LOCAL_BIN_DIR/rg"
                    fi
                    echo "[OK] Provisioned native ripgrep (rg) into canonical bin at: $RG_CANON_BIN"
                    break
                    ;;
            esac
        fi
    done
fi

GLOBAL_LDB="$LIBRE_HOME/customizations.ldb"
if [ ! -f "$GLOBAL_LDB" ]; then
    "$TARGET_EXE" init "$GLOBAL_LDB" >/dev/null
fi
chmod 600 "$GLOBAL_LDB" 2>/dev/null || true

escape_json_str() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

EXE_JSON=$(escape_json_str "$TARGET_EXE")
GLOBAL_JSON=$(escape_json_str "$GLOBAL_LDB")

# 1. Write plugin.json
cat > "$PLUGIN_DIR/plugin.json" <<EOF
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "$LIBRE_VERSION",
  "description": "Persistent project memory, fast code-graph search, and token-savings engine for Antigravity. Routes sub-millisecond lifecycle hooks via an in-memory MCP IPC coordinator with O(1) tail-sync, locates functions and call dependencies without reading whole files, enforces workspace guardrails, and automates Git/Gitea releases.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Show how many tokens LibreDB saved today and across my projects",
    "Load the project context, active decisions, and open tasks for this workspace",
    "Find where a function is defined and check which callers are affected before editing"
  ]
}
EOF

# 2. Write mcp_config.json
cat > "$PLUGIN_DIR/mcp_config.json" <<EOF
{
  "mcpServers": {
    "libredb-mcp": {
      "command": "$EXE_JSON",
      "args": [
        "mcp-serve",
        "--global",
        "$GLOBAL_JSON"
      ]
    }
  }
}
EOF

# 3. Probe canonical binary hook execution via /bin/sh -c and write hooks.json (unless --no-hooks was passed)
VERIFIED_HOOK_CMD=""
if [ "$NO_HOOKS" -eq 0 ]; then
    cand_bin="$BIN_DIR/libredb"
    cand_dir=$(dirname "$cand_bin")
    if test_safe_binary_dir "$cand_dir"; then
        case "$cand_bin" in
            *" "*) formatted_cmd="\"$cand_bin\"" ;;
            *) formatted_cmd="$cand_bin" ;;
        esac
        probe_out=$(printf '{}' | /bin/sh -c "$formatted_cmd hook-pre-invocation" 2>/dev/null || true)
        case "$probe_out" in
            *injectSteps*)
                VERIFIED_HOOK_CMD="$formatted_cmd"
                ;;
        esac
    fi
fi

if [ -n "$VERIFIED_HOOK_CMD" ]; then
    HOOK_JSON_CMD=$(escape_json_str "$VERIFIED_HOOK_CMD")
    cat > "$PLUGIN_DIR/hooks.json" <<EOF
{
  "libredb-autonomous-memory": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "$HOOK_JSON_CMD hook-pre-invocation",
        "timeout": 15
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|invoke_subagent|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "$HOOK_JSON_CMD hook-pre-tool",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
EOF
    echo "[OK] Verified POSIX sh hook execution and enabled hooks.json via: $VERIFIED_HOOK_CMD"
else
    cat > "$PLUGIN_DIR/hooks.json" <<'EOF'
{
  "libredb-autonomous-memory": {
    "enabled": false
  }
}
EOF
    if [ "$NO_HOOKS" -eq 1 ]; then
        echo "[OK] Installed hooks.json with enabled=false (--no-hooks MCP-only mode)."
    else
        echo "[WARN] Hook execution probe failed (e.g. noexec mount); set enabled=false in hooks.json so tool calls are never blocked."
    fi
fi

# 4. Optional personal rules profile: enterprise-neutral by default (never creates personal AGENTS.md unless --personal-rules)
if [ "$PROFILE" = "personal" ]; then
    UMLAUT_AE=$(printf '\303\244')
    UMLAUT_OE=$(printf '\303\266')
    UMLAUT_UE=$(printf '\303\274')
    UMLAUT_SS=$(printf '\303\237')
    UMLAUT_CAP_OE=$(printf '\303\226')
    UMLAUT_LIST="${UMLAUT_AE}, ${UMLAUT_OE}, ${UMLAUT_UE}, ${UMLAUT_SS}"
    TOKEN_OEK="Token${UMLAUT_OE}konomie"
    TOKEN_OEK_BAD="Token-${UMLAUT_CAP_OE}konomie"

    sed \
        -e "s/__UMLAUT_LIST__/$UMLAUT_LIST/g" \
        -e "s/__TOKEN_OEKONOMIE__/$TOKEN_OEK/g" \
        -e "s/__TOKEN_OEKONOMIE_BAD__/$TOKEN_OEK_BAD/g" \
        > "$RULES_DIR/AGENTS.md" <<'EOF'
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
EOF
    echo "[OK] Installed personal AGENTS.md rules directive (--personal-rules)."
elif [ -f "$RULES_DIR/AGENTS.md" ]; then
    first_line=$(head -n 1 "$RULES_DIR/AGENTS.md" 2>/dev/null || true)
    case "$first_line" in
        "# Central LibreDB rules directive"*)
            rm -f "$RULES_DIR/AGENTS.md"
            echo "[OK] Neutral profile: removed previous personal rules/AGENTS.md."
            ;;
        *)
            echo "[INFO] Neutral profile: preserving custom organization rules/AGENTS.md without modification."
            ;;
    esac
else
    echo "[OK] Neutral enterprise profile: no personal rules/AGENTS.md installed."
fi

# 5. Write progressive-disclosure SKILL.md
SKILL_MD_PATH="$SKILL_DIR/SKILL.md"
cat > "$SKILL_MD_PATH" <<'EOF'
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
   - `"backup"` / `"restore"` / `"migrate"` / `"read"`: Portable unencrypted export with `sys::backup_manifest` (`destination`), integrity-verified local re-encryption and sealing (`source`), standalone chat or moved-folder migration (`source`, `cid`, `from_path`, `include_artifacts`), and own-risk read-only inspection (`target`, `query`).
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
EOF

# Modernize global DB in-place (encrypting any plaintext/v1 tokens via ChaCha20-Poly1305 + read-only v4 workspace seal audit)
"$TARGET_EXE" modernize-global --global "$GLOBAL_LDB" --skill-md "$SKILL_MD_PATH" --skills-dir "$PROJECT_ROOT/skills" --profile "$PROFILE"

if [ "$PROFILE" = "personal" ]; then
    "$TARGET_EXE" config unset "hook:subagent_flash_routing" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config unset "hook:exploratory_firewall" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config set "guardrail:style_rules" "true" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config set "git:author_name" "Antigravity" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config set "git:author_email" "antigravity@local.dev" --global "$GLOBAL_LDB" >/dev/null
else
    "$TARGET_EXE" config unset "hook:subagent_flash_routing" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config unset "hook:exploratory_firewall" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config unset "guardrail:style_rules" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config unset "git:author_name" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config unset "git:author_email" --global "$GLOBAL_LDB" >/dev/null
fi

# Seal and incrementally index LibreDB's own workspace into .agents/memory.ldb ONLY if clean/untampered
SELF_LDB="$PROJECT_ROOT/.agents/memory.ldb"
trust_out=$("$TARGET_EXE" trust "$PROJECT_ROOT" --if-clean --global "$GLOBAL_LDB" 2>&1 || true)
printf '%s\n' "$trust_out"
case "$trust_out" in
    "[WARN]"*) ;;
    *) "$TARGET_EXE" index-workspace "$SELF_LDB" "$PROJECT_ROOT" --force || echo "[INFO] Workspace index skipped while older handle drains." ;;
esac

# 6. Write square transparent SVG logo
cat > "$ASSETS_DIR/logo.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <rect x="28" y="28" width="200" height="200" rx="44" fill="#0F172A" stroke="#38BDF8" stroke-width="10"/>
  <circle cx="88" cy="96" r="18" fill="#38BDF8"/>
  <circle cx="168" cy="96" r="18" fill="#A78BFA"/>
  <circle cx="128" cy="168" r="20" fill="#34D399"/>
  <line x1="103" y1="106" x2="117" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="153" y1="106" x2="139" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="106" y1="96" x2="150" y2="96" stroke="#94A3B8" stroke-width="7" stroke-dasharray="10 8" stroke-linecap="round"/>
</svg>
EOF

# 7. Write user-facing README.md inside plugin bundle
cat <<'EOF' | sed "s/__VERSION__/${LIBRE_VERSION}/g" > "$PLUGIN_DIR/README.md"
# LibreDB cognitive memory plugin (v__VERSION__)

`LibreDB` gives `Antigravity` persistent project memory, targeted code navigation, and automated release workflows in a single 100% pure-Rust binary:

- **Persistent project memory (`libredb_pulse`, `libredb_memorize`)**: Stores architectural decisions, project facts, open tasks, and global rules in a single `.agents/memory.ldb` file, synchronizing updates incrementally (`O(1)` tail-sync) and skipping entries already shown in the session.
- **In-memory hook coordinator (`libredb mcp-serve`)**: Runs `PreInvocation` and `PreToolUse` hooks directly against the live MCP server RAM over a local Unix socket or Named Pipe, avoiding duplicate file locks and timeouts on slow network drives while falling back transparently to disk.
- **Targeted code navigation (`libredb_code`)**: Indexes functions, classes, and call relationships across 25+ languages so the agent can jump directly to symbol definitions (`locate`), inspect file outlines (`skeleton`), check affected callers (`impact`), run symbol-annotated searches (`grep`), and read exact file-less or line-targeted slices (`fim`) instead of loading entire large files.
- **Self-correcting learning (`libredb learning --verify`)**: Remembers which code symbol solved a failed search and which fix resolved a compiler or test error, refutes wrong hints automatically across 15 verified stages (`L1..L15`), and surfaces accurate pitfalls when similar code is touched later.
- **Token-savings reports and verification (`libredb savings`, `libredb bench`)**: Tracks real token savings across sessions and workspaces and runs built-in performance and security audit suites.
- **Workspace security and Git/Gitea releases (`libredb trust`, `libredb guardrail`, `libredb git-sync`)**: Encrypts credentials via OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), seals workspace databases against tampering (`HMAC-SHA256`), checks staged commits against project guardrails, and publishes versioned Git/Gitea releases with binary deliverables.
- **Neutral default profile**: `deploy_plugin.sh` (neutral default) installs the MCP server and security guardrails with zero personal rules and preserves existing Git identities.
EOF

# 8. Enable "libredb" in ~/.gemini/config/config.json if present and python3 is available
AGY_CONFIG="$GEMINI_DIR/config/config.json"
if [ -f "$AGY_CONFIG" ] && [ ! -L "$AGY_CONFIG" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$AGY_CONFIG" <<'PYEOF' 2>/dev/null || true
import json, os, stat, sys, tempfile
p = sys.argv[1]
st = os.lstat(p)
if stat.S_ISLNK(st.st_mode):
    sys.exit(0)
with open(p, "r", encoding="utf-8") as f:
    cfg = json.load(f)
if isinstance(cfg.get("plugins"), dict):
    if cfg.get("plugins", {}).get("libredb", {}).get("enabled") is True:
        sys.exit(0)
    cfg["plugins"].setdefault("libredb", {})["enabled"] = True
    d = os.path.dirname(os.path.abspath(p))
    fd, tmp_p = tempfile.mkstemp(prefix=".config.json.tmp.", dir=d)
    try:
        os.chmod(tmp_p, stat.S_IMODE(st.st_mode))
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            json.dump(cfg, tf, indent=2)
            tf.flush()
            os.fsync(tf.fileno())
        os.replace(tmp_p, p)
    except Exception:
        try:
            os.unlink(tmp_p)
        except OSError:
            pass
PYEOF
    fi
fi

echo "[OK] Deployed LibreDB v${LIBRE_VERSION} standalone binary to: $BIN_DIR (profile=$PROFILE)"
echo "[OK] Hydrated and modernized global store at: $GLOBAL_LDB"
echo "[OK] Installed complete Antigravity plugin at: $PLUGIN_DIR"
