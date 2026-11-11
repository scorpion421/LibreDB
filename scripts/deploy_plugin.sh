#!/bin/sh
# POSIX / Linux / macOS Antigravity plugin installer for LibreDB (v0.10.0)
# Enterprise-neutral by default (never installs personal rules or imports legacy SQLite unless requested).
set -eu

PROFILE="neutral"
NO_HOOKS=0
MIGRATE_LEGACY=0
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
        --migrate-legacy)
            MIGRATE_LEGACY=1
            shift
            ;;
        -h|--help)
            echo "Usage: ./scripts/deploy_plugin.sh [--personal-rules | --profile neutral|personal] [--no-hooks] [--migrate-legacy]"
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

RELEASE_BIN="$PROJECT_ROOT/target/release/libredb"
if [ ! -f "$RELEASE_BIN" ]; then
    echo "[INFO] Release binary not found at $RELEASE_BIN; compiling from source..."
    (cd "$PROJECT_ROOT" && cargo build --release)
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

# Verify that a candidate hook directory is not world-writable without sticky bit (mirrors Test-SafeBinaryAcl).
test_safe_binary_dir() {
    check_dir="$1"
    [ -d "$check_dir" ] || return 1
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

# Install native CLI binary into ~/.gemini/antigravity/bin and ~/.local/bin for immediate PATH access
for path_dir in "$GEMINI_DIR/antigravity/bin" "$USER_HOME/.local/bin"; do
    mkdir -p "$path_dir"
    direct_bin="$path_dir/libredb"
    if [ "$direct_bin" != "$TARGET_EXE" ]; then
        install_binary_hot_safe "$RELEASE_BIN" "$direct_bin"
        echo "[OK] Installed native PATH CLI binary at: $direct_bin"
    fi
done

CENTRAL_SQLITE="$GEMINI_DIR/database/customizations.db"
GLOBAL_LDB="$LIBRE_HOME/customizations.ldb"
if [ ! -f "$GLOBAL_LDB" ]; then
    if { [ "$PROFILE" = "personal" ] || [ "$MIGRATE_LEGACY" -eq 1 ]; } && [ -f "$CENTRAL_SQLITE" ]; then
        "$TARGET_EXE" import-sqlite "$GLOBAL_LDB" "$CENTRAL_SQLITE" --scope central
    else
        "$TARGET_EXE" init "$GLOBAL_LDB" >/dev/null
    fi
fi
chmod 600 "$GLOBAL_LDB" 2>/dev/null || true

escape_json_str() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

EXE_JSON=$(escape_json_str "$TARGET_EXE")
GLOBAL_JSON=$(escape_json_str "$GLOBAL_LDB")

# 1. Write plugin.json
cat > "$PLUGIN_DIR/plugin.json" <<'EOF'
{
  "name": "libredb",
  "displayName": "LibreDB Cognitive Memory",
  "version": "0.10.0",
  "description": "Enterprise-ready Rust cognitive memory & MCP code graph: single-file LIBREDB1 storage, silent SQLite auto-porter, sub-2ms hooks, content-bound HMAC-SHA256 workspace trust seals, ChaCha20-Poly1305 OS credential vault, 20-language DI-aware causal code graph, and multi-remote Git/Gitea/GitHub automation.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Run a LibreDB cognitive pulse on the active workspace to load deduplicated context",
    "Check local Gitea status and run a strict LibreDB guardrail audit on the workspace",
    "Extract a surgical FIM code slice and DI blast-radius impact map with libredb_code"
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

# 3. Probe hook execution via /bin/sh -c and write hooks.json (unless --no-hooks was passed)
VERIFIED_HOOK_CMD=""
if [ "$NO_HOOKS" -eq 0 ]; then
    for cand_bin in "$BIN_DIR/libredb" "$GEMINI_DIR/antigravity/bin/libredb"; do
        cand_dir=$(dirname "$cand_bin")
        if ! test_safe_binary_dir "$cand_dir"; then
            continue
        fi
        case "$cand_bin" in
            *" "*) formatted_cmd="\"$cand_bin\"" ;;
            *) formatted_cmd="$cand_bin" ;;
        esac
        probe_out=$(printf '{}' | /bin/sh -c "$formatted_cmd hook-pre-invocation" 2>/dev/null || true)
        case "$probe_out" in
            *injectSteps*)
                VERIFIED_HOOK_CMD="$formatted_cmd"
                break
                ;;
        esac
    done
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
        "timeout": 5
      }
    ],
    "PreToolUse": [
      {
        "matcher": "run_command|invoke_subagent|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "$HOOK_JSON_CMD hook-pre-tool",
            "timeout": 5
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
   - Supports `ultra` (16 parallel reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 4 Carbon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, and `GPT-OSS 120B`. Keep 100% of code generation on `Gemini 4 Argon`, `Gemini 4 Carbon`, or `Claude 5.5`; route only read-only `research` subagents to `Model="flash"`.
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
   - `"skeleton"`: Returns a `92-99%` compressed `[Lstart-Lend]` contract map of a single `target` file or a multi-file batch (`files: [...]`) across 15+ languages (including `.smali`, `.asm`, `Makefile`, and `.md`) with session-aware `[Zero-Repeat Skeleton]` deduplication (`cid`).
   - `"impact"`: Returns bidirectional callers, DI/interface implementors, callees, and governing architectural decisions for a symbol.
   - `"fim"`: Returns a surgical `[Lstart-Lend]` edit slice with blast-radius callers, implementors, and governing decisions attached.
3. **`libredb_memorize`** (`cwd`, `cid`, `facts`, `decisions`, `tasks`, `snapshot`, `learn_assoc`, `learn_reflex`, `sync_central_sqlite`):
   - Atomically commits workspace/chat facts, architectural decisions (auto-linked to symbols), tasks, milestone snapshots, language-agnostic Hebbian concept bridges, or situational pitfall reflexes.

## CLI commands (`libredb`)

- **Guardrails:** `libredb guardrail check --path "<dir>" [--staged] [--strict]`
- **Workspace trust & universal config:**
  - `libredb trust [<dir>] [--revoke] [--list] [--accept-rollback] [--reinit-lost] [--migrate-v3 [--confirm-metadata]] [--migrate-v2] [--if-clean]`
  - `libredb config <get|set|unset|list> [<key>] [<value>] [--project "<dir>"]`
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
  - `libredb gitea-config [--url <u>] [--user <usr>] [--token <tok> | --token-stdin] [--allow-insecure-http <bool>] [--register-helper]`
EOF

# Modernize global DB in-place (encrypting any plaintext/v1 tokens via ChaCha20-Poly1305 + read-only v3 workspace seal audit)
if [ "$MIGRATE_LEGACY" -eq 1 ]; then
    "$TARGET_EXE" modernize-global --global "$GLOBAL_LDB" --skill-md "$SKILL_MD_PATH" --profile "$PROFILE" --migrate-legacy
else
    "$TARGET_EXE" modernize-global --global "$GLOBAL_LDB" --skill-md "$SKILL_MD_PATH" --profile "$PROFILE"
fi

if [ "$PROFILE" = "personal" ]; then
    "$TARGET_EXE" config set "hook:subagent_flash_routing" "true" --global "$GLOBAL_LDB" >/dev/null
    "$TARGET_EXE" config set "hook:exploratory_firewall" "true" --global "$GLOBAL_LDB" >/dev/null
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
cat > "$PLUGIN_DIR/README.md" <<'EOF'
# LibreDB cognitive memory plugin (v0.10.0)

Enterprise-ready standalone Rust cognitive memory & code-graph engine for `Antigravity`:
- `libredb-mcp`: 3-tool multi-workspace cognitive memory & 20-language zero-hardcode heuristic DI code-graph server with interface/implementation resolution (`implementors`), zero-I/O RAM session delta, `[Zero-Repeat Skeleton]` deduplication, and corpus-`IDF` call-graph disambiguation.
- Standards-compliant security: monotonic content-and-metadata-bound RFC 2104 `HMAC-SHA256` (`v4:r<rev>`) workspace trust seals (`libredb trust`), RFC 8439 `ChaCha20-Poly1305` AEAD OS credential vault (`0600` `.vault.key` with safe `vault:v1` -> `vault:v2` migration and symlink guards), symlink-canonicalized control-plane & credential path protection (`hooks.json`, `mcp_config.json`, `.git/hooks/*`, `.env`), and universal `libredb config` customization.
- Strictly neutral by default: `deploy_plugin.sh` installs `libredb-mcp` and security guardrails with `0` personal rules, `0` implicit legacy DB imports, and preserved corporate `git config` identity; pass `--personal-rules` for maintainer rules, `--migrate-legacy` to import legacy `customizations.db`, or `--no-hooks` for MCP-only evaluation.
- Compaction garbage collection (`compact_with_options`, `maybe_auto_compact`) and `INDEX_FORMAT_VERSION = 4` `HybridIndex` with dead-posting garbage collection across superseded Inodes.
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

echo "[OK] Deployed LibreDB v0.10.0 standalone binary to: $BIN_DIR (profile=$PROFILE)"
echo "[OK] Hydrated and modernized global store at: $GLOBAL_LDB"
echo "[OK] Installed complete Antigravity plugin at: $PLUGIN_DIR"
