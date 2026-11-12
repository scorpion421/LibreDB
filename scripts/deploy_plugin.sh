#!/bin/sh
# POSIX / Linux / macOS Antigravity plugin installer for LibreDB (v1.1.1)
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
  "version": "1.2.0",
  "description": "Enterprise-ready Rust cognitive memory, token-economy analytics & MCP code graph: single-file LIBREDB1 storage, silent SQLite auto-porter, sub-2ms hooks, content-bound HMAC-SHA256 workspace trust seals, ChaCha20-Poly1305 OS credential vault, zero-hardcode topology & Dalvik/DI causal code graph, built-in benchmarks & token-savings reports, and multi-remote Git/Gitea/GitHub automation.",
  "logo": "assets/logo.svg",
  "suggestedPrompts": [
    "Show my LibreDB token savings report for today and all workspaces",
    "Run a LibreDB cognitive pulse on the active workspace to load deduplicated context",
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
   - **Anti-salami-slicing**: Read files `<= 800 lines` in one `read_file` call; for `> 800 lines` use `libredb_code` (`skeleton`, `fim`, `impact`) and batch parallel reads.
   - **Subagent firewall**: Run 1-3 file edits and WMI/CIM commands in main context; delegate `>= 4` searches or `> 5` files to `research` (`Model="flash"`).
   - **Batching & verification**: Fix entire bug classes before rebuilding, chain `build && test && verify`, commit memory via `libredb_memorize`, check `libredb guardrail check --path "<dir>" --staged --strict`, inspect savings/benchmarks natively via `libredb savings` and `libredb bench` (zero ad-hoc scripts), and use `WaitMsBeforeAsync=10000` without polling. Note any internal tool workarounds briefly at the end.

6. **Autonomous project memory & Git/Gitea sync (pure Pull)**:
   - Persist/recall via `libredb_memorize`, `libredb_pulse` (`query`, `cwd`, `cid`, `budget`), and `libredb get-skill <name> [--section "<Section>"]` on `.agents/memory.ldb` (auto-migrating legacy `.agents/memory.db` 1:1).
   - Use `libredb git-init`, `git-sync`, `git-release`, and `gitea-status`. Never hijack non-Gitea `origin` remotes or leak Gitea auth headers; ask before `--allow-unversioned` ("Soll ich das wirklich ohne Versionierung hochladen?") and pause on `[GITEA REPOSITORY COLLISION]`. Link URLs as `[Label](url)`.

7. **Model & concurrency catalog**:
   - `ultra` (16 reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 4 Carbon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`. Keep 100% of code generation on `Argon`, `Carbon`, or `Claude 5.5`; route only read-only `research` subagents to `Model="flash"`.
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
EOF

# Modernize global DB in-place (encrypting any plaintext/v1 tokens via ChaCha20-Poly1305 + read-only v3 workspace seal audit)
if [ "$MIGRATE_LEGACY" -eq 1 ]; then
    "$TARGET_EXE" modernize-global --global "$GLOBAL_LDB" --skill-md "$SKILL_MD_PATH" --profile "$PROFILE" --migrate-legacy
else
    "$TARGET_EXE" modernize-global --global "$GLOBAL_LDB" --skill-md "$SKILL_MD_PATH" --profile "$PROFILE"
fi

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
cat > "$PLUGIN_DIR/README.md" <<'EOF'
# LibreDB cognitive memory plugin (v1.2.0)

Enterprise-ready standalone Rust cognitive memory, token-economy analytics & code-graph engine for `Antigravity`:
- `libredb-mcp`: 3-tool multi-workspace cognitive memory & 25+ language zero-hardcode topology + exact Dalvik/DI code-graph server with `< 0.5 ms` `locate`, batched `impact` (`symbols`) & `fim` (`slices`), tentative-verified `PreToolUse` ACID symbol shifting, subagent-aware priority-budgeted `BM25` `PreInvocation` hydration, zero-I/O RAM session delta, and `[Zero-Repeat Skeleton]` deduplication.
- Built-in analytics, benchmarks & verification suite: `libredb savings` (`report`) combines cross-process-atomic `~/.gemini/libredb/telemetry.ldb` counters with bounded streaming `Antigravity` transcript parsing (`<= 8 MiB/line`, 3-tier observed vs counterfactual vs provider usage), and `libredb bench` (`--suite kernel|full|audit`, `--workspace`) runs `C1..C6` token-economy benchmarks and `A1..A10` security/feature audits natively without external scripts.
- Standards-compliant security: monotonic content-and-metadata-bound RFC 2104 `HMAC-SHA256` (`v4:r<rev>`) workspace trust seals (`libredb trust`), RFC 8439 `ChaCha20-Poly1305` AEAD OS credential vault (`0600` `.vault.key` with safe `vault:v1` -> `vault:v2` migration and symlink guards), symlink-canonicalized control-plane & credential path protection, and universal `libredb config` customization.
- Strictly neutral by default: `deploy_plugin.sh` installs `libredb-mcp` and security guardrails with `0` personal rules, `0` implicit legacy DB imports, and preserved corporate `git config` identity.
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

echo "[OK] Deployed LibreDB v1.2.0 standalone binary to: $BIN_DIR (profile=$PROFILE)"
echo "[OK] Hydrated and modernized global store at: $GLOBAL_LDB"
echo "[OK] Installed complete Antigravity plugin at: $PLUGIN_DIR"
