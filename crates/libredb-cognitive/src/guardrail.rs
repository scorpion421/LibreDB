//! High-speed native Rust guardrail scanner (`< 0.3 ms` per file, binary-safe) enforcing
//! formatting invariants, SemVer immutability, zero-polling, and SOC-compliant administration.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailViolation {
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailAuditReport {
    pub files_checked: usize,
    pub violations: Vec<GuardrailViolation>,
}

impl GuardrailAuditReport {
    pub fn passed(&self, strict: bool) -> bool {
        if strict {
            self.violations.is_empty()
        } else {
            !self.violations.iter().any(|v| v.severity == "CRITICAL")
        }
    }
}

/// Checks full-file text content for formatting and scripting guardrail violations.
pub fn check_text_guardrails(text: &str, filename: &str) -> Vec<GuardrailViolation> {
    check_text_guardrails_with_options(text, filename, true, &[])
}

/// Checks text content (either a full file when `is_full_file == true`, or a partial `edit_file`
/// snippet when `is_full_file == false`) for formatting and scripting guardrail violations.
pub fn check_text_guardrails_with_mode(
    text: &str,
    filename: &str,
    is_full_file: bool,
) -> Vec<GuardrailViolation> {
    check_text_guardrails_with_options(text, filename, is_full_file, &[])
}

/// Checks text content with optional user-configured dynamic secret prefixes (`guardrail:secret_prefixes`).
pub fn check_text_guardrails_with_options(
    text: &str,
    filename: &str,
    is_full_file: bool,
    custom_secret_prefixes: &[String],
) -> Vec<GuardrailViolation> {
    let mut out = Vec::new();
    let low_name = filename.to_ascii_lowercase().replace('\\', "/");

    if low_name.ends_with(".vbs") || low_name.ends_with(".vbe") {
        out.push(GuardrailViolation {
            rule: "no-vbscript".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: filename.to_owned(),
            line: 1,
            message: "VBScript (.vbs/.vbe) files are strictly prohibited. Use PowerShell, Python, or Rust.".to_owned(),
            snippet: filename.to_owned(),
        });
    }

    let is_changelog = low_name == "changelog.md" || low_name.ends_with("/changelog.md");
    let mut seen_changelog_versions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut has_changelog_h1 = false;

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        for ch in line.chars() {
            if ch == '\u{2014}' || ch == '\u{2013}' {
                out.push(GuardrailViolation {
                    rule: "no-em-en-dash".to_owned(),
                    severity: "CRITICAL".to_owned(),
                    file: filename.to_owned(),
                    line: line_no,
                    message: "Em-dashes (U+2014) and en-dashes (U+2013) are forbidden; use ASCII '-', ':', or parentheses.".to_owned(),
                    snippet: truncate_ascii_safe(line.trim(), 90),
                });
                break;
            }
        }

        if let Some(bad_cp) = find_emoji_codepoint(line) {
            out.push(GuardrailViolation {
                rule: "no-emojis".to_owned(),
                severity: "CRITICAL".to_owned(),
                file: filename.to_owned(),
                line: line_no,
                message: format!(
                    "Emojis and decorative pictographs (U+{:04X}) are forbidden across all outputs and source files.",
                    bad_cp as u32
                ),
                snippet: truncate_ascii_safe(line.trim(), 90),
            });
        }

        if let Some(secret_kind) = detect_secret_leak(line, custom_secret_prefixes) {
            out.push(GuardrailViolation {
                rule: "no-hardcoded-secrets".to_owned(),
                severity: "CRITICAL".to_owned(),
                file: filename.to_owned(),
                line: line_no,
                message: format!(
                    "Hardcoded secret or private key detected ({secret_kind}). Store credentials in DPAPI or customizations.ldb instead."
                ),
                snippet: truncate_ascii_safe(line.trim(), 70),
            });
        }

        if let Some(host_leak) = detect_hardcoded_internal_unc(line) {
            out.push(GuardrailViolation {
                rule: "no-hardcoded-hosts-or-domains".to_owned(),
                severity: "CRITICAL".to_owned(),
                file: filename.to_owned(),
                line: line_no,
                message: format!(
                    "Hardcoded internal AD domain or UNC host path detected ({host_leak}). Use generic '.example' placeholders in tests and runtime configuration elsewhere."
                ),
                snippet: truncate_ascii_safe(line.trim(), 70),
            });
        }

        if is_changelog {
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("# changelog") {
                has_changelog_h1 = true;
            } else if let Some(rest) = trimmed.strip_prefix("## [") {
                if let Some(end_br) = rest.find(']') {
                    let ver = rest[..end_br].trim_start_matches(['v', 'V']).trim();
                    if !ver.eq_ignore_ascii_case("unreleased") {
                        if !seen_changelog_versions.insert(ver.to_ascii_lowercase()) {
                            out.push(GuardrailViolation {
                                rule: "changelog-duplicate-version".to_owned(),
                                severity: "CRITICAL".to_owned(),
                                file: filename.to_owned(),
                                line: line_no,
                                message: format!(
                                    "Duplicate version section '[{ver}]' in CHANGELOG.md. Never overwrite or duplicate a published SemVer release; increment to a new version."
                                ),
                                snippet: truncate_ascii_safe(trimmed, 90),
                            });
                        }
                        let after = rest[end_br + 1..].trim();
                        if !is_valid_changelog_date_suffix(after) {
                            out.push(GuardrailViolation {
                                rule: "keep-a-changelog-format".to_owned(),
                                severity: "CRITICAL".to_owned(),
                                file: filename.to_owned(),
                                line: line_no,
                                message: "Keep a Changelog 1.1.0 requires release headings to follow '## [X.Y.Z] - YYYY-MM-DD'.".to_owned(),
                                snippet: truncate_ascii_safe(trimmed, 90),
                            });
                        }
                    }
                }
            }
        }

        if is_executable_script_ext(&low_name) {
            let l_low = line.to_ascii_lowercase();
            if l_low.contains("createobject(\"wscript.")
                || l_low.contains("createobject('wscript.")
                || l_low.starts_with("cscript ")
                || l_low.starts_with("wscript ")
            {
                out.push(GuardrailViolation {
                    rule: "no-vbscript".to_owned(),
                    severity: "CRITICAL".to_owned(),
                    file: filename.to_owned(),
                    line: line_no,
                    message: "Invoking WScript/CScript or WScript COM objects is prohibited.".to_owned(),
                    snippet: truncate_ascii_safe(line.trim(), 90),
                });
            }
        }
    }

    if is_changelog && is_full_file && !text.trim().is_empty() && !has_changelog_h1 {
        out.push(GuardrailViolation {
            rule: "keep-a-changelog-format".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: filename.to_owned(),
            line: 1,
            message: "CHANGELOG.md must start with a '# Changelog' heading per Keep a Changelog 1.1.0.".to_owned(),
            snippet: truncate_ascii_safe(text.lines().next().unwrap_or(""), 90),
        });
    }

    out
}

/// Checks a shell command string (`run_command`) for operational, SemVer, and SOC security guardrails.
pub fn check_command_guardrails(cmd_line: &str) -> Option<GuardrailViolation> {
    let trimmed = cmd_line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. SemVer immutability: block `git tag -f` / `--force` on version tags
    if contains_forced_git_semver_tag(trimmed) {
        return Some(GuardrailViolation {
            rule: "semver-immutability".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: "<command>".to_owned(),
            line: 1,
            message: "Never overwrite an already published release tag in place (git tag -f is forbidden by SemVer 2.0.0). Increment VERSION and CHANGELOG.md instead.".to_owned(),
            snippet: truncate_ascii_safe(trimmed, 100),
        });
    }

    let cmd_low = trimmed.to_ascii_lowercase().replace('/', "\\");

    // 2. Zero-polling guard on background task logs
    if cmd_low.contains(".system_generated\\tasks\\task-")
        && (cmd_low.contains("get-content")
            || cmd_low.contains("cat ")
            || cmd_low.contains("type ")
            || cmd_low.contains("get-item"))
    {
        return Some(GuardrailViolation {
            rule: "zero-polling-guard".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: "<command>".to_owned(),
            line: 1,
            message: "Never use run_command to poll '.system_generated/tasks/*.log'. Wait for automatic Reactive Wakeup or use read_file after completion.".to_owned(),
            snippet: truncate_ascii_safe(trimmed, 100),
        });
    }

    // 3. SOC/EDR lateral movement & remote service / C:\Windows\Temp staging guard
    let is_remote = [
        "invoke-command",
        "icm ",
        "-computername",
        "-cimsession",
        "enter-pssession",
        "new-pssession",
        "\\\\",
    ]
    .iter()
    .any(|k| cmd_low.contains(k));

    let has_forbidden_lateral = [
        "register-scheduledtask",
        "start-scheduledtask",
        "new-scheduledtaskaction",
        "schtasks",
        "psexec",
        "sc.exe \\\\",
        "windows\\temp\\",
    ]
    .iter()
    .any(|k| cmd_low.contains(k));

    if (is_remote && has_forbidden_lateral)
        || cmd_low.contains("sc.exe \\\\")
        || cmd_low.contains("psexec")
    {
        return Some(GuardrailViolation {
            rule: "no-server-scheduled-tasks-or-temp-scripts".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: "<command>".to_owned(),
            line: 1,
            message: "Creating remote Scheduled Tasks, remote services (sc.exe \\\\), PsExec, or staging scripts in C:\\Windows\\Temp is strictly forbidden.".to_owned(),
            snippet: truncate_ascii_safe(trimmed, 100),
        });
    }

    // 4. Block obfuscated PowerShell Base64 command execution (`-EncodedCommand` / `-enc`)
    if contains_obfuscated_encoded_command(trimmed) {
        return Some(GuardrailViolation {
            rule: "no-obfuscated-encoded-command".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: "<command>".to_owned(),
            line: 1,
            message: "Obfuscated PowerShell -EncodedCommand execution is forbidden by transparent SOC administration rules; execute readable commands directly.".to_owned(),
            snippet: truncate_ascii_safe(trimmed, 100),
        });
    }

    // 5. Block Git execution-hook hijacks (`core.hooksPath`, `core.fsmonitor`, `core.sshCommand`,
    //    `protocol.ext.allow`) and shell tampering/exfiltration targeting `.vault.key` or `.seal_locks`.
    if let Some(reason) = detect_git_exec_or_vault_tamper_command(&cmd_low) {
        return Some(GuardrailViolation {
            rule: "no-git-exec-hijack-or-vault-tamper".to_owned(),
            severity: "CRITICAL".to_owned(),
            file: "<command>".to_owned(),
            line: 1,
            message: reason.to_owned(),
            snippet: truncate_ascii_safe(trimmed, 100),
        });
    }

    None
}

fn detect_git_exec_or_vault_tamper_command(cmd_low: &str) -> Option<&'static str> {
    for pat in [
        "core.hookspath",
        "core.fsmonitor",
        "core.sshcommand",
        "git_ssh_command=",
        "protocol.ext.allow",
        "uploadpack=",
        "receivepack=",
    ] {
        if cmd_low.contains(pat) {
            return Some(
                "Overriding Git execution hooks, fsmonitor, SSH command, or ext protocol via shell commands is prohibited.",
            );
        }
    }
    if cmd_low.contains(".vault.key") || cmd_low.contains(".seal_locks") {
        return Some(
            "Direct shell access to LibreDB '.vault.key' or '.seal_locks' security state is prohibited.",
        );
    }
    None
}

fn ascii_ci_tag_len(rest: &str, tag: &str) -> Option<usize> {
    if rest.len() < tag.len() {
        return None;
    }
    let bytes = rest.as_bytes();
    let tag_bytes = tag.as_bytes();
    if !bytes[..tag_bytes.len()].eq_ignore_ascii_case(tag_bytes) {
        return None;
    }
    let next = bytes.get(tag_bytes.len()).copied();
    if matches!(next, None | Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')) {
        Some(tag_bytes.len())
    } else {
        None
    }
}

fn close_raw_block_len(rest: &str, close_tag: &str) -> Option<usize> {
    if rest.len() < close_tag.len() {
        return None;
    }
    let bytes = rest.as_bytes();
    if !bytes[..close_tag.len()].eq_ignore_ascii_case(close_tag.as_bytes()) {
        return None;
    }
    let mut k = close_tag.len();
    while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') {
        k += 1;
    }
    if bytes.get(k) == Some(&b'>') {
        Some(k + 1)
    } else {
        None
    }
}

fn push_spaces_for_ascii_len(out: &mut String, len: usize) {
    for _ in 0..len {
        out.push(' ');
    }
}

/// Blanks Markdown code fences, inline backticks, Markdown link URLs, HTML comments,
/// raw/code HTML elements (`<pre>`, `<style>`, `<script>`, `<svg>`, `<code>`), and HTML
/// tag attributes across lines while preserving word boundaries as ASCII spaces.
fn sanitize_prose_lines(lines: &[&str]) -> Vec<String> {
    let mut sanitized = Vec::with_capacity(lines.len());
    let mut in_fence = false;
    let mut in_comment = false;
    let mut raw_block_end: Option<&'static str> = None;
    let mut code_depth = 0usize;
    let mut in_tag = false;
    let mut tag_quote: Option<char> = None;
    let mut self_closing_slash = false;
    let mut pending_raw_end: Option<&'static str> = None;
    let mut pending_code_open = false;
    let mut pending_code_close = false;

    for &line in lines {
        if line.trim().is_empty() && !in_comment && raw_block_end.is_none() && code_depth == 0 {
            // Reset dangling unclosed `<` in plain Markdown prose on blank paragraph boundaries.
            in_tag = false;
            tag_quote = None;
            self_closing_slash = false;
            pending_raw_end = None;
            pending_code_open = false;
            pending_code_close = false;
        }
        if raw_block_end.is_none()
            && !in_comment
            && !in_tag
            && line.trim_start().starts_with("```")
        {
            in_fence = !in_fence;
            sanitized.push(String::new());
            continue;
        }
        if in_fence {
            sanitized.push(String::new());
            continue;
        }

        let mut out = String::with_capacity(line.len());
        let mut in_tick = false;
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i < line.len() {
            let Some(ch) = line[i..].chars().next() else {
                break;
            };
            if in_comment {
                if line[i..].starts_with("-->") {
                    out.push_str("   ");
                    i += 3;
                    in_comment = false;
                } else {
                    out.push(' ');
                    i += ch.len_utf8();
                }
                continue;
            }
            if let Some(end_tag) = raw_block_end {
                if let Some(close_len) = close_raw_block_len(&line[i..], end_tag) {
                    push_spaces_for_ascii_len(&mut out, close_len);
                    i += close_len;
                    raw_block_end = None;
                } else {
                    out.push(' ');
                    i += ch.len_utf8();
                }
                continue;
            }
            if in_tag {
                out.push(' ');
                if let Some(q) = tag_quote {
                    if ch == q {
                        tag_quote = None;
                    }
                    self_closing_slash = false;
                } else if ch == '"' || ch == '\'' {
                    tag_quote = Some(ch);
                    self_closing_slash = false;
                } else if ch == '>' {
                    in_tag = false;
                    if pending_code_close {
                        code_depth = code_depth.saturating_sub(1);
                    } else if !self_closing_slash {
                        if let Some(end_tag) = pending_raw_end {
                            raw_block_end = Some(end_tag);
                        } else if pending_code_open {
                            code_depth += 1;
                        }
                    }
                    self_closing_slash = false;
                    pending_raw_end = None;
                    pending_code_open = false;
                    pending_code_close = false;
                } else if ch == '/' {
                    self_closing_slash = true;
                } else if !ch.is_whitespace() {
                    self_closing_slash = false;
                }
                i += ch.len_utf8();
                continue;
            }

            if ch == '`' && code_depth == 0 {
                in_tick = !in_tick;
                out.push(' ');
                i += 1;
                continue;
            }
            if !in_tick {
                if line[i..].starts_with("<!--") {
                    in_comment = true;
                    out.push_str("    ");
                    i += 4;
                    continue;
                }
                if ch == '<'
                    && bytes
                        .get(i + 1)
                        .is_some_and(|&b| b.is_ascii_alphabetic() || matches!(b, b'/' | b'!' | b'?'))
                {
                    let rest = &line[i + 1..];
                    pending_raw_end = None;
                    pending_code_open = false;
                    pending_code_close = false;
                    if ascii_ci_tag_len(rest, "/code").is_some() {
                        pending_code_close = true;
                    } else if ascii_ci_tag_len(rest, "code").is_some() {
                        pending_code_open = true;
                    } else if ascii_ci_tag_len(rest, "pre").is_some() {
                        pending_raw_end = Some("</pre");
                    } else if ascii_ci_tag_len(rest, "style").is_some() {
                        pending_raw_end = Some("</style");
                    } else if ascii_ci_tag_len(rest, "script").is_some() {
                        pending_raw_end = Some("</script");
                    } else if ascii_ci_tag_len(rest, "svg").is_some() {
                        pending_raw_end = Some("</svg");
                    }
                    in_tag = true;
                    tag_quote = None;
                    self_closing_slash = false;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                if code_depth == 0 && line[i..].starts_with("](") {
                    out.push(']');
                    out.push(' ');
                    i += 2;
                    let mut depth = 1usize;
                    while i < line.len() && depth > 0 {
                        let Some(u_ch) = line[i..].chars().next() else {
                            break;
                        };
                        match u_ch {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        out.push(' ');
                        i += u_ch.len_utf8();
                    }
                    continue;
                }
            }

            if in_tick || code_depth > 0 {
                out.push(' ');
            } else {
                out.push(ch);
            }
            i += ch.len_utf8();
        }
        sanitized.push(out);
    }

    sanitized
}

fn is_exempt_technical_hyphen_term(l_low: &str, r_low: &str) -> bool {
    matches!(
        (l_low, r_low),
        ("wi", "fi")
            | ("add", "in")
            | ("add", "ins")
            | ("add", "on")
            | ("add", "ons")
            | ("opt", "in")
            | ("opt", "out")
            | ("plug", "in")
            | ("plug", "ins")
            | ("stand", "by")
            | ("sign", "on")
            | ("sign", "in")
            | ("sign", "out")
            | ("log", "in")
            | ("log", "on")
            | ("log", "out")
            | ("check", "in")
            | ("check", "out")
            | ("roll", "out")
            | ("roll", "back")
            | ("fail", "over")
            | ("built", "in")
            | ("pass", "through")
    )
}

fn is_powershell_cmdlet_verb(l_low: &str) -> bool {
    matches!(
        l_low,
        "get"
            | "set"
            | "start"
            | "stop"
            | "restart"
            | "enable"
            | "disable"
            | "new"
            | "remove"
            | "invoke"
            | "test"
            | "select"
            | "where"
            | "foreach"
            | "import"
            | "export"
            | "register"
            | "unregister"
            | "resolve"
            | "clear"
            | "update"
            | "install"
            | "uninstall"
            | "add"
            | "read"
            | "write"
            | "out"
            | "format"
            | "convertto"
            | "convertfrom"
            | "compare"
            | "expand"
            | "compress"
            | "copy"
            | "move"
            | "rename"
            | "split"
            | "join"
            | "enter"
            | "exit"
            | "push"
            | "pop"
            | "show"
            | "hide"
            | "find"
            | "search"
            | "watch"
            | "wait"
            | "measure"
            | "trace"
            | "debug"
            | "reset"
            | "repair"
            | "restore"
            | "backup"
            | "confirm"
            | "grant"
            | "revoke"
            | "protect"
            | "unprotect"
            | "mount"
            | "dismount"
            | "publish"
            | "unpublish"
            | "connect"
            | "disconnect"
    )
}

fn has_german_prose_context_lines(sanitized_lines: &[&str]) -> bool {
    const GERMAN_MARKERS: &[&str] = &[
        concat!("ni", "cht"),
        concat!("au", "ch"),
        concat!("no", "ch"),
        concat!("od", "er"),
        concat!("ab", "er"),
        concat!("we", "il"),
        concat!("da", "ss"),
        concat!("si", "nd"),
        concat!("wi", "rd"),
        concat!("wer", "den"),
        concat!("ka", "nn"),
        concat!("ei", "ne"),
        concat!("ei", "nen"),
        concat!("ei", "ner"),
        concat!("ei", "nem"),
        concat!("fu", "er"),
        concat!("ue", "ber"),
        concat!("mi", "t"),
        concat!("au", "f"),
        concat!("be", "i"),
        concat!("na", "ch"),
        concat!("zu", "m"),
        concat!("zu", "r"),
        concat!("vo", "m"),
        concat!("se", "hr"),
        concat!("me", "hr"),
        concat!("sc", "hon"),
        concat!("die", "ser"),
        concat!("die", "se"),
        concat!("die", "ses"),
    ];
    let mut hits = 0usize;
    let mut seen = [false; 30];
    for line in sanitized_lines {
        for word in line.split(|c: char| !c.is_alphabetic()) {
            if word.len() < 2 {
                continue;
            }
            let lc = word.to_lowercase();
            for (idx, marker) in GERMAN_MARKERS.iter().enumerate() {
                if !seen[idx] && lc == *marker {
                    seen[idx] = true;
                    hits += 1;
                    if hits >= 2 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Checks German prose/Markdown/artifact text for ASCII umlaut substitutions (`ae`/`oe`/`ue`)
/// and hyphen-split German compound nouns (Deppenbindestriche), skipping code fences and inline code.
pub fn check_german_prose_style(text: &str, filename: &str) -> Vec<GuardrailViolation> {
    const ASCII_UMLAUT_WORDS: &[&str] = &[
        concat!("lae", "sst"),
        concat!("lae", "ngst"),
        concat!("lae", "nge"),
        concat!("wae", "re"),
        concat!("wae", "ren"),
        concat!("hae", "tte"),
        concat!("hae", "tten"),
        concat!("nae", "chste"),
        concat!("nae", "chsten"),
        concat!("nae", "chstes"),
        concat!("nae", "chster"),
        concat!("zae", "hlt"),
        concat!("ae", "hnlich"),
        concat!("ae", "hnliche"),
        concat!("ae", "nderung"),
        concat!("ae", "nderungen"),
        concat!("stae", "rker"),
        concat!("spae", "ter"),
        concat!("mae", "ssig"),
        concat!("trae", "gt"),
        concat!("fae", "llt"),
        concat!("hae", "lt"),
        concat!("schlae", "gt"),
        concat!("wae", "hlt"),
        concat!("wae", "hrend"),
        concat!("erwae", "hnt"),
        concat!("vertrae", "gt"),
        concat!("bewae", "hrt"),
        concat!("prae", "zise"),
        concat!("tempo", "raer"),
        concat!("pri", "maer"),
        concat!("sekun", "daer"),
        concat!("koe", "nnen"),
        concat!("koe", "nnte"),
        concat!("koe", "nnten"),
        concat!("koe", "nnt"),
        concat!("moe", "glich"),
        concat!("moe", "gliche"),
        concat!("moe", "glichen"),
        concat!("moe", "glichkeit"),
        concat!("moe", "chte"),
        concat!("moe", "chten"),
        concat!("groe", "sser"),
        concat!("groe", "sste"),
        concat!("groe", "ssten"),
        concat!("groe", "sse"),
        concat!("hoe", "her"),
        concat!("hoe", "chste"),
        concat!("loe", "sen"),
        concat!("loe", "sung"),
        concat!("loe", "sungen"),
        concat!("loe", "schen"),
        concat!("gehoe", "rt"),
        concat!("stoe", "rt"),
        concat!("voe", "llig"),
        concat!("noe", "tig"),
        concat!("benoe", "tigt"),
        concat!("persoe", "nlich"),
        concat!("woe", "rtlich"),
        concat!("unmoe", "glich"),
        concat!("ausloe", "sen"),
        concat!("abloe", "sen"),
        concat!("oeko", "nomie"),
        concat!("fu", "er"),
        concat!("fue", "rs"),
        concat!("fue", "hrt"),
        concat!("fue", "hren"),
        concat!("fue", "hrte"),
        concat!("fue", "hlen"),
        concat!("ue", "ber"),
        concat!("ue", "bersicht"),
        concat!("ueb", "rig"),
        concat!("ueb", "ung"),
        concat!("ueb", "lich"),
        concat!("rue", "ck"),
        concat!("zurue", "ck"),
        concat!("prue", "fen"),
        concat!("prue", "fung"),
        concat!("geprue", "ft"),
        concat!("mue", "ssen"),
        concat!("mue", "sste"),
        concat!("mue", "ssten"),
        concat!("gru", "en"),
        concat!("grue", "nde"),
        concat!("grue", "ndung"),
        concat!("gue", "ltig"),
        concat!("ungue", "ltig"),
        concat!("kue", "rzen"),
        concat!("frue", "h"),
        concat!("frue", "her"),
        concat!("natue", "rlich"),
        concat!("wue", "rde"),
        concat!("wue", "rden"),
        concat!("stue", "tzt"),
        concat!("unterstue", "tzt"),
        concat!("unterstue", "tzen"),
        concat!("verfue", "gbar"),
        concat!("fu", "enf"),
        concat!("schue", "tzt"),
        concat!("schlue", "ssel"),
        concat!("ausfue", "hren"),
        concat!("ausfue", "hrung"),
        concat!("einfue", "hren"),
        concat!("einfue", "hrung"),
        concat!("aufgefue", "hrt"),
        concat!("durchgefue", "hrt"),
        concat!("lue", "cke"),
        concat!("due", "rfen"),
        concat!("due", "rfte"),
        concat!("brue", "cke"),
        concat!("bue", "ro"),
        concat!("spue", "rbar"),
        concat!("verknue", "pft"),
    ];
    const GERMAN_NOUN_ROOTS: &[&str] = &[
        concat!("pra", "xis"),
        concat!("archi", "tektur"),
        concat!("feh", "ler"),
        concat!("bef", "und"),
        concat!("kon", "text"),
        concat!("kontin", "gent"),
        concat!("spei", "cher"),
        concat!("re", "gel"),
        concat!("steue", "rung"),
        concat!("verwal", "tung"),
        concat!("daten", "bank"),
        concat!("oeko", "nomie"),
        concat!("prue", "fung"),
        concat!("ue", "bersicht"),
        concat!("umset", "zung"),
        concat!("auswer", "tung"),
        concat!("einstel", "lung"),
        concat!("abfr", "age"),
        concat!("zugr", "iff"),
        concat!("lauf", "zeit"),
    ];

    let lines: Vec<&str> = text.lines().collect();
    let sanitized_lines = sanitize_prose_lines(&lines);
    let mut line_german_ctx = vec![false; lines.len()];
    {
        let mut start = 0usize;
        while start < lines.len() {
            if sanitized_lines[start].trim().is_empty() {
                start += 1;
                continue;
            }
            let mut end = start;
            let mut para_lines: Vec<&str> = Vec::new();
            while end < lines.len() && !sanitized_lines[end].trim().is_empty() {
                para_lines.push(sanitized_lines[end].as_str());
                end += 1;
            }
            if has_german_prose_context_lines(&para_lines) {
                for flag in &mut line_german_ctx[start..end] {
                    *flag = true;
                }
            }
            start = end;
        }
    }

    let mut violations = Vec::new();

    for (idx, &line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let cleaned = sanitized_lines[idx].as_str();
        if cleaned.trim().is_empty() {
            continue;
        }

        // 1. ASCII umlaut substitution check (`ae`/`oe`/`ue` in German words).
        // Preserve `'_'` inside tokens so snake_case code identifiers or template placeholders
        // such as `__TOKEN_...__` do not trigger prose umlaut matches.
        for word in cleaned.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            if word.len() < 4 || word.contains('_') {
                continue;
            }
            let lc = word.to_ascii_lowercase();
            if ASCII_UMLAUT_WORDS.contains(&lc.as_str()) {
                violations.push(GuardrailViolation {
                    rule: "german-ascii-umlaut".to_owned(),
                    severity: "CRITICAL".to_owned(),
                    file: filename.to_owned(),
                    line: line_no,
                    message: format!(
                        "Replace ASCII umlaut substitution '{word}' with natural German umlauts."
                    ),
                    snippet: truncate_ascii_safe(line.trim(), 100),
                });
                break;
            }
        }

        // 2. Deppenbindestrich check (`Upper+lower+ - Upper+lower+` in German prose or German nouns).
        let german_ctx = line_german_ctx[idx];
        for raw_tok in cleaned.split_whitespace() {
            let low_tok = raw_tok.to_ascii_lowercase();
            if low_tok.contains("://") || low_tok.contains("file:") {
                continue;
            }
            let switch_core = raw_tok.trim_matches(|c: char| {
                matches!(
                    c,
                    '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | ',' | '.' | ';' | ':' | '!' | '?'
                )
            });
            if switch_core.starts_with('/')
                || switch_core.starts_with('-')
                || switch_core.contains('/')
                || switch_core.contains('\\')
            {
                continue;
            }
            let tok = raw_tok.trim_matches(|c: char| {
                !c.is_alphabetic() && c != '-'
            });
            let mut parts = tok.split('-');
            let (Some(left), Some(right), None) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            let valid_side = |s: &str| {
                s.chars().count() >= 2
                    && s.chars().all(|c| c.is_alphabetic())
                    && s.chars().next().is_some_and(|c| c.is_uppercase())
                    && s.chars().any(|c| c.is_lowercase())
            };
            if !valid_side(left) || !valid_side(right) {
                continue;
            }
            let l_low = left.to_lowercase();
            let r_low = right.to_lowercase();
            if is_exempt_technical_hyphen_term(&l_low, &r_low) {
                continue;
            }
            if tok.is_ascii()
                && !GERMAN_NOUN_ROOTS.contains(&r_low.as_str())
                && is_powershell_cmdlet_verb(&l_low)
            {
                continue;
            }
            let has_non_ascii = tok.chars().any(|c| !c.is_ascii());
            let has_german_noun = GERMAN_NOUN_ROOTS.contains(&l_low.as_str())
                || GERMAN_NOUN_ROOTS.contains(&r_low.as_str());
            if german_ctx || has_non_ascii || has_german_noun {
                violations.push(GuardrailViolation {
                    rule: "german-deppenbindestrich".to_owned(),
                    severity: "CRITICAL".to_owned(),
                    file: filename.to_owned(),
                    line: line_no,
                    message: format!(
                        "Join German compound noun '{tok}' without a Deppenbindestrich."
                    ),
                    snippet: truncate_ascii_safe(line.trim(), 100),
                });
                break;
            }
        }
    }

    violations
}

/// Audits a workspace directory (either Git-staged files only or full source tree, skipping build/binary artifacts).
pub fn audit_workspace_guardrails(
    project_dir: &Path,
    staged_only: bool,
) -> std::io::Result<GuardrailAuditReport> {
    audit_workspace_guardrails_with_prefixes(project_dir, staged_only, &[])
}

/// Audits a workspace directory with optional custom secret prefixes loaded from `LibreDb` configuration.
pub fn audit_workspace_guardrails_with_prefixes(
    project_dir: &Path,
    staged_only: bool,
    custom_secret_prefixes: &[String],
) -> std::io::Result<GuardrailAuditReport> {
    let candidate_files = if staged_only {
        collect_git_staged_files(project_dir)?
    } else {
        let mut all = Vec::new();
        collect_workspace_text_files(project_dir, &mut all)?;
        all
    };

    let mut files_checked = 0usize;
    let mut violations = Vec::new();

    for path in candidate_files {
        let Ok(sym_meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if sym_meta.file_type().is_symlink() || !sym_meta.is_file() || should_skip_binary_ext(&path) {
            continue;
        }
        if sym_meta.len() == 0 || sym_meta.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(raw) = fs::read(&path) else {
            continue;
        };
        // Skip binary files containing NUL bytes in their header
        let probe = raw.len().min(8192);
        if raw[..probe].contains(&0) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&raw) else {
            continue;
        };

        files_checked += 1;
        let rel = path
            .strip_prefix(project_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        violations.extend(check_text_guardrails_with_options(
            text,
            &rel,
            true,
            custom_secret_prefixes,
        ));
        violations.extend(check_german_prose_style(text, &rel));
    }

    Ok(GuardrailAuditReport {
        files_checked,
        violations,
    })
}

/// Checks whether a Git-staged relative file path represents local agent memory, private keys,
/// certificates, or secret `.env` files that must never be pushed via `git-sync` unless explicitly
/// permitted in `allowed_patterns` (`guardrail:allow_staged_files`).
pub fn is_sensitive_staged_file(rel_path: &str, allowed_patterns: &[String]) -> Option<&'static str> {
    let norm = rel_path.trim().replace('\\', "/");
    let low = norm.to_ascii_lowercase();
    for pat in allowed_patterns {
        let p = pat.trim().replace('\\', "/").to_ascii_lowercase();
        if !p.is_empty() && (low == p || low.ends_with(&format!("/{p}")) || low.starts_with(&p)) {
            return None;
        }
    }

    if low == ".agents" || low.starts_with(".agents/") || low.contains("/.agents/") {
        return Some("local agent memory directory (.agents/)");
    }
    let fname = low.rsplit('/').next().unwrap_or(&low);
    if fname.ends_with(".tmp.ldb") || fname.ends_with(".bench.ldb") {
        return Some("ephemeral LibreDB database artifact");
    }
    if fname.ends_with(".credential.xml") {
        return Some("Windows DPAPI credential XML file");
    }
    if matches!(fname, ".netrc" | "_netrc" | ".git-credentials" | "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa") {
        return Some("SSH private key or Git/Netrc credential store");
    }
    if fname == ".env"
        || (fname.starts_with(".env.")
            && !fname.ends_with(".example")
            && !fname.ends_with(".sample")
            && !fname.ends_with(".template")
            && !fname.ends_with(".dist"))
    {
        return Some("dotenv environment secret file (.env)");
    }
    for (ext, reason) in [
        (".pfx", "PKCS#12 certificate/private key archive (.pfx)"),
        (".p12", "PKCS#12 certificate/private key archive (.p12)"),
        (".pem", "PEM key/certificate file (.pem)"),
        (".key", "private key file (.key)"),
        (".jks", "Java keystore (.jks)"),
        (".keystore", "signing keystore (.keystore)"),
    ] {
        if fname.ends_with(ext) {
            return Some(reason);
        }
    }
    None
}

pub fn is_test_or_scratch_path(path_str: &str) -> bool {
    let norm = path_str.to_ascii_lowercase().replace('\\', "/");
    norm.contains("/scratch/")
}

fn find_emoji_codepoint(s: &str) -> Option<char> {
    s.chars().find(|&c| {
        let u = c as u32;
        (0x1F300..=0x1FAFF).contains(&u)
            || (0x1F000..=0x1F2FF).contains(&u)
            || (0x1F1E6..=0x1F1FF).contains(&u)
            || (0x2600..=0x27BF).contains(&u)
            || u == 0xFE0F
    })
}

fn is_executable_script_ext(low_name: &str) -> bool {
    [".ps1", ".psm1", ".bat", ".cmd", ".sh"]
        .iter()
        .any(|ext| low_name.ends_with(ext))
}

fn is_valid_changelog_date_suffix(after_bracket: &str) -> bool {
    let Some(rest) = after_bracket.strip_prefix('-') else {
        return false;
    };
    let d = rest.trim();
    let bytes = d.as_bytes();
    bytes.len() >= 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn detect_secret_leak(line: &str, custom_prefixes: &[String]) -> Option<String> {
    let t = line.trim();
    if t.starts_with("-----BEGIN ") && t.ends_with("PRIVATE KEY-----") {
        return Some("PEM private key".to_owned());
    }
    for (prefix, label, min_tail) in [
        ("ghp_", "GitHub Personal Access Token", 28usize),
        ("github_pat_", "GitHub Fine-Grained PAT", 28usize),
        ("gho_", "GitHub OAuth Token", 28usize),
        ("ghs_", "GitHub App Installation Token", 28usize),
        ("glpat-", "GitLab Personal Access Token", 20usize),
        ("sk-proj-", "OpenAI API Key", 24usize),
        ("sk-ant-", "Anthropic API Key", 24usize),
        ("sk_live_", "Stripe Live Secret Key", 20usize),
        ("rk_live_", "Stripe Live Restricted Key", 20usize),
        ("xoxb-", "Slack Bot Token", 20usize),
        ("xoxp-", "Slack User Token", 20usize),
        ("AIza", "Google Cloud / Gemini API Key", 31usize),
        ("AKIA", "AWS Access Key ID", 16usize),
        ("ASIA", "AWS Temporary Access Key ID", 16usize),
    ] {
        if let Some(pos) = line.find(prefix) {
            let tail = &line[pos + prefix.len()..];
            let alnum_len = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if alnum_len >= min_tail {
                return Some(label.to_owned());
            }
        }
    }

    // Check user-configured dynamic token prefixes (`guardrail:secret_prefixes`)
    for raw_pref in custom_prefixes {
        let pref = raw_pref.trim();
        if pref.len() < 3 {
            continue;
        }
        if let Some(pos) = line.find(pref) {
            let tail = &line[pos + pref.len()..];
            let alnum_len = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if alnum_len >= 16 {
                return Some(format!("custom secret prefix '{pref}'"));
            }
        }
    }

    // Structural URL-embedded Basic Auth credentials (`https://user:secret@host`)
    for scheme in ["https://", "http://"] {
        if let Some(s_pos) = line.find(scheme) {
            let after = &line[s_pos + scheme.len()..];
            let authority_end = after
                .find(['/', '"', '\'', ' ', ')', '>', '`'])
                .unwrap_or(after.len());
            let authority = &after[..authority_end];
            if let Some((userinfo, host)) = authority.rsplit_once('@') {
                if let Some((usr, pwd)) = userinfo.split_once(':') {
                    let pwd_low = pwd.to_ascii_lowercase();
                    let is_placeholder = usr.is_empty()
                        || pwd.len() < 8
                        || usr.contains('{')
                        || pwd.contains('{')
                        || pwd.contains('$')
                        || pwd.contains('%')
                        || pwd.contains('<')
                        || matches!(
                            pwd_low.as_str(),
                            "password" | "pass" | "secret" | "token" | "changeme" | "example"
                        )
                        || host.contains("example.");
                    if !is_placeholder && !host.is_empty() {
                        return Some("URL-embedded Basic Auth credential".to_owned());
                    }
                }
            }
        }
    }

    None
}

fn contains_obfuscated_encoded_command(cmd: &str) -> bool {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    for (idx, w) in words.iter().enumerate() {
        let low = w.to_ascii_lowercase();
        if matches!(
            low.as_str(),
            "-encodedcommand" | "-enc" | "-ec" | "/encodedcommand" | "/enc"
        ) {
            if let Some(next_w) = words.get(idx + 1) {
                let clean = next_w.trim_matches(['"', '\'']);
                if clean.len() >= 16
                    && clean
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn detect_hardcoded_internal_unc(line: &str) -> Option<&'static str> {
    let low = line.to_ascii_lowercase();
    let marker = concat!(".lo", "cal\\");
    if let Some(pos) = low.find(marker) {
        let before = &low[..pos];
        if (before.contains("\\\\") || before.contains("//"))
            && !low.contains(".example")
            && !low.contains("example.")
        {
            return Some("internal .local Active Directory UNC FQDN");
        }
    }
    None
}

fn should_skip_binary_ext(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "exe"
            | "dll"
            | "pyd"
            | "so"
            | "dylib"
            | "rlib"
            | "rmeta"
            | "pdb"
            | "o"
            | "obj"
            | "lib"
            | "a"
            | "ldb"
            // Third-party and legacy binary DB extensions skipped by text guardrail scans
            | "db"
            | "sqlite"
            | "zip"
            | "7z"
            | "gz"
            | "whl"
            | "jar"
            | "apk"
            | "aab"
            | "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "ico"
            | "pdf"
            | "woff"
            | "woff2"
            | "ttf"
    )
}

fn collect_git_staged_files(project_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .current_dir(project_dir)
        .output()?;
    if !out.status.success() {
        let mut all = Vec::new();
        collect_workspace_text_files(project_dir, &mut all)?;
        return Ok(all);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|rel| project_dir.join(rel))
        .filter(|p| {
            fs::symlink_metadata(p)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.is_file())
        })
        .collect())
}

fn collect_workspace_text_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let skip_dirs = [
        ".git",
        ".agents",
        "target",
        "dist",
        "releases",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "build",
        "out",
        ".next",
    ];
    for entry_res in fs::read_dir(dir)? {
        let entry = entry_res?;
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if ft.is_dir() {
            if skip_dirs.iter().any(|&sd| name.eq_ignore_ascii_case(sd)) {
                continue;
            }
            collect_workspace_text_files(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn contains_forced_git_semver_tag(cmd: &str) -> bool {
    for segment in cmd.split([';', '|', '&', '\n']) {
        let words: Vec<&str> = segment.split_whitespace().collect();
        for win_idx in 0..words.len() {
            if words[win_idx].eq_ignore_ascii_case("git")
                && words.get(win_idx + 1).is_some_and(|w| *w == "tag")
            {
                let tail = &words[win_idx + 2..];
                let has_force = tail.iter().any(|&w| {
                    w == "-f"
                        || w == "--force"
                        || (w.starts_with('-') && !w.starts_with("--") && w.contains('f'))
                });
                let has_semver = tail.iter().any(|&w| {
                    let clean = w.strip_prefix('v').or_else(|| w.strip_prefix('V')).unwrap_or(w);
                    let parts: Vec<&str> = clean.split('.').collect();
                    parts.len() >= 3
                        && parts[0].chars().all(|c| c.is_ascii_digit())
                        && !parts[0].is_empty()
                        && parts[1].chars().all(|c| c.is_ascii_digit())
                        && !parts[1].is_empty()
                });
                if has_force && has_semver {
                    return true;
                }
            }
        }
    }
    false
}

fn truncate_ascii_safe(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(max_chars.min(s.len()));
    for (i, ch) in s.chars().enumerate() {
        if i >= max_chars {
            out.push_str("...");
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else {
            out.push_str(&format!("\\u{{{:04X}}}", ch as u32));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guardrail_detects_dashes_emojis_vbscript_and_force_tags() {
        let bad_md = format!("Heading {} bad dash and emoji \u{1F680}", '\u{2014}');
        let v = check_text_guardrails(&bad_md, "README.md");
        assert!(v.iter().any(|x| x.rule == "no-em-en-dash"));
        assert!(v.iter().any(|x| x.rule == "no-emojis"));

        let v_vbs = check_text_guardrails("MsgBox \"hi\"", "legacy.vbs");
        assert!(v_vbs.iter().any(|x| x.rule == "no-vbscript"));

        assert!(check_command_guardrails("git tag -f v1.2.0").is_some());
        assert!(check_command_guardrails("git tag -a v1.2.0 -m \"msg\"").is_none());
        assert!(check_command_guardrails("sc.exe \\\\fileserver create badsvc").is_some());

        let dup_cl = "# Changelog\n\n## [0.2.0] - 2026-11-10\n### Added\n- A\n\n## [0.2.0] - 2026-11-09\n### Added\n- B\n";
        let v_cl = check_text_guardrails(dup_cl, "CHANGELOG.md");
        assert!(v_cl.iter().any(|x| x.rule == "changelog-duplicate-version"));

        // Partial `edit_file` snippets on CHANGELOG.md without line 1 `# Changelog` must pass when `is_full_file == false`:
        let partial_cl = "## [0.3.0] - 2026-11-10\n\n### Fixed\n\n- Fixed partial edit check.\n";
        assert!(check_text_guardrails_with_mode(partial_cl, "CHANGELOG.md", false).is_empty());
        assert!(!check_text_guardrails_with_mode(partial_cl, "CHANGELOG.md", true).is_empty());

        // Obfuscated PowerShell -EncodedCommand, URL credentials, custom secret prefixes, and staged file policy:
        assert!(check_command_guardrails("pwsh -NoProfile -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=").is_some());
        let custom_v = check_text_guardrails_with_options(
            "token = \"corp_tok_9876543210abcdef987654\"",
            "config.toml",
            true,
            &["corp_tok_".to_owned()],
        );
        assert!(custom_v.iter().any(|x| x.rule == "no-hardcoded-secrets"));
        let synth_url = format!("remote = \"{}admin:{}@git.corp.net/repo.git\"", "https://", "SuperSecret99!");
        let url_v = check_text_guardrails(&synth_url, "cfg.toml");
        assert!(url_v.iter().any(|x| x.rule == "no-hardcoded-secrets"));
        assert!(is_sensitive_staged_file(".agents/memory.ldb", &[]).is_some());
        assert!(is_sensitive_staged_file(".env.production", &[]).is_some());
        assert!(is_sensitive_staged_file(".env.example", &[]).is_none());
        assert!(is_sensitive_staged_file("certs/test.pem", &["certs/test.pem".to_owned()]).is_none());
    }

    #[test]
    fn guardrail_blocks_git_exec_hijacks_vault_tamper_and_skips_symlink_loops() {
        for bad_cmd in [
            "git -c core.hooksPath=. status",
            "git -c core.fsmonitor=./pwn.sh diff",
            "git -c core.sshCommand=evil fetch",
            "git -c protocol.ext.allow=always clone ext::sh",
            "cat ~/.gemini/libredb/.vault.key",
            "Remove-Item C:\\Users\\dev\\.gemini\\libredb\\.seal_locks\\ws_123.lock",
        ] {
            let v = check_command_guardrails(bad_cmd);
            assert!(
                v.is_some_and(|x| x.rule == "no-git-exec-hijack-or-vault-tamper"),
                "expected command guardrail violation for '{bad_cmd}'"
            );
        }

        let tmp = std::env::temp_dir().join(format!(
            "libredb_guardrail_symlink_loop_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("src")).unwrap();
        fs::write(tmp.join("src").join("clean.rs"), "pub fn ok() -> u32 { 1 }\n").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&tmp, tmp.join("src").join("loop_dir")).unwrap();
        }
        #[cfg(windows)]
        {
            // Directory symlink creation on Windows may require Developer Mode; ignore if unprivileged.
            let _ = std::os::windows::fs::symlink_dir(&tmp, tmp.join("src").join("loop_dir"));
        }

        let report = audit_workspace_guardrails(&tmp, false).unwrap();
        assert_eq!(report.files_checked, 1);
        assert!(report.violations.is_empty());
        let _ = fs::remove_dir_all(&tmp);
    }
}
