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

/// Checks text content for formatting and scripting guardrail violations.
pub fn check_text_guardrails(text: &str, filename: &str) -> Vec<GuardrailViolation> {
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

    None
}

/// Audits a workspace directory (either Git-staged files only or full source tree, skipping build/binary artifacts).
pub fn audit_workspace_guardrails(
    project_dir: &Path,
    staged_only: bool,
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
        if !path.is_file() || should_skip_binary_ext(&path) {
            continue;
        }
        let Ok(meta) = path.metadata() else {
            continue;
        };
        if meta.len() == 0 || meta.len() > 4 * 1024 * 1024 {
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
        violations.extend(check_text_guardrails(text, &rel));
    }

    Ok(GuardrailAuditReport {
        files_checked,
        violations,
    })
}

pub fn is_test_or_scratch_path(path_str: &str) -> bool {
    let norm = path_str.to_ascii_lowercase().replace('\\', "/");
    if norm.contains("/scratch/") || norm.contains("/tests/") || norm.contains("/__tests__/") {
        return true;
    }
    let fname = norm.rsplit('/').next().unwrap_or(&norm);
    fname.starts_with("test_")
        || fname.contains("_test.")
        || fname.contains(".test.")
        || fname.contains(".spec.")
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
        let path = entry.path();
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if path.is_dir() {
            if skip_dirs.iter().any(|&sd| name.eq_ignore_ascii_case(sd)) {
                continue;
            }
            collect_workspace_text_files(&path, out)?;
        } else if path.is_file() {
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
    }
}
