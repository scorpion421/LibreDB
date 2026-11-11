//! Symlink-canonicalized, NTFS-ADS-stripped, and trailing-dot-normalized control-plane, credential,
//! `MCP` workspace containment, and `CVE-2022-24765` `safe.directory` path policies.

use super::seals::{
    check_global_trust_sync, has_config_key_fail_closed, is_workspace_memory_trusted,
};
use super::*;
use std::path::Component;
#[cfg(test)]
pub fn check_tool_write_path_policy(
    target_path: &str,
    custom_protected: &[String],
) -> Option<String> {
    check_tool_write_path_policy_with_base(target_path, None, custom_protected)
}

/// Evaluates `PreToolUse` write path policy resolving relative paths, NTFS Alternate Data Streams
/// (`:stream` / `::$DATA`), Win32 trailing dots/spaces, and symlinks against `base_dir`.
pub fn check_tool_write_path_policy_with_base(
    target_path: &str,
    base_dir: Option<&Path>,
    custom_protected: &[String],
) -> Option<String> {
    let raw_p = Path::new(target_path.trim());
    for low in resolve_policy_candidate_paths(raw_p, base_dir) {
        let slash_low = format!("/{}", low.trim_start_matches('/'));
        if slash_low.contains("/.git/hooks/")
            || slash_low.ends_with("/.git/hooks")
            || slash_low.ends_with("/.git/config")
            || slash_low.ends_with("/.git/info/attributes")
            || slash_low.ends_with("/.gitmodules")
        {
            return Some(
                "Modifying .git/hooks, .git/config, .git/info/attributes, or .gitmodules via file tools is blocked to prevent Git hook/filter/submodule execution hijacking."
                    .to_owned(),
            );
        }
        if slash_low.contains("/.gemini/")
            && (slash_low.ends_with("/hooks.json") || slash_low.ends_with("/mcp_config.json"))
        {
            return Some(
                "Direct agent modification of active Antigravity hooks.json or mcp_config.json is blocked; use user-approved deployment scripts."
                    .to_owned(),
            );
        }
        if slash_low.contains("/.gemini/libredb/")
            || slash_low.ends_with("/.gemini/libredb")
            || slash_low.contains("/.gemini/config/plugins/libredb/")
            || slash_low.ends_with("/.gemini/config/plugins/libredb")
            || slash_low.ends_with("/.gemini/antigravity/bin/libredb")
            || slash_low.ends_with("/.gemini/antigravity/bin/libredb.exe")
        {
            return Some(
                "Direct agent modification of active LibreDB control-plane files, binaries, or trust stores under ~/.gemini is blocked."
                    .to_owned(),
            );
        }
        if slash_low.ends_with("/.agents/memory.ldb")
            || slash_low.ends_with("/.agents/memory.db")
            || slash_low.contains("/.agents/memory.ldb.")
            || slash_low.contains("/.agents/memory.db.")
        {
            return Some(
                "Direct raw file writes to .agents/memory.ldb or .agents/memory.db are blocked to preserve workspace trust seals; use libredb_memorize or 'libredb batch'."
                    .to_owned(),
            );
        }
        if let Some(reason) = check_credential_store_path(&slash_low, custom_protected) {
            return Some(format!(
                "Writing to sensitive credential/key/control-plane path is blocked ({reason})."
            ));
        }
    }
    None
}

/// Evaluates whether `libredb-mcp` (`skeleton`, `fim`, `index`) must refuse reading or indexing `target_path`,
/// inspecting both the lexical path and the canonical symlink-resolved target on disk.
pub fn check_mcp_read_path_policy(
    target_path: &Path,
    custom_protected: &[String],
) -> Option<String> {
    for low in resolve_policy_candidate_paths(target_path, None) {
        let slash_low = format!("/{}", low.trim_start_matches('/'));
        if let Some(reason) = check_credential_store_path(&slash_low, custom_protected) {
            return Some(format!(
                "LibreDB MCP access denied for protected path ({reason}): {}",
                target_path.display()
            ));
        }
        let fname = slash_low.rsplit('/').next().unwrap_or(&slash_low);
        if fname == ".env"
            || (fname.starts_with(".env.")
                && !fname.ends_with(".example")
                && !fname.ends_with(".sample")
                && !fname.ends_with(".template")
                && !fname.ends_with(".dist"))
        {
            return Some(format!(
                "LibreDB MCP access denied for dotenv secret file: {}",
                target_path.display()
            ));
        }
    }
    None
}

/// Returns true if `ws_root` is a filesystem root (`/` or `C:\`), broad shared container root
/// (`$HOME`, `%TEMP%`, `/tmp`, `/var/tmp`, `$HOME/AppData`), or sensitive OS / LibreDB control-plane
/// directory that must never be accepted as an `MCP` workspace boundary.
pub fn is_forbidden_mcp_workspace_root(ws_root: &Path) -> bool {
    if ws_root.as_os_str().is_empty() {
        return true;
    }
    let canon = canonicalize_with_missing_tail(ws_root).unwrap_or_else(|| ws_root.to_path_buf());
    if canon.parent().is_none() {
        return true;
    }
    let norm = normalize_workspace_key(&canon);
    if norm.is_empty() || norm == "/" {
        return true;
    }
    let home_norm = normalize_workspace_key(&user_home_dir());
    let temp_norm = normalize_workspace_key(&std::env::temp_dir());
    if norm == home_norm || norm == temp_norm || norm == "/tmp" || norm == "/var/tmp" {
        return true;
    }
    let low = norm.to_ascii_lowercase();
    let home_low = home_norm.to_ascii_lowercase();
    if low == format!("{home_low}/.gemini")
        || low.starts_with(&format!("{home_low}/.gemini/libredb"))
        || low.starts_with(&format!("{home_low}/.gemini/config"))
        || low.starts_with(&format!("{home_low}/.gemini/database"))
        || low == format!("{home_low}/appdata")
        || low == format!("{home_low}/appdata/local")
        || low == format!("{home_low}/appdata/roaming")
    {
        return true;
    }
    low == "/etc"
        || low.starts_with("/etc/")
        || low == "/usr"
        || low.starts_with("/usr/")
        || low == "/proc"
        || low.starts_with("/proc/")
        || low == "/sys"
        || low.starts_with("/sys/")
        || low == "/dev"
        || low.starts_with("/dev/")
        || low == "/run"
        || low.starts_with("/run/")
        || low.ends_with(":/windows")
        || low.contains(":/windows/")
        || low.contains(":/program files")
}

/// Enforces mandatory workspace containment for `libredb-mcp` code inspection/indexing tools against
/// a resolved non-optional `ws_root`, failing closed on broad/root workspace boundaries and blocking
/// both `../` traversal and symlinks inside the workspace that resolve outside `ws_root`.
pub fn check_mcp_workspace_containment(target_path: &Path, ws_root: &Path) -> Option<String> {
    if is_forbidden_mcp_workspace_root(ws_root) {
        return Some(format!(
            "LibreDB MCP access denied: invalid or overly broad workspace root '{}'",
            ws_root.display()
        ));
    }
    let root_canon =
        canonicalize_with_missing_tail(ws_root).unwrap_or_else(|| ws_root.to_path_buf());
    let root_norm = normalize_workspace_key(&root_canon);
    if root_norm.is_empty() {
        return Some(format!(
            "LibreDB MCP access denied: empty workspace root '{}'",
            ws_root.display()
        ));
    }

    let joined = if target_path.is_relative() {
        ws_root.join(target_path)
    } else {
        target_path.to_path_buf()
    };
    let target_canon = canonicalize_with_missing_tail(&joined).unwrap_or(joined);
    let target_norm = normalize_workspace_key(&target_canon);
    if target_norm != root_norm && !target_norm.starts_with(&format!("{root_norm}/")) {
        return Some(format!(
            "LibreDB MCP access denied: target '{}' resolves outside active workspace '{}'",
            target_path.display(),
            ws_root.display()
        ));
    }
    None
}

pub(super) fn sanitize_policy_segment(seg: &str, is_drive_prefix: bool) -> String {
    let low = seg.to_ascii_lowercase();
    if low == "." || low == ".." {
        return low;
    }
    let without_ads = if is_drive_prefix
        && low.len() >= 2
        && low.as_bytes()[0].is_ascii_alphabetic()
        && low.as_bytes()[1] == b':'
    {
        match low[2..].find(':') {
            Some(idx) => &low[..2 + idx],
            None => low.as_str(),
        }
    } else {
        low.split(':').next().unwrap_or(&low)
    };
    without_ads.trim_end_matches(['.', ' ']).to_owned()
}

pub(super) fn sanitize_policy_path_str(raw: &str) -> String {
    let unified = raw.trim().trim_start_matches(r"\\?\").replace('\\', "/");
    let leading_slash = unified.starts_with('/');
    let mut parts = Vec::new();
    for (idx, part) in unified.split('/').enumerate() {
        if part.is_empty() {
            continue;
        }
        let cleaned = sanitize_policy_segment(part, idx == 0 && !leading_slash);
        if !cleaned.is_empty() {
            parts.push(cleaned);
        }
    }
    let joined = parts.join("/");
    if leading_slash {
        format!("/{joined}")
    } else {
        joined
    }
}

pub(super) fn resolve_policy_candidate_paths(raw_path: &Path, base_dir: Option<&Path>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(6);
    let mut push_unique = |s: String| {
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };

    let raw_lossy = raw_path.to_string_lossy();
    let stripped_ads_raw = sanitize_policy_path_str(&raw_lossy);
    push_unique(raw_lossy.replace('\\', "/").to_ascii_lowercase());
    push_unique(stripped_ads_raw.clone());
    push_unique(lexical_normalize_lower(raw_path));
    if !stripped_ads_raw.is_empty() {
        push_unique(lexical_normalize_lower(Path::new(&stripped_ads_raw)));
    }

    for cand_path in [raw_path, Path::new(stripped_ads_raw.as_str())] {
        if cand_path.as_os_str().is_empty() {
            continue;
        }
        if let Some(canon) = canonicalize_with_missing_tail(cand_path) {
            let clean = crate::gitea::strip_verbatim_prefix(&canon);
            push_unique(sanitize_policy_path_str(&clean.to_string_lossy()));
        }
    }

    if raw_path.is_relative() {
        if let Some(base) = base_dir {
            for rel_p in [raw_path, Path::new(stripped_ads_raw.as_str())] {
                if rel_p.as_os_str().is_empty() {
                    continue;
                }
                let joined = base.join(rel_p);
                push_unique(lexical_normalize_lower(&joined));
                if let Some(canon) = canonicalize_with_missing_tail(&joined) {
                    let clean = crate::gitea::strip_verbatim_prefix(&canon);
                    push_unique(sanitize_policy_path_str(&clean.to_string_lossy()));
                }
            }
        }
    }

    out
}

pub(super) fn lexical_normalize_lower(path: &Path) -> String {
    let mut stack: Vec<String> = Vec::new();
    let mut has_root = false;
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => {
                stack.clear();
                let raw_pref = p
                    .as_os_str()
                    .to_string_lossy()
                    .trim_start_matches(r"\\?\")
                    .replace('\\', "/");
                stack.push(sanitize_policy_segment(&raw_pref, true));
                has_root = true;
            }
            Component::RootDir => {
                if stack.is_empty() {
                    has_root = true;
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.len() > usize::from(has_root && stack.len() == 1) {
                    if stack.last().is_some_and(|s| s != "..") {
                        stack.pop();
                    } else if !has_root {
                        stack.push("..".to_owned());
                    }
                } else if !has_root {
                    stack.push("..".to_owned());
                }
            }
            Component::Normal(seg) => {
                let cleaned = sanitize_policy_segment(&seg.to_string_lossy(), false);
                if !cleaned.is_empty() {
                    stack.push(cleaned);
                }
            }
        }
    }
    let joined = stack.join("/");
    if has_root && !joined.contains(':') && !joined.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Resolves symlinks along the deepest existing ancestor of `path` and appends any not-yet-created
/// child segments (collapsing `.` and `..` in the missing tail) so symlinked directories, relative
/// `..` segments, and not-yet-created `.agents/memory.ldb` files all normalize to one canonical path.
pub(crate) fn canonicalize_with_missing_tail(path: &Path) -> Option<PathBuf> {
    let abs_or_rel = if path.is_relative() {
        std::env::current_dir()
            .ok()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    if let Ok(canon) = fs::canonicalize(&abs_or_rel) {
        return Some(canon);
    }

    // Walk components forward so intermediate `..` after an existing symlinked or non-existent segment
    // are collapsed deterministically once we hit the deepest existing prefix on disk.
    let comps: Vec<Component<'_>> = abs_or_rel.components().collect();
    for split in (1..=comps.len()).rev() {
        let mut cand = PathBuf::new();
        for c in &comps[..split] {
            cand.push(c.as_os_str());
        }
        if let Ok(mut canon) = fs::canonicalize(&cand) {
            for rem in &comps[split..] {
                match rem {
                    Component::CurDir => {}
                    Component::ParentDir => {
                        let _ = canon.pop();
                    }
                    Component::Normal(seg) => canon.push(seg),
                    _ => {}
                }
            }
            return Some(canon);
        }
    }
    None
}

pub(super) fn check_credential_store_path(low_norm: &str, custom_protected: &[String]) -> Option<String> {
    for seg in [
        "/.ssh/",
        "/.gnupg/",
        "/.aws/",
        "/.azure/",
        "/.kube/",
        "/.gemini/config/credentials/",
        "/.gemini/libredb/.seal_locks/",
    ] {
        let trimmed_seg = seg.trim_end_matches('/');
        if low_norm.contains(seg) || low_norm.ends_with(trimmed_seg) {
            return Some(format!("credential/lock directory '{trimmed_seg}'"));
        }
    }
    let fname = low_norm.rsplit('/').next().unwrap_or(low_norm);
    if fname.ends_with(".credential.xml")
        || fname.ends_with(".pem")
        || fname.ends_with(".p12")
        || fname.ends_with(".pfx")
        || fname.ends_with(".jks")
        || fname.ends_with(".kdbx")
        || fname == ".vault.key"
        || fname.starts_with(".vault.key.")
        || matches!(
            fname,
            ".netrc"
                | "_netrc"
                | ".git-credentials"
                | "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "customizations.ldb"
                | "customizations.db"
                | "default_memory.ldb"
                | "quarantined_workspace.ldb"
        )
    {
        return Some(format!("credential/key/control-plane file '{fname}'"));
    }
    for custom in custom_protected {
        let raw_c = custom.trim();
        if raw_c.is_empty() {
            continue;
        }
        let mut c_variants = vec![sanitize_policy_path_str(raw_c)];
        if let Some(canon_c) = canonicalize_with_missing_tail(Path::new(raw_c)) {
            let clean_c =
                sanitize_policy_path_str(&crate::gitea::strip_verbatim_prefix(&canon_c).to_string_lossy());
            if !c_variants.contains(&clean_c) {
                c_variants.push(clean_c);
            }
        }
        for c in c_variants {
            let c_trim = c.trim_matches('/');
            if !c_trim.is_empty()
                && (low_norm == format!("/{c_trim}")
                    || low_norm.starts_with(&format!("/{c_trim}/"))
                    || low_norm.contains(&format!("/{c_trim}/"))
                    || low_norm.ends_with(&format!("/{c_trim}")))
            {
                return Some(format!("custom protected path '{custom}'"));
            }
        }
    }
    None
}

/// Sanitizes a Git branch or ref string read from `.git/HEAD` so crafted branch names in untrusted
/// repositories can never inject newlines or prompt directives into `<SYSTEM_MESSAGE>`.
pub fn sanitize_git_ref_for_prompt(raw_ref: &str) -> String {
    let mut out = String::with_capacity(raw_ref.len().min(80));
    for ch in raw_ref.chars() {
        if out.len() >= 80 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/') {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "HEAD".to_owned()
    } else {
        out
    }
}

/// Returns true ONLY if `project_root` (owned by the current effective UID on Unix) resides inside
/// the current user's canonical home directory (`%USERPROFILE%` / `$HOME`) or has been EXPLICITLY
/// authorized in `global_db` (`trust:allowed::<ws>`) AND passes `is_workspace_memory_trusted`
/// (`CVE-2022-24765`). Never trusts spoofable `USERNAME`/`USER` path substrings or unapproved
/// directories outside `$HOME` that merely lack `.agents/`.
pub fn is_safe_auto_git_dir(global_db: Option<&LibreDb>, project_root: &Path) -> bool {
    let Some(canon_root) = canonicalize_with_missing_tail(project_root) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn geteuid() -> u32;
        }
        let Ok(meta) = fs::metadata(&canon_root) else {
            return false;
        };
        let euid = unsafe { geteuid() };
        if meta.uid() != euid {
            return false;
        }
    }
    let norm = normalize_workspace_key(&canon_root);
    let home_norm = normalize_workspace_key(&user_home_dir());
    if !home_norm.is_empty() && (norm == home_norm || norm.starts_with(&format!("{home_norm}/"))) {
        return true;
    }
    let Some(gdb) = global_db else {
        return false;
    };
    if check_global_trust_sync(gdb).is_err() {
        return false;
    }
    let Ok(false) = has_config_key_fail_closed(gdb, &format!("trust:revoked::{norm}")) else {
        return false;
    };
    let Ok(true) = has_config_key_fail_closed(gdb, &format!("trust:allowed::{norm}")) else {
        return false;
    };
    is_workspace_memory_trusted(Some(gdb), &canon_root)
}

