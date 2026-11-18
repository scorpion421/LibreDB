//! Standalone pure-Rust plugin installer and GitHub Release self-updater
//! (`libredb install` and `libredb update`).
//!
//! Enables zero-repo deployment from a single downloaded release binary without modifying
//! `mcp_config.json` or `hooks.json` via blocked file-edit tools (`PreToolUse` control-plane protection).

use crate::hooks::{default_global_ldb_path, open_global_ldb, open_global_ldb_checked, user_home_dir};
use crate::security;
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_GITHUB_REPO: &str = "scorpion421/LibreDB";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallProfile {
    Neutral,
    Personal,
}

pub struct InstallOptions {
    pub binary_path: Option<PathBuf>,
    pub profile: Option<String>,
    pub no_hooks: bool,
    pub fallback_drive: Option<PathBuf>,
    pub home_override: Option<PathBuf>,
    pub global_path: Option<PathBuf>,
    pub quiet_stdout: bool,
}

pub struct UpdateOptions {
    pub check_only: bool,
    pub force: bool,
    pub version: Option<String>,
    pub repo: Option<String>,
    pub profile: Option<String>,
    pub no_hooks: bool,
    pub fallback_drive: Option<PathBuf>,
    pub home_override: Option<PathBuf>,
    pub global_path: Option<PathBuf>,
    pub quiet_stdout: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub version: String,
    pub profile: InstallProfile,
    pub mcp_command: String,
    pub hooks_enabled: bool,
    pub hook_command: Option<String>,
    pub plugin_dir: String,
    pub global_ldb: String,
    pub installed_binaries: Vec<String>,
    pub ripgrep_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateReport {
    pub current_version: String,
    pub latest_version: String,
    pub tag_name: String,
    pub repo: String,
    pub asset_name: String,
    pub download_url: String,
    pub check_only: bool,
    pub updated: bool,
    pub staged_binary: Option<String>,
    pub install_report: Option<InstallReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseAssetSelection {
    pub tag_name: String,
    pub latest_version: String,
    pub asset_name: String,
    pub download_url: String,
}

struct StagingCleanupGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
}

impl Drop for StagingCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn strip_zone_identifier(path: &Path) {
    #[cfg(windows)]
    {
        let ads = format!("{}:Zone.Identifier", path.display());
        let _ = fs::remove_file(ads);
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

#[cfg(unix)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("Failed to set {mode:04o} permissions on '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn set_unix_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn set_executable_mode(path: &Path) -> Result<(), String> {
    set_unix_mode(path, 0o755)
}

fn canonical_compare_key(p: &Path) -> String {
    let resolved = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    security::normalize_workspace_key(&security::strip_verbatim_prefix(&resolved))
}

/// Copies `src` to `dst` safely even when `dst` is currently locked by a running `mcp-serve` process.
pub(crate) fn install_binary_hot_safe(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.is_file() {
        return Err(format!("Source binary '{}' does not exist.", src.display()));
    }
    strip_zone_identifier(src);
    if dst.exists() && canonical_compare_key(src) == canonical_compare_key(dst) {
        let _ = set_executable_mode(dst);
        strip_zone_identifier(dst);
        return Ok(());
    }

    let parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("Invalid destination binary path '{}'", dst.display()))?;
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create directory '{}': {e}", parent.display()))?;

    let dst_leaf = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("libredb");
    sweep_old_backup_files(parent, dst_leaf);

    #[cfg(unix)]
    {
        let tmp_dst = parent.join(format!(".{dst_leaf}.tmp.{}", std::process::id()));
        let _ = fs::remove_file(&tmp_dst);
        fs::copy(src, &tmp_dst).map_err(|e| {
            format!(
                "Failed to copy '{}' to '{}': {e}",
                src.display(),
                tmp_dst.display()
            )
        })?;
        set_executable_mode(&tmp_dst)?;
        fs::rename(&tmp_dst, dst).map_err(|e| {
            let _ = fs::remove_file(&tmp_dst);
            format!(
                "Failed to replace executable '{}': {e}",
                dst.display()
            )
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        if fs::copy(src, dst).is_err() {
            if dst.exists() {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos());
                let old_path = parent.join(format!("{dst_leaf}.{}.{nanos}.old", std::process::id()));
                fs::rename(dst, &old_path).map_err(|e| {
                    format!(
                        "Failed to move running binary '{}' aside before upgrade: {e}",
                        dst.display()
                    )
                })?;
            }
            fs::copy(src, dst).map_err(|e| {
                format!(
                    "Failed to copy '{}' to '{}': {e}",
                    src.display(),
                    dst.display()
                )
            })?;
        }
        strip_zone_identifier(dst);
        Ok(())
    }
}

fn sweep_old_backup_files(parent: &Path, leaf: &str) {
    let _ = fs::remove_file(parent.join(format!("{leaf}.old")));
    if let Ok(entries) = fs::read_dir(parent) {
        for ent in entries.flatten() {
            if let Some(name) = ent.file_name().to_str() {
                if name.starts_with(leaf) && name.ends_with(".old") {
                    let _ = fs::remove_file(ent.path());
                }
            }
        }
    }
}

/// Removes a legacy/duplicate binary copy (moving locked Windows executables aside via `.old` rename).
fn remove_stale_binary_copy(path: &Path) {
    if let (Some(parent), Some(leaf)) = (
        path.parent().filter(|p| !p.as_os_str().is_empty()),
        path.file_name().and_then(|s| s.to_str()),
    ) {
        if parent.is_dir() {
            sweep_old_backup_files(parent, leaf);
        }
    }
    if fs::symlink_metadata(path).is_err() {
        return;
    }
    if fs::remove_file(path).is_err() {
        #[cfg(windows)]
        if let (Some(parent), Some(leaf)) = (
            path.parent().filter(|p| !p.as_os_str().is_empty()),
            path.file_name().and_then(|s| s.to_str()),
        ) {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let old_path = parent.join(format!("{leaf}.{}.{nanos}.old", std::process::id()));
            if fs::rename(path, &old_path).is_ok() {
                let _ = fs::remove_file(&old_path);
            }
        }
    }
}

pub(crate) fn merge_windows_user_path_value(
    existing_raw: &str,
    user_profile_opt: Option<&str>,
    bin_dir: &Path,
) -> Option<String> {
    let target_clean = bin_dir
        .to_string_lossy()
        .trim()
        .trim_end_matches(['\\', '/'])
        .to_owned();
    if target_clean.is_empty() {
        return None;
    }
    let target_cmp = target_clean.replace('/', "\\");
    let up_clean = user_profile_opt
        .map(|s| s.trim().trim_end_matches(['\\', '/']).replace('/', "\\"))
        .filter(|s| !s.is_empty());

    for raw_part in existing_raw.split(';') {
        let clean_entry = raw_part
            .trim()
            .trim_matches('"')
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\");
        if clean_entry.is_empty() {
            continue;
        }
        if clean_entry.eq_ignore_ascii_case(&target_cmp) {
            return None;
        }
        if let Some(ref up) = up_clean {
            if clean_entry
                .get(..13)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("%USERPROFILE%"))
            {
                let expanded = format!("{up}{}", &clean_entry[13..]);
                if expanded.eq_ignore_ascii_case(&target_cmp) {
                    return None;
                }
            }
        }
    }

    let base = existing_raw.trim().trim_end_matches(';');
    if base.is_empty() {
        Some(target_clean)
    } else {
        Some(format!("{base};{target_clean}"))
    }
}

#[cfg(windows)]
mod win_env_path {
    use super::merge_windows_user_path_value;
    use std::ffi::c_void;
    use std::path::Path;
    use std::ptr;

    const HKEY_CURRENT_USER: *mut c_void = (-2147483647isize) as *mut c_void;
    const HWND_BROADCAST: *mut c_void = 0xffffusize as *mut c_void;
    const KEY_READ: u32 = 0x20019;
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hkey: *mut c_void,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *mut u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *const c_void,
            phk_result: *mut *mut c_void,
            lpdw_disposition: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            hkey: *mut c_void,
            lp_value_name: *const u16,
            lp_reserved: *const u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hkey: *mut c_void,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;
        fn RegCloseKey(hkey: *mut c_void) -> i32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
            fu_flags: u32,
            u_timeout: u32,
            lpdw_result: *mut usize,
        ) -> isize;
    }

    struct RegKeyGuard(*mut c_void);

    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    fn to_wide_z(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn ensure_user_path_in_registry(bin_dir: &Path) -> Result<bool, String> {
        let subkey = to_wide_z("Environment");
        let val_name = to_wide_z("Path");
        let mut hkey: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                ptr::null_mut(),
                0,
                KEY_READ | KEY_WRITE,
                ptr::null(),
                &mut hkey,
                ptr::null_mut(),
            )
        };
        if rc != 0 || hkey.is_null() {
            return Err(format!("Failed to open HKCU\\Environment (Win32 error {rc})"));
        }
        let _guard = RegKeyGuard(hkey);

        let mut val_type: u32 = 0;
        let mut cb_data: u32 = 0;
        let q1 = unsafe {
            RegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                ptr::null(),
                &mut val_type,
                ptr::null_mut(),
                &mut cb_data,
            )
        };

        let existing = if q1 == ERROR_FILE_NOT_FOUND {
            val_type = REG_EXPAND_SZ;
            String::new()
        } else if q1 == 0 {
            let mut raw = vec![0u8; cb_data as usize + 4];
            let mut cb2 = raw.len() as u32;
            let q2 = unsafe {
                RegQueryValueExW(
                    hkey,
                    val_name.as_ptr(),
                    ptr::null(),
                    &mut val_type,
                    raw.as_mut_ptr(),
                    &mut cb2,
                )
            };
            if q2 != 0 {
                return Err(format!("Failed to read HKCU\\Environment\\Path (Win32 error {q2})"));
            }
            let used = (cb2 as usize).min(raw.len());
            let mut units: Vec<u16> = raw[..used]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            while units.last() == Some(&0) {
                units.pop();
            }
            String::from_utf16_lossy(&units)
        } else {
            return Err(format!("Failed to query HKCU\\Environment\\Path (Win32 error {q1})"));
        };

        let user_profile = std::env::var("USERPROFILE").ok();
        let Some(merged) =
            merge_windows_user_path_value(&existing, user_profile.as_deref(), bin_dir)
        else {
            return Ok(false);
        };

        let out_type = if val_type == REG_SZ && !merged.contains('%') {
            REG_SZ
        } else {
            REG_EXPAND_SZ
        };
        let wide_val = to_wide_z(&merged);
        let byte_len = wide_val
            .len()
            .checked_mul(2)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| "Windows user PATH exceeds registry size limits".to_owned())?;
        let bytes: Vec<u8> = wide_val.iter().flat_map(|u| u.to_le_bytes()).collect();

        let set_rc = unsafe {
            RegSetValueExW(
                hkey,
                val_name.as_ptr(),
                0,
                out_type,
                bytes.as_ptr(),
                byte_len,
            )
        };
        if set_rc != 0 {
            return Err(format!("Failed to write HKCU\\Environment\\Path (Win32 error {set_rc})"));
        }

        let mut msg_result: usize = 0;
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                subkey.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1000,
                &mut msg_result,
            );
        }
        Ok(true)
    }
}

#[cfg(windows)]
fn ensure_windows_user_path_in_registry(bin_dir: &Path) -> Result<bool, String> {
    win_env_path::ensure_user_path_in_registry(bin_dir)
}

#[cfg(not(windows))]
fn ensure_windows_user_path_in_registry(bin_dir: &Path) -> Result<bool, String> {
    let _ = merge_windows_user_path_value("", None, bin_dir);
    Ok(false)
}

fn resolve_effective_home(home_override: Option<&Path>) -> Result<PathBuf, String> {
    let raw = match home_override {
        Some(h) => {
            if h.as_os_str().is_empty() {
                return Err("Empty '--home' directory path.".to_owned());
            }
            if h.is_relative() {
                env::current_dir()
                    .map(|c| c.join(h))
                    .unwrap_or_else(|_| h.to_path_buf())
            } else {
                h.to_path_buf()
            }
        }
        None => user_home_dir(),
    };
    Ok(security::strip_verbatim_prefix(&raw))
}

fn resolve_effective_profile(
    explicit: Option<&str>,
    plugin_dir: &Path,
    gdb_opt: Option<&LibreDb>,
) -> Result<InstallProfile, String> {
    if let Some(raw) = explicit {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "neutral" => Ok(InstallProfile::Neutral),
            "personal" => Ok(InstallProfile::Personal),
            other => Err(format!(
                "Unknown install profile '{other}'; expected 'neutral' or 'personal'."
            )),
        };
    }

    let agents_md = plugin_dir.join("rules").join("AGENTS.md");
    if let Ok(content) = fs::read_to_string(&agents_md) {
        if content.starts_with("# Central LibreDB rules directive") {
            return Ok(InstallProfile::Personal);
        }
    }
    if let Some(gdb) = gdb_opt {
        if security::load_bool_config(Some(gdb), None, "guardrail:style_rules", false) {
            return Ok(InstallProfile::Personal);
        }
    }
    Ok(InstallProfile::Neutral)
}

fn detect_existing_custom_mcp_command(plugin_dir: &Path, home_dir: &Path) -> Option<PathBuf> {
    let cfg_path = plugin_dir.join("mcp_config.json");
    let raw = fs::read_to_string(&cfg_path).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let cmd_str = val
        .get("mcpServers")?
        .get("libredb-mcp")?
        .get("command")?
        .as_str()?
        .trim()
        .trim_matches('"');
    if cmd_str.is_empty() {
        return None;
    }
    let p = PathBuf::from(cmd_str);
    let p_norm = security::normalize_workspace_key(&p).to_ascii_lowercase();
    let home_norm = security::normalize_workspace_key(home_dir).to_ascii_lowercase();
    if p_norm.starts_with(&format!("{home_norm}/"))
        || p_norm == home_norm
        || p_norm.contains("/target/debug/")
        || p_norm.contains("/target/release/")
    {
        return None;
    }
    if p.is_file() || p.parent().is_some_and(Path::is_dir) {
        Some(p)
    } else {
        None
    }
}

fn test_safe_binary_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    #[cfg(windows)]
    {
        let ps_exe = if Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe").is_file() {
            r"C:\Program Files\PowerShell\7\pwsh.exe"
        } else {
            "powershell.exe"
        };
        let script = r#"$ErrorActionPreference='Stop';$p=$env:LIBREDB_ACL_CHECK_DIR;try{$acl=Get-Acl -LiteralPath $p;foreach($r in $acl.Access){if($r.AccessControlType -ne 'Allow'){continue};try{$sid=$r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=$r.IdentityReference.Value};$broad=($sid -match '^(S-1-1-0|S-1-2-0|S-1-5-11|S-1-5-32-545|S-1-5-32-546)$') -or ($sid -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$');if($broad -and (([int]$r.FileSystemRights -band 0x50030116) -ne 0)){'UNSAFE';exit 0}};'SAFE'}catch{'UNSAFE'}"#;
        let out = Command::new(ps_exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("LIBREDB_ACL_CHECK_DIR", dir)
            .output();
        match out {
            Ok(res) if res.status.success() => {
                String::from_utf8_lossy(&res.stdout).trim() == "SAFE"
            }
            _ => false,
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = fs::metadata(dir) else {
            return false;
        };
        let uid_ok = Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
            .is_some_and(|euid| meta.uid() == euid || meta.uid() == 0);
        let mode = meta.mode();
        let world_writable_unsticky = (mode & 0o002) != 0 && (mode & 0o1000) == 0;
        uid_ok && !world_writable_unsticky
    }
}

fn format_hook_exec_token(raw_path: &str) -> String {
    if raw_path.contains(' ') {
        format!("\"{raw_path}\"")
    } else {
        raw_path.to_owned()
    }
}

fn probe_hook_command(
    hook_display_path: &str,
    exe_disk_path: &Path,
    home_dir: &Path,
) -> Option<String> {
    if !exe_disk_path.is_file() {
        return None;
    }
    let formatted = format_hook_exec_token(hook_display_path);

    // Tolerate short AV/EDR hash scans (e.g. Panda Zero-Trust / Defender) on newly written executables.
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(350));
        }
        #[cfg(windows)]
        let mut cmd = {
            let comspec = env::var_os("ComSpec")
                .map(PathBuf::from)
                .filter(|p| p.is_file())
                .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
            let mut c = Command::new(comspec);
            c.args(["/C", &format!("{formatted} hook-pre-invocation")]);
            c
        };

        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = Command::new("/bin/sh");
            c.args(["-c", &format!("{formatted} hook-pre-invocation")]);
            c
        };

        cmd.env("HOME", home_dir)
            .env("USERPROFILE", home_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let Ok(mut child) = cmd.spawn() else {
            continue;
        };
        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(b"{}");
        }
        if let Ok(out) = child.wait_with_output() {
            if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("injectSteps")
            {
                return Some(formatted);
            }
        }
    }
    None
}

fn verify_ripgrep_binary(exe: &Path) -> bool {
    if !exe.is_file() {
        return false;
    }
    let Ok(out) = Command::new(exe).arg("--version").output() else {
        return false;
    };
    out.status.success()
        && String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .is_some_and(|l| l.starts_with("ripgrep "))
}

fn locate_rg_on_path() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "rg.exe" } else { "rg" };
    let path_env = env::var_os("PATH")?;
    for dir in env::split_paths(&path_env) {
        let cand = dir.join(exe_name);
        if verify_ripgrep_binary(&cand) {
            return Some(cand);
        }
    }
    None
}

fn locate_local_ripgrep(home_dir: &Path) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "rg.exe" } else { "rg" };
    let candidates = [
        home_dir.join(".cargo").join("bin").join(exe_name),
        home_dir.join(".local").join("bin").join(exe_name),
        home_dir
            .join("scoop")
            .join("apps")
            .join("ripgrep")
            .join("current")
            .join(exe_name),
        #[cfg(unix)]
        PathBuf::from("/opt/homebrew/bin/rg"),
        #[cfg(unix)]
        PathBuf::from("/usr/local/bin/rg"),
    ];
    for cand in candidates {
        if verify_ripgrep_binary(&cand) {
            return Some(cand);
        }
    }
    None
}

fn copy_sibling_python_ext_if_present(src_exe: &Path, bin_dir: &Path) -> Option<PathBuf> {
    let src_dir = src_exe.parent()?;
    if cfg!(windows) {
        for name in ["libredb.pyd", "libredb_py.dll"] {
            let cand = src_dir.join(name);
            if cand.is_file() {
                let dst = bin_dir.join("libredb.pyd");
                if install_binary_hot_safe(&cand, &dst).is_ok() {
                    return Some(dst);
                }
            }
        }
    } else {
        for name in [
            "libredb.so",
            "libredb_py.so",
            "liblibredb_py.so",
            "liblibredb_py.dylib",
            "libredb.abi3.so",
        ] {
            let cand = src_dir.join(name);
            if cand.is_file() {
                let dst = bin_dir.join("libredb.so");
                if install_binary_hot_safe(&cand, &dst).is_ok() {
                    return Some(dst);
                }
            }
        }
    }
    None
}

fn enable_plugin_in_antigravity_config(gemini_dir: &Path) {
    let cfg_path = gemini_dir.join("config").join("config.json");
    if !cfg_path.is_file() {
        return;
    }
    let Ok(raw) = fs::read_to_string(&cfg_path) else {
        return;
    };
    let Ok(mut root) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    let Some(plugins) = root.get_mut("plugins").and_then(Value::as_object_mut) else {
        return;
    };
    let already_enabled = plugins
        .get("libredb")
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true);
    if already_enabled {
        return;
    }
    match plugins.get_mut("libredb").and_then(Value::as_object_mut) {
        Some(obj) => {
            obj.insert("enabled".to_owned(), Value::Bool(true));
        }
        None => {
            plugins.insert("libredb".to_owned(), json!({ "enabled": true }));
        }
    }
    if let Ok(formatted) = serde_json::to_string_pretty(&root) {
        let _ = fs::write(&cfg_path, formatted);
    }
}

pub(crate) const EMBEDDED_LIBREDB_SKILL_MD: &str = r#"---
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
"#;

fn personal_agents_md_text() -> String {
    concat!(
        "# Central LibreDB rules directive\n\n",
        "All system rules, coding standards, administrative credentials, and skills live in `~/.gemini/libredb/customizations.ldb` (pure Rust single-file `LIBREDB1` storage). Enforce with HIGHEST PRIORITY:\n\n",
        "1. **Global output formatting invariant**:\n",
        "   - **No em-dashes or en-dashes**: Never output U+2014 or U+2013 in chat, markdown, code comments, commits, or artifacts. Use `-`, `:`, or `(...)`.\n",
        "   - **No emojis**: Never output emojis, smileys, or decorative Unicode symbols.\n",
        "   - **Sentence case for headings and labels**: Capitalize only the first word and proper nouns/acronyms (`GitHub`, `Gitea`, `LibreDB`, `SQLite`, `JSONL`, `UTF-8`, `API`, `CLI`, `IDE`, `MCP`). Never use Title Case.\n\n",
        "2. **Conversational communication and writing standards**:\n",
        "   - Use informal German (\"Du\"/\"Dein\", \"wir\"/\"unser\"; NEVER formal \"Sie\" or plural \"Ihr\"/\"Euer\"/\"Euch\") with natural umlauts (\u{00E4}, \u{00F6}, \u{00FC}, \u{00DF}).\n",
        "   - **German compound nouns (no Deppenbindestriche)**: Join Komposita into one word (e.g., \"Abteilungskontingent\", \"Browsertool\", \"Tabwechsel\", \"Standardeinstellung\", \"Kontextkompaktierung\", \"Subagentenisolation\", \"Tokenreduktion\", \"Token\u{00F6}konomie\" never \"Token-\u{00D6}konomie\").\n",
        "   - **Candid architectural pushback**: When an idea overshoots the target, adds unnecessary complexity, or hardcodes a fragile assumption, say directly that it is suboptimal and propose the cleaner engineering approach immediately.\n\n",
        "3. **Coding, SemVer 2.0.0, and Keep a Changelog 1.1.0**:\n",
        "   - **Language boundary**: 100% grammatically correct ASCII English in all code, comments, logs, UI strings, and commits. Never translate UI strings to German.\n",
        "   - **SemVer & releases**: Follow https://semver.org/ (`MAJOR.MINOR.PATCH`) and https://keepachangelog.com/en/1.1.0/. Never overwrite published tags; bump version, update `CHANGELOG.md` (`## [X.Y.Z] - YYYY-MM-DD`), place deliverables (`.apk`, `.aab`, `.exe`, `.msi`, `.xpi`, `.vsix`, `.whl`, `.jar`, `.zip`) in `dist/` or `releases/`, and sync via `libredb git-sync -m \"<msg>\" --project \"<dir>\" --releases` / `libredb git-release vX.Y.Z --project \"<dir>\"`.\n",
        "   - **Human-readable changelogs, release notes & overviews**: Write all `README.md` summaries, plugin overviews, `CHANGELOG.md` entries, and Git/Gitea release descriptions in clear, logical IT prose for human engineers and users. Explain what changed, why it matters, and how to use it in 1-2 concise sentences per bullet - never dump internal helper function names, storage keys, or run-on buzzword chains.\n",
        "   - **Authoring & README**: Commit as `Antigravity <antigravity@local.dev>`. Strictly no VBScript (`.vbs`, `cscript`, `wscript`). Follow the 9-block `README.md` blueprint: (1) `# Title`, (2) Shields.io badges (`Version`, `Tests`, stack, `Apache 2.0 + Commons Clause`), (3) 1-3 sentence summary, (4) `## Table of contents`, (5) executive summary table, (6) installation & quickstart, (7) usage & commands, (8) architecture & ASCII tree (`|--`), (9) SemVer & license.\n\n",
        "4. **Admin elevation and SOC audit standard (`C:\\IT_ADMIN_LOGS\\<USERNAME>\\<TASK>\\<TARGET>\\<Date>\\<hh_mm_ss>\\`)**:\n",
        "   - Elevate directly, via DPAPI (`~/.gemini/config/credentials/*.credential.xml`), or `Start-Process -Verb RunAs`. Never stage in `C:\\Windows\\Temp`, use `cmd.exe /c` wrappers, create remote services (`sc.exe \\\\`), or hardcode identities. After approval, log `[1/4 PRE-CHECK]`, `[2/4..3/4 ACTION]`, `[4/4 POST-CHECK]`, `[CLEANUP]` to `AuditLog_<Target>_<Date>_<hh_mm_ss>.log`.\n\n",
        "5. **Turn-economy, diagnostics, and built-in benchmarks**:\n",
        "   - **Anti-salami-slicing**: Read files `<= 800 lines` in one `read_file` call; for `> 800 lines` use `libredb_code` (`skeleton`, `locate`, `fim` including file-less `symbol`, `impact`, `grep` with batched `files`/`symbols`/`slices`) and batch parallel reads.\n",
        "   - **Subagent firewall**: Run 1-3 file edits and WMI/CIM commands in main context; delegate `>= 4` searches or `> 5` files to `research` (`Model=\"flash\"`).\n",
        "   - **Batching & verification**: Fix entire bug classes before rebuilding, chain `build && test && verify`, commit memory via `libredb_memorize`, check `libredb guardrail check --path \"<dir>\" --staged --strict`, inspect savings/benchmarks natively via `libredb savings` and `libredb bench` (zero ad-hoc scripts), and use `WaitMsBeforeAsync=10000` without polling. Note any internal tool workarounds briefly at the end.\n\n",
        "6. **Autonomous project memory & Git/Gitea sync (pure Pull)**:\n",
        "   - Persist/recall via `libredb_memorize`, `libredb_pulse` (`query`, `cwd`, `cid`, `budget`), and `libredb get-skill <name> [--section \"<Section>\"]` / `libredb slice-skill \"<query>\"` on pure-Rust `.agents/memory.ldb`.\n",
        "   - Use `libredb git-init`, `git-sync`, `git-release`, and `gitea-status`. Never hijack non-Gitea `origin` remotes or leak Gitea auth headers; ask before `--allow-unversioned` (\"Soll ich das wirklich ohne Versionierung hochladen?\") and pause on `[GITEA REPOSITORY COLLISION]`. Link URLs as `[Label](url)`.\n\n",
        "7. **Model & concurrency catalog**:\n",
        "   - `ultra` (16 reader lanes) and `pro` (8 lanes) across `Gemini 4 Argon`, `Gemini 4 Carbon`, `Gemini 3.8 Flash`, `Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`. Keep 100% of code generation on `Argon`, `Carbon`, or `Claude 5.5`; route only read-only `research` subagents to `Model=\"flash\"`.\n\n",
        "8. **Native cross-platform app design & anti-AI-slop UI standard (`Windows Fluent 2`, `Android Material 3`, `Apple HIG`, `KDE / GNOME HIG`)**:\n",
        "   - Ban AI-slop aesthetics across ALL platforms and toolkits (`WinUI`, `WPF`, `egui`/`eframe`, `Tauri`, `Jetpack Compose`, `SwiftUI`/`UIKit`/`AppKit`, `GTK4`/`Libadwaita`, `Kirigami`/`Qt6`): zero neon purple/cyan/rainbow gradients, zero oversized pill-heavy `>= 16px` cards or glassmorphism blobs, zero gratuitous animations, zero heavy Bold-all-over text, and zero hardcoded palettes overriding system Light/Dark/High-Contrast themes.\n",
        "   - **Windows (`Fluent 2`)** (`https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview`, `https://learn.microsoft.com/en-us/windows/apps/get-started/best-practices`): `Segoe UI Variable` (`400`/`600` only), `8px`/`4px`/`2px` corner radii on a `4px` grid, neutral layered surfaces with `1px` borders, `Mica`/`Acrylic`, single system accent, `>= 4.5:1` contrast, `epx` DPI scaling, full keyboard + UI Automation focus (`libredb get-skill windows-app-design`).\n",
        "   - **Android (`Material 3` / `Compose`)** (`https://developer.android.com/design/ui/`, `https://developer.android.com/design/ui/mobile`): `Roboto`/`Roboto Flex` in nonlinearly scaled `sp` (up to `200%`), `dynamicLightColorScheme`/`dynamicDarkColorScheme` tonal `surfaceContainer` tiers, M3 shape scale (`4dp`..`28dp`), mandatory `enableEdgeToEdge()` + `WindowInsets` (`safeDrawing`/`ime`), `>= 48dp` touch targets, adaptive `NavigationBar`/`NavigationRail`/`PermanentNavigationDrawer` + `ListDetailPaneScaffold`, predictive back, `TalkBack` (`libredb get-skill android-app-design`).\n",
        "   - **Apple iOS/iPadOS & macOS (`Apple HIG`)** (`https://developer.apple.com/design/human-interface-guidelines`, `https://developer.apple.com/design/human-interface-guidelines/designing-for-ios`, `https://developer.apple.com/design/human-interface-guidelines/designing-for-macos`): `SF Pro` (`SF Mono`) + `Dynamic Type` & `SF Symbols`, semantic system colors + `Material`/`NSVisualEffectView` vibrancy (respecting `reduceTransparency`/`Contrast`), iOS `safeAreaInsets` + `44pt` touch targets + `3-5` bottom `TabView` + `.insetGrouped` `.continuous` squircles vs macOS `20-28pt` pointer density + `NavigationSplitView` sidebar + unified `toolbar` + Menu Bar `.commands` (`Cmd+,` Settings) + `VoiceOver` (`libredb get-skill apple-hig-design`).\n",
        "   - **Linux Desktop (`GNOME Libadwaita` & `KDE Kirigami` HIG)** (`https://develop.kde.org/hig/`, `https://developer.gnome.org/hig/`, `https://developer.gnome.org/hig/principles.html`): GNOME `AdwToolbarView`/`AdwHeaderBar`, `AdwNavigationSplitView` + `AdwBreakpoint`, `.boxed-list` (`12px`/`6px` radii), `AdwToastOverlay`/`AdwStatusPage`, `AdwStyleManager` `@window_bg_color`/`@accent_bg_color`; KDE `Kirigami.ApplicationWindow`, `FormLayout`, `InlineMessage`, `Kirigami.Theme`/`KColorScheme` + `Kirigami.Units`, `xdg-desktop-portal` dark/accent, Wayland fractional scaling, `AT-SPI2` (`libredb get-skill linux-desktop-hig-design`).\n"
    )
    .to_owned()
}

const EMBEDDED_LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <rect x="28" y="28" width="200" height="200" rx="44" fill="#0F172A" stroke="#38BDF8" stroke-width="10"/>
  <circle cx="88" cy="96" r="18" fill="#38BDF8"/>
  <circle cx="168" cy="96" r="18" fill="#A78BFA"/>
  <circle cx="128" cy="168" r="20" fill="#34D399"/>
  <line x1="103" y1="106" x2="117" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="153" y1="106" x2="139" y2="152" stroke="#E2E8F0" stroke-width="8" stroke-linecap="round"/>
  <line x1="106" y1="96" x2="150" y2="96" stroke="#94A3B8" stroke-width="7" stroke-dasharray="10 8" stroke-linecap="round"/>
</svg>
"##;

fn render_plugin_readme(version: &str) -> String {
    format!(
        r#"# LibreDB cognitive memory plugin (v{version})

`LibreDB` gives `Antigravity` persistent project memory, targeted code navigation, and automated release workflows in a single 100% pure-Rust binary:

- **Persistent project memory (`libredb_pulse`, `libredb_memorize`)**: Stores architectural decisions, project facts, open tasks, and global rules in a single `.agents/memory.ldb` file, synchronizing updates incrementally (`O(1)` tail-sync) and skipping entries already shown in the session.
- **In-memory hook coordinator (`libredb mcp-serve`)**: Runs `PreInvocation` and `PreToolUse` hooks directly against the live MCP server RAM over a local Named Pipe or Unix socket, avoiding duplicate file locks and timeouts on slow network drives while falling back transparently to disk.
- **Targeted code navigation (`libredb_code`)**: Indexes functions, classes, and call relationships across 25+ languages so the agent can jump directly to symbol definitions (`locate`), inspect file outlines (`skeleton`), check affected callers (`impact`), run symbol-annotated searches (`grep`), and read exact file-less or line-targeted slices (`fim`) instead of loading entire large files.
- **Self-correcting learning (`libredb learning --verify`)**: Remembers which code symbol solved a failed search and which fix resolved a compiler or test error, refutes wrong hints automatically across 15 verified stages (`L1..L15`), and surfaces accurate pitfalls when similar code is touched later.
- **Token-savings reports and verification (`libredb savings`, `libredb bench`)**: Tracks real token savings across sessions and workspaces and runs built-in performance and security audit suites.
- **Workspace security, backups, and self-updates (`libredb trust`, `libredb backup`, `libredb update`, `libredb install`)**: Encrypts credentials via OS keystores (`Windows DPAPI` / `ChaCha20-Poly1305`), seals workspace databases against tampering (`HMAC-SHA256`), exports portable backups, checks staged commits against guardrails, and updates directly from GitHub Releases.
- **Neutral default profile**: `libredb install` / `deploy_plugin.ps1` (`neutral` default) installs the MCP server and security guardrails with zero personal rules and preserves existing Git identities.
"#
    )
}

fn find_repo_skills_dir_near(exe_path: &Path) -> Option<PathBuf> {
    let mut cur = exe_path.parent();
    for _ in 0..5 {
        let Some(d) = cur else { break };
        let skills_cand = d.join("skills");
        if skills_cand
            .join("windows-app-design")
            .join("SKILL.md")
            .is_file()
        {
            return Some(skills_cand);
        }
        cur = d.parent();
    }
    if let Ok(cwd) = env::current_dir() {
        let cwd_skills = cwd.join("skills");
        if cwd_skills
            .join("windows-app-design")
            .join("SKILL.md")
            .is_file()
        {
            return Some(cwd_skills);
        }
    }
    None
}

pub fn execute_install_command(opts: &InstallOptions) -> Result<InstallReport, String> {
    let src_exe = match opts.binary_path {
        Some(ref p) => {
            if !p.is_file() {
                return Err(format!("Installer binary '{}' does not exist.", p.display()));
            }
            fs::canonicalize(p).unwrap_or_else(|_| p.clone())
        }
        None => env::current_exe().map_err(|e| format!("Failed to locate current executable: {e}"))?,
    };
    let src_exe = security::strip_verbatim_prefix(&src_exe);

    let home_dir = resolve_effective_home(opts.home_override.as_deref())?;
    let gemini_dir = home_dir.join(".gemini");
    let libre_home = gemini_dir.join("libredb");
    let bin_dir = libre_home.join("bin");
    let agy_bin_dir = gemini_dir.join("antigravity").join("bin");
    let plugin_dir = gemini_dir.join("config").join("plugins").join("libredb");
    let rules_dir = plugin_dir.join("rules");
    let skill_dir = plugin_dir.join("skills").join("libredb");
    let assets_dir = plugin_dir.join("assets");

    for dir in [&bin_dir, &rules_dir, &skill_dir, &assets_dir] {
        fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create directory '{}': {e}", dir.display()))?;
    }
    set_unix_mode(&libre_home, 0o700)?;
    set_unix_mode(&bin_dir, 0o755)?;

    let global_ldb = opts.global_path.clone().unwrap_or_else(|| {
        if opts.home_override.is_some() {
            libre_home.join("customizations.ldb")
        } else {
            default_global_ldb_path()
        }
    });
    if let Some(gp) = global_ldb.parent() {
        fs::create_dir_all(gp).map_err(|e| e.to_string())?;
    }

    let existing_gdb = open_global_ldb_checked(Some(&global_ldb))?;
    let profile = resolve_effective_profile(
        opts.profile.as_deref(),
        &plugin_dir,
        existing_gdb.as_deref(),
    )?;
    drop(existing_gdb);

    let bin_name = if cfg!(windows) { "libredb.exe" } else { "libredb" };
    let target_exe = bin_dir.join(bin_name);

    // Single canonical binary installation at `~/.gemini/libredb/bin/libredb(.exe)`.
    let mut installed_binaries = Vec::new();
    install_binary_hot_safe(&src_exe, &target_exe)?;
    installed_binaries.push(target_exe.display().to_string());

    // Remove legacy/redundant duplicate binary copies and batch shims under `~/.gemini/antigravity/bin`.
    remove_stale_binary_copy(&agy_bin_dir.join(bin_name));
    let _ = fs::remove_file(agy_bin_dir.join("libredb.cmd"));

    if opts.home_override.is_none() {
        let _ = ensure_windows_user_path_in_registry(&bin_dir);
    }

    #[cfg(unix)]
    {
        let local_bin_dir = home_dir.join(".local").join("bin");
        fs::create_dir_all(&local_bin_dir).map_err(|e| {
            format!(
                "Failed to create directory '{}': {e}",
                local_bin_dir.display()
            )
        })?;
        set_unix_mode(&local_bin_dir, 0o755)?;
        if canonical_compare_key(&local_bin_dir) != canonical_compare_key(&bin_dir) {
            let local_link = local_bin_dir.join(bin_name);
            let is_symlink = fs::symlink_metadata(&local_link)
                .is_ok_and(|m| m.file_type().is_symlink());
            let points_to_target = fs::read_link(&local_link).is_ok_and(|cur| {
                cur == target_exe
                    || canonical_compare_key(&local_link) == canonical_compare_key(&target_exe)
            });
            if !is_symlink || !points_to_target {
                let tmp_link = local_bin_dir.join(format!(".{bin_name}.lnk.{}", std::process::id()));
                let _ = fs::remove_file(&tmp_link);
                std::os::unix::fs::symlink(&target_exe, &tmp_link).map_err(|e| {
                    format!(
                        "Failed to create symlink '{}' -> '{}': {e}",
                        local_link.display(),
                        target_exe.display()
                    )
                })?;
                fs::rename(&tmp_link, &local_link).map_err(|e| {
                    let _ = fs::remove_file(&tmp_link);
                    format!("Failed to install symlink '{}': {e}", local_link.display())
                })?;
            }
        }
    }

    if let Some(ext_dst) = copy_sibling_python_ext_if_present(&src_exe, &bin_dir) {
        installed_binaries.push(ext_dst.display().to_string());
    }

    // Discover ripgrep (`rg`) or provision into canonical `bin_dir` when absent from PATH.
    let rg_name = if cfg!(windows) { "rg.exe" } else { "rg" };
    let canonical_rg = bin_dir.join(rg_name);
    let legacy_agy_rg = agy_bin_dir.join(rg_name);
    let ripgrep_path = if verify_ripgrep_binary(&canonical_rg) {
        Some(canonical_rg.display().to_string())
    } else if verify_ripgrep_binary(&legacy_agy_rg) {
        Some(legacy_agy_rg.display().to_string())
    } else if let Some(path_rg) = locate_rg_on_path() {
        Some(path_rg.display().to_string())
    } else if let Some(found_rg) = locate_local_ripgrep(&home_dir) {
        let _ = install_binary_hot_safe(&found_rg, &canonical_rg);
        if verify_ripgrep_binary(&canonical_rg) {
            #[cfg(unix)]
            {
                let local_bin_dir = home_dir.join(".local").join("bin");
                if local_bin_dir.is_dir()
                    && canonical_compare_key(&local_bin_dir) != canonical_compare_key(&bin_dir)
                {
                    let rg_link = local_bin_dir.join(rg_name);
                    if fs::symlink_metadata(&rg_link).is_err() {
                        let _ = std::os::unix::fs::symlink(&canonical_rg, &rg_link);
                    }
                }
            }
            Some(canonical_rg.display().to_string())
        } else {
            Some(found_rg.display().to_string())
        }
    } else {
        None
    };

    // Always probe canonical local `~/.gemini/libredb/bin/libredb(.exe)` FIRST; fall back to an
    // external directory ONLY when explicitly requested via `--fallback-drive` or as last resort.
    let mut verified_hook_cmd: Option<String> = None;
    let mut verified_exe_path: Option<PathBuf> = None;

    let stage_fallback_root = |fb: &Path, installed: &mut Vec<String>| -> Option<(PathBuf, String)> {
        if !test_safe_binary_dir(fb) {
            return None;
        }
        let fb_libre = fb.join(".gemini").join("libredb");
        let fb_dir = fb_libre.join("bin");
        let fb_exe = fb_dir.join(bin_name);
        install_binary_hot_safe(&src_exe, &fb_exe).ok()?;
        let _ = set_unix_mode(&fb_libre, 0o700);
        let _ = set_unix_mode(&fb_dir, 0o755);
        if let Some(ref rg_src) = locate_rg_on_path().or_else(|| locate_local_ripgrep(&home_dir)) {
            let _ = install_binary_hot_safe(rg_src, &fb_dir.join(rg_name));
        }
        let disp = fb_exe.display().to_string();
        installed.push(disp.clone());
        Some((fb_exe, disp))
    };

    if !opts.no_hooks {
        let local_cand = if cfg!(windows) && opts.home_override.is_none() {
            Some((
                r"%USERPROFILE%\.gemini\libredb\bin\libredb.exe".to_owned(),
                target_exe.clone(),
            ))
        } else if cfg!(windows) || test_safe_binary_dir(&bin_dir) {
            Some((target_exe.display().to_string(), target_exe.clone()))
        } else {
            None
        };

        if let Some((display_cmd, disk_exe)) = local_cand {
            if let Some(formatted) = probe_hook_command(&display_cmd, &disk_exe, &home_dir) {
                verified_hook_cmd = Some(formatted);
                verified_exe_path = Some(disk_exe);
            }
        }

        if verified_hook_cmd.is_none() {
            if let Some(ref fb) = opts.fallback_drive {
                if let Some((fb_exe, disp)) = stage_fallback_root(fb, &mut installed_binaries) {
                    if let Some(formatted) = probe_hook_command(&disp, &fb_exe, &home_dir) {
                        verified_hook_cmd = Some(formatted);
                        verified_exe_path = Some(fb_exe);
                    }
                }
            } else if let Some(custom_path) =
                detect_existing_custom_mcp_command(&plugin_dir, &home_dir)
            {
                if install_binary_hot_safe(&src_exe, &custom_path).is_ok() {
                    let disp = custom_path.display().to_string();
                    if let Some(formatted) = probe_hook_command(&disp, &custom_path, &home_dir) {
                        installed_binaries.push(disp);
                        verified_hook_cmd = Some(formatted);
                        verified_exe_path = Some(custom_path);
                    }
                }
            }
        }
    } else if let Some(ref fb) = opts.fallback_drive {
        if let Some((fb_exe, _)) = stage_fallback_root(fb, &mut installed_binaries) {
            verified_exe_path = Some(fb_exe);
        }
    } else {
        verified_exe_path = Some(target_exe.clone());
    }

    let mcp_exe = verified_exe_path.unwrap_or_else(|| target_exe.clone());
    let mcp_exe_fwd = mcp_exe.to_string_lossy().replace('\\', "/");
    let global_fwd = global_ldb.to_string_lossy().replace('\\', "/");

    let version = env!("CARGO_PKG_VERSION").to_owned();

    // 1. plugin.json
    let plugin_json = serde_json::to_string_pretty(&json!({
        "name": "libredb",
        "displayName": "LibreDB Cognitive Memory",
        "version": version,
        "description": "Persistent project memory, fast code-graph search, and token-savings engine for Antigravity. Routes sub-millisecond lifecycle hooks via an in-memory MCP IPC coordinator with O(1) tail-sync, locates functions and call dependencies without reading whole files, enforces workspace guardrails, and automates Git/Gitea releases.",
        "logo": "assets/logo.svg",
        "suggestedPrompts": [
            "Show how many tokens LibreDB saved today and across my projects",
            "Load the project context, active decisions, and open tasks for this workspace",
            "Find where a function is defined and check which callers are affected before editing"
        ]
    }))
    .map_err(|e| e.to_string())?;
    fs::write(plugin_dir.join("plugin.json"), plugin_json).map_err(|e| e.to_string())?;

    // 2. mcp_config.json
    let mcp_json = serde_json::to_string_pretty(&json!({
        "mcpServers": {
            "libredb-mcp": {
                "command": mcp_exe_fwd,
                "args": [
                    "mcp-serve",
                    "--global",
                    global_fwd
                ]
            }
        }
    }))
    .map_err(|e| e.to_string())?;
    fs::write(plugin_dir.join("mcp_config.json"), mcp_json).map_err(|e| e.to_string())?;

    // 3. hooks.json
    let hooks_json = if let Some(ref hook_cmd) = verified_hook_cmd {
        serde_json::to_string_pretty(&json!({
            "libredb-autonomous-memory": {
                "PreInvocation": [
                    {
                        "type": "command",
                        "command": format!("{hook_cmd} hook-pre-invocation"),
                        "timeout": 15
                    }
                ],
                "PreToolUse": [
                    {
                        "matcher": "run_command|invoke_subagent|write_file|edit_file|write_to_file|replace_file_content|multi_replace_file_content",
                        "hooks": [
                            {
                                "type": "command",
                                "command": format!("{hook_cmd} hook-pre-tool"),
                                "timeout": 15
                            }
                        ]
                    }
                ]
            }
        }))
        .map_err(|e| e.to_string())?
    } else {
        serde_json::to_string_pretty(&json!({
            "libredb-autonomous-memory": {
                "enabled": false
            }
        }))
        .map_err(|e| e.to_string())?
    };
    fs::write(plugin_dir.join("hooks.json"), hooks_json).map_err(|e| e.to_string())?;

    // 4. rules/AGENTS.md
    let agents_md_path = rules_dir.join("AGENTS.md");
    match profile {
        InstallProfile::Personal => {
            fs::write(&agents_md_path, personal_agents_md_text()).map_err(|e| e.to_string())?;
        }
        InstallProfile::Neutral => {
            if let Ok(existing) = fs::read_to_string(&agents_md_path) {
                if existing.starts_with("# Central LibreDB rules directive") {
                    let _ = fs::remove_file(&agents_md_path);
                }
            }
        }
    }

    // 5. skills/libredb/SKILL.md + assets + README.md
    let skill_md_path = skill_dir.join("SKILL.md");
    fs::write(&skill_md_path, EMBEDDED_LIBREDB_SKILL_MD).map_err(|e| e.to_string())?;
    fs::write(assets_dir.join("logo.svg"), EMBEDDED_LOGO_SVG).map_err(|e| e.to_string())?;
    fs::write(plugin_dir.join("README.md"), render_plugin_readme(&version))
        .map_err(|e| e.to_string())?;

    // 6. Enable plugin in ~/.gemini/config/config.json if present
    enable_plugin_in_antigravity_config(&gemini_dir);

    // 7. Hydrate and modernize global customizations.ldb in-place
    let gdb = open_global_ldb(Some(&global_ldb))?;
    set_unix_mode(&global_ldb, 0o600)?;
    let skills_dir = find_repo_skills_dir_near(&src_exe);
    crate::modernize_global_db_with_options(
        &gdb,
        Some(&skill_md_path),
        skills_dir.as_deref(),
        profile == InstallProfile::Personal,
        opts.quiet_stdout,
    )
    .map_err(|e| format!("Failed to modernize global LibreDB store: {e}"))?;

    let _ = gdb.deprecate_key(NodeKind::Config, "hook:subagent_flash_routing");
    let _ = gdb.deprecate_key(NodeKind::Config, "hook:exploratory_firewall");
    if profile == InstallProfile::Personal {
        let _ = gdb.put(
            WriteRequest::new(NodeKind::Config, b"true".to_vec()).with_key("guardrail:style_rules"),
        );
        let _ = gdb.put(
            WriteRequest::new(NodeKind::Config, b"Antigravity".to_vec())
                .with_key("git:author_name"),
        );
        let _ = gdb.put(
            WriteRequest::new(NodeKind::Config, b"antigravity@local.dev".to_vec())
                .with_key("git:author_email"),
        );
    } else {
        let _ = gdb.deprecate_key(NodeKind::Config, "guardrail:style_rules");
        let _ = gdb.deprecate_key(NodeKind::Config, "git:author_name");
        let _ = gdb.deprecate_key(NodeKind::Config, "git:author_email");
    }

    Ok(InstallReport {
        version,
        profile,
        mcp_command: mcp_exe_fwd,
        hooks_enabled: verified_hook_cmd.is_some(),
        hook_command: verified_hook_cmd,
        plugin_dir: plugin_dir.display().to_string(),
        global_ldb: global_ldb.display().to_string(),
        installed_binaries,
        ripgrep_path,
    })
}

fn validate_github_repo(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_matches('/');
    let Some((owner, repo)) = trimmed.split_once('/') else {
        return Err(format!(
            "Invalid GitHub repository '{raw}'; expected '<owner>/<repo>'."
        ));
    };
    let valid_part = |s: &str| {
        !s.is_empty()
            && !s.contains("..")
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !valid_part(owner) || !valid_part(repo) || repo.contains('/') {
        return Err(format!(
            "Invalid GitHub repository '{raw}'; contains unsafe characters."
        ));
    }
    Ok(format!("{owner}/{repo}"))
}

fn is_trusted_github_release_url(url: &str, repo: &str) -> bool {
    let expected_prefix = format!("https://github.com/{repo}/releases/download/");
    url.starts_with(&expected_prefix) || url.starts_with("https://objects.githubusercontent.com/")
}

pub(crate) fn parse_and_select_release_asset(
    json_bytes: &[u8],
    repo: &str,
    os: &str,
    arch: &str,
) -> Result<ReleaseAssetSelection, String> {
    let root: Value = serde_json::from_slice(json_bytes)
        .map_err(|e| format!("Failed to parse GitHub release metadata JSON: {e}"))?;
    let tag_name = root
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "GitHub release JSON is missing 'tag_name'.".to_owned())?
        .to_owned();
    let latest_version = tag_name.trim_start_matches(['v', 'V']).to_owned();

    let assets = root
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("GitHub release '{tag_name}' contains no binary assets."))?;

    let mut parsed_assets: Vec<(String, String)> = Vec::new();
    for a in assets {
        let Some(name) = a.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(url) = a.get("browser_download_url").and_then(Value::as_str) else {
            continue;
        };
        parsed_assets.push((name.to_owned(), url.to_owned()));
    }

    let arch_aliases: &[&str] = match arch {
        "x86_64" => &["x64", "x86_64", "amd64"],
        "aarch64" => &["arm64", "aarch64"],
        other => &[other],
    };
    let os_aliases: &[&str] = match os {
        "windows" => &["windows", "win32", "pc-windows"],
        "macos" => &["macos", "darwin", "apple"],
        "linux" => &["linux", "unknown-linux"],
        other => &[other],
    };
    let is_aux_file = |low: &str| {
        low.ends_with(".sha256")
            || low.ends_with(".sig")
            || low.ends_with(".asc")
            || low.ends_with(".txt")
            || low.ends_with(".zip")
            || low.ends_with(".tar.gz")
            || low.ends_with(".pyd")
            || low.ends_with(".dll")
            || low.ends_with(".so")
            || low.ends_with(".dylib")
            || low.ends_with(".whl")
            || low.ends_with(".pdb")
    };

    let mut chosen: Option<(String, String)> = None;
    for (name, url) in &parsed_assets {
        let low = name.to_ascii_lowercase();
        if is_aux_file(&low) || !low.contains("libredb") {
            continue;
        }
        if os == "windows" && !low.ends_with(".exe") {
            continue;
        }
        if os != "windows" && low.ends_with(".exe") {
            continue;
        }
        let has_os = os_aliases.iter().any(|k| low.contains(k));
        let has_arch = arch_aliases.iter().any(|k| low.contains(k));
        if has_os && has_arch {
            chosen = Some((name.clone(), url.clone()));
            break;
        }
    }

    // Fallback for plain `.exe` release asset names when only one Windows binary exists:
    if chosen.is_none() && os == "windows" && arch == "x86_64" {
        for (name, url) in &parsed_assets {
            let low = name.to_ascii_lowercase();
            if low.ends_with(".exe") && low.contains("libredb") && !low.contains("arm64") {
                chosen = Some((name.clone(), url.clone()));
                break;
            }
        }
    }

    let (asset_name, download_url) = chosen.ok_or_else(|| {
        let avail: Vec<&str> = parsed_assets.iter().map(|(n, _)| n.as_str()).collect();
        format!(
            "No matching {os}/{arch} binary asset found in release '{tag_name}' (available: [{}]).",
            avail.join(", ")
        )
    })?;

    if !is_trusted_github_release_url(&download_url, repo) {
        return Err(format!(
            "Refusing untrusted release asset download URL '{}' for repository '{repo}'.",
            download_url
        ));
    }

    Ok(ReleaseAssetSelection {
        tag_name,
        latest_version,
        asset_name,
        download_url,
    })
}

fn system_curl_bin() -> &'static str {
    if cfg!(windows) {
        let sys_curl = Path::new(r"C:\Windows\System32\curl.exe");
        if sys_curl.is_file() {
            r"C:\Windows\System32\curl.exe"
        } else {
            "curl.exe"
        }
    } else {
        "curl"
    }
}

fn fetch_github_release_json(repo: &str, version_opt: Option<&str>) -> Result<Vec<u8>, String> {
    let api_paths: Vec<String> = if let Some(raw_v) = version_opt {
        let clean = raw_v.trim();
        if clean.is_empty()
            || clean.contains("..")
            || !clean
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
        {
            return Err(format!("Invalid release version '{raw_v}'."));
        }
        if clean.starts_with('v') || clean.starts_with('V') {
            vec![format!("repos/{repo}/releases/tags/{clean}")]
        } else {
            vec![
                format!("repos/{repo}/releases/tags/v{clean}"),
                format!("repos/{repo}/releases/tags/{clean}"),
            ]
        }
    } else {
        vec![format!("repos/{repo}/releases/latest")]
    };

    let mut errors = Vec::new();
    for api_path in &api_paths {
        let url = format!("https://api.github.com/{api_path}");
        if let Ok(out) = Command::new(system_curl_bin())
            .args([
                "-fsSL",
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                "-A",
                "LibreDB-Updater",
                "-H",
                "Accept: application/vnd.github+json",
                &url,
            ])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                return Ok(out.stdout);
            }
            let err_s = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            if !err_s.is_empty() {
                errors.push(format!("curl ({api_path}): {err_s}"));
            }
        }
        if let Ok(out) = Command::new("gh").args(["api", api_path]).output() {
            if out.status.success() && !out.stdout.is_empty() {
                return Ok(out.stdout);
            }
            let err_s = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            if !err_s.is_empty() {
                errors.push(format!("gh api ({api_path}): {err_s}"));
            }
        }
    }

    Err(format!(
        "Failed to query GitHub releases for '{repo}' ({})",
        if errors.is_empty() {
            "network or curl/gh unavailable".to_owned()
        } else {
            errors.join("; ")
        }
    ))
}

fn verify_executable_magic(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Failed to read downloaded binary '{}': {e}", path.display()))?;
    if bytes.len() < 1024 {
        return Err(format!(
            "Downloaded file '{}' is too small ({} bytes) to be a valid executable.",
            path.display(),
            bytes.len()
        ));
    }
    #[cfg(target_os = "windows")]
    if &bytes[..2] != b"MZ" {
        return Err("Downloaded Windows executable is missing PE 'MZ' header.".to_owned());
    }
    #[cfg(target_os = "linux")]
    if &bytes[..4] != b"\x7fELF" {
        return Err("Downloaded Linux executable is missing ELF magic header.".to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        let m = &bytes[..4];
        let is_macho = matches!(
            m,
            [0xFE, 0xED, 0xFA, 0xCE]
                | [0xFE, 0xED, 0xFA, 0xCF]
                | [0xCE, 0xFA, 0xED, 0xFE]
                | [0xCF, 0xFA, 0xED, 0xFE]
                | [0xCA, 0xFE, 0xBA, 0xBE]
        );
        if !is_macho {
            return Err("Downloaded macOS executable is missing Mach-O magic header.".to_owned());
        }
    }
    Ok(())
}

fn download_release_asset(
    repo: &str,
    tag_name: &str,
    asset_name: &str,
    download_url: &str,
    staged_dest: &Path,
) -> Result<(), String> {
    if !is_trusted_github_release_url(download_url, repo) {
        return Err(format!("Refusing untrusted download URL '{download_url}'."));
    }
    if let Ok(out) = Command::new(system_curl_bin())
        .args([
            "-fSL",
            "--connect-timeout",
            "15",
            "--max-time",
            "180",
            "-A",
            "LibreDB-Updater",
            "-o",
        ])
        .arg(staged_dest)
        .arg(download_url)
        .output()
    {
        if out.status.success() && staged_dest.is_file() {
            return Ok(());
        }
    }

    let tmp_dir = staged_dest
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".gh_dl_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let gh_res = Command::new("gh")
        .args([
            "release",
            "download",
            tag_name,
            "--repo",
            repo,
            "--pattern",
            asset_name,
            "--dir",
        ])
        .arg(&tmp_dir)
        .arg("--clobber")
        .output();
    let dl_file = tmp_dir.join(asset_name);
    let moved = if matches!(gh_res, Ok(ref o) if o.status.success()) && dl_file.is_file() {
        fs::rename(&dl_file, staged_dest).or_else(|_| fs::copy(&dl_file, staged_dest).map(|_| ()))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Both system curl and gh release download failed",
        ))
    };
    let _ = fs::remove_dir_all(&tmp_dir);
    moved.map_err(|e| format!("Failed to download release asset '{asset_name}': {e}"))
}

fn pick_writable_staging_dir(home_dir: &Path, fallback_drive: Option<&Path>) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(cur_exe) = env::current_exe() {
        if let Some(p) = cur_exe.parent() {
            candidates.push(p.to_path_buf());
        }
    }
    if let Some(fb) = fallback_drive {
        candidates.push(fb.join(".gemini").join("libredb").join("bin"));
    }
    candidates.push(home_dir.join(".gemini").join("libredb").join("bin"));
    candidates.push(env::temp_dir());

    for dir in candidates {
        if fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let probe = dir.join(format!(".libredb_write_probe_{}", std::process::id()));
        if fs::write(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            return Ok(dir);
        }
    }
    Err("Could not find a writable directory to stage LibreDB update binary.".to_owned())
}

pub fn execute_update_command(opts: &UpdateOptions) -> Result<UpdateReport, String> {
    let repo = validate_github_repo(opts.repo.as_deref().unwrap_or(DEFAULT_GITHUB_REPO))?;
    let current_version = env!("CARGO_PKG_VERSION").to_owned();
    let home_dir = resolve_effective_home(opts.home_override.as_deref())?;

    let json_bytes = fetch_github_release_json(&repo, opts.version.as_deref())?;
    let selection = parse_and_select_release_asset(
        &json_bytes,
        &repo,
        env::consts::OS,
        env::consts::ARCH,
    )?;

    if opts.check_only {
        return Ok(UpdateReport {
            current_version,
            latest_version: selection.latest_version,
            tag_name: selection.tag_name,
            repo,
            asset_name: selection.asset_name,
            download_url: selection.download_url,
            check_only: true,
            updated: false,
            staged_binary: None,
            install_report: None,
        });
    }

    if selection.latest_version == current_version && !opts.force {
        let rep = execute_install_command(&InstallOptions {
            binary_path: None,
            profile: opts.profile.clone(),
            no_hooks: opts.no_hooks,
            fallback_drive: opts.fallback_drive.clone(),
            home_override: opts.home_override.clone(),
            global_path: opts.global_path.clone(),
            quiet_stdout: opts.quiet_stdout,
        })?;
        return Ok(UpdateReport {
            current_version,
            latest_version: selection.latest_version,
            tag_name: selection.tag_name,
            repo,
            asset_name: selection.asset_name,
            download_url: selection.download_url,
            check_only: false,
            updated: false,
            staged_binary: None,
            install_report: Some(rep),
        });
    }

    let stage_dir = pick_writable_staging_dir(&home_dir, opts.fallback_drive.as_deref())?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let staged_path = stage_dir.join(format!(
        ".libredb_update_{}_{nanos}{ext}",
        std::process::id()
    ));
    let _cleanup = StagingCleanupGuard::new(staged_path.clone());

    download_release_asset(
        &repo,
        &selection.tag_name,
        &selection.asset_name,
        &selection.download_url,
        &staged_path,
    )?;
    strip_zone_identifier(&staged_path);
    set_executable_mode(&staged_path)?;
    verify_executable_magic(&staged_path)?;

    let ver_out = Command::new(&staged_path)
        .arg("--version")
        .output()
        .map_err(|e| format!("Downloaded binary '{}' could not be executed: {e}", staged_path.display()))?;
    if !ver_out.status.success() {
        return Err(format!(
            "Downloaded binary '{}' failed '--version' check.",
            staged_path.display()
        ));
    }
    let ver_str = String::from_utf8_lossy(&ver_out.stdout).trim().to_owned();
    if !ver_str.contains(&selection.latest_version) {
        return Err(format!(
            "Downloaded binary reported version '{ver_str}', expected '{}'.",
            selection.latest_version
        ));
    }

    // Delegate installation to the newly downloaded binary so it embeds its own latest SKILL.md,
    // plugin metadata, reflexes, and design skills.
    let mut cmd = Command::new(&staged_path);
    cmd.arg("install").arg("--json");
    if let Some(ref p) = opts.profile {
        cmd.args(["--profile", p]);
    }
    if opts.no_hooks {
        cmd.arg("--no-hooks");
    }
    if let Some(ref fb) = opts.fallback_drive {
        cmd.arg("--fallback-drive").arg(fb);
    }
    if let Some(ref h) = opts.home_override {
        cmd.arg("--home").arg(h);
    }
    if let Some(ref g) = opts.global_path {
        cmd.arg("--global").arg(g);
    }

    let inst_out = cmd
        .output()
        .map_err(|e| format!("Failed to invoke staged installer '{}': {e}", staged_path.display()))?;
    if !inst_out.status.success() {
        return Err(format!(
            "Staged installer failed: {}",
            String::from_utf8_lossy(&inst_out.stderr).trim()
        ));
    }

    let json_txt = String::from_utf8_lossy(&inst_out.stdout);
    let rep_val: Value = serde_json::from_str(json_txt.trim()).map_err(|e| {
        format!("Staged installer returned invalid JSON output: {e} ({json_txt})")
    })?;

    Ok(UpdateReport {
        current_version,
        latest_version: selection.latest_version,
        tag_name: selection.tag_name,
        repo,
        asset_name: selection.asset_name,
        download_url: selection.download_url,
        check_only: false,
        updated: true,
        staged_binary: Some(staged_path.display().to_string()),
        install_report: Some(InstallReport {
            version: rep_val["version"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            profile: if rep_val["profile"].as_str() == Some("personal") {
                InstallProfile::Personal
            } else {
                InstallProfile::Neutral
            },
            mcp_command: rep_val["mcp_command"].as_str().unwrap_or("").to_owned(),
            hooks_enabled: rep_val["hooks_enabled"].as_bool().unwrap_or(false),
            hook_command: rep_val["hook_command"].as_str().map(ToOwned::to_owned),
            plugin_dir: rep_val["plugin_dir"].as_str().unwrap_or("").to_owned(),
            global_ldb: rep_val["global_ldb"].as_str().unwrap_or("").to_owned(),
            installed_binaries: rep_val["installed_binaries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            ripgrep_path: rep_val["ripgrep_path"].as_str().map(ToOwned::to_owned),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_installer_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!("libredb_{tag}_{}_{}", std::process::id(), nanos))
    }

    #[test]
    fn standalone_install_creates_plugin_preserves_profile_and_resets_stale_foreign_mcp_path() {
        let tmp = temp_installer_dir("standalone_install");
        let fake_home = tmp.join("user_home");
        let stale_foreign_dir = tmp.join("stale_q_drive").join(".gemini").join("libredb").join("bin");
        let bin_name = if cfg!(windows) { "libredb.exe" } else { "libredb" };
        let stale_foreign_exe = stale_foreign_dir.join(bin_name);
        let plugin_dir = fake_home
            .join(".gemini")
            .join("config")
            .join("plugins")
            .join("libredb");
        let agy_bin_dir = fake_home.join(".gemini").join("antigravity").join("bin");
        fs::create_dir_all(&stale_foreign_dir).unwrap();
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::create_dir_all(&agy_bin_dir).unwrap();

        // Pre-seed stale duplicate in `~/.gemini/antigravity/bin` and stale foreign path in `mcp_config.json`:
        let stale_agy_exe = agy_bin_dir.join(bin_name);
        let stale_agy_cmd = agy_bin_dir.join("libredb.cmd");
        fs::write(&stale_agy_exe, b"stale_duplicate").unwrap();
        fs::write(&stale_agy_cmd, b"@echo off\r\n").unwrap();

        let stale_foreign_fwd = stale_foreign_exe.to_string_lossy().replace('\\', "/");
        fs::write(
            plugin_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "libredb-mcp": {
                        "command": stale_foreign_fwd,
                        "args": ["mcp-serve", "--global", "old.ldb"]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let canonical_exe = fake_home.join(".gemini").join("libredb").join("bin").join(bin_name);
        let canonical_fwd = canonical_exe.to_string_lossy().replace('\\', "/");

        // 1. Install with Personal profile & no fallback drive -> must use canonical local binary,
        // never write to stale_q_drive, and remove duplicate binaries from antigravity/bin.
        let rep1 = execute_install_command(&InstallOptions {
            binary_path: None,
            profile: Some("personal".to_owned()),
            no_hooks: true,
            fallback_drive: None,
            home_override: Some(fake_home.clone()),
            global_path: None,
            quiet_stdout: true,
        })
        .unwrap();
        let canonical_bin_dir = canonical_exe
            .parent()
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let assert_single_canonical = |installed: &[String]| {
            let exe_entries: Vec<&String> = installed
                .iter()
                .filter(|p| Path::new(p).file_name().and_then(|s| s.to_str()) == Some(bin_name))
                .collect();
            assert_eq!(
                exe_entries,
                vec![&canonical_exe.display().to_string()],
                "Expected exactly one canonical CLI executable, got: {installed:?}"
            );
            assert!(
                installed
                    .iter()
                    .all(|p| p.replace('\\', "/").starts_with(&canonical_bin_dir)),
                "All installed binaries must stay inside canonical bin dir: {installed:?}"
            );
        };
        assert_eq!(rep1.profile, InstallProfile::Personal);
        assert_eq!(rep1.mcp_command, canonical_fwd);
        assert_single_canonical(&rep1.installed_binaries);
        assert!(canonical_exe.is_file(), "Canonical binary must exist at ~/.gemini/libredb/bin");
        assert!(
            !stale_foreign_exe.exists(),
            "Stale foreign drive binary must never be recreated or preferred"
        );
        assert!(
            !stale_agy_exe.exists() && !stale_agy_cmd.exists(),
            "Stale duplicate binaries under ~/.gemini/antigravity/bin must be removed"
        );
        #[cfg(unix)]
        {
            let local_link = fake_home.join(".local").join("bin").join(bin_name);
            let meta = fs::symlink_metadata(&local_link).expect("~/.local/bin/libredb symlink");
            assert!(
                meta.file_type().is_symlink(),
                "~/.local/bin/libredb must be a symlink to canonical binary, not a physical copy"
            );
            assert_eq!(fs::read_link(&local_link).unwrap(), canonical_exe);
        }
        assert!(plugin_dir.join("plugin.json").is_file());
        assert!(plugin_dir.join("hooks.json").is_file());
        assert!(plugin_dir.join("rules").join("AGENTS.md").is_file());
        assert!(plugin_dir.join("skills").join("libredb").join("SKILL.md").is_file());

        let gdb = LibreDb::open(Path::new(&rep1.global_ldb)).unwrap();
        assert!(gdb
            .get_by_key(NodeKind::Skill, "windows-app-design")
            .is_ok());
        assert!(gdb
            .get_by_key(NodeKind::Rule, "reflex::libredb-self-update-no-edit-guard")
            .is_ok());
        drop(gdb);

        // 2. Subsequent install with profile=None must auto-preserve Personal profile cleanly!
        let rep2 = execute_install_command(&InstallOptions {
            binary_path: None,
            profile: None,
            no_hooks: true,
            fallback_drive: None,
            home_override: Some(fake_home.clone()),
            global_path: None,
            quiet_stdout: true,
        })
        .unwrap();
        assert_eq!(rep2.profile, InstallProfile::Personal);
        assert_eq!(rep2.mcp_command, canonical_fwd);
        assert_single_canonical(&rep2.installed_binaries);

        // 3. Verify pure Windows HKCU\Environment\Path merging & deduplication logic.
        let win_bin = Path::new(r"C:\Users\alice\.gemini\libredb\bin");
        assert_eq!(
            merge_windows_user_path_value("", Some(r"C:\Users\alice"), win_bin),
            Some(r"C:\Users\alice\.gemini\libredb\bin".to_owned())
        );
        assert_eq!(
            merge_windows_user_path_value(
                r"%SystemRoot%\system32;%USERPROFILE%\.gemini\libredb\bin\",
                Some(r"C:\Users\alice"),
                win_bin
            ),
            None
        );
        assert_eq!(
            merge_windows_user_path_value(
                r"C:\Users\Alice\.gemini\libredb\bin;C:\Tools",
                Some(r"C:\Users\alice"),
                win_bin
            ),
            None
        );
        assert_eq!(
            merge_windows_user_path_value(
                r"%SystemRoot%\system32;%USERPROFILE%\AppData\Local\Programs;",
                Some(r"C:\Users\alice"),
                win_bin
            ),
            Some(r"%SystemRoot%\system32;%USERPROFILE%\AppData\Local\Programs;C:\Users\alice\.gemini\libredb\bin".to_owned())
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn release_asset_selector_picks_exact_platform_and_blocks_untrusted_download_hosts() {
        let sample = serde_json::to_vec(&json!({
            "tag_name": "v2.4.0",
            "assets": [
                {
                    "name": "libredb-v2.4.0-linux-x64",
                    "browser_download_url": "https://github.com/scorpion421/LibreDB/releases/download/v2.4.0/libredb-v2.4.0-linux-x64"
                },
                {
                    "name": "libredb-v2.4.0-macos-arm64",
                    "browser_download_url": "https://github.com/scorpion421/LibreDB/releases/download/v2.4.0/libredb-v2.4.0-macos-arm64"
                },
                {
                    "name": "libredb-v2.4.0-windows-x64.exe",
                    "browser_download_url": "https://github.com/scorpion421/LibreDB/releases/download/v2.4.0/libredb-v2.4.0-windows-x64.exe"
                }
            ]
        }))
        .unwrap();

        let win = parse_and_select_release_asset(&sample, "scorpion421/LibreDB", "windows", "x86_64").unwrap();
        assert_eq!(win.latest_version, "2.4.0");
        assert_eq!(win.asset_name, "libredb-v2.4.0-windows-x64.exe");

        let lin = parse_and_select_release_asset(&sample, "scorpion421/LibreDB", "linux", "x86_64").unwrap();
        assert_eq!(lin.asset_name, "libredb-v2.4.0-linux-x64");

        let mac = parse_and_select_release_asset(&sample, "scorpion421/LibreDB", "macos", "aarch64").unwrap();
        assert_eq!(mac.asset_name, "libredb-v2.4.0-macos-arm64");

        let evil = serde_json::to_vec(&json!({
            "tag_name": "v2.4.0",
            "assets": [
                {
                    "name": "libredb-v2.4.0-windows-x64.exe",
                    "browser_download_url": "https://evil.example.com/libredb-v2.4.0-windows-x64.exe"
                }
            ]
        }))
        .unwrap();
        assert!(parse_and_select_release_asset(&evil, "scorpion421/LibreDB", "windows", "x86_64").is_err());
    }
}
