//! Standards-compliant OS secret vault, revision-monotonic `HMAC-SHA256` workspace trust seals
//! (`hmac-sha256:v4:r<rev>:`), ephemeral `0700` `MCP` directory management, and canonical path policies.
//!
//! Modular architecture (`v1.0.0`):
//! - `mod.rs`: Shared domain-separation constants, config loaders, workspace key canonicalization,
//!   and constant-time / encoding primitives.
//! - `ephemeral.rs`: CSPRNG `0700` ephemeral directory creation and `.owner.lock` crash reaping.
//! - `vault.rs`: Windows `DPAPI` and POSIX `ChaCha20-Poly1305` AEAD secret vault & trust anchor init.
//! - `seals.rs`: `WorkspaceTrustLockGuard`, `hmac-sha256:v4:r<rev>:` seals, rollback/loss ratchets,
//!   `PreMutationSealGuard`, and `v2`/`v3` -> `v4` migrations.
//! - `path_policy.rs`: Symlink/NTFS-ADS/Win32-dot path policy, `MCP` containment, and `CVE-2022-24765`.

mod ephemeral;
mod path_policy;
mod seals;
mod vault;
#[cfg(test)]
mod tests;

pub(crate) use ephemeral::{
    create_private_ephemeral_dir, ephemeral_workspace_ldb_filename, reap_abandoned_ephemeral_dirs,
};
pub(crate) use path_policy::canonicalize_with_missing_tail;
pub use path_policy::{
    check_mcp_read_path_policy, check_mcp_workspace_containment,
    check_tool_write_path_policy_with_base, is_forbidden_mcp_workspace_root, is_safe_auto_git_dir,
    sanitize_git_ref_for_prompt,
};

pub(crate) use seals::{
    has_config_key_fail_closed, is_mcp_untrusted_workspaces_allowed,
    is_workspace_path_authorized_synced,
};
#[cfg(test)]
pub(crate) use seals::{
    is_mcp_workspace_authorized_in_global, workspace_trust_lock_path_for_root,
};
pub use seals::{
    check_global_trust_sync, compute_cognitive_content_digest, detect_workspace_seal_rollback,
    has_prior_workspace_seal_marker,
    has_valid_legacy_v3_content_seal, is_unsealed_replacement_of_sealed_workspace,
    is_workspace_memory_trusted, list_trusted_workspaces, migrate_workspace_seal_v2_to_v3,
    migrate_workspace_seal_v3_to_v4, revoke_workspace_trust, seal_workspace_memory,
    PreMutationSealGuard, WorkspaceTrustLockGuard,
};

pub use vault::{is_ciphertext_envelope, protect_secret, unprotect_secret};

use crate::hooks::user_home_dir;
use hmac::Hmac;
use libredb_core::{LibreDb, LibreDbError, NodeKind, OsFileBackend, WriteRequest};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
pub(super) type HmacSha256 = Hmac<Sha256>;

#[cfg(any(windows, test))]
pub(super) const DPAPI_PREFIX: &str = "dpapi:v1:";
pub(super) const VAULT_V1_PREFIX: &str = "vault:v1:";
pub(super) const VAULT_V2_PREFIX: &str = "vault:v2:";
pub(super) const VAULT_AEAD_AAD: &[u8] = b"LibreDB::CredentialVault::v2";
pub(super) const CONTENT_DIGEST_V3_DOMAIN: &[u8] = b"LibreDB::CognitiveContent::v3\0";
pub(super) const CONTENT_DIGEST_DOMAIN: &[u8] = b"LibreDB::CognitiveContent::v4\0";
pub(super) const SEAL_V2_DOMAIN_SEP: &[u8] = b"LibreDB::WorkspaceTrustSeal::v2\0";
pub(super) const SEAL_V3_DOMAIN_SEP: &[u8] = b"LibreDB::WorkspaceTrustSeal::v3\0";
pub(super) const SEAL_V4_DOMAIN_SEP: &[u8] = b"LibreDB::WorkspaceTrustSeal::v4\0";
pub(super) const SEAL_V4_REV_DOMAIN_SEP: &[u8] = b"LibreDB::WorkspaceTrustSeal::v4r\0";
pub(super) const TRUST_SECRET_KEY: &str = "sys::trust_anchor_secret";
pub(super) const TRUST_SEALS_KEY: &str = "sys::trust_seals";


pub fn load_config_list(
    global_db: Option<&LibreDb>,
    proj_db: Option<&LibreDb>,
    key: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for db_opt in [global_db, proj_db] {
        if let Some(db) = db_opt {
            if let Ok(rec) = db.get_by_key(NodeKind::Config, key) {
                for item in String::from_utf8_lossy(&rec.payload).split([',', ';', '\n']) {
                    let s = item.trim();
                    if !s.is_empty() && !out.iter().any(|x: &String| x.eq_ignore_ascii_case(s)) {
                        out.push(s.to_owned());
                    }
                }
            }
        }
    }
    out
}

/// Resolves a boolean configuration toggle (`proj_db` overrides `global_db`, falling back to `default_val`).
pub fn load_bool_config(
    global_db: Option<&LibreDb>,
    proj_db: Option<&LibreDb>,
    key: &str,
    default_val: bool,
) -> bool {
    for db_opt in [proj_db, global_db] {
        if let Some(db) = db_opt {
            if let Ok(rec) = db.get_by_key(NodeKind::Config, key) {
                let low = String::from_utf8_lossy(&rec.payload).trim().to_ascii_lowercase();
                if matches!(low.as_str(), "1" | "true" | "yes" | "on") {
                    return true;
                }
                if matches!(low.as_str(), "0" | "false" | "no" | "off") {
                    return false;
                }
            }
        }
    }
    default_val
}

/// Resolves a string configuration value (`proj_db` overrides `global_db`).
pub fn load_string_config(
    global_db: Option<&LibreDb>,
    proj_db: Option<&LibreDb>,
    key: &str,
) -> Option<String> {
    for db_opt in [proj_db, global_db] {
        if let Some(db) = db_opt {
            if let Ok(rec) = db.get_by_key(NodeKind::Config, key) {
                let val = String::from_utf8_lossy(&rec.payload).trim().to_owned();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Checks whether `ws_root`'s `.git/index` tracks `.agents/memory.ldb` or `.agents/memory.db`
/// in `< 0.05 ms` pure Rust without spawning `git.exe`.
pub fn is_git_index_tracking_agents_db(ws_root: &Path) -> bool {
    let git_entry = ws_root.join(".git");
    let index_path = if git_entry.is_dir() {
        git_entry.join("index")
    } else {
        return false;
    };
    let Ok(meta) = index_path.metadata() else {
        return false;
    };
    if meta.len() == 0 || meta.len() > 16 * 1024 * 1024 {
        return false;
    }
    let Ok(raw) = fs::read(&index_path) else {
        return false;
    };
    contains_subslice(&raw, b".agents/memory.ldb") || contains_subslice(&raw, b".agents/memory.db")
}

/// Normalizes a workspace path into a canonical lookup key across verbatim UNC, mapped drives, and slashes.
pub fn normalize_workspace_key(path: &Path) -> String {
    let resolved = canonicalize_with_missing_tail(path).unwrap_or_else(|| path.to_path_buf());
    let cleaned = crate::gitea::strip_verbatim_prefix(&resolved);
    let mut s = cleaned.to_string_lossy().replace('\\', "/");
    while s.len() > 3 && s.ends_with('/') {
        s.pop();
    }
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s
    }
}


/// Returns true if `key` addresses a security-critical internal configuration namespace
/// (`sys::*`, `trust:*`, `workspace:*`, `workspace_id::*`) that must never be mutated via
/// generic `libredb config set/unset`, `libredb put`, `libredb deprecate`, or SQLite imports.
pub fn is_reserved_security_config_key(key: &str) -> bool {
    libredb_core::is_reserved_security_config_key(key)
}

/// Returns true if `key` addresses either a reserved internal trust/system namespace or a
/// privileged host/MCP/guardrail policy switch (`mcp:*`, `gitea_allow_insecure_http`,
/// `guardrail:allow_staged_files`) that must never be imported from SQLite or mutated via
/// low-level `libredb put` / `libredb deprecate`.
pub fn is_admin_only_security_config_key(key: &str) -> bool {
    libredb_core::is_admin_only_security_config_key(key)
}


/// Computes a deterministic collision-free `Config` key (`workspace_id::<16-hex>`) from a
/// normalized workspace path so distinct repositories sharing the same folder basename never
/// overwrite or revoke one another's learned workspace records.
pub fn workspace_id_config_key(norm: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"LibreDB::WorkspaceIdKey::v1\0");
    h.update(norm.as_bytes());
    let digest = h.finalize();
    format!("workspace_id::{}", hex_encode(&digest[..8]))
}


/// Returns true if `ws_root` resides inside an Antigravity per-conversation private brain folder
/// (`~/.gemini/antigravity*/brain/<cid>`).
pub fn is_private_brain_workspace(ws_root: &Path) -> bool {
    let norm = normalize_workspace_key(ws_root);
    let home_norm = normalize_workspace_key(&user_home_dir());
    norm.starts_with(&format!("{home_norm}/.gemini/")) && norm.contains("/brain/")
}


pub(super) fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(super) fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(super) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }
    let val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if chunk[2] == b'=' { 0 } else { val(chunk[2])? };
        let v3 = if chunk[3] == b'=' { 0 } else { val(chunk[3])? };
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((n >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((n & 0xFF) as u8);
        }
    }
    Some(out)
}

