//! Crash-resilient `0700` ephemeral directory allocation and `.owner.lock` orphan reaping.

use super::vault::fill_csprng;
use super::{hex_encode, normalize_workspace_key};
use libredb_core::OsFileBackend;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
/// Scans `std::env::temp_dir()` for `prefix_*` directories orphaned by hard-crashed (`SIGKILL` /
/// `TerminateProcess`) MCP server processes and removes ONLY directories whose `.owner.lock`
/// sentinel is NOT held by any live OS file handle (plus lockless partial dirs older than 60s).
/// Active MCP server processes hold an exclusive kernel lock on `.owner.lock` for their entire
/// lifetime and are never disturbed.
pub(crate) fn reap_abandoned_ephemeral_dirs(prefix: &str) -> usize {
    let base = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(&base) else {
        return 0;
    };
    let match_prefix = format!("{prefix}_");
    let mut reaped = 0usize;
    for entry_res in entries {
        let Ok(entry) = entry_res else { continue };
        let fname_os = entry.file_name();
        let Some(fname) = fname_os.to_str() else {
            continue;
        };
        if !fname.starts_with(&match_prefix) {
            continue;
        }
        let dir_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&dir_path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            extern "C" {
                fn geteuid() -> u32;
            }
            if meta.uid() != unsafe { geteuid() } {
                continue;
            }
        }
        let init_marker = dir_path.join(".initializing");
        if let Ok(init_meta) = fs::symlink_metadata(&init_marker) {
            let init_recent = init_meta
                .modified()
                .ok()
                .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                .is_none_or(|age| age < std::time::Duration::from_secs(60));
            if init_recent {
                // Concurrent sibling process is between `DirBuilder::create` and `.owner.lock` acquisition.
                continue;
            }
        }
        let sentinel = dir_path.join(".owner.lock");
        match fs::symlink_metadata(&sentinel) {
            Ok(s_meta) => {
                if s_meta.file_type().is_symlink() || !s_meta.is_file() {
                    continue;
                }
                let Ok(probe_lock) = OsFileBackend::open(&sentinel) else {
                    continue;
                };
                match probe_lock.try_lock_write_region() {
                    Ok(true) => {
                        let _ = probe_lock.unlock_exclusive();
                        drop(probe_lock);
                        if fs::remove_dir_all(&dir_path).is_ok() {
                            reaped += 1;
                        }
                    }
                    Ok(false) | Err(_) => {
                        // Active MCP process holds `.owner.lock`; never touch!
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let is_stale_partial = meta
                    .modified()
                    .ok()
                    .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                    .is_some_and(|age| age >= std::time::Duration::from_secs(60));
                if is_stale_partial && fs::remove_dir_all(&dir_path).is_ok() {
                    reaped += 1;
                }
            }
            Err(_) => {}
        }
    }
    reaped
}

/// Creates an owner-only (`0700` on Unix) CSPRNG-named ephemeral directory inside `std::env::temp_dir()`
/// using non-recursive `DirBuilder::create` (atomic fail-if-exists semantics against pre-created symlinks)
/// and acquires an exclusive kernel liveness lock on `<dir>/.owner.lock`.
pub(crate) fn create_private_ephemeral_dir(
    prefix: &str,
) -> Result<(PathBuf, OsFileBackend), String> {
    let _ = reap_abandoned_ephemeral_dirs(prefix);
    let base = std::env::temp_dir();
    for _ in 0..8 {
        let mut rnd = [0u8; 16];
        fill_csprng(&mut rnd)?;
        let candidate = base.join(format!(
            "{prefix}_{}_{}",
            std::process::id(),
            hex_encode(&rnd)
        ));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&candidate) {
            Ok(()) => {
                let init_marker = candidate.join(".initializing");
                if let Err(e) = fs::write(&init_marker, b"1") {
                    let _ = fs::remove_dir_all(&candidate);
                    return Err(format!(
                        "Failed to stage ephemeral init marker '{}': {e}",
                        init_marker.display()
                    ));
                }
                let sentinel = candidate.join(".owner.lock");
                let lock_backend = match OsFileBackend::open(&sentinel) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = fs::remove_dir_all(&candidate);
                        return Err(format!(
                            "Failed to create ephemeral liveness sentinel '{}': {e}",
                            sentinel.display()
                        ));
                    }
                };
                match lock_backend.try_lock_write_region() {
                    Ok(true) => {
                        let _ = fs::remove_file(&init_marker);
                        return Ok((candidate, lock_backend));
                    }
                    Ok(false) => {
                        drop(lock_backend);
                        let _ = fs::remove_dir_all(&candidate);
                        return Err(format!(
                            "Unexpected lock contention on fresh ephemeral sentinel '{}'",
                            sentinel.display()
                        ));
                    }
                    Err(e) => {
                        drop(lock_backend);
                        let _ = fs::remove_dir_all(&candidate);
                        return Err(format!(
                            "Failed to lock ephemeral sentinel '{}': {e}",
                            sentinel.display()
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Failed to create private ephemeral directory '{}': {e}",
                    candidate.display()
                ));
            }
        }
    }
    Err("Failed to allocate unique CSPRNG ephemeral directory after 8 attempts".to_owned())
}

/// Computes a deterministic collision-free filename (`ws_<32-hex>.ldb`) for ephemeral MCP brains.
pub(crate) fn ephemeral_workspace_ldb_filename(ws_root: &Path) -> String {
    let norm = normalize_workspace_key(ws_root);
    let mut h = Sha256::new();
    h.update(b"LibreDB::EphemeralMcpBrain::v1\0");
    h.update(norm.as_bytes());
    let digest = h.finalize();
    format!("ws_{}.ldb", hex_encode(&digest[..16]))
}

