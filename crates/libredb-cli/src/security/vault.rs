//! OS secret protection (Windows `DPAPI` / POSIX `0600` vault keyfile + RFC 8439 `ChaCha20-Poly1305`
//! AEAD), safe read-only `vault:v1:` -> `vault:v2:` migration, and single-winner trust anchor init.

use super::seals::check_global_trust_sync;
use super::*;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use libredb_core::crc::hash_key;
use libredb_core::StorageBackend;
pub fn is_ciphertext_envelope(stored: &str) -> bool {
    let t = stored.trim();
    t.starts_with("dpapi:") || t.starts_with("vault:")
}

/// Returns true if `stored` is already encrypted in the current standards-compliant vault format
/// (`dpapi:v1:` on Windows, `vault:v2:` on POSIX).
#[cfg(test)]
pub fn is_protected_secret(stored: &str) -> bool {
    let t = stored.trim();
    t.starts_with(DPAPI_PREFIX) || t.starts_with(VAULT_V2_PREFIX)
}

/// Encrypts a plaintext secret string using Windows DPAPI (`CryptProtectData` bound to the current
/// Windows/AD logon user) or RFC 8439 `ChaCha20-Poly1305` AEAD backed by a `0600` keyfile on POSIX.
/// Refuses to double-encrypt any legacy (`vault:v1:`) or foreign ciphertext envelope.
pub fn protect_secret(plaintext: &str) -> Result<String, String> {
    let trimmed = plaintext.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    #[cfg(windows)]
    if trimmed.starts_with(DPAPI_PREFIX) {
        return Ok(trimmed.to_owned());
    }
    #[cfg(not(windows))]
    if trimmed.starts_with(VAULT_V2_PREFIX) {
        return Ok(trimmed.to_owned());
    }
    if is_ciphertext_envelope(trimmed) {
        return Err(
            "Refusing to double-encrypt an existing or cross-platform ciphertext envelope"
                .to_owned(),
        );
    }

    #[cfg(windows)]
    {
        let cipher = win_dpapi::protect(plaintext.as_bytes())?;
        Ok(format!("{DPAPI_PREFIX}{}", base64_encode(&cipher)))
    }

    #[cfg(not(windows))]
    {
        let dir = user_home_dir().join(".gemini").join("libredb");
        let mut key = load_or_create_posix_vault_key_at(&dir, true)?;
        let mut nonce = [0u8; 12];
        if let Err(e) = fill_csprng(&mut nonce) {
            secure_zero(&mut key);
            return Err(e);
        }
        let res = aead_seal_v2(&key, &nonce, plaintext.as_bytes());
        secure_zero(&mut key);
        res
    }
}

/// Decrypts a vault-protected secret string in memory, returning `(plaintext, needs_upgrade)`:
/// - Current format (`dpapi:v1:` on Windows, `vault:v2:` on POSIX) -> `Ok((plaintext, false))`.
/// - Legacy POSIX `vault:v1:` (from v0.8.7/v0.8.8) -> verifies legacy tag, decrypts read-only, and
///   returns `Ok((plaintext, true))` for immediate re-encryption into RFC 8439 `vault:v2:`.
/// - Corrupt, unknown, or cross-OS `vault:*:` / `dpapi:*:` envelopes -> returns `Err(...)` so callers
///   never treat ciphertext as plaintext or overwrite stored credentials.
/// - Plaintext legacy string -> returns `Ok((raw, true))`.
pub fn unprotect_secret(stored: &str) -> Result<(String, bool), String> {
    let trimmed = stored.trim();
    if trimmed.is_empty() {
        return Ok((String::new(), false));
    }

    #[cfg(windows)]
    {
        if let Some(b64) = trimmed.strip_prefix(DPAPI_PREFIX) {
            let cipher =
                base64_decode(b64).ok_or_else(|| "invalid base64 in dpapi:v1 secret".to_owned())?;
            let mut plain_bytes = win_dpapi::unprotect(&cipher)?;
            let out = String::from_utf8_lossy(&plain_bytes).into_owned();
            secure_zero(&mut plain_bytes);
            return Ok((out, false));
        }
        if is_ciphertext_envelope(trimmed) {
            return Err(
                "Unsupported or non-Windows ciphertext envelope; refusing to double-encrypt or overwrite"
                    .to_owned(),
            );
        }
        Ok((trimmed.to_owned(), true))
    }

    #[cfg(not(windows))]
    {
        if is_ciphertext_envelope(trimmed) {
            if !trimmed.starts_with(VAULT_V2_PREFIX) && !trimmed.starts_with(VAULT_V1_PREFIX) {
                return Err(
                    "Unsupported or non-POSIX ciphertext envelope; refusing to double-encrypt or overwrite"
                        .to_owned(),
                );
            }
            let dir = user_home_dir().join(".gemini").join("libredb");
            let mut key = load_or_create_posix_vault_key_at(&dir, false)?;
            let res = unprotect_posix_envelope_with_key(&key, trimmed);
            secure_zero(&mut key);
            return res;
        }
        Ok((trimmed.to_owned(), true))
    }
}

/// Evaluates POSIX `vault:v2:` and legacy `vault:v1:` envelopes against `key`, rejecting any
/// unrecognized or cross-platform ciphertext envelope so it is never mistaken for plaintext.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn unprotect_posix_envelope_with_key(
    key: &[u8; 32],
    stored: &str,
) -> Result<(String, bool), String> {
    let trimmed = stored.trim();
    if let Some(b64) = trimmed.strip_prefix(VAULT_V2_PREFIX) {
        let plain = aead_open_v2(key, b64)?;
        return Ok((plain, false));
    }
    if let Some(b64) = trimmed.strip_prefix(VAULT_V1_PREFIX) {
        let plain = legacy_v1_open_for_migration(key, b64)?;
        return Ok((plain, true));
    }
    if is_ciphertext_envelope(trimmed) {
        return Err(
            "Unsupported or non-POSIX ciphertext envelope; refusing to double-encrypt".to_owned(),
        );
    }
    Ok((trimmed.to_owned(), true))
}

/// RFC 8439 `ChaCha20-Poly1305` authenticated encryption binding `key`, 96-bit `nonce`, `VAULT_AEAD_AAD`, and `plaintext`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn aead_seal_v2(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<String, String> {
    let cipher = <ChaCha20Poly1305 as KeyInit>::new(Key::from_slice(key));
    let ciphertext_and_tag = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: VAULT_AEAD_AAD,
            },
        )
        .map_err(|_| "ChaCha20-Poly1305 AEAD encryption failed".to_owned())?;
    let mut wire = Vec::with_capacity(12 + ciphertext_and_tag.len());
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ciphertext_and_tag);
    Ok(format!("{VAULT_V2_PREFIX}{}", base64_encode(&wire)))
}

/// RFC 8439 `ChaCha20-Poly1305` authenticated decryption; rejects any bit flip in `nonce`, `ciphertext`, `AAD`, or 128-bit `Poly1305` tag.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn aead_open_v2(key: &[u8; 32], b64_wire: &str) -> Result<String, String> {
    let blob =
        base64_decode(b64_wire).ok_or_else(|| "invalid base64 in vault:v2 secret".to_owned())?;
    if blob.len() < 12 + 16 {
        return Err("truncated vault:v2 AEAD payload".to_owned());
    }
    let (nonce_bytes, ct_and_tag) = blob.split_at(12);
    let cipher = <ChaCha20Poly1305 as KeyInit>::new(Key::from_slice(key));
    let mut plain_bytes = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ct_and_tag,
                aad: VAULT_AEAD_AAD,
            },
        )
        .map_err(|_| {
            "ChaCha20-Poly1305 AEAD authentication failed (tampered nonce, ciphertext, or tag)"
                .to_owned()
        })?;
    let out = String::from_utf8_lossy(&plain_bytes).into_owned();
    secure_zero(&mut plain_bytes);
    Ok(out)
}

/// Read-only legacy `vault:v1:` decoder used strictly to migrate existing v0.8.7/v0.8.8 POSIX secrets
/// to RFC 8439 `ChaCha20-Poly1305` (`vault:v2:`). Never used for encryption.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn legacy_v1_open_for_migration(key: &[u8; 32], b64_wire: &str) -> Result<String, String> {
    let blob = base64_decode(b64_wire)
        .ok_or_else(|| "invalid base64 in legacy vault:v1 secret".to_owned())?;
    if blob.len() < 32 {
        return Err("truncated legacy vault:v1 secret".to_owned());
    }
    let nonce = &blob[0..16];
    let expected_tag = hex_encode(&blob[16..32]);
    let masked = &blob[32..];
    let actual_tag = legacy_v1_mac_hex(key, masked);
    if !constant_time_eq(expected_tag.as_bytes(), &actual_tag.as_bytes()[..32]) {
        return Err("legacy vault:v1 authentication tag mismatch".to_owned());
    }
    let mut plain_bytes = Vec::with_capacity(masked.len());
    let mut block_idx = 0u64;
    let mut stream_pos = 0usize;
    let mut block = [0u8; 32];
    while stream_pos < masked.len() {
        let mut seed = Vec::with_capacity(56);
        seed.extend_from_slice(key);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(&block_idx.to_le_bytes());
        let hex = legacy_v1_mac_hex(key, &seed);
        secure_zero(&mut seed);
        if let Some(mut b) = hex_decode(&hex) {
            block.copy_from_slice(&b[..32]);
            secure_zero(&mut b);
        }
        let take = (masked.len() - stream_pos).min(32);
        for j in 0..take {
            plain_bytes.push(masked[stream_pos + j] ^ block[j]);
        }
        stream_pos += take;
        block_idx += 1;
    }
    secure_zero(&mut block);
    let out = String::from_utf8_lossy(&plain_bytes).into_owned();
    secure_zero(&mut plain_bytes);
    Ok(out)
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn legacy_v1_mac_hex(secret: &[u8; 32], message: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for lane in 0..4u8 {
        let mut buf = Vec::with_capacity(64 + message.len());
        buf.push(0xA5 ^ lane);
        buf.extend_from_slice(secret);
        buf.extend_from_slice(message);
        buf.extend_from_slice(&secret[(lane as usize * 8)..((lane as usize + 1) * 8)]);
        let h1 = hash_key(200 + lane, &buf);
        buf.extend_from_slice(&h1.to_le_bytes());
        buf.extend_from_slice(secret);
        let h2 = hash_key(220 + lane, &buf);
        secure_zero(&mut buf);
        let mixed = h1.rotate_left(17) ^ h2.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        out.push_str(&format!("{mixed:016x}"));
    }
    out
}

/// Loads comma/newline-separated dynamic configuration values from `global_db` and optional `proj_db`.

pub(super) fn decode_and_maybe_upgrade_trust_anchor_record(
    global_db: &LibreDb,
    rec: &libredb_core::NodeRecord,
) -> Result<[u8; 32], String> {
    let raw = String::from_utf8_lossy(&rec.payload).into_owned();
    let (mut hex_str, needs_upgrade) = unprotect_secret(&raw)?;
    let decoded = hex_decode(hex_str.trim());
    if let Some(mut bytes) = decoded {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            secure_zero(&mut bytes);
            if needs_upgrade {
                if let Ok(enc) = protect_secret(hex_str.trim()) {
                    let expected_id = rec.node_id;
                    let expected_gen = rec.generation;
                    let _ = global_db.transact_key(NodeKind::Config, TRUST_SECRET_KEY, |cur| {
                        match cur {
                            Some(cur_rec)
                                if cur_rec.node_id == expected_id
                                    && cur_rec.generation == expected_gen =>
                            {
                                Ok(Some(
                                    WriteRequest::new(NodeKind::Config, enc.into_bytes())
                                        .with_key(TRUST_SECRET_KEY)
                                        .with_importance(240),
                                ))
                            }
                            _ => Ok(None),
                        }
                    });
                }
            }
            secure_zero(unsafe { hex_str.as_bytes_mut() });
            return Ok(arr);
        }
        secure_zero(&mut bytes);
    }
    secure_zero(unsafe { hex_str.as_bytes_mut() });
    Err(
        "Existing sys::trust_anchor_secret is invalid (expected 32-byte hex); refusing to overwrite"
            .to_owned(),
    )
}

pub(super) fn ensure_trust_anchor_secret(global_db: &LibreDb) -> Result<[u8; 32], String> {
    check_global_trust_sync(global_db)?;
    match global_db.get_by_key(NodeKind::Config, TRUST_SECRET_KEY) {
        Ok(rec) => return decode_and_maybe_upgrade_trust_anchor_record(global_db, &rec),
        Err(LibreDbError::KeyNotFound { .. }) => {}
        Err(e) => {
            return Err(format!(
                "Failed to read existing sys::trust_anchor_secret from customizations.ldb (refusing to overwrite): {e}"
            ));
        }
    }

    let mut candidate_secret = [0u8; 32];
    fill_csprng(&mut candidate_secret)?;
    let mut hex_secret = hex_encode(&candidate_secret);
    let protected_res = protect_secret(&hex_secret);
    secure_zero(unsafe { hex_secret.as_bytes_mut() });
    let protected = match protected_res {
        Ok(p) => p,
        Err(e) => {
            secure_zero(&mut candidate_secret);
            return Err(e);
        }
    };

    match global_db.put_if_absent(
        WriteRequest::new(NodeKind::Config, protected.into_bytes())
            .with_key(TRUST_SECRET_KEY)
            .with_importance(240),
    ) {
        Ok((_rec, true)) => Ok(candidate_secret),
        Ok((winner_rec, false)) => {
            secure_zero(&mut candidate_secret);
            decode_and_maybe_upgrade_trust_anchor_record(global_db, &winner_rec)
        }
        Err(e) => {
            secure_zero(&mut candidate_secret);
            Err(format!(
                "Failed to persist sys::trust_anchor_secret in customizations.ldb: {e}"
            ))
        }
    }
}


pub(super) fn fill_csprng(dest: &mut [u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        win_dpapi::csprng_fill(dest)
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
        f.read_exact(dest).map_err(|e| e.to_string())
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn read_existing_posix_vault_key(key_path: &Path, meta: &fs::Metadata) -> Result<[u8; 32], String> {
    if meta.file_type().is_symlink() {
        return Err("Refusing to use symlinked POSIX vault keyfile (.vault.key)".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o077) != 0 {
            let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
        }
    }
    let mut raw = fs::read(key_path).map_err(|e| {
        format!("Failed to read existing POSIX .vault.key (refusing to overwrite): {e}")
    })?;
    if raw.len() != 32 {
        let bad_len = raw.len();
        secure_zero(&mut raw);
        return Err(format!(
            "Existing POSIX .vault.key has invalid length {bad_len} bytes (expected 32); refusing to overwrite"
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    secure_zero(&mut raw);
    Ok(arr)
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) struct PosixVaultInitLock {
    backend: OsFileBackend,
}

#[cfg_attr(windows, allow(dead_code))]
impl PosixVaultInitLock {
    fn acquire(lock_path: &Path) -> Result<Self, String> {
        if let Ok(meta) = fs::symlink_metadata(lock_path) {
            if meta.file_type().is_symlink() {
                return Err(
                    "Refusing to use symlinked POSIX vault lockfile (.vault.key.lock)".to_owned(),
                );
            }
        }
        let backend = OsFileBackend::open(lock_path)
            .map_err(|e| format!("Failed to open POSIX .vault.key.lock: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600));
        }
        backend
            .lock_write_region()
            .map_err(|e| format!("Failed to acquire POSIX .vault.key.lock: {e}"))?;
        Ok(Self { backend })
    }
}

impl Drop for PosixVaultInitLock {
    fn drop(&mut self) {
        let _ = self.backend.unlock_write_region();
    }
}

/// Kernel-atomic non-overwriting same-directory rename (`RENAME_NOREPLACE` on Linux,
/// `RENAME_EXCL` on macOS, `MoveFileExW(..., 0)` without `MOVEFILE_REPLACE_EXISTING` on Windows).
/// Returns `ErrorKind::AlreadyExists` if `dst` already exists, and NEVER falls back to an
/// overwriting `rename(2)` if the kernel or filesystem rejects the non-replace flag.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn atomic_rename_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        const AT_FDCWD: i32 = -100;
        const RENAME_NOREPLACE: u32 = 1;
        extern "C" {
            fn renameat2(
                olddirfd: i32,
                oldpath: *const core::ffi::c_char,
                newdirfd: i32,
                newpath: *const core::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        let src_c = CString::new(src.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior NUL in src path")
        })?;
        let dst_c = CString::new(dst.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior NUL in dst path")
        })?;
        let rc = unsafe {
            renameat2(
                AT_FDCWD,
                src_c.as_ptr(),
                AT_FDCWD,
                dst_c.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        const RENAME_EXCL: u32 = 0x0000_0004;
        extern "C" {
            fn renamex_np(
                from: *const core::ffi::c_char,
                to: *const core::ffi::c_char,
                flags: u32,
            ) -> i32;
        }
        let src_c = CString::new(src.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior NUL in src path")
        })?;
        let dst_c = CString::new(dst.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior NUL in dst path")
        })?;
        let rc = unsafe { renamex_np(src_c.as_ptr(), dst_c.as_ptr(), RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(
                lpExistingFileName: *const u16,
                lpNewFileName: *const u16,
                dwFlags: u32,
            ) -> i32;
        }
        let src_w: Vec<u16> = src
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let dst_w: Vec<u16> = dst
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        // `dwFlags = 0` omits `MOVEFILE_REPLACE_EXISTING` (`0x1`), guaranteeing an atomic
        // non-overwriting publish (`ERROR_ALREADY_EXISTS` / `ERROR_FILE_EXISTS` -> `AlreadyExists`).
        let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), 0) };
        if ok != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (src, dst);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "non-overwriting atomic rename is unsupported on this OS",
        ))
    }
}

/// Loads an existing 32-byte `.vault.key` from `dir`, or initializes a new `0600` keyfile
/// atomically when missing and `create_if_missing == true`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn load_or_create_posix_vault_key_at(
    dir: &Path,
    create_if_missing: bool,
) -> Result<[u8; 32], String> {
    load_or_create_posix_vault_key_inner(dir, create_if_missing, false)
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn load_or_create_posix_vault_key_inner(
    dir: &Path,
    create_if_missing: bool,
    force_no_hardlink: bool,
) -> Result<[u8; 32], String> {
    load_or_create_posix_vault_key_inner_with_hook(dir, create_if_missing, force_no_hardlink, None)
}

/// Internal synchronized `.vault.key` loader/initializer:
/// - Fast path reads an existing `.vault.key` with zero lock contention.
/// - Slow initialization path acquires BOTH an intra-process `Mutex` AND a cross-process OS lock
///   on `.vault.key.lock`, re-checks `.vault.key` inside the lock, writes + `sync_all()`-flushes
///   all `32` bytes into a unique `0600` sibling `.vault.key.init.<pid>.<nonce>` staging file, and
///   publishes it atomically via `fs::hard_link` (or via kernel-atomic non-overwriting
///   `atomic_rename_noreplace` when hard links are unsupported, failing closed if unsupported).
/// - `.vault.key` is NEVER created empty, written in-place, or published via overwriting `rename(2)`,
///   so concurrent readers can never observe `< 32` bytes and even an uncooperative external process
///   creating `.vault.key` without `.vault.key.lock` can never have its file overwritten.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn load_or_create_posix_vault_key_inner_with_hook(
    dir: &Path,
    create_if_missing: bool,
    force_no_hardlink: bool,
    pre_rename_hook: Option<&dyn Fn(&Path)>,
) -> Result<[u8; 32], String> {
    static VAULT_KEY_INIT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let dir_meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if dir_meta.file_type().is_symlink() {
        return Err("Refusing to use symlinked vault directory".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }

    let key_path = dir.join(".vault.key");
    match fs::symlink_metadata(&key_path) {
        Ok(meta) => return read_existing_posix_vault_key(&key_path, &meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create_if_missing {
                return Err(
                    "POSIX .vault.key does not exist; cannot decrypt existing vault secret"
                        .to_owned(),
                );
            }
        }
        Err(e) => {
            return Err(format!(
                "Cannot inspect POSIX .vault.key metadata (refusing to overwrite): {e}"
            ));
        }
    }

    let _proc_guard = VAULT_KEY_INIT_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let lock_path = dir.join(".vault.key.lock");
    let _ipc_guard = PosixVaultInitLock::acquire(&lock_path)?;

    // Double-check inside the dual intra-process + cross-process lock before generating a new key:
    match fs::symlink_metadata(&key_path) {
        Ok(meta) => return read_existing_posix_vault_key(&key_path, &meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "Cannot inspect POSIX .vault.key metadata inside lock (refusing to overwrite): {e}"
            ));
        }
    }

    let mut key = [0u8; 32];
    fill_csprng(&mut key)?;
    let mut rand_tag = [0u8; 8];
    if let Err(rng_err) = fill_csprng(&mut rand_tag) {
        secure_zero(&mut key);
        return Err(rng_err);
    }
    let tmp_path = dir.join(format!(
        ".vault.key.init.{}.{:016x}",
        std::process::id(),
        u64::from_le_bytes(rand_tag)
    ));

    let mut tmp_opts = fs::OpenOptions::new();
    tmp_opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        tmp_opts.mode(0o600);
    }

    let mut tmp_file = match tmp_opts.open(&tmp_path) {
        Ok(f) => f,
        Err(open_err) => {
            secure_zero(&mut key);
            return Err(format!(
                "Failed to create staging keyfile '{}': {open_err}",
                tmp_path.display()
            ));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp_file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    {
        use std::io::Write;
        if let Err(w_err) = tmp_file.write_all(&key).and_then(|()| tmp_file.sync_all()) {
            drop(tmp_file);
            let _ = fs::remove_file(&tmp_path);
            secure_zero(&mut key);
            return Err(format!(
                "Failed to write and sync 32-byte staging keyfile: {w_err}"
            ));
        }
    }
    drop(tmp_file);

    if !force_no_hardlink {
        match fs::hard_link(&tmp_path, &key_path) {
            Ok(()) => {
                let _ = fs::remove_file(&tmp_path);
                #[cfg(unix)]
                if let Ok(df) = fs::File::open(dir) {
                    let _ = df.sync_all();
                }
                return Ok(key);
            }
            Err(link_err) if link_err.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&tmp_path);
                secure_zero(&mut key);
                let meta = fs::symlink_metadata(&key_path).map_err(|e| {
                    format!("Cannot inspect POSIX .vault.key metadata after concurrent link: {e}")
                })?;
                return read_existing_posix_vault_key(&key_path, &meta);
            }
            Err(_) => {
                // Hard links unsupported on this filesystem: fall through to kernel-atomic
                // non-overwriting rename (`atomic_rename_noreplace`) while still holding both locks.
            }
        }
    }

    match fs::symlink_metadata(&key_path) {
        Ok(meta) => {
            let _ = fs::remove_file(&tmp_path);
            secure_zero(&mut key);
            return read_existing_posix_vault_key(&key_path, &meta);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            secure_zero(&mut key);
            return Err(format!(
                "Cannot inspect POSIX .vault.key metadata before fallback rename: {e}"
            ));
        }
    }

    if let Some(hook) = pre_rename_hook {
        hook(&key_path);
    }

    match atomic_rename_noreplace(&tmp_path, &key_path) {
        Ok(()) => {
            #[cfg(unix)]
            if let Ok(df) = fs::File::open(dir) {
                let _ = df.sync_all();
            }
            Ok(key)
        }
        Err(ren_err) if ren_err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp_path);
            secure_zero(&mut key);
            let meta = fs::symlink_metadata(&key_path).map_err(|e| {
                format!(
                    "Cannot inspect POSIX .vault.key metadata after non-overwriting rename race: {e}"
                )
            })?;
            read_existing_posix_vault_key(&key_path, &meta)
        }
        Err(ren_err) => {
            let _ = fs::remove_file(&tmp_path);
            secure_zero(&mut key);
            Err(format!(
                "Refusing non-atomic or overwriting POSIX .vault.key fallback publish (hard_link and non-overwriting atomic rename failed): {ren_err}"
            ))
        }
    }
}


#[cfg(windows)]
mod win_dpapi {
    use core::ffi::c_void;
    use std::ptr;

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x0000_0001;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(random_buffer: *mut u8, random_buffer_length: u32) -> u8;
    }

    const ENTROPY_LABEL: &[u8] = b"LibreDB::CredentialVault::v1";

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        let in_blob = DataBlob {
            cb_data: plain.len() as u32,
            pb_data: plain.as_ptr() as *mut u8,
        };
        let ent_blob = DataBlob {
            cb_data: ENTROPY_LABEL.len() as u32,
            pb_data: ENTROPY_LABEL.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                &ent_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pb_data.is_null() {
            return Err(format!(
                "Windows DPAPI CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let out = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(out)
    }

    pub fn unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
        let in_blob = DataBlob {
            cb_data: cipher.len() as u32,
            pb_data: cipher.as_ptr() as *mut u8,
        };
        let ent_blob = DataBlob {
            cb_data: ENTROPY_LABEL.len() as u32,
            pb_data: ENTROPY_LABEL.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                &ent_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pb_data.is_null() {
            return Err(format!(
                "Windows DPAPI CryptUnprotectData failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let len = out_blob.cb_data as usize;
        let out = unsafe { std::slice::from_raw_parts(out_blob.pb_data, len).to_vec() };
        unsafe {
            for i in 0..len {
                core::ptr::write_volatile(out_blob.pb_data.add(i), 0);
            }
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(out)
    }

    pub fn csprng_fill(dest: &mut [u8]) -> Result<(), String> {
        let ok = unsafe { SystemFunction036(dest.as_mut_ptr(), dest.len() as u32) };
        if ok != 0 {
            Ok(())
        } else {
            Err("RtlGenRandom (SystemFunction036) failed".to_owned())
        }
    }
}

