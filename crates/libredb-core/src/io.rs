//! Cross-platform random-offset storage backend and deterministic power-loss fault simulator.

use crate::error::{LibreDbError, Result};
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Abstract block/extent I/O backend supporting lock-free concurrent offset reads.
pub trait StorageBackend: Send + Sync {
    /// Reads exact `buf.len()` bytes starting at `offset` without mutating any shared file cursor.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Writes all bytes of `buf` starting at `offset`.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Flushes dirty OS buffers stably to persistent storage (`fsync` / `FlushFileBuffers`).
    fn sync_data(&self) -> Result<()>;

    /// Truncates or extends the underlying storage to `len` bytes.
    fn set_len(&self, len: u64) -> Result<()>;

    /// Returns the current physical byte length of the underlying storage.
    fn len(&self) -> Result<u64>;

    /// Returns true if the storage has zero bytes.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Returns cumulative `read_at` calls issued against this backend (for telemetry and tests).
    fn read_ops_count(&self) -> u64;

    /// Returns cumulative `write_at` calls issued against this backend.
    fn write_ops_count(&self) -> u64;

    /// Returns true if the backing path resides on a remote UNC / SMB network share.
    fn is_network_share(&self) -> bool {
        false
    }
}

/// Production OS file backend using overlap/positional reads (`seek_read` on Windows, `read_at` on Unix).
pub struct OsFileBackend {
    file: File,
    path: PathBuf,
    is_network: bool,
    read_ops: AtomicU64,
    write_ops: AtomicU64,
}

impl OsFileBackend {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let is_network = detect_network_path(&path_buf);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path_buf)?;

        Ok(Self {
            file,
            path: path_buf,
            is_network,
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Detects UNC paths (`\\server\share` or `\\?\UNC\...`) to apply SMB-safe sync semantics.
pub fn detect_network_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    raw.starts_with("\\\\")
}

impl StorageBackend for OsFileBackend {
    fn read_at(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        while !buf.is_empty() {
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(&self.file, buf, offset)?;
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::read_at(&self.file, buf, offset)?;

            if n == 0 {
                return Err(LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF during positional read_at",
                )));
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    }

    fn write_at(&self, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        self.write_ops.fetch_add(1, Ordering::Relaxed);
        while !buf.is_empty() {
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_write(&self.file, buf, offset)?;
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::write_at(&self.file, buf, offset)?;

            if n == 0 {
                return Err(LibreDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write_at wrote 0 bytes",
                )));
            }
            offset += n as u64;
            buf = &buf[n..];
        }
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        if self.is_network {
            self.file.sync_all()?;
        } else {
            self.file.sync_data()?;
        }
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        self.file.set_len(len)?;
        Ok(())
    }

    fn len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn read_ops_count(&self) -> u64 {
        self.read_ops.load(Ordering::Relaxed)
    }

    fn write_ops_count(&self) -> u64 {
        self.write_ops.load(Ordering::Relaxed)
    }

    fn is_network_share(&self) -> bool {
        self.is_network
    }
}

/// Deterministic in-memory storage backend with power-loss and torn-sector fault injection.
///
/// Models both persistent disk platters (`synced`) and volatile OS page cache (`working`),
/// allowing tests to cut power mid-write with partial torn bytes and discard unsynced buffers.
pub struct FaultInjectingBackend {
    state: Mutex<SimDiskState>,
    read_ops: AtomicU64,
    write_ops: AtomicU64,
}

#[derive(Clone)]
struct SimDiskState {
    /// Volatile OS buffer view seen before power loss.
    working: Vec<u8>,
    /// Durable platter image updated only on `sync_data()`.
    synced: Vec<u8>,
    /// Optional countdown of `write_at` operations until simulated power loss triggers.
    fault_countdown: Option<u64>,
    /// Number of leading bytes of the failing write that hit the platter before power dies.
    torn_prefix_bytes: usize,
    /// True once power has been lost (rejects all subsequent I/O until reboot).
    crashed: bool,
}

impl FaultInjectingBackend {
    pub fn new() -> Self {
        Self::from_durable_image(Vec::new())
    }

    pub fn from_durable_image(image: Vec<u8>) -> Self {
        Self {
            state: Mutex::new(SimDiskState {
                working: image.clone(),
                synced: image,
                fault_countdown: None,
                torn_prefix_bytes: 0,
                crashed: false,
            }),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
        }
    }

    /// Arms a deterministic power failure on the `writes_until_crash`-th `write_at` call (`0` = next write),
    /// persisting only `torn_prefix_bytes` of that final write onto the durable platter and discarding
    /// any prior unsynced OS cache pages.
    pub fn arm_power_loss(&self, writes_until_crash: u64, torn_prefix_bytes: usize) {
        let mut st = self.state.lock();
        st.fault_countdown = Some(writes_until_crash);
        st.torn_prefix_bytes = torn_prefix_bytes;
        st.crashed = false;
    }

    /// Disarms fault injection for clean operations.
    pub fn disarm(&self) {
        let mut st = self.state.lock();
        st.fault_countdown = None;
        st.crashed = false;
    }

    /// Extracts the durable post-power-loss disk image (`synced` bytes + any torn prefix) to simulate reboot.
    pub fn durable_crash_image(&self) -> Vec<u8> {
        self.state.lock().synced.clone()
    }
}

impl Default for FaultInjectingBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for FaultInjectingBackend {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        let st = self.state.lock();
        if st.crashed {
            return Err(LibreDbError::SimulatedPowerLoss(self.write_ops_count()));
        }
        let start = offset as usize;
        let end = start.saturating_add(buf.len());
        if end > st.working.len() {
            return Err(LibreDbError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "simulated read past EOF",
            )));
        }
        buf.copy_from_slice(&st.working[start..end]);
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let write_num = self.write_ops.fetch_add(1, Ordering::Relaxed) + 1;
        let mut st = self.state.lock();
        if st.crashed {
            return Err(LibreDbError::SimulatedPowerLoss(write_num));
        }

        if let Some(rem) = st.fault_countdown {
            if rem == 0 {
                // Power dies right inside this write!
                // Only `torn_prefix_bytes` leak directly onto the durable platter; unsynced cache vanishes.
                let torn = st.torn_prefix_bytes.min(buf.len());
                if torn > 0 {
                    let start = offset as usize;
                    let end = start + torn;
                    if end > st.synced.len() {
                        st.synced.resize(end, 0);
                    }
                    st.synced[start..end].copy_from_slice(&buf[..torn]);
                }
                st.crashed = true;
                st.fault_countdown = None;
                return Err(LibreDbError::SimulatedPowerLoss(write_num));
            }
            st.fault_countdown = Some(rem - 1);
        }

        let start = offset as usize;
        let end = start + buf.len();
        if end > st.working.len() {
            st.working.resize(end, 0);
        }
        st.working[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        let mut st = self.state.lock();
        if st.crashed {
            return Err(LibreDbError::SimulatedPowerLoss(self.write_ops_count()));
        }
        let working_clone = st.working.clone();
        st.synced = working_clone;
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        let mut st = self.state.lock();
        if st.crashed {
            return Err(LibreDbError::SimulatedPowerLoss(self.write_ops_count()));
        }
        st.working.resize(len as usize, 0);
        Ok(())
    }

    fn len(&self) -> Result<u64> {
        let st = self.state.lock();
        Ok(st.working.len() as u64)
    }

    fn read_ops_count(&self) -> u64 {
        self.read_ops.load(Ordering::Relaxed)
    }

    fn write_ops_count(&self) -> u64 {
        self.write_ops.load(Ordering::Relaxed)
    }
}
