//! Native `PyO3` (`abi3-py312` stable ABI) Python extension (`import libredb`) for Python 3.12+.

use libredb_bridge::{export_sqlite_database, import_sqlite_readonly, verify_sqlite_equivalence};
use libredb_cognitive::{
    create_subagent_handoff, execute_atomic_batch, extract_fim_slice, index_workspace,
    query_symbol_impact, sync_transcript_epoch, AtomicBatchSpec, CognitiveEngine, FileSkeleton,
    OverlayBrain, PulseRequest, ReflexEngine, ReflexRule,
};
use libredb_core::{EdgeKind, LibreDb, NodeKind, WriteRequest};
use parking_lot::Mutex;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Native Rust-backed cognitive database handle for Python (`libredb.Brain`).
#[pyclass(name = "Brain")]
pub struct PyBrain {
    project_db: Arc<LibreDb>,
    global_db: Option<Arc<LibreDb>>,
    cached_brain: Mutex<Option<OverlayBrain>>,
}

#[pymethods]
impl PyBrain {
    #[new]
    #[pyo3(signature = (path, global_path=None))]
    pub fn new(path: &str, global_path: Option<&str>) -> PyResult<Self> {
        let project_db = Arc::new(LibreDb::open(path).map_err(to_py_err)?);
        let global_db = match global_path {
            Some(gp) => Some(Arc::new(LibreDb::open(gp).map_err(to_py_err)?)),
            None => None,
        };
        Ok(Self {
            project_db,
            global_db,
            cached_brain: Mutex::new(None),
        })
    }

    /// Stores a typed cognitive capsule (`Supersedes` prior key automatically if `key` is set).
    #[pyo3(signature = (kind, payload, key=None, importance=128, pinned=false))]
    pub fn put(
        &self,
        kind: &str,
        payload: &str,
        key: Option<&str>,
        importance: u8,
        pinned: bool,
    ) -> PyResult<u64> {
        let nk = NodeKind::parse(kind)
            .ok_or_else(|| PyValueError::new_err(format!("Unknown node kind '{kind}'")))?;
        let mut req = WriteRequest::new(nk, payload.as_bytes().to_vec())
            .with_importance(importance)
            .with_pinned(pinned);
        if let Some(k) = key {
            req = req.with_key(k);
        }
        self.project_db.put(req).map_err(to_py_err)
    }

    /// Reads a capsule by immutable `NodeId` and returns a JSON string of `NodeRecord`.
    pub fn get_json(&self, node_id: u64) -> PyResult<String> {
        let rec = self.project_db.get(node_id).map_err(to_py_err)?;
        serde_json::to_string(&rec).map_err(to_py_err)
    }

    /// Reads the active version of `(kind, key)` and returns its UTF-8 text payload.
    pub fn get_key_text(&self, kind: &str, key: &str) -> PyResult<String> {
        let nk = NodeKind::parse(kind)
            .ok_or_else(|| PyValueError::new_err(format!("Unknown node kind '{kind}'")))?;
        let rec = self.project_db.get_by_key(nk, key).map_err(to_py_err)?;
        Ok(String::from_utf8_lossy(&rec.payload).into_owned())
    }

    /// Wires a directed synapse `src_id --[edge_kind]--> dst_id`.
    #[pyo3(signature = (src_id, edge_kind, dst_id, weight=200))]
    pub fn link(&self, src_id: u64, edge_kind: &str, dst_id: u64, weight: u8) -> PyResult<()> {
        let ek = EdgeKind::parse(edge_kind)
            .ok_or_else(|| PyValueError::new_err(format!("Unknown edge kind '{edge_kind}'")))?;
        self.project_db
            .link(src_id, ek, dst_id, weight)
            .map_err(to_py_err)
    }

    /// Executes a dual-layer (`global` + `project`), session-deduplicated `pulse` in microseconds.
    #[pyo3(signature = (query, budget=800, cid=None, epoch=1, transcript_path=None, cwd=None, error=None, as_json=false))]
    #[allow(clippy::too_many_arguments)]
    pub fn pulse(
        &self,
        query: &str,
        budget: u32,
        cid: Option<&str>,
        epoch: u32,
        transcript_path: Option<&str>,
        cwd: Option<&str>,
        error: Option<&str>,
        as_json: bool,
    ) -> PyResult<String> {
        let mut req = PulseRequest::new(query, budget);
        req.epoch = epoch;
        if let Some(c) = cid {
            req.conversation_id = Some(c.to_owned());
            if let Some(tp) = transcript_path {
                req.epoch =
                    sync_transcript_epoch(&self.project_db, c, Path::new(tp)).map_err(to_py_err)?;
            }
        }
        if let Some(d) = cwd {
            req.workspace_dir = Some(PathBuf::from(d));
        }
        if let Some(e) = error {
            req.error_context = Some(e.to_owned());
        }

        let mut guard = self.cached_brain.lock();
        if guard.is_none() {
            *guard = Some(
                OverlayBrain::open(self.global_db.clone(), Arc::clone(&self.project_db))
                    .map_err(to_py_err)?,
            );
        } else {
            guard.as_mut().unwrap().refresh_if_needed().map_err(to_py_err)?;
        }
        let resp = guard.as_ref().unwrap().pulse(&req).map_err(to_py_err)?;
        if as_json {
            serde_json::to_string(&resp).map_err(to_py_err)
        } else {
            Ok(resp.format_compact())
        }
    }

    /// Extracts or retrieves a hash-cached `[Lstart-Lend]` symbol contract skeleton.
    #[pyo3(signature = (file_path, filter=None))]
    pub fn skeleton(&self, file_path: &str, filter: Option<&str>) -> PyResult<String> {
        let (skel, _) = FileSkeleton::index_or_get_cached(&self.project_db, Path::new(file_path), None)
            .map_err(to_py_err)?;
        Ok(skel.render_compact(filter, filter.is_some()))
    }

    /// Indexes all non-binary source files under `root_dir` and wires call + governance synapses.
    #[pyo3(signature = (root_dir, force=false))]
    pub fn index_workspace(&self, root_dir: &str, force: bool) -> PyResult<String> {
        let rep = index_workspace(&self.project_db, Path::new(root_dir), force).map_err(to_py_err)?;
        serde_json::to_string(&rep).map_err(to_py_err)
    }

    /// Queries bidirectional symbol blast-radius (`callers`, `callees`) and governing decisions.
    pub fn impact(&self, symbol_query: &str) -> PyResult<String> {
        let rep = query_symbol_impact(&self.project_db, symbol_query).map_err(to_py_err)?;
        serde_json::to_string(&rep).map_err(to_py_err)
    }

    /// Extracts a surgical Fill-in-the-Middle edit window with blast-radius and governing decisions.
    #[pyo3(signature = (file_path, symbol=None, line=None, pad=12))]
    pub fn fim(
        &self,
        file_path: &str,
        symbol: Option<&str>,
        line: Option<usize>,
        pad: usize,
    ) -> PyResult<String> {
        let bundle =
            extract_fim_slice(&self.project_db, Path::new(file_path), symbol, line, pad)
                .map_err(to_py_err)?;
        Ok(bundle.format_compact())
    }

    /// Commits multiple `(key, value)` facts, `(title, body)` decisions, and an optional snapshot atomically.
    #[pyo3(signature = (facts=None, decisions=None, tasks=None, snapshot=None))]
    pub fn batch(
        &self,
        facts: Option<Vec<(String, String)>>,
        decisions: Option<Vec<(String, String)>>,
        tasks: Option<Vec<(String, String, String, String)>>,
        snapshot: Option<String>,
    ) -> PyResult<String> {
        let spec = AtomicBatchSpec {
            facts: facts.unwrap_or_default(),
            decisions: decisions.unwrap_or_default(),
            tasks: tasks.unwrap_or_default(),
            snapshot,
        };
        let rep = execute_atomic_batch(&self.project_db, &spec).map_err(to_py_err)?;
        serde_json::to_string(&rep).map_err(to_py_err)
    }

    /// Builds a deterministic subagent delegation block linked to `task_key`.
    #[pyo3(signature = (handoff_id, task_key, role, instructions=""))]
    pub fn handoff(
        &self,
        handoff_id: &str,
        task_key: &str,
        role: &str,
        instructions: &str,
    ) -> PyResult<String> {
        let (_, block) =
            create_subagent_handoff(&self.project_db, handoff_id, task_key, role, instructions)
                .map_err(to_py_err)?;
        Ok(block)
    }

    /// Learns a persistent language-agnostic Hebbian concept bridge.
    pub fn learn_assoc(&self, cue_phrase: &str, target_ids: Vec<u64>) -> PyResult<usize> {
        let mut cog = CognitiveEngine::open_db(Arc::clone(&self.project_db)).map_err(to_py_err)?;
        let n = cog
            .reinforce_association(cue_phrase, &target_ids)
            .map_err(to_py_err)?;
        cog.save_index_snapshot().map_err(to_py_err)?;
        Ok(n)
    }

    /// Learns a persistent situational pitfall reflex.
    #[pyo3(signature = (reflex_id, directive, stack=None, action=None, env=None))]
    pub fn learn_reflex(
        &self,
        reflex_id: &str,
        directive: &str,
        stack: Option<Vec<String>>,
        action: Option<Vec<String>>,
        env: Option<Vec<String>>,
    ) -> PyResult<u64> {
        let rule = ReflexRule {
            id: reflex_id.to_owned(),
            stack_any: stack.unwrap_or_default(),
            action_any: action.unwrap_or_default(),
            env_or_error_any: env.unwrap_or_default(),
            directive: directive.to_owned(),
        };
        ReflexEngine::learn_reflex(&self.project_db, &rule).map_err(to_py_err)
    }

    /// Imports an existing SQLite database (`central` or `project`) strictly read-only and saves an index snapshot.
    #[pyo3(signature = (sqlite_path, scope="central"))]
    pub fn import_sqlite(&self, sqlite_path: &str, scope: &str) -> PyResult<String> {
        let sum =
            import_sqlite_readonly(Path::new(sqlite_path), &self.project_db, scope).map_err(to_py_err)?;
        let mut cog = CognitiveEngine::open_db(Arc::clone(&self.project_db)).map_err(to_py_err)?;
        cog.save_index_snapshot().map_err(to_py_err)?;
        serde_json::to_string(&sum).map_err(to_py_err)
    }

    /// Exports the lossless SQLite mirror back to `out_sqlite_path`.
    #[pyo3(signature = (out_sqlite_path, scope="central"))]
    pub fn export_sqlite(&self, out_sqlite_path: &str, scope: &str) -> PyResult<usize> {
        export_sqlite_database(&self.project_db, scope, Path::new(out_sqlite_path))
            .map_err(to_py_err)
    }

    /// Runs Gravity locality compaction, refreshes the persistent index snapshot, and verifies CRC integrity.
    pub fn compact(&self) -> PyResult<String> {
        let mut cog = CognitiveEngine::open_db(Arc::clone(&self.project_db)).map_err(to_py_err)?;
        cog.save_index_snapshot().map_err(to_py_err)?;
        let rep = self.project_db.compact_with_gravity().map_err(to_py_err)?;
        serde_json::to_string(&rep).map_err(to_py_err)
    }

    /// Returns JSON database statistics.
    pub fn stats_json(&self) -> PyResult<String> {
        let st = self.project_db.stats().map_err(to_py_err)?;
        serde_json::to_string(&st).map_err(to_py_err)
    }
}

/// Verifies lossless `SQLite -> LibreDB -> SQLite` parity on a temporary copy of `sqlite_path`.
#[pyfunction]
#[pyo3(signature = (sqlite_path, scope="central"))]
pub fn verify_sqlite_roundtrip_json(sqlite_path: &str, scope: &str) -> PyResult<String> {
    let pid = std::process::id();
    let tmp_dir = std::env::temp_dir().join(format!("libredb_py_rt_{pid}"));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).map_err(to_py_err)?;

    let copy_src = tmp_dir.join("src.db");
    let ldb_file = tmp_dir.join("mid.ldb");
    let recon_db = tmp_dir.join("recon.db");
    std::fs::copy(sqlite_path, &copy_src).map_err(to_py_err)?;

    {
        let ldb = LibreDb::open(&ldb_file).map_err(to_py_err)?;
        import_sqlite_readonly(&copy_src, &ldb, scope).map_err(to_py_err)?;
        ldb.compact_with_gravity().map_err(to_py_err)?;
        export_sqlite_database(&ldb, scope, &recon_db).map_err(to_py_err)?;
    }
    let rep = verify_sqlite_equivalence(&copy_src, &recon_db).map_err(to_py_err)?;
    let _ = std::fs::remove_dir_all(&tmp_dir);
    serde_json::to_string(&rep).map_err(to_py_err)
}

#[pymodule(name = "libredb")]
fn libredb_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyBrain>()?;
    m.add_function(wrap_pyfunction!(verify_sqlite_roundtrip_json, m)?)?;
    Ok(())
}
