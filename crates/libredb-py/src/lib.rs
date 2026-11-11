//! Native `PyO3` (`abi3-py312` stable ABI) Python extension (`import libredb`) for Python 3.12+.

use libredb_bridge::{
    export_sqlite_database, import_sqlite_readonly, open_or_auto_migrate, verify_sqlite_equivalence,
};
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
        let (project_db, mig_proj) =
            open_or_auto_migrate(Path::new(path), None, "project").map_err(to_py_err)?;
        if mig_proj.is_some() {
            if let Ok(mut cog) = CognitiveEngine::open_db(Arc::clone(&project_db)) {
                let _ = cog.save_index_snapshot();
            }
        }
        let global_db = match global_path {
            Some(gp) => {
                let (gdb, mig_glob) =
                    open_or_auto_migrate(Path::new(gp), None, "central").map_err(to_py_err)?;
                if mig_glob.is_some() {
                    if let Ok(mut cog) = CognitiveEngine::open_db(Arc::clone(&gdb)) {
                        let _ = cog.save_index_snapshot();
                    }
                }
                Some(gdb)
            }
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
        py: Python<'_>,
        query: &str,
        budget: u32,
        cid: Option<&str>,
        epoch: u32,
        transcript_path: Option<&str>,
        cwd: Option<&str>,
        error: Option<&str>,
        as_json: bool,
    ) -> PyResult<String> {
        let query_owned = query.to_owned();
        let cid_owned = cid.map(ToOwned::to_owned);
        let tp_owned = transcript_path.map(PathBuf::from);
        let cwd_owned = cwd.map(PathBuf::from);
        let err_owned = error.map(ToOwned::to_owned);
        py.allow_threads(|| {
            let mut req = PulseRequest::new(&query_owned, budget);
            req.epoch = epoch;
            if let Some(c) = cid_owned {
                if let Some(ref tp) = tp_owned {
                    req.epoch =
                        sync_transcript_epoch(&self.project_db, &c, tp).map_err(to_py_err)?;
                }
                req.conversation_id = Some(c);
            }
            if let Some(d) = cwd_owned {
                req.workspace_dir = Some(d);
            }
            if let Some(e) = err_owned {
                req.error_context = Some(e);
            }

            let mut guard = self.cached_brain.lock();
            if guard.is_none() {
                *guard = Some(
                    OverlayBrain::open(self.global_db.clone(), Arc::clone(&self.project_db))
                        .map_err(to_py_err)?,
                );
            } else {
                guard
                    .as_mut()
                    .unwrap()
                    .refresh_if_needed()
                    .map_err(to_py_err)?;
            }
            let resp = guard.as_ref().unwrap().pulse(&req).map_err(to_py_err)?;
            if as_json {
                serde_json::to_string(&resp).map_err(to_py_err)
            } else {
                Ok(resp.format_compact())
            }
        })
    }

    /// Extracts or retrieves a hash-cached `[Lstart-Lend]` symbol contract skeleton.
    #[pyo3(signature = (file_path, filter=None))]
    pub fn skeleton(
        &self,
        py: Python<'_>,
        file_path: &str,
        filter: Option<&str>,
    ) -> PyResult<String> {
        let fp = PathBuf::from(file_path);
        let flt = filter.map(ToOwned::to_owned);
        py.allow_threads(|| {
            let (skel, _) =
                FileSkeleton::index_or_get_cached(&self.project_db, &fp, None).map_err(to_py_err)?;
            Ok(skel.render_compact(flt.as_deref(), flt.is_some()))
        })
    }

    /// Extracts or retrieves hash-cached skeletons for a batch of files in a single `commit_batch` (`1` `fsync`).
    #[pyo3(signature = (file_paths, filter=None))]
    pub fn skeleton_batch(
        &self,
        py: Python<'_>,
        file_paths: Vec<String>,
        filter: Option<&str>,
    ) -> PyResult<Vec<String>> {
        let flt = filter.map(ToOwned::to_owned);
        py.allow_threads(|| {
            let items: Vec<(&Path, Option<&str>)> = file_paths
                .iter()
                .map(|p| (Path::new(p.as_str()), None))
                .collect();
            let batch =
                FileSkeleton::index_or_get_cached_batch(&self.project_db, &items).map_err(to_py_err)?;
            Ok(batch
                .into_iter()
                .map(|(sk, _)| sk.render_compact(flt.as_deref(), flt.is_some()))
                .collect())
        })
    }

    /// Indexes all non-binary source files under `root_dir` and wires call + governance synapses.
    #[pyo3(signature = (root_dir, force=false))]
    pub fn index_workspace(&self, py: Python<'_>, root_dir: &str, force: bool) -> PyResult<String> {
        let root = PathBuf::from(root_dir);
        py.allow_threads(|| {
            let rep = index_workspace(&self.project_db, &root, force).map_err(to_py_err)?;
            serde_json::to_string(&rep).map_err(to_py_err)
        })
    }

    /// Queries bidirectional symbol blast-radius (`callers`, `callees`) and governing decisions.
    pub fn impact(&self, py: Python<'_>, symbol_query: &str) -> PyResult<String> {
        let q = symbol_query.to_owned();
        py.allow_threads(|| {
            let rep = query_symbol_impact(&self.project_db, &q).map_err(to_py_err)?;
            serde_json::to_string(&rep).map_err(to_py_err)
        })
    }

    /// Extracts a surgical Fill-in-the-Middle edit window with blast-radius and governing decisions.
    #[pyo3(signature = (file_path, symbol=None, line=None, pad=12))]
    pub fn fim(
        &self,
        py: Python<'_>,
        file_path: &str,
        symbol: Option<&str>,
        line: Option<usize>,
        pad: usize,
    ) -> PyResult<String> {
        let fp = PathBuf::from(file_path);
        let sym = symbol.map(ToOwned::to_owned);
        py.allow_threads(|| {
            let bundle =
                extract_fim_slice(&self.project_db, &fp, sym.as_deref(), line, pad)
                    .map_err(to_py_err)?;
            Ok(bundle.format_compact())
        })
    }

    /// Commits multiple `(key, value)` facts, `(title, body)` decisions, and an optional snapshot atomically.
    #[pyo3(signature = (facts=None, decisions=None, tasks=None, snapshot=None))]
    pub fn batch(
        &self,
        py: Python<'_>,
        facts: Option<Vec<(String, String)>>,
        decisions: Option<Vec<(String, String)>>,
        tasks: Option<Vec<(String, String, String, String)>>,
        snapshot: Option<String>,
    ) -> PyResult<String> {
        py.allow_threads(|| {
            let spec = AtomicBatchSpec {
                facts: facts.unwrap_or_default(),
                decisions: decisions.unwrap_or_default(),
                tasks: tasks.unwrap_or_default(),
                snapshot,
            };
            let rep = execute_atomic_batch(&self.project_db, &spec).map_err(to_py_err)?;
            serde_json::to_string(&rep).map_err(to_py_err)
        })
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
    pub fn import_sqlite(&self, py: Python<'_>, sqlite_path: &str, scope: &str) -> PyResult<String> {
        let sp = PathBuf::from(sqlite_path);
        let sc = scope.to_owned();
        py.allow_threads(|| {
            let sum =
                import_sqlite_readonly(&sp, &self.project_db, &sc).map_err(to_py_err)?;
            let mut cog = CognitiveEngine::open_db(Arc::clone(&self.project_db)).map_err(to_py_err)?;
            cog.save_index_snapshot().map_err(to_py_err)?;
            serde_json::to_string(&sum).map_err(to_py_err)
        })
    }

    /// Exports the lossless SQLite mirror back to `out_sqlite_path`.
    #[pyo3(signature = (out_sqlite_path, scope="central"))]
    pub fn export_sqlite(
        &self,
        py: Python<'_>,
        out_sqlite_path: &str,
        scope: &str,
    ) -> PyResult<usize> {
        let op = PathBuf::from(out_sqlite_path);
        let sc = scope.to_owned();
        py.allow_threads(|| export_sqlite_database(&self.project_db, &sc, &op).map_err(to_py_err))
    }

    /// Runs Gravity locality compaction, refreshes the persistent index snapshot, and verifies CRC integrity.
    #[pyo3(signature = (prune=false))]
    pub fn compact(&self, py: Python<'_>, prune: bool) -> PyResult<String> {
        py.allow_threads(|| {
            let mut cog = CognitiveEngine::open_db(Arc::clone(&self.project_db)).map_err(to_py_err)?;
            cog.save_index_snapshot().map_err(to_py_err)?;
            let rep = self
                .project_db
                .compact_with_options(prune)
                .map_err(to_py_err)?;
            serde_json::to_string(&rep).map_err(to_py_err)
        })
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
pub fn verify_sqlite_roundtrip_json(
    py: Python<'_>,
    sqlite_path: &str,
    scope: &str,
) -> PyResult<String> {
    let sp = PathBuf::from(sqlite_path);
    let sc = scope.to_owned();
    py.allow_threads(move || {
        let sym_meta = std::fs::symlink_metadata(&sp).map_err(to_py_err)?;
        if sym_meta.file_type().is_symlink() {
            return Err(PyRuntimeError::new_err(format!(
                "refusing symlinked SQLite path '{}'",
                sp.display()
            )));
        }
        let tmp_dir = tempfile::Builder::new()
            .prefix("libredb_py_rt_")
            .tempdir()
            .map_err(to_py_err)?;
        let copy_src = tmp_dir.path().join("src.db");
        let ldb_file = tmp_dir.path().join("mid.ldb");
        let recon_db = tmp_dir.path().join("recon.db");
        std::fs::copy(&sp, &copy_src).map_err(to_py_err)?;

        {
            let ldb = LibreDb::open(&ldb_file).map_err(to_py_err)?;
            import_sqlite_readonly(&copy_src, &ldb, &sc).map_err(to_py_err)?;
            ldb.compact_with_gravity().map_err(to_py_err)?;
            export_sqlite_database(&ldb, &sc, &recon_db).map_err(to_py_err)?;
        }
        let rep = verify_sqlite_equivalence(&copy_src, &recon_db).map_err(to_py_err)?;
        serde_json::to_string(&rep).map_err(to_py_err)
    })
}

#[pymodule(name = "libredb")]
fn libredb_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<PyBrain>()?;
    m.add_function(wrap_pyfunction!(verify_sqlite_roundtrip_json, m)?)?;
    Ok(())
}
