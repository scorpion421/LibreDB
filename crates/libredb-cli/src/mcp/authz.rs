//! Server-side workspace authorization, nested workspace boundary isolation, ephemeral `0700`
//! `.ldb` brain routing, and `WorkspaceTrustLockGuard` seal orchestration.

use super::{canonical_brain_cache_key, insert_brain_bounded, McpServerState};
use crate::hooks::{
    find_workspace_root, open_project_ldb_silent, resolve_brain_conv_dir, user_home_dir,
};
use libredb_cognitive::{index_workspace_with_exclusions, CognitiveEngine, OverlayBrain};
use libredb_core::LibreDb;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) fn validate_pinned_workspace_root(raw_root: &Path) -> Result<PathBuf, String> {
    if let Ok(sym_meta) = std::fs::symlink_metadata(raw_root) {
        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing symlinked '--workspace-root' path '{}'",
                raw_root.display()
            ));
        }
    }
    let abs = if raw_root.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(raw_root))
            .unwrap_or_else(|_| raw_root.to_path_buf())
    } else {
        raw_root.to_path_buf()
    };
    let canon = crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs);
    if !canon.is_dir() {
        return Err(format!(
            "Pinned MCP '--workspace-root' '{}' does not exist or is not a directory",
            raw_root.display()
        ));
    }
    if crate::security::is_forbidden_mcp_workspace_root(&canon) {
        return Err(format!(
            "Refusing overly broad or control-plane '--workspace-root' '{}'",
            raw_root.display()
        ));
    }
    Ok(canon)
}

/// Resolves the canonical owning workspace root whose `.seal_locks/ws_<hash>.lock` serializes all
/// mutations to `proj_db`. Always prefers the parent workspace of `<ws_root>/.agents/memory.ldb`
/// over any subdirectory `fallback_dir` so subdirectory `index`, `impact`, `fim`, and `memorize`
/// contend on the exact same lock identity.
pub(crate) fn resolve_canonical_workspace_lock_root(
    proj_db: &LibreDb,
    authorized_ws_root: &Path,
) -> PathBuf {
    if let Some(db_path) = proj_db.path() {
        if let Some(ws_root) = workspace_root_from_agents_ldb(db_path) {
            return ws_root;
        }
    }
    let abs = if authorized_ws_root.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(authorized_ws_root))
            .unwrap_or_else(|_| authorized_ws_root.to_path_buf())
    } else {
        authorized_ws_root.to_path_buf()
    };
    crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs)
}

pub(super) fn find_owning_repo_or_agents_ancestor(start_dir: &Path) -> Option<PathBuf> {
    let mut curr = Some(start_dir);
    while let Some(c) = curr {
        if crate::security::is_forbidden_mcp_workspace_root(c) {
            break;
        }
        if c.join(".agents").is_dir() || c.join(".git").exists() {
            return Some(c.to_path_buf());
        }
        curr = c.parent();
    }
    None
}

impl McpServerState {
    pub(super) fn ephemeral_workspace_ldb_path(
        &mut self,
        ws_root: &Path,
    ) -> Result<PathBuf, String> {
        if self.ephemeral_dir.is_none() {
            let (dir, lock_backend) =
                crate::security::create_private_ephemeral_dir("libredb_mcp_eph")?;
            self.ephemeral_dir = Some(dir);
            self.ephemeral_lock = Some(lock_backend);
        }
        let dir = self.ephemeral_dir.as_ref().unwrap();
        Ok(dir.join(crate::security::ephemeral_workspace_ldb_filename(ws_root)))
    }

    /// Validates `candidate_dir` against server-side workspace boundaries (`pinned_workspace_root`,
    /// MCP `initialize` / `roots/list` `client_workspace_roots`, or `customizations.ldb` trusted
    /// workspaces) and returns the MOST SPECIFIC (deepest) canonical authorized workspace root.
    /// Never depends on client root registration order and never falls back to self-declared `cwd`.
    pub(super) fn authorize_mcp_workspace_path(
        &mut self,
        candidate_dir: &Path,
        allow_private_brain: bool,
    ) -> Result<PathBuf, String> {
        self.sync_global_db_or_purge()?;
        let abs = if candidate_dir.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(candidate_dir))
                .unwrap_or_else(|_| candidate_dir.to_path_buf())
        } else {
            candidate_dir.to_path_buf()
        };
        let canon = crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs);
        if allow_private_brain && crate::security::is_private_brain_workspace(&canon) {
            return Ok(canon);
        }
        if crate::security::is_forbidden_mcp_workspace_root(&canon) {
            return Err(format!(
                "LibreDB MCP access denied: '{}' is a forbidden root or control-plane directory",
                candidate_dir.display()
            ));
        }
        if !canon.is_dir() {
            return Err(format!(
                "LibreDB MCP access denied: workspace directory '{}' does not exist",
                candidate_dir.display()
            ));
        }

        let mut candidates_by_specificity: Vec<PathBuf> = Vec::new();

        // 1. Hard server pin (`--workspace-root`, `LIBREDB_MCP_WORKSPACE_ROOT`, or `--project`):
        //    Enforces a strict outer containment boundary on `canon` before considering nested roots.
        if let Some(ref pin_root) = self.pinned_workspace_root {
            if let Some(err) = crate::security::check_mcp_workspace_containment(&canon, pin_root) {
                return Err(err);
            }
            if !crate::security::is_workspace_memory_trusted(self.global_db.as_deref(), pin_root) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                    pin_root.display(),
                    pin_root.display()
                ));
            }
            candidates_by_specificity.push(pin_root.clone());
        }

        // 2. Trusted MCP host client roots (`initialize` / `roots/list`):
        //    Always select the deepest containing workspace root (`max_by_key`), never `.iter().find()`.
        //    Suspended fail-closed while `client_roots_refresh_pending` is awaiting `roots/list`.
        if !self.client_roots_refresh_pending {
            if let Some(deepest_client_root) = self
                .client_workspace_roots
                .iter()
                .filter(|cr| crate::security::check_mcp_workspace_containment(&canon, cr).is_none())
                .max_by_key(|cr| crate::security::normalize_workspace_key(cr).len())
                .cloned()
            {
                candidates_by_specificity.push(deepest_client_root);
            }
        }

        // 3. Server-side `customizations.ldb` explicitly authorized workspaces:
        //    Walking upward from `canon` yields the deepest explicitly authorized workspace first.
        if let Some(ref gdb) = self.global_db {
            let mut cur = Some(canon.as_path());
            while let Some(anc) = cur {
                if crate::security::is_forbidden_mcp_workspace_root(anc) {
                    break;
                }
                if crate::security::is_workspace_path_authorized_synced(gdb, anc) {
                    candidates_by_specificity.push(anc.to_path_buf());
                    break;
                }
                cur = anc.parent();
            }
        }

        if let Some(selected_root) = candidates_by_specificity
            .into_iter()
            .max_by_key(|p| crate::security::normalize_workspace_key(p).len())
        {
            // Reject unapproved nested `.agents` boundaries strictly below `selected_root`:
            // if `selected_root < d <= canon` contains its own `.agents` directory, `d` was NOT
            // authorized as a nested workspace (otherwise `max_by_key` would have selected `d`),
            // so `canon` must NOT silently fall back into `selected_root`'s cognitive brain!
            let selected_norm = crate::security::normalize_workspace_key(&selected_root);
            let mut probe_anc = Some(canon.as_path());
            while let Some(d) = probe_anc {
                if crate::security::normalize_workspace_key(d) == selected_norm {
                    break;
                }
                if d.join(".agents").is_dir() {
                    return Err(format!(
                        "LibreDB MCP access denied: nested workspace '{}' contains its own '.agents' cognitive store that is not authorized or sealed on the server; refusing to fall back to parent workspace '{}'. Run 'libredb trust \"{}\"' in a terminal if you trust this nested workspace.",
                        d.display(),
                        selected_root.display(),
                        d.display()
                    ));
                }
                probe_anc = d.parent();
            }

            if !crate::security::is_workspace_memory_trusted(
                self.global_db.as_deref(),
                &selected_root,
            ) {
                return Err(format!(
                    "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                    selected_root.display(),
                    selected_root.display()
                ));
            }
            return Ok(selected_root);
        }

        // 4. Optional administrator opt-out (`mcp:allow_untrusted_workspaces = true` in `customizations.ldb`):
        if let Some(ref gdb) = self.global_db {
            if crate::security::is_mcp_untrusted_workspaces_allowed(gdb) {
                let inferred_root = find_owning_repo_or_agents_ancestor(&canon)
                    .or_else(|| find_workspace_root(&canon))
                    .unwrap_or_else(|| canon.clone());
                if crate::security::is_forbidden_mcp_workspace_root(&inferred_root) {
                    return Err(format!(
                        "LibreDB MCP access denied: '{}' is a forbidden workspace root",
                        candidate_dir.display()
                    ));
                }
                if !crate::security::is_workspace_memory_trusted(Some(gdb), &inferred_root) {
                    return Err(format!(
                        "LibreDB MCP access denied: workspace memory in '{}' is untrusted, tampered, or rolled back; run 'libredb trust \"{}\"' in a terminal.",
                        inferred_root.display(),
                        inferred_root.display()
                    ));
                }
                return Ok(inferred_root);
            }
            return Err(format!(
                "LibreDB MCP access denied: workspace '{}' is not authorized on the server (neither pinned via '--workspace-root', declared in MCP 'initialize' roots, nor trusted in customizations.ldb). Run 'libredb trust \"{}\"' in a terminal if you trust this workspace.",
                candidate_dir.display(),
                canon.display()
            ));
        }

        Err(format!(
            "LibreDB MCP access denied: workspace '{}' has no server-side authorization (global customizations.ldb is absent and neither '--workspace-root' nor MCP 'initialize' workspaceFolders was configured). Start 'libredb mcp --workspace-root \"{}\"', configure MCP 'initialize' roots, or run 'libredb init' and 'libredb trust \"{}\"'.",
            candidate_dir.display(),
            canon.display(),
            canon.display()
        ))
    }

    /// Resolves `(ws_root, containment_root)` for `libredb_code` and legacy code tools, failing
    /// closed whenever `cwd` is invalid, missing without a server-known workspace, or unauthorized.
    pub(super) fn resolve_authorized_code_workspace(
        &mut self,
        raw_cwd_opt: Option<&str>,
        target_hint_opt: Option<&str>,
        allow_symbol_only: bool,
    ) -> Result<(PathBuf, PathBuf), String> {
        self.sync_global_db_or_purge()?;
        if let Some(raw_cwd) = raw_cwd_opt.map(str::trim).filter(|s| !s.is_empty()) {
            let cwd_p = Path::new(raw_cwd);
            let cwd_abs = if cwd_p.is_relative() {
                std::env::current_dir()
                    .map(|c| c.join(cwd_p))
                    .unwrap_or_else(|_| cwd_p.to_path_buf())
            } else {
                cwd_p.to_path_buf()
            };
            let cwd_canon =
                crate::security::canonicalize_with_missing_tail(&cwd_abs).unwrap_or(cwd_abs);
            if !cwd_canon.is_dir() {
                return Err(format!(
                    "LibreDB MCP access denied: 'cwd' ('{raw_cwd}') does not exist or is not a directory"
                ));
            }
            if crate::security::is_forbidden_mcp_workspace_root(&cwd_canon) {
                return Err(format!(
                    "LibreDB MCP access denied: 'cwd' ('{raw_cwd}') is an invalid or overly broad workspace root"
                ));
            }
            let ws_root = self.authorize_mcp_workspace_path(&cwd_canon, false)?;
            if let Some(err) = crate::security::check_mcp_workspace_containment(&cwd_canon, &ws_root)
            {
                return Err(err);
            }
            return Ok((ws_root, cwd_canon));
        }

        if let Some(pin_root) = self.pinned_workspace_root.clone() {
            let ws_root = self.authorize_mcp_workspace_path(&pin_root, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if !self.client_roots_refresh_pending
            && self.client_workspace_roots.len() == 1
            && (allow_symbol_only
                || target_hint_opt.is_some_and(|h| Path::new(h.trim()).is_relative()))
        {
            let cr = self.client_workspace_roots[0].clone();
            let ws_root = self.authorize_mcp_workspace_path(&cr, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if !allow_symbol_only {
            let Some(hint) = target_hint_opt.map(str::trim).filter(|s| !s.is_empty()) else {
                return Err(
                    "LibreDB MCP access denied: missing target and 'cwd' workspace root".to_owned(),
                );
            };
            let hint_p = Path::new(hint);
            if hint_p.is_relative() {
                return Err(
                    "LibreDB MCP access denied: 'cwd' is required for relative target paths when server is not pinned via '--workspace-root'"
                        .to_owned(),
                );
            }
            if self.global_db.is_none()
                && (self.client_roots_refresh_pending || self.client_workspace_roots.is_empty())
            {
                return Err(
                    "LibreDB MCP access denied: omitting 'cwd' is not permitted when neither customizations.ldb nor active client workspace roots are available"
                        .to_owned(),
                );
            }
            let hint_canon = crate::security::canonicalize_with_missing_tail(hint_p)
                .unwrap_or_else(|| hint_p.to_path_buf());
            let probe_dir = if hint_canon.is_dir() {
                hint_canon.as_path()
            } else {
                hint_canon
                    .parent()
                    .ok_or_else(|| "LibreDB MCP access denied: invalid target path".to_owned())?
            };
            let ws_root = self.authorize_mcp_workspace_path(probe_dir, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        if let Some(def_ws) = workspace_root_from_agents_ldb(&self.default_project_path) {
            let ws_root = self.authorize_mcp_workspace_path(&def_ws, false)?;
            return Ok((ws_root.clone(), ws_root));
        }

        Err(
            "LibreDB MCP access denied: 'cwd' is required for symbol impact queries when server is not pinned via '--workspace-root'"
                .to_owned(),
        )
    }

    pub(super) fn is_quarantined_db(&self, proj_db: &LibreDb) -> bool {
        let Some(p) = proj_db.path() else {
            return false;
        };
        let q_path = default_libredb_home().join("quarantined_workspace.ldb");
        canonical_brain_cache_key(p) == canonical_brain_cache_key(&q_path)
    }

    /// Collects all server-known nested child workspace roots strictly inside `parent_ws` so
    /// parent-level `index` / `impact` / `fim` scans never ingest a nested project's source files.
    pub(super) fn collect_nested_child_workspaces(&self, parent_ws: &Path) -> Vec<PathBuf> {
        let parent_norm = crate::security::normalize_workspace_key(parent_ws);
        let child_prefix = format!("{parent_norm}/");
        let mut out: Vec<PathBuf> = Vec::new();
        let mut push_unique = |cand: PathBuf| {
            let cn = crate::security::normalize_workspace_key(&cand);
            if cn.starts_with(&child_prefix)
                && !out
                    .iter()
                    .any(|existing| crate::security::normalize_workspace_key(existing) == cn)
            {
                out.push(cand);
            }
        };
        for cr in &self.client_workspace_roots {
            push_unique(cr.clone());
        }
        if let Some(ref gdb) = self.global_db {
            if let Ok(trusted) = crate::security::list_trusted_workspaces(gdb) {
                for (norm, raw) in trusted {
                    if norm.starts_with(&child_prefix) {
                        push_unique(PathBuf::from(raw));
                    }
                }
            }
        }
        out
    }

    /// Enforces strict cognitive workspace boundary isolation between `expected_ws_root` (derived
    /// from `cwd`) and a concrete `target_path` (`skeleton`, `fim`, `index`, or batch `files`):
    /// if `target_path` resolves into a more specific nested workspace (either registered on the
    /// server or owning its own `.agents` directory), fails closed instead of polluting or reading
    /// across workspace brains.
    pub(super) fn verify_target_belongs_to_workspace(
        &mut self,
        target_path: &Path,
        expected_ws_root: &Path,
    ) -> Result<(), String> {
        let abs = if target_path.is_relative() {
            expected_ws_root.join(target_path)
        } else {
            target_path.to_path_buf()
        };
        let canon = crate::security::canonicalize_with_missing_tail(&abs).unwrap_or(abs);
        let probe_dir = if canon.is_dir() {
            canon.as_path()
        } else {
            canon
                .parent()
                .ok_or_else(|| "LibreDB MCP access denied: invalid target path".to_owned())?
        };
        let expected_norm = crate::security::normalize_workspace_key(expected_ws_root);

        let mut cur = Some(probe_dir);
        while let Some(d) = cur {
            if crate::security::normalize_workspace_key(d) == expected_norm {
                break;
            }
            if d.join(".agents").is_dir() {
                return Err(format!(
                    "LibreDB MCP workspace boundary violation: target '{}' resides inside nested workspace '{}', which maintains its own isolated cognitive store separate from '{}'. Pass cwd='{}' to query or index that nested workspace directly.",
                    target_path.display(),
                    d.display(),
                    expected_ws_root.display(),
                    d.display()
                ));
            }
            cur = d.parent();
        }

        let actual_ws = self.authorize_mcp_workspace_path(probe_dir, false)?;
        if crate::security::normalize_workspace_key(&actual_ws) != expected_norm {
            return Err(format!(
                "LibreDB MCP workspace boundary violation: target '{}' belongs to nested workspace '{}', which is isolated from requested cwd workspace '{}'. Pass cwd='{}' to query or index that nested workspace directly.",
                target_path.display(),
                actual_ws.display(),
                expected_ws_root.display(),
                actual_ws.display()
            ));
        }
        Ok(())
    }

    /// Acquires `WorkspaceTrustLockGuard` on the canonical owning workspace root (never swallowing
    /// lock failures via `.ok()`), runs `index_workspace_with_exclusions`, updates the cognitive
    /// index snapshot, and refreshes the cached `OverlayBrain`.
    pub(super) fn run_locked_workspace_index(
        &mut self,
        proj_db: &Arc<LibreDb>,
        ws_root: &Path,
        scan_dir: &Path,
        brain_hint: Option<&str>,
        cid_opt: Option<&str>,
    ) -> Result<libredb_cognitive::WorkspaceIndexReport, String> {
        if self.is_quarantined_db(proj_db) {
            return Err(format!(
                "Refusing to index '{}' because workspace memory is quarantined; run 'libredb trust' in a terminal first.",
                scan_dir.display()
            ));
        }
        let nested_exclusions = self.collect_nested_child_workspaces(ws_root);
        let lock_root = resolve_canonical_workspace_lock_root(proj_db, ws_root);
        let _idx_lock = match self
            .global_db
            .as_deref()
            .filter(|_| !crate::security::is_private_brain_workspace(&lock_root))
        {
            Some(gdb) => Some(crate::security::WorkspaceTrustLockGuard::acquire(
                gdb, &lock_root,
            )?),
            None => None,
        };
        let rep = index_workspace_with_exclusions(proj_db, scan_dir, false, &nested_exclusions)
            .map_err(|e| e.to_string())?;
        if !rep.fast_path_hit
            || proj_db
                .get_by_key(libredb_core::NodeKind::Generic, "sys::index_snapshot")
                .is_err()
        {
            let mut cog = CognitiveEngine::open_db(Arc::clone(proj_db)).map_err(|e| e.to_string())?;
            cog.save_index_snapshot().map_err(|e| e.to_string())?;
        }
        drop(_idx_lock);
        let brain = self.resolve_brain_mut(brain_hint, cid_opt, false)?;
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok(rep)
    }

    pub(super) fn seal_project_db_if_authorized(
        &mut self,
        ws_root_opt: Option<&Path>,
        proj_db: &LibreDb,
    ) -> Result<(), String> {
        if let (Some(ref gdb), Some(ws_root)) = (&self.global_db, ws_root_opt) {
            if let Err(err) = crate::security::seal_workspace_memory(gdb, proj_db, ws_root) {
                let cache_key =
                    canonical_brain_cache_key(&ws_root.join(".agents").join("memory.ldb"));
                self.brains.remove(&cache_key);
                self.clear_ram_sessions_for_cache_key(&cache_key);
                return Err(format!(
                    "Workspace mutation succeeded, but updating hmac-sha256:v4 trust seal for '{}' failed: {err}",
                    ws_root.display()
                ));
            }
        }
        Ok(())
    }

    fn is_global_customizations_target(&self, candidate_key: &str) -> bool {
        if candidate_key.ends_with("/.gemini/libredb/customizations.ldb") {
            return true;
        }
        if let Some(ref gp) = self.global_path {
            if canonical_brain_cache_key(gp) == candidate_key {
                return true;
            }
        }
        false
    }

    fn open_quarantined_brain(&mut self) -> Result<&mut OverlayBrain, String> {
        let q_path = default_libredb_home().join("quarantined_workspace.ldb");
        let q_key = canonical_brain_cache_key(&q_path);
        if !self.brains.contains_key(&q_key) {
            let (q_db, _) = open_project_ldb_silent(&q_path)?;
            let q_brain = OverlayBrain::open(self.global_db.clone(), q_db)
                .map_err(|e| e.to_string())?;
            insert_brain_bounded(&mut self.brains, q_key.clone(), q_brain);
        }
        let brain = self.brains.get_mut(&q_key).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok(brain)
    }

    pub(super) fn resolve_brain_with_seal_target(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<
        (
            Option<crate::security::WorkspaceTrustLockGuard>,
            Option<PathBuf>,
            &mut OverlayBrain,
        ),
        String,
    > {
        // Synchronize `customizations.ldb` from disk BEFORE trusting any cached `OverlayBrain` or
        // evaluating workspace seals; fail closed and purge RAM brains on any global DB corruption.
        self.sync_global_db_or_purge()?;

        let explicit_hint = hint_path.map(str::trim).filter(|s| !s.is_empty());
        if let Some(ref pin_root) = self.pinned_workspace_root {
            if let Some(raw) = explicit_hint {
                if let Some(err) =
                    crate::security::check_mcp_workspace_containment(Path::new(raw), pin_root)
                {
                    return Err(err);
                }
            }
        }

        let candidate_path = match explicit_hint {
            Some(raw) => match resolve_explicit_hint_ldb_path(Path::new(raw)) {
                Ok(p) => p,
                Err(err) => {
                    if is_explicit_memorize {
                        return Err(err);
                    }
                    let brain = self.open_quarantined_brain()?;
                    return Ok((None, None, brain));
                }
            },
            None => {
                if let Some(ref pin) = self.pinned_workspace_root {
                    pin.join(".agents").join("memory.ldb")
                } else if !self.client_roots_refresh_pending
                    && self.client_workspace_roots.len() == 1
                {
                    self.client_workspace_roots[0]
                        .join(".agents")
                        .join("memory.ldb")
                } else if let Some(chat_ldb) = cid_opt.and_then(infer_chat_memory_ldb_path) {
                    chat_ldb
                } else {
                    self.default_project_path.clone()
                }
            }
        };
        let candidate_cache_key = canonical_brain_cache_key(&candidate_path);

        if self.is_global_customizations_target(&candidate_cache_key) {
            if is_explicit_memorize {
                return Err(
                    "Refusing to mutate global customizations.ldb via workspace MCP tools; use 'libredb config' or 'libredb trust'."
                        .to_owned(),
                );
            }
            let brain = self.open_quarantined_brain()?;
            return Ok((None, None, brain));
        }

        let mut ws_write_lock: Option<crate::security::WorkspaceTrustLockGuard> = None;
        let mut ws_root_to_seal: Option<PathBuf> = None;
        let (mut db_path, mut cache_key) =
            if let Some(ws_root) = workspace_root_from_agents_ldb(&candidate_path) {
                if crate::security::is_private_brain_workspace(&ws_root) {
                    (candidate_path, candidate_cache_key)
                } else {
                    match self.authorize_mcp_workspace_path(&ws_root, false) {
                        Ok(auth_root) => {
                            let auth_ldb = auth_root.join(".agents").join("memory.ldb");
                            let auth_cache_key = canonical_brain_cache_key(&auth_ldb);
                            if self.global_db.is_none() {
                                if is_explicit_memorize {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&candidate_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&auth_cache_key);
                                    return Err(format!(
                                        "LibreDB MCP access denied: persisting workspace memory in '{}' via libredb_memorize requires an initialized global customizations.ldb trust store; run 'libredb init' and 'libredb trust \"{}\"' in a terminal.",
                                        auth_root.display(),
                                        auth_root.display()
                                    ));
                                }
                                if crate::security::is_workspace_memory_trusted(None, &auth_root) {
                                    let eph_path = self.ephemeral_workspace_ldb_path(&auth_root)?;
                                    let eph_key = canonical_brain_cache_key(&eph_path);
                                    (eph_path, eph_key)
                                } else {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&candidate_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&auth_cache_key);
                                    let q_path =
                                        default_libredb_home().join("quarantined_workspace.ldb");
                                    let q_key = canonical_brain_cache_key(&q_path);
                                    (q_path, q_key)
                                }
                            } else {
                                let has_disk_memory =
                                    auth_ldb.is_file() || auth_ldb.with_extension("db").exists();
                                let needs_mig_lock =
                                    !auth_ldb.is_file() && auth_ldb.with_extension("db").exists();
                                if is_explicit_memorize || needs_mig_lock {
                                    if let Some(ref gdb) = self.global_db {
                                        ws_write_lock = Some(
                                            crate::security::WorkspaceTrustLockGuard::acquire(
                                                gdb, &auth_root,
                                            )?,
                                        );
                                    }
                                }
                                let allow_readonly_sqlite_mig = !needs_mig_lock
                                    || is_explicit_memorize
                                    || self.global_db.as_deref().is_some_and(|gdb| {
                                        let norm =
                                            crate::security::normalize_workspace_key(&auth_root);
                                        gdb.get_by_key(
                                            libredb_core::NodeKind::Config,
                                            &format!("trust:allowed::{norm}"),
                                        )
                                        .is_ok()
                                    });
                                if allow_readonly_sqlite_mig
                                    && crate::security::is_workspace_memory_trusted(
                                        self.global_db.as_deref(),
                                        &auth_root,
                                    )
                                {
                                    if !is_explicit_memorize && !has_disk_memory {
                                        let eph_path =
                                            self.ephemeral_workspace_ldb_path(&auth_root)?;
                                        let eph_key = canonical_brain_cache_key(&eph_path);
                                        (eph_path, eph_key)
                                    } else {
                                        if is_explicit_memorize {
                                            if let Some(ref dir) = self.ephemeral_dir {
                                                let eph_path = dir.join(
                                                    crate::security::ephemeral_workspace_ldb_filename(
                                                        &auth_root,
                                                    ),
                                                );
                                                let eph_key = canonical_brain_cache_key(&eph_path);
                                                self.brains.remove(&eph_key);
                                                self.clear_ram_sessions_for_cache_key(&eph_key);
                                            }
                                            ws_root_to_seal = Some(auth_root);
                                        }
                                        (auth_ldb, auth_cache_key)
                                    }
                                } else {
                                    self.brains.remove(&candidate_cache_key);
                                    self.brains.remove(&auth_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&candidate_cache_key);
                                    self.clear_ram_sessions_for_cache_key(&auth_cache_key);
                                    if is_explicit_memorize {
                                        return Err(format!(
                                            "Workspace memory at '{}' is quarantined because a pre-existing unsealed, tampered, rolled-back, or Git-tracked .agents database was detected. Run 'libredb trust \"{}\"' (or '--reinit-lost' / '--accept-rollback' if recovering) in a terminal if you trust this repository.",
                                            auth_ldb.display(),
                                            auth_root.display()
                                        ));
                                    }
                                    ws_write_lock = None;
                                    let q_path =
                                        default_libredb_home().join("quarantined_workspace.ldb");
                                    let q_key = canonical_brain_cache_key(&q_path);
                                    (q_path, q_key)
                                }
                            }
                        }
                        Err(auth_err) => {
                            // Evict any cached OverlayBrain via canonical key (unless client roots
                            // are merely suspended awaiting `roots/list`) and never create
                            // `.agents/memory.ldb` inside unauthorized or quarantined workspaces.
                            if !self.client_roots_refresh_pending {
                                self.brains.remove(&candidate_cache_key);
                                self.clear_ram_sessions_for_cache_key(&candidate_cache_key);
                            }
                            if is_explicit_memorize || self.global_db.is_none() {
                                return Err(auth_err);
                            }
                            let q_path = default_libredb_home().join("quarantined_workspace.ldb");
                            let q_key = canonical_brain_cache_key(&q_path);
                            (q_path, q_key)
                        }
                    }
                }
            } else if explicit_hint.is_some() {
                if is_explicit_memorize {
                    return Err(format!(
                        "Refusing to mutate arbitrary non-workspace .ldb file '{}' via MCP; pass an authorized workspace directory in 'cwd'.",
                        candidate_path.display()
                    ));
                }
                let q_path = default_libredb_home().join("quarantined_workspace.ldb");
                let q_key = canonical_brain_cache_key(&q_path);
                (q_path, q_key)
            } else if is_explicit_memorize {
                return Err(
                    "LibreDB MCP access denied: 'cwd' (authorized workspace directory) or 'cid' (conversation ID) is required for libredb_memorize when server is not pinned via '--workspace-root'."
                        .to_owned(),
                );
            } else {
                (candidate_path, candidate_cache_key)
            };

        if !self.brains.contains_key(&cache_key) {
            let (proj_db, did_migrate) = open_project_ldb_silent(&db_path)?;
            let mut ready_db = Some(proj_db);
            if did_migrate {
                if let Some(mig_ws) = workspace_root_from_agents_ldb(&db_path) {
                    if !crate::security::is_private_brain_workspace(&mig_ws) {
                        let seal_res =
                            if crate::security::is_forbidden_mcp_workspace_root(&mig_ws) {
                                Err("workspace resolves to a forbidden root or control-plane directory".to_owned())
                            } else if let Some(ref gdb) = self.global_db {
                                crate::security::seal_workspace_memory(
                                    gdb,
                                    ready_db.as_ref().unwrap(),
                                    &mig_ws,
                                )
                            } else {
                                Err("global customizations.ldb is unavailable".to_owned())
                            };
                        if let Err(err) = seal_res {
                            ready_db = None;
                            if is_explicit_memorize {
                                return Err(format!(
                                    "Post-migration hmac-sha256:v4 workspace seal failed for '{}': {err}",
                                    mig_ws.display()
                                ));
                            }
                            ws_root_to_seal = None;
                            db_path = default_libredb_home().join("quarantined_workspace.ldb");
                            cache_key = canonical_brain_cache_key(&db_path);
                            if !self.brains.contains_key(&cache_key) {
                                let (q_db, _) = open_project_ldb_silent(&db_path)?;
                                let q_brain = OverlayBrain::open(self.global_db.clone(), q_db)
                                    .map_err(|e| e.to_string())?;
                                insert_brain_bounded(&mut self.brains, cache_key.clone(), q_brain);
                            }
                        }
                    }
                }
            }
            if let Some(valid_db) = ready_db {
                let brain = OverlayBrain::open(self.global_db.clone(), valid_db)
                    .map_err(|e| e.to_string())?;
                insert_brain_bounded(&mut self.brains, cache_key.clone(), brain);
            }
        }

        let brain = self.brains.get_mut(&cache_key).unwrap();
        brain.refresh_if_needed().map_err(|e| e.to_string())?;
        Ok((ws_write_lock, ws_root_to_seal, brain))
    }

    pub(super) fn resolve_brain_mut(
        &mut self,
        hint_path: Option<&str>,
        cid_opt: Option<&str>,
        is_explicit_memorize: bool,
    ) -> Result<&mut OverlayBrain, String> {
        let (_, _, brain) =
            self.resolve_brain_with_seal_target(hint_path, cid_opt, is_explicit_memorize)?;
        Ok(brain)
    }
}

pub(super) fn default_libredb_home() -> PathBuf {
    user_home_dir().join(".gemini").join("libredb")
}

pub(super) fn workspace_root_from_agents_ldb(db_path: &Path) -> Option<PathBuf> {
    let joined = if db_path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(db_path))
            .unwrap_or_else(|_| db_path.to_path_buf())
    } else {
        db_path.to_path_buf()
    };
    let resolved = crate::security::canonicalize_with_missing_tail(&joined).unwrap_or(joined);
    let fname = resolved.file_name()?.to_str()?;
    if !fname.eq_ignore_ascii_case("memory.ldb") {
        return None;
    }
    let parent = resolved.parent()?;
    if parent
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case(".agents"))
    {
        parent
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
    } else {
        None
    }
}

pub(super) fn infer_chat_memory_ldb_path(cid: &str) -> Option<PathBuf> {
    if cid.trim().is_empty() || cid.contains('/') || cid.contains('\\') {
        return None;
    }
    let brain_dir = resolve_brain_conv_dir(cid.trim());
    if brain_dir.is_dir() {
        Some(brain_dir.join(".agents").join("memory.ldb"))
    } else {
        None
    }
}

pub(super) fn infer_antigravity_transcript_path(cid: &str) -> Option<PathBuf> {
    if cid.trim().is_empty() || cid.contains('/') || cid.contains('\\') {
        return None;
    }
    Some(
        resolve_brain_conv_dir(cid.trim())
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl"),
    )
}

pub(super) fn resolve_explicit_hint_ldb_path(probe: &Path) -> Result<PathBuf, String> {
    if probe
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ldb"))
    {
        return Ok(probe.to_path_buf());
    }
    let joined = if probe.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(probe))
            .unwrap_or_else(|_| probe.to_path_buf())
    } else {
        probe.to_path_buf()
    };
    if !joined.exists() {
        return Err(format!(
            "LibreDB MCP access denied: workspace path '{}' does not exist",
            probe.display()
        ));
    }
    let start_dir = if joined.is_file() {
        joined.parent().unwrap_or(&joined)
    } else {
        &joined
    };
    if crate::security::is_forbidden_mcp_workspace_root(start_dir) {
        return Err(format!(
            "LibreDB MCP access denied: '{}' is a forbidden root or control-plane directory",
            probe.display()
        ));
    }
    if crate::security::is_private_brain_workspace(start_dir) {
        if let Some(repo_anc) = find_owning_repo_or_agents_ancestor(start_dir) {
            return Ok(repo_anc.join(".agents").join("memory.ldb"));
        }
    }
    Ok(start_dir.join(".agents").join("memory.ldb"))
}
