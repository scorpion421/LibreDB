//! Native Rust Gitea workflow automation (`gitea-status`, `gitea-config`, `gitea-init`,
//! `gitea-sync`, `gitea-release`, `gitea-credential-helper`) backed by `customizations.ldb`.
//!
//! Uses a self-contained `std::net::TcpStream` HTTP/1.1 client for zero external TLS/HTTP crate bloat,
//! transient in-memory Git `Authorization: Basic` headers (never storing plaintext tokens in `.git/config`),
//! and strict SemVer 2.0.0 + Keep a Changelog 1.1.0 + `[GITEA REPOSITORY COLLISION]` guardrails.

use crate::hooks::open_global_ldb;
use libredb_cognitive::{audit_workspace_guardrails, index_workspace, CognitiveEngine};
use libredb_core::{LibreDb, NodeKind, WriteRequest};
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GiteaConfig {
    pub url: String,
    pub user: String,
    pub token: String,
    pub service_name: String,
}

impl GiteaConfig {
    pub fn load(ldb: &LibreDb) -> Self {
        let get_cfg = |k: &str| -> Option<String> {
            ldb.get_by_key(NodeKind::Config, k)
                .ok()
                .map(|r| String::from_utf8_lossy(&r.payload).trim().to_owned())
                .filter(|s| !s.is_empty())
        };

        let url = env::var("SKILLSDB_GITEA_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_url"))
            .unwrap_or_else(|| "http://127.0.0.1:3000".to_owned())
            .trim_end_matches('/')
            .to_owned();

        let user = env::var("SKILLSDB_GITEA_USER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_user"))
            .unwrap_or_default();

        let token = env::var("SKILLSDB_GITEA_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_token"))
            .unwrap_or_default();

        let service_name = env::var("SKILLSDB_GITEA_SERVICE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_service"))
            .unwrap_or_else(|| "gitea".to_owned());

        Self {
            url,
            user,
            token,
            service_name,
        }
    }

    pub fn is_gitea_remote_url(&self, remote_url: &str) -> bool {
        let low = remote_url.trim().to_ascii_lowercase();
        let cfg_low = self.url.trim().trim_end_matches('/').to_ascii_lowercase();
        (!cfg_low.is_empty() && low.starts_with(&cfg_low))
            || low.starts_with("http://127.0.0.1:3000")
            || low.starts_with("http://localhost:3000")
    }

    /// Returns transient Basic Auth args ONLY when `remote_url` matches the configured Gitea host.
    /// Never attaches local Gitea credentials to GitHub, GitLab, or external Git servers!
    pub fn git_auth_args_for_remote(&self, remote_url: &str) -> Vec<String> {
        if self.is_gitea_remote_url(remote_url) && !self.user.is_empty() && !self.token.is_empty()
        {
            let b64 = base64_encode(format!("{}:{}", self.user, self.token).as_bytes());
            vec![
                "-c".to_owned(),
                format!("http.extraHeader=Authorization: Basic {b64}"),
            ]
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    pub version: String,
    pub tag: String,
    pub date: String,
    pub body: String,
}

pub fn cmd_gitea_credential_helper(
    action: &str,
    global_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if action != "get" {
        return Ok(());
    }
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    if !cfg.user.is_empty() && !cfg.token.is_empty() {
        let mut out = std::io::stdout().lock();
        write!(out, "username={}\npassword={}\n\n", cfg.user, cfg.token)?;
        out.flush()?;
    }
    Ok(())
}

pub fn cmd_gitea_config(
    global_opt: Option<&Path>,
    url: Option<&str>,
    user: Option<&str>,
    token: Option<&str>,
    register_helper: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ldb = open_global_ldb(global_opt)?;
    if let Some(u) = url {
        ldb.put(
            WriteRequest::new(NodeKind::Config, u.trim().trim_end_matches('/').as_bytes().to_vec())
                .with_key("gitea_url")
                .with_importance(190),
        )?;
    }
    if let Some(usr) = user {
        ldb.put(
            WriteRequest::new(NodeKind::Config, usr.trim().as_bytes().to_vec())
                .with_key("gitea_user")
                .with_importance(190),
        )?;
    }
    if let Some(tok) = token {
        ldb.put(
            WriteRequest::new(NodeKind::Config, tok.trim().as_bytes().to_vec())
                .with_key("gitea_token")
                .with_importance(190),
        )?;
    }

    let cfg = GiteaConfig::load(&ldb);
    if register_helper {
        if let Ok(exe) = env::current_exe() {
            let exe_fwd = exe.to_string_lossy().replace('\\', "/");
            let helper_cmd = format!("!\"{exe_fwd}\" gitea-credential-helper");
            for ep in ["http://127.0.0.1:3000", "http://localhost:3000", cfg.url.as_str()] {
                let _ = Command::new("git")
                    .args(["config", "--global", &format!("credential.{ep}.helper"), &helper_cmd])
                    .output();
            }
        }
    }

    let masked = if cfg.token.len() > 10 {
        format!("{}...{}", &cfg.token[..6], &cfg.token[cfg.token.len() - 4..])
    } else if !cfg.token.is_empty() {
        "(set)".to_owned()
    } else {
        "(not set)".to_owned()
    };

    println!("============================================================");
    println!("LibreDB - Gitea & Workspace Configuration");
    println!("============================================================");
    println!("Gitea URL:          {}", cfg.url);
    println!("Repository Owner:   {}", if cfg.user.is_empty() { "(not set)" } else { &cfg.user });
    println!("API Token:          {masked}");
    println!("Service Name:       {}", cfg.service_name);
    println!("============================================================");
    Ok(())
}

pub fn cmd_gitea_status(global_opt: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    let mut svc_state = query_service_state(&cfg.service_name);
    let mut ver_opt = check_gitea_version(&cfg);

    if ver_opt.is_none() || svc_state == "STOPPED" {
        let _ = Command::new("sc.exe").args(["start", &cfg.service_name]).output();
        std::thread::sleep(Duration::from_millis(900));
        svc_state = query_service_state(&cfg.service_name);
        ver_opt = check_gitea_version(&cfg);
    }

    println!("============================================================");
    println!("LibreDB - Gitea Integration Status");
    println!("============================================================");
    println!("Windows Service:  {} ({svc_state})", cfg.service_name);
    println!("Server URL:       {}", cfg.url);
    if let Some(ver) = ver_opt {
        println!("API Health:       ONLINE");
        println!("Gitea Version:    {ver}");
        println!("Repository Owner: {}", cfg.user);
        let repos = list_remote_repos(&cfg);
        println!("Tracked Repos:    {}", repos.len());
        for (full_name, html_url) in repos {
            println!("  * {full_name} ({html_url})");
        }
    } else {
        println!("API Health:       OFFLINE");
    }
    println!("============================================================");
    Ok(())
}

pub fn cmd_gitea_init(
    project_dir: &Path,
    repo_name_opt: Option<&str>,
    use_existing: bool,
    overwrite: bool,
    global_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let abs_dir = fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let clean_root = strip_verbatim_prefix(&abs_dir);
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);

    let repo_name = repo_name_opt
        .map(ToOwned::to_owned)
        .or_else(|| clean_root.file_name().and_then(|n| n.to_str()).map(ToOwned::to_owned))
        .ok_or("Cannot determine repository name")?;

    if !cfg.user.is_empty() && !cfg.token.is_empty() {
        if let Some((exists, is_empty, html_url, _clone_url)) = inspect_remote_repo(&cfg, &repo_name)
        {
            let already_linked = get_configured_gitea_url(&clean_root, &cfg.url)
                .map(|u| u.to_ascii_lowercase().ends_with(&format!("/{}", repo_name.to_ascii_lowercase())))
                .unwrap_or(false);
            if exists && !is_empty && !already_linked && !use_existing && !overwrite {
                eprintln!(
                    "[GITEA REPOSITORY COLLISION]: Repository '{}/{}' already exists on Gitea ({html_url}) and is non-empty! Pause and ask the user whether to pass --use-existing, --name <new_name>, or --overwrite.",
                    cfg.user, repo_name
                );
                std::process::exit(2);
            }
            if exists && overwrite {
                let _ = http_request(
                    "DELETE",
                    &format!("{}/api/v1/repos/{}/{}", cfg.url, cfg.user, repo_name),
                    &cfg.token,
                    None,
                    None,
                );
            }
        }
    }

    ensure_local_git_initialized(&clean_root)?;

    let clone_url = ensure_remote_repo_created(&cfg, &repo_name)?;
    let remotes = list_git_remotes(&clean_root);
    let mut linked_remote_name = "origin";

    if let Some((_, existing_origin_url)) = remotes.iter().find(|(n, _)| n == "origin") {
        if cfg.is_gitea_remote_url(existing_origin_url) {
            let _ = Command::new("git")
                .args(["remote", "set-url", "origin", &clone_url])
                .current_dir(&clean_root)
                .output()?;
        } else {
            // Preserve non-Gitea `origin` (e.g., GitHub/GitLab) and attach local Gitea as `gitea` remote!
            linked_remote_name = "gitea";
            if remotes.iter().any(|(n, _)| n == "gitea") {
                let _ = Command::new("git")
                    .args(["remote", "set-url", "gitea", &clone_url])
                    .current_dir(&clean_root)
                    .output()?;
            } else {
                let _ = Command::new("git")
                    .args(["remote", "add", "gitea", &clone_url])
                    .current_dir(&clean_root)
                    .output()?;
            }
        }
    } else {
        let _ = Command::new("git")
            .args(["remote", "add", "origin", &clone_url])
            .current_dir(&clean_root)
            .output()?;
    }

    record_learned_workspace(&ldb, &clean_root);
    println!(
        "[OK] Initialized Git & linked remote '{linked_remote_name}' ('{}') -> {}/{}/{}",
        clean_root.display(),
        cfg.url,
        cfg.user,
        repo_name
    );
    Ok(())
}

pub fn cmd_gitea_sync(
    project_dir: &Path,
    message: &str,
    sync_releases: bool,
    allow_unversioned: bool,
    target_remote_opt: Option<&str>,
    push_all_remotes: bool,
    push_github: bool,
    global_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let abs_dir = fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let clean_root = strip_verbatim_prefix(&abs_dir);

    if !allow_unversioned && !workspace_has_semver_metadata(&clean_root) {
        return Err(
            "[UNVERSIONED WORKSPACE]: Missing VERSION or CHANGELOG.md. Ask user confirmation ('Soll ich das wirklich ohne Versionierung hochladen?') before passing --allow-unversioned."
                .into(),
        );
    }

    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);

    ensure_local_git_initialized(&clean_root)?;
    record_learned_workspace(&ldb, &clean_root);

    let proj_ldb_path = clean_root.join(".agents").join("memory.ldb");
    if proj_ldb_path.is_file() {
        if let Ok(pdb) = LibreDb::open(&proj_ldb_path) {
            let pdb = Arc::new(pdb);
            if let Ok(rep) = index_workspace(&pdb, &clean_root, false) {
                if rep.files_reindexed > 0 {
                    if let Ok(mut cog) = CognitiveEngine::open_db(pdb) {
                        let _ = cog.save_index_snapshot();
                    }
                }
            }
        }
    }

    let _ = Command::new("git")
        .args(["add", "-A"])
        .current_dir(&clean_root)
        .output()?;

    let audit = audit_workspace_guardrails(&clean_root, true)?;
    if !audit.passed(false) {
        let first = &audit.violations[0];
        return Err(format!(
            "Guardrail audit blocked git-sync ({} in {}:L{}): {}",
            first.rule, first.file, first.line, first.message
        )
        .into());
    }

    let st_out = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&clean_root)
        .output()?;
    let changed_cnt = String::from_utf8_lossy(&st_out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();

    // Strict SemVer 2.0.0 Tag Immutability Guard: if new code changes are staged and `--allow-unversioned`
    // was NOT passed, verify that the top version in `CHANGELOG.md` is not already locked to an existing Git tag!
    if changed_cnt > 0 && !allow_unversioned && clean_root.join("CHANGELOG.md").is_file() {
        if let Ok(entries) = parse_keep_a_changelog(&clean_root.join("CHANGELOG.md")) {
            if let Some(latest) = entries.first() {
                if let Some(existing_tag_sha) = resolve_git_tag_commit(&clean_root, &latest.tag) {
                    return Err(format!(
                        "[SEMVER IMMUTABILITY VIOLATION]: Top CHANGELOG.md version {} is already tagged at commit {}. Never overwrite or append code changes to an already published release version; increment VERSION and add a new '## [X.Y.Z] - YYYY-MM-DD' section in CHANGELOG.md first (or ask user confirmation before passing --allow-unversioned).",
                        latest.tag,
                        &existing_tag_sha[..existing_tag_sha.len().min(7)]
                    )
                    .into());
                }
            }
        }
    }

    if changed_cnt > 0 {
        let c_out = Command::new("git")
            .args([
                "-c",
                "user.name=Antigravity",
                "-c",
                "user.email=antigravity@local.dev",
                "commit",
                "-m",
                message,
            ])
            .current_dir(&clean_root)
            .output()?;
        if !c_out.status.success() {
            return Err(format!(
                "git commit failed: {}",
                String::from_utf8_lossy(&c_out.stderr)
            )
            .into());
        }
    }

    let rev_out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&clean_root)
        .output()?;
    let short_hash = String::from_utf8_lossy(&rev_out.stdout).trim().to_owned();

    let repo_name = resolve_repo_name_from_git_or_dir(&clean_root);
    let mut remotes = list_git_remotes(&clean_root);
    if remotes.is_empty() && !cfg.user.is_empty() && !cfg.token.is_empty() {
        if let Ok(clone_url) = ensure_remote_repo_created(&cfg, &repo_name) {
            let _ = Command::new("git")
                .args(["remote", "add", "origin", &clone_url])
                .current_dir(&clean_root)
                .output();
            remotes = list_git_remotes(&clean_root);
        }
    }

    let target_remotes = select_target_remotes(
        &remotes,
        target_remote_opt,
        push_all_remotes,
        push_github,
    );
    if target_remotes.is_empty() {
        return Err("No Git remotes configured for workspace. Run 'libredb gitea-init' or 'git remote add origin <url>'.".into());
    }

    let branch = current_git_branch(&clean_root);
    println!("Synchronizing workspace: {} ({})", repo_name, clean_root.display());
    println!("  [OK] HEAD commit:    {short_hash} ({changed_cnt} files committed)");

    for (rem_name, rem_url) in &target_remotes {
        if cfg.is_gitea_remote_url(rem_url) && !cfg.user.is_empty() && !cfg.token.is_empty() {
            let _ = ensure_remote_repo_created(&cfg, &repo_name);
        }
        let mut push_args = cfg.git_auth_args_for_remote(rem_url);
        push_args.extend(["push".to_owned(), "-u".to_owned(), rem_name.clone(), branch.clone()]);
        let p_out = Command::new("git")
            .args(&push_args)
            .current_dir(&clean_root)
            .output()?;
        if !p_out.status.success() {
            return Err(format!(
                "git push to remote '{}' ({}) failed: {}",
                rem_name,
                rem_url,
                String::from_utf8_lossy(&p_out.stderr)
            )
            .into());
        }
        println!("  [OK] Pushed to '{rem_name}': {rem_url}");
    }

    if sync_releases && clean_root.join("CHANGELOG.md").is_file() {
        let synced = publish_gitea_release_internal(&clean_root, None, &cfg, &target_remotes)?;
        if !synced.is_empty() {
            println!("  [OK] Synced Keep a Changelog releases: {}", synced.join(", "));
        }
    }
    Ok(())
}

pub fn cmd_gitea_release(
    project_dir: &Path,
    tag_opt: Option<&str>,
    target_remote_opt: Option<&str>,
    push_all_remotes: bool,
    push_github: bool,
    global_opt: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let abs_dir = fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let clean_root = strip_verbatim_prefix(&abs_dir);
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);

    let remotes = list_git_remotes(&clean_root);
    let target_remotes = select_target_remotes(
        &remotes,
        target_remote_opt,
        push_all_remotes,
        push_github,
    );

    let synced = publish_gitea_release_internal(&clean_root, tag_opt, &cfg, &target_remotes)?;
    let repo_name = resolve_repo_name_from_git_or_dir(&clean_root);
    for t in &synced {
        println!(
            "  [OK] Published Release {t} for {repo_name} ({}/{}/{repo_name}/releases/tag/{t})",
            cfg.url, cfg.user
        );
    }
    Ok(())
}

fn publish_gitea_release_internal(
    project_root: &Path,
    target_tag_opt: Option<&str>,
    cfg: &GiteaConfig,
    target_remotes: &[(String, String)],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let changelog_path = project_root.join("CHANGELOG.md");
    let entries = parse_keep_a_changelog(&changelog_path)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let clean_target = target_tag_opt.map(|t| t.trim().trim_start_matches(['v', 'V']).to_owned());
    let selected: Vec<&ChangelogEntry> = if let Some(ref ct) = clean_target {
        entries.iter().filter(|e| &e.version == ct).collect()
    } else {
        vec![&entries[0]]
    };
    if selected.is_empty() {
        return Err(format!("Version {:?} not found in CHANGELOG.md", target_tag_opt).into());
    }

    let repo_name = resolve_repo_name_from_git_or_dir(project_root);

    // Ensure local annotated Git tag exists for selected release(s) and verify SemVer tag immutability!
    let head_sha = resolve_git_head_commit(project_root);
    let mut created_any_tag = false;
    for entry in &selected {
        if let Some(tag_sha) = resolve_git_tag_commit(project_root, &entry.tag) {
            // If explicitly releasing the top changelog version (`entries[0]`) and its tag points to an older commit than HEAD:
            if target_tag_opt.is_some()
                && entry.tag == entries[0].tag
                && !head_sha.is_empty()
                && tag_sha != head_sha
            {
                return Err(format!(
                    "[SEMVER IMMUTABILITY VIOLATION]: Tag '{}' already exists at commit {}, which differs from current HEAD ({}). Never move or re-tag an existing release; bump VERSION and add a new CHANGELOG.md entry.",
                    entry.tag,
                    &tag_sha[..tag_sha.len().min(7)],
                    &head_sha[..head_sha.len().min(7)]
                )
                .into());
            }
        } else {
            let _ = Command::new("git")
                .args([
                    "-c",
                    "user.name=Antigravity",
                    "-c",
                    "user.email=antigravity@local.dev",
                    "tag",
                    "-a",
                    &entry.tag,
                    "-m",
                    &format!("{repo_name} {}", entry.tag),
                ])
                .current_dir(project_root)
                .output()?;
            created_any_tag = true;
        }
    }
    if created_any_tag || target_tag_opt.is_some() {
        for (rem_name, rem_url) in target_remotes {
            let mut tpush = cfg.git_auth_args_for_remote(rem_url);
            tpush.extend(["push".to_owned(), rem_name.clone(), "--tags".to_owned()]);
            let _ = Command::new("git")
                .args(&tpush)
                .current_dir(project_root)
                .output();
        }
    }

    // If any target remote is GitHub (`github.com`), also sync the release + assets via `gh release` when available
    let has_github_target = target_remotes
        .iter()
        .any(|(n, u)| n == "github" || u.to_ascii_lowercase().contains("github.com"));
    if has_github_target {
        for entry in &selected {
            publish_github_cli_release(project_root, &repo_name, entry);
        }
    }

    if cfg.user.is_empty() || cfg.token.is_empty() {
        return Ok(selected.iter().map(|e| e.tag.clone()).collect());
    }

    // Fetch existing Gitea releases
    let rels_url = format!(
        "{}/api/v1/repos/{}/{}/releases?limit=100",
        cfg.url, cfg.user, repo_name
    );
    let existing_rels: Vec<Value> = match http_request("GET", &rels_url, &cfg.token, None, None) {
        Ok((200, body)) => serde_json::from_slice(&body).unwrap_or_default(),
        _ => Vec::new(),
    };

    let branch = current_git_branch(project_root);
    let mut synced_tags = Vec::new();

    for entry in selected {
        let is_prerelease = entry.version.contains('-');
        let payload = json!({
            "tag_name": entry.tag,
            "target_commitish": branch,
            "name": format!("{repo_name} {}", entry.tag),
            "body": entry.body,
            "draft": false,
            "prerelease": is_prerelease,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        let existing_rel = existing_rels
            .iter()
            .find(|r| r.get("tag_name").and_then(Value::as_str) == Some(entry.tag.as_str()));

        let rel_obj: Option<Value> = if let Some(ex) = existing_rel {
            let rel_id = ex.get("id").and_then(Value::as_u64).unwrap_or(0);
            let patch_url = format!(
                "{}/api/v1/repos/{}/{}/releases/{rel_id}",
                cfg.url, cfg.user, repo_name
            );
            match http_request(
                "PATCH",
                &patch_url,
                &cfg.token,
                Some("application/json"),
                Some(&payload_bytes),
            ) {
                Ok((st, b)) if st == 200 || st == 201 => serde_json::from_slice(&b).ok(),
                _ => Some(ex.clone()),
            }
        } else {
            let post_url = format!("{}/api/v1/repos/{}/{}/releases", cfg.url, cfg.user, repo_name);
            match http_request(
                "POST",
                &post_url,
                &cfg.token,
                Some("application/json"),
                Some(&payload_bytes),
            ) {
                Ok((st, b)) if st == 200 || st == 201 => serde_json::from_slice(&b).ok(),
                _ => None,
            }
        };

        if let Some(robj) = rel_obj {
            if let Some(rel_id) = robj.get("id").and_then(Value::as_u64) {
                let existing_assets = robj
                    .get("assets")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let attached = attach_release_assets(
                    cfg,
                    &repo_name,
                    rel_id,
                    &entry.tag,
                    &existing_assets,
                    project_root,
                );
                if !attached.is_empty() {
                    println!(
                        "  [OK] Attached release assets ({} [{}]): {}",
                        entry.tag,
                        if entry.date.is_empty() { "undated" } else { &entry.date },
                        attached.join(", ")
                    );
                }
            }
            synced_tags.push(entry.tag.clone());
        }
    }

    Ok(synced_tags)
}

fn attach_release_assets(
    cfg: &GiteaConfig,
    repo_name: &str,
    rel_id: u64,
    tag: &str,
    existing_assets: &[Value],
    project_root: &Path,
) -> Vec<String> {
    let deliverables = discover_deliverable_files(project_root, tag);
    let mut uploaded = Vec::new();

    for file_path in deliverables {
        let Some(fname) = file_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(file_bytes) = fs::read(&file_path) else {
            continue;
        };

        // Replace existing asset of the same name if overwriting/updating release
        for ex in existing_assets {
            if ex.get("name").and_then(Value::as_str) == Some(fname) {
                if let Some(aid) = ex.get("id").and_then(Value::as_u64) {
                    let del_url = format!(
                        "{}/api/v1/repos/{}/{}/releases/{rel_id}/assets/{aid}",
                        cfg.url, cfg.user, repo_name
                    );
                    let _ = http_request("DELETE", &del_url, &cfg.token, None, None);
                }
            }
        }

        let boundary = format!("----LibreDBAssetBoundary{}", std::process::id());
        let content_type_inner = if fname.ends_with(".zip") || fname.ends_with(".whl") {
            "application/zip"
        } else {
            "application/octet-stream"
        };

        let mut body = Vec::with_capacity(file_bytes.len() + 512);
        write!(
            &mut body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{fname}\"\r\nContent-Type: {content_type_inner}\r\n\r\n"
        )
        .unwrap();
        body.extend_from_slice(&file_bytes);
        write!(&mut body, "\r\n--{boundary}--\r\n").unwrap();

        let up_url = format!(
            "{}/api/v1/repos/{}/{}/releases/{rel_id}/assets?name={}",
            cfg.url,
            cfg.user,
            repo_name,
            percent_encode(fname)
        );
        let mp_hdr = format!("multipart/form-data; boundary={boundary}");
        if let Ok((st, _)) = http_request("POST", &up_url, &cfg.token, Some(&mp_hdr), Some(&body)) {
            if st == 200 || st == 201 {
                uploaded.push(fname.to_owned());
            }
        }
    }
    uploaded
}

fn discover_deliverable_files(project_root: &Path, tag: &str) -> Vec<PathBuf> {
    let exts = [
        ".exe", ".msi", ".msix", ".zip", ".7z", ".tar.gz", ".whl", ".jar", ".apk", ".aab", ".vsix",
        ".xpi", ".deb", ".rpm", ".dmg",
    ];
    let mut found = Vec::new();
    for sub in ["dist", "releases"] {
        let dir = project_root.join(sub);
        if let Ok(rd) = fs::read_dir(&dir) {
            let mut entries: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|x| x.path()))
                .filter(|p| p.is_file())
                .filter(|p| {
                    let low = p.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
                    exts.iter().any(|ext| low.ends_with(ext))
                })
                .collect();
            entries.sort();
            found.extend(entries);
        }
    }
    let clean_ver = tag.trim_start_matches(['v', 'V']).to_ascii_lowercase();
    let tag_low = tag.to_ascii_lowercase();
    let tag_matched: Vec<PathBuf> = found
        .iter()
        .filter(|p| {
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
            n.contains(&tag_low) || (!clean_ver.is_empty() && n.contains(&clean_ver))
        })
        .cloned()
        .collect();
    if tag_matched.is_empty() {
        found
    } else {
        tag_matched
    }
}

pub fn parse_keep_a_changelog(path: &Path) -> std::io::Result<Vec<ChangelogEntry>> {
    let text = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    let mut curr_ver: Option<String> = None;
    let mut curr_date = String::new();
    let mut curr_lines: Vec<String> = Vec::new();

    let flush = |ver_opt: &mut Option<String>,
                 date: &mut String,
                 lines: &mut Vec<String>,
                 out: &mut Vec<ChangelogEntry>| {
        if let Some(v) = ver_opt.take() {
            let mut body = lines.join("\n").trim().to_owned();
            if !body.contains("keepachangelog.com") {
                body.push_str(
                    "\n\n---\n*Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).*",
                );
            }
            out.push(ChangelogEntry {
                tag: format!("v{v}"),
                version: v,
                date: std::mem::take(date),
                body,
            });
            lines.clear();
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("## [") {
            flush(&mut curr_ver, &mut curr_date, &mut curr_lines, &mut entries);
            if let Some(end_br) = rest.find(']') {
                let raw_v = rest[..end_br].trim_start_matches(['v', 'V']);
                if raw_v.split('.').count() >= 3
                    && raw_v.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    curr_ver = Some(raw_v.to_owned());
                    let after = rest[end_br + 1..].trim();
                    curr_date = after
                        .strip_prefix('-')
                        .map(|s| s.trim().to_owned())
                        .unwrap_or_default();
                    curr_lines.push(trimmed.to_owned());
                }
            }
        } else if trimmed.starts_with("## ") {
            flush(&mut curr_ver, &mut curr_date, &mut curr_lines, &mut entries);
        } else if curr_ver.is_some() {
            curr_lines.push(line.to_owned());
        }
    }
    flush(&mut curr_ver, &mut curr_date, &mut curr_lines, &mut entries);
    Ok(entries)
}

fn ensure_local_git_initialized(project_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if project_root.join(".git").exists() {
        ensure_git_safe_dir(project_root);
    }
    if !project_root.join(".git").join("HEAD").exists() {
        let init_out = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(project_root)
            .output()?;
        if !init_out.status.success() {
            let _ = Command::new("git")
                .arg("init")
                .current_dir(project_root)
                .output()?;
        }
        ensure_git_safe_dir(project_root);
    }
    let _ = Command::new("git")
        .args(["config", "user.name", "Antigravity"])
        .current_dir(project_root)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "antigravity@local.dev"])
        .current_dir(project_root)
        .output();
    Ok(())
}

fn ensure_git_safe_dir(project_root: &Path) {
    let chk = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(project_root)
        .output();
    if let Ok(out) = chk {
        if !out.status.success()
            && String::from_utf8_lossy(&out.stderr).contains("dubious ownership")
        {
            let posix = project_root.to_string_lossy().replace('\\', "/");
            let _ = Command::new("git")
                .args(["config", "--global", "--add", "safe.directory", &posix])
                .output();
        }
    }
}

fn workspace_has_semver_metadata(root: &Path) -> bool {
    root.join("VERSION").is_file()
        || root.join("CHANGELOG.md").is_file()
        || root.join("Cargo.toml").is_file()
        || root.join("pyproject.toml").is_file()
        || root.join("package.json").is_file()
}

fn current_git_branch(root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|b| !b.is_empty() && b != "HEAD")
        .unwrap_or_else(|| "main".to_owned())
}

fn resolve_repo_name_from_git_or_dir(root: &Path) -> String {
    if let Ok(out) = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(root)
        .output()
    {
        if out.status.success() {
            let u = String::from_utf8_lossy(&out.stdout).trim().trim_end_matches('/').to_owned();
            let u = u.strip_suffix(".git").unwrap_or(&u);
            if let Some(last) = u.rsplit('/').next() {
                if !last.is_empty() {
                    return last.to_owned();
                }
            }
        }
    }
    root.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace")
        .to_owned()
}

fn get_configured_gitea_url(root: &Path, base_url: &str) -> Option<String> {
    for (rem_name, rem_url) in list_git_remotes(root) {
        if rem_name == "gitea"
            || rem_url.contains("localhost:3000")
            || rem_url.contains("127.0.0.1:3000")
            || rem_url.starts_with(base_url)
        {
            return Some(rem_url.trim_end_matches(".git").to_owned());
        }
    }
    None
}

fn list_git_remotes(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(rem_out) = Command::new("git")
        .args(["remote"])
        .current_dir(root)
        .output()
    else {
        return out;
    };
    if !rem_out.status.success() {
        return out;
    }
    for name in String::from_utf8_lossy(&rem_out.stdout).lines() {
        let rem = name.trim();
        if rem.is_empty() {
            continue;
        }
        if let Ok(u_out) = Command::new("git")
            .args(["remote", "get-url", rem])
            .current_dir(root)
            .output()
        {
            if u_out.status.success() {
                let u = String::from_utf8_lossy(&u_out.stdout).trim().to_owned();
                if !u.is_empty() {
                    out.push((rem.to_owned(), u));
                }
            }
        }
    }
    out
}

fn select_target_remotes(
    remotes: &[(String, String)],
    target_remote_opt: Option<&str>,
    push_all_remotes: bool,
    push_github: bool,
) -> Vec<(String, String)> {
    if push_all_remotes {
        return remotes.to_vec();
    }
    if let Some(target_name) = target_remote_opt {
        return remotes
            .iter()
            .filter(|(n, _)| n == target_name)
            .cloned()
            .collect();
    }
    let mut selected = Vec::new();
    if let Some(orig) = remotes.iter().find(|(n, _)| n == "origin") {
        selected.push(orig.clone());
    } else if let Some(first) = remotes.first() {
        selected.push(first.clone());
    }
    if let Some(gt) = remotes.iter().find(|(n, _)| n == "gitea") {
        if !selected.iter().any(|(n, _)| n == &gt.0) {
            selected.push(gt.clone());
        }
    }
    if push_github {
        for r in remotes {
            if (r.0 == "github" || r.1.to_ascii_lowercase().contains("github.com"))
                && !selected.iter().any(|(n, _)| n == &r.0)
            {
                selected.push(r.clone());
            }
        }
    }
    selected
}

fn resolve_git_tag_commit(root: &Path, tag: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-list", "-n", "1", tag])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

fn resolve_git_head_commit(root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn publish_github_cli_release(project_root: &Path, repo_name: &str, entry: &ChangelogEntry) {
    let title = format!("{repo_name} {}", entry.tag);
    let deliverables = discover_deliverable_files(project_root, &entry.tag);
    let view_ok = Command::new("gh")
        .args(["release", "view", &entry.tag])
        .current_dir(project_root)
        .output()
        .is_ok_and(|o| o.status.success());

    if view_ok {
        let _ = Command::new("gh")
            .args([
                "release",
                "edit",
                &entry.tag,
                "--title",
                &title,
                "--notes",
                &entry.body,
            ])
            .current_dir(project_root)
            .output();
        for f in &deliverables {
            if let Some(fs_str) = f.to_str() {
                let _ = Command::new("gh")
                    .args(["release", "upload", &entry.tag, fs_str, "--clobber"])
                    .current_dir(project_root)
                    .output();
            }
        }
    } else {
        let mut create_args = vec![
            "release".to_owned(),
            "create".to_owned(),
            entry.tag.clone(),
            "--title".to_owned(),
            title,
            "--notes".to_owned(),
            entry.body.clone(),
        ];
        if entry.version.contains('-') {
            create_args.push("--prerelease".to_owned());
        }
        for f in &deliverables {
            if let Some(fs_str) = f.to_str() {
                create_args.push(fs_str.to_owned());
            }
        }
        let _ = Command::new("gh")
            .args(&create_args)
            .current_dir(project_root)
            .output();
    }
}

fn record_learned_workspace(ldb: &LibreDb, clean_root: &Path) {
    if let Some(name) = clean_root.file_name().and_then(|n| n.to_str()) {
        let key = format!("workspace:{name}");
        let val = clean_root.to_string_lossy().into_owned();
        let _ = ldb.put(
            WriteRequest::new(NodeKind::Config, val.into_bytes())
                .with_key(key)
                .with_importance(175),
        );
    }
}

fn strip_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        p.to_path_buf()
    }
}

fn query_service_state(service_name: &str) -> String {
    if cfg!(windows) {
        if let Ok(out) = Command::new("sc.exe").args(["query", service_name]).output() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for l in txt.lines() {
                if l.contains("STATE") {
                    if let Some(st) = l.split_whitespace().nth(3) {
                        return st.to_owned();
                    }
                }
            }
        }
    }
    "UNKNOWN".to_owned()
}

fn check_gitea_version(cfg: &GiteaConfig) -> Option<String> {
    let url = format!("{}/api/v1/version", cfg.url);
    let (status, body) = http_request("GET", &url, &cfg.token, None, None).ok()?;
    if status == 200 {
        let v: Value = serde_json::from_slice(&body).ok()?;
        v.get("version").and_then(Value::as_str).map(ToOwned::to_owned)
    } else {
        None
    }
}

fn list_remote_repos(cfg: &GiteaConfig) -> Vec<(String, String)> {
    if cfg.token.is_empty() {
        return Vec::new();
    }
    let url = if !cfg.user.is_empty() {
        format!("{}/api/v1/users/{}/repos?limit=100", cfg.url, cfg.user)
    } else {
        format!("{}/api/v1/user/repos?limit=100", cfg.url)
    };
    let Ok((200, body)) = http_request("GET", &url, &cfg.token, None, None) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_slice::<Vec<Value>>(&body) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = arr
        .into_iter()
        .filter_map(|r| {
            let fnm = r.get("full_name")?.as_str()?.to_owned();
            let hurl = r.get("html_url")?.as_str()?.to_owned();
            Some((fnm, hurl))
        })
        .collect();
    out.sort_by(|a, b| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()));
    out
}

fn inspect_remote_repo(
    cfg: &GiteaConfig,
    repo_name: &str,
) -> Option<(bool, bool, String, String)> {
    let url = format!("{}/api/v1/repos/{}/{}", cfg.url, cfg.user, repo_name);
    match http_request("GET", &url, &cfg.token, None, None) {
        Ok((200, body)) => {
            let v: Value = serde_json::from_slice(&body).ok()?;
            let empty = v.get("empty").and_then(Value::as_bool).unwrap_or(false);
            let html = v
                .get("html_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let clone = v
                .get("clone_url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            Some((true, empty, html, clone))
        }
        Ok((404, _)) => Some((false, true, String::new(), String::new())),
        _ => None,
    }
}

fn ensure_remote_repo_created(
    cfg: &GiteaConfig,
    repo_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some((true, _, _, clone_url)) = inspect_remote_repo(cfg, repo_name) {
        if !clone_url.is_empty() {
            return Ok(clone_url);
        }
    }
    let payload = json!({
        "name": repo_name,
        "description": format!("Antigravity workspace {repo_name}"),
        "private": true,
        "auto_init": false,
        "default_branch": "main",
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let post_url = format!("{}/api/v1/user/repos", cfg.url);
    let (st, body) = http_request(
        "POST",
        &post_url,
        &cfg.token,
        Some("application/json"),
        Some(&payload_bytes),
    )?;
    if st == 200 || st == 201 {
        let v: Value = serde_json::from_slice(&body)?;
        if let Some(c) = v.get("clone_url").and_then(Value::as_str) {
            return Ok(c.to_owned());
        }
    }
    Ok(format!("{}/{}/{repo_name}.git", cfg.url, cfg.user))
}

/// Minimal, dependency-free HTTP/1.1 client over `std::net::TcpStream` for local/LAN Gitea API calls.
fn http_request(
    method: &str,
    url: &str,
    token: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> std::io::Result<(u16, Vec<u8>)> {
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "only http:// supported"))?;
    let (host_port, path_query) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };
    let addr_str = if host_port.contains(':') {
        host_port.to_owned()
    } else {
        format!("{host_port}:80")
    };
    let sock_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "unable to resolve host"))?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let payload = body.unwrap_or(&[]);
    let mut req_hdr = format!(
        "{method} {path_query} HTTP/1.1\r\nHost: {host_port}\r\nUser-Agent: LibreDB-GiteaSync/1.0\r\nConnection: close\r\n"
    );
    if !token.is_empty() {
        req_hdr.push_str(&format!("Authorization: token {token}\r\n"));
    }
    if let Some(ct) = content_type {
        req_hdr.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if !payload.is_empty() || matches!(method, "POST" | "PATCH" | "PUT") {
        req_hdr.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req_hdr.push_str("\r\n");

    stream.write_all(req_hdr.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    stream.flush()?;

    let mut raw_resp = Vec::new();
    stream.read_to_end(&mut raw_resp)?;

    let Some(hdr_end) = find_double_crlf(&raw_resp) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed HTTP response headers",
        ));
    };
    let hdr_text = String::from_utf8_lossy(&raw_resp[..hdr_end]);
    let status_line = hdr_text.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);

    let is_chunked = hdr_text
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));

    let raw_body = &raw_resp[hdr_end + 4..];
    let decoded_body = if is_chunked {
        decode_chunked_body(raw_body)
    } else {
        raw_body.to_vec()
    };

    Ok((status_code, decoded_body))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn decode_chunked_body(mut src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = src.windows(2).position(|w| w == b"\r\n") {
        let len_str = String::from_utf8_lossy(&src[..pos]);
        let hex_part = len_str.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        if chunk_len == 0 {
            break;
        }
        let data_start = pos + 2;
        if data_start + chunk_len > src.len() {
            out.extend_from_slice(&src[data_start..]);
            break;
        }
        out.extend_from_slice(&src[data_start..data_start + chunk_len]);
        let next_pos = data_start + chunk_len + 2;
        if next_pos > src.len() {
            break;
        }
        src = &src[next_pos..];
    }
    out
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
