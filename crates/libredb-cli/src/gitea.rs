//! Native Rust Gitea workflow automation (`gitea-status`, `gitea-config`, `gitea-init`,
//! `gitea-sync`, `gitea-release`, `gitea-credential-helper`) backed by `customizations.ldb`.
//!
//! Uses a self-contained `std::net::TcpStream` HTTP/1.1 client for zero external TLS/HTTP crate bloat,
//! transient in-memory Git `Authorization: Basic` headers (never storing plaintext tokens in `.git/config`),
//! and strict SemVer 2.0.0 + Keep a Changelog 1.1.0 + `[GITEA REPOSITORY COLLISION]` guardrails.

use crate::hooks::open_global_ldb;
use crate::security::{base64_encode, protect_secret, unprotect_secret};
use libredb_cognitive::{
    audit_workspace_guardrails_with_prefixes, index_workspace, is_sensitive_staged_file,
    CognitiveEngine,
};
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
    pub allow_insecure_http: bool,
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

        let token = if let Some(env_tok) = env::var("SKILLSDB_GITEA_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
        {
            env_tok.trim().to_owned()
        } else if let Some(raw_stored) = get_cfg("gitea_token") {
            match unprotect_secret(&raw_stored) {
                Ok((plain, needs_upgrade)) => {
                    if needs_upgrade && !plain.is_empty() {
                        if let Ok(encrypted) = protect_secret(&plain) {
                            let _ = ldb.put(
                                WriteRequest::new(NodeKind::Config, encrypted.into_bytes())
                                    .with_key("gitea_token")
                                    .with_importance(190),
                            );
                        }
                    }
                    plain
                }
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };

        let service_name = env::var("SKILLSDB_GITEA_SERVICE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_service"))
            .unwrap_or_else(|| "gitea".to_owned());

        let allow_insecure_http = env::var("SKILLSDB_GITEA_ALLOW_INSECURE_HTTP")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| get_cfg("gitea_allow_insecure_http"))
            .map(|v| {
                let low = v.trim().to_ascii_lowercase();
                matches!(low.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);

        Self {
            url,
            user,
            token,
            service_name,
            allow_insecure_http,
        }
    }

    pub fn is_gitea_remote_url(&self, remote_url: &str) -> bool {
        let low = remote_url.trim().trim_end_matches('/').to_ascii_lowercase();
        let cfg_low = self.url.trim().trim_end_matches('/').to_ascii_lowercase();
        if !cfg_low.is_empty() && (low == cfg_low || low.starts_with(&format!("{cfg_low}/"))) {
            return true;
        }
        if is_loopback_http_url(&cfg_low) && is_loopback_http_url(&low) {
            return extract_url_port(&cfg_low) == extract_url_port(&low);
        }
        false
    }

    pub fn allows_credentials_for_url(&self, target_url: &str) -> bool {
        if !self.is_gitea_remote_url(target_url) {
            return false;
        }
        let low = target_url.trim().to_ascii_lowercase();
        if low.starts_with("https://") {
            true
        } else if low.starts_with("http://") {
            is_loopback_http_url(&low) || self.allow_insecure_http
        } else {
            false
        }
    }

    /// Injects transient Basic Auth (and Windows Schannel TLS backend for `https://` Gitea hosts)
    /// exclusively via child-process `GIT_CONFIG_*` environment variables when `remote_url` matches
    /// the configured Gitea server and satisfies transport security policy (`https://`, loopback `http://`,
    /// or explicit `gitea_allow_insecure_http=true`).
    pub fn configure_git_command_for_remote(&self, cmd: &mut Command, remote_url: &str) {
        if !self.allows_credentials_for_url(remote_url) {
            return;
        }
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if !self.user.is_empty() && !self.token.is_empty() {
            let b64 = base64_encode(format!("{}:{}", self.user, self.token).as_bytes());
            pairs.push(("http.extraHeader", format!("Authorization: Basic {b64}")));
        }
        if cfg!(windows) && remote_url.trim().to_ascii_lowercase().starts_with("https://") {
            pairs.push(("http.sslBackend", "schannel".to_owned()));
        }
        if !pairs.is_empty() {
            cmd.env("GIT_CONFIG_COUNT", pairs.len().to_string());
            for (idx, (k, v)) in pairs.into_iter().enumerate() {
                cmd.env(format!("GIT_CONFIG_KEY_{idx}"), k);
                cmd.env(format!("GIT_CONFIG_VALUE_{idx}"), v);
            }
        }
    }
}

pub fn is_loopback_http_url(url: &str) -> bool {
    let low = url.trim().to_ascii_lowercase();
    let Some(rest) = low.strip_prefix("http://") else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn extract_url_port(url: &str) -> u16 {
    let low = url.trim().to_ascii_lowercase();
    let default_port = if low.starts_with("https://") { 443 } else { 80 };
    let rest = low
        .strip_prefix("https://")
        .or_else(|| low.strip_prefix("http://"))
        .unwrap_or(&low);
    let host_port = rest.split('/').next().unwrap_or("");
    if let Some(after_bracket) = host_port.strip_prefix('[') {
        if let Some((_, tail)) = after_bracket.split_once(']') {
            if let Some(p_str) = tail.strip_prefix(':') {
                if let Ok(p) = p_str.parse::<u16>() {
                    return p;
                }
            }
        }
        return default_port;
    }
    if let Some((_, p_str)) = host_port.rsplit_once(':') {
        if let Ok(p) = p_str.parse::<u16>() {
            return p;
        }
    }
    default_port
}

fn should_supply_git_credentials(cfg: &GiteaConfig, git_stdin: &str) -> bool {
    let mut proto = "";
    let mut host = "";
    for line in git_stdin.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(p) = trimmed.strip_prefix("protocol=") {
            proto = p.trim();
        } else if let Some(h) = trimmed.strip_prefix("host=") {
            host = h.trim();
        }
    }
    if proto.is_empty() || host.is_empty() {
        return false;
    }
    let candidate = format!("{proto}://{host}");
    cfg.allows_credentials_for_url(&candidate)
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
    let mut stdin_buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    if action != "get" {
        return Ok(());
    }
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    if !cfg.user.is_empty()
        && !cfg.token.is_empty()
        && should_supply_git_credentials(&cfg, &stdin_buf)
    {
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
    allow_insecure_http: Option<bool>,
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
        let trimmed_tok = tok.trim();
        if trimmed_tok.is_empty() {
            let _ = ldb.deprecate_key(NodeKind::Config, "gitea_token");
        } else {
            let encrypted = protect_secret(trimmed_tok)?;
            ldb.put(
                WriteRequest::new(NodeKind::Config, encrypted.into_bytes())
                    .with_key("gitea_token")
                    .with_importance(190),
            )?;
        }
    }
    if let Some(allow_http) = allow_insecure_http {
        let val = if allow_http { "true" } else { "false" };
        ldb.put(
            WriteRequest::new(NodeKind::Config, val.as_bytes().to_vec())
                .with_key("gitea_allow_insecure_http")
                .with_importance(190),
        )?;
    }

    let cfg = GiteaConfig::load(&ldb);
    if register_helper {
        if let Ok(exe) = env::current_exe() {
            let exe_fwd = exe.to_string_lossy().replace('\\', "/");
            let helper_cmd = format!("!\"{exe_fwd}\" gitea-credential-helper");
            let mut endpoints = vec![cfg.url.clone()];
            if is_loopback_http_url(&cfg.url) {
                let port = extract_url_port(&cfg.url);
                for host in ["127.0.0.1", "localhost"] {
                    let ep = if port == 80 {
                        format!("http://{host}")
                    } else {
                        format!("http://{host}:{port}")
                    };
                    if !endpoints.iter().any(|x| x.eq_ignore_ascii_case(&ep)) {
                        endpoints.push(ep);
                    }
                }
            }
            for ep in endpoints {
                let _ = Command::new("git")
                    .args(["config", "--global", &format!("credential.{ep}.helper"), &helper_cmd])
                    .output();
            }
        }
    }

    let masked = if cfg.token.len() > 10 {
        format!(
            "{}...{} (OS vault encrypted)",
            &cfg.token[..4],
            &cfg.token[cfg.token.len() - 4..]
        )
    } else if !cfg.token.is_empty() {
        "(set, OS vault encrypted)".to_owned()
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
    println!("Allow Remote HTTP:  {}", cfg.allow_insecure_http);
    println!("============================================================");
    Ok(())
}

pub fn cmd_gitea_status(global_opt: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    let mut svc_state = query_service_state(&cfg.service_name);
    let mut ver_opt = check_gitea_version(&cfg);

    #[cfg(windows)]
    if (ver_opt.is_none() || svc_state == "STOPPED") && is_loopback_http_url(&cfg.url) {
        let _ = Command::new("sc.exe").args(["start", &cfg.service_name]).output();
        std::thread::sleep(Duration::from_millis(900));
        svc_state = query_service_state(&cfg.service_name);
        ver_opt = check_gitea_version(&cfg);
    }
    #[cfg(not(windows))]
    let _ = &mut svc_state;

    let svc_label = if cfg!(windows) {
        "Windows Service:"
    } else {
        "System Service: "
    };

    println!("============================================================");
    println!("LibreDB - Gitea Integration Status");
    println!("============================================================");
    println!("{svc_label}  {} ({svc_state})", cfg.service_name);
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
                    cfg.allow_insecure_http,
                    None,
                    None,
                );
            }
        }
    }

    ensure_local_git_initialized(&clean_root, Some(&ldb))?;

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
    let proj_ldb_path = clean_root.join(".agents").join("memory.ldb");
    if proj_ldb_path.is_file() {
        if let Ok(pdb) = LibreDb::open(&proj_ldb_path) {
            let _ = crate::security::seal_workspace_memory(&ldb, &pdb, &clean_root);
        }
    }
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

    ensure_local_git_initialized(&clean_root, Some(&ldb))?;

    let mut proj_db_opt: Option<Arc<LibreDb>> = None;
    let proj_ldb_path = clean_root.join(".agents").join("memory.ldb");
    if proj_ldb_path.is_file()
        && crate::security::is_workspace_memory_trusted(Some(&ldb), &clean_root)
    {
        if let Ok(pdb) = LibreDb::open(&proj_ldb_path) {
            let pdb = Arc::new(pdb);
            let _ = crate::security::seal_workspace_memory(&ldb, &pdb, &clean_root);
            if let Ok(rep) = index_workspace(&pdb, &clean_root, false) {
                if rep.files_reindexed > 0 {
                    if let Ok(mut cog) = CognitiveEngine::open_db(Arc::clone(&pdb)) {
                        let _ = cog.save_index_snapshot();
                    }
                }
            }
            proj_db_opt = Some(pdb);
        }
    }
    record_learned_workspace(&ldb, &clean_root);

    let custom_prefixes = crate::security::load_config_list(
        Some(&ldb),
        proj_db_opt.as_deref(),
        "guardrail:secret_prefixes",
    );
    let allowed_staged = crate::security::load_config_list(
        Some(&ldb),
        proj_db_opt.as_deref(),
        "guardrail:allow_staged_files",
    );

    let _ = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "add", "-A"])
        .current_dir(&clean_root)
        .output()?;

    // Sensitive Staged-File Firewall: prevent `.agents/*`, `.env`, private keys, or DPAPI
    // `.credential.xml` files from ever being committed or pushed to Gitea/GitHub.
    let staged_out = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "diff", "--cached", "--name-only"])
        .current_dir(&clean_root)
        .output()?;
    if staged_out.status.success() {
        for raw_line in String::from_utf8_lossy(&staged_out.stdout).lines() {
            let rel = raw_line.trim();
            if rel.is_empty() {
                continue;
            }
            if let Some(reason) = is_sensitive_staged_file(rel, &allowed_staged) {
                let norm_rel = rel.replace('\\', "/");
                if norm_rel == ".agents" || norm_rel.starts_with(".agents/") {
                    let _ = Command::new("git")
                        .args(["-c", "core.fsmonitor=false", "rm", "-r", "--cached", "--quiet", "--", rel])
                        .current_dir(&clean_root)
                        .output();
                    continue;
                }
                return Err(format!(
                    "[SENSITIVE FILE STAGED]: Refusing to commit or push sensitive file '{}' ({reason}). Unstage/ignore it, or if it is an intentional non-secret fixture, authorize it via: libredb config set guardrail:allow_staged_files \"{}\" --project \"{}\"",
                    rel,
                    rel,
                    clean_root.display()
                )
                .into());
            }
        }
    }

    let audit =
        audit_workspace_guardrails_with_prefixes(&clean_root, true, &custom_prefixes)?;
    if !audit.passed(false) {
        let first = &audit.violations[0];
        return Err(format!(
            "Guardrail audit blocked git-sync ({} in {}:L{}): {}",
            first.rule, first.file, first.line, first.message
        )
        .into());
    }

    let st_out = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "status", "--porcelain"])
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
        let mut push_cmd = Command::new("git");
        cfg.configure_git_command_for_remote(&mut push_cmd, rem_url);
        let p_out = push_cmd
            .args(["push", "-u", rem_name, &branch])
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
            let mut tpush_cmd = Command::new("git");
            cfg.configure_git_command_for_remote(&mut tpush_cmd, rem_url);
            let _ = tpush_cmd
                .args(["push", rem_name, "--tags"])
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
    let existing_rels: Vec<Value> =
        match http_request("GET", &rels_url, &cfg.token, cfg.allow_insecure_http, None, None) {
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
                cfg.allow_insecure_http,
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
                cfg.allow_insecure_http,
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
                    let _ = http_request(
                        "DELETE",
                        &del_url,
                        &cfg.token,
                        cfg.allow_insecure_http,
                        None,
                        None,
                    );
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
        if let Ok((st, _)) = http_request(
            "POST",
            &up_url,
            &cfg.token,
            cfg.allow_insecure_http,
            Some(&mp_hdr),
            Some(&body),
        ) {
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

fn ensure_local_git_initialized(
    project_root: &Path,
    global_db: Option<&LibreDb>,
) -> Result<(), Box<dyn std::error::Error>> {
    if project_root.join(".git").exists() {
        ensure_git_safe_dir(project_root, global_db);
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
        ensure_git_safe_dir(project_root, global_db);
    }
    ensure_git_info_exclude(project_root);
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

fn ensure_git_info_exclude(project_root: &Path) {
    let info_dir = project_root.join(".git").join("info");
    if !info_dir.is_dir() && fs::create_dir_all(&info_dir).is_err() {
        return;
    }
    let exclude_path = info_dir.join("exclude");
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    let mut missing = Vec::new();
    for rule in ["/.agents/", "*.tmp.ldb", "*.credential.xml"] {
        if !existing.lines().any(|l| l.trim() == rule) {
            missing.push(rule);
        }
    }
    if !missing.is_empty() {
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        for rule in missing {
            updated.push_str(rule);
            updated.push('\n');
        }
        let _ = fs::write(&exclude_path, updated);
    }
}

fn ensure_git_safe_dir(project_root: &Path, global_db: Option<&LibreDb>) {
    if !crate::security::is_safe_auto_git_dir(global_db, project_root) {
        return;
    }
    let chk = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "rev-parse", "--git-dir"])
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
        .args(["-c", "core.fsmonitor=false", "rev-parse", "--abbrev-ref", "HEAD"])
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
        .args(["-c", "core.fsmonitor=false", "remote", "get-url", "origin"])
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
    let base_low = base_url.trim().trim_end_matches('/').to_ascii_lowercase();
    for (rem_name, rem_url) in list_git_remotes(root) {
        let low = rem_url.trim().to_ascii_lowercase();
        if rem_name == "gitea"
            || (!base_low.is_empty() && (low == base_low || low.starts_with(&format!("{base_low}/"))))
            || (is_loopback_http_url(&base_low)
                && is_loopback_http_url(&low)
                && extract_url_port(&base_low) == extract_url_port(&low))
        {
            return Some(rem_url.trim_end_matches(".git").to_owned());
        }
    }
    None
}

fn list_git_remotes(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(rem_out) = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "remote"])
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
            .args(["-c", "core.fsmonitor=false", "remote", "get-url", rem])
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
        .args(["-c", "core.fsmonitor=false", "rev-list", "-n", "1", tag])
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
        .args(["-c", "core.fsmonitor=false", "rev-parse", "HEAD"])
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
            WriteRequest::new(NodeKind::Config, val.clone().into_bytes())
                .with_key(key)
                .with_importance(175),
        );
        let norm = crate::security::normalize_workspace_key(clean_root);
        let _ = ldb.put(
            WriteRequest::new(NodeKind::Config, val.into_bytes())
                .with_key(format!("trust:allowed::{norm}"))
                .with_importance(185),
        );
    }
}

pub fn strip_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s.len() >= 8 && s[..8].eq_ignore_ascii_case(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", &s[8..]));
    }
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
        return "UNKNOWN".to_owned();
    }
    if cfg!(unix) {
        for extra_flag in [None, Some("--user")] {
            let mut cmd = Command::new("systemctl");
            if let Some(flag) = extra_flag {
                cmd.arg(flag);
            }
            if let Ok(out) = cmd.args(["is-active", service_name]).output() {
                let state = String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase();
                match state.as_str() {
                    "active" | "activating" => return "RUNNING".to_owned(),
                    "inactive" | "failed" | "deactivating" => return "STOPPED".to_owned(),
                    _ => {}
                }
            }
        }
    }
    "N/A".to_owned()
}

fn check_gitea_version(cfg: &GiteaConfig) -> Option<String> {
    let url = format!("{}/api/v1/version", cfg.url);
    let (status, body) =
        http_request("GET", &url, &cfg.token, cfg.allow_insecure_http, None, None).ok()?;
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
    let Ok((200, body)) =
        http_request("GET", &url, &cfg.token, cfg.allow_insecure_http, None, None)
    else {
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
    match http_request("GET", &url, &cfg.token, cfg.allow_insecure_http, None, None) {
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
        cfg.allow_insecure_http,
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

/// Minimal, dependency-free HTTP/1.1 client over `std::net::TcpStream` for local loopback `http://`
/// Gitea API calls, with automatic native OS `curl` (`System32\curl.exe` Schannel / POSIX `curl`)
/// fallback for `https://`. Refuses to transmit tokens over remote cleartext `http://` unless
/// `allow_insecure_http` is explicitly enabled.
fn http_request(
    method: &str,
    url: &str,
    token: &str,
    allow_insecure_http: bool,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> std::io::Result<(u16, Vec<u8>)> {
    if url.starts_with("https://") {
        return https_request_via_system_curl(method, url, token, content_type, body);
    }
    if !token.is_empty() && !is_loopback_http_url(url) && !allow_insecure_http {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to transmit Gitea API token over unencrypted non-loopback http:// connection; configure an https:// URL or set 'libredb config set gitea_allow_insecure_http true'",
        ));
    }
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "only http:// or https:// supported"))?;
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
    parse_http_response(&raw_resp)
}

fn parse_http_response(mut resp: &[u8]) -> std::io::Result<(u16, Vec<u8>)> {
    loop {
        let Some(hdr_end) = find_double_crlf(resp) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP response headers",
            ));
        };
        let hdr_text = String::from_utf8_lossy(&resp[..hdr_end]);
        let status_line = hdr_text.lines().next().unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);

        // Skip interim `1xx` frames (such as `HTTP/1.1 100 Continue\r\n\r\n` on multipart uploads).
        if (100..200).contains(&status_code) && status_code != 101 {
            resp = &resp[hdr_end + 4..];
            continue;
        }

        let is_chunked = hdr_text.lines().any(|l| {
            let low = l.to_ascii_lowercase();
            low.starts_with("transfer-encoding:") && low.contains("chunked")
        });

        let raw_body = &resp[hdr_end + 4..];
        let decoded_body = if is_chunked {
            decode_chunked_body(raw_body)
        } else {
            raw_body.to_vec()
        };

        return Ok((status_code, decoded_body));
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn format_curl_auth_header_line(token: &str) -> String {
    let sanitized: String = token
        .chars()
        .filter(|&c| c != '\r' && c != '\n')
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            other => vec![other],
        })
        .collect();
    format!("header = \"Authorization: token {sanitized}\"\n")
}

struct EphemeralCurlConfig {
    path: PathBuf,
    byte_len: usize,
}

impl EphemeralCurlConfig {
    fn create_with_token(token: &str) -> std::io::Result<Self> {
        let base_dir = crate::hooks::user_home_dir().join(".gemini").join("libredb");
        let dir = if fs::create_dir_all(&base_dir).is_ok() {
            base_dir
        } else {
            env::temp_dir()
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let cfg_path = dir.join(format!(".curl_hdr_{}_{stamp}.cfg", std::process::id()));
        let content = format_curl_auth_header_line(token);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
            opts.attributes(FILE_ATTRIBUTE_TEMPORARY);
        }
        let mut f = opts.open(&cfg_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(content.as_bytes())?;
        f.flush()?;
        Ok(Self {
            path: cfg_path,
            byte_len: content.len(),
        })
    }
}

impl Drop for EphemeralCurlConfig {
    fn drop(&mut self) {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&self.path) {
            let zeros = vec![0u8; self.byte_len.max(64)];
            let _ = f.write_all(&zeros);
            let _ = f.flush();
        }
        let _ = fs::remove_file(&self.path);
    }
}

/// Executes an `https://` API call via the OS-native `curl` binary (`C:\Windows\System32\curl.exe` on Windows,
/// which natively uses Windows Schannel and trusts Active Directory GPO Enterprise Root CAs).
/// Enforces `--proto =https`, disables cross-origin redirect auth leaks (no `--location`), pipes `-K -`
/// over `stdin` with zero disk writes when `body.is_none()`, and falls back to `FILE_ATTRIBUTE_TEMPORARY`
/// RAII-wiped `EphemeralCurlConfig` only when `stdin` carries a request body.
fn https_request_via_system_curl(
    method: &str,
    url: &str,
    token: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> std::io::Result<(u16, Vec<u8>)> {
    use std::process::Stdio;

    let curl_bin = if cfg!(windows) {
        let sys_curl = Path::new(r"C:\Windows\System32\curl.exe");
        if sys_curl.is_file() {
            r"C:\Windows\System32\curl.exe"
        } else {
            "curl.exe"
        }
    } else {
        "curl"
    };

    let pipe_auth_over_stdin = !token.is_empty() && body.is_none();
    let auth_cfg_guard = if !token.is_empty() && body.is_some() {
        Some(EphemeralCurlConfig::create_with_token(token)?)
    } else {
        None
    };

    let marker = "\n__LIBREDB_HTTP_STATUS__:";
    let mut cmd = Command::new(curl_bin);
    cmd.args([
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-time",
        "30",
        "-X",
        method,
        "-H",
        "User-Agent: LibreDB-GiteaSync/1.0",
    ]);
    if pipe_auth_over_stdin {
        cmd.args(["-K", "-"]);
    } else if let Some(ref guard) = auth_cfg_guard {
        cmd.arg("-K").arg(&guard.path);
    }
    if let Some(ct) = content_type {
        cmd.args(["-H", &format!("Content-Type: {ct}")]);
    }
    if body.is_some() {
        cmd.args(["--data-binary", "@-"]);
        cmd.stdin(Stdio::piped());
    } else if pipe_auth_over_stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.args(["-w", &format!("{marker}%{{http_code}}"), url]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(payload) = body {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            stdin_pipe.write_all(payload)?;
        }
    } else if pipe_auth_over_stdin {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            let mut line_bytes = format_curl_auth_header_line(token).into_bytes();
            let write_res = stdin_pipe.write_all(&line_bytes);
            for b in line_bytes.iter_mut() {
                *b = 0;
            }
            write_res?;
        }
    }
    let out = child.wait_with_output()?;
    drop(auth_cfg_guard);
    if !out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "curl https request failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }

    let m_bytes = marker.as_bytes();
    if let Some(pos) = out
        .stdout
        .windows(m_bytes.len())
        .rposition(|w| w == m_bytes)
    {
        let body_part = out.stdout[..pos].to_vec();
        let code_str = String::from_utf8_lossy(&out.stdout[pos + m_bytes.len()..]);
        let status = code_str.trim().parse::<u16>().unwrap_or(500);
        Ok((status, body_part))
    } else {
        Ok((200, out.stdout))
    }
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

#[cfg(test)]
mod tests {
    use super::{
        http_request, parse_http_response, should_supply_git_credentials, strip_verbatim_prefix,
        GiteaConfig,
    };
    use std::path::{Path, PathBuf};
    use std::process::Command;

    #[test]
    fn strip_verbatim_prefix_preserves_unc_and_drive_paths() {
        assert_eq!(
            strip_verbatim_prefix(Path::new(
                r"\\?\UNC\fileserver.corp.example\home$\user\Antigravity\LibreDB"
            )),
            PathBuf::from(r"\\fileserver.corp.example\home$\user\Antigravity\LibreDB")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(
                r"\\?\unc\fileserver.corp.example\share\workspace"
            )),
            PathBuf::from(r"\\fileserver.corp.example\share\workspace")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\D:\Antigravity\LibreDB")),
            PathBuf::from(r"D:\Antigravity\LibreDB")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"Q:\Antigravity\LibreDB")),
            PathBuf::from(r"Q:\Antigravity\LibreDB")
        );
    }

    #[test]
    fn git_remote_auth_uses_env_only_blocks_domain_spoof_and_remote_cleartext_http() {
        let cfg = GiteaConfig {
            url: "https://git.corp.example".to_owned(),
            user: "ci_bot".to_owned(),
            token: "test_placeholder_tok".to_owned(),
            service_name: "gitea".to_owned(),
            allow_insecure_http: false,
        };

        let mut gitea_cmd = Command::new("git");
        cfg.configure_git_command_for_remote(&mut gitea_cmd, "https://git.corp.example/org/repo.git");
        assert_eq!(
            gitea_cmd.get_args().count(),
            0,
            "credentials must never be passed as command-line arguments"
        );
        let envs: Vec<(String, String)> = gitea_cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v?.to_str()?.to_owned())))
            .collect();
        assert!(envs.iter().any(|(k, _)| k == "GIT_CONFIG_COUNT"));
        assert!(envs
            .iter()
            .any(|(k, v)| k.starts_with("GIT_CONFIG_KEY_") && v == "http.extraHeader"));
        if cfg!(windows) {
            assert!(envs
                .iter()
                .any(|(k, v)| k.starts_with("GIT_CONFIG_VALUE_") && v == "schannel"));
        }

        // Subdomain-prefix spoofing (`git.corp.example.evil.org`) and GitHub must receive ZERO auth envs!
        for untrusted_url in [
            "https://github.com/org/repo.git",
            "https://git.corp.example.attacker.example/org/repo.git",
        ] {
            let mut ext_cmd = Command::new("git");
            cfg.configure_git_command_for_remote(&mut ext_cmd, untrusted_url);
            assert_eq!(ext_cmd.get_envs().count(), 0);
            assert_eq!(ext_cmd.get_args().count(), 0);
        }

        // Credential helper must verify stdin `protocol` + `host` and reject empty or non-matching hosts!
        assert!(!should_supply_git_credentials(&cfg, ""));
        assert!(!should_supply_git_credentials(
            &cfg,
            "protocol=https\nhost=github.com\n\n"
        ));
        assert!(should_supply_git_credentials(
            &cfg,
            "protocol=https\nhost=git.corp.example\n\n"
        ));

        // Non-loopback cleartext `http://` must refuse transmitting API tokens unless explicitly opted in!
        let http_err = http_request(
            "GET",
            "http://git.corp.example:3000/api/v1/version",
            "secret_tok",
            false,
            None,
            None,
        );
        assert!(http_err.is_err());
    }

    #[test]
    fn parse_http_response_skips_100_continue_frames() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":42}";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 201);
        assert_eq!(body, b"{\"id\":42}");
    }
}
