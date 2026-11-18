//! Native Rust Gitea workflow automation (`gitea-status`, `gitea-config`, `gitea-init`,
//! `gitea-sync`, `gitea-release`, `gitea-credential-helper`) backed by `customizations.ldb`.
//!
//! Uses a self-contained `std::net::TcpStream` HTTP/1.1 client for zero external TLS/HTTP crate bloat,
//! transient in-memory Git `Authorization: Basic` headers (never storing plaintext tokens in `.git/config`),
//! and strict SemVer 2.0.0 + Keep a Changelog 1.1.0 + `[GITEA REPOSITORY COLLISION]` guardrails.

use crate::hooks::open_global_ldb;
use crate::security::{base64_encode, protect_secret, strip_verbatim_prefix, unprotect_secret};
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
        Self::load_with_lookup(ldb, |k| env::var(k).ok())
    }

    fn load_with_lookup(ldb: &LibreDb, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let get_cfg = |k: &str| -> Option<String> {
            ldb.get_by_key(NodeKind::Config, k)
                .ok()
                .map(|r| String::from_utf8_lossy(&r.payload).trim().to_owned())
                .filter(|s| !s.is_empty())
        };

        let get_env = |primary: &str, legacy: &str| -> Option<String> {
            lookup(primary)
                .filter(|s| !s.trim().is_empty())
                .or_else(|| lookup(legacy).filter(|s| !s.trim().is_empty()))
        };

        let url = get_env("LIBREDB_GITEA_URL", "SKILLSDB_GITEA_URL")
            .or_else(|| get_cfg("gitea_url"))
            .unwrap_or_else(|| "http://127.0.0.1:3000".to_owned())
            .trim_end_matches('/')
            .to_owned();

        let user = get_env("LIBREDB_GITEA_USER", "SKILLSDB_GITEA_USER")
            .or_else(|| get_cfg("gitea_user"))
            .unwrap_or_default();

        let token = if let Some(env_tok) = get_env("LIBREDB_GITEA_TOKEN", "SKILLSDB_GITEA_TOKEN") {
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

        let service_name = get_env("LIBREDB_GITEA_SERVICE", "SKILLSDB_GITEA_SERVICE")
            .or_else(|| get_cfg("gitea_service"))
            .unwrap_or_else(|| "gitea".to_owned());

        let allow_insecure_http = get_env(
            "LIBREDB_GITEA_ALLOW_INSECURE_HTTP",
            "SKILLSDB_GITEA_ALLOW_INSECURE_HTTP",
        )
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

pub(crate) fn validate_safe_git_identifier(val: &str, kind: &str) -> Result<(), String> {
    let t = val.trim();
    if t.is_empty() {
        return Err(format!("{kind} must not be empty"));
    }
    if t.starts_with('-') || t.starts_with('.') {
        return Err(format!(
            "Refusing {kind} '{t}' starting with '-' or '.' (potential Git CLI option or hidden-ref injection)"
        ));
    }
    if t.ends_with(".lock") || t.ends_with('/') || t.ends_with('.') {
        return Err(format!(
            "Refusing {kind} '{t}' with unsafe trailing '.lock', '/', or '.'"
        ));
    }
    if t.contains("..")
        || t.contains("//")
        || t.contains("@{")
        || t.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '\\' | ':' | '?' | '*' | '[' | '~' | '^')
        })
    {
        return Err(format!(
            "Refusing unsafe {kind} '{t}' violating git-check-ref-format character invariants"
        ));
    }
    Ok(())
}

fn ensure_no_http_header_chars(val: &str, field: &str) -> Result<(), String> {
    if val.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return Err(format!(
            "Refusing {field} containing CR/LF/NUL header-injection characters"
        ));
    }
    Ok(())
}

fn should_supply_git_credentials(cfg: &GiteaConfig, git_stdin: &str) -> bool {
    let mut proto = "";
    let mut host = "";
    let mut path_part = "";
    for line in git_stdin.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(p) = trimmed.strip_prefix("protocol=") {
            proto = p.trim();
        } else if let Some(h) = trimmed.strip_prefix("host=") {
            host = h.trim();
        } else if let Some(pa) = trimmed.strip_prefix("path=") {
            path_part = pa.trim();
        }
    }
    if proto.is_empty()
        || host.is_empty()
        || proto.chars().any(|c| c.is_whitespace() || c.is_control())
        || host.chars().any(|c| c.is_whitespace() || c.is_control() || c == '@')
    {
        return false;
    }
    let candidate = if path_part.is_empty() {
        format!("{proto}://{host}")
    } else {
        format!("{proto}://{host}/{}", path_part.trim_start_matches('/'))
    };
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
    let _ = std::io::stdin()
        .take(16 * 1024)
        .read_to_string(&mut stdin_buf);
    if action != "get" {
        return Ok(());
    }
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    if !cfg.user.is_empty()
        && !cfg.token.is_empty()
        && ensure_no_http_header_chars(&cfg.user, "gitea_user").is_ok()
        && ensure_no_http_header_chars(&cfg.token, "gitea_token").is_ok()
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
        let trimmed_u = u.trim().trim_end_matches('/');
        ensure_no_http_header_chars(trimmed_u, "gitea_url")?;
        if !trimmed_u.is_empty()
            && !trimmed_u.starts_with("http://")
            && !trimmed_u.starts_with("https://")
        {
            return Err("gitea_url must start with http:// or https://".into());
        }
        ldb.put(
            WriteRequest::new(NodeKind::Config, trimmed_u.as_bytes().to_vec())
                .with_key("gitea_url")
                .with_importance(190),
        )?;
    }
    if let Some(usr) = user {
        let trimmed_usr = usr.trim();
        ensure_no_http_header_chars(trimmed_usr, "gitea_user")?;
        ldb.put(
            WriteRequest::new(NodeKind::Config, trimmed_usr.as_bytes().to_vec())
                .with_key("gitea_user")
                .with_importance(190),
        )?;
    }
    if let Some(tok) = token {
        let trimmed_tok = tok.trim();
        ensure_no_http_header_chars(trimmed_tok, "gitea_token")?;
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
            if !exe_fwd.contains('"') && !exe_fwd.chars().any(char::is_control) {
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
                    if (ep.starts_with("http://") || ep.starts_with("https://"))
                        && !ep.chars().any(|c| c.is_whitespace() || c.is_control())
                    {
                        let _ = Command::new("git")
                            .args([
                                "config",
                                "--global",
                                &format!("credential.{ep}.helper"),
                                &helper_cmd,
                            ])
                            .output();
                    }
                }
            }
        }
    }

    let masked = mask_token_for_status(&cfg.token);

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

fn mask_token_for_status(token: &str) -> String {
    let char_cnt = token.chars().count();
    if char_cnt > 10 {
        let head: String = token.chars().take(4).collect();
        let tail: String = token.chars().skip(char_cnt - 4).collect();
        format!("{head}...{tail} (OS vault encrypted)")
    } else if !token.is_empty() {
        "(set, OS vault encrypted)".to_owned()
    } else {
        "(not set)".to_owned()
    }
}

pub fn cmd_gitea_status(global_opt: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let ldb = open_global_ldb(global_opt)?;
    let cfg = GiteaConfig::load(&ldb);
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut svc_state = query_service_state(&cfg.service_name);
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut ver_opt = check_gitea_version(&cfg);

    #[cfg(windows)]
    if (ver_opt.is_none() || svc_state == "STOPPED") && is_loopback_http_url(&cfg.url) {
        let _ = Command::new("sc.exe").args(["start", &cfg.service_name]).output();
        std::thread::sleep(Duration::from_millis(900));
        svc_state = query_service_state(&cfg.service_name);
        ver_opt = check_gitea_version(&cfg);
    }

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
    validate_safe_git_identifier(&repo_name, "repository name")?;

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
                    &format!("{}/api/v1/repos/{}/{}", cfg.url, cfg.user, percent_encode(&repo_name)),
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
                .args(["remote", "set-url", "--", "origin", &clone_url])
                .current_dir(&clean_root)
                .output()?;
        } else {
            // Preserve non-Gitea `origin` (e.g., GitHub/GitLab) and attach local Gitea as `gitea` remote!
            linked_remote_name = "gitea";
            if remotes.iter().any(|(n, _)| n == "gitea") {
                let _ = Command::new("git")
                    .args(["remote", "set-url", "--", "gitea", &clone_url])
                    .current_dir(&clean_root)
                    .output()?;
            } else {
                let _ = Command::new("git")
                    .args(["remote", "add", "--", "gitea", &clone_url])
                    .current_dir(&clean_root)
                    .output()?;
            }
        }
    } else {
        let _ = Command::new("git")
            .args(["remote", "add", "--", "origin", &clone_url])
            .current_dir(&clean_root)
            .output()?;
    }

    let proj_ldb_path = clean_root.join(".agents").join("memory.ldb");
    if proj_ldb_path.is_file() {
        let _ws_lock = crate::security::WorkspaceTrustLockGuard::acquire(&ldb, &clean_root)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if crate::security::is_workspace_memory_trusted(Some(&ldb), &clean_root) {
            if let Ok(pdb) = LibreDb::open(&proj_ldb_path) {
                crate::security::seal_workspace_memory(&ldb, &pdb, &clean_root)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            }
        }
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

    ensure_local_git_initialized(&clean_root, Some(&ldb))?;

    let mut proj_db_opt: Option<Arc<LibreDb>> = None;
    let proj_ldb_path = clean_root.join(".agents").join("memory.ldb");
    if proj_ldb_path.is_file() {
        let _ws_lock = crate::security::WorkspaceTrustLockGuard::acquire(&ldb, &clean_root)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if crate::security::is_workspace_memory_trusted(Some(&ldb), &clean_root) {
            if let Ok(pdb) = LibreDb::open(&proj_ldb_path) {
                let pdb = Arc::new(pdb);
                crate::security::seal_workspace_memory(&ldb, &pdb, &clean_root)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
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
        let mut skipped_deliverables = 0usize;
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
            // Release binaries are uploaded as release assets; never duplicate them in the Git tree.
            if is_release_deliverable_path(rel) {
                let _ = Command::new("git")
                    .args(["-c", "core.fsmonitor=false", "rm", "--cached", "--quiet", "--", rel])
                    .current_dir(&clean_root)
                    .output();
                skipped_deliverables += 1;
                continue;
            }
        }
        if skipped_deliverables > 0 {
            println!(
                "  [OK] Kept {skipped_deliverables} release deliverable(s) out of the Git tree (published as release assets instead)"
            );
        }
    }

    let enforce_style = crate::security::load_bool_config(
        Some(&ldb),
        proj_db_opt.as_deref(),
        "guardrail:style_rules",
        false,
    );
    let mut audit =
        audit_workspace_guardrails_with_prefixes(&clean_root, true, &custom_prefixes)?;
    if !enforce_style {
        audit
            .violations
            .retain(|v| !matches!(v.rule.as_str(), "no-em-en-dash" | "no-emojis"));
    }
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

    let repo_name = resolve_repo_name_from_git_or_dir(&clean_root);
    validate_safe_git_identifier(&repo_name, "repository name")?;
    let mut remotes = list_git_remotes(&clean_root);
    if remotes.is_empty() && !cfg.user.is_empty() && !cfg.token.is_empty() {
        if let Ok(clone_url) = ensure_remote_repo_created(&cfg, &repo_name) {
            let _ = Command::new("git")
                .args(["remote", "add", "--", "origin", &clone_url])
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
    validate_safe_git_identifier(&branch, "branch name")?;

    for (rem_name, rem_url) in &target_remotes {
        validate_safe_git_identifier(rem_name, "remote name")?;
        if cfg.is_gitea_remote_url(rem_url) && !cfg.user.is_empty() && !cfg.token.is_empty() {
            let _ = ensure_remote_repo_created(&cfg, &repo_name);
        }
    }
    // Atomic preflight across ALL target remotes BEFORE creating a local commit or pushing any
    // mirror, so a diverged secondary remote (e.g. `github` behind `origin`) never leaves mirrors skewed.
    preflight_verify_remotes_fast_forward(&clean_root, &cfg, &target_remotes, &branch)?;

    if changed_cnt > 0 {
        let cfg_author_name = crate::security::load_string_config(
            Some(&ldb),
            proj_db_opt.as_deref(),
            "git:author_name",
        );
        let cfg_author_email = crate::security::load_string_config(
            Some(&ldb),
            proj_db_opt.as_deref(),
            "git:author_email",
        );

        let mut commit_cmd = Command::new("git");
        commit_cmd.current_dir(&clean_root);
        if let (Some(name), Some(email)) = (cfg_author_name, cfg_author_email) {
            commit_cmd.args([
                "-c",
                &format!("user.name={name}"),
                "-c",
                &format!("user.email={email}"),
            ]);
        } else if !git_has_configured_identity(&clean_root) {
            commit_cmd.args([
                "-c",
                "user.name=LibreDB",
                "-c",
                "user.email=libredb@localhost",
            ]);
        }
        commit_cmd.args(["commit", "-m", message]);
        let c_out = commit_cmd.output()?;
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

    println!("Synchronizing workspace: {} ({})", repo_name, clean_root.display());
    println!("  [OK] HEAD commit:    {short_hash} ({changed_cnt} files committed)");

    for (rem_name, rem_url) in &target_remotes {
        let mut push_cmd = Command::new("git");
        cfg.configure_git_command_for_remote(&mut push_cmd, rem_url);
        let p_out = push_cmd
            .args(["push", "-u", "--", rem_name, &branch])
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
        let (synced, _) = publish_gitea_release_internal(&clean_root, None, &cfg, &target_remotes)?;
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

    let (synced, effective_owner) =
        publish_gitea_release_internal(&clean_root, tag_opt, &cfg, &target_remotes)?;
    let (_, repo_name) = resolve_gitea_owner_and_repo(&clean_root, &cfg, &target_remotes);
    if synced.is_empty() {
        let tag_label = tag_opt.unwrap_or("latest");
        println!(
            "  [WARN] Processed tag {tag_label} for {effective_owner}/{repo_name}, but Gitea release API did not return a synced release (verify Gitea server at {} and token/permissions).",
            cfg.url
        );
    } else {
        for t in &synced {
            println!(
                "  [OK] Published Release {t} for {repo_name} ({}/{effective_owner}/{repo_name}/releases/tag/{t})",
                cfg.url
            );
        }
    }
    Ok(())
}

fn gitea_releases_base_url(cfg: &GiteaConfig, owner: &str, enc_repo: &str) -> String {
    format!("{}/api/v1/repos/{owner}/{enc_repo}/releases", cfg.url)
}

fn fetch_gitea_releases_for_owner(
    cfg: &GiteaConfig,
    owner: &str,
    enc_repo: &str,
) -> Result<Vec<Value>, Option<u16>> {
    let url = format!("{}?limit=100", gitea_releases_base_url(cfg, owner, enc_repo));
    match http_request("GET", &url, &cfg.token, cfg.allow_insecure_http, None, None) {
        Ok((200, body)) => Ok(serde_json::from_slice(&body).unwrap_or_default()),
        Ok((st, _)) => Err(Some(st)),
        Err(_) => Err(None),
    }
}

fn patch_gitea_release(
    cfg: &GiteaConfig,
    base_url: &str,
    rel_id: u64,
    payload_bytes: &[u8],
) -> Option<Value> {
    let patch_url = format!("{base_url}/{rel_id}");
    match http_request(
        "PATCH",
        &patch_url,
        &cfg.token,
        cfg.allow_insecure_http,
        Some("application/json"),
        Some(payload_bytes),
    ) {
        Ok((st, b)) if st == 200 || st == 201 => serde_json::from_slice(&b).ok(),
        _ => None,
    }
}

fn publish_gitea_release_internal(
    project_root: &Path,
    target_tag_opt: Option<&str>,
    cfg: &GiteaConfig,
    target_remotes: &[(String, String)],
) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    let changelog_path = project_root.join("CHANGELOG.md");
    let entries = parse_keep_a_changelog(&changelog_path)?;
    let (mut effective_owner, repo_name) =
        resolve_gitea_owner_and_repo(project_root, cfg, target_remotes);
    if entries.is_empty() {
        return Ok((Vec::new(), effective_owner));
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

    validate_safe_git_identifier(&repo_name, "repository name")?;
    if !effective_owner.is_empty() {
        validate_safe_git_identifier(&effective_owner, "repository owner")?;
    }

    // Ensure local annotated Git tag exists for selected release(s) and verify SemVer tag immutability!
    let head_sha = resolve_git_head_commit(project_root);
    let mut created_any_tag = false;
    for entry in &selected {
        validate_safe_git_identifier(&entry.tag, "release tag")?;
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
                    "-m",
                    &format!("{repo_name} {}", entry.tag),
                    "--",
                    &entry.tag,
                ])
                .current_dir(project_root)
                .output()?;
            created_any_tag = true;
        }
    }
    if created_any_tag || target_tag_opt.is_some() {
        for (rem_name, rem_url) in target_remotes {
            validate_safe_git_identifier(rem_name, "remote name")?;
            let mut tpush_cmd = Command::new("git");
            cfg.configure_git_command_for_remote(&mut tpush_cmd, rem_url);
            let _ = tpush_cmd
                .args(["push", "--tags", "--", rem_name])
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
            let is_latest = entry.tag == entries[0].tag;
            publish_github_cli_release(project_root, &repo_name, entry, is_latest);
        }
    }

    if cfg.user.is_empty() || cfg.token.is_empty() || effective_owner.is_empty() {
        return Ok((selected.iter().map(|e| e.tag.clone()).collect(), effective_owner));
    }

    let enc_repo = percent_encode(&repo_name);
    // Fetch existing Gitea releases under resolved remote owner; retry once under cfg.user on 404.
    let existing_rels: Vec<Value> = match fetch_gitea_releases_for_owner(cfg, &effective_owner, &enc_repo) {
        Ok(rels) => rels,
        Err(Some(404)) if !cfg.user.is_empty() && effective_owner != cfg.user => {
            match fetch_gitea_releases_for_owner(cfg, &cfg.user, &enc_repo) {
                Ok(rels) => {
                    effective_owner = cfg.user.clone();
                    rels
                }
                Err(status_opt) => {
                    eprintln!(
                        "  [WARN] Gitea releases lookup returned {} for both '{}/{}' and '{}/{}'.",
                        status_opt.map(|s| s.to_string()).unwrap_or_else(|| "network error".to_owned()),
                        effective_owner,
                        repo_name,
                        cfg.user,
                        repo_name
                    );
                    Vec::new()
                }
            }
        }
        Err(status_opt) => {
            eprintln!(
                "  [WARN] Gitea releases lookup failed for {}/{repo_name}: {}.",
                effective_owner,
                status_opt.map(|s| format!("HTTP {s}")).unwrap_or_else(|| "network error".to_owned())
            );
            Vec::new()
        }
    };

    let base_url = gitea_releases_base_url(cfg, &effective_owner, &enc_repo);
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
            patch_gitea_release(cfg, &base_url, rel_id, &payload_bytes).or_else(|| Some(ex.clone()))
        } else {
            match http_request(
                "POST",
                &base_url,
                &cfg.token,
                cfg.allow_insecure_http,
                Some("application/json"),
                Some(&payload_bytes),
            ) {
                Ok((st, b)) if st == 200 || st == 201 => serde_json::from_slice(&b).ok(),
                Ok((st, _)) if st == 409 || st == 422 => {
                    let by_tag_url = format!("{base_url}/tags/{}", percent_encode(&entry.tag));
                    match http_request("GET", &by_tag_url, &cfg.token, cfg.allow_insecure_http, None, None) {
                        Ok((200, tb)) => {
                            let existing_by_tag: Option<Value> = serde_json::from_slice(&tb).ok();
                            if let Some(ex) = existing_by_tag {
                                let rel_id = ex.get("id").and_then(Value::as_u64).unwrap_or(0);
                                patch_gitea_release(cfg, &base_url, rel_id, &payload_bytes)
                                    .or(Some(ex))
                            } else {
                                None
                            }
                        }
                        Ok((gs, _)) => {
                            eprintln!(
                                "  [WARN] Gitea release tag lookup {} returned HTTP {gs} after HTTP {st}.",
                                entry.tag
                            );
                            None
                        }
                        Err(e) => {
                            eprintln!("  [WARN] Gitea release tag lookup {} failed: {e}", entry.tag);
                            None
                        }
                    }
                }
                Ok((st, b)) => {
                    let msg = String::from_utf8_lossy(&b);
                    eprintln!(
                        "  [WARN] Gitea release creation for {}/{repo_name}@{} failed (HTTP {st}): {}",
                        effective_owner,
                        entry.tag,
                        msg.trim()
                    );
                    None
                }
                Err(e) => {
                    eprintln!(
                        "  [WARN] Gitea release request for {}/{repo_name}@{} failed: {e}",
                        effective_owner, entry.tag
                    );
                    None
                }
            }
        };

        if let Some(robj) = rel_obj {
            if let Some(rel_id) = robj.get("id").and_then(Value::as_u64) {
                let existing_assets = robj
                    .get("assets")
                    .and_then(Value::as_array)
                    .or_else(|| {
                        existing_rel
                            .and_then(|ex| ex.get("assets"))
                            .and_then(Value::as_array)
                    })
                    .cloned()
                    .unwrap_or_default();
                let is_latest_release = entry.tag == entries[0].tag;
                let attached = attach_release_assets(
                    cfg,
                    &effective_owner,
                    &repo_name,
                    rel_id,
                    &entry.tag,
                    is_latest_release,
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

    Ok((synced_tags, effective_owner))
}

const MAX_DELIVERABLE_ASSET_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

#[allow(clippy::too_many_arguments)]
fn attach_release_assets(
    cfg: &GiteaConfig,
    repo_owner: &str,
    repo_name: &str,
    rel_id: u64,
    tag: &str,
    is_latest_release: bool,
    existing_assets: &[Value],
    project_root: &Path,
) -> Vec<String> {
    let clean_ver = tag.trim_start_matches(['v', 'V']).to_ascii_lowercase();
    let deliverables = discover_deliverable_files(project_root, tag, is_latest_release);
    let mut uploaded = Vec::new();
    let enc_repo = percent_encode(repo_name);

    let desired_names: std::collections::HashSet<String> = deliverables
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .map(|s| {
            s.chars()
                .filter(|&c| c != '"' && c != '\\' && c != '\r' && c != '\n' && !c.is_control())
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut pruned_names = Vec::new();
    for ex in existing_assets {
        let Some(ex_name) = ex.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(aid) = ex.get("id").and_then(Value::as_u64) else {
            continue;
        };
        let ex_low = ex_name.to_ascii_lowercase();
        let is_replaced = desired_names.contains(ex_name);
        let has_version_conflict = filename_conflicts_with_version(&ex_low, &clean_ver);
        let stale_unversioned_on_historical = !is_latest_release
            && !deliverables.is_empty()
            && extract_filename_version(&ex_low).is_none()
            && RELEASE_DELIVERABLE_EXTS.iter().any(|ext| ex_low.ends_with(ext));
        if is_replaced || has_version_conflict || stale_unversioned_on_historical {
            let del_url = format!(
                "{}/api/v1/repos/{repo_owner}/{enc_repo}/releases/{rel_id}/assets/{aid}",
                cfg.url
            );
            if let Ok((st, _)) = http_request(
                "DELETE",
                &del_url,
                &cfg.token,
                cfg.allow_insecure_http,
                None,
                None,
            ) {
                if (st == 200 || st == 204) && !is_replaced {
                    pruned_names.push(ex_name.to_owned());
                }
            }
        }
    }
    if !pruned_names.is_empty() {
        println!(
            "  [OK] Pruned {} stale/mismatched release asset(s) from {tag}: {}",
            pruned_names.len(),
            pruned_names.join(", ")
        );
    }

    for file_path in deliverables {
        let Ok(sym_meta) = fs::symlink_metadata(&file_path) else {
            continue;
        };
        if !sym_meta.file_type().is_file() || sym_meta.len() > MAX_DELIVERABLE_ASSET_BYTES {
            continue;
        }
        let Some(fname) = file_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let safe_fname: String = fname
            .chars()
            .filter(|&c| c != '"' && c != '\\' && c != '\r' && c != '\n' && !c.is_control())
            .collect();
        if safe_fname.is_empty() {
            continue;
        }
        let Ok(file_bytes) = fs::read(&file_path) else {
            continue;
        };

        let boundary = format!("----LibreDBAssetBoundary{}", std::process::id());
        let content_type_inner = if safe_fname.ends_with(".zip") || safe_fname.ends_with(".whl") {
            "application/zip"
        } else {
            "application/octet-stream"
        };

        let mut body = Vec::with_capacity(file_bytes.len() + 512);
        write!(
            &mut body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{safe_fname}\"\r\nContent-Type: {content_type_inner}\r\n\r\n"
        )
        .unwrap();
        body.extend_from_slice(&file_bytes);
        write!(&mut body, "\r\n--{boundary}--\r\n").unwrap();

        let up_url = format!(
            "{}/api/v1/repos/{repo_owner}/{enc_repo}/releases/{rel_id}/assets?name={}",
            cfg.url,
            percent_encode(&safe_fname)
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
                uploaded.push(safe_fname);
            }
        }
    }
    uploaded
}

/// File extensions treated as binary release deliverables (uploaded as release assets).
const RELEASE_DELIVERABLE_EXTS: [&str; 15] = [
    ".exe", ".msi", ".msix", ".zip", ".7z", ".tar.gz", ".whl", ".jar", ".apk", ".aab", ".vsix",
    ".xpi", ".deb", ".rpm", ".dmg",
];

fn is_allowed_release_outbox_filename(fname: &str) -> bool {
    let low = fname.trim().to_ascii_lowercase();
    if low.is_empty()
        || low.starts_with('.')
        || low.starts_with('-')
        || matches!(low.as_str(), "thumbs.db" | "desktop.ini" | "readme.md")
        || [".old", ".tmp", ".part", ".bak", ".ldbbak"]
            .iter()
            .any(|sfx| low.ends_with(sfx))
    {
        return false;
    }
    is_sensitive_staged_file(&low, &[]).is_none()
}

/// Returns `true` for release outbox deliverables under `releases/` or `release/` (any extension
/// allowed by the outbox filename/secret filter) and binary release deliverables under `dist/`
/// that must never be committed to the Git tree because they are published as release assets.
fn is_release_deliverable_path(rel: &str) -> bool {
    let clean = rel.trim().trim_matches('"').replace('\\', "/");
    let low = clean.to_ascii_lowercase();
    let leaf = low.rsplit('/').next().unwrap_or(&low);
    if low.starts_with("releases/") || low.starts_with("release/") {
        return is_allowed_release_outbox_filename(leaf)
            && is_sensitive_staged_file(&clean, &[]).is_none();
    }
    low.starts_with("dist/")
        && is_sensitive_staged_file(&clean, &[]).is_none()
        && (RELEASE_DELIVERABLE_EXTS.iter().any(|ext| low.ends_with(ext))
            || matches!(
                low.rsplit_once('.').map(|(_, ext)| ext),
                Some("pyd" | "so" | "dylib" | "dll")
            ))
}

/// Extracts an explicit `major.minor.patch` SemVer core string from a lowercase deliverable filename.
fn extract_filename_version(filename_low: &str) -> Option<String> {
    let b = filename_low.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let prefix_ok = i == 0
            || matches!(b[i - 1], b'-' | b'_' | b' ')
            || (b[i - 1] == b'v' && (i == 1 || matches!(b[i - 2], b'-' | b'_' | b' ')));
        if !prefix_ok {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        let start = i;
        let d1 = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=4).contains(&d1) || b.get(i + d1) != Some(&b'.') {
            i += d1.max(1);
            continue;
        }
        let p2 = i + d1 + 1;
        let d2 = b[p2..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=4).contains(&d2) || b.get(p2 + d2) != Some(&b'.') {
            i = p2;
            continue;
        }
        let p3 = p2 + d2 + 1;
        let d3 = b[p3..].iter().take_while(|c| c.is_ascii_digit()).count();
        if !(1..=4).contains(&d3) {
            i = p3;
            continue;
        }
        let end = p3 + d3;
        let next_is_dot_digit =
            b.get(end) == Some(&b'.') && b.get(end + 1).is_some_and(|c| c.is_ascii_digit());
        let suffix_ok = !next_is_dot_digit
            && match b.get(end) {
                None => true,
                Some(&c) => matches!(c, b'-' | b'_' | b'.' | b' '),
            };
        if suffix_ok {
            return Some(filename_low[start..end].to_owned());
        }
        i = end;
    }
    None
}

/// Returns `true` when `filename_low` carries an explicit SemVer version differing from `clean_ver`.
fn filename_conflicts_with_version(filename_low: &str, clean_ver: &str) -> bool {
    let target_core = clean_ver
        .split(['-', '+'])
        .next()
        .unwrap_or(clean_ver)
        .to_ascii_lowercase();
    if target_core.is_empty() {
        return false;
    }
    extract_filename_version(filename_low).is_some_and(|found| found != target_core)
}

fn is_allowed_release_outbox_file(path: &Path, clean_ver: &str) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_file() || meta.len() > MAX_DELIVERABLE_ASSET_BYTES {
        return false;
    }
    let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !is_allowed_release_outbox_filename(fname) {
        return false;
    }
    let low = fname.to_ascii_lowercase();
    !filename_conflicts_with_version(&low, clean_ver)
}

fn discover_deliverable_files(
    project_root: &Path,
    tag: &str,
    is_latest_release: bool,
) -> Vec<PathBuf> {
    let exts = RELEASE_DELIVERABLE_EXTS;
    let clean_ver = tag.trim_start_matches(['v', 'V']).to_ascii_lowercase();
    let tag_low = tag.to_ascii_lowercase();

    let mut outbox = Vec::new();
    for sub in ["releases", "release"] {
        let dir = project_root.join(sub);
        if fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        if let Ok(rd) = fs::read_dir(&dir) {
            let mut entries: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|x| x.path()))
                .filter(|p| is_allowed_release_outbox_file(p, &clean_ver))
                .collect();
            entries.sort();
            outbox.extend(entries);
        }
    }

    let mut dist_found = Vec::new();
    let dist_dir = project_root.join("dist");
    if !fs::symlink_metadata(&dist_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        if let Ok(rd) = fs::read_dir(&dist_dir) {
            let mut entries: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|x| x.path()))
                .filter(|p| {
                    fs::symlink_metadata(p).is_ok_and(|m| {
                        m.file_type().is_file() && m.len() <= MAX_DELIVERABLE_ASSET_BYTES
                    })
                })
                .filter(|p| {
                    let low = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_ascii_lowercase();
                    !low.starts_with('-')
                        && exts.iter().any(|ext| low.ends_with(ext))
                        && !filename_conflicts_with_version(&low, &clean_ver)
                })
                .collect();
            entries.sort();
            dist_found.extend(entries);
        }
    }

    let is_tag_match = |p: &Path| {
        let n = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        n.contains(&tag_low) || (!clean_ver.is_empty() && n.contains(&clean_ver))
    };

    if is_latest_release && !outbox.is_empty() {
        let mut seen_names: std::collections::HashSet<String> = outbox
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()))
            .collect();
        let mut merged = outbox;
        for p in dist_found {
            if is_tag_match(&p) {
                let name_low = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if seen_names.insert(name_low) {
                    merged.push(p);
                }
            }
        }
        return merged;
    }

    let mut combined = outbox;
    combined.extend(dist_found);
    let tag_matched: Vec<PathBuf> = combined
        .iter()
        .filter(|p| is_tag_match(p))
        .cloned()
        .collect();
    if !tag_matched.is_empty() {
        tag_matched
    } else if is_latest_release {
        combined
    } else {
        Vec::new()
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
    let cfg_name = crate::security::load_string_config(global_db, None, "git:author_name");
    let cfg_email = crate::security::load_string_config(global_db, None, "git:author_email");
    if let (Some(name), Some(email)) = (cfg_name, cfg_email) {
        let _ = Command::new("git")
            .args(["config", "user.name", &name])
            .current_dir(project_root)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.email", &email])
            .current_dir(project_root)
            .output();
    } else if !git_has_configured_identity(project_root) {
        let _ = Command::new("git")
            .args(["config", "user.name", "LibreDB"])
            .current_dir(project_root)
            .output();
        let _ = Command::new("git")
            .args(["config", "user.email", "libredb@localhost"])
            .current_dir(project_root)
            .output();
    }
    Ok(())
}

fn git_has_configured_identity(root: &Path) -> bool {
    let has_key = |k: &str| -> bool {
        Command::new("git")
            .args(["config", k])
            .current_dir(root)
            .output()
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false)
    };
    has_key("user.name") && has_key("user.email")
}

fn ensure_git_info_exclude(project_root: &Path) {
    let info_dir = project_root.join(".git").join("info");
    if !info_dir.is_dir() && fs::create_dir_all(&info_dir).is_err() {
        return;
    }
    let exclude_path = info_dir.join("exclude");
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    let mut missing = Vec::new();
    for rule in [
        "/.agents/",
        "/releases/",
        "/release/",
        "/dist/",
        "*.tmp.ldb",
        "*.credential.xml",
    ] {
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
    if let Some(b) = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|b| !b.is_empty() && b != "HEAD")
    {
        return b;
    }
    if let Some(b) = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "symbolic-ref", "--short", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|b| !b.is_empty())
    {
        return b;
    }
    "main".to_owned()
}

/// Fetches `branch` from EVERY target remote BEFORE `cmd_gitea_sync` creates a commit or pushes
/// any mirror, rejecting diverged/unpulled remote history or unreachable remotes atomically.
fn preflight_verify_remotes_fast_forward(
    clean_root: &Path,
    cfg: &GiteaConfig,
    target_remotes: &[(String, String)],
    branch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_safe_git_identifier(branch, "branch name")?;
    let local_head_opt = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "rev-parse", "--verify", "-q", "HEAD"])
        .current_dir(clean_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty());

    for (rem_name, rem_url) in target_remotes {
        validate_safe_git_identifier(rem_name, "remote name")?;
        let mut fetch_cmd = Command::new("git");
        cfg.configure_git_command_for_remote(&mut fetch_cmd, rem_url);
        let f_out = fetch_cmd
            .args([
                "-c",
                "core.fsmonitor=false",
                "fetch",
                "--no-tags",
                "--quiet",
                "--",
                rem_name,
                branch,
            ])
            .current_dir(clean_root)
            .output()?;
        if !f_out.status.success() {
            let err_msg = String::from_utf8_lossy(&f_out.stderr);
            let err_low = err_msg.to_ascii_lowercase();
            // Brand new remote repository / branch has no remote ref yet; fast-forward push is safe.
            if err_low.contains("couldn't find remote ref")
                || err_low.contains("remote ref does not exist")
            {
                continue;
            }
            return Err(format!(
                "[PREFLIGHT FETCH FAILED]: Could not inspect remote '{rem_name}' ({rem_url}) for branch '{branch}' before committing/pushing: {}",
                err_msg.trim()
            )
            .into());
        }

        let remote_head_opt = Command::new("git")
            .args([
                "-c",
                "core.fsmonitor=false",
                "rev-parse",
                "--verify",
                "-q",
                "FETCH_HEAD",
            ])
            .current_dir(clean_root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .filter(|s| !s.is_empty());

        let Some(ref remote_head) = remote_head_opt else {
            continue;
        };
        let Some(ref local_head) = local_head_opt else {
            return Err(format!(
                "[PREFLIGHT SYNC CONFLICT]: Local branch '{branch}' has no commits while remote '{rem_name}' ({rem_url}) already points to {}.",
                &remote_head[..remote_head.len().min(7)]
            )
            .into());
        };
        if local_head == remote_head {
            continue;
        }
        let anc_out = Command::new("git")
            .args([
                "-c",
                "core.fsmonitor=false",
                "merge-base",
                "--is-ancestor",
                remote_head,
                "HEAD",
            ])
            .current_dir(clean_root)
            .output()?;
        if !anc_out.status.success() {
            return Err(format!(
                "[PREFLIGHT SYNC CONFLICT]: Remote '{rem_name}' ({rem_url}) has unpulled commits on branch '{branch}' (remote {} is not an ancestor of local {}). Pull or rebase before running 'git-sync' so multi-remote mirrors stay atomic.",
                &remote_head[..remote_head.len().min(7)],
                &local_head[..local_head.len().min(7)]
            )
            .into());
        }
    }
    Ok(())
}

fn parse_owner_and_repo_from_remote_url(raw_url: &str) -> Option<(String, String)> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let path_part = if let Some((_, rest)) = trimmed.split_once("://") {
        rest.split_once('/').map(|(_, p)| p)?
    } else if let Some((_, after_colon)) = trimmed.split_once(':') {
        after_colon.trim_start_matches('/')
    } else {
        trimmed
    };
    let path_clean = path_part.strip_suffix(".git").unwrap_or(path_part);
    let mut rev_segs = path_clean.rsplit('/').filter(|s| !s.is_empty());
    let repo = rev_segs.next()?.to_owned();
    let owner = rev_segs.next()?.to_owned();
    if validate_safe_git_identifier(&owner, "repository owner").is_ok()
        && validate_safe_git_identifier(&repo, "repository name").is_ok()
    {
        Some((owner, repo))
    } else {
        None
    }
}

pub(crate) fn resolve_gitea_owner_and_repo(
    project_root: &Path,
    cfg: &GiteaConfig,
    remotes: &[(String, String)],
) -> (String, String) {
    let pick_from = |slice: &[(String, String)]| -> Option<(String, String)> {
        if let Some((_, url)) = slice.iter().find(|(name, _)| name == "gitea") {
            if let Some(pair) = parse_owner_and_repo_from_remote_url(url) {
                return Some(pair);
            }
        }
        if let Some((_, url)) = slice
            .iter()
            .find(|(name, url)| name == "origin" && cfg.is_gitea_remote_url(url))
        {
            if let Some(pair) = parse_owner_and_repo_from_remote_url(url) {
                return Some(pair);
            }
        }
        for (_, url) in slice {
            if cfg.is_gitea_remote_url(url) {
                if let Some(pair) = parse_owner_and_repo_from_remote_url(url) {
                    return Some(pair);
                }
            }
        }
        None
    };

    if let Some(pair) = pick_from(remotes) {
        return pair;
    }
    let all_remotes = list_git_remotes(project_root);
    if let Some(pair) = pick_from(&all_remotes) {
        return pair;
    }
    (cfg.user.clone(), resolve_repo_name_from_git_or_dir(project_root))
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
        if rem.is_empty() || validate_safe_git_identifier(rem, "remote name").is_err() {
            continue;
        }
        if let Ok(u_out) = Command::new("git")
            .args(["-c", "core.fsmonitor=false", "remote", "get-url", "--", rem])
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
    if validate_safe_git_identifier(tag, "tag").is_err() {
        return None;
    }
    let out = Command::new("git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "rev-list",
            "-n",
            "1",
            tag,
            "--",
        ])
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

fn publish_github_cli_release(
    project_root: &Path,
    repo_name: &str,
    entry: &ChangelogEntry,
    is_latest_release: bool,
) {
    if validate_safe_git_identifier(&entry.tag, "release tag").is_err() {
        return;
    }
    let title = format!("{repo_name} {}", entry.tag);
    let deliverables = discover_deliverable_files(project_root, &entry.tag, is_latest_release);
    let view_ok = Command::new("gh")
        .args(["release", "view", "--", &entry.tag])
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
                if !fs_str.starts_with('-') {
                    let _ = Command::new("gh")
                        .args(["release", "upload", "--clobber", "--", &entry.tag, fs_str])
                        .current_dir(project_root)
                        .output();
                }
            }
        }
    } else {
        let mut create_args = vec![
            "release".to_owned(),
            "create".to_owned(),
            "--title".to_owned(),
            title,
            "--notes".to_owned(),
            entry.body.clone(),
        ];
        if entry.version.contains('-') {
            create_args.push("--prerelease".to_owned());
        }
        create_args.push("--".to_owned());
        create_args.push(entry.tag.clone());
        for f in &deliverables {
            if let Some(fs_str) = f.to_str() {
                if !fs_str.starts_with('-') {
                    create_args.push(fs_str.to_owned());
                }
            }
        }
        let _ = Command::new("gh")
            .args(&create_args)
            .current_dir(project_root)
            .output();
    }
}

fn record_learned_workspace(ldb: &LibreDb, clean_root: &Path) {
    if crate::hooks::is_protected_profile_dir(clean_root) {
        return;
    }
    let norm = crate::security::normalize_workspace_key(clean_root);
    if norm.is_empty() {
        return;
    }
    let _ws_lock = match crate::security::WorkspaceTrustLockGuard::acquire_norm(ldb, &norm) {
        Ok(g) => g,
        Err(_) => return,
    };
    if crate::security::has_config_key_fail_closed(ldb, &format!("trust:revoked::{norm}"))
        .unwrap_or(true)
    {
        return;
    }
    let has_existing_or_prior_memory = clean_root.join(".agents").join("memory.ldb").exists()
        || crate::security::has_prior_workspace_seal_marker(ldb, clean_root)
        || crate::security::is_git_index_tracking_agents_db(clean_root);
    if has_existing_or_prior_memory
        && !crate::security::is_workspace_memory_trusted(Some(ldb), clean_root)
    {
        // Never grant `trust:allowed::<norm>` to a repository containing an untrusted, unsealed,
        // tampered, or Git-tracked `.agents/memory.ldb` database!
        return;
    }

    let val = clean_root.to_string_lossy().into_owned();
    let ws_id_key = crate::security::workspace_id_config_key(&norm);
    let _ = ldb.put(
        WriteRequest::new(NodeKind::Config, val.clone().into_bytes())
            .with_key(ws_id_key)
            .with_importance(175),
    );
    let _ = ldb.put(
        WriteRequest::new(NodeKind::Config, val.into_bytes())
            .with_key(format!("trust:allowed::{norm}"))
            .with_importance(185),
    );
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
        format!(
            "{}/api/v1/users/{}/repos?limit=100",
            cfg.url,
            percent_encode(&cfg.user)
        )
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
    let url = format!(
        "{}/api/v1/repos/{}/{}",
        cfg.url,
        percent_encode(&cfg.user),
        percent_encode(repo_name)
    );
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
    validate_safe_git_identifier(repo_name, "repository name")?;
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
/// `allow_insecure_http` is explicitly enabled, validates all header inputs against CRLF/NUL
/// injection, and bounds response bodies to `32 MiB`.
fn http_request(
    method: &str,
    url: &str,
    token: &str,
    allow_insecure_http: bool,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> std::io::Result<(u16, Vec<u8>)> {
    ensure_no_http_header_chars(method, "HTTP method")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    ensure_no_http_header_chars(url, "HTTP URL")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    ensure_no_http_header_chars(token, "API token")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if let Some(ct) = content_type {
        ensure_no_http_header_chars(ct, "Content-Type")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    }

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
    stream
        .take(MAX_HTTP_RESPONSE_BYTES + 1)
        .read_to_end(&mut raw_resp)?;
    if raw_resp.len() as u64 > MAX_HTTP_RESPONSE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP response exceeded 32 MiB safety limit",
        ));
    }
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
        use std::sync::atomic::{AtomicU64, Ordering};
        static CURL_CFG_SEQ: AtomicU64 = AtomicU64::new(0);

        let base_dir = crate::hooks::user_home_dir().join(".gemini").join("libredb");
        let dir = if fs::create_dir_all(&base_dir).is_ok()
            && fs::symlink_metadata(&base_dir).is_ok_and(|m| m.file_type().is_dir())
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700));
            }
            base_dir
        } else {
            env::temp_dir()
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = CURL_CFG_SEQ.fetch_add(1, Ordering::Relaxed);
        let cfg_path = dir.join(format!(
            ".curl_hdr_{}_{stamp}_{seq}.cfg",
            std::process::id()
        ));
        let content = format_curl_auth_header_line(token);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
            opts.attributes(FILE_ATTRIBUTE_TEMPORARY);
        }
        let mut f = opts.open(&cfg_path)?;
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
/// `0600` RAII-wiped `EphemeralCurlConfig` only when `stdin` carries a request body.
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
        "--max-filesize",
        "33554432",
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
    cmd.args(["-w", &format!("{marker}%{{http_code}}"), "--", url]);
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
        ensure_no_http_header_chars, http_request, parse_http_response, record_learned_workspace,
        resolve_gitea_owner_and_repo, should_supply_git_credentials, validate_safe_git_identifier,
        GiteaConfig,
    };
    use libredb_core::{LibreDb, NodeKind, WriteRequest};
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    /// S19 (v1.4.0): release binaries under `dist/` and `releases/` never enter the Git tree,
    /// while source files in those directories and deliverable-like names elsewhere are kept.
    #[test]
    fn release_deliverables_are_kept_out_of_git_tree_only_under_dist_and_releases() {
        use super::is_release_deliverable_path;
        assert!(is_release_deliverable_path("releases/libredb-v1.4.0-x86_64-pc-windows-msvc.zip"));
        assert!(is_release_deliverable_path("dist\\installer.msi"));
        assert!(is_release_deliverable_path("dist/pkg/libredb-1.4.0.tar.gz"));
        assert!(is_release_deliverable_path("\"releases/app.apk\""));
        assert!(!is_release_deliverable_path("dist/index.html"));
        assert!(!is_release_deliverable_path("releases/README.md"));
        assert!(!is_release_deliverable_path("tests/fixtures/sample.zip"));
        assert!(!is_release_deliverable_path("src/dist/notes.zipper"));
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

    #[test]
    fn git_identifiers_crlf_headers_and_untrusted_workspace_learning_are_guarded() {
        for bad_id in [
            "--upload-pack=evil",
            "-u",
            "foo..bar",
            "bad\nref",
            "bad space",
            ".hidden",
            "repo.lock",
        ] {
            assert!(
                validate_safe_git_identifier(bad_id, "identifier").is_err(),
                "Expected unsafe Git identifier '{bad_id}' to be rejected!"
            );
        }
        for good_id in ["v0.10.0", "origin", "feature/sec-audit", "LibreDB"] {
            assert!(validate_safe_git_identifier(good_id, "identifier").is_ok());
        }

        assert!(ensure_no_http_header_chars("tok\r\nX-Injected: 1", "token").is_err());
        assert!(
            http_request(
                "GET",
                "http://127.0.0.1:3000/api\r\nInjected: 1",
                "tok",
                false,
                None,
                None
            )
            .is_err(),
            "CRLF header injection in URL must be rejected before opening socket!"
        );

        // Subpath-hosted Gitea (`https://corp.example/gitea`) must enforce path prefix in credential helper!
        let subpath_cfg = GiteaConfig {
            url: "https://corp.example/gitea".to_owned(),
            user: "bot".to_owned(),
            token: "tok".to_owned(),
            service_name: "gitea".to_owned(),
            allow_insecure_http: false,
        };
        assert!(!should_supply_git_credentials(
            &subpath_cfg,
            "protocol=https\nhost=corp.example\npath=gitlab/other.git\n\n"
        ));
        assert!(should_supply_git_credentials(
            &subpath_cfg,
            "protocol=https\nhost=corp.example\npath=gitea/org/repo.git\n\n"
        ));

        // `record_learned_workspace` must NOT grant `trust:allowed` to OS temp dirs or when an
        // unsealed `.agents/memory.*` is present, while recording clean non-temp workspaces!
        let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join(format!(
                "test_gitea_learn_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
        let clean_ws = tmp.join("clean_ws");
        let poisoned_ws = tmp.join("poisoned_ws");
        let os_temp_ws = std::env::temp_dir().join(format!("libredb_tmp_ws_{}", std::process::id()));
        fs::create_dir_all(&clean_ws).unwrap();
        fs::create_dir_all(poisoned_ws.join(".agents")).unwrap();
        fs::create_dir_all(&os_temp_ws).unwrap();
        let unsealed_pdb = LibreDb::open(poisoned_ws.join(".agents").join("memory.ldb")).unwrap();
        unsealed_pdb
            .put(WriteRequest::new(NodeKind::Rule, b"evil".to_vec()).with_key("r"))
            .unwrap();
        drop(unsealed_pdb);

        let gdb = LibreDb::open(tmp.join("customizations.ldb")).unwrap();
        record_learned_workspace(&gdb, &clean_ws);
        record_learned_workspace(&gdb, &poisoned_ws);
        record_learned_workspace(&gdb, &os_temp_ws);

        let clean_norm = crate::security::normalize_workspace_key(&clean_ws);
        let poisoned_norm = crate::security::normalize_workspace_key(&poisoned_ws);
        let os_temp_norm = crate::security::normalize_workspace_key(&os_temp_ws);
        assert!(
            gdb.get_by_key(NodeKind::Config, &format!("trust:allowed::{clean_norm}"))
                .is_ok(),
            "Clean workspace without .agents must be recorded!"
        );
        assert!(
            gdb.get_by_key(
                NodeKind::Config,
                &crate::security::workspace_id_config_key(&clean_norm)
            )
            .is_ok(),
            "Clean workspace must record collision-free workspace_id::<hash>!"
        );
        assert!(
            gdb.get_by_key(NodeKind::Config, &format!("trust:allowed::{poisoned_norm}"))
                .is_err(),
            "Workspace with unsealed .agents/memory.ldb MUST NOT receive trust:allowed via git-sync/git-init!"
        );
        assert!(
            gdb.get_by_key(NodeKind::Config, &format!("trust:allowed::{os_temp_norm}"))
                .is_err(),
            "OS temp directories MUST NOT be learned as trusted workspaces!"
        );

        drop(gdb);
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&os_temp_ws);
    }

    #[test]
    fn resolve_gitea_owner_uses_remote_namespace_over_login_user() {
        let cfg = GiteaConfig {
            url: "http://localhost:3000".to_owned(),
            user: "MickyFoley".to_owned(),
            token: String::new(),
            service_name: "gitea".to_owned(),
            allow_insecure_http: true,
        };
        let tmp = std::env::temp_dir().join("libredb_owner_res_test");
        let _ = fs::create_dir_all(&tmp);

        let remotes = vec![(
            "origin".to_owned(),
            "http://localhost:3000/Antigravity/WgServerforWindows.git".to_owned(),
        )];
        assert_eq!(
            resolve_gitea_owner_and_repo(&tmp, &cfg, &remotes),
            ("Antigravity".to_owned(), "WgServerforWindows".to_owned())
        );

        let dual_remotes = vec![
            (
                "origin".to_owned(),
                "https://github.com/someone/WgServerforWindows.git".to_owned(),
            ),
            (
                "gitea".to_owned(),
                "http://127.0.0.1:3000/OrgNamespace/MirrorRepo".to_owned(),
            ),
        ];
        assert_eq!(
            resolve_gitea_owner_and_repo(&tmp, &cfg, &dual_remotes),
            ("OrgNamespace".to_owned(), "MirrorRepo".to_owned())
        );

        assert_eq!(
            resolve_gitea_owner_and_repo(&tmp, &cfg, &[]),
            ("MickyFoley".to_owned(), "libredb_owner_res_test".to_owned())
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn discover_deliverable_files_excludes_conflicting_versions_and_historical_fallbacks() {
        use crate::gitea::discover_deliverable_files;

        let tmp = std::env::temp_dir().join(format!("libredb_deliverables_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("dist")).unwrap();
        fs::create_dir_all(tmp.join("releases")).unwrap();

        fs::write(tmp.join("dist").join("libredb.exe"), b"unversioned").unwrap();
        fs::write(tmp.join("dist").join("libredb-v1.5.1-windows-x64.exe"), b"151").unwrap();
        fs::write(tmp.join("dist").join("libredb-v1.6.0-windows-x64.exe"), b"160").unwrap();
        fs::write(tmp.join("dist").join("libredb-v1.6.2-windows-x64.exe"), b"162").unwrap();
        fs::write(tmp.join("dist").join("libredb-v1.6.3-windows-x64.exe"), b"163").unwrap();
        fs::write(tmp.join("releases").join("helper-v1.6.0.zip"), b"zip160").unwrap();

        let exact_names = |files: Vec<PathBuf>| -> Vec<String> {
            files
                .into_iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect()
        };

        assert_eq!(
            exact_names(discover_deliverable_files(&tmp, "v1.6.2", false)),
            vec!["libredb-v1.6.2-windows-x64.exe".to_owned()],
            "Matched release tag must upload only matching versioned assets and exclude v1.5.1/v1.6.0/v1.6.3"
        );

        fs::remove_file(tmp.join("dist").join("libredb-v1.6.2-windows-x64.exe")).unwrap();
        assert!(
            discover_deliverable_files(&tmp, "v1.6.2", false).is_empty(),
            "Historical release without exact tag asset must never fall back to unversioned executables"
        );
        assert_eq!(
            exact_names(discover_deliverable_files(&tmp, "v1.6.2", true)),
            vec!["libredb.exe".to_owned()],
            "Latest release fallback may upload unversioned binary while still excluding mismatched versions"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn release_outbox_uploads_extensionless_and_pyd_files_while_blocking_secrets_and_old_versions() {
        use crate::gitea::discover_deliverable_files;

        let tmp = std::env::temp_dir().join(format!(
            "libredb_release_outbox_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = fs::remove_dir_all(&tmp);
        let rel_dir = tmp.join("releases");
        let dist_dir = tmp.join("dist");
        fs::create_dir_all(&rel_dir).unwrap();
        fs::create_dir_all(&dist_dir).unwrap();

        // Outbox contains arbitrary release deliverables plus files that must be excluded.
        fs::write(rel_dir.join("libredb-v2.4.4-linux-x64"), b"elf").unwrap();
        fs::write(rel_dir.join("libredb.pyd"), b"pyd").unwrap();
        fs::write(rel_dir.join("SHA256SUMS.txt"), b"sums").unwrap();
        fs::write(rel_dir.join("libredb-v2.4.4-windows-x64.exe"), b"exe").unwrap();
        fs::write(rel_dir.join(".env"), b"SECRET=1").unwrap();
        fs::write(rel_dir.join("secret.ldb"), b"ldb").unwrap();
        fs::write(rel_dir.join("notes.tmp"), b"tmp").unwrap();
        fs::write(rel_dir.join("helper-v1.5.0.zip"), b"old").unwrap();

        // When `releases/` is populated, `dist/` must not leak into release uploads.
        fs::write(dist_dir.join("libredb.exe"), b"local_dist_only").unwrap();

        let exact_names = |files: Vec<std::path::PathBuf>| -> Vec<String> {
            let mut names: Vec<String> = files
                .into_iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            names.sort();
            names
        };

        assert!(super::is_release_deliverable_path("releases/libredb-v2.4.4-linux-x64"));
        assert!(super::is_release_deliverable_path("releases/libredb.pyd"));
        assert!(super::is_release_deliverable_path("release/libredb-v2.4.5-linux-arm64"));
        assert!(!super::is_release_deliverable_path("releases/.env"));
        assert!(!super::is_release_deliverable_path("releases/secret.ldb"));
        assert!(!super::is_release_deliverable_path("releases/notes.tmp"));

        assert_eq!(
            exact_names(discover_deliverable_files(&tmp, "v2.4.4", true)),
            vec![
                "SHA256SUMS.txt".to_owned(),
                "libredb-v2.4.4-linux-x64".to_owned(),
                "libredb-v2.4.4-windows-x64.exe".to_owned(),
                "libredb.pyd".to_owned(),
            ],
            "Release outbox must upload extensionless binaries and .pyd extensions while excluding secrets, temp files, old tags, and dist/"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gitea_env_vars_prefer_libredb_prefix_and_token_mask_is_utf8_safe() {
        let tmp = std::env::temp_dir().join(format!("libredb_gitea_env_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let db = LibreDb::open(tmp.join("cfg.ldb")).unwrap();

        let cfg = GiteaConfig::load_with_lookup(&db, |k| match k {
            "LIBREDB_GITEA_URL" => Some("https://gitea.new.example/".to_owned()),
            "SKILLSDB_GITEA_URL" => Some("https://gitea.old.example/".to_owned()),
            "SKILLSDB_GITEA_USER" => Some("legacy_user".to_owned()),
            "LIBREDB_GITEA_TOKEN" => Some("tok_prim_123456".to_owned()),
            "SKILLSDB_GITEA_TOKEN" => Some("tok_old_999999".to_owned()),
            "LIBREDB_GITEA_SERVICE" => Some("gitea_custom".to_owned()),
            "LIBREDB_GITEA_ALLOW_INSECURE_HTTP" => Some("true".to_owned()),
            _ => None,
        });
        assert_eq!(cfg.url, "https://gitea.new.example");
        assert_eq!(cfg.user, "legacy_user");
        assert_eq!(cfg.token, "tok_prim_123456");
        assert_eq!(cfg.service_name, "gitea_custom");
        assert!(cfg.allow_insecure_http);

        // Multibyte UTF-8 tokens where byte index 4 would fall inside a scalar must never panic.
        assert_eq!(
            super::mask_token_for_status("äöü€αβγδεζηθικ"),
            "äöü€...ηθικ (OS vault encrypted)"
        );
        assert_eq!(
            super::mask_token_for_status("short_ö"),
            "(set, OS vault encrypted)"
        );
        assert_eq!(super::mask_token_for_status(""), "(not set)");

        drop(db);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn preflight_detects_unpulled_remote_commits_before_partial_multi_remote_push() {
        let tmp = std::env::temp_dir().join(format!(
            "libredb_preflight_git_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let bare_origin = tmp.join("origin.git");
        let bare_github = tmp.join("github.git");
        let bare_empty = tmp.join("empty_mirror.git");
        let work_a = tmp.join("work_a");
        let work_b = tmp.join("work_b");

        for bare in [&bare_origin, &bare_github, &bare_empty] {
            let st = Command::new("git")
                .args(["init", "--bare"])
                .arg(bare)
                .status()
                .unwrap();
            assert!(st.success());
        }

        // Seed work_a -> initial commit pushed to both origin & github on branch `master`.
        assert!(Command::new("git").arg("init").arg(&work_a).status().unwrap().success());
        for args in [
            vec!["config", "user.name", "Test"],
            vec!["config", "user.email", "test@local.dev"],
            vec!["checkout", "-b", "master"],
        ] {
            assert!(Command::new("git").args(&args).current_dir(&work_a).status().unwrap().success());
        }
        fs::write(work_a.join("README.md"), "# Seed\n").unwrap();
        assert!(Command::new("git").args(["add", "README.md"]).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["commit", "-m", "initial seed"]).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["remote", "add", "origin"]).arg(&bare_origin).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["remote", "add", "github"]).arg(&bare_github).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["remote", "add", "empty"]).arg(&bare_empty).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["push", "-u", "origin", "master"]).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["push", "-u", "github", "master"]).current_dir(&work_a).status().unwrap().success());

        let base_sha = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work_a)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();

        // Clone `bare_github` into `work_b` and push a new upstream commit ONLY to `bare_github`.
        assert!(Command::new("git").arg("clone").arg(&bare_github).arg(&work_b).status().unwrap().success());
        assert!(Command::new("git").args(["config", "user.name", "Other"]).current_dir(&work_b).status().unwrap().success());
        assert!(Command::new("git").args(["config", "user.email", "other@local.dev"]).current_dir(&work_b).status().unwrap().success());
        fs::write(work_b.join("UPSTREAM.txt"), "upstream commit\n").unwrap();
        assert!(Command::new("git").args(["add", "UPSTREAM.txt"]).current_dir(&work_b).status().unwrap().success());
        assert!(Command::new("git").args(["commit", "-m", "upstream commit"]).current_dir(&work_b).status().unwrap().success());
        assert!(Command::new("git").args(["push", "origin", "master"]).current_dir(&work_b).status().unwrap().success());

        // Add local commit in `work_a` (now diverged relative to `github`, fast-forward relative to `origin`).
        fs::write(work_a.join("LOCAL.txt"), "local work\n").unwrap();
        assert!(Command::new("git").args(["add", "LOCAL.txt"]).current_dir(&work_a).status().unwrap().success());
        assert!(Command::new("git").args(["commit", "-m", "local commit"]).current_dir(&work_a).status().unwrap().success());

        let cfg = GiteaConfig {
            url: "http://127.0.0.1:3000".to_owned(),
            user: String::new(),
            token: String::new(),
            service_name: "gitea".to_owned(),
            allow_insecure_http: true,
        };
        let remotes = vec![
            ("origin".to_owned(), bare_origin.to_string_lossy().into_owned()),
            ("github".to_owned(), bare_github.to_string_lossy().into_owned()),
        ];

        // Preflight MUST fail on `github` BEFORE pushing anything to `origin`!
        let err = super::preflight_verify_remotes_fast_forward(&work_a, &cfg, &remotes, "master")
            .expect_err("Diverged secondary remote must abort atomic multi-remote sync");
        let err_s = err.to_string();
        assert!(
            err_s.contains("PREFLIGHT SYNC CONFLICT") && err_s.contains("github"),
            "Unexpected preflight conflict message: {err_s}"
        );

        let origin_ref = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "refs/heads/master"])
                .current_dir(&bare_origin)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        assert_eq!(origin_ref, base_sha, "Primary remote must remain untouched on preflight failure");

        // An empty brand-new mirror (without remote branch ref) alongside an up-to-date remote passes preflight cleanly.
        let clean_remotes = vec![
            ("origin".to_owned(), bare_origin.to_string_lossy().into_owned()),
            ("empty".to_owned(), bare_empty.to_string_lossy().into_owned()),
        ];
        super::preflight_verify_remotes_fast_forward(&work_a, &cfg, &clean_remotes, "master").unwrap();

        let _ = fs::remove_dir_all(&tmp);
    }
}
