//! Structured zero-dependency command-line flag and positional parser (`CliSpec` / `ParsedCli`).
//!
//! Guarantees deterministic validation across all `libredb` subcommands:
//! - Rejects unknown flags (`Unknown <cmd> flag '--typo'`), including single trailing flags that
//!   legacy `while i + 1 < args.len()` loops previously ignored.
//! - Rejects missing option values (`Missing value after '--budget' in 'pulse'`).
//! - Rejects unexpected extra positional arguments while supporting `--` end-of-options and
//!   hyphen-prefixed literal payload/query slots (`put <db> <kind> "-42"`, `pulse <db> "-D warnings"`).
//! - Uniformly supports `--global <customizations.ldb>` at any position when enabled.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct CliSpec<'a> {
    cmd: &'a str,
    usage: &'a str,
    min_positionals: usize,
    max_positionals: Option<usize>,
    raw_value_slots: Vec<usize>,
    allow_global: bool,
    switches: HashSet<&'a str>,
    values: HashSet<&'a str>,
    multi_values: HashSet<&'a str>,
    optional_bools: HashSet<&'a str>,
    aliases: HashMap<&'a str, &'a str>,
}

#[derive(Debug, Default)]
pub struct ParsedCli {
    pub global_path: Option<PathBuf>,
    pub positionals: Vec<String>,
    switches: HashSet<String>,
    values: HashMap<String, String>,
    multi_values: HashMap<String, Vec<String>>,
    optional_bools: HashMap<String, bool>,
}

impl<'a> CliSpec<'a> {
    pub fn new(cmd: &'a str, usage: &'a str) -> Self {
        Self {
            cmd,
            usage,
            min_positionals: 0,
            max_positionals: Some(0),
            raw_value_slots: Vec::new(),
            allow_global: false,
            switches: HashSet::new(),
            values: HashSet::new(),
            multi_values: HashSet::new(),
            optional_bools: HashSet::new(),
            aliases: HashMap::new(),
        }
    }

    pub fn positionals(mut self, min: usize, max: Option<usize>) -> Self {
        self.min_positionals = min;
        self.max_positionals = max;
        self
    }

    /// Marks 0-based positional indices whose literal value may legitimately start with `-`
    /// (such as a search query `"-D warnings"` or node payload `"-1"`), provided the token is
    /// not one of the subcommand's own declared flags.
    pub fn raw_value_slots(mut self, slots: &[usize]) -> Self {
        self.raw_value_slots = slots.to_vec();
        self
    }

    pub fn allow_global(mut self) -> Self {
        self.allow_global = true;
        self
    }

    pub fn switches(mut self, flags: &[&'a str]) -> Self {
        self.switches.extend(flags.iter().copied());
        self
    }

    pub fn values(mut self, flags: &[&'a str]) -> Self {
        self.values.extend(flags.iter().copied());
        self
    }

    pub fn multi_values(mut self, flags: &[&'a str]) -> Self {
        self.multi_values.extend(flags.iter().copied());
        self
    }

    pub fn optional_bools(mut self, flags: &[&'a str]) -> Self {
        self.optional_bools.extend(flags.iter().copied());
        self
    }

    pub fn alias(mut self, short_or_alt: &'a str, canonical: &'a str) -> Self {
        self.aliases.insert(short_or_alt, canonical);
        self
    }

    pub fn parse(&self, raw_sub_args: &[String]) -> Result<ParsedCli, String> {
        let mut out = ParsedCli::default();
        let mut i = 0usize;
        let mut after_double_dash = false;

        while i < raw_sub_args.len() {
            let tok = raw_sub_args[i].as_str();
            if !after_double_dash && tok == "--" {
                after_double_dash = true;
                i += 1;
                continue;
            }

            if !after_double_dash {
                let canonical = self.aliases.get(tok).copied().unwrap_or(tok);

                if self.allow_global && canonical == "--global" {
                    if i + 1 >= raw_sub_args.len() {
                        return Err(format!(
                            "Missing path argument after '{tok}' in '{}'",
                            self.cmd
                        ));
                    }
                    out.global_path = Some(PathBuf::from(&raw_sub_args[i + 1]));
                    i += 2;
                    continue;
                }

                if self.switches.contains(canonical) {
                    out.switches.insert(canonical.to_owned());
                    i += 1;
                    continue;
                }

                if self.values.contains(canonical) {
                    if i + 1 >= raw_sub_args.len() {
                        return Err(format!("Missing value after '{tok}' in '{}'", self.cmd));
                    }
                    out.values
                        .insert(canonical.to_owned(), raw_sub_args[i + 1].clone());
                    i += 2;
                    continue;
                }

                if self.multi_values.contains(canonical) {
                    if i + 1 >= raw_sub_args.len() {
                        return Err(format!("Missing value after '{tok}' in '{}'", self.cmd));
                    }
                    out.multi_values
                        .entry(canonical.to_owned())
                        .or_default()
                        .push(raw_sub_args[i + 1].clone());
                    i += 2;
                    continue;
                }

                if self.optional_bools.contains(canonical) {
                    if i + 1 < raw_sub_args.len() && !raw_sub_args[i + 1].starts_with('-') {
                        let b = parse_cli_bool(&raw_sub_args[i + 1]).ok_or_else(|| {
                            format!(
                                "Invalid boolean value '{}' after '{tok}' in '{}' (expected true/false)",
                                raw_sub_args[i + 1], self.cmd
                            )
                        })?;
                        out.optional_bools.insert(canonical.to_owned(), b);
                        i += 2;
                    } else {
                        out.optional_bools.insert(canonical.to_owned(), true);
                        i += 1;
                    }
                    continue;
                }

                if tok.starts_with('-') && !self.raw_value_slots.contains(&out.positionals.len()) {
                    return Err(format!("Unknown {} flag '{tok}'", self.cmd));
                }
            }

            if self
                .max_positionals
                .is_some_and(|max| out.positionals.len() >= max)
            {
                return Err(format!(
                    "Unexpected argument '{tok}' for '{}'.\nUsage: {}",
                    self.cmd, self.usage
                ));
            }
            out.positionals.push(tok.to_owned());
            i += 1;
        }

        if out.positionals.len() < self.min_positionals {
            return Err(format!("Usage: {}", self.usage));
        }

        Ok(out)
    }
}

impl ParsedCli {
    #[inline]
    pub fn global_deref(&self) -> Option<&Path> {
        self.global_path.as_deref()
    }

    #[inline]
    pub fn has_switch(&self, flag: &str) -> bool {
        self.switches.contains(flag)
    }

    #[inline]
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values.get(flag).map(String::as_str)
    }

    pub fn path_value(&self, flag: &str) -> Option<PathBuf> {
        self.values.get(flag).map(PathBuf::from)
    }

    pub fn parse_value<T>(&self, flag: &str) -> Result<Option<T>, String>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.values.get(flag) {
            Some(raw) => raw
                .parse::<T>()
                .map(Some)
                .map_err(|e| format!("Invalid value '{raw}' for '{flag}': {e}")),
            None => Ok(None),
        }
    }

    pub fn values_list(&self, flag: &str) -> &[String] {
        self.multi_values
            .get(flag)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn optional_bool(&self, flag: &str) -> Option<bool> {
        self.optional_bools.get(flag).copied()
    }
}

fn parse_cli_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_s(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn cli_spec_rejects_trailing_missing_values_and_unknown_flags() {
        let pulse_spec = CliSpec::new("pulse", "libredb pulse <db.ldb> <query> [--budget <tok>]")
            .positionals(2, Some(2))
            .raw_value_slots(&[1])
            .allow_global()
            .values(&["--cid", "--transcript", "--epoch", "--budget", "--cwd", "--err"]);

        // 1. Missing value on trailing `--budget` (previously swallowed by `while i + 1 < args.len()`!):
        let err_missing = pulse_spec
            .parse(&vec_s(&["proj.ldb", "auth seal", "--budget"]))
            .unwrap_err();
        assert!(err_missing.contains("Missing value after '--budget'"));

        // 2. Single trailing unknown flag (previously swallowed by `while i + 1 < args.len()`!):
        let err_unknown = pulse_spec
            .parse(&vec_s(&["proj.ldb", "auth seal", "--bogus"]))
            .unwrap_err();
        assert!(err_unknown.contains("Unknown pulse flag '--bogus'"));

        // 3. Hyphen-prefixed search query (`-D warnings`) + flexible `--global` placement:
        let ok = pulse_spec
            .parse(&vec_s(&[
                "--global",
                "custom.ldb",
                "proj.ldb",
                "-D warnings",
                "--budget",
                "450",
            ]))
            .unwrap();
        assert_eq!(ok.global_deref(), Some(Path::new("custom.ldb")));
        assert_eq!(ok.positionals, vec!["proj.ldb", "-D warnings"]);
        assert_eq!(ok.parse_value::<u32>("--budget").unwrap(), Some(450));
    }

    #[test]
    fn cli_spec_handles_aliases_multi_values_optional_bools_and_double_dash() {
        let cfg_spec = CliSpec::new("gitea-config", "libredb gitea-config ...")
            .positionals(0, Some(0))
            .allow_global()
            .switches(&["--token-stdin", "--register-helper"])
            .values(&["--url", "--user", "--token"])
            .optional_bools(&["--allow-insecure-http"]);

        let p1 = cfg_spec
            .parse(&vec_s(&["--allow-insecure-http", "--register-helper"]))
            .unwrap();
        assert_eq!(p1.optional_bool("--allow-insecure-http"), Some(true));
        assert!(p1.has_switch("--register-helper"));

        let p2 = cfg_spec
            .parse(&vec_s(&["--allow-insecure-http", "false"]))
            .unwrap();
        assert_eq!(p2.optional_bool("--allow-insecure-http"), Some(false));

        assert!(cfg_spec
            .parse(&vec_s(&["--allow-insecure-http", "notabool"]))
            .is_err());

        let sync_spec = CliSpec::new("git-sync", "libredb git-sync ...")
            .positionals(0, Some(0))
            .allow_global()
            .switches(&["--all-remotes", "--github", "--releases"])
            .values(&["--message", "--project", "--remote"])
            .alias("-m", "--message");
        let ps = sync_spec
            .parse(&vec_s(&["-m", "Ship v1.0.0", "--github", "--releases"]))
            .unwrap();
        assert_eq!(ps.value("--message"), Some("Ship v1.0.0"));
        assert!(ps.has_switch("--github"));
        assert!(ps.has_switch("--releases"));

        let batch_spec = CliSpec::new("batch", "libredb batch <db.ldb> ...")
            .positionals(1, Some(1))
            .allow_global()
            .multi_values(&["--fact", "--decision", "--task"])
            .values(&["--snapshot"]);
        let pb = batch_spec
            .parse(&vec_s(&[
                "mem.ldb",
                "--fact",
                "a=1",
                "--fact",
                "b=2",
                "--snapshot",
                "s1",
            ]))
            .unwrap();
        assert_eq!(pb.values_list("--fact"), &["a=1", "b=2"]);
        assert_eq!(pb.value("--snapshot"), Some("s1"));

        let put_spec = CliSpec::new("put", "libredb put <db> <kind> <payload>")
            .positionals(3, Some(3))
            .raw_value_slots(&[2])
            .switches(&["--pin"])
            .values(&["--key", "--importance"]);
        let pp = put_spec
            .parse(&vec_s(&["db.ldb", "Fact", "--", "--pin"]))
            .unwrap();
        assert_eq!(pp.positionals, vec!["db.ldb", "Fact", "--pin"]);
        assert!(!pp.has_switch("--pin"));
    }
}
