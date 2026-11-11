//! Hash-Verified Polyglot Code Contract Skeleton Extractor (`ContractSkeleton`).
//!
//! Compresses large source files (`1,000 - 20,000` lines) by `95-99%` into exact
//! module boundaries, symbol signatures, `[Lstart-Lend]` jump ranges, and lead docstrings,
//! skipping unchanged files in `O(1)` via deterministic 64-bit content hashing.

use libredb_core::crc::{count_tokens_exact, hash_key};
use libredb_core::{LibreDb, LibreDbError, NodeKind, Result, WriteRequest};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SKELETON_KEY_PREFIX: &str = "skeleton::";
/// Content-hash seed bumped whenever `FileSkeleton` extraction semantics upgrade (e.g. `container`
/// qualification, `supertypes`, interface/abstract method contracts, `Makefile`, and `< 5 us`
/// content-topology dispatch + `end`-block extraction in v1.1.0).
pub const SKELETON_HASH_SEED: u8 = 110;
/// Hard safety cap (`16 MiB`) for individual source files read by `skeleton` and `fim` so oversized
/// or special files cannot trigger unbounded memory allocations.
pub const MAX_SKELETON_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Reads `path` only after verifying via `symlink_metadata` that it is a regular non-symlink file
/// bounded by `MAX_SKELETON_FILE_BYTES` (`16 MiB`).
pub fn read_bounded_source_file(path: &Path) -> Result<Vec<u8>> {
    let sym_meta = std::fs::symlink_metadata(path).map_err(|e| {
        LibreDbError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })?;
    if sym_meta.file_type().is_symlink() {
        return Err(LibreDbError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing symlinked source file '{}'", path.display()),
        )));
    }
    if !sym_meta.is_file() {
        return Err(LibreDbError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{}' is not a regular file", path.display()),
        )));
    }
    if sym_meta.len() > MAX_SKELETON_FILE_BYTES {
        return Err(LibreDbError::PayloadTooLarge {
            size: usize::try_from(sym_meta.len()).unwrap_or(usize::MAX),
            max: MAX_SKELETON_FILE_BYTES as usize,
        });
    }
    let raw_bytes = std::fs::read(path).map_err(|e| {
        LibreDbError::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })?;
    if raw_bytes.len() > MAX_SKELETON_FILE_BYTES as usize {
        return Err(LibreDbError::PayloadTooLarge {
            size: raw_bytes.len(),
            max: MAX_SKELETON_FILE_BYTES as usize,
        });
    }
    Ok(raw_bytes)
}

/// Section boundary (e.g., `# SECTION: skillsdb.core.db` or `mod ...`) inside a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSpan {
    pub title: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Extracted structural contract for a single function, struct, enum, trait, or class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolContract {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supertypes: Vec<String>,
    pub signature: String,
    pub doc_summary: String,
    pub start_line: usize,
    pub end_line: usize,
}

impl SymbolContract {
    /// Returns `Container::name` when enclosed in an `impl`, `class`, `struct`, `trait`, or `interface`,
    /// or `name` for top-level declarations.
    pub fn qualified_name(&self) -> String {
        match self.container.as_deref() {
            Some(c) if !c.is_empty() => format!("{c}::{}", self.name),
            _ => self.name.clone(),
        }
    }
}

/// Cached structural map of a source file stored inside `LibreDb` (`NodeKind::WorkingSet`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSkeleton {
    pub file_label: String,
    pub language: String,
    pub content_hash: u64,
    pub total_lines: usize,
    pub raw_tokens: u32,
    pub skeleton_tokens: u32,
    pub sections: Vec<SectionSpan>,
    pub symbols: Vec<SymbolContract>,
}

impl FileSkeleton {
    /// Extracts a `FileSkeleton` directly from in-memory source text.
    pub fn extract(file_label: impl Into<String>, source: &str) -> Self {
        Self::extract_from_bytes(file_label, source.as_bytes())
    }

    /// Extracts a `FileSkeleton` from raw file bytes, computing `content_hash` over the exact raw
    /// byte buffer (`CRLF` or `LF` preserved) so in-RAM `PreToolUse` simulations match post-edit
    /// disk files identically.
    pub fn extract_from_bytes(file_label: impl Into<String>, raw_bytes: &[u8]) -> Self {
        let label = file_label.into();
        let content_hash = hash_key(SKELETON_HASH_SEED, raw_bytes);
        let raw_tokens = count_tokens_exact(raw_bytes);
        let text = String::from_utf8_lossy(raw_bytes);
        let lines: Vec<&str> = text.lines().collect();
        let total_lines = lines.len();
        let ext_lang = detect_language(&label);
        let lang = if ext_lang == "code" {
            infer_topology_from_content(&lines).to_owned()
        } else {
            ext_lang
        };

        let sections = extract_sections(&lines, total_lines);
        let symbols = match lang.as_str() {
            "python" | "nim" | "gdscript" => extract_python_symbols(&lines, total_lines),
            "smali" => extract_smali_symbols(&lines, total_lines),
            "asm" => extract_asm_symbols(&lines, total_lines),
            "markdown" => extract_markdown_symbols(&lines, total_lines),
            "makefile" => extract_makefile_symbols(&lines, total_lines),
            "sql" => extract_sql_symbols(&lines, total_lines),
            "powershell" => extract_powershell_symbols(&lines, total_lines),
            "shell" => extract_shell_symbols(&lines, total_lines),
            "ruby" | "lua" | "elixir" | "julia" | "verilog" | "endblock" => {
                extract_end_block_symbols(&lines, total_lines)
            }
            _ => extract_brace_symbols(&lines, total_lines, &lang),
        };

        let mut skel = Self {
            file_label: label,
            language: lang,
            content_hash,
            total_lines,
            raw_tokens,
            skeleton_tokens: 0,
            sections,
            symbols,
        };
        let rendered = skel.render_compact(None, true);
        skel.skeleton_tokens = count_tokens_exact(rendered.as_bytes());
        skel
    }

    /// Returns a cached `FileSkeleton` from `db` if the file's 64-bit content hash matches,
    /// or extracts and persists an updated skeleton when the file is new or modified!
    pub fn index_or_get_cached(db: &LibreDb, path: &Path, display_label: Option<&str>) -> Result<(Self, bool)> {
        let raw_bytes = read_bounded_source_file(path)?;
        let label = display_label
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"));
        Self::index_or_get_cached_bytes(db, label, &raw_bytes)
    }

    /// Returns a cached `FileSkeleton` for an already-read `raw_bytes` buffer (avoiding duplicate disk reads).
    pub fn index_or_get_cached_bytes(
        db: &LibreDb,
        label: String,
        raw_bytes: &[u8],
    ) -> Result<(Self, bool)> {
        let current_hash = hash_key(SKELETON_HASH_SEED, raw_bytes);
        let key = format!("{SKELETON_KEY_PREFIX}{label}");

        if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &key) {
            if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                if cached.content_hash == current_hash {
                    return Ok((cached, true)); // `true` = cache hit, zero re-parse!
                }
            }
        }

        let skel = Self::extract_from_bytes(label, raw_bytes);
        let encoded = serde_json::to_vec(&skel)
            .map_err(|_| LibreDbError::CorruptFormat("skeleton json serialize"))?;
        db.put(
            WriteRequest::new(NodeKind::WorkingSet, encoded)
                .with_key(key)
                .with_importance(200),
        )?;

        Ok((skel, false))
    }

    /// Extracts or retrieves hash-cached `FileSkeleton`s for a batch of files and commits all
    /// cache misses in a **single `commit_batch` (`1` `fsync` total instead of `N` `fsync` calls!)**.
    pub fn index_or_get_cached_batch(
        db: &LibreDb,
        items: &[(&Path, Option<&str>)],
    ) -> Result<Vec<(Self, bool)>> {
        let mut results: Vec<(Self, bool)> = Vec::with_capacity(items.len());
        let mut pending_writes: Vec<libredb_core::PreparedWrite> = Vec::new();

        for (idx, &(path, display_label)) in items.iter().enumerate() {
            let raw_bytes = read_bounded_source_file(path)?;
            let current_hash = hash_key(SKELETON_HASH_SEED, &raw_bytes);
            let label = display_label
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"));
            let key = format!("{SKELETON_KEY_PREFIX}{label}");

            if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &key) {
                if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                    if cached.content_hash == current_hash {
                        results.push((cached, true));
                        continue;
                    }
                }
            }

            let skel = Self::extract_from_bytes(label, &raw_bytes);
            let encoded = serde_json::to_vec(&skel)
                .map_err(|_| LibreDbError::CorruptFormat("skeleton json serialize"))?;
            let prep = db.prepare(
                WriteRequest::new(NodeKind::WorkingSet, encoded)
                    .with_key(key)
                    .with_importance(200),
                idx,
            )?;
            pending_writes.push(prep);
            results.push((skel, false));
        }

        if !pending_writes.is_empty() {
            db.commit_batch(&pending_writes)?;
        }

        Ok(results)
    }

    /// Renders a dense, LLM-optimized contract map (`95-99%` smaller than raw file reads).
    pub fn render_compact(&self, filter: Option<&str>, include_private: bool) -> String {
        let filt_low = filter.map(str::to_ascii_lowercase);
        let saved_pct = if self.raw_tokens > 0 && self.skeleton_tokens > 0 && self.skeleton_tokens < self.raw_tokens {
            (1.0 - (self.skeleton_tokens as f64 / self.raw_tokens as f64)) * 100.0
        } else {
            0.0
        };

        let mut out = String::new();
        if saved_pct > 0.0 {
            out.push_str(&format!(
                "=== SKELETON: {} ({}, L1-L{}, ~{} -> ~{} tok, -{:.1}%) ===\n",
                self.file_label, self.language, self.total_lines, self.raw_tokens, self.skeleton_tokens, saved_pct
            ));
        } else {
            out.push_str(&format!(
                "=== SKELETON: {} ({}, L1-L{}) ===\n",
                self.file_label, self.language, self.total_lines
            ));
        }

        if !self.sections.is_empty() {
            out.push_str("Sections:\n");
            for sec in &self.sections {
                if let Some(ref flt) = filt_low {
                    if !sec.title.to_ascii_lowercase().contains(flt) {
                        continue;
                    }
                }
                out.push_str(&format!(
                    "  [L{}-L{}] {}\n",
                    sec.start_line, sec.end_line, sec.title
                ));
            }
        }

        out.push_str("Contracts:\n");
        for sym in &self.symbols {
            if !include_private && sym.name.starts_with('_') && !sym.name.starts_with("__") {
                continue;
            }
            if let Some(ref flt) = filt_low {
                let hay = format!(
                    "{} {} {} {}",
                    sym.qualified_name(),
                    sym.name,
                    sym.signature,
                    sym.doc_summary
                )
                .to_ascii_lowercase();
                if !hay.contains(flt) {
                    continue;
                }
            }
            if sym.doc_summary.is_empty() {
                out.push_str(&format!(
                    "  [L{}-L{}] {}\n",
                    sym.start_line, sym.end_line, sym.signature
                ));
            } else {
                out.push_str(&format!(
                    "  [L{}-L{}] {} // {}\n",
                    sym.start_line, sym.end_line, sym.signature, sym.doc_summary
                ));
            }
        }
        out
    }
}

fn detect_language(label: &str) -> String {
    let low = label.to_ascii_lowercase();
    let fname = low.rsplit(['/', '\\']).next().unwrap_or(&low);
    if matches!(fname, "makefile" | "gnumakefile" | "justfile") || low.ends_with(".mk") {
        return "makefile".to_owned();
    }
    if low.ends_with(".rs") {
        "rust".to_owned()
    } else if low.ends_with(".py") || low.ends_with(".pyi") || low.ends_with(".star") || low.ends_with(".mojo") {
        "python".to_owned()
    } else if low.ends_with(".nim") {
        "nim".to_owned()
    } else if low.ends_with(".gd") {
        "gdscript".to_owned()
    } else if low.ends_with(".ts") || low.ends_with(".tsx") {
        "typescript".to_owned()
    } else if low.ends_with(".js") || low.ends_with(".jsx") || low.ends_with(".mjs") || low.ends_with(".cjs") {
        "javascript".to_owned()
    } else if low.ends_with(".dart") {
        "dart".to_owned()
    } else if low.ends_with(".go") {
        "go".to_owned()
    } else if low.ends_with(".zig") {
        "zig".to_owned()
    } else if low.ends_with(".smali") {
        "smali".to_owned()
    } else if low.ends_with(".asm")
        || low.ends_with(".s")
        || low.ends_with(".inc")
        || low.ends_with(".dis")
    {
        "asm".to_owned()
    } else if low.ends_with(".md") || low.ends_with(".markdown") || low.ends_with(".mdx") {
        "markdown".to_owned()
    } else if low.ends_with(".ps1") || low.ends_with(".psm1") {
        "powershell".to_owned()
    } else if low.ends_with(".sql") {
        "sql".to_owned()
    } else if low.ends_with(".sh") || low.ends_with(".bash") || low.ends_with(".zsh") {
        "shell".to_owned()
    } else if low.ends_with(".java") {
        "java".to_owned()
    } else if low.ends_with(".kt") || low.ends_with(".kts") {
        "kotlin".to_owned()
    } else if low.ends_with(".cs") {
        "csharp".to_owned()
    } else if low.ends_with(".c") || low.ends_with(".h") {
        "c".to_owned()
    } else if low.ends_with(".cc")
        || low.ends_with(".cpp")
        || low.ends_with(".cxx")
        || low.ends_with(".hpp")
        || low.ends_with(".hh")
    {
        "cpp".to_owned()
    } else if low.ends_with(".swift") {
        "swift".to_owned()
    } else if low.ends_with(".rb") {
        "ruby".to_owned()
    } else if low.ends_with(".lua") {
        "lua".to_owned()
    } else if low.ends_with(".ex") || low.ends_with(".exs") {
        "elixir".to_owned()
    } else if low.ends_with(".jl") {
        "julia".to_owned()
    } else if low.ends_with(".v") || low.ends_with(".sv") {
        "verilog".to_owned()
    } else if low.ends_with(".php") {
        "php".to_owned()
    } else {
        "code".to_owned()
    }
}

/// Deterministic `< 5 us` local syntax-topology fingerprint over at most the first `80` lines
/// when a file lacks a known extension (extensionless scripts, `.dump`, `.txt`, `.bak`, etc.).
/// Zero network calls, zero LLM tokens, `O(1)` bounded work.
fn infer_topology_from_content(lines: &[&str]) -> &'static str {
    if let Some(first) = lines.first().map(|l| l.trim()) {
        if let Some(shebang) = first.strip_prefix("#!") {
            let low = shebang.to_ascii_lowercase();
            if low.contains("python") || low.contains("mojo") {
                return "python";
            }
            if low.contains("ruby") || low.contains("lua") || low.contains("elixir") || low.contains("julia") {
                return "endblock";
            }
            if low.contains("pwsh") || low.contains("powershell") {
                return "powershell";
            }
            if low.contains("node") || low.contains("deno") || low.contains("bun") {
                return "javascript";
            }
            if low.contains("bash") || low.contains("/sh") || low.contains(" sh") || low.contains("zsh") {
                return "shell";
            }
        }
    }

    let mut smali_hits = 0usize;
    let mut asm_hits = 0usize;
    let mut sql_hits = 0usize;
    let mut brace_hits = 0usize;
    let mut indent_colon_hits = 0usize;
    let mut end_block_openers = 0usize;
    let mut end_block_closers = 0usize;
    let mut md_heading_hits = 0usize;
    let mut non_empty = 0usize;

    for &line in lines.iter().take(120) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        non_empty += 1;
        if non_empty > 80 {
            break;
        }

        if trimmed.starts_with(".class ")
            || trimmed.starts_with(".super ")
            || trimmed.starts_with(".method ")
            || trimmed == ".end method"
            || trimmed.starts_with("invoke-")
        {
            smali_hits += 1;
        }
        if trimmed.contains(" PROC")
            || trimmed.ends_with(" ENDP")
            || trimmed.starts_with(".globl ")
            || trimmed.starts_with(".section ")
            || trimmed.starts_with("SECTION ")
        {
            asm_hits += 1;
        }
        let up = trimmed.to_ascii_uppercase();
        if up.starts_with("CREATE TABLE ")
            || up.starts_with("CREATE VIEW ")
            || up.starts_with("CREATE FUNCTION ")
            || up.starts_with("ALTER TABLE ")
        {
            sql_hits += 1;
        }
        if trimmed.ends_with('{') || trimmed == "}" || trimmed.starts_with("} ") {
            brace_hits += 1;
        }
        if !trimmed.contains('{')
            && trimmed.ends_with(':')
            && (trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("func ")
                || trimmed.starts_with("proc "))
        {
            indent_colon_hits += 1;
        }
        if !trimmed.contains('{')
            && !trimmed.ends_with(':')
            && (trimmed.starts_with("function ")
                || trimmed.starts_with("local function ")
                || trimmed.starts_with("def ")
                || trimmed.starts_with("defp ")
                || trimmed.starts_with("defmodule ")
                || trimmed.starts_with("module ")
                || trimmed.starts_with("class "))
        {
            end_block_openers += 1;
        }
        if matches!(trimmed, "end" | "endmodule") {
            end_block_closers += 1;
        }
        if trimmed.starts_with("# ") || trimmed.starts_with("## ") || trimmed.starts_with("### ") {
            md_heading_hits += 1;
        }
    }

    if smali_hits >= 2 {
        "smali"
    } else if asm_hits >= 2 {
        "asm"
    } else if sql_hits >= 1 && brace_hits == 0 {
        "sql"
    } else if indent_colon_hits >= 1 && brace_hits == 0 {
        "python"
    } else if end_block_openers >= 1 && end_block_closers >= 1 && brace_hits == 0 {
        "endblock"
    } else if md_heading_hits >= 2 && brace_hits == 0 {
        "markdown"
    } else {
        "code"
    }
}

fn extract_sections(lines: &[&str], total_lines: usize) -> Vec<SectionSpan> {
    let mut raw: Vec<(usize, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# SECTION:") {
            raw.push((idx + 1, rest.trim().to_owned()));
        } else if let Some(rest) = trimmed.strip_prefix("// SECTION:") {
            raw.push((idx + 1, rest.trim().to_owned()));
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let (start, ref title) = raw[i];
        let end = if i + 1 < raw.len() {
            raw[i + 1].0.saturating_sub(1)
        } else {
            total_lines
        };
        out.push(SectionSpan {
            title: title.clone(),
            start_line: start,
            end_line: end,
        });
    }
    out
}

fn extract_python_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut raw: Vec<(usize, usize, String, String, String)> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let indent = line.len() - line.trim_start().len();
        // Capture top-level and class-method definitions (`indent <= 4`).
        if indent > 4 {
            continue;
        }
        let trimmed = line.trim();
        let (kind, rest) = if let Some(r) = trimmed.strip_prefix("def ") {
            ("def", r)
        } else if let Some(r) = trimmed.strip_prefix("async def ") {
            ("async def", r)
        } else if let Some(r) = trimmed.strip_prefix("func ") {
            ("func", r)
        } else if let Some(r) = trimmed.strip_prefix("proc ") {
            ("proc", r)
        } else if let Some(r) = trimmed.strip_prefix("class ") {
            ("class", r)
        } else {
            continue;
        };

        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }

        // Gather multi-line signature up to closing `:`
        let mut sig = trimmed.to_owned();
        let mut sig_end_idx = idx;
        while !sig.trim_end().ends_with(':') && sig_end_idx + 1 < total_lines && sig_end_idx < idx + 8 {
            sig_end_idx += 1;
            sig.push(' ');
            sig.push_str(lines[sig_end_idx].trim());
        }
        let clean_sig = collapse_ws(&sig).trim_end_matches(':').to_owned();
        let doc = extract_python_docstring(lines, sig_end_idx + 1);
        raw.push((idx + 1, indent, kind.to_owned(), name, format!("{clean_sig}|DOC|{doc}")));
    }

    let mut out = Vec::with_capacity(raw.len());
    let mut active_class: Option<(String, usize, usize)> = None;
    for i in 0..raw.len() {
        let (start_line, indent, ref kind, ref name, ref packed) = raw[i];
        // Find end line where a non-empty non-comment line returns to `<= indent`.
        let mut end_line = start_line;
        for (scan_idx, scan_line) in lines.iter().enumerate().skip(start_line) {
            let t = scan_line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let scan_indent = scan_line.len() - scan_line.trim_start().len();
            if scan_indent <= indent && !t.starts_with(')') && !t.starts_with(']') {
                break;
            }
            end_line = scan_idx + 1;
        }
        let resolved_end = end_line.max(start_line);
        if let Some((_, cls_end, cls_indent)) = active_class.as_ref() {
            if start_line > *cls_end || indent <= *cls_indent {
                active_class = None;
            }
        }
        let container = if kind == "class" {
            None
        } else {
            active_class.as_ref().map(|(c, _, _)| c.clone())
        };
        if kind == "class" {
            active_class = Some((name.clone(), resolved_end, indent));
        }
        let (signature, doc_summary) = packed.split_once("|DOC|").unwrap_or((packed, ""));
        let supertypes = if kind == "class" {
            extract_python_supertypes(signature)
        } else {
            Vec::new()
        };
        out.push(SymbolContract {
            kind: kind.clone(),
            name: name.clone(),
            container,
            supertypes,
            signature: truncate_chars(signature, 115),
            doc_summary: truncate_chars(doc_summary, 85),
            start_line,
            end_line: resolved_end,
        });
    }
    out
}

fn extract_python_docstring(lines: &[&str], body_start_idx: usize) -> String {
    if body_start_idx >= lines.len() {
        return String::new();
    }
    let first = lines[body_start_idx].trim();
    for delim in ["\"\"\"", "'''"] {
        if let Some(after) = first.strip_prefix(delim) {
            let inline_clean = after.trim_end_matches(delim).trim();
            if !inline_clean.is_empty() {
                return collapse_ws(inline_clean);
            }
            for next in lines.iter().skip(body_start_idx + 1).take(3) {
                let nt = next.trim().trim_end_matches(delim).trim();
                if !nt.is_empty() && nt != delim {
                    return collapse_ws(nt);
                }
            }
        }
    }
    String::new()
}

fn extract_smali_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    let mut current_class: Option<String> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(".class ") {
            if let Some(tok) = rest.split_whitespace().last() {
                let clean = tok.trim_start_matches('L').trim_end_matches(';');
                let short = clean.rsplit('/').next().unwrap_or(clean).to_owned();
                if !short.is_empty() {
                    current_class = Some(short.clone());
                    out.push(SymbolContract {
                        kind: "class".to_owned(),
                        name: short,
                        container: None,
                        supertypes: Vec::new(),
                        signature: truncate_chars(trimmed, 115),
                        doc_summary: String::new(),
                        start_line: idx + 1,
                        end_line: total_lines.max(idx + 1),
                    });
                }
            }
        } else if let Some(rest) = trimmed
            .strip_prefix(".super ")
            .or_else(|| trimmed.strip_prefix(".implements "))
        {
            if let Some(tok) = rest.split_whitespace().last() {
                let clean = tok.trim_start_matches('L').trim_end_matches(';');
                let short = clean.rsplit('/').next().unwrap_or(clean);
                if !short.is_empty() && short != "Object" {
                    if let Some(cls_sym) = out.iter_mut().rev().find(|s| s.kind == "class") {
                        if !cls_sym.supertypes.iter().any(|x| x == short) {
                            cls_sym.supertypes.push(short.to_owned());
                        }
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix(".field ") {
            let head = rest.split('=').next().unwrap_or(rest).trim();
            if let Some(tok) = head.split_whitespace().last() {
                if let Some((fname, _)) = tok.split_once(':') {
                    if !fname.is_empty() {
                        out.push(SymbolContract {
                            kind: "field".to_owned(),
                            name: fname.to_owned(),
                            container: current_class.clone(),
                            supertypes: Vec::new(),
                            signature: truncate_chars(trimmed, 115),
                            doc_summary: String::new(),
                            start_line: idx + 1,
                            end_line: idx + 1,
                        });
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix(".method ") {
            if let Some(tok) = rest.split_whitespace().last() {
                if let Some((mname, _)) = tok.split_once('(') {
                    if !mname.is_empty() {
                        let mut end_line = idx + 1;
                        for (s_idx, s_line) in lines.iter().enumerate().skip(idx + 1) {
                            if s_line.trim().starts_with(".end method") {
                                end_line = s_idx + 1;
                                break;
                            }
                        }
                        out.push(SymbolContract {
                            kind: "method".to_owned(),
                            name: mname.to_owned(),
                            container: current_class.clone(),
                            supertypes: Vec::new(),
                            signature: truncate_chars(trimmed, 115),
                            doc_summary: String::new(),
                            start_line: idx + 1,
                            end_line,
                        });
                    }
                }
            }
        }
    }
    out
}

fn strip_disasm_address_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    // Handle IDA/Ghidra/objdump prefixes such as `.text:0000000140001000 ` or `00007ff612345678 `
    let Some((first_tok, rest)) = trimmed.split_once(char::is_whitespace) else {
        return trimmed;
    };
    let rest = rest.trim_start();
    if let Some((seg, addr)) = first_tok.split_once(':') {
        if (seg.starts_with('.') || seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
            && !addr.is_empty()
            && addr.chars().all(|c| c.is_ascii_hexdigit())
        {
            return rest;
        }
    }
    if first_tok.len() >= 6
        && first_tok.len() <= 18
        && first_tok.trim_end_matches(':').chars().all(|c| c.is_ascii_hexdigit())
    {
        return rest;
    }
    trimmed
}

fn is_local_branch_label(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    name.starts_with('.')
        || name.starts_with("@@")
        || low.starts_with("loc_")
        || low.starts_with("locret_")
        || low.starts_with("jpt_")
        || low.starts_with("def_")
}

fn extract_asm_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut raw: Vec<(usize, Option<usize>, String, String, String)> = Vec::new();

    for (idx, &line) in lines.iter().enumerate() {
        let stripped = strip_disasm_address_prefix(line);
        let code_part = stripped.split(';').next().unwrap_or(stripped).trim();
        if code_part.is_empty() || code_part.starts_with("//") || code_part.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = code_part.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // 1. Section / segment directives (`SECTION .text`, `.section .text`, `.text`)
        let t0_up = tokens[0].to_ascii_uppercase();
        if matches!(t0_up.as_str(), "SECTION" | ".SECTION" | "SEGMENT") && tokens.len() >= 2 {
            let sec_name = tokens[1].trim_matches([',', '"']);
            raw.push((
                idx + 1,
                Some(idx + 1),
                "section".to_owned(),
                sec_name.to_owned(),
                truncate_chars(code_part, 115),
            ));
            continue;
        }

        // 2. MASM / IDA `<name> PROC ...`
        if tokens.len() >= 2 && tokens[1].eq_ignore_ascii_case("PROC") {
            let proc_name = tokens[0].trim_end_matches(':');
            if !proc_name.is_empty() && !is_local_branch_label(proc_name) {
                let mut end_opt = None;
                for (s_idx, &s_line) in lines.iter().enumerate().skip(idx + 1) {
                    let s_clean = strip_disasm_address_prefix(s_line)
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim();
                    let s_toks: Vec<&str> = s_clean.split_whitespace().collect();
                    if s_toks.iter().any(|t| t.eq_ignore_ascii_case("ENDP")) {
                        end_opt = Some(s_idx + 1);
                        break;
                    }
                }
                raw.push((
                    idx + 1,
                    end_opt,
                    "proc".to_owned(),
                    proc_name.to_owned(),
                    truncate_chars(code_part, 115),
                ));
                continue;
            }
        }

        // 3. objdump `<00401000 <func_name>:` or top-level `<label>:`
        if let Some(before_colon) = code_part.strip_suffix(':') {
            let cand = before_colon.trim();
            let label = if let (Some(lt), Some(gt)) = (cand.find('<'), cand.rfind('>')) {
                if lt + 1 < gt {
                    &cand[lt + 1..gt]
                } else {
                    cand
                }
            } else {
                cand
            };
            if !label.is_empty()
                && !label.contains(char::is_whitespace)
                && !is_local_branch_label(label)
                && label
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '?' | '@'))
            {
                raw.push((
                    idx + 1,
                    None,
                    "label".to_owned(),
                    label.to_owned(),
                    truncate_chars(code_part, 115),
                ));
            }
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let (start, explicit_end, ref kind, ref name, ref sig) = raw[i];
        let end_line = explicit_end.unwrap_or_else(|| {
            if i + 1 < raw.len() {
                raw[i + 1].0.saturating_sub(1).max(start)
            } else {
                total_lines.max(start)
            }
        });
        out.push(SymbolContract {
            kind: kind.clone(),
            name: name.clone(),
            container: None,
            supertypes: Vec::new(),
            signature: sig.clone(),
            doc_summary: String::new(),
            start_line: start,
            end_line,
        });
    }
    out
}

fn extract_markdown_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut raw: Vec<(usize, usize, String, String)> = Vec::new();
    let mut in_fence = false;

    for (idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || !trimmed.starts_with('#') {
            continue;
        }
        let hashes = trimmed.chars().take_while(|&c| c == '#').count();
        if (1..=4).contains(&hashes) {
            let rest = trimmed[hashes..].trim();
            if !rest.is_empty() {
                raw.push((
                    idx + 1,
                    hashes,
                    rest.to_owned(),
                    truncate_chars(trimmed.trim_end(), 115),
                ));
            }
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let (start, level, ref title, ref sig) = raw[i];
        let mut end_line = total_lines.max(start);
        for &(next_start, next_level, _, _) in &raw[i + 1..] {
            if next_level <= level {
                end_line = next_start.saturating_sub(1).max(start);
                break;
            }
        }
        out.push(SymbolContract {
            kind: format!("h{level}"),
            name: title.clone(),
            container: None,
            supertypes: Vec::new(),
            signature: sig.clone(),
            doc_summary: String::new(),
            start_line: start,
            end_line,
        });
    }
    out
}

fn extract_makefile_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut raw: Vec<(usize, String, String, String)> = Vec::new();
    let mut pending_doc = String::new();

    for (idx, &line) in lines.iter().enumerate() {
        if line.starts_with('\t') {
            pending_doc.clear();
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            pending_doc.clear();
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix('#') {
            let c = comment.trim();
            if !c.is_empty() && pending_doc.is_empty() {
                pending_doc = c.to_owned();
            }
            continue;
        }
        if trimmed.starts_with('.') {
            pending_doc.clear();
            continue;
        }
        // Distinguish target rules (`build: deps`) from variable assignments (`CC := gcc`, `CFLAGS ?= ...`)
        if let Some((lhs, rhs)) = trimmed.split_once(':') {
            if rhs.starts_with('=') || lhs.ends_with(['?', '+', '!']) || lhs.contains('=') {
                pending_doc.clear();
                continue;
            }
            let target = lhs.split_whitespace().next().unwrap_or("").trim();
            if !target.is_empty()
                && !target.contains('$')
                && target
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'))
            {
                let inline_doc = rhs.split_once("##").map_or("", |(_, d)| d.trim());
                let doc = if !inline_doc.is_empty() {
                    inline_doc.to_owned()
                } else {
                    std::mem::take(&mut pending_doc)
                };
                let sig = trimmed.split("##").next().unwrap_or(trimmed).trim();
                raw.push((idx + 1, target.to_owned(), truncate_chars(sig, 115), doc));
                pending_doc.clear();
                continue;
            }
        }
        pending_doc.clear();
    }

    let mut out = Vec::with_capacity(raw.len());
    for i in 0..raw.len() {
        let (start, ref name, ref sig, ref doc) = raw[i];
        let mut end_line = start;
        for (s_idx, &s_line) in lines.iter().enumerate().skip(start) {
            if i + 1 < raw.len() && s_idx + 1 >= raw[i + 1].0 {
                break;
            }
            if s_line.starts_with('\t') || s_line.trim_end().ends_with('\\') {
                end_line = s_idx + 1;
            } else if s_line.trim().is_empty() {
                continue;
            } else {
                break;
            }
        }
        out.push(SymbolContract {
            kind: "target".to_owned(),
            name: name.clone(),
            container: None,
            supertypes: Vec::new(),
            signature: sig.clone(),
            doc_summary: truncate_chars(doc, 85),
            start_line: start,
            end_line: end_line.min(total_lines.max(start)),
        });
    }
    out
}

/// Extracts `class`/`module`/`defmodule` containers and `def`/`defp`/`function`/`local function`
/// contracts across keyword-delimited `end` languages (`Ruby`, `Lua`, `Elixir`, `Julia`, `Verilog`).
fn extract_end_block_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    let mut active_container: Option<(String, usize)> = None;

    for (idx, &line) in lines.iter().enumerate() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("--") || trimmed.starts_with("//") {
            continue;
        }

        if let Some((_, c_indent)) = active_container {
            if indent <= c_indent && matches!(trimmed, "end" | "endmodule") {
                active_container = None;
                continue;
            }
        }

        let (kind, raw_rest, is_container) = if let Some(r) = trimmed.strip_prefix("defmodule ") {
            ("module", r, true)
        } else if let Some(r) = trimmed.strip_prefix("module ") {
            ("module", r, true)
        } else if let Some(r) = trimmed.strip_prefix("class ") {
            ("class", r, true)
        } else if let Some(r) = trimmed.strip_prefix("local function ") {
            ("function", r, false)
        } else if let Some(r) = trimmed.strip_prefix("function ") {
            ("function", r, false)
        } else if let Some(r) = trimmed.strip_prefix("defp ") {
            ("defp", r, false)
        } else if let Some(r) = trimmed.strip_prefix("def ") {
            ("def", r, false)
        } else {
            continue;
        };

        let raw_head = raw_rest
            .split(['(', ' ', '<', ';', ','])
            .next()
            .unwrap_or("")
            .trim();
        if raw_head.is_empty() {
            continue;
        }

        // Handle Lua `M.foo` / `M:foo` and Ruby `self.foo` qualified method syntax cleanly:
        let (explicit_owner, clean_name) = if let Some((owner, m)) = raw_head.rsplit_once(['.', ':']) {
            let owner_clean = owner.trim();
            if owner_clean == "self" {
                (None, m.trim())
            } else {
                (Some(owner_clean.to_owned()), m.trim())
            }
        } else {
            (None, raw_head)
        };
        if clean_name.is_empty() {
            continue;
        }

        let mut supertypes = Vec::new();
        if is_container {
            if let Some((_, sup_part)) = raw_rest.split_once('<') {
                let sup = sup_part
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
                    .trim();
                if !sup.is_empty() {
                    supertypes.push(sup.to_owned());
                }
            }
        }

        // Scan forward for matching indentation `end` / `endmodule` (or single-line `, do:` in Elixir):
        let mut end_line = idx + 1;
        if !trimmed.contains(", do:") {
            for (s_idx, &s_line) in lines.iter().enumerate().skip(idx + 1) {
                let s_trim = s_line.trim();
                if s_trim.is_empty() || s_trim.starts_with('#') || s_trim.starts_with("--") {
                    continue;
                }
                let s_indent = s_line.len() - s_line.trim_start().len();
                if s_indent <= indent && matches!(s_trim, "end" | "endmodule") {
                    end_line = s_idx + 1;
                    break;
                }
            }
        }

        let container = if is_container {
            active_container = Some((clean_name.to_owned(), indent));
            None
        } else {
            explicit_owner.or_else(|| active_container.as_ref().map(|(c, _)| c.clone()))
        };

        out.push(SymbolContract {
            kind: kind.to_owned(),
            name: clean_name.to_owned(),
            container,
            supertypes,
            signature: truncate_chars(trimmed, 115),
            doc_summary: String::new(),
            start_line: idx + 1,
            end_line: end_line.min(total_lines.max(idx + 1)),
        });
    }

    out
}

fn extract_sql_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("--") {
            continue;
        }
        let up = trimmed.to_ascii_uppercase();
        if !up.starts_with("CREATE ") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let mut i = 1usize;
        if tokens.get(i).is_some_and(|t| t.eq_ignore_ascii_case("OR"))
            && tokens.get(i + 1).is_some_and(|t| t.eq_ignore_ascii_case("REPLACE"))
        {
            i += 2;
        }
        if tokens.get(i).is_some_and(|t| {
            t.eq_ignore_ascii_case("TEMP")
                || t.eq_ignore_ascii_case("TEMPORARY")
                || t.eq_ignore_ascii_case("UNIQUE")
                || t.eq_ignore_ascii_case("VIRTUAL")
        }) {
            i += 1;
        }
        let Some(&kind_tok) = tokens.get(i) else {
            continue;
        };
        let kind_up = kind_tok.to_ascii_uppercase();
        if !matches!(
            kind_up.as_str(),
            "TABLE" | "VIEW" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "INDEX" | "TYPE"
        ) {
            continue;
        }
        i += 1;
        if tokens.get(i).is_some_and(|t| t.eq_ignore_ascii_case("IF"))
            && tokens.get(i + 1).is_some_and(|t| t.eq_ignore_ascii_case("NOT"))
            && tokens.get(i + 2).is_some_and(|t| t.eq_ignore_ascii_case("EXISTS"))
        {
            i += 3;
        }
        let Some(&raw_name) = tokens.get(i) else {
            continue;
        };
        let clean_name = raw_name
            .split('(')
            .next()
            .unwrap_or(raw_name)
            .trim_matches(['"', '`', '[', ']', ';'])
            .rsplit('.')
            .next()
            .unwrap_or(raw_name);
        if clean_name.is_empty() {
            continue;
        }
        let mut end_line = idx + 1;
        for (s_idx, s_line) in lines.iter().enumerate().skip(idx) {
            let st = s_line.trim();
            end_line = s_idx + 1;
            if st.ends_with(';') {
                break;
            }
        }
        out.push(SymbolContract {
            kind: kind_up.to_ascii_lowercase(),
            name: clean_name.to_owned(),
            container: None,
            supertypes: Vec::new(),
            signature: truncate_chars(&collapse_ws(trimmed), 115),
            doc_summary: String::new(),
            start_line: idx + 1,
            end_line: end_line.min(total_lines.max(1)),
        });
    }
    out
}

fn extract_powershell_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let low = trimmed.to_ascii_lowercase();
        for kw in ["function ", "filter ", "class ", "enum "] {
            if low.starts_with(kw) {
                let rest = trimmed[kw.len()..].trim_start();
                let name_raw: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | ':'))
                    .collect();
                let short_name = name_raw.rsplit(':').next().unwrap_or(&name_raw).to_owned();
                if !short_name.is_empty() {
                    let sig_head = trimmed.split('{').next().unwrap_or(trimmed).trim();
                    let end_line = find_matching_brace_end(lines, idx, total_lines, "powershell");
                    let supertypes = if kw == "class " {
                        extract_brace_supertypes(sig_head, &short_name)
                    } else {
                        Vec::new()
                    };
                    out.push(SymbolContract {
                        kind: kw.trim().to_owned(),
                        name: short_name,
                        container: None,
                        supertypes,
                        signature: truncate_chars(&collapse_ws(sig_head), 115),
                        doc_summary: String::new(),
                        start_line: idx + 1,
                        end_line,
                    });
                }
                break;
            }
        }
    }
    out
}

fn extract_shell_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let name_opt = if let Some(rest) = trimmed.strip_prefix("function ") {
            let n: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-'))
                .collect();
            Some(n)
        } else if let Some((before_paren, _)) = trimmed.split_once("()") {
            let candidate = before_paren.trim();
            if !candidate.is_empty()
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            {
                Some(candidate.to_owned())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(name) = name_opt.filter(|s| !s.is_empty()) {
            let sig_head = trimmed.split('{').next().unwrap_or(trimmed).trim();
            let end_line = find_matching_brace_end(lines, idx, total_lines, "shell");
            out.push(SymbolContract {
                kind: "function".to_owned(),
                name,
                container: None,
                supertypes: Vec::new(),
                signature: truncate_chars(&collapse_ws(sig_head), 115),
                doc_summary: String::new(),
                start_line: idx + 1,
                end_line,
            });
        }
    }
    out
}

fn extract_brace_symbols(lines: &[&str], total_lines: usize, lang: &str) -> Vec<SymbolContract> {
    let mut out: Vec<SymbolContract> = Vec::new();
    let mut pending_doc = String::new();
    // Active container stack: `(container_type_name, container_kind, end_line, indent)`
    let mut container_stack: Vec<(String, String, usize, usize)> = Vec::new();
    let mut active_callable_end: usize = 0;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(doc) = trimmed.strip_prefix("///").or_else(|| trimmed.strip_prefix("//!")) {
            if pending_doc.is_empty() {
                let d = doc.trim();
                if !d.is_empty() {
                    pending_doc = d.to_owned();
                }
            }
            continue;
        }
        if trimmed.starts_with("#[")
            || trimmed.starts_with("#!")
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('@')
            || (trimmed.starts_with('#')
                && (!matches!(lang, "javascript" | "typescript") || !trimmed.contains('(')))
        {
            continue;
        }
        if trimmed.is_empty() {
            pending_doc.clear();
            continue;
        }

        let start_line = idx + 1;
        let indent = line.len() - line.trim_start().len();
        while let Some((_, _, c_end, c_indent)) = container_stack.last() {
            if start_line > *c_end || indent <= *c_indent {
                container_stack.pop();
            } else {
                break;
            }
        }
        if start_line > active_callable_end {
            active_callable_end = 0;
        }

        if trimmed.starts_with('}')
            || trimmed.starts_with('{')
            || trimmed.starts_with("import ")
            || trimmed.starts_with("package ")
            || trimmed.starts_with("using ")
            || matches!(
                trimmed,
                "public:"
                    | "private:"
                    | "protected:"
                    | "signals:"
                    | "slots:"
                    | "public slots:"
                    | "private slots:"
                    | "protected slots:"
            )
        {
            pending_doc.clear();
            continue;
        }

        if indent <= 12 {
            let in_type_body = !container_stack.is_empty();
            let in_interface_like = container_stack
                .last()
                .is_some_and(|(_, k, _, _)| matches!(k.as_str(), "interface" | "trait" | "protocol"));
            let outside_callable = start_line > active_callable_end;
            let valid_decl_lead = trimmed
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '~' | '*' | '&' | '#'));

            // Collect multi-line signature up to opening `{` or top-level `;` when outside a method body
            // (or when a nested keyword declaration begins), avoiding allocations on ordinary body lines.
            let mut sig_end_idx = idx;
            let candidate_sig = if valid_decl_lead
                && (outside_callable || starts_with_decl_keyword(trimmed))
            {
                let mut sig = trimmed.to_owned();
                let mut sig_idx = idx;
                while !has_top_level_sig_terminator(&sig)
                    && sig_idx + 1 < total_lines
                    && sig_idx < idx + 14
                {
                    let next_trim = lines[sig_idx + 1].trim();
                    if next_trim.starts_with("//") || next_trim.starts_with("/*") {
                        sig_idx += 1;
                        continue;
                    }
                    let unclosed_parens = open_paren_depth(&sig) > 0;
                    if !unclosed_parens
                        && (next_trim.is_empty()
                            || next_trim.starts_with('}')
                            || next_trim.starts_with("#[")
                            || next_trim.starts_with('@')
                            || starts_with_new_member_or_decl(next_trim))
                    {
                        break;
                    }
                    sig_idx += 1;
                    sig_end_idx = sig_idx;
                    sig.push(' ');
                    sig.push_str(next_trim);
                }
                Some(sig)
            } else {
                None
            };

            if let Some(ref full_sig) = candidate_sig {
                if let Some((kind, mut name, explicit_container)) = match_brace_declaration(
                    trimmed,
                    full_sig,
                    in_type_body,
                    in_interface_like,
                    outside_callable,
                ) {
                    let sig_head = full_sig
                        .split('{')
                        .next()
                        .unwrap_or(full_sig)
                        .trim_end_matches(';')
                        .trim();
                    let end_line = if full_sig.contains('{') {
                        find_matching_brace_end(lines, idx, total_lines, lang)
                    } else {
                        (sig_end_idx + 1).min(total_lines)
                    };

                    let mut container = explicit_container
                        .or_else(|| container_stack.last().map(|(c, _, _, _)| c.clone()));
                    let mut supertypes: Vec<String> = Vec::new();

                    if kind == "impl" {
                        if let Some((impl_display, target_type, trait_opt)) =
                            parse_impl_header(sig_head)
                        {
                            name = impl_display;
                            container = None;
                            if let Some(ref tr) = trait_opt {
                                supertypes.push(tr.clone());
                                if let Some(struct_sym) = out.iter_mut().rev().find(|s| {
                                    s.name == target_type
                                        && matches!(s.kind.as_str(), "struct" | "enum" | "class")
                                }) {
                                    if !struct_sym.supertypes.iter().any(|x| x == tr) {
                                        struct_sym.supertypes.push(tr.clone());
                                    }
                                }
                            }
                            if end_line > start_line && !target_type.is_empty() {
                                container_stack.push((
                                    target_type,
                                    "impl".to_owned(),
                                    end_line,
                                    indent,
                                ));
                            }
                        }
                    } else if matches!(
                        kind.as_str(),
                        "class"
                            | "struct"
                            | "trait"
                            | "interface"
                            | "object"
                            | "extension"
                            | "protocol"
                            | "record"
                    ) {
                        supertypes = extract_brace_supertypes(sig_head, &name);
                        if end_line > start_line {
                            container_stack.push((
                                name.clone(),
                                kind.clone(),
                                end_line,
                                indent,
                            ));
                        }
                    } else if matches!(
                        kind.as_str(),
                        "fn" | "fun" | "func" | "function" | "method"
                    ) && end_line > start_line
                    {
                        active_callable_end = end_line;
                    }

                    out.push(SymbolContract {
                        kind,
                        name,
                        container,
                        supertypes,
                        signature: truncate_chars(&collapse_ws(sig_head), 115),
                        doc_summary: truncate_chars(&pending_doc, 85),
                        start_line,
                        end_line,
                    });
                    pending_doc.clear();
                    continue;
                }
            }
        }
        pending_doc.clear();
    }

    out
}

fn starts_with_decl_keyword(trimmed: &str) -> bool {
    let first = trimmed.split_whitespace().next().unwrap_or("");
    matches!(
        first,
        "pub"
            | "pub(crate)"
            | "pub(super)"
            | "fn"
            | "async"
            | "unsafe"
            | "const"
            | "fun"
            | "func"
            | "function"
            | "struct"
            | "enum"
            | "trait"
            | "impl"
            | "class"
            | "interface"
            | "record"
            | "protocol"
            | "type"
    ) || trimmed.starts_with("impl<")
}

fn open_paren_depth(sig: &str) -> i32 {
    let mut paren = 0i32;
    for ch in sig.chars() {
        match ch {
            '(' => paren += 1,
            ')' => paren = (paren - 1).max(0),
            _ => {}
        }
    }
    paren
}

fn starts_with_new_member_or_decl(trimmed: &str) -> bool {
    if starts_with_decl_keyword(trimmed) {
        return true;
    }
    let first = trimmed.split_whitespace().next().unwrap_or("");
    matches!(
        first,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "export"
            | "abstract"
            | "override"
            | "virtual"
            | "static"
            | "sealed"
            | "suspend"
    )
}

fn has_top_level_sig_terminator(sig: &str) -> bool {
    let mut paren = 0i32;
    let mut bracket = 0i32;
    for ch in sig.chars() {
        match ch {
            '(' => paren += 1,
            ')' => paren = (paren - 1).max(0),
            '[' => bracket += 1,
            ']' => bracket = (bracket - 1).max(0),
            '{' if paren == 0 && bracket == 0 => return true,
            ';' if paren == 0 && bracket == 0 => return true,
            _ => {}
        }
    }
    false
}

fn parse_impl_header(sig_head: &str) -> Option<(String, String, Option<String>)> {
    let mut s = sig_head.trim();
    for prefix in ["pub(crate) ", "pub(super) ", "pub ", "unsafe ", "default ", "const "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim_start();
        }
    }
    let after_impl = s.strip_prefix("impl")?.trim_start();
    let after_generics = if after_impl.starts_with('<') {
        let mut depth = 0i32;
        let mut end_pos = None;
        for (i, ch) in after_impl.char_indices() {
            if ch == '<' {
                depth += 1;
            } else if ch == '>' {
                depth -= 1;
                if depth == 0 {
                    end_pos = Some(i + ch.len_utf8());
                    break;
                }
            }
        }
        match end_pos {
            Some(pos) => after_impl[pos..].trim_start(),
            None => after_impl,
        }
    } else {
        after_impl
    };

    let without_where = split_outside_angles(after_generics, " where ")
        .map_or(after_generics, |(head, _)| head)
        .trim();
    if let Some((trait_part, type_part)) = split_outside_angles(without_where, " for ") {
        let target_type = extract_base_type_ident(type_part);
        let trait_short = extract_base_type_ident(trait_part);
        if !target_type.is_empty() {
            let (label, trait_opt) = if trait_short.is_empty() {
                (format!("impl {target_type}"), None)
            } else {
                (
                    format!("impl {trait_short} for {target_type}"),
                    Some(trait_short),
                )
            };
            return Some((label, target_type, trait_opt));
        }
    } else {
        let target_type = extract_base_type_ident(without_where);
        if !target_type.is_empty() {
            return Some((format!("impl {target_type}"), target_type, None));
        }
    }
    None
}

fn split_outside_angles<'a>(input: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
    let mut angle = 0i32;
    let bytes = input.as_bytes();
    let n_bytes = needle.as_bytes();
    if n_bytes.is_empty() || bytes.len() < n_bytes.len() {
        return None;
    }
    let mut i = 0usize;
    while i + n_bytes.len() <= bytes.len() {
        let b = bytes[i];
        if b == b'<' {
            angle += 1;
        } else if b == b'>' && angle > 0 {
            angle -= 1;
        } else if angle == 0 && &bytes[i..i + n_bytes.len()] == n_bytes {
            return Some((&input[..i], &input[i + n_bytes.len()..]));
        }
        i += 1;
    }
    None
}

fn extract_base_type_ident(type_expr: &str) -> String {
    let mut t = type_expr.trim();
    loop {
        if let Some(r) = t.strip_prefix('&') {
            t = r.trim_start();
            if t.starts_with('\'') {
                t = t
                    .trim_start_matches('\'')
                    .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_')
                    .trim_start();
            }
            if let Some(rm) = t.strip_prefix("mut ") {
                t = rm.trim_start();
            }
            continue;
        }
        if let Some(r) = t.strip_prefix("*const ").or_else(|| t.strip_prefix("*mut ")) {
            t = r.trim_start();
            continue;
        }
        if let Some(r) = t.strip_prefix("dyn ") {
            t = r.trim_start();
            continue;
        }
        for cpp_mod in ["public ", "protected ", "private ", "virtual "] {
            if let Some(r) = t.strip_prefix(cpp_mod) {
                t = r.trim_start();
            }
        }
        break;
    }
    let before_gen = t.split(['<', '[', '(', ' ', '{']).next().unwrap_or(t);
    let last_seg = before_gen
        .rsplit(|c| c == ':' || c == '.' || c == '\\')
        .next()
        .unwrap_or(before_gen);
    last_seg
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn strip_balanced_groups(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut angle = 0i32;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    for ch in input.chars() {
        match ch {
            '<' => {
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
                angle += 1;
            }
            '>' if angle > 0 => {
                angle -= 1;
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
            }
            '(' => {
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
                paren += 1;
            }
            ')' if paren > 0 => {
                paren -= 1;
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
            }
            '[' => {
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
                bracket += 1;
            }
            ']' if bracket > 0 => {
                bracket -= 1;
                if angle == 0 && paren == 0 && bracket == 0 {
                    out.push(' ');
                }
            }
            _ if angle == 0 && paren == 0 && bracket == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

fn find_single_colon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b':' {
            let prev_colon = i > 0 && bytes[i - 1] == b':';
            let next_colon = i + 1 < bytes.len() && bytes[i + 1] == b':';
            if !prev_colon && !next_colon {
                return Some(i);
            }
        }
    }
    None
}

fn take_qualified_ident(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b == b'_' {
            i += 1;
        } else if b == b':' && i + 1 < bytes.len() && bytes[i + 1] == b':' {
            i += 2;
        } else {
            break;
        }
    }
    s[..i].to_owned()
}

fn extract_brace_supertypes(sig_head: &str, declared_name: &str) -> Vec<String> {
    if declared_name.is_empty() {
        return Vec::new();
    }
    let stripped = collapse_ws(&strip_balanced_groups(sig_head));
    let without_where = stripped
        .split(" where ")
        .next()
        .unwrap_or(&stripped)
        .split(" permits ")
        .next()
        .unwrap_or(&stripped);

    let Some(name_pos) = without_where.find(declared_name) else {
        return Vec::new();
    };
    let after_name = without_where[name_pos + declared_name.len()..].trim();
    if after_name.is_empty() {
        return Vec::new();
    }

    let raw_clause = if let Some(colon_idx) = find_single_colon(after_name) {
        after_name[colon_idx + 1..].to_owned()
    } else {
        let padded = format!(" {after_name} ");
        let first_kw = [" extends ", " implements ", " with "]
            .iter()
            .filter_map(|kw| padded.find(kw))
            .min();
        match first_kw {
            Some(pos) => padded[pos..]
                .replace(" extends ", ",")
                .replace(" implements ", ",")
                .replace(" with ", ","),
            None => return Vec::new(),
        }
    };

    let mut out = Vec::new();
    for part in raw_clause.split([',', '+']) {
        let ident = extract_base_type_ident(part);
        if ident.len() >= 2
            && !matches!(
                ident.as_str(),
                "Object" | "Send" | "Sync" | "Sized" | "Copy" | "Clone" | "Debug" | "Unpin"
            )
            && !out.iter().any(|x| x == &ident)
        {
            out.push(ident);
        }
    }
    out
}

fn extract_python_supertypes(clean_sig: &str) -> Vec<String> {
    let Some((_, after_open)) = clean_sig.split_once('(') else {
        return Vec::new();
    };
    let Some((inside, _)) = after_open.rsplit_once(')') else {
        return Vec::new();
    };
    let stripped = strip_balanced_groups(inside);
    let mut out = Vec::new();
    for part in stripped.split(',') {
        let p = part.trim();
        if p.is_empty() || p.contains('=') {
            continue;
        }
        let ident = extract_base_type_ident(p);
        if ident.len() >= 2
            && !matches!(ident.as_str(), "object" | "ABC" | "Protocol" | "Generic")
            && !out.iter().any(|x| x == &ident)
        {
            out.push(ident);
        }
    }
    out
}

fn match_brace_declaration(
    first_line: &str,
    full_sig: &str,
    in_type_body: bool,
    in_interface_like: bool,
    outside_callable: bool,
) -> Option<(String, String, Option<String>)> {
    // Strip visibility and storage modifiers across Rust, TS/JS, Java, Kotlin, C#, C++, Dart, Swift.
    let mut s = first_line;
    let mut full_stripped = full_sig;
    let mut had_abstract_mod = false;
    loop {
        let mut stripped_any = false;
        for prefix in [
            "pub(crate) ",
            "pub(super) ",
            "pub ",
            "public ",
            "private ",
            "protected ",
            "internal ",
            "export ",
            "default ",
            "static ",
            "virtual ",
            "override ",
            "abstract ",
            "final ",
            "readonly ",
            "inline ",
            "constexpr ",
            "extern ",
            "async ",
            "unsafe ",
            "const ",
            "synchronized ",
            "suspend ",
            "open ",
            "data ",
            "sealed ",
            "partial ",
        ] {
            if let Some(rest) = s.strip_prefix(prefix) {
                if prefix == "abstract " {
                    had_abstract_mod = true;
                }
                s = rest.trim_start();
                stripped_any = true;
            }
            if let Some(rest_f) = full_stripped.strip_prefix(prefix) {
                full_stripped = rest_f.trim_start();
            }
        }
        if !stripped_any {
            break;
        }
    }

    for kw in [
        "fn ",
        "fun ",
        "func ",
        "function ",
        "struct ",
        "enum ",
        "trait ",
        "impl ",
        "impl<",
        "class ",
        "interface ",
        "object ",
        "record ",
        "protocol ",
        "extension ",
        "namespace ",
        "type ",
    ] {
        if let Some(rest) = s.strip_prefix(kw) {
            let clean_kw = kw.trim_end_matches('<').trim().to_owned();
            let mut explicit_container: Option<String> = None;
            let target = if kw == "impl<" {
                full_stripped
                    .strip_prefix("impl<")
                    .and_then(|r| {
                        let mut d = 1i32;
                        for (i, ch) in r.char_indices() {
                            if ch == '<' {
                                d += 1;
                            } else if ch == '>' {
                                d -= 1;
                                if d == 0 {
                                    return Some(r[i + 1..].trim_start());
                                }
                            }
                        }
                        None
                    })
                    .unwrap_or(rest)
            } else if kw == "func " && rest.starts_with('(') {
                // Go receiver method: `func (s *Server) Handle(...)`
                if let Some((recv, after)) = rest[1..].split_once(')') {
                    let recv_type = recv
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_start_matches('*')
                        .split('[')
                        .next()
                        .unwrap_or("");
                    if !recv_type.is_empty() {
                        explicit_container = Some(recv_type.to_owned());
                    }
                    after.trim_start()
                } else {
                    rest
                }
            } else {
                rest
            };
            let raw_name = take_qualified_ident(target);
            if explicit_container.is_none() && clean_kw != "impl" {
                if let Some((qual, _)) = raw_name.rsplit_once("::") {
                    let base = qual.rsplit("::").next().unwrap_or(qual);
                    if !base.is_empty() {
                        explicit_container = Some(base.to_owned());
                    }
                }
            }
            let short_name = raw_name.rsplit("::").next().unwrap_or(&raw_name).to_owned();
            if !short_name.is_empty() {
                return Some((clean_kw, short_name, explicit_container));
            }
        }
    }

    // Typed or class/interface method & constructor declarations across Java/Quarkus, C#/.NET,
    // Angular/TypeScript, C/C++, Kotlin, and Dart (evaluated strictly outside callable bodies).
    if outside_callable {
        if let Some((before_paren, _)) = full_stripped.split_once('(') {
            let head_raw = before_paren.trim();
            if !head_raw.is_empty()
                && !head_raw.contains('=')
                && !head_raw.contains(';')
                && !head_raw.contains('!')
                && !head_raw.starts_with('#')
            {
                // Find the matching `)` for the opening parameter list `(`
                let open_idx = full_stripped.find('(').unwrap_or(0);
                let mut p_depth = 0i32;
                let mut after_params_opt: Option<&str> = None;
                for (off, ch) in full_stripped[open_idx..].char_indices() {
                    if ch == '(' {
                        p_depth += 1;
                    } else if ch == ')' {
                        p_depth -= 1;
                        if p_depth == 0 {
                            after_params_opt = Some(full_stripped[open_idx + off + 1..].trim());
                            break;
                        }
                    }
                }

                if let Some(after_params) = after_params_opt {
                    let before_brace = after_params.split('{').next().unwrap_or(after_params);
                    let is_body_def = after_params.contains('{') && !before_brace.contains('=');
                    let is_abstract_or_iface_sig = (in_interface_like || had_abstract_mod)
                        && after_params.ends_with(';')
                        && !after_params.contains('=');

                    if is_body_def || is_abstract_or_iface_sig {
                        let head_clean = strip_balanced_groups(head_raw);
                        let parts: Vec<&str> = head_clean.split_whitespace().collect();
                        let valid_arity = (parts.len() >= 2 && parts.len() <= 5)
                            || (parts.len() == 1 && in_type_body);
                        if valid_arity {
                            let first_low = parts[0].to_ascii_lowercase();
                            if !matches!(
                                first_low.as_str(),
                                "if" | "else"
                                    | "for"
                                    | "foreach"
                                    | "while"
                                    | "switch"
                                    | "case"
                                    | "catch"
                                    | "return"
                                    | "throw"
                                    | "new"
                                    | "delete"
                                    | "sizeof"
                                    | "typeof"
                                    | "synchronized"
                                    | "using"
                                    | "lock"
                                    | "fixed"
                                    | "when"
                                    | "match"
                                    | "select"
                                    | "super"
                                    | "this"
                            ) {
                                let cand = parts.last().copied().unwrap_or("");
                                let cand_clean = cand.trim_start_matches(['*', '&', '~']);
                                let explicit_container = cand_clean
                                    .rsplit_once("::")
                                    .and_then(|(q, _)| q.rsplit("::").next())
                                    .filter(|c| !c.is_empty())
                                    .map(ToOwned::to_owned);
                                let short = cand_clean.rsplit("::").next().unwrap_or(cand_clean);
                                if !short.is_empty()
                                    && short
                                        .chars()
                                        .next()
                                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                                    && short
                                        .chars()
                                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                                {
                                    return Some((
                                        "method".to_owned(),
                                        short.to_owned(),
                                        explicit_container,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn find_matching_brace_end(
    lines: &[&str],
    start_idx: usize,
    total_lines: usize,
    lang: &str,
) -> usize {
    let mut brace_depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    let mut bracket_depth: i32 = 0;
    let mut seen_open = false;
    let mut in_block_comment = false;
    let mut in_ps_block_comment = false;
    let mut in_double_quote = false;
    let mut raw_str_hashes: Option<usize> = None;
    let is_hash_comment_lang = matches!(lang, "powershell" | "shell" | "ruby");

    for (idx, &line) in lines.iter().enumerate().skip(start_idx) {
        let chars: Vec<char> = line.chars().collect();
        let n = chars.len();
        let mut i = 0usize;

        while i < n {
            if in_block_comment {
                if i + 1 < n && chars[i] == '*' && chars[i + 1] == '/' {
                    in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_ps_block_comment {
                if i + 1 < n && chars[i] == '#' && chars[i + 1] == '>' {
                    in_ps_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(hashes) = raw_str_hashes {
                if chars[i] == '"' {
                    let mut matched = true;
                    for h in 0..hashes {
                        if i + 1 + h >= n || chars[i + 1 + h] != '#' {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        raw_str_hashes = None;
                        i += 1 + hashes;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if in_double_quote {
                if lang == "powershell" {
                    // PowerShell uses backtick (`` ` ``) as escape character; `\` is a literal path separator!
                    if chars[i] == '`' {
                        i = (i + 2).min(n);
                    } else if chars[i] == '"' {
                        in_double_quote = false;
                        i += 1;
                    } else {
                        i += 1;
                    }
                } else if chars[i] == '\\' {
                    i = (i + 2).min(n);
                } else if chars[i] == '"' {
                    in_double_quote = false;
                    i += 1;
                } else {
                    i += 1;
                }
                continue;
            }

            let ch = chars[i];
            if is_hash_comment_lang {
                if lang == "powershell" && ch == '<' && i + 1 < n && chars[i + 1] == '#' {
                    in_ps_block_comment = true;
                    i += 2;
                    continue;
                }
                if ch == '#' {
                    break;
                }
            } else {
                if ch == '/' && i + 1 < n && chars[i + 1] == '/' {
                    break;
                }
                if ch == '/' && i + 1 < n && chars[i + 1] == '*' {
                    in_block_comment = true;
                    i += 2;
                    continue;
                }
            }
            if lang == "rust" && ch == 'r' {
                let prev_ident = i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
                if !prev_ident {
                    let mut h = 0usize;
                    while i + 1 + h < n && chars[i + 1 + h] == '#' {
                        h += 1;
                    }
                    if i + 1 + h < n && chars[i + 1 + h] == '"' {
                        raw_str_hashes = Some(h);
                        i += 2 + h;
                        continue;
                    }
                }
            }
            if ch == '"' {
                in_double_quote = true;
                i += 1;
                continue;
            }
            if ch == '\'' {
                if lang == "rust" {
                    // Rust has character literals (`'x'`, `'\n'`, `'\x7f'`, `'\u{10ffff}'`) and lifetimes (`'a`).
                    if i + 1 < n && chars[i + 1] == '\\' {
                        let limit = n.min(i + 13);
                        let mut close_idx = None;
                        for (pos, &c) in chars.iter().enumerate().take(limit).skip(i + 2) {
                            if c == '\'' {
                                close_idx = Some(pos);
                                break;
                            }
                        }
                        if let Some(pos) = close_idx {
                            i = pos + 1;
                        } else {
                            i += 1;
                        }
                        continue;
                    } else if i + 2 < n && chars[i + 2] == '\'' {
                        i += 3;
                        continue;
                    }
                    // Rust lifetime (`'a`, `'static`, `'_`) or loop label: advance strictly by 1!
                    i += 1;
                    continue;
                } else {
                    // Single-quoted string or char literal in PowerShell, Shell, JS/TS, C/C++/Java/C#, etc.
                    let mut j = i + 1;
                    let mut found_end = None;
                    while j < n {
                        if matches!(lang, "powershell" | "sql") {
                            // Doubled `''` escapes a single quote; `\` is literal!
                            if chars[j] == '\'' {
                                if j + 1 < n && chars[j + 1] == '\'' {
                                    j += 2;
                                    continue;
                                }
                                found_end = Some(j + 1);
                                break;
                            }
                            j += 1;
                        } else if lang == "shell" {
                            // POSIX shell single quotes have no escape sequences at all.
                            if chars[j] == '\'' {
                                found_end = Some(j + 1);
                                break;
                            }
                            j += 1;
                        } else {
                            if chars[j] == '\\' {
                                j = (j + 2).min(n);
                                continue;
                            }
                            if chars[j] == '\'' {
                                found_end = Some(j + 1);
                                break;
                            }
                            j += 1;
                        }
                    }
                    i = found_end.unwrap_or(i + 1);
                    continue;
                }
            }

            match ch {
                '(' => paren_depth += 1,
                ')' => paren_depth = (paren_depth - 1).max(0),
                '[' => bracket_depth += 1,
                ']' => bracket_depth = (bracket_depth - 1).max(0),
                '{' => {
                    brace_depth += 1;
                    seen_open = true;
                }
                '}' => {
                    brace_depth -= 1;
                    if seen_open && brace_depth <= 0 {
                        return idx + 1;
                    }
                }
                ';' if !seen_open && paren_depth == 0 && bracket_depth == 0 && !is_hash_comment_lang => {
                    return idx + 1;
                }
                _ => {}
            }
            i += 1;
        }
    }
    (start_idx + 1).min(total_lines)
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_owned()
    } else {
        let head: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_polyglot_smali_sql_powershell_and_typed_cpp_java_methods() {
        let smali_src = ".class public Lcom/example/MainActivity;\n.super Landroid/app/Activity;\n.field private count:I\n.method protected onCreate(Landroid/os/Bundle;)V\n    .locals 1\n    return-void\n.end method\n";
        let sk_smali = FileSkeleton::extract("MainActivity.smali", smali_src);
        assert_eq!(sk_smali.language, "smali");
        assert!(sk_smali.symbols.iter().any(|s| s.kind == "class" && s.name == "MainActivity"));
        assert!(sk_smali.symbols.iter().any(|s| s.kind == "field" && s.name == "count"));
        assert!(sk_smali.symbols.iter().any(|s| s.kind == "method" && s.name == "onCreate" && s.start_line == 4 && s.end_line == 7));

        let sql_src = "CREATE TABLE IF NOT EXISTS users (\n  id INTEGER PRIMARY KEY\n);\nCREATE OR REPLACE FUNCTION calc_score(uid INT) RETURNS INT AS $$\nBEGIN\n  RETURN 42;\nEND;\n$$ LANGUAGE plpgsql;\n";
        let sk_sql = FileSkeleton::extract("schema.sql", sql_src);
        assert_eq!(sk_sql.language, "sql");
        assert!(sk_sql.symbols.iter().any(|s| s.kind == "table" && s.name == "users"));
        assert!(sk_sql.symbols.iter().any(|s| s.kind == "function" && s.name == "calc_score"));

        let ps_src = "function Invoke-SafeDeploy {\n    param([string]$Target)\n    Write-Output $Target\n}\n";
        let sk_ps = FileSkeleton::extract("deploy.ps1", ps_src);
        assert_eq!(sk_ps.language, "powershell");
        assert!(sk_ps.symbols.iter().any(|s| s.name == "Invoke-SafeDeploy" && s.start_line == 1 && s.end_line == 4));

        let cpp_src = "class EngineCore {\npublic:\n    bool initializeGraph(int threads) {\n        if (threads <= 0) {\n            return false;\n        }\n        return true;\n    }\n};\n";
        let sk_cpp = FileSkeleton::extract("engine.cpp", cpp_src);
        assert_eq!(sk_cpp.language, "cpp");
        assert!(sk_cpp.symbols.iter().any(|s| s.kind == "class" && s.name == "EngineCore"));
        assert!(sk_cpp.symbols.iter().any(|s| s.kind == "method" && s.name == "initializeGraph"));

        let asm_src = "SECTION .text\n.text:0000000140001000 sub_140001000 PROC NEAR\n.text:0000000140001000 mov rax, rcx\n.text:0000000140001003 loc_140001003:\n.text:0000000140001003 ret\n.text:0000000140001004 sub_140001000 ENDP\nDecryptPayload:\n    xor eax, eax\n    ret\n";
        let sk_asm = FileSkeleton::extract("dump.asm", asm_src);
        assert_eq!(sk_asm.language, "asm");
        assert!(sk_asm.symbols.iter().any(|s| s.kind == "section" && s.name == ".text"));
        assert!(sk_asm.symbols.iter().any(|s| s.kind == "proc" && s.name == "sub_140001000" && s.start_line == 2 && s.end_line == 6));
        assert!(sk_asm.symbols.iter().any(|s| s.kind == "label" && s.name == "DecryptPayload" && s.start_line == 7 && s.end_line == 9));
        assert!(!sk_asm.symbols.iter().any(|s| s.name == "loc_140001003"));

        let md_src = "# Top Guide\nIntro\n## Architecture\n```python\n# comment inside fence\n```\n### Subcomponent\nDetails\n## Benchmarks\nDone\n";
        let sk_md = FileSkeleton::extract("README.md", md_src);
        assert_eq!(sk_md.language, "markdown");
        assert_eq!(sk_md.symbols.len(), 4);
        assert!(sk_md.symbols.iter().any(|s| s.kind == "h2" && s.name == "Architecture" && s.start_line == 3 && s.end_line == 8));

        let mk_src = "CARGO ?= cargo\n\n## Build optimized release binary\nbuild: check-deps\n\t$(CARGO) build --release\n\ninstall: build ## Install plugin\n\tsh ./scripts/deploy_plugin.sh\n";
        let sk_mk = FileSkeleton::extract("Makefile", mk_src);
        assert_eq!(sk_mk.language, "makefile");
        assert!(sk_mk.symbols.iter().any(|s| s.kind == "target" && s.name == "build" && s.start_line == 4 && s.end_line == 5));
        assert!(sk_mk.symbols.iter().any(|s| s.kind == "target" && s.name == "install" && s.start_line == 7 && s.end_line == 8));
    }

    #[test]
    fn rust_array_return_types_lifetimes_and_trait_impl_containers_parse_accurately() {
        let rust_src = r##"pub struct Inode {
    pub id: u64,
}

impl Inode {
    pub fn encode<'a>(&'a self) -> [u8; 64] {
        let _brace_in_char = '{';
        let _raw = r#"unbalanced { in raw string"#;
        [0u8; 64]
    }
}

pub struct Superblock {
    pub seq: u64,
}

impl Superblock {
    pub fn encode(&self) -> [u8; 512] {
        [0u8; 512]
    }
}

impl Drop for Inode {
    fn drop(&mut self) {}
}
"##;
        let sk = FileSkeleton::extract("format.rs", rust_src);
        let inode_enc = sk
            .symbols
            .iter()
            .find(|s| s.qualified_name() == "Inode::encode")
            .expect("Inode::encode present");
        assert_eq!(inode_enc.start_line, 6);
        assert_eq!(inode_enc.end_line, 10, "[u8; 64] semicolon must not truncate body");

        let sb_enc = sk
            .symbols
            .iter()
            .find(|s| s.qualified_name() == "Superblock::encode")
            .expect("Superblock::encode present");
        assert_eq!(sb_enc.start_line, 18);
        assert_eq!(sb_enc.end_line, 20);

        let drop_fn = sk
            .symbols
            .iter()
            .find(|s| s.qualified_name() == "Inode::drop")
            .expect("impl Drop for Inode must attach container Inode, not Drop");
        assert_eq!(drop_fn.container.as_deref(), Some("Inode"));
    }

    #[test]
    fn powershell_regex_backslashes_and_windows_paths_never_hang_or_misbalance_braces() {
        let ps_src = r#"function Test-SafeBinaryAcl([string]$Path) {
    $dir = "$env:USERPROFILE\bin\"
    # Comment with unbalanced { brace
    if ($id -notmatch '\\(BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM)$') {
        return $false
    }
    return $true
}
"#;
        let sk = FileSkeleton::extract("deploy_plugin.ps1", ps_src);
        let fn_sym = sk
            .symbols
            .iter()
            .find(|s| s.name == "Test-SafeBinaryAcl")
            .expect("Test-SafeBinaryAcl extracted");
        assert_eq!(fn_sym.start_line, 1);
        assert_eq!(fn_sym.end_line, 8);
    }

    #[test]
    fn extracts_enterprise_supertypes_and_interface_methods_across_languages() {
        let java_src = r#"package com.acme.orders;
public interface OrderPort {
    boolean approveOrder(String orderId);
}
public class OrderService extends BaseService implements OrderPort, Auditable {
    @Override
    public boolean approveOrder(String orderId) {
        return true;
    }
}
"#;
        let sk_java = FileSkeleton::extract("OrderService.java", java_src);
        let iface_method = sk_java
            .symbols
            .iter()
            .find(|s| s.qualified_name() == "OrderPort::approveOrder")
            .expect("Java interface method extracted");
        assert_eq!(iface_method.start_line, 3);
        assert_eq!(iface_method.end_line, 3);
        let svc_cls = sk_java
            .symbols
            .iter()
            .find(|s| s.name == "OrderService" && s.kind == "class")
            .expect("Java OrderService class extracted");
        assert_eq!(svc_cls.supertypes, vec!["BaseService", "OrderPort", "Auditable"]);

        let cs_src = r#"namespace Acme.Orders;
public interface IOrderRepo {
    Task<bool> SaveAsync(Guid id);
}
public sealed class SqlOrderRepo(IDbConnection db) : BaseRepo, IOrderRepo {
    public async Task<bool> SaveAsync(Guid id) {
        return true;
    }
}
"#;
        let sk_cs = FileSkeleton::extract("OrderRepo.cs", cs_src);
        let cs_cls = sk_cs
            .symbols
            .iter()
            .find(|s| s.name == "SqlOrderRepo" && s.kind == "class")
            .expect("C# primary-constructor class extracted");
        assert_eq!(cs_cls.supertypes, vec!["BaseRepo", "IOrderRepo"]);
        assert!(sk_cs
            .symbols
            .iter()
            .any(|s| s.qualified_name() == "IOrderRepo::SaveAsync"));
        assert!(sk_cs
            .symbols
            .iter()
            .any(|s| s.qualified_name() == "SqlOrderRepo::SaveAsync"));

        let py_src = "class OrderPort(Protocol):\n    def approve(self, oid: str) -> bool:\n        ...\n\nclass LiveOrderService(BaseService, OrderPort):\n    def approve(self, oid: str) -> bool:\n        return True\n";
        let sk_py = FileSkeleton::extract("orders.py", py_src);
        let py_cls = sk_py
            .symbols
            .iter()
            .find(|s| s.name == "LiveOrderService")
            .expect("Python class extracted");
        assert_eq!(py_cls.supertypes, vec!["BaseService", "OrderPort"]);
    }

    #[test]
    fn infers_extensionless_and_end_block_topologies_locally_without_hardcoding() {
        // 1. Extensionless Python script via shebang
        let extless_py = "#!/usr/bin/env python3\nclass TokenLedger:\n    def record_save(self, n: int) -> int:\n        return n * 2\n";
        let sk_shebang = FileSkeleton::extract("bin/ledger-tool", extless_py);
        assert_eq!(sk_shebang.language, "python");
        assert!(sk_shebang
            .symbols
            .iter()
            .any(|s| s.qualified_name() == "TokenLedger::record_save"));

        // 2. Unknown `.dump` Smali file detected via structural directives
        let dump_smali = ".class public final Lci/p1;\n.super Ljava/lang/Object;\n.method public final l(I)Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method\n";
        let sk_smali = FileSkeleton::extract("decompiled_p1.dump", dump_smali);
        assert_eq!(sk_smali.language, "smali");
        assert!(sk_smali
            .symbols
            .iter()
            .any(|s| s.qualified_name() == "p1::l" && s.start_line == 3 && s.end_line == 7));

        // 3. Lua & Elixir `end`-block topology (both extensionless and `.lua`)
        let lua_src = "local M = {}\nfunction M:dispatch(req)\n    return req\nend\nreturn M\n";
        let sk_lua = FileSkeleton::extract("router.unknown", lua_src);
        assert_eq!(sk_lua.language, "endblock");
        assert!(sk_lua
            .symbols
            .iter()
            .any(|s| s.qualified_name() == "M::dispatch" && s.start_line == 2 && s.end_line == 4));
    }
}
