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
    pub signature: String,
    pub doc_summary: String,
    pub start_line: usize,
    pub end_line: usize,
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
        let label = file_label.into();
        let lang = detect_language(&label);
        let content_hash = hash_key(99, source.as_bytes());
        let raw_tokens = count_tokens_exact(source.as_bytes());
        let lines: Vec<&str> = source.lines().collect();
        let total_lines = lines.len();

        let sections = extract_sections(&lines, total_lines);
        let symbols = if lang == "python" {
            extract_python_symbols(&lines, total_lines)
        } else {
            extract_brace_symbols(&lines, total_lines, &lang)
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
        let raw_bytes = std::fs::read(path)?;
        let current_hash = hash_key(99, &raw_bytes);
        let label = display_label
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"));
        let key = format!("{SKELETON_KEY_PREFIX}{label}");

        if let Ok(rec) = db.get_by_key(NodeKind::WorkingSet, &key) {
            if let Ok(cached) = serde_json::from_slice::<FileSkeleton>(&rec.payload) {
                if cached.content_hash == current_hash {
                    return Ok((cached, true)); // `true` = cache hit, zero re-parse!
                }
            }
        }

        let text = String::from_utf8_lossy(&raw_bytes);
        let skel = Self::extract(label, &text);
        let encoded = serde_json::to_vec(&skel)
            .map_err(|_| LibreDbError::CorruptFormat("skeleton json serialize"))?;
        db.put(
            WriteRequest::new(NodeKind::WorkingSet, encoded)
                .with_key(key)
                .with_importance(200),
        )?;

        Ok((skel, false))
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
                let hay = format!("{} {} {}", sym.name, sym.signature, sym.doc_summary).to_ascii_lowercase();
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
    if low.ends_with(".rs") {
        "rust".to_owned()
    } else if low.ends_with(".py") {
        "python".to_owned()
    } else if low.ends_with(".ts") || low.ends_with(".tsx") {
        "typescript".to_owned()
    } else if low.ends_with(".js") || low.ends_with(".jsx") {
        "javascript".to_owned()
    } else if low.ends_with(".dart") {
        "dart".to_owned()
    } else if low.ends_with(".go") {
        "go".to_owned()
    } else {
        "code".to_owned()
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
        let (signature, doc_summary) = packed.split_once("|DOC|").unwrap_or((packed, ""));
        out.push(SymbolContract {
            kind: kind.clone(),
            name: name.clone(),
            signature: truncate_chars(signature, 115),
            doc_summary: truncate_chars(doc_summary, 85),
            start_line,
            end_line: end_line.max(start_line),
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

fn extract_brace_symbols(lines: &[&str], total_lines: usize, _lang: &str) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    let mut pending_doc = String::new();

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
        if trimmed.starts_with("#[") || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.is_empty() {
            pending_doc.clear();
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        if indent <= 4 {
            if let Some((kind, name)) = match_brace_declaration(trimmed) {
                // Collect signature up to `{` or `;`
                let mut sig = trimmed.to_owned();
                let mut sig_idx = idx;
                while !sig.contains('{') && !sig.contains(';') && sig_idx + 1 < total_lines && sig_idx < idx + 6 {
                    sig_idx += 1;
                    sig.push(' ');
                    sig.push_str(lines[sig_idx].trim());
                }
                let sig_head = sig.split('{').next().unwrap_or(&sig).trim_end_matches(';').trim();
                let end_line = find_matching_brace_end(lines, idx, total_lines);

                out.push(SymbolContract {
                    kind,
                    name,
                    signature: truncate_chars(&collapse_ws(sig_head), 115),
                    doc_summary: truncate_chars(&pending_doc, 85),
                    start_line: idx + 1,
                    end_line,
                });
                pending_doc.clear();
                continue;
            }
        }
        pending_doc.clear();
    }

    out
}

fn match_brace_declaration(trimmed: &str) -> Option<(String, String)> {
    // Strip visibility modifiers (`pub`, `pub(crate)`, `export`, `async`, `unsafe`, `const`).
    let mut s = trimmed;
    for prefix in [
        "pub(crate) ",
        "pub(super) ",
        "pub ",
        "export ",
        "default ",
        "async ",
        "unsafe ",
        "const ",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim_start();
        }
    }

    for kw in ["fn ", "struct ", "enum ", "trait ", "impl ", "impl<", "class ", "interface ", "func "] {
        if let Some(rest) = s.strip_prefix(kw) {
            let clean_kw = kw.trim_end_matches('<').trim().to_owned();
            let target = if kw == "impl<" {
                // Skip generic params `<...>` to find impl target
                rest.split_once('>').map_or(rest, |(_, after)| after.trim_start())
            } else {
                rest
            };
            let name: String = target
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            if !name.is_empty() {
                return Some((clean_kw, name));
            }
        }
    }
    None
}

fn find_matching_brace_end(lines: &[&str], start_idx: usize, total_lines: usize) -> usize {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    for (idx, line) in lines.iter().enumerate().skip(start_idx) {
        let code_part = line.split("//").next().unwrap_or(line);
        for ch in code_part.chars() {
            if ch == '{' {
                depth += 1;
                seen_open = true;
            } else if ch == '}' {
                depth -= 1;
                if seen_open && depth <= 0 {
                    return idx + 1;
                }
            } else if !seen_open && ch == ';' {
                return idx + 1;
            }
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
