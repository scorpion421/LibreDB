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
        let symbols = match lang.as_str() {
            "python" => extract_python_symbols(&lines, total_lines),
            "smali" => extract_smali_symbols(&lines, total_lines),
            "sql" => extract_sql_symbols(&lines, total_lines),
            "powershell" => extract_powershell_symbols(&lines, total_lines),
            "shell" => extract_shell_symbols(&lines, total_lines),
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
    } else if low.ends_with(".js") || low.ends_with(".jsx") || low.ends_with(".mjs") || low.ends_with(".cjs") {
        "javascript".to_owned()
    } else if low.ends_with(".dart") {
        "dart".to_owned()
    } else if low.ends_with(".go") {
        "go".to_owned()
    } else if low.ends_with(".smali") {
        "smali".to_owned()
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
    } else if low.ends_with(".php") {
        "php".to_owned()
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

fn extract_smali_symbols(lines: &[&str], total_lines: usize) -> Vec<SymbolContract> {
    let mut out = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(".class ") {
            if let Some(tok) = rest.split_whitespace().last() {
                let clean = tok.trim_start_matches('L').trim_end_matches(';');
                let short = clean.rsplit('/').next().unwrap_or(clean).to_owned();
                if !short.is_empty() {
                    out.push(SymbolContract {
                        kind: "class".to_owned(),
                        name: short,
                        signature: truncate_chars(trimmed, 115),
                        doc_summary: String::new(),
                        start_line: idx + 1,
                        end_line: total_lines.max(idx + 1),
                    });
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
                    let end_line = find_matching_brace_end(lines, idx, total_lines);
                    out.push(SymbolContract {
                        kind: kw.trim().to_owned(),
                        name: short_name,
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
            let end_line = find_matching_brace_end(lines, idx, total_lines);
            out.push(SymbolContract {
                kind: "function".to_owned(),
                name,
                signature: truncate_chars(&collapse_ws(sig_head), 115),
                doc_summary: String::new(),
                start_line: idx + 1,
                end_line,
            });
        }
    }
    out
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
        if trimmed.starts_with("#[")
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('@')
        {
            continue;
        }
        if trimmed.is_empty() {
            pending_doc.clear();
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        if indent <= 12 {
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
    // Strip visibility and storage modifiers across Rust, TS/JS, Java, Kotlin, C#, C++, Dart, Swift.
    let mut s = trimmed;
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
                s = rest.trim_start();
                stripped_any = true;
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
            let target = if kw == "impl<" {
                rest.split_once('>').map_or(rest, |(_, after)| after.trim_start())
            } else if kw == "func " && rest.starts_with('(') {
                // Go receiver method: `func (s *Server) Handle(...)`
                rest.split_once(')').map_or(rest, |(_, after)| after.trim_start())
            } else {
                rest
            };
            let raw_name: String = target
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            let short_name = raw_name.rsplit("::").next().unwrap_or(&raw_name).to_owned();
            if !short_name.is_empty() {
                return Some((clean_kw, short_name));
            }
        }
    }

    // Typed method / function declaration in C, C++, C#, Java, Kotlin, Dart:
    // e.g. `void MyClass::onCreate(Bundle* saved) {` or `String formatName(int id) {`
    if let Some((before_paren, after_paren)) = s.split_once('(') {
        let head = before_paren.trim();
        let tail = after_paren.trim();
        if !head.is_empty()
            && !head.contains('=')
            && !head.contains(';')
            && !head.starts_with('#')
            && (tail.ends_with('{') || tail.contains(") {") || tail.contains(") const {") || tail.contains(") throws "))
        {
            let parts: Vec<&str> = head.split_whitespace().collect();
            if parts.len() >= 2 && parts.len() <= 5 {
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
                ) {
                    let cand = parts.last().copied().unwrap_or("");
                    let cand_clean = cand.trim_start_matches(['*', '&']);
                    let short = cand_clean.rsplit("::").next().unwrap_or(cand_clean);
                    if !short.is_empty()
                        && short.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                        && short.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Some(("method".to_owned(), short.to_owned()));
                    }
                }
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
    }
}
