use std::collections::HashMap;

const MAX_YAML_PADDED_BYTES: usize = 16 * 1024 * 1024;
const MAX_ANCHOR_ENTRIES: usize = 256;

/// Strips trailing `# ...` YAML comments while preserving `#` characters inside single or double quotes.
pub fn strip_yaml_comment_quoted(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if in_double {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if b == b'\'' {
            in_single = !in_single;
        } else if b == b'"' && !in_single {
            in_double = true;
        } else if b == b'#' && !in_single && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return &line[..i];
        }
    }
    line
}

/// Zero-copy multi-document YAML splitter returning `(1-based start_line, document_slice)`.
pub fn split_yaml_document_slices(content: &str) -> Vec<(usize, &str)> {
    let mut docs: Vec<(usize, &str)> = Vec::new();
    let mut doc_start_byte: usize = 0;
    let mut doc_start_line: usize = 1;
    let mut has_content = false;
    let mut offset = 0usize;

    for (line_no, raw_line) in (1usize..).zip(content.split_inclusive('\n')) {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let stripped = strip_yaml_comment_quoted(line).trim_end();
        if stripped == "---" || stripped == "..." {
            if has_content {
                docs.push((doc_start_line, &content[doc_start_byte..offset]));
                has_content = false;
            }
            doc_start_byte = offset + raw_line.len();
            doc_start_line = line_no + 1;
        } else if !stripped.trim().is_empty() {
            has_content = true;
        }
        offset += raw_line.len();
    }
    if has_content || docs.is_empty() {
        docs.push((doc_start_line, &content[doc_start_byte..]));
    }
    docs
}

/// Splits a multi-document YAML stream (`---` / `...` document boundaries at column 0)
/// while preserving line alignment (bounded to prevent quadratic memory amplification).
pub fn split_yaml_documents_preserving_lines(content: &str) -> Vec<String> {
    let slices = split_yaml_document_slices(content);
    let mut docs = Vec::with_capacity(slices.len());
    let mut total_padding = 0usize;
    for (start_line, slice) in slices {
        let pad_lines = start_line.saturating_sub(1);
        let body = slice.trim_end_matches('\n');
        if total_padding.saturating_add(pad_lines) <= MAX_YAML_PADDED_BYTES {
            total_padding += pad_lines;
            let mut out = String::with_capacity(pad_lines + body.len());
            for _ in 0..pad_lines {
                out.push('\n');
            }
            out.push_str(body);
            docs.push(out);
        } else {
            docs.push(body.to_string());
        }
    }
    docs
}

/// Parses an inline YAML list (`["a", "b"]` or `[a, b]`) or scalar token into cleaned strings.
pub fn parse_yaml_inline_list_or_scalar(raw: &str) -> Vec<String> {
    let trimmed = strip_yaml_comment_quoted(raw).trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let mut items = Vec::new();
        let mut cur = String::new();
        let mut in_single = false;
        let mut in_double = false;
        let mut escaped = false;
        for ch in inner.chars() {
            if in_double {
                if escaped {
                    cur.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_double = false;
                } else {
                    cur.push(ch);
                }
                continue;
            }
            if in_single {
                if ch == '\'' {
                    in_single = false;
                } else {
                    cur.push(ch);
                }
                continue;
            }
            match ch {
                '"' => in_double = true,
                '\'' => in_single = true,
                ',' => {
                    let s = cur.trim().to_string();
                    if !s.is_empty() {
                        items.push(s);
                    }
                    cur.clear();
                }
                _ => cur.push(ch),
            }
        }
        let s = cur.trim().to_string();
        if !s.is_empty() {
            items.push(s);
        }
        items
    } else {
        let clean = trimmed
            .trim_matches(|c| c == '"' || c == '\'')
            .trim()
            .to_string();
        if clean.is_empty() {
            Vec::new()
        } else {
            vec![clean]
        }
    }
}

/// Finds the first mapping key-value separator `:` outside quotes that is followed by whitespace or EOL.
fn split_yaml_mapping_kv(body: &str) -> Option<(&str, &str)> {
    let bytes = body.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_double {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_double = false;
            }
            continue;
        }
        if b == b'\'' {
            in_single = !in_single;
        } else if b == b'"' && !in_single {
            in_double = true;
        } else if b == b':' && !in_single {
            let next_is_boundary = i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace();
            if next_is_boundary {
                return Some((&body[..i], &body[i + 1..]));
            }
        }
    }
    None
}

/// Lightweight structural representation of a parsed YAML key-value entry with 1-based line metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlEntry {
    pub indent: usize,
    pub line: usize,
    pub key: String,
    pub value: String,
    pub is_list_item: bool,
}

/// Parses a single YAML document into structural indentation-ordered [`YamlEntry`] records,
/// resolving simple `&anchor` and `<<: *anchor` / `<<: [*a, *b]` / `*alias` references deterministically.
pub fn parse_structural_yaml_entries(doc: &str) -> Vec<YamlEntry> {
    parse_structural_yaml_entries_with_offset(doc, 1)
}

pub fn parse_structural_yaml_entries_with_offset(doc: &str, start_line: usize) -> Vec<YamlEntry> {
    const MAX_YAML_ENTRIES: usize = 65_536;
    const MAX_ANCHORS: usize = 512;
    const MAX_MERGE_ALIASES_PER_LINE: usize = 32;

    let mut entries = Vec::new();
    let mut anchors: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut scalar_anchors: HashMap<String, String> = HashMap::new();
    let mut current_anchor: Option<(String, usize)> = None;

    for (idx, raw_line) in doc.lines().enumerate() {
        if entries.len() >= MAX_YAML_ENTRIES {
            break;
        }
        let ln = start_line + idx;
        let line = strip_yaml_comment_quoted(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        let indent: usize = line
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .map(|b| if b == b'\t' { 2 } else { 1 })
            .sum();
        let trimmed = line.trim();

        if let Some((_, a_indent)) = &current_anchor
            && indent <= *a_indent
        {
            current_anchor = None;
        }

        let (is_list_item, body) = if let Some(rest) = trimmed.strip_prefix("- ") {
            (true, rest.trim())
        } else if trimmed == "-" {
            (true, "")
        } else {
            (false, trimmed)
        };

        if let Some((raw_k, raw_v)) = split_yaml_mapping_kv(body) {
            let key = raw_k
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
            let mut val = raw_v.trim().to_string();

            // Record `&anchor` on mapping header (`defaults: &def`) or inline scalar (`privileged: &p true`)
            if let Some(after_amp) = val.strip_prefix('&') {
                let mut parts = after_amp.splitn(2, char::is_whitespace);
                let aname = parts.next().unwrap_or("").trim().to_string();
                let inline_scalar = parts.next().unwrap_or("").trim().to_string();
                if !aname.is_empty() {
                    if inline_scalar.is_empty() {
                        current_anchor = Some((aname, indent));
                        val.clear();
                    } else {
                        let clean_scalar = inline_scalar
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string();
                        scalar_anchors.insert(aname, clean_scalar.clone());
                        val = clean_scalar;
                    }
                }
            }

            // Expand `<<: *anchor` or `<<: [*a, *b]` merge keys (including chained merges)
            if key == "<<" {
                let alias_names: Vec<String> = if val.starts_with('[') {
                    parse_yaml_inline_list_or_scalar(&val)
                        .into_iter()
                        .filter_map(|item| item.strip_prefix('*').map(|s| s.trim().to_string()))
                        .collect()
                } else if let Some(alias) = val.strip_prefix('*') {
                    vec![alias.trim().to_string()]
                } else {
                    Vec::new()
                };
                if !alias_names.is_empty() {
                    for alias in alias_names.into_iter().take(MAX_MERGE_ALIASES_PER_LINE) {
                        if let Some(merged) = anchors.get(&alias).cloned() {
                            for (mk, mv) in merged {
                                if entries.len() >= MAX_YAML_ENTRIES {
                                    break;
                                }
                                if let Some((ref aname, a_indent)) = current_anchor
                                    && indent > a_indent
                                    && (anchors.contains_key(aname) || anchors.len() < MAX_ANCHORS)
                                {
                                    let slot = anchors.entry(aname.clone()).or_default();
                                    if slot.len() < MAX_ANCHOR_ENTRIES {
                                        slot.push((mk.clone(), mv.clone()));
                                    }
                                }
                                entries.push(YamlEntry {
                                    indent,
                                    line: ln,
                                    key: mk,
                                    value: mv,
                                    is_list_item: false,
                                });
                            }
                        }
                    }
                    continue;
                }
            }

            // Resolve scalar alias (`other: *p`)
            if let Some(alias) = val.strip_prefix('*')
                && let Some(resolved) = scalar_anchors.get(alias.trim())
            {
                val = resolved.clone();
            }

            let clean_val = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            if let Some((ref aname, a_indent)) = current_anchor
                && indent > a_indent
            {
                let slot = anchors.entry(aname.clone()).or_default();
                if slot.len() < MAX_ANCHOR_ENTRIES {
                    slot.push((key.clone(), clean_val.clone()));
                }
            }

            entries.push(YamlEntry {
                indent,
                line: ln,
                key,
                value: clean_val,
                is_list_item,
            });
        } else if is_list_item && !body.is_empty() {
            let clean_val = body.trim_matches(|c| c == '"' || c == '\'').to_string();
            entries.push(YamlEntry {
                indent,
                line: ln,
                key: String::new(),
                value: clean_val,
                is_list_item: true,
            });
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_yaml_comment_preserves_quoted_hash_and_openapi_refs() {
        assert_eq!(
            strip_yaml_comment_quoted("  $ref: '#/components/schemas/User' # trailing comment")
                .trim(),
            "$ref: '#/components/schemas/User'"
        );
        assert_eq!(
            strip_yaml_comment_quoted("  url: \"https://example.com/#frag\" # note").trim(),
            "url: \"https://example.com/#frag\""
        );
    }

    #[test]
    fn test_split_yaml_documents_and_anchor_merge() {
        let multi = "apiVersion: v1\nkind: ServiceAccount\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n";
        let docs = split_yaml_documents_preserving_lines(multi);
        assert_eq!(docs.len(), 2);
        // Line 5 in original is `kind: Role` -> index 4 (1-based line 5) in doc 2!
        assert_eq!(docs[1].lines().nth(4).unwrap(), "kind: Role");

        let anchored = "base: &def\n  runAsNonRoot: false\nservice:\n  <<: *def\n  name: web\n";
        let entries = parse_structural_yaml_entries(anchored);
        assert!(
            entries
                .iter()
                .filter(|e| e.key == "runAsNonRoot" && e.value == "false")
                .count()
                == 2
        );
    }

    #[test]
    fn test_yaml_inline_scalar_anchor_colon_list_escaped_quote_and_chained_merge() {
        assert_eq!(
            strip_yaml_comment_quoted(r#"path: "C:\\" # trailing comment"#).trim(),
            r#"path: "C:\\""#
        );
        assert_eq!(
            parse_yaml_inline_list_or_scalar(r#"["a,b", "c"]"#),
            vec!["a,b".to_string(), "c".to_string()]
        );
        let yml = "privileged: &p true\nother: *p\nResource:\n  - arn:aws:iam::*:root\n  - https://example.com\nbase: &a\n  readOnlyRootFilesystem: false\nmid: &b\n  <<: *a\nsvc:\n  <<: [*b]\n";
        let entries = parse_structural_yaml_entries(yml);
        assert!(
            entries
                .iter()
                .any(|e| e.key == "privileged" && e.value == "true")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.key == "other" && e.value == "true")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.is_list_item && e.key.is_empty() && e.value == "arn:aws:iam::*:root")
        );
        assert!(
            entries
                .iter()
                .any(|e| e.is_list_item && e.key.is_empty() && e.value == "https://example.com")
        );
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.key == "readOnlyRootFilesystem" && e.value == "false")
                .count(),
            3
        );
    }
}
