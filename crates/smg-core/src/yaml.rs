use std::collections::HashMap;

/// Strips trailing `# ...` YAML comments while preserving `#` characters inside single or double quotes
/// (critical for OpenAPI `$ref: '#/components/schemas/...'`, URLs, and CI expressions).
pub fn strip_yaml_comment_quoted(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\'' && !in_double {
            in_single = !in_single;
        } else if b == b'"' && !in_single && (i == 0 || bytes[i - 1] != b'\\') {
            in_double = !in_double;
        } else if b == b'#'
            && !in_single
            && !in_double
            && (i == 0 || bytes[i - 1].is_ascii_whitespace())
        {
            return &line[..i];
        }
    }
    line
}

/// Splits a multi-document YAML stream (`---` / `...` document boundaries at column 0)
/// while preserving line alignment (leading blank lines keep 1-based line numbers exact)
/// and ignoring `---` inside indented block scalars.
pub fn split_yaml_documents_preserving_lines(content: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut cur_lines: Vec<&str> = Vec::new();
    let mut has_content = false;

    for line in content.lines() {
        let stripped = strip_yaml_comment_quoted(line).trim_end();
        if stripped == "---" || stripped == "..." {
            if has_content {
                docs.push(cur_lines.join("\n"));
                cur_lines = vec![""; cur_lines.len() + 1];
                has_content = false;
            } else {
                cur_lines.push("");
            }
            continue;
        }
        if !stripped.trim().is_empty() {
            has_content = true;
        }
        cur_lines.push(line);
    }
    if has_content || docs.is_empty() {
        docs.push(cur_lines.join("\n"));
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
        inner
            .split(',')
            .map(|item| item.trim().trim_matches(|c| c == '"' || c == '\'').trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()
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
/// resolving simple `&anchor` and `<<: *anchor` / `*alias` references deterministically.
pub fn parse_structural_yaml_entries(doc: &str) -> Vec<YamlEntry> {
    let mut entries = Vec::new();
    let mut anchors: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut current_anchor: Option<(String, usize)> = None;

    for (idx, raw_line) in doc.lines().enumerate() {
        let ln = idx + 1;
        let line = strip_yaml_comment_quoted(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
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

        if let Some((raw_k, raw_v)) = body.split_once(':') {
            let key = raw_k
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string();
            let mut val = raw_v.trim().to_string();

            // Record `&anchor` on mapping header `defaults: &def`
            if let Some(anchor_name) = val.strip_prefix('&') {
                let aname = anchor_name
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !aname.is_empty() {
                    current_anchor = Some((aname, indent));
                    val.clear();
                }
            }

            // Expand `<<: *anchor` merge key
            if key == "<<"
                && let Some(alias) = val.strip_prefix('*')
                && let Some(merged) = anchors.get(alias.trim()).cloned()
            {
                for (mk, mv) in merged {
                    entries.push(YamlEntry {
                        indent,
                        line: ln,
                        key: mk,
                        value: mv,
                        is_list_item: false,
                    });
                }
                continue;
            }

            let clean_val = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            if let Some((ref aname, a_indent)) = current_anchor
                && indent > a_indent
            {
                anchors
                    .entry(aname.clone())
                    .or_default()
                    .push((key.clone(), clean_val.clone()));
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
}
