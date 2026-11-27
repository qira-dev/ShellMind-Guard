use smg_graph::RULE_CATALOG;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name != "target" && name != "tests" {
                collect_rs_files(&p, out);
            }
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn is_rule_id_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-'
}

fn extract_smg_tokens(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        if &bytes[i..i + 4] == b"SMG-" && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let mut end = i + 4;
            while end < bytes.len() && is_rule_id_char(bytes[end]) {
                end += 1;
            }
            let tok = &text[i..end];
            // Skip wildcard family globs (`SMG-CFG-IAC-*`) and `format!("SMG-TLS-{}", ...)` templates
            let next_b = bytes.get(end).copied().unwrap_or(b' ');
            if tok.ends_with('-') && (next_b == b'*' || next_b == b'{' || next_b == b'<') {
                i = end;
                continue;
            }
            let trimmed = tok.trim_end_matches('-');
            if trimmed.len() > 4 && trimmed[4..].contains('-') {
                out.insert(trimmed.to_string());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn test_all_emitted_rule_ids_exist_in_rule_catalog() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let catalog_ids: BTreeSet<&str> = RULE_CATALOG.iter().map(|r| r.rule_id).collect();
    assert!(
        catalog_ids.len() >= 170,
        "Expected >= 170 canonical rules in RULE_CATALOG, found {}",
        catalog_ids.len()
    );

    let mut rs_files = Vec::new();
    collect_rs_files(&root.join("src"), &mut rs_files);
    collect_rs_files(&root.join("crates"), &mut rs_files);

    let mut missing = Vec::new();
    for path in rs_files {
        if matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some("rules.rs" | "tests.rs")
        ) {
            continue;
        }
        let raw = fs::read_to_string(&path).expect("read rs file");
        // Strip inline #[cfg(test)] tail so synthetic test IDs do not pollute production checks
        let prod = raw.split("#[cfg(test)]").next().unwrap_or(&raw);
        for line in prod.lines() {
            let t = line.trim();
            let emits_rule = t.contains("rule_id:")
                || t.starts_with("id: \"SMG-")
                || t.contains("make_phase9_finding(");
            if !emits_rule {
                continue;
            }
            for tok in extract_smg_tokens(t) {
                // Skip legacy codemod match arms (`"SMG-IAC-001" | "SMG-DOCKER-001" | "SMG-SSRF-002"`)
                if t.contains("=>") {
                    continue;
                }
                if !catalog_ids.contains(tok.as_str()) {
                    missing.push(format!("{}: {}", path.display(), tok));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "Production code emits rule IDs missing from RULE_CATALOG:\n{}",
        missing.join("\n")
    );
}

#[test]
fn test_readme_stays_in_sync_with_rule_catalog_layers_cli_and_pinning() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(root.join("README.md")).expect("read README.md");
    let catalog_ids: BTreeSet<&str> = RULE_CATALOG.iter().map(|r| r.rule_id).collect();

    // 1. Every SMG-* rule token in README.md must exist in RULE_CATALOG
    //    (excluding sequential finding-instance example IDs `SMG-RACE-002` / `SMG-FUZZ-001`
    //     and non-rule markers `[SMG-VAR]` / `[SMG-PROFILE]`).
    let allowed_non_catalog = BTreeSet::from(["SMG-RACE-002", "SMG-FUZZ-001"]);
    let mut bad_readme_ids = Vec::new();
    for tok in extract_smg_tokens(&readme) {
        if !catalog_ids.contains(tok.as_str()) && !allowed_non_catalog.contains(tok.as_str()) {
            bad_readme_ids.push(tok);
        }
    }
    assert!(
        bad_readme_ids.is_empty(),
        "README.md references unknown/stale rule IDs not in RULE_CATALOG: {:?}",
        bad_readme_ids
    );

    // 2. Every layer in RULE_CATALOG must have at least one documented rule ID in README.md
    let readme_tokens = extract_smg_tokens(&readme);
    let catalog_layers: BTreeSet<&str> = RULE_CATALOG.iter().map(|r| r.layer).collect();
    for layer in catalog_layers {
        let has_rule_in_readme = RULE_CATALOG
            .iter()
            .filter(|r| r.layer == layer)
            .any(|r| readme_tokens.contains(r.rule_id));
        assert!(
            has_rule_in_readme,
            "RULE_CATALOG layer `{layer}` has 0 documented rule IDs in README.md"
        );
    }

    // 3. Every top-level CLI subcommand in `src/cli.rs` `enum Commands` must appear in README.md
    for subcmd in [
        "init",
        "index",
        "scan",
        "replay",
        "ui",
        "rules",
        "explain",
        "completions",
        "mcp",
        "hook",
        "deps",
        "image",
        "tls",
        "verify-attestation",
        "idor",
        "templates",
        "sqli",
        "dast",
        "proxy",
        "oob",
        "http-audit",
        "enterprise",
        "doctor",
    ] {
        assert!(
            readme.contains(subcmd),
            "CLI subcommand `smg {subcmd}` is missing from README.md"
        );
    }

    // 4. Quickstart numbered headings (`### <N>. `) must be strictly increasing with zero duplicates
    let mut in_quickstart = false;
    let mut seen_nums = Vec::new();
    for line in readme.lines() {
        if line.starts_with("## Quickstart") {
            in_quickstart = true;
            continue;
        }
        if in_quickstart && line.starts_with("## ") {
            break;
        }
        if in_quickstart
            && let Some(rest) = line.strip_prefix("### ")
            && let Some((num_str, _)) = rest.split_once(". ")
            && let Ok(n) = num_str.parse::<usize>()
        {
            seen_nums.push(n);
        }
    }
    assert!(
        !seen_nums.is_empty(),
        "Expected numbered Quickstart headings in README.md"
    );
    for w in seen_nums.windows(2) {
        assert!(
            w[1] == w[0] + 1,
            "Non-sequential or duplicate Quickstart heading numbers in README.md: {:?}",
            seen_nums
        );
    }

    // 5. Security hygiene: installer one-liners in README.md must never pipe unpinned `/main/install.`
    assert!(
        !readme.contains("/main/install.sh") && !readme.contains("/main/install.ps1"),
        "README.md must pin installer URLs to a release tag instead of mutable `/main/install.*`"
    );

    // 6. No stale `16-language` or `16 languages` drift or `Tree-sitter AST (18 Languages)` claim
    assert!(
        !readme.contains("16-language")
            && !readme.contains("Tree-sitter AST (18 Languages)")
            && !readme.contains("Wave 2-3"),
        "README.md contains stale language count or internal `Wave 2-3` jargon"
    );
}
