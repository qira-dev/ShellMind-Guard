//! Phase 31B: 16-Language Multi-Hunk Semantic AST Patcher & Atomic `--verify-fix` Gate
//! - Synthesizes coordinated multi-hunk unified diffs (import/guard declaration + sink-line wrap)
//!   across all 16 supported languages (`Rust`, `TS`, `JS`, `Python`, `Go`, `Java`, `C#`, `PHP`,
//!   `Ruby`, `Kotlin`, `Swift`, `Dart`, `C`, `C++`, `Solidity`, `Move`).
//! - Verifies patched source syntax via `smg_graph::check_source_syntax` and executes a
//!   `--verify-fix` predicate with automatic atomic rollback if syntax breaks or the finding persists.

use crate::codemods::format_multi_hunk_udiff;
use smg_core::Language;
use smg_graph::{GuardKind, check_source_syntax};

/// Outcome of an atomic `--verify-fix` multi-hunk patch application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFixOutcome {
    pub applied: bool,
    pub syntax_ok: bool,
    pub finding_eliminated: bool,
    pub rolled_back: bool,
    pub unified_diff: String,
    pub final_source: String,
    pub reason: String,
}

/// Returns `(optional_import_line, guard_prefix_statement)` tailored to each of the 16 languages
/// and the missing `GuardKind`.
fn lang_semantic_guard_snippet(
    lang: Language,
    guard: GuardKind,
) -> (Option<&'static str>, &'static str) {
    match (lang, guard) {
        (Language::Rust, GuardKind::Auth) => (None, "ensure_authenticated(ctx)?;"),
        (Language::Rust, GuardKind::TxLock) => (
            None,
            "let _tx_guard = tx.lock().map_err(|_| anyhow::anyhow!(\"lock poisoned\"))?;",
        ),
        (Language::TypeScript | Language::JavaScript, GuardKind::Auth) => (
            Some("import { requireAuth } from './middleware/auth';"),
            "await requireAuth(req, res);",
        ),
        (Language::TypeScript | Language::JavaScript, GuardKind::TxLock) => (
            None,
            "await db.transaction(async (tx) => { /* SELECT ... FOR UPDATE */ });",
        ),
        (Language::Python, GuardKind::Auth) => (
            Some("from app.security import require_authenticated"),
            "require_authenticated(request)",
        ),
        (Language::Python, GuardKind::TxLock) => {
            (None, "with db.begin():  # row-level SELECT FOR UPDATE")
        }
        (Language::Go, GuardKind::Auth) => (
            None,
            "if err := requireAuth(ctx); err != nil { return err }",
        ),
        (Language::Java, GuardKind::Auth) => {
            (None, "SecurityGuard.requireAuthenticated(principal);")
        }
        (Language::CSharp, GuardKind::Auth) => (None, "SecurityGuard.EnsureAuthenticated(User);"),
        (Language::Php, GuardKind::Auth) => (None, "AuthGuard::requireAuthenticated($request);"),
        (Language::Ruby, GuardKind::Auth) => (None, "authenticate_user!"),
        (Language::Kotlin, GuardKind::Auth) => (None, "requireAuthenticated(call)"),
        (Language::Swift, GuardKind::Auth) => (None, "try requireAuthenticated(req)"),
        (Language::Dart, GuardKind::Auth) => (None, "await requireAuthenticated(request);"),
        (Language::C | Language::Cpp, GuardKind::Auth) => {
            (None, "if (!smg_check_auth(ctx)) { return -1; }")
        }
        (Language::Solidity, GuardKind::Auth) => {
            (None, "require(msg.sender == owner, \"Unauthorized\");")
        }
        (Language::Move, GuardKind::Auth) => {
            (None, "assert!(signer::address_of(account) == admin, 0);")
        }
        // Generic safe guard fallback for remaining guard kinds across all 16 languages
        (Language::Python, _) => (None, "validate_and_sanitize_input(payload)"),
        (Language::Ruby, _) => (None, "validate_and_sanitize_input!(params)"),
        (Language::Go, _) => (
            None,
            "if err := validateInput(req); err != nil { return err }",
        ),
        (Language::Kotlin | Language::Swift, _) => (None, "validateInput(input)"),
        (Language::Solidity, _) => (None, "require(amount > 0, \"Invalid input\");"),
        (Language::Move, _) => (None, "assert!(amount > 0, 1);"),
        _ => (None, "validateInput(input);"),
    }
}

fn import_insert_index(lang: Language, lines: &[String]) -> usize {
    let mut idx = 0usize;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if idx == 0 && trimmed.starts_with("#!") {
            idx += 1;
            continue;
        }
        match lang {
            Language::Python => {
                if trimmed.starts_with("# -*-")
                    || trimmed.starts_with("# coding")
                    || trimmed.starts_with("from __future__ import ")
                {
                    idx += 1;
                    continue;
                }
                if trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''") {
                    let delim = if trimmed.starts_with("\"\"\"") {
                        "\"\"\""
                    } else {
                        "'''"
                    };
                    if trimmed.len() >= 6 && trimmed[3..].contains(delim) {
                        idx += 1;
                        continue;
                    }
                    idx += 1;
                    while idx < lines.len() {
                        let closing = lines[idx].contains(delim);
                        idx += 1;
                        if closing {
                            break;
                        }
                    }
                    continue;
                }
            }
            Language::TypeScript | Language::JavaScript => {
                if matches!(
                    trimmed,
                    "'use client'"
                        | "\"use client\""
                        | "'use client';"
                        | "\"use client\";"
                        | "'use server'"
                        | "\"use server\""
                        | "'use server';"
                        | "\"use server\";"
                        | "'use strict'"
                        | "\"use strict\""
                        | "'use strict';"
                        | "\"use strict\";"
                ) {
                    idx += 1;
                    continue;
                }
            }
            _ => {}
        }
        break;
    }
    idx
}

/// Synthesizes a multi-hunk unified diff AND the resulting patched source for any of the 16
/// supported languages: Hunk 1 inserts a required import after leading directives/shebangs (if
/// absent), and Hunk 2 inserts or wraps the semantic guard around `sink_line_1based` matching
/// the sink line's indentation.
pub fn synthesize_16lang_multi_hunk_patch(
    lang: Language,
    guard: GuardKind,
    rel_path: &str,
    source: &str,
    sink_line_1based: usize,
) -> Option<(String, String)> {
    let lines: Vec<String> = source.lines().map(str::to_string).collect();
    if lines.is_empty() || sink_line_1based == 0 || sink_line_1based > lines.len() {
        return None;
    }

    let (opt_import, guard_stmt) = lang_semantic_guard_snippet(lang, guard);
    let sink_idx = sink_line_1based - 1;
    let sink_line = &lines[sink_idx];
    let indent: String = sink_line
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();

    let mut hunks: Vec<(usize, Vec<String>, Vec<String>)> = Vec::new();
    let mut new_lines = lines.clone();
    let mut line_shift = 0usize;

    if let Some(import_stmt) = opt_import
        && !source.contains(import_stmt)
    {
        let ins_idx = import_insert_index(lang, &lines);
        if ins_idx < sink_idx {
            let anchor = lines[ins_idx].clone();
            hunks.push((
                ins_idx + 1,
                vec![anchor.clone()],
                vec![import_stmt.to_string(), anchor],
            ));
            new_lines.insert(ins_idx, import_stmt.to_string());
            line_shift = 1;
        }
    }

    let replacement_lines: Vec<String> = match (lang, guard) {
        (Language::Python, GuardKind::TxLock) => {
            // Indent sink line inside `with db.begin():` so Python indentation stays valid
            vec![
                format!("{indent}{guard_stmt}"),
                format!("{indent}    {}", sink_line.trim_start()),
            ]
        }
        (Language::TypeScript | Language::JavaScript, GuardKind::TxLock) => {
            let trimmed = sink_line.trim();
            if let Some(ret_expr) = trimmed.strip_prefix("return ") {
                vec![
                    format!("{indent}return await db.transaction(async (_tx) => {{"),
                    format!("{indent}  return {ret_expr}"),
                    format!("{indent}}});"),
                ]
            } else {
                vec![
                    format!("{indent}await db.transaction(async (_tx) => {{"),
                    format!("{indent}  {trimmed}"),
                    format!("{indent}}});"),
                ]
            }
        }
        _ => vec![format!("{indent}{guard_stmt}"), sink_line.clone()],
    };

    hunks.push((
        sink_line_1based,
        vec![sink_line.clone()],
        replacement_lines.clone(),
    ));
    let target_pos = sink_idx + line_shift;
    new_lines.splice(target_pos..=target_pos, replacement_lines);

    let udiff = format_multi_hunk_udiff(rel_path, &hunks);
    let mut patched = new_lines.join("\n");
    if source.ends_with('\n') {
        patched.push('\n');
    }
    Some((udiff, patched))
}

/// Applies a 16-language multi-hunk semantic patch with pre-commit syntax verification
/// (`smg_graph::check_source_syntax`) and a `--verify-fix` closure. If syntax fails OR the
/// finding is not eliminated, rolls back atomically to the original `source`.
pub fn apply_patch_and_verify_fix<F>(
    lang: Language,
    guard: GuardKind,
    rel_path: &str,
    source: &str,
    sink_line_1based: usize,
    verify_finding_eliminated: F,
) -> VerifyFixOutcome
where
    F: Fn(&str) -> bool,
{
    let Some((udiff, patched)) =
        synthesize_16lang_multi_hunk_patch(lang, guard, rel_path, source, sink_line_1based)
    else {
        return VerifyFixOutcome {
            applied: false,
            syntax_ok: true,
            finding_eliminated: false,
            rolled_back: false,
            unified_diff: String::new(),
            final_source: source.to_string(),
            reason: "Invalid target line or empty source".into(),
        };
    };

    let syntax_ok = check_source_syntax(lang, rel_path, &patched).is_ok();
    if !syntax_ok {
        return VerifyFixOutcome {
            applied: false,
            syntax_ok: false,
            finding_eliminated: false,
            rolled_back: true,
            unified_diff: udiff,
            final_source: source.to_string(),
            reason: "Patched source failed tree-sitter syntax gate — rolled back atomically".into(),
        };
    }

    let finding_eliminated = verify_finding_eliminated(&patched);
    if !finding_eliminated {
        return VerifyFixOutcome {
            applied: false,
            syntax_ok: true,
            finding_eliminated: false,
            rolled_back: true,
            unified_diff: udiff,
            final_source: source.to_string(),
            reason:
                "--verify-fix check reported target finding still present — rolled back atomically"
                    .into(),
        };
    }

    VerifyFixOutcome {
        applied: true,
        syntax_ok: true,
        finding_eliminated: true,
        rolled_back: false,
        unified_diff: udiff,
        final_source: patched,
        reason: "Multi-hunk semantic patch verified (syntax OK + finding eliminated)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_and_verifies_multi_hunk_patches_across_all_16_languages() {
        let cases: &[(Language, &str, &str, usize)] = &[
            (
                Language::Rust,
                "a.rs",
                "fn pay(ctx: &Ctx) -> anyhow::Result<()> {\n    debit();\n    Ok(())\n}\n",
                2,
            ),
            (
                Language::TypeScript,
                "a.ts",
                "export async function pay(req: any, res: any) {\n  return debit();\n}\n",
                2,
            ),
            (
                Language::JavaScript,
                "a.js",
                "export async function pay(req, res) {\n  return debit();\n}\n",
                2,
            ),
            (
                Language::Python,
                "a.py",
                "def pay(request):\n    return debit()\n",
                2,
            ),
            (
                Language::Go,
                "a.go",
                "package main\nfunc pay(ctx any) error {\n\treturn debit()\n}\n",
                3,
            ),
            (
                Language::Java,
                "A.java",
                "class A {\n  void pay() {\n    debit();\n  }\n}\n",
                3,
            ),
            (
                Language::CSharp,
                "A.cs",
                "class A {\n  void Pay() {\n    Debit();\n  }\n}\n",
                3,
            ),
            (
                Language::Php,
                "a.php",
                "<?php\nfunction pay($request) {\n  debit();\n}\n",
                3,
            ),
            (Language::Ruby, "a.rb", "def pay\n  debit\nend\n", 2),
            (
                Language::Kotlin,
                "A.kt",
                "fun pay(call: Any) {\n  debit()\n}\n",
                2,
            ),
            (
                Language::Swift,
                "a.swift",
                "func pay(_ req: Any) throws {\n  debit()\n}\n",
                2,
            ),
            (
                Language::Dart,
                "a.dart",
                "Future<void> pay(dynamic request) async {\n  debit();\n}\n",
                2,
            ),
            (
                Language::C,
                "a.c",
                "int pay(void *ctx) {\n  return debit();\n}\n",
                2,
            ),
            (
                Language::Cpp,
                "a.cpp",
                "int pay(void *ctx) {\n  return debit();\n}\n",
                2,
            ),
            (
                Language::Solidity,
                "A.sol",
                "contract A {\n  function pay() external {\n    debit();\n  }\n}\n",
                3,
            ),
            (
                Language::Move,
                "a.move",
                "module m::a {\n  public fun pay(account: &signer) {\n    debit();\n  }\n}\n",
                3,
            ),
        ];

        for &(lang, file, src, line) in cases {
            let outcome =
                apply_patch_and_verify_fix(lang, GuardKind::Auth, file, src, line, |patched| {
                    patched.len() > src.len()
                });
            assert!(
                outcome.applied && outcome.syntax_ok && outcome.finding_eliminated,
                "16-lang patch failed for {lang:?}: {outcome:#?}"
            );
            assert!(outcome.unified_diff.contains("@@ -"));
        }

        // Verify atomic rollback when `--verify-fix` reports finding still present
        let src = "def pay(request):\n    return debit()\n";
        let rolled =
            apply_patch_and_verify_fix(Language::Python, GuardKind::Auth, "a.py", src, 2, |_| {
                false
            });
        assert!(!rolled.applied);
        assert!(rolled.rolled_back);
        assert_eq!(rolled.final_source, src);
    }
}
