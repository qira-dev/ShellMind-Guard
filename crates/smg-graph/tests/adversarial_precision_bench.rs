use smg_core::{IndexedFile, Language, ShellMindGuardConfig};
use smg_graph::{Confidence, GraphAnalysisResult, analyze_codebase};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
struct BenchFile {
    rel_path: &'static str,
    lang: Language,
    code: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum TrapKind {
    BaselineVuln,
    BaselineSafe,
    ScopeCollisionTrap,
    DominatorGuardTrap,
    OneHopWrapperTrap,
    CheckedBoundsTrap,
}

#[derive(Clone, Debug)]
struct AdversarialCase {
    id: &'static str,
    family: &'static str,
    expected_prefix: &'static str,
    expect_finding: bool,
    trap_kind: TrapKind,
    files: Vec<BenchFile>,
}

fn build_indexed(files: &[BenchFile]) -> Vec<IndexedFile> {
    files
        .iter()
        .map(|f| {
            let bytes = f.code.as_bytes().to_vec();
            let hash = blake3::hash(&bytes).to_hex().to_string();
            IndexedFile {
                rel_path: f.rel_path.to_string(),
                abs_path: PathBuf::from(f.rel_path),
                language: f.lang,
                blake3_hash: hash,
                mtime_ns: 0,
                size_bytes: bytes.len() as u64,
                cached_bytes: Some(bytes),
            }
        })
        .collect()
}

fn matches_prefix(res: &GraphAnalysisResult, prefix: &str) -> bool {
    res.findings
        .iter()
        .any(|f| f.rule_id.starts_with(prefix) || f.rule_id == prefix)
}

fn corpus() -> Vec<AdversarialCase> {
    vec![
        // -----------------------------------------------------------------
        // 1. Auth Middleware & Route Mutation (TS / Python / Go / Rust)
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_auth_vuln_unguarded_withdraw",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/routes/billing.ts",
                lang: Language::TypeScript,
                code: r#"
import express from 'express';
const app = express();
function debitBalance(userId: string, amount: number) {
    return db.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, userId]);
}
app.post('/api/v1/checkout/withdraw', (req, res) => {
    const out = debitBalance(req.body.userId, req.body.amount);
    res.json(out);
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_auth_safe_dominator_early_return",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: false,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/routes/billing_safe.ts",
                lang: Language::TypeScript,
                code: r#"
import express from 'express';
const app = express();
app.post('/api/v1/checkout/withdraw', requireAuth, async (req, res) => {
    if (!req.user?.id) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    await db.transaction(async (tx) => {
        await tx.query('SELECT balance FROM accounts WHERE id = $1 FOR UPDATE', [req.user.id]);
        await tx.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [req.body.amount, req.user.id]);
    });
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_auth_vuln_non_dominating_branch_guard",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/routes/partial_auth.ts",
                lang: Language::TypeScript,
                code: r#"
import express from 'express';
const app = express();
function writeRefund(id: string) {
    return db.query('UPDATE accounts SET balance = balance + 100 WHERE id = $1', [id]);
}
app.post('/api/v1/refund', (req, res) => {
    if (req.query.strict === '1') {
        requireAuth(req, res, () => {});
    }
    // Vulnerable: guard only executes when strict === '1'
    writeRefund(req.body.id);
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "py_auth_vuln_flask_transfer",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/routes.py",
                lang: Language::Python,
                code: r#"
from flask import Flask, request
app = Flask(__name__)

def debit_wallet(uid, amount):
    cursor.execute("UPDATE wallets SET balance = balance - %s WHERE user_id = %s", (amount, uid))

@app.post("/api/wallet/debit")
def handle_debit():
    debit_wallet(request.json["user_id"], request.json["amount"])
    return {"ok": True}
"#,
            }],
        },
        AdversarialCase {
            id: "py_auth_safe_fastapi_depends",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "app/safe_routes.py",
                lang: Language::Python,
                code: r#"
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/api/wallet/debit")
def handle_debit(user = Depends(require_auth)):
    with db.transaction():
        cursor.execute("UPDATE wallets SET balance = balance - %s WHERE user_id = %s", (10, user.id))
    return {"ok": True}
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 2. Race Condition / Double Spend (TS / Go)
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_race_vuln_balance_no_tx",
            family: "RACE",
            expected_prefix: "SMG-RACE",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/pay/withdraw.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/api/pay/withdraw', requireAuth, async (req, res) => {
    const row = await db.query('SELECT balance FROM wallets WHERE user_id = $1', [req.user.id]);
    if (row.balance >= req.body.amount) {
        await db.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [req.body.amount, req.user.id]);
    }
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_race_safe_for_update_tx",
            family: "RACE",
            expected_prefix: "SMG-RACE",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/pay/withdraw_safe.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/api/pay/withdraw', requireAuth, async (req, res) => {
    await db.transaction(async (tx) => {
        await tx.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [req.user.id]);
        await tx.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [req.body.amount, req.user.id]);
    });
    res.json({ ok: true });
});
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 3. IDOR (Authenticated access without ownership predicate)
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_idor_vuln_order_by_param_id",
            family: "IDOR",
            expected_prefix: "SMG-IDOR",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/orders/controller.ts",
                lang: Language::TypeScript,
                code: r#"
app.get('/api/orders/:id', requireAuth, async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order);
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_idor_safe_scoped_owner",
            family: "IDOR",
            expected_prefix: "SMG-IDOR",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/orders/controller_safe.ts",
                lang: Language::TypeScript,
                code: r#"
app.get('/api/orders/:id', requireAuth, async (req, res) => {
    const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
    res.json(order);
});
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 4. SQLi & Scope-Collision Adversarial Traps (JS/TS/Py/Go/Java)
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "js_sqli_vuln_template_interp",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/users/search.js",
                lang: Language::JavaScript,
                code: r#"
app.get('/users', requireAuth, async (req, res) => {
    const name = req.query.q;
    const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
    res.json(rows);
});
"#,
            }],
        },
        AdversarialCase {
            id: "js_sqli_safe_parameterized_query",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/users/search_safe.js",
                lang: Language::JavaScript,
                code: r#"
app.get('/users', requireAuth, async (req, res) => {
    const name = req.query.q;
    const rows = await db.query('SELECT * FROM users WHERE name = $1 AND owner_id = $2', [name, req.user.id]);
    res.json(rows);
});
"#,
            }],
        },
        AdversarialCase {
            id: "go_sqli_vuln_sprintf",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "internal/users/repo.go",
                lang: Language::Go,
                code: r#"
package users
import (
    "database/sql"
    "fmt"
    "net/http"
)
func FindUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("name")
    stmt := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", q)
    db.Query(stmt)
}
"#,
            }],
        },
        AdversarialCase {
            id: "go_sqli_safe_placeholder",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "internal/users/repo_safe.go",
                lang: Language::Go,
                code: r#"
package users
import (
    "database/sql"
    "net/http"
)
func FindUserSafe(db *sql.DB, w http.ResponseWriter, r *http.Request, callerId string) {
    q := r.URL.Query().Get("name")
    db.Query("SELECT id FROM users WHERE name = $1 AND user_id = $2", q, callerId)
}
"#,
            }],
        },
        AdversarialCase {
            id: "ts_scope_collision_unrelated_execute_not_sqli",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![
                BenchFile {
                    rel_path: "src/analytics/metrics.ts",
                    lang: Language::TypeScript,
                    code: r#"
export class LocalMetricsRunner {
    query(metricName: string): number {
        return 42 + metricName.length;
    }
}
"#,
                },
                BenchFile {
                    rel_path: "src/routes/metrics_route.ts",
                    lang: Language::TypeScript,
                    code: r#"
import { LocalMetricsRunner } from '../analytics/metrics';
const runner = new LocalMetricsRunner();
app.get('/metrics', requireAuth, (req, res) => {
    const count = runner.query(String(req.query.name || 'cpu'));
    res.json({ count });
});
"#,
                },
            ],
        },
        // -----------------------------------------------------------------
        // 5. Command Injection (Py / TS / Rust) & 1-Hop Sanitizer
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "py_cmdi_vuln_shell_true",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/git_tools.py",
                lang: Language::Python,
                code: r#"
import subprocess
from flask import request

def inspect_log():
    branch = request.args.get("branch", "main")
    return subprocess.run(f"git log {branch}", shell=True)
"#,
            }],
        },
        AdversarialCase {
            id: "py_cmdi_safe_arg_list_shell_false",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "app/git_tools_safe.py",
                lang: Language::Python,
                code: r#"
import subprocess
from flask import request

def inspect_log():
    n = int(request.args.get("n", "5"))
    return subprocess.run(["git", "log", "-n", str(n)], shell=False)
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 6. Path Traversal + 1-Hop Sanitizer Wrapper Trap
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_path_vuln_raw_join",
            family: "PATH",
            expected_prefix: "SMG-PATH",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/files/download.ts",
                lang: Language::TypeScript,
                code: r#"
import path from 'path';
app.get('/download', requireAuth, (req, res) => {
    const target = path.join('/srv/uploads', String(req.query.file));
    res.sendFile(target);
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_path_safe_one_hop_wrapper",
            family: "PATH",
            expected_prefix: "SMG-PATH",
            expect_finding: false,
            trap_kind: TrapKind::OneHopWrapperTrap,
            files: vec![
                BenchFile {
                    rel_path: "src/files/sanitize.ts",
                    lang: Language::TypeScript,
                    code: r#"
import path from 'path';
const BASE = '/srv/uploads';
export function resolveSafeUploadPath(raw: string): string {
    const clean = path.basename(String(raw));
    const resolved = path.resolve(BASE, clean);
    if (!resolved.startsWith(BASE + path.sep)) {
        throw new Error('blocked traversal');
    }
    return resolved;
}
"#,
                },
                BenchFile {
                    rel_path: "src/files/download_safe.ts",
                    lang: Language::TypeScript,
                    code: r#"
import { resolveSafeUploadPath } from './sanitize';
app.get('/download', requireAuth, (req, res) => {
    const target = resolveSafeUploadPath(String(req.query.file));
    res.sendFile(target);
});
"#,
                },
            ],
        },
        // -----------------------------------------------------------------
        // 7. SSRF & XSS
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_ssrf_vuln_unvalidated_fetch",
            family: "SSRF",
            expected_prefix: "SMG-SSRF",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/webhooks/proxy.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/proxy', requireAuth, async (req, res) => {
    const r = await fetch(req.body.webhookUrl);
    res.send(await r.text());
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_xss_vuln_dangerously_set_inner_html",
            family: "XSS",
            expected_prefix: "SMG-XSS",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/ui/bio.tsx",
                lang: Language::TypeScript,
                code: r#"
export function Bio({ req }: any) {
    return <div dangerouslySetInnerHTML={{ __html: req.query.bio }} />;
}
"#,
            }],
        },
        AdversarialCase {
            id: "ts_xss_safe_dompurify",
            family: "XSS",
            expected_prefix: "SMG-XSS",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/ui/bio_safe.tsx",
                lang: Language::TypeScript,
                code: r#"
import DOMPurify from 'dompurify';
export function BioSafe({ req }: any) {
    const clean = DOMPurify.sanitize(String(req.query.bio || ''));
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 8. C/C++ Memory Bounds & Checked Allocation Trap + Cross-Lang Config/Secrets
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "c_mem_vuln_unchecked_mul_memcpy",
            family: "MEM",
            expected_prefix: "SMG-MEM",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "native/alloc.c",
                lang: Language::C,
                code: r#"
#include <stdlib.h>
#include <string.h>
void* copy_items(void* src, size_t count, size_t item_sz, size_t n) {
    void* buf = malloc(count * item_sz);
    memcpy(buf, src, n);
    return buf;
}
"#,
            }],
        },
        AdversarialCase {
            id: "c_mem_safe_checked_bounds",
            family: "MEM",
            expected_prefix: "SMG-MEM",
            expect_finding: false,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "native/alloc_safe.c",
                lang: Language::C,
                code: r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
void* copy_items_safe(const void* src, size_t count, size_t item_sz, size_t cap) {
    if (item_sz == 0 || count > SIZE_MAX / item_sz) {
        return NULL;
    }
    size_t total = count * item_sz;
    if (total > cap) {
        return NULL;
    }
    void* buf = calloc(count, item_sz);
    if (!buf) return NULL;
    memcpy(buf, src, total);
    return buf;
}
"#,
            }],
        },
        AdversarialCase {
            id: "cfg_secret_vuln_jwt_decode_and_stripe",
            family: "SEC_CFG",
            expected_prefix: "SMG-",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/auth/jwt_bad.js",
                lang: Language::JavaScript,
                code: concat!(
                    "\nconst STRIPE_LIVE_SECRET = \"sk_live_",
                    "51H7FakeTestKey9999999999999999999999\";\n",
                    "function parseUser(req) {\n",
                    "    return jwt.decode(req.headers.authorization);\n",
                    "}\n",
                ),
            }],
        },
        AdversarialCase {
            id: "java_sqli_vuln_concat",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/main/java/com/acme/UserDao.java",
                lang: Language::Java,
                code: r#"
package com.acme;
import java.sql.*;
import javax.servlet.http.*;
public class UserDao {
    public ResultSet find(Connection conn, HttpServletRequest req) throws SQLException {
        String name = req.getParameter("name");
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
"#,
            }],
        },
        AdversarialCase {
            id: "php_cmdi_vuln_shell_exec",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "public/ping.php",
                lang: Language::Php,
                code: r#"<?php
$host = $_GET['host'];
echo shell_exec("ping -c 1 " . $host);
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 9. Extended 40-Case Tough Multi-Language & Dominator Traps
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "ts_auth_vuln_guard_after_sink",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/routes/late_guard.ts",
                lang: Language::TypeScript,
                code: r#"
import express from 'express';
const app = express();
app.post('/api/v1/late-debit', async (req, res) => {
    await db.query('UPDATE wallets SET balance = balance - $1 WHERE id = $2', [req.body.amt, req.body.id]);
    requireAuth(req, res, () => {});
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_auth_safe_diamond_both_branches",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: false,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/routes/diamond_safe.ts",
                lang: Language::TypeScript,
                code: r#"
import express from 'express';
const app = express();
app.post('/api/v1/diamond', async (req, res) => {
    if (req.headers['x-mode'] === 'sso') {
        verifyJwt(req);
    } else {
        requireAuth(req, res, () => {});
    }
    await db.transaction(async (tx) => {
        await tx.query('SELECT balance FROM wallets WHERE id = $1 FOR UPDATE', [req.body.id]);
        await tx.query('UPDATE wallets SET balance = balance - $1 WHERE id = $2', [req.body.amt, req.body.id]);
    });
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_sqli_safe_prisma_tagged_template",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/users/prisma_safe.ts",
                lang: Language::TypeScript,
                code: r#"
app.get('/api/users/find', requireAuth, async (req, res) => {
    const q = String(req.query.q || '');
    const rows = await prisma.$queryRaw`SELECT id, email FROM users WHERE email = ${q} AND org_id = ${req.user.orgId}`;
    res.json(rows);
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_sqli_vuln_prisma_raw_unsafe",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/users/prisma_unsafe.ts",
                lang: Language::TypeScript,
                code: r#"
app.get('/api/users/find', requireAuth, async (req, res) => {
    const q = String(req.query.q || '');
    const rows = await prisma.$queryRawUnsafe(`SELECT id FROM users WHERE email = '${q}'`);
    res.json(rows);
});
"#,
            }],
        },
        AdversarialCase {
            id: "py_deser_vuln_yaml_load",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/yaml_loader.py",
                lang: Language::Python,
                code: r#"
import yaml
from flask import request

def parse_cfg():
    raw = request.data
    return yaml.load(raw)
"#,
            }],
        },
        AdversarialCase {
            id: "py_deser_safe_yaml_safe_load",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "app/yaml_loader_safe.py",
                lang: Language::Python,
                code: r#"
import yaml
from flask import request

def parse_cfg_safe():
    raw = request.data
    return yaml.safe_load(raw)
"#,
            }],
        },
        AdversarialCase {
            id: "rust_sqli_safe_sqlx_bind",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/orders.rs",
                lang: Language::Rust,
                code: r#"
pub async fn get_order(pool: &PgPool, id: i64, user_id: i64) {
    let _ = sqlx::query("SELECT id FROM orders WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .fetch_one(pool)
        .await;
}
"#,
            }],
        },
        AdversarialCase {
            id: "rust_cmdi_vuln_sh_dash_c",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/cli_exec.rs",
                lang: Language::Rust,
                code: r#"
use std::process::Command;
pub async fn run_user_cmd(Json(req_cmd): Json<String>) {
    let _ = Command::new("sh").arg("-c").arg(format!("echo {}", req_cmd)).output();
}
"#,
            }],
        },
        AdversarialCase {
            id: "ruby_sqli_vuln_rails_interp",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/controllers/users_controller.rb",
                lang: Language::Ruby,
                code: r#"
class UsersController < ApplicationController
  def search
    name = params[:name]
    @users = User.where("name = '#{name}'")
    render json: @users
  end
end
"#,
            }],
        },
        AdversarialCase {
            id: "ruby_sqli_safe_rails_placeholder",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "app/controllers/safe_users_controller.rb",
                lang: Language::Ruby,
                code: r#"
class SafeUsersController < ApplicationController
  before_action :authenticate_user!
  def search
    name = params[:name]
    @users = User.where("name = ? AND account_id = ?", name, current_user.account_id)
    render json: @users
  end
end
"#,
            }],
        },
        AdversarialCase {
            id: "cs_sqli_vuln_interp",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "Controllers/UsersController.cs",
                lang: Language::CSharp,
                code: r#"
using Microsoft.AspNetCore.Mvc;
public class UsersController : ControllerBase {
    [HttpGet("/api/users/find")]
    public IActionResult Find([FromQuery] string name) {
        var q = $"SELECT * FROM Users WHERE Name = '{name}'";
        var cmd = new SqlCommand(q);
        return Ok();
    }
}
"#,
            }],
        },
        AdversarialCase {
            id: "kotlin_cmdi_vuln_runtime_exec",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/main/kotlin/ShellService.kt",
                lang: Language::Kotlin,
                code: r#"
fun configureRoutes(routing: Routing) {
    routing.post("/api/run") {
        val userInput = call.parameters["cmd"] ?: ""
        val cmd = "grep " + userInput + " /var/log/app.log"
        Runtime.getRuntime().exec(cmd)
    }
}
"#,
            }],
        },
        AdversarialCase {
            id: "cfg_jwt_safe_verify_rs256",
            family: "SEC_CFG",
            expected_prefix: "SMG-CFG-JWT",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/auth/jwt_safe.js",
                lang: Language::JavaScript,
                code: r#"
function verifyUser(req, pubKey) {
    return jwt.verify(req.headers.authorization, pubKey, { algorithms: ['RS256'] });
}
"#,
            }],
        },
        AdversarialCase {
            id: "cross_file_same_name_isolation_safe",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![
                BenchFile {
                    rel_path: "src/db/safe_repo.ts",
                    lang: Language::TypeScript,
                    code: r#"
export async function runRecord(id: string, ownerId: string) {
    return db.query('SELECT id FROM records WHERE id = $1 AND owner_id = $2', [id, ownerId]);
}
"#,
                },
                BenchFile {
                    rel_path: "src/routes/safe_handler.ts",
                    lang: Language::TypeScript,
                    code: r#"
import { runRecord } from '../db/safe_repo';
app.get('/records/:id', requireAuth, async (req, res) => {
    const out = await runRecord(req.params.id, req.user.id);
    res.json(out);
});
"#,
                },
            ],
        },
        // -----------------------------------------------------------------
        // 13. Wave 2 Core Domains: CI/CD, K8s, ReDoS, ZipSlip, Crypto, Async Queue
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "gha_cicd_vuln_pwn_request",
            family: "CICD",
            expected_prefix: "SMG-CICD",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: ".github/workflows/pr.yml",
                lang: Language::Config,
                code: r#"
on:
  pull_request_target:
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"#,
            }],
        },
        AdversarialCase {
            id: "gha_cicd_safe_env_bound_sha_pinned",
            family: "CICD",
            expected_prefix: "SMG-CICD",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: ".github/workflows/pr_safe.yml",
                lang: Language::Config,
                code: r#"
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
"#,
            }],
        },
        AdversarialCase {
            id: "k8s_vuln_privileged_dockersock",
            family: "K8S",
            expected_prefix: "SMG-K8S",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "deploy/pod.yaml",
                lang: Language::Config,
                code: r#"
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  containers:
    - name: runner
      securityContext:
        privileged: true
"#,
            }],
        },
        AdversarialCase {
            id: "k8s_safe_restricted_pod",
            family: "K8S",
            expected_prefix: "SMG-K8S",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "deploy/safe_pod.yaml",
                lang: Language::Config,
                code: r#"
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
"#,
            }],
        },
        AdversarialCase {
            id: "ts_redos_vuln_nested_quantifier",
            family: "DOS",
            expected_prefix: "SMG-DOS",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/validate/email.ts",
                lang: Language::TypeScript,
                code: r#"
export function isEmailFast(v: string) {
    const re = new RegExp("^([a-zA-Z0-9]+)+$");
    return re.test(v);
}
"#,
            }],
        },
        AdversarialCase {
            id: "ts_redos_safe_linear_pattern",
            family: "DOS",
            expected_prefix: "SMG-DOS",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/validate/slug.ts",
                lang: Language::TypeScript,
                code: r#"
export function isSlug(v: string) {
    const re = new RegExp("^[a-z0-9_-]{3,32}$");
    return re.test(v);
}
"#,
            }],
        },
        AdversarialCase {
            id: "py_zipslip_vuln_extractall",
            family: "PATH",
            expected_prefix: "SMG-ZIP",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/archive.py",
                lang: Language::Python,
                code: r#"
import zipfile

def extract_upload(p: str):
    with zipfile.ZipFile(p) as z:
        z.extractall("/var/data/uploads")
"#,
            }],
        },
        AdversarialCase {
            id: "py_zipslip_safe_realpath_prefix",
            family: "PATH",
            expected_prefix: "SMG-ZIP",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "app/archive_safe.py",
                lang: Language::Python,
                code: r#"
import os, zipfile

def extract_upload(p: str, root: str):
    with zipfile.ZipFile(p) as z:
        for member in z.infolist():
            dst = os.path.realpath(os.path.join(root, member.filename))
            if dst.startswith(os.path.realpath(root) + os.sep):
                z.extract(member, root)
"#,
            }],
        },
        AdversarialCase {
            id: "ts_crypto_vuln_timing_cmp",
            family: "CRYPTO",
            expected_prefix: "SMG-CRYPTO",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/webhooks/verify.ts",
                lang: Language::TypeScript,
                code: r#"
export function verifyWebhook(signature: string, expectedSig: string) {
    return signature === expectedSig;
}
"#,
            }],
        },
        AdversarialCase {
            id: "ts_crypto_safe_timing_safe_equal",
            family: "CRYPTO",
            expected_prefix: "SMG-CRYPTO",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/webhooks/verify_safe.ts",
                lang: Language::TypeScript,
                code: r#"
import crypto from 'node:crypto';
export function verifyWebhook(signature: Buffer, expectedSig: Buffer) {
    return crypto.timingSafeEqual(signature, expectedSig);
}
"#,
            }],
        },
        AdversarialCase {
            id: "ts_queue_vuln_missing_tenant_validation",
            family: "QUEUE",
            expected_prefix: "SMG-QUEUE",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/workers/jobs.ts",
                lang: Language::TypeScript,
                code: r#"
const worker = new Worker('payout', async (job) => {
    await exec(job.data.cmd);
});
"#,
            }],
        },
        AdversarialCase {
            id: "ts_queue_safe_validated_tenant_scoped",
            family: "QUEUE",
            expected_prefix: "SMG-QUEUE",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/workers/jobs_safe.ts",
                lang: Language::TypeScript,
                code: r#"
const worker = new Worker('payout', async (job) => {
    const data = payoutSchema.parse(job.data);
    await debitForTenant(data.tenantId, data.amount, data.idempotencyKey);
});
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 14. Wave 3 Engine Precision + Protocols / AI / OAuth / State
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "wave3_constant_literal_sql_safe",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/db/audit_safe.ts",
                lang: Language::TypeScript,
                code: r#"
app.get('/api/logs', requireAuth, async (req, res) => {
    const TABLE = "audit_logs";
    const id = req.query.id;
    const rows = await db.query("SELECT * FROM " + TABLE + " WHERE id = $1", [id]);
    res.json(rows);
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_discarded_sanitizer_xss_vuln",
            family: "XSS",
            expected_prefix: "SMG-XSS",
            expect_finding: true,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "src/views/bio_discarded.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/profile/bio', requireAuth, (req, res) => {
    const bio = req.body.bio;
    DOMPurify.sanitize(bio);
    if (escapeHtml(bio)) {
        res.send(`<div>${bio}</div>`);
    }
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_assigned_sanitizer_xss_safe",
            family: "XSS",
            expected_prefix: "SMG-XSS",
            expect_finding: false,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "src/views/bio_clean.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/profile/bio-clean', requireAuth, (req, res) => {
    const bio = DOMPurify.sanitize(req.body.bio);
    res.send(`<div>${bio}</div>`);
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_dynamic_dispatch_cmdi_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::OneHopWrapperTrap,
            files: vec![BenchFile {
                rel_path: "src/ops/dispatcher.ts",
                lang: Language::TypeScript,
                code: r#"
const handlers = { diag: runDiag };
function runDiag(cmd: string) {
    execSync(cmd);
}
app.post('/api/ops', requireAuth, (req, res) => {
    const action = req.body.action;
    handlers[action](req.body.cmd);
    res.json({ ok: true });
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_graphql_ws_unauth_vuln",
            family: "API",
            expected_prefix: "SMG-API",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/api/graphql_ws.ts",
                lang: Language::TypeScript,
                code: r#"
const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
wss.on('connection', (ws) => {
    ws.on('message', (msg) => execSync(msg.toString()));
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_graphql_ws_hardened_safe",
            family: "API",
            expected_prefix: "SMG-API",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/api/graphql_ws_safe.ts",
                lang: Language::TypeScript,
                code: r#"
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
    validationRules: [depthLimit(6)],
});
const wss = new WebSocketServer({ verifyClient: checkJwt });
wss.on('connection', (ws) => {
    ws.on('message', (msg) => {
        jwt.verify(msg.token, process.env.JWT_PUBLIC_KEY);
        console.log(msg.event);
    });
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_ai_llm_sql_vuln",
            family: "AI",
            expected_prefix: "SMG-AI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/ai/agent_vuln.ts",
                lang: Language::TypeScript,
                code: r#"
import OpenAI from 'openai';
export async function askDb(prompt: string) {
    const res = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });
    const generatedSql = res.choices[0].message.content;
    return db.query(generatedSql);
}
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_ai_llm_allowlisted_safe",
            family: "AI",
            expected_prefix: "SMG-AI",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/ai/agent_safe.ts",
                lang: Language::TypeScript,
                code: r#"
import OpenAI from 'openai';
export async function askDbSafe(prompt: string) {
    const ALLOWED_TOOLS = { lookup: true };
    const res = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });
    const call = ToolSchema.safeParse(res.choices[0].message);
    if (ALLOWED_TOOLS[call.tool]) {
        return db.query('SELECT * FROM items WHERE id = $1', [call.id]);
    }
}
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_oauth_pkce_missing_vuln",
            family: "OAUTH",
            expected_prefix: "SMG-AUTH-PKCE",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/auth/oauth_bad.ts",
                lang: Language::TypeScript,
                code: r#"
export function loginUrl(redirectUri: string, clientId: string) {
    return `https://idp.example.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}`;
}
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_oauth_pkce_hardened_safe",
            family: "OAUTH",
            expected_prefix: "SMG-AUTH-PKCE",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/auth/oauth_safe.ts",
                lang: Language::TypeScript,
                code: r#"
export function loginUrlSafe(state: string, codeChallenge: string) {
    const ALLOWED_REDIRECT_URIS = ['https://app.example.com/callback'];
    return `https://idp.example.com/oauth/authorize?response_type=code&client_id=app1&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
}
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_http_crlf_host_vuln",
            family: "SMUGGLE",
            expected_prefix: "SMG-HTTP-SMUGGLE",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/routes/reset_vuln.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/reset', requireAuth, (req, res) => {
    res.setHeader('Location', req.query.next);
    return `https://${req.headers['x-forwarded-host']}/reset?token=abc`;
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_http_crlf_host_safe",
            family: "SMUGGLE",
            expected_prefix: "SMG-HTTP-SMUGGLE",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/routes/reset_safe.ts",
                lang: Language::TypeScript,
                code: r#"
app.post('/reset-safe', requireAuth, (req, res) => {
    const next = encodeURIComponent(String(req.query.next || ''));
    res.setHeader('Location', next);
    return `${process.env.APP_URL}/reset?token=abc`;
});
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_workflow_state_skip_vuln",
            family: "STATE",
            expected_prefix: "SMG-STATE",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/orders/ship_vuln.ts",
                lang: Language::TypeScript,
                code: r#"
export async function shipOrder(req, db) {
    await db.query("UPDATE orders SET status = 'SHIPPED' WHERE id = $1", [req.params.id]);
}
"#,
            }],
        },
        AdversarialCase {
            id: "wave3_workflow_state_guarded_safe",
            family: "STATE",
            expected_prefix: "SMG-STATE",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "src/orders/ship_safe.ts",
                lang: Language::TypeScript,
                code: r#"
export async function shipOrderSafe(req, db) {
    const order = await db.findOne(req.params.id);
    if (order.status !== 'PAID') throw new Error('Order not paid');
    await db.query("UPDATE orders SET status = 'SHIPPED' WHERE id = $1 AND status = 'PAID'", [req.params.id]);
}
"#,
            }],
        },
        // -----------------------------------------------------------------
        // 15. Real-World CI-Green Regression & Deep Rule Pack Matrix
        // -----------------------------------------------------------------
        AdversarialCase {
            id: "rw_sec_public_pem_cert_safe",
            family: "SEC",
            expected_prefix: "SMG-SEC",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![
                BenchFile {
                    rel_path: ".gitignore",
                    lang: Language::Config,
                    code: ".env\n",
                },
                BenchFile {
                    rel_path: "certs/ca-bundle-prod.pem",
                    lang: Language::Config,
                    code: concat!(
                        "-----BEGIN ",
                        "CERTIFICATE-----\n",
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n",
                        "-----END ",
                        "CERTIFICATE-----\n"
                    ),
                },
            ],
        },
        AdversarialCase {
            id: "rw_sec_sops_encrypted_safe",
            family: "SEC",
            expected_prefix: "SMG-SEC",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "deploy/secrets.enc.yaml",
                lang: Language::Config,
                code: concat!(
                    "db_dsn: ENC[AES256_GCM,data:aBcDeFgHiJkLmNoPqRsTuVwXyZ012345,iv:AbCdEf,tag:GhIjKl,type:str]\n",
                    "sops:\n",
                    "    mac: ENC[AES256_GCM,data:1234567890AbCdEfGhIjKlMnOpQrStUv,iv:x,tag:y,type:str]\n"
                ),
            }],
        },
        AdversarialCase {
            id: "rw_sec_ci_throwaway_dsn_safe",
            family: "SEC",
            expected_prefix: "SMG-SEC",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: ".github/workflows/ci.yml",
                lang: Language::Config,
                code: concat!(
                    "jobs:\n  test:\n    env:\n",
                    "      DATABASE_URL: ",
                    "postgres://postgres:ci-pass@localhost:5432/testdb\n"
                ),
            }],
        },
        AdversarialCase {
            id: "rw_sec_provider_token_pack_vuln",
            family: "SEC",
            expected_prefix: "SMG-SEC",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "src/config/tokens.ts",
                lang: Language::TypeScript,
                code: concat!(
                    "export const GL = '",
                    "glpat-",
                    "9xKmPq2RtYv8ZwNc3VbH7dFj';\n",
                    "export const HF = '",
                    "hf_",
                    "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf';\n"
                ),
            }],
        },
        AdversarialCase {
            id: "rw_crypto_empty_digest_safe",
            family: "CRYPTO",
            expected_prefix: "SMG-CRYPTO",
            expect_finding: false,
            trap_kind: TrapKind::BaselineSafe,
            files: vec![BenchFile {
                rel_path: "internal/auth/digest.go",
                lang: Language::Go,
                code: r#"
package auth
func validateDigest(digest, macAddress string) bool {
    if digest == "" || digest != "" { return false }
    if digest == "sha256" { return true }
    return macAddress != "00:00:00:00:00:00"
}
"#,
            }],
        },
        AdversarialCase {
            id: "rw_sqli_go_const_placeholder_builder_safe",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "internal/store/items.go",
                lang: Language::Go,
                code: r#"
package store
import (
    "context"
    "database/sql"
    "fmt"
    "strconv"
    "strings"
)
const baseSelect = "SELECT id, name FROM items WHERE org_id = $1"
var sortColumns = map[string]string{
    "name": "name",
    "created": "created_at",
}
func ListItems(ctx context.Context, db *sql.DB, orgID, status, sortKey string, ids []string) (*sql.Rows, error) {
    query := baseSelect
    args := []any{orgID}
    if status != "" {
        args = append(args, status)
        query += fmt.Sprintf(" AND status = $%d", len(args))
    }
    if len(ids) > 0 {
        placeholders := make([]string, 0, len(ids))
        for _, id := range ids {
            args = append(args, id)
            placeholders = append(placeholders, "$"+strconv.Itoa(len(args)))
        }
        query += " AND id IN (" + strings.Join(placeholders, ", ") + ")"
    }
    if col, ok := sortColumns[sortKey]; ok {
        query += " ORDER BY " + col + " DESC"
    }
    return db.QueryContext(ctx, query, args...)
}
"#,
            }],
        },
        AdversarialCase {
            id: "rw_sqli_go_dynamic_fmt_sprintf_vuln",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "internal/store/items_vuln.go",
                lang: Language::Go,
                code: r#"
package store
import (
    "context"
    "database/sql"
    "fmt"
    "net/http"
)
const baseQuery = "SELECT id, name FROM items WHERE org_id = $1"
func SearchItems(ctx context.Context, db *sql.DB, r *http.Request) (*sql.Rows, error) {
    name := r.URL.Query().Get("name")
    q := baseQuery + fmt.Sprintf(" AND name = '%s'", name)
    return db.QueryContext(ctx, q)
}
"#,
            }],
        },
        AdversarialCase {
            id: "rw_auth_go_nested_require_session_safe",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: false,
            trap_kind: TrapKind::OneHopWrapperTrap,
            files: vec![BenchFile {
                rel_path: "internal/api/server.go",
                lang: Language::Go,
                code: r#"
package api
import "net/http"
func customGate(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        sess, ok := loadSess(r)
        if !ok || sess == nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
func Register(mux *http.ServeMux) {
    mux.HandleFunc("POST /api/v1/billing/charge", withTrace(customGate(handleCharge)))
}
func handleCharge(w http.ResponseWriter, r *http.Request) {
    stripe.charges.Create(100)
}
"#,
            }],
        },
        AdversarialCase {
            id: "rw_auth_go_unguarded_handle_vuln",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "internal/api/server_vuln.go",
                lang: Language::Go,
                code: r#"
package api
import "net/http"
func RegisterVuln(mux *http.ServeMux) {
    mux.HandleFunc("POST /api/v1/billing/charge", handleChargeVuln)
}
func handleChargeVuln(w http.ResponseWriter, r *http.Request) {
    stripe.charges.Create(100)
}
"#,
            }],
        },
        AdversarialCase {
            id: "rw_fe404_go_scoped_route_and_122_parity_safe",
            family: "FE",
            expected_prefix: "SMG-FE-404",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![
                BenchFile {
                    rel_path: "internal/api/router.go",
                    lang: Language::Go,
                    code: r#"
package api
import "net/http"
func Mount(r chi.Router, mux *http.ServeMux) {
    r.Route("/api/v1", func(r chi.Router) {
        r.Use(RequireSession)
        r.Post("/orders", createOrder)
    })
    mux.HandleFunc("GET /api/v1/items/{id}", RequireSession(getItem))
}
"#,
                },
                BenchFile {
                    rel_path: "web/src/client.tsx",
                    lang: Language::TypeScript,
                    code: r#"
export async function syncData(id: string) {
    try {
        await fetch('/api/v1/orders', { method: 'POST' });
        await fetch('/api/v1/items/' + id);
    } catch (err) {
        reportError(err);
    }
}
"#,
                },
            ],
        },
        AdversarialCase {
            id: "rw_pack_python_yaml_unsafe_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "app/config_loader.py",
                lang: Language::Python,
                code: "import yaml\ndef parse_cfg(raw: str):\n    return yaml.load(raw, Loader=yaml.Loader)\n",
            }],
        },
        AdversarialCase {
            id: "rw_pack_go_weak_tls10_vuln",
            family: "CFG",
            expected_prefix: "SMG-CFG-TLS",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "pkg/net/tls.go",
                lang: Language::Go,
                code: "package netpkg\nfunc insecureTLS() any {\n    return &tls.Config{MinVersion: tls.VersionTLS10}\n}\n",
            }],
        },
        // ------------------------------------------------------------------
        // Phase 2: Multi-Domain Maximum Depth & Adversarial FP Regression Pack
        // ------------------------------------------------------------------
        AdversarialCase {
            id: "phase2_pg_positional_bind_arithmetic_safe",
            family: "SQLI",
            expected_prefix: "SMG-SQLI",
            expect_finding: false,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "src/repo/orders.ts",
                lang: Language::TypeScript,
                code: "export async function pageOrders(db: any, orgId: string, limit: number, skip: number) {\n  return db.query('SELECT id FROM orders WHERE org_id = $1 AND rank > $2', [orgId, limit + skip]);\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_dart_request_read_as_string_safe",
            family: "PATH",
            expected_prefix: "SMG-PATH",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![BenchFile {
                rel_path: "lib/handlers/webhook.dart",
                lang: Language::Dart,
                code: "Future<Response> handleHook(Request request) async {\n  final body = await request.readAsString();\n  return Response.ok('received:' + body.length.toString());\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_ml_torch_load_unsafe_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "ml/infer.py",
                lang: Language::Python,
                code: "import torch\ndef load_model(p: str):\n    return torch.load(p)\n",
            }],
        },
        AdversarialCase {
            id: "phase2_ml_torch_load_weights_only_safe",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: false,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "ml/safe_infer.py",
                lang: Language::Python,
                code: "import torch\ndef load_model(p: str):\n    return torch.load(p, weights_only=True)\n",
            }],
        },
        AdversarialCase {
            id: "phase2_hf_trust_remote_code_vuln",
            family: "AI",
            expected_prefix: "SMG-AI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "ml/tokenizer.py",
                lang: Language::Python,
                code: "def load_hf():\n    return AutoModel.from_pretrained('org/model', trust_remote_code=True)\n",
            }],
        },
        AdversarialCase {
            id: "phase2_electron_node_integration_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "electron/main.ts",
                lang: Language::TypeScript,
                code: "export function createWindow() {\n  return new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_nextjs_allow_svg_vuln",
            family: "XSS",
            expected_prefix: "SMG-XSS",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "next.config.ts",
                lang: Language::TypeScript,
                code: "export default { images: { dangerouslyAllowSVG: true } };\n",
            }],
        },
        AdversarialCase {
            id: "phase2_csharp_json_typename_all_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "Services/Serializer.cs",
                lang: Language::CSharp,
                code: "public class Serializer {\n  public JsonSerializerSettings Opts() => new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_terraform_imdsv1_optional_vuln",
            family: "CFG",
            expected_prefix: "SMG-CFG-IAC",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "infra/ec2.tf",
                lang: Language::Hcl,
                code: "resource \"aws_instance\" \"app\" {\n  metadata_options {\n    http_tokens = \"optional\"\n  }\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_iam_nested_condition_deny_safe",
            family: "CFG",
            expected_prefix: "SMG-CFG",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![BenchFile {
                rel_path: "infra/policy.tf",
                lang: Language::Hcl,
                code: "resource \"aws_iam_policy\" \"guard\" {\n  policy = jsonencode({\n    Statement = [{\n      Effect = \"Deny\",\n      Action = \"*\",\n      Resource = \"*\",\n      Condition = { Bool = { \"aws:SecureTransport\" = \"false\" } }\n    }]\n  })\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_c_malloc_sizeof_safe",
            family: "MEM",
            expected_prefix: "SMG-MEM",
            expect_finding: false,
            trap_kind: TrapKind::CheckedBoundsTrap,
            files: vec![BenchFile {
                rel_path: "native/alloc.c",
                lang: Language::C,
                code: "#include <stdlib.h>\nint *alloc_ints(void) {\n    int *p = (int *)malloc(sizeof(int) * 4);\n    return p;\n}\n",
            }],
        },
        AdversarialCase {
            id: "phase2_stream_read_not_mutex_safe",
            family: "RACE",
            expected_prefix: "SMG-RACE",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![BenchFile {
                rel_path: "app/stream.py",
                lang: Language::Python,
                code: "def load_cfg(fp):\n    data = fp.read()\n    return len(data)\n",
            }],
        },
        AdversarialCase {
            id: "phase2_bash_heredoc_body_safe",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: false,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![BenchFile {
                rel_path: "scripts/gen.sh",
                lang: Language::Bash,
                code: "#!/usr/bin/env bash\ncat << 'EOF' > /tmp/note.txt\neval \"$1\"\nEOF\n",
            }],
        },
        AdversarialCase {
            id: "phase2_bash_github_env_injection_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::BaselineVuln,
            files: vec![BenchFile {
                rel_path: "scripts/ci.sh",
                lang: Language::Bash,
                code: "#!/usr/bin/env bash\necho \"PR_TITLE=$1\" >> $GITHUB_ENV\n",
            }],
        },
        // ------------------------------------------------------------------
        // Phase 11 (Sprint 1): CFG Else-Abort, Closure Isolation, Multi-Hop Alias & Switch Join
        // ------------------------------------------------------------------
        AdversarialCase {
            id: "sprint1_inverted_if_else_abort_auth_safe",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: false,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/pay_else_abort.ts",
                lang: Language::TypeScript,
                code: "function doCharge(req: any) { balance -= req.body.amount; }\napp.post('/api/pay-inv', (req, res) => {\n  if (verifyJwt(req)) {\n    doCharge(req);\n  } else {\n    return res.status(401).end();\n  }\n});\n",
            }],
        },
        AdversarialCase {
            id: "sprint1_uninvoked_closure_auth_leak_vuln",
            family: "AUTH",
            expected_prefix: "SMG-AUTH",
            expect_finding: true,
            trap_kind: TrapKind::ScopeCollisionTrap,
            files: vec![BenchFile {
                rel_path: "src/pay_uninvoked_closure.ts",
                lang: Language::TypeScript,
                code: "app.post('/api/pay-closure', (req, res) => {\n  const deadGuard = () => { requireAuth(req); return res.status(401).end(); };\n  balance -= req.body.amount;\n});\n",
            }],
        },
        AdversarialCase {
            id: "sprint1_multihop_object_alias_cmdi_vuln",
            family: "CMDI",
            expected_prefix: "SMG-CMDI",
            expect_finding: true,
            trap_kind: TrapKind::OneHopWrapperTrap,
            files: vec![BenchFile {
                rel_path: "src/alias_cmd.ts",
                lang: Language::TypeScript,
                code: "import child_process from 'child_process';\napp.post('/api/alias-exec', (req, res) => {\n  const ctx: any = { cmd: 'echo safe' };\n  const a = ctx;\n  const b = a;\n  b.cmd = req.body.userCmd;\n  child_process.execSync(ctx.cmd);\n});\n",
            }],
        },
        AdversarialCase {
            id: "sprint1_switch_sibling_arm_sanitizer_leak_vuln",
            family: "PATH",
            expected_prefix: "SMG-PATH",
            expect_finding: true,
            trap_kind: TrapKind::DominatorGuardTrap,
            files: vec![BenchFile {
                rel_path: "src/switch_path.ts",
                lang: Language::TypeScript,
                code: "import fs from 'fs';\nimport path from 'path';\napp.get('/api/switch-file', (req, res) => {\n  let p = req.query.file;\n  switch (req.query.mode) {\n    case 'safe':\n      p = path.basename(p);\n      break;\n    case 'raw':\n      fs.readFileSync(p);\n      break;\n  }\n});\n",
            }],
        },
    ]
}

fn run_synthetic_scale_repo(num_modules: usize) -> Vec<f64> {
    let mut files = Vec::with_capacity(num_modules);
    for i in 0..num_modules {
        let code = format!(
            r#"
import express from 'express';
const app{i} = express();
export function helper{i}(v: string) {{
    return v.trim();
}}
app{i}.get('/api/items/{i}/:id', requireAuth, async (req, res) => {{
    const row = await db.query('SELECT id, name FROM items WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json(row);
}});
"#
        );
        let bytes = code.into_bytes();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        files.push(IndexedFile {
            rel_path: format!("src/mod_{i}.ts"),
            abs_path: PathBuf::from(format!("src/mod_{i}.ts")),
            language: Language::TypeScript,
            blake3_hash: hash,
            mtime_ns: 0,
            size_bytes: bytes.len() as u64,
            cached_bytes: Some(bytes),
        });
    }

    let cfg = ShellMindGuardConfig::default();
    let mut samples_ms = Vec::with_capacity(10);
    for _ in 0..10 {
        let t0 = Instant::now();
        let res = analyze_codebase(&files, &cfg).expect("scale analyze_codebase should not fail");
        assert!(res.parsed_files >= num_modules);
        samples_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples_ms
}

#[test]
fn test_adversarial_precision_recall_and_latency_benchmark() {
    let cfg = ShellMindGuardConfig::default();
    let cases = corpus();

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut fn_count = 0usize;
    let mut per_case_ms = Vec::with_capacity(cases.len());
    let mut misses: Vec<String> = Vec::new();
    let mut by_family: BTreeMap<&'static str, (usize, usize, usize, usize)> = BTreeMap::new();

    for case in &cases {
        let indexed = build_indexed(&case.files);
        let t0 = Instant::now();
        let res = analyze_codebase(&indexed, &cfg).expect("analyze_codebase must not panic");
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        per_case_ms.push(elapsed_ms);

        let hit = matches_prefix(&res, case.expected_prefix);
        let entry = by_family.entry(case.family).or_insert((0, 0, 0, 0));

        match (case.expect_finding, hit) {
            (true, true) => {
                tp += 1;
                entry.0 += 1;
            }
            (false, true) => {
                fp += 1;
                entry.1 += 1;
                misses.push(format!(
                    "FP [{}] ({:?}) emitted {:?}",
                    case.id,
                    case.trap_kind,
                    res.findings
                        .iter()
                        .map(|f| format!("{}:{}", f.rule_id, f.file))
                        .collect::<Vec<_>>()
                ));
            }
            (false, false) => {
                tn += 1;
                entry.2 += 1;
            }
            (true, false) => {
                fn_count += 1;
                entry.3 += 1;
                misses.push(format!(
                    "FN [{}] ({:?}) missed prefix {} (emitted {:?})",
                    case.id,
                    case.trap_kind,
                    case.expected_prefix,
                    res.findings
                        .iter()
                        .map(|f| f.rule_id.as_str())
                        .collect::<Vec<_>>()
                ));
            }
        }
    }

    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_count == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_count) as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    per_case_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let case_p99 = per_case_ms[((per_case_ms.len() * 99) / 100).min(per_case_ms.len() - 1)];

    let scale_samples = run_synthetic_scale_repo(120);
    let scale_p50 = scale_samples[scale_samples.len() / 2];
    let scale_p99 = scale_samples[scale_samples.len() - 1];

    eprintln!(
        "\n=== SMG Adversarial Benchmark Summary ===\n\
         Cases={} | TP={} FP={} TN={} FN={}\n\
         Precision={:.2}% | Recall={:.2}% | F1={:.2}%\n\
         Micro-Case P99={:.2}ms | 120-Module Repo P50={:.2}ms P99={:.2}ms",
        cases.len(),
        tp,
        fp,
        tn,
        fn_count,
        precision * 100.0,
        recall * 100.0,
        f1 * 100.0,
        case_p99,
        scale_p50,
        scale_p99
    );
    for (fam, (ftp, ffp, ftn, ffn)) in &by_family {
        eprintln!("  [{fam}] TP={ftp} FP={ffp} TN={ftn} FN={ffn}");
    }
    for m in &misses {
        eprintln!("  MISS: {m}");
    }

    // Permanent precision, recall, and latency non-regression gates:
    let strict_gate = std::env::var("SMG_ENFORCE_PRECISION_GATE")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if strict_gate {
        assert_eq!(
            fp, 0,
            "SMG_ENFORCE_PRECISION_GATE=1 requires 0 false positives! Misses: {:?}",
            misses
        );
        assert_eq!(
            fn_count, 0,
            "SMG_ENFORCE_PRECISION_GATE=1 requires 0 false negatives! Misses: {:?}",
            misses
        );
    }
    assert!(scale_p99.is_finite() && scale_p99 > 0.0);
    assert!(
        tp >= 20,
        "core precision benchmark suffered recall drop (tp={tp})"
    );
    assert!(
        precision >= 0.98,
        "precision {:.2}% < 98.00% target! Misses: {:?}",
        precision * 100.0,
        misses
    );
    assert!(
        recall >= 0.95,
        "recall {:.2}% < 95.00% target! Misses: {:?}",
        recall * 100.0,
        misses
    );
    assert!(
        scale_p99 < 2000.0,
        "120-module P99 {:.2}ms >= 2000ms budget",
        scale_p99
    );
}

#[test]
fn test_realworld_ci_green_zero_confirmed_fps() {
    let files = build_indexed(&[
        BenchFile {
            rel_path: ".gitignore",
            lang: Language::Config,
            code: ".env\ndist/\n",
        },
        BenchFile {
            rel_path: ".github/workflows/ci.yml",
            lang: Language::Config,
            code: concat!(
                "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env:\n",
                "      DATABASE_URL: postgres://postgres:ci-pass@localhost:5432/ci\n"
            ),
        },
        BenchFile {
            rel_path: "certs/public-root.pem",
            lang: Language::Config,
            code: concat!(
                "-----BEGIN ",
                "CERTIFICATE-----\n",
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n",
                "-----END ",
                "CERTIFICATE-----\n"
            ),
        },
        BenchFile {
            rel_path: "deploy/secrets.enc.yaml",
            lang: Language::Config,
            code: concat!(
                "api_key: ENC[AES256_GCM,data:xK9mZp4qR2wL8vN1tY5bC7dF0hJ3nQ==,iv:AbCdEf,tag:GhIjKl,type:str]\n",
                "sops:\n",
                "    mac: ENC[AES256_GCM,data:AbCdEfGhIjKlMnOpQrStUvWxYz012345,iv:x,tag:y,type:str]\n"
            ),
        },
        BenchFile {
            rel_path: "internal/store/orders.go",
            lang: Language::Go,
            code: r#"
package store
import (
    "context"
    "database/sql"
    "fmt"
    "strconv"
    "strings"
)
const orderSelectSQL = "SELECT id, status FROM orders WHERE org_id = $1"
var orderSortMap = map[string]string{"created": "created_at", "total": "total_cents"}
func QueryOrders(ctx context.Context, db *sql.DB, orgID, status, sortKey string, ids []string) (*sql.Rows, error) {
    q := orderSelectSQL
    args := []any{orgID}
    if status != "" {
        args = append(args, status)
        q += fmt.Sprintf(" AND status = $%d", len(args))
    }
    if len(ids) > 0 {
        ph := make([]string, 0, len(ids))
        for _, id := range ids {
            args = append(args, id)
            ph = append(ph, "$"+strconv.Itoa(len(args)))
        }
        q += " AND id IN (" + strings.Join(ph, ", ") + ")"
    }
    if col, ok := orderSortMap[sortKey]; ok {
        q += " ORDER BY " + col + " DESC"
    }
    return db.QueryContext(ctx, q, args...)
}
"#,
        },
        BenchFile {
            rel_path: "internal/http/routes.go",
            lang: Language::Go,
            code: r#"
package httpapi
import "net/http"
func RequireSession(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-Session") == "" {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
func verifySig(digest string) bool {
    if digest == "" { return false }
    return true
}
func Mount(r chi.Router, mux *http.ServeMux) {
    r.Route("/api/v1", func(r chi.Router) {
        r.Use(RequireSession)
        r.Post("/orders", handleCreateOrder)
    })
    mux.HandleFunc("GET /api/v1/orders/{id}", RequireSession(handleGetOrder))
}
func handleCreateOrder(w http.ResponseWriter, r *http.Request) {
    tx.Exec("INSERT INTO orders (id) VALUES ($1)", "ok")
}
func handleGetOrder(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(200)
}
"#,
        },
        BenchFile {
            rel_path: "web/src/orders.tsx",
            lang: Language::TypeScript,
            code: r#"
export async function fetchOrders(id: string) {
    try {
        await fetch('/api/v1/orders', { method: 'POST' });
        await fetch('/api/v1/orders/' + id);
    } catch (err) {
        reportError(err);
    }
}
"#,
        },
    ]);

    let cfg = ShellMindGuardConfig::default();
    let res = analyze_codebase(&files, &cfg).expect("CI-green integration scan must succeed");
    let confirmed: Vec<_> = res
        .findings
        .iter()
        .filter(|f| matches!(f.confidence, Confidence::Confirmed | Confidence::Proven))
        .collect();
    assert!(
        confirmed.is_empty(),
        "CI-green repo must produce 0 CONFIRMED/PROVEN false positives, got: {:?}",
        confirmed
            .iter()
            .map(|f| (&f.rule_id, &f.title, &f.file, f.line, &f.entry_route))
            .collect::<Vec<_>>()
    );
    assert!(
        res.findings.iter().all(|f| f.rule_id != "SMG-FE-404"),
        "All frontend calls match Go routes; expected 0 SMG-FE-404 findings, got: {:?}",
        res.findings
    );
}
