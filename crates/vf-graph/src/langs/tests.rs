use crate::ast::{FileAstSummary, parse_file_ast};
use crate::lattice::{GraphAnalysisResult, solve_guard_lattice};
use std::path::PathBuf;
use vf_core::{IndexedFile, Language, ShellMindGuardConfig, scan_repository};

fn analyze_inline(files: &[(&str, &str)]) -> GraphAnalysisResult {
    let cfg = ShellMindGuardConfig::default();
    let summaries: Vec<FileAstSummary> = files
        .iter()
        .map(|(rel_path, code)| {
            let lang = Language::from_path(std::path::Path::new(rel_path))
                .unwrap_or_else(|| panic!("unsupported test file extension: {}", rel_path));
            let indexed = IndexedFile {
                rel_path: (*rel_path).to_string(),
                abs_path: PathBuf::from(rel_path),
                language: lang,
                blake3_hash: String::new(),
                mtime_ns: 0,
                size_bytes: code.len() as u64,
                cached_bytes: Some(code.as_bytes().to_vec()),
            };
            parse_file_ast(&indexed, &cfg)
                .unwrap_or_else(|| panic!("failed to parse AST for {}", rel_path))
        })
        .collect();
    solve_guard_lattice(&summaries)
}

#[test]
fn test_phase8_php_laravel_vulnerable_vs_guarded() {
    // Vulnerable: unguarded route -> cross-file service debit (race) + direct SQLi / CMDi / XSS
    let vuln = analyze_inline(&[
        (
            "routes/api.php",
            r#"<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PayController;

Route::post('/pay', [PayController::class, 'withdraw']);
"#,
        ),
        (
            "app/Http/Controllers/PayController.php",
            r#"<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\Services\LedgerService;

class PayController {
    public function withdraw(Request $request) {
        $id = $request->input('id');
        $cmd = $request->input('cmd');
        $service = new LedgerService();
        $service->debitBalance($id);
        DB::select("SELECT * FROM users WHERE id = '$id'");
        shell_exec($cmd);
        echo $request->input('q');
    }
}
"#,
        ),
        (
            "app/Services/LedgerService.php",
            r#"<?php
namespace App\Services;
use Illuminate\Support\Facades\DB;

class LedgerService {
    public function debitBalance($id) {
        DB::update("UPDATE accounts SET balance = balance - 10 WHERE id = ?", [$id]);
    }
}
"#,
        ),
    ]);

    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"VF-AUTH-001"),
        "expected PHP VF-AUTH-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-RACE-001"),
        "expected cross-file PHP VF-RACE-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-SQLI-001"),
        "expected PHP VF-SQLI-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-CMDI-001"),
        "expected PHP VF-CMDI-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-XSS-001"),
        "expected PHP VF-XSS-001, got: {:?}",
        rules
    );

    // Safe: auth middleware + DB::transaction + prepared PDO statement + escapeshellarg + htmlspecialchars + Bearer
    let safe = analyze_inline(&[
        (
            "routes/api.php",
            r#"<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SafePayController;

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/pay', [SafePayController::class, 'withdraw']);
});
"#,
        ),
        (
            "app/Http/Controllers/SafePayController.php",
            r#"<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SafePayController {
    public function withdraw(Request $request) {
        $authHeader = $request->header('Authorization');
        $id = $request->input('id');
        DB::transaction(function () use ($id) {
            $stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, auth()->id()]);
            DB::update('UPDATE accounts SET balance = balance - 10 WHERE id = ?', [$id]);
        });
        $safeCmd = escapeshellarg($request->input('tag'));
        echo htmlspecialchars($request->input('q'));
    }
}
"#,
        ),
    ]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on guarded/sanitized PHP, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_java_spring_cross_file_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[
        (
            "src/main/java/com/example/web/PayController.java",
            r#"package com.example.web;
import com.example.service.LedgerService;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
public class PayController {
    private final LedgerService ledger;

    @PostMapping("/orders/{id}/refund")
    public void refundOrder(@PathVariable String id, HttpServletRequest request) {
        String note = request.getParameter("note");
        ledger.debitWallet(id, note);
    }
}
"#,
        ),
        (
            "src/main/java/com/example/service/LedgerService.java",
            r#"package com.example.service;
import java.sql.Statement;

public class LedgerService {
    public void debitWallet(String id, String note) {
        statement.executeQuery("SELECT * FROM wallets WHERE id = '" + id + "'");
        repo.save(wallet);
    }
}
"#,
        ),
    ]);

    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"VF-AUTH-001"),
        "expected Java VF-AUTH-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-RACE-001"),
        "expected Java cross-file VF-RACE-001, got: {:?}",
        rules
    );
    assert!(
        rules.contains(&"VF-SQLI-001"),
        "expected Java cross-file VF-SQLI-001, got: {:?}",
        rules
    );

    let safe = analyze_inline(&[(
        "src/main/java/com/example/web/SafeOrderController.java",
        r#"package com.example.web;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import java.security.Principal;
import java.sql.PreparedStatement;

@RestController
@RequestMapping("/api")
public class SafeOrderController {
    @PreAuthorize("isAuthenticated()")
    @Transactional
    @PostMapping("/orders/{id}/refund")
    public void refundOrder(@PathVariable String id, Principal principal) {
        String owner = principal.getName();
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM orders WHERE id = ? AND owner_id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on guarded Spring Java controller, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_csharp_aspnet_mvc_and_minimal_api() {
    let vuln = analyze_inline(&[
        (
            "Controllers/OrdersController.cs",
            r#"using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Shop.Controllers {
    [Route("api/[controller]")]
    public class OrdersController : ControllerBase {
        [HttpPost("search")]
        public IActionResult Search(string id) {
            var q = Request.Query["q"];
            var rows = db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Name = '{q}'");
            return Ok(rows);
        }
    }
}
"#,
        ),
        (
            "Program.cs",
            r#"using Microsoft.AspNetCore.Builder;

app.MapPost("/admin/wipe", (HttpRequest req) => {
    var target = req.Query["table"];
    db.Database.ExecuteSqlRaw("DELETE FROM Users");
    return Results.Ok(target);
});

app.MapPost("/pay", (HttpRequest req) => {
    db.SaveChanges();
    return Results.Ok();
}).RequireAuthorization();

app.MapGet("/health", () => Results.Ok("ok")).AllowAnonymous();
"#,
        ),
    ]);

    let auth_routes: Vec<&str> = vuln
        .findings
        .iter()
        .filter(|f| f.rule_id == "VF-AUTH-001")
        .map(|f| f.entry_route.as_str())
        .collect();
    assert!(
        auth_routes.iter().any(|r| r.contains("/admin/wipe")),
        "expected unguarded Minimal API /admin/wipe to trigger VF-AUTH-001, got: {:?}",
        auth_routes
    );
    assert!(
        !auth_routes.iter().any(|r| r.contains("/pay")),
        "did not expect .RequireAuthorization() /pay to trigger VF-AUTH-001, got: {:?}",
        auth_routes
    );
    assert!(
        !auth_routes.iter().any(|r| r.contains("/health")),
        "did not expect .AllowAnonymous() /health to trigger VF-AUTH-001, got: {:?}",
        auth_routes
    );
    assert!(
        vuln.findings.iter().any(|f| f.rule_id == "VF-SQLI-001"),
        "expected C# EF FromSqlRaw SQLi finding, got: {:#?}",
        vuln.findings
    );

    let safe = analyze_inline(&[(
        "Controllers/SafeOrdersController.cs",
        r#"using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers {
    [Authorize]
    [Route("api/[controller]")]
    public class SafeOrdersController : ControllerBase {
        [HttpPost("create")]
        [ValidateAntiForgeryToken]
        public IActionResult Create([FromBody] CreateOrderDto dto) {
            var header = Request.Headers["Authorization"];
            var rows = db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE UserId = {currentUserId}");
            return Ok(rows);
        }
    }
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on authorized C# controller, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_kotlin_ktor_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[(
        "src/Routes.kt",
        r#"package com.example.routes
import io.ktor.server.routing.*

fun Route.paymentRoutes() {
    post("/withdraw") {
        val id = call.parameters["id"]
        stmt.executeQuery("SELECT * FROM accounts WHERE id = '$id'")
        stmt.executeUpdate("UPDATE accounts SET balance = balance - 10 WHERE id = ?")
    }
}
"#,
    )]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-AUTH-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);

    let safe = analyze_inline(&[(
        "src/SafeRoutes.kt",
        r#"package com.example.routes
import io.ktor.server.routing.*
import io.ktor.server.auth.*

fun Route.safeRoutes() {
    authenticate("jwt") {
        post("/withdraw") {
            val id = call.parameters["id"]
            transaction {
                db.rawQuery("SELECT * FROM accounts WHERE id = ?", arrayOf(id))
            }
        }
    }
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on authenticated Kotlin Ktor route, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_swift_vapor_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[(
        "Sources/App/routes.swift",
        r#"import Vapor

func routes(_ app: Application) throws {
    app.post("withdraw") { req async throws -> String in
        let id = try req.query.get(String.self, at: "id")
        let _ = try await sql.raw("SELECT * FROM wallets WHERE id = \(id)").all()
        try await wallet.save(on: req.db)
        return "ok"
    }
}
"#,
    )]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-AUTH-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);

    let safe = analyze_inline(&[(
        "Sources/App/SafeRoutes.swift",
        r#"import Vapor

func safeRoutes(_ app: Application) throws {
    let protected = app.grouped(User.authenticator(), User.guardMiddleware())
    protected.post("withdraw") { req async throws -> String in
        let id = try req.query.get(String.self, at: "id")
        try await req.db.transaction { db in
            let _ = try await db.raw("SELECT * FROM wallets WHERE id = $1", binds: [id]).all()
        }
        return "ok"
    }
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on Vapor guarded route, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_dart_shelf_and_dart_frog_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[
        (
            "routes/users.dart",
            r#"import 'package:dart_frog/dart_frog.dart';

Future<Response> onRequest(RequestContext context) async {
  final id = context.request.uri.queryParameters['id'];
  final rows = await db.rawQuery('SELECT * FROM users WHERE id = $id');
  await db.rawUpdate('UPDATE accounts SET balance = balance - 10 WHERE id = ?', [id]);
  return Response.json(body: rows);
}
"#,
        ),
        (
            "lib/server.dart",
            r#"import 'package:shelf_router/shelf_router.dart';

void registerRoutes(Router router) {
  router.post('/pay', (Request request) async {
    return Response.ok('paid');
  });
}
"#,
        ),
    ]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-AUTH-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);

    let safe = analyze_inline(&[(
        "lib/safe_server.dart",
        r#"import 'package:shelf_router/shelf_router.dart';

Future<List<Map<String, dynamic>>> fetchOrders(Database db, String userId) async {
  return db.rawQuery('SELECT * FROM orders WHERE owner_id = ?', [userId]);
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on parameterized Dart helper, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_c_cpp_cross_file_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[
        (
            "src/ledger.h",
            r#"#pragma once
void debit_balance(const char* user_id);
"#,
        ),
        (
            "src/ledger.cpp",
            r#"#include "ledger.h"
#include <sqlite3.h>
#include <cstdlib>

void debit_balance(const char* user_id) {
    // balance -= 10
    database_update_wallet(user_id);
}
"#,
        ),
        (
            "src/main.cpp",
            r#"#include "ledger.h"
#include <cstdlib>

int handle_debit(const HttpRequest& req) {
    auto cmd = req.get_param_value("cmd");
    system(cmd.c_str());
    debit_balance("u1");
    return 0;
}

void register_routes() {
    CROW_ROUTE(app, "/debit").methods("POST"_method)(handle_debit);
}
"#,
        ),
    ]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-AUTH-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-RACE-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-CMDI-001"), "got {:?}", rules);

    let safe = analyze_inline(&[(
        "src/safe_engine.c",
        r#"#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

int query_user(sqlite3* db, const char* id) {
    sqlite3_stmt* stmt = NULL;
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, NULL);
    system("git status");
    return 0;
}
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on safe native C prepared statement + static command, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_scanner_discovers_8_languages_and_ignores_test_files() {
    let dir = std::env::temp_dir().join(format!("smg_phase8_scanner_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("__tests__")).unwrap();

    let prod_files = [
        ("src/app.php", Language::Php),
        ("src/Main.java", Language::Java),
        ("src/Program.cs", Language::CSharp),
        ("src/App.kt", Language::Kotlin),
        ("src/App.swift", Language::Swift),
        ("src/main.dart", Language::Dart),
        ("src/engine.c", Language::C),
        ("src/server.cpp", Language::Cpp),
    ];
    for (rel, _) in &prod_files {
        std::fs::write(dir.join(rel), "// phase8 source\n").unwrap();
    }

    let test_files = [
        "src/PayControllerTest.php",
        "src/OrderServiceTest.java",
        "src/OrdersControllerTests.cs",
        "src/RoutesTest.kt",
        "src/AuthTests.swift",
        "src/widget_test.dart",
        "src/engine_test.c",
        "src/server_test.cpp",
        "__tests__/smoke.java",
    ];
    for rel in &test_files {
        std::fs::write(dir.join(rel), "// should be filtered\n").unwrap();
    }

    let summary = scan_repository(&dir, &ShellMindGuardConfig::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        summary.files.len(),
        prod_files.len(),
        "expected exact 8 source files and all test files skipped, got: {:?}",
        summary
            .files
            .iter()
            .map(|f| &f.rel_path)
            .collect::<Vec<_>>()
    );
    for (rel, expected_lang) in &prod_files {
        let found = summary
            .files
            .iter()
            .find(|f| f.rel_path == *rel)
            .unwrap_or_else(|| panic!("missing indexed file {}", rel));
        assert_eq!(found.language, *expected_lang);
    }
}
