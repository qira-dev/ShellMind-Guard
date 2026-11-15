use crate::ast::{FileAstSummary, parse_file_ast};
use crate::lattice::{GraphAnalysisResult, solve_guard_lattice};
use sh_core::{IndexedFile, Language, ShellMindGuardConfig, scan_repository};
use std::path::PathBuf;

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
fn test_phase8_ruby_rails_and_sinatra_vulnerable_vs_safe() {
    let vuln = analyze_inline(&[
        (
            "config/routes.rb",
            r#"Rails.application.routes.draw do
  post '/transfer', to: 'orders#transfer'
  get '/search', to: 'orders#search'
end
"#,
        ),
        (
            "app/controllers/orders_controller.rb",
            r#"require_relative '../services/ledger_service'

class OrdersController < ApplicationController
  def transfer
    LedgerService.new.debit(params[:id])
    render json: { ok: true }
  end

  def search
    q = params[:q]
    @users = User.where("name = #{q}")
    system("echo #{q}")
    render json: @users
  end
end
"#,
        ),
        (
            "app/services/ledger_service.rb",
            r#"class LedgerService
  def debit(account_id)
    acct = Account.find(account_id)
    balance = acct.balance - 10
    acct.update!(balance: balance)
  end
end
"#,
        ),
        (
            "app/sinatra_admin.rb",
            r#"require 'sinatra'

post '/admin/exec' do
  cmd = params[:cmd]
  system("ls #{cmd}")
end
"#,
        ),
    ]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-AUTH-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-RACE-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-CMDI-001"), "got {:?}", rules);

    let safe = analyze_inline(&[
        (
            "config/routes.rb",
            r#"Rails.application.routes.draw do
  post '/safe_transfer', to: 'safe_orders#transfer'
end
"#,
        ),
        (
            "app/controllers/safe_orders_controller.rb",
            r#"class SafeOrdersController < ApplicationController
  before_action :authenticate_user!
  protect_from_forgery with: :exception

  def transfer
    id = params[:id].to_i
    ActiveRecord::Base.transaction do
      rows = User.where("id = ?", id)
      safe_arg = Shellwords.escape(params[:tag].to_s)
      system("git tag #{safe_arg}")
      render json: rows
    end
  end
end
"#,
        ),
    ]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on guarded/parameterized Rails route, got: {:#?}",
        safe.findings
    );
}

#[test]
fn test_phase8_bash_vulnerable_cross_file_vs_safe_and_install_sh() {
    let vuln = analyze_inline(&[
        (
            "scripts/lib.sh",
            r#"#!/usr/bin/env bash
run_cmd() {
    local c="$1"
    eval "$c"
}

run_sql() {
    psql -c "SELECT * FROM users WHERE id = '$1'"
}
"#,
        ),
        (
            "scripts/deploy.sh",
            r#"#!/usr/bin/env bash
source ./lib.sh

target="$QUERY_STRING"
run_cmd "$target"
run_sql "$target"
curl -sL "https://get.example.com/install.sh" | bash
curl -s "$target"
rm -rf "$target"
"#,
        ),
    ]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-CMDI-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SQLI-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-SSRF-001"), "got {:?}", rules);
    assert!(rules.contains(&"VF-PATH-001"), "got {:?}", rules);

    let safe = analyze_inline(&[(
        "scripts/safe.sh",
        r#"#!/usr/bin/env bash
set -euo pipefail
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

user_id="$USER_INPUT"
if [[ "$user_id" =~ ^[0-9]+$ ]]; then
  psql -v uid="$user_id" -c "SELECT * FROM users WHERE id = :'uid'"
fi
run_cmd "git status"
base_url="https://github.com/qira-dev/ShellMind-Guard/releases/download/v0.1.0"
curl -fsSL "${base_url}/shellmind-guard-linux-x86_64.tar.gz" -o "${work_dir}/app.tar.gz"
"#,
    )]);
    assert!(
        safe.findings.is_empty(),
        "expected 0 findings on safe bash script, got: {:#?}",
        safe.findings
    );

    let real_install = analyze_inline(&[("install.sh", include_str!("../../../../install.sh"))]);
    assert!(
        real_install.findings.is_empty(),
        "expected 0 false positives on real install.sh, got: {:#?}",
        real_install.findings
    );
}

#[test]
fn test_phase8_terraform_hcl_iac_vulnerable_vs_hardened() {
    let vuln = analyze_inline(&[
        (
            "infra/modules/vpc/main.tf",
            r#"resource "aws_security_group" "ssh_world" {
  name = "allow_ssh_all"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#,
        ),
        (
            "infra/main.tf",
            r#"module "vpc" {
  source = "./modules/vpc"
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = "prod-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = "prod-assets"
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "main" {
  identifier          = "prod-db"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_lb_listener" "tls" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}

resource "aws_iam_policy" "admin" {
  name   = "overprivileged"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
"#,
        ),
    ]);
    let rules: Vec<&str> = vuln.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.contains(&"VF-CFG-IAC-PUBLIC"), "got {:?}", rules);
    assert!(rules.contains(&"VF-CFG-IAC-NET"), "got {:?}", rules);
    assert!(rules.contains(&"VF-CFG-IAC-CRYPTO"), "got {:?}", rules);
    assert!(rules.contains(&"VF-CFG-IAC-IAM"), "got {:?}", rules);

    let hardened = analyze_inline(&[(
        "infra/hardened.tf",
        r#"resource "aws_s3_bucket_acl" "assets" {
  bucket = "prod-assets"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = "prod-assets"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "alb_https" {
  name = "allow_https_world"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "prod-db"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_lb_listener" "tls" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

data "aws_iam_policy_document" "readonly_s3" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::prod-assets/*"]
  }
}
"#,
    )]);
    assert!(
        hardened.findings.is_empty(),
        "expected 0 findings on hardened Terraform config, got: {:#?}",
        hardened.findings
    );
}

#[test]
fn test_phase8_scanner_discovers_11_extension_languages_and_ignores_test_files() {
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
        ("src/app.rb", Language::Ruby),
        ("src/deploy.sh", Language::Bash),
        ("src/main.tf", Language::Hcl),
    ];
    for (rel, _) in &prod_files {
        std::fs::write(dir.join(rel), "# phase8 extension source\n").unwrap();
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
        "src/orders_spec.rb",
        "src/ledger_test.rb",
        "src/deploy_test.sh",
        "src/deploy.bats",
        "__tests__/smoke.java",
    ];
    for rel in &test_files {
        std::fs::write(dir.join(rel), "# should be filtered\n").unwrap();
    }

    let summary = scan_repository(&dir, &ShellMindGuardConfig::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        summary.files.len(),
        prod_files.len(),
        "expected exact 11 extension source files and all test files skipped, got: {:?}",
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
