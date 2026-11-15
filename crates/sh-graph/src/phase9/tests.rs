use crate::ast::parse_file_ast;
use crate::lattice::{GraphAnalysisResult, solve_guard_lattice};
use sh_core::{IndexedFile, Language, ShellMindGuardConfig};
use std::path::PathBuf;

fn run_inline(files: &[(&str, &str)]) -> GraphAnalysisResult {
    let cfg = ShellMindGuardConfig::default();
    let indexed: Vec<IndexedFile> = files
        .iter()
        .filter_map(|(path, content)| {
            let lang = Language::from_path(&PathBuf::from(path))?;
            Some(IndexedFile {
                rel_path: (*path).to_string(),
                abs_path: PathBuf::from(path),
                language: lang,
                blake3_hash: String::new(),
                mtime_ns: 0,
                size_bytes: content.len() as u64,
                cached_bytes: Some(content.as_bytes().to_vec()),
            })
        })
        .collect();
    let summaries: Vec<_> = indexed
        .iter()
        .filter_map(|f| parse_file_ast(f, &cfg))
        .collect();
    solve_guard_lattice(&summaries)
}

#[test]
fn test_phase9_domain_aware_routing_isolates_web_engine_and_mobile() {
    // 1. Pure Kotlin Ktor backend: Web domain active, Mobile domain NOT active -> no VF-MOB-* false positives
    let ktor_backend = r#"
package com.example.server

import io.ktor.server.routing.*
import javax.net.ssl.HttpsURLConnection

fun Route.paymentRoutes() {
    post("/api/pay") {
        processPayment()
    }
}

fun processPayment() {
    val conn = HttpsURLConnection.getDefaultHostnameVerifier()
}
"#;
    let res_web = run_inline(&[("src/Server.kt", ktor_backend)]);
    assert!(
        res_web.active_domains.contains(&"web".to_string()),
        "Expected web domain for Ktor backend: {:?}",
        res_web.active_domains
    );
    assert!(
        !res_web.active_domains.contains(&"mobile".to_string()),
        "Server Ktor app must not activate mobile domain: {:?}",
        res_web.active_domains
    );
    assert!(
        !res_web
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("VF-MOB-")),
        "Mobile rules must stay inactive on pure server codebases: {:?}",
        res_web.findings
    );

    // 2. Pure C++ core engine: system_engine domain active
    let cpp_engine = r#"
#include <mutex>
static std::mutex engine_lock;
void tick_engine() {
    std::lock_guard<std::mutex> g(engine_lock);
}
"#;
    let res_eng = run_inline(&[("core/engine.cpp", cpp_engine)]);
    assert!(
        res_eng
            .active_domains
            .contains(&"system_engine".to_string()),
        "Expected system_engine domain for native C++ code: {:?}",
        res_eng.active_domains
    );
    assert!(res_eng.findings.is_empty());
}

#[test]
fn test_phase9_concurrency_deadlocks_and_resource_leaks() {
    // Cross-function A->B vs B->A deadlock across two C++ engine files + early-return FILE* leak + Rust sync lock across .await
    let eng_a = r#"
#include <mutex>
#include <stdio.h>
#include "eng_b.hpp"

std::mutex account_mutex;

void refresh_account() {
    std::lock_guard<std::mutex> lock(account_mutex);
}

void transfer_step() {
    std::lock_guard<std::mutex> lock(account_mutex);
    update_ledger();
}

int read_config_leaking(const char* path, int strict) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (strict < 0) {
        return -2;
    }
    fclose(fp);
    return 0;
}
"#;

    let eng_b = r#"
#include <mutex>
#include "eng_a.hpp"

std::mutex ledger_mutex;

void update_ledger() {
    std::lock_guard<std::mutex> lock(ledger_mutex);
}

void audit_step() {
    std::lock_guard<std::mutex> lock(ledger_mutex);
    refresh_account();
}
"#;

    let rust_async_deadlock = r#"
use std::sync::Mutex;

async fn hold_across_await(mu: &Mutex<u64>) {
    let guard = mu.lock().unwrap();
    do_async_io(*guard).await;
}
"#;

    let go_leak = r#"
package worker

import "os"

func loadChunk(p string, failFast bool) int {
    f, err := os.Open(p)
    if err != nil {
        return -1
    }
    if failFast {
        return -2
    }
    f.Close()
    return 0
}
"#;

    let res = run_inline(&[
        ("core/eng_a.cpp", eng_a),
        ("core/eng_b.cpp", eng_b),
        ("core/worker.rs", rust_async_deadlock),
        ("core/loader.go", go_leak),
    ]);
    let rules: Vec<&str> = res.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"VF-ENG-DEADLOCK"),
        "Expected VF-ENG-DEADLOCK across C++ ABBA + Rust lock across .await, got: {:?}",
        rules
    );
    assert!(
        res.findings
            .iter()
            .any(|f| f.rule_id == "VF-ENG-DEADLOCK" && f.entry_route.contains("LOCK")),
        "Expected cross-function Lock-Order Inversion finding: {:?}",
        res.findings
    );
    assert_eq!(
        res.findings
            .iter()
            .filter(|f| f.rule_id == "VF-ENG-LEAK")
            .count(),
        2,
        "Expected 2 VF-ENG-LEAK findings (C++ early return + Go missing defer), got: {:?}",
        res.findings
    );

    // Hardened concurrency + RAII/defer + dropped guard before `.await` -> ZERO findings
    let safe_cpp = r#"
#include <mutex>
#include <stdio.h>

std::mutex m1, m2;

void safe_dual_lock() {
    std::scoped_lock lk(m1, m2);
}

int safe_read(const char* path, int strict) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (strict < 0) {
        fclose(fp);
        return -2;
    }
    fclose(fp);
    return 0;
}
"#;

    let safe_rust = r#"
use std::sync::Mutex;

async fn scoped_sync_lock(mu: &Mutex<u64>) {
    let val = {
        let guard = mu.lock().unwrap();
        *guard
    };
    do_async_io(val).await;
}
"#;

    let safe_go = r#"
package worker

import "os"

func loadChunkSafe(p string, failFast bool) int {
    f, err := os.Open(p)
    if err != nil {
        return -1
    }
    defer f.Close()
    if failFast {
        return -2
    }
    return 0
}
"#;

    let clean = run_inline(&[
        ("core/safe.cpp", safe_cpp),
        ("core/safe.rs", safe_rust),
        ("core/safe.go", safe_go),
    ]);
    assert!(
        clean.findings.is_empty(),
        "Hardened concurrency and RAII/defer code must produce zero findings, got: {:?}",
        clean.findings
    );
}

#[test]
fn test_phase9_native_memory_bounds_and_integer_overflows() {
    let vuln_cpp = r#"
#include <stdlib.h>
#include <string.h>

void copy_packet(char *dst, const char *src, size_t user_len) {
    strcpy(dst, src);
    memcpy(dst, src, user_len);
}

char* alloc_records(size_t count, size_t item_sz) {
    char *buf = (char*)malloc(count * item_sz);
    return buf;
}
"#;

    let vuln_rust = r#"
pub fn fast_index(slice: &[u8], idx: usize) -> u8 {
    unsafe { *slice.get_unchecked(idx) }
}

pub fn alloc_slab(n: usize, stride: usize) -> Vec<u8> {
    let total = n.wrapping_mul(stride);
    Vec::with_capacity(total)
}
"#;

    let res = run_inline(&[
        ("native/parser.cpp", vuln_cpp),
        ("native/slab.rs", vuln_rust),
    ]);
    let rules: Vec<&str> = res.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rules.iter().filter(|&&r| r == "VF-MEM-BOUNDS").count() >= 3,
        "Expected VF-MEM-BOUNDS on strcpy, unchecked memcpy, and Rust get_unchecked: {:?}",
        res.findings
    );
    assert!(
        rules.iter().filter(|&&r| r == "VF-ENG-INT").count() >= 2,
        "Expected VF-ENG-INT on C malloc multiplication + Rust wrapping_mul: {:?}",
        res.findings
    );

    // Hardened native memory & checked integer math -> ZERO findings
    let safe_cpp = r#"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int copy_packet_safe(char *dst, size_t dst_cap, const char *src, size_t user_len) {
    if (user_len >= dst_cap) return -1;
    memcpy(dst, src, user_len);
    dst[user_len] = '\0';
    return 0;
}

char* alloc_records_safe(size_t count, size_t item_sz) {
    size_t total = 0;
    if (__builtin_mul_overflow(count, item_sz, &total)) return NULL;
    return (char*)malloc(total);
}
"#;

    let safe_rust = r#"
pub fn safe_index(slice: &[u8], idx: usize) -> Option<u8> {
    if idx < slice.len() {
        Some(unsafe { *slice.get_unchecked(idx) })
    } else {
        None
    }
}

pub fn alloc_slab_safe(n: usize, stride: usize) -> Option<Vec<u8>> {
    let total = n.checked_mul(stride)?;
    Some(Vec::with_capacity(total))
}
"#;

    let clean = run_inline(&[("native/safe.cpp", safe_cpp), ("native/safe.rs", safe_rust)]);
    assert!(
        clean.findings.is_empty(),
        "Hardened native memory and overflow checks must produce zero findings, got: {:?}",
        clean.findings
    );
}

#[test]
fn test_phase9_mobile_android_ios_flutter_vulnerable_vs_hardened() {
    let manifest = r#"
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <receiver android:name=".SyncReceiver" android:exported="true" />
  </application>
</manifest>
"#;

    let kotlin_mobile = r#"
package com.example.wallet

import android.content.Context
import javax.net.ssl.X509TrustManager
import javax.net.ssl.HostnameVerifier

fun saveAuth(ctx: Context, jwt: String) {
    val prefs = ctx.getSharedPreferences("wallet", Context.MODE_PRIVATE)
    prefs.edit().putString("auth_token", jwt).apply()
}

class InsecureTrust : X509TrustManager {
    override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {
    }
}

val verifier = HostnameVerifier { _, _ -> true }
"#;

    let plist = r#"
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
</dict></plist>
"#;

    let swift_mobile = r#"
import UIKit

func persistSession(token: String) {
    UserDefaults.standard.set(token, forKey: "access_token")
}
"#;

    let dart_mobile = r#"
import 'dart:io';
import 'package:shared_preferences/shared_preferences.dart';

Future<void> storeCred(String secret) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('api_key', secret);
    HttpClient()..badCertificateCallback = (cert, host, port) => true;
}
"#;

    let res = run_inline(&[
        ("android/app/src/main/AndroidManifest.xml", manifest),
        ("android/app/src/main/java/Wallet.kt", kotlin_mobile),
        ("ios/Runner/Info.plist", plist),
        ("ios/Runner/AuthStore.swift", swift_mobile),
        ("lib/auth_store.dart", dart_mobile),
    ]);

    assert!(res.active_domains.contains(&"mobile".to_string()));
    let rules: Vec<&str> = res.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rules.contains(&"VF-MOB-IPC"),
        "Expected VF-MOB-IPC on exported SyncReceiver, got: {:?}",
        res.findings
    );
    assert!(
        rules.iter().filter(|&&r| r == "VF-MOB-STORAGE").count() >= 4,
        "Expected VF-MOB-STORAGE on allowBackup, Android SharedPreferences, iOS UserDefaults, Flutter SharedPreferences: {:?}",
        res.findings
    );
    assert!(
        rules.iter().filter(|&&r| r == "VF-MOB-TLS").count() >= 5,
        "Expected VF-MOB-TLS on cleartextTraffic, empty TrustManager, HostnameVerifier, ATS plist, Flutter badCertificateCallback: {:?}",
        res.findings
    );

    // Hardened mobile codebase -> ZERO findings
    let safe_manifest = r#"
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="false">
    <receiver android:name=".SyncReceiver" android:exported="true" android:permission="com.example.SYNC_PERM" />
  </application>
</manifest>
"#;
    let safe_kt = r#"
package com.example.wallet
import androidx.security.crypto.EncryptedSharedPreferences

fun saveAuthSafe(ctx: Context, jwt: String) {
    val prefs = EncryptedSharedPreferences.create("secret_prefs", masterKeyAlias, ctx, a, b)
    prefs.edit().putString("auth_token", jwt).apply()
}
"#;
    let safe_swift = r#"
import UIKit
import Security

func saveToKeychain(tokenData: Data) {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword]
    SecItemAdd(query as CFDictionary, nil)
}
"#;
    let safe_dart = r#"
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> storeSafe(String secret) async {
    final storage = FlutterSecureStorage();
    await storage.write(key: 'api_key', value: secret);
}
"#;

    let clean = run_inline(&[
        ("android/app/src/main/AndroidManifest.xml", safe_manifest),
        ("android/app/src/main/java/SafeWallet.kt", safe_kt),
        ("ios/Runner/SafeAuth.swift", safe_swift),
        ("lib/safe_auth.dart", safe_dart),
    ]);
    assert!(
        clean.findings.is_empty(),
        "Hardened mobile app must produce zero findings, got: {:?}",
        clean.findings
    );
}
