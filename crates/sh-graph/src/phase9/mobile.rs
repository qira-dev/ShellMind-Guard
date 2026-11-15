use super::make_phase9_finding;
use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind, node_text, strip_comments};
use regex::Regex;
use sh_core::Language;
use std::path::Path;
use std::sync::OnceLock;
use tree_sitter::Node;

fn sensitive_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)["'](?:[a-z0-9_.-]*_)?(auth|token|access_?token|refresh_?token|id_?token|auth_?token|jwt|secret|password|passwd|pin|api_?key|private_?key|credential|session_?id|bearer)(?:_[a-z0-9_.-]*)?["']"#,
        )
        .expect("valid sensitive key regex")
    })
}

fn manifest_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<(activity|service|receiver|provider|application)\b([^>]*)>"#)
            .expect("valid android manifest regex")
    })
}

/// Scans Android/iOS mobile manifests and network security XML/plist files.
pub fn scan_mobile_config(rel_path: &str, source: &str) -> Vec<LocalStaticFinding> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let mut findings = Vec::new();

    if fname == "AndroidManifest.xml" {
        scan_android_manifest(rel_path, source, &mut findings);
    } else if fname == "network_security_config.xml" {
        scan_network_security_config(rel_path, source, &mut findings);
    } else if fname == "Info.plist" {
        scan_info_plist(rel_path, source, &mut findings);
    }
    findings
}

fn line_at_byte(src: &str, byte_offset: usize) -> usize {
    src[..byte_offset.min(src.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

fn scan_android_manifest(rel_path: &str, source: &str, out: &mut Vec<LocalStaticFinding>) {
    let source_low = source.to_ascii_lowercase();
    for cap in manifest_tag_re().captures_iter(source) {
        let full = cap.get(0).unwrap();
        let tag = cap
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let raw_attrs = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let self_closing = raw_attrs.trim_end().ends_with('/');
        let attrs = raw_attrs.trim_end().trim_end_matches('/');
        let ln = line_at_byte(source, full.start());
        let attrs_low = attrs.to_ascii_lowercase();
        let body_low = if tag == "application" || self_closing {
            ""
        } else {
            let close_tag = format!("</{tag}>");
            source_low[full.end()..]
                .find(&close_tag)
                .map(|end_rel| &source_low[full.end()..full.end() + end_rel])
                .unwrap_or("")
        };

        if tag == "application" {
            if attrs_low.contains("android:usescleartexttraffic=\"true\"") {
                out.push(make_phase9_finding(
                    "VF-MOB-TLS",
                    "HIGH",
                    "Android `android:usesCleartextTraffic=\"true\"` permits plaintext HTTP traffic".into(),
                    rel_path,
                    ln,
                    "AndroidManifest.xml",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Set `android:usesCleartextTraffic=\"false\"` and enforce HTTPS via `network_security_config.xml`.",
                ));
            }
            if attrs_low.contains("android:allowbackup=\"true\"") {
                out.push(make_phase9_finding(
                    "VF-MOB-STORAGE",
                    "MEDIUM",
                    "Android `android:allowBackup=\"true\"` permits ADB/cloud extraction of app storage".into(),
                    rel_path,
                    ln,
                    "AndroidManifest.xml",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Set `android:allowBackup=\"false\"` or configure strict `fullBackupContent`/`dataExtractionRules` exclusions.",
                ));
            }
            if attrs_low.contains("android:debuggable=\"true\"") {
                out.push(make_phase9_finding(
                    "VF-MOB-IPC",
                    "HIGH",
                    "Android `android:debuggable=\"true\"` hardcoded in manifest".into(),
                    rel_path,
                    ln,
                    "AndroidManifest.xml",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Remove `android:debuggable=\"true\"` from `AndroidManifest.xml` so release APKs are non-debuggable.",
                ));
            }
            continue;
        }

        let is_launcher = tag == "activity"
            && body_low.contains("android.intent.action.main")
            && body_low.contains("android.intent.category.launcher");
        if is_launcher {
            continue;
        }

        let explicitly_exported = attrs_low.contains("android:exported=\"true\"");
        let explicitly_disabled = attrs_low.contains("android:exported=\"false\"");
        let has_intent_filter = body_low.contains("<intent-filter");
        let has_permission = attrs_low.contains("android:permission=")
            || attrs_low.contains("android:readpermission=")
            || attrs_low.contains("android:writepermission=");

        if (explicitly_exported || (has_intent_filter && !explicitly_disabled)) && !has_permission {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "HIGH",
                format!(
                    "Exported Android `<{}>` component lacks `android:permission` protection (IPC hijacking risk)",
                    tag
                ),
                rel_path,
                ln,
                &tag,
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Set `android:exported=\"false\"` for internal components, or require a `signature`-level `android:permission`.",
            ));
        }
    }
}

fn scan_network_security_config(rel_path: &str, source: &str, out: &mut Vec<LocalStaticFinding>) {
    for (idx, line) in source.lines().enumerate() {
        let ln = idx + 1;
        let low = line.to_ascii_lowercase();
        if low.contains("cleartexttrafficpermitted=\"true\"") {
            out.push(make_phase9_finding(
                "VF-MOB-TLS",
                "HIGH",
                "Android `network_security_config.xml` sets `cleartextTrafficPermitted=\"true\"`".into(),
                rel_path,
                ln,
                "network_security_config.xml",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Set `cleartextTrafficPermitted=\"false\"` in `base-config` and enforce TLS certificate pinning.",
            ));
        }
        if low.contains("<certificates") && low.contains("src=\"user\"") {
            out.push(make_phase9_finding(
                "VF-MOB-TLS",
                "HIGH",
                "Android `network_security_config.xml` trusts user-installed root CAs in release config".into(),
                rel_path,
                ln,
                "network_security_config.xml",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Restrict `src=\"user\"` exclusively to `<debug-overrides>` instead of `<base-config>`.",
            ));
        }
    }
}

fn scan_info_plist(rel_path: &str, source: &str, out: &mut Vec<LocalStaticFinding>) {
    let lines: Vec<&str> = source.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if line.contains("NSAllowsArbitraryLoads") {
            let next_few = lines[idx..lines.len().min(idx + 3)].join(" ");
            if next_few.contains("<true/>") || next_few.contains("<true />") {
                out.push(make_phase9_finding(
                    "VF-MOB-TLS",
                    "HIGH",
                    "iOS `Info.plist` disables App Transport Security (`NSAllowsArbitraryLoads = true`)".into(),
                    rel_path,
                    idx + 1,
                    "Info.plist",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Remove `NSAllowsArbitraryLoads` or scope exceptions strictly via `NSExceptionDomains` with TLS 1.2+.",
                ));
            }
        }
    }
}

/// Scans Kotlin, Java, Swift, and Dart mobile application sources for
/// `VF-MOB-STORAGE`, `VF-MOB-IPC`, and `VF-MOB-TLS`.
pub fn analyze_mobile_ast(
    root: Node,
    src: &[u8],
    rel_path: &str,
    lang: Language,
    out: &mut Vec<LocalStaticFinding>,
) {
    let raw_code = node_text(root, src);
    let cleaned = strip_comments(raw_code);
    let low_full = cleaned.to_ascii_lowercase();
    let lines: Vec<&str> = cleaned.lines().collect();

    match lang {
        Language::Kotlin | Language::Java => {
            scan_android_code(rel_path, &lines, &low_full, out);
        }
        Language::Swift => {
            scan_swift_mobile(rel_path, &lines, &low_full, out);
        }
        Language::Dart => {
            scan_dart_mobile(rel_path, &lines, &low_full, out);
        }
        _ => {}
    }
}

fn scan_android_code(
    rel_path: &str,
    lines: &[&str],
    full_low: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let has_encrypted_prefs = full_low.contains("encryptedsharedpreferences");
    let has_keystore = full_low.contains("androidkeystore") || full_low.contains("keystore");

    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();

        // 1. VF-MOB-STORAGE: Unencrypted SharedPreferences storing sensitive tokens/secrets or world-readable mode
        if low.contains("mode_world_readable") || low.contains("mode_world_writeable") {
            out.push(make_phase9_finding(
                "VF-MOB-STORAGE",
                "HIGH",
                "Android `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` exposes app storage to other apps".into(),
                rel_path,
                ln,
                "android_storage",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Use `Context.MODE_PRIVATE` and `EncryptedSharedPreferences` backed by Android Keystore.",
            ));
        }

        if !has_encrypted_prefs
            && !has_keystore
            && (low.contains(".putstring(") || low.contains("sharedpreferences"))
            && sensitive_key_re().is_match(trimmed)
        {
            out.push(make_phase9_finding(
                "VF-MOB-STORAGE",
                "HIGH",
                "Sensitive credential/token written to plaintext Android `SharedPreferences`".into(),
                rel_path,
                ln,
                "SharedPreferences",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Store tokens, secrets, and PINs in `EncryptedSharedPreferences` / Android `Keystore` instead of plaintext `SharedPreferences`.",
            ));
        }

        // 2. VF-MOB-IPC: Unsafe WebView JS bridge / exported registerReceiver / implicit broadcast Intent
        if low.contains("addjavascriptinterface(") {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "HIGH",
                "Android `WebView.addJavascriptInterface()` exposes native objects to web content".into(),
                rel_path,
                ln,
                "addJavascriptInterface",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Avoid `addJavascriptInterface` for untrusted URLs; validate origins strictly or use `androidx.webkit.WebViewCompat.addWebMessageListener`.",
            ));
        }

        if low.contains("setallowfileaccessfromfileurls(true)")
            || low.contains("allowfileaccessfromfileurls = true")
            || low.contains("allowuniversalaccessfromfileurls = true")
        {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "HIGH",
                "Android WebView enables cross-file URL access (`allowFileAccessFromFileURLs = true`)".into(),
                rel_path,
                ln,
                "WebViewSettings",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Keep `allowFileAccessFromFileURLs = false` and `allowUniversalAccessFromFileURLs = false` on WebView settings.",
            ));
        }

        if low.contains("registerreceiver(")
            && !low.contains("receiver_not_exported")
            && trimmed.matches(',').count() <= 2
            && !lines[idx..lines.len().min(idx + 3)]
                .join(" ")
                .to_ascii_lowercase()
                .contains("receiver_not_exported")
        {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "MEDIUM",
                "Dynamic `registerReceiver()` without `RECEIVER_NOT_EXPORTED` or signature permission".into(),
                rel_path,
                ln,
                "registerReceiver",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Pass `Context.RECEIVER_NOT_EXPORTED` (Android 13+) or specify a signature broadcast permission.",
            ));
        }

        if (low.contains("sendbroadcast(") || low.contains("startservice("))
            && low.contains("intent(")
            && !low.contains(".setpackage(")
            && !low.contains(".setcomponent(")
        {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "MEDIUM",
                "Implicit `Intent` dispatched via `sendBroadcast`/`startService` without package target".into(),
                rel_path,
                ln,
                "Intent",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Heuristic,
                "Restrict `Intent` with `.setPackage(...)`, explicit `ComponentName`, or `LocalBroadcastManager`.",
            ));
        }

        // 3. VF-MOB-TLS: TrustManager / HostnameVerifier / WebView SslError bypass
        if low.contains("override fun checkservertrusted(")
            || low.contains("public void checkservertrusted(")
        {
            let window = lines[idx..lines.len().min(idx + 6)].join(" ");
            let wlow = window.to_ascii_lowercase();
            let has_throw_or_verify = wlow.contains("throw ")
                || wlow.contains("checkvalidity")
                || wlow.contains("verify(");
            if !has_throw_or_verify {
                out.push(make_phase9_finding(
                    "VF-MOB-TLS",
                    "CRITICAL",
                    "Custom `X509TrustManager.checkServerTrusted()` does not validate or reject untrusted certificates".into(),
                    rel_path,
                    ln,
                    "X509TrustManager",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Remove custom trust-all `X509TrustManager` and rely on system CA validation + certificate pinning.",
                ));
            }
        }

        if (low.contains("hostnameverifier")
            && (low.contains("-> true") || low.contains("return true")))
            || low.contains("allow_all_hostname_verifier")
        {
            out.push(make_phase9_finding(
                "VF-MOB-TLS",
                "CRITICAL",
                "TLS hostname verification disabled (`HostnameVerifier` unconditionally returns `true`)".into(),
                rel_path,
                ln,
                "HostnameVerifier",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Use default strict `HostnameVerifier` (`HttpsURLConnection.getDefaultHostnameVerifier()`).",
            ));
        }

        if low.contains("sslerrorhandler") || low.contains("onreceivedsslerror") {
            let window = lines[idx..lines.len().min(idx + 5)]
                .join(" ")
                .to_ascii_lowercase();
            if window.contains(".proceed(") {
                out.push(make_phase9_finding(
                    "VF-MOB-TLS",
                    "CRITICAL",
                    "WebView `onReceivedSslError` calls `handler.proceed()` ignoring TLS errors".into(),
                    rel_path,
                    ln,
                    "onReceivedSslError",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Call `handler.cancel()` inside `onReceivedSslError` instead of `handler.proceed()`.",
                ));
            }
        }
    }
}

fn scan_swift_mobile(
    rel_path: &str,
    lines: &[&str],
    full_low: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let uses_keychain = full_low.contains("secitemadd") || full_low.contains("keychain");

    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();

        // 1. VF-MOB-STORAGE: UserDefaults storing secrets/tokens
        if !uses_keychain
            && low.contains("userdefaults")
            && low.contains(".set(")
            && sensitive_key_re().is_match(trimmed)
        {
            out.push(make_phase9_finding(
                "VF-MOB-STORAGE",
                "HIGH",
                "Sensitive token/secret stored in unencrypted iOS `UserDefaults`".into(),
                rel_path,
                ln,
                "UserDefaults",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Store tokens, keys, and passwords in iOS Keychain (`SecItemAdd` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).",
            ));
        }

        // 2. VF-MOB-IPC: Unvalidated iOS deep-link / URL scheme forwarded to WebView
        if (low.contains("openurl")
            || low.contains("func application(") && low.contains("open url:"))
            && lines[idx..lines.len().min(idx + 12)].iter().any(|l| {
                l.to_ascii_lowercase().contains("webview.load")
                    || l.to_ascii_lowercase().contains("load(urlrequest")
            })
            && !lines[idx..lines.len().min(idx + 12)].iter().any(|l| {
                let ll = l.to_ascii_lowercase();
                ll.contains("url.host")
                    || ll.contains("allowedhosts")
                    || ll.contains("url.scheme ==")
            })
        {
            out.push(make_phase9_finding(
                "VF-MOB-IPC",
                "HIGH",
                "iOS deep-link URL handler passes unvalidated URL directly into `WebView.load()`".into(),
                rel_path,
                ln,
                "onOpenURL",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Validate `url.scheme` and `url.host` against an explicit allowlist before opening deep links.",
            ));
        }

        // 3. VF-MOB-TLS: URLSession challenge trust bypass
        if low.contains(".usecredential")
            && low.contains("urlcredential(trust:")
            && !lines[idx.saturating_sub(5)..idx].iter().any(|l| {
                let ll = l.to_ascii_lowercase();
                ll.contains("sectrustevaluate")
                    || ll.contains("pinned")
                    || ll.contains("seccertificate")
            })
        {
            out.push(make_phase9_finding(
                "VF-MOB-TLS",
                "CRITICAL",
                "iOS `URLSessionDelegate` calls `completionHandler(.useCredential, URLCredential(trust:))` without certificate pinning/evaluation".into(),
                rel_path,
                ln,
                "URLSessionDelegate",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Evaluate server trust via `SecTrustEvaluateWithError` and compare against pinned public keys/certificates.",
            ));
        }
    }
}

fn scan_dart_mobile(
    rel_path: &str,
    lines: &[&str],
    full_low: &str,
    out: &mut Vec<LocalStaticFinding>,
) {
    let uses_secure_storage = full_low.contains("fluttersecurestorage");

    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();

        // 1. VF-MOB-STORAGE: SharedPreferences storing sensitive tokens/secrets
        if !uses_secure_storage
            && (low.contains("sharedpreferences") || full_low.contains("sharedpreferences"))
            && low.contains(".setstring(")
            && sensitive_key_re().is_match(trimmed)
        {
            out.push(make_phase9_finding(
                "VF-MOB-STORAGE",
                "HIGH",
                "Sensitive credential/token saved in plaintext Flutter `SharedPreferences`".into(),
                rel_path,
                ln,
                "SharedPreferences",
                SinkKind::MobileSecurity,
                GuardKind::MobilePolicy,
                Confidence::Confirmed,
                "Use `FlutterSecureStorage` (Keychain/EncryptedSharedPreferences) instead of `SharedPreferences` for tokens and secrets.",
            ));
        }

        // 2. VF-MOB-TLS: HttpClient.badCertificateCallback = (...) => true
        if low.contains("badcertificatecallback") {
            let window = lines[idx..lines.len().min(idx + 3)].join(" ");
            if window.contains("=> true") || window.contains("return true") {
                out.push(make_phase9_finding(
                    "VF-MOB-TLS",
                    "CRITICAL",
                    "Flutter `HttpClient.badCertificateCallback` unconditionally accepts invalid TLS certificates".into(),
                    rel_path,
                    ln,
                    "badCertificateCallback",
                    SinkKind::MobileSecurity,
                    GuardKind::MobilePolicy,
                    Confidence::Confirmed,
                    "Remove `badCertificateCallback => true` or verify pinned certificate SHA-256 fingerprints strictly.",
                ));
            }
        }
    }
}
