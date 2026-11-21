//! Opt-in Live Credential Verification engine (TruffleHog `--verify-live` parity).
//!
//! Strictly OFF by default — zero outbound network requests occur unless the user
//! explicitly passes `--verify-live`. Every check uses a strictly read-only,
//! non-destructive identity/whoami endpoint with redirects disabled so credentials
//! are never forwarded to third parties, and raw tokens are NEVER logged or printed.

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use smg_graph::{
    Confidence, LatticeFinding, SecretCandidate, extract_aws_secret_near, extract_tokens_from_line,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveVerifyStatus {
    VerifiedLive {
        provider: &'static str,
        identity_hint: String,
    },
    Inactive {
        provider: &'static str,
        http_status: u16,
    },
    Unverified {
        provider: &'static str,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct LiveVerifySummary {
    pub checked: usize,
    pub verified_live: usize,
    pub inactive: usize,
    pub unverified: usize,
}

/// Redacts a raw secret token so it is NEVER exposed in logs, JSON, SARIF, or terminal output.
pub fn redact_token(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 10 {
        return "****".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}****...{tail}")
}

fn build_verify_client() -> anyhow::Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(8))
        .redirect(Policy::none())
        .user_agent(concat!("ShellMind-Guard/", env!("CARGO_PKG_VERSION")))
        .build()?;
    Ok(client)
}

#[derive(Clone, Copy)]
enum AuthStyle {
    Bearer,
    Header(&'static str),
    BasicUserOnly,
    Anthropic,
    Notion,
    QueryKey(&'static str),
    TelegramGetMe,
    LinearGraphQl,
    SlackAuthTest,
    AwsSts,
}

#[derive(Clone, Copy)]
struct ProviderVerifier {
    provider: &'static str,
    url: &'static str,
    method_post: bool,
    auth: AuthStyle,
}

fn match_provider(token: &str) -> Option<ProviderVerifier> {
    if token.starts_with("ghp_")
        || token.starts_with("gho_")
        || token.starts_with("ghu_")
        || token.starts_with("ghs_")
        || token.starts_with("ghr_")
        || token.starts_with("github_pat_")
    {
        return Some(ProviderVerifier {
            provider: "GitHub",
            url: "https://api.github.com/user",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("glpat-") {
        return Some(ProviderVerifier {
            provider: "GitLab",
            url: "https://gitlab.com/api/v4/user",
            method_post: false,
            auth: AuthStyle::Header("PRIVATE-TOKEN"),
        });
    }
    if token.starts_with("sk-proj-")
        || token.starts_with("sk-svcacct-")
        || token.starts_with("sk-admin-")
    {
        return Some(ProviderVerifier {
            provider: "OpenAI",
            url: "https://api.openai.com/v1/models",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("sk-ant-") {
        return Some(ProviderVerifier {
            provider: "Anthropic",
            url: "https://api.anthropic.com/v1/models",
            method_post: false,
            auth: AuthStyle::Anthropic,
        });
    }
    if token.starts_with("sk_live_") || token.starts_with("rk_live_") {
        return Some(ProviderVerifier {
            provider: "Stripe",
            url: "https://api.stripe.com/v1/balance",
            method_post: false,
            auth: AuthStyle::BasicUserOnly,
        });
    }
    if token.starts_with("xoxb-")
        || token.starts_with("xoxp-")
        || token.starts_with("xoxa-")
        || token.starts_with("xoxr-")
    {
        return Some(ProviderVerifier {
            provider: "Slack",
            url: "https://slack.com/api/auth.test",
            method_post: true,
            auth: AuthStyle::SlackAuthTest,
        });
    }
    if token.starts_with("hf_") {
        return Some(ProviderVerifier {
            provider: "HuggingFace",
            url: "https://huggingface.co/api/whoami-v2",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("gsk_") {
        return Some(ProviderVerifier {
            provider: "Groq",
            url: "https://api.groq.com/openai/v1/models",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("sk-or-v1-") {
        return Some(ProviderVerifier {
            provider: "OpenRouter",
            url: "https://openrouter.ai/api/v1/auth/key",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("SG.") {
        return Some(ProviderVerifier {
            provider: "SendGrid",
            url: "https://api.sendgrid.com/v3/user/account",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("dop_v1_") || token.starts_with("doo_v1_") || token.starts_with("dor_v1_")
    {
        return Some(ProviderVerifier {
            provider: "DigitalOcean",
            url: "https://api.digitalocean.com/v2/account",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("lin_api_") {
        return Some(ProviderVerifier {
            provider: "Linear",
            url: "https://api.linear.app/graphql",
            method_post: true,
            auth: AuthStyle::LinearGraphQl,
        });
    }
    if token.starts_with("npm_") {
        return Some(ProviderVerifier {
            provider: "npm",
            url: "https://registry.npmjs.org/-/whoami",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("PMAK-") {
        return Some(ProviderVerifier {
            provider: "Postman",
            url: "https://api.getpostman.com/me",
            method_post: false,
            auth: AuthStyle::Header("X-Api-Key"),
        });
    }
    if token.starts_with("figd_") {
        return Some(ProviderVerifier {
            provider: "Figma",
            url: "https://api.figma.com/v1/me",
            method_post: false,
            auth: AuthStyle::Header("X-Figma-Token"),
        });
    }
    if token.starts_with("ntn_") {
        return Some(ProviderVerifier {
            provider: "Notion",
            url: "https://api.notion.com/v1/users/me",
            method_post: false,
            auth: AuthStyle::Notion,
        });
    }
    if token.starts_with("vcp_") {
        return Some(ProviderVerifier {
            provider: "Vercel",
            url: "https://api.vercel.com/v2/user",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("nfp_") {
        return Some(ProviderVerifier {
            provider: "Netlify",
            url: "https://api.netlify.com/api/v1/user",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("rnd_") {
        return Some(ProviderVerifier {
            provider: "Render",
            url: "https://api.render.com/v1/owners",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("sbp_") {
        return Some(ProviderVerifier {
            provider: "Supabase",
            url: "https://api.supabase.com/v1/projects",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("r8_") {
        return Some(ProviderVerifier {
            provider: "Replicate",
            url: "https://api.replicate.com/v1/account",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("xai-") {
        return Some(ProviderVerifier {
            provider: "xAI",
            url: "https://api.x.ai/v1/models",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("re_") {
        return Some(ProviderVerifier {
            provider: "Resend",
            url: "https://api.resend.com/domains",
            method_post: false,
            auth: AuthStyle::Bearer,
        });
    }
    if token.starts_with("AIza") && token.len() == 39 {
        return Some(ProviderVerifier {
            provider: "Google/Gemini",
            url: "https://generativelanguage.googleapis.com/v1beta/models",
            method_post: false,
            auth: AuthStyle::QueryKey("key"),
        });
    }
    if token.starts_with("AKIA") && token.len() == 20 {
        return Some(ProviderVerifier {
            provider: "AWS-STS",
            url: "https://sts.amazonaws.com/",
            method_post: true,
            auth: AuthStyle::AwsSts,
        });
    }
    if token.contains(":AA") && token.len() >= 42 {
        return Some(ProviderVerifier {
            provider: "Telegram",
            url: "https://api.telegram.org",
            method_post: false,
            auth: AuthStyle::TelegramGetMe,
        });
    }
    None
}

/// Verifies a single credential against its provider's read-only endpoint (or `override_url` for tests).
pub fn verify_single_token(
    client: &Client,
    token: &str,
    paired_secret: Option<&str>,
    override_url: Option<&str>,
) -> LiveVerifyStatus {
    let Some(spec) = match_provider(token) else {
        return LiveVerifyStatus::Unverified {
            provider: "Unknown",
            reason: "no read-only live verifier registered for this token format".to_string(),
        };
    };

    let target_url = match (override_url, spec.auth) {
        (Some(u), _) => u.to_string(),
        (None, AuthStyle::TelegramGetMe) => format!("{}/bot{token}/getMe", spec.url),
        (None, AuthStyle::QueryKey(k)) => format!("{}?{k}={token}", spec.url),
        (None, _) => spec.url.to_string(),
    };

    if matches!(spec.auth, AuthStyle::AwsSts) {
        let Some(paired_aws_cred) = paired_secret else {
            return LiveVerifyStatus::Unverified {
                provider: spec.provider,
                reason: "AKIA key found without paired AWS_SECRET_ACCESS_KEY".to_string(),
            };
        };
        return verify_aws_sts(client, token, paired_aws_cred, &target_url);
    }

    let mut req = if spec.method_post {
        client.post(&target_url)
    } else {
        client.get(&target_url)
    };

    req = match spec.auth {
        AuthStyle::Bearer => req.bearer_auth(token),
        AuthStyle::Header(h) => req.header(h, token),
        AuthStyle::BasicUserOnly => req.basic_auth(token, Some("")),
        AuthStyle::Anthropic => req
            .header("x-api-key", token)
            .header("anthropic-version", "2023-06-01"),
        AuthStyle::Notion => req
            .bearer_auth(token)
            .header("Notion-Version", "2022-06-28"),
        AuthStyle::LinearGraphQl => req
            .header("Authorization", token)
            .header("Content-Type", "application/json")
            .body(r#"{"query":"{ viewer { id } }"}"#),
        AuthStyle::SlackAuthTest => req.bearer_auth(token),
        AuthStyle::QueryKey(_) | AuthStyle::TelegramGetMe | AuthStyle::AwsSts => req,
    };

    let resp = match req.send() {
        Ok(r) => r,
        Err(e) => {
            return LiveVerifyStatus::Unverified {
                provider: spec.provider,
                reason: format!("network error: {}", sanitize_reqwest_error(&e)),
            };
        }
    };

    let status = resp.status().as_u16();
    let body = read_response_bounded(resp, 256 * 1024);

    // Slack returns HTTP 200 with {"ok": false} for revoked tokens
    if matches!(spec.auth, AuthStyle::SlackAuthTest)
        && status == 200
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(ok) = val.get("ok").and_then(|v| v.as_bool())
    {
        if ok {
            return LiveVerifyStatus::VerifiedLive {
                provider: spec.provider,
                identity_hint: extract_identity_hint(&body),
            };
        }
        return LiveVerifyStatus::Inactive {
            provider: spec.provider,
            http_status: 401,
        };
    }

    // Linear GraphQL returns 200 with "errors" on bad key
    if matches!(spec.auth, AuthStyle::LinearGraphQl) {
        if status == 200 && body.contains("\"viewer\"") && !body.contains("\"errors\"") {
            return LiveVerifyStatus::VerifiedLive {
                provider: spec.provider,
                identity_hint: "authenticated viewer".to_string(),
            };
        }
        if status == 401 || status == 403 || body.contains("AUTHENTICATION_ERROR") {
            return LiveVerifyStatus::Inactive {
                provider: spec.provider,
                http_status: 401,
            };
        }
    }

    match status {
        200..=299 => LiveVerifyStatus::VerifiedLive {
            provider: spec.provider,
            identity_hint: extract_identity_hint(&body),
        },
        401 | 403 => LiveVerifyStatus::Inactive {
            provider: spec.provider,
            http_status: status,
        },
        429 => LiveVerifyStatus::Unverified {
            provider: spec.provider,
            reason: "HTTP 429 rate-limited".to_string(),
        },
        other => LiveVerifyStatus::Unverified {
            provider: spec.provider,
            reason: format!("unexpected HTTP {other}"),
        },
    }
}

fn extract_identity_hint(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["login", "username", "email", "name", "team", "id"] {
            if let Some(s) = v.get(key).and_then(|x| x.as_str())
                && !s.is_empty()
            {
                let safe: String = s.chars().take(32).collect();
                return format!("{key}={safe}");
            }
        }
    }
    "active".to_string()
}

/// Pure-Rust AWS SigV4 `sts:GetCallerIdentity` verification (zero external crypto crate needed).
fn verify_aws_sts(
    client: &Client,
    access_key: &str,
    aws_signing_cred: &str,
    url: &str,
) -> LiveVerifyStatus {
    let body = "Action=GetCallerIdentity&Version=2011-06-15";
    let (amz_date, date_stamp) = utc_iso8601_basic();
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("sts.amazonaws.com");
    let region = "us-east-1";
    let service = "sts";

    let payload_hash = sha256_hex(body.as_bytes());
    let canonical_headers = format!(
        "content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "content-type;host;x-amz-date";
    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(
        format!("AWS4{aws_signing_cred}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let resp = match client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Amz-Date", &amz_date)
        .header("Authorization", auth_header)
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            return LiveVerifyStatus::Unverified {
                provider: "AWS-STS",
                reason: format!("network error: {}", sanitize_reqwest_error(&e)),
            };
        }
    };

    let status = resp.status().as_u16();
    let text = read_response_bounded(resp, 256 * 1024);
    if status == 200 && text.contains("GetCallerIdentityResult") {
        let arn = text
            .split("<Arn>")
            .nth(1)
            .and_then(|s| s.split("</Arn>").next())
            .unwrap_or("active-iam")
            .to_string();
        LiveVerifyStatus::VerifiedLive {
            provider: "AWS-STS",
            identity_hint: arn,
        }
    } else if status == 403 || status == 401 {
        LiveVerifyStatus::Inactive {
            provider: "AWS-STS",
            http_status: status,
        }
    } else {
        LiveVerifyStatus::Unverified {
            provider: "AWS-STS",
            reason: format!("HTTP {status}"),
        }
    }
}

/// Verifies all secret findings (working tree + git history candidates) and mutates
/// `findings` in-place with live verification tags, severity upgrades, and optional `--only-verified` filtering.
fn sanitize_reqwest_error(e: &reqwest::Error) -> String {
    let raw = e.to_string();
    let without_url = raw.split(" for url (").next().unwrap_or(&raw).trim();
    if without_url.is_empty() {
        "request failed".to_string()
    } else {
        without_url.to_string()
    }
}

fn read_response_bounded(resp: reqwest::blocking::Response, max_bytes: usize) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = resp.take(max_bytes as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn run_live_secret_verification(
    repo_root: &Path,
    findings: &mut Vec<LatticeFinding>,
    history_candidates: &[SecretCandidate],
    only_verified: bool,
) -> anyhow::Result<LiveVerifySummary> {
    let client = build_verify_client()?;
    let mut summary = LiveVerifySummary {
        checked: 0,
        verified_live: 0,
        inactive: 0,
        unverified: 0,
    };

    // Index history candidates by (file, line)
    let mut hist_map: HashMap<(String, usize), &SecretCandidate> = HashMap::new();
    for c in history_candidates {
        hist_map.insert((c.file.clone(), c.line), c);
    }

    // Cache file reads for working-tree token extraction
    let mut file_cache: HashMap<String, String> = HashMap::new();
    // Cache live verification verdicts by raw token hash so duplicate findings only probe once
    let mut verdict_cache: HashMap<String, LiveVerifyStatus> = HashMap::new();

    let mut verified_indices: Vec<bool> = vec![true; findings.len()];

    for (idx, f) in findings.iter_mut().enumerate() {
        if !f.rule_id.starts_with("SMG-SEC-") {
            continue;
        }

        let (raw_token, paired_secret) = if let Some(cand) = hist_map.get(&(f.file.clone(), f.line))
        {
            (cand.raw_token.clone(), cand.paired_secret.clone())
        } else {
            let content = file_cache.entry(f.file.clone()).or_insert_with(|| {
                let Ok(canon_root) = fs::canonicalize(repo_root) else {
                    return String::new();
                };
                let Ok(canon_file) = fs::canonicalize(repo_root.join(&f.file)) else {
                    return String::new();
                };
                if !canon_file.starts_with(&canon_root) {
                    return String::new();
                }
                fs::read_to_string(&canon_file).unwrap_or_default()
            });
            let lines: Vec<&str> = content.lines().collect();
            let line_idx = f.line.saturating_sub(1);
            let line_str = lines.get(line_idx).copied().unwrap_or("");
            let toks = extract_tokens_from_line(line_str);
            let tok = match toks.into_iter().next() {
                Some(t) => t,
                None => {
                    if only_verified {
                        verified_indices[idx] = false;
                    }
                    continue;
                }
            };
            let paired = if tok.starts_with("AKIA") {
                extract_aws_secret_near(&lines, line_idx)
            } else {
                None
            };
            (tok, paired)
        };

        let tok_hash = sha256_hex(raw_token.as_bytes());
        let status = if let Some(cached) = verdict_cache.get(&tok_hash) {
            cached.clone()
        } else {
            summary.checked += 1;
            let st = verify_single_token(&client, &raw_token, paired_secret.as_deref(), None);
            match &st {
                LiveVerifyStatus::VerifiedLive { .. } => summary.verified_live += 1,
                LiveVerifyStatus::Inactive { .. } => summary.inactive += 1,
                LiveVerifyStatus::Unverified { .. } => summary.unverified += 1,
            }
            verdict_cache.insert(tok_hash, st.clone());
            st
        };

        let redacted = redact_token(&raw_token);
        match status {
            LiveVerifyStatus::VerifiedLive {
                provider,
                identity_hint,
            } => {
                f.severity = "CRITICAL".to_string();
                f.confidence = Confidence::Proven;
                f.title = format!(
                    "[VERIFIED LIVE: {provider} ({identity_hint}) token={redacted}] {}",
                    f.title
                );
                f.proof_reasons.push(format!(
                    "Live read-only API verification confirmed active {provider} credential ({identity_hint}, token={redacted})"
                ));
            }
            LiveVerifyStatus::Inactive {
                provider,
                http_status,
            } => {
                f.confidence = Confidence::Heuristic;
                f.title = format!(
                    "[VERIFIED INACTIVE: {provider} HTTP {http_status} token={redacted}] {}",
                    f.title
                );
                f.proof_reasons.push(format!(
                    "Live read-only API verification returned HTTP {http_status} inactive/revoked ({provider}, token={redacted})"
                ));
                if only_verified {
                    verified_indices[idx] = false;
                }
            }
            LiveVerifyStatus::Unverified { provider, reason } => {
                f.title = format!(
                    "[LIVE-CHECK UNVERIFIED: {provider} ({reason}) token={redacted}] {}",
                    f.title
                );
                if only_verified {
                    verified_indices[idx] = false;
                }
            }
        }
    }

    if only_verified {
        let mut keep_iter = verified_indices.into_iter();
        findings.retain(|_| keep_iter.next().unwrap_or(true));
    }

    Ok(summary)
}

// ---------- Minimal pure-Rust SHA-256 & HMAC-SHA256 (FIPS 180-4 / RFC 2104) ----------

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256(data))
}

fn utc_iso8601_basic() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    // Howard Hinnant's civil-from-days algorithm
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let date_stamp = format!("{year:04}{m:02}{d:02}");
    let amz_date = format!("{date_stamp}T{hour:02}{min:02}{sec:02}Z");
    (amz_date, date_stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn spawn_one_shot_http(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}/")
    }

    #[test]
    fn sha256_and_hmac_match_rfc_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn verify_single_token_distinguishes_live_inactive_and_rate_limited() {
        let client = build_verify_client().unwrap();
        let fake_gh = ["ghp_", "9kLm2nPq7rSt4vWx8yZa3bCd6eFg1hIj5kLm"].concat();

        let live_url = spawn_one_shot_http("200 OK", r#"{"login":"octocat"}"#);
        let st1 = verify_single_token(&client, &fake_gh, None, Some(&live_url));
        assert_eq!(
            st1,
            LiveVerifyStatus::VerifiedLive {
                provider: "GitHub",
                identity_hint: "login=octocat".to_string()
            }
        );

        let dead_url = spawn_one_shot_http("401 Unauthorized", r#"{"message":"Bad credentials"}"#);
        let st2 = verify_single_token(&client, &fake_gh, None, Some(&dead_url));
        assert_eq!(
            st2,
            LiveVerifyStatus::Inactive {
                provider: "GitHub",
                http_status: 401
            }
        );

        let rl_url = spawn_one_shot_http("429 Too Many Requests", r#"{"message":"rate limit"}"#);
        let st3 = verify_single_token(&client, &fake_gh, None, Some(&rl_url));
        assert!(matches!(
            st3,
            LiveVerifyStatus::Unverified {
                provider: "GitHub",
                ..
            }
        ));
    }

    #[test]
    fn redacts_tokens_cleanly() {
        let raw = "ghp_1234567890abcdef1234567890";
        let red = redact_token(raw);
        assert_eq!(red, "ghp_****...7890");
        assert!(!red.contains("123456"));
    }
}
