use crate::ast::{Confidence, GuardKind, LocalStaticFinding, SinkKind};
use regex::{Regex, RegexSet};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

fn aws_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b").expect("valid aws regex")
    })
}

fn stripe_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b((?:sk|rk)_live_[0-9A-Za-z_]{10,}|whsec_[0-9A-Za-z+/=_-]{24,})\b")
            .expect("valid stripe regex")
    })
}

fn github_pat_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(gh[pousr]_[0-9A-Za-z]{16,}|github_pat_[0-9A-Za-z_]{16,})\b")
            .expect("valid github regex")
    })
}

#[derive(Clone, Copy)]
struct SecretTokenSpec {
    provider: &'static str,
    rule_id: &'static str,
    severity: &'static str,
    prefix_skip: usize,
    min_entropy: f64,
    requires_keyword: Option<&'static str>,
}

fn secret_token_pack() -> &'static (RegexSet, Vec<(SecretTokenSpec, Regex)>) {
    static PACK: OnceLock<(RegexSet, Vec<(SecretTokenSpec, Regex)>)> = OnceLock::new();
    PACK.get_or_init(|| {
        let defs: &[(&str, SecretTokenSpec)] = &[
            (
                r"\b(sk-proj-[0-9A-Za-z_-]{20,}|sk-svcacct-[0-9A-Za-z_-]{20,}|sk-admin-[0-9A-Za-z_-]{20,})\b",
                SecretTokenSpec { provider: "OpenAI API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 8, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(sk-ant-(?:api|admin)[0-9A-Za-z_-]{20,})\b",
                SecretTokenSpec { provider: "Anthropic API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 10, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(xox[baprs]-[0-9A-Za-z-]{16,})\b",
                SecretTokenSpec { provider: "Slack Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"(https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{20,})",
                SecretTokenSpec { provider: "Slack Webhook URL", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 33, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,22}/[0-9A-Za-z_-]{50,})",
                SecretTokenSpec { provider: "Discord Webhook URL", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 36, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(AIza[0-9A-Za-z_-]{35})\b",
                SecretTokenSpec { provider: "Google Cloud / Gemini API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(gl(?:pat|dt|rt|ft)-[0-9A-Za-z_-]{20,})\b",
                SecretTokenSpec { provider: "GitLab Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 6, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(hf_[A-Za-z]{24,})\b",
                SecretTokenSpec { provider: "Hugging Face Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(r8_[0-9A-Za-z]{24,})\b",
                SecretTokenSpec { provider: "Replicate API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(gsk_[0-9A-Za-z]{40,})\b",
                SecretTokenSpec { provider: "Groq API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(pplx-[0-9a-fA-F]{40,})\b",
                SecretTokenSpec { provider: "Perplexity API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(xai-[0-9A-Za-z]{32,})\b",
                SecretTokenSpec { provider: "xAI API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(npm_[0-9A-Za-z]{30,})\b",
                SecretTokenSpec { provider: "npm Access Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(pypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[0-9A-Za-z_-]{30,})\b",
                SecretTokenSpec { provider: "PyPI API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 20, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(rubygems_[0-9a-f]{40,})\b",
                SecretTokenSpec { provider: "RubyGems API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 9, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{20,})\b",
                SecretTokenSpec { provider: "SendGrid API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(do[por]_v1_[0-9a-f]{64})\b",
                SecretTokenSpec { provider: "DigitalOcean Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(dapi[0-9a-f]{32}(?:-[0-9])?)\b",
                SecretTokenSpec { provider: "Databricks Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(dp\.(?:st|pt|sa|scim)\.(?:[a-z0-9_-]+\.)?[0-9A-Za-z]{30,})\b",
                SecretTokenSpec { provider: "Doppler Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 6, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(lin_api_[0-9A-Za-z]{35,})\b",
                SecretTokenSpec { provider: "Linear API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 8, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(pscale_(?:tkn|pw)_[0-9A-Za-z_.-]{32,})\b",
                SecretTokenSpec { provider: "PlanetScale Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 10, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(sbp_[0-9a-f]{40}|sb_secret_[0-9A-Za-z_-]{24,})\b",
                SecretTokenSpec { provider: "Supabase Secret Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(glc_eyJ[0-9A-Za-z+/=_-]{20,}|glsa_[0-9A-Za-z]{32}_[0-9a-f]{8})\b",
                SecretTokenSpec { provider: "Grafana Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b",
                SecretTokenSpec { provider: "Postman API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(hv[sb]\.[0-9A-Za-z_-]{24,})\b",
                SecretTokenSpec { provider: "HashiCorp Vault Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b([0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,})\b",
                SecretTokenSpec { provider: "Terraform Cloud Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 23, min_entropy: 3.3, requires_keyword: None },
            ),
            (
                r"\b(shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32})\b",
                SecretTokenSpec { provider: "Shopify Access Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 6, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(sq0(?:atp|csp)-[0-9A-Za-z_-]{22,})\b",
                SecretTokenSpec { provider: "Square API Secret", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b",
                SecretTokenSpec { provider: "Age Private Key", rule_id: "SMG-SEC-KEY", severity: "CRITICAL", prefix_skip: 16, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(tskey-(?:auth|api|client)-[0-9A-Za-z-]{16,})\b",
                SecretTokenSpec { provider: "Tailscale Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 10, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(pul-[0-9a-f]{40})\b",
                SecretTokenSpec { provider: "Pulumi Access Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(figd_[0-9A-Za-z_-]{35,})\b",
                SecretTokenSpec { provider: "Figma Access Token", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(ntn_[0-9A-Za-z]{40,})\b",
                SecretTokenSpec { provider: "Notion Integration Token", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(sntrys_eyJ[0-9A-Za-z+/=_-]{30,}|sntryu_[0-9a-f]{64})\b",
                SecretTokenSpec { provider: "Sentry Auth Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(vcp_[0-9A-Za-z]{20,})\b",
                SecretTokenSpec { provider: "Vercel Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(SK[0-9a-f]{32})\b",
                SecretTokenSpec { provider: "Twilio API Secret", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 2, min_entropy: 2.9, requires_keyword: Some("twilio") },
            ),
            (
                r"\b(sk-or-v1-[0-9a-f]{48,})\b",
                SecretTokenSpec { provider: "OpenRouter API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 9, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(fw_[0-9A-Za-z]{24,})\b",
                SecretTokenSpec { provider: "Fireworks AI Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(re_[0-9A-Za-z]{24,})\b",
                SecretTokenSpec { provider: "Resend API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.1, requires_keyword: Some("resend") },
            ),
            (
                r"\b(dckr_pat_[0-9A-Za-z_-]{20,})\b",
                SecretTokenSpec { provider: "Docker Hub PAT", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 9, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(oy2[a-z0-9]{43})\b",
                SecretTokenSpec { provider: "NuGet API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.1, requires_keyword: Some("nuget") },
            ),
            (
                r"\b(cio[0-9A-Za-z]{28,})\b",
                SecretTokenSpec { provider: "Crates.io API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(fo1_[0-9A-Za-z_-]{24,})\b",
                SecretTokenSpec { provider: "Fly.io Deploy Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(napi_[0-9A-Za-z]{40,})\b",
                SecretTokenSpec { provider: "Neon API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(nfp_[0-9A-Za-z]{32,})\b",
                SecretTokenSpec { provider: "Netlify Access Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(rnd_[0-9A-Za-z]{24,})\b",
                SecretTokenSpec { provider: "Render API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(NRAK-[0-9A-Z]{27})\b",
                SecretTokenSpec { provider: "New Relic User Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
                SecretTokenSpec { provider: "Mailchimp API Key", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 0, min_entropy: 2.9, requires_keyword: Some("mailchimp") },
            ),
            (
                r"\b(xoxe\.xoxp-[0-9A-Za-z-]{24,}|xoxe-[0-9]-[0-9A-Za-z]{30,})\b",
                SecretTokenSpec { provider: "Slack Refresh Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b([0-9]{8,12}:AA[0-9A-Za-z_-]{33})\b",
                SecretTokenSpec { provider: "Telegram Bot Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 12, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b",
                SecretTokenSpec { provider: "Airtable Personal Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(sk\.eyJ[0-9A-Za-z_-]{30,}\.[0-9A-Za-z_-]{15,})\b",
                SecretTokenSpec { provider: "Mapbox Secret Token", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 6, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(sq[pau]_[0-9a-f]{40})\b",
                SecretTokenSpec { provider: "SonarQube / SonarCloud Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(dt0c01\.[0-9A-Z]{24}\.[0-9A-Z]{64})\b",
                SecretTokenSpec { provider: "Dynatrace API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(bkua_[0-9a-f]{40})\b",
                SecretTokenSpec { provider: "Buildkite Agent Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(rdme_[0-9a-f]{64})\b",
                SecretTokenSpec { provider: "ReadMe API Key", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 5, min_entropy: 2.9, requires_keyword: None },
            ),
            (
                r"\b(ATBB[0-9A-Za-z]{28,})\b",
                SecretTokenSpec { provider: "Bitbucket App Password", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(ATATT3xFfGF0[0-9A-Za-z_-]{40,})\b",
                SecretTokenSpec { provider: "Atlassian API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 12, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(LTAI[0-9A-Za-z]{16,})\b",
                SecretTokenSpec { provider: "Alibaba Cloud AccessKey ID", rule_id: "SMG-SEC-AWS", severity: "HIGH", prefix_skip: 4, min_entropy: 3.0, requires_keyword: Some("alibaba") },
            ),
            (
                r"\b(AccountKey=[0-9A-Za-z+/=]{60,}==)\b",
                SecretTokenSpec { provider: "Azure Storage Account Key", rule_id: "SMG-SEC-KEY", severity: "CRITICAL", prefix_skip: 11, min_entropy: 3.4, requires_keyword: None },
            ),
            (
                r"(sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&[^&\s]*sig=[0-9A-Za-z%+/=]{24,})",
                SecretTokenSpec { provider: "Azure SAS Signature URL", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 18, min_entropy: 3.2, requires_keyword: None },
            ),
            (
                r"\b(key-[0-9a-f]{32})\b",
                SecretTokenSpec { provider: "Mailgun API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 4, min_entropy: 2.9, requires_keyword: Some("mailgun") },
            ),
            (
                r"\b(secret_[0-9A-Za-z]{40,})\b",
                SecretTokenSpec { provider: "Notion / Service Integration Secret", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: Some("notion") },
            ),
            (
                r"\b(sdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
                SecretTokenSpec { provider: "LaunchDarkly SDK Key", rule_id: "SMG-SEC-APIKEY", severity: "HIGH", prefix_skip: 4, min_entropy: 2.9, requires_keyword: Some("launchdarkly") },
            ),
            (
                r"\b(access_token\$production\$[0-9a-z]{12,}\$[0-9a-f]{32})\b",
                SecretTokenSpec { provider: "PayPal Production Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 24, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(sk_[0-9a-f]{48})\b",
                SecretTokenSpec { provider: "ElevenLabs API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 3.0, requires_keyword: Some("eleven") },
            ),
            (
                r"\b(sk-[0-9a-f]{32})\b",
                SecretTokenSpec { provider: "DeepSeek API Key", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 3, min_entropy: 2.9, requires_keyword: Some("deepseek") },
            ),
            (
                r"\b(00[0-9A-Za-z_-]{40})\b",
                SecretTokenSpec { provider: "Okta API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 2, min_entropy: 3.2, requires_keyword: Some("okta") },
            ),
            (
                r"\b(dop_v1_[0-9a-f]{64}|doo_v1_[0-9a-f]{64}|dor_v1_[0-9a-f]{64})\b",
                SecretTokenSpec { provider: "DigitalOcean v1 Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(ya29\.[0-9A-Za-z_-]{50,})\b",
                SecretTokenSpec { provider: "Google OAuth2 Access Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.4, requires_keyword: None },
            ),
            (
                r"\b(r_live_[0-9A-Za-z]{20,})\b",
                SecretTokenSpec { provider: "Razorpay / Live Payment Key", rule_id: "SMG-SEC-STRIPE", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(rzp_live_[0-9A-Za-z]{14,})\b",
                SecretTokenSpec { provider: "Razorpay Live Key", rule_id: "SMG-SEC-STRIPE", severity: "CRITICAL", prefix_skip: 9, min_entropy: 3.0, requires_keyword: None },
            ),
            (
                r"\b(gph_[0-9A-Za-z]{36,})\b",
                SecretTokenSpec { provider: "GitHub Enterprise Token", rule_id: "SMG-SEC-GITHUB", severity: "CRITICAL", prefix_skip: 4, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(sbp_v0_[0-9A-Za-z]{32,})\b",
                SecretTokenSpec { provider: "Supabase Management Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 7, min_entropy: 3.1, requires_keyword: None },
            ),
            (
                r"\b(cfat_[0-9A-Za-z_-]{32,}|v1\.0-[0-9a-f]{24}-[0-9a-f]{120,})\b",
                SecretTokenSpec { provider: "Cloudflare / Cloud API Token", rule_id: "SMG-SEC-APIKEY", severity: "CRITICAL", prefix_skip: 5, min_entropy: 3.1, requires_keyword: None },
            ),
        ];

        let patterns: Vec<&str> = defs.iter().map(|(p, _)| *p).collect();
        let set = RegexSet::new(&patterns).expect("valid secret_token_pack RegexSet");
        let compiled = defs
            .iter()
            .map(|(p, spec)| (*spec, Regex::new(p).expect("valid secret_token_pack Regex")))
            .collect();
        (set, compiled)
    })
}

fn private_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"-----BEGIN (?:(?:RSA|EC|OPENSSH|PGP|DSA|ENCRYPTED) ?)?PRIVATE KEY(?: BLOCK)?-----",
        )
        .expect("valid pem regex")
    })
}

fn db_uri_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://([^:\s"'`<>@/]+):([^@\s"'`<>]+)@([^\s"'`<>]+)"#,
        )
        .expect("valid db uri regex")
    })
}

fn client_secret_env_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b((?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE(?:_KEY)?|DATABASE_URL|DB_PASSWORD|JWT_SECRET|ENCRYPTION_KEY|MASTER_KEY)[A-Z0-9_]*)\b"#,
        )
        .expect("valid client secret env regex")
    })
}

fn jwt_js_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:jwt|jsonwebtoken)\.sign\s*\([^;\n]+?,\s*(?:"([^"\n]{4,})"|'([^'\n]{4,})')"#,
        )
        .expect("valid jwt js regex")
    })
}

fn jwt_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.SignedString\s*\(\s*\[\]\s*byte\s*\(\s*["`]([^"`\n]{4,})["`]\s*\)\s*\)"#)
            .expect("valid jwt go regex")
    })
}

fn jwt_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bjwt\.encode\s*\([^;\n]+?,\s*(?:"([^"\n]{4,})"|'([^'\n]{4,})')"#)
            .expect("valid jwt py regex")
    })
}

fn jwt_rs_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"EncodingKey::from_secret\s*\(\s*b"([^"\n]{4,})"\s*\)"#)
            .expect("valid jwt rs regex")
    })
}

fn cors_header_wildcard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)access-control-allow-origin['"]?\s*[:,=]\s*['"]?\*['"]?"#)
            .expect("valid cors header regex")
    })
}

fn cors_origin_wildcard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:origin\s*[:=]\s*['"]\*['"]|origins\s*[:=]\s*\[\s*['"]\*['"]\s*\]|allow_origins\s*[:=]\s*\[\s*['"]\*['"]\s*\]|AllowAllOrigins\s*:\s*true)"#,
        )
        .expect("valid cors origin regex")
    })
}

fn cors_credentials_true_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:credentials\s*[:=]\s*true|supports_credentials\s*[:=]\s*true|allow_credentials\s*[:=]\s*true|AllowCredentials\s*:\s*true)"#,
        )
        .expect("valid cors credentials regex")
    })
}

fn tls_disabled_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b|danger_accept_invalid_certs\s*\(\s*true\s*\))"#,
        )
        .expect("valid tls regex")
    })
}

fn insecure_cookie_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:httpOnly|httponly|secure)\s*[:=]\s*false\b"#)
            .expect("valid cookie regex")
    })
}

fn weak_hash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|\b(?:md5|sha1)\.(?:New|Sum)\s*\()"#,
        )
        .expect("valid weak hash regex")
    })
}

fn weak_prng_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:\bMath\.random\s*\(\s*\)|\brand\.Intn\s*\(|\brandom\.(?:random|randint|choice)\s*\()"#,
        )
        .expect("valid weak prng regex")
    })
}

fn debug_mode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?:(?:^|[\s,{;])DEBUG\s*=\s*(?:True|true)\b|\bapp\.debug\s*=\s*(?:True|true)\b|\.run\s*\([^)\n]*\bdebug\s*=\s*True\b|\bgin\.SetMode\s*\(\s*gin\.DebugMode\s*\))"#,
        )
        .expect("valid debug regex")
    })
}

fn docker_privileged_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*privileged\s*:\s*true\b").expect("valid docker priv re"))
}

fn docker_user_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*USER\s+(\S+)").expect("valid docker user re"))
}

fn docker_from_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*FROM\s+(\S+)").expect("valid docker from re"))
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u8, usize> = HashMap::new();
    let bytes = s.as_bytes();
    for &b in bytes {
        *counts.entry(b).or_insert(0) += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for count in counts.values() {
        let p = (*count as f64) / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn is_placeholder_secret(val: &str) -> bool {
    let low = val.trim().to_ascii_lowercase();
    if low.is_empty() {
        return true;
    }
    if low.contains("${") || low.contains("{{") || low.contains("<your") || low.contains("%s") {
        return true;
    }
    const MARKERS: &[&str] = &[
        "your-",
        "your_",
        "example",
        "placeholder",
        "changeme",
        "change_me",
        "replace_me",
        "replace-me",
        "dummy",
        "sample",
        "xxxx",
        "****",
        "insert_",
        "ci-pass",
        "ci_pass",
        "test-pass",
        "test_pass",
        "testpass",
        "dev-pass",
        "dev_pass",
        "devpass",
        "localdev",
        "local-dev",
        "local_dev",
        "not-a-secret",
        "not_a_secret",
        "redacted",
        "fake-",
        "fake_",
        "mock-",
        "mock_",
    ];
    if MARKERS.iter().any(|m| low.contains(m)) {
        return true;
    }
    matches!(
        low.as_str(),
        "password"
            | "pass"
            | "pwd"
            | "secret"
            | "token"
            | "api-key"
            | "apikey"
            | "root"
            | "123456"
            | "cipass"
            | "localpass"
            | "local-pass"
            | "docker"
            | "postgres"
            | "mysql"
            | "mariadb"
            | "mongodb"
            | "redis"
            | "test123"
            | "test1234"
            | "pass123"
            | "password123"
            | "secret123"
            | "qwerty"
            | "letmein"
            | "fixture"
            | "mock"
            | "testing"
            | "test"
    )
}

fn line_has_sops_ciphertext(line: &str) -> bool {
    if !line.contains("ENC[") {
        return false;
    }
    const SOPS_MODES: &[&str] = &[
        "AES256_GCM,",
        "AGE,",
        "PGP,",
        "KMS,",
        "GCP_KMS,",
        "AZURE_KV,",
        "HASHICORP_VAULT,",
    ];
    SOPS_MODES.iter().any(|m| line.contains(m))
}

pub fn is_sops_encrypted_content(content: &str) -> bool {
    if !line_has_sops_ciphertext(content) {
        return false;
    }
    content.contains("\nsops:")
        || content.starts_with("sops:")
        || content.contains("\"sops\":")
        || content.contains("sops_mac=")
        || content.contains("sops_version=")
}

fn is_ci_or_compose_or_test_path(rel_path: &str) -> bool {
    if smg_core::is_test_source_path(rel_path) {
        return true;
    }
    let low = rel_path.replace('\\', "/").to_ascii_lowercase();
    let fname = low.rsplit('/').next().unwrap_or(&low);
    low.contains(".github/workflows/")
        || low.contains(".gitlab-ci")
        || low.contains(".circleci/")
        || low.contains("/testdata/")
        || low.contains("/fixtures/")
        || low.contains("/mocks/")
        || low.contains("/e2e/")
        || fname.contains("docker-compose")
        || fname == "compose.yml"
        || fname == "compose.yaml"
        || fname == "makefile"
        || fname == "justfile"
        || fname.starts_with("taskfile.")
}

fn is_loopback_or_service_host(host_port_path: &str) -> bool {
    let authority = host_port_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
    .to_ascii_lowercase();
    matches!(
        host.as_str(),
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "::1"
            | "postgres"
            | "postgresql"
            | "pg"
            | "mysql"
            | "mariadb"
            | "redis"
            | "mongo"
            | "mongodb"
            | "db"
            | "database"
            | "cache"
            | "test-db"
            | "db-test"
            | "host.docker.internal"
    ) || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".test")
}

fn redact_token(tok: &str) -> String {
    let chars: Vec<char> = tok.chars().collect();
    if chars.len() <= 10 {
        return "***".to_string();
    }
    let prefix: String = chars.iter().take(6).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{}...{}", prefix, suffix)
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
}

fn has_context_keyword(lines: &[&str], idx: usize, radius: usize, keywords: &[&str]) -> bool {
    let start = idx.saturating_sub(radius);
    let end = (idx + radius + 1).min(lines.len());
    for line in &lines[start..end] {
        let low = line.to_ascii_lowercase();
        if keywords.iter().any(|k| low.contains(k)) {
            return true;
        }
    }
    false
}

fn is_dockerfile(rel_path: &str) -> bool {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let low = fname.to_ascii_lowercase();
    low == "dockerfile" || low.starts_with("dockerfile.") || low.ends_with(".dockerfile")
}

fn is_yaml_file(rel_path: &str) -> bool {
    let low = rel_path.to_ascii_lowercase();
    low.ends_with(".yml") || low.ends_with(".yaml")
}

pub fn is_sensitive_env_or_pem(rel_path: &str) -> bool {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let low = fname.to_ascii_lowercase();
    if low == ".env"
        || (low.starts_with(".env.")
            && !matches!(
                low.as_str(),
                ".env.example" | ".env.sample" | ".env.template" | ".env.dist"
            ))
    {
        return true;
    }
    if matches!(
        low.as_str(),
        "cacert.pem" | "ca-bundle.pem" | "ca-certificates.pem" | "public.pem" | "pubkey.pem"
    ) {
        return false;
    }
    low.ends_with(".pem")
}

/// Content-aware check for committed `.env*` / `.pem` artifacts:
/// exempts public X.509 certificates/public keys/CSRs and fully SOPS-encrypted files.
pub fn is_sensitive_env_or_pem_with_content(rel_path: &str, content: &str) -> bool {
    if !is_sensitive_env_or_pem(rel_path) {
        return false;
    }
    let low = rel_path.to_ascii_lowercase();
    if low.ends_with(".pem") {
        let has_private_key = content.contains("PRIVATE KEY");
        let is_public_cert_only = content.contains("-----BEGIN ")
            && !has_private_key
            && (content.contains("-----BEGIN CERTIFICATE-----")
                || content.contains("-----BEGIN X509 CRL-----")
                || content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
                || content.contains("-----BEGIN PUBLIC KEY-----")
                || content.contains("-----BEGIN RSA PUBLIC KEY-----")
                || content.contains("-----BEGIN EC PUBLIC KEY-----")
                || content.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        if is_public_cert_only {
            return false;
        }
        if is_sops_encrypted_content(content) {
            return false;
        }
    }
    if is_sops_encrypted_content(content) {
        let all_encrypted = content.lines().all(|l| {
            let t = l.trim();
            t.is_empty()
                || t.starts_with('#')
                || t.starts_with("sops_")
                || t == "sops:"
                || line_has_sops_ciphertext(t)
        });
        if all_encrypted {
            return false;
        }
    }
    true
}

fn make_sec_finding(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    remediation: &str,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line,
        symbol: format!("{}:{}", rel_path, line),
        sink_kind: SinkKind::SecretLeak,
        missing_guard: GuardKind::SecretPolicy,
        confidence: if rule_id == "SMG-SEC-ENTROPY" {
            Confidence::Heuristic
        } else {
            Confidence::Confirmed
        },
        remediation: remediation.to_string(),
    }
}

fn make_cfg_finding(
    rule_id: &str,
    severity: &str,
    title: String,
    rel_path: &str,
    line: usize,
    remediation: &str,
) -> LocalStaticFinding {
    LocalStaticFinding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        title,
        rel_path: rel_path.to_string(),
        line,
        symbol: format!("{}:{}", rel_path, line),
        sink_kind: SinkKind::Misconfiguration,
        missing_guard: GuardKind::ConfigPolicy,
        confidence: if rule_id == "SMG-CFG-DEBUG" {
            Confidence::Heuristic
        } else {
            Confidence::Confirmed
        },
        remediation: remediation.to_string(),
    }
}

/// Scans a single file's content in-memory (zero disk I/O) for hardcoded secrets and security misconfigurations.
pub fn scan_secrets_and_config(rel_path: &str, content: &str) -> Vec<LocalStaticFinding> {
    let fname = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if matches!(fname, "package-lock.json" | "Cargo.lock" | ".gitignore")
        || matches!(
            fname,
            ".env.example" | ".env.sample" | ".env.template" | ".env.dist"
        )
    {
        return Vec::new();
    }

    let is_rust = rel_path.ends_with(".rs");
    let is_docker = is_dockerfile(rel_path);
    let is_yaml = is_yaml_file(rel_path);
    let is_ci_or_test = is_ci_or_compose_or_test_path(rel_path);
    let is_sops_file = is_sops_encrypted_content(content);
    let mut in_sops_meta = false;
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    // Pre-scan Rust test module start so #[cfg(test)] blocks don't emit test-fixture false positives
    let mut in_cfg_test = false;
    let mut test_brace_depth: i32 = 0;
    let mut test_saw_open_brace = false;

    // Track CORS wildcard origins and credentials lines for block-level pairing
    let mut cors_origin_lines: Vec<usize> = Vec::new();
    let mut cors_cred_lines: Vec<usize> = Vec::new();

    // Track Dockerfile FROM / USER instructions
    let mut docker_from_line: Option<usize> = None;
    let mut docker_root_lines: Vec<usize> = Vec::new();
    let mut docker_last_non_root_line: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();

        if is_rust {
            if trimmed.starts_with("#[cfg(test)]") {
                in_cfg_test = true;
                test_brace_depth = 0;
                test_saw_open_brace = false;
            }
            if in_cfg_test {
                let mut in_str = false;
                let mut escaped = false;
                for ch in line.chars() {
                    if in_str {
                        if escaped {
                            escaped = false;
                        } else if ch == '\\' {
                            escaped = true;
                        } else if ch == '"' {
                            in_str = false;
                        }
                        continue;
                    }
                    if ch == '"' {
                        in_str = true;
                    } else if ch == '{' {
                        test_brace_depth += 1;
                        test_saw_open_brace = true;
                    } else if ch == '}' {
                        test_brace_depth -= 1;
                        if test_saw_open_brace && test_brace_depth <= 0 {
                            in_cfg_test = false;
                            break;
                        }
                    }
                }
                if !test_saw_open_brace
                    && !trimmed.starts_with("#[")
                    && !trimmed.is_empty()
                    && trimmed.ends_with(';')
                {
                    in_cfg_test = false;
                }
                continue;
            }
        }

        // Skip SOPS encrypted ciphertext values & SOPS metadata footer (`sops:` block)
        if is_sops_file {
            if trimmed == "sops:" || trimmed == "\"sops\": {" || trimmed.starts_with("sops_mac=") {
                in_sops_meta = true;
                continue;
            }
            if in_sops_meta {
                if !line.starts_with(' ')
                    && !line.starts_with('\t')
                    && !trimmed.starts_with('}')
                    && !trimmed.starts_with("sops_")
                {
                    in_sops_meta = false;
                } else {
                    continue;
                }
            }
            if line_has_sops_ciphertext(line) {
                continue;
            }
        } else if line_has_sops_ciphertext(line) {
            continue;
        }

        // Skip regex pattern literals & Rust rule-catalog documentation examples
        if trimmed.contains("Regex::new(")
            || trimmed.contains("RegexSet::new(")
            || trimmed.starts_with("r\"")
            || trimmed.starts_with("r#\"")
            || (is_rust
                && (trimmed.starts_with("vulnerable_example:")
                    || trimmed.starts_with("fixed_example:")
                    || trimmed.starts_with("remediation:")))
        {
            continue;
        }

        // --- Layer 1a: Secrets & Credential Leak Rules (SMG-SEC-*) ---
        if line.contains("AKIA")
            || line.contains("ASIA")
            || line.contains("ABIA")
            || line.contains("ACCA")
        {
            for cap in aws_key_re().captures_iter(line) {
                let tok = &cap[1];
                let suffix = &tok[4..];
                if !is_placeholder_secret(tok) && shannon_entropy(suffix) >= 2.5 {
                    findings.push(make_sec_finding(
                        "SMG-SEC-AWS",
                        "CRITICAL",
                        format!("Hardcoded AWS Access Key ID ({})", redact_token(tok)),
                        rel_path,
                        ln,
                        "Remove the hardcoded AWS access key, rotate it in IAM immediately, and load credentials via IAM roles or environment variables.",
                    ));
                }
            }
        }

        if line.contains("sk_live_") || line.contains("rk_live_") || line.contains("whsec_") {
            for cap in stripe_key_re().captures_iter(line) {
                let tok = &cap[1];
                let suffix = tok
                    .strip_prefix("sk_live_")
                    .or_else(|| tok.strip_prefix("rk_live_"))
                    .or_else(|| tok.strip_prefix("whsec_"))
                    .unwrap_or(tok);
                if !is_placeholder_secret(suffix) && shannon_entropy(suffix) >= 2.5 {
                    findings.push(make_sec_finding(
                        "SMG-SEC-STRIPE",
                        "CRITICAL",
                        format!("Hardcoded Stripe live/webhook secret ({})", redact_token(tok)),
                        rel_path,
                        ln,
                        "Revoke and roll the Stripe secret key/webhook secret in the Stripe Dashboard and read it from `process.env.STRIPE_SECRET_KEY` / a secret manager.",
                    ));
                }
            }
        }

        if line.contains("ghp_")
            || line.contains("gho_")
            || line.contains("ghu_")
            || line.contains("ghs_")
            || line.contains("ghr_")
            || line.contains("github_pat_")
        {
            for cap in github_pat_re().captures_iter(line) {
                let tok = &cap[1];
                let suffix = tok
                    .strip_prefix("github_pat_")
                    .or_else(|| tok.get(4..))
                    .unwrap_or(tok);
                if !is_placeholder_secret(suffix) && shannon_entropy(suffix) >= 2.5 {
                    findings.push(make_sec_finding(
                        "SMG-SEC-GITHUB",
                        "CRITICAL",
                        format!("Hardcoded GitHub Access Token ({})", redact_token(tok)),
                        rel_path,
                        ln,
                        "Revoke the GitHub token immediately and inject credentials via CI/runtime secrets or `GITHUB_TOKEN`.",
                    ));
                }
            }
        }

        let (pack_set, pack_specs) = secret_token_pack();
        let pack_matches = pack_set.matches(line);
        if pack_matches.matched_any() {
            for pat_idx in pack_matches.iter() {
                let (spec, re) = &pack_specs[pat_idx];
                if let Some(kw) = spec.requires_keyword
                    && !has_context_keyword(&lines, idx, 2, &[kw])
                {
                    continue;
                }
                for cap in re.captures_iter(line) {
                    let tok = &cap[1];
                    let suffix = tok.get(spec.prefix_skip..).unwrap_or(tok);
                    if !is_placeholder_secret(tok)
                        && !is_placeholder_secret(suffix)
                        && shannon_entropy(suffix) >= spec.min_entropy
                    {
                        findings.push(make_sec_finding(
                            spec.rule_id,
                            spec.severity,
                            format!("Hardcoded {} ({})", spec.provider, redact_token(tok)),
                            rel_path,
                            ln,
                            "Revoke the leaked API token immediately and load secrets from environment variables or a secret manager.",
                        ));
                    }
                }
            }
        }

        if line.contains("-----BEGIN ") && private_key_re().is_match(line) {
            findings.push(make_sec_finding(
                "SMG-SEC-KEY",
                "CRITICAL",
                "Committed private cryptographic key block".into(),
                rel_path,
                ln,
                "Remove the private key file/block from source control, rotate the keypair, and mount keys via a secret store at runtime.",
            ));
        }

        if line.contains("://") && line.contains('@') {
            for cap in db_uri_re().captures_iter(line) {
                let pass = &cap[2];
                let host_port_path = &cap[3];
                let is_local_host = is_loopback_or_service_host(host_port_path);
                if is_placeholder_secret(pass) || (is_ci_or_test && is_local_host) {
                    continue;
                }
                if shannon_entropy(pass) >= 2.2 {
                    let mut f = make_sec_finding(
                        "SMG-SEC-DBURI",
                        if is_local_host { "MEDIUM" } else { "HIGH" },
                        "Hardcoded database URI with embedded credentials".into(),
                        rel_path,
                        ln,
                        "Move the database connection string to an environment variable (e.g., `DATABASE_URL`) and rotate the database password.",
                    );
                    if is_local_host {
                        f.confidence = Confidence::Heuristic;
                    }
                    findings.push(f);
                }
            }
        }

        let check_jwt_literal = |secret: &str, findings: &mut Vec<LocalStaticFinding>| {
            let low_sec = secret.trim().to_ascii_lowercase();
            let weak_jwt_default = matches!(
                low_sec.as_str(),
                "secret"
                    | "mysecret"
                    | "jwtsecret"
                    | "jwt-secret"
                    | "changeme"
                    | "password"
                    | "dev-secret"
                    | "123456"
                    | "supersecret"
            );
            if weak_jwt_default {
                findings.push(make_cfg_finding(
                    "SMG-CFG-JWT-LOGIC",
                    "CRITICAL",
                    "JWT signs tokens with a weak predictable hardcoded secret literal".into(),
                    rel_path,
                    ln,
                    "Replace weak hardcoded JWT secrets with a high-entropy 256-bit key loaded from environment/KMS.",
                ));
            } else if secret.len() >= 6
                && !is_placeholder_secret(secret)
                && shannon_entropy(secret) >= 2.2
            {
                findings.push(make_sec_finding(
                    "SMG-SEC-JWT",
                    "HIGH",
                    "Hardcoded JWT signing secret literal".into(),
                    rel_path,
                    ln,
                    "Load the JWT signing key from a high-entropy environment secret (`process.env.JWT_SECRET` / `os.Getenv(\"JWT_SECRET\")`) or asymmetric KMS/JWKS.",
                ));
            }
        };

        if line.contains(".sign(") || line.contains(".sign (") {
            let lines_vec: Vec<&str> = content.lines().collect();
            let window = lines_vec[idx..lines_vec.len().min(idx + 4)].join(" ");
            for cap in jwt_js_re().captures_iter(&window) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(2)) {
                    check_jwt_literal(m.as_str(), &mut findings);
                }
            }
        }
        if line.contains("SignedString") {
            for cap in jwt_go_re().captures_iter(line) {
                check_jwt_literal(&cap[1], &mut findings);
            }
        }
        if line.contains("jwt.encode") {
            for cap in jwt_py_re().captures_iter(line) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(2)) {
                    check_jwt_literal(m.as_str(), &mut findings);
                }
            }
        }
        if line.contains("from_secret") {
            for cap in jwt_rs_re().captures_iter(line) {
                check_jwt_literal(&cap[1], &mut findings);
            }
        }

        // Skip comment lines and Rust catalog metadata descriptions for misconfiguration checks
        if is_comment_line(trimmed)
            || (is_rust && (trimmed.starts_with("title:") || trimmed.starts_with("description:")))
        {
            continue;
        }

        // Public browser-bundle env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`) exposing private secrets
        if !is_rust
            && (line.contains("NEXT_PUBLIC_")
                || line.contains("VITE_")
                || line.contains("REACT_APP_")
                || line.contains("NUXT_PUBLIC_"))
            && let Some(cap) = client_secret_env_re().captures(line)
        {
            findings.push(make_sec_finding(
                "SMG-SEC-CLIENT-ENV",
                "CRITICAL",
                format!(
                    "Client-exposed frontend env variable `{}` leaks server secret into browser bundle",
                    &cap[1]
                ),
                rel_path,
                ln,
                "Remove the public browser prefix (`NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`) and keep secrets strictly server-side.",
            ));
        }

        // --- Layer 1b: Security Misconfiguration Rules (SMG-CFG-*) ---
        if line
            .to_ascii_lowercase()
            .contains("access-control-allow-origin")
            && !line.contains("`Access-Control-Allow-Origin")
            && cors_header_wildcard_re().is_match(line)
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-CORS",
                "HIGH",
                "Wildcard CORS header (Access-Control-Allow-Origin set to wildcard) allows arbitrary origins"
                    .into(),
                rel_path,
                ln,
                "Restrict CORS `Access-Control-Allow-Origin` to an explicit allowlist of trusted origins.",
            ));
        }

        if cors_origin_wildcard_re().is_match(line) {
            cors_origin_lines.push(ln);
        }
        if cors_credentials_true_re().is_match(line) {
            cors_cred_lines.push(ln);
        }

        if !crate::taint::is_pattern_matcher_or_doc_line(line)
            && (line.contains("rejectUnauthorized")
                || line.contains("InsecureSkipVerify")
                || line.contains("verify")
                || line.contains("NODE_TLS_REJECT_UNAUTHORIZED")
                || line.contains("danger_accept_invalid_certs"))
            && tls_disabled_re().is_match(line)
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-TLS",
                "HIGH",
                "TLS certificate verification disabled (MITM vulnerability)".into(),
                rel_path,
                ln,
                "Re-enable TLS certificate validation and configure trusted CA certificates instead of bypassing verification.",
            ));
        }

        if (line.to_ascii_lowercase().contains("httponly")
            || line.to_ascii_lowercase().contains("secure"))
            && !line.contains("`httpOnly")
            && !line.contains("`secure")
            && insecure_cookie_re().is_match(line)
            && has_context_keyword(
                &lines,
                idx,
                8,
                &[
                    "cookie",
                    "session",
                    "auth",
                    "token",
                    "jwt",
                    "sid",
                    "set-cookie",
                    "res.cookie",
                ],
            )
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-COOKIE",
                "MEDIUM",
                "Insecure session/auth cookie flag (httpOnly or secure disabled)".into(),
                rel_path,
                ln,
                "Set `httpOnly: true`, `secure: true`, and `sameSite: 'lax' | 'strict'` on session and authentication cookies.",
            ));
        }

        if weak_hash_re().is_match(line)
            && has_context_keyword(
                &lines,
                idx,
                5,
                &[
                    "password",
                    "passwd",
                    "pwd",
                    "pw",
                    "token",
                    "secret",
                    "auth",
                    "session",
                    "hmac",
                    "sign",
                    "credential",
                    "salt",
                    "login",
                ],
            )
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-CRYPTO",
                "HIGH",
                "Weak cryptographic hash (MD5/SHA1) used for password, token, or auth material"
                    .into(),
                rel_path,
                ln,
                "Replace MD5/SHA1 with Argon2id/bcrypt/scrypt for passwords or SHA-256/HMAC-SHA256 for tokens.",
            ));
        } else if weak_prng_re().is_match(line)
            && has_context_keyword(
                &lines,
                idx,
                4,
                &[
                    "token", "secret", "key", "password", "salt", "nonce", "otp", "csrf",
                    "session", "auth", "reset", "api_key", "apikey", "pin",
                ],
            )
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-CRYPTO",
                "HIGH",
                "Non-cryptographic PRNG (`Math.random` / `rand.Intn`) used for security token"
                    .into(),
                rel_path,
                ln,
                "Use a CSPRNG (`crypto.randomBytes` / `crypto.randomUUID` / `crypto/rand` / `secrets.token_urlsafe`).",
            ));
        }

        if (line.contains("DEBUG") || line.contains("debug")) && debug_mode_re().is_match(line) {
            findings.push(make_cfg_finding(
                "SMG-CFG-DEBUG",
                "MEDIUM",
                "Debug mode enabled in application/config (stack traces & info exposure risk)"
                    .into(),
                rel_path,
                ln,
                "Disable debug mode in production configurations (`DEBUG = False`, `gin.ReleaseMode`) and gate via environment variables.",
            ));
        }

        if is_yaml && docker_privileged_re().is_match(line) {
            findings.push(make_cfg_finding(
                "SMG-CFG-DOCKER",
                "HIGH",
                "Container configured with `privileged: true` (host escape risk)".into(),
                rel_path,
                ln,
                "Remove `privileged: true` and grant only minimal required Linux capabilities via `cap_add`.",
            ));
        }

        if is_docker {
            if let Some(cap) = docker_from_re().captures(line) {
                let img = cap[1].trim().to_ascii_lowercase();
                docker_root_lines.clear();
                docker_last_non_root_line = None;
                if img != "scratch" && !img.ends_with(":nonroot") && !img.ends_with("-nonroot") {
                    docker_from_line = Some(ln);
                } else {
                    docker_from_line = None;
                }
            }
            if let Some(cap) = docker_user_re().captures(line) {
                let user = cap[1].trim().to_ascii_lowercase();
                if user == "root" || user == "0" || user.starts_with("root:") {
                    docker_root_lines.push(ln);
                } else {
                    docker_last_non_root_line = Some(ln);
                }
            }
        }
    }

    // Emit SMG-CFG-CORS for `origin: "*"` paired with `credentials: true` within 15 lines
    for &orig_ln in &cors_origin_lines {
        if cors_cred_lines
            .iter()
            .any(|&cred_ln| orig_ln.abs_diff(cred_ln) <= 15)
        {
            findings.push(make_cfg_finding(
                "SMG-CFG-CORS",
                "HIGH",
                "Wildcard CORS (`origin: \"*\"`) combined with `credentials: true`".into(),
                rel_path,
                orig_ln,
                "Specify explicit trusted origins instead of `*` when `credentials: true` is enabled.",
            ));
        }
    }

    // Emit SMG-CFG-DOCKER if Dockerfile sets `USER root` without dropping to a non-root USER afterwards,
    // or if Dockerfile has a non-scratch `FROM` stage without any non-root `USER` instruction.
    if let Some(&root_ln) = docker_root_lines.last() {
        let dropped_after = docker_last_non_root_line.is_some_and(|non_root| non_root > root_ln);
        if !dropped_after {
            findings.push(make_cfg_finding(
                "SMG-CFG-DOCKER",
                "MEDIUM",
                "Dockerfile runs as `USER root` without dropping to a non-root user".into(),
                rel_path,
                root_ln,
                "Add a non-root user (`RUN useradd ...` / `adduser ...`) and switch to it with `USER appuser` before `CMD`/`ENTRYPOINT`.",
            ));
        }
    } else if docker_last_non_root_line.is_none()
        && let Some(from_ln) = docker_from_line
    {
        findings.push(make_cfg_finding(
            "SMG-CFG-DOCKER",
            "MEDIUM",
            "Dockerfile is missing a non-root `USER` instruction (defaults to root)".into(),
            rel_path,
            from_ln,
            "Add a non-root user (`RUN useradd ...` / `adduser ...`) and switch to it with `USER appuser` before `CMD`/`ENTRYPOINT`.",
        ));
    }

    scan_jwt_logic_flaws(rel_path, content, is_rust, &mut findings);

    findings
}

fn jwt_alg_none_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:\b(?:alg|algorithm)\b\s*[:=]\s*["']none["']|\balgorithms\b\s*[:=]\s*\[[^\]]*["']none["']|\bSigningMethodNone\b|\bAlgorithm::None\b)"#,
        )
        .expect("valid jwt alg none regex")
    })
}

fn jwt_unverified_sig_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:\bverify\s*=\s*False\b|["']?verify_signature["']?\s*[:=]\s*(?:False|false)\b|\bParseUnverified\s*\(|\bdangerouslyDisableSignatureValidation\b|\bignoreSignature\s*[:=]\s*true\b)"#,
        )
        .expect("valid jwt verify false regex")
    })
}

fn scan_jwt_logic_flaws(
    rel_path: &str,
    content: &str,
    is_rust: bool,
    findings: &mut Vec<LocalStaticFinding>,
) {
    let low_path = rel_path.to_ascii_lowercase();
    let is_code = low_path.ends_with(".js")
        || low_path.ends_with(".mjs")
        || low_path.ends_with(".cjs")
        || low_path.ends_with(".ts")
        || low_path.ends_with(".tsx")
        || low_path.ends_with(".jsx")
        || low_path.ends_with(".py")
        || low_path.ends_with(".go")
        || low_path.ends_with(".rs")
        || low_path.ends_with(".php")
        || low_path.ends_with(".rb")
        || low_path.ends_with(".java")
        || low_path.ends_with(".kt")
        || low_path.ends_with(".cs");
    if !is_code {
        return;
    }

    let active_low =
        crate::taint::strip_comments_and_non_attr_strings(content).to_ascii_lowercase();
    let has_jwt_context = active_low.contains("jwt")
        || active_low.contains("jsonwebtoken")
        || active_low.contains("jose")
        || active_low.contains("pyjwt");
    let lines_vec: Vec<&str> = content.lines().collect();

    let mut in_cfg_test = false;
    let mut test_brace_depth: i32 = 0;
    let mut test_saw_open_brace = false;
    let mut in_decode_call = false;
    let mut decode_start_ln = 0usize;
    let mut decode_window_buf = String::new();
    let mut decode_lines_left = 0usize;

    for (idx, line) in lines_vec.iter().enumerate() {
        let ln = idx + 1;
        let trimmed = line.trim();

        if is_rust {
            if trimmed.starts_with("#[cfg(test)]") {
                in_cfg_test = true;
                test_brace_depth = 0;
                test_saw_open_brace = false;
            }
            if in_cfg_test {
                for ch in line.chars() {
                    if ch == '{' {
                        test_brace_depth += 1;
                        test_saw_open_brace = true;
                    } else if ch == '}' {
                        test_brace_depth -= 1;
                        if test_saw_open_brace && test_brace_depth <= 0 {
                            in_cfg_test = false;
                            break;
                        }
                    }
                }
                if !test_saw_open_brace && trimmed.ends_with(';') {
                    in_cfg_test = false;
                }
                continue;
            }
        }

        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }
        // Skip regex definition string literals inside source analyzers themselves
        if trimmed.contains("Regex::new(") || trimmed.starts_with("r#\"") {
            continue;
        }

        if has_jwt_context && jwt_alg_none_re().is_match(line) {
            findings.push(make_cfg_finding(
                "SMG-CFG-JWT-LOGIC",
                "CRITICAL",
                "JWT accepts insecure unsigned 'none' algorithm (signature bypass risk)".into(),
                rel_path,
                ln,
                "Reject unsigned 'none' JWT tokens and enforce an explicit asymmetric/HMAC algorithm allowlist (e.g., HS256 or RS256).",
            ));
        }

        if has_jwt_context && jwt_unverified_sig_re().is_match(line) {
            findings.push(make_cfg_finding(
                "SMG-CFG-JWT-LOGIC",
                "CRITICAL",
                "JWT verification disabled cryptographic signature validation".into(),
                rel_path,
                ln,
                "Enable cryptographic signature verification (`jwt.verify` with pinned algorithm list) before trusting JWT claims.",
            ));
        }

        // Track multi-line `jwt.decode(...)` calls in Python (`options={"verify_signature": False}`) or JS unverified decode scoped locally (~15 lines)
        if line.contains("jwt.decode(") {
            in_decode_call = true;
            decode_start_ln = ln;
            decode_window_buf.clear();
            decode_window_buf.push_str(line);
            decode_lines_left = 6;

            let lo = idx.saturating_sub(15);
            let hi = lines_vec.len().min(idx + 16);
            let local_has_js_verify = lines_vec[lo..hi].iter().any(|wl| {
                let low = wl.to_ascii_lowercase();
                low.contains("jwt.verify(")
                    || low.contains("jwtverify(")
                    || low.contains("jsonwebtoken.verify(")
            });

            if (low_path.ends_with(".js")
                || low_path.ends_with(".ts")
                || low_path.ends_with(".mjs")
                || low_path.ends_with(".cjs"))
                && !local_has_js_verify
                && !line.contains("complete: true")
            {
                let mut f = make_cfg_finding(
                    "SMG-CFG-JWT-LOGIC",
                    "HIGH",
                    "`jwt.decode()` decodes JWT payload without verifying signature (`jwt.verify()` missing)".into(),
                    rel_path,
                    ln,
                    "Replace `jwt.decode()` with `jwt.verify(token, secret, { algorithms: [...] })` before trusting token claims.",
                );
                f.confidence = Confidence::Heuristic;
                findings.push(f);
            }
        } else if in_decode_call && decode_lines_left > 0 {
            decode_lines_left -= 1;
            decode_window_buf.push(' ');
            decode_window_buf.push_str(trimmed);
            if jwt_unverified_sig_re().is_match(trimmed) {
                // Already emitted at `ln` above; close window to prevent duplicates
                in_decode_call = false;
            } else if trimmed.contains(')') {
                let _ = decode_start_ln;
                in_decode_call = false;
            }
        }
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_ignored_by_gitignore(rel_path: &str, gitignore_files: &[(&str, &[String])]) -> bool {
    let norm_path = rel_path.trim_start_matches("./").replace('\\', "/");
    let file_name = Path::new(&norm_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&norm_path);

    let mut ignored = false;
    for (gi_path, lines) in gitignore_files {
        let gi_dir = Path::new(gi_path)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let candidate_rel = if gi_dir.is_empty() {
            norm_path.as_str()
        } else if let Some(rest) = norm_path.strip_prefix(&format!("{}/", gi_dir)) {
            rest
        } else {
            continue;
        };

        for raw in *lines {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (negated, pat) = if let Some(rest) = trimmed.strip_prefix('!') {
                (true, rest.trim())
            } else {
                (false, trimmed)
            };
            let clean_pat = pat.trim_start_matches('/').trim_end_matches('/');
            let matched = if clean_pat.contains('/') {
                glob_match(clean_pat, candidate_rel)
            } else {
                glob_match(clean_pat, file_name) || glob_match(clean_pat, candidate_rel)
            };
            if matched {
                ignored = !negated;
            }
        }
    }
    ignored
}

/// Checks if `.env`, `.env.local`, `.env.*`, or `*.pem` files exist in the repository without being ignored by `.gitignore`.
pub fn check_gitignore_exposure(
    sensitive_files: &[&str],
    gitignore_files: &[(&str, &[String])],
) -> Vec<LocalStaticFinding> {
    let mut findings = Vec::new();
    for &rel_path in sensitive_files {
        if !is_ignored_by_gitignore(rel_path, gitignore_files) {
            findings.push(make_sec_finding(
                "SMG-SEC-ENV",
                "HIGH",
                format!(
                    "Sensitive file `{}` is not ignored by `.gitignore`",
                    rel_path
                ),
                rel_path,
                1,
                "Add `.env`, `.env.*`, and `*.pem` to `.gitignore`, and purge any previously committed secrets from git history.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_detection_and_entropy_false_positive_guard() {
        let aws_real = concat!("AKIA", "Z7X9K2M4P8Q1R5T3");
        let stripe_real = concat!("sk_live_", "51H9xK2L8mNpQ4rStUvWxYz78");
        let github_real = concat!("ghp_", "9aBcDeFgHiJkLmNoPqRsTuVwXyZ12345");
        let pem_real = concat!("-----BEGIN ", "RSA PRIVATE KEY-----");
        let dburi_real = concat!(
            "postgres://",
            "admin:S3cr3tP4ss99@db.prod.internal:5432/app"
        );
        let jwt_real = concat!(
            "jwt.sign(payload, \"",
            "super-secret-prod-jwt-key-99",
            "\")"
        );

        let dummy_src = concat!(
            "const a = 'your-api-key';\n",
            "const b = '",
            "sk_live_",
            "xxxxxxxxxxxx';\n",
            "const c = '",
            "sk_live_",
            "your_key_here';\n",
            "const d = 'AKIAIOSFODNN7EXAMPLE';\n",
            "const e = jwt.sign(p, 'your-secret-key');\n",
            "const f = 'postgres://user:password@localhost/db';\n",
        );
        assert!(
            scan_secrets_and_config("src/example.ts", dummy_src).is_empty(),
            "Dummy/example strings must not trigger false positives"
        );

        let vuln_src = format!(
            "export const AWS = '{aws_real}';\n\
             export const STRIPE = '{stripe_real}';\n\
             export const GH = '{github_real}';\n\
             export const KEY = `{pem_real}`;\n\
             export const DB = '{dburi_real}';\n\
             export const TOK = {jwt_real};\n"
        );
        let hits = scan_secrets_and_config("src/secrets.ts", &vuln_src);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(rules.contains(&"SMG-SEC-AWS"));
        assert!(rules.contains(&"SMG-SEC-STRIPE"));
        assert!(rules.contains(&"SMG-SEC-GITHUB"));
        assert!(rules.contains(&"SMG-SEC-KEY"));
        assert!(rules.contains(&"SMG-SEC-DBURI"));
        assert!(rules.contains(&"SMG-SEC-JWT"));
    }

    #[test]
    fn test_misconfig_rules_and_dockerfile_root_drop() {
        let cors_js = r#"
app.use(cors({
  origin: "*",
  credentials: true,
}));
app.get('/x', () => {
  res.cookie('sid', val, { httpOnly: false, secure: true });
});
https.get({ rejectUnauthorized: false });
const token = Math.random().toString(36);
const pwHash = crypto.createHash('md5').update(password).digest('hex');
"#;
        let hits = scan_secrets_and_config("src/app.js", cors_js);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(rules.contains(&"SMG-CFG-CORS"));
        assert!(rules.contains(&"SMG-CFG-COOKIE"));
        assert!(rules.contains(&"SMG-CFG-TLS"));
        assert!(rules.contains(&"SMG-CFG-CRYPTO"));

        let safe_docker =
            "FROM node:20\nUSER root\nRUN apt-get update\nUSER node\nCMD [\"node\"]\n";
        assert!(scan_secrets_and_config("Dockerfile", safe_docker).is_empty());

        let unsafe_docker = "FROM node:20\nUSER root\nCMD [\"node\"]\n";
        let dhits = scan_secrets_and_config("Dockerfile", unsafe_docker);
        assert!(dhits.iter().any(|h| h.rule_id == "SMG-CFG-DOCKER"));

        let missing_user_docker = "FROM node:20\nCMD [\"node\", \"server.js\"]\n";
        let mhits = scan_secrets_and_config("Dockerfile", missing_user_docker);
        assert!(mhits.iter().any(|h| h.rule_id == "SMG-CFG-DOCKER"));

        let multistage_unsafe = "FROM golang:1.22 AS builder\nUSER nonroot\nFROM debian:bookworm-slim\nCMD [\"/app\"]\n";
        assert!(
            scan_secrets_and_config("Dockerfile", multistage_unsafe)
                .iter()
                .any(|h| h.rule_id == "SMG-CFG-DOCKER"),
            "Final stage in multi-stage Dockerfile without USER must be flagged even if builder stage had USER"
        );

        let multistage_safe = "FROM golang:1.22 AS builder\nUSER root\nFROM gcr.io/distroless/static:nonroot\nCMD [\"/app\"]\n";
        assert!(
            scan_secrets_and_config("Dockerfile", multistage_safe).is_empty(),
            "Final nonroot stage must not be flagged because builder stage used USER root"
        );

        let self_src = include_str!("secrets_config.rs");
        assert!(
            scan_secrets_and_config("crates/smg-graph/src/secrets_config.rs", self_src).is_empty(),
            "secrets_config.rs must not trigger false positives on itself"
        );

        let debug_py = "DEBUG = True\n";
        assert!(
            scan_secrets_and_config("settings.py", debug_py)
                .iter()
                .any(|h| h.rule_id == "SMG-CFG-DEBUG")
        );
    }

    #[test]
    fn test_gitignore_env_exposure() {
        let gi = vec![".gitignore".into(), "*.log".into()];
        let gi_refs: Vec<(&str, &[String])> = vec![(".gitignore", &gi)];
        let exposed = check_gitignore_exposure(&[".env", "certs/dev.pem"], &gi_refs);
        assert_eq!(exposed.len(), 2);
        assert!(exposed.iter().all(|f| f.rule_id == "SMG-SEC-ENV"));

        let gi_safe = vec![".env*".into(), "*.pem".into()];
        let gi_safe_refs: Vec<(&str, &[String])> = vec![(".gitignore", &gi_safe)];
        assert!(
            check_gitignore_exposure(&[".env", ".env.local", "certs/dev.pem"], &gi_safe_refs)
                .is_empty()
        );
    }

    #[test]
    fn test_pem_cert_sops_ci_dsn_and_provider_pack() {
        let public_cert = concat!(
            "-----BEGIN ",
            "CERTIFICATE-----\n",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n",
            "-----END ",
            "CERTIFICATE-----\n"
        );
        assert!(!is_sensitive_env_or_pem_with_content(
            "certs/service-ca.pem",
            public_cert
        ));
        assert!(scan_secrets_and_config("certs/service-ca.pem", public_cert).is_empty());

        let private_pem = concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----\n",
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk\n",
            "-----END ",
            "PRIVATE KEY-----\n"
        );
        assert!(is_sensitive_env_or_pem_with_content(
            "certs/server-key.pem",
            private_pem
        ));
        assert!(
            scan_secrets_and_config("certs/server-key.pem", private_pem)
                .iter()
                .any(|f| f.rule_id == "SMG-SEC-KEY")
        );

        let sops_yaml = concat!(
            "db_url: ",
            "ENC[AES256_GCM,data:xK9mZp4qR2wL8vN1tY5bC7dF0hJ3nQ==,iv:AbCdEfGhIjKlMnOp,tag:QrStUvWxYz123456,type:str]\n",
            "sops:\n",
            "    age:\n",
            "        - recipient: age1examplekey\n",
            "    mac: ENC[AES256_GCM,data:AbCdEfGhIjKlMnOp,iv:1234,tag:5678,type:str]\n"
        );
        assert!(scan_secrets_and_config("deploy/secrets.enc.yaml", sops_yaml).is_empty());
        assert!(!is_sensitive_env_or_pem_with_content(
            ".env",
            "DB_PASS=ENC[AES256_GCM,data:abc123def456,iv:x,tag:y,type:str]\nsops_version=3.8.1\n"
        ));

        let ci_workflow = concat!(
            "jobs:\n  test:\n    env:\n",
            "      DATABASE_URL: ",
            "postgres://postgres:ci-pass@localhost:5432/testdb\n",
            "      SVC_URL: ",
            "postgres://appuser:Rand0mCiOnly@postgres:5432/ci\n"
        );
        assert!(scan_secrets_and_config(".github/workflows/ci.yml", ci_workflow).is_empty());

        let provider_src = format!(
            "const gl = '{gl}';\nconst hf = '{hf}';\nconst wh = '{wh}';\nconst sg = '{sg}';\n",
            gl = concat!("glpat-", "9xKmPq2RtYv8ZwNc3VbH7dFj"),
            hf = concat!("hf_", "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"),
            wh = concat!("whsec_", "8kLmNpQrStUvWxYz23456789AbCdEfGh"),
            sg = concat!(
                "SG.",
                "aBcDeFgHiJkLmNoP1234",
                ".",
                "qRsTuVwXyZ0123456789AbCdEf"
            ),
        );
        let hits = scan_secrets_and_config("src/providers.ts", &provider_src);
        assert!(
            hits.iter()
                .filter(|h| h.rule_id == "SMG-SEC-APIKEY")
                .count()
                >= 3
        );
        assert!(hits.iter().any(|h| h.rule_id == "SMG-SEC-STRIPE"));
        assert!(hits.iter().all(|h| h.confidence == Confidence::Confirmed));
    }
}
