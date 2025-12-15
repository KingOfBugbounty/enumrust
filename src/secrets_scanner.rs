#![allow(dead_code)]
// secrets_scanner.rs - Advanced Hardcoded Secrets Detection & Cloud Storage Testing
// Author: Enhanced EnumRust v2.2.0
// Purpose: CRITICAL security findings detection with token validation

use chrono::Utc;
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════
// DATA STRUCTURES FOR CRITICAL FINDINGS
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardcodedSecret {
    pub secret_type: String,
    pub secret_value: String,
    pub secret_preview: String,
    pub found_in_url: String,
    /// Direct URL to the JavaScript file where this secret was found (for easy access)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub js_source_url: Option<String>,
    pub context: String,
    pub severity: String,
    pub validated: bool,
    pub validation_status: String,
    pub discovered_at: String,
    // Enhanced fields for detailed code context and remediation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_code_context: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorageExposure {
    pub provider: String,
    pub bucket_url: String,
    pub bucket_name: String,
    pub permissions: StoragePermissions,
    pub risk_level: String,
    pub test_results: StorageTestResults,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePermissions {
    pub read: bool,
    pub write: bool,
    pub list: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageTestResults {
    pub anonymous_read: String,
    pub anonymous_write: String,
    pub anonymous_list: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedToken {
    pub token_type: String,
    pub token_preview: String,
    pub validation_status: String,
    pub validation_method: String,
    pub validation_response: String,
    pub token_scopes: Vec<String>,
    pub validated_at: String,
    pub risk_level: String,
}

// ═══════════════════════════════════════════════════════════════════
// ENHANCED REGEX PATTERNS FOR CRITICAL SECRETS
// ═══════════════════════════════════════════════════════════════════

lazy_static! {
    // ═══════════════════════════════════════════════════════════════════
    // AUTHENTICATION TOKENS & API KEYS
    // ═══════════════════════════════════════════════════════════════════

    // Vercel
    pub static ref RE_VERCEL_TOKEN_ENHANCED: Regex = Regex::new(r#"(?i)(?:vercel[_\s]*token[_\s]*[=:]|Bearer\s+)['"]?((?:vcel_|vc_)[a-zA-Z0-9]{32,})['"]?"#).unwrap();

    // GitHub tokens (multiple formats)
    pub static ref RE_GITHUB_PAT_NEW: Regex = Regex::new(r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}").unwrap();
    pub static ref RE_GITHUB_PAT_CLASSIC: Regex = Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap();
    pub static ref RE_GITHUB_OAUTH: Regex = Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap();
    pub static ref RE_GITHUB_APP_TOKEN: Regex = Regex::new(r"(?:ghu|ghs)_[a-zA-Z0-9]{36}").unwrap();
    pub static ref RE_GITHUB_REFRESH_TOKEN: Regex = Regex::new(r"ghr_[a-zA-Z0-9]{36}").unwrap();

    // Stripe
    pub static ref RE_STRIPE_SECRET_KEY: Regex = Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap();
    pub static ref RE_STRIPE_PUBLIC_KEY: Regex = Regex::new(r"pk_live_[0-9a-zA-Z]{24,}").unwrap();
    pub static ref RE_STRIPE_RESTRICTED_KEY: Regex = Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap();
    pub static ref RE_STRIPE_WEBHOOK_SECRET: Regex = Regex::new(r"whsec_[a-zA-Z0-9]{32,}").unwrap();

    // Twilio
    pub static ref RE_TWILIO_API_KEY: Regex = Regex::new(r"SK[0-9a-fA-F]{32}").unwrap();
    pub static ref RE_TWILIO_ACCOUNT_SID: Regex = Regex::new(r"AC[a-f0-9]{32}").unwrap();
    pub static ref RE_TWILIO_AUTH_TOKEN: Regex = Regex::new(r#"(?i)twilio[_\s]*(?:auth[_\s]*)?token[_\s]*[=:]["']([a-f0-9]{32})["']"#).unwrap();

    // Firebase / Google
    pub static ref RE_FIREBASE_API_KEY: Regex = Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap();
    pub static ref RE_FIREBASE_URL: Regex = Regex::new(r"https://[a-z0-9-]+\.firebaseio\.com").unwrap();
    pub static ref RE_FIREBASE_DATABASE_URL: Regex = Regex::new(r#"(?i)(?:firebase[_\s]*)?database[_\s]*url[_\s]*[=:]["']?(https://[a-z0-9-]+\.firebaseio\.com)["']?"#).unwrap();
    pub static ref RE_GOOGLE_API_KEY: Regex = Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap();
    pub static ref RE_GOOGLE_OAUTH_ID: Regex = Regex::new(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com").unwrap();
    pub static ref RE_GCP_SERVICE_ACCOUNT: Regex = Regex::new(r#""type"\s*:\s*"service_account""#).unwrap();

    // AWS
    pub static ref RE_AWS_ACCESS_KEY: Regex = Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap();
    pub static ref RE_AWS_SECRET_KEY: Regex = Regex::new(r#"(?i)(?:aws[_\s]*)?secret[_\s]*(?:access[_\s]*)?key[_\s]*[=:]["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap();
    pub static ref RE_AWS_SESSION_TOKEN: Regex = Regex::new(r#"(?i)aws[_\s]*session[_\s]*token[_\s]*[=:]["']?([A-Za-z0-9/+=]{100,})["']?"#).unwrap();

    // Azure
    pub static ref RE_AZURE_CLIENT_SECRET: Regex = Regex::new(r#"(?i)(?:azure|client)[_\s]*secret[_\s]*[=:]['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"#).unwrap();
    pub static ref RE_AZURE_CONNECTION_STRING: Regex = Regex::new(r#"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};EndpointSuffix="#).unwrap();
    pub static ref RE_AZURE_SAS_TOKEN: Regex = Regex::new(r"[?&]sig=[A-Za-z0-9%]+").unwrap();

    // Supabase
    pub static ref RE_SUPABASE_KEY: Regex = Regex::new(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();
    pub static ref RE_SUPABASE_URL: Regex = Regex::new(r"https://[a-z0-9]+\.supabase\.co").unwrap();
    pub static ref RE_SUPABASE_ANON_KEY: Regex = Regex::new(r#"(?i)(?:supabase[_\s]*)?(?:anon[_\s]*)?key[_\s]*[=:].*?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"#).unwrap();

    // SendGrid
    pub static ref RE_SENDGRID_API_KEY: Regex = Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap();

    // Mailchimp
    pub static ref RE_MAILCHIMP_API_KEY: Regex = Regex::new(r"[a-f0-9]{32}-us[0-9]{1,2}").unwrap();

    // Mailgun
    pub static ref RE_MAILGUN_API_KEY: Regex = Regex::new(r"key-[a-zA-Z0-9]{32}").unwrap();

    // Slack
    pub static ref RE_SLACK_TOKEN: Regex = Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap();
    pub static ref RE_SLACK_WEBHOOK: Regex = Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").unwrap();

    // Discord
    pub static ref RE_DISCORD_TOKEN: Regex = Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}").unwrap();
    pub static ref RE_DISCORD_WEBHOOK: Regex = Regex::new(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+").unwrap();

    // Telegram
    pub static ref RE_TELEGRAM_BOT_TOKEN: Regex = Regex::new(r"[0-9]+:AA[0-9A-Za-z_-]{33}").unwrap();

    // Sentry
    pub static ref RE_SENTRY_DSN: Regex = Regex::new(r"https://[a-f0-9]{32}@(?:o[0-9]+\.)?(?:sentry\.io|[a-z0-9-]+\.sentry\.io)/[0-9]+").unwrap();
    pub static ref RE_SENTRY_AUTH_TOKEN: Regex = Regex::new(r"sntrys_[a-zA-Z0-9]{64}").unwrap();

    // Algolia
    pub static ref RE_ALGOLIA_API_KEY: Regex = Regex::new(r#"(?i)algolia[_\s]*(?:api[_\s]*)?key[_\s]*[=:]["']?([a-f0-9]{32})["']?"#).unwrap();
    pub static ref RE_ALGOLIA_ADMIN_KEY: Regex = Regex::new(r#"(?i)algolia[_\s]*admin[_\s]*key[_\s]*[=:]["']?([a-f0-9]{32})["']?"#).unwrap();

    // Datadog
    pub static ref RE_DATADOG_API_KEY: Regex = Regex::new(r#"(?i)datadog[_\s]*(?:api[_\s]*)?key[_\s]*[=:]["']?([a-f0-9]{32})["']?"#).unwrap();

    // New Relic
    pub static ref RE_NEWRELIC_KEY: Regex = Regex::new(r"NRAK-[A-Z0-9]{27}").unwrap();

    // Heroku
    pub static ref RE_HEROKU_API_KEY: Regex = Regex::new(r#"(?i)heroku[_\s]*(?:api[_\s]*)?key[_\s]*[=:]["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?"#).unwrap();

    // NPM
    pub static ref RE_NPM_TOKEN: Regex = Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap();

    // PyPI
    pub static ref RE_PYPI_TOKEN: Regex = Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // JWT & AUTHENTICATION SECRETS
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_JWT_SECRET: Regex = Regex::new(r#"(?i)jwt[_\s]*secret[_\s]*[=:]["']?([a-zA-Z0-9_\-]{16,})["']?"#).unwrap();
    pub static ref RE_JWT_TOKEN: Regex = Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap();
    pub static ref RE_BEARER_TOKEN: Regex = Regex::new(r#"(?i)(?:bearer|authorization)[_\s]*[=:]["']?Bearer\s+([a-zA-Z0-9_\-.]+)["']?"#).unwrap();
    pub static ref RE_BASIC_AUTH: Regex = Regex::new(r#"(?i)authorization[_\s]*[=:]["']?Basic\s+([A-Za-z0-9+/=]+)["']?"#).unwrap();
    pub static ref RE_API_KEY_GENERIC: Regex = Regex::new(r#"(?i)(?:api[_\s]*key|apikey|x-api-key)[_\s]*[=:]["']?([a-zA-Z0-9_\-]{20,})["']?"#).unwrap();
    pub static ref RE_SECRET_KEY_GENERIC: Regex = Regex::new(r#"(?i)(?:secret[_\s]*key|secretkey|app[_\s]*secret)[_\s]*[=:]["']?([a-zA-Z0-9_\-]{16,})["']?"#).unwrap();
    pub static ref RE_ACCESS_TOKEN_GENERIC: Regex = Regex::new(r#"(?i)(?:access[_\s]*token|accesstoken)[_\s]*[=:]["']?([a-zA-Z0-9_\-.]{20,})["']?"#).unwrap();
    pub static ref RE_REFRESH_TOKEN: Regex = Regex::new(r#"(?i)refresh[_\s]*token[_\s]*[=:]["']?([a-zA-Z0-9_\-.]{20,})["']?"#).unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // PRIVATE KEYS & CERTIFICATES
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_PRIVATE_KEY_BLOCK: Regex = Regex::new(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----[\s\S]{50,2000}-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----").unwrap();
    pub static ref RE_CERTIFICATE: Regex = Regex::new(r"-----BEGIN\s+CERTIFICATE-----[\s\S]{50,2000}-----END\s+CERTIFICATE-----").unwrap();
    pub static ref RE_SSH_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+(?:OPENSSH|RSA|DSA|EC)\s+PRIVATE\s+KEY-----").unwrap();
    pub static ref RE_PGP_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----").unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // DATABASE CREDENTIALS
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_DATABASE_CREDS: Regex = Regex::new(r#"(?i)(postgres|mysql|mongodb|mssql|oracle|mariadb|redis|cockroachdb)(?:\+srv)?://([^:]+):([^@]{8,})@([^/\s"']+)"#).unwrap();
    pub static ref RE_MONGODB_SRV: Regex = Regex::new(r"mongodb\+srv://[^:]+:[^@]+@[a-z0-9-]+\.mongodb\.net").unwrap();
    pub static ref RE_REDIS_URL: Regex = Regex::new(r"redis(?:s)?://(?::[^@]+@)?[a-zA-Z0-9.-]+:[0-9]+").unwrap();
    pub static ref RE_DATABASE_PASSWORD: Regex = Regex::new(r#"(?i)(?:db|database)[_\s]*password[_\s]*[=:]["']?([^"'\s]{8,})["']?"#).unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // HARDCODED CREDENTIALS IN VARIABLES
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_PASSWORD_ASSIGNMENT: Regex = Regex::new(r#"(?i)(?:password|passwd|pwd|pass)[_\s]*[=:]["']([^"']{8,64})["']"#).unwrap();
    pub static ref RE_USERNAME_PASSWORD_PAIR: Regex = Regex::new(r#"(?i)(?:username|user)[_\s]*[=:]["']([^"']+)["'][,;\s]+(?:password|passwd|pwd)[_\s]*[=:]["']([^"']+)["']"#).unwrap();
    pub static ref RE_ADMIN_CREDENTIALS: Regex = Regex::new(r#"(?i)admin[_\s]*(?:password|passwd|pwd)[_\s]*[=:]["']([^"']{6,})["']"#).unwrap();
    pub static ref RE_ROOT_PASSWORD: Regex = Regex::new(r#"(?i)root[_\s]*password[_\s]*[=:]["']([^"']{6,})["']"#).unwrap();
    pub static ref RE_MASTER_KEY: Regex = Regex::new(r#"(?i)master[_\s]*key[_\s]*[=:]["']([^"']{16,})["']"#).unwrap();
    pub static ref RE_ENCRYPTION_KEY: Regex = Regex::new(r#"(?i)(?:encryption|cipher|aes|des)[_\s]*key[_\s]*[=:]["']([^"']{16,})["']"#).unwrap();
    pub static ref RE_SALT_VALUE: Regex = Regex::new(r#"(?i)(?:password[_\s]*)?salt[_\s]*[=:]["']([^"']{8,})["']"#).unwrap();
    pub static ref RE_IV_VALUE: Regex = Regex::new(r#"(?i)(?:initialization[_\s]*vector|iv)[_\s]*[=:]["']([^"']{16,})["']"#).unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // OAUTH & SOCIAL LOGIN
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_OAUTH_CLIENT_SECRET: Regex = Regex::new(r#"(?i)(?:oauth[_\s]*)?client[_\s]*secret[_\s]*[=:]["']([a-zA-Z0-9_\-]{16,})["']"#).unwrap();
    pub static ref RE_FACEBOOK_ACCESS_TOKEN: Regex = Regex::new(r"EAA[a-zA-Z0-9]+").unwrap();
    pub static ref RE_FACEBOOK_SECRET: Regex = Regex::new(r#"(?i)facebook[_\s]*(?:app[_\s]*)?secret[_\s]*[=:]["']([a-f0-9]{32})["']"#).unwrap();
    pub static ref RE_TWITTER_SECRET: Regex = Regex::new(r#"(?i)twitter[_\s]*(?:api[_\s]*)?secret[_\s]*[=:]["']([a-zA-Z0-9]{35,50})["']"#).unwrap();
    pub static ref RE_LINKEDIN_SECRET: Regex = Regex::new(r#"(?i)linkedin[_\s]*(?:client[_\s]*)?secret[_\s]*[=:]["']([a-zA-Z0-9]{16})["']"#).unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // PAYMENT PROVIDERS
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_PAYPAL_SECRET: Regex = Regex::new(r#"(?i)paypal[_\s]*(?:client[_\s]*)?secret[_\s]*[=:]["']([a-zA-Z0-9_\-]{32,})["']"#).unwrap();
    pub static ref RE_SQUARE_ACCESS_TOKEN: Regex = Regex::new(r"sq0atp-[a-zA-Z0-9_-]{22}").unwrap();
    pub static ref RE_SQUARE_SECRET: Regex = Regex::new(r"sq0csp-[a-zA-Z0-9_-]{43}").unwrap();
    pub static ref RE_BRAINTREE_ACCESS_TOKEN: Regex = Regex::new(r"access_token\$production\$[a-z0-9]+\$[a-f0-9]{32}").unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // WEBHOOKS & INTERNAL URLS
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_WEBHOOK_URL: Regex = Regex::new(r"https://[a-z0-9.-]+(?:\.[a-z]{2,})+/(?:webhook|hook|callback|notify)[a-zA-Z0-9/_\-?=&]*").unwrap();
    pub static ref RE_INTERNAL_URL: Regex = Regex::new(r"https?://(?:localhost|127\.0\.0\.1|192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)(?::[0-9]+)?").unwrap();
    pub static ref RE_DEBUG_ENDPOINT: Regex = Regex::new(r#"(?i)(?:debug|test|staging|dev)[_\s]*(?:url|endpoint|api)[_\s]*[=:]["'](https?://[^"']+)["']"#).unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // CLOUD STORAGE PATTERNS
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_S3_BUCKET_URL: Regex = Regex::new(r"(?i)https?://([a-z0-9\-]{3,63})\.s3(?:[\.-][a-z0-9\-]+)?\.amazonaws\.com").unwrap();
    pub static ref RE_S3_PATH_STYLE_URL: Regex = Regex::new(r"(?i)https?://s3(?:[\.-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9\-]{3,63})").unwrap();
    pub static ref RE_GCS_BUCKET_URL: Regex = Regex::new(r"(?i)https?://storage\.googleapis\.com/([a-z0-9\-_\.]{3,63})").unwrap();
    pub static ref RE_GCS_BUCKET_DOMAIN: Regex = Regex::new(r"(?i)https?://([a-z0-9\-_\.]{3,63})\.storage\.googleapis\.com").unwrap();
    pub static ref RE_AZURE_BLOB_URL: Regex = Regex::new(r"(?i)https?://([a-z0-9\-]{3,24})\.blob\.core\.windows\.net").unwrap();
    pub static ref RE_DIGITALOCEAN_SPACES_URL: Regex = Regex::new(r"(?i)https?://([a-z0-9\-]{3,63})\.(?:[a-z0-9\-]+\.)?digitaloceanspaces\.com").unwrap();
    pub static ref RE_CLOUDINARY_URL: Regex = Regex::new(r"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-z0-9-]+").unwrap();

    // ═══════════════════════════════════════════════════════════════════
    // MISCELLANEOUS SENSITIVE DATA
    // ═══════════════════════════════════════════════════════════════════

    pub static ref RE_IP_ADDRESS_PRIVATE: Regex = Regex::new(r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b").unwrap();
    pub static ref RE_CREDIT_CARD: Regex = Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap();
    pub static ref RE_SSN: Regex = Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap();
    pub static ref RE_EMAIL_PASSWORD: Regex = Regex::new(r#"(?i)email[_\s]*password[_\s]*[=:]["']([^"']+)["']"#).unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// ENHANCED TOKEN VALIDATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

/// Validate Stripe API keys (live keys only)
pub async fn validate_stripe_key(api_key: &str, client: &Client) -> (bool, String, Vec<String>) {
    let url = "https://api.stripe.com/v1/balance";

    match client
        .get(url)
        .bearer_auth(api_key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                // Key is valid and active
                (true, "VALID_ACTIVE".to_string(), vec!["balance:read".to_string()])
            } else if status.as_u16() == 401 {
                (false, "INVALID_EXPIRED".to_string(), vec![])
            } else {
                (false, "ERROR_TESTING".to_string(), vec![])
            }
        }
        Err(_) => (false, "ERROR_TESTING".to_string(), vec![]),
    }
}

/// Validate Twilio API keys
#[allow(dead_code)]
pub async fn validate_twilio_key(api_key: &str, account_sid: &str, client: &Client) -> (bool, String, Vec<String>) {
    let url = format!("https://api.twilio.com/2010-04-01/Accounts/{}.json", account_sid);

    match client
        .get(&url)
        .basic_auth(account_sid, Some(api_key))
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                (true, "VALID_ACTIVE".to_string(), vec!["account:read".to_string()])
            } else if status.as_u16() == 401 {
                (false, "INVALID_EXPIRED".to_string(), vec![])
            } else {
                (false, "ERROR_TESTING".to_string(), vec![])
            }
        }
        Err(_) => (false, "ERROR_TESTING".to_string(), vec![]),
    }
}

/// Enhanced GitHub token validator with scope detection
pub async fn validate_github_token_enhanced(token: &str, client: &Client) -> (bool, String, Vec<String>) {
    let url = "https://api.github.com/user";

    match client
        .get(url)
        .bearer_auth(token)
        .header("User-Agent", "EnumRust-Security-Scanner")
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            let scopes = response
                .headers()
                .get("x-oauth-scopes")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if status.is_success() {
                (true, "VALID_ACTIVE".to_string(), scopes)
            } else if status.as_u16() == 401 {
                (false, "INVALID_EXPIRED".to_string(), vec![])
            } else {
                (false, "ERROR_TESTING".to_string(), vec![])
            }
        }
        Err(_) => (false, "ERROR_TESTING".to_string(), vec![]),
    }
}

/// Enhanced Vercel token validator
pub async fn validate_vercel_token_enhanced(token: &str, client: &Client) -> (bool, String, Vec<String>) {
    let url = "https://api.vercel.com/v2/user";

    match client
        .get(url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                (true, "VALID_ACTIVE".to_string(), vec!["user:read".to_string()])
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                (false, "INVALID_EXPIRED".to_string(), vec![])
            } else {
                (false, "ERROR_TESTING".to_string(), vec![])
            }
        }
        Err(_) => (false, "ERROR_TESTING".to_string(), vec![]),
    }
}

/// Enhanced SendGrid API key validator with scopes
#[allow(dead_code)]
pub async fn validate_sendgrid_key_enhanced(api_key: &str, client: &Client) -> (bool, String, Vec<String>) {
    let url = "https://api.sendgrid.com/v3/scopes";

    match client
        .get(url)
        .bearer_auth(api_key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                // Try to parse scopes from response
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    if let Some(scopes) = json["scopes"].as_array() {
                        let scope_list: Vec<String> = scopes
                            .iter()
                            .filter_map(|s| s.as_str().map(|s| s.to_string()))
                            .collect();
                        return (true, "VALID_ACTIVE".to_string(), scope_list);
                    }
                }
                (true, "VALID_ACTIVE".to_string(), vec!["unknown".to_string()])
            } else if status.as_u16() == 401 {
                (false, "INVALID_EXPIRED".to_string(), vec![])
            } else {
                (false, "ERROR_TESTING".to_string(), vec![])
            }
        }
        Err(_) => (false, "ERROR_TESTING".to_string(), vec![]),
    }
}

// ═══════════════════════════════════════════════════════════════════
// CLOUD STORAGE TESTING FUNCTIONS (READ-ONLY)
// ═══════════════════════════════════════════════════════════════════

/// Test AWS S3 bucket permissions (anonymous access only)
pub async fn test_s3_bucket_permissions(bucket_url: &str, bucket_name: &str, client: &Client) -> CloudStorageExposure {
    let mut permissions = StoragePermissions {
        read: false,
        write: false,
        list: false,
    };

    let mut test_results = StorageTestResults {
        anonymous_read: "DENIED".to_string(),
        anonymous_write: "NOT_TESTED".to_string(), // We don't test write
        anonymous_list: "DENIED".to_string(),
    };

    // Test 1: Anonymous LIST (bucket enumeration)
    let list_url = format!("https://{}.s3.amazonaws.com/?prefix=&delimiter=/", bucket_name);
    match client
        .get(&list_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                permissions.list = true;
                test_results.anonymous_list = "SUCCESS".to_string();
            } else if status.as_u16() == 403 {
                test_results.anonymous_list = "DENIED".to_string();
            } else {
                test_results.anonymous_list = format!("HTTP_{}", status.as_u16());
            }
        }
        Err(_) => {
            test_results.anonymous_list = "TIMEOUT".to_string();
        }
    }

    // Test 2: Anonymous READ (try to access a common file)
    // We'll test with common file names like index.html, robots.txt, etc.
    let test_files = vec!["index.html", "robots.txt", "favicon.ico", "README.md"];

    for file in test_files {
        let read_url = format!("https://{}.s3.amazonaws.com/{}", bucket_name, file);
        match client
            .head(&read_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    permissions.read = true;
                    test_results.anonymous_read = "SUCCESS".to_string();
                    break;
                }
            }
            Err(_) => continue,
        }
    }

    // Determine risk level
    let risk_level = if permissions.list && permissions.read {
        "CRITICAL".to_string()
    } else if permissions.list || permissions.read {
        "HIGH".to_string()
    } else {
        "LOW".to_string()
    };

    CloudStorageExposure {
        provider: "AWS_S3".to_string(),
        bucket_url: bucket_url.to_string(),
        bucket_name: bucket_name.to_string(),
        permissions,
        risk_level,
        test_results,
        discovered_at: Utc::now().to_rfc3339(),
    }
}

/// Test Google Cloud Storage bucket permissions
pub async fn test_gcs_bucket_permissions(bucket_url: &str, bucket_name: &str, client: &Client) -> CloudStorageExposure {
    let mut permissions = StoragePermissions {
        read: false,
        write: false,
        list: false,
    };

    let mut test_results = StorageTestResults {
        anonymous_read: "DENIED".to_string(),
        anonymous_write: "NOT_TESTED".to_string(),
        anonymous_list: "DENIED".to_string(),
    };

    // Test LIST permission
    let list_url = format!("https://storage.googleapis.com/storage/v1/b/{}/o", bucket_name);
    match client
        .get(&list_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                permissions.list = true;
                test_results.anonymous_list = "SUCCESS".to_string();
            } else if status.as_u16() == 403 || status.as_u16() == 401 {
                test_results.anonymous_list = "DENIED".to_string();
            } else {
                test_results.anonymous_list = format!("HTTP_{}", status.as_u16());
            }
        }
        Err(_) => {
            test_results.anonymous_list = "TIMEOUT".to_string();
        }
    }

    // Test READ permission with common files
    let test_files = vec!["index.html", "robots.txt"];
    for file in test_files {
        let read_url = format!("https://storage.googleapis.com/{}/{}", bucket_name, file);
        match client
            .head(&read_url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    permissions.read = true;
                    test_results.anonymous_read = "SUCCESS".to_string();
                    break;
                }
            }
            Err(_) => continue,
        }
    }

    let risk_level = if permissions.list && permissions.read {
        "CRITICAL".to_string()
    } else if permissions.list || permissions.read {
        "HIGH".to_string()
    } else {
        "LOW".to_string()
    };

    CloudStorageExposure {
        provider: "GOOGLE_CLOUD_STORAGE".to_string(),
        bucket_url: bucket_url.to_string(),
        bucket_name: bucket_name.to_string(),
        permissions,
        risk_level,
        test_results,
        discovered_at: Utc::now().to_rfc3339(),
    }
}

/// Test Azure Blob Storage container permissions
pub async fn test_azure_blob_permissions(blob_url: &str, account_name: &str, client: &Client) -> CloudStorageExposure {
    let mut permissions = StoragePermissions {
        read: false,
        write: false,
        list: false,
    };

    let mut test_results = StorageTestResults {
        anonymous_read: "DENIED".to_string(),
        anonymous_write: "NOT_TESTED".to_string(),
        anonymous_list: "DENIED".to_string(),
    };

    // Test container listing
    let list_url = format!("https://{}.blob.core.windows.net/?comp=list", account_name);
    match client
        .get(&list_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                permissions.list = true;
                test_results.anonymous_list = "SUCCESS".to_string();
            } else if status.as_u16() == 403 || status.as_u16() == 401 {
                test_results.anonymous_list = "DENIED".to_string();
            } else {
                test_results.anonymous_list = format!("HTTP_{}", status.as_u16());
            }
        }
        Err(_) => {
            test_results.anonymous_list = "TIMEOUT".to_string();
        }
    }

    let risk_level = if permissions.list && permissions.read {
        "CRITICAL".to_string()
    } else if permissions.list || permissions.read {
        "HIGH".to_string()
    } else {
        "LOW".to_string()
    };

    CloudStorageExposure {
        provider: "AZURE_BLOB".to_string(),
        bucket_url: blob_url.to_string(),
        bucket_name: account_name.to_string(),
        permissions,
        risk_level,
        test_results,
        discovered_at: Utc::now().to_rfc3339(),
    }
}

/// Test DigitalOcean Spaces permissions
pub async fn test_do_spaces_permissions(spaces_url: &str, space_name: &str, client: &Client) -> CloudStorageExposure {
    let mut permissions = StoragePermissions {
        read: false,
        write: false,
        list: false,
    };

    let mut test_results = StorageTestResults {
        anonymous_read: "DENIED".to_string(),
        anonymous_write: "NOT_TESTED".to_string(),
        anonymous_list: "DENIED".to_string(),
    };

    // Test LIST permission (similar to S3)
    match client
        .get(spaces_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                permissions.list = true;
                test_results.anonymous_list = "SUCCESS".to_string();
            } else if status.as_u16() == 403 {
                test_results.anonymous_list = "DENIED".to_string();
            } else {
                test_results.anonymous_list = format!("HTTP_{}", status.as_u16());
            }
        }
        Err(_) => {
            test_results.anonymous_list = "TIMEOUT".to_string();
        }
    }

    let risk_level = if permissions.list {
        "HIGH".to_string()
    } else {
        "LOW".to_string()
    };

    CloudStorageExposure {
        provider: "DIGITALOCEAN_SPACES".to_string(),
        bucket_url: spaces_url.to_string(),
        bucket_name: space_name.to_string(),
        permissions,
        risk_level,
        test_results,
        discovered_at: Utc::now().to_rfc3339(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// ENHANCED SECRETS EXTRACTION WITH CONTEXT
// ═══════════════════════════════════════════════════════════════════

/// Extract secrets with surrounding context for better understanding
pub fn extract_context(content: &str, match_start: usize, match_end: usize, context_chars: usize) -> String {
    let start = match_start.saturating_sub(context_chars);
    let end = (match_end + context_chars).min(content.len());

    content[start..end]
        .replace('\n', " ")
        .replace('\r', "")
        .trim()
        .to_string()
}

/// Create a safe preview of a secret (show first 8 and last 4 characters)
pub fn create_safe_preview(secret: &str) -> String {
    if secret.len() <= 16 {
        format!("{}***", &secret[..4.min(secret.len())])
    } else {
        format!("{}...{}", &secret[..8], &secret[secret.len()-4..])
    }
}

/// Scan content for enhanced hardcoded secrets
pub async fn scan_for_enhanced_secrets(
    content: &str,
    source_url: &str,
    client: &Client,
    validate_tokens: bool,
) -> Vec<HardcodedSecret> {
    let mut secrets = Vec::new();

    // Vercel tokens
    for mat in RE_VERCEL_TOKEN_ENHANCED.find_iter(content) {
        if let Some(token_capture) = RE_VERCEL_TOKEN_ENHANCED.captures(mat.as_str()) {
            if let Some(token) = token_capture.get(1) {
                let token_str = token.as_str();
                let context = extract_context(content, mat.start(), mat.end(), 50);
                let preview = create_safe_preview(token_str);

                let (validated, status, _) = if validate_tokens {
                    validate_vercel_token_enhanced(token_str, client).await
                } else {
                    (false, "NOT_VALIDATED".to_string(), vec![])
                };

                secrets.push(HardcodedSecret {
                    secret_type: "VERCEL_TOKEN".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: preview,
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "CRITICAL".to_string(),
                    validated,
                    validation_status: status,
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: None,
                });
            }
        }
    }

    // GitHub PAT (new format)
    for mat in RE_GITHUB_PAT_NEW.find_iter(content) {
        let token_str = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 50);
        let preview = create_safe_preview(token_str);

        let (validated, status, scopes) = if validate_tokens {
            validate_github_token_enhanced(token_str, client).await
        } else {
            (false, "NOT_VALIDATED".to_string(), vec![])
        };

        secrets.push(HardcodedSecret {
            secret_type: "GITHUB_PAT_NEW".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: preview,
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context: if scopes.is_empty() {
                context
            } else {
                format!("{} | Scopes: {}", context, scopes.join(", "))
            },
            severity: "CRITICAL".to_string(),
            validated,
            validation_status: status,
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: None,
        });
    }

    // Stripe live keys
    for mat in RE_STRIPE_SECRET_KEY.find_iter(content) {
        let key_str = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 50);
        let preview = create_safe_preview(key_str);

        let (validated, status, _) = if validate_tokens {
            validate_stripe_key(key_str, client).await
        } else {
            (false, "NOT_VALIDATED".to_string(), vec![])
        };

        secrets.push(HardcodedSecret {
            secret_type: "STRIPE_SECRET_KEY".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: preview,
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: "CRITICAL".to_string(),
            validated,
            validation_status: status,
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: None,
        });
    }

    // Twilio API keys
    for mat in RE_TWILIO_API_KEY.find_iter(content) {
        let key_str = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 50);
        let preview = create_safe_preview(key_str);

        secrets.push(HardcodedSecret {
            secret_type: "TWILIO_API_KEY".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: preview,
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: "CRITICAL".to_string(),
            validated: false,
            validation_status: "REQUIRES_ACCOUNT_SID".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: None,
        });
    }

    // Azure client secrets
    for cap in RE_AZURE_CLIENT_SECRET.captures_iter(content) {
        if let Some(secret_match) = cap.get(1) {
            let secret_str = secret_match.as_str();
            let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
            let preview = create_safe_preview(secret_str);

            secrets.push(HardcodedSecret {
                secret_type: "AZURE_CLIENT_SECRET".to_string(),
                secret_value: "***REDACTED***".to_string(),
                secret_preview: preview,
                found_in_url: source_url.to_string(),
                js_source_url: Some(source_url.to_string()),
                context,
                severity: "CRITICAL".to_string(),
                validated: false,
                validation_status: "REQUIRES_TENANT_CLIENT_ID".to_string(),
                discovered_at: Utc::now().to_rfc3339(),
                code_snippet: None,
                has_code_context: None,
                line_number: None,
                remediation: None,
            });
        }
    }

    // JWT secrets
    for cap in RE_JWT_SECRET.captures_iter(content) {
        if let Some(secret_match) = cap.get(1) {
            let secret_str = secret_match.as_str();
            if secret_str.len() >= 16 {
                let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
                let preview = create_safe_preview(secret_str);

                secrets.push(HardcodedSecret {
                    secret_type: "JWT_SECRET".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: preview,
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "HIGH".to_string(),
                    validated: false,
                    validation_status: "NOT_VALIDATABLE".to_string(),
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: None,
                });
            }
        }
    }

    // Private key blocks
    for mat in RE_PRIVATE_KEY_BLOCK.find_iter(content) {
        let _key_str = mat.as_str();
        let context = "-----BEGIN PRIVATE KEY----- [FULL KEY DETECTED]".to_string();

        secrets.push(HardcodedSecret {
            secret_type: "PRIVATE_KEY".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: "-----BEGIN...KEY-----".to_string(),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: "CRITICAL".to_string(),
            validated: false,
            validation_status: "NOT_VALIDATABLE".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: None,
        });
    }

    // Database credentials
    for cap in RE_DATABASE_CREDS.captures_iter(content) {
        if let Some(full_match) = cap.get(0) {
            let db_type = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let username = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let host = cap.get(4).map(|m| m.as_str()).unwrap_or("");

            let context = extract_context(content, full_match.start(), full_match.end(), 50);
            let preview = format!("{}://{}:***@{}", db_type, username, host);

            secrets.push(HardcodedSecret {
                secret_type: format!("{}_CREDENTIALS", db_type.to_uppercase()),
                secret_value: "***REDACTED***".to_string(),
                secret_preview: preview,
                found_in_url: source_url.to_string(),
                js_source_url: Some(source_url.to_string()),
                context,
                severity: "CRITICAL".to_string(),
                validated: false,
                validation_status: "FORMAT_VALID".to_string(),
                discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: None,
            });
        }
    }

    secrets
}

/// Helper macro to add a simple pattern match secret
fn add_simple_secret(
    secrets: &mut Vec<HardcodedSecret>,
    content: &str,
    source_url: &str,
    regex: &Regex,
    secret_type: &str,
    severity: &str,
) {
    for mat in regex.find_iter(content) {
        let secret_str = mat.as_str();
        // Filter out obvious false positives
        if is_likely_false_positive(secret_str) {
            continue;
        }
        let context = extract_context(content, mat.start(), mat.end(), 50);
        let preview = create_safe_preview(secret_str);

        secrets.push(HardcodedSecret {
            secret_type: secret_type.to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: preview,
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: severity.to_string(),
            validated: false,
            validation_status: "NOT_VALIDATED".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some(get_remediation_advice(secret_type)),
        });
    }
}

/// Check if a matched string is likely a false positive
fn is_likely_false_positive(value: &str) -> bool {
    let value_lower = value.to_lowercase();

    // Common false positive patterns
    let false_positive_patterns = [
        "example", "placeholder", "your_", "xxx", "test", "demo", "sample",
        "fake", "dummy", "mock", "undefined", "null", "none", "todo",
        "replace_me", "insert_", "enter_", "put_your", "changeme",
        "aaaaaaa", "bbbbbbb", "0000000", "1111111", "abcdefg",
    ];

    for pattern in &false_positive_patterns {
        if value_lower.contains(pattern) {
            return true;
        }
    }

    // Check for repeated characters (like "aaaaaaaaaaaa")
    if value.len() > 10 {
        let first_char = value.chars().next().unwrap();
        if value.chars().all(|c| c == first_char) {
            return true;
        }
    }

    false
}

/// Get remediation advice based on secret type
fn get_remediation_advice(secret_type: &str) -> String {
    match secret_type {
        "AWS_ACCESS_KEY" | "AWS_SECRET_KEY" =>
            "Rotate AWS credentials immediately. Use IAM roles instead of hardcoded keys.".to_string(),
        "GITHUB_PAT" | "GITHUB_PAT_NEW" | "GITHUB_PAT_CLASSIC" =>
            "Revoke GitHub token immediately at github.com/settings/tokens".to_string(),
        "STRIPE_SECRET_KEY" =>
            "Rotate Stripe API key immediately in dashboard.stripe.com/apikeys".to_string(),
        "FIREBASE_API_KEY" | "GOOGLE_API_KEY" =>
            "Restrict API key in Google Cloud Console. Add referrer/IP restrictions.".to_string(),
        "JWT_SECRET" =>
            "Rotate JWT secret and invalidate all existing tokens.".to_string(),
        "PRIVATE_KEY" | "SSH_PRIVATE_KEY" =>
            "Remove private key immediately. Generate new key pair and revoke old one.".to_string(),
        "DATABASE_CREDENTIALS" | "MONGODB_CREDENTIALS" | "POSTGRES_CREDENTIALS" =>
            "Rotate database password immediately. Use environment variables.".to_string(),
        "SLACK_TOKEN" | "SLACK_WEBHOOK" =>
            "Revoke Slack token/webhook at api.slack.com/apps".to_string(),
        "DISCORD_TOKEN" | "DISCORD_WEBHOOK" =>
            "Regenerate Discord token/webhook in Discord Developer Portal.".to_string(),
        "SENDGRID_API_KEY" =>
            "Revoke SendGrid key immediately at app.sendgrid.com/settings/api_keys".to_string(),
        "SENTRY_DSN" =>
            "Regenerate Sentry DSN if exposed to unauthorized parties.".to_string(),
        _ => "Remove hardcoded secret and use environment variables or secret management service.".to_string(),
    }
}

/// COMPREHENSIVE scan for ALL types of hardcoded secrets
/// This function checks for 70+ types of secrets and credentials
pub async fn scan_for_all_hardcoded_secrets(
    content: &str,
    source_url: &str,
    client: &Client,
    validate_tokens: bool,
) -> Vec<HardcodedSecret> {
    let mut secrets = Vec::new();

    // Start with the original enhanced scan
    let enhanced_secrets = scan_for_enhanced_secrets(content, source_url, client, validate_tokens).await;
    secrets.extend(enhanced_secrets);

    // ═══════════════════════════════════════════════════════════════════
    // GITHUB TOKENS (All Formats)
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_GITHUB_PAT_CLASSIC, "GITHUB_PAT_CLASSIC", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_GITHUB_OAUTH, "GITHUB_OAUTH_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_GITHUB_APP_TOKEN, "GITHUB_APP_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_GITHUB_REFRESH_TOKEN, "GITHUB_REFRESH_TOKEN", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // STRIPE (Additional Patterns)
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_STRIPE_PUBLIC_KEY, "STRIPE_PUBLIC_KEY", "MEDIUM");
    add_simple_secret(&mut secrets, content, source_url, &RE_STRIPE_RESTRICTED_KEY, "STRIPE_RESTRICTED_KEY", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_STRIPE_WEBHOOK_SECRET, "STRIPE_WEBHOOK_SECRET", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // TWILIO (Additional)
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_TWILIO_ACCOUNT_SID, "TWILIO_ACCOUNT_SID", "MEDIUM");

    // ═══════════════════════════════════════════════════════════════════
    // FIREBASE / GOOGLE
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_FIREBASE_API_KEY, "FIREBASE_API_KEY", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_FIREBASE_URL, "FIREBASE_DATABASE_URL", "MEDIUM");
    add_simple_secret(&mut secrets, content, source_url, &RE_GOOGLE_OAUTH_ID, "GOOGLE_OAUTH_CLIENT_ID", "MEDIUM");

    // GCP Service Account detection
    if RE_GCP_SERVICE_ACCOUNT.is_match(content) {
        secrets.push(HardcodedSecret {
            secret_type: "GCP_SERVICE_ACCOUNT_JSON".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: "[SERVICE ACCOUNT JSON DETECTED]".to_string(),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context: "Google Cloud Platform service account credentials found".to_string(),
            severity: "CRITICAL".to_string(),
            validated: false,
            validation_status: "FORMAT_VALID".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Remove service account JSON. Use workload identity or managed identities.".to_string()),
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // AWS
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_AWS_ACCESS_KEY, "AWS_ACCESS_KEY", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // AZURE
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_AZURE_CONNECTION_STRING, "AZURE_CONNECTION_STRING", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // SUPABASE
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_SUPABASE_URL, "SUPABASE_URL", "LOW");
    // Note: Supabase anon keys are meant to be public, but service_role keys are critical
    for mat in RE_SUPABASE_KEY.find_iter(content) {
        let key_str = mat.as_str();
        // Try to determine if it's anon or service_role key
        let context = extract_context(content, mat.start(), mat.end(), 100);
        let is_service_role = context.to_lowercase().contains("service_role") ||
                              context.to_lowercase().contains("service-role") ||
                              context.to_lowercase().contains("servicerole");

        if is_service_role {
            secrets.push(HardcodedSecret {
                secret_type: "SUPABASE_SERVICE_ROLE_KEY".to_string(),
                secret_value: "***REDACTED***".to_string(),
                secret_preview: create_safe_preview(key_str),
                found_in_url: source_url.to_string(),
                js_source_url: Some(source_url.to_string()),
                context: context.clone(),
                severity: "CRITICAL".to_string(),
                validated: false,
                validation_status: "SERVICE_ROLE_KEY_DETECTED".to_string(),
                discovered_at: Utc::now().to_rfc3339(),
                code_snippet: None,
                has_code_context: None,
                line_number: None,
                remediation: Some("Service role keys should NEVER be exposed in frontend code!".to_string()),
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // MESSAGING & EMAIL SERVICES
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_SENDGRID_API_KEY, "SENDGRID_API_KEY", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_MAILCHIMP_API_KEY, "MAILCHIMP_API_KEY", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_MAILGUN_API_KEY, "MAILGUN_API_KEY", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // CHAT & COMMUNICATION
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_SLACK_TOKEN, "SLACK_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_SLACK_WEBHOOK, "SLACK_WEBHOOK_URL", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_DISCORD_TOKEN, "DISCORD_BOT_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_DISCORD_WEBHOOK, "DISCORD_WEBHOOK_URL", "MEDIUM");
    add_simple_secret(&mut secrets, content, source_url, &RE_TELEGRAM_BOT_TOKEN, "TELEGRAM_BOT_TOKEN", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // MONITORING & LOGGING
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_SENTRY_DSN, "SENTRY_DSN", "MEDIUM");
    add_simple_secret(&mut secrets, content, source_url, &RE_SENTRY_AUTH_TOKEN, "SENTRY_AUTH_TOKEN", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_NEWRELIC_KEY, "NEWRELIC_LICENSE_KEY", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // PACKAGE MANAGERS
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_NPM_TOKEN, "NPM_AUTH_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_PYPI_TOKEN, "PYPI_API_TOKEN", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // JWT & AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════
    // JWT tokens (might be session tokens exposed in code)
    for mat in RE_JWT_TOKEN.find_iter(content) {
        let token = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 50);

        // Check if this looks like a hardcoded token vs. just JWT format reference
        if !context.to_lowercase().contains("example") &&
           !context.to_lowercase().contains("format") &&
           token.len() > 50 {
            secrets.push(HardcodedSecret {
                secret_type: "JWT_TOKEN_HARDCODED".to_string(),
                secret_value: "***REDACTED***".to_string(),
                secret_preview: create_safe_preview(token),
                found_in_url: source_url.to_string(),
                js_source_url: Some(source_url.to_string()),
                context,
                severity: "HIGH".to_string(),
                validated: false,
                validation_status: "JWT_FORMAT_DETECTED".to_string(),
                discovered_at: Utc::now().to_rfc3339(),
                code_snippet: None,
                has_code_context: None,
                line_number: None,
                remediation: Some("Remove hardcoded JWT. Tokens should be fetched dynamically.".to_string()),
            });
        }
    }

    add_simple_secret(&mut secrets, content, source_url, &RE_API_KEY_GENERIC, "GENERIC_API_KEY", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_SECRET_KEY_GENERIC, "GENERIC_SECRET_KEY", "HIGH");
    add_simple_secret(&mut secrets, content, source_url, &RE_ACCESS_TOKEN_GENERIC, "GENERIC_ACCESS_TOKEN", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // PRIVATE KEYS & CERTIFICATES
    // ═══════════════════════════════════════════════════════════════════
    if RE_SSH_PRIVATE_KEY.is_match(content) {
        secrets.push(HardcodedSecret {
            secret_type: "SSH_PRIVATE_KEY".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: "-----BEGIN ... PRIVATE KEY-----".to_string(),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context: "SSH Private Key detected in code".to_string(),
            severity: "CRITICAL".to_string(),
            validated: false,
            validation_status: "FORMAT_VALID".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Remove private key immediately. Generate new key pair.".to_string()),
        });
    }

    if RE_PGP_PRIVATE_KEY.is_match(content) {
        secrets.push(HardcodedSecret {
            secret_type: "PGP_PRIVATE_KEY".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: "-----BEGIN PGP PRIVATE KEY BLOCK-----".to_string(),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context: "PGP Private Key detected in code".to_string(),
            severity: "CRITICAL".to_string(),
            validated: false,
            validation_status: "FORMAT_VALID".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Revoke PGP key and generate new one.".to_string()),
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // DATABASE CONNECTIONS
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_MONGODB_SRV, "MONGODB_CONNECTION_STRING", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_REDIS_URL, "REDIS_CONNECTION_URL", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // HARDCODED CREDENTIALS IN VARIABLES
    // ═══════════════════════════════════════════════════════════════════
    for cap in RE_PASSWORD_ASSIGNMENT.captures_iter(content) {
        if let Some(password_match) = cap.get(1) {
            let password = password_match.as_str();
            if !is_likely_false_positive(password) && password.len() >= 8 {
                let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
                secrets.push(HardcodedSecret {
                    secret_type: "HARDCODED_PASSWORD".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: create_safe_preview(password),
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "HIGH".to_string(),
                    validated: false,
                    validation_status: "PATTERN_MATCH".to_string(),
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: Some("Remove hardcoded password. Use environment variables.".to_string()),
                });
            }
        }
    }

    for cap in RE_ADMIN_CREDENTIALS.captures_iter(content) {
        if let Some(password_match) = cap.get(1) {
            let password = password_match.as_str();
            if !is_likely_false_positive(password) {
                let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
                secrets.push(HardcodedSecret {
                    secret_type: "ADMIN_PASSWORD_HARDCODED".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: create_safe_preview(password),
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "CRITICAL".to_string(),
                    validated: false,
                    validation_status: "PATTERN_MATCH".to_string(),
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: Some("Admin credentials should NEVER be hardcoded!".to_string()),
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // ENCRYPTION KEYS & SECRETS
    // ═══════════════════════════════════════════════════════════════════
    for cap in RE_ENCRYPTION_KEY.captures_iter(content) {
        if let Some(key_match) = cap.get(1) {
            let key = key_match.as_str();
            if !is_likely_false_positive(key) {
                let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
                secrets.push(HardcodedSecret {
                    secret_type: "ENCRYPTION_KEY".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: create_safe_preview(key),
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "CRITICAL".to_string(),
                    validated: false,
                    validation_status: "PATTERN_MATCH".to_string(),
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: Some("Encryption keys should be stored in secure key management systems.".to_string()),
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // OAUTH & SOCIAL LOGIN
    // ═══════════════════════════════════════════════════════════════════
    for cap in RE_OAUTH_CLIENT_SECRET.captures_iter(content) {
        if let Some(secret_match) = cap.get(1) {
            let secret = secret_match.as_str();
            if !is_likely_false_positive(secret) {
                let context = extract_context(content, cap.get(0).unwrap().start(), cap.get(0).unwrap().end(), 50);
                secrets.push(HardcodedSecret {
                    secret_type: "OAUTH_CLIENT_SECRET".to_string(),
                    secret_value: "***REDACTED***".to_string(),
                    secret_preview: create_safe_preview(secret),
                    found_in_url: source_url.to_string(),
                    js_source_url: Some(source_url.to_string()),
                    context,
                    severity: "CRITICAL".to_string(),
                    validated: false,
                    validation_status: "PATTERN_MATCH".to_string(),
                    discovered_at: Utc::now().to_rfc3339(),
                    code_snippet: None,
                    has_code_context: None,
                    line_number: None,
                    remediation: Some("OAuth client secrets should never be in frontend code!".to_string()),
                });
            }
        }
    }

    add_simple_secret(&mut secrets, content, source_url, &RE_FACEBOOK_ACCESS_TOKEN, "FACEBOOK_ACCESS_TOKEN", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // PAYMENT PROVIDERS
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_SQUARE_ACCESS_TOKEN, "SQUARE_ACCESS_TOKEN", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_SQUARE_SECRET, "SQUARE_SECRET", "CRITICAL");
    add_simple_secret(&mut secrets, content, source_url, &RE_BRAINTREE_ACCESS_TOKEN, "BRAINTREE_ACCESS_TOKEN", "CRITICAL");

    // ═══════════════════════════════════════════════════════════════════
    // WEBHOOKS & INTERNAL URLS
    // ═══════════════════════════════════════════════════════════════════
    for mat in RE_WEBHOOK_URL.find_iter(content) {
        let webhook = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 30);
        secrets.push(HardcodedSecret {
            secret_type: "WEBHOOK_URL".to_string(),
            secret_value: webhook.to_string(),
            secret_preview: create_safe_preview(webhook),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: "MEDIUM".to_string(),
            validated: false,
            validation_status: "URL_DETECTED".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Webhook URLs can be abused for spam or data exfiltration.".to_string()),
        });
    }

    for mat in RE_INTERNAL_URL.find_iter(content) {
        let url = mat.as_str();
        let context = extract_context(content, mat.start(), mat.end(), 30);
        secrets.push(HardcodedSecret {
            secret_type: "INTERNAL_URL_EXPOSED".to_string(),
            secret_value: url.to_string(),
            secret_preview: url.to_string(),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context,
            severity: "MEDIUM".to_string(),
            validated: false,
            validation_status: "INTERNAL_IP_DETECTED".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Internal URLs reveal infrastructure details.".to_string()),
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // CLOUD STORAGE
    // ═══════════════════════════════════════════════════════════════════
    add_simple_secret(&mut secrets, content, source_url, &RE_CLOUDINARY_URL, "CLOUDINARY_URL", "HIGH");

    // ═══════════════════════════════════════════════════════════════════
    // SENSITIVE DATA PATTERNS
    // ═══════════════════════════════════════════════════════════════════
    // Private IP addresses (indicates internal infrastructure exposure)
    let private_ips: HashSet<String> = RE_IP_ADDRESS_PRIVATE.find_iter(content)
        .map(|m| m.as_str().to_string())
        .collect();

    if private_ips.len() > 2 {
        // Multiple internal IPs suggest infrastructure exposure
        secrets.push(HardcodedSecret {
            secret_type: "INTERNAL_INFRASTRUCTURE_EXPOSED".to_string(),
            secret_value: "***REDACTED***".to_string(),
            secret_preview: format!("{} private IPs found", private_ips.len()),
            found_in_url: source_url.to_string(),
            js_source_url: Some(source_url.to_string()),
            context: format!("Private IPs: {}", private_ips.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
            severity: "MEDIUM".to_string(),
            validated: false,
            validation_status: "INFRASTRUCTURE_EXPOSURE".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
            code_snippet: None,
            has_code_context: None,
            line_number: None,
            remediation: Some("Internal IPs should not be exposed in frontend code.".to_string()),
        });
    }

    // Deduplicate secrets by type + preview
    let mut seen: HashSet<String> = HashSet::new();
    secrets.retain(|s| {
        let key = format!("{}:{}", s.secret_type, s.secret_preview);
        seen.insert(key)
    });

    secrets
}

/// Scan content for cloud storage URLs and test them
pub async fn scan_for_cloud_storage(
    content: &str,
    _source_url: &str,
    client: &Client,
    test_permissions: bool,
) -> Vec<CloudStorageExposure> {
    let mut exposures = Vec::new();
    let mut tested_buckets = HashSet::new();

    // AWS S3 buckets (virtual-hosted style)
    for cap in RE_S3_BUCKET_URL.captures_iter(content) {
        if let Some(bucket_match) = cap.get(1) {
            let bucket_name = bucket_match.as_str();
            if tested_buckets.insert(bucket_name.to_string()) {
                let bucket_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_s3_bucket_permissions(bucket_url, bucket_name, client).await;
                    exposures.push(exposure);
                } else {
                    exposures.push(CloudStorageExposure {
                        provider: "AWS_S3".to_string(),
                        bucket_url: bucket_url.to_string(),
                        bucket_name: bucket_name.to_string(),
                        permissions: StoragePermissions {
                            read: false,
                            write: false,
                            list: false,
                        },
                        risk_level: "UNKNOWN".to_string(),
                        test_results: StorageTestResults {
                            anonymous_read: "NOT_TESTED".to_string(),
                            anonymous_write: "NOT_TESTED".to_string(),
                            anonymous_list: "NOT_TESTED".to_string(),
                        },
                        discovered_at: Utc::now().to_rfc3339(),
                    });
                }
            }
        }
    }

    // AWS S3 path-style URLs
    for cap in RE_S3_PATH_STYLE_URL.captures_iter(content) {
        if let Some(bucket_match) = cap.get(1) {
            let bucket_name = bucket_match.as_str();
            if tested_buckets.insert(bucket_name.to_string()) {
                let bucket_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_s3_bucket_permissions(bucket_url, bucket_name, client).await;
                    exposures.push(exposure);
                }
            }
        }
    }

    // Google Cloud Storage
    for cap in RE_GCS_BUCKET_URL.captures_iter(content) {
        if let Some(bucket_match) = cap.get(1) {
            let bucket_name = bucket_match.as_str();
            if tested_buckets.insert(format!("gcs_{}", bucket_name)) {
                let bucket_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_gcs_bucket_permissions(bucket_url, bucket_name, client).await;
                    exposures.push(exposure);
                }
            }
        }
    }

    // Google Cloud Storage (domain style)
    for cap in RE_GCS_BUCKET_DOMAIN.captures_iter(content) {
        if let Some(bucket_match) = cap.get(1) {
            let bucket_name = bucket_match.as_str();
            if tested_buckets.insert(format!("gcs_{}", bucket_name)) {
                let bucket_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_gcs_bucket_permissions(bucket_url, bucket_name, client).await;
                    exposures.push(exposure);
                }
            }
        }
    }

    // Azure Blob Storage
    for cap in RE_AZURE_BLOB_URL.captures_iter(content) {
        if let Some(account_match) = cap.get(1) {
            let account_name = account_match.as_str();
            if tested_buckets.insert(format!("azure_{}", account_name)) {
                let blob_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_azure_blob_permissions(blob_url, account_name, client).await;
                    exposures.push(exposure);
                }
            }
        }
    }

    // DigitalOcean Spaces
    for cap in RE_DIGITALOCEAN_SPACES_URL.captures_iter(content) {
        if let Some(space_match) = cap.get(1) {
            let space_name = space_match.as_str();
            if tested_buckets.insert(format!("do_{}", space_name)) {
                let spaces_url = cap.get(0).unwrap().as_str();

                if test_permissions {
                    let exposure = test_do_spaces_permissions(spaces_url, space_name, client).await;
                    exposures.push(exposure);
                }
            }
        }
    }

    exposures
}

// ═══════════════════════════════════════════════════════════════════
// FILE I/O OPERATIONS
// ═══════════════════════════════════════════════════════════════════

/// Save hardcoded secrets to JSON file
pub fn save_secrets_to_file(secrets: &[HardcodedSecret], output_path: &Path) -> anyhow::Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    let json = serde_json::to_string_pretty(secrets)?;
    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;

    println!("{}", format!("[+] Saved {} critical secrets to: {}", secrets.len(), output_path.display()).green());

    Ok(())
}

/// Save cloud storage exposures to JSON file
pub fn save_cloud_storage_to_file(exposures: &[CloudStorageExposure], output_path: &Path) -> anyhow::Result<()> {
    if exposures.is_empty() {
        return Ok(());
    }

    let json = serde_json::to_string_pretty(exposures)?;
    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;

    println!("{}", format!("[+] Saved {} cloud storage findings to: {}", exposures.len(), output_path.display()).green());

    Ok(())
}

/// Save validated tokens to JSON file
pub fn save_validated_tokens_to_file(tokens: &[ValidatedToken], output_path: &Path) -> anyhow::Result<()> {
    if tokens.is_empty() {
        return Ok(());
    }

    let json = serde_json::to_string_pretty(tokens)?;
    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;

    println!("{}", format!("[+] Saved {} validated tokens to: {}", tokens.len(), output_path.display()).green());

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// REPORTING AND DISPLAY
// ═══════════════════════════════════════════════════════════════════

/// Display critical secrets summary
pub fn display_secrets_summary(secrets: &[HardcodedSecret]) {
    if secrets.is_empty() {
        return;
    }

    println!("\n{}", "═══════════════════════════════════════════════════════".red().bold());
    println!("{}", format!("  CRITICAL SECRETS DETECTED: {}", secrets.len()).red().bold());
    println!("{}", "═══════════════════════════════════════════════════════".red().bold());

    for secret in secrets {
        println!("\n{}", format!("  Type: {}", secret.secret_type).yellow().bold());
        println!("  Preview: {}", secret.secret_preview);
        println!("  Found in: {}", secret.found_in_url);

        // Display JS source URL prominently if available
        if let Some(ref js_url) = secret.js_source_url {
            println!("{}", format!("  JS File: {}", js_url).cyan().bold());
        }

        println!("  Validated: {}", if secret.validated { "YES".green() } else { "NO".red() });
        println!("  Status: {}", secret.validation_status);
    }

    println!("\n{}", "═══════════════════════════════════════════════════════".red().bold());
}

/// Display cloud storage exposures summary
pub fn display_cloud_storage_summary(exposures: &[CloudStorageExposure]) {
    if exposures.is_empty() {
        return;
    }

    println!("\n{}", "═══════════════════════════════════════════════════════".cyan().bold());
    println!("{}", format!("  CLOUD STORAGE EXPOSURES: {}", exposures.len()).cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════".cyan().bold());

    for exposure in exposures {
        let risk_color = match exposure.risk_level.as_str() {
            "CRITICAL" => "red",
            "HIGH" => "yellow",
            _ => "white",
        };

        println!("\n{}", format!("  Provider: {}", exposure.provider).cyan().bold());
        println!("  Bucket: {}", exposure.bucket_name);
        println!("  URL: {}", exposure.bucket_url);
        println!("  Risk Level: {}", exposure.risk_level.color(risk_color));
        println!("  Read Access: {}", if exposure.permissions.read { "YES".red() } else { "NO".green() });
        println!("  List Access: {}", if exposure.permissions.list { "YES".red() } else { "NO".green() });
    }

    println!("\n{}", "═══════════════════════════════════════════════════════".cyan().bold());
}
