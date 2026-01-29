// info_disclosure_scanner.rs - Information Disclosure Scanner Module
// Purpose: Detect and exploit information disclosure vulnerabilities
// All scanners implemented natively in Rust - NO external tool dependencies
// Author: EnumRust v2.3.0

use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use chrono::Utc;
use futures::{stream, StreamExt};

// ═══════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoDisclosureResults {
    pub domain: String,
    pub scan_timestamp: String,
    pub cloud_storage_findings: Vec<CloudStorageFinding>,
    pub actuator_findings: Vec<ActuatorFinding>,
    pub graphql_findings: Vec<GraphQLFinding>,
    pub sensitive_files: Vec<SensitiveFileFinding>,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorageFinding {
    pub bucket_url: String,
    pub bucket_name: String,
    pub provider: String,
    pub region: Option<String>,
    pub can_list: bool,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub takeover_possible: bool,
    pub files_found: Vec<String>,
    pub severity: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuatorFinding {
    pub url: String,
    pub endpoint: String,
    pub status_code: u16,
    pub response_size: usize,
    pub content_preview: String,
    pub has_sensitive_data: bool,
    pub sensitive_data_types: Vec<String>,
    pub severity: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLFinding {
    pub url: String,
    pub introspection_enabled: bool,
    pub schema: Option<GraphQLSchema>,
    pub types_discovered: usize,
    pub queries_discovered: usize,
    pub mutations_discovered: usize,
    pub subscriptions_discovered: usize,
    pub severity: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLSchema {
    pub types: Vec<GraphQLType>,
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLType {
    pub name: String,
    pub kind: String,
    pub fields: Vec<GraphQLField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLField {
    pub name: String,
    pub field_type: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFileFinding {
    pub url: String,
    pub file_type: String,
    pub status_code: u16,
    pub content_length: usize,
    pub content_preview: String,
    pub secrets_found: Vec<String>,
    pub severity: String,
    pub discovered_at: String,
}

// ═══════════════════════════════════════════════════════════════════
// CLOUD STORAGE URL PATTERNS
// ═══════════════════════════════════════════════════════════════════

lazy_static::lazy_static! {
    // AWS S3 patterns
    static ref RE_S3_VIRTUAL: Regex = Regex::new(r"https?://([a-zA-Z0-9._-]+)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com").unwrap();
    static ref RE_S3_PATH: Regex = Regex::new(r"https?://s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com/([a-zA-Z0-9._-]+)").unwrap();
    static ref RE_S3_URI: Regex = Regex::new(r"s3://([a-zA-Z0-9._-]+)").unwrap();

    // Google Cloud Storage
    static ref RE_GCS_VIRTUAL: Regex = Regex::new(r"https?://([a-zA-Z0-9._-]+)\.storage\.googleapis\.com").unwrap();
    static ref RE_GCS_PATH: Regex = Regex::new(r"https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)").unwrap();

    // Azure Blob Storage
    static ref RE_AZURE_BLOB: Regex = Regex::new(r"https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net(?:/([a-zA-Z0-9._-]+))?").unwrap();

    // DigitalOcean Spaces
    static ref RE_DO_SPACES: Regex = Regex::new(r"https?://([a-zA-Z0-9._-]+)\.([a-z0-9]+)\.digitaloceanspaces\.com").unwrap();

    // Cloudflare R2
    static ref RE_CLOUDFLARE_R2: Regex = Regex::new(r"https?://([a-zA-Z0-9]+)\.r2\.dev(?:/([a-zA-Z0-9._-]+))?").unwrap();

    // Alibaba Cloud OSS
    static ref RE_ALIBABA_OSS: Regex = Regex::new(r"https?://([a-zA-Z0-9._-]+)\.oss-([a-z0-9-]+)\.aliyuncs\.com").unwrap();

    // Backblaze B2
    static ref RE_BACKBLAZE_B2: Regex = Regex::new(r"https?://([a-zA-Z0-9._-]+)\.s3\.([a-z0-9-]+)\.backblazeb2\.com").unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// SPRING BOOT ACTUATOR ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

const ACTUATOR_ENDPOINTS: &[(&str, &str, &str)] = &[
    // Critical - Memory/Heap dumps
    ("/actuator/heapdump", "heapdump", "CRITICAL"),
    ("/heapdump", "heapdump", "CRITICAL"),
    ("/dump", "dump", "CRITICAL"),
    ("/actuator/threaddump", "threaddump", "HIGH"),
    ("/threaddump", "threaddump", "HIGH"),

    // Critical - Environment/Config
    ("/actuator/env", "env", "CRITICAL"),
    ("/env", "env", "CRITICAL"),
    ("/actuator/configprops", "configprops", "CRITICAL"),
    ("/configprops", "configprops", "CRITICAL"),

    // High - Sensitive info
    ("/actuator/beans", "beans", "HIGH"),
    ("/beans", "beans", "HIGH"),
    ("/actuator/mappings", "mappings", "HIGH"),
    ("/mappings", "mappings", "HIGH"),
    ("/actuator/conditions", "conditions", "HIGH"),
    ("/actuator/scheduledtasks", "scheduledtasks", "HIGH"),
    ("/actuator/httptrace", "httptrace", "HIGH"),
    ("/httptrace", "httptrace", "HIGH"),
    ("/trace", "trace", "HIGH"),
    ("/actuator/auditevents", "auditevents", "HIGH"),
    ("/auditevents", "auditevents", "HIGH"),
    ("/actuator/sessions", "sessions", "HIGH"),
    ("/actuator/caches", "caches", "MEDIUM"),
    ("/actuator/flyway", "flyway", "MEDIUM"),
    ("/actuator/liquibase", "liquibase", "MEDIUM"),

    // Medium - Info disclosure
    ("/actuator", "actuator_index", "MEDIUM"),
    ("/actuator/info", "info", "MEDIUM"),
    ("/info", "info", "MEDIUM"),
    ("/actuator/health", "health", "LOW"),
    ("/health", "health", "LOW"),
    ("/actuator/metrics", "metrics", "MEDIUM"),
    ("/metrics", "metrics", "MEDIUM"),
    ("/actuator/prometheus", "prometheus", "MEDIUM"),
    ("/actuator/loggers", "loggers", "MEDIUM"),
    ("/loggers", "loggers", "MEDIUM"),
    ("/actuator/logfile", "logfile", "HIGH"),
    ("/logfile", "logfile", "HIGH"),

    // Dangerous - Control endpoints
    ("/actuator/shutdown", "shutdown", "CRITICAL"),
    ("/shutdown", "shutdown", "CRITICAL"),
    ("/actuator/restart", "restart", "CRITICAL"),
    ("/restart", "restart", "CRITICAL"),
    ("/actuator/refresh", "refresh", "HIGH"),
    ("/actuator/pause", "pause", "HIGH"),
    ("/actuator/resume", "resume", "HIGH"),

    // Jolokia (JMX over HTTP)
    ("/actuator/jolokia", "jolokia", "CRITICAL"),
    ("/jolokia", "jolokia", "CRITICAL"),
    ("/jolokia/list", "jolokia_list", "CRITICAL"),

    // Management variations
    ("/management/heapdump", "heapdump", "CRITICAL"),
    ("/management/env", "env", "CRITICAL"),
    ("/management/beans", "beans", "HIGH"),
    ("/management/mappings", "mappings", "HIGH"),
    ("/management/health", "health", "LOW"),
    ("/management/info", "info", "MEDIUM"),

    // Gateway routes
    ("/actuator/gateway/routes", "gateway_routes", "HIGH"),
    ("/gateway/routes", "gateway_routes", "HIGH"),
];

// ═══════════════════════════════════════════════════════════════════
// GRAPHQL ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/__graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/playground",
    "/graphql/playground",
    "/graphql/console",
    "/altair",
    "/explorer",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/graphql-explorer",
    "/graphql/v1",
    "/graph",
    "/graphql/schema",
];

// ═══════════════════════════════════════════════════════════════════
// SENSITIVE FILES LIST
// ═══════════════════════════════════════════════════════════════════

const SENSITIVE_FILES: &[(&str, &str, &str)] = &[
    // Git exposure
    ("/.git/config", "git_config", "CRITICAL"),
    ("/.git/HEAD", "git_head", "HIGH"),
    ("/.git/index", "git_index", "HIGH"),
    ("/.git/logs/HEAD", "git_logs", "HIGH"),
    ("/.git/COMMIT_EDITMSG", "git_commit_msg", "MEDIUM"),
    ("/.gitignore", "gitignore", "LOW"),

    // Environment files
    ("/.env", "env_file", "CRITICAL"),
    ("/.env.local", "env_file", "CRITICAL"),
    ("/.env.production", "env_file", "CRITICAL"),
    ("/.env.development", "env_file", "HIGH"),
    ("/.env.staging", "env_file", "CRITICAL"),
    ("/.env.backup", "env_file", "CRITICAL"),
    ("/.env.bak", "env_file", "CRITICAL"),
    ("/.env.old", "env_file", "CRITICAL"),
    ("/.env.example", "env_example", "MEDIUM"),
    ("/env.js", "env_js", "HIGH"),
    ("/config.js", "config_js", "HIGH"),

    // Web server configs
    ("/.htaccess", "htaccess", "MEDIUM"),
    ("/.htpasswd", "htpasswd", "CRITICAL"),
    ("/web.config", "web_config", "HIGH"),
    ("/crossdomain.xml", "crossdomain", "MEDIUM"),
    ("/clientaccesspolicy.xml", "client_access_policy", "MEDIUM"),
    ("/nginx.conf", "nginx_config", "HIGH"),
    ("/apache.conf", "apache_config", "HIGH"),

    // Package managers
    ("/package.json", "package_json", "MEDIUM"),
    ("/package-lock.json", "package_lock", "LOW"),
    ("/yarn.lock", "yarn_lock", "LOW"),
    ("/composer.json", "composer_json", "MEDIUM"),
    ("/composer.lock", "composer_lock", "LOW"),
    ("/Gemfile", "gemfile", "MEDIUM"),
    ("/Gemfile.lock", "gemfile_lock", "LOW"),
    ("/requirements.txt", "requirements", "LOW"),
    ("/Pipfile", "pipfile", "MEDIUM"),
    ("/go.mod", "go_mod", "LOW"),
    ("/go.sum", "go_sum", "LOW"),
    ("/Cargo.toml", "cargo_toml", "LOW"),
    ("/pom.xml", "pom_xml", "MEDIUM"),
    ("/build.gradle", "build_gradle", "MEDIUM"),

    // Database dumps
    ("/backup.sql", "sql_dump", "CRITICAL"),
    ("/database.sql", "sql_dump", "CRITICAL"),
    ("/dump.sql", "sql_dump", "CRITICAL"),
    ("/db.sql", "sql_dump", "CRITICAL"),
    ("/data.sql", "sql_dump", "CRITICAL"),
    ("/mysql.sql", "sql_dump", "CRITICAL"),
    ("/backup.tar.gz", "backup_archive", "CRITICAL"),
    ("/backup.zip", "backup_archive", "CRITICAL"),

    // Backup files
    ("/config.php.bak", "config_backup", "CRITICAL"),
    ("/wp-config.php.bak", "wordpress_config", "CRITICAL"),
    ("/config.php.old", "config_backup", "CRITICAL"),
    ("/config.php~", "config_backup", "CRITICAL"),
    ("/settings.php.bak", "config_backup", "CRITICAL"),
    ("/web.config.bak", "web_config_backup", "HIGH"),
    ("/.config.php.swp", "vim_swap", "HIGH"),

    // SVN/HG exposure
    ("/.svn/entries", "svn_entries", "HIGH"),
    ("/.svn/wc.db", "svn_db", "HIGH"),
    ("/.hg/hgrc", "hg_config", "HIGH"),
    ("/.bzr/README", "bzr_readme", "MEDIUM"),

    // IDE files
    ("/.idea/workspace.xml", "idea_workspace", "MEDIUM"),
    ("/.vscode/settings.json", "vscode_settings", "MEDIUM"),
    ("/.DS_Store", "ds_store", "LOW"),

    // Server info
    ("/server-status", "server_status", "HIGH"),
    ("/server-info", "server_info", "HIGH"),
    ("/phpinfo.php", "phpinfo", "HIGH"),
    ("/info.php", "phpinfo", "HIGH"),
    ("/php_info.php", "phpinfo", "HIGH"),
    ("/test.php", "test_file", "MEDIUM"),
    ("/debug.php", "debug_file", "HIGH"),
    ("/adminer.php", "adminer", "CRITICAL"),
    ("/phpmyadmin/", "phpmyadmin", "CRITICAL"),

    // Keys and credentials
    ("/id_rsa", "ssh_private_key", "CRITICAL"),
    ("/id_rsa.pub", "ssh_public_key", "MEDIUM"),
    ("/id_dsa", "ssh_private_key", "CRITICAL"),
    ("/.ssh/id_rsa", "ssh_private_key", "CRITICAL"),
    ("/.ssh/authorized_keys", "ssh_authorized_keys", "HIGH"),
    ("/credentials.json", "credentials", "CRITICAL"),
    ("/secrets.json", "secrets", "CRITICAL"),
    ("/service-account.json", "gcp_service_account", "CRITICAL"),
    ("/.aws/credentials", "aws_credentials", "CRITICAL"),
    ("/aws.yml", "aws_config", "CRITICAL"),

    // Config files
    ("/config.yml", "config_yaml", "HIGH"),
    ("/config.yaml", "config_yaml", "HIGH"),
    ("/application.yml", "spring_config", "HIGH"),
    ("/application.yaml", "spring_config", "HIGH"),
    ("/application.properties", "spring_config", "HIGH"),
    ("/appsettings.json", "dotnet_config", "HIGH"),
    ("/settings.json", "settings_json", "MEDIUM"),
    ("/firebase.json", "firebase_config", "HIGH"),
    ("/firebaseConfig.js", "firebase_config", "HIGH"),

    // Debug/Admin endpoints
    ("/debug", "debug_endpoint", "HIGH"),
    ("/debug/", "debug_endpoint", "HIGH"),
    ("/trace", "trace_endpoint", "HIGH"),
    ("/elmah.axd", "elmah", "HIGH"),
    ("/_profiler", "symfony_profiler", "HIGH"),
    ("/_debugbar", "laravel_debugbar", "HIGH"),
    ("/telescope", "laravel_telescope", "HIGH"),

    // API documentation
    ("/swagger.json", "swagger", "MEDIUM"),
    ("/swagger.yaml", "swagger", "MEDIUM"),
    ("/swagger-ui.html", "swagger_ui", "MEDIUM"),
    ("/swagger-ui/", "swagger_ui", "MEDIUM"),
    ("/api-docs", "api_docs", "MEDIUM"),
    ("/v2/api-docs", "api_docs", "MEDIUM"),
    ("/v3/api-docs", "api_docs", "MEDIUM"),
    ("/openapi.json", "openapi", "MEDIUM"),
    ("/openapi.yaml", "openapi", "MEDIUM"),
    ("/redoc", "redoc", "MEDIUM"),
    ("/docs", "docs", "LOW"),

    // Logs
    ("/logs/", "logs_dir", "HIGH"),
    ("/log/", "logs_dir", "HIGH"),
    ("/error.log", "error_log", "HIGH"),
    ("/access.log", "access_log", "HIGH"),
    ("/debug.log", "debug_log", "HIGH"),
    ("/application.log", "app_log", "HIGH"),

    // Well-known
    ("/.well-known/security.txt", "security_txt", "INFO"),
    ("/.well-known/openid-configuration", "openid_config", "MEDIUM"),
    ("/.well-known/jwks.json", "jwks", "MEDIUM"),
    ("/robots.txt", "robots", "INFO"),
    ("/sitemap.xml", "sitemap", "INFO"),
    ("/crossdomain.xml", "crossdomain", "MEDIUM"),

    // WordPress specific
    ("/wp-config.php", "wp_config", "CRITICAL"),
    ("/wp-config.php.bak", "wp_config_backup", "CRITICAL"),
    ("/wp-includes/version.php", "wp_version", "LOW"),
    ("/readme.html", "wp_readme", "LOW"),
    ("/license.txt", "license", "INFO"),
    ("/xmlrpc.php", "xmlrpc", "MEDIUM"),

    // Drupal specific
    ("/sites/default/settings.php", "drupal_settings", "CRITICAL"),
    ("/CHANGELOG.txt", "drupal_changelog", "LOW"),

    // Laravel specific
    ("/storage/logs/laravel.log", "laravel_log", "HIGH"),
    ("/.env.example", "env_example", "MEDIUM"),

    // Node.js/JS frameworks
    ("/node_modules/", "node_modules", "LOW"),
    ("/dist/", "dist_folder", "LOW"),
    ("/build/", "build_folder", "LOW"),
];

// ═══════════════════════════════════════════════════════════════════
// MAIN SCANNER FUNCTION
// ═══════════════════════════════════════════════════════════════════

pub async fn run_info_disclosure_scan(
    domain: &str,
    output_dir: &Path,
    http200_file: Option<&Path>,
    js_files: Option<&[String]>,
    verbose: bool,
) -> Result<InfoDisclosureResults> {
    println!(
        "\n{} Starting Information Disclosure Scan for {}",
        "[INFO-DISCLOSURE]".cyan().bold(),
        domain.yellow()
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .context("Failed to create HTTP client")?;

    let mut results = InfoDisclosureResults {
        domain: domain.to_string(),
        scan_timestamp: Utc::now().to_rfc3339(),
        cloud_storage_findings: Vec::new(),
        actuator_findings: Vec::new(),
        graphql_findings: Vec::new(),
        sensitive_files: Vec::new(),
        total_findings: 0,
    };

    // 1. Extract cloud storage URLs and scan
    println!("\n{} Scanning for cloud storage misconfigurations...", "[S3/CLOUD]".magenta().bold());
    let cloud_urls = extract_cloud_storage_urls(http200_file, js_files).await;
    if !cloud_urls.is_empty() {
        results.cloud_storage_findings = scan_cloud_storage(&client, &cloud_urls, verbose).await?;
    } else if verbose {
        println!("  {} No cloud storage URLs found to scan", "[INFO]".blue());
    }

    // 2. Scan for Spring Boot Actuator endpoints
    println!("\n{} Scanning for Spring Boot Actuator endpoints...", "[ACTUATOR]".magenta().bold());
    results.actuator_findings = scan_actuator_endpoints(&client, domain, output_dir, verbose).await?;

    // 3. Scan for GraphQL endpoints
    println!("\n{} Scanning for GraphQL introspection...", "[GRAPHQL]".magenta().bold());
    results.graphql_findings = scan_graphql_endpoints(&client, domain, output_dir, verbose).await?;

    // 4. Scan for sensitive files
    println!("\n{} Scanning for sensitive files...", "[SENSITIVE]".magenta().bold());
    results.sensitive_files = scan_sensitive_files(&client, domain, verbose).await?;

    // Calculate total findings
    results.total_findings = results.cloud_storage_findings.len()
        + results.actuator_findings.len()
        + results.graphql_findings.len()
        + results.sensitive_files.len();

    // Save results
    let results_path = output_dir.join("info_disclosure_results.json");
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&results_path, &json)?;

    // Print summary
    println!(
        "\n{} Information Disclosure Scan Complete!",
        "[DONE]".green().bold()
    );
    println!(
        "  {} Cloud Storage: {} findings",
        "├─".cyan(),
        results.cloud_storage_findings.len().to_string().yellow()
    );
    println!(
        "  {} Actuator: {} findings",
        "├─".cyan(),
        results.actuator_findings.len().to_string().yellow()
    );
    println!(
        "  {} GraphQL: {} findings",
        "├─".cyan(),
        results.graphql_findings.len().to_string().yellow()
    );
    println!(
        "  {} Sensitive Files: {} findings",
        "└─".cyan(),
        results.sensitive_files.len().to_string().yellow()
    );
    println!(
        "\n  {} Results saved to: {}",
        "📄".cyan(),
        results_path.display().to_string().green()
    );

    Ok(results)
}

// ═══════════════════════════════════════════════════════════════════
// CLOUD STORAGE SCANNING (Native Rust Implementation)
// ═══════════════════════════════════════════════════════════════════

async fn extract_cloud_storage_urls(
    http200_file: Option<&Path>,
    js_files: Option<&[String]>,
) -> Vec<StorageTarget> {
    let mut targets: HashSet<StorageTarget> = HashSet::new();

    // Extract from http200 file
    if let Some(path) = http200_file {
        if path.exists() {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    extract_storage_targets_from_text(&line, &mut targets);
                }
            }
        }
    }

    // Extract from JS file contents
    if let Some(js_list) = js_files {
        for content in js_list {
            extract_storage_targets_from_text(content, &mut targets);
        }
    }

    targets.into_iter().collect()
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct StorageTarget {
    bucket_name: String,
    provider: String,
    region: Option<String>,
    original_url: String,
}

fn extract_storage_targets_from_text(text: &str, targets: &mut HashSet<StorageTarget>) {
    // AWS S3 Virtual-hosted style
    for cap in RE_S3_VIRTUAL.captures_iter(text) {
        let bucket = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let region = cap.get(2).map(|m| m.as_str().to_string());
        targets.insert(StorageTarget {
            bucket_name: bucket.to_string(),
            provider: "AWS S3".to_string(),
            region,
            original_url: cap[0].to_string(),
        });
    }

    // AWS S3 Path style
    for cap in RE_S3_PATH.captures_iter(text) {
        let region = cap.get(1).map(|m| m.as_str().to_string());
        let bucket = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        targets.insert(StorageTarget {
            bucket_name: bucket.to_string(),
            provider: "AWS S3".to_string(),
            region,
            original_url: cap[0].to_string(),
        });
    }

    // AWS S3 URI
    for cap in RE_S3_URI.captures_iter(text) {
        if let Some(bucket) = cap.get(1) {
            targets.insert(StorageTarget {
                bucket_name: bucket.as_str().to_string(),
                provider: "AWS S3".to_string(),
                region: None,
                original_url: cap[0].to_string(),
            });
        }
    }

    // Google Cloud Storage
    for cap in RE_GCS_VIRTUAL.captures_iter(text) {
        if let Some(bucket) = cap.get(1) {
            targets.insert(StorageTarget {
                bucket_name: bucket.as_str().to_string(),
                provider: "Google Cloud Storage".to_string(),
                region: None,
                original_url: cap[0].to_string(),
            });
        }
    }
    for cap in RE_GCS_PATH.captures_iter(text) {
        if let Some(bucket) = cap.get(1) {
            targets.insert(StorageTarget {
                bucket_name: bucket.as_str().to_string(),
                provider: "Google Cloud Storage".to_string(),
                region: None,
                original_url: cap[0].to_string(),
            });
        }
    }

    // Azure Blob Storage
    for cap in RE_AZURE_BLOB.captures_iter(text) {
        let account = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let container = cap.get(2).map(|m| m.as_str()).unwrap_or("$root");
        targets.insert(StorageTarget {
            bucket_name: format!("{}/{}", account, container),
            provider: "Azure Blob Storage".to_string(),
            region: None,
            original_url: cap[0].to_string(),
        });
    }

    // DigitalOcean Spaces
    for cap in RE_DO_SPACES.captures_iter(text) {
        let bucket = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let region = cap.get(2).map(|m| m.as_str().to_string());
        targets.insert(StorageTarget {
            bucket_name: bucket.to_string(),
            provider: "DigitalOcean Spaces".to_string(),
            region,
            original_url: cap[0].to_string(),
        });
    }

    // Cloudflare R2
    for cap in RE_CLOUDFLARE_R2.captures_iter(text) {
        let account = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        targets.insert(StorageTarget {
            bucket_name: account.to_string(),
            provider: "Cloudflare R2".to_string(),
            region: None,
            original_url: cap[0].to_string(),
        });
    }

    // Alibaba OSS
    for cap in RE_ALIBABA_OSS.captures_iter(text) {
        let bucket = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let region = cap.get(2).map(|m| m.as_str().to_string());
        targets.insert(StorageTarget {
            bucket_name: bucket.to_string(),
            provider: "Alibaba Cloud OSS".to_string(),
            region,
            original_url: cap[0].to_string(),
        });
    }
}

async fn scan_cloud_storage(
    client: &Client,
    targets: &[StorageTarget],
    verbose: bool,
) -> Result<Vec<CloudStorageFinding>> {
    let mut findings = Vec::new();

    println!(
        "  {} Found {} cloud storage targets to scan",
        "[INFO]".blue(),
        targets.len()
    );

    for target in targets {
        let finding = test_storage_permissions(client, target, verbose).await;
        if let Some(f) = finding {
            // Only report vulnerable buckets
            if f.can_list || f.can_write || f.can_delete || f.takeover_possible {
                let severity_color = match f.severity.as_str() {
                    "CRITICAL" => f.severity.red().bold(),
                    "HIGH" => f.severity.red(),
                    _ => f.severity.yellow(),
                };

                println!(
                    "  {} [{}] {} ({}) - LIST:{} WRITE:{} DELETE:{} TAKEOVER:{}",
                    "[VULN]".red().bold(),
                    severity_color,
                    target.bucket_name.yellow(),
                    target.provider.cyan(),
                    if f.can_list { "YES".red() } else { "NO".green() },
                    if f.can_write { "YES".red() } else { "NO".green() },
                    if f.can_delete { "YES".red() } else { "NO".green() },
                    if f.takeover_possible { "YES".red() } else { "NO".green() },
                );

                findings.push(f);
            } else if verbose {
                println!(
                    "  {} {} - Bucket exists but properly secured",
                    "[SECURE]".green(),
                    target.bucket_name
                );
            }
        }
    }

    Ok(findings)
}

async fn test_storage_permissions(
    client: &Client,
    target: &StorageTarget,
    _verbose: bool,
) -> Option<CloudStorageFinding> {
    let test_urls = generate_test_urls(target);

    let mut finding = CloudStorageFinding {
        bucket_url: target.original_url.clone(),
        bucket_name: target.bucket_name.clone(),
        provider: target.provider.clone(),
        region: target.region.clone(),
        can_list: false,
        can_read: false,
        can_write: false,
        can_delete: false,
        takeover_possible: false,
        files_found: Vec::new(),
        severity: "INFO".to_string(),
        discovered_at: Utc::now().to_rfc3339(),
    };

    // Test LIST permission
    for url in &test_urls.list_urls {
        if let Ok(response) = client.get(url).send().await {
            let status = response.status();
            if status == StatusCode::OK {
                finding.can_list = true;
                finding.can_read = true;

                // Try to extract file list from XML response
                if let Ok(body) = response.text().await {
                    let file_regex = Regex::new(r"<Key>([^<]+)</Key>").ok();
                    if let Some(re) = file_regex {
                        for cap in re.captures_iter(&body) {
                            if let Some(key) = cap.get(1) {
                                finding.files_found.push(key.as_str().to_string());
                                if finding.files_found.len() >= 10 {
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            } else if status == StatusCode::NOT_FOUND {
                // Bucket doesn't exist - potential takeover
                finding.takeover_possible = true;
            }
        }
    }

    // Test WRITE permission (only if bucket exists)
    if !finding.takeover_possible {
        let test_key = format!("enumrust-write-test-{}.txt", uuid::Uuid::new_v4());
        for url in &test_urls.write_urls {
            let write_url = format!("{}/{}", url.trim_end_matches('/'), test_key);
            if let Ok(response) = client
                .put(&write_url)
                .body("enumrust-security-test")
                .send()
                .await
            {
                if response.status().is_success() || response.status() == StatusCode::OK {
                    finding.can_write = true;

                    // Try to delete test file
                    if let Ok(del_response) = client.delete(&write_url).send().await {
                        if del_response.status().is_success() {
                            finding.can_delete = true;
                        }
                    }
                    break;
                }
            }
        }
    }

    // Determine severity
    finding.severity = if finding.takeover_possible {
        "CRITICAL".to_string()
    } else if finding.can_write || finding.can_delete {
        "CRITICAL".to_string()
    } else if finding.can_list {
        "HIGH".to_string()
    } else if finding.can_read {
        "MEDIUM".to_string()
    } else {
        "INFO".to_string()
    };

    // Only return if there's something interesting
    if finding.can_list || finding.can_write || finding.can_delete || finding.takeover_possible {
        Some(finding)
    } else {
        None
    }
}

struct TestUrls {
    list_urls: Vec<String>,
    write_urls: Vec<String>,
}

fn generate_test_urls(target: &StorageTarget) -> TestUrls {
    let mut list_urls = Vec::new();
    let mut write_urls = Vec::new();

    match target.provider.as_str() {
        "AWS S3" => {
            let regions = if let Some(ref r) = target.region {
                vec![r.clone()]
            } else {
                vec![
                    "us-east-1".to_string(),
                    "us-west-2".to_string(),
                    "eu-west-1".to_string(),
                ]
            };

            for region in &regions {
                // Virtual-hosted style
                list_urls.push(format!(
                    "https://{}.s3.{}.amazonaws.com/",
                    target.bucket_name, region
                ));
                list_urls.push(format!(
                    "https://{}.s3.amazonaws.com/",
                    target.bucket_name
                ));
                // Path style
                list_urls.push(format!(
                    "https://s3.{}.amazonaws.com/{}/",
                    region, target.bucket_name
                ));
            }
            write_urls = list_urls.clone();
        }
        "Google Cloud Storage" => {
            list_urls.push(format!(
                "https://storage.googleapis.com/{}/",
                target.bucket_name
            ));
            list_urls.push(format!(
                "https://{}.storage.googleapis.com/",
                target.bucket_name
            ));
            write_urls = list_urls.clone();
        }
        "Azure Blob Storage" => {
            let parts: Vec<&str> = target.bucket_name.split('/').collect();
            if parts.len() >= 2 {
                let account = parts[0];
                let container = parts[1];
                list_urls.push(format!(
                    "https://{}.blob.core.windows.net/{}?restype=container&comp=list",
                    account, container
                ));
                write_urls.push(format!(
                    "https://{}.blob.core.windows.net/{}/",
                    account, container
                ));
            }
        }
        "DigitalOcean Spaces" => {
            let region = target.region.as_deref().unwrap_or("nyc3");
            list_urls.push(format!(
                "https://{}.{}.digitaloceanspaces.com/",
                target.bucket_name, region
            ));
            write_urls = list_urls.clone();
        }
        "Cloudflare R2" => {
            list_urls.push(format!("https://{}.r2.dev/", target.bucket_name));
            write_urls = list_urls.clone();
        }
        _ => {
            list_urls.push(target.original_url.clone());
            write_urls = list_urls.clone();
        }
    }

    TestUrls {
        list_urls,
        write_urls,
    }
}

// ═══════════════════════════════════════════════════════════════════
// SPRING BOOT ACTUATOR SCANNING (Native Rust Implementation)
// ═══════════════════════════════════════════════════════════════════

async fn scan_actuator_endpoints(
    client: &Client,
    domain: &str,
    output_dir: &Path,
    verbose: bool,
) -> Result<Vec<ActuatorFinding>> {
    let mut findings = Vec::new();
    let actuator_dir = output_dir.join("actuator_scan");
    fs::create_dir_all(&actuator_dir)?;

    let base_urls = vec![
        format!("https://{}", domain),
        format!("http://{}", domain),
    ];

    let total_checks = base_urls.len() * ACTUATOR_ENDPOINTS.len();
    println!(
        "  {} Testing {} actuator endpoints...",
        "[INFO]".blue(),
        total_checks
    );

    // Use concurrent scanning
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(20));

    let mut tasks = Vec::new();

    for base_url in &base_urls {
        for (path, endpoint_type, severity) in ACTUATOR_ENDPOINTS {
            let url = format!("{}{}", base_url, path);
            let client = client.clone();
            let endpoint_type = endpoint_type.to_string();
            let severity = severity.to_string();
            let permit = semaphore.clone();
            let actuator_dir = actuator_dir.clone();

            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.ok()?;
                test_actuator_endpoint(&client, &url, &endpoint_type, &severity, &actuator_dir).await
            });

            tasks.push(task);
        }
    }

    // Collect results
    for task in tasks {
        if let Ok(Some(finding)) = task.await {
            let severity_color = match finding.severity.as_str() {
                "CRITICAL" => finding.severity.clone().red().bold(),
                "HIGH" => finding.severity.clone().red(),
                "MEDIUM" => finding.severity.clone().yellow(),
                _ => finding.severity.clone().blue(),
            };

            println!(
                "  {} [{}] {} - {} ({} bytes)",
                "[FOUND]".red().bold(),
                severity_color,
                finding.endpoint.cyan(),
                finding.url.yellow(),
                finding.response_size
            );

            if !finding.sensitive_data_types.is_empty() {
                println!(
                    "       {} Sensitive data: {}",
                    "└─".cyan(),
                    finding.sensitive_data_types.join(", ").red()
                );
            }

            findings.push(finding);
        }
    }

    // Sort by severity
    findings.sort_by(|a, b| {
        let sev_order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 4,
        };
        sev_order(&a.severity).cmp(&sev_order(&b.severity))
    });

    if verbose && findings.is_empty() {
        println!("  {} No exposed actuator endpoints found", "[SECURE]".green());
    }

    Ok(findings)
}

async fn test_actuator_endpoint(
    client: &Client,
    url: &str,
    endpoint_type: &str,
    severity: &str,
    output_dir: &Path,
) -> Option<ActuatorFinding> {
    let response = client.get(url).send().await.ok()?;
    let status = response.status();

    if !status.is_success() {
        return None;
    }

    let headers = response.headers().clone();
    let body = response.bytes().await.ok()?;
    let body_str = String::from_utf8_lossy(&body);

    // Validate it's actually an actuator endpoint
    if !is_valid_actuator_response(&body_str, endpoint_type, &headers) {
        return None;
    }

    // Check for sensitive data
    let (has_sensitive, sensitive_types) = detect_sensitive_data(&body_str, endpoint_type);

    // Save heapdump/threaddump to file
    if endpoint_type == "heapdump" || endpoint_type == "threaddump" {
        let filename = format!("{}_{}.bin", endpoint_type, chrono::Utc::now().timestamp());
        let filepath = output_dir.join(&filename);
        if fs::write(&filepath, &body).is_ok() {
            println!(
                "  {} Saved {} to {}",
                "[SAVED]".green(),
                endpoint_type,
                filepath.display()
            );
        }
    }

    // Create preview (sanitized)
    let preview: String = body_str
        .chars()
        .take(200)
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();

    Some(ActuatorFinding {
        url: url.to_string(),
        endpoint: endpoint_type.to_string(),
        status_code: status.as_u16(),
        response_size: body.len(),
        content_preview: preview,
        has_sensitive_data: has_sensitive,
        sensitive_data_types: sensitive_types,
        severity: severity.to_string(),
        discovered_at: Utc::now().to_rfc3339(),
    })
}

fn is_valid_actuator_response(body: &str, endpoint_type: &str, headers: &reqwest::header::HeaderMap) -> bool {
    // Check content type
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match endpoint_type {
        "heapdump" => {
            // Heapdump should be binary/octet-stream and contain Java signatures
            content_type.contains("octet-stream") ||
            body.contains("java/lang/") ||
            body.len() > 1_000_000 // Usually > 1MB
        }
        "threaddump" => {
            body.contains("threadName") || body.contains("java.lang.Thread")
        }
        "env" | "configprops" => {
            body.contains("\"propertySources\"") ||
            body.contains("\"property\"") ||
            body.contains("spring.") ||
            body.contains("\"contextId\"")
        }
        "beans" => {
            body.contains("\"beans\"") || body.contains("\"context\"")
        }
        "mappings" => {
            body.contains("\"dispatcherServlets\"") ||
            body.contains("\"requestMappingConditions\"") ||
            body.contains("\"handler\"")
        }
        "health" => {
            body.contains("\"status\"") && (body.contains("UP") || body.contains("DOWN"))
        }
        "info" => {
            body.starts_with("{") && (body.contains("\"build\"") || body.contains("\"git\"") || body.len() > 2)
        }
        "actuator_index" => {
            body.contains("\"_links\"") || body.contains("\"self\"")
        }
        "metrics" | "prometheus" => {
            body.contains("jvm.") || body.contains("http.") || body.contains("# HELP")
        }
        "loggers" => {
            body.contains("\"levels\"") || body.contains("\"loggers\"")
        }
        "jolokia" | "jolokia_list" => {
            body.contains("\"request\"") || body.contains("\"value\"") || body.contains("jolokia")
        }
        "gateway_routes" => {
            body.contains("\"route_id\"") || body.contains("\"predicates\"")
        }
        _ => {
            // Generic JSON check
            body.starts_with("{") || body.starts_with("[")
        }
    }
}

fn detect_sensitive_data(body: &str, endpoint_type: &str) -> (bool, Vec<String>) {
    let mut sensitive_types = Vec::new();
    let body_lower = body.to_lowercase();

    // Check for common sensitive patterns
    let patterns = [
        ("password", "passwords"),
        ("secret", "secrets"),
        ("api_key", "API keys"),
        ("apikey", "API keys"),
        ("token", "tokens"),
        ("credential", "credentials"),
        ("private_key", "private keys"),
        ("aws_access", "AWS credentials"),
        ("jdbc:", "database connections"),
        ("mongodb://", "MongoDB connections"),
        ("redis://", "Redis connections"),
        ("mysql://", "MySQL connections"),
        ("postgres://", "PostgreSQL connections"),
    ];

    for (pattern, label) in patterns {
        if body_lower.contains(pattern) {
            sensitive_types.push(label.to_string());
        }
    }

    // Endpoint-specific sensitive data
    match endpoint_type {
        "env" | "configprops" => {
            if body.contains("spring.datasource") {
                sensitive_types.push("database config".to_string());
            }
            if body.contains("spring.mail") {
                sensitive_types.push("mail config".to_string());
            }
        }
        "heapdump" => {
            sensitive_types.push("memory dump (may contain secrets)".to_string());
        }
        "httptrace" => {
            sensitive_types.push("HTTP request history".to_string());
        }
        _ => {}
    }

    let has_sensitive = !sensitive_types.is_empty();
    sensitive_types.dedup();
    (has_sensitive, sensitive_types)
}

// ═══════════════════════════════════════════════════════════════════
// GRAPHQL INTROSPECTION SCANNING (Native Rust Implementation)
// ═══════════════════════════════════════════════════════════════════

const INTROSPECTION_QUERY: &str = r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields(includeDeprecated: true) { name description args { name description type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}"#;

const SIMPLE_INTROSPECTION: &str = r#"{"query":"{ __schema { types { name kind } } }"}"#;

async fn scan_graphql_endpoints(
    client: &Client,
    domain: &str,
    output_dir: &Path,
    verbose: bool,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();
    let graphql_dir = output_dir.join("graphql_scan");
    fs::create_dir_all(&graphql_dir)?;

    let base_urls = vec![
        format!("https://{}", domain),
        format!("http://{}", domain),
    ];

    println!(
        "  {} Testing {} GraphQL endpoints...",
        "[INFO]".blue(),
        GRAPHQL_PATHS.len() * 2
    );

    for base_url in &base_urls {
        for path in GRAPHQL_PATHS {
            let url = format!("{}{}", base_url, path);

            if let Some(finding) = test_graphql_endpoint(client, &url, &graphql_dir, verbose).await {
                let severity_color = match finding.severity.as_str() {
                    "CRITICAL" => finding.severity.clone().red().bold(),
                    "HIGH" => finding.severity.clone().red(),
                    _ => finding.severity.clone().yellow(),
                };

                println!(
                    "  {} [{}] {} - Introspection: {}",
                    "[FOUND]".red().bold(),
                    severity_color,
                    url.yellow(),
                    if finding.introspection_enabled { "ENABLED".red() } else { "disabled".green() }
                );

                if finding.introspection_enabled {
                    println!(
                        "       {} Types: {}, Queries: {}, Mutations: {}",
                        "└─".cyan(),
                        finding.types_discovered.to_string().yellow(),
                        finding.queries_discovered.to_string().yellow(),
                        finding.mutations_discovered.to_string().yellow()
                    );
                }

                findings.push(finding);
            }
        }
    }

    if verbose && findings.is_empty() {
        println!("  {} No GraphQL endpoints found", "[INFO]".blue());
    }

    Ok(findings)
}

async fn test_graphql_endpoint(
    client: &Client,
    url: &str,
    output_dir: &Path,
    _verbose: bool,
) -> Option<GraphQLFinding> {
    // First, try simple introspection
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(SIMPLE_INTROSPECTION)
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let body = response.text().await.ok()?;

    // Check if it's a valid GraphQL response
    if !body.contains("__schema") && !body.contains("data") {
        return None;
    }

    let introspection_enabled = body.contains("__schema") && body.contains("types");

    let mut finding = GraphQLFinding {
        url: url.to_string(),
        introspection_enabled,
        schema: None,
        types_discovered: 0,
        queries_discovered: 0,
        mutations_discovered: 0,
        subscriptions_discovered: 0,
        severity: if introspection_enabled { "HIGH".to_string() } else { "MEDIUM".to_string() },
        discovered_at: Utc::now().to_rfc3339(),
    };

    // If introspection is enabled, get full schema
    if introspection_enabled {
        if let Some(schema) = extract_full_schema(client, url, output_dir).await {
            finding.types_discovered = schema.types.len();
            finding.queries_discovered = schema.types.iter()
                .filter(|t| t.name == schema.query_type.as_deref().unwrap_or("Query"))
                .flat_map(|t| t.fields.iter())
                .count();
            finding.mutations_discovered = schema.types.iter()
                .filter(|t| Some(&t.name) == schema.mutation_type.as_ref())
                .flat_map(|t| t.fields.iter())
                .count();
            finding.subscriptions_discovered = schema.types.iter()
                .filter(|t| Some(&t.name) == schema.subscription_type.as_ref())
                .flat_map(|t| t.fields.iter())
                .count();
            finding.schema = Some(schema);
        }
    }

    Some(finding)
}

async fn extract_full_schema(
    client: &Client,
    url: &str,
    output_dir: &Path,
) -> Option<GraphQLSchema> {
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(INTROSPECTION_QUERY)
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let body = response.text().await.ok()?;

    // Save raw schema
    let safe_url = url.replace("://", "_").replace("/", "_").replace(":", "_");
    let schema_path = output_dir.join(format!("schema_{}.json", safe_url));
    let _ = fs::write(&schema_path, &body);

    // Parse schema
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let schema_data = json.get("data")?.get("__schema")?;

    let query_type = schema_data
        .get("queryType")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mutation_type = schema_data
        .get("mutationType")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let subscription_type = schema_data
        .get("subscriptionType")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let types_array = schema_data.get("types")?.as_array()?;
    let mut types = Vec::new();

    for type_obj in types_array {
        let name = type_obj.get("name")?.as_str()?.to_string();

        // Skip internal types
        if name.starts_with("__") {
            continue;
        }

        let kind = type_obj
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        let mut fields = Vec::new();
        if let Some(fields_array) = type_obj.get("fields").and_then(|v| v.as_array()) {
            for field_obj in fields_array {
                let field_name = field_obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let field_type = extract_type_name(field_obj.get("type"));

                let args: Vec<String> = field_obj
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|a| a.get("name").and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                fields.push(GraphQLField {
                    name: field_name,
                    field_type,
                    args,
                });
            }
        }

        types.push(GraphQLType { name, kind, fields });
    }

    Some(GraphQLSchema {
        types,
        query_type,
        mutation_type,
        subscription_type,
    })
}

fn extract_type_name(type_value: Option<&serde_json::Value>) -> String {
    let type_obj = match type_value {
        Some(v) => v,
        None => return "Unknown".to_string(),
    };

    if let Some(name) = type_obj.get("name").and_then(|v| v.as_str()) {
        return name.to_string();
    }

    if let Some(of_type) = type_obj.get("ofType") {
        let inner = extract_type_name(Some(of_type));
        let kind = type_obj
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        return match kind {
            "NON_NULL" => format!("{}!", inner),
            "LIST" => format!("[{}]", inner),
            _ => inner,
        };
    }

    "Unknown".to_string()
}

// ═══════════════════════════════════════════════════════════════════
// SENSITIVE FILES SCANNING (Native Rust Implementation)
// ═══════════════════════════════════════════════════════════════════

async fn scan_sensitive_files(
    client: &Client,
    domain: &str,
    verbose: bool,
) -> Result<Vec<SensitiveFileFinding>> {
    let mut findings = Vec::new();

    let base_urls = vec![
        format!("https://{}", domain),
        format!("http://{}", domain),
    ];

    println!(
        "  {} Testing {} sensitive file paths...",
        "[INFO]".blue(),
        SENSITIVE_FILES.len()
    );

    // Use concurrent scanning
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(30));
    let mut tasks = Vec::new();

    for base_url in &base_urls {
        for (path, file_type, severity) in SENSITIVE_FILES {
            let url = format!("{}{}", base_url, path);
            let client = client.clone();
            let file_type = file_type.to_string();
            let severity = severity.to_string();
            let permit = semaphore.clone();

            let task = tokio::spawn(async move {
                let _permit = permit.acquire().await.ok()?;
                test_sensitive_file(&client, &url, &file_type, &severity).await
            });

            tasks.push(task);
        }
    }

    // Collect results
    let mut seen_files: HashSet<String> = HashSet::new();

    for task in tasks {
        if let Ok(Some(finding)) = task.await {
            // Deduplicate by file type (same file found on http and https)
            if seen_files.contains(&finding.file_type) {
                continue;
            }
            seen_files.insert(finding.file_type.clone());

            let severity_color = match finding.severity.as_str() {
                "CRITICAL" => finding.severity.clone().red().bold(),
                "HIGH" => finding.severity.clone().red(),
                "MEDIUM" => finding.severity.clone().yellow(),
                _ => finding.severity.clone().blue(),
            };

            println!(
                "  {} [{}] {} - {} ({} bytes)",
                "[FOUND]".red().bold(),
                severity_color,
                finding.file_type.cyan(),
                finding.url.yellow(),
                finding.content_length
            );

            if !finding.secrets_found.is_empty() {
                println!(
                    "       {} Secrets found: {}",
                    "└─".cyan(),
                    finding.secrets_found.join(", ").red()
                );
            }

            findings.push(finding);
        }
    }

    // Sort by severity
    findings.sort_by(|a, b| {
        let sev_order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 4,
        };
        sev_order(&a.severity).cmp(&sev_order(&b.severity))
    });

    if verbose && findings.is_empty() {
        println!("  {} No sensitive files found", "[SECURE]".green());
    }

    Ok(findings)
}

async fn test_sensitive_file(
    client: &Client,
    url: &str,
    file_type: &str,
    severity: &str,
) -> Option<SensitiveFileFinding> {
    let response = client.get(url).send().await.ok()?;

    if response.status() != StatusCode::OK {
        return None;
    }

    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let body = response.text().await.ok()?;

    // Validate content
    if !validate_sensitive_content(&body, file_type) {
        return None;
    }

    // Look for secrets in content
    let secrets_found = find_secrets_in_content(&body);

    // Create preview (sanitized)
    let preview: String = body
        .chars()
        .take(300)
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();

    Some(SensitiveFileFinding {
        url: url.to_string(),
        file_type: file_type.to_string(),
        status_code: 200,
        content_length: if content_length > 0 { content_length } else { body.len() },
        content_preview: preview,
        secrets_found,
        severity: severity.to_string(),
        discovered_at: Utc::now().to_rfc3339(),
    })
}

fn validate_sensitive_content(content: &str, file_type: &str) -> bool {
    // Reject HTML error pages
    if content.contains("<!DOCTYPE html") || content.contains("<html") {
        // Unless it's specifically swagger-ui or similar
        if !matches!(file_type, "swagger_ui" | "redoc" | "docs") {
            return false;
        }
    }

    match file_type {
        "git_config" => content.contains("[core]") || content.contains("[remote") || content.contains("repositoryformatversion"),
        "git_head" => content.starts_with("ref:") || (content.len() == 40 && content.chars().all(|c| c.is_ascii_hexdigit())),
        "git_index" => content.starts_with("DIRC"),
        "env_file" => content.contains("=") && !content.starts_with("<"),
        "htaccess" => content.contains("Rewrite") || content.contains("Deny") || content.contains("Allow") || content.contains("Options"),
        "htpasswd" => content.contains(":") && content.lines().all(|l| l.contains(":") || l.is_empty()),
        "package_json" | "composer_json" => content.contains("\"name\"") && content.contains("\"version\""),
        "sql_dump" => content.contains("INSERT INTO") || content.contains("CREATE TABLE") || content.contains("DROP TABLE"),
        "phpinfo" => content.contains("PHP Version") || content.contains("phpinfo()") || content.contains("PHP Credits"),
        "swagger" | "openapi" => content.contains("swagger") || content.contains("openapi") || content.contains("\"paths\""),
        "swagger_ui" => content.contains("swagger-ui"),
        "web_config" => content.contains("<configuration") || content.contains("connectionStrings"),
        "spring_config" => content.contains("spring.") || content.contains("server.port") || content.contains("datasource"),
        "config_yaml" => content.contains(":") && (content.contains("database") || content.contains("password") || content.contains("host")),
        "wp_config" => content.contains("DB_NAME") || content.contains("DB_PASSWORD") || content.contains("WP_"),
        "drupal_settings" => content.contains("$databases") || content.contains("$settings"),
        "laravel_log" => content.contains("[stacktrace]") || content.contains("local.ERROR"),
        "server_status" | "server_info" => content.contains("Server Version") || content.contains("Apache"),
        "firebase_config" => content.contains("apiKey") && content.contains("projectId"),
        "credentials" | "secrets" => content.contains("\"") && (content.contains("key") || content.contains("secret") || content.contains("password")),
        "gcp_service_account" => content.contains("\"type\"") && content.contains("service_account"),
        "aws_credentials" => content.contains("[default]") || content.contains("aws_access_key_id"),
        _ => !content.is_empty() && content.len() < 10_000_000, // Accept non-empty responses under 10MB
    }
}

fn find_secrets_in_content(content: &str) -> Vec<String> {
    let mut secrets = Vec::new();
    let content_lower = content.to_lowercase();

    // Common secret patterns
    let patterns: &[(&str, &str)] = &[
        (r#"(?i)password\s*[=:]\s*['"]?([^'"\s\n]+)"#, "password"),
        (r#"(?i)api[_-]?key\s*[=:]\s*['"]?([^'"\s\n]+)"#, "API key"),
        (r#"(?i)secret[_-]?key\s*[=:]\s*['"]?([^'"\s\n]+)"#, "secret key"),
        (r#"(?i)access[_-]?token\s*[=:]\s*['"]?([^'"\s\n]+)"#, "access token"),
        (r#"(?i)auth[_-]?token\s*[=:]\s*['"]?([^'"\s\n]+)"#, "auth token"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"(?i)aws[_-]?secret", "AWS Secret"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key"),
        (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}", "Slack Token"),
    ];

    for (pattern, label) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(content) {
                secrets.push(label.to_string());
            }
        }
    }

    // Check for common keywords
    if content_lower.contains("private_key") || content_lower.contains("-----begin") {
        secrets.push("private key".to_string());
    }

    secrets.dedup();
    secrets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_url_extraction() {
        let mut targets = HashSet::new();

        let test_text = r#"
            https://my-bucket.s3.amazonaws.com/file.txt
            https://s3.us-west-2.amazonaws.com/another-bucket/
            s3://direct-bucket
            https://storage.googleapis.com/gcs-bucket/file
            https://myaccount.blob.core.windows.net/container/blob
            https://space.nyc3.digitaloceanspaces.com/
        "#;

        extract_storage_targets_from_text(test_text, &mut targets);

        assert!(targets.len() >= 5);
    }

    #[test]
    fn test_validate_git_config() {
        assert!(validate_sensitive_content("[core]\n\trepositoryformatversion = 0", "git_config"));
        assert!(!validate_sensitive_content("<!DOCTYPE html>", "git_config"));
    }

    #[test]
    fn test_validate_env_file() {
        assert!(validate_sensitive_content("DATABASE_URL=postgres://localhost", "env_file"));
        assert!(!validate_sensitive_content("<html><body>404</body></html>", "env_file"));
    }
}
