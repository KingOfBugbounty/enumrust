use axum::{
    extract::{State, Json, Path, Query},
    http::{StatusCode, HeaderMap, header},
    response::{IntoResponse, Response, Html},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::fs;
use std::path::PathBuf;
use chrono::Utc;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use tower_http::cors::CorsLayer;
use reqwest::Client;
use futures::stream::{self, StreamExt};
use tokio::sync::Semaphore;

use crate::progress::{ProgressEvent, ProgressTracker};
use crate::secrets_scanner::{HardcodedSecret, CloudStorageExposure};
use crate::package_scanner::PackageDependency;
use crate::ip_validator::ValidatedHost;
use rand::Rng;
use lazy_static::lazy_static;

// Gerar JWT Secret e Setup Code aleatórios em tempo de execução
lazy_static! {
    static ref JWT_SECRET: String = generate_random_string(64);
    static ref SETUP_CODE: String = generate_random_string(16);
}

fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// Custom error type for authentication to avoid large Result variant
#[derive(Debug)]
struct AuthError(Response);

impl From<AuthError> for Response {
    fn from(err: AuthError) -> Self {
        err.0
    }
}

// Configuração de paralelização - Limitar para não sobrecarregar
const MAX_PARALLEL_TRUFFLEHOG_SCANS: usize = 5; // Máximo de scans simultâneos

#[derive(Debug, Clone)]
pub struct AppState {
    pub base_path: PathBuf,
    pub webhook_url: Arc<Mutex<Option<String>>>,
    pub github_config: Arc<Mutex<Option<GitHubConfig>>>,
    pub trufflehog_secrets: Arc<Mutex<Vec<TruffleHogSecret>>>,
    pub admin_config: Arc<Mutex<Option<AdminConfig>>>,
    #[allow(dead_code)]
    pub http_client: Client,
}

// Estruturas para configuração de admin
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminConfig {
    pub username: String,
    pub password_hash: String,
    pub setup_completed: bool,
    pub created_at: String,
    pub last_password_change: String,
    #[serde(default = "default_false")]
    pub must_change_password: bool,
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    token: String,
    must_change_password: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    error: String,
}

// Estruturas para primeiro acesso e troca de senha
#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    setup_code: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
    setup_completed: bool,
    username: Option<String>,
    must_change_password: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub host: String,
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    #[serde(rename = "template-id")]
    pub template_id: String,
    pub info: VulnInfo,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub vuln_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(rename = "template-url", skip_serializing_if = "Option::is_none")]
    pub template_url: Option<String>,
    #[serde(rename = "template-path", skip_serializing_if = "Option::is_none")]
    pub template_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curl_command: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
    pub reference: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenPort {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub status: String,
}

// Helper function to parse ports.txt file
// Format: http://IP:PORT or https://IP:PORT
fn parse_ports_txt(ports_txt_path: &std::path::Path) -> Vec<OpenPort> {
    let mut ports = Vec::new();

    if !ports_txt_path.exists() {
        return ports;
    }

    if let Ok(content) = fs::read_to_string(ports_txt_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse URL format: http://IP:PORT or https://IP:PORT
            if let Some(url_str) = line.strip_prefix("http://").or(line.strip_prefix("https://")) {
                let is_https = line.starts_with("https://");
                let service = if is_https { "https" } else { "http" };

                // Split by ':' to get host and port
                if let Some((host, port_str)) = url_str.split_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        ports.push(OpenPort {
                            host: host.to_string(),
                            port,
                            protocol: "TCP".to_string(),
                            service: service.to_string(),
                            status: "open".to_string(),
                        });
                    }
                }
            }
        }
    }

    ports
}

// Helper function to parse js_secrets.txt file
// Format: [SECRET_TYPE] secret_value - source_url (validation_status)
#[allow(dead_code)]
fn parse_js_secrets_file(secrets_path: &std::path::Path) -> Vec<JsSecret> {
    let mut secrets = Vec::new();

    if !secrets_path.exists() {
        return secrets;
    }

    if let Ok(content) = fs::read_to_string(secrets_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to parse different formats
            // Format 1: [TYPE] value - url (STATUS)
            // Format 2: [TYPE] value - url
            // Format 3: Simple: type:value:url
            if let Some(rest) = line.strip_prefix('[') {
                if let Some((secret_type, rest)) = rest.split_once(']') {
                    let parts: Vec<&str> = rest.splitn(2, " - ").collect();
                    if parts.len() >= 2 {
                        let secret_value = parts[0].trim().to_string();
                        let url_and_status = parts[1];

                        // Check if there's a validation status in parentheses
                        let (source_url, validation_status) = if url_and_status.contains('(') {
                            let status_parts: Vec<&str> = url_and_status.rsplitn(2, '(').collect();
                            if status_parts.len() == 2 {
                                let status = status_parts[0].trim_end_matches(')').trim().to_string();
                                (status_parts[1].trim().to_string(), Some(status))
                            } else {
                                (url_and_status.trim().to_string(), None)
                            }
                        } else {
                            (url_and_status.trim().to_string(), None)
                        };

                        secrets.push(JsSecret {
                            secret_type: secret_type.trim().to_string(),
                            secret_value,
                            source_url,
                            validation_status,
                        });
                    }
                }
            }
        }
    }

    secrets
}

// Helper function to parse js_endpoints.txt file
// Format: [METHOD] endpoint - source_url or just endpoint - source_url
fn parse_js_endpoints_file(endpoints_path: &std::path::Path) -> Vec<JsEndpoint> {
    let mut endpoints = Vec::new();

    if !endpoints_path.exists() {
        return endpoints;
    }

    if let Ok(content) = fs::read_to_string(endpoints_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Format 1: [METHOD] endpoint - source_url
            if let Some(rest) = line.strip_prefix('[') {
                if let Some((method, rest)) = rest.split_once(']') {
                    let parts: Vec<&str> = rest.splitn(2, " - ").collect();
                    if parts.len() >= 2 {
                        endpoints.push(JsEndpoint {
                            endpoint: parts[0].trim().to_string(),
                            source_url: parts[1].trim().to_string(),
                            method: Some(method.trim().to_string()),
                        });
                    }
                }
            } else {
                // Format 2: endpoint - source_url (without method)
                let parts: Vec<&str> = line.splitn(2, " - ").collect();
                if parts.len() >= 2 {
                    endpoints.push(JsEndpoint {
                        endpoint: parts[0].trim().to_string(),
                        source_url: parts[1].trim().to_string(),
                        method: None,
                    });
                } else if line.starts_with("http") {
                    // Format 3: Just a URL
                    endpoints.push(JsEndpoint {
                        endpoint: line.to_string(),
                        source_url: "unknown".to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    endpoints
}

// Helper function to parse ferox_access_pages.txt file
// Format: [ACCESS][content-type] - URL
fn parse_access_pages_file(access_path: &std::path::Path) -> Vec<AccessPage> {
    let mut pages = Vec::new();

    if !access_path.exists() {
        return pages;
    }

    if let Ok(content) = fs::read_to_string(access_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Format: [ACCESS][content-type] - URL
            if let Some(rest) = line.strip_prefix("[ACCESS]") {
                if let Some(rest) = rest.strip_prefix('[') {
                    if let Some((content_type, url_part)) = rest.split_once(']') {
                        if let Some(url) = url_part.strip_prefix(" - ") {
                            pages.push(AccessPage {
                                url: url.trim().to_string(),
                                content_type: content_type.trim().to_string(),
                                status_code: Some(200), // Ferox only shows accessible pages
                            });
                        }
                    }
                }
            }
        }
    }

    pages
}

// Helper function to parse s3.txt file
// Format: Various S3 URL formats
fn parse_s3_buckets_file(s3_path: &std::path::Path) -> Vec<S3Bucket> {
    let mut buckets = Vec::new();

    if !s3_path.exists() {
        return buckets;
    }

    if let Ok(content) = fs::read_to_string(s3_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || !line.contains("s3") {
                continue;
            }

            // Extract bucket name from different S3 URL formats
            let bucket_name = if line.contains("s3.amazonaws.com/") {
                // Format: https://s3.amazonaws.com/bucket-name/...
                line.split("s3.amazonaws.com/")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("unknown")
                    .to_string()
            } else if line.contains(".s3.amazonaws.com") || line.contains(".s3-") {
                // Format: bucket-name.s3.amazonaws.com or https://bucket-name.s3.amazonaws.com
                // or bucket-name.s3-region.amazonaws.com
                let domain_part = if line.contains("://") {
                    line.split("://").nth(1).unwrap_or(line)
                } else {
                    line
                };
                domain_part.split('.').next().unwrap_or("unknown").to_string()
            } else {
                "unknown".to_string()
            };

            // Try to extract source URL if format is: bucket_url - source_url
            let (bucket_url, source_url) = if line.contains(" - ") {
                let parts: Vec<&str> = line.splitn(2, " - ").collect();
                (parts[0].trim().to_string(), parts[1].trim().to_string())
            } else {
                (line.to_string(), "direct_scan".to_string())
            };

            buckets.push(S3Bucket {
                bucket_url,
                bucket_name,
                source_url,
            });
        }
    }

    buckets
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemInfo {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub total_urls: usize,
    pub scan_date: String,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_vulnerabilities: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
    pub medium_vulns: usize,
    pub low_vulns: usize,
    pub total_ports: usize,
    pub total_domains: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub open_ports: Vec<OpenPort>,
    pub systems: Vec<SystemInfo>,
}

// Estruturas para JS Secrets
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsSecret {
    pub secret_type: String,
    pub secret_value: String,
    pub source_url: String,
    pub validation_status: Option<String>,
}

// Estruturas para JS Endpoints
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JsEndpoint {
    pub endpoint: String,
    pub source_url: String,
    pub method: Option<String>,
}

// Estruturas para Access Pages
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessPage {
    pub url: String,
    pub content_type: String,
    pub status_code: Option<u16>,
}

// Estruturas para S3 Buckets
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct S3Bucket {
    pub bucket_url: String,
    pub bucket_name: String,
    pub source_url: String,
}

// Estruturas para HTTP URLs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpUrl {
    pub url: String,
}

// Estruturas para Subdomains
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Subdomain {
    pub subdomain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CurrentStatus {
    pub scan_id: String,
    pub target: String,
    pub last_update: String,
    pub progress: f32,
    pub current_message: String,
    pub event_type: serde_json::Value,
    pub total_events: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanProgress {
    pub target: String,
    pub status: String,
    pub progress: f32,
    pub current_task: String,
    pub events: Vec<ProgressEvent>,
}

// Estruturas para Infrastructure
#[derive(Debug, Serialize)]
struct InfrastructureScan {
    scan_id: String,
    target_range: String,
    total_hosts_scanned: usize,
    hosts_up: usize,
    total_ports_found: usize,
    total_vulnerabilities_found: usize,
    start_time: String,
}

#[derive(Debug, Serialize)]
struct InfrastructurePort {
    port: u16,
    protocol: String,
    state: String,
    service: String,
    version: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Serialize)]
struct InfrastructureService {
    service_name: String,
    port: u16,
    count: usize,
    hosts: Vec<String>,
}

// Estruturas para GitHub
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GitHubConfig {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubConfigRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationQuery {
    organization: String,
}

#[derive(Debug, Serialize)]
pub struct GitHubConfigResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GitHubRepository {
    pub name: String,
    pub full_name: String,
    pub html_url: String,
    pub description: Option<String>,
    pub private: bool,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TruffleHogSecret {
    pub source_name: String,
    pub source_type: String,
    pub detector_name: String,
    pub verified: bool,
    pub raw: Option<String>,
    pub redacted: Option<String>,
    pub extra_data: Option<serde_json::Value>,
    pub repository: String,
}

#[derive(Debug, Deserialize)]
pub struct TruffleHogScanRequest {
    pub org: String,
    #[allow(dead_code)]
    pub include_issues: Option<bool>,
    #[allow(dead_code)]
    pub include_prs: Option<bool>,
    #[allow(dead_code)]
    pub verified_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TruffleHogScanStatus {
    pub status: String,
    pub organization: String,
    pub total_repos: usize,
    pub scanned_repos: usize,
    pub total_secrets: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TruffleHogCheckpoint {
    pub organization: String,
    pub status: String, // "running", "paused", "completed"
    pub scanned_repositories: Vec<String>,
    pub total_repos: usize,
    pub total_secrets_found: usize,
    pub started_at: String,
    pub last_update: String,
    pub github_token: String,
}

// Estruturas para webhook do Discord
#[derive(Debug, Deserialize)]
pub struct WebhookRequest {
    webhook_url: String,
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct DiscordWebhook {
    content: Option<String>,
    embeds: Vec<DiscordEmbed>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    fields: Vec<DiscordField>,
    footer: Option<DiscordFooter>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct DiscordField {
    name: String,
    value: String,
    inline: bool,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct DiscordFooter {
    text: String,
}

// Função de login
async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, Response> {
    // Verificar se existe configuração de admin
    let admin_config = if let Ok(config) = state.admin_config.lock() {
        config.clone()
    } else {
        None
    };

    // Se não houver configuração, usuário precisa fazer setup primeiro
    let Some(config) = admin_config else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Setup required. Please complete the initial setup first.".to_string(),
            }),
        )
            .into_response());
    };

    // Verificar se o setup foi completado
    if !config.setup_completed {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Setup not completed. Please finish the setup process.".to_string(),
            }),
        )
            .into_response());
    }

    // Validar username
    if payload.username != config.username {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".to_string(),
            }),
        )
            .into_response());
    }

    // Verificar senha com bcrypt
    match bcrypt::verify(&payload.password, &config.password_hash) {
        Ok(valid) if valid => {
            let expiration = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .expect("valid timestamp")
                .timestamp();

            let claims = Claims {
                sub: payload.username.clone(),
                exp: expiration as usize,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
            )
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to generate token".to_string(),
                    }),
                )
                    .into_response()
            })?;

            Ok(Json(LoginResponse { token, must_change_password: config.must_change_password }))
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".to_string(),
            }),
        )
            .into_response()),
    }
}

// Middleware para verificar JWT
#[allow(clippy::result_large_err)]
fn verify_token(headers: &HeaderMap) -> Result<String, AuthError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            AuthError((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing authorization header".to_string(),
                }),
            )
                .into_response())
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            AuthError((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid authorization format".to_string(),
                }),
            )
                .into_response())
        })?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| {
        AuthError((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".to_string(),
            }),
        )
            .into_response())
    })?;

    Ok(token_data.claims.sub)
}

// Endpoint para obter estatísticas do dashboard
async fn get_dashboard_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DashboardStats>, Response> {
    verify_token(&headers)?;

    eprintln!("[DEBUG] get_dashboard_stats: base_path = {:?}", state.base_path);

    let mut vulnerabilities = Vec::new();
    let mut open_ports = Vec::new();
    let mut systems = Vec::new();

    // Função auxiliar para processar um diretório de domínio
    let mut process_domain_dir = |domain_path: std::path::PathBuf, domain_name: String| {
        eprintln!("[DEBUG] Processing domain: {} at path: {:?}", domain_name, domain_path);

        // Ler vulnerabilidades do Nuclei (múltiplos formatos possíveis)
        let nuclei_paths = vec![
            domain_path.join("files_").join("nuclei.txt"),
            domain_path.join("nuclei.txt"),
            domain_path.join("nuclei_results.json"),
            domain_path.join("nuclei_web_vulnerabilities.json"),
        ];

        for nuclei_path in nuclei_paths {
            if nuclei_path.exists() {
                eprintln!("[DEBUG] Reading nuclei file: {:?}", nuclei_path);
                if let Ok(content) = fs::read_to_string(&nuclei_path) {
                    let lines: Vec<&str> = content.lines().collect();
                    eprintln!("[DEBUG] Found {} lines in nuclei file", lines.len());
                    for (idx, line) in lines.iter().enumerate() {
                        if line.trim().is_empty() {
                            continue;
                        }
                        // Try to parse the raw nuclei format first
                        if let Ok(raw_vuln) = serde_json::from_str::<serde_json::Value>(line) {
                            // Transform to our Vulnerability format
                            if let Some(vuln) = transform_nuclei_to_vulnerability(&raw_vuln) {
                                vulnerabilities.push(vuln);
                            } else {
                                eprintln!("[DEBUG] Failed to transform line {}: {}", idx + 1, line);
                            }
                        } else {
                            eprintln!("[DEBUG] Failed to parse JSON on line {}: {}", idx + 1, line);
                        }
                    }
                }
            } else {
                eprintln!("[DEBUG] Nuclei file does not exist: {:?}", nuclei_path);
            }
        }

        // Ler portas do arquivo ports.txt (gerado por httpx após masscan)
        let ports_txt_path = domain_path.join("ports.txt");
        let mut ports_from_txt = parse_ports_txt(&ports_txt_path);
        open_ports.append(&mut ports_from_txt);

        // Coletar informações do sistema
        let urls_path = domain_path.join("validated_urls.txt");
        let subdomains_path = domain_path.join("subdomains.txt");

        let total_urls = if urls_path.exists() {
            fs::read_to_string(&urls_path)
                .map(|c| c.lines().count())
                .unwrap_or(0)
        } else {
            0
        };

        let subdomains = if subdomains_path.exists() {
            fs::read_to_string(&subdomains_path)
                .map(|c| c.lines().map(|s| s.to_string()).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        systems.push(SystemInfo {
            domain: domain_name,
            subdomains,
            total_urls,
            scan_date: Utc::now().to_rfc3339(),
            ip_addresses: Vec::new(),
        });
    };

    // Ler dados de todos os domínios (filtrar apenas não ocultos)
    eprintln!("[DEBUG] Scanning base_path for domains: {:?}", state.base_path);
    if let Ok(entries) = fs::read_dir(&state.base_path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let domain_name = entry.file_name().to_string_lossy().to_string();
                eprintln!("[DEBUG] Found directory: {}", domain_name);

                // Filtrar diretórios ocultos (começam com '.')
                if domain_name.starts_with('.') {
                    continue;
                }

                // Se for um diretório file_domains_*, processar subdiretórios
                if domain_name.starts_with("file_domains_") {
                    if let Ok(sub_entries) = fs::read_dir(entry.path()) {
                        for sub_entry in sub_entries.flatten() {
                            if sub_entry.path().is_dir() {
                                let sub_domain_name = sub_entry.file_name().to_string_lossy().to_string();

                                // Filtrar diretórios ocultos
                                if sub_domain_name.starts_with('.') {
                                    continue;
                                }

                                process_domain_dir(sub_entry.path(), sub_domain_name);
                            }
                        }
                    }
                    continue;
                }

                // Processar domínio normal (não file_domains)
                process_domain_dir(entry.path(), domain_name);
            }
        }
    }

    // Contar vulnerabilidades por severidade
    let critical_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "critical").count();
    let high_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "high").count();
    let medium_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "medium").count();
    let low_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "low").count();

    Ok(Json(DashboardStats {
        total_vulnerabilities: vulnerabilities.len(),
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
        total_ports: open_ports.len(),
        total_domains: systems.len(),
        vulnerabilities,
        open_ports,
        systems,
    }))
}

// Endpoint para obter vulnerabilidades de um domínio específico
async fn get_domain_vulnerabilities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<Vulnerability>>, Response> {
    verify_token(&headers)?;

    let mut vulnerabilities = Vec::new();

    // Tentar múltiplos arquivos possíveis
    let nuclei_paths = vec![
        state.base_path.join(&domain).join("files_").join("nuclei.txt"),
        state.base_path.join(&domain).join("nuclei.txt"),
        state.base_path.join(&domain).join("nuclei_results.json"),
        state.base_path.join(&domain).join("nuclei_web_vulnerabilities.json"),
    ];

    for nuclei_path in nuclei_paths {
        if nuclei_path.exists() {
            if let Ok(content) = fs::read_to_string(&nuclei_path) {
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    // Try to parse the raw nuclei format first
                    if let Ok(raw_vuln) = serde_json::from_str::<serde_json::Value>(line) {
                        // Transform to our Vulnerability format
                        if let Some(vuln) = transform_nuclei_to_vulnerability(&raw_vuln) {
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }
    }

    Ok(Json(vulnerabilities))
}

// Helper function to transform raw nuclei JSON to Vulnerability struct
fn transform_nuclei_to_vulnerability(raw: &serde_json::Value) -> Option<Vulnerability> {
    let template_id = raw["template-id"].as_str()?.to_string();
    let matched_at = raw["matched-at"].as_str().unwrap_or("unknown").to_string();
    let host = raw["host"].as_str().unwrap_or("unknown").to_string();

    let info = raw["info"].as_object()?;
    let name = info.get("name")?.as_str()?.to_string();
    let severity = info.get("severity").and_then(|v| v.as_str()).unwrap_or("info").to_string();
    let description = info.get("description").and_then(|v| v.as_str()).map(|s| s.to_string());

    let reference = info.get("reference")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect());

    let tags = info.get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect());

    let author = info.get("author")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect());

    let classification = info.get("classification").cloned();
    let metadata = info.get("metadata").cloned();

    Some(Vulnerability {
        host,
        matched_at,
        template_id,
        info: VulnInfo {
            name,
            severity,
            description,
            reference,
            tags,
            author,
            classification,
            metadata,
        },
        vuln_type: raw["type"].as_str().map(|s| s.to_string()),
        template: raw["template"].as_str().map(|s| s.to_string()),
        template_url: raw["template-url"].as_str().map(|s| s.to_string()),
        template_path: raw["template-path"].as_str().map(|s| s.to_string()),
        request: raw["request"].as_str().map(|s| s.to_string()),
        response: raw["response"].as_str().map(|s| s.to_string()),
        curl_command: raw["curl-command"].as_str().map(|s| s.to_string()),
    })
}

// Endpoint para obter JS secrets de um domínio específico
// MODIFIED: Now returns the same enhanced data as hardcoded_secrets endpoint
async fn get_js_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<HardcodedSecret>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let secrets_path = domain_path.join("hardcoded_secrets_critical.json");

    if !secrets_path.exists() {
        return Ok(Json(Vec::new()));
    }

    match fs::read_to_string(&secrets_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<HardcodedSecret>>(&content) {
                Ok(secrets) => Ok(Json(secrets)),
                Err(_) => Ok(Json(Vec::new()))
            }
        }
        Err(_) => Ok(Json(Vec::new()))
    }
}

// Endpoint para obter JS endpoints de um domínio específico
async fn get_js_endpoints(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<JsEndpoint>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let endpoints_path = domain_path.join("js_endpoints.txt");

    let endpoints = parse_js_endpoints_file(&endpoints_path);

    Ok(Json(endpoints))
}

// Endpoint para download de JS endpoints em formato TXT (para wordlist)
async fn download_js_endpoints_txt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Response, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let endpoints_path = domain_path.join("js_endpoints.txt");

    if !endpoints_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "JS endpoints file not found"}))
        ).into_response());
    }

    match fs::read_to_string(&endpoints_path) {
        Ok(content) => {
            // Parse e extrair apenas os endpoints (primeira coluna antes de " - from:")
            let mut endpoints_only = Vec::new();
            for line in content.lines() {
                if let Some(endpoint_part) = line.split(" - from:").next() {
                    let endpoint = endpoint_part.trim();
                    if !endpoint.is_empty() {
                        endpoints_only.push(endpoint.to_string());
                    }
                }
            }

            let txt_content = endpoints_only.join("\n");
            let filename = format!("{}_js_endpoints_wordlist.txt", domain);

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                    (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", filename)),
                ],
                txt_content,
            ).into_response())
        }
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to read JS endpoints file"}))
        ).into_response()),
    }
}

// Endpoint para obter páginas de acesso de um domínio específico
async fn get_access_pages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<AccessPage>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let access_path = domain_path.join("ferox_access_pages.txt");

    let pages = parse_access_pages_file(&access_path);

    Ok(Json(pages))
}

// Endpoint para obter S3 buckets de um domínio específico
async fn get_s3_buckets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<S3Bucket>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let s3_path = domain_path.join("s3.txt");

    let buckets = parse_s3_buckets_file(&s3_path);

    Ok(Json(buckets))
}

// Query parameter para listar arquivos com suporte a subdiretórios
#[derive(Debug, Deserialize)]
struct FileListQuery {
    path: Option<String>,
}

// Estrutura para listar arquivos
#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub size: u64,
}

// Endpoint para listar arquivos de um domínio (com suporte a subdiretórios)
async fn list_domain_files(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(query): Query<FileListQuery>,
) -> Result<Json<Vec<FileInfo>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);

    // Se um subpath foi fornecido, navegar para ele
    let target_path = if let Some(ref sub_path) = query.path {
        domain_path.join(sub_path)
    } else {
        domain_path.clone()
    };

    // Verificação de segurança contra path traversal
    let canonical_base = match fs::canonicalize(&domain_path) {
        Ok(p) => p,
        Err(_) => {
            return Ok(Json(Vec::new()));
        }
    };
    let canonical_target = match fs::canonicalize(&target_path) {
        Ok(p) => p,
        Err(_) => {
            return Ok(Json(Vec::new()));
        }
    };
    if !canonical_target.starts_with(&canonical_base) {
        return Err((StatusCode::FORBIDDEN, "Acesso negado").into_response());
    }

    let mut files = Vec::new();

    if target_path.exists() && target_path.is_dir() {
        if let Ok(entries) = fs::read_dir(&target_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    let name = entry.file_name().to_string_lossy().to_string();

                    // Filtrar arquivos ocultos (começam com '.')
                    if name.starts_with('.') {
                        continue;
                    }

                    let path = entry.path().strip_prefix(&state.base_path)
                        .unwrap_or(entry.path().as_path())
                        .to_string_lossy()
                        .to_string();

                    files.push(FileInfo {
                        name,
                        path,
                        is_dir: metadata.is_dir(),
                        size: metadata.len(),
                    });
                }
            }
        }
    }

    // Ordenar: diretórios primeiro, depois arquivos
    files.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        }
    });

    Ok(Json(files))
}

// Endpoint para ler conteúdo de arquivo
async fn read_file_content(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_path): Path<String>,
) -> Result<Json<FileContent>, Response> {
    verify_token(&headers)?;

    let full_path = state.base_path.join(&file_path);

    // Verificar se o arquivo está dentro do base_path (segurança)
    if !full_path.starts_with(&state.base_path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
            }),
        )
            .into_response());
    }

    if full_path.exists() && full_path.is_file() {
        if let Ok(content) = fs::read_to_string(&full_path) {
            let size = content.len() as u64;
            // Limitar tamanho para arquivos muito grandes
            let limited_content = if content.len() > 100000 {
                format!("{}\n\n... (arquivo muito grande, mostrando primeiras 100KB)", &content[..100000])
            } else {
                content
            };

            return Ok(Json(FileContent {
                path: file_path,
                content: limited_content,
                size,
            }));
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "File not found or cannot be read".to_string(),
        }),
    )
        .into_response())
}

// Função auxiliar para processar um único domínio
fn process_single_domain(
    domain_path: &std::path::Path,
    domain_name: &str,
    vulnerabilities: &mut Vec<Vulnerability>,
    open_ports: &mut Vec<OpenPort>,
    systems: &mut Vec<SystemInfo>,
) {
    if !domain_path.exists() || !domain_path.is_dir() {
        return;
    }

    // Ler vulnerabilidades do Nuclei (múltiplos formatos possíveis)
    let nuclei_paths = vec![
        domain_path.join("files_").join("nuclei.txt"),
        domain_path.join("nuclei.txt"),
        domain_path.join("nuclei_results.json"),
        domain_path.join("nuclei_web_vulnerabilities.json"),
    ];

    for nuclei_path in nuclei_paths {
        if nuclei_path.exists() {
            eprintln!("[DEBUG] process_single_domain: Reading nuclei file: {:?}", nuclei_path);
            if let Ok(content) = fs::read_to_string(&nuclei_path) {
                let lines: Vec<&str> = content.lines().collect();
                eprintln!("[DEBUG] process_single_domain: Found {} lines in nuclei file", lines.len());
                for (idx, line) in lines.iter().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    // Try to parse the raw nuclei format first
                    if let Ok(raw_vuln) = serde_json::from_str::<serde_json::Value>(line) {
                        // Transform to our Vulnerability format
                        if let Some(vuln) = transform_nuclei_to_vulnerability(&raw_vuln) {
                            vulnerabilities.push(vuln);
                        } else {
                            eprintln!("[DEBUG] process_single_domain: Failed to transform line {}: {}", idx + 1, line);
                        }
                    } else {
                        eprintln!("[DEBUG] process_single_domain: Failed to parse JSON on line {}: {}", idx + 1, line);
                    }
                }
            }
        } else {
            eprintln!("[DEBUG] process_single_domain: Nuclei file does not exist: {:?}", nuclei_path);
        }
    }

    // Ler portas do arquivo ports.txt (gerado por httpx após masscan)
    let ports_txt_path = domain_path.join("ports.txt");
    let mut ports_from_txt = parse_ports_txt(&ports_txt_path);
    open_ports.append(&mut ports_from_txt);

    // Coletar informações do domínio
    let urls_path = domain_path.join("validated_urls.txt");
    let subdomains_path = domain_path.join("subdomains.txt");
    let ips_path = domain_path.join("ips.txt");

    let total_urls = if urls_path.exists() {
        fs::read_to_string(&urls_path)
            .map(|c| c.lines().count())
            .unwrap_or(0)
    } else {
        0
    };

    let subdomains = if subdomains_path.exists() {
        fs::read_to_string(&subdomains_path)
            .map(|c| c.lines().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let ip_addresses = if ips_path.exists() {
        fs::read_to_string(&ips_path)
            .map(|c| c.lines().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    systems.push(SystemInfo {
        domain: domain_name.to_string(),
        subdomains,
        total_urls,
        scan_date: Utc::now().to_rfc3339(),
        ip_addresses,
    });
}

// Endpoint para obter dados completos de um domínio específico
async fn get_domain_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<DashboardStats>, Response> {
    verify_token(&headers)?;

    let mut vulnerabilities = Vec::new();
    let mut open_ports = Vec::new();
    let mut systems = Vec::new();

    let domain_path = state.base_path.join(&domain);

    // Verificar se é um diretório file_domains_* (modo -f file)
    // Se for, somar todos os subdomínios dentro dele
    if domain.starts_with("file_domains_") && !domain.contains('/') {
        // É o diretório pai file_domains_*, processar todos os subdomínios
        if let Ok(sub_entries) = fs::read_dir(&domain_path) {
            for sub_entry in sub_entries.flatten() {
                if sub_entry.path().is_dir() {
                    let sub_domain_name = sub_entry.file_name().to_string_lossy().to_string();

                    // Filtrar diretórios ocultos
                    if sub_domain_name.starts_with('.') {
                        continue;
                    }

                    // Processar cada subdomínio
                    process_single_domain(
                        &sub_entry.path(),
                        &sub_domain_name,
                        &mut vulnerabilities,
                        &mut open_ports,
                        &mut systems,
                    );
                }
            }
        }
    } else {
        // Domínio individual ou subdomínio específico
        process_single_domain(
            &domain_path,
            &domain,
            &mut vulnerabilities,
            &mut open_ports,
            &mut systems,
        );
    }

    // Contar vulnerabilidades por severidade
    let critical_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "critical").count();
    let high_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "high").count();
    let medium_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "medium").count();
    let low_vulns = vulnerabilities.iter().filter(|v| v.info.severity.to_lowercase() == "low").count();

    Ok(Json(DashboardStats {
        total_vulnerabilities: vulnerabilities.len(),
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
        total_ports: open_ports.len(),
        total_domains: systems.len(),
        vulnerabilities,
        open_ports,
        systems,
    }))
}

// Helper: collect domain directories (filters out cargo/project dirs)
fn collect_domain_dirs(base_path: &std::path::Path) -> Vec<PathBuf> {
    let cargo_dirs = [
        "build", "deps", "examples", "incremental", ".fingerprint",
        "target", "src", "dashboard-ui", "test_domain",
        "docs", "k8s", "bin"
    ];

    let mut dirs = Vec::new();
    if let Ok(entries) = fs::read_dir(base_path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || cargo_dirs.contains(&name.as_str()) {
                    continue;
                }
                if name.starts_with("file_domains_") {
                    if let Ok(sub_entries) = fs::read_dir(entry.path()) {
                        for sub_entry in sub_entries.flatten() {
                            if sub_entry.path().is_dir() {
                                let sub_name = sub_entry.file_name().to_string_lossy().to_string();
                                if !sub_name.starts_with('.') {
                                    dirs.push(sub_entry.path());
                                }
                            }
                        }
                    }
                } else {
                    dirs.push(entry.path());
                }
            }
        }
    }
    dirs
}

// Endpoint para listar scans de infraestrutura
async fn get_infrastructure_scans(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<InfrastructureScan>>, Response> {
    verify_token(&headers)?;

    let domain_dirs = collect_domain_dirs(&state.base_path);
    let mut scans = Vec::new();

    for dir in &domain_dirs {
        let domain_name = dir.file_name().unwrap_or_default().to_string_lossy().to_string();

        // Count subdomains/hosts
        let subdomains_path = dir.join("subdomains.txt");
        let (total_hosts, hosts_up) = if subdomains_path.exists() {
            if let Ok(content) = fs::read_to_string(&subdomains_path) {
                let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
                (lines.len(), lines.len())
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        // Count ports
        let ports_path = dir.join("ports.txt");
        let total_ports = parse_ports_txt(&ports_path).len();

        // Count vulnerabilities from nuclei output
        let nuclei_path = dir.join("files_").join("nuclei.txt");
        let nuclei_alt = dir.join("nuclei.txt");
        let nuclei_file = if nuclei_path.exists() { &nuclei_path } else { &nuclei_alt };
        let total_vulns = if nuclei_file.exists() {
            if let Ok(content) = fs::read_to_string(nuclei_file) {
                content.lines().filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.is_empty() && (trimmed.starts_with('{') || trimmed.contains("\"template-id\""))
                }).count()
            } else {
                0
            }
        } else {
            0
        };

        // Get modification time for start_time
        let start_time = if let Ok(metadata) = fs::metadata(dir) {
            if let Ok(modified) = metadata.modified() {
                let datetime: chrono::DateTime<chrono::Utc> = modified.into();
                datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Generate scan_id from domain name
        let scan_id = format!("{:x}", md5_hash(&domain_name));

        // Only include dirs that look like actual scan results
        if total_hosts > 0 || total_ports > 0 || total_vulns > 0 {
            scans.push(InfrastructureScan {
                scan_id,
                target_range: domain_name,
                total_hosts_scanned: total_hosts,
                hosts_up,
                total_ports_found: total_ports,
                total_vulnerabilities_found: total_vulns,
                start_time,
            });
        }
    }

    Ok(Json(scans))
}

// Simple hash for scan_id generation
fn md5_hash(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// Endpoint para listar portas de infraestrutura
async fn get_infrastructure_ports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<InfrastructurePort>>, Response> {
    verify_token(&headers)?;

    let domain_dirs = collect_domain_dirs(&state.base_path);
    let mut seen = std::collections::HashSet::new();
    let mut ports = Vec::new();

    for dir in &domain_dirs {
        let ports_path = dir.join("ports.txt");
        for open_port in parse_ports_txt(&ports_path) {
            let key = (open_port.host.clone(), open_port.port);
            if seen.insert(key) {
                ports.push(InfrastructurePort {
                    port: open_port.port,
                    protocol: open_port.protocol,
                    state: "open".to_string(),
                    service: open_port.service,
                    version: None,
                    banner: None,
                });
            }
        }
    }

    Ok(Json(ports))
}

// Endpoint para listar serviços de infraestrutura
async fn get_infrastructure_services(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<InfrastructureService>>, Response> {
    verify_token(&headers)?;

    let domain_dirs = collect_domain_dirs(&state.base_path);
    let mut service_map: std::collections::HashMap<String, InfrastructureService> = std::collections::HashMap::new();

    for dir in &domain_dirs {
        let ports_path = dir.join("ports.txt");
        for open_port in parse_ports_txt(&ports_path) {
            let entry = service_map.entry(open_port.service.clone()).or_insert_with(|| {
                InfrastructureService {
                    service_name: open_port.service.clone(),
                    port: open_port.port,
                    count: 0,
                    hosts: Vec::new(),
                }
            });
            entry.count += 1;
            if !entry.hosts.contains(&open_port.host) {
                entry.hosts.push(open_port.host.clone());
            }
        }
    }

    let services: Vec<InfrastructureService> = service_map.into_values().collect();
    Ok(Json(services))
}

// Endpoint para obter progresso de um scan
async fn get_scan_progress(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(target): Path<String>,
) -> Result<Json<ScanProgress>, Response> {
    verify_token(&headers)?;

    let target_dir = state.base_path.join(&target);
    let progress_file = target_dir.join("progress.jsonl");
    let status_file = target_dir.join("current_status.json");

    // Ler status atual
    let (status_str, progress, current_task) = if status_file.exists() {
        if let Ok(content) = fs::read_to_string(&status_file) {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&content) {
                let msg = status["current_message"].as_str().unwrap_or("Carregando...").to_string();
                let prog = status["progress"].as_f64().unwrap_or(0.0) as f32;
                ("running".to_string(), prog, msg)
            } else {
                ("idle".to_string(), 0.0, "Aguardando início".to_string())
            }
        } else {
            ("idle".to_string(), 0.0, "Aguardando início".to_string())
        }
    } else {
        ("idle".to_string(), 0.0, "Aguardando início".to_string())
    };

    // Ler eventos
    let events = if progress_file.exists() {
        ProgressTracker::read_events_from_file(&progress_file)
    } else {
        Vec::new()
    };

    Ok(Json(ScanProgress {
        target,
        status: status_str,
        progress,
        current_task,
        events,
    }))
}

// Endpoint para listar todos os scans
async fn list_scans(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, Response> {
    verify_token(&headers)?;

    let mut scans = Vec::new();

    // Diretórios do Cargo e do projeto para ignorar
    let cargo_dirs = [
        "build", "deps", "examples", "incremental", ".fingerprint",
        "target", "src", "dashboard-ui", "test_domain",
        "docs", "k8s", "bin"
    ];

    if let Ok(entries) = fs::read_dir(&state.base_path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();

                // Filtrar diretórios ocultos (começam com '.')
                if name.starts_with('.') {
                    continue;
                }

                // Filtrar diretórios do Cargo
                if cargo_dirs.contains(&name.as_str()) {
                    continue;
                }

                // Se for um diretório file_domains_*, adicionar o pai E os subdomínios
                if name.starts_with("file_domains_") {
                    // Adicionar o diretório pai (para visualizar todos juntos)
                    scans.push(name.clone());

                    // Também adicionar cada subdomínio individualmente
                    if let Ok(sub_entries) = fs::read_dir(entry.path()) {
                        for sub_entry in sub_entries.flatten() {
                            if sub_entry.path().is_dir() {
                                let sub_name = sub_entry.file_name().to_string_lossy().to_string();

                                // Filtrar diretórios ocultos
                                if sub_name.starts_with('.') {
                                    continue;
                                }

                                // Adicionar com caminho completo: file_domains_xxx/dominio
                                scans.push(format!("{}/{}", name, sub_name));
                            }
                        }
                    }
                } else {
                    // Domínio individual (não dentro de file_domains_*)
                    scans.push(name);
                }
            }
        }
    }

    // Ordenar alfabeticamente
    scans.sort();

    Ok(Json(scans))
}

// Endpoint para obter status atual de um scan
async fn get_current_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(target): Path<String>,
) -> Result<Json<CurrentStatus>, Response> {
    verify_token(&headers)?;

    let status_file = state.base_path.join(&target).join("current_status.json");

    if status_file.exists() {
        if let Ok(content) = fs::read_to_string(&status_file) {
            if let Ok(status) = serde_json::from_str::<CurrentStatus>(&content) {
                return Ok(Json(status));
            }
        }
    }

    // Retornar status padrão se não existir
    Ok(Json(CurrentStatus {
        scan_id: "unknown".to_string(),
        target: target.clone(),
        last_update: Utc::now().to_rfc3339(),
        progress: 0.0,
        current_message: "Aguardando início do scan".to_string(),
        event_type: serde_json::json!({"type": "Idle"}),
        total_events: 0,
    }))
}

// Endpoint para salvar configuração do GitHub
async fn save_github_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<GitHubConfigRequest>,
) -> Result<Json<GitHubConfigResponse>, Response> {
    verify_token(&headers)?;

    // Validar se o token não está vazio
    if payload.token.is_empty() {
        return Ok(Json(GitHubConfigResponse {
            success: false,
            message: "Token não pode estar vazio".to_string(),
        }));
    }

    let config = GitHubConfig {
        token: payload.token.clone(),
    };

    // Salvar configuração no estado
    if let Ok(mut github) = state.github_config.lock() {
        *github = Some(config.clone());

        // Salvar também em arquivo para persistência
        let github_file = state.base_path.join(".github_config.json");
        if let Ok(json_content) = serde_json::to_string_pretty(&config) {
            let _ = fs::write(&github_file, json_content);
        }

        Ok(Json(GitHubConfigResponse {
            success: true,
            message: "Token GitHub salvo com sucesso!".to_string(),
        }))
    } else {
        Ok(Json(GitHubConfigResponse {
            success: false,
            message: "Erro ao salvar configuração".to_string(),
        }))
    }
}

// Endpoint para obter configuração do GitHub
async fn get_github_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    verify_token(&headers)?;

    let config = if let Ok(github) = state.github_config.lock() {
        github.clone()
    } else {
        None
    };

    // Retornar o token para usuário autenticado poder editar
    if let Some(cfg) = config {
        Ok(Json(serde_json::json!({
            "configured": true,
            "token": cfg.token
        })))
    } else {
        Ok(Json(serde_json::json!({
            "configured": false,
            "token": ""
        })))
    }
}

// Endpoint para listar repositórios da organização no GitHub
async fn list_github_repos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Vec<GitHubRepository>>, Response> {
    verify_token(&headers)?;

    let config = state.github_config.lock().unwrap().clone();

    let Some(cfg) = config else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "GitHub não configurado. Configure o token primeiro.".to_string(),
            }),
        ).into_response());
    };

    // Usar função com paginação automática para buscar TODOS os repositórios
    eprintln!("[API] Buscando repositórios da organização: {}", query.organization);
    let repos = fetch_github_repositories(&cfg.token, &query.organization).await;
    eprintln!("[API] Retornando {} repositórios para o dashboard", repos.len());

    Ok(Json(repos))
}

// Endpoint para executar TruffleHog scan
async fn run_trufflehog_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<TruffleHogScanRequest>,
) -> Result<Json<TruffleHogScanStatus>, Response> {
    verify_token(&headers)?;

    let config = state.github_config.lock().unwrap().clone();

    let Some(cfg) = config else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "GitHub não configurado. Configure o token primeiro.".to_string(),
            }),
        ).into_response());
    };

    let org = payload.org.clone();
    let base_path = state.base_path.clone();

    // Verificar se já existe checkpoint
    let existing_checkpoint = load_trufflehog_checkpoint(&base_path, &org);

    if let Some(checkpoint) = &existing_checkpoint {
        if checkpoint.status == "running" {
            // Scan já está em andamento
            return Ok(Json(TruffleHogScanStatus {
                status: checkpoint.status.clone(),
                organization: org,
                total_repos: checkpoint.total_repos,
                scanned_repos: checkpoint.scanned_repositories.len(),
                total_secrets: checkpoint.total_secrets_found,
            }));
        }
    }

    // Criar novo checkpoint ou retomar
    let checkpoint = existing_checkpoint.unwrap_or_else(|| {
        let now = chrono::Utc::now().to_rfc3339();
        TruffleHogCheckpoint {
            organization: org.clone(),
            status: "running".to_string(),
            scanned_repositories: Vec::new(),
            total_repos: 0,
            total_secrets_found: 0,
            started_at: now.clone(),
            last_update: now,
            github_token: cfg.token.clone(),
        }
    });

    save_trufflehog_checkpoint(&base_path, &checkpoint);

    // Executar TruffleHog em background
    let org_for_spawn = org.clone();
    let secrets_arc = state.trufflehog_secrets.clone();
    let github_token = cfg.token.clone();

    tokio::spawn(async move {
        eprintln!("[TruffleHog] Iniciando scan da organização: {}", org_for_spawn);

        // Buscar repositórios da organização
        let repos = fetch_github_repositories(&github_token, &org_for_spawn).await;

        eprintln!("[TruffleHog] Encontrados {} repositórios", repos.len());

        // Atualizar checkpoint com total de repos
        if let Some(mut checkpoint) = load_trufflehog_checkpoint(&base_path, &org_for_spawn) {
            checkpoint.total_repos = repos.len();
            save_trufflehog_checkpoint(&base_path, &checkpoint);
        }

        // ============================================================
        // SCAN PARALELO COM CONTROLE DE CONCORRÊNCIA
        // ============================================================
        let num_workers = MAX_PARALLEL_TRUFFLEHOG_SCANS;
        eprintln!("[TruffleHog] 🚀 Usando {} workers paralelos para máxima performance!", num_workers);
        eprintln!("[TruffleHog] ⚡ Isso vai acelerar o scan em {}x!", num_workers);

        // Criar semáforo para controlar concorrência
        let semaphore = Arc::new(Semaphore::new(num_workers));

        // Processar repositórios em paralelo
        let results: Vec<_> = stream::iter(repos)
            .map(|repo| {
                let org = org_for_spawn.clone();
                let token = github_token.clone();
                let base = base_path.clone();
                let sem = semaphore.clone();

                async move {
                    // Verificar se já foi escaneado
                    if let Some(checkpoint) = load_trufflehog_checkpoint(&base, &org) {
                        if checkpoint.scanned_repositories.contains(&repo.name) {
                            eprintln!("[TruffleHog] ⏭️  Pulando repositório já escaneado: {}", repo.name);
                            return (repo.name, 0, Vec::new(), Vec::new());
                        }
                    }

                    // Adquirir permissão do semáforo (limita concorrência)
                    let _permit = sem.acquire().await.unwrap();

                    eprintln!("[TruffleHog] 🔍 [Worker] Escaneando: {}/{}", org, repo.name);

                    // Executar TruffleHog (ASYNC para não bloquear)
                    let result = tokio::process::Command::new("trufflehog")
                        .arg("github")
                        .arg("--repo")
                        .arg(format!("https://github.com/{}/{}", org, repo.name))
                        .arg("--token")
                        .arg(&token)
                        .arg("--issue-comments")
                        .arg("--pr-comments")
                        .arg("--results=verified")
                        .arg("--json")
                        .env("GITHUB_TOKEN", &token)
                        .output()
                        .await;

                    let mut secrets = Vec::new();
                    let mut vulns = Vec::new();
                    let mut repo_secrets = 0;

                    match result {
                        Ok(output) => {
                            if output.status.success() {
                                let content = String::from_utf8_lossy(&output.stdout);

                                for line in content.lines() {
                                    if line.trim().is_empty() {
                                        continue;
                                    }

                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                                        if let Some(secret) = parse_trufflehog_secret(&json, &org) {
                                            secrets.push(secret);
                                            repo_secrets += 1;
                                        }

                                        if let Some(vuln) = trufflehog_to_vulnerability(&json, &org) {
                                            vulns.push(vuln);
                                        }
                                    }
                                }

                                eprintln!("[TruffleHog] ✅ [Worker] {} - {} secrets encontrados", repo.name, repo_secrets);

                                // Atualizar checkpoint
                                update_checkpoint_status(&base, &org, "running", Some(repo.name.clone()), repo_secrets);
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                eprintln!("[TruffleHog] ❌ ERRO ao escanear {}: {}", repo.name, stderr);
                            }
                        }
                        Err(e) => {
                            eprintln!("[TruffleHog] ❌ ERRO ao executar comando para {}: {}", repo.name, e);
                        }
                    }

                    // Pequeno delay entre scans para não sobrecarregar
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                    (repo.name, repo_secrets, secrets, vulns)
                }
            })
            .buffer_unordered(num_workers) // MAGIA: Executa N em paralelo!
            .collect()
            .await;

        // Agregar todos os resultados
        let mut all_secrets = Vec::new();
        let mut all_vulnerabilities = Vec::new();

        for (_repo_name, _count, mut secrets, mut vulns) in results {
            all_secrets.append(&mut secrets);
            all_vulnerabilities.append(&mut vulns);
        }

        eprintln!("[TruffleHog] Scan completo! Total de secrets: {}", all_secrets.len());

        // Salvar todos os secrets no estado
        if let Ok(mut stored_secrets) = secrets_arc.lock() {
            *stored_secrets = all_secrets.clone();
        }

        // Salvar secrets em arquivo para persistência
        if !all_secrets.is_empty() {
            let org_dir = base_path.join(&org_for_spawn);
            let _ = fs::create_dir_all(&org_dir);
            let secrets_file = org_dir.join("trufflehog_secrets.json");

            let mut lines = Vec::new();
            for secret in &all_secrets {
                if let Ok(json) = serde_json::to_string(secret) {
                    lines.push(json);
                }
            }

            let content = lines.join("\n") + "\n";
            let _ = fs::write(&secrets_file, content);
            eprintln!("[TruffleHog] Secrets salvos em: {:?}", secrets_file);
        }

        // Salvar vulnerabilidades no arquivo nuclei.txt
        if !all_vulnerabilities.is_empty() {
            let org_dir = base_path.join(&org_for_spawn);
            let _ = fs::create_dir_all(&org_dir);
            let nuclei_file = org_dir.join("nuclei.txt");

            let mut lines = Vec::new();
            for vuln in all_vulnerabilities {
                if let Ok(json) = serde_json::to_string(&vuln) {
                    lines.push(json);
                }
            }

            let content = lines.join("\n") + "\n";
            if nuclei_file.exists() {
                if let Ok(existing) = fs::read_to_string(&nuclei_file) {
                    let _ = fs::write(&nuclei_file, existing + &content);
                }
            } else {
                let _ = fs::write(&nuclei_file, content);
            }
        }

        // Marcar checkpoint como completo
        update_checkpoint_status(&base_path, &org_for_spawn, "completed", None, 0);
    });

    Ok(Json(TruffleHogScanStatus {
        status: "running".to_string(),
        organization: org,
        total_repos: 0,
        scanned_repos: 0,
        total_secrets: 0,
    }))
}

// Função auxiliar para buscar repositórios do GitHub
async fn fetch_github_repositories(token: &str, org: &str) -> Vec<GitHubRepository> {
    let client = reqwest::Client::new();
    let mut all_repos = Vec::new();
    let mut page = 1;

    loop {
        let url = format!("https://api.github.com/orgs/{}/repos?per_page=100&page={}", org, page);

        match client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("User-Agent", "EnumRust")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<Vec<GitHubRepository>>().await {
                        Ok(repos) => {
                            if repos.is_empty() {
                                // Não há mais repositórios, finalizar paginação
                                break;
                            }

                            eprintln!("[GitHub] Página {}: {} repositórios encontrados", page, repos.len());
                            all_repos.extend(repos);
                            page += 1;
                        }
                        Err(e) => {
                            eprintln!("[GitHub] Erro ao parsear resposta da página {}: {}", page, e);
                            break;
                        }
                    }
                } else {
                    eprintln!("[GitHub] Erro HTTP na página {}: {}", page, response.status());
                    break;
                }
            }
            Err(e) => {
                eprintln!("[GitHub] Erro de requisição na página {}: {}", page, e);
                break;
            }
        }
    }

    eprintln!("[GitHub] Total de repositórios encontrados: {}", all_repos.len());
    all_repos
}

// Função auxiliar para parsear secret do TruffleHog
fn parse_trufflehog_secret(json: &serde_json::Value, org: &str) -> Option<TruffleHogSecret> {
    Some(TruffleHogSecret {
        source_name: json["SourceMetadata"]["Data"]["Github"]["repository"].as_str()?.to_string(),
        source_type: json["SourceType"].as_u64().unwrap_or(0).to_string(),
        detector_name: json["DetectorName"].as_str()?.to_string(),
        verified: json["Verified"].as_bool().unwrap_or(false),
        raw: json["Raw"].as_str().map(|s| s.to_string()),
        redacted: json["Redacted"].as_str().map(|s| s.to_string()),
        extra_data: json["ExtraData"].as_object().map(|_| json["ExtraData"].clone()),
        repository: org.to_string(),
    })
}

// Converter TruffleHog secret para formato Vulnerability
fn trufflehog_to_vulnerability(json: &serde_json::Value, org: &str) -> Option<Vulnerability> {
    let detector = json["DetectorName"].as_str()?;
    let verified = json["Verified"].as_bool().unwrap_or(false);

    // Tentar extrair repositório de diferentes locais
    let repository = json["SourceMetadata"]["Data"]["Github"]["repository"]
        .as_str()
        .or_else(|| json["SourceMetadata"]["Data"]["Filesystem"]["repository"].as_str())
        .unwrap_or("unknown");

    // Tentar extrair arquivo de diferentes locais
    let file = json["SourceMetadata"]["Data"]["Github"]["file"]
        .as_str()
        .or_else(|| json["SourceMetadata"]["Data"]["Filesystem"]["file"].as_str())
        .unwrap_or("unknown");

    let link = json["SourceMetadata"]["Data"]["Github"]["link"].as_str().unwrap_or("");

    // Se repository é "unknown" ou está vazio, tentar extrair do path do arquivo
    let display_repository = if repository == "unknown" || repository.is_empty() {
        if !file.is_empty() && file.contains('/') {
            // Extrair nome do repositório do path do arquivo
            let parts: Vec<&str> = file.split('/').collect();
            if parts.len() >= 2 {
                // Tentar extrair owner/repo do path (geralmente em /tmp/trufflehog_targets ou similar)
                if let Some(repo_index) = parts.iter().position(|&x| x.contains("github") || x.contains("repo")) {
                    if repo_index + 2 < parts.len() {
                        format!("{}/{}", parts[repo_index + 1], parts[repo_index + 2])
                    } else {
                        file.to_string()
                    }
                } else {
                    file.to_string()
                }
            } else {
                file.to_string()
            }
        } else {
            format!("{}/scan-result", org)
        }
    } else {
        repository.to_string()
    };

    // Criar uma URL de host baseada no repositório
    let host = if display_repository.starts_with("http") || display_repository.contains("github.com") {
        display_repository.clone()
    } else {
        format!("https://github.com/{}", display_repository)
    };

    // Criar matched_at com o arquivo onde foi encontrado
    let matched_at = if !link.is_empty() {
        link.to_string()
    } else if display_repository.starts_with("http") {
        format!("{} -> {}", display_repository, file)
    } else {
        format!("{}/blob/main/{}", host, file)
    };

    // Determinar severidade baseado na verificação
    let severity = if verified { "critical" } else { "high" };

    // Criar descrição detalhada
    let redacted = json["Redacted"].as_str().unwrap_or("***REDACTED***");
    let description = format!(
        "TruffleHog detected {} secret in GitHub repository. File: {}. Verified: {}. Preview: {}",
        detector, file, verified, redacted
    );

    Some(Vulnerability {
        host,
        matched_at,
        template_id: format!("trufflehog-{}", detector.to_lowercase()),
        info: VulnInfo {
            name: format!("GitHub Secret Exposure - {}", detector),
            severity: severity.to_string(),
            description: Some(description),
            reference: Some(vec![
                "https://github.com/trufflesecurity/trufflehog".to_string(),
            ]),
            tags: Some(vec![
                "github".to_string(),
                "secrets".to_string(),
                detector.to_lowercase(),
            ]),
            author: Some(vec!["trufflehog".to_string()]),
            classification: None,
            metadata: json["ExtraData"].as_object().map(|_| json["ExtraData"].clone()),
        },
        vuln_type: Some("github-secret".to_string()),
        template: Some(format!("trufflehog/{}", detector)),
        template_url: None,
        template_path: None,
        request: None,
        response: json["Raw"].as_str().map(|_s| format!("Found in: {}\nRepository: {}\nOrganization: {}", file, repository, org)),
        curl_command: None,
    })
}

// Funções para gerenciar checkpoint do TruffleHog
fn save_trufflehog_checkpoint(base_path: &std::path::Path, checkpoint: &TruffleHogCheckpoint) {
    let checkpoint_file = base_path.join(format!("trufflehog_checkpoint_{}.json", checkpoint.organization));
    if let Ok(json) = serde_json::to_string_pretty(checkpoint) {
        let _ = fs::write(&checkpoint_file, json);
    }
}

fn load_trufflehog_checkpoint(base_path: &std::path::Path, org: &str) -> Option<TruffleHogCheckpoint> {
    let checkpoint_file = base_path.join(format!("trufflehog_checkpoint_{}.json", org));
    if checkpoint_file.exists() {
        if let Ok(content) = fs::read_to_string(&checkpoint_file) {
            return serde_json::from_str(&content).ok();
        }
    }
    None
}

fn update_checkpoint_status(base_path: &std::path::Path, org: &str, status: &str, scanned_repo: Option<String>, secrets_count: usize) {
    if let Some(mut checkpoint) = load_trufflehog_checkpoint(base_path, org) {
        checkpoint.status = status.to_string();
        checkpoint.last_update = chrono::Utc::now().to_rfc3339();
        checkpoint.total_secrets_found += secrets_count;

        if let Some(repo) = scanned_repo {
            if !checkpoint.scanned_repositories.contains(&repo) {
                checkpoint.scanned_repositories.push(repo);
            }
        }

        save_trufflehog_checkpoint(base_path, &checkpoint);
    }
}

// Endpoint para obter resultados do TruffleHog
async fn get_trufflehog_results(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<TruffleHogSecret>>, Response> {
    verify_token(&headers)?;

    let mut secrets = if let Ok(stored_secrets) = state.trufflehog_secrets.lock() {
        stored_secrets.clone()
    } else {
        Vec::new()
    };

    // Se vazio na memória ou se org foi especificado, tentar ler do arquivo
    if let Some(org) = params.get("org") {
        let secrets_file = state.base_path.join(org).join("trufflehog_secrets.json");
        if secrets_file.exists() {
            if let Ok(content) = fs::read_to_string(&secrets_file) {
                let mut file_secrets = Vec::new();
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(secret) = serde_json::from_str::<TruffleHogSecret>(line) {
                        file_secrets.push(secret);
                    }
                }

                // Se temos secrets do arquivo, usá-los
                if !file_secrets.is_empty() {
                    secrets = file_secrets;
                    eprintln!("[TruffleHog] Carregados {} secrets do arquivo para org {}", secrets.len(), org);
                }
            }
        }
    }

    Ok(Json(secrets))
}

// Endpoint para obter status do checkpoint do TruffleHog
async fn get_trufflehog_checkpoint_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org): Path<String>,
) -> Result<Json<Option<TruffleHogCheckpoint>>, Response> {
    verify_token(&headers)?;

    let checkpoint = load_trufflehog_checkpoint(&state.base_path, &org);
    Ok(Json(checkpoint))
}

// Endpoint para salvar webhook do Discord
async fn save_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<WebhookRequest>,
) -> Result<Json<WebhookResponse>, Response> {
    verify_token(&headers)?;

    // Validar se a URL é válida
    if payload.webhook_url.is_empty() || !payload.webhook_url.starts_with("https://discord.com/api/webhooks/") {
        return Ok(Json(WebhookResponse {
            success: false,
            message: "URL de webhook inválida. Deve começar com https://discord.com/api/webhooks/".to_string(),
        }));
    }

    // Salvar webhook no estado
    if let Ok(mut webhook) = state.webhook_url.lock() {
        *webhook = Some(payload.webhook_url.clone());

        // Salvar também em arquivo para persistência
        let webhook_file = state.base_path.join(".webhook_discord.txt");
        let _ = fs::write(&webhook_file, payload.webhook_url);

        Ok(Json(WebhookResponse {
            success: true,
            message: "Webhook salvo com sucesso!".to_string(),
        }))
    } else {
        Ok(Json(WebhookResponse {
            success: false,
            message: "Erro ao salvar webhook".to_string(),
        }))
    }
}

// Endpoint para obter webhook configurado
async fn get_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    verify_token(&headers)?;

    let webhook_url = if let Ok(webhook) = state.webhook_url.lock() {
        webhook.clone()
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "webhook_url": webhook_url
    })))
}

// Função pública para enviar notificação ao Discord
#[allow(dead_code)]
pub async fn send_discord_notification(
    webhook_url: &str,
    client: &Client,
    vulnerability: &Vulnerability,
) -> anyhow::Result<()> {
    // Determinar cor baseada na severidade
    let color = match vulnerability.info.severity.to_lowercase().as_str() {
        "critical" => 0xFF0000, // Vermelho
        "high" => 0xFF6600,     // Laranja
        "medium" => 0xFFCC00,   // Amarelo
        "low" => 0x0099FF,      // Azul
        _ => 0x808080,          // Cinza
    };

    let severity_emoji = match vulnerability.info.severity.to_lowercase().as_str() {
        "critical" => "🔴",
        "high" => "🟠",
        "medium" => "🟡",
        "low" => "🔵",
        _ => "⚪",
    };

    // Criar embed do Discord
    let embed = DiscordEmbed {
        title: format!("{} Nova Vulnerabilidade Detectada", severity_emoji),
        description: format!("**{}**\n\n{}",
            vulnerability.info.name,
            vulnerability.info.description.as_deref().unwrap_or("Sem descrição disponível")
        ),
        color,
        fields: vec![
            DiscordField {
                name: "🎯 Alvo".to_string(),
                value: vulnerability.host.clone(),
                inline: true,
            },
            DiscordField {
                name: "⚠️ Severidade".to_string(),
                value: vulnerability.info.severity.clone(),
                inline: true,
            },
            DiscordField {
                name: "🔍 Template ID".to_string(),
                value: format!("`{}`", vulnerability.template_id),
                inline: false,
            },
            DiscordField {
                name: "📍 Local".to_string(),
                value: vulnerability.matched_at.clone(),
                inline: false,
            },
        ],
        footer: Some(DiscordFooter {
            text: format!("EnumRust Scanner • {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")),
        }),
    };

    // Criar webhook payload
    let webhook = DiscordWebhook {
        content: Some(format!("🚨 **Vulnerabilidade {} detectada!**", vulnerability.info.severity.to_uppercase())),
        embeds: vec![embed],
    };

    // Enviar para Discord
    let response = client
        .post(webhook_url)
        .json(&webhook)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Falha ao enviar notificação ao Discord: {}", response.status());
    }

    Ok(())
}

// Endpoint para obter lista de subdomínios de um domínio específico
async fn get_subdomains_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<Subdomain>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let subdomains_path = domain_path.join("subdomains.txt");

    let mut subdomains = Vec::new();

    if subdomains_path.exists() {
        if let Ok(content) = fs::read_to_string(&subdomains_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                subdomains.push(Subdomain {
                    subdomain: line.to_string(),
                });
            }
        }
    }

    Ok(Json(subdomains))
}

// Endpoint para obter resultados do Nuclei (alias para get_domain_vulnerabilities)
async fn get_nuclei_results(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<Vulnerability>>, Response> {
    // Reutilizar a função existente de vulnerabilidades
    get_domain_vulnerabilities(State(state), headers, Path(domain)).await
}

// Endpoint para obter URLs com status HTTP 200
async fn get_http200_urls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<HttpUrl>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let http200_path = domain_path.join("http200.txt");

    let mut urls = Vec::new();

    if http200_path.exists() {
        if let Ok(content) = fs::read_to_string(&http200_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                urls.push(HttpUrl {
                    url: line.to_string(),
                });
            }
        }
    }

    Ok(Json(urls))
}

// Endpoint para obter URLs com status HTTP 403
async fn get_http403_urls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<HttpUrl>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let http403_path = domain_path.join("http403.txt");

    let mut urls = Vec::new();

    if http403_path.exists() {
        if let Ok(content) = fs::read_to_string(&http403_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                urls.push(HttpUrl {
                    url: line.to_string(),
                });
            }
        }
    }

    Ok(Json(urls))
}

// Endpoint para obter hardcoded secrets de um domínio específico
async fn get_hardcoded_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<HardcodedSecret>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let secrets_path = domain_path.join("hardcoded_secrets_critical.json");

    // Se o arquivo não existir, retornar array vazio
    if !secrets_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Ler e parsear o arquivo JSON
    match fs::read_to_string(&secrets_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<HardcodedSecret>>(&content) {
                Ok(secrets) => Ok(Json(secrets)),
                Err(_) => {
                    // Se falhar ao parsear, retornar array vazio
                    Ok(Json(Vec::new()))
                }
            }
        }
        Err(_) => {
            // Se falhar ao ler o arquivo, retornar array vazio
            Ok(Json(Vec::new()))
        }
    }
}

// Endpoint para obter cloud storage exposures de um domínio específico
async fn get_cloud_storage_exposures(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<CloudStorageExposure>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let cloud_storage_path = domain_path.join("cloud_storage_exposure.json");

    // Se o arquivo não existir, retornar array vazio
    if !cloud_storage_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Ler e parsear o arquivo JSON
    match fs::read_to_string(&cloud_storage_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<CloudStorageExposure>>(&content) {
                Ok(exposures) => Ok(Json(exposures)),
                Err(_) => {
                    // Se falhar ao parsear, retornar array vazio
                    Ok(Json(Vec::new()))
                }
            }
        }
        Err(_) => {
            // Se falhar ao ler o arquivo, retornar array vazio
            Ok(Json(Vec::new()))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// VALIDATED HOSTS ENDPOINT
// ═══════════════════════════════════════════════════════════════════

// Endpoint para obter hosts validados com resolução DNS
async fn get_validated_hosts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<ValidatedHost>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let validated_hosts_path = domain_path.join("validated_hosts.json");

    // Se o arquivo não existir, retornar array vazio
    if !validated_hosts_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Ler e parsear o arquivo JSON
    match fs::read_to_string(&validated_hosts_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<ValidatedHost>>(&content) {
                Ok(hosts) => Ok(Json(hosts)),
                Err(_) => {
                    // Se falhar ao parsear, retornar array vazio
                    Ok(Json(Vec::new()))
                }
            }
        }
        Err(_) => {
            // Se falhar ao ler o arquivo, retornar array vazio
            Ok(Json(Vec::new()))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// PACKAGE DEPENDENCIES ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

// Endpoint para obter todas as dependências de pacotes de um domínio específico
async fn get_package_dependencies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<PackageDependency>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let packages_path = domain_path.join("package_dependencies.json");

    // Se o arquivo não existir, retornar array vazio
    if !packages_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Ler e parsear o arquivo JSON
    match fs::read_to_string(&packages_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<PackageDependency>>(&content) {
                Ok(packages) => Ok(Json(packages)),
                Err(_) => {
                    // Se falhar ao parsear, retornar array vazio
                    Ok(Json(Vec::new()))
                }
            }
        }
        Err(_) => {
            // Se falhar ao ler o arquivo, retornar array vazio
            Ok(Json(Vec::new()))
        }
    }
}

// Endpoint para obter apenas as vulnerabilidades de dependency confusion
// Retorna diretamente um array de packages com potential_confusion = true
async fn get_dependency_confusion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<PackageDependency>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let packages_path = domain_path.join("package_dependencies.json");

    // Se o arquivo não existir, retornar array vazio
    if !packages_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Ler e parsear o arquivo JSON
    match fs::read_to_string(&packages_path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<PackageDependency>>(&content) {
                Ok(packages) => {
                    let vulnerable_packages: Vec<PackageDependency> = packages
                        .into_iter()
                        .filter(|p| p.potential_confusion)
                        .collect();

                    Ok(Json(vulnerable_packages))
                }
                Err(_) => {
                    Ok(Json(Vec::new()))
                }
            }
        }
        Err(_) => {
            Ok(Json(Vec::new()))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TRUFFLEHOG SECRETS ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

// Simpler struct for TruffleHog results from file scan
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TruffleHogFileSecret {
    pub detector_name: String,
    pub raw_secret: String,
    pub verified: bool,
    pub source_file: String,
}

// Endpoint to get TruffleHog secrets from file-based scan
async fn get_trufflehog_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Result<Json<Vec<TruffleHogFileSecret>>, Response> {
    verify_token(&headers)?;

    let domain_path = state.base_path.join(&domain);
    let json_path = domain_path.join("trufflehog.json");

    // If file doesn't exist, return empty array
    if !json_path.exists() {
        return Ok(Json(Vec::new()));
    }

    // Read and parse the NDJSON file (newline-delimited JSON)
    match fs::read_to_string(&json_path) {
        Ok(content) => {
            let mut secrets = Vec::new();

            // Parse each line as a separate JSON object
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }

                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                    // Extract fields from TruffleHog JSON format
                    let detector_name = json
                        .get("DetectorName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();

                    let raw_secret = json
                        .get("Raw")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let verified = json
                        .get("Verified")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    // Extract source file from SourceMetadata.Data.Filesystem.file
                    let source_file = json
                        .get("SourceMetadata")
                        .and_then(|v| v.get("Data"))
                        .and_then(|d| d.get("Filesystem"))
                        .and_then(|f| f.get("file"))
                        .and_then(|f| f.as_str())
                        .unwrap_or("Unknown")
                        .to_string();

                    secrets.push(TruffleHogFileSecret {
                        detector_name,
                        raw_secret,
                        verified,
                        source_file,
                    });
                }
            }

            Ok(Json(secrets))
        }
        Err(_) => {
            // If file read fails, return empty array
            Ok(Json(Vec::new()))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// AUTHENTICATION & SETUP ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

// Endpoint para verificar status do setup
async fn check_setup_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SetupStatusResponse>, Response> {
    let admin_config = if let Ok(config) = state.admin_config.lock() {
        config.clone()
    } else {
        None
    };

    match admin_config {
        Some(config) if config.setup_completed => {
            Ok(Json(SetupStatusResponse {
                setup_completed: true,
                username: Some(config.username.clone()),
                must_change_password: config.must_change_password,
            }))
        }
        _ => {
            Ok(Json(SetupStatusResponse {
                setup_completed: false,
                username: None,
                must_change_password: false,
            }))
        }
    }
}

// Endpoint para setup inicial
async fn initial_setup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, Response> {
    // Verificar se já foi configurado
    let existing_config = if let Ok(config) = state.admin_config.lock() {
        config.clone()
    } else {
        None
    };

    if let Some(config) = existing_config {
        if config.setup_completed {
            return Ok(Json(SetupResponse {
                success: false,
                message: "Setup already completed. Use change password to update credentials.".to_string(),
            }));
        }
    }

    // Validar setup code
    if payload.setup_code != *SETUP_CODE {
        return Ok(Json(SetupResponse {
            success: false,
            message: "Invalid setup code".to_string(),
        }));
    }

    // Validações
    if payload.username.len() < 3 {
        return Ok(Json(SetupResponse {
            success: false,
            message: "Username must be at least 3 characters".to_string(),
        }));
    }

    if payload.password.len() < 8 {
        return Ok(Json(SetupResponse {
            success: false,
            message: "Password must be at least 8 characters".to_string(),
        }));
    }

    // Hash da senha com bcrypt
    let password_hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => {
            return Ok(Json(SetupResponse {
                success: false,
                message: "Failed to hash password".to_string(),
            }));
        }
    };

    // Criar configuração
    let now = Utc::now().to_rfc3339();
    let config = AdminConfig {
        username: payload.username,
        password_hash,
        setup_completed: true,
        created_at: now.clone(),
        last_password_change: now,
        must_change_password: false,
    };

    // Salvar no estado
    if let Ok(mut admin) = state.admin_config.lock() {
        *admin = Some(config.clone());

        // Salvar em arquivo
        let config_file = state.base_path.join(".admin_config.json");
        if let Ok(json_content) = serde_json::to_string_pretty(&config) {
            let _ = fs::write(&config_file, json_content);
        }

        Ok(Json(SetupResponse {
            success: true,
            message: "Setup completed successfully! You can now login with your credentials.".to_string(),
        }))
    } else {
        Ok(Json(SetupResponse {
            success: false,
            message: "Failed to save configuration".to_string(),
        }))
    }
}

// Endpoint para trocar senha
async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, Response> {
    // Verificar token
    let username = verify_token(&headers)?;

    // Obter configuração atual
    let current_config = if let Ok(config) = state.admin_config.lock() {
        config.clone()
    } else {
        None
    };

    let Some(mut config) = current_config else {
        return Ok(Json(ChangePasswordResponse {
            success: false,
            message: "No admin configuration found".to_string(),
        }));
    };

    // Verificar se o usuário do token corresponde
    if username != config.username {
        return Ok(Json(ChangePasswordResponse {
            success: false,
            message: "Unauthorized".to_string(),
        }));
    }

    // Verificar senha atual
    match bcrypt::verify(&payload.current_password, &config.password_hash) {
        Ok(valid) if valid => {
            // Validar nova senha
            if payload.new_password.len() < 8 {
                return Ok(Json(ChangePasswordResponse {
                    success: false,
                    message: "New password must be at least 8 characters".to_string(),
                }));
            }

            // Hash da nova senha
            let new_hash = match bcrypt::hash(&payload.new_password, bcrypt::DEFAULT_COST) {
                Ok(hash) => hash,
                Err(_) => {
                    return Ok(Json(ChangePasswordResponse {
                        success: false,
                        message: "Failed to hash new password".to_string(),
                    }));
                }
            };

            // Atualizar configuração
            config.password_hash = new_hash;
            config.last_password_change = Utc::now().to_rfc3339();
            config.must_change_password = false;

            // Salvar no estado
            if let Ok(mut admin) = state.admin_config.lock() {
                *admin = Some(config.clone());

                // Salvar em arquivo
                let config_file = state.base_path.join(".admin_config.json");
                if let Ok(json_content) = serde_json::to_string_pretty(&config) {
                    let _ = fs::write(&config_file, json_content);
                }

                Ok(Json(ChangePasswordResponse {
                    success: true,
                    message: "Password changed successfully!".to_string(),
                }))
            } else {
                Ok(Json(ChangePasswordResponse {
                    success: false,
                    message: "Failed to save new password".to_string(),
                }))
            }
        }
        _ => Ok(Json(ChangePasswordResponse {
            success: false,
            message: "Current password is incorrect".to_string(),
        })),
    }
}

// Criar o router da aplicação
pub fn create_router(base_path: PathBuf) -> Router {
    // Carregar webhook do arquivo se existir
    let webhook_file = base_path.join(".webhook_discord.txt");
    let saved_webhook = if webhook_file.exists() {
        fs::read_to_string(&webhook_file).ok()
    } else {
        None
    };

    // Carregar configuração GitHub do arquivo se existir
    let github_file = base_path.join(".github_config.json");
    let saved_github = if github_file.exists() {
        if let Ok(content) = fs::read_to_string(&github_file) {
            serde_json::from_str::<GitHubConfig>(&content).ok()
        } else {
            None
        }
    } else {
        None
    };

    // Load admin config from file, or create default admin/enumrust
    let admin_file = base_path.join(".admin_config.json");
    let saved_admin = if admin_file.exists() {
        if let Ok(content) = fs::read_to_string(&admin_file) {
            serde_json::from_str::<AdminConfig>(&content).ok()
        } else {
            None
        }
    } else {
        None
    };
    let saved_admin = match saved_admin {
        Some(config) => Some(config),
        None => {
            // Auto-create default admin account: admin / enumrust
            let default_hash = bcrypt::hash("enumrust", bcrypt::DEFAULT_COST)
                .expect("Failed to hash default password");
            let now = Utc::now().to_rfc3339();
            let default_config = AdminConfig {
                username: "admin".to_string(),
                password_hash: default_hash,
                setup_completed: true,
                created_at: now.clone(),
                last_password_change: now,
                must_change_password: true,
            };
            // Save default config to file
            if let Ok(json_content) = serde_json::to_string_pretty(&default_config) {
                let _ = fs::write(&admin_file, json_content);
            }
            println!("📋 Default credentials created: admin / enumrust");
            println!("⚠️  You will be required to change the password on first login.");
            Some(default_config)
        }
    };

    let state = Arc::new(AppState {
        base_path,
        webhook_url: Arc::new(Mutex::new(saved_webhook)),
        github_config: Arc::new(Mutex::new(saved_github)),
        trufflehog_secrets: Arc::new(Mutex::new(Vec::new())),
        admin_config: Arc::new(Mutex::new(saved_admin)),
        http_client: Client::new(),
    });

    Router::new()
        // Setup & Authentication
        .route("/api/setup/status", get(check_setup_status))
        .route("/api/setup/initial", post(initial_setup))
        .route("/api/auth/change-password", post(change_password))
        .route("/api/login", post(login))
        .route("/api/dashboard/stats", get(get_dashboard_stats))
        .route("/api/domain/:domain/data", get(get_domain_data))
        .route("/api/domain/:domain/files", get(list_domain_files))
        .route("/api/domain/:domain/vulnerabilities", get(get_domain_vulnerabilities))
        .route("/api/domain/:domain/subdomains", get(get_subdomains_list))
        .route("/api/domain/:domain/nuclei", get(get_nuclei_results))
        .route("/api/domain/:domain/http200", get(get_http200_urls))
        .route("/api/domain/:domain/http403", get(get_http403_urls))
        .route("/api/domain/:domain/js_secrets", get(get_js_secrets))
        .route("/api/domain/:domain/js_endpoints", get(get_js_endpoints))
        .route("/api/domain/:domain/js_endpoints/download", get(download_js_endpoints_txt))
        .route("/api/domain/:domain/access_pages", get(get_access_pages))
        .route("/api/domain/:domain/s3_buckets", get(get_s3_buckets))
        .route("/api/domain/:domain/hardcoded_secrets", get(get_hardcoded_secrets))
        .route("/api/domain/:domain/trufflehog", get(get_trufflehog_secrets))
        .route("/api/domain/:domain/cloud_storage", get(get_cloud_storage_exposures))
        .route("/api/domain/:domain/validated_hosts", get(get_validated_hosts))
        .route("/api/domain/:domain/packages", get(get_package_dependencies))
        .route("/api/domain/:domain/dependency_confusion", get(get_dependency_confusion))
        .route("/api/infrastructure/scans", get(get_infrastructure_scans))
        .route("/api/infrastructure/ports", get(get_infrastructure_ports))
        .route("/api/infrastructure/services", get(get_infrastructure_services))
        .route("/api/file/*file_path", get(read_file_content))
        .route("/api/scans", get(list_scans))
        .route("/api/scan/:target/progress", get(get_scan_progress))
        .route("/api/scan/:target/status", get(get_current_status))
        .route("/api/webhook/save", post(save_webhook))
        .route("/api/webhook/get", get(get_webhook))
        .route("/api/github/config/save", post(save_github_config))
        .route("/api/github/config/get", get(get_github_config))
        .route("/api/github/repos", get(list_github_repos))
        .route("/api/github/trufflehog/scan", post(run_trufflehog_scan))
        .route("/api/github/trufflehog/results", get(get_trufflehog_results))
        .route("/api/github/trufflehog/checkpoint/:org", get(get_trufflehog_checkpoint_status))
        .route("/", get(serve_frontend))
        .fallback(serve_frontend)
        .with_state(state)
        .layer(CorsLayer::permissive())
}

// Servir o frontend React com headers anti-cache
async fn serve_frontend() -> Response {
    let html_content = include_str!("../dashboard-ui/index.html").to_string();

    // Criar response com headers que forçam o navegador a sempre recarregar
    let mut response = Html(html_content).into_response();
    let headers = response.headers_mut();

    // Headers anti-cache super agressivos
    headers.insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate, max-age=0".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(header::EXPIRES, "0".parse().unwrap());

    // ETag que muda a cada build (timestamp ou versão)
    headers.insert(header::ETAG, format!("\"enumrust-v{}\"", chrono::Utc::now().timestamp()).parse().unwrap());

    response
}

// Iniciar o servidor do dashboard
pub async fn start_dashboard_server(base_path: PathBuf, port: u16) -> anyhow::Result<()> {
    let app = create_router(base_path);
    let addr = format!("0.0.0.0:{}", port);

    println!("🚀 Dashboard server starting on http://{}", addr);
    println!("📊 Access the dashboard at http://{}", addr);
    println!("🔑 Default credentials: admin / enumrust (password change required on first login)");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Graceful shutdown with signal handling
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    println!("✅ Dashboard server shut down gracefully");

    Ok(())
}

// Graceful shutdown signal handler
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            println!("\n⚠️ Received Ctrl+C signal, shutting down gracefully...");
        },
        _ = terminate => {
            println!("\n⚠️ Received SIGTERM signal, shutting down gracefully...");
        },
    }
}
