#![allow(dead_code)]
// js_crawler.rs - Enhanced JavaScript File Crawler & Secrets Extractor
// Purpose: Collect, analyze, and extract secrets from JavaScript files
// Integration: URLFinder + HTTP200 + Dynamic JS discovery

use colored::*;
use dashmap::DashSet;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

use crate::secrets_scanner::{
    scan_for_all_hardcoded_secrets, scan_for_cloud_storage, HardcodedSecret, CloudStorageExposure,
};

// JavaScript file extensions and patterns
const JS_EXTENSIONS: &[&str] = &[".js", ".jsx", ".mjs", ".ts", ".tsx", ".js.map", ".mjs.map"];
const JS_PATTERNS: &[&str] = &[
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "application/json",
];

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct JsFile {
    pub url: String,
    pub source: String, // Where it was found: "urlfinder", "http200", "dom"
    pub size: Option<usize>,
    pub content_type: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct JsSecret {
    pub secret_type: String,
    pub secret_value: String,
    pub source_url: String,
    pub validation_status: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JsEndpoint {
    pub endpoint: String,
    pub source_url: String,
    pub method: Option<String>,
}

/// Extract JavaScript URLs from URLFinder output
pub async fn extract_js_from_urlfinder(urlfinder_path: &Path) -> Vec<String> {
    let mut js_urls = Vec::new();

    if !urlfinder_path.exists() {
        return js_urls;
    }

    if let Ok(file) = File::open(urlfinder_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Check if URL ends with JS extension
            if JS_EXTENSIONS.iter().any(|ext| line.to_lowercase().ends_with(ext)) {
                js_urls.push(line.to_string());
            }

            // Check if URL contains .js in query params or path
            if line.contains(".js?") || line.contains(".js#") {
                js_urls.push(line.to_string());
            }
        }
    }

    // Deduplicate
    let unique_urls: HashSet<String> = js_urls.into_iter().collect();
    unique_urls.into_iter().collect()
}

/// Extract JavaScript URLs from HTTP 200 responses
pub async fn extract_js_from_http200(http200_path: &Path) -> Vec<String> {
    let mut js_urls = Vec::new();

    if !http200_path.exists() {
        return js_urls;
    }

    if let Ok(file) = File::open(http200_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if JS_EXTENSIONS.iter().any(|ext| line.to_lowercase().ends_with(ext)) {
                js_urls.push(line.to_string());
            }
        }
    }

    let unique_urls: HashSet<String> = js_urls.into_iter().collect();
    unique_urls.into_iter().collect()
}

/// Discover JavaScript files dynamically from HTML pages
pub async fn discover_js_from_html(
    html_url: &str,
    client: &Client,
) -> Vec<String> {
    let mut js_urls = Vec::new();

    // Fetch HTML content with timeout
    let response = match client
        .get(html_url)
        .timeout(Duration::from_secs(15))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => return js_urls,
    };

    if !response.status().is_success() {
        return js_urls;
    }

    let html_content = match response.text().await {
        Ok(content) => content,
        Err(_) => return js_urls,
    };

    // Parse HTML
    let document = Html::parse_document(&html_content);

    // Extract from <script src="...">
    let script_selector = Selector::parse("script[src]").unwrap();
    for element in document.select(&script_selector) {
        if let Some(src) = element.value().attr("src") {
            if let Ok(absolute_url) = make_absolute_url(html_url, src) {
                js_urls.push(absolute_url);
            }
        }
    }

    // Extract from <link> tags (for module preloads)
    let link_selector = Selector::parse("link[href]").unwrap();
    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            if JS_EXTENSIONS.iter().any(|ext| href.ends_with(ext)) {
                if let Ok(absolute_url) = make_absolute_url(html_url, href) {
                    js_urls.push(absolute_url);
                }
            }
        }
    }

    // Extract inline references (more aggressive)
    let inline_js_regex = Regex::new(r#"(?:src|href)=["']([^"']+\.(?:js|jsx|mjs|ts))["']"#).unwrap();
    for cap in inline_js_regex.captures_iter(&html_content) {
        if let Some(url_match) = cap.get(1) {
            if let Ok(absolute_url) = make_absolute_url(html_url, url_match.as_str()) {
                js_urls.push(absolute_url);
            }
        }
    }

    // Deduplicate
    let unique_urls: HashSet<String> = js_urls.into_iter().collect();
    unique_urls.into_iter().collect()
}

/// Make URL absolute based on base URL
fn make_absolute_url(base: &str, relative: &str) -> Result<String, url::ParseError> {
    let base_url = Url::parse(base)?;

    // Handle protocol-relative URLs
    if relative.starts_with("//") {
        return Ok(format!("{}{}", base_url.scheme(), relative));
    }

    // Handle absolute URLs
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return Ok(relative.to_string());
    }

    // Join relative URL with base
    let joined = base_url.join(relative)?;
    Ok(joined.to_string())
}

/// Fetch and analyze a JavaScript file for secrets and endpoints
pub async fn analyze_js_file(
    js_url: &str,
    client: &Client,
    validate_tokens: bool,
) -> (Vec<HardcodedSecret>, Vec<JsEndpoint>, Vec<CloudStorageExposure>) {
    let mut secrets = Vec::new();
    let mut endpoints = Vec::new();
    let mut cloud_storage = Vec::new();

    // Fetch JS file content
    let response = match client
        .get(js_url)
        .timeout(Duration::from_secs(20))
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(_) => return (secrets, endpoints, cloud_storage),
    };

    if !response.status().is_success() {
        return (secrets, endpoints, cloud_storage);
    }

    // Check content type
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Only process if it's actually JavaScript
    if !JS_PATTERNS.iter().any(|pattern| content_type.contains(pattern))
        && !JS_EXTENSIONS.iter().any(|ext| js_url.ends_with(ext))
    {
        return (secrets, endpoints, cloud_storage);
    }

    let js_content = match response.text().await {
        Ok(content) => content,
        Err(_) => return (secrets, endpoints, cloud_storage),
    };

    // Scan for hardcoded secrets (using comprehensive scan)
    let found_secrets = scan_for_all_hardcoded_secrets(&js_content, js_url, client, validate_tokens).await;
    secrets.extend(found_secrets);

    // Scan for cloud storage URLs
    let found_storage = scan_for_cloud_storage(&js_content, js_url, client, false).await;
    cloud_storage.extend(found_storage);

    // Extract API endpoints
    let found_endpoints = extract_api_endpoints(&js_content, js_url);
    endpoints.extend(found_endpoints);

    (secrets, endpoints, cloud_storage)
}

/// Extract API endpoints from JavaScript content - ENHANCED VERSION
pub fn extract_api_endpoints(js_content: &str, source_url: &str) -> Vec<JsEndpoint> {
    let mut endpoints = Vec::new();

    // Common API endpoint patterns - EXPANDED
    let patterns = vec![
        // Fetch API calls
        Regex::new(r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        Regex::new(r#"fetch\s*\(\s*`([^`]+)`"#).unwrap(),
        // Axios calls
        Regex::new(r#"axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // jQuery AJAX
        Regex::new(r#"\$\.(?:ajax|get|post)\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // XMLHttpRequest open
        Regex::new(r#"\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // API endpoint definitions
        Regex::new(r#"(?:apiUrl|API_URL|endpoint|ENDPOINT|baseUrl|BASE_URL|apiEndpoint|API_ENDPOINT)\s*[:=]\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // Route definitions
        Regex::new(r#"(?:route|path|url|uri|URI):\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // GraphQL endpoints
        Regex::new(r#"(?:graphql|GRAPHQL|gql|GQL).*?["'`]([^"'`]*(?:graphql|query)[^"'`]*)["'`]"#).unwrap(),
        // REST API patterns
        Regex::new(r#"["'`](/(?:api|rest|v\d+)/[^"'`\s]+)["'`]"#).unwrap(),
        // WebSocket endpoints
        Regex::new(r#"(?:ws|wss)://([^"'`\s]+)"#).unwrap(),
        // URL constructor
        Regex::new(r#"new\s+URL\s*\(\s*["'`]([^"'`]+)["'`]"#).unwrap(),
        // Template literals with endpoints
        Regex::new(r#"`([^`]*(?:/api|/v\d+|/rest|/graphql)[^`]*)`"#).unwrap(),
        // Relative API paths
        Regex::new(r#"["']/(api|admin|dashboard|backend|service|auth|user|data)/[^"'\s]*["']"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(endpoint_match) = cap.get(1) {
                let endpoint = endpoint_match.as_str().trim().to_string();

                // Enhanced filtering - accept more endpoint patterns
                if !endpoint.is_empty() && (
                    endpoint.starts_with("http")
                    || endpoint.starts_with("ws://")
                    || endpoint.starts_with("wss://")
                    || endpoint.starts_with("/api")
                    || endpoint.starts_with("/v1")
                    || endpoint.starts_with("/v2")
                    || endpoint.starts_with("/v3")
                    || endpoint.starts_with("/admin")
                    || endpoint.starts_with("/dashboard")
                    || endpoint.starts_with("/backend")
                    || endpoint.starts_with("/auth")
                    || endpoint.starts_with("/user")
                    || endpoint.starts_with("/service")
                    || endpoint.contains("/graphql")
                    || endpoint.contains("/rest")
                    || endpoint.contains("/query")
                ) {
                    endpoints.push(JsEndpoint {
                        endpoint: endpoint.clone(),
                        source_url: source_url.to_string(),
                        method: None,
                    });
                }
            }
        }
    }

    // Deduplicate
    let mut seen = HashSet::new();
    endpoints.retain(|e| seen.insert(e.endpoint.clone()));

    endpoints
}

/// Comprehensive JS crawler that combines all sources
pub async fn crawl_all_js_sources(
    base_path: &Path,
    http200_urls: &[String],
    client: &Client,
    validate_tokens: bool,
    max_concurrent: usize,
) -> (Vec<HardcodedSecret>, Vec<JsEndpoint>, Vec<CloudStorageExposure>, Vec<String>) {
    let mut all_secrets = Vec::new();
    let mut all_endpoints = Vec::new();
    let mut all_cloud_storage = Vec::new();

    let seen_js_urls: Arc<DashSet<String>> = Arc::new(DashSet::new());

    println!("{}", "[*] Phase 1: Extracting JS from ffuf discovery...".cyan());
    let ffuf_js_path = base_path.join("ffuf_discovered_js.txt");
    let ffuf_js = extract_js_from_urlfinder(&ffuf_js_path).await;
    for url in &ffuf_js {
        seen_js_urls.insert(url.clone());
    }
    println!("{}", format!("[+] Found {} JS files via ffuf", ffuf_js.len()).green());

    println!("{}", "[*] Phase 2: Extracting JS from URLFinder...".cyan());
    let urlfinder_path = base_path.join("urlfinder.txt");
    let urlfinder_js = extract_js_from_urlfinder(&urlfinder_path).await;
    for url in &urlfinder_js {
        seen_js_urls.insert(url.clone());
    }
    println!("{}", format!("[+] Found {} JS files in URLFinder", urlfinder_js.len()).green());

    println!("{}", "[*] Phase 3: Extracting JS from HTTP200...".cyan());
    let http200_path = base_path.join("http200.txt");
    let http200_js = extract_js_from_http200(&http200_path).await;
    for url in &http200_js {
        seen_js_urls.insert(url.clone());
    }
    println!("{}", format!("[+] Found {} JS files in HTTP200", http200_js.len()).green());

    println!("{}", "[*] Phase 4: Discovering JS from HTML pages...".cyan());
    let mut html_discovery_count = 0;
    for url in http200_urls.iter().take(50) {
        // Limit to first 50 HTML pages
        if url.ends_with(".html") || url.ends_with("/") || !url.contains('.') {
            let discovered = discover_js_from_html(url, client).await;
            for js_url in discovered {
                if seen_js_urls.insert(js_url.clone()) {
                    html_discovery_count += 1;
                }
            }
            sleep(Duration::from_millis(100)).await; // Rate limiting
        }
    }
    println!("{}", format!("[+] Discovered {} additional JS files from HTML", html_discovery_count).green());

    let total_js_files: Vec<String> = seen_js_urls.iter().map(|r| r.key().clone()).collect();
    println!("{}", format!("[*] Total unique JS files to analyze: {}", total_js_files.len()).cyan().bold());

    // Analyze all JS files with concurrency control
    println!("{}", "[*] Phase 5: Analyzing JS files for secrets and endpoints...".cyan());

    use futures::stream::{self, StreamExt};

    // Clone the list for analysis while keeping the original for return
    let results = stream::iter(total_js_files.clone())
        .map(|js_url| {
            let client = client.clone();
            async move {
                let result = analyze_js_file(&js_url, &client, validate_tokens).await;
                (js_url, result)
            }
        })
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await;

    for (url, (secrets, endpoints, storage)) in results {
        if !secrets.is_empty() {
            println!("{}", format!("  [!] Found {} secrets in: {}", secrets.len(), url).red());
        }
        if !endpoints.is_empty() {
            println!("{}", format!("  [+] Found {} endpoints in: {}", endpoints.len(), url).yellow());
        }
        all_secrets.extend(secrets);
        all_endpoints.extend(endpoints);
        all_cloud_storage.extend(storage);
    }

    // Return discovered JS files along with analysis results
    (all_secrets, all_endpoints, all_cloud_storage, total_js_files)
}

/// Save JS secrets to file (compatible with dashboard format)
pub fn save_js_secrets_to_file(
    secrets: &[HardcodedSecret],
    output_path: &Path,
) -> std::io::Result<()> {
    let mut file = File::create(output_path)?;

    for secret in secrets {
        // Format: [TYPE] preview - url (STATUS)
        let status_str = if secret.validated {
            format!("({})", secret.validation_status)
        } else {
            String::new()
        };

        writeln!(
            file,
            "[{}] {} - {} {}",
            secret.secret_type, secret.secret_preview, secret.found_in_url, status_str
        )?;
    }

    Ok(())
}

/// Save JS endpoints to file
pub fn save_js_endpoints_to_file(
    endpoints: &[JsEndpoint],
    output_path: &Path,
) -> std::io::Result<()> {
    let mut file = File::create(output_path)?;

    for endpoint in endpoints {
        if let Some(ref method) = endpoint.method {
            writeln!(
                file,
                "[{}] {} - {}",
                method, endpoint.endpoint, endpoint.source_url
            )?;
        } else {
            writeln!(file, "{} - {}", endpoint.endpoint, endpoint.source_url)?;
        }
    }

    Ok(())
}

/// Extract S3 bucket URLs from JavaScript content
pub fn extract_s3_buckets(js_content: &str, source_url: &str) -> Vec<String> {
    let mut buckets = HashSet::new();

    // Comprehensive S3 URL patterns
    let patterns = vec![
        // Format: https://bucket-name.s3.amazonaws.com
        Regex::new(r#"https?://([a-z0-9][a-z0-9\-\.]+)\.s3\.amazonaws\.com"#).unwrap(),

        // Format: https://bucket-name.s3-region.amazonaws.com
        Regex::new(r#"https?://([a-z0-9][a-z0-9\-\.]+)\.s3-[a-z0-9\-]+\.amazonaws\.com"#).unwrap(),

        // Format: https://bucket-name.s3.region.amazonaws.com
        Regex::new(r#"https?://([a-z0-9][a-z0-9\-\.]+)\.s3\.[a-z0-9\-]+\.amazonaws\.com"#).unwrap(),

        // Format: https://s3.amazonaws.com/bucket-name
        Regex::new(r#"https?://s3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]+)"#).unwrap(),

        // Format: https://s3.region.amazonaws.com/bucket-name
        Regex::new(r#"https?://s3\.[a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]+)"#).unwrap(),

        // Format: s3://bucket-name
        Regex::new(r#"s3://([a-z0-9][a-z0-9\-\.]+)"#).unwrap(),

        // Config patterns: S3_BUCKET, AWS_BUCKET, etc.
        Regex::new(r#"(?:S3_BUCKET|AWS_BUCKET|BUCKET_NAME|s3Bucket|awsBucket)["'\s:=]+["']([a-z0-9][a-z0-9\-\.]+)["']"#).unwrap(),

        // CloudFront distributions pointing to S3
        Regex::new(r#"https?://([a-z0-9]+)\.cloudfront\.net"#).unwrap(),
    ];

    for pattern in &patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(bucket_match) = cap.get(0) {
                let url = bucket_match.as_str().to_string();

                // Validar se não é uma URL genérica demais
                if !url.contains("example") && !url.contains("placeholder") {
                    buckets.insert(format!("{} - {}", url, source_url));
                }
            } else if let Some(bucket_name) = cap.get(1) {
                let name = bucket_name.as_str();

                // Validar nome do bucket
                if is_valid_s3_bucket_name(name) {
                    // Gerar URL completa do bucket
                    let full_url = format!("https://{}.s3.amazonaws.com", name);
                    buckets.insert(format!("{} - {}", full_url, source_url));
                }
            }
        }
    }

    buckets.into_iter().collect()
}

/// Validate S3 bucket name according to AWS rules
fn is_valid_s3_bucket_name(name: &str) -> bool {
    // S3 bucket naming rules:
    // 1. Between 3 and 63 characters
    // 2. Can contain lowercase letters, numbers, hyphens, and dots
    // 3. Must start and end with letter or number
    // 4. Cannot be formatted as IP address

    if name.len() < 3 || name.len() > 63 {
        return false;
    }

    // Must start and end with lowercase letter or number
    if !name.chars().next().unwrap().is_ascii_alphanumeric()
        || !name.chars().last().unwrap().is_ascii_alphanumeric() {
        return false;
    }

    // Check for valid characters
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') {
        return false;
    }

    // Reject if looks like IP address (e.g., 192.168.1.1)
    if name.split('.').all(|part| part.parse::<u8>().is_ok()) {
        return false;
    }

    // Reject common false positives
    let false_positives = ["localhost", "example", "test", "demo", "sample", "default"];
    if false_positives.iter().any(|&fp| name.contains(fp)) {
        return false;
    }

    true
}

/// Save S3 buckets to file
pub fn save_s3_buckets_to_file(
    buckets: &[String],
    output_path: &Path,
) -> std::io::Result<()> {
    let mut file = File::create(output_path)?;

    writeln!(file, "=== S3 BUCKETS DISCOVERED ===")?;
    writeln!(file, "Total: {}", buckets.len())?;
    writeln!(file)?;

    for bucket_entry in buckets {
        writeln!(file, "{}", bucket_entry)?;
    }

    Ok(())
}

/// Crawl JS files and extract S3 buckets
pub async fn crawl_s3_buckets_from_js(
    js_files: &[String],
    client: &Client,
) -> Vec<String> {
    let mut all_buckets = HashSet::new();

    println!("{}", "[*] Scanning JavaScript files for S3 buckets...".cyan());

    let mut scanned = 0;
    let total = js_files.len();

    for js_url in js_files {
        scanned += 1;

        // Fetch JS content
        match client
            .get(js_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(response) => {
                if let Ok(js_content) = response.text().await {
                    let buckets = extract_s3_buckets(&js_content, js_url);

                    if !buckets.is_empty() {
                        println!(
                            "{}",
                            format!("  [+] [{}/{}] Found {} S3 buckets in: {}",
                                scanned, total, buckets.len(), js_url
                            ).green()
                        );
                        all_buckets.extend(buckets);
                    } else if scanned <= 10 || scanned % 20 == 0 {
                        println!(
                            "{}",
                            format!("  [-] [{}/{}] No S3 buckets in: {}",
                                scanned, total, js_url
                            ).yellow()
                        );
                    }
                }
            }
            Err(e) => {
                if scanned <= 10 {
                    println!(
                        "{}",
                        format!("  [!] [{}/{}] Failed to fetch: {} - {}",
                            scanned, total, js_url, e
                        ).red()
                    );
                }
                continue;
            }
        }
    }

    let result: Vec<String> = all_buckets.into_iter().collect();
    println!("{}", format!("[+] Total S3 buckets discovered: {}", result.len()).green().bold());

    result
}

// ==================== SOURCE MAP ANALYSIS ====================

/// Source Map structure for parsing .map files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMap {
    pub version: Option<u32>,
    pub file: Option<String>,
    pub sources: Vec<String>,
    pub names: Vec<String>,
    #[serde(rename = "sourcesContent")]
    pub sources_content: Option<Vec<String>>,
}

/// Information extracted from source maps
#[derive(Debug, Clone)]
pub struct SourceMapInfo {
    pub map_url: String,
    pub original_files: Vec<String>,
    pub secrets: Vec<HardcodedSecret>,
    pub endpoints: Vec<JsEndpoint>,
    pub comments: Vec<String>,
    pub file_paths: Vec<String>,
}

/// Try to find and fetch source map for a JS file
pub async fn find_source_map(js_url: &str, js_content: &str, _client: &Client) -> Option<String> {
    // Check for sourceMappingURL comment at the end of file
    let source_map_regex = Regex::new(r"//[@#]\s*sourceMappingURL=([^\s]+)").ok()?;

    if let Some(cap) = source_map_regex.captures(js_content) {
        if let Some(map_path) = cap.get(1) {
            let map_url = make_absolute_url(js_url, map_path.as_str()).ok()?;
            return Some(map_url);
        }
    }

    // Try common .map file convention
    if let Ok(map_url) = make_absolute_url(js_url, &format!("{}.map", js_url)) {
        return Some(map_url);
    }

    None
}

/// Fetch and parse source map
pub async fn fetch_source_map(map_url: &str, client: &Client) -> Option<SourceMap> {
    let response = client
        .get(map_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let map_text = response.text().await.ok()?;
    serde_json::from_str::<SourceMap>(&map_text).ok()
}

/// Analyze source map for secrets and information
pub async fn analyze_source_map(
    map_url: &str,
    source_map: &SourceMap,
    client: &Client,
    validate_tokens: bool,
) -> SourceMapInfo {
    let mut info = SourceMapInfo {
        map_url: map_url.to_string(),
        original_files: source_map.sources.clone(),
        secrets: Vec::new(),
        endpoints: Vec::new(),
        comments: Vec::new(),
        file_paths: Vec::new(),
    };

    // Extract file paths - these reveal directory structure
    for source in &source_map.sources {
        if !source.is_empty() {
            info.file_paths.push(source.clone());
        }
    }

    // Analyze sourcesContent if available
    if let Some(ref sources_content) = source_map.sources_content {
        for (idx, content) in sources_content.iter().enumerate() {
            if content.is_empty() {
                continue;
            }

            let source_name = source_map.sources.get(idx)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            // Scan for secrets in original source (using comprehensive scan)
            // Pass the source map URL as the main URL for reference
            let mut secrets = scan_for_all_hardcoded_secrets(
                content,
                map_url,  // Keep the actual source map URL for direct access
                client,
                validate_tokens
            ).await;

            // Add source file context to each secret found in this source
            for secret in &mut secrets {
                secret.context = format!("[Source: {}] {}", source_name, secret.context);
            }

            info.secrets.append(&mut secrets);

            // Extract endpoints from original source
            let mut endpoints = extract_api_endpoints(
                content,
                &format!("{} ({})", map_url, source_name)
            );
            info.endpoints.append(&mut endpoints);

            // Extract comments (they often contain TODO, DEBUG, credentials info)
            let comments = extract_code_comments(content);
            info.comments.extend(comments);
        }
    }

    info
}

/// Extract comments from JavaScript code
fn extract_code_comments(code: &str) -> Vec<String> {
    let mut comments = Vec::new();

    // Single-line comments
    let single_line_regex = Regex::new(r"//\s*(.+)$").unwrap();
    for line in code.lines() {
        if let Some(cap) = single_line_regex.captures(line) {
            if let Some(comment) = cap.get(1) {
                let comment_text = comment.as_str().trim();
                // Filter out source map references
                if !comment_text.starts_with("# sourceMappingURL") &&
                   !comment_text.starts_with("@ sourceMappingURL") &&
                   comment_text.len() > 5 {
                    comments.push(comment_text.to_string());
                }
            }
        }
    }

    // Multi-line comments
    let multi_line_regex = Regex::new(r"/\*\s*([\s\S]*?)\s*\*/").unwrap();
    for cap in multi_line_regex.captures_iter(code) {
        if let Some(comment) = cap.get(1) {
            let comment_text = comment.as_str().trim();
            if comment_text.len() > 5 {
                comments.push(comment_text.to_string());
            }
        }
    }

    comments
}

/// Extract environment variable references from code
pub fn extract_env_variables(code: &str) -> Vec<String> {
    let mut env_vars = HashSet::new();

    let patterns = vec![
        // process.env.VAR_NAME
        Regex::new(r"process\.env\.([A-Z_][A-Z0-9_]*)").unwrap(),
        // process.env['VAR_NAME'] or process.env["VAR_NAME"]
        Regex::new(r#"process\.env\[["']([A-Z_][A-Z0-9_]*)["']\]"#).unwrap(),
        // import.meta.env.VAR_NAME (Vite)
        Regex::new(r"import\.meta\.env\.([A-Z_][A-Z0-9_]*)").unwrap(),
        // Webpack DefinePlugin
        Regex::new(r#"typeof\s+([A-Z_][A-Z0-9_]*)\s*!==\s*["']undefined["']"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(code) {
            if let Some(var_name) = cap.get(1) {
                env_vars.insert(var_name.as_str().to_string());
            }
        }
    }

    env_vars.into_iter().collect()
}

/// Extract debug/development code patterns
pub fn extract_debug_info(code: &str) -> Vec<String> {
    let mut debug_info = Vec::new();

    let patterns = vec![
        // console.log with interesting content
        Regex::new(r#"console\.(?:log|debug|info|warn|error)\s*\(\s*["'`]([^"'`]{10,})["'`]"#).unwrap(),
        // debugger statements
        Regex::new(r"debugger\s*;").unwrap(),
        // TODO comments
        Regex::new(r"//\s*TODO:?\s*(.+)$").unwrap(),
        // FIXME comments
        Regex::new(r"//\s*FIXME:?\s*(.+)$").unwrap(),
        // DEBUG flags
        Regex::new(r#"(?:DEBUG|debug|IS_DEBUG)\s*[:=]\s*(true|false)"#).unwrap(),
    ];

    for pattern in &patterns {
        for cap in pattern.captures_iter(code) {
            if let Some(info) = cap.get(0) {
                debug_info.push(info.as_str().to_string());
            }
        }
    }

    debug_info
}

/// Comprehensive source map crawler
pub async fn crawl_source_maps(
    js_files: &[String],
    client: &Client,
    validate_tokens: bool,
    max_concurrent: usize,
) -> Vec<SourceMapInfo> {
    println!("{}", "[*] Searching for source maps (.map files)...".cyan());

    let mut all_maps = Vec::new();
    let mut found = 0;

    use futures::stream::{self, StreamExt};

    let results = stream::iter(js_files.to_vec())
        .map(|js_url| {
            let client = client.clone();
            async move {
                // Fetch JS file
                let js_response = client
                    .get(&js_url)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await
                    .ok()?;

                let js_content = js_response.text().await.ok()?;

                // Try to find source map
                let map_url = find_source_map(&js_url, &js_content, &client).await?;

                // Fetch and parse source map
                let source_map = fetch_source_map(&map_url, &client).await?;

                // Analyze it
                let info = analyze_source_map(&map_url, &source_map, &client, validate_tokens).await;

                Some(info)
            }
        })
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await;

    for info in results.into_iter().flatten() {
        found += 1;
        println!("{}", format!("  [+] Found source map: {}", info.map_url).green());
        println!("{}", format!("      Original files: {}", info.original_files.len()).cyan());
        if !info.secrets.is_empty() {
            println!("{}", format!("      Secrets found: {}", info.secrets.len()).red());
        }
        if !info.endpoints.is_empty() {
            println!("{}", format!("      Endpoints found: {}", info.endpoints.len()).yellow());
        }
        all_maps.push(info);
    }

    println!("{}", format!("[+] Source map analysis complete: {} maps found", found).green().bold());

    all_maps
}

/// Save source map analysis results
pub fn save_source_map_info(
    maps: &[SourceMapInfo],
    output_path: &Path,
) -> std::io::Result<()> {
    let mut file = File::create(output_path)?;

    writeln!(file, "=== SOURCE MAP ANALYSIS ===")?;
    writeln!(file, "Total source maps found: {}", maps.len())?;
    writeln!(file)?;

    for (idx, map_info) in maps.iter().enumerate() {
        writeln!(file, "--- Source Map {} ---", idx + 1)?;
        writeln!(file, "Map URL: {}", map_info.map_url)?;
        writeln!(file, "Original files ({}):", map_info.original_files.len())?;
        for orig_file in &map_info.original_files {
            writeln!(file, "  - {}", orig_file)?;
        }

        if !map_info.file_paths.is_empty() {
            writeln!(file, "\nFile paths revealed ({}):", map_info.file_paths.len())?;
            for path in &map_info.file_paths {
                writeln!(file, "  {}", path)?;
            }
        }

        if !map_info.comments.is_empty() {
            writeln!(file, "\nComments found ({}):", map_info.comments.len())?;
            for comment in map_info.comments.iter().take(20) {
                writeln!(file, "  // {}", comment)?;
            }
            if map_info.comments.len() > 20 {
                writeln!(file, "  ... and {} more", map_info.comments.len() - 20)?;
            }
        }

        if !map_info.secrets.is_empty() {
            writeln!(file, "\nSecrets found ({}):", map_info.secrets.len())?;
            for secret in &map_info.secrets {
                writeln!(file, "  [{}] {}", secret.secret_type, secret.secret_preview)?;
            }
        }

        if !map_info.endpoints.is_empty() {
            writeln!(file, "\nEndpoints found ({}):", map_info.endpoints.len())?;
            for endpoint in &map_info.endpoints {
                writeln!(file, "  {}", endpoint.endpoint)?;
            }
        }

        writeln!(file)?;
    }

    Ok(())
}
