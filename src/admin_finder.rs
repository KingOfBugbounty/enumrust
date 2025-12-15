// admin_finder.rs - Admin Panel Discovery Module
// Purpose: Discover administrative panels and login pages across multiple ports
// Features:
//  - Multi-port scanning (80, 443, 8080, 8443, 8000, 3000, 5000, 9000, etc.)
//  - Common admin path enumeration
//  - HTTP status code analysis
//  - Title and content fingerprinting
//  - Parallel scanning for performance

use anyhow::{Context, Result};
use colored::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

/// Common ports for admin interfaces
const COMMON_ADMIN_PORTS: &[u16] = &[
    80,    // HTTP
    443,   // HTTPS
    8080,  // HTTP alternate
    8443,  // HTTPS alternate
    8000,  // Development
    3000,  // Node.js / React
    5000,  // Flask / Python
    9000,  // PHP-FPM / Portainer
    8888,  // Jupyter / Custom
    8088,  // Custom admin panels
    8081,  // Common alternate
    9090,  // Prometheus / Custom
    3001,  // React alternate
    4200,  // Angular
    5001,  // Custom
];

/// Common admin paths to check
const ADMIN_PATHS: &[&str] = &[
    // Generic admin paths
    "/admin",
    "/administrator",
    "/admin.php",
    "/admin.html",
    "/admin/",
    "/admin/index.php",
    "/admin/login.php",
    "/admin/login.html",
    "/admin/dashboard",
    "/admin/panel",
    "/admin/cp",
    "/admin/controlpanel",

    // WordPress
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/wordpress/wp-admin",

    // Common CMS
    "/administrator/",
    "/administrator/index.php",
    "/admin/index.html",
    "/admin/home.php",
    "/admin/admin.php",
    "/admin_area/",
    "/adminarea/",
    "/bb-admin/",
    "/adminLogin/",
    "/admin_login.php",
    "/admin_login.html",
    "/adminpanel.php",
    "/adminpanel.html",

    // Management panels
    "/manager",
    "/manager/html",
    "/management",
    "/admin/manage",
    "/controlpanel",
    "/control",
    "/panel",
    "/panel/",

    // Backend paths
    "/backend",
    "/backend/",
    "/backend/admin",
    "/backoffice",
    "/back-office",

    // Login pages
    "/login",
    "/login.php",
    "/login.html",
    "/login/",
    "/signin",
    "/signin.php",
    "/sign-in",
    "/user/login",
    "/auth/login",
    "/account/login",

    // Dashboard
    "/dashboard",
    "/dashboard/",
    "/dashboard/index.php",
    "/dashboard.php",
    "/dash",

    // Database management
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/dbadmin",
    "/mysql",
    "/myadmin",
    "/phpmyadmin/index.php",
    "/adminer.php",
    "/adminer",

    // System admin
    "/system",
    "/system-admin",
    "/sysadmin",
    "/admin/sysadmin",
    "/cpanel",
    "/plesk",
    "/webadmin",
    "/serveradmin",

    // API admin
    "/api/admin",
    "/api/v1/admin",
    "/admin/api",

    // Other common paths
    "/moderator",
    "/webmaster",
    "/admin1",
    "/admin2",
    "/admin_backup",
    "/yonetim",
    "/yonetici",
    "/adm",
    "/admin_console",
    "/secret",
    "/private",
    "/console",
    "/consola",
];

/// Admin panel finding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPanelResult {
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub response_size: usize,
    pub is_likely_admin: bool,
    pub fingerprint: Vec<String>,
}

impl AdminPanelResult {
    /// Check if this looks like an admin panel based on heuristics
    fn analyze_admin_likelihood(&mut self, body: &str) {
        let mut signals = Vec::new();

        let body_lower = body.to_lowercase();
        let title_lower = self.title.as_ref().map(|t| t.to_lowercase()).unwrap_or_default();

        // Check for admin keywords in title
        let admin_title_keywords = [
            "admin", "administrator", "dashboard", "control panel", "management",
            "login", "sign in", "panel", "backend", "manager"
        ];

        for keyword in &admin_title_keywords {
            if title_lower.contains(keyword) {
                signals.push(format!("Title contains '{}'", keyword));
            }
        }

        // Check for admin keywords in body
        let admin_body_keywords = [
            "admin panel", "administration", "dashboard", "control panel",
            "username", "password", "login", "sign in", "authenticate"
        ];

        for keyword in &admin_body_keywords {
            if body_lower.contains(keyword) {
                signals.push(format!("Body contains '{}'", keyword));
            }
        }

        // Check for login forms
        if body_lower.contains("<form") &&
           (body_lower.contains("password") || body_lower.contains("type=\"password\"")) {
            signals.push("Contains login form".to_string());
        }

        // Check for common admin CSS/JS frameworks
        if body_lower.contains("bootstrap") || body_lower.contains("admin-lte") ||
           body_lower.contains("adminlte") {
            signals.push("Uses admin UI framework".to_string());
        }

        self.is_likely_admin = !signals.is_empty();
        self.fingerprint = signals;
    }
}

/// Baseline response for detecting soft 404s and catch-all pages
#[derive(Clone)]
pub struct BaselineResponse {
    pub status: u16,
    pub size: usize,
    pub content_hash: u64,
    pub title: Option<String>,
}

/// Calculate a simple hash for content comparison
fn simple_hash(content: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    // Hash a normalized version (lowercase, whitespace normalized)
    let normalized: String = content.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Test for baseline 404 response to detect false positives
/// Tests multiple random paths with different "extensions" to detect catch-all patterns
async fn get_baseline_404(domain: &str, client: &Client) -> Option<BaselineResponse> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Test multiple random paths with different extensions
    let test_extensions = ["", ".php", ".html", ".asp", ".jsp"];
    let mut responses: Vec<(u16, usize, u64, Option<String>)> = Vec::new();

    for ext in &test_extensions {
        let random_path = format!("/nonexistent{}{}{}", rng.gen::<u32>(), rng.gen::<u32>(), ext);
        let test_url = format!("http://{}{}", domain, random_path);

        if let Ok(response) = client.get(&test_url).timeout(Duration::from_secs(2)).send().await {
            let status = response.status().as_u16();
            if let Ok(body) = response.text().await {
                let hash = simple_hash(&body);
                let title = extract_title(&body);
                responses.push((status, body.len(), hash, title));
            }
        }
    }

    if responses.is_empty() {
        return None;
    }

    // Return the most common response pattern (likely the catch-all)
    let first = &responses[0];
    Some(BaselineResponse {
        status: first.0,
        size: first.1,
        content_hash: first.2,
        title: first.3.clone(),
    })
}

/// Discover admin panels for a given domain
pub async fn discover_admin_panels(
    domain: &str,
    validated_hosts: &[String],
    client: &Client,
    workers: usize,
) -> Vec<AdminPanelResult> {
    println!("{}", "[*] Starting admin panel discovery...".cyan());
    println!("{}", format!("    Checking {} ports per host", COMMON_ADMIN_PORTS.len()).cyan());
    println!("{}", format!("    Checking {} admin paths", ADMIN_PATHS.len()).cyan());

    // Get baseline 404 response for smart filtering
    let baseline_404 = get_baseline_404(domain, client).await;
    if let Some(ref baseline) = baseline_404 {
        println!("{}", format!("    Baseline 404 detection: status={}, size={} bytes", baseline.status, baseline.size).cyan());
        if let Some(ref title) = baseline.title {
            println!("{}", format!("    Baseline title: \"{}\"", title).cyan());
        }
    }

    let mut results = Vec::new();
    let mut tested_urls = HashSet::new();

    // Build list of URLs to test
    let mut urls_to_test = Vec::new();

    // Test main domain
    for port in COMMON_ADMIN_PORTS {
        for path in ADMIN_PATHS {
            // OPTIMIZATION: Use only the appropriate protocol for each port
            let scheme = if *port == 443 || *port == 8443 { "https" } else { "http" };

            let url = if *port == 80 || *port == 443 {
                format!("{}://{}{}", scheme, domain, path)
            } else {
                format!("{}://{}:{}{}", scheme, domain, port, path)
            };

            if tested_urls.insert(url.clone()) {
                urls_to_test.push(url);
            }
        }
    }

    // Test validated hosts (top 5 only to avoid too many requests)
    for host in validated_hosts.iter().take(5) {
        for port in COMMON_ADMIN_PORTS {
            for path in ADMIN_PATHS {
                // OPTIMIZATION: Use only the appropriate protocol for each port
                let scheme = if *port == 443 || *port == 8443 { "https" } else { "http" };

                let url = if *port == 80 || *port == 443 {
                    format!("{}://{}{}", scheme, host, path)
                } else {
                    format!("{}://{}:{}{}", scheme, host, port, path)
                };

                if tested_urls.insert(url.clone()) {
                    urls_to_test.push(url);
                }
            }
        }
    }

    println!("{}", format!("[*] Testing {} unique URLs...", urls_to_test.len()).cyan());

    // PERFORMANCE OPTIMIZATION: Use higher concurrency for admin panel discovery
    // Increase workers by 3x for faster scanning (with reasonable limit)
    let admin_workers = std::cmp::min(workers * 3, 100);
    if admin_workers > workers {
        println!("{}", format!("    Using {} concurrent workers for faster scanning", admin_workers).cyan());
    }

    // Process URLs in parallel batches
    use futures::stream::{self, StreamExt};

    let mut stream = stream::iter(urls_to_test)
        .map(|url| {
            let client = client.clone();
            let baseline = baseline_404.clone();
            async move {
                let (result, body_hash) = check_admin_url_with_hash(&url, &client).await;

                // Filter out results that match the baseline 404 response
                match (result, baseline) {
                    (Some(admin_result), Some(ref base)) => {
                        // If content hash matches baseline, it's definitely a catch-all
                        if let Some(hash) = body_hash {
                            if hash == base.content_hash {
                                return None;
                            }
                        }

                        // If response matches baseline (same status and similar size), it's likely a false positive
                        if admin_result.status_code == base.status &&
                           admin_result.response_size.abs_diff(base.size) < 100 {
                            return None;
                        }

                        // If title matches baseline title, likely catch-all
                        if let (Some(ref result_title), Some(ref base_title)) = (&admin_result.title, &base.title) {
                            if result_title == base_title && !result_title.is_empty() {
                                return None;
                            }
                        }

                        // If it's a 200 but with the same size as baseline, likely a catch-all
                        if admin_result.status_code == 200 &&
                           base.status == 200 &&
                           admin_result.response_size.abs_diff(base.size) < 100 {
                            return None;
                        }

                        Some(admin_result)
                    }
                    (result, _) => result,
                }
            }
        })
        .buffer_unordered(admin_workers);

    let mut checked = 0;
    let total = tested_urls.len();

    while let Some(result) = stream.next().await {
        checked += 1;

        // Show progress every 50 URLs instead of 100 for better feedback
        if checked % 50 == 0 || checked == total {
            let percentage = (checked as f64 / total as f64 * 100.0) as u32;
            println!("{}", format!("    Progress: {}/{} URLs checked ({}%)", checked, total, percentage).cyan());
        }

        if let Some(admin_result) = result {
            // Immediately show found admin panels
            if admin_result.is_likely_admin {
                println!("{}", format!("    [!] Found likely admin: {} [{}]", admin_result.url, admin_result.status_code).green().bold());
            }
            results.push(admin_result);
        }
    }

    println!("{}", format!("[+] Admin discovery complete: Found {} potential admin panels", results.len()).green());

    results
}

/// Validate that Content-Type matches expected extension
fn validate_content_type_for_extension(url: &str, content_type: &Option<String>) -> bool {
    let url_lower = url.to_lowercase();

    // Extract file extension from URL
    let extension = url_lower
        .split('?').next()
        .and_then(|path| path.rsplit('.').next())
        .unwrap_or("");

    let ct = content_type.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();

    match extension {
        // PHP, HTML, ASP, JSP should return text/html or similar
        "php" | "html" | "htm" | "asp" | "aspx" | "jsp" | "do" => {
            // Must contain text/html, application/xhtml, or similar
            // Reject if it's an image, javascript, css, or other non-HTML
            if ct.contains("image/") || ct.contains("text/css") ||
               ct.contains("application/javascript") || ct.contains("text/javascript") ||
               ct.contains("application/octet-stream") || ct.contains("font/") {
                return false;
            }
            true
        }
        // For paths without extension (like /admin), be more lenient
        "" | "admin" | "login" | "dashboard" | "panel" => true,
        _ => true,
    }
}

/// Check if body contains actual HTML content (not just error/generic page)
fn has_real_html_content(body: &str) -> bool {
    let body_lower = body.to_lowercase();

    // Must have basic HTML structure
    if !body_lower.contains("<html") && !body_lower.contains("<!doctype") {
        return false;
    }

    // Check for common "not found" patterns that indicate soft 404
    let not_found_patterns = [
        "page not found",
        "404 not found",
        "file not found",
        "not found",
        "does not exist",
        "doesn't exist",
        "cannot be found",
        "no such file",
        "the page you requested",
        "this page doesn't exist",
        "we couldn't find",
        "pagina não encontrada",
        "página não existe",
    ];

    for pattern in &not_found_patterns {
        if body_lower.contains(pattern) {
            return false;
        }
    }

    true
}

/// Check a single URL for admin panel (returns hash for comparison)
async fn check_admin_url_with_hash(url: &str, client: &Client) -> (Option<AdminPanelResult>, Option<u64>) {
    // Set timeout for request - OPTIMIZED: 1.5s for faster scanning
    let request_future = async {
        client
            .get(url)
            .timeout(Duration::from_millis(1500))
            .send()
            .await
    };

    match timeout(Duration::from_secs(2), request_future).await {
        Ok(Ok(response)) => {
            let status_code = response.status().as_u16();

            // CRITICAL FIX: Explicitly filter out 404, 403, and server errors
            // Only process 2xx (success) and 3xx (redirects)
            if status_code == 404 || status_code == 403 || !(200..500).contains(&status_code) {
                return (None, None);
            }

            let headers = response.headers().clone();
            let content_type = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let server = headers
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Validate Content-Type matches the expected file extension
            if !validate_content_type_for_extension(url, &content_type) {
                return (None, None);
            }

            // Try to get body
            match response.text().await {
                Ok(body) => {
                    let response_size = body.len();
                    let body_hash = simple_hash(&body);

                    // Skip if response is too small (likely error/redirect)
                    if response_size < 50 && status_code == 200 {
                        return (None, Some(body_hash));
                    }

                    // Skip if body doesn't have real HTML content (soft 404 detection)
                    if status_code == 200 && !has_real_html_content(&body) {
                        return (None, Some(body_hash));
                    }

                    // Extract title
                    let title = extract_title(&body);

                    let mut result = AdminPanelResult {
                        url: url.to_string(),
                        status_code,
                        title,
                        content_type,
                        server,
                        response_size,
                        is_likely_admin: false,
                        fingerprint: Vec::new(),
                    };

                    // Analyze if this looks like an admin panel (only for 200 responses)
                    if status_code == 200 {
                        result.analyze_admin_likelihood(&body);
                    }

                    // Return if likely admin OR successful response/redirect
                    if result.is_likely_admin || status_code == 200 || status_code == 301 || status_code == 302 {
                        (Some(result), Some(body_hash))
                    } else {
                        (None, Some(body_hash))
                    }
                }
                Err(_) => (None, None),
            }
        }
        _ => (None, None),
    }
}

/// Extract page title from HTML
fn extract_title(html: &str) -> Option<String> {
    use regex::Regex;

    let re = Regex::new(r"(?i)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Save admin panel results to file
pub fn save_admin_panels_to_file(results: &[AdminPanelResult], output_file: &Path) -> Result<()> {
    // Save JSON
    let json = serde_json::to_string_pretty(results)
        .context("Failed to serialize admin panel results")?;
    fs::write(output_file, json)
        .context(format!("Failed to write admin panels to {:?}", output_file))?;

    // Also save a text summary
    let txt_file = output_file.with_extension("txt");
    let mut file = File::create(&txt_file)
        .context(format!("Failed to create admin panels text file: {:?}", txt_file))?;

    writeln!(file, "=== ADMIN PANEL DISCOVERY RESULTS ===")?;
    writeln!(file, "Total panels found: {}", results.len())?;
    writeln!(file)?;

    // Group by likelihood
    let likely_admin: Vec<_> = results.iter().filter(|r| r.is_likely_admin).collect();
    let possible_admin: Vec<_> = results.iter().filter(|r| !r.is_likely_admin).collect();

    writeln!(file, "HIGH CONFIDENCE ADMIN PANELS ({}):", likely_admin.len())?;
    writeln!(file, "=")?;
    for result in likely_admin {
        writeln!(file)?;
        writeln!(file, "URL: {}", result.url)?;
        writeln!(file, "Status: {}", result.status_code)?;
        if let Some(ref title) = result.title {
            writeln!(file, "Title: {}", title)?;
        }
        if !result.fingerprint.is_empty() {
            writeln!(file, "Indicators:")?;
            for indicator in &result.fingerprint {
                writeln!(file, "  - {}", indicator)?;
            }
        }
    }

    writeln!(file)?;
    writeln!(file, "POSSIBLE ADMIN PANELS ({}):", possible_admin.len())?;
    writeln!(file, "=")?;
    for result in possible_admin {
        writeln!(file, "  [{}] {}", result.status_code, result.url)?;
        if let Some(ref title) = result.title {
            writeln!(file, "      Title: {}", title)?;
        }
    }

    Ok(())
}

/// Display admin panel summary
pub fn display_admin_panel_summary(results: &[AdminPanelResult]) {
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  ADMIN PANEL DISCOVERY SUMMARY".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    let high_confidence: Vec<_> = results.iter().filter(|r| r.is_likely_admin).collect();
    let possible: Vec<_> = results.iter().filter(|r| !r.is_likely_admin).collect();

    println!("{}", format!("Total results: {}", results.len()).cyan());
    println!("{}", format!("High confidence: {}", high_confidence.len()).green());
    println!("{}", format!("Possible panels: {}", possible.len()).yellow());
    println!();

    if !high_confidence.is_empty() {
        println!("{}", "HIGH CONFIDENCE ADMIN PANELS:".red().bold());
        for (idx, result) in high_confidence.iter().take(10).enumerate() {
            println!("{}", format!("  {}. {}", idx + 1, result.url).yellow());
            if let Some(ref title) = result.title {
                println!("{}", format!("     Title: {}", title).cyan());
            }
            println!("{}", format!("     Status: {}", result.status_code).cyan());
            if !result.fingerprint.is_empty() {
                println!("{}", "     Indicators:".cyan());
                for indicator in &result.fingerprint {
                    println!("{}", format!("       • {}", indicator).cyan());
                }
            }
            println!();
        }

        if high_confidence.len() > 10 {
            println!("{}", format!("     ... and {} more", high_confidence.len() - 10).cyan());
        }
    }

    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_panel_analysis() {
        let html = r#"
            <html>
                <title>Admin Dashboard</title>
                <body>
                    <form>
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                    </form>
                </body>
            </html>
        "#;

        let mut result = AdminPanelResult {
            url: "http://example.com/admin".to_string(),
            status_code: 200,
            title: Some("Admin Dashboard".to_string()),
            content_type: Some("text/html".to_string()),
            server: None,
            response_size: html.len(),
            is_likely_admin: false,
            fingerprint: Vec::new(),
        };

        result.analyze_admin_likelihood(html);

        assert!(result.is_likely_admin);
        assert!(!result.fingerprint.is_empty());
    }
}
