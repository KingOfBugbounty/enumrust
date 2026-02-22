// wpscan.rs - WordPress Security Scanner Integration
// Purpose: Detect WordPress sites and run WPScan for deep vulnerability analysis
// Detects WordPress from admin panels and HTTP200 URLs, parses WPScan JSON output

use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

// ═══════════════════════════════════════════════════════════════════
// STRUCTS
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPScanResults {
    pub target_url: String,
    pub wordpress_version: Option<WordPressVersion>,
    pub plugins: Vec<WPPlugin>,
    pub themes: Vec<WPTheme>,
    pub users: Vec<WPUser>,
    pub vulnerabilities: Vec<WPVulnerability>,
    pub interesting_findings: Vec<WPInterestingFinding>,
    pub total_vulnerabilities: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPressVersion {
    pub number: String,
    pub status: String, // "insecure", "latest", "outdated"
    pub vulnerabilities: Vec<WPVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPPlugin {
    pub slug: String,
    pub version: Option<String>,
    pub outdated: bool,
    pub vulnerabilities: Vec<WPVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPTheme {
    pub slug: String,
    pub version: Option<String>,
    pub outdated: bool,
    pub vulnerabilities: Vec<WPVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPUser {
    pub id: u64,
    pub login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPVulnerability {
    pub title: String,
    pub vuln_type: String,
    pub severity: String, // "critical", "high", "medium", "low", "info"
    pub cve: Option<String>,
    pub fixed_in: Option<String>,
    pub component: String, // "core", plugin slug, theme slug
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WPInterestingFinding {
    pub url: String,
    pub finding_type: String,
    pub description: String,
}

// ═══════════════════════════════════════════════════════════════════
// DETECTION
// ═══════════════════════════════════════════════════════════════════

/// Detect WordPress sites from admin panels and HTTP 200 URLs
pub fn detect_wordpress(
    admin_panels: &[crate::admin_finder::AdminPanelResult],
    http200_urls: &[String],
) -> Vec<String> {
    let mut wp_targets = Vec::new();

    // Check admin panels for WordPress indicators
    for panel in admin_panels {
        let url_lower = panel.url.to_lowercase();
        if url_lower.contains("/wp-admin")
            || url_lower.contains("/wp-login.php")
            || url_lower.contains("/wp-login")
        {
            // Extract base URL (remove /wp-admin or /wp-login.php path)
            if let Some(base) = extract_wp_base_url(&panel.url) {
                if !wp_targets.contains(&base) {
                    wp_targets.push(base);
                }
            }
        }

        // Check fingerprints for WordPress
        for fp in &panel.fingerprint {
            let fp_lower = fp.to_lowercase();
            if fp_lower.contains("wordpress") || fp_lower.contains("wp-") {
                if let Some(base) = extract_wp_base_url(&panel.url) {
                    if !wp_targets.contains(&base) {
                        wp_targets.push(base);
                    }
                }
            }
        }
    }

    // Check HTTP 200 URLs for WordPress indicators
    for url in http200_urls {
        let url_lower = url.to_lowercase();
        if url_lower.contains("/wp-content/")
            || url_lower.contains("/wp-includes/")
            || url_lower.contains("/wp-json/")
            || url_lower.contains("/wp-admin")
            || url_lower.contains("/wp-login.php")
        {
            if let Some(base) = extract_wp_base_url(url) {
                if !wp_targets.contains(&base) {
                    wp_targets.push(base);
                }
            }
        }
    }

    wp_targets
}

/// Extract the base WordPress URL from a URL containing wp-admin, wp-content, etc.
fn extract_wp_base_url(url: &str) -> Option<String> {
    // Find the WordPress path markers and extract base URL
    let markers = [
        "/wp-admin",
        "/wp-login.php",
        "/wp-login",
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/",
    ];

    for marker in &markers {
        if let Some(idx) = url.to_lowercase().find(&marker.to_lowercase()) {
            let base = &url[..idx];
            // Ensure it has a scheme
            if base.starts_with("http://") || base.starts_with("https://") {
                return Some(base.trim_end_matches('/').to_string());
            }
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════
// DOCKER HELPERS
// ═══════════════════════════════════════════════════════════════════

/// Check if Docker is installed and the daemon is running
pub async fn check_docker_available() -> bool {
    // Check if docker binary exists
    let which = Command::new("which")
        .arg("docker")
        .output()
        .await;
    if which.is_err() || !which.unwrap().status.success() {
        return false;
    }

    // Check if Docker daemon is running
    let info = Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    matches!(info, Ok(status) if status.success())
}

/// Ensure Docker is available and the wpscanteam/wpscan image is pulled
pub async fn ensure_wpscan_docker() -> Result<bool> {
    if !check_docker_available().await {
        println!("{}", "[!] Docker not available for WPScan".yellow());
        return Ok(false);
    }

    // Check if wpscanteam/wpscan image exists locally
    let images = Command::new("docker")
        .arg("images")
        .arg("-q")
        .arg("wpscanteam/wpscan")
        .output()
        .await?;

    let output = String::from_utf8_lossy(&images.stdout);
    if output.trim().is_empty() {
        println!("{}", "[*] Pulling wpscanteam/wpscan Docker image...".cyan());
        let pull = Command::new("docker")
            .arg("pull")
            .arg("wpscanteam/wpscan")
            .status()
            .await?;

        if !pull.success() {
            println!("{}", "[!] Failed to pull wpscanteam/wpscan image".yellow());
            return Ok(false);
        }
        println!("{}", "[+] wpscanteam/wpscan image pulled successfully".green());
    }

    Ok(true)
}

// ═══════════════════════════════════════════════════════════════════
// EXECUTION
// ═══════════════════════════════════════════════════════════════════

/// Run WPScan against a WordPress target via Docker
pub async fn run_wpscan(
    target_url: &str,
    output_dir: &Path,
    api_token: Option<&str>,
    idx: usize,
) -> Result<WPScanResults> {
    let output_file = output_dir.join(format!("wpscan_raw_{}.json", idx));
    let container_output = format!("/output/wpscan_raw_{}.json", idx);

    // Canonicalize output_dir for Docker volume mount
    let abs_output_dir = std::fs::canonicalize(output_dir)
        .unwrap_or_else(|_| output_dir.to_path_buf());

    let mut cmd = Command::new("docker");
    cmd.arg("run").arg("--rm")
        .arg("-v").arg(format!("{}:/output", abs_output_dir.display()))
        .arg("wpscanteam/wpscan")
        .arg("--url").arg(target_url)
        .arg("--format").arg("json")
        .arg("-o").arg(&container_output)
        .arg("--enumerate").arg("vp,vt,u,cb,dbe")
        .arg("--plugins-detection").arg("mixed")
        .arg("--no-banner")
        .arg("--random-user-agent")
        .arg("--disable-tls-checks");

    if let Some(token) = api_token {
        if !token.is_empty() {
            cmd.arg("--api-token").arg(token);
        }
    }

    // Run with 5 minute timeout
    let result = tokio::time::timeout(
        Duration::from_secs(300),
        cmd.output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // WPScan may exit non-zero but still produce valid JSON output
                if !output_file.exists() {
                    return Err(anyhow::anyhow!(
                        "WPScan failed for {}: {}",
                        target_url,
                        stderr.lines().take(3).collect::<Vec<_>>().join(" | ")
                    ));
                }
            }

            // Read and parse the JSON output
            if output_file.exists() {
                let raw_json = std::fs::read_to_string(&output_file)?;
                parse_wpscan_json(&raw_json, target_url)
            } else {
                Err(anyhow::anyhow!("WPScan produced no output for {}", target_url))
            }
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("Failed to execute wpscan via Docker: {}", e)),
        Err(_) => Err(anyhow::anyhow!("WPScan timed out after 5 minutes for {}", target_url)),
    }
}

// ═══════════════════════════════════════════════════════════════════
// PARSING
// ═══════════════════════════════════════════════════════════════════

/// Parse WPScan JSON output into structured results
pub fn parse_wpscan_json(raw_json: &str, target_url: &str) -> Result<WPScanResults> {
    let json: serde_json::Value = serde_json::from_str(raw_json)?;

    // Parse WordPress version
    let wordpress_version = parse_wp_version(&json);

    // Parse plugins (map format: {"slug": {...}})
    let plugins = parse_wp_plugins(&json);

    // Parse themes (map format: {"slug": {...}})
    let themes = parse_wp_themes(&json);

    // Parse users (map format: {"id": {...}})
    let users = parse_wp_users(&json);

    // Parse interesting findings
    let interesting_findings = parse_interesting_findings(&json);

    // Collect all vulnerabilities
    let mut all_vulns = Vec::new();
    if let Some(ref ver) = wordpress_version {
        all_vulns.extend(ver.vulnerabilities.clone());
    }
    for plugin in &plugins {
        all_vulns.extend(plugin.vulnerabilities.clone());
    }
    for theme in &themes {
        all_vulns.extend(theme.vulnerabilities.clone());
    }

    let total_vulnerabilities = all_vulns.len();

    Ok(WPScanResults {
        target_url: target_url.to_string(),
        wordpress_version,
        plugins,
        themes,
        users,
        vulnerabilities: all_vulns,
        interesting_findings,
        total_vulnerabilities,
    })
}

fn parse_wp_version(json: &serde_json::Value) -> Option<WordPressVersion> {
    let version_obj = json.get("version")?;
    let number = version_obj.get("number")?.as_str()?.to_string();
    let status = version_obj
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();

    let vulnerabilities = parse_vulns_array(
        version_obj.get("vulnerabilities"),
        "core",
    );

    Some(WordPressVersion {
        number,
        status,
        vulnerabilities,
    })
}

fn parse_wp_plugins(json: &serde_json::Value) -> Vec<WPPlugin> {
    let mut plugins = Vec::new();

    if let Some(plugins_obj) = json.get("plugins").and_then(|p| p.as_object()) {
        for (slug, plugin_data) in plugins_obj {
            let version = plugin_data
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let outdated = plugin_data
                .get("outdated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let vulnerabilities = parse_vulns_array(
                plugin_data.get("vulnerabilities"),
                slug,
            );

            plugins.push(WPPlugin {
                slug: slug.clone(),
                version,
                outdated,
                vulnerabilities,
            });
        }
    }

    plugins
}

fn parse_wp_themes(json: &serde_json::Value) -> Vec<WPTheme> {
    let mut themes = Vec::new();

    if let Some(themes_obj) = json.get("main_theme").and_then(|t| t.as_object()) {
        // Main theme is a single object, not a map
        let slug = themes_obj
            .get("slug")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string();
        let version = themes_obj
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let outdated = themes_obj
            .get("outdated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let vulnerabilities = parse_vulns_array(
            themes_obj.get("vulnerabilities").map(|v| &*v),
            &slug,
        );
        themes.push(WPTheme {
            slug,
            version,
            outdated,
            vulnerabilities,
        });
    }

    // Also check "themes" map if present
    if let Some(themes_obj) = json.get("themes").and_then(|t| t.as_object()) {
        for (slug, theme_data) in themes_obj {
            let version = theme_data
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let outdated = theme_data
                .get("outdated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let vulnerabilities = parse_vulns_array(
                theme_data.get("vulnerabilities"),
                slug,
            );
            // Avoid duplicates
            if !themes.iter().any(|t| t.slug == *slug) {
                themes.push(WPTheme {
                    slug: slug.clone(),
                    version,
                    outdated,
                    vulnerabilities,
                });
            }
        }
    }

    themes
}

fn parse_wp_users(json: &serde_json::Value) -> Vec<WPUser> {
    let mut users = Vec::new();

    if let Some(users_obj) = json.get("users").and_then(|u| u.as_object()) {
        for (login, _user_data) in users_obj {
            // WPScan users map: {"username": {"id": N, ...}}
            let id = _user_data
                .get("id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            users.push(WPUser {
                id,
                login: login.clone(),
            });
        }
    }

    users
}

fn parse_interesting_findings(json: &serde_json::Value) -> Vec<WPInterestingFinding> {
    let mut findings = Vec::new();

    if let Some(arr) = json.get("interesting_findings").and_then(|f| f.as_array()) {
        for finding in arr {
            let url = finding
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let finding_type = finding
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_string();
            let description = finding
                .get("to_s")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();

            if !url.is_empty() {
                findings.push(WPInterestingFinding {
                    url,
                    finding_type,
                    description,
                });
            }
        }
    }

    findings
}

fn parse_vulns_array(
    vulns_value: Option<&serde_json::Value>,
    component: &str,
) -> Vec<WPVulnerability> {
    let mut vulns = Vec::new();

    if let Some(arr) = vulns_value.and_then(|v| v.as_array()) {
        for vuln in arr {
            let title = vuln
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let vuln_type = vuln
                .get("vuln_type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown")
                .to_string();

            // WPScan uses "cvss" or infer severity from vuln_type
            let severity = infer_severity(&title, &vuln_type, vuln);

            let cve = vuln
                .get("references")
                .and_then(|r| r.get("cve"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(|s| format!("CVE-{}", s));

            let fixed_in = vuln
                .get("fixed_in")
                .and_then(|f| f.as_str())
                .map(|s| s.to_string());

            vulns.push(WPVulnerability {
                title,
                vuln_type,
                severity,
                cve,
                fixed_in,
                component: component.to_string(),
            });
        }
    }

    vulns
}

fn infer_severity(
    title: &str,
    vuln_type: &str,
    vuln: &serde_json::Value,
) -> String {
    // Check if CVSS score is available
    if let Some(cvss) = vuln.get("cvss").and_then(|c| c.get("score")).and_then(|s| s.as_f64()) {
        return if cvss >= 9.0 {
            "critical".to_string()
        } else if cvss >= 7.0 {
            "high".to_string()
        } else if cvss >= 4.0 {
            "medium".to_string()
        } else {
            "low".to_string()
        };
    }

    // Infer from vuln type and title
    let title_lower = title.to_lowercase();
    let type_lower = vuln_type.to_lowercase();

    if type_lower.contains("rce")
        || title_lower.contains("remote code execution")
        || title_lower.contains("sql injection")
        || title_lower.contains("sqli")
        || type_lower.contains("sqli")
    {
        "critical".to_string()
    } else if type_lower.contains("lfi")
        || type_lower.contains("rfi")
        || title_lower.contains("file inclusion")
        || title_lower.contains("arbitrary file")
        || title_lower.contains("authentication bypass")
        || title_lower.contains("privilege escalation")
    {
        "high".to_string()
    } else if type_lower.contains("xss")
        || title_lower.contains("cross-site scripting")
        || type_lower.contains("csrf")
        || title_lower.contains("cross-site request")
        || title_lower.contains("ssrf")
    {
        "medium".to_string()
    } else {
        "low".to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════
// DISPLAY
// ═══════════════════════════════════════════════════════════════════

/// Display WPScan summary with colored output
pub fn display_wpscan_summary(results: &WPScanResults) {
    println!(
        "\n{}",
        format!("  [WordPress] {}", results.target_url).cyan().bold()
    );

    // WordPress version
    if let Some(ref ver) = results.wordpress_version {
        let status_color = match ver.status.as_str() {
            "insecure" => format!("{}", ver.status.to_uppercase().red().bold()),
            "outdated" => format!("{}", ver.status.to_uppercase().yellow()),
            "latest" => format!("{}", ver.status.to_uppercase().green()),
            _ => ver.status.clone(),
        };
        println!(
            "  {}  WordPress {} ({})",
            "[-]".cyan(),
            ver.number,
            status_color
        );
        if !ver.vulnerabilities.is_empty() {
            println!(
                "  {}  Core vulnerabilities: {}",
                "[!]".red(),
                format!("{}", ver.vulnerabilities.len()).red().bold()
            );
        }
    }

    // Plugins
    let vuln_plugins: Vec<_> = results
        .plugins
        .iter()
        .filter(|p| !p.vulnerabilities.is_empty())
        .collect();
    if !vuln_plugins.is_empty() {
        println!(
            "  {}  Vulnerable plugins: {}",
            "[!]".red(),
            format!("{}", vuln_plugins.len()).red().bold()
        );
        for plugin in &vuln_plugins {
            let ver_str = plugin
                .version
                .as_deref()
                .unwrap_or("unknown");
            let cves: Vec<String> = plugin
                .vulnerabilities
                .iter()
                .filter_map(|v| v.cve.clone())
                .collect();
            let cve_str = if cves.is_empty() {
                String::new()
            } else {
                format!(" [{}]", cves.join(", "))
            };
            println!(
                "      {} {} v{} - {} vuln(s){}",
                "->".yellow(),
                plugin.slug.yellow(),
                ver_str,
                plugin.vulnerabilities.len(),
                cve_str.red()
            );
        }
    }
    if !results.plugins.is_empty() {
        let outdated = results.plugins.iter().filter(|p| p.outdated).count();
        if outdated > 0 {
            println!(
                "  {}  Outdated plugins: {}",
                "[*]".yellow(),
                outdated
            );
        }
    }

    // Themes
    let vuln_themes: Vec<_> = results
        .themes
        .iter()
        .filter(|t| !t.vulnerabilities.is_empty())
        .collect();
    if !vuln_themes.is_empty() {
        println!(
            "  {}  Vulnerable themes: {}",
            "[!]".red(),
            format!("{}", vuln_themes.len()).red().bold()
        );
    }

    // Users
    if !results.users.is_empty() {
        println!(
            "  {}  Users enumerated: {} ({})",
            "[+]".green(),
            results.users.len(),
            results
                .users
                .iter()
                .map(|u| u.login.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Total vulnerabilities
    if results.total_vulnerabilities > 0 {
        let critical_count = results
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == "critical")
            .count();
        let high_count = results
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == "high")
            .count();

        println!(
            "  {}  Total vulnerabilities: {} (Critical: {}, High: {})",
            "[!]".red().bold(),
            format!("{}", results.total_vulnerabilities).red().bold(),
            format!("{}", critical_count).red(),
            format!("{}", high_count).yellow()
        );
    } else {
        println!(
            "  {}  No known vulnerabilities found",
            "[*]".green()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// SAVE
// ═══════════════════════════════════════════════════════════════════

/// Save WPScan results to JSON file
pub fn save_wpscan_results(results: &[WPScanResults], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    Ok(())
}
