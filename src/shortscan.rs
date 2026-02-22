// shortscan.rs - IIS Short Filename Scanner Integration
// Purpose: Detect IIS servers and run shortscan for 8.3 short filename bruteforce
// Exploits the Windows tilde (~) vulnerability to discover hidden files/directories

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
pub struct ShortscanResult {
    pub target_url: String,
    pub findings: Vec<ShortscanFinding>,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortscanFinding {
    pub shortname: String,
    pub fullname: Option<String>,
    pub finding_type: String, // "file" or "dir"
}

// ═══════════════════════════════════════════════════════════════════
// DETECTION
// ═══════════════════════════════════════════════════════════════════

/// Detect IIS servers by checking Server header of HTTP 200 URLs
pub async fn detect_iis_servers(http200_urls: &[String]) -> Vec<String> {
    let mut iis_targets = Vec::new();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .unwrap_or_default();

    // Check a reasonable sample of URLs
    let max_check = http200_urls.len().min(100);
    for url in http200_urls.iter().take(max_check) {
        match client.head(url).send().await {
            Ok(resp) => {
                if let Some(server) = resp.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        let server_lower = server_str.to_lowercase();
                        if server_lower.contains("microsoft-iis") || server_lower.contains("iis") {
                            // Extract base URL (scheme + host)
                            if let Some(base) = extract_base_url(url) {
                                if !iis_targets.contains(&base) {
                                    iis_targets.push(base);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    iis_targets
}

/// Extract scheme + host from a URL
fn extract_base_url(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")))
        .filter(|u| !u.ends_with("://"))
}

// ═══════════════════════════════════════════════════════════════════
// EXECUTION
// ═══════════════════════════════════════════════════════════════════

/// Run shortscan against an IIS target
pub async fn run_shortscan(
    target: &str,
    output_dir: &Path,
    idx: usize,
) -> Result<ShortscanResult> {
    let output_file = output_dir.join(format!("shortscan_raw_{}.json", idx));

    // Find shortscan binary
    let shortscan_bin = crate::discover_tool_path("shortscan")
        .unwrap_or_else(|| std::path::PathBuf::from("shortscan"));

    let result = tokio::time::timeout(
        Duration::from_secs(180),
        Command::new(&shortscan_bin)
            .arg(target)
            .arg("-o")
            .arg("json")
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Save raw output
            let _ = std::fs::write(&output_file, stdout.as_ref());

            if stdout.trim().is_empty() {
                return Ok(ShortscanResult {
                    target_url: target.to_string(),
                    findings: Vec::new(),
                    total_findings: 0,
                });
            }

            parse_shortscan_output(&stdout, target)
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("Failed to execute shortscan: {}", e)),
        Err(_) => Err(anyhow::anyhow!("Shortscan timed out after 3 minutes for {}", target)),
    }
}

// ═══════════════════════════════════════════════════════════════════
// PARSING
// ═══════════════════════════════════════════════════════════════════

/// Parse shortscan JSON output into structured results
fn parse_shortscan_output(raw: &str, target: &str) -> Result<ShortscanResult> {
    // shortscan JSON output is an object with a "results" array
    let json: serde_json::Value = serde_json::from_str(raw)
        .unwrap_or_else(|_| serde_json::Value::Null);

    let mut findings = Vec::new();

    // Try parsing as array of results or object with results key
    let results_arr = json.get("results")
        .and_then(|r| r.as_array())
        .or_else(|| json.as_array());

    if let Some(arr) = results_arr {
        for item in arr {
            let shortname = item.get("shortname")
                .or_else(|| item.get("name"))
                .or_else(|| item.get("short"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();

            if shortname.is_empty() {
                continue;
            }

            let fullname = item.get("fullname")
                .or_else(|| item.get("full"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            let finding_type = item.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("file")
                .to_string();

            findings.push(ShortscanFinding {
                shortname,
                fullname,
                finding_type,
            });
        }
    }

    let total_findings = findings.len();
    Ok(ShortscanResult {
        target_url: target.to_string(),
        findings,
        total_findings,
    })
}

// ═══════════════════════════════════════════════════════════════════
// DISPLAY
// ═══════════════════════════════════════════════════════════════════

/// Display shortscan results with colored output
pub fn display_shortscan_summary(results: &ShortscanResult) {
    println!(
        "\n{}",
        format!("  [IIS 8.3] {}", results.target_url).cyan().bold()
    );

    if results.findings.is_empty() {
        println!(
            "  {}  No short filenames discovered",
            "[*]".green()
        );
        return;
    }

    println!(
        "  {}  Discovered {} short filename(s)",
        "[!]".red(),
        format!("{}", results.total_findings).red().bold()
    );

    for finding in &results.findings {
        let type_icon = if finding.finding_type == "dir" { "DIR " } else { "FILE" };
        let fullname_str = finding.fullname.as_deref().unwrap_or("???");
        println!(
            "      {} [{}] {} -> {}",
            "->".yellow(),
            type_icon.cyan(),
            finding.shortname.yellow(),
            fullname_str.white()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// SAVE
// ═══════════════════════════════════════════════════════════════════

/// Save shortscan results to JSON file
pub fn save_shortscan_results(results: &[ShortscanResult], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    Ok(())
}
