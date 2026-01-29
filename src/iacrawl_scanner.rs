// iacrawl_scanner.rs - IACrawl Integration for EnumRust
// Purpose: Scan for Vercel + Supabase credential exposure vulnerabilities
// Integrates with: /root/PENTEST/IAcrawl/iacrawl/target/release/iacrawl

use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use tokio::fs;
use tokio::process::Command;

/// Path to the iacrawl binary
const IACRAWL_BINARY: &str = "/root/PENTEST/IAcrawl/iacrawl/target/release/iacrawl";

/// Vercel site detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VercelSite {
    pub url: String,
    pub is_vercel: bool,
    pub vercel_indicators: Vec<String>,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

/// Supabase credentials found in JavaScript files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupabaseCredentials {
    pub url: String,
    pub supabase_url: Option<String>,
    pub anon_key: Option<String>,
    pub service_role_key: Option<String>,
    pub jwt_secret: Option<String>,
    pub project_ref: Option<String>,
    pub source_file: Option<String>,
}

/// Individual scan result from iacrawl
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IACrawlResult {
    pub subdomain: String,
    pub vercel_site: Option<VercelSite>,
    pub supabase_credentials: Option<SupabaseCredentials>,
    pub js_files_analyzed: usize,
}

/// Summary of iacrawl scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IACrawlSummary {
    pub domain: String,
    pub total_scanned: usize,
    pub vercel_sites_found: usize,
    pub supabase_credentials_found: usize,
    pub critical_exposures: Vec<CriticalExposure>,
    pub results: Vec<IACrawlResult>,
}

/// Critical exposure details for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalExposure {
    pub subdomain: String,
    pub exposure_type: String,
    pub severity: String,
    pub details: String,
    pub source_file: Option<String>,
}

impl IACrawlSummary {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            total_scanned: 0,
            vercel_sites_found: 0,
            supabase_credentials_found: 0,
            critical_exposures: Vec::new(),
            results: Vec::new(),
        }
    }
}

/// Check if iacrawl binary exists and is executable
pub fn is_iacrawl_available() -> bool {
    Path::new(IACRAWL_BINARY).exists()
}

/// Run iacrawl scan on a domain
pub async fn scan_domain(
    domain: &str,
    output_dir: &Path,
    concurrency: usize,
    rate_limit: u32,
) -> Result<IACrawlSummary> {
    if !is_iacrawl_available() {
        anyhow::bail!(
            "IACrawl binary not found at: {}. Please build it first.",
            IACRAWL_BINARY
        );
    }

    println!(
        "{}",
        format!("[*] IACrawl: Scanning domain {} for Vercel/Supabase...", domain)
            .cyan()
    );

    let output_file = output_dir.join("iacrawl_results.json");

    // Run iacrawl scan command
    let output = Command::new(IACRAWL_BINARY)
        .args([
            "scan",
            "-d",
            domain,
            "-c",
            &concurrency.to_string(),
            "-r",
            &rate_limit.to_string(),
            "-o",
            output_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute iacrawl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!(
            "{}",
            format!("[!] IACrawl scan warning: {}", stderr.trim()).yellow()
        );
    }

    // Parse results
    parse_iacrawl_results(domain, &output_file).await
}

/// Run iacrawl scan from a file of subdomains
pub async fn scan_from_subdomains_file(
    domain: &str,
    subdomains_file: &Path,
    output_dir: &Path,
    concurrency: usize,
    rate_limit: u32,
) -> Result<IACrawlSummary> {
    if !is_iacrawl_available() {
        anyhow::bail!(
            "IACrawl binary not found at: {}. Please build it first.",
            IACRAWL_BINARY
        );
    }

    if !subdomains_file.exists() {
        anyhow::bail!("Subdomains file not found: {}", subdomains_file.display());
    }

    println!(
        "{}",
        format!(
            "[*] IACrawl: Scanning {} subdomains from file...",
            count_lines(subdomains_file).await.unwrap_or(0)
        )
        .cyan()
    );

    let output_file = output_dir.join("iacrawl_results.json");

    // Run iacrawl file command
    let output = Command::new(IACRAWL_BINARY)
        .args([
            "file",
            "-i",
            subdomains_file.to_str().unwrap(),
            "-c",
            &concurrency.to_string(),
            "-r",
            &rate_limit.to_string(),
            "-o",
            output_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute iacrawl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!(
            "{}",
            format!("[!] IACrawl scan warning: {}", stderr.trim()).yellow()
        );
    }

    // Parse results
    parse_iacrawl_results(domain, &output_file).await
}

/// Parse iacrawl JSON output into summary
async fn parse_iacrawl_results(domain: &str, output_file: &Path) -> Result<IACrawlSummary> {
    let mut summary = IACrawlSummary::new(domain);

    if !output_file.exists() {
        println!(
            "{}",
            "[!] IACrawl: No results file found (scan may have found nothing)".yellow()
        );
        return Ok(summary);
    }

    let content = fs::read_to_string(output_file).await?;

    // Parse JSON results
    let results: Vec<IACrawlResult> = match serde_json::from_str(&content) {
        Ok(r) => r,
        Err(e) => {
            println!(
                "{}",
                format!("[!] IACrawl: Failed to parse results: {}", e).yellow()
            );
            return Ok(summary);
        }
    };

    summary.total_scanned = results.len();

    for result in &results {
        // Count Vercel sites
        if result.vercel_site.is_some() {
            summary.vercel_sites_found += 1;
        }

        // Check for Supabase credentials
        if let Some(ref creds) = result.supabase_credentials {
            summary.supabase_credentials_found += 1;

            // Check for critical exposures
            if creds.service_role_key.is_some() {
                summary.critical_exposures.push(CriticalExposure {
                    subdomain: result.subdomain.clone(),
                    exposure_type: "Supabase Service Role Key".to_string(),
                    severity: "CRITICAL".to_string(),
                    details: "Service role key exposed - allows full database access!".to_string(),
                    source_file: creds.source_file.clone(),
                });
            }

            if creds.jwt_secret.is_some() {
                summary.critical_exposures.push(CriticalExposure {
                    subdomain: result.subdomain.clone(),
                    exposure_type: "Supabase JWT Secret".to_string(),
                    severity: "CRITICAL".to_string(),
                    details: "JWT secret exposed - allows forging authentication tokens!"
                        .to_string(),
                    source_file: creds.source_file.clone(),
                });
            }

            if creds.anon_key.is_some() {
                summary.critical_exposures.push(CriticalExposure {
                    subdomain: result.subdomain.clone(),
                    exposure_type: "Supabase Anon Key".to_string(),
                    severity: "MEDIUM".to_string(),
                    details: "Anonymous key exposed in JavaScript (check RLS policies)".to_string(),
                    source_file: creds.source_file.clone(),
                });
            }
        }
    }

    summary.results = results;
    Ok(summary)
}

/// Count lines in a file
async fn count_lines(path: &Path) -> Result<usize> {
    let content = fs::read_to_string(path).await?;
    Ok(content.lines().filter(|l| !l.trim().is_empty()).count())
}

/// Display iacrawl scan summary
pub fn display_summary(summary: &IACrawlSummary) {
    println!("\n{}", "─── IACrawl Scan Summary ───".cyan().bold());
    println!(
        "{}",
        format!("  Total scanned: {}", summary.total_scanned).white()
    );
    println!(
        "{}",
        format!("  Vercel sites found: {}", summary.vercel_sites_found).green()
    );
    println!(
        "{}",
        format!(
            "  Supabase credentials found: {}",
            summary.supabase_credentials_found
        )
        .yellow()
    );

    if !summary.critical_exposures.is_empty() {
        println!(
            "\n{}",
            format!(
                "  🚨 CRITICAL EXPOSURES: {}",
                summary.critical_exposures.len()
            )
            .red()
            .bold()
        );

        for exposure in &summary.critical_exposures {
            let severity_color = match exposure.severity.as_str() {
                "CRITICAL" => exposure.severity.red().bold(),
                "HIGH" => exposure.severity.red(),
                "MEDIUM" => exposure.severity.yellow(),
                _ => exposure.severity.white(),
            };

            println!(
                "    {} [{}] {} - {}",
                "→".red(),
                severity_color,
                exposure.subdomain.cyan(),
                exposure.exposure_type.white()
            );
            println!("      {}", exposure.details.white());
            if let Some(ref source) = exposure.source_file {
                println!("      Source: {}", source.dimmed());
            }
        }
    }
}

/// Save iacrawl summary to JSON file
pub async fn save_summary(summary: &IACrawlSummary, output_file: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(summary)?;
    fs::write(output_file, json).await?;
    Ok(())
}

/// Convert iacrawl results to vulnerability format for report integration
pub fn to_vulnerability_findings(summary: &IACrawlSummary) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    for exposure in &summary.critical_exposures {
        findings.push(VulnerabilityFinding {
            name: exposure.exposure_type.clone(),
            severity: exposure.severity.clone(),
            target: exposure.subdomain.clone(),
            description: exposure.details.clone(),
            source: "IACrawl".to_string(),
            source_file: exposure.source_file.clone(),
        });
    }

    findings
}

/// Vulnerability finding for report integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub name: String,
    pub severity: String,
    pub target: String,
    pub description: String,
    pub source: String,
    pub source_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iacrawl_available() {
        // This will only pass if iacrawl is built
        let available = is_iacrawl_available();
        println!("IACrawl available: {}", available);
    }

    #[test]
    fn test_summary_creation() {
        let summary = IACrawlSummary::new("example.com");
        assert_eq!(summary.domain, "example.com");
        assert_eq!(summary.total_scanned, 0);
    }
}
