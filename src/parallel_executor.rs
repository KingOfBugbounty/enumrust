#![allow(dead_code)]
// parallel_executor.rs - Optimized Parallel Execution with Rate Limiting
// Purpose: Accelerate Nuclei and Cloud scanning with controlled parallelism
// Author: EnumRust v2.3.0

use anyhow::Result;
use colored::*;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::sleep;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct ParallelConfig {
    /// Number of parallel Nuclei instances
    pub nuclei_workers: usize,
    /// Targets per Nuclei batch
    pub nuclei_batch_size: usize,
    /// Nuclei concurrency per instance (-c flag)
    pub nuclei_concurrency: usize,
    /// Rate limit (requests per second, 0 = unlimited)
    pub rate_limit: usize,
    /// Delay between batches in milliseconds
    pub batch_delay_ms: u64,
    /// Cloud scanning workers
    pub cloud_workers: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Bulk size for nuclei requests
    pub nuclei_bulk_size: usize,
    /// Headless bulk size
    pub nuclei_headless_bulk: usize,
    /// Max retries (0 = no retries for speed)
    pub nuclei_retries: usize,
    /// Max host errors before skipping
    pub nuclei_max_host_errors: usize,
    /// Response size limit in bytes (0 = no limit)
    pub nuclei_response_size_limit: usize,
    /// Enable turbo mode (maximum speed settings)
    pub turbo_mode: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            nuclei_workers: 4,
            nuclei_batch_size: 50,
            nuclei_concurrency: 50,
            rate_limit: 150,
            batch_delay_ms: 100,
            cloud_workers: 20,
            timeout_secs: 30,
            nuclei_bulk_size: 25,
            nuclei_headless_bulk: 10,
            nuclei_retries: 1,
            nuclei_max_host_errors: 30,
            nuclei_response_size_limit: 0,
            turbo_mode: false,
        }
    }
}

impl ParallelConfig {
    /// Create aggressive config for faster scanning
    pub fn aggressive() -> Self {
        Self {
            nuclei_workers: 8,
            nuclei_batch_size: 100,
            nuclei_concurrency: 100,
            rate_limit: 500,
            batch_delay_ms: 50,
            cloud_workers: 50,
            timeout_secs: 15,
            nuclei_bulk_size: 50,
            nuclei_headless_bulk: 25,
            nuclei_retries: 0,
            nuclei_max_host_errors: 50,
            nuclei_response_size_limit: 1024 * 1024, // 1MB limit
            turbo_mode: false,
        }
    }

    /// Create TURBO config for MAXIMUM speed (use with caution)
    pub fn turbo() -> Self {
        Self {
            nuclei_workers: 16,              // Maximum parallel instances
            nuclei_batch_size: 200,          // Large batches
            nuclei_concurrency: 200,         // High concurrency per instance
            rate_limit: 0,                   // NO rate limiting
            batch_delay_ms: 0,               // NO delay between batches
            cloud_workers: 100,              // Maximum cloud workers
            timeout_secs: 10,                // Short timeout
            nuclei_bulk_size: 100,           // Large bulk size
            nuclei_headless_bulk: 50,        // Large headless bulk
            nuclei_retries: 0,               // NO retries
            nuclei_max_host_errors: 100,     // High error tolerance
            nuclei_response_size_limit: 512 * 1024, // 512KB limit for speed
            turbo_mode: true,
        }
    }

    /// Create respectful config with rate limiting
    pub fn respectful() -> Self {
        Self {
            nuclei_workers: 2,
            nuclei_batch_size: 25,
            nuclei_concurrency: 25,
            rate_limit: 50,
            batch_delay_ms: 200,
            cloud_workers: 10,
            timeout_secs: 45,
            nuclei_bulk_size: 10,
            nuclei_headless_bulk: 5,
            nuclei_retries: 2,
            nuclei_max_host_errors: 10,
            nuclei_response_size_limit: 0,
            turbo_mode: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PARALLEL NUCLEI EXECUTOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct ParallelNucleiExecutor {
    config: ParallelConfig,
    semaphore: Arc<Semaphore>,
    completed: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
}

impl ParallelNucleiExecutor {
    pub fn new(config: ParallelConfig) -> Self {
        let workers = config.nuclei_workers;
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(workers)),
            completed: Arc::new(AtomicUsize::new(0)),
            total: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Execute Nuclei scan with parallel batching
    pub async fn execute_parallel(
        &self,
        targets: Vec<String>,
        output_dir: &Path,
        severities: &str,
    ) -> Result<usize> {
        if targets.is_empty() {
            return Ok(0);
        }

        let total_targets = targets.len();
        self.total.store(total_targets, Ordering::SeqCst);

        let mode_indicator = if self.config.turbo_mode {
            "🔥 TURBO MODE".red().bold().to_string()
        } else if self.config.rate_limit == 0 {
            "⚡ AGGRESSIVE".yellow().bold().to_string()
        } else {
            "🎯 STANDARD".cyan().to_string()
        };

        println!("{}", format!(
            "┌───────────────────────────────────────────────────────────────────────────────┐"
        ).cyan().bold());
        if self.config.turbo_mode {
            println!("{}", format!(
                "│  🔥 PARALLEL NUCLEI EXECUTOR - TURBO MODE                                     │"
            ).red().bold());
        } else {
            println!("{}", format!(
                "│  🚀 PARALLEL NUCLEI EXECUTOR                                                  │"
            ).cyan().bold());
        }
        println!("{}", format!(
            "├───────────────────────────────────────────────────────────────────────────────┤"
        ).cyan());
        println!("{}", format!(
            "│  📊 Total targets: {:<58}│", total_targets
        ).cyan());
        println!("{}", format!(
            "│  👷 Workers: {:<64}│", self.config.nuclei_workers
        ).cyan());
        println!("{}", format!(
            "│  📦 Batch size: {:<61}│", self.config.nuclei_batch_size
        ).cyan());
        println!("{}", format!(
            "│  ⚡ Concurrency per worker: {:<50}│", self.config.nuclei_concurrency
        ).cyan());
        println!("{}", format!(
            "│  📤 Bulk size: {:<62}│", self.config.nuclei_bulk_size
        ).cyan());
        println!("{}", format!(
            "│  🎚️  Rate limit: {}/s{:<53}│",
            if self.config.rate_limit == 0 { "UNLIMITED".to_string() } else { self.config.rate_limit.to_string() },
            ""
        ).cyan());
        println!("{}", format!(
            "│  ⏱️  Timeout: {}s | Retries: {} | Max errors: {}{:<30}│",
            self.config.timeout_secs, self.config.nuclei_retries, self.config.nuclei_max_host_errors, ""
        ).cyan());
        if self.config.turbo_mode {
            println!("{}", format!(
                "│  🔥 TURBO: No-probe, Template-spray, Silent-stats ENABLED                     │"
            ).red().bold());
        }
        println!("{}", format!(
            "└───────────────────────────────────────────────────────────────────────────────┘"
        ).cyan().bold());
        println!();

        // Split targets into batches
        let batches: Vec<Vec<String>> = targets
            .chunks(self.config.nuclei_batch_size)
            .map(|c| c.to_vec())
            .collect();

        let num_batches = batches.len();
        println!("{}", format!("   📦 Split into {} batches", num_batches).yellow());

        // Create temp files for each batch
        let temp_dir = output_dir.join("nuclei_batches");
        std::fs::create_dir_all(&temp_dir)?;

        // Spawn parallel batch executions
        let mut handles = Vec::new();
        let output_dir = output_dir.to_path_buf();
        let severities = severities.to_string();

        for (batch_idx, batch) in batches.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let completed = Arc::clone(&self.completed);
            let total = Arc::clone(&self.total);
            let config = self.config.clone();
            let temp_dir = temp_dir.clone();
            let output_dir = output_dir.clone();
            let severities = severities.clone();

            let handle = tokio::spawn(async move {
                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();

                // Create batch input file
                let batch_input = temp_dir.join(format!("batch_{}.txt", batch_idx));
                let batch_output = temp_dir.join(format!("nuclei_batch_{}.txt", batch_idx));

                std::fs::write(&batch_input, batch.join("\n")).ok();

                // Build nuclei command with all speed optimizations
                let mut cmd_args = vec![
                    "-l".to_string(),
                    batch_input.display().to_string(),
                    "-jsonl".to_string(),
                    "-silent".to_string(),
                    "-etags".to_string(),
                    "ssl".to_string(),
                    "-severity".to_string(),
                    severities.clone(),
                    "-c".to_string(),
                    config.nuclei_concurrency.to_string(),
                    "-o".to_string(),
                    batch_output.display().to_string(),
                    // Speed optimizations
                    "-bs".to_string(),
                    config.nuclei_bulk_size.to_string(),
                    "-hbs".to_string(),
                    config.nuclei_headless_bulk.to_string(),
                    "-timeout".to_string(),
                    config.timeout_secs.to_string(),
                    "-retries".to_string(),
                    config.nuclei_retries.to_string(),
                    "-mhe".to_string(),
                    config.nuclei_max_host_errors.to_string(),
                ];

                // Add rate limiting if configured (0 = unlimited)
                if config.rate_limit > 0 {
                    cmd_args.push("-rl".to_string());
                    cmd_args.push(config.rate_limit.to_string());
                }

                // Add response size limit if configured
                if config.nuclei_response_size_limit > 0 {
                    cmd_args.push("-rsr".to_string());
                    cmd_args.push(config.nuclei_response_size_limit.to_string());
                }

                // TURBO MODE: Additional speed optimizations
                if config.turbo_mode {
                    cmd_args.push("-nc".to_string());        // No color (faster output)
                    cmd_args.push("-nh".to_string());        // No httpx probe
                    cmd_args.push("-ss".to_string());        // Silent stats
                    cmd_args.push("template-spray".to_string()); // Spray mode
                }

                // Execute nuclei
                let status = Command::new("nuclei")
                    .args(&cmd_args)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;

                // Update progress
                let done = completed.fetch_add(batch.len(), Ordering::SeqCst) + batch.len();
                let total_count = total.load(Ordering::SeqCst);
                let pct = (done as f64 / total_count as f64 * 100.0) as usize;

                println!("{}", format!(
                    "   ✓ Batch {} complete ({}/{} targets - {}%)",
                    batch_idx + 1, done, total_count, pct
                ).green());

                // Small delay between batches for rate limiting
                if config.batch_delay_ms > 0 {
                    sleep(Duration::from_millis(config.batch_delay_ms)).await;
                }

                // Return results count
                if batch_output.exists() {
                    std::fs::read_to_string(&batch_output)
                        .map(|c| c.lines().count())
                        .unwrap_or(0)
                } else {
                    0
                }
            });

            handles.push(handle);
        }

        // Wait for all batches
        let mut total_vulns = 0;
        for handle in handles {
            if let Ok(count) = handle.await {
                total_vulns += count;
            }
        }

        // Merge all batch outputs into final file
        let final_output = output_dir.join("files_").join("nuclei.txt");
        std::fs::create_dir_all(final_output.parent().unwrap())?;

        let mut final_content = String::new();
        for entry in std::fs::read_dir(&temp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "txt").unwrap_or(false)
                && path.file_name().map(|n| n.to_string_lossy().starts_with("nuclei_batch_")).unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    final_content.push_str(&content);
                }
            }
        }

        std::fs::write(&final_output, final_content)?;

        // Cleanup temp files
        let _ = std::fs::remove_dir_all(&temp_dir);

        println!();
        println!("{}", format!(
            "   🎯 Nuclei scan complete: {} vulnerabilities found", total_vulns
        ).green().bold());

        Ok(total_vulns)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PARALLEL CLOUD SCANNER
// ═══════════════════════════════════════════════════════════════════════════

use reqwest::Client;
use std::collections::HashSet;

pub struct ParallelCloudScanner {
    config: ParallelConfig,
    client: Client,
    semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub struct CloudAsset {
    pub provider: String,
    pub url: String,
    pub bucket_name: String,
    pub is_public: bool,
    pub allows_listing: bool,
    pub status_code: u16,
}

impl ParallelCloudScanner {
    pub fn new(config: ParallelConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        let workers = config.cloud_workers;
        Self {
            config,
            client,
            semaphore: Arc::new(Semaphore::new(workers)),
        }
    }

    /// Scan for cloud storage assets in parallel
    pub async fn scan_cloud_assets(&self, urls: Vec<String>) -> Vec<CloudAsset> {
        if urls.is_empty() {
            return Vec::new();
        }

        println!("{}", format!(
            "┌───────────────────────────────────────────────────────────────────────────────┐"
        ).cyan().bold());
        println!("{}", format!(
            "│  ☁️  PARALLEL CLOUD SCANNER                                                   │"
        ).cyan().bold());
        println!("{}", format!(
            "├───────────────────────────────────────────────────────────────────────────────┤"
        ).cyan());
        println!("{}", format!(
            "│  📊 URLs to scan: {:<59}│", urls.len()
        ).cyan());
        println!("{}", format!(
            "│  👷 Workers: {:<64}│", self.config.cloud_workers
        ).cyan());
        println!("{}", format!(
            "└───────────────────────────────────────────────────────────────────────────────┘"
        ).cyan().bold());
        println!();

        // Extract potential cloud storage URLs
        let cloud_urls = self.extract_cloud_urls(&urls);

        if cloud_urls.is_empty() {
            println!("{}", "   ℹ️  No cloud storage URLs found".yellow());
            return Vec::new();
        }

        println!("{}", format!("   🔍 Found {} potential cloud URLs", cloud_urls.len()).yellow());

        let mut handles = Vec::new();

        for url in cloud_urls {
            let semaphore = Arc::clone(&self.semaphore);
            let client = self.client.clone();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                // Rate limiting delay
                if config.rate_limit > 0 && config.batch_delay_ms > 0 {
                    sleep(Duration::from_millis(config.batch_delay_ms)).await;
                }

                Self::check_cloud_url(&client, &url).await
            });

            handles.push(handle);
        }

        let mut assets = Vec::new();
        for handle in handles {
            if let Ok(Some(asset)) = handle.await {
                assets.push(asset);
            }
        }

        println!("{}", format!(
            "   ✅ Cloud scan complete: {} accessible assets found",
            assets.iter().filter(|a| a.is_public).count()
        ).green().bold());

        assets
    }

    /// Extract cloud storage URLs from a list of URLs
    fn extract_cloud_urls(&self, urls: &[String]) -> Vec<String> {
        let mut cloud_urls = HashSet::new();

        let patterns = [
            // S3
            r"https?://[a-z0-9][a-z0-9\-\.]+\.s3\.amazonaws\.com",
            r"https?://[a-z0-9][a-z0-9\-\.]+\.s3-[a-z0-9\-]+\.amazonaws\.com",
            r"https?://[a-z0-9][a-z0-9\-\.]+\.s3\.[a-z0-9\-]+\.amazonaws\.com",
            r"https?://s3\.amazonaws\.com/[a-z0-9][a-z0-9\-\.]+",
            r"https?://s3\.[a-z0-9\-]+\.amazonaws\.com/[a-z0-9][a-z0-9\-\.]+",
            // Azure
            r"https?://[a-z0-9]+\.blob\.core\.windows\.net",
            // GCP
            r"https?://storage\.googleapis\.com/[a-z0-9][a-z0-9\-_\.]+",
            r"https?://[a-z0-9][a-z0-9\-_\.]+\.storage\.googleapis\.com",
            // DigitalOcean Spaces
            r"https?://[a-z0-9][a-z0-9\-\.]+\.[a-z0-9]+\.digitaloceanspaces\.com",
            // Backblaze B2
            r"https?://f[0-9]+\.backblazeb2\.com/file/[a-z0-9][a-z0-9\-_]+",
            // Wasabi
            r"https?://s3\.[a-z0-9\-]+\.wasabisys\.com/[a-z0-9][a-z0-9\-_]+",
            // CloudFront (may point to S3)
            r"https?://[a-z0-9]+\.cloudfront\.net",
        ];

        for url in urls {
            for pattern in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    for cap in re.find_iter(url) {
                        cloud_urls.insert(cap.as_str().to_string());
                    }
                }
            }
        }

        // Also check for common bucket naming patterns
        for url in urls {
            if url.contains("s3") || url.contains("bucket") ||
               url.contains("storage") || url.contains("blob") ||
               url.contains("cdn") || url.contains("assets") {
                cloud_urls.insert(url.clone());
            }
        }

        cloud_urls.into_iter().collect()
    }

    /// Check a single cloud URL for accessibility
    async fn check_cloud_url(client: &Client, url: &str) -> Option<CloudAsset> {
        // Determine provider
        let provider = if url.contains("s3.amazonaws.com") || url.contains("s3-") {
            "AWS S3"
        } else if url.contains("blob.core.windows.net") {
            "Azure Blob"
        } else if url.contains("storage.googleapis.com") {
            "Google Cloud Storage"
        } else if url.contains("digitaloceanspaces.com") {
            "DigitalOcean Spaces"
        } else if url.contains("backblazeb2.com") {
            "Backblaze B2"
        } else if url.contains("wasabisys.com") {
            "Wasabi"
        } else if url.contains("cloudfront.net") {
            "CloudFront"
        } else {
            "Unknown"
        };

        // Extract bucket name
        let bucket_name = url
            .split('/')
            .find(|s| !s.is_empty() && !s.contains("http") && !s.contains("."))
            .unwrap_or("unknown")
            .to_string();

        // Try to access the URL
        let resp = client.get(url).send().await.ok()?;
        let status = resp.status().as_u16();

        // Check if listable (common indicator of misconfiguration)
        let body = resp.text().await.unwrap_or_default();
        let allows_listing = body.contains("<ListBucketResult") ||
                            body.contains("<EnumerationResults") ||
                            body.contains("Contents") ||
                            body.contains("<Key>");

        let is_public = status == 200 || status == 403; // 403 means exists but no access

        Some(CloudAsset {
            provider: provider.to_string(),
            url: url.to_string(),
            bucket_name,
            is_public: status == 200,
            allows_listing,
            status_code: status,
        })
    }

    /// Save cloud assets to file
    pub fn save_to_file(&self, assets: &[CloudAsset], output_path: &Path) -> Result<()> {
        let mut content = String::new();
        content.push_str("=== CLOUD STORAGE ASSETS DISCOVERED ===\n");
        content.push_str(&format!("Total: {}\n", assets.len()));
        content.push_str(&format!("Public: {}\n", assets.iter().filter(|a| a.is_public).count()));
        content.push_str(&format!("Listable: {}\n\n", assets.iter().filter(|a| a.allows_listing).count()));

        // Critical findings first
        content.push_str("=== CRITICAL: LISTABLE BUCKETS ===\n");
        for asset in assets.iter().filter(|a| a.allows_listing) {
            content.push_str(&format!("[{}] {} - {}\n", asset.provider, asset.bucket_name, asset.url));
        }

        content.push_str("\n=== PUBLIC BUCKETS ===\n");
        for asset in assets.iter().filter(|a| a.is_public && !a.allows_listing) {
            content.push_str(&format!("[{}] {} - {} (HTTP {})\n",
                asset.provider, asset.bucket_name, asset.url, asset.status_code));
        }

        content.push_str("\n=== ALL CLOUD ASSETS ===\n");
        for asset in assets {
            content.push_str(&format!("[{}] {} | {} | Public: {} | Listable: {}\n",
                asset.provider, asset.url, asset.bucket_name, asset.is_public, asset.allows_listing));
        }

        std::fs::write(output_path, content)?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Check if nuclei is installed
pub fn is_nuclei_installed() -> bool {
    std::process::Command::new("which")
        .arg("nuclei")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get nuclei version
pub async fn get_nuclei_version() -> Option<String> {
    let output = Command::new("nuclei")
        .arg("-version")
        .output()
        .await
        .ok()?;

    String::from_utf8(output.stdout)
        .ok()
        .or_else(|| String::from_utf8(output.stderr).ok())
        .map(|s| s.trim().to_string())
}

/// Read targets from file
pub fn read_targets_from_file(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ParallelConfig::default();
        assert_eq!(config.nuclei_workers, 4);
        assert_eq!(config.nuclei_batch_size, 50);
    }

    #[test]
    fn test_aggressive_config() {
        let config = ParallelConfig::aggressive();
        assert!(config.nuclei_workers > ParallelConfig::default().nuclei_workers);
    }
}
