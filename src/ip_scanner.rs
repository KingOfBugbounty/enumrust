// ip_scanner.rs - IP Port Scanning and Directory Fuzzing Module
// Purpose: Scan discovered IPs for open ports and perform recursive directory fuzzing
// Only reports HTTP 200 responses

use anyhow::Result;
use colored::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Semaphore;
use std::sync::Arc;

/// Represents an open port on an IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPort {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub is_http: bool,
}

/// Represents a discovered directory/path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPath {
    pub url: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub redirect_url: Option<String>,
}

/// Represents IP scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpScanResult {
    pub ip: String,
    pub open_ports: Vec<OpenPort>,
    pub discovered_paths: Vec<DiscoveredPath>,
    pub total_paths_found: usize,
}

/// Configuration for IP scanning
#[derive(Debug, Clone)]
pub struct IpScanConfig {
    pub ports: String,           // Port range to scan (e.g., "1-65535" or "80,443,8080")
    pub rate: u32,               // Masscan rate
    pub threads: usize,          // Fuzzing threads
    pub depth: u8,               // Recursion depth for fuzzing
    pub wordlist: Option<String>, // Custom wordlist path
    pub timeout: u64,            // Request timeout in seconds
    pub fuzz_timeout_per_ip: u64, // Max time (seconds) to spend fuzzing each IP (0 = no limit)
}

/// Get optimal thread count based on system resources
pub fn get_optimal_threads() -> usize {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    // Use 4x CPU cores, but cap at reasonable limits
    // Min: 50, Max: 200 (to avoid overwhelming the system)
    let optimal = cpu_count * 4;
    optimal.clamp(50, 200)
}

impl Default for IpScanConfig {
    fn default() -> Self {
        Self {
            ports: get_top_1000_ports(),
            rate: 1000,
            threads: get_optimal_threads(),
            depth: 2,
            wordlist: None,
            timeout: 10,
            fuzz_timeout_per_ip: 60, // Default: 60 seconds per IP
        }
    }
}

/// Format a discovery result in a nice side-by-side format
fn format_discovery(url: &str, status: u16, length: Option<u64>, content_type: Option<&str>) -> String {
    let status_colored = match status {
        200 => format!("{}", "200".green().bold()),
        _ => format!("{}", status.to_string().yellow()),
    };

    // Truncate URL if too long for nice display
    let max_url_len = 70;
    let url_display = if url.len() > max_url_len {
        format!("{}...", &url[..max_url_len-3])
    } else {
        url.to_string()
    };

    // Format additional info
    let length_str = length.map(|l| format!("{}b", l)).unwrap_or_else(|| "-".to_string());
    let ct_short = content_type
        .map(|ct| {
            if ct.contains("json") { "json" }
            else if ct.contains("html") { "html" }
            else if ct.contains("javascript") || ct.contains("js") { "js" }
            else if ct.contains("xml") { "xml" }
            else if ct.contains("text") { "text" }
            else { "other" }
        })
        .unwrap_or("-");

    format!(
        "{:<75} │ {} │ {:>8} │ {}",
        url_display,
        status_colored,
        length_str,
        ct_short
    )
}

/// Top 1000 HTTP ports to check (most common web services)
const HTTP_PORTS: &[u16] = &[
    // Most common web ports
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443,
    // Extended common ports
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    // 8xxx range (very common for web apps)
    8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010,
    8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020,
    8021, 8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029, 8030,
    8040, 8042, 8045, 8050, 8060, 8069, 8070, 8071, 8072, 8073,
    8074, 8075, 8076, 8077, 8078, 8079, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094,
    8095, 8096, 8097, 8098, 8099, 8100, 8118, 8123, 8126, 8139,
    8140, 8180, 8181, 8182, 8183, 8184, 8185, 8186, 8187, 8188,
    8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 8198,
    8199, 8200, 8222, 8243, 8280, 8281, 8300, 8333, 8383, 8400,
    8443, 8484, 8500, 8530, 8531, 8545, 8546, 8600, 8686, 8765,
    8787, 8834, 8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887,
    8888, 8889, 8890, 8899, 8900, 8983, 8989, 8990, 8991, 8999,
    // 9xxx range
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009,
    9010, 9011, 9012, 9013, 9014, 9015, 9016, 9017, 9018, 9019,
    9020, 9021, 9022, 9023, 9024, 9025, 9042, 9043, 9060, 9080,
    9081, 9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9090,
    9091, 9092, 9093, 9094, 9095, 9099, 9100, 9111, 9191, 9200,
    9201, 9300, 9301, 9400, 9418, 9443, 9500, 9600, 9800, 9900,
    9981, 9999,
    // Common app server ports
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009,
    3010, 3030, 3031, 3050, 3080, 3128, 3128, 3200, 3260, 3268,
    3269, 3300, 3306, 3333, 3389, 3478, 3500, 3702, 3790, 3872,
    // 4xxx range
    4000, 4001, 4002, 4040, 4200, 4242, 4243, 4369, 4443, 4444,
    4445, 4500, 4567, 4646, 4848, 4993,
    // 5xxx range
    5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009,
    5010, 5050, 5060, 5080, 5100, 5200, 5222, 5280, 5357, 5400,
    5432, 5500, 5555, 5556, 5601, 5631, 5666, 5672, 5800, 5801,
    5802, 5900, 5901, 5984, 5985, 5986,
    // 6xxx range
    6000, 6001, 6060, 6080, 6379, 6443, 6500, 6501, 6543, 6666,
    6667, 6688, 6789, 6868, 6969,
    // 7xxx range
    7000, 7001, 7002, 7003, 7004, 7005, 7070, 7071, 7077, 7080,
    7170, 7180, 7443, 7474, 7500, 7547, 7575, 7657, 7676, 7777,
    7778, 7779, 7780, 7890, 7999,
    // 10xxx+ range
    10000, 10001, 10010, 10080, 10243, 10250, 10255, 10443, 10800,
    11211, 12000, 12345, 13000, 14000, 15000, 15672, 16000, 16080,
    17000, 18000, 18080, 19000, 20000, 20080, 20443, 25000, 27017,
    28017, 30000, 32400, 32768, 33000, 37777, 40000, 41000, 443,
    44158, 49152, 50000, 50070, 50443, 55000, 55555, 60000, 60080,
    61000, 61616, 62078, 64738, 65000, 65535,
    // Additional common web app ports
    591, 593, 631, 832, 888, 981, 1010, 1080, 1099, 1100,
    1241, 1311, 1352, 1433, 1434, 1521, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2100,
    2181, 2222, 2375, 2376, 2379, 2380, 2480, 2483, 2484, 2638,
    2812,
];

/// Get top 1000 common HTTP ports as a string for scanning
pub fn get_top_1000_ports() -> String {
    HTTP_PORTS.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Scan IPs for open ports using masscan
pub async fn scan_ports(
    ips: &[String],
    config: &IpScanConfig,
    output_dir: &Path,
) -> Result<Vec<OpenPort>> {
    if ips.is_empty() {
        println!("{}", "[!] No IPs provided for port scanning".yellow());
        return Ok(Vec::new());
    }

    println!("{}", format!("[*] Scanning {} IPs for open ports...", ips.len()).cyan());

    // Create temp file with IPs
    let ips_file = output_dir.join("ip_scan_targets.txt");
    let mut file = File::create(&ips_file)?;
    for ip in ips {
        writeln!(file, "{}", ip)?;
    }

    // Run masscan
    let masscan_output = output_dir.join("ip_masscan_results.txt");
    let masscan_json = output_dir.join("ip_masscan_results.json");

    println!("{}", format!("[*] Running masscan on ports: {}", config.ports).cyan());

    let masscan_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "sudo masscan -iL {} -p{} --rate {} -oJ {} -oL {} 2>/dev/null",
            ips_file.display(),
            config.ports,
            config.rate,
            masscan_json.display(),
            masscan_output.display()
        ))
        .status()
        .await;

    let mut open_ports = Vec::new();

    match masscan_status {
        Ok(status) if status.success() => {
            // Parse masscan output
            if masscan_output.exists() {
                let content = fs::read_to_string(&masscan_output)?;
                for line in content.lines() {
                    // masscan format: open tcp 80 192.168.1.1 timestamp
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 && parts[0] == "open" {
                        if let Ok(port) = parts[2].parse::<u16>() {
                            let ip = parts[3].to_string();
                            let is_http = HTTP_PORTS.contains(&port);

                            open_ports.push(OpenPort {
                                ip: ip.clone(),
                                port,
                                protocol: parts[1].to_string(),
                                service: None,
                                is_http,
                            });
                        }
                    }
                }
            }
            println!("{}", format!("[+] Found {} open ports", open_ports.len()).green());
        }
        _ => {
            println!("{}", "[!] Masscan failed, trying alternative port scan...".yellow());
            // Fallback to basic TCP connect scan using Rust
            open_ports = basic_port_scan(ips, config).await?;
        }
    }

    // Save results
    let results_file = output_dir.join("ip_open_ports.json");
    let json = serde_json::to_string_pretty(&open_ports)?;
    fs::write(&results_file, json)?;

    Ok(open_ports)
}

/// Basic TCP port scan fallback
async fn basic_port_scan(ips: &[String], config: &IpScanConfig) -> Result<Vec<OpenPort>> {
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let mut open_ports = Vec::new();
    let semaphore = Arc::new(Semaphore::new(100)); // Limit concurrent connections

    // Parse ports from config
    let ports_to_scan: Vec<u16> = parse_ports(&config.ports);

    println!("{}", format!("[*] Scanning {} ports on {} IPs...", ports_to_scan.len(), ips.len()).cyan());

    let mut handles = Vec::new();

    for ip in ips {
        for &port in &ports_to_scan {
            let ip = ip.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let addr = format!("{}:{}", ip, port);

                match timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => Some(OpenPort {
                        ip,
                        port,
                        protocol: "tcp".to_string(),
                        service: None,
                        is_http: HTTP_PORTS.contains(&port),
                    }),
                    _ => None,
                }
            });

            handles.push(handle);
        }
    }

    // Collect results
    for handle in handles {
        if let Ok(Some(port)) = handle.await {
            open_ports.push(port);
        }
    }

    Ok(open_ports)
}

/// Parse port specification string
fn parse_ports(ports_spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in ports_spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range like "80-100"
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }

    ports
}

/// Find wordlist path
fn find_wordlist(config: &IpScanConfig) -> Option<String> {
    if let Some(ref custom) = config.wordlist {
        if Path::new(custom).exists() {
            return Some(custom.clone());
        }
    }

    // Try common wordlist locations
    let wordlist_paths = [
        "/root/PENTEST/enumrust/enumrust/src/words_and_files_top5000.txt",
        "./src/words_and_files_top5000.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    ];

    for path in wordlist_paths {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    None
}

/// Fuzz a single IP with timeout - returns discovered paths
async fn fuzz_single_ip(
    port: &OpenPort,
    config: &IpScanConfig,
    output_dir: &Path,
    wordlist: &str,
    idx: usize,
    total: usize,
) -> Result<Vec<DiscoveredPath>> {
    let scheme = if port.port == 443 || port.port == 8443 || port.port == 9443 {
        "https"
    } else {
        "http"
    };

    let base_url = format!("{}://{}:{}", scheme, port.ip, port.port);
    let mut discovered = Vec::new();

    println!("{}", format!(
        "\n[*] [{}/{}] Fuzzing: {} (timeout: {}s)",
        idx + 1,
        total,
        base_url,
        config.fuzz_timeout_per_ip
    ).cyan());

    // Run ffuf with recursive mode, only status 200
    let ffuf_output = output_dir.join(format!("ffuf_ip_{}_{}.json", port.ip.replace('.', "_"), port.port));

    let ffuf_cmd = format!(
        "ffuf -u {}/FUZZ -w {} -mc 200 -recursion -recursion-depth {} -t {} -timeout {} -ac -s -json -o {} 2>/dev/null",
        base_url,
        wordlist,
        config.depth,
        config.threads,
        config.timeout,
        ffuf_output.display()
    );

    let ffuf_status = Command::new("sh")
        .arg("-c")
        .arg(&ffuf_cmd)
        .status()
        .await;

    match ffuf_status {
        Ok(status) if status.success() => {
            // Parse ffuf JSON output
            if ffuf_output.exists() {
                if let Ok(content) = fs::read_to_string(&ffuf_output) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(results) = json["results"].as_array() {
                            for result in results {
                                let url = result["url"].as_str().unwrap_or("");
                                let status = result["status"].as_u64().unwrap_or(0) as u16;
                                let length = result["length"].as_u64();
                                let content_type = result["content-type"].as_str().map(|s| s.to_string());
                                let redirect = result["redirectlocation"].as_str()
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string());

                                // Only add HTTP 200 responses
                                if status == 200 {
                                    let path = DiscoveredPath {
                                        url: url.to_string(),
                                        status_code: status,
                                        content_length: length,
                                        content_type: content_type.clone(),
                                        title: None,
                                        redirect_url: redirect.clone(),
                                    };

                                    discovered.push(path);

                                    // Display in side-by-side format
                                    let display = format_discovery(url, status, length, content_type.as_deref());
                                    println!("│ {} │", display);
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            println!("{}", format!("    [!] ffuf failed for {}, trying feroxbuster...", base_url).yellow());

            // Fallback to feroxbuster
            let ferox_output = output_dir.join(format!("ferox_ip_{}_{}.txt", port.ip.replace('.', "_"), port.port));

            let ferox_cmd = format!(
                "feroxbuster -u {} -w {} -s 200 -d {} -t {} --timeout {} -q -o {} 2>/dev/null",
                base_url,
                wordlist,
                config.depth,
                config.threads,
                config.timeout,
                ferox_output.display()
            );

            let ferox_status = Command::new("sh")
                .arg("-c")
                .arg(&ferox_cmd)
                .status()
                .await;

            if let Ok(status) = ferox_status {
                if status.success() && ferox_output.exists() {
                    // Parse feroxbuster output (simple text format)
                    if let Ok(content) = fs::read_to_string(&ferox_output) {
                        for line in content.lines() {
                            // feroxbuster format: 200 GET 1234l 5678w 9012c http://...
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 6 {
                                if let Ok(status) = parts[0].parse::<u16>() {
                                    if status == 200 {
                                        let url = parts.last().unwrap_or(&"").to_string();

                                        let path = DiscoveredPath {
                                            url: url.clone(),
                                            status_code: 200,
                                            content_length: None,
                                            content_type: None,
                                            title: None,
                                            redirect_url: None,
                                        };

                                        discovered.push(path);

                                        // Display in side-by-side format
                                        let display = format_discovery(&url, 200, None, None);
                                        println!("│ {} │", display);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(discovered)
}

/// Perform recursive directory fuzzing on HTTP services - only 200 responses
pub async fn fuzz_directories(
    open_ports: &[OpenPort],
    config: &IpScanConfig,
    output_dir: &Path,
    _client: &Client,
) -> Result<Vec<DiscoveredPath>> {
    use tokio::time::timeout;

    // Filter only HTTP ports
    let http_ports: Vec<&OpenPort> = open_ports.iter().filter(|p| p.is_http).collect();

    if http_ports.is_empty() {
        println!("{}", "[!] No HTTP ports found for directory fuzzing".yellow());
        return Ok(Vec::new());
    }

    println!("{}", format!("[*] Starting recursive directory fuzzing on {} HTTP services...", http_ports.len()).cyan());
    println!("{}", format!("[*] Recursion depth: {}", config.depth).cyan());
    println!("{}", format!("[*] Threads: {} (auto-optimized)", config.threads).cyan());
    println!("{}", format!("[*] Timeout per IP: {}s (skip slow targets)", config.fuzz_timeout_per_ip).cyan().bold());
    println!("{}", "[*] Filtering: Only HTTP 200 responses".cyan().bold());

    // Print header for side-by-side display
    println!();
    println!("{}", "┌───────────────────────────────────────────────────────────────────────────────┬─────┬──────────┬───────┐".cyan());
    println!("{}", "│ URL                                                                           │ ST  │   SIZE   │ TYPE  │".cyan().bold());
    println!("{}", "├───────────────────────────────────────────────────────────────────────────────┼─────┼──────────┼───────┤".cyan());

    let wordlist = match find_wordlist(config) {
        Some(w) => w,
        None => {
            create_minimal_wordlist(output_dir)?
        }
    };

    let mut all_discovered = Vec::new();
    let results_file = output_dir.join("ip_fuzz_results_200.txt");
    let mut results_out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&results_file)?;

    writeln!(results_out, "# IP Directory Fuzzing Results - HTTP 200 Only")?;
    writeln!(results_out, "# Generated by EnumRust")?;
    writeln!(results_out, "# Timeout per IP: {}s", config.fuzz_timeout_per_ip)?;
    writeln!(results_out, "# ═══════════════════════════════════════════════════════════════\n")?;

    let mut skipped_count = 0;
    let total = http_ports.len();

    for (idx, port) in http_ports.iter().enumerate() {
        let base_url = format!("{}://{}:{}",
            if port.port == 443 || port.port == 8443 || port.port == 9443 { "https" } else { "http" },
            port.ip,
            port.port
        );

        // Apply timeout per IP (0 = no timeout)
        let fuzz_result = if config.fuzz_timeout_per_ip > 0 {
            let timeout_duration = Duration::from_secs(config.fuzz_timeout_per_ip);
            match timeout(timeout_duration, fuzz_single_ip(port, config, output_dir, &wordlist, idx, total)).await {
                Ok(result) => result,
                Err(_) => {
                    // Timeout occurred - skip this IP
                    skipped_count += 1;
                    println!("{}", format!(
                        "\n[!] TIMEOUT: {} exceeded {}s limit - SKIPPING",
                        base_url,
                        config.fuzz_timeout_per_ip
                    ).yellow().bold());
                    writeln!(results_out, "\n# TIMEOUT: {} - skipped after {}s", base_url, config.fuzz_timeout_per_ip)?;
                    continue;
                }
            }
        } else {
            // No timeout - fuzz without limit
            fuzz_single_ip(port, config, output_dir, &wordlist, idx, total).await
        };

        // Process results
        if let Ok(paths) = fuzz_result {
            writeln!(results_out, "\n# Target: {}", base_url)?;
            writeln!(results_out, "# Found: {} paths with HTTP 200", paths.len())?;
            writeln!(results_out, "# ───────────────────────────────────────────────────────────────")?;

            for path in &paths {
                let length_str = path.content_length.map(|l| format!(" [{}b]", l)).unwrap_or_default();
                let ct_str = path.content_type.clone().map(|c| format!(" [{}]", c)).unwrap_or_default();
                writeln!(results_out, "[200]{}{} {}", length_str, ct_str, path.url)?;
            }

            all_discovered.extend(paths);
        }
    }

    // Close the table
    println!("{}", "└───────────────────────────────────────────────────────────────────────────────┴─────┴──────────┴───────┘".cyan());

    // Save JSON results
    let json_results = output_dir.join("ip_discovered_paths_200.json");
    let json = serde_json::to_string_pretty(&all_discovered)?;
    fs::write(&json_results, json)?;

    println!("{}", format!("\n[+] Total paths discovered (HTTP 200): {}", all_discovered.len()).green().bold());
    if skipped_count > 0 {
        println!("{}", format!("[!] Skipped {} slow IPs (exceeded {}s timeout)", skipped_count, config.fuzz_timeout_per_ip).yellow());
    }
    println!("{}", format!("[+] Results saved to: {}", results_file.display()).green());

    Ok(all_discovered)
}

/// Create minimal wordlist if none found
fn create_minimal_wordlist(output_dir: &Path) -> Result<String> {
    let wordlist_path = output_dir.join("minimal_wordlist.txt");
    let mut file = File::create(&wordlist_path)?;

    let common_paths = [
        // Common directories
        "admin", "administrator", "login", "dashboard", "panel", "api", "v1", "v2",
        "config", "configuration", "settings", "setup", "install",
        "backup", "backups", "bak", "old", "temp", "tmp",
        "test", "testing", "dev", "development", "staging", "prod",
        "uploads", "upload", "files", "images", "img", "assets", "static",
        "css", "js", "javascript", "scripts", "lib", "libs", "vendor",
        "docs", "documentation", "doc", "help", "faq",
        "user", "users", "account", "accounts", "profile", "profiles",
        "auth", "authentication", "oauth", "sso",
        "data", "database", "db", "sql", "mysql", "postgres",
        "log", "logs", "debug", "error", "errors",
        "public", "private", "internal", "external",
        "wp-admin", "wp-content", "wp-includes", "wordpress",
        "phpmyadmin", "pma", "adminer", "mysql-admin",
        "cgi-bin", "cgi", "bin", "scripts",
        "server-status", "server-info", "status", "info", "health", "healthcheck",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
        "web.config", "package.json", "composer.json", "Gemfile",
        // API endpoints
        "graphql", "rest", "soap", "rpc", "json", "xml",
        "swagger", "openapi", "redoc", "api-docs",
        // Common files
        "index.php", "index.html", "index.asp", "default.asp",
        "login.php", "admin.php", "config.php", "connect.php",
        "info.php", "phpinfo.php", "test.php",
        "readme", "readme.txt", "readme.md", "README.md",
        "changelog", "changelog.txt", "CHANGELOG.md",
        "license", "license.txt", "LICENSE",
        // Framework specific
        "actuator", "actuator/health", "actuator/env", "actuator/info",
        "metrics", "prometheus", "grafana",
        "console", "manager", "jmx-console", "web-console",
        "elmah.axd", "trace.axd", "glimpse.axd",
        ".well-known", ".well-known/security.txt",
    ];

    for path in common_paths {
        writeln!(file, "{}", path)?;
    }

    Ok(wordlist_path.to_string_lossy().to_string())
}

/// Main function to scan IPs and fuzz directories
pub async fn scan_ips_and_fuzz(
    ips_file: &Path,
    config: &IpScanConfig,
    output_dir: &Path,
    client: &Client,
) -> Result<Vec<IpScanResult>> {
    // Read IPs from file
    let ips: Vec<String> = if ips_file.exists() {
        let file = File::open(ips_file)?;
        let reader = BufReader::new(file);
        reader
            .lines()
            .map_while(Result::ok)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };

    if ips.is_empty() {
        println!("{}", "[!] No IPs found for scanning".yellow());
        return Ok(Vec::new());
    }

    println!("\n{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
    println!("{}", "  IP SCANNER: PORT SCAN + DIRECTORY FUZZING".magenta().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
    println!("{}", format!("[*] Target IPs: {}", ips.len()).cyan());
    println!("{}", format!("[*] Port range: {}", config.ports).cyan());
    println!("{}", format!("[*] Recursion depth: {}", config.depth).cyan());
    println!("{}", "[*] Filter: HTTP 200 responses only".cyan().bold());

    // Create output directory for IP scan results
    let ip_scan_dir = output_dir.join("ip_scan");
    fs::create_dir_all(&ip_scan_dir)?;

    // Step 1: Port scanning
    println!("\n{}", "─── PHASE 1: PORT SCANNING ───".yellow().bold());
    let open_ports = scan_ports(&ips, config, &ip_scan_dir).await?;

    if open_ports.is_empty() {
        println!("{}", "[!] No open ports found".yellow());
        return Ok(Vec::new());
    }

    // Display open ports summary
    let http_count = open_ports.iter().filter(|p| p.is_http).count();
    println!("{}", format!("[+] Open ports: {} (HTTP services: {})", open_ports.len(), http_count).green());

    // Step 2: Directory fuzzing on HTTP services
    println!("\n{}", "─── PHASE 2: RECURSIVE DIRECTORY FUZZING (200 Only) ───".yellow().bold());
    let discovered_paths = fuzz_directories(&open_ports, config, &ip_scan_dir, client).await?;

    // Aggregate results by IP
    let mut results: Vec<IpScanResult> = Vec::new();
    let mut seen_ips: HashSet<String> = HashSet::new();

    for port in &open_ports {
        if !seen_ips.contains(&port.ip) {
            seen_ips.insert(port.ip.clone());

            let ip_ports: Vec<OpenPort> = open_ports
                .iter()
                .filter(|p| p.ip == port.ip)
                .cloned()
                .collect();

            let ip_paths: Vec<DiscoveredPath> = discovered_paths
                .iter()
                .filter(|p| p.url.contains(&port.ip))
                .cloned()
                .collect();

            results.push(IpScanResult {
                ip: port.ip.clone(),
                open_ports: ip_ports,
                discovered_paths: ip_paths.clone(),
                total_paths_found: ip_paths.len(),
            });
        }
    }

    // Save consolidated results
    let final_results = ip_scan_dir.join("ip_scan_complete.json");
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&final_results, json)?;

    // Print summary
    println!("\n{}", "═══════════════════════════════════════════════════════════════".green().bold());
    println!("{}", "  IP SCAN SUMMARY".green().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".green().bold());
    println!("{}", format!("  IPs scanned: {}", ips.len()).white());
    println!("{}", format!("  Open ports found: {}", open_ports.len()).white());
    println!("{}", format!("  HTTP services: {}", http_count).white());
    println!("{}", format!("  Paths discovered (200): {}", discovered_paths.len()).green().bold());
    println!("{}", format!("  Results saved to: {}/", ip_scan_dir.display()).cyan());
    println!("{}", "═══════════════════════════════════════════════════════════════".green().bold());

    Ok(results)
}

/// Quick scan for common ports only (faster)
#[allow(dead_code)]
pub async fn quick_port_scan(
    ips: &[String],
    output_dir: &Path,
) -> Result<Vec<OpenPort>> {
    let config = IpScanConfig {
        ports: "80,443,8080,8443,3000,5000,8000,9000".to_string(),
        rate: 500,
        ..Default::default()
    };

    scan_ports(ips, &config, output_dir).await
}

/// Full port scan (slower but comprehensive)
#[allow(dead_code)]
pub async fn full_port_scan(
    ips: &[String],
    output_dir: &Path,
) -> Result<Vec<OpenPort>> {
    let config = IpScanConfig {
        ports: "1-65535".to_string(),
        rate: 10000,
        ..Default::default()
    };

    scan_ports(ips, &config, output_dir).await
}
