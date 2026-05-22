// main.rs - EnumRust v2.3.0 - Advanced Security Reconnaissance Tool
// Purpose: Complete domain enumeration, subdomain discovery, port scanning,
//          JS analysis, package scanning, secrets detection, and vulnerability assessment
// Author: Claude Code (Anthropic)
// License: MIT

#![recursion_limit = "512"]

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use trust_dns_resolver::TokioAsyncResolver;

// Module declarations
mod admin_finder;
mod bruteforce;
mod credential_tester;
mod discord_notifier;
mod ip_scanner;
mod ip_validator;
mod js_crawler;
mod metrics;
mod package_scanner;
mod progress;
mod report_generator;
mod secret_validators;
mod secrets_scanner;
mod info_disclosure_scanner;
mod ollama;
mod wpscan;
mod shortscan;
mod update_checker;

use metrics::EnumRustMetrics;
use progress::{EventType, ProgressTracker};


/// EnumRust - Advanced Security Reconnaissance Tool
#[derive(Parser, Debug)]
#[command(
    name = "EnumRust",
    version = "2.3.0",
    author = "Security Research Team",
    about = "Complete domain enumeration and security reconnaissance platform",
    long_about = r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    ENUMRUST - Security Reconnaissance Tool                     ║
╚═══════════════════════════════════════════════════════════════════════════════╝

EnumRust performs comprehensive security reconnaissance including:

  📡 SUBDOMAIN ENUMERATION
     • haktrails, subfinder, tlsx (certificate SANs)
     • DNS resolution and validation with trust-dns

  🔍 PORT SCANNING & SERVICE DISCOVERY
     • masscan for fast port scanning
     • httpx for HTTP service validation
     • IP-based scanning with directory fuzzing

  🌐 WEB ANALYSIS
     • JavaScript file discovery and analysis
     • API endpoint extraction
     • Cloud storage URL detection (S3, Azure, GCP)
     • Admin panel discovery

  🔐 SECRET DETECTION
     • Hardcoded secrets in JS files
     • TruffleHog integration
     • API keys, tokens, credentials

  🎯 VULNERABILITY SCANNING
     • Nuclei vulnerability scanner
     • Chameleon directory enumeration
     • Package dependency analysis

  🚨 BUG BOUNTY MODE
     • Default credential testing
     • Discord notifications for findings

═══════════════════════════════════════════════════════════════════════════════

EXAMPLES:

  Basic domain scan:
    enumrust -d example.com

  Full scan with all features:
    enumrust -d example.com --full-scan

  Scan with IP port scanning and directory fuzzing:
    enumrust -d example.com --ip-scan

  IP scan with full port range (1-65535):
    enumrust -d example.com --ip-scan --ip-full-scan

  IP scan with custom recursion depth:
    enumrust -d example.com --ip-scan --ip-fuzz-depth 3

  IP scan with custom ports:
    enumrust -d example.com --ip-scan --ip-ports "80,443,8080,8443,9000-9100"

  IP scan with custom wordlist:
    enumrust -d example.com --ip-scan --ip-wordlist /path/to/wordlist.txt

  Bug bounty mode with Discord notifications:
    enumrust -d example.com --bugbounty --discord-webhook "https://discord.com/api/webhooks/..."

  Scan multiple domains from file:
    enumrust -f domains.txt --full-scan

  Enable login bruteforce:
    enumrust -d example.com --bruteforce --userlist users.txt --passlist passwords.txt

═══════════════════════════════════════════════════════════════════════════════

OUTPUT FILES:

  {domain}/
  ├── subdomains.txt          # Discovered subdomains
  ├── ips.txt                 # Resolved IP addresses
  ├── http200.txt             # Live hosts (HTTP 200)
  ├── admin_panels.json       # Discovered admin panels
  ├── js_secrets_enhanced.json # Secrets from JS files
  ├── js_endpoints.txt        # API endpoints
  ├── trufflehog.json         # TruffleHog results
  ├── scan_metrics.json       # Scan statistics
  ├── report.html             # HTML report
  ├── ip_scan/                # IP scanning results
  │   ├── ip_open_ports.json      # Open ports found
  │   ├── ip_fuzz_results_200.txt # Directories (HTTP 200)
  │   └── ip_scan_complete.json   # Complete results
  └── files_/
      ├── nuclei.txt          # Vulnerabilities found
      └── chameleon_*.txt     # Directory enumeration

═══════════════════════════════════════════════════════════════════════════════
"#,
    after_help = r#"
IP SCANNING OPTIONS:

  The --ip-scan feature performs:
  1. Port scanning on all discovered IPs using masscan
  2. Recursive directory fuzzing on HTTP services
  3. Reports ONLY HTTP 200 responses (filters out 403, 404, etc.)

  Port formats supported:
    • Single ports: "80,443,8080"
    • Port ranges: "8000-9000"
    • Combined: "80,443,8000-8100,9443"

  The fuzzing uses ffuf with recursion. If ffuf is not available,
  it falls back to chameleon.

REQUIRED TOOLS:

  Core:      httpx, dnsx, masscan (sudo), nuclei
  Optional:  subfinder, haktrails, tlsx, chameleon, ffuf, trufflehog

  Install with: apt install masscan && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

MORE INFO:

  GitHub: https://github.com/enumrust/enumrust
  Docs:   https://enumrust.io/docs
"#
)]
struct Args {
    // ═══════════════════════════════════════════════════════════════════════════
    // TARGET OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Target domain to enumerate (e.g., example.com)
    #[arg(short, long, value_name = "DOMAIN", help_heading = "Target Options")]
    domain: Option<String>,

    /// File containing list of domains (one per line)
    #[arg(short, long, value_name = "FILE", help_heading = "Target Options",
          help = "Process multiple domains from a file (one domain per line, # for comments)")]
    file: Option<String>,

    // ═══════════════════════════════════════════════════════════════════════════
    // SCAN MODE OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable full scan with all tools and features
    #[arg(long, help_heading = "Scan Modes",
          help = "Enable ALL scanning features (subfinder, haktrails, whois, ip-scan, etc.)")]
    full_scan: bool,

    /// Enable bug bounty mode (aggressive scanning + credential testing)
    #[arg(long, help_heading = "Scan Modes",
          help = "Bug bounty mode: test default credentials on admin panels, aggressive scanning")]
    bugbounty: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // SUBDOMAIN ENUMERATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable subfinder for subdomain enumeration
    #[arg(long, help_heading = "Subdomain Enumeration",
          help = "Use subfinder for passive subdomain discovery")]
    subfinder: bool,

    /// Enable haktrails for subdomain enumeration
    #[arg(long, help_heading = "Subdomain Enumeration",
          help = "Use haktrails (SecurityTrails) for subdomain discovery")]
    hacktrails: bool,

    /// Enable WHOIS lookup for domain information
    #[arg(long, help_heading = "Subdomain Enumeration",
          help = "Perform WHOIS lookup to gather domain registration info")]
    whois: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // IP SCANNING OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable IP port scanning and directory fuzzing
    #[arg(long, help_heading = "IP Scanning",
          help = "Scan discovered IPs: port scan + recursive directory fuzzing (HTTP 200 only)")]
    ip_scan: bool,

    /// Ports to scan on IPs (use 'top1000' for common HTTP ports)
    #[arg(long, default_value = "top1000",
          value_name = "PORTS", help_heading = "IP Scanning",
          help = "Ports to scan. Use 'top1000' for ~350 common HTTP ports, or specify custom: '80,443' or '8000-9000'")]
    ip_ports: String,

    /// Full port scan (1-65535) - slower but comprehensive
    #[arg(long, help_heading = "IP Scanning",
          help = "Scan ALL 65535 ports (slow but thorough, requires sudo for masscan)")]
    ip_full_scan: bool,

    /// Recursion depth for directory fuzzing
    #[arg(long, default_value = "2", value_name = "DEPTH", help_heading = "IP Scanning",
          help = "Directory fuzzing recursion depth (1-5, higher = slower but deeper)")]
    ip_fuzz_depth: u8,

    /// Custom wordlist for IP directory fuzzing
    #[arg(long, value_name = "FILE", help_heading = "IP Scanning",
          help = "Custom wordlist for directory fuzzing (default: built-in common paths)")]
    ip_wordlist: Option<String>,

    /// Timeout per IP for directory fuzzing (skip slow targets)
    #[arg(long, default_value = "60", value_name = "SECONDS", help_heading = "IP Scanning",
          help = "Max time in seconds per IP for fuzzing (0 = no limit, skip slow targets faster)")]
    ip_fuzz_timeout: u64,

    /// Filter IPs - remove CDN/Cloud IPs (Cloudflare, AWS, Akamai, etc.)
    #[arg(long, help_heading = "IP Scanning",
          help = "Filter IPs: remove CDNs (Cloudflare, AWS, Akamai) and verify via reverse DNS")]
    ip_filter: bool,

    /// Strict IP filtering - only scan IPs that reverse DNS to the target domain
    #[arg(long, help_heading = "IP Scanning",
          help = "Strict mode: only scan IPs whose PTR record matches the target domain")]
    ip_strict: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // INFORMATION DISCLOSURE SCANNING OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable information disclosure scanning (S3, Actuator, GraphQL, sensitive files)
    #[arg(long, help_heading = "Info Disclosure",
          help = "Scan for information disclosure: cloud storage misconfig, Spring Actuator, GraphQL introspection, sensitive files")]
    disclosure_scan: bool,

    /// Enable S3/Cloud storage misconfiguration scanning
    #[arg(long, help_heading = "Info Disclosure",
          help = "Scan cloud storage (S3, GCS, Azure, R2) for misconfigurations using s3scan")]
    s3_scan: bool,

    /// Enable Spring Boot Actuator endpoint scanning
    #[arg(long, help_heading = "Info Disclosure",
          help = "Scan for exposed Spring Boot Actuator endpoints (heapdump, env, etc.) using actuatoRust")]
    actuator_scan: bool,

    /// Enable GraphQL introspection scanning
    #[arg(long, help_heading = "Info Disclosure",
          help = "Scan for GraphQL endpoints and extract schemas using clairvoyance")]
    graphql_scan: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // BRUTEFORCE OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable bruteforce on login pages
    #[arg(long, help_heading = "Bruteforce",
          help = "Enable login form detection and credential bruteforce")]
    bruteforce: bool,

    /// Path to username wordlist for bruteforce
    #[arg(long, value_name = "FILE", help_heading = "Bruteforce",
          help = "Username wordlist for login bruteforce (required with --bruteforce)")]
    userlist: Option<String>,

    /// Path to password wordlist for bruteforce
    #[arg(long, value_name = "FILE", help_heading = "Bruteforce",
          help = "Password wordlist for login bruteforce (required with --bruteforce)")]
    passlist: Option<String>,

    // ═══════════════════════════════════════════════════════════════════════════
    // NOTIFICATION OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Discord webhook URL for real-time notifications
    #[arg(long, value_name = "URL", help_heading = "Notifications",
          help = "Discord webhook URL for critical findings (admin panels, vulns, credentials)")]
    discord_webhook: Option<String>,

    // ═══════════════════════════════════════════════════════════════════════════
    // OUTPUT & PERFORMANCE OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Export results in JSON format
    #[arg(long, help_heading = "Output",
          help = "Export all scan results in JSON format")]
    json: bool,

    /// Number of concurrent workers
    #[arg(long, default_value = "10", value_name = "NUM", help_heading = "Performance",
          help = "Number of concurrent workers for async operations (default: 10, max recommended: 100)")]
    workers: usize,

    // ═══════════════════════════════════════════════════════════════════════════
    // TOOL MANAGEMENT OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Install all required external tools
    #[arg(long, help_heading = "Tool Management",
          help = "Install all required tools (httpx, nuclei, subfinder, masscan, etc.)")]
    install_tools: bool,

    /// Check which tools are installed
    #[arg(long, help_heading = "Tool Management",
          help = "Check which required tools are installed and their versions")]
    check_tools: bool,

    /// Force re-validation of tools (clear cache)
    #[arg(long, help_heading = "Tool Management",
          help = "Force re-discovery and re-validation of all tools (clears cache)")]
    revalidate_tools: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // WPSCAN OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// WPScan API token for vulnerability data (optional, enhances results)
    #[arg(long, value_name = "TOKEN", help_heading = "WPScan",
          help = "WPScan API token for vulnerability database (get free token at https://wpscan.com)")]
    wpscan_token: Option<String>,

    /// Disable WordPress scanning even if WordPress is detected
    #[arg(long, help_heading = "WPScan",
          help = "Skip WordPress vulnerability scanning (WPScan) even if WordPress sites are detected")]
    no_wpscan: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // IIS SHORT FILENAME SCANNING
    // ═══════════════════════════════════════════════════════════════════════════

    /// Disable IIS short filename scanning (shortscan)
    #[arg(long, help_heading = "Shortscan",
          help = "Skip IIS short filename scanning (shortscan) even if IIS servers are detected")]
    no_shortscan: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // UPDATE OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Skip auto-update check on startup
    #[arg(long, help_heading = "Tool Management",
          help = "Skip automatic update check on startup")]
    no_update: bool,

    /// Check for updates and exit
    #[arg(long, help_heading = "Tool Management",
          help = "Check for updates from GitHub and apply if available")]
    check_update: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // AI ANALYSIS OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enable Ollama AI analysis for false positive filtering
    #[arg(long, help_heading = "AI Analysis",
          help = "Use Ollama AI to filter false positives in scan results (requires Ollama running on localhost:11434)")]
    ollama: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // MCP SERVER OPTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Start EnumRust as an MCP server for AI assistants (Claude Code, etc.)
    #[arg(long, help_heading = "MCP Server",
          help = "Start EnumRust as an MCP server via stdio. Enables AI assistants to invoke security scans programmatically")]
    mcp: bool,

}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Print banner
    print_banner();

    // ═══════════════════════════════════════════════════════════════════════════
    // MCP SERVER MODE
    // ═══════════════════════════════════════════════════════════════════════════
    if args.mcp {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".cyan().bold());
        println!("{}", "║                        MCP SERVER MODE                                      ║".cyan().bold());
        println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".cyan().bold());
        println!("{}", "║  Para usar EnumRust como servidor MCP, execute o binário separado:          ║".cyan());
        println!();
        println!("{}", "║    cargo run --package enumrust_mcp                                        ║".yellow());
        println!();
        println!("{}", "║  Ou compile e execute:                                                      ║".cyan());
        println!("{}", "║    cargo build --release --package enumrust_mcp                            ║".yellow());
        println!("{}", "║    ./target/release/enumrust-mcp                                           ║".yellow());
        println!();
        println!("{}", "║  Isso inicia um servidor MCP via stdio para integração com AI assistants    ║".cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".cyan().bold());
        println!();
        return Ok(());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AUTO-UPDATE CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    if args.check_update {
        update_checker::check_and_update_force().await;
        return Ok(());
    }

    if !args.no_update {
        update_checker::check_and_update().await;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TOOL MANAGEMENT: Install or check tools
    // ═══════════════════════════════════════════════════════════════════════════
    if args.check_tools {
        check_tools_status().await;
        return Ok(());
    }

    if args.install_tools {
        invalidate_tools_cache();
        install_all_tools().await?;
        return Ok(());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // VALIDATION: Require --haktrails or --subfinder for domain scans
    // ═══════════════════════════════════════════════════════════════════════════
    if args.domain.is_some() || args.file.is_some() {
        // Only validate if not in full_scan mode (which enables both)
        if !args.full_scan && !args.hacktrails && !args.subfinder {
            eprintln!("{}", "".red());
            eprintln!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".red().bold());
            eprintln!("{}", "║                      ERRO: SUBDOMAIN DISCOVERY REQUIRED                      ║".red().bold());
            eprintln!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".red().bold());
            eprintln!("{}", "║  Você DEVE especificar pelo menos uma ferramenta de subdomain discovery:     ║".red());
            eprintln!("{}", "║                                                                              ║".red());
            eprintln!("{}", "║    --hacktrails   Use haktrails (SecurityTrails) para subdomain discovery    ║".yellow());
            eprintln!("{}", "║    --subfinder    Use subfinder para passive subdomain discovery             ║".yellow());
            eprintln!("{}", "║    --full-scan    Habilita AMBAS as ferramentas automaticamente              ║".green());
            eprintln!("{}", "║                                                                              ║".red());
            eprintln!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".red().bold());
            eprintln!("{}", "║  EXEMPLOS:                                                                   ║".cyan());
            eprintln!("{}", "║    enumrust -d example.com --hacktrails                                      ║".cyan());
            eprintln!("{}", "║    enumrust -d example.com --subfinder                                       ║".cyan());
            eprintln!("{}", "║    enumrust -d example.com --hacktrails --subfinder                          ║".cyan());
            eprintln!("{}", "║    enumrust -d example.com --full-scan                                       ║".green());
            eprintln!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".red().bold());
            eprintln!();
            std::process::exit(1);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TOOL VALIDATION: Auto-discover tools and validate before scan
    // ═══════════════════════════════════════════════════════════════════════════
    if args.domain.is_some() || args.file.is_some() {
        validate_tools_before_scan(&args).await?;
    }

    // Mode selection: file or single domain scan
    if let Some(ref file_path) = args.file {
        // Process multiple domains from file
        println!("{}", format!("[*] Processing domains from file: {}", file_path).cyan().bold());
        process_domains_from_file(file_path, &args).await?;
    } else if let Some(ref raw_domain) = args.domain {
        let domain = normalize_domain(raw_domain).unwrap_or_else(|| {
            eprintln!("{}", "[ERROR] Invalid domain provided in --domain".red().bold());
            eprintln!("{}", format!("  Input: {}", raw_domain).yellow());
            eprintln!("{}", "  Use only valid hostnames (e.g. example.com)".yellow());
            std::process::exit(1);
        });

        // ═══════════════════════════════════════════════════════════════════════════
        // TMUX AUTO-START: Se não estiver em tmux, criar sessão automaticamente
        // ═══════════════════════════════════════════════════════════════════════════
        if !is_running_in_tmux() && !is_running_in_docker() {
            println!("{}", "🔍 Detectado scan CLI - Iniciando em modo TMUX persistente...".cyan().bold());
            println!("{}", "   Isso garante que o scan continue mesmo se você desconectar SSH!".cyan());
            println!();

            let session_name = format!("enumrust-{}", domain.replace('.', "-"));

            // Verificar se tmux está instalado
            if !is_tmux_installed() {
                println!("{}", "⚠️  AVISO: tmux não está instalado!".yellow().bold());
                println!("{}", "   O scan rodará normalmente, mas será interrompido se desconectar SSH.".yellow());
                println!("{}", "   Instale tmux com: apt-get install tmux".yellow());
                println!();

                // Continuar sem tmux
            } else {
                // Verificar se já existe sessão com este nome
                let session_exists = Command::new("tmux")
                    .args(["has-session", "-t", &session_name])
                    .output()
                    .await?
                    .status
                    .success();

                if session_exists {
                    println!("{}", format!("⚠️  Sessão tmux '{}' já existe!", session_name).yellow().bold());
                    println!();
                    println!("{}", "Opções:".cyan());
                    println!("{}", format!("  1) Conectar à sessão existente: tmux attach -t {}", session_name).cyan());
                    println!("{}", format!("  2) Matar sessão antiga:         tmux kill-session -t {}", session_name).cyan());
                    println!("{}", "  3) Cancelar (Ctrl+C)".cyan());
                    println!();
                    std::process::exit(1);
                }

                // Reconstruir argumentos da linha de comando
                let current_exe = std::env::current_exe()
                    .context("Failed to get current executable path")?;

                let mut cmd_args = vec![
                    "-d".to_string(),
                    domain.clone(),
                ];

                if args.full_scan {
                    cmd_args.push("--full-scan".to_string());
                }
                if args.subfinder {
                    cmd_args.push("--subfinder".to_string());
                }
                if args.hacktrails {
                    cmd_args.push("--hacktrails".to_string());
                }
                if args.whois {
                    cmd_args.push("--whois".to_string());
                }
                if args.bruteforce {
                    cmd_args.push("--bruteforce".to_string());
                }
                if let Some(ref userlist) = args.userlist {
                    cmd_args.push("--userlist".to_string());
                    cmd_args.push(userlist.clone());
                }
                if let Some(ref passlist) = args.passlist {
                    cmd_args.push("--passlist".to_string());
                    cmd_args.push(passlist.clone());
                }
                if args.workers != 10 {
                    cmd_args.push("--workers".to_string());
                    cmd_args.push(args.workers.to_string());
                }
                if args.json {
                    cmd_args.push("--json".to_string());
                }
                if args.ip_scan {
                    cmd_args.push("--ip-scan".to_string());
                }
                if args.ip_full_scan {
                    cmd_args.push("--ip-full-scan".to_string());
                }
                if args.ip_ports != "top1000" {
                    cmd_args.push("--ip-ports".to_string());
                    cmd_args.push(args.ip_ports.clone());
                }
                if args.ip_fuzz_depth != 2 {
                    cmd_args.push("--ip-fuzz-depth".to_string());
                    cmd_args.push(args.ip_fuzz_depth.to_string());
                }
                if let Some(ref wordlist) = args.ip_wordlist {
                    cmd_args.push("--ip-wordlist".to_string());
                    cmd_args.push(wordlist.clone());
                }
                if args.ip_fuzz_timeout != 60 {
                    cmd_args.push("--ip-fuzz-timeout".to_string());
                    cmd_args.push(args.ip_fuzz_timeout.to_string());
                }
                if args.no_wpscan {
                    cmd_args.push("--no-wpscan".to_string());
                }
                if args.no_shortscan {
                    cmd_args.push("--no-shortscan".to_string());
                }
                if let Some(ref token) = args.wpscan_token {
                    cmd_args.push("--wpscan-token".to_string());
                    cmd_args.push(token.clone());
                }
                let cmd_string = format!("{} {}", current_exe.display(), cmd_args.join(" "));

                // Criar sessão tmux e executar comando dentro dela
                println!("{}", format!("🚀 Criando sessão TMUX: {}", session_name).green().bold());
                println!("{}", format!("📋 Comando: {}", cmd_string).cyan());
                println!();

                let tmux_cmd = format!(
                    "cd {} && TMUX_SESSION_ACTIVE=1 {} ; echo ''; echo '═══════════════════════════════════════════════════════════════'; if [ $? -eq 0 ]; then echo '✅ Scan completo com sucesso!'; else echo '❌ Scan terminou com erros'; fi; echo '═══════════════════════════════════════════════════════════════'; echo ''; echo 'Resultados salvos em: {}/'; echo ''; echo 'Pressione ENTER para fechar esta sessão...'; read",
                    std::env::current_dir()?.display(),
                    cmd_string,
                    domain
                );

                let tmux_status = Command::new("tmux")
                    .args([
                        "new-session",
                        "-d",
                        "-s",
                        &session_name,
                        &tmux_cmd,
                    ])
                    .status()
                    .await?;

                if tmux_status.success() {
                    println!("{}", "✅ Sessão TMUX criada com sucesso!".green().bold());
                    println!();
                    println!("{}", "🔥 IMPORTANTE: O scan está rodando em BACKGROUND".yellow().bold());
                    println!("{}", "   Mesmo se você fechar o SSH, ele continua rodando!".yellow());
                    println!();
                    println!("{}", "📋 Comandos úteis:".cyan().bold());
                    println!("{}", format!("   Ver logs ao vivo:  tmux attach -t {}", session_name).cyan());
                    println!("{}", "   Sair sem parar:    Ctrl+B depois D".cyan());
                    println!("{}", format!("   Parar scan:        tmux kill-session -t {}", session_name).cyan());
                    println!("{}", "   Listar sessões:    tmux ls".cyan());
                    println!();
                    println!("{}", format!("📂 Resultados serão salvos em: ./{}/", domain).green());
                    println!();

                    // Sair sem executar o scan aqui (ele está rodando no tmux)
                    std::process::exit(0);
                } else {
                    println!("{}", "❌ ERRO: Falha ao criar sessão tmux".red().bold());
                    println!("{}", "   Continuando sem tmux...".yellow());
                    println!();
                }
            }
        }
        // Run domain scan mode
        println!("{}", format!("[*] Starting domain scan for: {}", domain).green().bold());
        process_domain(&domain, &args).await?;
    } else {
        // No mode specified
        eprintln!("{}", "[ERROR] Please specify --domain or --file".red().bold());
        eprintln!("{}", "Usage:".yellow());
        eprintln!("  enumrust --domain example.com --subfinder");
        eprintln!("  enumrust --file domains.txt --full-scan");
        std::process::exit(1);
    }

    Ok(())
}

/// Check if currently running inside a tmux session
fn is_running_in_tmux() -> bool {
    // Verificar variável de ambiente TMUX (indica que está em tmux)
    if std::env::var("TMUX").is_ok() {
        return true;
    }

    // Verificar flag customizada (usada quando re-executamos dentro do tmux)
    if std::env::var("TMUX_SESSION_ACTIVE").is_ok() {
        return true;
    }

    false
}

/// Check if running inside a Docker container
fn is_running_in_docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
}

/// Check if tmux is installed
fn is_tmux_installed() -> bool {
    std::process::Command::new("which")
        .arg("tmux")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Normalize and validate domain input to avoid command injection and path traversal.
fn normalize_domain(input: &str) -> Option<String> {
    let domain = input.trim().trim_end_matches('.').to_lowercase();

    // Basic FQDN constraints
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return None;
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }

    Some(domain)
}

/// Print application banner
fn print_banner() {
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!("{}", "  ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗███████╗████████╗".cyan().bold());
    println!("{}", "  ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗██║   ██║██╔════╝╚══██╔══╝".cyan().bold());
    println!("{}", "  █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝██║   ██║███████╗   ██║   ".cyan().bold());
    println!("{}", "  ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ".cyan().bold());
    println!("{}", "  ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║╚██████╔╝███████║   ██║   ".cyan().bold());
    println!("{}", "  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!("{}", format!("  EnumRust v{} - Advanced Security Reconnaissance", env!("CARGO_PKG_VERSION")).white().bold());
    println!("{}", "  Offensive Security | OSINT | Vulnerability Assessment".white());
    println!("{}", "═══════════════════════════════════════════════════════════════\n".cyan().bold());
}

/// Process multiple domains from a file
async fn process_domains_from_file(file_path: &str, args: &Args) -> Result<()> {
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", format!("📋 Reading domains from: {}", file_path).yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════\n".yellow().bold());

    // Create base output directory for all domains from this file
    let file_stem = Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("domains");
    let base_output_dir = format!("file_domains_{}", file_stem);

    fs::create_dir_all(&base_output_dir)
        .context(format!("Failed to create base output directory: {}", base_output_dir))?;

    println!("{}", format!("📁 Output directory: {}/", base_output_dir).cyan().bold());
    println!();

    // Read file
    let file = File::open(file_path)
        .context(format!("Failed to open file: {}", file_path))?;
    let reader = BufReader::new(file);

    // Parse domains
    let mut domains = Vec::new();
    let mut seen = HashSet::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context(format!("Failed to read line {} from file", line_num + 1))?;
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(normalized_domain) = normalize_domain(trimmed) else {
            eprintln!(
                "{}",
                format!(
                    "[!] Skipping invalid domain at line {}: {}",
                    line_num + 1,
                    trimmed
                )
                .yellow()
            );
            continue;
        };

        if seen.insert(normalized_domain.clone()) {
            domains.push(normalized_domain);
        }
    }

    if domains.is_empty() {
        eprintln!("{}", "[ERROR] No valid domains found in file".red().bold());
        eprintln!("{}", "  Make sure the file contains one domain per line".yellow());
        eprintln!("{}", "  Lines starting with # are treated as comments".yellow());
        std::process::exit(1);
    }

    println!("{}", format!("✅ Found {} domain(s) to process", domains.len()).green().bold());
    println!();

    // Display domains
    println!("{}", "📝 Domains to scan:".cyan().bold());
    for (idx, domain) in domains.iter().enumerate() {
        println!("  {}. {}", idx + 1, domain.white());
    }
    println!();

    // Process statistics
    let total_domains = domains.len();
    let mut successful = 0;
    let mut failed = 0;

    // Process each domain
    for (idx, domain) in domains.iter().enumerate() {
        println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
        println!("{}", format!("🔍 Processing domain [{}/{}]: {}", idx + 1, total_domains, domain).cyan().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════\n".cyan().bold());

        match process_domain_with_base_dir(domain, args, &base_output_dir).await {
            Ok(_) => {
                successful += 1;
                println!("{}", format!("✅ Domain {} completed successfully\n", domain).green().bold());
            }
            Err(e) => {
                failed += 1;
                eprintln!("{}", format!("❌ Domain {} failed: {}\n", domain, e).red().bold());
            }
        }
    }

    // Print summary
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "📊 SCAN SUMMARY".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", format!("Total domains:     {}", total_domains).white());
    println!("{}", format!("✅ Successful:      {}", successful).green());
    println!("{}", format!("❌ Failed:          {}", failed).red());
    println!("{}", "═══════════════════════════════════════════════════════════════\n".yellow().bold());

    if failed > 0 {
        eprintln!("{}", "⚠️  Some scans failed. Check the output above for details.".yellow());
    }

    // Display all nuclei vulnerabilities found across all scanned domains
    display_nuclei_vulnerabilities(&base_output_dir).await?;

    Ok(())
}

/// Process domain scan with custom base directory (for -f file mode)
async fn process_domain_with_base_dir(domain: &str, args: &Args, base_output_dir: &str) -> Result<()> {
    let base_path = PathBuf::from(base_output_dir).join(domain);
    process_domain_impl(domain, args, base_path).await
}

/// Process domain scan with all stages
async fn process_domain(domain: &str, args: &Args) -> Result<()> {
    let base_path = PathBuf::from(domain);
    process_domain_impl(domain, args, base_path).await
}

/// Internal implementation of domain scanning
async fn process_domain_impl(domain: &str, args: &Args, base_path: PathBuf) -> Result<()> {
    // Initialize metrics
    let mut metrics = EnumRustMetrics::new_web_scan(domain.to_string());

    // Create output directory
    fs::create_dir_all(&base_path)
        .context(format!("Failed to create output directory: {}", base_path.display()))?;

    // Create files_ subdirectory for tool outputs
    let files_dir = base_path.join("files_");
    fs::create_dir_all(&files_dir)
        .context(format!("Failed to create files directory: {}", files_dir.display()))?;

    // Initialize progress tracker
    let scan_id = uuid::Uuid::new_v4().to_string();
    let progress = ProgressTracker::new(scan_id.clone(), domain.to_string(), base_path.clone());
    progress.scan_started();

    println!("{}", format!("[*] Output directory: {}/", base_path.display()).cyan());
    println!("{}", format!("[*] Scan ID: {}", scan_id).cyan());

    // Initialize HTTP client (async)
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Initialize Ollama AI client (auto-installs, auto-starts, auto-pulls model)
    let ollama = ollama::OllamaClient::new().await;

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 1: WHOIS LOOKUP (Optional, 0-5%)
    // ═══════════════════════════════════════════════════════════════════════════
    if args.whois {
        println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
        println!("{}", "  STAGE 1: WHOIS LOOKUP (0-5%)".yellow().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

        progress.add_event(
            EventType::ToolStarted {
                tool_name: "WHOIS".to_string(),
            },
            "Starting WHOIS lookup...".to_string(),
            0.0,
            None,
        );

        let whois_file = base_path.join("whois_ips.txt");
        println!("{}", format!("[*] Running WHOIS lookup for domain: {}", domain).cyan());

        let whois_status = Command::new("sh")
            .arg("-c")
            .arg(format!("whois {} > {}", domain, whois_file.display()))
            .status()
            .await?;

        if whois_status.success() {
            progress.tool_completed("WHOIS", 5.0);
            println!("{}", format!("[+] WHOIS results saved to: {}", whois_file.display()).green());
        } else {
            progress.tool_failed("WHOIS", "Command failed", 5.0);
            println!("{}", "[!] WHOIS lookup failed".yellow());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 2: SUBDOMAIN ENUMERATION (5-30%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 2: SUBDOMAIN ENUMERATION (5-30%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    let subdomains_file = base_path.join("subdomains.txt");

    // Create empty subdomains file
    File::create(&subdomains_file)?;

    // Haktrails (if enabled)
    if args.hacktrails || args.full_scan {
        progress.tool_started("haktrails");
        println!("{}", "[*] Running haktrails for subdomain discovery...".cyan());

        let haktrails_status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "echo {} | haktrails subdomains | anew {}",
                domain,
                subdomains_file.display()
            ))
            .status()
            .await?;

        if haktrails_status.success() {
            progress.tool_completed("haktrails", 15.0);
            let count = count_lines(&subdomains_file)?;
            println!("{}", format!("[+] Haktrails found {} subdomains", count).green());
        } else {
            progress.tool_failed("haktrails", "Command failed", 15.0);
            println!("{}", "[!] Haktrails failed (command not found or error)".yellow());
        }
    }

    // Subfinder (if enabled)
    if args.subfinder || args.full_scan {
        progress.tool_started("subfinder");
        println!("{}", "[*] Running subfinder for subdomain discovery...".cyan());

        let subfinder_status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "subfinder -d {} -silent | anew {}",
                domain,
                subdomains_file.display()
            ))
            .status()
            .await?;

        if subfinder_status.success() {
            progress.tool_completed("subfinder", 22.0);
            let count = count_lines(&subdomains_file)?;
            println!("{}", format!("[+] Subfinder results added (total: {})", count).green());
        } else {
            progress.tool_failed("subfinder", "Command failed", 22.0);
            println!("{}", "[!] Subfinder failed (command not found or error)".yellow());
        }
    }

    // TLSX - Certificate SAN extraction
    progress.tool_started("tlsx");
    println!("{}", "[*] Extracting certificate SANs with tlsx...".cyan());

    let tlsx_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | tlsx -json -silent | jq -r '.subject_an[] | ltrimstr(\"*.\")' | anew {}",
            domain,
            subdomains_file.display()
        ))
        .status()
        .await?;

    if tlsx_status.success() {
        progress.tool_completed("tlsx", 30.0);
        println!("{}", "[+] Certificate SANs extracted".green());
    } else {
        progress.tool_failed("tlsx", "Command failed or no results", 30.0);
        println!("{}", "[!] TLSX extraction failed or no certificates found".yellow());
    }

    // Native passive OSINT sources (no external binaries required)
    progress.tool_started("passive-osint");
    println!("{}", "[*] Enriching subdomains with native passive sources (crt.sh, bufferover)...".cyan());
    let passive_candidates = fetch_native_passive_subdomains(&client, domain).await;
    match passive_candidates {
        Ok(candidates) => {
            let mut merged = read_normalized_subdomains(&subdomains_file, domain)?;
            merged.insert(domain.to_ascii_lowercase());
            let before = merged.len();
            for candidate in candidates {
                if let Some(normalized) = normalize_subdomain_candidate(&candidate, domain) {
                    merged.insert(normalized);
                }
            }
            write_subdomains_sorted(&subdomains_file, &merged)?;
            let added = merged.len().saturating_sub(before);
            progress.tool_completed("passive-osint", 28.0);
            println!("{}", format!("[+] Native passive sources added {} unique subdomains", added).green());
        }
        Err(err) => {
            progress.tool_failed("passive-osint", &err.to_string(), 28.0);
            println!("{}", format!("[!] Native passive enrichment failed: {}", err).yellow());
        }
    }

    // Archive URL sources (gau/waybackurls) -> host extraction
    progress.tool_started("archive-osint");
    println!("{}", "[*] Mining subdomains from historical URL archives (gau, waybackurls)...".cyan());
    let archive_candidates = collect_archive_subdomain_candidates(domain).await;
    match archive_candidates {
        Ok(candidates) => {
            let mut merged = read_normalized_subdomains(&subdomains_file, domain)?;
            let before = merged.len();
            for candidate in candidates {
                if let Some(normalized) = normalize_subdomain_candidate(&candidate, domain) {
                    merged.insert(normalized);
                }
            }
            write_subdomains_sorted(&subdomains_file, &merged)?;
            let added = merged.len().saturating_sub(before);
            progress.tool_completed("archive-osint", 29.0);
            println!("{}", format!("[+] Archive sources added {} unique subdomains", added).green());
        }
        Err(err) => {
            progress.tool_failed("archive-osint", &err.to_string(), 29.0);
            println!("{}", format!("[!] Archive enrichment failed: {}", err).yellow());
        }
    }

    // Active DNS bruteforce for high-yield names (full-scan mode only)
    if args.full_scan {
        progress.tool_started("dns-bruteforce");
        println!("{}", "[*] Running DNS bruteforce for common subdomain names...".cyan());
        match brute_force_common_subdomains(domain, args.workers).await {
            Ok(found) => {
                let mut merged = read_normalized_subdomains(&subdomains_file, domain)?;
                let before = merged.len();
                for host in found {
                    merged.insert(host);
                }
                write_subdomains_sorted(&subdomains_file, &merged)?;
                let added = merged.len().saturating_sub(before);
                progress.tool_completed("dns-bruteforce", 29.5);
                println!("{}", format!("[+] DNS bruteforce added {} valid subdomains", added).green());
            }
            Err(err) => {
                progress.tool_failed("dns-bruteforce", &err.to_string(), 29.5);
                println!("{}", format!("[!] DNS bruteforce failed: {}", err).yellow());
            }
        }
    }

    // Final normalization and deduplication pass before DNS resolution
    let mut final_set = read_normalized_subdomains(&subdomains_file, domain)?;
    final_set.insert(domain.to_ascii_lowercase());
    write_subdomains_sorted(&subdomains_file, &final_set)?;

    // Count total subdomains found
    let total_subdomains = final_set.len();
    progress.data_found("subdomains", total_subdomains, 30.0);
    println!("{}", format!("[+] Total unique subdomains found: {}", total_subdomains).green().bold());

    // Update metrics
    if let Some(ref mut web_metrics) = metrics.web_metrics {
        web_metrics.total_subdomains = total_subdomains;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 3: DNS RESOLUTION (30-40%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 3: DNS RESOLUTION (30-40%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("dnsx");
    println!("{}", "[*] Resolving subdomains to IPs with dnsx...".cyan());

    let ips_file = base_path.join("ips.txt");
    let dnsx_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | dnsx -a -resp-only -silent -o {}",
            subdomains_file.display(),
            ips_file.display()
        ))
        .status()
        .await?;

    if dnsx_status.success() {
        progress.tool_completed("dnsx", 40.0);
        let ip_count = count_lines(&ips_file)?;
        progress.data_found("unique IPs", ip_count, 40.0);
        println!("{}", format!("[+] Resolved {} unique IP addresses", ip_count).green());

        if let Some(ref mut web_metrics) = metrics.web_metrics {
            web_metrics.total_unique_ips = ip_count;
        }
    } else {
        progress.tool_failed("dnsx", "Resolution failed", 40.0);
        println!("{}", "[!] DNS resolution failed".yellow());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 3.5: IP PORT SCANNING + DIRECTORY FUZZING (Optional)
    // ═══════════════════════════════════════════════════════════════════════════
    if args.ip_scan || args.full_scan {
        println!("\n{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
        println!("{}", "  STAGE 3.5: IP SCANNING + DIRECTORY FUZZING (40-48%)".magenta().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());

        // ═══════════════════════════════════════════════════════════════════
        // IP FILTERING - Remove CDN IPs (Cloudflare, AWS, Akamai, etc.)
        // ═══════════════════════════════════════════════════════════════════
        let scan_ips_file = if args.ip_filter || args.ip_strict {
            println!("\n{}", "─── IP FILTERING ───".yellow().bold());
            println!("{}", "[*] Filtering IPs: removing CDN/Cloud providers...".cyan());
            if args.ip_strict {
                println!("{}", "[*] Strict mode: only IPs with reverse DNS matching domain".cyan().bold());
            }

            // Filter IPs and save to filtered file
            let filtered_ips_file = base_path.join("ips_filtered.txt");
            match ip_validator::filter_ips_for_domain(&ips_file, domain, args.ip_strict).await {
                Ok(filtered_ips) => {
                    if filtered_ips.is_empty() {
                        println!("{}", "[!] No valid IPs after filtering. Skipping IP scan.".yellow());
                        println!("{}", "[!] All IPs are from CDN/Cloud providers or don't belong to the domain.".yellow());
                        // Skip to next stage
                        base_path.join("ips_empty.txt") // Non-existent file to skip scan
                    } else {
                        // Save filtered IPs
                        if let Err(e) = ip_validator::save_filtered_ips(&filtered_ips, &filtered_ips_file) {
                            println!("{}", format!("[!] Failed to save filtered IPs: {}", e).yellow());
                            ips_file.clone()
                        } else {
                            println!("{}", format!("[+] {} IPs válidos para scan (salvos em ips_filtered.txt)", filtered_ips.len()).green().bold());
                            filtered_ips_file
                        }
                    }
                }
                Err(e) => {
                    println!("{}", format!("[!] IP filtering failed: {}. Using unfiltered IPs.", e).yellow());
                    ips_file.clone()
                }
            }
        } else {
            ips_file.clone()
        };

        progress.tool_started("IP Scanner");
        println!("{}", "[*] Starting IP port scanning and directory fuzzing...".cyan());
        println!("{}", "[*] Filter: Only HTTP 200 responses will be reported".cyan().bold());

        // Configure IP scan with optimized threads
        let optimal_threads = ip_scanner::get_optimal_threads();
        let ip_scan_config = ip_scanner::IpScanConfig {
            ports: if args.ip_full_scan {
                "1-65535".to_string()
            } else if args.ip_ports == "top1000" {
                ip_scanner::get_top_1000_ports()
            } else {
                args.ip_ports.clone()
            },
            rate: if args.ip_full_scan { 10000 } else { 1000 },
            threads: optimal_threads.max(args.workers),
            depth: args.ip_fuzz_depth,
            wordlist: args.ip_wordlist.clone(),
            timeout: 10,
            fuzz_timeout_per_ip: args.ip_fuzz_timeout,
        };

        println!("{}", format!("[*] Threads otimizadas: {} (baseado nos recursos do sistema)", ip_scan_config.threads).cyan());

        // Run IP scan with filtered IPs
        let ip_scan_results = ip_scanner::scan_ips_and_fuzz(
            &scan_ips_file,
            &ip_scan_config,
            &base_path,
            &client,
        )
        .await;

        match ip_scan_results {
            Ok(results) => {
                progress.tool_completed("IP Scanner", 48.0);

                let total_ports: usize = results.iter().map(|r| r.open_ports.len()).sum();
                let total_paths: usize = results.iter().map(|r| r.discovered_paths.len()).sum();

                progress.data_found("IP open ports", total_ports, 45.0);
                progress.data_found("IP directories (200)", total_paths, 48.0);

                println!("{}", format!("[+] IP Scan completed: {} IPs scanned", results.len()).green());
                println!("{}", format!("[+] Total open ports: {}", total_ports).green());
                println!("{}", format!("[+] Total paths found (HTTP 200): {}", total_paths).green().bold());

                // Update metrics
                if let Some(ref mut web_metrics) = metrics.web_metrics {
                    web_metrics.total_unique_ips = results.len();
                }
            }
            Err(e) => {
                progress.tool_failed("IP Scanner", &e.to_string(), 48.0);
                println!("{}", format!("[!] IP scanning failed: {}", e).yellow());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 4: DOMAIN VALIDATION WITH TRUST-DNS-RESOLVER (48-52%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 4: DOMAIN VALIDATION (48-52%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("DNS Validator");
    println!("{}", "[*] Validating domains with trust-dns-resolver...".cyan());

    // Read subdomains
    let subdomains: Vec<String> = if subdomains_file.exists() {
        fs::read_to_string(&subdomains_file)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let validated_hosts = ip_validator::validate_domains_batch(subdomains, args.workers).await;
    let resolvable_count = validated_hosts.iter().filter(|h| h.is_resolvable).count();
    let non_resolvable_count = validated_hosts.len() - resolvable_count;

    // Save validated hosts
    let validated_hosts_file = base_path.join("validated_hosts.json");
    ip_validator::save_validated_hosts(&validated_hosts, &validated_hosts_file)?;

    progress.tool_completed("DNS Validator", 48.0);
    progress.data_found("validated hosts", resolvable_count, 48.0);
    println!(
        "{}",
        format!(
            "[+] Validated {} domains: {} resolvable, {} non-resolvable",
            validated_hosts.len(),
            resolvable_count,
            non_resolvable_count
        )
        .green()
    );
    println!("{}", format!("[+] Results saved to: {}", validated_hosts_file.display()).green());

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 5: PORT SCANNING (48-60%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 5: PORT SCANNING (48-60%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    // Masscan port scan
    progress.tool_started("masscan");
    println!("{}", "[*] Scanning ports with masscan (this may take a while)...".cyan());

    let masscan_file = base_path.join("masscan.txt");
    let masscan_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "sudo masscan -iL {} --ports 1-65535 --rate 10000 -oL {} 2>/dev/null || echo 'masscan failed'",
            ips_file.display(),
            masscan_file.display()
        ))
        .status()
        .await?;

    if masscan_status.success() && masscan_file.exists() {
        progress.tool_completed("masscan", 55.0);
        let port_count = count_lines(&masscan_file)?;
        println!("{}", format!("[+] Masscan completed: {} port entries found", port_count).green());
    } else {
        progress.tool_failed("masscan", "Command failed or requires sudo", 55.0);
        println!("{}", "[!] Masscan failed (requires sudo or not installed)".yellow());
    }

    // Validate open ports with httpx
    progress.tool_started("httpx-port-validation");
    println!("{}", "[*] Validating open ports with httpx...".cyan());

    let ports_file = base_path.join("ports.txt");
    if masscan_file.exists() {
        let httpx_port_status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                r#"cat {} | awk '/open/ {{print $4 ":" $3}}' | httpx -silent -o {}"#,
                masscan_file.display(),
                ports_file.display()
            ))
            .status()
            .await?;

        if httpx_port_status.success() {
            progress.tool_completed("httpx-port-validation", 60.0);
            let validated_ports = count_lines(&ports_file)?;
            println!("{}", format!("[+] Validated {} open ports", validated_ports).green());
        } else {
            progress.tool_failed("httpx-port-validation", "Validation failed", 60.0);
            println!("{}", "[!] Port validation failed".yellow());
        }
    } else {
        progress.tool_failed("httpx-port-validation", "No masscan results", 60.0);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 6: HTTP VALIDATION (60-70%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 6: HTTP VALIDATION (60-70%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("httpx");
    println!("{}", "[*] Resolving alive hosts with httpx...".cyan());

    let http200_file = base_path.join("http200.txt");
    let _http403_file = base_path.join("http403.txt");

    let httpx_status = Command::new("httpx")
        .args([
            "-silent",
            "-follow-redirects",
            "-max-redirects",
            "10",
            "-list",
            &subdomains_file.to_string_lossy(),
            "-o",
            &http200_file.to_string_lossy(),
        ])
        .status()
        .await?;

    if httpx_status.success() {
        progress.tool_completed("httpx", 70.0);
        let http200_count = count_lines(&http200_file)?;
        progress.data_found("HTTP 200 responses", http200_count, 70.0);
        println!("{}", format!("[+] Found {} alive hosts (HTTP 200)", http200_count).green());

        if let Some(ref mut web_metrics) = metrics.web_metrics {
            web_metrics.total_urls_crawled = http200_count;
            *web_metrics.status_codes.entry(200).or_insert(0) = http200_count;
        }
    } else {
        progress.tool_failed("httpx", "HTTP validation failed", 70.0);
        println!("{}", "[!] HTTP validation failed".yellow());
    }

    // Run URLFinder for deeper URL discovery
    println!("{}", "[*] Discovering URLs with URLFinder...".cyan());
    let urlfinder_file = base_path.join("urlfinder.txt");

    if http200_file.exists() {
        let urlfinder_status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cat {} | hakrawler -d 2 -u -subs | anew {}",
                http200_file.display(),
                urlfinder_file.display()
            ))
            .status()
            .await?;

        if urlfinder_status.success() {
            let url_count = count_lines(&urlfinder_file)?;
            println!("{}", format!("[+] URLFinder discovered {} URLs", url_count).green());
        } else {
            println!("{}", "[!] URLFinder failed or not installed".yellow());
        }
    }

    // Read HTTP200 URLs for later stages
    let http200_urls: Vec<String> = if http200_file.exists() {
        fs::read_to_string(&http200_file)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 6.5: JS FILE DISCOVERY WITH FFUF (68-70%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 6.5: JS FILE DISCOVERY (68-70%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("ffuf JS Discovery");
    println!("{}", "[*] Discovering JavaScript files with ffuf...".cyan());

    // Create JS paths wordlist
    let js_wordlist_file = base_path.join("js_paths_wordlist.txt");
    let js_paths = vec![
        "app.js", "main.js", "bundle.js", "vendor.js", "chunk.js",
        "app.min.js", "main.min.js", "bundle.min.js",
        "js/app.js", "js/main.js", "js/bundle.js", "js/vendor.js",
        "static/js/main.js", "static/js/app.js", "static/js/bundle.js",
        "assets/js/app.js", "assets/js/main.js", "assets/js/bundle.js",
        "dist/js/app.js", "dist/js/main.js", "dist/js/bundle.js",
        "build/js/app.js", "build/js/main.js",
        "scripts/app.js", "scripts/main.js", "scripts/bundle.js",
        "webpack/bundle.js", "webpack/app.js",
        "public/js/app.js", "public/js/main.js",
        "common.js", "config.js", "utils.js", "helpers.js",
        "lib/jquery.js", "lib/angular.js", "lib/react.js", "lib/vue.js",
        "api.js", "client.js", "app.bundle.js",
        "runtime.js", "polyfills.js", "vendors.js",
        "index.js", "core.js", "bootstrap.js",
    ];

    let mut wordlist_file = File::create(&js_wordlist_file)?;
    for path in &js_paths {
        writeln!(wordlist_file, "{}", path)?;
    }

    // Run ffuf for first 10 HTTP200 URLs
    let ffuf_js_file = base_path.join("ffuf_discovered_js.txt");
    File::create(&ffuf_js_file)?;  // Create empty file

    let mut total_js_discovered = 0;

    for (idx, url) in http200_urls.iter().take(10).enumerate() {
        println!("{}", format!("  [*] [{}/{}] Fuzzing: {}", idx + 1, std::cmp::min(10, http200_urls.len()), url).cyan());

        let ffuf_output = base_path.join(format!("ffuf_js_{}.txt", idx));

        let ffuf_status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "ffuf -u {}/FUZZ -w {} -mc 200 -ac -t 50 -s -of json -o {} 2>/dev/null || echo 'ffuf completed'",
                url.trim_end_matches('/'),
                js_wordlist_file.display(),
                ffuf_output.display()
            ))
            .status()
            .await?;

        if ffuf_status.success() && ffuf_output.exists() {
            // Parse ffuf JSON output and extract URLs
            if let Ok(content) = fs::read_to_string(&ffuf_output) {
                let ffuf_urls = extract_ffuf_urls(&content);
                if !ffuf_urls.is_empty() {
                    let mut ffuf_append = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&ffuf_js_file)?;

                    for url_found in ffuf_urls {
                        writeln!(ffuf_append, "{}", url_found)?;
                        total_js_discovered += 1;
                    }
                }
            }
        }
    }

    progress.tool_completed("ffuf JS Discovery", 70.0);
    progress.data_found("JS files via ffuf", total_js_discovered, 70.0);
    println!("{}", format!("[+] ffuf discovered {} JS files", total_js_discovered).green());

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 7: JAVASCRIPT CRAWLER (70-79%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 7: JAVASCRIPT ANALYSIS (70-79%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("JS Crawler");
    println!("{}", "[*] Crawling and analyzing JavaScript files...".cyan());

    // Run comprehensive JS crawler
    let validate_tokens = args.full_scan; // Only validate tokens in full scan mode
    let (mut enhanced_secrets, enhanced_endpoints, enhanced_cloud_storage, discovered_js_files) =
        js_crawler::crawl_all_js_sources(
            &base_path,
            &http200_urls,
            &client,
            validate_tokens,
            args.workers,
        )
        .await;

    // AI Filter: Validate secrets with Ollama to remove false positives
    if ollama.is_available().await && !enhanced_secrets.is_empty() {
        println!("{}", "[AI] Filtrando secrets com Ollama para remover falsos positivos...".cyan());
        let before_count = enhanced_secrets.len();
        let mut filtered = Vec::new();
        for secret in &enhanced_secrets {
            let verdict = ollama.analyze_secret(
                &secret.secret_type,
                &secret.secret_preview,
                &secret.context,
                &secret.found_in_url,
            ).await;
            match verdict {
                Some(v) if !v.is_real && v.confidence >= 70 => {
                    println!("{}", format!("  [AI] FP removido: {} em {} ({})", secret.secret_type, secret.found_in_url, v.reason).bright_black());
                }
                _ => filtered.push(secret.clone()),
            }
        }
        let removed = before_count - filtered.len();
        if removed > 0 {
            println!("{}", format!("[AI] Secrets: {} falsos positivos removidos ({} reais restantes)", removed, filtered.len()).green());
        }
        enhanced_secrets = filtered;
    }

    // Save JS analysis results
    let js_secrets_file = base_path.join("js_secrets_enhanced.json");
    let js_secrets_json = serde_json::to_string_pretty(&enhanced_secrets)?;
    fs::write(&js_secrets_file, js_secrets_json)?;

    let js_endpoints_file = base_path.join("js_endpoints.txt");
    js_crawler::save_js_endpoints_to_file(&enhanced_endpoints, &js_endpoints_file)?;

    let js_cloud_storage_file = base_path.join("js_cloud_storage.json");
    let js_cloud_json = serde_json::to_string_pretty(&enhanced_cloud_storage)?;
    fs::write(&js_cloud_storage_file, js_cloud_json)?;

    // ═══════════════════════════════════════════════════════════════
    // SUPABASE KEY EXPLOITATION
    // ═══════════════════════════════════════════════════════════════
    {
        // Find Supabase secrets and URLs from enhanced_secrets
        let supabase_keys: Vec<&secrets_scanner::HardcodedSecret> = enhanced_secrets.iter()
            .filter(|s| s.secret_type.starts_with("SUPABASE_") && s.secret_type != "SUPABASE_URL")
            .collect();

        let supabase_url: Option<String> = enhanced_secrets.iter()
            .find(|s| s.secret_type == "SUPABASE_URL")
            .map(|s| s.secret_value.clone())
            .or_else(|| {
                // Try to extract from context of any Supabase key
                enhanced_secrets.iter()
                    .filter(|s| s.secret_type.starts_with("SUPABASE_"))
                    .find_map(|s| {
                        let re = regex::Regex::new(r"https://[a-z0-9]+\.supabase\.co").ok()?;
                        re.find(&s.context).map(|m| m.as_str().to_string())
                    })
            });

        if !supabase_keys.is_empty() {
            println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".magenta().bold());
            println!("{}", "║  🔮 SUPABASE EXPLOITATION - Testing Discovered Keys                           ║".magenta().bold());
            println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".magenta().bold());

            println!("{}", format!("[*] Found {} Supabase key(s) in JavaScript files", supabase_keys.len()).cyan());

            if let Some(ref supa_url) = supabase_url {
                println!("{}", format!("[*] Supabase URL: {}", supa_url).cyan());

                let mut exploit_results: Vec<secrets_scanner::SupabaseExploitResult> = Vec::new();

                for (idx, key_secret) in supabase_keys.iter().enumerate() {
                    let key_type = if key_secret.secret_type.contains("SERVICE_ROLE") {
                        "service_role"
                    } else if key_secret.secret_type.contains("ANON") {
                        "anon"
                    } else {
                        "unknown"
                    };

                    println!("{}", format!("\n   🔑 [{}/{}] Testing {} key...", idx + 1, supabase_keys.len(), key_type).yellow());

                    let result = secrets_scanner::validate_supabase_key(
                        supa_url,
                        &key_secret.secret_value,
                        key_type,
                        key_secret.js_source_url.as_deref().unwrap_or(&key_secret.found_in_url),
                        &client,
                    ).await;

                    // Display results
                    println!("{}", format!("      ├─ Severity: {}", result.severity).color(
                        if result.severity == "CRITICAL" { "red" } else { "yellow" }
                    ));
                    println!("{}", format!("      ├─ Signup: {}", if result.signup_enabled { "OPEN" } else { "Disabled" }).color(
                        if result.signup_enabled { "red" } else { "green" }
                    ));
                    println!("{}", format!("      ├─ Tables found: {}", result.tables_accessible.len()).cyan());
                    if !result.tables_accessible.is_empty() {
                        let tables_preview: Vec<&str> = result.tables_accessible.iter().take(5).map(|s| s.as_str()).collect();
                        println!("{}", format!("      │  └─ {}", tables_preview.join(", ")).bright_black());
                    }
                    println!("{}", format!("      ├─ Data exposed: {}", if !result.sample_data.is_empty() { "YES" } else { "No" }).color(
                        if !result.sample_data.is_empty() { "red" } else { "green" }
                    ));

                    for finding in &result.findings {
                        println!("{}", format!("      │  ⚡ {}", finding).yellow());
                    }

                    exploit_results.push(result);
                }

                // AI analysis with Ollama
                let mut ollama_analysis: Option<String> = None;
                if ollama.is_available().await && !exploit_results.is_empty() {
                    println!("{}", "\n[AI] Analisando vulnerabilidades Supabase com Ollama...".cyan());

                    let first = &exploit_results[0];
                    let ai_result = ollama.analyze_supabase_finding(
                        supa_url,
                        &first.key_type,
                        &first.source_js_url,
                        first.signup_enabled,
                        &first.tables_accessible,
                        !first.sample_data.is_empty(),
                        &first.findings,
                    ).await;

                    if let Some(ref analysis) = ai_result {
                        println!("{}", "[AI] Supabase analysis:".green().bold());
                        for line in analysis.lines().take(8) {
                            println!("{}", format!("  {}", line).bright_black());
                        }
                        ollama_analysis = ai_result;
                    }
                }

                // Generate markdown report
                let report_path = base_path.join("supabase_vulnerability_report.md");
                match secrets_scanner::generate_supabase_report(
                    &domain,
                    &exploit_results,
                    ollama_analysis.as_deref(),
                    &report_path,
                ) {
                    Ok(_) => {
                        println!("{}", format!("\n[+] Supabase vulnerability report: {}", report_path.display()).green().bold());
                    }
                    Err(e) => {
                        println!("{}", format!("[-] Error generating Supabase report: {}", e).red());
                    }
                }

                // Save JSON results too
                let exploit_json_path = base_path.join("supabase_exploit_results.json");
                if let Ok(json) = serde_json::to_string_pretty(&exploit_results) {
                    let _ = fs::write(&exploit_json_path, json);
                    println!("{}", format!("[+] Supabase exploit results: {}", exploit_json_path.display()).green());
                }
            } else {
                println!("{}", "[-] Supabase key(s) found but no Supabase URL discovered - cannot test".yellow());
                println!("{}", "    Keys detected:".yellow());
                for key in &supabase_keys {
                    println!("{}", format!("    - {} in {}", key.secret_type, key.found_in_url).yellow());
                }
            }
        }
    }

    // Extract S3 buckets from discovered JS files
    println!("{}", "[*] Extracting S3 buckets from JavaScript files...".cyan());
    let s3_buckets = js_crawler::crawl_s3_buckets_from_js(
        &discovered_js_files,
        &client,
    )
    .await;

    let s3_file = base_path.join("s3.txt");
    js_crawler::save_s3_buckets_to_file(&s3_buckets, &s3_file)?;

    progress.tool_completed("JS Crawler", 79.0);
    progress.data_found("JS secrets", enhanced_secrets.len(), 79.0);
    progress.data_found("JS endpoints", enhanced_endpoints.len(), 79.0);
    progress.data_found("cloud storage URLs", enhanced_cloud_storage.len(), 79.0);
    progress.data_found("S3 buckets", s3_buckets.len(), 79.0);

    println!("{}", format!("[+] Discovered {} JavaScript files", discovered_js_files.len()).green());
    println!("{}", format!("[+] Found {} secrets in JS files", enhanced_secrets.len()).green());
    println!("{}", format!("[+] Extracted {} API endpoints", enhanced_endpoints.len()).green());
    println!("{}", format!("[+] Found {} cloud storage URLs", enhanced_cloud_storage.len()).green());
    println!("{}", format!("[+] Discovered {} S3 buckets", s3_buckets.len()).green());

    if let Some(ref mut web_metrics) = metrics.web_metrics {
        web_metrics.total_endpoints_found = enhanced_endpoints.len();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 7.5: ADMIN PANEL DISCOVERY (79-81%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 7.5: ADMIN PANEL DISCOVERY (79-81%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("Admin Panel Finder");
    println!("{}", "[*] Discovering administrative panels across multiple ports...".cyan());

    // Get list of validated resolvable hosts
    let resolvable_hosts: Vec<String> = validated_hosts
        .iter()
        .filter(|h| h.is_resolvable)
        .map(|h| h.subdomain.clone())
        .collect();

    // Discover admin panels
    let mut admin_panels = admin_finder::discover_admin_panels(
        domain,
        &resolvable_hosts,
        &client,
        args.workers,
    )
    .await;

    // AI Filter: Validate admin panels with Ollama
    if ollama.is_available().await && !admin_panels.is_empty() {
        println!("{}", "[AI] Validando admin panels com Ollama...".cyan());
        let before_count = admin_panels.len();
        let mut filtered = Vec::new();
        for panel in &admin_panels {
            let verdict = ollama.analyze_admin_panel(
                &panel.url,
                panel.status_code,
                panel.title.as_deref().unwrap_or(""),
                &panel.fingerprint.join(", "),
                &panel.fingerprint,
            ).await;
            match verdict {
                Some(v) if !v.is_real && v.confidence >= 70 => {
                    println!("{}", format!("  [AI] Falso positivo removido: {} ({})", panel.url, v.reason).bright_black());
                }
                _ => filtered.push(panel.clone()),
            }
        }
        let removed = before_count - filtered.len();
        if removed > 0 {
            println!("{}", format!("[AI] Admin panels: {} filtrados como falso positivo ({} restantes)", removed, filtered.len()).green());
        }
        admin_panels = filtered;
    }

    // Save admin panel results
    let admin_panels_file = base_path.join("admin_panels.json");
    admin_finder::save_admin_panels_to_file(&admin_panels, &admin_panels_file)?;

    progress.tool_completed("Admin Panel Finder", 81.0);
    progress.data_found("admin panels", admin_panels.len(), 81.0);

    // Display summary
    admin_finder::display_admin_panel_summary(&admin_panels);

    let high_confidence_panels = admin_panels.iter().filter(|p| p.is_likely_admin).count();
    if high_confidence_panels > 0 {
        println!(
            "{}",
            format!(
                "[!] WARNING: Found {} high-confidence admin panels!",
                high_confidence_panels
            )
            .red()
            .bold()
        );
    }
    println!("{}", format!("[+] Admin panel discovery saved to: {}", admin_panels_file.display()).green());

    // Bug Bounty Mode: Test default credentials on admin panels
    let mut valid_credentials = Vec::new();
    if args.bugbounty && !admin_panels.is_empty() {
        println!("\n{}", "═══════════════════════════════════════════════════════════════".red().bold());
        println!("{}", "  🎯 BUG BOUNTY MODE: TESTING DEFAULT CREDENTIALS".red().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════".red().bold());

        let panels_to_test: Vec<_> = admin_panels
            .iter()
            .filter(|p| p.is_likely_admin)
            .take(10) // Test top 10 high-confidence panels
            .collect();

        println!("{}", format!("[*] Testing default credentials on {} admin panels...", panels_to_test.len()).cyan());

        for (idx, panel) in panels_to_test.iter().enumerate() {
            println!("{}", format!("\n[*] [{}/{}] Testing: {}", idx + 1, panels_to_test.len(), panel.url).cyan());

            let cred_results = credential_tester::test_default_credentials(&panel.url, &client).await;

            // Check for valid credentials
            for result in &cred_results {
                if result.is_valid {
                    valid_credentials.push(result.clone());

                    // Send Discord notification if webhook is configured
                    if let Some(ref webhook_url) = args.discord_webhook {
                        println!("{}", "[*] Sending Discord notification...".cyan());
                        let _ = discord_notifier::notify_valid_credentials(
                            webhook_url,
                            domain,
                            &panel.url,
                            &result.username,
                            &result.password,
                        )
                        .await;
                    }
                }
            }
        }

        // AI Filter: Validate credential results with Ollama
        if ollama.is_available().await && !valid_credentials.is_empty() {
            println!("{}", "[AI] Validando credenciais encontradas com Ollama...".cyan());
            let before_count = valid_credentials.len();
            let mut filtered = Vec::new();
            for cred in &valid_credentials {
                let verdict = ollama.analyze_credential_result(
                    &cred.url,
                    &cred.username,
                    "",
                    &cred.response_indicators.join(", "),
                    200,
                ).await;
                match verdict {
                    Some(v) if !v.is_real && v.confidence >= 75 => {
                        println!("{}", format!("  [AI] Credencial FP: {}:{} em {} ({})", cred.username, cred.password, cred.url, v.reason).bright_black());
                    }
                    _ => filtered.push(cred.clone()),
                }
            }
            let removed = before_count - filtered.len();
            if removed > 0 {
                println!("{}", format!("[AI] Credenciais: {} falsos positivos removidos ({} validas)", removed, filtered.len()).green());
            }
            valid_credentials = filtered;
        }

        // Save valid credentials
        if !valid_credentials.is_empty() {
            let creds_file = base_path.join("bugbounty_valid_credentials.json");
            credential_tester::save_credential_results(&valid_credentials, &creds_file)?;

            println!("\n{}", "═══════════════════════════════════════════════════════════════".red().bold());
            println!(
                "{}",
                format!(
                    "  🔥 CRITICAL: FOUND {} VALID CREDENTIALS!",
                    valid_credentials.len()
                )
                .red()
                .bold()
            );
            println!("{}", "═══════════════════════════════════════════════════════════════".red().bold());
            println!("{}", format!("[+] Valid credentials saved to: {}", creds_file.display()).green().bold());

            for cred in &valid_credentials {
                println!(
                    "{}",
                    format!("  🎯 {}: {}:{}", cred.url, cred.username, cred.password)
                        .yellow()
                        .bold()
                );
            }
        } else {
            println!("{}", "\n[*] No valid default credentials found".yellow());
        }
    }

    // Send Discord notification for admin panels if webhook configured
    if let Some(ref webhook_url) = args.discord_webhook {
        if !admin_panels.is_empty() {
            for panel in admin_panels.iter().filter(|p| p.is_likely_admin).take(5) {
                let _ = discord_notifier::notify_admin_panel_found(
                    webhook_url,
                    domain,
                    &panel.url,
                    panel.status_code,
                    panel.title.as_deref(),
                    &panel.fingerprint,
                )
                .await;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 7.6: WORDPRESS VULNERABILITY SCANNING (79-81%)
    // ═══════════════════════════════════════════════════════════════════════════
    let mut wpscan_all_results: Vec<wpscan::WPScanResults> = Vec::new();

    if !args.no_wpscan {
        let wp_targets = wpscan::detect_wordpress(&admin_panels, &http200_urls);

        if !wp_targets.is_empty() {
            println!("\n{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
            println!("{}", "  STAGE 7.6: WORDPRESS VULNERABILITY SCANNING (79-81%)".magenta().bold());
            println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
            println!("{}", format!("[*] Detected {} WordPress target(s)", wp_targets.len()).cyan());

            if wpscan::ensure_wpscan_docker().await.unwrap_or(false) {
                progress.tool_started("WPScan");

                let max_targets = wp_targets.len().min(5);
                for (idx, target) in wp_targets.iter().take(max_targets).enumerate() {
                    println!("{}", format!("\n[*] [{}/{}] Scanning: {}", idx + 1, max_targets, target).cyan());

                    match wpscan::run_wpscan(
                        target,
                        &base_path,
                        args.wpscan_token.as_deref(),
                        idx,
                    ).await {
                        Ok(mut results) => {
                            // AI Filter: Validate WPScan vulnerabilities with Ollama
                            if ollama.is_available().await && !results.vulnerabilities.is_empty() {
                                println!("{}", "[AI] Validando vulnerabilidades WordPress com Ollama...".cyan());
                                let before_count = results.vulnerabilities.len();
                                let mut filtered_vulns = Vec::new();

                                for vuln in &results.vulnerabilities {
                                    let verdict = ollama.analyze_wpscan_finding(
                                        &vuln.component,
                                        &vuln.fixed_in.as_deref().unwrap_or("N/A"),
                                        &vuln.title,
                                        &vuln.severity,
                                        &vuln.cve.as_deref().unwrap_or("N/A"),
                                        &vuln.fixed_in.as_deref().unwrap_or("N/A"),
                                        target,
                                    ).await;

                                    match verdict {
                                        Some(v) if !v.is_real && v.confidence >= 70 => {
                                            println!("{}", format!("  [AI] WP FP: {} ({})", vuln.title, v.reason).bright_black());
                                        }
                                        _ => filtered_vulns.push(vuln.clone()),
                                    }
                                }

                                let removed = before_count - filtered_vulns.len();
                                if removed > 0 {
                                    println!("{}", format!("[AI] WordPress: {} falsos positivos removidos ({} vulns validas)", removed, filtered_vulns.len()).green());
                                    results.vulnerabilities = filtered_vulns;
                                    results.total_vulnerabilities = results.vulnerabilities.len();
                                }
                            }

                            wpscan::display_wpscan_summary(&results);

                            // Discord notification for critical/high WPScan findings
                            if let Some(ref webhook_url) = args.discord_webhook {
                                let critical_vulns: Vec<_> = results.vulnerabilities.iter()
                                    .filter(|v| v.severity == "critical" || v.severity == "high")
                                    .collect();
                                if !critical_vulns.is_empty() {
                                    let vuln_summary: Vec<String> = critical_vulns.iter().take(5)
                                        .map(|v| format!("[{}] {} ({})", v.severity.to_uppercase(), v.title, v.cve.as_deref().unwrap_or("no CVE")))
                                        .collect();
                                    let fields = vec![
                                        ("Target".to_string(), target.to_string(), true),
                                        ("Vulns".to_string(), format!("{} critical/high", critical_vulns.len()), true),
                                        ("Details".to_string(), vuln_summary.join("\n"), false),
                                    ];
                                    let _ = discord_notifier::send_discord_notification(
                                        webhook_url,
                                        &format!("WordPress Vulnerabilities - {}", domain),
                                        &format!("{} critical/high vulnerabilities found on WordPress site", critical_vulns.len()),
                                        0xff0000,
                                        fields,
                                    ).await;
                                }
                            }

                            wpscan_all_results.push(results);
                        }
                        Err(e) => {
                            println!("{}", format!("[!] WPScan failed for {}: {}", target, e).yellow());
                        }
                    }
                }

                // Save all WPScan results
                if !wpscan_all_results.is_empty() {
                    let wpscan_file = base_path.join("wpscan_results.json");
                    if let Err(e) = wpscan::save_wpscan_results(&wpscan_all_results, &wpscan_file) {
                        println!("{}", format!("[!] Failed to save WPScan results: {}", e).yellow());
                    } else {
                        println!("{}", format!("[+] WPScan results saved to: {}", wpscan_file.display()).green());
                    }
                }

                progress.tool_completed("WPScan", 81.0);
            } else {
                println!("{}", "[!] Docker not available - skipping WordPress vulnerability scanning".yellow());
                println!("{}", "    Install Docker: curl -fsSL https://get.docker.com | sh".yellow());
                println!("{}", "    Then pull image: docker pull wpscanteam/wpscan".yellow());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 7.7: IIS SHORT FILENAME SCANNING (81-82%)
    // ═══════════════════════════════════════════════════════════════════════════
    let mut shortscan_all_results: Vec<shortscan::ShortscanResult> = Vec::new();

    if !args.no_shortscan {
        println!("{}", "[*] Checking for IIS servers...".cyan());
        let iis_targets = shortscan::detect_iis_servers(&http200_urls).await;

        if !iis_targets.is_empty() {
            println!("\n{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
            println!("{}", "  STAGE 7.7: IIS SHORT FILENAME SCANNING (81-82%)".magenta().bold());
            println!("{}", "═══════════════════════════════════════════════════════════════".magenta().bold());
            println!("{}", format!("[*] Detected {} IIS server(s)", iis_targets.len()).cyan());

            if let Some(_shortscan_path) = discover_tool_path("shortscan") {
                progress.tool_started("Shortscan");

                let max_targets = iis_targets.len().min(10);
                for (idx, target) in iis_targets.iter().take(max_targets).enumerate() {
                    println!("{}", format!("\n[*] [{}/{}] Scanning: {}", idx + 1, max_targets, target).cyan());

                    match shortscan::run_shortscan(
                        target,
                        &base_path,
                        idx,
                    ).await {
                        Ok(results) => {
                            shortscan::display_shortscan_summary(&results);
                            if results.total_findings > 0 {
                                shortscan_all_results.push(results);
                            }
                        }
                        Err(e) => {
                            println!("{}", format!("[!] Shortscan failed for {}: {}", target, e).yellow());
                        }
                    }
                }

                // Save all shortscan results
                if !shortscan_all_results.is_empty() {
                    let shortscan_file = base_path.join("shortscan_results.json");
                    if let Err(e) = shortscan::save_shortscan_results(&shortscan_all_results, &shortscan_file) {
                        println!("{}", format!("[!] Failed to save shortscan results: {}", e).yellow());
                    } else {
                        println!("{}", format!("[+] Shortscan results saved to: {}", shortscan_file.display()).green());
                    }
                }

                progress.tool_completed("Shortscan", 82.0);
            } else {
                println!("{}", "[!] shortscan not installed - skipping IIS short filename scanning".yellow());
                println!("{}", "    Install: go install github.com/bitquark/shortscan/cmd/shortscan@latest".yellow());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 8: PACKAGE SCANNER (82-84%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 8: PACKAGE DEPENDENCY SCANNER (82-84%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("Package Scanner");
    println!("{}", "[*] Scanning JavaScript files for package dependencies...".cyan());

    // Scan discovered JS files for packages
    let mut package_dependencies = package_scanner::scan_js_for_packages(
        &discovered_js_files,
        &client,
        args.workers,
    )
    .await;

    // AI Filter: Validate package findings with Ollama
    if ollama.is_available().await && !package_dependencies.is_empty() {
        println!("{}", "[AI] Validando package dependencies com Ollama...".cyan());
        let before_count = package_dependencies.len();
        let mut filtered = Vec::new();
        for pkg in &package_dependencies {
            let verdict = ollama.analyze_package(
                &pkg.package_name,
                &format!("{}", pkg.package_type),
                &pkg.found_in_context,
                pkg.exists_in_public_registry,
            ).await;
            match verdict {
                Some(v) if !v.is_real && v.confidence >= 70 => {
                    println!("{}", format!("  [AI] Falso positivo: {} ({})", pkg.package_name, v.reason).bright_black());
                }
                _ => filtered.push(pkg.clone()),
            }
        }
        let removed = before_count - filtered.len();
        if removed > 0 {
            println!("{}", format!("[AI] Packages: {} falsos positivos removidos ({} restantes)", removed, filtered.len()).green());
        }
        package_dependencies = filtered;
    }

    // Save package dependencies
    let packages_file = base_path.join("package_dependencies.json");
    package_scanner::save_packages_to_json(&package_dependencies, &packages_file)?;

    let confusion_file = base_path.join("dependency_confusion.txt");
    package_scanner::save_dependency_confusion_findings(&package_dependencies, &confusion_file)?;

    progress.tool_completed("Package Scanner", 84.0);

    let confusion_count = package_dependencies
        .iter()
        .filter(|p| p.potential_confusion)
        .count();

    progress.data_found("packages analyzed", package_dependencies.len(), 84.0);
    if confusion_count > 0 {
        println!(
            "{}",
            format!(
                "[!] WARNING: Found {} potential dependency confusion vulnerabilities!",
                confusion_count
            )
            .red()
            .bold()
        );
    }
    println!(
        "{}",
        format!(
            "[+] Analyzed {} package dependencies ({} potential confusion)",
            package_dependencies.len(),
            confusion_count
        )
        .green()
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 9: TRUFFLEHOG INTEGRATION (84-87%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 9: TRUFFLEHOG SECRET SCANNING (84-87%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("TruffleHog");
    println!("{}", "[*] Running TruffleHog for deep secret detection...".cyan());

    // Prepare target files for TruffleHog
    let trufflehog_targets_dir = PathBuf::from("/tmp/trufflehog_targets");
    fs::create_dir_all(&trufflehog_targets_dir)?;

    // Write discovered JS files to target directory
    let mut total_targets = 0;

    // Add discovered JS files
    for (idx, js_url) in discovered_js_files.iter().enumerate() {
        let target_file = trufflehog_targets_dir.join(format!("js_{}.url", idx));
        fs::write(&target_file, js_url)?;
        total_targets += 1;
    }

    // Add first 50 HTTP200 URLs
    for (idx, url) in http200_urls.iter().take(50).enumerate() {
        let target_file = trufflehog_targets_dir.join(format!("http_{}.url", idx));
        fs::write(&target_file, url)?;
        total_targets += 1;
    }

    println!(
        "{}",
        format!(
            "[*] TruffleHog: Prepared {} targets for scanning...",
            total_targets
        )
        .cyan()
    );
    println!("{}", format!("  - {} JavaScript files", discovered_js_files.len()).cyan());
    println!("{}", format!("  - {} HTTP URLs", http200_urls.iter().take(50).count()).cyan());

    progress.add_event(
        EventType::ToolProgress {
            tool_name: "TruffleHog".to_string(),
            current: 0,
            total: total_targets,
        },
        format!("Scanning {} URLs with TruffleHog...", total_targets),
        85.0,
        None,
    );

    // Run TruffleHog
    let trufflehog_json = base_path.join("trufflehog.json");
    let trufflehog_status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "trufflehog filesystem --directory {} --json --no-update > {} 2>/dev/null || echo 'trufflehog failed'",
            trufflehog_targets_dir.display(),
            trufflehog_json.display()
        ))
        .status()
        .await?;

    // Parse TruffleHog results
    let mut trufflehog_secrets = Vec::new();
    if trufflehog_status.success() && trufflehog_json.exists() {
        if let Ok(content) = fs::read_to_string(&trufflehog_json) {
            trufflehog_secrets = parse_json_objects_from_content(&content);
        }
    }

    // AI Filter: Validate TruffleHog secrets with Ollama
    if ollama.is_available().await && !trufflehog_secrets.is_empty() {
        println!("{}", "[AI] Validando TruffleHog secrets com Ollama...".cyan());
        let before_count = trufflehog_secrets.len();
        let mut filtered = Vec::new();
        for secret in &trufflehog_secrets {
            let detector = secret["DetectorName"].as_str().unwrap_or("Unknown");
            let raw_preview = secret["Raw"].as_str().unwrap_or("").chars().take(60).collect::<String>();
            let source = secret["SourceMetadata"]["Data"]["Filesystem"]["file"]
                .as_str().unwrap_or("Unknown");
            let verdict = ollama.analyze_secret(
                detector,
                &raw_preview,
                &format!("TruffleHog detector: {}", detector),
                source,
            ).await;
            match verdict {
                Some(v) if !v.is_real && v.confidence >= 70 => {
                    println!("{}", format!("  [AI] TruffleHog FP removido: {} ({})", detector, v.reason).bright_black());
                }
                _ => filtered.push(secret.clone()),
            }
        }
        let removed = before_count - filtered.len();
        if removed > 0 {
            println!("{}", format!("[AI] TruffleHog: {} falsos positivos removidos ({} restantes)", removed, filtered.len()).green());
        }
        trufflehog_secrets = filtered;
    }

    // Save TruffleHog text summary
    let trufflehog_txt = base_path.join("trufflehog.txt");
    let mut trufflehog_file = File::create(&trufflehog_txt)?;
    writeln!(trufflehog_file, "=== TRUFFLEHOG SECRET SCAN RESULTS ===")?;
    writeln!(trufflehog_file, "Targets scanned: {}", total_targets)?;
    writeln!(trufflehog_file, "Secrets found: {}", trufflehog_secrets.len())?;
    writeln!(trufflehog_file)?;

    for (idx, secret) in trufflehog_secrets.iter().enumerate() {
        writeln!(trufflehog_file, "Secret #{}", idx + 1)?;
        writeln!(trufflehog_file, "{}", serde_json::to_string_pretty(secret)?)?;
        writeln!(trufflehog_file)?;
    }

    progress.tool_completed("TruffleHog", 87.0);
    progress.data_found("TruffleHog secrets", trufflehog_secrets.len(), 87.0);

    if !trufflehog_secrets.is_empty() {
        println!(
            "{}",
            format!(
                "[!] TruffleHog found {} secrets!",
                trufflehog_secrets.len()
            )
            .red()
            .bold()
        );
    } else {
        println!("{}", "[+] TruffleHog scan completed: No secrets found".green());
    }
    println!("{}", format!("[+] Results saved to: {}", trufflehog_json.display()).green());
    println!("{}", format!("[+] Summary saved to: {}", trufflehog_txt.display()).green());

    // Clean up temp directory
    let _ = fs::remove_dir_all(&trufflehog_targets_dir);

    // Send Discord notifications for critical secrets found by TruffleHog
    if let Some(ref webhook_url) = args.discord_webhook {
        if !trufflehog_secrets.is_empty() {
            for secret in trufflehog_secrets.iter().take(5) {
                if let Some(detector_name) = secret["DetectorName"].as_str() {
                    let source_name = secret["SourceMetadata"]["Data"]["Filesystem"]["file"]
                        .as_str()
                        .unwrap_or("Unknown");
                    let preview = secret["Raw"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(50)
                        .collect::<String>();

                    let _ = discord_notifier::notify_secret_found(
                        webhook_url,
                        domain,
                        detector_name,
                        source_name,
                        &format!("{}...", preview),
                    )
                    .await;
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 10: SECRETS SCANNER (87-92%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
    println!("{}", "  STAGE 10: HARDCODED SECRETS DETECTION (87-92%)".yellow().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

    progress.tool_started("Secrets Scanner");
    println!("{}", "[*] Scanning for hardcoded secrets and cloud storage exposure...".cyan());

    // Aggregate all secrets from JS analysis (already done in stage 7)
    let hardcoded_secrets_file = base_path.join("hardcoded_secrets_critical.json");
    let cloud_storage_file = base_path.join("cloud_storage_exposure.json");

    // Save hardcoded secrets
    secrets_scanner::save_secrets_to_file(&enhanced_secrets, &hardcoded_secrets_file)?;

    // Save cloud storage exposures
    secrets_scanner::save_cloud_storage_to_file(&enhanced_cloud_storage, &cloud_storage_file)?;

    progress.tool_completed("Secrets Scanner", 92.0);

    // Display summaries
    secrets_scanner::display_secrets_summary(&enhanced_secrets);
    secrets_scanner::display_cloud_storage_summary(&enhanced_cloud_storage);

    if let Some(ref mut web_metrics) = metrics.web_metrics {
        web_metrics.total_secrets_found = enhanced_secrets.len() + trufflehog_secrets.len();
        for secret in &enhanced_secrets {
            *web_metrics
                .secrets_by_type
                .entry(secret.secret_type.clone())
                .or_insert(0) += 1;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 10.5: INFORMATION DISCLOSURE SCANNING (S3, Actuator, GraphQL)
    // ═══════════════════════════════════════════════════════════════════════════
    let _disclosure_results = if args.disclosure_scan || args.s3_scan || args.actuator_scan || args.graphql_scan || args.full_scan {
        println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".cyan().bold());
        println!("{}", "║  🔓 STAGE 10.5: INFORMATION DISCLOSURE SCANNING                               ║".cyan().bold());
        println!("{}", "║     S3/Cloud Storage | Spring Actuator | GraphQL Introspection               ║".cyan());
        println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".cyan().bold());

        progress.tool_started("Info Disclosure Scanner");

        // Collect JS file contents for cloud storage URL extraction
        let js_contents: Vec<String> = if let Ok(entries) = std::fs::read_dir(&base_path) {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "js" || ext == "txt"))
                .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                .collect()
        } else {
            Vec::new()
        };

        let http200_path = if http200_file.exists() {
            Some(http200_file.as_path())
        } else {
            None
        };

        match info_disclosure_scanner::run_info_disclosure_scan(
            domain,
            &base_path,
            http200_path,
            Some(&js_contents),
            true, // verbose
        ).await {
            Ok(mut results) => {
                // AI Filter: Validate info disclosure findings with Ollama
                if ollama.is_available().await && results.total_findings > 0 {
                    println!("{}", "[AI] Validando info disclosure findings com Ollama...".cyan());
                    let mut total_removed = 0usize;

                    // Filter actuator findings
                    if !results.actuator_findings.is_empty() {
                        let before = results.actuator_findings.len();
                        let mut filtered = Vec::new();
                        for finding in &results.actuator_findings {
                            let verdict = ollama.analyze_info_disclosure(
                                &finding.url,
                                &format!("Spring Actuator: {}", finding.endpoint),
                                &finding.content_preview,
                            ).await;
                            match verdict {
                                Some(v) if !v.is_real && v.confidence >= 70 => {
                                    println!("{}", format!("  [AI] Actuator FP: {} ({})", finding.endpoint, v.reason).bright_black());
                                }
                                _ => filtered.push(finding.clone()),
                            }
                        }
                        total_removed += before - filtered.len();
                        results.actuator_findings = filtered;
                    }

                    // Filter sensitive file findings
                    if !results.sensitive_files.is_empty() {
                        let before = results.sensitive_files.len();
                        let mut filtered = Vec::new();
                        for finding in &results.sensitive_files {
                            let verdict = ollama.analyze_info_disclosure(
                                &finding.url,
                                &format!("Sensitive File: {}", finding.file_type),
                                &finding.content_preview,
                            ).await;
                            match verdict {
                                Some(v) if !v.is_real && v.confidence >= 70 => {
                                    println!("{}", format!("  [AI] File FP: {} ({})", finding.url, v.reason).bright_black());
                                }
                                _ => filtered.push(finding.clone()),
                            }
                        }
                        total_removed += before - filtered.len();
                        results.sensitive_files = filtered;
                    }

                    // Filter GraphQL findings
                    if !results.graphql_findings.is_empty() {
                        let before = results.graphql_findings.len();
                        let mut filtered = Vec::new();
                        for finding in &results.graphql_findings {
                            let schema_info = format!("types:{} queries:{} mutations:{}",
                                finding.types_discovered, finding.queries_discovered, finding.mutations_discovered);
                            let verdict = ollama.analyze_info_disclosure(
                                &finding.url,
                                "GraphQL Introspection",
                                &schema_info,
                            ).await;
                            match verdict {
                                Some(v) if !v.is_real && v.confidence >= 70 => {
                                    println!("{}", format!("  [AI] GraphQL FP: {} ({})", finding.url, v.reason).bright_black());
                                }
                                _ => filtered.push(finding.clone()),
                            }
                        }
                        total_removed += before - filtered.len();
                        results.graphql_findings = filtered;
                    }

                    if total_removed > 0 {
                        results.total_findings = results.cloud_storage_findings.len()
                            + results.actuator_findings.len()
                            + results.graphql_findings.len()
                            + results.sensitive_files.len();
                        println!("{}", format!("[AI] Info Disclosure: {} falsos positivos removidos ({} reais)", total_removed, results.total_findings).green());

                        // Re-save filtered results
                        let results_path = base_path.join("info_disclosure_results.json");
                        if let Ok(json) = serde_json::to_string_pretty(&results) {
                            let _ = fs::write(&results_path, json);
                        }
                    }
                }

                progress.tool_completed("Info Disclosure Scanner", 92.0);
                progress.data_found("disclosure_findings", results.total_findings, 92.0);
                Some(results)
            }
            Err(e) => {
                eprintln!("{} Info disclosure scan error: {}", "[ERROR]".red(), e);
                progress.tool_completed("Info Disclosure Scanner", 92.0);
                None
            }
        }
    } else {
        None
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 11: NUCLEI + CHAMELEON (92-100%)
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".magenta().bold());
    println!("{}", "║  🎯 STAGE 11: VULNERABILITY SCANNING & DIRECTORY ENUMERATION (92-100%)        ║".magenta().bold());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".magenta().bold());

    let nuclei_file = files_dir.join("nuclei.txt");
    let chameleon_access_file = files_dir.join("chameleon_access_pages.txt");

    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 1: NUCLEI VULNERABILITY SCAN
    // ═══════════════════════════════════════════════════════════════════════════
    println!();
    println!("{}", "┌───────────────────────────────────────────────────────────────────────────────┐".cyan().bold());
    println!("{}", "│  🔬 NUCLEI - Vulnerability Scanner                                            │".cyan().bold());
    println!("{}", "├───────────────────────────────────────────────────────────────────────────────┤".cyan());
    println!("{}", format!("│  📁 Target file: {}{}│", http200_file.display(), " ".repeat(54_usize.saturating_sub(http200_file.display().to_string().len()))).cyan());
    println!("{}", format!("│  📝 Output: {}{}│", nuclei_file.display(), " ".repeat(59_usize.saturating_sub(nuclei_file.display().to_string().len()))).cyan());
    println!("{}", "│  ⚙️  Severities: critical, high, medium, low                                  │".cyan());
    println!("{}", "└───────────────────────────────────────────────────────────────────────────────┘".cyan());
    println!();
    println!("{}", "   ⏳ Running Nuclei scan... (this may take a while)".yellow());
    println!();

    progress.tool_started("Nuclei");

    // Run Nuclei FIRST (sequentially, not in parallel)
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | nuclei -jsonl -silent -etags ssl -severity critical,high,medium,low -c 100 -o {} 2>/dev/null",
            http200_file.display(),
            nuclei_file.display()
        ))
        .status()
        .await;

    // AI Filter: Validate Nuclei findings with Ollama
    if ollama.is_available().await && nuclei_file.exists() {
        if let Ok(content) = fs::read_to_string(&nuclei_file) {
            let all_lines: Vec<&str> = content.lines().collect();
            if !all_lines.is_empty() {
                println!("{}", "[AI] Triando vulnerabilidades Nuclei com Ollama...".cyan());
                let before_count = all_lines.len();
                let mut validated_lines = Vec::new();
                for line in &all_lines {
                    if let Ok(vuln) = serde_json::from_str::<serde_json::Value>(line) {
                        let template_id = vuln["template-id"].as_str().unwrap_or("");
                        let name = vuln["info"]["name"].as_str().unwrap_or("");
                        let severity = vuln["info"]["severity"].as_str().unwrap_or("info");
                        let matched_at = vuln["matched-at"].as_str()
                            .or_else(|| vuln["host"].as_str())
                            .unwrap_or("");
                        let extracted = vuln["extracted-results"].as_str()
                            .or_else(|| vuln["matcher-name"].as_str())
                            .unwrap_or("");

                        let verdict = ollama.analyze_nuclei_finding(
                            template_id, name, severity, matched_at, extracted,
                        ).await;
                        match verdict {
                            Some(v) if !v.is_real && v.confidence >= 75 => {
                                println!("{}", format!("  [AI] Nuclei FP: {} - {} ({})", severity, name, v.reason).bright_black());
                            }
                            _ => validated_lines.push(*line),
                        }
                    } else {
                        validated_lines.push(*line);
                    }
                }
                let removed = before_count - validated_lines.len();
                if removed > 0 {
                    // Rewrite nuclei file with only validated findings
                    let validated_content = validated_lines.join("\n");
                    let _ = fs::write(&nuclei_file, validated_content);
                    println!("{}", format!("[AI] Nuclei: {} falsos positivos removidos ({} vulns reais)", removed, validated_lines.len()).green());
                }
            }
        }
    }

    // Count and display Nuclei results
    let nuclei_count = if nuclei_file.exists() {
        count_lines(&nuclei_file)?
    } else {
        0
    };

    progress.tool_completed("Nuclei", 96.0);
    progress.data_found("vulnerabilities", nuclei_count, 96.0);

    // Display Nuclei results with nice formatting
    println!("{}", "┌───────────────────────────────────────────────────────────────────────────────┐".green().bold());
    println!("{}", "│  ✅ NUCLEI SCAN COMPLETE                                                      │".green().bold());
    println!("{}", "├───────────────────────────────────────────────────────────────────────────────┤".green());

    if nuclei_count > 0 {
        println!("{}", format!("│  🚨 Found {} vulnerabilities!{}│", nuclei_count, " ".repeat(55_usize.saturating_sub(nuclei_count.to_string().len()))).red().bold());
        println!("{}", "├───────────────────────────────────────────────────────────────────────────────┤".green());

        // Parse and display vulnerabilities by severity
        if nuclei_file.exists() {
            if let Ok(content) = fs::read_to_string(&nuclei_file) {
                let mut critical_count = 0;
                let mut high_count = 0;
                let mut medium_count = 0;
                let mut low_count = 0;

                for line in content.lines() {
                    if let Ok(vuln) = serde_json::from_str::<serde_json::Value>(line) {
                        match vuln["info"]["severity"].as_str().unwrap_or("info") {
                            "critical" => critical_count += 1,
                            "high" => high_count += 1,
                            "medium" => medium_count += 1,
                            "low" => low_count += 1,
                            _ => {}
                        }
                    }
                }

                if critical_count > 0 {
                    println!("{}", format!("│  💀 CRITICAL: {}{}│", critical_count, " ".repeat(60_usize.saturating_sub(critical_count.to_string().len()))).red().bold());
                }
                if high_count > 0 {
                    println!("{}", format!("│  🔴 HIGH: {}{}│", high_count, " ".repeat(64_usize.saturating_sub(high_count.to_string().len()))).red());
                }
                if medium_count > 0 {
                    println!("{}", format!("│  🟠 MEDIUM: {}{}│", medium_count, " ".repeat(62_usize.saturating_sub(medium_count.to_string().len()))).yellow());
                }
                if low_count > 0 {
                    println!("{}", format!("│  🟡 LOW: {}{}│", low_count, " ".repeat(65_usize.saturating_sub(low_count.to_string().len()))).cyan());
                }
            }
        }
    } else {
        println!("{}", "│  ✨ No vulnerabilities found                                                  │".green());
    }
    println!("{}", "└───────────────────────────────────────────────────────────────────────────────┘".green());
    println!();

    // ═══════════════════════════════════════════════════════════════════════════
    // STEP 2: CHAMELEON DIRECTORY ENUMERATION
    // ═══════════════════════════════════════════════════════════════════════════
    println!("{}", "┌───────────────────────────────────────────────────────────────────────────────┐".cyan().bold());
    println!("{}", "│  📂 CHAMELEON - Smart Directory Enumeration (Wappalyzer tech detection)       │".cyan().bold());
    println!("{}", "├───────────────────────────────────────────────────────────────────────────────┤".cyan());

    let targets_to_scan = http200_urls.len().min(10);
    println!("{}", format!("│  🎯 Targets: {} URLs (max 10){}│", targets_to_scan, " ".repeat(52_usize.saturating_sub(targets_to_scan.to_string().len()))).cyan());
    println!("{}", format!("│  📝 Output: {}{}│", chameleon_access_file.display(), " ".repeat(53_usize.saturating_sub(chameleon_access_file.display().to_string().len()))).cyan());
    println!("{}", "│  ⚙️  Threads: 50 | Tech detect: ON (-a) | Multi-host: ON (-L)                │".cyan());
    println!("{}", "└───────────────────────────────────────────────────────────────────────────────┘".cyan());
    println!();

    progress.tool_started("Chameleon");

    let chameleon_count;

    {
        // Write http200 URLs to temp file for chameleon -L flag
        let chameleon_hosts_file = base_path.join("chameleon_hosts.txt");
        {
            let urls_to_scan: Vec<&String> = http200_urls.iter().take(10).collect();
            let mut hosts_file = OpenOptions::new()
                .create(true).write(true).truncate(true)
                .open(&chameleon_hosts_file)?;
            for url in &urls_to_scan {
                writeln!(hosts_file, "{}", url)?;
            }
            println!("{}", format!("   📋 Wrote {} targets to {}", urls_to_scan.len(), chameleon_hosts_file.display()).yellow());
        }

        let chameleon_raw_output = base_path.join("chameleon_raw.txt");

        println!("{}", "   ⏳ Running Chameleon with auto tech detection...".yellow());

        let _ = Command::new("chameleon")
            .args([
                "-L", &chameleon_hosts_file.to_string_lossy(),
                "-a",
                "-c", "200,204,301,302,307,401,403,405",
                "-C", "404",
                "-t", "50",
                "-o", &chameleon_raw_output.to_string_lossy(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .status()
            .await;

        // Parse chameleon output and aggregate with status code filtering and size dedup
        let mut all_lines: Vec<String> = Vec::new();
        let mut seen_sizes: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        if chameleon_raw_output.exists() {
            if let Ok(content) = fs::read_to_string(&chameleon_raw_output) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }

                    // Parse chameleon output format: STATUS SIZE URL
                    // or lines that are just URLs
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();

                    if let Some(first) = parts.first() {
                        if let Ok(status) = first.parse::<u16>() {
                            // Filter: keep only useful status codes
                            match status {
                                200 | 201 | 204 | 301 | 302 | 307 | 401 | 403 | 405 => {
                                    // Track response sizes for dedup (custom 404s have identical sizes)
                                    let size_key = parts.get(1)
                                        .map(|s| s.to_string())
                                        .unwrap_or_default();
                                    let count = seen_sizes.entry(size_key).or_insert(0);
                                    *count += 1;
                                    all_lines.push(trimmed.to_string());
                                }
                                _ => {
                                    continue;
                                }
                            }
                        } else {
                            // Line doesn't start with status code (URL or comment) - keep it
                            all_lines.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // Dedup pass: remove lines with sizes that appear too many times (likely custom error pages)
        let size_threshold = 5;
        let before_dedup = all_lines.len();
        all_lines.retain(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(size_field) = parts.get(1) {
                let size_key = size_field.to_string();
                if let Some(&count) = seen_sizes.get(&size_key) {
                    return count <= size_threshold;
                }
            }
            true
        });
        let dedup_removed = before_dedup - all_lines.len();
        if dedup_removed > 0 {
            println!("{}", format!("   🧹 Removed {} duplicate-size responses (custom error pages)", dedup_removed).yellow());
        }

        // Write filtered results
        if let Ok(mut out_file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&chameleon_access_file)
        {
            for line in &all_lines {
                let _ = writeln!(out_file, "{}", line);
            }
        }

        // AI Filter: Validate chameleon findings with Ollama
        if ollama.is_available().await && chameleon_access_file.exists() {
            if let Ok(content) = fs::read_to_string(&chameleon_access_file) {
                let all_lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
                if !all_lines.is_empty() {
                    println!("{}", "[AI] Filtrando resultados do Chameleon com Ollama...".cyan());
                    let before_count = all_lines.len();
                    let mut validated_lines = Vec::new();
                    for line in &all_lines {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        // Parse chameleon output: STATUS SIZE URL
                        let (status_code, response_size, url_str) = if parts.len() >= 3 {
                            let sc = parts[0].parse::<u16>().unwrap_or(0);
                            let sz = parts[1];
                            let u = parts[2];
                            (sc, sz.to_string(), u.to_string())
                        } else if parts.len() == 1 {
                            (200, "unknown".to_string(), parts[0].to_string())
                        } else {
                            validated_lines.push(*line);
                            continue;
                        };

                        // Extract path from URL
                        let path = url_str.split("://")
                            .nth(1)
                            .and_then(|s| s.find('/').map(|i| &s[i..]))
                            .unwrap_or(&url_str);

                        let verdict = ollama.analyze_directory_finding(
                            &url_str, status_code, &response_size, path,
                        ).await;
                        match verdict {
                            Some(v) if !v.is_real && v.confidence >= 70 => {
                                println!("{}", format!("  [AI] Chameleon FP: {} - {} ({})", status_code, path, v.reason).bright_black());
                            }
                            _ => validated_lines.push(*line),
                        }
                    }
                    let removed = before_count - validated_lines.len();
                    if removed > 0 {
                        let validated_content = validated_lines.join("\n");
                        let _ = fs::write(&chameleon_access_file, validated_content);
                        println!("{}", format!("[AI] Chameleon: {} falsos positivos removidos ({} findings reais)", removed, validated_lines.len()).green());
                    }
                }
            }
        }

        chameleon_count = if chameleon_access_file.exists() {
            count_lines(&chameleon_access_file)?
        } else {
            0
        };
    }

    progress.tool_completed("Chameleon", 100.0);
    progress.data_found("directory findings", chameleon_count, 100.0);

    // Display Chameleon results summary
    println!();
    println!("{}", "┌───────────────────────────────────────────────────────────────────────────────┐".green().bold());
    println!("{}", "│  ✅ CHAMELEON SCAN COMPLETE                                                   │".green().bold());
    println!("{}", "├───────────────────────────────────────────────────────────────────────────────┤".green());
    if chameleon_count > 0 {
        println!("{}", format!("│  📁 Found {} interesting paths/directories{}│", chameleon_count, " ".repeat(42_usize.saturating_sub(chameleon_count.to_string().len()))).cyan().bold());
    } else {
        println!("{}", "│  ⚪ No interesting paths found                                                │".bright_black());
    }
    println!("{}", "└───────────────────────────────────────────────────────────────────────────────┘".green());
    println!();

    // ═══════════════════════════════════════════════════════════════════════════
    // VULNERABILITY SCANNING SUMMARY
    // ═══════════════════════════════════════════════════════════════════════════
    println!("{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".magenta().bold());
    println!("{}", "║  📊 STAGE 11 SUMMARY                                                          ║".magenta().bold());
    println!("{}", "╠═══════════════════════════════════════════════════════════════════════════════╣".magenta());
    println!("{}", format!("║  🔬 Nuclei Vulnerabilities: {}{}║", nuclei_count, " ".repeat(48_usize.saturating_sub(nuclei_count.to_string().len()))).magenta());
    println!("{}", format!("║  📂 Directory Findings: {}{}║", chameleon_count, " ".repeat(52_usize.saturating_sub(chameleon_count.to_string().len()))).magenta());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".magenta().bold());
    println!();

    // Parse and add vulnerability details from Nuclei output
    if let Some(ref mut web_metrics) = metrics.web_metrics {
        web_metrics.total_vulnerabilities = nuclei_count;

        // Read and parse Nuclei NDJSON output
        if nuclei_file.exists() {
            if let Ok(content) = fs::read_to_string(&nuclei_file) {
                for line in content.lines() {
                    if let Ok(vuln) = serde_json::from_str::<serde_json::Value>(line) {
                        let name = vuln["info"]["name"].as_str().unwrap_or("Unknown").to_string();
                        let severity = vuln["info"]["severity"].as_str().unwrap_or("info").to_string();
                        let target = vuln["matched-at"]
                            .as_str()
                            .or_else(|| vuln["host"].as_str())
                            .unwrap_or("Unknown")
                            .to_string();

                        // Add vulnerability to metrics
                        web_metrics.add_vulnerability(name.clone(), severity.clone(), target.clone());

                        // Send Discord notification for critical/high vulnerabilities
                        if let Some(ref webhook_url) = args.discord_webhook {
                            if severity == "critical" || severity == "high" {
                                let _ = discord_notifier::notify_critical_vulnerability(
                                    webhook_url,
                                    domain,
                                    &name,
                                    &severity,
                                    &target,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STAGE 12: LOGIN BRUTEFORCE (Optional, if enabled)
    // ═══════════════════════════════════════════════════════════════════════════
    if args.bruteforce {
        println!("\n{}", "═══════════════════════════════════════════════════════════════".yellow().bold());
        println!("{}", "  STAGE 12: LOGIN BRUTEFORCE (Optional)".yellow().bold());
        println!("{}", "═══════════════════════════════════════════════════════════════".yellow().bold());

        progress.tool_started("Login Bruteforce");

        // Validate wordlists
        if args.userlist.is_none() || args.passlist.is_none() {
            println!("{}", "[!] Bruteforce enabled but wordlists not provided!".yellow());
            println!("{}", "    Use --userlist <FILE> and --passlist <FILE>".yellow());
        } else {
            let userlist = args.userlist.as_ref().unwrap();
            let passlist = args.passlist.as_ref().unwrap();

            // Detect login forms
            println!("{}", "[*] Detecting login forms on discovered URLs...".cyan());
            let login_forms = bruteforce::detect_login_forms(&http200_urls, &client).await;

            // Save detected forms
            let login_forms_file = base_path.join("login_forms.json");
            if let Err(e) = bruteforce::save_login_forms(&login_forms, &login_forms_file) {
                eprintln!("[!] Failed to save login forms: {}", e);
            } else {
                println!("{}", format!("[+] Login forms saved to: {}", login_forms_file.display()).green());
            }

            if !login_forms.is_empty() {
                // Perform bruteforce
                let config = bruteforce::BruteforceConfig::default();
                println!("{}", format!("[*] Starting bruteforce attack on {} login forms...", login_forms.len()).cyan());
                println!("{}", format!("    Rate limit: {}ms between requests", config.rate_limit_ms).cyan());

                let mut valid_credentials = bruteforce::bruteforce_logins(
                    &login_forms,
                    userlist,
                    passlist,
                    &client,
                    &config,
                ).await;

                // AI Filter: Validate bruteforce results with Ollama
                if ollama.is_available().await && !valid_credentials.is_empty() {
                    println!("{}", "[AI] Validando credenciais bruteforce com Ollama...".cyan());
                    let before_count = valid_credentials.len();
                    let mut filtered = Vec::new();
                    for cred in &valid_credentials {
                        let indicators = cred.success_indicators.join(", ");
                        let verdict = ollama.analyze_credential_result(
                            &cred.url,
                            &cred.username,
                            "",
                            &indicators,
                            cred.response_status,
                        ).await;
                        match verdict {
                            Some(v) if !v.is_real && v.confidence >= 75 => {
                                println!("{}", format!("  [AI] Bruteforce FP: {}:{} em {} ({})", cred.username, cred.password, cred.url, v.reason).bright_black());
                            }
                            _ => filtered.push(cred.clone()),
                        }
                    }
                    let removed = before_count - filtered.len();
                    if removed > 0 {
                        println!("{}", format!("[AI] Bruteforce: {} falsos positivos removidos ({} validas)", removed, filtered.len()).green());
                    }
                    valid_credentials = filtered;
                }

                // Save valid credentials
                if !valid_credentials.is_empty() {
                    let creds_file = base_path.join("valid_credentials.json");
                    if let Err(e) = bruteforce::save_valid_credentials(&valid_credentials, &creds_file) {
                        eprintln!("[!] Failed to save valid credentials: {}", e);
                    } else {
                        println!("{}", "═══════════════════════════════════════════════════════════════".red().bold());
                        println!("{}", format!("  [!] CRITICAL: Found {} VALID CREDENTIALS!", valid_credentials.len()).red().bold());
                        println!("{}", "═══════════════════════════════════════════════════════════════".red().bold());
                        println!("{}", format!("[+] Credentials saved to: {}", creds_file.display()).green().bold());

                        for cred in &valid_credentials {
                            println!("{}", format!("    [{}] {}:{}", cred.url, cred.username, cred.password).yellow());
                        }
                    }
                } else {
                    println!("{}", "[*] No valid credentials found".yellow());
                }
            } else {
                println!("{}", "[*] No login forms detected on target URLs".yellow());
            }

            progress.tool_completed("Login Bruteforce", 100.0);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CONSOLIDATION & FINAL REPORT
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".green().bold());
    println!("{}", "  CONSOLIDATION & FINAL REPORT".green().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".green().bold());

    // Generate consolidated results file
    let all_results_file = base_path.join("all_results.txt");
    generate_consolidated_report(
        &base_path,
        &all_results_file,
        domain,
        total_subdomains,
        &http200_urls,
        &enhanced_secrets,
        &trufflehog_secrets,
        &admin_panels,
        nuclei_count,
        &wpscan_all_results,
        &shortscan_all_results,
    )?;

    println!("{}", format!("[+] Consolidated report: {}", all_results_file.display()).green().bold());

    // AI: Generate executive summary with Ollama
    if ollama.is_available().await {
        println!("{}", "[AI] Gerando executive summary com Ollama...".cyan());
        let mut critical_findings = Vec::new();
        for secret in enhanced_secrets.iter().filter(|s| s.severity == "CRITICAL").take(5) {
            critical_findings.push(format!("{}: {} em {}", secret.secret_type, secret.secret_preview, secret.found_in_url));
        }
        for panel in admin_panels.iter().filter(|p| p.is_likely_admin).take(3) {
            critical_findings.push(format!("Admin Panel: {} ({})", panel.url, panel.title.as_deref().unwrap_or("N/A")));
        }
        for wp_result in &wpscan_all_results {
            for vuln in wp_result.vulnerabilities.iter().filter(|v| v.severity == "critical" || v.severity == "high").take(3) {
                critical_findings.push(format!("WordPress {}: {} on {} ({})", vuln.severity.to_uppercase(), vuln.title, wp_result.target_url, vuln.cve.as_deref().unwrap_or("no CVE")));
            }
        }
        for ss_result in &shortscan_all_results {
            if ss_result.total_findings > 0 {
                critical_findings.push(format!("IIS 8.3 Short Filenames: {} hidden file(s) on {}", ss_result.total_findings, ss_result.target_url));
            }
        }

        if let Some(summary) = ollama.generate_executive_summary(
            domain,
            total_subdomains,
            http200_urls.len(),
            enhanced_secrets.len() + trufflehog_secrets.len(),
            nuclei_count,
            admin_panels.len(),
            &critical_findings,
        ).await {
            let summary_file = base_path.join("ai_executive_summary.txt");
            let _ = fs::write(&summary_file, &summary);
            println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".magenta().bold());
            println!("{}", "║  🤖 AI EXECUTIVE SUMMARY                                                      ║".magenta().bold());
            println!("{}", "╠═══════════════════════════════════════════════════════════════════════════════╣".magenta());
            for line in summary.lines().take(12) {
                let padded = format!("║  {}{}║", line, " ".repeat(75_usize.saturating_sub(line.len())));
                println!("{}", padded.magenta());
            }
            println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".magenta().bold());
            println!("{}", format!("[AI] Summary salvo em: {}", summary_file.display()).green());
        }
    }

    // Finalize metrics
    metrics.finalize();
    let metrics_file = base_path.join("scan_metrics.json");
    let metrics_json = serde_json::to_string_pretty(&metrics)?;
    fs::write(&metrics_file, metrics_json)?;
    println!("{}", format!("[+] Scan metrics saved: {}", metrics_file.display()).green());

    // Mark scan as completed
    progress.scan_completed();

    // ═══════════════════════════════════════════════════════════════════════════
    // GENERATE HTML REPORT
    // ═══════════════════════════════════════════════════════════════════════════
    println!("\n{}", "═══════════════════════════════════════════════════════════════".cyan().bold());
    println!("{}", "  GENERATING HTML REPORT".cyan().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan().bold());

    match report_generator::generate_html_report(&base_path, domain) {
        Ok(html_path) => {
            println!("{}", format!("[+] HTML report generated: {}", html_path).green().bold());
            println!("{}", format!("    Open in browser: file://{}", html_path).cyan());
        }
        Err(e) => {
            println!("{}", format!("[!] Failed to generate HTML report: {}", e).yellow());
        }
    }

    // Print summary
    print_scan_summary(domain, &base_path, &metrics);

    // Send final scan summary to Discord
    if let Some(ref webhook_url) = args.discord_webhook {
        let wpscan_vuln_count: usize = wpscan_all_results.iter().map(|r| r.total_vulnerabilities).sum();
        let shortscan_finding_count: usize = shortscan_all_results.iter().map(|r| r.total_findings).sum();
        let total_findings = admin_panels.len() + enhanced_secrets.len() + trufflehog_secrets.len() + nuclei_count + wpscan_vuln_count + shortscan_finding_count;
        let _ = discord_notifier::notify_scan_complete(
            webhook_url,
            domain,
            total_findings,
            admin_panels.len(),
            valid_credentials.len(),
            enhanced_secrets.len() + trufflehog_secrets.len(),
            nuclei_count,
        )
        .await;
    }

    Ok(())
}

/// Generate consolidated report
#[allow(clippy::too_many_arguments)]
fn generate_consolidated_report(
    base_path: &Path,
    output_file: &Path,
    domain: &str,
    total_subdomains: usize,
    http200_urls: &[String],
    secrets: &[secrets_scanner::HardcodedSecret],
    trufflehog_secrets: &[serde_json::Value],
    admin_panels: &[admin_finder::AdminPanelResult],
    vulnerabilities: usize,
    wpscan_results: &[wpscan::WPScanResults],
    shortscan_results: &[shortscan::ShortscanResult],
) -> Result<()> {
    let mut file = File::create(output_file)?;

    writeln!(file, "═══════════════════════════════════════════════════════════════")?;
    writeln!(file, "  ENUMRUST SCAN REPORT")?;
    writeln!(file, "═══════════════════════════════════════════════════════════════")?;
    writeln!(file, "Target Domain: {}", domain)?;
    writeln!(file, "Scan Date: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(file)?;

    writeln!(file, "SUMMARY:")?;
    writeln!(file, "  - Subdomains found: {}", total_subdomains)?;
    writeln!(file, "  - Live hosts (HTTP 200): {}", http200_urls.len())?;
    writeln!(file, "  - Admin panels found: {}", admin_panels.len())?;
    let high_confidence_admin = admin_panels.iter().filter(|p| p.is_likely_admin).count();
    writeln!(file, "  - High confidence admin panels: {}", high_confidence_admin)?;
    writeln!(file, "  - Hardcoded secrets: {}", secrets.len())?;
    writeln!(file, "  - TruffleHog secrets: {}", trufflehog_secrets.len())?;
    writeln!(file, "  - Vulnerabilities: {}", vulnerabilities)?;

    // WordPress section
    if !wpscan_results.is_empty() {
        let total_wp_vulns: usize = wpscan_results.iter().map(|r| r.total_vulnerabilities).sum();
        let total_wp_users: usize = wpscan_results.iter().map(|r| r.users.len()).sum();
        writeln!(file, "  - WordPress sites scanned: {}", wpscan_results.len())?;
        writeln!(file, "  - WordPress vulnerabilities: {}", total_wp_vulns)?;
        writeln!(file, "  - WordPress users enumerated: {}", total_wp_users)?;
    }
    writeln!(file)?;

    // WordPress details
    if !wpscan_results.is_empty() {
        writeln!(file, "WORDPRESS FINDINGS:")?;
        for result in wpscan_results {
            writeln!(file, "  Target: {}", result.target_url)?;
            if let Some(ref ver) = result.wordpress_version {
                writeln!(file, "    Version: {} ({})", ver.number, ver.status)?;
            }
            if !result.vulnerabilities.is_empty() {
                writeln!(file, "    Vulnerabilities:")?;
                for vuln in &result.vulnerabilities {
                    writeln!(file, "      - [{}] {} ({})", vuln.severity.to_uppercase(), vuln.title, vuln.cve.as_deref().unwrap_or("no CVE"))?;
                }
            }
            if !result.users.is_empty() {
                let user_list: Vec<&str> = result.users.iter().map(|u| u.login.as_str()).collect();
                writeln!(file, "    Users: {}", user_list.join(", "))?;
            }
        }
        writeln!(file)?;
    }

    // IIS Short Filename section
    if !shortscan_results.is_empty() {
        let total_short_findings: usize = shortscan_results.iter().map(|r| r.total_findings).sum();
        writeln!(file, "  - IIS servers scanned (shortscan): {}", shortscan_results.len())?;
        writeln!(file, "  - IIS short filenames discovered: {}", total_short_findings)?;
        writeln!(file)?;

        writeln!(file, "IIS SHORT FILENAME FINDINGS:")?;
        for result in shortscan_results {
            writeln!(file, "  Target: {}", result.target_url)?;
            for finding in &result.findings {
                let fullname = finding.fullname.as_deref().unwrap_or("???");
                writeln!(file, "    - [{}] {} -> {}", finding.finding_type.to_uppercase(), finding.shortname, fullname)?;
            }
        }
        writeln!(file)?;
    }

    writeln!(file, "OUTPUT FILES:")?;
    for entry in (fs::read_dir(base_path)?).flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                writeln!(file, "  - {}", file_name.to_string_lossy())?;
            }
        }
    }

    writeln!(file)?;
    writeln!(file, "═══════════════════════════════════════════════════════════════")?;

    Ok(())
}

/// Print final scan summary
fn print_scan_summary(domain: &str, base_path: &Path, metrics: &EnumRustMetrics) {
    println!("\n{}", "═══════════════════════════════════════════════════════════════".green().bold());
    println!("{}", format!("  SCAN COMPLETED: {}", domain).green().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".green().bold());

    if let Some(ref web_metrics) = metrics.web_metrics {
        println!("{}", format!("  Subdomains discovered: {}", web_metrics.total_subdomains).cyan());
        println!("{}", format!("  Unique IPs: {}", web_metrics.total_unique_ips).cyan());
        println!("{}", format!("  Live hosts: {}", web_metrics.total_urls_crawled).cyan());
        println!("{}", format!("  API endpoints: {}", web_metrics.total_endpoints_found).cyan());
        println!("{}", format!("  Secrets found: {}", web_metrics.total_secrets_found).yellow());
        println!("{}", format!("  Vulnerabilities: {}", web_metrics.total_vulnerabilities).red());
    }

    println!("{}", format!("  Scan duration: {:.2}s", metrics.duration_seconds).cyan());
    println!("{}", format!("  Results directory: {}/", base_path.display()).green());
    println!("{}", "═══════════════════════════════════════════════════════════════".green().bold());
    println!("\n{}", "[*] All results saved successfully!".green().bold());
    println!("{}", format!("[*] View consolidated report: {}/all_results.txt", base_path.display()).cyan());
}

/// Display nuclei vulnerabilities from a directory with colored output
async fn display_nuclei_vulnerabilities(base_dir: &str) -> Result<()> {
    println!("\n{}", "═══════════════════════════════════════════════════════════════".red().bold());
    println!("{}", "  🔍 NUCLEI VULNERABILITIES SUMMARY".red().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".red().bold());

    let cmd = format!(
        r#"find {} -name nuclei.txt | xargs cat 2>/dev/null | jq -r '
          select(.info != null) |
          "\(.info.severity)|\(.info.name)|\(.host // .url // "N/A")|\(.["matched-at"] // .matched // "N/A")|\(.["curl-command"] // "N/A")"
        ' 2>/dev/null | while IFS='|' read -r severity title host matched curl_cmd; do
          case "$severity" in
            critical) color="\e[1;31m" ;;
            high)     color="\e[0;91m" ;;
            medium)   color="\e[0;33m" ;;
            low)      color="\e[0;32m" ;;
            info)     color="\e[0;34m" ;;
            *)        color="\e[0;37m" ;;
          esac

          echo -e "${{color}}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
          echo -e "${{color}}[${{severity^^}}]\e[0m \e[1;37m$title\e[0m"
          echo -e "\e[0;36m[URL]\e[0m $host"
          echo -e "\e[0;35m[MATCHED]\e[0m $matched"
          echo -e "\e[0;33m[PoC]\e[0m $curl_cmd"
        done"#,
        base_dir
    );

    let output = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            println!("{}", "\n[*] No nuclei vulnerabilities found in this scan.".yellow());
        } else {
            println!("{}", stdout);
        }
    } else {
        println!("{}", "[!] Failed to parse nuclei results (jq may not be installed)".yellow());
    }

    println!("{}", "═══════════════════════════════════════════════════════════════\n".red().bold());

    Ok(())
}

/// Count lines in a file
fn count_lines(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let raw = fs::read(path)?;
    let content = String::from_utf8_lossy(&raw);
    Ok(content.lines().filter(|line| !line.trim().is_empty()).count())
}

/// Parse JSON outputs in object-per-line or full JSON formats and return JSON objects.
fn parse_json_objects_from_content(content: &str) -> Vec<serde_json::Value> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        match value {
            serde_json::Value::Array(items) => {
                out.extend(items.into_iter().filter(|item| item.is_object()));
                return out;
            }
            serde_json::Value::Object(_) => {
                out.push(value);
                return out;
            }
            _ => {}
        }
    }

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if value.is_object() {
                out.push(value);
            }
        }
    }

    out
}

/// Parse FFUF output in JSON or NDJSON variants and extract discovered URLs.
fn extract_ffuf_urls(content: &str) -> Vec<String> {
    let mut urls = Vec::new();

    for value in parse_json_objects_from_content(content) {
        if let Some(results) = value.get("results").and_then(|v| v.as_array()) {
            for result in results {
                if let Some(url) = result.get("url").and_then(|u| u.as_str()) {
                    urls.push(url.to_string());
                }
            }
            continue;
        }

        if let Some(url) = value.get("url").and_then(|u| u.as_str()) {
            urls.push(url.to_string());
        }
    }

    urls
}

/// Normalize a candidate hostname and keep only valid entries for target domain
fn normalize_subdomain_candidate(candidate: &str, domain: &str) -> Option<String> {
    let mut host = candidate.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    // Remove scheme/path/query/fragment if present
    if let Some(pos) = host.find("://") {
        host = host[(pos + 3)..].to_string();
    }
    host = host.split('/').next()?.to_string();
    host = host.split('?').next()?.to_string();
    host = host.split('#').next()?.to_string();
    host = host.split_whitespace().next()?.to_string();

    // Strip wildcard prefix and trailing dot
    host = host.trim_start_matches("*.").trim_end_matches('.').to_string();
    if host.is_empty() {
        return None;
    }

    // Remove trailing :port if present
    if let Some((left, right)) = host.rsplit_once(':') {
        if right.chars().all(|c| c.is_ascii_digit()) {
            host = left.to_string();
        }
    }

    // Skip obvious invalid entries
    if host.contains('*')
        || host.contains(' ')
        || host.starts_with('.')
        || host.ends_with('.')
        || !host.contains('.')
    {
        return None;
    }

    let target = domain.to_ascii_lowercase();
    if host == target || host.ends_with(&format!(".{}", target)) {
        Some(host)
    } else {
        None
    }
}

/// Read and normalize subdomains file into a unique set
fn read_normalized_subdomains(path: &Path, domain: &str) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    if !path.exists() {
        return Ok(set);
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if let Some(normalized) = normalize_subdomain_candidate(&line, domain) {
            set.insert(normalized);
        }
    }
    Ok(set)
}

/// Persist subdomains in sorted deterministic order
fn write_subdomains_sorted(path: &Path, subdomains: &HashSet<String>) -> Result<()> {
    let sorted: BTreeSet<String> = subdomains.iter().cloned().collect();
    let mut output = String::new();
    for host in sorted {
        output.push_str(&host);
        output.push('\n');
    }
    fs::write(path, output)?;
    Ok(())
}

/// Fetch subdomains from native passive sources
async fn fetch_native_passive_subdomains(client: &Client, domain: &str) -> Result<Vec<String>> {
    let mut all = Vec::new();

    // crt.sh JSON certificate transparency feed
    let crt_url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    if let Ok(response) = client.get(&crt_url).send().await {
        if response.status().is_success() {
            if let Ok(body) = response.text().await {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                    for entry in entries {
                        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
                            for item in name_value.lines() {
                                all.push(item.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // dns.bufferover.run passive DNS feed
    let buffer_url = format!("https://dns.bufferover.run/dns?q=.{}", domain);
    if let Ok(response) = client.get(&buffer_url).send().await {
        if response.status().is_success() {
            if let Ok(body) = response.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(fdns_a) = json.get("FDNS_A").and_then(|v| v.as_array()) {
                        for row in fdns_a {
                            if let Some(value) = row.as_str() {
                                if let Some((_, host)) = value.split_once(',') {
                                    all.push(host.to_string());
                                }
                            }
                        }
                    }
                    if let Some(rd_ns) = json.get("RDNS").and_then(|v| v.as_array()) {
                        for row in rd_ns {
                            if let Some(value) = row.as_str() {
                                all.push(value.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // CertSpotter certificate transparency API
    let certspotter_url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        domain
    );
    if let Ok(response) = client.get(&certspotter_url).send().await {
        if response.status().is_success() {
            if let Ok(body) = response.text().await {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                    for entry in entries {
                        if let Some(dns_names) = entry.get("dns_names").and_then(|v| v.as_array()) {
                            for dns_name in dns_names {
                                if let Some(name) = dns_name.as_str() {
                                    all.push(name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // AlienVault OTX passive DNS
    let otx_url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    if let Ok(response) = client.get(&otx_url).send().await {
        if response.status().is_success() {
            if let Ok(body) = response.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(passive_dns) = json.get("passive_dns").and_then(|v| v.as_array()) {
                        for record in passive_dns {
                            if let Some(hostname) = record.get("hostname").and_then(|v| v.as_str()) {
                                all.push(hostname.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(all)
}

/// Best-effort extraction of host from a URL-like line.
fn extract_host_from_url_like(value: &str) -> Option<String> {
    let raw = value.trim();
    if raw.is_empty() {
        return None;
    }

    // Try as full URL first
    if let Ok(url) = url::Url::parse(raw) {
        return url.host_str().map(|h| h.to_ascii_lowercase());
    }

    // Fallback: parse as host/path by forcing scheme
    let with_scheme = format!("https://{}", raw.trim_start_matches("//"));
    if let Ok(url) = url::Url::parse(&with_scheme) {
        return url.host_str().map(|h| h.to_ascii_lowercase());
    }

    None
}

/// Collect additional candidates by mining historical URL providers.
async fn collect_archive_subdomain_candidates(domain: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    // gau --subs domain
    if discover_tool_path("gau").is_some() {
        let cmd = format!("gau --subs {} 2>/dev/null", domain);
        if let Ok(output) = Command::new("sh").arg("-c").arg(&cmd).output().await {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(host) = extract_host_from_url_like(line) {
                        if seen.insert(host.clone()) {
                            out.push(host);
                        }
                    }
                }
            }
        }
    }

    // echo domain | waybackurls
    if discover_tool_path("waybackurls").is_some() {
        let cmd = format!("echo {} | waybackurls 2>/dev/null", domain);
        if let Ok(output) = Command::new("sh").arg("-c").arg(&cmd).output().await {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(host) = extract_host_from_url_like(line) {
                        if seen.insert(host.clone()) {
                            out.push(host);
                        }
                    }
                }
            }
        }
    }

    Ok(out)
}

/// DNS bruteforce of common high-yield subdomain labels.
async fn brute_force_common_subdomains(domain: &str, workers: usize) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("failed to initialize DNS resolver from system config")?;

    let common_labels: &[&str] = &[
        "www", "api", "app", "admin", "portal", "staging", "dev", "test", "uat", "prod",
        "auth", "login", "sso", "oauth", "id", "identity", "accounts", "account",
        "m", "mobile", "cdn", "assets", "static", "media", "img", "images",
        "files", "download", "uploads", "docs", "help", "support", "status",
        "mail", "smtp", "imap", "pop", "mx", "webmail", "autodiscover",
        "vpn", "remote", "rdp", "ssh", "git", "gitlab", "github", "repo",
        "jenkins", "ci", "grafana", "kibana", "monitor", "metrics",
        "shop", "store", "checkout", "payment", "payments", "billing",
        "blog", "news", "forum", "community", "beta", "alpha", "sandbox",
        "internal", "intranet", "secure", "edge", "origin", "ns1", "ns2",
    ];

    let concurrency = workers.clamp(10, 200);
    let labels: Vec<String> = common_labels.iter().map(|s| s.to_string()).collect();

    let found = stream::iter(labels)
        .map(|label| {
            let resolver = resolver.clone();
            let fqdn = format!("{}.{}", label, domain);
            async move {
                match tokio::time::timeout(Duration::from_secs(4), resolver.lookup_ip(fqdn.clone())).await {
                    Ok(Ok(lookup)) if lookup.iter().next().is_some() => Some(fqdn),
                    _ => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<Option<String>>>()
        .await;

    Ok(found.into_iter().flatten().collect())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TOOL MANAGEMENT FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════════

/// Tool definition with installation info
struct ToolInfo {
    name: &'static str,
    binary: &'static str,
    description: &'static str,
    is_core: bool,
    install_cmd: &'static str,
}

/// Get list of all required tools
fn get_tools_list() -> Vec<ToolInfo> {
    vec![
        // Core tools (required)
        ToolInfo {
            name: "httpx",
            binary: "httpx",
            description: "HTTP probing and validation",
            is_core: true,
            install_cmd: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        ToolInfo {
            name: "dnsx",
            binary: "dnsx",
            description: "DNS resolution and validation",
            is_core: true,
            install_cmd: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
        ToolInfo {
            name: "nuclei",
            binary: "nuclei",
            description: "Vulnerability scanner",
            is_core: true,
            install_cmd: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        ToolInfo {
            name: "masscan",
            binary: "masscan",
            description: "Port scanner (requires sudo)",
            is_core: true,
            install_cmd: "apt-get install -y masscan || brew install masscan || pacman -S masscan",
        },
        // Optional tools
        ToolInfo {
            name: "subfinder",
            binary: "subfinder",
            description: "Passive subdomain discovery",
            is_core: false,
            install_cmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        ToolInfo {
            name: "haktrails",
            binary: "haktrails",
            description: "SecurityTrails subdomain discovery",
            is_core: false,
            install_cmd: "go install -v github.com/hakluke/haktrails@latest",
        },
        ToolInfo {
            name: "tlsx",
            binary: "tlsx",
            description: "TLS/SSL certificate analysis",
            is_core: false,
            install_cmd: "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        },
        ToolInfo {
            name: "ffuf",
            binary: "ffuf",
            description: "Fast web fuzzer",
            is_core: false,
            install_cmd: "go install -v github.com/ffuf/ffuf/v2@latest",
        },
        ToolInfo {
            name: "chameleon",
            binary: "chameleon",
            description: "Smart directory brute-forcer with tech detection",
            is_core: false,
            install_cmd: "Download from https://github.com/iustin24/chameleon/releases",
        },
        ToolInfo {
            name: "trufflehog",
            binary: "trufflehog",
            description: "Secret scanner",
            is_core: false,
            install_cmd: "go install -v github.com/trufflesecurity/trufflehog/v3@latest",
        },
        ToolInfo {
            name: "anew",
            binary: "anew",
            description: "Append unique lines to file",
            is_core: false,
            install_cmd: "go install -v github.com/tomnomnom/anew@latest",
        },
        ToolInfo {
            name: "jq",
            binary: "jq",
            description: "JSON processor",
            is_core: false,
            install_cmd: "apt-get install -y jq || brew install jq || pacman -S jq",
        },
        ToolInfo {
            name: "whois",
            binary: "whois",
            description: "Domain registration lookup",
            is_core: false,
            install_cmd: "apt-get install -y whois || brew install whois || pacman -S whois",
        },
        ToolInfo {
            name: "tmux",
            binary: "tmux",
            description: "Terminal multiplexer (persistent sessions)",
            is_core: false,
            install_cmd: "apt-get install -y tmux || brew install tmux || pacman -S tmux",
        },
        // Additional discovery tools
        ToolInfo {
            name: "hakrawler",
            binary: "hakrawler",
            description: "Web crawler for URL discovery",
            is_core: false,
            install_cmd: "go install -v github.com/hakluke/hakrawler@latest",
        },
        ToolInfo {
            name: "urlfinder",
            binary: "urlfinder",
            description: "Passive URL discovery from archives",
            is_core: false,
            install_cmd: "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
        },
        ToolInfo {
            name: "katana",
            binary: "katana",
            description: "Fast web crawler",
            is_core: false,
            install_cmd: "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        },
        ToolInfo {
            name: "gau",
            binary: "gau",
            description: "Fetch URLs from web archives",
            is_core: false,
            install_cmd: "go install -v github.com/lc/gau/v2/cmd/gau@latest",
        },
        ToolInfo {
            name: "waybackurls",
            binary: "waybackurls",
            description: "Fetch URLs from Wayback Machine",
            is_core: false,
            install_cmd: "go install -v github.com/tomnomnom/waybackurls@latest",
        },
        ToolInfo {
            name: "wpscan",
            binary: "docker",
            description: "WordPress security scanner (Docker)",
            is_core: false,
            install_cmd: "curl -fsSL https://get.docker.com | sh && docker pull wpscanteam/wpscan",
        },
        ToolInfo {
            name: "shortscan",
            binary: "shortscan",
            description: "IIS short filename scanner",
            is_core: false,
            install_cmd: "go install github.com/bitquark/shortscan/cmd/shortscan@latest",
        },
    ]
}

/// Common paths where security tools may be installed
fn get_common_tool_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let gopath = std::env::var("GOPATH").unwrap_or_else(|_| format!("{}/go", home));

    vec![
        // Go binaries (most common for security tools)
        PathBuf::from(format!("{}/bin", gopath)),
        PathBuf::from(format!("{}/go/bin", home)),
        PathBuf::from("/usr/local/go/bin"),
        // Cargo binaries (chameleon, etc.)
        PathBuf::from(format!("{}/.cargo/bin", home)),
        // System paths
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        // Snap packages
        PathBuf::from("/snap/bin"),
        // Homebrew (Linux)
        PathBuf::from("/home/linuxbrew/.linuxbrew/bin"),
        PathBuf::from(format!("{}/.linuxbrew/bin", home)),
        // Pipx / pip user installs
        PathBuf::from(format!("{}/.local/bin", home)),
        // nix
        PathBuf::from(format!("{}/.nix-profile/bin", home)),
        // Common pentest tool locations
        PathBuf::from("/opt/tools"),
        PathBuf::from("/opt/bin"),
    ]
}

/// Search for a binary in common paths and return full path if found
fn discover_tool_path(binary: &str) -> Option<PathBuf> {
    // First try the current PATH via `which`
    if let Ok(output) = std::process::Command::new("which")
        .arg(binary)
        .output()
    {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }

    // Search common paths
    for dir in get_common_tool_paths() {
        let candidate = dir.join(binary);
        if candidate.exists() && candidate.is_file() {
            // Verify it's executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&candidate) {
                    if metadata.permissions().mode() & 0o111 != 0 {
                        return Some(candidate);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(candidate);
            }
        }
    }

    None
}

/// Auto-discover all tools and add their directories to PATH
/// Returns a map of tool binary -> full path for discovered tools
fn auto_discover_and_configure_path() -> std::collections::HashMap<String, PathBuf> {
    let tools = get_tools_list();
    let mut discovered: std::collections::HashMap<String, PathBuf> = std::collections::HashMap::new();
    let mut new_path_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let current_path = std::env::var("PATH").unwrap_or_default();

    for tool in &tools {
        if let Some(full_path) = discover_tool_path(tool.binary) {
            // Add the parent directory to PATH if not already there
            if let Some(parent) = full_path.parent() {
                let parent_str = parent.to_string_lossy().to_string();
                if !current_path.contains(&parent_str) {
                    new_path_dirs.insert(parent_str);
                }
            }
            discovered.insert(tool.binary.to_string(), full_path);
        }
    }

    // Also check for Go binary itself
    if let Some(go_path) = discover_tool_path("go") {
        if let Some(parent) = go_path.parent() {
            let parent_str = parent.to_string_lossy().to_string();
            if !current_path.contains(&parent_str) {
                new_path_dirs.insert(parent_str);
            }
        }
    }

    // Update PATH with all discovered directories
    if !new_path_dirs.is_empty() {
        let additions: Vec<&str> = new_path_dirs.iter().map(|s| s.as_str()).collect();
        let new_path = format!("{}:{}", additions.join(":"), current_path);
        std::env::set_var("PATH", &new_path);
    }

    discovered
}

/// Get path to the tools cache file
fn get_tools_cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".enumrust_tools_cache.json")
}

/// Save discovered tool paths to cache file
fn save_tools_cache(discovered: &std::collections::HashMap<String, PathBuf>) {
    let cache_path = get_tools_cache_path();
    let cache_data: std::collections::HashMap<String, String> = discovered
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string_lossy().to_string()))
        .collect();

    if let Ok(json) = serde_json::to_string_pretty(&cache_data) {
        let _ = fs::write(&cache_path, json);
    }
}

/// Load tool paths from cache and configure PATH
/// Returns true if cache was valid and loaded successfully
fn load_tools_cache_and_configure() -> bool {
    let cache_path = get_tools_cache_path();

    // Check if cache exists
    let content = match fs::read_to_string(&cache_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Parse cache
    let cache_data: std::collections::HashMap<String, String> = match serde_json::from_str(&content) {
        Ok(d) => d,
        Err(_) => return false,
    };

    if cache_data.is_empty() {
        return false;
    }

    // Verify that cached paths still exist (quick check on core tools only)
    let core_binaries = ["httpx", "dnsx", "nuclei"];
    for binary in &core_binaries {
        if let Some(path_str) = cache_data.get(*binary) {
            let path = PathBuf::from(path_str);
            if !path.exists() {
                // Cache is stale - a core tool was removed/moved
                let _ = fs::remove_file(&cache_path);
                return false;
            }
        }
    }

    // Cache is valid - add all directories to PATH
    let current_path = std::env::var("PATH").unwrap_or_default();
    let mut new_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for path_str in cache_data.values() {
        let path = PathBuf::from(path_str);
        if let Some(parent) = path.parent() {
            let parent_str = parent.to_string_lossy().to_string();
            if !current_path.contains(&parent_str) {
                new_dirs.insert(parent_str);
            }
        }
    }

    if !new_dirs.is_empty() {
        let additions: Vec<&str> = new_dirs.iter().map(|s| s.as_str()).collect();
        let new_path = format!("{}:{}", additions.join(":"), current_path);
        std::env::set_var("PATH", &new_path);
    }

    true
}

/// Invalidate (delete) the tools cache
fn invalidate_tools_cache() {
    let cache_path = get_tools_cache_path();
    let _ = fs::remove_file(&cache_path);
}

/// Validate that required tools are available before starting a scan
/// Uses cache to skip full discovery on subsequent runs
async fn validate_tools_before_scan(args: &Args) -> Result<()> {
    // Try loading from cache first (unless --revalidate-tools was passed)
    if !args.revalidate_tools && load_tools_cache_and_configure() {
        println!("{}", "[+] Tools validated (cached) - PATH configured.".green());
        println!();
        return Ok(());
    }

    // Full discovery needed
    println!("{}", "── TOOL VALIDATION ──".cyan().bold());
    println!("{}", "[*] Auto-discovering tools in system paths...".cyan());

    let discovered = auto_discover_and_configure_path();
    let tools = get_tools_list();

    let mut core_missing: Vec<&ToolInfo> = Vec::new();
    let mut optional_missing: Vec<&ToolInfo> = Vec::new();

    for tool in &tools {
        if discovered.get(tool.binary).is_none() {
            let is_needed = is_tool_needed_for_scan(tool.binary, args);
            if tool.is_core && is_needed {
                core_missing.push(tool);
            } else if is_needed {
                optional_missing.push(tool);
            }
        }
    }

    // Report discovered tools
    let found_count = discovered.len();
    let total_tools = tools.len();
    println!("{}", format!("[+] Found {}/{} tools in system", found_count, total_tools).green());

    for tool in &tools {
        if let Some(path) = discovered.get(tool.binary) {
            println!("    {} {} → {}",
                "✓".green(),
                tool.name.green(),
                path.display().to_string().dimmed()
            );
        }
    }

    // Show warnings for missing optional tools
    if !optional_missing.is_empty() {
        println!();
        println!("{}", format!("[!] {} optional tool(s) not found (some features will be skipped):", optional_missing.len()).yellow());
        for tool in &optional_missing {
            println!("    {} {} - {}",
                "⚠".yellow(),
                tool.name.yellow(),
                tool.description
            );
        }
    }

    // Block if core tools are missing
    if !core_missing.is_empty() {
        println!();
        eprintln!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".red().bold());
        eprintln!("{}", "║              ERRO: FERRAMENTAS CORE NÃO ENCONTRADAS!                         ║".red().bold());
        eprintln!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".red().bold());
        for tool in &core_missing {
            eprintln!("{}",
                format!("║  ✗ {} - {}",
                    tool.name, tool.description
                ).red()
            );
            eprintln!("{}",
                format!("║    Instalar: {}",
                    tool.install_cmd
                ).yellow()
            );
        }
        eprintln!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".red().bold());
        eprintln!("{}", "║  Instale automaticamente com:  enumrust --install-tools                      ║".green());
        eprintln!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".red().bold());
        std::process::exit(1);
    }

    // Save cache for future runs
    save_tools_cache(&discovered);
    println!("{}", "[+] Tool validation complete - cached for next runs.".green().bold());
    println!("{}", "    Use --revalidate-tools to force re-discovery.".dimmed());
    println!();

    Ok(())
}

/// Check if a specific tool is needed for the current scan configuration
fn is_tool_needed_for_scan(binary: &str, args: &Args) -> bool {
    match binary {
        // Core tools always needed
        "httpx" | "dnsx" | "nuclei" => true,
        "masscan" => args.ip_scan || args.full_scan,
        // Conditional tools
        "subfinder" => args.subfinder || args.full_scan,
        "haktrails" => args.hacktrails || args.full_scan,
        "anew" => true, // Used in multiple pipeline stages
        "jq" => true,   // Used with tlsx output
        "tlsx" => true,  // Certificate SAN extraction
        "whois" => true, // WHOIS lookup
        "tmux" => false, // Nice to have but not required
        "hakrawler" => true, // URL discovery
        "ffuf" => true,  // Directory fuzzing (has chameleon fallback)
        "chameleon" => true, // Smart directory brute-forcer
        "trufflehog" => true, // Secret scanning
        "urlfinder" => true,
        "katana" => true,
        "gau" => true,
        "waybackurls" => true,
        "docker" => !args.no_wpscan, // WPScan runs via Docker
        "shortscan" => !args.no_shortscan, // IIS short filename scanning
        _ => false,
    }
}

/// Check if a tool is installed and get its version (with auto-discovery)
async fn check_tool_installed(binary: &str) -> (bool, Option<String>) {
    // Use discovery to find tool in common paths
    if discover_tool_path(binary).is_none() {
        return (false, None);
    }

    // Try to get version
    let version = get_tool_version(binary).await;
    (true, version)
}

/// Strip ANSI escape codes from a string
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip escape sequence: ESC [ ... final_byte
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // Consume until we hit a letter (the final byte of the sequence)
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Get tool version by running it with --version or -version flag
async fn get_tool_version(binary: &str) -> Option<String> {
    // Try --version first
    if let Ok(output) = Command::new(binary)
        .arg("--version")
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let version_str = if !stdout.trim().is_empty() { stdout } else { stderr };
            if let Some(line) = version_str.lines().next() {
                let clean = strip_ansi_codes(line.trim());
                if !clean.is_empty() {
                    return Some(clean);
                }
            }
        }
    }

    // Try -version for some tools
    if let Ok(output) = Command::new(binary)
        .arg("-version")
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let version_str = if !stdout.trim().is_empty() { stdout } else { stderr };
            if let Some(line) = version_str.lines().next() {
                let clean = strip_ansi_codes(line.trim());
                if !clean.is_empty() {
                    return Some(clean);
                }
            }
        }
    }

    None
}

/// Check and display status of all tools (with auto-discovery)
async fn check_tools_status() {
    println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║                        ENUMRUST - TOOL STATUS CHECK                          ║".cyan().bold());
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".cyan().bold());
    println!();

    // Auto-discover tools first
    println!("{}", "[*] Auto-discovering tools in system paths...".cyan());
    let discovered = auto_discover_and_configure_path();
    println!("{}", format!("[+] Searched {} common directories", get_common_tool_paths().len()).dimmed());
    println!();

    let tools = get_tools_list();

    // Check Go installation
    let go_path = discover_tool_path("go");
    if let Some(ref gp) = go_path {
        println!("{}", format!("✓ Go is installed → {}", gp.display()).green());
    } else {
        println!("{}", "⚠️  Go is NOT installed! Most tools require Go to install.".red().bold());
        println!("{}", "   Install Go from: https://go.dev/dl/".yellow());
        println!("{}", "   Or run: apt-get install golang-go".yellow());
    }
    println!();

    // Core tools
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());
    println!("{}", "  CORE TOOLS (Required)".white().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());

    let mut core_missing = 0;
    let mut optional_missing = 0;

    for tool in tools.iter().filter(|t| t.is_core) {
        let (installed, version) = check_tool_installed(tool.binary).await;
        let tool_path = discovered.get(tool.binary);
        print_tool_status_with_path(tool, installed, version.as_deref(), tool_path);
        if !installed {
            core_missing += 1;
        }
    }

    // Optional tools
    println!();
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());
    println!("{}", "  OPTIONAL TOOLS".white().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());

    for tool in tools.iter().filter(|t| !t.is_core) {
        let (installed, version) = check_tool_installed(tool.binary).await;
        let tool_path = discovered.get(tool.binary);
        print_tool_status_with_path(tool, installed, version.as_deref(), tool_path);
        if !installed {
            optional_missing += 1;
        }
    }

    // Show PATH configuration
    println!();
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());
    println!("{}", "  DISCOVERED PATHS".white().bold());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".white());

    let mut unique_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for path in discovered.values() {
        if let Some(parent) = path.parent() {
            unique_dirs.insert(parent.to_string_lossy().to_string());
        }
    }
    if unique_dirs.is_empty() {
        println!("{}", "  No tool directories discovered outside of PATH".dimmed());
    } else {
        for dir in &unique_dirs {
            println!("  {} {}", "→".cyan(), dir);
        }
    }

    // Summary
    println!();
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".cyan().bold());
    println!("{}", "║  SUMMARY                                                                     ║".cyan().bold());
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".cyan().bold());

    let found_count = discovered.len();
    let total_count = tools.len();
    println!("{}", format!("  Tools found: {}/{}", found_count, total_count).white());

    if core_missing > 0 {
        println!("{}", format!("  ⚠️  {} core tool(s) missing - some features won't work!", core_missing).red().bold());
    } else {
        println!("{}", "  ✓ All core tools installed!".green().bold());
    }

    if optional_missing > 0 {
        println!("{}", format!("  ℹ️  {} optional tool(s) missing", optional_missing).yellow());
    }

    println!();
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".cyan().bold());
    println!("{}", "║  To install missing tools, run:                                              ║".cyan());
    println!("{}", "║    enumrust --install-tools                                                  ║".green());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".cyan().bold());
}

/// Print status of a single tool with discovered path
fn print_tool_status_with_path(tool: &ToolInfo, installed: bool, version: Option<&str>, path: Option<&PathBuf>) {
    let status_icon = if installed { "✓".green() } else { "✗".red() };
    let name_colored = if installed {
        tool.name.green()
    } else {
        tool.name.red()
    };

    let version_str = if let Some(v) = version {
        let truncated = if v.len() > 30 { &v[..30] } else { v };
        format!("({})", truncated).dimmed().to_string()
    } else {
        "".to_string()
    };

    let path_str = if let Some(p) = path {
        format!("→ {}", p.display()).dimmed().to_string()
    } else if !installed {
        format!("Install: {}", tool.install_cmd).dimmed().to_string()
    } else {
        "".to_string()
    };

    println!(
        "  {} {:<15} - {:<35} {} {}",
        status_icon,
        name_colored,
        tool.description,
        version_str,
        path_str
    );
}

/// Install all required tools
async fn install_all_tools() -> Result<()> {
    println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".green().bold());
    println!("{}", "║                      ENUMRUST - INSTALLING TOOLS                             ║".green().bold());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".green().bold());
    println!();

    // Auto-discover existing tools first
    println!("{}", "[*] Auto-discovering already installed tools...".cyan());
    let _ = auto_discover_and_configure_path();
    println!();

    // Check if Go is installed (using discovery)
    let go_installed = discover_tool_path("go").is_some();

    if !go_installed {
        println!("{}", "⚠️  Go is NOT installed! Installing Go first...".yellow().bold());
        println!();

        // Try to install Go
        let go_install = Command::new("sh")
            .arg("-c")
            .arg("apt-get update && apt-get install -y golang-go")
            .status()
            .await;

        match go_install {
            Ok(status) if status.success() => {
                println!("{}", "✓ Go installed successfully!".green());
            }
            _ => {
                println!("{}", "✗ Failed to install Go automatically.".red());
                println!("{}", "  Please install Go manually from: https://go.dev/dl/".yellow());
                println!("{}", "  Then run this command again.".yellow());
                return Ok(());
            }
        }
        println!();
    }

    // Configure GOPATH and PATH
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let gopath = format!("{}/go", home);
    let gobin = format!("{}/bin", gopath);

    // Ensure go/bin directory exists
    let _ = fs::create_dir_all(&gobin);

    // Update PATH for this session
    let current_path = std::env::var("PATH").unwrap_or_default();
    if !current_path.contains(&gobin) {
        std::env::set_var("PATH", format!("{}:{}", gobin, current_path));
    }
    std::env::set_var("GOPATH", &gopath);

    println!("{}", format!("📁 GOPATH: {}", gopath).cyan());
    println!("{}", format!("📁 GOBIN:  {}", gobin).cyan());
    println!();

    let tools = get_tools_list();
    let mut installed_count = 0;
    let mut failed_count = 0;
    let mut skipped_count = 0;

    for tool in &tools {
        // Check if already installed
        let (already_installed, _) = check_tool_installed(tool.binary).await;

        if already_installed {
            println!("{}", format!("⏭️  {} - already installed, skipping", tool.name).dimmed());
            skipped_count += 1;
            continue;
        }

        println!("{}", format!("📦 Installing {}...", tool.name).cyan().bold());
        println!("{}", format!("   {}", tool.description).dimmed());

        let install_result = Command::new("sh")
            .arg("-c")
            .arg(tool.install_cmd)
            .env("GOPATH", &gopath)
            .env("PATH", format!("{}:{}", gobin, std::env::var("PATH").unwrap_or_default()))
            .status()
            .await;

        match install_result {
            Ok(status) if status.success() => {
                // Verify installation
                let (now_installed, version) = check_tool_installed(tool.binary).await;
                if now_installed {
                    let ver_str = version.unwrap_or_else(|| "version unknown".to_string());
                    println!("{}", format!("   ✓ {} installed successfully! ({})", tool.name, ver_str).green());
                    installed_count += 1;
                } else {
                    println!("{}", format!("   ⚠️  {} - command succeeded but binary not found in PATH", tool.name).yellow());
                    println!("{}", format!("      Try adding {} to your PATH", gobin).yellow());
                    failed_count += 1;
                }
            }
            _ => {
                println!("{}", format!("   ✗ Failed to install {}", tool.name).red());
                println!("{}", format!("      Manual install: {}", tool.install_cmd).dimmed());
                failed_count += 1;
            }
        }
        println!();
    }

    // Update nuclei templates if nuclei was installed
    let (nuclei_installed, _) = check_tool_installed("nuclei").await;
    if nuclei_installed {
        println!("{}", "📥 Updating nuclei templates...".cyan());
        let _ = Command::new("nuclei")
            .arg("-ut")
            .status()
            .await;
        println!("{}", "   ✓ Nuclei templates updated".green());
        println!();
    }

    // Auto-configure PATH in shell config files
    let path_configured = configure_shell_path(&gobin).await;

    // Summary
    println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".green().bold());
    println!("{}", "║                         INSTALLATION COMPLETE                                ║".green().bold());
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".green().bold());
    println!("{}", format!("║  ✓ Installed: {:<62}║", installed_count).green());
    println!("{}", format!("║  ⏭️  Skipped:  {:<62}║", skipped_count).dimmed());
    if failed_count > 0 {
        println!("{}", format!("║  ✗ Failed:    {:<62}║", failed_count).red());
    }
    println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".green().bold());

    if path_configured {
        println!("{}", "║  ✓ PATH configured automatically in shell config files                      ║".green());
        println!("{}", "║                                                                              ║".cyan());
        println!("{}", "║  To apply changes NOW, run:                                                  ║".cyan());
        println!("{}", "║    source ~/.bashrc   OR   source ~/.zshrc                                   ║".yellow());
        println!("{}", "║                                                                              ║".cyan());
        println!("{}", "║  Or simply open a new terminal window.                                       ║".cyan());
    } else {
        println!("{}", "║  ℹ️  PATH already configured or couldn't be auto-configured                  ║".yellow());
    }
    println!("{}", "║                                                                              ║".cyan());
    println!("{}", "║  Verify installation with:                                                   ║".cyan());
    println!("{}", "║    enumrust --check-tools                                                    ║".green());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".green().bold());

    Ok(())
}

/// Configure PATH in shell configuration files (.bashrc, .zshrc, .profile)
async fn configure_shell_path(gobin: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

    // Export line to add
    let export_line = format!("export PATH=\"$PATH:{}\"", gobin);
    let marker = "# EnumRust Go binaries PATH";
    let full_block = format!("\n{}\n{}\n", marker, export_line);

    let shell_configs = vec![
        format!("{}/.bashrc", home),
        format!("{}/.zshrc", home),
        format!("{}/.profile", home),
    ];

    let mut configured = false;

    for config_path in shell_configs {
        let path = Path::new(&config_path);

        // Skip if file doesn't exist
        if !path.exists() {
            continue;
        }

        // Read current content
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Skip if already configured (check for marker or the gobin path)
        if content.contains(marker) || content.contains(gobin) {
            println!("{}", format!("   ℹ️  PATH already in {}", config_path).dimmed());
            continue;
        }

        // Append the export line
        let mut file = match OpenOptions::new().append(true).open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if file.write_all(full_block.as_bytes()).is_ok() {
            println!("{}", format!("   ✓ Added PATH to {}", config_path).green());
            configured = true;
        }
    }

    // Also try to update current session's PATH via /etc/profile.d if we have permissions
    let profile_d = "/etc/profile.d/enumrust-go.sh";
    if !Path::new(profile_d).exists() {
        let profile_content = format!("#!/bin/sh\n{}\n{}\n", marker, export_line);
        if fs::write(profile_d, profile_content).is_ok() {
            let _ = std::process::Command::new("chmod")
                .args(["+x", profile_d])
                .output();
            println!("{}", format!("   ✓ Created system-wide profile: {}", profile_d).green());
            configured = true;
        }
    }

    configured
}

#[cfg(test)]
mod tests {
    use super::{
        extract_ffuf_urls, extract_host_from_url_like, normalize_domain, normalize_subdomain_candidate,
        parse_json_objects_from_content,
    };

    #[test]
    fn normalize_domain_accepts_valid_domains() {
        assert_eq!(
            normalize_domain("Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_domain("api.staging.example.co.uk"),
            Some("api.staging.example.co.uk".to_string())
        );
    }

    #[test]
    fn normalize_domain_rejects_invalid_input() {
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("example"), None);
        assert_eq!(normalize_domain("https://example.com"), None);
        assert_eq!(normalize_domain("../example.com"), None);
        assert_eq!(normalize_domain("exa mple.com"), None);
        assert_eq!(normalize_domain("-bad.example.com"), None);
        assert_eq!(normalize_domain("bad-.example.com"), None);
    }

    #[test]
    fn normalize_subdomain_candidate_handles_common_variants() {
        assert_eq!(
            normalize_subdomain_candidate("https://Api.EXAMPLE.com/v1/users", "example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            normalize_subdomain_candidate("*.cdn.example.com", "example.com"),
            Some("cdn.example.com".to_string())
        );
        assert_eq!(
            normalize_subdomain_candidate("other-domain.com", "example.com"),
            None
        );
    }

    #[test]
    fn extract_host_from_url_like_supports_urls_and_host_paths() {
        assert_eq!(
            extract_host_from_url_like("https://sub.example.com/path?a=1"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url_like("sub.example.com/path"),
            Some("sub.example.com".to_string())
        );
        assert_eq!(extract_host_from_url_like(""), None);
    }

    #[test]
    fn parse_json_objects_from_content_supports_array_and_ndjson() {
        let array_json = r#"[{"a":1},{"b":2}]"#;
        let array_items = parse_json_objects_from_content(array_json);
        assert_eq!(array_items.len(), 2);

        let ndjson = r#"{"x":1}
{"y":2}
"#;
        let ndjson_items = parse_json_objects_from_content(ndjson);
        assert_eq!(ndjson_items.len(), 2);
    }

    #[test]
    fn extract_ffuf_urls_supports_ffuf_json_and_line_json() {
        let ffuf_json = r#"{
  "results": [
    {"url": "https://a.example.com/app.js"},
    {"url": "https://a.example.com/main.js"}
  ]
}"#;
        let urls = extract_ffuf_urls(ffuf_json);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://a.example.com/app.js");

        let ndjson = r#"{"url":"https://b.example.com/vendor.js"}
{"url":"https://b.example.com/runtime.js"}"#;
        let line_urls = extract_ffuf_urls(ndjson);
        assert_eq!(line_urls.len(), 2);
    }
}
