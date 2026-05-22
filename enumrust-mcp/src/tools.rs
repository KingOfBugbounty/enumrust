// tools.rs - MCP tool definitions for EnumRust

use rust_mcp_sdk::macros::JsonSchema;
use rust_mcp_sdk::{macros::mcp_tool, tool_box};

//****************//
//  SubdomainEnumTool  //
//****************//
#[mcp_tool(
    name = "subdomain_enum",
    description = "Perform passive subdomain enumeration using subfinder and certificate transparency",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct SubdomainEnumTool {
    /// Target domain (e.g., example.com)
    domain: String,
}

impl SubdomainEnumTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.args(&["-d", &self.domain, "--subfinder"]);
        cmd
    }
}

//****************//
//  DnsResolveTool  //
//****************//
#[mcp_tool(
    name = "dns_resolve",
    description = "Resolve domains to IP addresses using dnsx",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct DnsResolveTool {
    /// List of domains to resolve
    domains: Vec<String>,
}

impl DnsResolveTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        let _domains_input = self.domains.join("\n");
        cmd.arg("-f").arg("-").stdin(std::process::Stdio::piped())
            .args(&["--dns"]);
        cmd
    }
}

//****************//
//  IpScanTool  //
//****************//
#[mcp_tool(
    name = "ip_scan",
    description = "Scan IP addresses for open ports and perform recursive directory fuzzing",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct IpScanTool {
    /// Target IP address or CIDR range
    ip: String,
    /// Ports to scan (default: top 1000)
    ports: Option<String>,
    /// Custom wordlist path for fuzzing
    wordlist: Option<String>,
}

impl IpScanTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.args(&["--infraestrutura", "--ip-range", &self.ip]);
        if let Some(ports) = &self.ports {
            cmd.args(&["--ip-ports", ports]);
        }
        if let Some(wordlist) = &self.wordlist {
            cmd.args(&["--ip-wordlist", wordlist]);
        }
        cmd
    }
}

//****************//
//  HttpProbeTool  //
//****************//
#[mcp_tool(
    name = "http_probe",
    description = "Probe HTTP hosts to check if they are alive/reachable",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct HttpProbeTool {
    /// List of hosts (URLs or IPs) to probe
    hosts: Vec<String>,
}

impl HttpProbeTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--httpx"]);
        cmd
    }
}

//****************//
//  JsCrawlTool  //
//****************//
#[mcp_tool(
    name = "js_crawl",
    description = "Crawl JavaScript files for hardcoded secrets, API endpoints, and cloud storage URLs",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct JsCrawlTool {
    /// List of JavaScript file URLs to analyze
    urls: Vec<String>,
}

impl JsCrawlTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--js-crawl"]);
        cmd
    }
}

//****************//
//  AdminFinderTool  //
//****************//
#[mcp_tool(
    name = "admin_finder",
    description = "Discover admin panels on common ports and paths",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct AdminFinderTool {
    /// List of hosts to scan for admin panels
    hosts: Vec<String>,
}

impl AdminFinderTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--admin-finder"]);
        cmd
    }
}

//****************//
//  SecretsScanTool  //
//****************//
#[mcp_tool(
    name = "secrets_scan",
    description = "Scan for hardcoded secrets, API keys, tokens, and credentials",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct SecretsScanTool {
    /// List of hosts to scan for secrets
    hosts: Vec<String>,
}

impl SecretsScanTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--secrets-scan"]);
        cmd
    }
}

//****************//
//  VulnScanTool  //
//****************//
#[mcp_tool(
    name = "vuln_scan",
    description = "Run nuclei vulnerability scanner against hosts",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct VulnScanTool {
    /// List of hosts to scan for vulnerabilities
    hosts: Vec<String>,
}

impl VulnScanTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--nuclei"]);
        cmd
    }
}

//****************//
//  WordPressScanTool  //
//****************//
#[mcp_tool(
    name = "wordpress_scan",
    description = "Scan WordPress sites for vulnerabilities, exposed plugins, and themes",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct WordPressScanTool {
    /// List of WordPress site URLs to scan
    urls: Vec<String>,
}

impl WordPressScanTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--wpscan"]);
        cmd
    }
}

//****************//
//  InfoDisclosureTool  //
//****************//
#[mcp_tool(
    name = "info_disclosure",
    description = "Scan for information disclosure: S3 buckets, Spring Actuator endpoints, GraphQL introspections",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct InfoDisclosureTool {
    /// List of hosts to scan for info disclosure
    hosts: Vec<String>,
}

impl InfoDisclosureTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.arg("-f").arg("-").args(&["--disclosure-scan"]);
        cmd
    }
}

//****************//
//  FullScanTool  //
//****************//
#[mcp_tool(
    name = "full_scan",
    description = "Run a complete bug bounty scan including subdomain enum, port scan, nuclei, secrets, admin panels, and more",
    idempotent_hint = false,
    destructive_hint = false,
    open_world_hint = true,
    read_only_hint = false,
)]
#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct FullScanTool {
    /// Target domain to scan
    domain: String,
    /// Additional scan options
    options: Option<FullScanOptions>,
}

#[derive(Debug, ::serde::Deserialize, ::serde::Serialize, JsonSchema)]
pub struct FullScanOptions {
    /// Number of concurrent workers
    workers: Option<u32>,
    /// Discord webhook for notifications
    discord_webhook: Option<String>,
}

impl FullScanTool {
    pub fn call_tool(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("enumrust");
        cmd.args(&["-d", &self.domain, "--bugbounty", "--full-scan"]);
        if let Some(options) = &self.options {
            if let Some(workers) = options.workers {
                cmd.args(&["--workers", &workers.to_string()]);
            }
            if let Some(webhook) = &options.discord_webhook {
                cmd.args(&["--discord-webhook", webhook]);
            }
        }
        cmd
    }
}

//***********************//
//  EnumRustTools enum  //
//***********************//
tool_box!(EnumRustTools, [
    SubdomainEnumTool,
    DnsResolveTool,
    IpScanTool,
    HttpProbeTool,
    JsCrawlTool,
    AdminFinderTool,
    SecretsScanTool,
    VulnScanTool,
    WordPressScanTool,
    InfoDisclosureTool,
    FullScanTool
]);