# 🛡️ EnumRust - Advanced Security Scanner

<div align="center">

**A comprehensive Rust-based security enumeration tool with real-time dashboard**

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

</div>

---

## 🎯 Features

### Core Capabilities
- 🕵️ **Subdomain Enumeration** - haktrails, subfinder, certificate transparency
- 🌐 **DNS Resolution** - Fast IP resolution with dnsx
- ⚡ **Port Scanning** - masscan for speed, httpx for validation
- 🔍 **Web Crawling** - JavaScript analysis, endpoint discovery
- 🚨 **Vulnerability Scanning** - Nuclei integration
- 🗄️ **Infrastructure Mode** - Network scanning with IP ranges

### 🎯 Bug Bounty Mode (NEW!)
- 🔍 **Admin Panel Discovery** - Scans 15 ports & 80+ admin paths
- 🔑 **Default Credential Testing** - Tests 40+ common username/password combinations
- 🔔 **Discord Notifications** - Real-time alerts for critical findings
- 🎯 **Multi-Auth Support** - Form-based, Basic Auth, API JSON
- 💥 **Instant Alerts** - Valid credentials, secrets, vulnerabilities
- 📊 **Detailed Reports** - JSON + TXT outputs for bug submissions

👉 **[Full Bug Bounty Guide](BUGBOUNTY_MODE.md)**

---

## 🆕 Recent Improvements (v2.2.0)

### Advanced Secrets Scanner
- **70+ Token Patterns** - GitHub (PAT, OAuth, App), AWS, GCP, Azure, Vercel, Stripe, Twilio, SendGrid, Slack, Discord, and more
- **Token Validation** - Automatic validation against real APIs to confirm if secrets are active
- **Code Context** - Shows exact line number and code snippet where secret was found
- **Remediation Guidance** - Provides specific steps to fix each type of exposed secret

### Cloud Storage Security Testing
- **S3 Bucket Testing** - Tests for anonymous read/write/list permissions
- **GCS & Azure Blob** - Multi-cloud storage exposure detection
- **Risk Level Assessment** - Automatic severity classification

### IP Validator & CDN Filter
- **CDN Detection** - Automatically filters out IPs from Cloudflare, Akamai, Fastly, AWS CloudFront, Google Cloud CDN, Azure CDN, Incapsula
- **Smart IP Validation** - Removes invalid IPs and duplicates from scan results
- **False Positive Reduction** - Only scans real target infrastructure, not shared CDN IPs

### Dependency Confusion Scanner
- **NPM Package Detection** - Extracts packages from require(), import statements
- **Public Registry Validation** - Checks if internal packages exist on public npm registry
- **Dependency Confusion Alert** - Identifies potential supply chain attack vectors

### Enhanced JavaScript Crawler
- **Multi-source Collection** - Aggregates JS from URLFinder, HTTP200, DOM parsing
- **Deep Secret Extraction** - Analyzes JavaScript content for hardcoded credentials
- **API Endpoint Discovery** - Extracts REST/GraphQL endpoints from JS code

### Admin Panel Discovery
- **15 Port Scanning** - Covers ports 80, 443, 8080, 8443, 8000, 3000, 5000, 9000, 8888, 8088, 8081, 9090, 3001, 4200, 5001
- **80+ Admin Paths** - WordPress, Joomla, Laravel, Django, phpMyAdmin, and more
- **Smart Fingerprinting** - Identifies CMS type from response content

### Credential Testing Engine
- **40+ Default Credentials** - Common admin/password combinations
- **Multi-Auth Support** - Form-based, HTTP Basic Auth, API JSON authentication
- **Rate Limiting** - Built-in delays to avoid account lockouts

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/yourusername/enumrust.git
cd enumrust

# Build release version
cargo build --release
```

### 2. Basic Scan

```bash
# Domain enumeration with vulnerability scan
./target/release/enumrust -d example.com --subfinder --vuln-scan

# Infrastructure scan with IP range
./target/release/enumrust --infraestrutura --ip-range 192.168.1.0/24 --vuln-scan
```

---

## 📖 Usage Examples

### Bug Bounty Mode 🎯
```bash
# Bug bounty scan with Discord notifications
./target/release/enumrust -d target.com \
  --bugbounty \
  --discord-webhook "https://discord.com/api/webhooks/YOUR_WEBHOOK"

# Aggressive bug bounty scan
./target/release/enumrust -d target.com \
  --bugbounty \
  --full-scan \
  --workers 20 \
  --discord-webhook "https://discord.com/api/webhooks/YOUR_WEBHOOK"
```

**What it does:**
- ✅ Discovers admin panels on 15 different ports
- ✅ Tests 40+ default credentials automatically
- ✅ Sends Discord alerts for valid credentials found
- ✅ Notifies about critical vulnerabilities & secrets
- ✅ Generates detailed reports for bug submissions

👉 **See [BUGBOUNTY_MODE.md](BUGBOUNTY_MODE.md) for complete guide**

### Domain Reconnaissance
```bash
# Full enumeration with all sources
./target/release/enumrust -d target.com \
  --whois \
  --subfinder \
  --hacktrails \
  --vuln-scan

# Quick scan with specific tools
./target/release/enumrust -d target.com --subfinder --vuln-scan
```

### Infrastructure Scanning
```bash
# Single IP
./target/release/enumrust --infraestrutura --ip-range 192.168.1.100

# CIDR notation
./target/release/enumrust --infraestrutura --ip-range 192.168.1.0/24

# IP range
./target/release/enumrust --infraestrutura --ip-range 192.168.1.1-192.168.1.254

# Comma-separated IPs
./target/release/enumrust --infraestrutura --ip-range 192.168.1.1,192.168.1.5,192.168.1.10

# From file
./target/release/enumrust --infraestrutura --ip-list targets.txt --vuln-scan
```

### Advanced Options
```bash
# Full port scan with vulnerability detection
./target/release/enumrust --infraestrutura \
  --ip-list production.txt \
  --full-port-scan \
  --vuln-scan
```

---

## 📂 Output Structure

After scanning `example.com`, results are saved in:

```
example.com/
├── subdomains.txt          # Discovered subdomains
├── ips.txt                 # Resolved IP addresses
├── http200.txt             # Active HTTP(S) hosts
├── masscan.txt             # Port scan results
├── ports.txt               # Validated open ports
├── nuclei.txt              # Vulnerability findings
├── urls.txt                # Discovered URLs
├── js_endpoints.txt        # JavaScript endpoints
├── js_secrets.txt          # Potential secrets in JS
├── s3.txt                  # S3 bucket URLs
├── ferox_200_only.txt      # Directory bruteforce results
├── all_results.txt         # Consolidated report
├── current_status.json     # Scan status
├── progress.jsonl          # Real-time progress log
└── metrics.json            # Performance metrics
```

---

## 🛠️ Dependencies

### Required Tools
- [haktrails](https://github.com/projectdiscovery/haktrails) - Subdomain discovery
- [subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain enumeration
- [dnsx](https://github.com/projectdiscovery/dnsx) - DNS resolution
- [masscan](https://github.com/robertdavidgraham/masscan) - Fast port scanner
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [feroxbuster](https://github.com/epi052/feroxbuster) - Directory bruteforce

### Installation Script
```bash
# Install all dependencies
./target/release/enumrust --install-tools
```

---

## 📊 Performance

- **Concurrent Scanning** - Parallel tool execution
- **Async I/O** - Non-blocking operations
- **Resource Management** - Automatic cleanup
- **Timeout Handling** - Prevents hanging scans

**Typical Scan Times:**
- Small domain (< 10 subdomains): 2-5 minutes
- Medium domain (10-50 subdomains): 5-15 minutes
- Large domain (> 50 subdomains): 15-30 minutes

---

## 🔒 Security

- **Path Validation** - Prevents directory traversal
- **Input Sanitization** - Command injection protection

---

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👤 Author

**OFJAAAH**

- GitHub: [@yourusername](https://github.com/yourusername)

---

## 🙏 Acknowledgments

Built with amazing tools from:
- [ProjectDiscovery](https://projectdiscovery.io/)
- [Hakluke](https://github.com/hakluke)
- [EPI052](https://github.com/epi052)

---

<div align="center">

**Made with ❤️ and Rust 🦀**

</div>
