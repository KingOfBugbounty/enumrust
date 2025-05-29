# 🚀 Subdomain Enumerator and Simple Crawler

![image](https://github.com/user-attachments/assets/0ff77e11-79d7-4232-abb6-785a6815221c)

A comprehensive Rust-based tool to:

* 🕵️‍♂️ **Enumerate subdomains** with **subfinder**
* 🔐 **Augment with TLS certificate SANs** via **tlsx**
* 🌐 **Resolve to IPs** using **dnsx**
* ⚡ **Perform fast port scanning** with **masscan** and validate via **httpx**
* 🕸️ **Crawl live hosts** to extract:

  * 🪣 S3 bucket URLs
  * 🔗 In-scope links (including HTML comments)
  * 🔒 Hidden form parameters
  * 🔍 Additional parameters via **hakrawler**

---

## 🎯 Features

1. 🚀 **Subdomain Enumeration**: `subfinder` + `anew` for deduplication  
2. 🧾 **Certificate SAN Extraction**: `tlsx -json -silent` + `jq`  
3. 🌐 **DNS Resolution**: `dnsx -a -resp-only -silent`  
4. 🔎 **Port Scanning**: `masscan` (1–65535, 10kpps)  
5. 🔍 **Port Validation**: `httpx -silent`  
6. 🕸️ **Web Crawling**:

   * 🔍 Extract S3 buckets via regex  
   * 🔗 Grab `<a>` links & HTML comments  
   * 🔒 Find hidden form inputs  
   * 🏹 Use `hakrawler` for parameter enumeration  

---

## 🛠️ Installation

Ensure the following tools are in your `$PATH`:

> Rust, subfinder, tlsx, jq, dnsx, masscan, httpx, hakrawler

### 🔧 Rust and Dependencies

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone repository
git clone https://github.com/KingOfBugbounty/enumrust.git
cd enumrust

# Build binary
cargo build --release
```

### ⚙️ External Tools

Below are commands to install dependencies on macOS 🍎 (Homebrew) and Debian/Ubuntu 🐧:

```bash
# 🛠️ haktrails (ProjectDiscovery)
# macOS 🍎
brew install projectdiscovery/tap/haktrails
or
go install -v github.com/hakluke/haktrails@latest

# 🔒 tlsx (ProjectDiscovery)
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# 🛠️ jq (JSON processor)
# macOS 🍎
brew install jq
# Debian/Ubuntu 🐧
sudo apt-get install -y jq

# 🌐 dnsx & subfinder (ProjectDiscovery)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/subfinder@latest

# ⚡ masscan (fast port scanner)
# macOS 🍎
brew install masscan
# Debian/Ubuntu 🐧
sudo apt-get install -y masscan

# 🔍 httpx (ProjectDiscovery)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# 🕵️ hakrawler (Hakluke)
go install github.com/hakluke/hakrawler@latest
```

---

## 🚀 Usage

```bash
./target/release/enumrust --domain example.com
```

This generates a folder `example.com` with:

| File               | Description                                 |
| ------------------ | ------------------------------------------- |
| `subdomains.txt`   | Enumerated and SAN-derived subdomains       |
| `ips.txt`          | Resolved A records                          |
| `masscan.txt`      | Raw masscan output                          |
| `ports.txt`        | Validated open HTTP(S) ports                |
| `http200.txt`      | Alive hosts via httpx                       |
| `s3.txt`           | Discovered S3 buckets                       |
| `urls.txt`         | Extracted URLs                              |
| `hiddenparams.txt` | Generated hidden-input test URLs            |
| `params.txt`       | Additional parameterized URLs via hakrawler |

---

## 🙏 Acknowledgements

* [haktrails](https://github.com/hakluke/haktrails) by ProjectDiscovery
* [tlsx](https://github.com/projectdiscovery/tlsx) by ProjectDiscovery
* [dnsx](https://github.com/projectdiscovery/dnsx) by ProjectDiscovery
* [masscan](https://github.com/robertdavidgraham/masscan) by Robert David Graham
* [httpx](https://github.com/projectdiscovery/httpx) by ProjectDiscovery
* [hakrawler](https://github.com/hakluke/hakrawler) by hakluke
* [Clap](https://github.com/clap-rs/clap) for CLI parsing
* [Reqwest](https://github.com/seanmonstar/reqwest)
* [Scraper](https://github.com/causal-agent/scraper)

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
