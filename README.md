# 👵️ enumRust - Automated Offensive Recon Framework



> **"Recon like a pro. Hunt like a ghost."**

<div align="center">
  <img src="https://github.com/user-attachments/assets/eca9253f-ea3e-4a77-8ebc-fb56e961bedd" width="350" alt="Recon Tool Banner" />
</div>
---

## 📖 Overview

`enumRust` is an **automated offensive recon framework** written in Rust that performs comprehensive reconnaissance and vulnerability analysis on any target domain.
It integrates top-tier tools like `subfinder`, `httpx`, `masscan`, `nuclei`, `ffuf`, and `feroxbuster` to uncover:

* 🔍 Subdomains
* 🌐 Open ports & services
* 🧪 Vulnerabilities (XSS, RCE, SSRF, etc.)
* 📂 Sensitive files & directories
* ☑️ Exposed cloud buckets
* 🧪 Hidden form parameters
* 🛡️ Misconfigurations via `robots.txt` and more!

---

## 🛠️ Features

| Module                     | Description                                                            |
| -------------------------- | ---------------------------------------------------------------------- |
| 🧐 Subdomain Enumeration   | Uses `subfinder` & `tlsx` to find valid subdomains                     |
| 📡 Port Scanning           | Executes `masscan` for lightning-fast port discovery                   |
| 🔍 Service Validation      | Resolves IPs & checks HTTP/HTTPS services using `httpx`                |
| 🔸 Crawler + Analysis      | Extracts JS/HTML paths, comments, URLs, and cloud storage exposures    |
| 🧪 Vulnerability Scan      | Executes `nuclei` with critical tags like XSS, RCE, SSRF               |
| 🏗️ Directory Brute-Force  | Uses `feroxbuster` with intelligent timeouts and result parsing        |
| ☑️ Cloud Bucket Finder     | Regex-based discovery for AWS, GCP, Azure buckets                      |
| 🧕‍♀️ Hidden Param Grabber | Extracts hidden form parameters for parameter pollution attacks        |
| 📂 VHost Brute-Force       | Uses `ffuf` to brute virtual hosts with custom `Host:` headers         |
| 🛡️ robots.txt Extractor   | Parses disallowed paths and adds them to wordlists for further fuzzing |

---

## 🛠️ Dependencies

The following tools must be installed and available in your `$PATH`:

```
subfinder, anew, tlsx, jq, dnsx, masscan, httpx, hakrawler, nuclei, curl, feroxbuster, ffuf, haktrails
```

You can check dependencies by running:

```bash
cargo run --release -- -d example.com
```

---

## 📦 Installation

```bash
apt install rustup pkg-config libssl-dev
rustup default stable
git clone https://github.com/KingOfBugbounty/enumrust.git
cd enumrust
cargo build --release
```

---

## ⚙️ Usage

```bash
./enumRust -d example.com
```

This will:

1. Create a directory named `example.com`
2. Perform full recon and scan workflow
3. Save all results inside this directory

---

## 📂 Output Files

| File                 | Description                            |
| -------------------- | -------------------------------------- |
| `subdomains.txt`     | All discovered subdomains              |
| `masscan.txt`        | Raw port scan results                  |
| `ports.txt`          | HTTP/HTTPS services on open ports      |
| `http200.txt`        | Alive and reachable HTTP URLs          |
| `cloud_buckets.txt`  | Detected exposed cloud storage         |
| `urls.txt`           | Discovered internal URLs               |
| `hiddenparams.txt`   | URLs with injectable hidden parameters |
| `params.txt`         | Crawled parameters from URLs           |
| `ferox_results.json` | Raw output from Feroxbuster            |
| `ferox_parsed.txt`   | Clean parsed output from Feroxbuster   |
| `nuclei_results.txt` | All vulnerability results              |
| `vhost_results.txt`  | Found vhosts via FFUF                  |

---

## 📖 Methodology

### 1. Subdomain Enumeration

```bash
subfinder -d domain.com | anew subdomains.txt
tlsx → Collect SANs → append
```

### 2. Port & Service Discovery

```bash
dnsx → IPs
masscan → Open ports
httpx → Validate services
```

### 3. Crawling & Bucket Analysis

* `reqwest` + `scraper` for HTML/JS/Comment URLs
* Regex search for:

  * ☑️ S3 Buckets
  * 🧱 GCP/Azure Storage
  * 👁️ Hidden Params

### 4. Brute Forcing

* `feroxbuster` with depth control and image filtering
* `ffuf` for virtual hosts via `Host: FUZZ.domain.com`

### 5. Vulnerability Scanning

* `nuclei` with:

  * `-tags` xss,rce,ssrf,keycloak,actuator,misconfig
  * `-severity` medium,high,critical

---

## 🧬 Example Workflow

```bash
./enumRust -d target.com

# Outputs directory:
# └── target.com/
#     ├── subdomains.txt
#     ├── ports.txt
#     ├── cloud_buckets.txt
#     ├── ferox_results.json
#     ├── nuclei_results.txt
#     └── ...
```

---

## 🔐 Ethics

> This tool is for educational and authorized penetration testing only.
> Do **not** use against targets without proper authorization.
> The developer assumes **no liability** for misuse.

---

## ❤️ Credits

* ProjectDiscovery (Subfinder, HTTPX, Nuclei)
* Daniel Miessler (SecLists)
* Feroxbuster by @epi052
* FFUF by @ffuf

---

## 🤋 Bug Reports / Suggestions

Found a bug or want a new feature?

📬 Open an issue or PR at:
**[github.com/KingOfBugbounty/enumrust](https://github.com/KingOfBugbounty/enumrust)**


---

## 🧠 "Let Recon Rule The Hunt"

---
