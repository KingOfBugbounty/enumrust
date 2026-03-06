// ollama.rs - AI-Powered False Positive Filtering via Ollama
// Purpose: Integrate local LLM (Ollama) for intelligent analysis across all scan modules
// Architecture: Auto-installs, auto-starts, auto-pulls model - zero user setup required
// Env vars: OLLAMA_URL (default: http://localhost:11434), OLLAMA_MODEL (default: llama3)

use colored::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// ═══════════════════════════════════════════════════════════════════
// OLLAMA CLIENT
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct OllamaClient {
    client: Client,
    base_url: String,
    model: String,
    available: Arc<RwLock<bool>>,
    cache: Arc<RwLock<HashMap<u64, OllamaVerdict>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaVerdict {
    pub is_real: bool,
    pub confidence: u8,
    pub reason: String,
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f32,
    num_predict: u32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

impl OllamaClient {
    /// Create new OllamaClient - auto-installs, auto-starts, auto-pulls model
    pub async fn new() -> Self {
        let base_url = std::env::var("OLLAMA_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());
        let model = std::env::var("OLLAMA_MODEL")
            .unwrap_or_else(|_| "llama3".to_string());

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default();

        let ollama = Self {
            client,
            base_url: base_url.clone(),
            model: model.clone(),
            available: Arc::new(RwLock::new(false)),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Full auto-bootstrap: install → start → pull → verify
        ollama.auto_bootstrap(&base_url, &model).await;
        ollama
    }

    /// Complete auto-bootstrap pipeline
    async fn auto_bootstrap(&self, base_url: &str, model: &str) {
        use tokio::process::Command;

        println!("\n{}", "╔═══════════════════════════════════════════════════════════════════════════════╗".cyan().bold());
        println!("{}", "║  🤖 AI ENGINE: Ollama Auto-Setup                                              ║".cyan().bold());
        println!("{}", "╚═══════════════════════════════════════════════════════════════════════════════╝".cyan().bold());

        // Step 1: Check if Ollama binary exists
        let ollama_installed = Command::new("which")
            .arg("ollama")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !ollama_installed {
            println!("{}", "[AI] Ollama nao encontrado - instalando automaticamente...".yellow());
            let install_ok = Command::new("sh")
                .arg("-c")
                .arg("curl -fsSL https://ollama.com/install.sh | sh")
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);

            if !install_ok {
                println!("{}", "[AI] Falha ao instalar Ollama - continuando sem AI".red());
                return;
            }
            println!("{}", "[AI] Ollama instalado com sucesso!".green());
        } else {
            println!("{}", "[AI] Ollama binario encontrado".green());
        }

        // Step 2: Check if Ollama server is running
        let server_running = self.ping_server().await;

        if !server_running {
            println!("{}", "[AI] Ollama server nao esta rodando - iniciando...".yellow());

            // Start ollama serve in background
            let _ = Command::new("sh")
                .arg("-c")
                .arg("nohup ollama serve > /tmp/ollama.log 2>&1 &")
                .status()
                .await;

            // Wait for server to be ready (max 15 seconds)
            let mut ready = false;
            for i in 0..15 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if self.ping_server().await {
                    ready = true;
                    println!("{}", format!("[AI] Ollama server pronto! ({}s)", i + 1).green());
                    break;
                }
                if i == 0 {
                    print!("{}", "[AI] Aguardando server".yellow());
                }
                print!("{}", ".".yellow());
            }
            println!();

            if !ready {
                println!("{}", "[AI] Timeout aguardando Ollama server - continuando sem AI".red());
                return;
            }
        } else {
            println!("{}", "[AI] Ollama server ja esta rodando".green());
        }

        // Step 3: Check if model is available, pull if needed
        let model_ready = self.check_model_exists(model).await;

        if !model_ready {
            println!("{}", format!("[AI] Modelo '{}' nao encontrado - baixando...", model).yellow());
            println!("{}", "[AI] Isso pode levar alguns minutos na primeira vez...".yellow());

            let pull_ok = Command::new("ollama")
                .arg("pull")
                .arg(model)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);

            if !pull_ok {
                println!("{}", format!("[AI] Falha ao baixar modelo '{}' - continuando sem AI", model).red());
                return;
            }
            println!("{}", format!("[AI] Modelo '{}' baixado com sucesso!", model).green());
        } else {
            println!("{}", format!("[AI] Modelo '{}' disponivel", model).green());
        }

        // Step 4: Final verification - do a test query
        let test_ok = self.warmup_test().await;
        if test_ok {
            let mut avail = self.available.write().await;
            *avail = true;
            println!("{}", format!("[AI] Filtro inteligente ATIVO | Modelo: {} | URL: {}", model, base_url).green().bold());
        } else {
            println!("{}", "[AI] Teste de verificacao falhou - continuando sem AI".red());
        }

        println!();
    }

    /// Ping the Ollama server to check if it's running
    async fn ping_server(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        self.client
            .get(&url)
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Check if a specific model is already pulled
    async fn check_model_exists(&self, model: &str) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        let response = match self.client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };

        if let Ok(json) = response.json::<serde_json::Value>().await {
            if let Some(models) = json["models"].as_array() {
                return models.iter().any(|m| {
                    let name = m["name"].as_str().unwrap_or("");
                    // Match model name against installed models
                    name == model || name.starts_with(&format!("{}:", model))
                });
            }
        }
        false
    }

    /// Quick warmup test to verify model responds correctly
    async fn warmup_test(&self) -> bool {
        let url = format!("{}/api/generate", self.base_url);
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt: "Reply ONLY with: {\"status\":\"ok\"}".to_string(),
            stream: false,
            options: OllamaOptions {
                temperature: 0.0,
                num_predict: 20,
            },
        };

        self.client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Returns true if Ollama is available for analysis
    pub async fn is_available(&self) -> bool {
        *self.available.read().await
    }

    /// Simple hash for caching
    fn hash_prompt(prompt: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        prompt.hash(&mut hasher);
        hasher.finish()
    }

    /// Core query method - sends prompt to Ollama and parses JSON verdict
    async fn query(&self, prompt: &str) -> Option<OllamaVerdict> {
        if !self.is_available().await {
            return None;
        }

        // Check cache
        let key = Self::hash_prompt(prompt);
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&key) {
                return Some(cached.clone());
            }
        }

        let url = format!("{}/api/generate", self.base_url);
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt: prompt.to_string(),
            stream: false,
            options: OllamaOptions {
                temperature: 0.1,
                num_predict: 200,
            },
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let ollama_resp: OllamaResponse = response.json().await.ok()?;
        let verdict = Self::parse_verdict(&ollama_resp.response);

        // Cache result
        if let Some(ref v) = verdict {
            let mut cache = self.cache.write().await;
            if cache.len() < 5000 {
                cache.insert(key, v.clone());
            }
        }

        verdict
    }

    /// Parse LLM response into structured verdict
    fn parse_verdict(response: &str) -> Option<OllamaVerdict> {
        let text = response.trim();

        // Try JSON parse first
        if let Some(start) = text.find('{') {
            if let Some(end) = text.rfind('}') {
                let json_str = &text[start..=end];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                    let is_real = v.get("real")
                        .or_else(|| v.get("is_real"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let confidence = v.get("confidence")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(50) as u8;
                    let reason = v.get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("LLM analysis")
                        .to_string();

                    return Some(OllamaVerdict { is_real, confidence, reason });
                }
            }
        }

        // Fallback: keyword-based parsing
        let lower = text.to_lowercase();
        if lower.contains("false positive") || lower.contains("not real") || lower.contains("placeholder") || lower.contains("fake") || lower.contains("example") {
            Some(OllamaVerdict {
                is_real: false,
                confidence: 70,
                reason: "LLM classified as false positive".to_string(),
            })
        } else if lower.contains("real") || lower.contains("valid") || lower.contains("genuine") || lower.contains("confirmed") {
            Some(OllamaVerdict {
                is_real: true,
                confidence: 70,
                reason: "LLM classified as real finding".to_string(),
            })
        } else {
            // Can't determine - default to keeping the finding
            Some(OllamaVerdict {
                is_real: true,
                confidence: 50,
                reason: "LLM analysis inconclusive, keeping finding".to_string(),
            })
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // DOMAIN-SPECIFIC ANALYSIS METHODS
    // ═══════════════════════════════════════════════════════════════════

    /// Analyze a detected secret for false positive filtering
    pub async fn analyze_secret(
        &self,
        secret_type: &str,
        secret_preview: &str,
        context: &str,
        source_url: &str,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing secrets found during web reconnaissance.

Analyze this finding and determine if it's a REAL secret or a FALSE POSITIVE.

Secret Type: {}
Secret Preview: {}
Code Context: {}
Source URL: {}

Common false positives:
- Example/placeholder values (test, demo, example, TODO, your-key-here)
- Public API keys (Firebase public keys, Stripe publishable keys, Supabase anon keys)
- Expired/revoked tokens in documentation
- CSS hashes, webpack chunk IDs, tracking IDs
- Base64-encoded non-secret data (images, fonts)
- UUID identifiers that are not secrets

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            secret_type, secret_preview, truncate(context, 300), source_url
        );

        self.query(&prompt).await
    }

    /// Analyze a Nuclei vulnerability finding
    pub async fn analyze_nuclei_finding(
        &self,
        template_id: &str,
        vuln_name: &str,
        severity: &str,
        matched_at: &str,
        extracted: &str,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert triaging vulnerability scan results from Nuclei.

Analyze this finding and determine if it's a REAL exploitable vulnerability or a FALSE POSITIVE.

Template: {}
Vulnerability: {}
Severity: {}
Matched URL: {}
Extracted Data: {}

Common false positives from Nuclei:
- Technology detection templates reported as vulnerabilities
- Version detection where the system is actually patched
- Headers/cookies that match patterns but aren't exploitable
- Generic path detection (robots.txt, sitemap.xml) reported as exposure
- SSL/TLS info that is not actually a vulnerability
- Redirect pages that match vulnerability patterns

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            template_id, vuln_name, severity, matched_at, truncate(extracted, 200)
        );

        self.query(&prompt).await
    }

    /// Analyze if a URL is really an admin panel
    pub async fn analyze_admin_panel(
        &self,
        url: &str,
        status_code: u16,
        title: &str,
        body_excerpt: &str,
        fingerprints: &[String],
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing discovered admin panels during reconnaissance.

Analyze this finding and determine if it's a REAL admin panel or a FALSE POSITIVE.

URL: {}
Status Code: {}
Page Title: {}
Body Excerpt: {}
Fingerprints: {}

Common false positives:
- Regular user login pages (not admin-specific)
- CDN/WAF login pages (Cloudflare, Akamai)
- Default 404/403 pages that contain "admin" or "login" keywords
- Redirect pages to main site
- Honeypots / decoy admin panels
- Public API documentation pages
- Status pages with "dashboard" in name

A REAL admin panel typically has: admin-specific branding, CMS admin interface (WordPress wp-admin, Django admin), database tools (phpMyAdmin), server management (cPanel, Plesk), or custom admin dashboard with privileged functionality.

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            url, status_code, title, truncate(body_excerpt, 400), fingerprints.join(", ")
        );

        self.query(&prompt).await
    }

    /// Analyze if a package dependency is a real finding or false positive
    pub async fn analyze_package(
        &self,
        package_name: &str,
        package_type: &str,
        context: &str,
        exists_in_registry: bool,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing package dependencies found in JavaScript files.

Analyze this finding and determine if it's a REAL package import or a FALSE POSITIVE from regex matching.

Package Name: {}
Package Type: {}
Code Context: {}
Exists in Public Registry: {}

Common false positives:
- Short variable names mistaken for packages (e, t, n, r, o)
- CSS class names or HTML attributes
- Internal module paths confused with npm packages
- Webpack/bundler internal references
- String literals that match import patterns but aren't imports
- Function arguments that look like require() calls

A REAL package reference: has a valid npm/pip package name format, appears in an actual import/require context, and makes sense as a dependency.

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            package_name, package_type, truncate(context, 300), exists_in_registry
        );

        self.query(&prompt).await
    }

    /// Analyze if a credential test really succeeded
    pub async fn analyze_credential_result(
        &self,
        url: &str,
        username: &str,
        pre_login_excerpt: &str,
        post_login_excerpt: &str,
        status_code: u16,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing credential testing results.

Determine if the login was REALLY SUCCESSFUL or if it's a FALSE POSITIVE.

URL: {}
Username tested: {}
HTTP Status after login: {}
Page BEFORE login attempt: {}
Page AFTER login attempt: {}

Common false positives:
- SPA applications always return 200 regardless of login success
- WAF/CDN challenge pages that look different but aren't successful logins
- CSRF token failures causing different response
- Rate limiting / account lockout pages
- Redirect to same login page with error message
- JSON error responses interpreted as different page

A REAL successful login: shows dashboard/welcome content, session cookie set, redirect to authenticated area, user-specific content visible.

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            url, username, status_code, truncate(pre_login_excerpt, 300), truncate(post_login_excerpt, 300)
        );

        self.query(&prompt).await
    }

    /// Analyze if an info disclosure finding contains real sensitive data
    pub async fn analyze_info_disclosure(
        &self,
        url: &str,
        finding_type: &str,
        content_preview: &str,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing information disclosure findings.

Determine if this finding contains REAL sensitive data or is a FALSE POSITIVE.

URL: {}
Finding Type: {}
Content Preview: {}

Common false positives:
- /actuator/health returning just {{"status":"UP"}} (not sensitive)
- /package.json with only public dependency names
- GraphQL introspection on intentionally public APIs
- .env.example files with placeholder values
- /robots.txt and sitemap.xml (public by design)
- Health check endpoints with no secrets
- Public configuration without credentials

A REAL info disclosure: exposes credentials, internal IPs, private API keys, database connection strings, user data, heap dumps with secrets, environment variables with passwords.

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            url, finding_type, truncate(content_preview, 500)
        );

        self.query(&prompt).await
    }

    /// Analyze a chameleon directory finding for false positive filtering
    pub async fn analyze_directory_finding(
        &self,
        url: &str,
        status_code: u16,
        response_size: &str,
        path: &str,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert analyzing directory/path enumeration results from chameleon.

Analyze this finding and determine if it's a REAL interesting finding or a FALSE POSITIVE.

URL: {}
Status Code: {}
Response Size: {}
Path: {}

Common false positives:
- Custom 404 pages that return 200/403 status (same HTML size for all paths)
- Generic redirect pages (301/302 to homepage or login)
- CDN/WAF block pages (Cloudflare, Akamai challenge pages)
- Default web server pages (Apache/Nginx welcome)
- Static asset directories (css/, js/, images/, fonts/)
- Favicon.ico, robots.txt (public by design, not interesting)
- Generic error pages with fixed response size

REAL interesting findings:
- Admin panels (/admin, /wp-admin, /cpanel, /phpmyadmin)
- Configuration files (.env, config.php, web.config, .htaccess)
- Backup files (.bak, .sql, .zip, .tar.gz)
- API endpoints (/api/, /graphql, /swagger)
- Hidden directories with unique response sizes
- Debug/development endpoints (/debug, /test, /staging)
- Source code exposure (.git, .svn, .DS_Store)

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            url, status_code, response_size, path
        );

        self.query(&prompt).await
    }

    /// Analyze a WPScan vulnerability finding for false positive filtering
    pub async fn analyze_wpscan_finding(
        &self,
        component: &str,
        version: &str,
        vuln_title: &str,
        severity: &str,
        cve: &str,
        fixed_in: &str,
        target_url: &str,
    ) -> Option<OllamaVerdict> {
        let prompt = format!(
            r#"You are a security expert triaging WordPress vulnerability scan results from WPScan.

Analyze this finding and determine if it's a REAL exploitable vulnerability or a FALSE POSITIVE.

Target: {}
Component: {} (version: {})
Vulnerability: {}
Severity: {}
CVE: {}
Fixed in: {}

Common false positives in WPScan:
- Vulnerabilities already patched in the installed version
- Plugin/theme detected but vulnerability requires authenticated access that isn't available
- Informational findings reported as vulnerabilities (readme.txt exposure, version detection)
- Vulnerabilities in features that are disabled or not in use
- WordPress core version flagged but running security-patched distro (Debian/Ubuntu backports)
- Duplicate CVEs for the same underlying issue

REAL vulnerabilities: unpatched CVEs affecting the detected version, RCE/SQLi/auth bypass in active plugins, known exploited vulnerabilities with public PoCs.

Respond ONLY with JSON: {{"real": true/false, "confidence": 0-100, "reason": "brief explanation"}}"#,
            target_url, component, version, vuln_title, severity, cve, fixed_in
        );

        self.query(&prompt).await
    }

    /// Analyze a Supabase key finding and exploitation results
    pub async fn analyze_supabase_finding(
        &self,
        supabase_url: &str,
        key_type: &str,
        source_url: &str,
        signup_enabled: bool,
        tables: &[String],
        data_exposed: bool,
        findings: &[String],
    ) -> Option<String> {
        if !self.is_available().await {
            return None;
        }

        let findings_text = if findings.is_empty() {
            "None".to_string()
        } else {
            findings.join("\n- ")
        };

        let prompt = format!(
            r#"You are a senior security consultant analyzing a Supabase vulnerability found during an AUTHORIZED penetration test.

Supabase URL: {}
Key Type: {} (exposed in frontend JavaScript)
Found in JS file: {}
Signup enabled: {}
Tables discovered: {} ({})
Data directly exposed: {}

Findings:
- {}

Provide a concise security assessment covering:
1. Risk level and real-world impact
2. What an attacker can do with this access
3. Whether this is a misconfiguration or intentional
4. Priority remediation steps

Be direct and technical. Focus on exploitability."#,
            supabase_url, key_type, source_url,
            if signup_enabled { "YES" } else { "NO" },
            tables.len(),
            if tables.is_empty() { "none".to_string() } else { tables.join(", ") },
            if data_exposed { "YES" } else { "NO" },
            findings_text
        );

        let url = format!("{}/api/generate", self.base_url);
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
            options: OllamaOptions {
                temperature: 0.2,
                num_predict: 600,
            },
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(45))
            .send()
            .await
            .ok()?;

        let ollama_resp: OllamaResponse = response.json().await.ok()?;
        Some(ollama_resp.response.trim().to_string())
    }

    /// Generate executive summary for the final report
    pub async fn generate_executive_summary(
        &self,
        domain: &str,
        total_subdomains: usize,
        total_live_hosts: usize,
        total_secrets: usize,
        total_vulns: usize,
        total_admin_panels: usize,
        critical_findings: &[String],
    ) -> Option<String> {
        if !self.is_available().await {
            return None;
        }

        let findings_text = if critical_findings.is_empty() {
            "No critical findings.".to_string()
        } else {
            critical_findings.iter().take(20).cloned().collect::<Vec<_>>().join("\n- ")
        };

        let prompt = format!(
            r#"You are a senior security consultant writing a penetration test executive summary.

Write a concise executive summary (max 10 lines) for this reconnaissance scan:

Target: {}
Subdomains discovered: {}
Live hosts: {}
Secrets found: {}
Vulnerabilities: {}
Admin panels: {}

Top critical findings:
- {}

Write a professional executive summary covering:
1. Attack surface overview
2. Most critical risks
3. Immediate recommended actions

Be direct and technical. No marketing language."#,
            domain, total_subdomains, total_live_hosts, total_secrets,
            total_vulns, total_admin_panels, findings_text
        );

        let url = format!("{}/api/generate", self.base_url);
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
            options: OllamaOptions {
                temperature: 0.3,
                num_predict: 500,
            },
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(45))
            .send()
            .await
            .ok()?;

        let ollama_resp: OllamaResponse = response.json().await.ok()?;
        Some(ollama_resp.response.trim().to_string())
    }
}

/// Truncate string to max length with ellipsis
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}
