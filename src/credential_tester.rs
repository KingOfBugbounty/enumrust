// credential_tester.rs - Default Credential Testing for Bug Bounty
// Purpose: Test common default credentials on discovered admin panels
// Features:
//  - Common username/password combinations
//  - Multiple authentication methods (Form, Basic Auth, API)
//  - Smart login detection
//  - Rate limiting to avoid lockouts

use anyhow::Result;
use colored::*;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

/// Common default credentials to test
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    // Super common
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "12345678"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("administrator", "password"),

    // Root access
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "admin"),

    // Database defaults
    ("admin", "Admin123"),
    ("admin", "P@ssw0rd"),
    ("admin", "Welcome1"),
    ("admin", "changeme"),

    // Common services
    ("admin", ""),
    ("guest", "guest"),
    ("user", "user"),
    ("test", "test"),

    // Manufacturer defaults
    ("admin", "1234"),
    ("admin", "admin1234"),
    ("administrator", "admin"),
    ("admin", "letmein"),

    // CMS defaults
    ("admin", "demo"),
    ("demo", "demo"),
    ("webadmin", "webadmin"),
    ("sysadmin", "sysadmin"),

    // IoT/Router defaults
    ("admin", "password1"),
    ("admin", "0000"),
    ("admin", "1111"),
    ("admin", "admin2020"),
    ("admin", "admin2021"),
    ("admin", "admin2022"),
    ("admin", "admin2023"),
    ("admin", "admin2024"),

    // WordPress
    ("admin", "wordpress"),
    ("admin", "wp-admin"),

    // Common weak passwords
    ("admin", "123456"),
    ("admin", "qwerty"),
    ("admin", "abc123"),
    ("admin", "password123"),
];

/// Credential test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResult {
    pub url: String,
    pub username: String,
    pub password: String,
    pub is_valid: bool,
    pub auth_method: String,
    pub response_indicators: Vec<String>,
}

/// Test credentials on a URL
pub async fn test_default_credentials(
    url: &str,
    client: &Client,
) -> Vec<CredentialResult> {
    println!("{}", format!("[*] Testing default credentials on: {}", url).cyan());

    let mut results = Vec::new();

    // First, detect what type of login page this is
    let login_method = detect_login_method(url, client).await;

    match login_method {
        LoginMethod::FormBased(form_fields) => {
            results = test_form_based_login(url, &form_fields, client).await;
        }
        LoginMethod::BasicAuth => {
            results = test_basic_auth(url, client).await;
        }
        LoginMethod::ApiJson => {
            results = test_api_json_login(url, client).await;
        }
        LoginMethod::Unknown => {
            println!("{}", format!("  [!] Could not detect login method for {}", url).yellow());
        }
    }

    // Filter only valid credentials
    let valid_results: Vec<_> = results.iter().filter(|r| r.is_valid).collect();

    if !valid_results.is_empty() {
        println!(
            "{}",
            format!(
                "  [!!!] FOUND {} VALID CREDENTIALS on {}",
                valid_results.len(),
                url
            )
            .red()
            .bold()
        );

        for result in &valid_results {
            println!(
                "{}",
                format!("    ✓ {}:{}", result.username, result.password).green().bold()
            );
        }
    } else {
        println!("{}", "  [-] No valid default credentials found".white());
    }

    results
}

/// Login method detection
#[derive(Debug)]
enum LoginMethod {
    FormBased(FormFields),
    BasicAuth,
    ApiJson,
    Unknown,
}

#[derive(Debug, Clone)]
struct FormFields {
    action: String,
    username_field: String,
    password_field: String,
    additional_fields: HashMap<String, String>,
}

/// Detect login method from page
async fn detect_login_method(url: &str, client: &Client) -> LoginMethod {
    // Try to fetch the page
    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return LoginMethod::Unknown,
    };

    // Check for Basic Auth challenge
    if response.status().as_u16() == 401 {
        if let Some(auth_header) = response.headers().get("www-authenticate") {
            if auth_header.to_str().unwrap_or("").contains("Basic") {
                return LoginMethod::BasicAuth;
            }
        }
    }

    // Get page HTML
    let html = match response.text().await {
        Ok(h) => h,
        Err(_) => return LoginMethod::Unknown,
    };

    // Check if it's an API endpoint (JSON response)
    if html.trim().starts_with('{') || html.trim().starts_with('[') {
        return LoginMethod::ApiJson;
    }

    // Try to find login form
    let document = Html::parse_document(&html);

    // Look for forms with password fields
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input").unwrap();

    for form in document.select(&form_selector) {
        let mut username_field = None;
        let mut password_field = None;
        let mut additional_fields = HashMap::new();

        for input in form.select(&input_selector) {
            let input_type = input.value().attr("type").unwrap_or("text");
            let input_name = input.value().attr("name").unwrap_or("");

            match input_type {
                "password" => {
                    password_field = Some(input_name.to_string());
                }
                "text" | "email" => {
                    if username_field.is_none() &&
                       (input_name.contains("user") ||
                        input_name.contains("login") ||
                        input_name.contains("email") ||
                        input_name == "username") {
                        username_field = Some(input_name.to_string());
                    }
                }
                "hidden" => {
                    if let Some(value) = input.value().attr("value") {
                        additional_fields.insert(input_name.to_string(), value.to_string());
                    }
                }
                _ => {}
            }
        }

        // If we found both username and password fields
        if let (Some(user_field), Some(pass_field)) = (username_field, password_field) {
            let action = form
                .value()
                .attr("action")
                .unwrap_or("")
                .to_string();

            let action_url = if action.is_empty() {
                url.to_string()
            } else if action.starts_with("http") {
                action
            } else if action.starts_with('/') {
                // Extract base URL
                let base_url = url.split('/').take(3).collect::<Vec<_>>().join("/");
                format!("{}{}", base_url, action)
            } else {
                format!("{}/{}", url.trim_end_matches('/'), action)
            };

            return LoginMethod::FormBased(FormFields {
                action: action_url,
                username_field: user_field,
                password_field: pass_field,
                additional_fields,
            });
        }
    }

    LoginMethod::Unknown
}

/// Test form-based login
async fn test_form_based_login(
    url: &str,
    form_fields: &FormFields,
    client: &Client,
) -> Vec<CredentialResult> {
    let mut results = Vec::new();

    println!("{}", format!("  [*] Testing form-based login (username={}, password={})",
        form_fields.username_field, form_fields.password_field).cyan());

    for (username, password) in DEFAULT_CREDENTIALS.iter().take(15) {
        // Rate limiting - wait between attempts
        sleep(Duration::from_millis(1000)).await;

        // Build form data
        let mut form_data = form_fields.additional_fields.clone();
        form_data.insert(form_fields.username_field.clone(), username.to_string());
        form_data.insert(form_fields.password_field.clone(), password.to_string());

        // Send login request
        let response = match client
            .post(&form_fields.action)
            .form(&form_data)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = response.status().as_u16();
        let response_url = response.url().to_string();
        let body = response.text().await.unwrap_or_default();

        // Detect if login was successful
        let is_valid = detect_successful_login(status, &response_url, &body, url);

        let mut indicators = Vec::new();
        if is_valid {
            indicators.push(format!("Status: {}", status));
            if response_url != form_fields.action {
                indicators.push(format!("Redirect to: {}", response_url));
            }
        }

        results.push(CredentialResult {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            is_valid,
            auth_method: "Form-based".to_string(),
            response_indicators: indicators,
        });

        if is_valid {
            break; // Stop after first valid credential
        }
    }

    results
}

/// Test HTTP Basic Authentication
async fn test_basic_auth(url: &str, client: &Client) -> Vec<CredentialResult> {
    let mut results = Vec::new();

    println!("{}", "  [*] Testing HTTP Basic Authentication".cyan());

    for (username, password) in DEFAULT_CREDENTIALS.iter().take(15) {
        sleep(Duration::from_millis(1000)).await;

        let response = match client
            .get(url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = response.status().as_u16();
        let is_valid = status == 200;

        let mut indicators = Vec::new();
        if is_valid {
            indicators.push(format!("Status: {}", status));
        }

        results.push(CredentialResult {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            is_valid,
            auth_method: "Basic Auth".to_string(),
            response_indicators: indicators,
        });

        if is_valid {
            break;
        }
    }

    results
}

/// Test API JSON login
async fn test_api_json_login(url: &str, client: &Client) -> Vec<CredentialResult> {
    let mut results = Vec::new();

    println!("{}", "  [*] Testing API JSON login".cyan());

    for (username, password) in DEFAULT_CREDENTIALS.iter().take(15) {
        sleep(Duration::from_millis(1000)).await;

        let json_body = serde_json::json!({
            "username": username,
            "password": password
        });

        let response = match client
            .post(url)
            .json(&json_body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        // Check for success indicators in JSON response
        let is_valid = status == 200 &&
            (body.contains("\"success\":true") ||
             body.contains("\"token\"") ||
             body.contains("\"authenticated\":true"));

        let mut indicators = Vec::new();
        if is_valid {
            indicators.push(format!("Status: {}", status));
            indicators.push("API returned success".to_string());
        }

        results.push(CredentialResult {
            url: url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            is_valid,
            auth_method: "API JSON".to_string(),
            response_indicators: indicators,
        });

        if is_valid {
            break;
        }
    }

    results
}

/// Detect if login was successful based on response
fn detect_successful_login(status: u16, response_url: &str, body: &str, original_url: &str) -> bool {
    // Success indicators
    let success_keywords = [
        "dashboard", "welcome", "logout", "profile",
        "home", "panel", "admin", "success"
    ];

    // Failure indicators
    let failure_keywords = [
        "invalid", "incorrect", "failed", "error",
        "wrong", "denied", "unauthorized"
    ];

    let body_lower = body.to_lowercase();

    // Check for redirect (common after successful login)
    if response_url != original_url && status == 200 {
        return true;
    }

    // Check for success keywords without failure keywords
    let has_success = success_keywords.iter().any(|&kw| body_lower.contains(kw));
    let has_failure = failure_keywords.iter().any(|&kw| body_lower.contains(kw));

    if has_success && !has_failure {
        return true;
    }

    // Status code 302/303 (redirect) often indicates success
    if status == 302 || status == 303 {
        return true;
    }

    false
}

/// Save credential results to file
pub fn save_credential_results(results: &[CredentialResult], output_path: &std::path::Path) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(output_path, json)?;
    Ok(())
}
