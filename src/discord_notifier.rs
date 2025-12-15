// discord_notifier.rs - Discord Webhook Integration for Bug Bounty
// Purpose: Send critical findings to Discord for real-time notifications
// Features:
//  - Rich embeds with color coding
//  - Admin panel discoveries
//  - Valid credentials found
//  - Critical vulnerabilities
//  - Secrets detected

use anyhow::{Context, Result};
use colored::*;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

/// Discord embed color codes
const COLOR_SUCCESS: u32 = 0x00ff00;  // Green
const COLOR_WARNING: u32 = 0xffaa00;  // Orange
const COLOR_CRITICAL: u32 = 0xff0000; // Red
const COLOR_INFO: u32 = 0x0099ff;     // Blue

/// Send Discord notification
pub async fn send_discord_notification(
    webhook_url: &str,
    title: &str,
    description: &str,
    color: u32,
    fields: Vec<(String, String, bool)>,
) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Build fields array
    let mut field_objects = Vec::new();
    for (name, value, inline) in fields {
        field_objects.push(json!({
            "name": name,
            "value": value,
            "inline": inline
        }));
    }

    // Build embed
    let embed = json!({
        "title": title,
        "description": description,
        "color": color,
        "fields": field_objects,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "footer": {
            "text": "EnumRust Bug Bounty Scanner"
        }
    });

    // Build webhook payload
    let payload = json!({
        "embeds": [embed]
    });

    // Send to Discord
    let response = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .context("Failed to send Discord notification")?;

    if response.status().is_success() {
        println!("{}", "[+] Discord notification sent successfully".green());
        Ok(())
    } else {
        let error_text = response.text().await.unwrap_or_default();
        eprintln!("{}", format!("[!] Discord notification failed: {}", error_text).yellow());
        Err(anyhow::anyhow!("Discord webhook returned error"))
    }
}

/// Notify about admin panel discovery
pub async fn notify_admin_panel_found(
    webhook_url: &str,
    domain: &str,
    url: &str,
    status_code: u16,
    title: Option<&str>,
    fingerprints: &[String],
) -> Result<()> {
    let description = format!(
        "🎯 **ADMIN PANEL DISCOVERED**\n\nA potential admin panel was found on **{}**",
        domain
    );

    let mut fields = vec![
        ("URL".to_string(), url.to_string(), false),
        ("Status Code".to_string(), status_code.to_string(), true),
    ];

    if let Some(page_title) = title {
        fields.push(("Page Title".to_string(), page_title.to_string(), false));
    }

    if !fingerprints.is_empty() {
        let indicators = fingerprints.join("\n• ");
        let indicators_text = format!("• {}", indicators);
        fields.push(("Indicators".to_string(), indicators_text, false));
    }

    send_discord_notification(
        webhook_url,
        "🚨 Admin Panel Found",
        &description,
        COLOR_WARNING,
        fields,
    )
    .await
}

/// Notify about valid credentials found
pub async fn notify_valid_credentials(
    webhook_url: &str,
    domain: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let description = format!(
        "💥 **CRITICAL: VALID CREDENTIALS FOUND**\n\n\
         Default credentials are working on **{}**!\n\n\
         ⚠️ This is a **HIGH PRIORITY** finding!",
        domain
    );

    let fields = vec![
        ("URL".to_string(), url.to_string(), false),
        ("Username".to_string(), username.to_string(), true),
        ("Password".to_string(), password.to_string(), true),
        ("Severity".to_string(), "🔴 CRITICAL".to_string(), true),
    ];

    send_discord_notification(
        webhook_url,
        "🔥 VALID CREDENTIALS DISCOVERED",
        &description,
        COLOR_CRITICAL,
        fields,
    )
    .await
}

/// Notify about high-severity vulnerability
pub async fn notify_critical_vulnerability(
    webhook_url: &str,
    domain: &str,
    vulnerability_name: &str,
    severity: &str,
    target: &str,
) -> Result<()> {
    let description = format!(
        "🔴 **CRITICAL VULNERABILITY DETECTED**\n\n\
         A {} severity vulnerability was found on **{}**",
        severity.to_uppercase(),
        domain
    );

    let fields = vec![
        ("Vulnerability".to_string(), vulnerability_name.to_string(), false),
        ("Severity".to_string(), severity.to_string(), true),
        ("Target URL".to_string(), target.to_string(), false),
    ];

    let color = match severity.to_lowercase().as_str() {
        "critical" => COLOR_CRITICAL,
        "high" => COLOR_WARNING,
        _ => COLOR_INFO,
    };

    send_discord_notification(
        webhook_url,
        "🚨 Critical Vulnerability Found",
        &description,
        color,
        fields,
    )
    .await
}

/// Notify about secret/API key found
pub async fn notify_secret_found(
    webhook_url: &str,
    domain: &str,
    secret_type: &str,
    location: &str,
    preview: &str,
) -> Result<()> {
    let description = format!(
        "🔑 **SECRET/API KEY DETECTED**\n\n\
         A {} was found on **{}**",
        secret_type, domain
    );

    let fields = vec![
        ("Secret Type".to_string(), secret_type.to_string(), true),
        ("Location".to_string(), location.to_string(), false),
        ("Preview".to_string(), preview.to_string(), false),
    ];

    send_discord_notification(
        webhook_url,
        "🔐 Secret Detected",
        &description,
        COLOR_WARNING,
        fields,
    )
    .await
}

/// Send scan completion summary
pub async fn notify_scan_complete(
    webhook_url: &str,
    domain: &str,
    total_findings: usize,
    admin_panels: usize,
    valid_creds: usize,
    secrets: usize,
    vulnerabilities: usize,
) -> Result<()> {
    let description = format!(
        "✅ **SCAN COMPLETED**\n\n\
         Bug bounty scan finished for **{}**",
        domain
    );

    let fields = vec![
        ("Total Findings".to_string(), total_findings.to_string(), true),
        ("Admin Panels".to_string(), admin_panels.to_string(), true),
        ("Valid Credentials".to_string(), valid_creds.to_string(), true),
        ("Secrets Found".to_string(), secrets.to_string(), true),
        ("Vulnerabilities".to_string(), vulnerabilities.to_string(), true),
    ];

    send_discord_notification(
        webhook_url,
        "📊 Scan Summary",
        &description,
        COLOR_SUCCESS,
        fields,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webhook_format() {
        // Test that we can build the JSON payload correctly
        let fields = vec![
            ("Test Field".to_string(), "Test Value".to_string(), false),
        ];

        let embed = json!({
            "title": "Test",
            "description": "Test description",
            "color": COLOR_INFO,
            "fields": fields.iter().map(|(name, value, inline)| {
                json!({
                    "name": name,
                    "value": value,
                    "inline": inline
                })
            }).collect::<Vec<_>>(),
        });

        assert_eq!(embed["title"], "Test");
        assert_eq!(embed["color"], COLOR_INFO);
    }
}
