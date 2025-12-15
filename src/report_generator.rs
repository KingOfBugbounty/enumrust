// report_generator.rs - HTML Report Generator for EnumRust
// Generates a comprehensive, interactive HTML report with all scan results

use anyhow::Result;
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Generate comprehensive HTML report from scan results
pub fn generate_html_report(scan_dir: &Path, domain: &str) -> Result<String> {
    let html_path = scan_dir.join("report.html");

    // Read all scan results
    let subdomains = read_file_lines(&scan_dir.join("subdomains.txt"));
    let http200_urls = read_file_lines(&scan_dir.join("http200.txt"));
    let ips = read_file_lines(&scan_dir.join("ips.txt"));

    // Read JSON files
    let js_secrets = read_json_file(&scan_dir.join("js_secrets_enhanced.json"));
    let trufflehog = read_json_file(&scan_dir.join("trufflehog.json"));

    // Try to read nuclei.txt from files_ subdirectory first, then fallback to root
    let nuclei_path = if scan_dir.join("files_").join("nuclei.txt").exists() {
        scan_dir.join("files_").join("nuclei.txt")
    } else {
        scan_dir.join("nuclei.txt")
    };
    let nuclei = read_nuclei_json(&nuclei_path);

    let cloud_storage = read_json_file(&scan_dir.join("cloud_storage_exposure.json"));
    let js_endpoints = read_file_lines(&scan_dir.join("js_endpoints.txt"));
    let packages = read_json_file(&scan_dir.join("package_dependencies.json"));
    let s3_buckets = read_file_lines(&scan_dir.join("s3.txt"));
    let validated_hosts = read_json_file(&scan_dir.join("validated_hosts.json"));
    let metrics = read_json_file(&scan_dir.join("scan_metrics.json"));

    let html_content = generate_html_content(
        domain,
        &subdomains,
        &http200_urls,
        &ips,
        &js_secrets,
        &trufflehog,
        &nuclei,
        &cloud_storage,
        &js_endpoints,
        &packages,
        &s3_buckets,
        &validated_hosts,
        &metrics,
    );

    fs::write(&html_path, html_content)?;
    Ok(html_path.to_string_lossy().to_string())
}

/// Read file lines into Vec<String>
fn read_file_lines(path: &Path) -> Vec<String> {
    if !path.exists() {
        return Vec::new();
    }

    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Read JSON file
fn read_json_file(path: &Path) -> Vec<Value> {
    if !path.exists() {
        return Vec::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();

    // Try parsing as array first
    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&content) {
        return arr;
    }

    // Try parsing as single object
    if let Ok(obj) = serde_json::from_str::<Value>(&content) {
        return vec![obj];
    }

    Vec::new()
}

/// Read Nuclei NDJSON format
fn read_nuclei_json(path: &Path) -> Vec<Value> {
    if !path.exists() {
        return Vec::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Generate complete HTML content
#[allow(clippy::too_many_arguments)]
fn generate_html_content(
    domain: &str,
    subdomains: &[String],
    http200_urls: &[String],
    ips: &[String],
    js_secrets: &[Value],
    trufflehog: &[Value],
    nuclei: &[Value],
    cloud_storage: &[Value],
    js_endpoints: &[String],
    packages: &[Value],
    s3_buckets: &[String],
    validated_hosts: &[Value],
    metrics: &[Value],
) -> String {
    // Count vulnerabilities by severity for executive summary
    let (critical_count, high_count, medium_count, low_count) = count_vuln_severities(nuclei);
    let total_secrets = js_secrets.len() + trufflehog.len();

    let stats = generate_stats_summary(
        subdomains.len(),
        http200_urls.len(),
        ips.len(),
        total_secrets,
        nuclei.len(),
        js_endpoints.len(),
    );

    let executive_summary = generate_executive_summary(
        domain,
        subdomains.len(),
        http200_urls.len(),
        total_secrets,
        critical_count,
        high_count,
        medium_count,
        low_count,
    );

    let subdomains_html = generate_subdomains_tab(subdomains, validated_hosts);
    let live_hosts_html = generate_live_hosts_tab(http200_urls);
    let secrets_html = generate_secrets_tab(js_secrets, trufflehog);
    let vulnerabilities_html = generate_vulnerabilities_tab(nuclei);
    let cloud_html = generate_cloud_tab(cloud_storage, s3_buckets);
    let endpoints_html = generate_endpoints_tab(js_endpoints);
    let packages_html = generate_packages_tab(packages);
    let poc_html = generate_poc_tab();
    let raw_data_html = generate_raw_data_tab(metrics);

    let current_date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #273449;
            --bg-input: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: #334155;
            --border-light: #475569;
            --accent-blue: #3b82f6;
            --accent-blue-light: #60a5fa;
            --accent-green: #22c55e;
            --accent-green-dark: #16a34a;
            --accent-red: #ef4444;
            --accent-red-dark: #dc2626;
            --accent-yellow: #eab308;
            --accent-orange: #f97316;
            --accent-purple: #a855f7;
            --accent-cyan: #06b6d4;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        /* ===== LAYOUT ===== */
        .app-container {{
            display: flex;
            min-height: 100vh;
        }}

        /* ===== SIDEBAR ===== */
        .sidebar {{
            width: 280px;
            background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
            border-right: 1px solid var(--border-color);
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            overflow-y: auto;
            z-index: 100;
            display: flex;
            flex-direction: column;
        }}

        .sidebar-header {{
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}

        .logo-icon {{
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-purple) 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            font-weight: 700;
            color: white;
        }}

        .logo-text {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .logo-subtitle {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .target-info {{
            background: var(--bg-input);
            padding: 0.875rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .target-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.25rem;
        }}

        .target-domain {{
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--accent-blue-light);
            word-break: break-all;
        }}

        /* Navigation */
        .nav-section {{
            padding: 1rem 0;
            flex: 1;
        }}

        .nav-title {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 0 1.5rem;
            margin-bottom: 0.5rem;
        }}

        .nav-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1.5rem;
            color: var(--text-secondary);
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
            font-size: 0.9rem;
        }}

        .nav-item:hover {{
            background: rgba(59, 130, 246, 0.1);
            color: var(--text-primary);
        }}

        .nav-item.active {{
            background: rgba(59, 130, 246, 0.15);
            color: var(--accent-blue-light);
            border-left-color: var(--accent-blue);
        }}

        .nav-icon {{
            width: 20px;
            text-align: center;
            font-size: 1rem;
        }}

        .nav-badge {{
            margin-left: auto;
            background: var(--bg-input);
            padding: 0.125rem 0.5rem;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-secondary);
        }}

        .nav-badge.critical {{
            background: var(--accent-red);
            color: white;
        }}

        .nav-badge.warning {{
            background: var(--accent-yellow);
            color: black;
        }}

        /* Sidebar Footer */
        .sidebar-footer {{
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
            background: var(--bg-card);
        }}

        .report-meta {{
            font-size: 0.75rem;
            color: var(--text-muted);
        }}

        .report-meta-item {{
            display: flex;
            justify-content: space-between;
            padding: 0.25rem 0;
        }}

        /* ===== MAIN CONTENT ===== */
        .main-content {{
            flex: 1;
            margin-left: 280px;
            min-height: 100vh;
        }}

        /* Header */
        .page-header {{
            background: linear-gradient(135deg, var(--bg-card) 0%, #1a2744 100%);
            padding: 2rem 2.5rem;
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 50;
        }}

        .header-content {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .page-title {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .page-title-icon {{
            font-size: 1.5rem;
        }}

        .page-description {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}

        /* Stats Bar */
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 1rem;
            padding: 1.5rem 2.5rem;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
        }}

        .stat-item {{
            text-align: center;
            padding: 1rem;
            background: var(--bg-dark);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.2s ease;
        }}

        .stat-item:hover {{
            border-color: var(--accent-blue);
            transform: translateY(-2px);
        }}

        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--accent-blue-light);
            line-height: 1.2;
        }}

        .stat-value.critical {{ color: var(--accent-red); }}
        .stat-value.warning {{ color: var(--accent-yellow); }}
        .stat-value.success {{ color: var(--accent-green); }}

        .stat-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 0.25rem;
        }}

        /* Tab Content */
        .tab-content {{
            display: none;
            padding: 2rem 2.5rem;
            max-width: 1400px;
            margin: 0 auto;
        }}

        .tab-content.active {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        /* ===== CARDS ===== */
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }}

        .card-header {{
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(0, 0, 0, 0.2);
        }}

        .card-title {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .card-title-icon {{
            color: var(--accent-blue);
        }}

        .card-badge {{
            background: var(--bg-input);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--text-secondary);
        }}

        .card-body {{
            padding: 1.5rem;
        }}

        .card-body-compact {{
            padding: 1rem 1.5rem;
        }}

        /* ===== EXECUTIVE SUMMARY ===== */
        .executive-summary {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }}

        .summary-main {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }}

        .summary-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }}

        .summary-item {{
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .summary-item-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .summary-item-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent-blue-light);
            margin-top: 0.25rem;
        }}

        .risk-score {{
            background: linear-gradient(135deg, var(--bg-card) 0%, #1a2744 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}

        .risk-score-title {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 1rem;
        }}

        .risk-score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            font-weight: 700;
            color: white;
        }}

        .risk-score-circle.critical {{
            background: linear-gradient(135deg, var(--accent-red) 0%, #991b1b 100%);
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.4);
        }}

        .risk-score-circle.high {{
            background: linear-gradient(135deg, var(--accent-orange) 0%, #c2410c 100%);
            box-shadow: 0 0 30px rgba(249, 115, 22, 0.4);
        }}

        .risk-score-circle.medium {{
            background: linear-gradient(135deg, var(--accent-yellow) 0%, #a16207 100%);
            box-shadow: 0 0 30px rgba(234, 179, 8, 0.4);
        }}

        .risk-score-circle.low {{
            background: linear-gradient(135deg, var(--accent-green) 0%, #15803d 100%);
            box-shadow: 0 0 30px rgba(34, 197, 94, 0.4);
        }}

        .risk-score-label {{
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}

        .risk-score-desc {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        /* Severity Distribution */
        .severity-distribution {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.75rem;
            margin-top: 1.5rem;
        }}

        .severity-item {{
            background: var(--bg-dark);
            padding: 0.875rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}

        .severity-count {{
            font-size: 1.25rem;
            font-weight: 700;
        }}

        .severity-count.critical {{ color: var(--accent-red); }}
        .severity-count.high {{ color: var(--accent-orange); }}
        .severity-count.medium {{ color: var(--accent-yellow); }}
        .severity-count.low {{ color: var(--accent-blue-light); }}

        .severity-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* ===== DATA TABLE ===== */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .data-table th {{
            text-align: left;
            padding: 0.875rem 1rem;
            background: var(--bg-dark);
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
        }}

        .data-table td {{
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .data-table tr:hover td {{
            background: rgba(59, 130, 246, 0.05);
        }}

        .data-table tr:last-child td {{
            border-bottom: none;
        }}

        /* ===== LIST ITEMS ===== */
        .list-container {{
            max-height: 500px;
            overflow-y: auto;
        }}

        .list-item {{
            display: flex;
            align-items: center;
            padding: 0.875rem 1rem;
            border-bottom: 1px solid var(--border-color);
            transition: background 0.2s ease;
            gap: 0.75rem;
        }}

        .list-item:hover {{
            background: rgba(59, 130, 246, 0.05);
        }}

        .list-item:last-child {{
            border-bottom: none;
        }}

        .list-item-icon {{
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-input);
            color: var(--accent-blue);
            font-size: 0.9rem;
            flex-shrink: 0;
        }}

        .list-item-content {{
            flex: 1;
            min-width: 0;
        }}

        .list-item-title {{
            font-size: 0.9rem;
            color: var(--text-primary);
            word-break: break-all;
        }}

        .list-item-subtitle {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.125rem;
        }}

        .list-item-link {{
            color: var(--accent-blue-light);
            text-decoration: none;
            transition: color 0.2s;
        }}

        .list-item-link:hover {{
            color: var(--accent-blue);
            text-decoration: underline;
        }}

        /* ===== VULNERABILITY CARD ===== */
        .vuln-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.2s ease;
        }}

        .vuln-card:hover {{
            border-color: var(--border-light);
            box-shadow: var(--shadow-lg);
        }}

        .vuln-card-header {{
            padding: 1rem 1.25rem;
            background: rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: flex-start;
            gap: 1rem;
        }}

        .vuln-severity {{
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            flex-shrink: 0;
        }}

        .vuln-severity.critical {{
            background: var(--accent-red);
            color: white;
        }}

        .vuln-severity.high {{
            background: var(--accent-orange);
            color: white;
        }}

        .vuln-severity.medium {{
            background: var(--accent-yellow);
            color: #1e293b;
        }}

        .vuln-severity.low {{
            background: var(--accent-blue);
            color: white;
        }}

        .vuln-severity.info {{
            background: var(--accent-cyan);
            color: #1e293b;
        }}

        .vuln-info {{
            flex: 1;
        }}

        .vuln-name {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }}

        .vuln-template {{
            font-size: 0.8rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}

        .vuln-card-body {{
            padding: 1.25rem;
        }}

        .vuln-description {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 1rem;
        }}

        .vuln-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}

        .vuln-meta-item {{
            display: flex;
            align-items: center;
            gap: 0.375rem;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        .vuln-target {{
            background: var(--bg-dark);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--accent-purple);
            word-break: break-all;
            border: 1px solid var(--border-color);
        }}

        .vuln-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }}

        .vuln-tag {{
            background: var(--bg-input);
            padding: 0.25rem 0.625rem;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}

        .vuln-details {{
            margin-top: 1rem;
        }}

        .vuln-details summary {{
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--accent-blue-light);
            padding: 0.5rem 0;
        }}

        .vuln-details summary:hover {{
            color: var(--accent-blue);
        }}

        .vuln-curl {{
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 6px;
            margin-top: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--accent-green);
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }}

        /* ===== SECRET CARD ===== */
        .secret-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-red);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}

        .secret-header {{
            padding: 1rem 1.25rem;
            background: rgba(239, 68, 68, 0.1);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}

        .secret-type {{
            background: var(--accent-red);
            padding: 0.25rem 0.625rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}

        .secret-confidence {{
            background: var(--bg-input);
            padding: 0.25rem 0.625rem;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}

        .secret-body {{
            padding: 1rem 1.25rem;
        }}

        .secret-value {{
            background: var(--bg-dark);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--accent-yellow);
            word-break: break-all;
            border: 1px solid var(--border-color);
            margin-bottom: 0.75rem;
        }}

        .secret-source {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        .secret-source a {{
            color: var(--accent-blue-light);
            text-decoration: none;
        }}

        .secret-source a:hover {{
            text-decoration: underline;
        }}

        /* ===== SEARCH & FILTERS ===== */
        .search-filters {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}

        .search-input {{
            flex: 1;
            min-width: 250px;
            padding: 0.75rem 1rem;
            padding-left: 2.5rem;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }}

        .search-input:focus {{
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }}

        .search-input::placeholder {{
            color: var(--text-muted);
        }}

        .search-wrapper {{
            position: relative;
            flex: 1;
            min-width: 250px;
        }}

        .search-icon {{
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .filter-buttons {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 0.625rem 1rem;
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .filter-btn:hover {{
            background: var(--bg-card-hover);
            border-color: var(--border-light);
        }}

        .filter-btn.active {{
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: white;
        }}

        /* ===== POC EDITOR ===== */
        .poc-editor {{
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}

        .poc-toolbar {{
            padding: 0.75rem 1rem;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 0.5rem;
        }}

        .poc-textarea {{
            width: 100%;
            min-height: 400px;
            padding: 1rem;
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            line-height: 1.6;
            resize: vertical;
        }}

        .poc-textarea:focus {{
            outline: none;
        }}

        .poc-textarea::placeholder {{
            color: var(--text-muted);
        }}

        /* ===== BUTTONS ===== */
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.625rem 1.25rem;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }}

        .btn-primary {{
            background: var(--accent-blue);
            color: white;
        }}

        .btn-primary:hover {{
            background: #2563eb;
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }}

        .btn-secondary {{
            background: var(--bg-input);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }}

        .btn-secondary:hover {{
            background: var(--bg-card-hover);
            color: var(--text-primary);
        }}

        /* ===== BADGES ===== */
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.625rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .badge-info {{
            background: rgba(6, 182, 212, 0.2);
            color: var(--accent-cyan);
        }}

        .badge-success {{
            background: rgba(34, 197, 94, 0.2);
            color: var(--accent-green);
        }}

        .badge-warning {{
            background: rgba(234, 179, 8, 0.2);
            color: var(--accent-yellow);
        }}

        .badge-danger {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--accent-red);
        }}

        /* ===== EMPTY STATE ===== */
        .empty-state {{
            text-align: center;
            padding: 3rem 2rem;
            color: var(--text-muted);
        }}

        .empty-state-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }}

        .empty-state-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }}

        .empty-state-desc {{
            font-size: 0.9rem;
        }}

        /* ===== GRID LAYOUTS ===== */
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.5rem;
        }}

        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }}

        /* ===== SCROLLBAR ===== */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}

        ::-webkit-scrollbar-track {{
            background: var(--bg-dark);
        }}

        ::-webkit-scrollbar-thumb {{
            background: var(--border-light);
            border-radius: 4px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: var(--text-muted);
        }}

        /* ===== CODE BLOCKS ===== */
        pre {{
            background: var(--bg-dark);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-cyan);
            font-size: 0.9em;
        }}

        /* ===== RESPONSIVE ===== */
        @media (max-width: 1200px) {{
            .stats-bar {{
                grid-template-columns: repeat(3, 1fr);
            }}

            .executive-summary {{
                grid-template-columns: 1fr;
            }}

            .grid-2 {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (max-width: 768px) {{
            .sidebar {{
                transform: translateX(-100%);
                transition: transform 0.3s ease;
            }}

            .sidebar.open {{
                transform: translateX(0);
            }}

            .main-content {{
                margin-left: 0;
            }}

            .stats-bar {{
                grid-template-columns: repeat(2, 1fr);
                padding: 1rem;
            }}

            .tab-content {{
                padding: 1rem;
            }}

            .page-header {{
                padding: 1.5rem;
            }}

            .severity-distribution {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        /* ===== PRINT STYLES ===== */
        @media print {{
            .sidebar {{
                display: none;
            }}

            .main-content {{
                margin-left: 0;
            }}

            .tab-content {{
                display: block !important;
                page-break-inside: avoid;
            }}

            .vuln-card, .secret-card, .card {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar Navigation -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <div class="logo-icon">ER</div>
                    <div>
                        <div class="logo-text">EnumRust</div>
                        <div class="logo-subtitle">Security Assessment</div>
                    </div>
                </div>
                <div class="target-info">
                    <div class="target-label">Target Domain</div>
                    <div class="target-domain">{domain}</div>
                </div>
            </div>

            <nav class="nav-section">
                <div class="nav-title">Analysis</div>
                <div class="nav-item active" onclick="openTab('overview')">
                    <span class="nav-icon">&#128202;</span>
                    Executive Summary
                </div>
                <div class="nav-item" onclick="openTab('subdomains')">
                    <span class="nav-icon">&#127760;</span>
                    Subdomains
                    <span class="nav-badge">{total_subdomains}</span>
                </div>
                <div class="nav-item" onclick="openTab('live-hosts')">
                    <span class="nav-icon">&#9989;</span>
                    Live Hosts
                    <span class="nav-badge">{total_live_hosts}</span>
                </div>

                <div class="nav-title" style="margin-top: 1rem;">Security Findings</div>
                <div class="nav-item" onclick="openTab('vulnerabilities')">
                    <span class="nav-icon">&#128680;</span>
                    Vulnerabilities
                    <span class="nav-badge critical">{total_vulns}</span>
                </div>
                <div class="nav-item" onclick="openTab('secrets')">
                    <span class="nav-icon">&#128273;</span>
                    Secrets
                    <span class="nav-badge warning">{total_secrets}</span>
                </div>

                <div class="nav-title" style="margin-top: 1rem;">Resources</div>
                <div class="nav-item" onclick="openTab('cloud')">
                    <span class="nav-icon">&#9729;</span>
                    Cloud Storage
                </div>
                <div class="nav-item" onclick="openTab('endpoints')">
                    <span class="nav-icon">&#128279;</span>
                    API Endpoints
                </div>
                <div class="nav-item" onclick="openTab('packages')">
                    <span class="nav-icon">&#128230;</span>
                    Dependencies
                </div>

                <div class="nav-title" style="margin-top: 1rem;">Tools</div>
                <div class="nav-item" onclick="openTab('poc')">
                    <span class="nav-icon">&#128187;</span>
                    POC Editor
                </div>
                <div class="nav-item" onclick="openTab('raw')">
                    <span class="nav-icon">&#128196;</span>
                    Raw Data
                </div>
            </nav>

            <div class="sidebar-footer">
                <div class="report-meta">
                    <div class="report-meta-item">
                        <span>Generated</span>
                        <span>{current_date}</span>
                    </div>
                    <div class="report-meta-item">
                        <span>Version</span>
                        <span>EnumRust v2.2.0</span>
                    </div>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            {stats}

            <!-- Executive Summary Tab -->
            <div id="overview" class="tab-content active">
                {executive_summary}

                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <span class="card-title-icon">&#9881;</span>
                            Scan Configuration
                        </div>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <tr>
                                <td style="width: 200px; font-weight: 500;">Target Domain</td>
                                <td><code>{domain}</code></td>
                            </tr>
                            <tr>
                                <td style="font-weight: 500;">Scan Type</td>
                                <td>Full Security Reconnaissance</td>
                            </tr>
                            <tr>
                                <td style="font-weight: 500;">Tools Utilized</td>
                                <td>haktrails, subfinder, tlsx, dnsx, masscan, httpx, nuclei, trufflehog</td>
                            </tr>
                            <tr>
                                <td style="font-weight: 500;">Report Generated</td>
                                <td>{current_date}</td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>

            {subdomains_html}
            {live_hosts_html}
            {secrets_html}
            {vulnerabilities_html}
            {cloud_html}
            {endpoints_html}
            {packages_html}
            {poc_html}
            {raw_data_html}
        </main>
    </div>

    <script>
        let currentVulnFilter = 'all';

        function openTab(tabName) {{
            // Hide all tabs
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));

            // Deactivate all nav items
            const navItems = document.querySelectorAll('.nav-item');
            navItems.forEach(item => item.classList.remove('active'));

            // Show selected tab
            document.getElementById(tabName).classList.add('active');

            // Activate clicked nav item
            event.target.closest('.nav-item').classList.add('active');
        }}

        function searchList(inputId, listClass) {{
            const input = document.getElementById(inputId);
            const filter = input.value.toLowerCase();
            const items = document.querySelectorAll('.' + listClass);

            items.forEach(item => {{
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(filter) ? '' : 'none';
            }});
        }}

        function filterVulns(severity) {{
            currentVulnFilter = severity;

            // Update active button
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => {{
                btn.classList.remove('active');
                if (btn.dataset.filter === severity) {{
                    btn.classList.add('active');
                }}
            }});

            // Filter vulnerabilities
            const vulnCards = document.querySelectorAll('.vuln-card');
            vulnCards.forEach(card => {{
                if (severity === 'all') {{
                    card.style.display = '';
                }} else {{
                    const cardSeverity = card.dataset.severity;
                    card.style.display = cardSeverity === severity ? '' : 'none';
                }}
            }});

            // Apply search filter
            searchVulns();
        }}

        function searchVulns() {{
            const input = document.getElementById('vuln-search');
            if (!input) return;

            const filter = input.value.toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');

            cards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                const severity = card.dataset.severity;

                const matchesSearch = text.includes(filter);
                const matchesSeverity = currentVulnFilter === 'all' || severity === currentVulnFilter;

                card.style.display = (matchesSearch && matchesSeverity) ? '' : 'none';
            }});
        }}

        function savePOC() {{
            const poc = document.getElementById('poc-text').value;
            const blob = new Blob([poc], {{ type: 'text/plain' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'poc_{domain}.txt';
            a.click();
            URL.revokeObjectURL(url);
        }}

        function copyPOC() {{
            const poc = document.getElementById('poc-text');
            poc.select();
            navigator.clipboard.writeText(poc.value);

            // Show feedback
            const btn = event.target;
            const originalText = btn.innerHTML;
            btn.innerHTML = '&#10003; Copied!';
            setTimeout(() => {{ btn.innerHTML = originalText; }}, 2000);
        }}

        // Auto-save POC
        const pocText = document.getElementById('poc-text');
        if (pocText) {{
            const saved = localStorage.getItem('enumrust_poc_{domain}');
            if (saved) {{
                pocText.value = saved;
            }}

            pocText.addEventListener('input', () => {{
                localStorage.setItem('enumrust_poc_{domain}', pocText.value);
            }});
        }}

        // Mobile menu toggle
        function toggleSidebar() {{
            document.querySelector('.sidebar').classList.toggle('open');
        }}
    </script>
</body>
</html>"#,
        domain = domain,
        stats = stats,
        executive_summary = executive_summary,
        subdomains_html = subdomains_html,
        live_hosts_html = live_hosts_html,
        secrets_html = secrets_html,
        vulnerabilities_html = vulnerabilities_html,
        cloud_html = cloud_html,
        endpoints_html = endpoints_html,
        packages_html = packages_html,
        poc_html = poc_html,
        raw_data_html = raw_data_html,
        total_subdomains = subdomains.len(),
        total_live_hosts = http200_urls.len(),
        total_secrets = total_secrets,
        total_vulns = nuclei.len(),
        current_date = current_date,
    )
}

/// Count vulnerabilities by severity
fn count_vuln_severities(nuclei: &[Value]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for vuln in nuclei {
        match vuln["info"]["severity"].as_str().unwrap_or("info") {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    (critical, high, medium, low)
}

/// Generate executive summary section
fn generate_executive_summary(
    _domain: &str,
    subdomains: usize,
    live_hosts: usize,
    secrets: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
) -> String {
    let total_vulns = critical + high + medium + low;

    // Calculate risk score and level
    let risk_score = (critical * 40) + (high * 25) + (medium * 10) + (low * 5) + (secrets * 15);
    let (risk_level, risk_class, risk_desc) = if critical > 0 || risk_score > 100 {
        ("CRITICAL", "critical", "Immediate action required")
    } else if high > 0 || risk_score > 50 {
        ("HIGH", "high", "Significant risks identified")
    } else if medium > 0 || risk_score > 20 {
        ("MEDIUM", "medium", "Moderate risks present")
    } else {
        ("LOW", "low", "Minor issues found")
    };

    format!(
        r#"<div class="executive-summary">
            <div class="summary-main">
                <div class="summary-title">
                    <span>&#128202;</span>
                    Security Assessment Overview
                </div>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-item-label">Attack Surface</div>
                        <div class="summary-item-value">{}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Subdomains discovered</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-item-label">Active Hosts</div>
                        <div class="summary-item-value" style="color: var(--accent-green);">{}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Responding to requests</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-item-label">Vulnerabilities</div>
                        <div class="summary-item-value" style="color: var(--accent-red);">{}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Security issues found</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-item-label">Exposed Secrets</div>
                        <div class="summary-item-value" style="color: var(--accent-yellow);">{}</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Credentials/keys found</div>
                    </div>
                </div>

                <div class="severity-distribution">
                    <div class="severity-item">
                        <div class="severity-count critical">{}</div>
                        <div class="severity-label">Critical</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-count high">{}</div>
                        <div class="severity-label">High</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-count medium">{}</div>
                        <div class="severity-label">Medium</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-count low">{}</div>
                        <div class="severity-label">Low</div>
                    </div>
                </div>
            </div>

            <div class="risk-score">
                <div class="risk-score-title">Overall Risk Level</div>
                <div class="risk-score-circle {}">
                    {}
                </div>
                <div class="risk-score-label">{}</div>
                <div class="risk-score-desc">{}</div>
            </div>
        </div>"#,
        subdomains,
        live_hosts,
        total_vulns,
        secrets,
        critical,
        high,
        medium,
        low,
        risk_class,
        risk_level,
        if total_vulns > 0 { format!("{} Issues", total_vulns) } else { "Secure".to_string() },
        risk_desc
    )
}

fn generate_stats_summary(
    subdomains: usize,
    live_hosts: usize,
    ips: usize,
    secrets: usize,
    vulnerabilities: usize,
    endpoints: usize,
) -> String {
    format!(
        r#"<div class="stats-bar">
            <div class="stat-item">
                <div class="stat-value">{}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-item">
                <div class="stat-value success">{}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-item">
                <div class="stat-value warning">{}</div>
                <div class="stat-label">Secrets</div>
            </div>
            <div class="stat-item">
                <div class="stat-value critical">{}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{}</div>
                <div class="stat-label">Endpoints</div>
            </div>
        </div>"#,
        subdomains, live_hosts, ips, secrets, vulnerabilities, endpoints
    )
}

fn generate_subdomains_tab(subdomains: &[String], _validated_hosts: &[Value]) -> String {
    let mut html = String::from(r#"<div id="subdomains" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#127760;</span>
                    Discovered Subdomains
                </div>
                <span class="card-badge">"#);

    html.push_str(&format!("{} found</span>", subdomains.len()));
    html.push_str(r#"</div>
            <div class="card-body">
                <div class="search-wrapper" style="margin-bottom: 1rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="subdomain-search" class="search-input" placeholder="Search subdomains..." onkeyup="searchList('subdomain-search', 'subdomain-item')">
                </div>
                <div class="list-container">"#);

    if subdomains.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#127760;</div>
                        <div class="empty-state-title">No Subdomains Found</div>
                        <div class="empty-state-desc">No subdomains were discovered during the scan.</div>
                    </div>"#);
    } else {
        for subdomain in subdomains {
            html.push_str(&format!(
                r#"<div class="list-item subdomain-item">
                    <div class="list-item-icon">&#127760;</div>
                    <div class="list-item-content">
                        <div class="list-item-title">{}</div>
                    </div>
                </div>"#,
                subdomain
            ));
        }
    }

    html.push_str("</div></div></div></div>");
    html
}

fn generate_live_hosts_tab(http200_urls: &[String]) -> String {
    let mut html = String::from(r#"<div id="live-hosts" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#9989;</span>
                    Live Hosts (HTTP 200)
                </div>
                <span class="card-badge">"#);

    html.push_str(&format!("{} responding</span>", http200_urls.len()));
    html.push_str(r#"</div>
            <div class="card-body">
                <div class="search-wrapper" style="margin-bottom: 1rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="host-search" class="search-input" placeholder="Search live hosts..." onkeyup="searchList('host-search', 'host-item')">
                </div>
                <div class="list-container">"#);

    if http200_urls.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#9989;</div>
                        <div class="empty-state-title">No Live Hosts Found</div>
                        <div class="empty-state-desc">No hosts responded with HTTP 200 during the scan.</div>
                    </div>"#);
    } else {
        for url in http200_urls {
            html.push_str(&format!(
                r#"<div class="list-item host-item">
                    <div class="list-item-icon" style="background: rgba(34, 197, 94, 0.2); color: var(--accent-green);">&#9989;</div>
                    <div class="list-item-content">
                        <a href="{}" target="_blank" class="list-item-link">{}</a>
                    </div>
                </div>"#,
                url, url
            ));
        }
    }

    html.push_str("</div></div></div></div>");
    html
}

fn generate_secrets_tab(js_secrets: &[Value], trufflehog: &[Value]) -> String {
    let total_secrets = js_secrets.len() + trufflehog.len();

    let mut html = String::from(r#"<div id="secrets" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128273;</span>
                    Exposed Secrets &amp; Credentials
                </div>
                <span class="card-badge" style="background: rgba(239, 68, 68, 0.2); color: var(--accent-red);">"#);

    html.push_str(&format!("{} found</span>", total_secrets));
    html.push_str(r#"</div>
            <div class="card-body">
                <div class="search-wrapper" style="margin-bottom: 1.5rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="secret-search" class="search-input" placeholder="Search secrets..." onkeyup="searchList('secret-search', 'secret-card')">
                </div>"#);

    if js_secrets.is_empty() && trufflehog.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#128273;</div>
                        <div class="empty-state-title">No Secrets Found</div>
                        <div class="empty-state-desc">No hardcoded secrets or credentials were detected.</div>
                    </div>"#);
    } else {
        // JS Secrets
        for secret in js_secrets {
            let secret_type = secret["secret_type"].as_str().unwrap_or("Unknown");
            let value = secret["value"].as_str().unwrap_or("N/A");
            let location = secret["source_url"].as_str().unwrap_or("Unknown");
            let confidence = secret["confidence"].as_str().unwrap_or("unknown");

            html.push_str(&format!(
                r#"<div class="secret-card">
                    <div class="secret-header">
                        <span class="secret-type">{}</span>
                        <span class="secret-confidence">Confidence: {}</span>
                    </div>
                    <div class="secret-body">
                        <div class="secret-value">{}</div>
                        <div class="secret-source">
                            <strong>Source:</strong> <a href="{}" target="_blank">{}</a>
                        </div>
                    </div>
                </div>"#,
                secret_type, confidence, value, location, location
            ));
        }

        // TruffleHog Secrets
        for secret in trufflehog {
            let detector = secret["DetectorName"].as_str().unwrap_or("Unknown");
            let raw = secret["Raw"].as_str().unwrap_or("N/A");
            let verified = secret["Verified"].as_bool().unwrap_or(false);

            html.push_str(&format!(
                r#"<div class="secret-card">
                    <div class="secret-header">
                        <span class="secret-type">TruffleHog: {}</span>
                        <span class="secret-confidence" style="background: {}; color: {};">{}</span>
                    </div>
                    <div class="secret-body">
                        <div class="secret-value">{}</div>
                    </div>
                </div>"#,
                detector,
                if verified { "rgba(34, 197, 94, 0.2)" } else { "rgba(234, 179, 8, 0.2)" },
                if verified { "var(--accent-green)" } else { "var(--accent-yellow)" },
                if verified { "Verified" } else { "Unverified" },
                raw
            ));
        }
    }

    html.push_str("</div></div></div>");
    html
}

fn generate_vulnerabilities_tab(nuclei: &[Value]) -> String {
    // Count vulnerabilities by severity
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for vuln in nuclei {
        match vuln["info"]["severity"].as_str().unwrap_or("info") {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => info += 1,
        }
    }

    let mut html = String::from(r#"<div id="vulnerabilities" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128680;</span>
                    Security Vulnerabilities
                </div>
                <span class="card-badge" style="background: rgba(239, 68, 68, 0.2); color: var(--accent-red);">"#);

    html.push_str(&format!("{} detected</span>", nuclei.len()));
    html.push_str(r#"</div>
            <div class="card-body">"#);

    // Add severity breakdown
    if !nuclei.is_empty() {
        html.push_str(r#"<div class="grid-3" style="margin-bottom: 1.5rem; grid-template-columns: repeat(5, 1fr);">"#);

        html.push_str(&format!(
            r#"<div class="severity-item" style="border-left: 3px solid var(--accent-red);">
                <div class="severity-count critical">{}</div>
                <div class="severity-label">Critical</div>
            </div>"#,
            critical
        ));

        html.push_str(&format!(
            r#"<div class="severity-item" style="border-left: 3px solid var(--accent-orange);">
                <div class="severity-count high">{}</div>
                <div class="severity-label">High</div>
            </div>"#,
            high
        ));

        html.push_str(&format!(
            r#"<div class="severity-item" style="border-left: 3px solid var(--accent-yellow);">
                <div class="severity-count medium">{}</div>
                <div class="severity-label">Medium</div>
            </div>"#,
            medium
        ));

        html.push_str(&format!(
            r#"<div class="severity-item" style="border-left: 3px solid var(--accent-blue);">
                <div class="severity-count low">{}</div>
                <div class="severity-label">Low</div>
            </div>"#,
            low
        ));

        html.push_str(&format!(
            r#"<div class="severity-item" style="border-left: 3px solid var(--accent-cyan);">
                <div class="severity-count" style="color: var(--accent-cyan);">{}</div>
                <div class="severity-label">Info</div>
            </div>"#,
            info
        ));

        html.push_str("</div>");

        // Search and filters
        html.push_str(r#"<div class="search-filters">
                <div class="search-wrapper">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="vuln-search" class="search-input" placeholder="Search vulnerabilities..." onkeyup="searchVulns()">
                </div>
                <div class="filter-buttons">"#);

        html.push_str(&format!(
            r#"<button class="filter-btn active" onclick="filterVulns('all')" data-filter="all">All ({})</button>"#,
            nuclei.len()
        ));
        html.push_str(&format!(
            r#"<button class="filter-btn" onclick="filterVulns('critical')" data-filter="critical">Critical ({})</button>"#,
            critical
        ));
        html.push_str(&format!(
            r#"<button class="filter-btn" onclick="filterVulns('high')" data-filter="high">High ({})</button>"#,
            high
        ));
        html.push_str(&format!(
            r#"<button class="filter-btn" onclick="filterVulns('medium')" data-filter="medium">Medium ({})</button>"#,
            medium
        ));
        html.push_str(&format!(
            r#"<button class="filter-btn" onclick="filterVulns('low')" data-filter="low">Low ({})</button>"#,
            low
        ));

        html.push_str("</div></div>");
    }

    if nuclei.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#128680;</div>
                        <div class="empty-state-title">No Vulnerabilities Detected</div>
                        <div class="empty-state-desc">No security vulnerabilities were found during the scan.</div>
                    </div>"#);
    } else {
        for vuln in nuclei {
            let name = vuln["info"]["name"].as_str().unwrap_or("Unknown");
            let severity = vuln["info"]["severity"].as_str().unwrap_or("info");
            let description = vuln["info"]["description"].as_str().unwrap_or("No description available");
            let matched_at = vuln["matched-at"].as_str().unwrap_or(vuln["host"].as_str().unwrap_or("Unknown"));
            let template_id = vuln["template-id"].as_str().unwrap_or("unknown");
            let ip = vuln["ip"].as_str().unwrap_or("N/A");

            // Get tags
            let tags = if let Some(tag_arr) = vuln["info"]["tags"].as_array() {
                tag_arr.iter()
                    .filter_map(|t| t.as_str())
                    .map(|t| format!(r#"<span class="vuln-tag">{}</span>"#, t))
                    .collect::<Vec<_>>()
                    .join("")
            } else {
                String::new()
            };

            // Get references
            let references = if let Some(ref_arr) = vuln["info"]["reference"].as_array() {
                let refs = ref_arr.iter()
                    .filter_map(|r| r.as_str())
                    .take(3)
                    .map(|r| format!(r#"<a href="{}" target="_blank" class="list-item-link" style="display: block; margin: 0.25rem 0; font-size: 0.8rem;">{}</a>"#, r, r))
                    .collect::<Vec<_>>()
                    .join("");
                if !refs.is_empty() {
                    format!(r#"<details class="vuln-details">
                        <summary>View References</summary>
                        <div style="padding: 0.5rem 0;">{}</div>
                    </details>"#, refs)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // Get extracted results if available
            let extracted = if let Some(ext_arr) = vuln["extracted-results"].as_array() {
                let items = ext_arr.iter()
                    .filter_map(|e| e.as_str())
                    .take(5)
                    .map(|e| format!(r#"<div style="background: var(--bg-dark); padding: 0.5rem; border-radius: 4px; margin: 0.25rem 0; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent-green);">{}</div>"#, e))
                    .collect::<Vec<_>>()
                    .join("");
                if !items.is_empty() {
                    format!(r#"<details class="vuln-details">
                        <summary>Extracted Results</summary>
                        <div style="padding: 0.5rem 0;">{}</div>
                    </details>"#, items)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // Get CURL command if available
            let curl_cmd = if let Some(curl) = vuln["curl-command"].as_str() {
                format!(r#"<details class="vuln-details">
                        <summary>CURL Command</summary>
                        <div class="vuln-curl">{}</div>
                    </details>"#, curl)
            } else {
                String::new()
            };

            html.push_str(&format!(
                r#"<div class="vuln-card" data-severity="{}">
                    <div class="vuln-card-header">
                        <span class="vuln-severity {}">{}</span>
                        <div class="vuln-info">
                            <div class="vuln-name">{}</div>
                            <div class="vuln-template">{}</div>
                        </div>
                    </div>
                    <div class="vuln-card-body">
                        <div class="vuln-description">{}</div>
                        <div class="vuln-meta">
                            <span class="vuln-meta-item"><strong>IP:</strong> {}</span>
                            <span class="vuln-meta-item"><strong>Template:</strong> {}</span>
                        </div>
                        <div class="vuln-target">{}</div>
                        {}
                        {}
                        {}
                        {}
                    </div>
                </div>"#,
                severity,
                severity,
                severity.to_uppercase(),
                name,
                template_id,
                description,
                ip,
                template_id,
                matched_at,
                if !tags.is_empty() {
                    format!(r#"<div class="vuln-tags">{}</div>"#, tags)
                } else {
                    String::new()
                },
                references,
                extracted,
                curl_cmd
            ));
        }
    }

    html.push_str("</div></div></div>");
    html
}

fn generate_cloud_tab(cloud_storage: &[Value], s3_buckets: &[String]) -> String {
    let total = cloud_storage.len() + s3_buckets.len();

    let mut html = String::from(r#"<div id="cloud" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#9729;</span>
                    Cloud Storage Exposure
                </div>
                <span class="card-badge">"#);

    html.push_str(&format!("{} resources</span>", total));
    html.push_str(r#"</div>
            <div class="card-body">
                <div class="search-wrapper" style="margin-bottom: 1rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="cloud-search" class="search-input" placeholder="Search cloud resources..." onkeyup="searchList('cloud-search', 'cloud-item')">
                </div>
                <div class="list-container">"#);

    if cloud_storage.is_empty() && s3_buckets.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#9729;</div>
                        <div class="empty-state-title">No Cloud Resources Found</div>
                        <div class="empty-state-desc">No exposed cloud storage resources were detected.</div>
                    </div>"#);
    } else {
        for item in cloud_storage {
            let url = item["url"].as_str().unwrap_or("N/A");
            let storage_type = item["storage_type"].as_str().unwrap_or("Unknown");

            html.push_str(&format!(
                r#"<div class="list-item cloud-item">
                    <div class="list-item-icon" style="background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan);">&#9729;</div>
                    <div class="list-item-content">
                        <span class="badge badge-info" style="margin-right: 0.5rem;">{}</span>
                        <a href="{}" target="_blank" class="list-item-link">{}</a>
                    </div>
                </div>"#,
                storage_type, url, url
            ));
        }

        for bucket in s3_buckets {
            html.push_str(&format!(
                r#"<div class="list-item cloud-item">
                    <div class="list-item-icon" style="background: rgba(234, 179, 8, 0.2); color: var(--accent-yellow);">&#128230;</div>
                    <div class="list-item-content">
                        <span class="badge badge-warning" style="margin-right: 0.5rem;">S3 Bucket</span>
                        <span class="list-item-title">{}</span>
                    </div>
                </div>"#,
                bucket
            ));
        }
    }

    html.push_str("</div></div></div></div>");
    html
}

fn generate_endpoints_tab(js_endpoints: &[String]) -> String {
    let mut html = String::from(r#"<div id="endpoints" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128279;</span>
                    Discovered API Endpoints
                </div>
                <span class="card-badge">"#);

    html.push_str(&format!("{} endpoints</span>", js_endpoints.len()));
    html.push_str(r#"</div>
            <div class="card-body">
                <div class="search-wrapper" style="margin-bottom: 1rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="endpoint-search" class="search-input" placeholder="Search endpoints..." onkeyup="searchList('endpoint-search', 'endpoint-item')">
                </div>
                <div class="list-container">"#);

    if js_endpoints.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#128279;</div>
                        <div class="empty-state-title">No Endpoints Found</div>
                        <div class="empty-state-desc">No API endpoints were discovered in JavaScript files.</div>
                    </div>"#);
    } else {
        for endpoint in js_endpoints {
            html.push_str(&format!(
                r#"<div class="list-item endpoint-item">
                    <div class="list-item-icon">&#128279;</div>
                    <div class="list-item-content">
                        <code style="font-size: 0.9rem;">{}</code>
                    </div>
                </div>"#,
                endpoint
            ));
        }
    }

    html.push_str("</div></div></div></div>");
    html
}

fn generate_packages_tab(packages: &[Value]) -> String {
    let confusion_count = packages.iter()
        .filter(|p| p["potential_confusion"].as_bool().unwrap_or(false))
        .count();

    let mut html = String::from(r#"<div id="packages" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128230;</span>
                    Package Dependencies
                </div>
                <span class="card-badge">"#);

    html.push_str(&format!("{} packages</span>", packages.len()));
    html.push_str(r#"</div>
            <div class="card-body">"#);

    if confusion_count > 0 {
        html.push_str(&format!(
            r#"<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--accent-red); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem; color: var(--accent-red); font-weight: 600;">
                    <span>&#9888;</span>
                    {} package(s) with potential dependency confusion risk
                </div>
            </div>"#,
            confusion_count
        ));
    }

    html.push_str(r#"<div class="search-wrapper" style="margin-bottom: 1rem;">
                    <span class="search-icon">&#128269;</span>
                    <input type="text" id="package-search" class="search-input" placeholder="Search packages..." onkeyup="searchList('package-search', 'package-item')">
                </div>
                <div class="list-container">"#);

    if packages.is_empty() {
        html.push_str(r#"<div class="empty-state">
                        <div class="empty-state-icon">&#128230;</div>
                        <div class="empty-state-title">No Packages Found</div>
                        <div class="empty-state-desc">No package dependencies were detected.</div>
                    </div>"#);
    } else {
        for pkg in packages {
            let name = pkg["package_name"].as_str().unwrap_or("Unknown");
            let pkg_type = pkg["package_type"].as_str().unwrap_or("Unknown");
            let confusion = pkg["potential_confusion"].as_bool().unwrap_or(false);

            let icon_bg = if confusion {
                "background: rgba(239, 68, 68, 0.2); color: var(--accent-red);"
            } else {
                "background: rgba(59, 130, 246, 0.2); color: var(--accent-blue);"
            };

            html.push_str(&format!(
                r#"<div class="list-item package-item">
                    <div class="list-item-icon" style="{}">&#128230;</div>
                    <div class="list-item-content">
                        <div class="list-item-title">
                            <span class="badge badge-info" style="margin-right: 0.5rem;">{}</span>
                            {}
                            {}
                        </div>
                    </div>
                </div>"#,
                icon_bg,
                pkg_type,
                name,
                if confusion {
                    r#"<span class="badge badge-danger" style="margin-left: 0.5rem;">Confusion Risk</span>"#
                } else {
                    ""
                }
            ));
        }
    }

    html.push_str("</div></div></div></div>");
    html
}

fn generate_poc_tab() -> String {
    String::from(r#"<div id="poc" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128187;</span>
                    Proof of Concept Editor
                </div>
            </div>
            <div class="card-body">
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem; line-height: 1.6;">
                    Use this editor to write, test, and document your proof of concept exploits.
                    Your work is automatically saved to browser localStorage.
                </p>
                <div class="poc-editor">
                    <div class="poc-toolbar">
                        <button class="btn btn-primary" onclick="savePOC()">
                            <span>&#128190;</span> Save to File
                        </button>
                        <button class="btn btn-secondary" onclick="copyPOC()">
                            <span>&#128203;</span> Copy to Clipboard
                        </button>
                    </div>
                    <textarea id="poc-text" class="poc-textarea" placeholder="Write your proof of concept here..."></textarea>
                </div>
            </div>
        </div>
    </div>"#)
}

fn generate_raw_data_tab(metrics: &[Value]) -> String {
    let mut html = String::new();

    html.push_str(r#"<div id="raw" class="tab-content">
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-title-icon">&#128196;</span>
                    Raw Scan Data
                </div>
            </div>
            <div class="card-body">
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem; line-height: 1.6;">
                    Complete scan metrics and raw JSON data for advanced analysis and integration.
                </p>
                <pre style="max-height: 600px; overflow: auto;">"#);

    if metrics.is_empty() {
        html.push_str(r#"<code style="color: var(--text-muted);">No metrics data available</code>"#);
    } else {
        html.push_str("<code>");
        for metric in metrics {
            let json_str = serde_json::to_string_pretty(metric).unwrap_or_default();
            // Escape HTML characters
            let escaped = json_str
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            html.push_str(&escaped);
            html.push_str("\n\n");
        }
        html.push_str("</code>");
    }

    html.push_str("</pre></div></div></div>");
    html
}
