// package_scanner.rs - Package Dependency & Dependency Confusion Scanner
// Purpose: Detect npm, pip, go packages in JS files and validate against public registries
// Security Focus: Identify dependency confusion vulnerabilities

use colored::*;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDependency {
    pub package_name: String,
    pub package_type: PackageType,
    pub source_url: String,
    pub found_in_context: String,
    pub exists_in_public_registry: bool,
    pub registry_url: Option<String>,
    pub potential_confusion: bool,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum PackageType {
    NPM,
    PIP,
    GO,
}

impl std::fmt::Display for PackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PackageType::NPM => write!(f, "npm"),
            PackageType::PIP => write!(f, "pip"),
            PackageType::GO => write!(f, "go"),
        }
    }
}

/// Extract npm package imports from JavaScript content
pub fn extract_npm_packages(js_content: &str, source_url: &str) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Patterns for npm packages - MORE STRICT to avoid false positives
    let patterns = vec![
        // require() calls - must be followed by closing quote and paren
        Regex::new(r#"require\s*\(\s*["']([a-z0-9@][a-z0-9\-_./]*?)["']\s*\)"#).unwrap(),
        // import statements - must have 'from' keyword
        Regex::new(r#"import\s+(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+["']([a-z0-9@][a-z0-9\-_./]*?)["']"#).unwrap(),
        // dynamic imports - must be followed by closing quote and paren
        Regex::new(r#"import\s*\(\s*["']([a-z0-9@][a-z0-9\-_./]*?)["']\s*\)"#).unwrap(),
        // package.json dependencies (if embedded) - must have version pattern
        Regex::new(r#"["']([a-z0-9@][a-z0-9\-_./]+?)["']\s*:\s*["'][~^]?[\d.]+"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(package_match) = cap.get(1) {
                let package_name = package_match.as_str().to_string();

                // Clean up package name
                let cleaned_name = clean_package_name(&package_name, PackageType::NPM);

                // Skip if empty or already seen
                if cleaned_name.is_empty() {
                    continue;
                }

                if !seen.insert(cleaned_name.clone()) {
                    continue;
                }

                // *** CRITICAL: Validate NPM package name format ***
                if !is_valid_npm_package_name(&cleaned_name) {
                    // Debug log for filtered invalid names (only in verbose mode)
                    #[cfg(debug_assertions)]
                    {
                        if has_css_unit_suffix(&cleaned_name) {
                            eprintln!("[DEBUG] Filtered CSS value: {}", cleaned_name);
                        } else if cleaned_name.chars().all(|c| c.is_ascii_digit()) {
                            eprintln!("[DEBUG] Filtered pure number: {}", cleaned_name);
                        } else {
                            eprintln!("[DEBUG] Filtered invalid NPM name: {}", cleaned_name);
                        }
                    }
                    continue;
                }

                // Skip built-in Node.js modules
                if is_builtin_nodejs_module(&cleaned_name) {
                    continue;
                }

                // Skip relative paths
                if cleaned_name.starts_with('.') || cleaned_name.starts_with('/') {
                    continue;
                }

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::NPM,
                    source_url: source_url.to_string(),
                    found_in_context: extract_context(js_content, &package_name),
                    exists_in_public_registry: false,
                    registry_url: None,
                    potential_confusion: false,
                    validation_error: None,
                });
            }
        }
    }

    packages
}

/// Extract Python/pip package imports
pub fn extract_pip_packages(js_content: &str, source_url: &str) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Patterns for Python imports (found in JS code embedding Python or comments)
    let patterns = vec![
        // Python import statements (might be in comments or strings)
        Regex::new(r#"import\s+([a-z][a-z0-9_]*)"#).unwrap(),
        // from X import Y
        Regex::new(r#"from\s+([a-z][a-z0-9_]*)\s+import"#).unwrap(),
        // pip install commands in comments or strings
        Regex::new(r#"pip\s+install\s+([a-z][a-z0-9\-_]+)"#).unwrap(),
        // requirements.txt format
        Regex::new(r#"^([a-z][a-z0-9\-_]+)==[\d.]+"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(package_match) = cap.get(1) {
                let package_name = package_match.as_str().to_string();
                let cleaned_name = clean_package_name(&package_name, PackageType::PIP);

                if cleaned_name.is_empty() || !seen.insert(cleaned_name.clone()) {
                    continue;
                }

                // *** APPLY SAME FILTERS AS NPM ***

                // Skip Python built-ins
                if is_builtin_python_module(&cleaned_name) {
                    continue;
                }

                // Skip programming keywords
                if is_programming_keyword(&cleaned_name) {
                    continue;
                }

                // Skip CSS properties and values
                if is_css_property(&cleaned_name) || is_css_value(&cleaned_name) {
                    continue;
                }

                // Skip hashes and IDs
                if is_hash_or_id(&cleaned_name) {
                    continue;
                }

                // Skip names that look invalid
                if is_likely_invalid_package_name(&cleaned_name) {
                    continue;
                }

                // Must contain at least one letter and not be pure numbers
                if !cleaned_name.chars().any(|c| c.is_alphabetic()) {
                    continue;
                }

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::PIP,
                    source_url: source_url.to_string(),
                    found_in_context: extract_context(js_content, &package_name),
                    exists_in_public_registry: false,
                    registry_url: None,
                    potential_confusion: false,
                    validation_error: None,
                });
            }
        }
    }

    packages
}

/// Extract Go package imports
pub fn extract_go_packages(js_content: &str, source_url: &str) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Patterns for Go imports (found in embedded Go code or comments)
    let patterns = vec![
        // Go import statements
        Regex::new(r#"import\s+["']([a-z][a-z0-9\-_./]+/[a-z0-9\-_./]+)["']"#).unwrap(),
        // Go mod require
        Regex::new(r#"require\s+([a-z][a-z0-9\-_./]+/[a-z0-9\-_./]+)\s+v[\d.]+"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(package_match) = cap.get(1) {
                let package_name = package_match.as_str().to_string();
                let cleaned_name = clean_package_name(&package_name, PackageType::GO);

                if cleaned_name.is_empty() || !seen.insert(cleaned_name.clone()) {
                    continue;
                }

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::GO,
                    source_url: source_url.to_string(),
                    found_in_context: extract_context(js_content, &package_name),
                    exists_in_public_registry: false,
                    registry_url: None,
                    potential_confusion: false,
                    validation_error: None,
                });
            }
        }
    }

    packages
}

/// Extract all packages from JS content
pub fn extract_all_packages(js_content: &str, source_url: &str) -> Vec<PackageDependency> {
    let mut all_packages = Vec::new();

    all_packages.extend(extract_npm_packages(js_content, source_url));
    all_packages.extend(extract_pip_packages(js_content, source_url));
    all_packages.extend(extract_go_packages(js_content, source_url));

    all_packages
}

/// Validate npm package against npm registry
pub async fn validate_npm_package(package_name: &str, client: &Client) -> (bool, Option<String>, Option<String>) {
    let registry_url = format!("https://registry.npmjs.org/{}", package_name);

    // Retry logic for transient failures
    for attempt in 1..=3 {
        match client
            .get(&registry_url)
            .timeout(Duration::from_secs(15))
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    return (true, Some(registry_url), None);
                } else if response.status().as_u16() == 404 {
                    return (false, Some(registry_url), None);
                } else if response.status().as_u16() == 429 {
                    // Rate limit - aguardar e tentar novamente
                    if attempt < 3 {
                        eprintln!("[WARN] Rate limit atingido para {}, tentativa {}/3", package_name, attempt);
                        sleep(Duration::from_secs(2 * attempt as u64)).await;
                        continue;
                    }
                    return (false, Some(registry_url), Some("Rate limited".to_string()));
                } else {
                    return (false, Some(registry_url), Some(format!("HTTP {}", response.status())));
                }
            }
            Err(e) => {
                if attempt < 3 && (e.is_timeout() || e.is_connect()) {
                    eprintln!("[WARN] Erro temporário para {}, tentativa {}/3: {}", package_name, attempt, e);
                    sleep(Duration::from_millis(500 * attempt as u64)).await;
                    continue;
                }
                return (false, Some(registry_url), Some(e.to_string()));
            }
        }
    }

    (false, Some(registry_url), Some("Max retries exceeded".to_string()))
}

/// Validate pip package against PyPI
pub async fn validate_pip_package(package_name: &str, client: &Client) -> (bool, Option<String>, Option<String>) {
    let registry_url = format!("https://pypi.org/pypi/{}/json", package_name);

    for attempt in 1..=2 {
        match client
            .get(&registry_url)
            .timeout(Duration::from_secs(15))
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    return (true, Some(registry_url), None);
                } else if response.status().as_u16() == 404 {
                    return (false, Some(registry_url), None);
                } else {
                    return (false, Some(registry_url), Some(format!("HTTP {}", response.status())));
                }
            }
            Err(e) => {
                if attempt < 2 && (e.is_timeout() || e.is_connect()) {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return (false, Some(registry_url), Some(e.to_string()));
            }
        }
    }

    (false, Some(registry_url), Some("Max retries exceeded".to_string()))
}

/// Validate Go package against proxy.golang.org
pub async fn validate_go_package(package_name: &str, client: &Client) -> (bool, Option<String>, Option<String>) {
    let registry_url = format!("https://proxy.golang.org/{0}/@latest", package_name);

    for attempt in 1..=2 {
        match client
            .get(&registry_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    return (true, Some(registry_url), None);
                } else if response.status().as_u16() == 404 || response.status().as_u16() == 410 {
                    return (false, Some(registry_url), None);
                } else {
                    return (false, Some(registry_url), Some(format!("HTTP {}", response.status())));
                }
            }
            Err(e) => {
                if attempt < 2 && (e.is_timeout() || e.is_connect()) {
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
                return (false, Some(registry_url), Some(e.to_string()));
            }
        }
    }

    (false, Some(registry_url), Some("Max retries exceeded".to_string()))
}

/// Validate package dependency against public registry
pub async fn validate_package(
    package: &mut PackageDependency,
    client: &Client,
) -> Result<(), String> {
    sleep(Duration::from_millis(100)).await; // Rate limiting

    let (exists, registry_url, error) = match package.package_type {
        PackageType::NPM => validate_npm_package(&package.package_name, client).await,
        PackageType::PIP => validate_pip_package(&package.package_name, client).await,
        PackageType::GO => validate_go_package(&package.package_name, client).await,
    };

    package.exists_in_public_registry = exists;
    package.registry_url = registry_url;
    package.validation_error = error;

    // Mark as potential dependency confusion if package doesn't exist publicly
    package.potential_confusion = !exists && package.validation_error.is_none();

    Ok(())
}

/// Scan JS files for packages and validate them
pub async fn scan_js_for_packages(
    js_files: &[String],
    client: &Client,
    max_concurrent: usize,
) -> Vec<PackageDependency> {
    use futures::stream::{self, StreamExt};

    println!("{}", "[*] Scanning JS files for package dependencies...".cyan());

    // Extract packages from all JS files
    let mut all_packages = Vec::new();
    let total_files = js_files.len();
    let mut scanned = 0;
    let mut found_in_files = 0;

    for js_url in js_files {
        scanned += 1;

        // Fetch JS content
        match client
            .get(js_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(response) => {
                if let Ok(js_content) = response.text().await {
                    let packages = extract_all_packages(&js_content, js_url);
                    if !packages.is_empty() {
                        found_in_files += 1;
                        println!(
                            "{}",
                            format!("  [+] [{}/{}] Found {} packages in: {}",
                                scanned, total_files, packages.len(), js_url
                            ).green()
                        );
                    } else if scanned <= 10 || scanned % 20 == 0 {
                        // Show progress for first 10 files and every 20th file
                        println!(
                            "{}",
                            format!("  [-] [{}/{}] No packages in: {}",
                                scanned, total_files, js_url
                            ).yellow()
                        );
                    }
                    all_packages.extend(packages);
                }
            }
            Err(e) => {
                if scanned <= 10 {
                    println!(
                        "{}",
                        format!("  [!] [{}/{}] Failed to fetch: {} - {}",
                            scanned, total_files, js_url, e
                        ).red()
                    );
                }
                continue;
            }
        }
    }

    println!("{}", format!("[+] Scanned {} files, found packages in {} files", total_files, found_in_files).green());
    println!("{}", format!("[+] Total package references found: {}", all_packages.len()).green());

    // Validate packages against public registries
    println!("{}", "[*] Validating packages against public registries...".cyan());

    let validated_packages = stream::iter(all_packages)
        .map(|mut package| {
            let client = client.clone();
            async move {
                let _ = validate_package(&mut package, &client).await;
                package
            }
        })
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await;

    // Report findings
    let confusion_count = validated_packages
        .iter()
        .filter(|p| p.potential_confusion)
        .count();

    if confusion_count > 0 {
        println!("{}", format!("[!] Found {} potential dependency confusion vulnerabilities!", confusion_count).red().bold());
    }

    validated_packages
}

/// Save package dependencies to JSON file
pub fn save_packages_to_json(
    packages: &[PackageDependency],
    output_path: &Path,
) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(packages)?;
    let mut file = File::create(output_path)?;
    writeln!(file, "{}", json)?;
    Ok(())
}

/// Save only dependency confusion findings
pub fn save_dependency_confusion_findings(
    packages: &[PackageDependency],
    output_path: &Path,
) -> std::io::Result<()> {
    let confusion_packages: Vec<&PackageDependency> = packages
        .iter()
        .filter(|p| p.potential_confusion)
        .collect();

    let mut file = File::create(output_path)?;

    writeln!(file, "=== DEPENDENCY CONFUSION VULNERABILITIES ===")?;
    writeln!(file, "Total packages analyzed: {}", packages.len())?;
    writeln!(file, "Potential confusion vulnerabilities: {}", confusion_packages.len())?;
    writeln!(file)?;

    for package in confusion_packages {
        writeln!(file, "[{}] {} - NOT FOUND IN PUBLIC REGISTRY",
                 package.package_type, package.package_name)?;
        writeln!(file, "  Source: {}", package.source_url)?;
        writeln!(file, "  Context: {}", package.found_in_context)?;
        if let Some(ref url) = package.registry_url {
            writeln!(file, "  Checked: {}", url)?;
        }
        writeln!(file)?;
    }

    Ok(())
}

// Helper functions

fn clean_package_name(name: &str, pkg_type: PackageType) -> String {
    match pkg_type {
        PackageType::NPM => {
            // Remove sub-paths for npm packages
            if let Some(idx) = name.find('/') {
                if name.starts_with('@') {
                    // Scoped package: @org/package
                    if let Some(second_slash) = name[idx + 1..].find('/') {
                        return name[..idx + 1 + second_slash].to_string();
                    }
                } else {
                    // Regular package: package/subpath
                    return name[..idx].to_string();
                }
            }
            name.to_string()
        }
        PackageType::PIP | PackageType::GO => name.to_string(),
    }
}

fn extract_context(content: &str, package_name: &str) -> String {
    // Find the line containing the package reference
    for line in content.lines() {
        if line.contains(package_name) {
            return line.trim().chars().take(100).collect();
        }
    }
    String::new()
}

fn is_builtin_nodejs_module(name: &str) -> bool {
    const BUILTINS: &[&str] = &[
        "fs", "path", "http", "https", "os", "crypto", "util", "events",
        "stream", "buffer", "child_process", "cluster", "dgram", "dns",
        "domain", "net", "querystring", "readline", "repl", "tls", "tty",
        "url", "v8", "vm", "zlib", "assert", "console", "module", "process",
        "timers", "string_decoder", "punycode", "async_hooks", "inspector",
        "perf_hooks", "worker_threads",
    ];
    BUILTINS.contains(&name)
}

fn is_builtin_python_module(name: &str) -> bool {
    const BUILTINS: &[&str] = &[
        "os", "sys", "re", "json", "time", "datetime", "math", "random",
        "collections", "itertools", "functools", "pathlib", "subprocess",
        "threading", "multiprocessing", "asyncio", "io", "pickle", "csv",
        "xml", "html", "urllib", "http", "email", "socket", "ssl", "hashlib",
        "hmac", "base64", "binascii", "struct", "codecs", "locale", "gettext",
        "logging", "argparse", "configparser", "warnings", "abc", "contextlib",
    ];
    BUILTINS.contains(&name)
}

/// Check if name is a common CSS property
fn is_css_property(name: &str) -> bool {
    const CSS_PROPERTIES: &[&str] = &[
        // Layout
        "display", "position", "top", "right", "bottom", "left", "float", "clear",
        "overflow", "overflow-x", "overflow-y", "z-index", "visibility",
        // Box model
        "width", "height", "max-width", "max-height", "min-width", "min-height",
        "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
        "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
        "border", "border-width", "border-style", "border-color", "border-radius",
        "box-sizing", "box-shadow",
        // Typography
        "font", "font-family", "font-size", "font-weight", "font-style",
        "line-height", "letter-spacing", "word-spacing", "text-align",
        "text-decoration", "text-transform", "white-space", "word-wrap",
        // Colors
        "color", "background", "background-color", "background-image",
        "background-position", "background-size", "background-repeat",
        "opacity", "fill", "stroke", "stroke-width", "stroke-dasharray",
        // Flexbox
        "flex", "flex-direction", "flex-wrap", "flex-grow", "flex-shrink",
        "justify-content", "align-items", "align-self", "align-content",
        // Grid
        "grid", "grid-template", "grid-column", "grid-row", "gap", "row-gap", "column-gap",
        // Animation
        "transition", "transform", "animation", "animation-duration",
        // Others
        "cursor", "pointer-events", "user-select", "outline", "content",
        "data-period", "data-value", "data-type", // Common data attributes
    ];

    CSS_PROPERTIES.contains(&name) || name.starts_with("data-") || name.starts_with("aria-")
}

/// Check if name is a JavaScript/Python reserved keyword or common built-in
fn is_programming_keyword(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        // JavaScript keywords
        "this", "that", "self", "new", "var", "let", "const", "function",
        "return", "if", "else", "for", "while", "do", "switch", "case",
        "break", "continue", "try", "catch", "throw", "typeof", "instanceof",
        "delete", "void", "null", "undefined", "true", "false",
        // Python keywords
        "and", "or", "not", "is", "in", "as", "with", "from", "import",
        "def", "class", "pass", "lambda", "yield", "raise", "assert",
        // Common built-ins that aren't packages
        "string", "number", "boolean", "array", "object", "promise",
        "error", "date", "math", "json", "console", "window", "document",
        "length", "value", "name", "type", "data", "index", "key",
        // Common variable patterns
        "item", "items", "list", "dict", "map", "set", "args", "kwargs",
        "params", "options", "config", "props", "state", "context",
    ];

    KEYWORDS.contains(&name.to_lowercase().as_str())
}

/// Check if name looks like a hash or ID (long hexadecimal string)
fn is_hash_or_id(name: &str) -> bool {
    // Detect long hexadecimal strings (likely hashes, webpack chunk IDs, etc)
    if name.len() >= 16 {
        // More than 90% hexadecimal characters = probably a hash
        let hex_chars = name.chars().filter(|c| c.is_ascii_hexdigit()).count();
        if hex_chars as f32 / name.len() as f32 > 0.9 {
            return true;
        }
    }

    // Pure numeric strings longer than 4 digits (port numbers, IDs, etc)
    if name.len() > 4 && name.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    false
}

/// Check if name contains only non-alphanumeric separators (likely not a package)
fn is_likely_invalid_package_name(name: &str) -> bool {
    // Names with too many hyphens relative to letters (like CSS props)
    let hyphen_count = name.chars().filter(|c| *c == '-').count();
    let letter_count = name.chars().filter(|c| c.is_alphabetic()).count();

    if letter_count > 0 && hyphen_count as f32 / letter_count as f32 > 0.5 {
        return true; // e.g., "a-b-c-d" has too many hyphens
    }

    // Names that are too short and generic
    if name.len() <= 2 && !name.starts_with('@') {
        return true; // "a", "ab", "x", etc.
    }

    false
}

/// Validate NPM package name according to NPM naming rules
/// Reference: https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
fn is_valid_npm_package_name(name: &str) -> bool {
    // NPM package names rules:
    // 1. Length: 1-214 characters
    // 2. Cannot start with . or _
    // 3. Scoped packages: @scope/name (scope and name must be valid)
    // 4. No uppercase letters
    // 5. Only lowercase, hyphens, underscores, dots, and @ for scoped packages
    // 6. Must contain at least one letter (not just numbers)

    if name.is_empty() || name.len() > 214 {
        return false;
    }

    // *** CRITICAL FILTERS: Enhanced validation ***

    // Reject CSS properties (padding-right, stroke-width, etc)
    if is_css_property(name) {
        return false;
    }

    // Reject programming keywords (this, and, or, etc)
    if is_programming_keyword(name) {
        return false;
    }

    // Reject hashes and long IDs (0175b6513d6d8f1e484e)
    if is_hash_or_id(name) {
        return false;
    }

    // Reject names that are structurally invalid (too many hyphens, too short)
    if is_likely_invalid_package_name(name) {
        return false;
    }

    // Reject pure numbers
    if name.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Reject CSS values
    if is_css_value(name) {
        return false;
    }

    // Reject values ending with CSS units
    if has_css_unit_suffix(name) {
        return false;
    }

    // Cannot start with . or _
    if name.starts_with('.') || name.starts_with('_') {
        return false;
    }

    // Check for uppercase (NPM packages must be lowercase)
    if name.chars().any(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Must contain at least one alphabetic character
    if !name.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Handle scoped packages: @scope/name
    if name.starts_with('@') {
        let parts: Vec<&str> = name.splitn(2, '/').collect();
        if parts.len() != 2 {
            return false; // Invalid scoped package format
        }

        let scope = parts[0];
        let package_name = parts[1];

        // Validate scope (must be @something with valid chars)
        if scope.len() < 2 || !scope[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return false;
        }

        // Validate package name part
        if package_name.is_empty() || !package_name.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
        }) {
            return false;
        }

        return true;
    }

    // Regular (non-scoped) package: only lowercase letters, numbers, hyphens, underscores
    // Must NOT contain / (that would be a subpath, not a package name)
    if name.contains('/') {
        return false;
    }

    // Valid characters for non-scoped packages
    name.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
    })
}

/// Check if a string looks like a CSS value
fn is_css_value(value: &str) -> bool {
    // Common CSS value patterns
    let css_patterns = vec![
        // Colors: #fff, #ffffff, rgb(), rgba(), hsl()
        Regex::new(r"^#[0-9a-fA-F]{3,8}$").unwrap(),
        Regex::new(r"^rgba?\(").unwrap(),
        Regex::new(r"^hsla?\(").unwrap(),

        // CSS functions
        Regex::new(r"^(calc|var|url|linear-gradient|radial-gradient)\(").unwrap(),

        // Common CSS keywords (single word)
        Regex::new(r"^(auto|none|inherit|initial|unset|revert|normal|bold|italic|flex|grid|block|inline|absolute|relative|fixed|sticky|hidden|visible)$").unwrap(),
    ];

    for pattern in &css_patterns {
        if pattern.is_match(value) {
            return true;
        }
    }

    false
}

/// Check if string ends with CSS unit suffix
fn has_css_unit_suffix(value: &str) -> bool {
    const CSS_UNITS: &[&str] = &[
        // Length units
        "px", "em", "rem", "pt", "pc", "in", "cm", "mm", "ex", "ch",
        // Viewport units
        "vw", "vh", "vmin", "vmax",
        // Percentage
        "%",
        // Angle units
        "deg", "rad", "grad", "turn",
        // Time units
        "s", "ms",
        // Frequency units
        "hz", "khz",
        // Flex units
        "fr",
    ];

    let lower = value.to_lowercase();

    for unit in CSS_UNITS {
        if lower.ends_with(unit) {
            // Check if there's a number before the unit
            let prefix = &lower[..lower.len() - unit.len()];
            if !prefix.is_empty() {
                // Check if prefix is a number (with optional decimal point)
                if prefix.chars().all(|c| c.is_ascii_digit() || c == '.') {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_unit_suffix_detection() {
        // Should detect CSS units
        assert!(has_css_unit_suffix("130px"));
        assert!(has_css_unit_suffix("42px"));
        assert!(has_css_unit_suffix("99vw"));
        assert!(has_css_unit_suffix("100vw"));
        assert!(has_css_unit_suffix("10px"));
        assert!(has_css_unit_suffix("1.5rem"));
        assert!(has_css_unit_suffix("50%"));
        assert!(has_css_unit_suffix("2em"));

        // Should NOT detect these as CSS units
        assert!(!has_css_unit_suffix("react"));
        assert!(!has_css_unit_suffix("lodash"));
        assert!(!has_css_unit_suffix("express"));
    }

    #[test]
    fn test_pure_numbers_rejected() {
        assert!(!is_valid_npm_package_name("443"));
        assert!(!is_valid_npm_package_name("8080"));
        assert!(!is_valid_npm_package_name("3000"));
    }

    #[test]
    fn test_css_values_rejected() {
        assert!(!is_valid_npm_package_name("130px"));
        assert!(!is_valid_npm_package_name("42px"));
        assert!(!is_valid_npm_package_name("99vw"));
        assert!(!is_valid_npm_package_name("100vw"));
        assert!(!is_valid_npm_package_name("10px"));
    }

    #[test]
    fn test_css_properties_rejected() {
        // Test CSS properties from user's examples
        assert!(!is_valid_npm_package_name("padding-right"));
        assert!(!is_valid_npm_package_name("stroke-width"));
        assert!(!is_valid_npm_package_name("data-period"));
        assert!(!is_valid_npm_package_name("border-radius"));
        assert!(!is_valid_npm_package_name("margin-left"));

        // Verify the is_css_property function works
        assert!(is_css_property("padding-right"));
        assert!(is_css_property("stroke-width"));
        assert!(is_css_property("data-period"));
        assert!(is_css_property("data-value"));
        assert!(is_css_property("aria-label"));
    }

    #[test]
    fn test_programming_keywords_rejected() {
        // Test JavaScript keywords
        assert!(!is_valid_npm_package_name("this"));
        assert!(!is_valid_npm_package_name("function"));
        assert!(!is_valid_npm_package_name("return"));

        // Test Python keywords
        assert!(!is_valid_npm_package_name("and"));
        assert!(!is_valid_npm_package_name("or"));
        assert!(!is_valid_npm_package_name("import"));

        // Verify the is_programming_keyword function works
        assert!(is_programming_keyword("this"));
        assert!(is_programming_keyword("and"));
        assert!(is_programming_keyword("or"));
        assert!(is_programming_keyword("import"));
    }

    #[test]
    fn test_hash_and_id_rejected() {
        // Test long hexadecimal strings (from user's example)
        assert!(!is_valid_npm_package_name("0175b6513d6d8f1e484e"));
        assert!(!is_valid_npm_package_name("ffcfc0b7"));
        assert!(!is_valid_npm_package_name("abcdef1234567890"));

        // Verify the is_hash_or_id function works
        assert!(is_hash_or_id("0175b6513d6d8f1e484e"));
        assert!(is_hash_or_id("abcdef1234567890"));
        assert!(is_hash_or_id("12345")); // Port number

        // Should NOT be detected as hash
        assert!(!is_hash_or_id("react"));
        assert!(!is_hash_or_id("123")); // Too short
    }

    #[test]
    fn test_valid_npm_packages_accepted() {
        assert!(is_valid_npm_package_name("react"));
        assert!(is_valid_npm_package_name("lodash"));
        assert!(is_valid_npm_package_name("express"));
        assert!(is_valid_npm_package_name("axios"));
        assert!(is_valid_npm_package_name("moment"));
    }

    #[test]
    fn test_scoped_packages_accepted() {
        assert!(is_valid_npm_package_name("@babel/core"));
        assert!(is_valid_npm_package_name("@angular/core"));
        assert!(is_valid_npm_package_name("@types/node"));
    }

    #[test]
    fn test_extract_npm_packages_filters_css() {
        let js_content = r#"var x = {width: "130px", paddingRight: "10px"}; var port = 443;"#;
        let packages = extract_npm_packages(js_content, "https://test.com/test.js");
        assert_eq!(packages.len(), 0);
    }

    #[test]
    fn test_extract_npm_packages_filters_false_positives() {
        // Content similar to user's examples
        let js_content = r#"
            var style = {'padding-right': '0px', 'stroke-width': '2px'};
            var config = {'data-period': 30};
            if (this.value && that.name) { return; }
            import something from 'module-0175b6513d6d8f1e484e';
        "#;
        let packages = extract_npm_packages(js_content, "https://test.com/test.js");

        // Should NOT detect: padding-right, stroke-width, data-period, this, 0175b6513d6d8f1e484e
        assert!(!packages.iter().any(|p| p.package_name == "padding-right"));
        assert!(!packages.iter().any(|p| p.package_name == "stroke-width"));
        assert!(!packages.iter().any(|p| p.package_name == "data-period"));
        assert!(!packages.iter().any(|p| p.package_name == "this"));
        assert!(!packages.iter().any(|p| p.package_name.contains("0175b6513d6d8f1e484e")));
    }

    #[test]
    fn test_extract_npm_packages_detects_valid() {
        let js_content = r#"import React from 'react'; const l = require('lodash');"#;
        let packages = extract_npm_packages(js_content, "https://test.com/test.js");
        assert!(packages.iter().any(|p| p.package_name == "react"));
        assert!(packages.iter().any(|p| p.package_name == "lodash"));
    }

    #[test]
    fn test_likely_invalid_package_names() {
        // Too many hyphens
        assert!(is_likely_invalid_package_name("a-b-c-d"));

        // Too short
        assert!(is_likely_invalid_package_name("ab"));
        assert!(is_likely_invalid_package_name("x"));

        // Valid names
        assert!(!is_likely_invalid_package_name("react"));
        assert!(!is_likely_invalid_package_name("lodash"));
        assert!(!is_likely_invalid_package_name("react-dom"));
    }
}
