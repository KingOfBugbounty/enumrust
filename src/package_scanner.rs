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
    pub source_url: String,           // URL do arquivo JS onde foi encontrado
    pub reference_url: Option<String>, // URL da página HTML que referencia o JS
    pub found_in_context: String,      // Linha de código onde o pacote foi detectado
    pub line_number: Option<usize>,    // Número da linha no arquivo JS
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
/// reference_url: URL da página HTML que referencia o arquivo JS (opcional)
pub fn extract_npm_packages(js_content: &str, source_url: &str, reference_url: Option<&str>) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // Patterns for npm packages - balanced between avoiding false positives and catching real imports
    // Multiple patterns to catch different JS formats (minified, bundled, source)
    let patterns = vec![
        // require() calls - flexible format for minified JS
        Regex::new(r#"require\s*\(\s*["']([a-z@][a-z0-9\-_./]*)["']\s*\)"#).unwrap(),
        // ES6 import with from keyword (most common)
        Regex::new(r#"from\s*["']([a-z@][a-z0-9\-_./]*)["']"#).unwrap(),
        // Dynamic imports - import("package")
        Regex::new(r#"import\s*\(\s*["']([a-z@][a-z0-9\-_./]*)["']\s*\)"#).unwrap(),
        // Webpack/bundler style: __webpack_require__("package")
        Regex::new(r#"__webpack_require__\s*\(\s*["']([a-z@][a-z0-9\-_./]*)["']\s*\)"#).unwrap(),
        // AMD define dependencies: define(["dep1", "dep2"], ...)
        Regex::new(r#"define\s*\(\s*\[[^\]]*["']([a-z@][a-z0-9\-_./]*)["']"#).unwrap(),
        // package.json dependencies - must have version pattern
        Regex::new(r#""([a-z@][a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)?)"\s*:\s*"[~^]?[\d]"#).unwrap(),
        // Vite/Rollup resolved imports: "node_modules/package" pattern
        Regex::new(r#"node_modules/([a-z@][a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)?)"#).unwrap(),
        // ESM imports in bundled code: e("package")
        Regex::new(r#"\be\s*\(\s*["']([a-z@][a-z0-9\-_]+)["']\s*\)"#).unwrap(),
        // Minified require patterns: n("package"), r("package"), etc
        Regex::new(r#"[=,;:\(]\s*[a-z]\s*\(\s*["']([a-z@][a-z0-9\-_]+)["']\s*\)"#).unwrap(),
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

                // Skip URLs and file paths
                if is_url_or_path(&cleaned_name) {
                    continue;
                }

                // Skip common false positive patterns
                if is_common_false_positive(&cleaned_name) {
                    continue;
                }

                let (context, line_number) = extract_context_with_line(js_content, &package_name);

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::NPM,
                    source_url: source_url.to_string(),
                    reference_url: reference_url.map(|s| s.to_string()),
                    found_in_context: context,
                    line_number,
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

/// Extract Python/pip package imports from embedded Python code or config files
/// reference_url: URL da página HTML que referencia o arquivo (opcional)
pub fn extract_pip_packages(js_content: &str, source_url: &str, reference_url: Option<&str>) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // STRICT patterns for Python imports - only match real Python code patterns
    // These patterns look for Python-specific syntax that won't match JS
    let patterns = vec![
        // pip install commands (strongest indicator)
        Regex::new(r#"pip(?:3)?\s+install\s+(?:-[a-zA-Z]+\s+)*([a-z][a-z0-9\-_]+)"#).unwrap(),
        // pip install with requirements syntax
        Regex::new(r#"pip(?:3)?\s+install\s+["']([a-z][a-z0-9\-_]+)(?:[=<>!]+[\d.]+)?["']"#).unwrap(),
        // requirements.txt format - must have version specifier
        Regex::new(r#"^([a-z][a-z0-9\-_]+)\s*(?:==|>=|<=|~=|!=)[\d.]+"#).unwrap(),
        // Python from X import Y (must have Python-specific patterns)
        Regex::new(r#"#.*?from\s+([a-z][a-z0-9_]+)\s+import\s+[A-Z]"#).unwrap(),
        // pyproject.toml / setup.py dependencies
        Regex::new(r#"["']([a-z][a-z0-9\-_]+)["']\s*(?:>=|<=|==|~=)[\d.]+"#).unwrap(),
        // Conda/pip in shell commands
        Regex::new(r#"(?:conda|pip)\s+install\s+(?:-[yqc]\s+)*([a-z][a-z0-9\-_]+)"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(package_match) = cap.get(1) {
                let package_name = package_match.as_str().to_string();
                let cleaned_name = clean_package_name(&package_name, PackageType::PIP);

                if cleaned_name.is_empty() || !seen.insert(cleaned_name.clone()) {
                    continue;
                }

                // Skip Python built-ins
                if is_builtin_python_module(&cleaned_name) {
                    continue;
                }

                // Skip common JS/generic keywords
                if is_programming_keyword(&cleaned_name) {
                    continue;
                }

                // Skip CSS properties
                if is_css_property(&cleaned_name) || is_css_value(&cleaned_name) {
                    continue;
                }

                // Skip hashes and IDs
                if is_hash_or_id(&cleaned_name) {
                    continue;
                }

                // Skip names that look invalid for pip
                if is_likely_invalid_pip_name(&cleaned_name) {
                    continue;
                }

                // Skip common false positives
                if is_common_false_positive(&cleaned_name) {
                    continue;
                }

                // Must contain at least 2 letters (avoid single letters)
                let letter_count = cleaned_name.chars().filter(|c| c.is_alphabetic()).count();
                if letter_count < 2 {
                    continue;
                }

                let (context, line_number) = extract_context_with_line(js_content, &package_name);

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::PIP,
                    source_url: source_url.to_string(),
                    reference_url: reference_url.map(|s| s.to_string()),
                    found_in_context: context,
                    line_number,
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

/// Extract Go package imports from embedded Go code or config files
/// reference_url: URL da página HTML que referencia o arquivo (opcional)
pub fn extract_go_packages(js_content: &str, source_url: &str, reference_url: Option<&str>) -> Vec<PackageDependency> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // STRICT patterns for Go imports - must match Go-specific syntax
    // Go packages typically have domain/org/repo format (e.g., github.com/user/repo)
    let patterns = vec![
        // Go import statements - must have domain-like pattern
        Regex::new(r#"import\s+["']((github\.com|gitlab\.com|bitbucket\.org|golang\.org|gopkg\.in)/[a-z0-9\-_.]+/[a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)*)["']"#).unwrap(),
        // Go import with alias
        Regex::new(r#"import\s+\w+\s+["']((github\.com|gitlab\.com|bitbucket\.org|golang\.org|gopkg\.in)/[a-z0-9\-_.]+/[a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)*)["']"#).unwrap(),
        // Go mod require - must have version
        Regex::new(r#"require\s+((github\.com|gitlab\.com|bitbucket\.org|golang\.org|gopkg\.in)/[a-z0-9\-_.]+/[a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)*)\s+v[\d]+\.[\d]+\.[\d]+"#).unwrap(),
        // go.mod require block entries
        Regex::new(r#"^\s*((github\.com|gitlab\.com|bitbucket\.org|golang\.org|gopkg\.in)/[a-z0-9\-_.]+/[a-z0-9\-_.]+(?:/[a-z0-9\-_.]+)*)\s+v[\d]+\.[\d]+\.[\d]+"#).unwrap(),
        // go get commands
        Regex::new(r#"go\s+get\s+(?:-[a-z]+\s+)*((github\.com|gitlab\.com|bitbucket\.org|golang\.org|gopkg\.in)/[a-z0-9\-_.]+/[a-z0-9\-_.]+)"#).unwrap(),
        // Internal company packages (must start with valid domain)
        Regex::new(r#"import\s+["']([a-z0-9]+\.[a-z]+/[a-z0-9\-_.]+/[a-z0-9\-_.]+)["']"#).unwrap(),
    ];

    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(package_match) = cap.get(1) {
                let package_name = package_match.as_str().to_string();
                let cleaned_name = clean_package_name(&package_name, PackageType::GO);

                if cleaned_name.is_empty() || !seen.insert(cleaned_name.clone()) {
                    continue;
                }

                // Validate Go package name - must look like a valid Go import path
                if !is_valid_go_package_name(&cleaned_name) {
                    continue;
                }

                // Skip common false positives
                if is_common_false_positive(&cleaned_name) {
                    continue;
                }

                let (context, line_number) = extract_context_with_line(js_content, &package_name);

                packages.push(PackageDependency {
                    package_name: cleaned_name.clone(),
                    package_type: PackageType::GO,
                    source_url: source_url.to_string(),
                    reference_url: reference_url.map(|s| s.to_string()),
                    found_in_context: context,
                    line_number,
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
/// reference_url: URL da página HTML que referencia o arquivo JS (opcional)
pub fn extract_all_packages(js_content: &str, source_url: &str, reference_url: Option<&str>) -> Vec<PackageDependency> {
    let mut all_packages = Vec::new();

    all_packages.extend(extract_npm_packages(js_content, source_url, reference_url));
    all_packages.extend(extract_pip_packages(js_content, source_url, reference_url));
    all_packages.extend(extract_go_packages(js_content, source_url, reference_url));

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

/// Information about a JS file and where it was referenced
#[derive(Debug, Clone)]
pub struct JsFileInfo {
    pub js_url: String,
    pub reference_url: Option<String>, // URL da página HTML que referencia o JS
}

/// Scan JS files for packages and validate them
/// js_files_info: Lista de arquivos JS com informações de referência
pub async fn scan_js_for_packages(
    js_files: &[String],
    client: &Client,
    max_concurrent: usize,
) -> Vec<PackageDependency> {
    // Convert to JsFileInfo with None reference for backward compatibility
    let files_info: Vec<JsFileInfo> = js_files.iter().map(|url| JsFileInfo {
        js_url: url.clone(),
        reference_url: None,
    }).collect();

    scan_js_for_packages_with_refs(&files_info, client, max_concurrent).await
}

/// Scan JS files for packages with reference URLs
pub async fn scan_js_for_packages_with_refs(
    js_files_info: &[JsFileInfo],
    client: &Client,
    max_concurrent: usize,
) -> Vec<PackageDependency> {
    use futures::stream::{self, StreamExt};

    println!("{}", "[*] Scanning JS files for package dependencies...".cyan());

    // Extract packages from all JS files
    let mut all_packages = Vec::new();
    let total_files = js_files_info.len();
    let mut scanned = 0;
    let mut found_in_files = 0;

    for file_info in js_files_info {
        scanned += 1;

        // Fetch JS content
        match client
            .get(&file_info.js_url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(response) => {
                if let Ok(js_content) = response.text().await {
                    let packages = extract_all_packages(
                        &js_content,
                        &file_info.js_url,
                        file_info.reference_url.as_deref()
                    );
                    if !packages.is_empty() {
                        found_in_files += 1;
                        println!(
                            "{}",
                            format!("  [+] [{}/{}] Found {} packages in: {}",
                                scanned, total_files, packages.len(), file_info.js_url
                            ).green()
                        );
                    } else if scanned <= 10 || scanned % 20 == 0 {
                        // Show progress for first 10 files and every 20th file
                        println!(
                            "{}",
                            format!("  [-] [{}/{}] No packages in: {}",
                                scanned, total_files, file_info.js_url
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
                            scanned, total_files, file_info.js_url, e
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

/// Save only dependency confusion findings with detailed reference information
pub fn save_dependency_confusion_findings(
    packages: &[PackageDependency],
    output_path: &Path,
) -> std::io::Result<()> {
    let confusion_packages: Vec<&PackageDependency> = packages
        .iter()
        .filter(|p| p.potential_confusion)
        .collect();

    let mut file = File::create(output_path)?;

    writeln!(file, "╔════════════════════════════════════════════════════════════════════╗")?;
    writeln!(file, "║          DEPENDENCY CONFUSION VULNERABILITIES REPORT              ║")?;
    writeln!(file, "╚════════════════════════════════════════════════════════════════════╝")?;
    writeln!(file)?;
    writeln!(file, "Summary:")?;
    writeln!(file, "  Total packages analyzed: {}", packages.len())?;
    writeln!(file, "  Potential vulnerabilities: {}", confusion_packages.len())?;
    writeln!(file)?;
    writeln!(file, "────────────────────────────────────────────────────────────────────")?;
    writeln!(file)?;

    for (idx, package) in confusion_packages.iter().enumerate() {
        writeln!(file, "┌─ Finding #{} ─────────────────────────────────────────────────────", idx + 1)?;
        writeln!(file, "│")?;
        writeln!(file, "│  Package:     {} ({})", package.package_name, package.package_type)?;
        writeln!(file, "│  Status:      NOT FOUND IN PUBLIC REGISTRY")?;
        writeln!(file, "│")?;
        writeln!(file, "│  JS File:     {}", package.source_url)?;

        // Show line number if available
        if let Some(line) = package.line_number {
            writeln!(file, "│  Line:        {}", line)?;
        }

        // Show reference URL if available (HTML page that loaded this JS)
        if let Some(ref ref_url) = package.reference_url {
            writeln!(file, "│  Referenced:  {}", ref_url)?;
        }

        writeln!(file, "│")?;
        writeln!(file, "│  Context:")?;
        // Truncate context if too long for display
        let context = if package.found_in_context.len() > 120 {
            format!("{}...", &package.found_in_context[..120])
        } else {
            package.found_in_context.clone()
        };
        writeln!(file, "│    {}", context)?;

        if let Some(ref url) = package.registry_url {
            writeln!(file, "│")?;
            writeln!(file, "│  Verified at: {}", url)?;
        }

        writeln!(file, "│")?;
        writeln!(file, "└──────────────────────────────────────────────────────────────────")?;
        writeln!(file)?;
    }

    if !confusion_packages.is_empty() {
        writeln!(file, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
        writeln!(file, "NEXT STEPS:")?;
        writeln!(file, "  1. Verify if these packages are internal/private packages")?;
        writeln!(file, "  2. If internal, check if the package name is available on public registry")?;
        writeln!(file, "  3. Consider registering placeholder packages to prevent hijacking")?;
        writeln!(file, "  4. Implement registry scoping/namespacing for internal packages")?;
        writeln!(file, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
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

/// Extract context (line content and line number) where package was found
fn extract_context_with_line(content: &str, package_name: &str) -> (String, Option<usize>) {
    // Find the line containing the package reference
    for (idx, line) in content.lines().enumerate() {
        if line.contains(package_name) {
            let context = line.trim().chars().take(150).collect();
            return (context, Some(idx + 1)); // Line numbers are 1-indexed
        }
    }
    (String::new(), None)
}

fn is_builtin_nodejs_module(name: &str) -> bool {
    const BUILTINS: &[&str] = &[
        // Core modules
        "fs", "path", "http", "https", "os", "crypto", "util", "events",
        "stream", "buffer", "child_process", "cluster", "dgram", "dns",
        "domain", "net", "querystring", "readline", "repl", "tls", "tty",
        "url", "v8", "vm", "zlib", "assert", "console", "module", "process",
        "timers", "string_decoder", "punycode", "async_hooks", "inspector",
        "perf_hooks", "worker_threads", "constants", "sys", "wasi",
        // Node prefixed modules
        "node:fs", "node:path", "node:http", "node:https", "node:os",
        "node:crypto", "node:util", "node:events", "node:stream", "node:buffer",
        "node:child_process", "node:cluster", "node:dgram", "node:dns",
        "node:net", "node:querystring", "node:readline", "node:tls", "node:url",
        "node:v8", "node:vm", "node:zlib", "node:assert", "node:console",
        "node:module", "node:process", "node:timers", "node:worker_threads",
        // fs submodules
        "fs/promises", "node:fs/promises",
        // Stream submodules
        "stream/promises", "stream/consumers", "stream/web",
        // Other common built-ins
        "diagnostics_channel", "trace_events", "node:test",
    ];

    // Check exact match
    if BUILTINS.contains(&name) {
        return true;
    }

    // Check if starts with node: prefix
    if name.starts_with("node:") {
        return true;
    }

    false
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
    // Detect hexadecimal strings (likely hashes, webpack chunk IDs, etc)

    // Short hashes (8+ chars) must be 100% hex
    if name.len() >= 8 && name.len() < 16 {
        if name.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    // Longer hashes (16+ chars) can have 90%+ hex
    if name.len() >= 16 {
        let hex_chars = name.chars().filter(|c| c.is_ascii_hexdigit()).count();
        if hex_chars as f32 / name.len() as f32 > 0.9 {
            return true;
        }
    }

    // Pure numeric strings longer than 4 digits (port numbers, IDs, etc)
    if name.len() > 4 && name.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // Detect patterns like "module-hash" where hash is 8+ hex chars
    if let Some(last_segment) = name.rsplit('-').next() {
        if last_segment.len() >= 8 && last_segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
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

/// Check if name looks like a URL or file path (common false positive)
fn is_url_or_path(name: &str) -> bool {
    // URLs
    if name.starts_with("http://") || name.starts_with("https://") || name.starts_with("//") {
        return true;
    }

    // File extensions that indicate it's a path, not a package
    let file_extensions = [".js", ".ts", ".jsx", ".tsx", ".css", ".scss", ".json", ".html", ".svg", ".png", ".jpg", ".gif", ".woff", ".ttf"];
    if file_extensions.iter().any(|ext| name.ends_with(ext)) {
        return true;
    }

    // Looks like a file path with directory separators (not npm scoped)
    if !name.starts_with('@') && name.matches('/').count() > 1 {
        return true;
    }

    // Windows-style paths
    if name.contains('\\') {
        return true;
    }

    // Data URLs
    if name.starts_with("data:") {
        return true;
    }

    false
}

/// Check for common false positive patterns
fn is_common_false_positive(name: &str) -> bool {
    const FALSE_POSITIVES: &[&str] = &[
        // Generic/test names
        "test", "tests", "example", "examples", "demo", "sample", "mock", "stub",
        "foo", "bar", "baz", "qux", "dummy", "fake", "temp", "tmp", "spec",
        // Build artifacts / chunks
        "chunk", "vendor", "bundle", "main", "app", "index", "runtime", "common",
        "shared", "core", "lib", "libs", "dist", "build", "output", "polyfill",
        // Asset names
        "styles", "style", "images", "image", "fonts", "font", "assets", "static",
        "icons", "icon", "media", "public", "resources",
        // Common variables that get caught
        "undefined", "null", "true", "false", "default", "module", "exports",
        "require", "define", "global", "self", "this", "super", "prototype",
        // HTML/DOM related
        "document", "window", "navigator", "location", "history", "screen",
        "element", "node", "text", "html", "body", "head", "script", "link",
        // Single-letter or very short (common in minified code)
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
        "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        // Numbers as strings
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        // Common web/dev terms
        "api", "url", "uri", "src", "href", "cdn", "env", "dev", "prod", "staging",
        "config", "settings", "options", "params", "args", "data", "info",
        // Webpack/bundler artifacts (internal references, not package names)
        "webpackchunk", "__webpack", "turbopack",
        // Event/action names
        "click", "change", "submit", "load", "error", "success", "pending",
        "init", "start", "stop", "open", "close", "show", "hide", "toggle",
    ];

    let lower = name.to_lowercase();

    // Exact match
    if FALSE_POSITIVES.contains(&lower.as_str()) {
        return true;
    }

    // Prefixes that indicate internal/test code
    if lower.starts_with("__") || lower.starts_with("_") {
        return true;
    }

    // Looks like a hash/chunk ID (common in bundled code)
    if name.len() >= 8 && name.chars().filter(|c| c.is_ascii_hexdigit()).count() == name.len() {
        return true;
    }

    // Numbered chunks (e.g., "123", "chunk-456")
    if name.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return true;
    }

    // Very short names (1-2 chars) are likely minified variable names
    if name.len() <= 2 && !name.starts_with('@') {
        return true;
    }

    // Names with only vowels or consonants (likely not real packages)
    let has_vowel = name.chars().any(|c| "aeiou".contains(c.to_ascii_lowercase()));
    let has_consonant = name.chars().any(|c| c.is_ascii_alphabetic() && !"aeiou".contains(c.to_ascii_lowercase()));
    if name.len() >= 3 && name.chars().all(|c| c.is_ascii_alphabetic()) && (!has_vowel || !has_consonant) {
        return true;
    }

    false
}

/// Check if name is likely an invalid pip package name
fn is_likely_invalid_pip_name(name: &str) -> bool {
    // PyPI package names must:
    // - Start with a letter or number
    // - Contain only letters, numbers, dots, underscores, hyphens
    // - Be at least 2 characters

    if name.len() < 2 {
        return true;
    }

    // Must start with letter or number
    if !name.chars().next().unwrap().is_alphanumeric() {
        return true;
    }

    // Check for invalid characters
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return true;
    }

    // Common false positives for pip
    const PIP_FALSE_POSITIVES: &[&str] = &[
        "import", "from", "as", "with", "def", "class", "return", "if", "else",
        "elif", "for", "while", "try", "except", "finally", "raise", "assert",
        "lambda", "yield", "global", "nonlocal", "pass", "break", "continue",
        "and", "or", "not", "in", "is", "none", "true", "false",
    ];

    if PIP_FALSE_POSITIVES.contains(&name.to_lowercase().as_str()) {
        return true;
    }

    false
}

/// Validate Go package name - must look like a valid Go import path
fn is_valid_go_package_name(name: &str) -> bool {
    // Go packages should:
    // 1. Start with a domain (contain at least one dot before first slash)
    // 2. Have at least 2 path segments (domain/owner/repo)
    // 3. Not contain spaces or special characters

    let parts: Vec<&str> = name.split('/').collect();

    // Must have at least 2 parts (domain/package or domain/org/package)
    if parts.len() < 2 {
        return false;
    }

    // First part should look like a domain
    let domain = parts[0];
    if !domain.contains('.') {
        return false;
    }

    // Domain should have valid TLD
    let valid_domains = ["github.com", "gitlab.com", "bitbucket.org", "golang.org", "gopkg.in", "google.golang.org"];
    let is_known_domain = valid_domains.iter().any(|&d| domain.eq_ignore_ascii_case(d));

    // Or it should at least look like a domain (word.tld)
    let looks_like_domain = domain.split('.').count() >= 2 &&
        domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-');

    if !is_known_domain && !looks_like_domain {
        return false;
    }

    // All parts should be valid
    for part in &parts[1..] {
        if part.is_empty() {
            return false;
        }
        if !part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
            return false;
        }
    }

    true
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
        let packages = extract_npm_packages(js_content, "https://test.com/test.js", None);
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
        let packages = extract_npm_packages(js_content, "https://test.com/test.js", None);

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
        let packages = extract_npm_packages(js_content, "https://test.com/test.js", None);
        assert!(packages.iter().any(|p| p.package_name == "react"));
        assert!(packages.iter().any(|p| p.package_name == "lodash"));
    }

    #[test]
    fn test_extract_npm_packages_with_reference_url() {
        let js_content = r#"import axios from 'axios';"#;
        let packages = extract_npm_packages(
            js_content,
            "https://example.com/js/app.js",
            Some("https://example.com/index.html")
        );
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_name, "axios");
        assert_eq!(packages[0].reference_url, Some("https://example.com/index.html".to_string()));
        assert!(packages[0].line_number.is_some());
    }

    #[test]
    fn test_common_false_positives() {
        // Test the is_common_false_positive function
        assert!(is_common_false_positive("test"));
        assert!(is_common_false_positive("example"));
        assert!(is_common_false_positive("__webpack"));
        assert!(is_common_false_positive("chunk"));
        assert!(is_common_false_positive("abcdef12")); // Hash-like

        // Should NOT be false positives
        assert!(!is_common_false_positive("axios"));
        assert!(!is_common_false_positive("react"));
        assert!(!is_common_false_positive("express"));
    }

    #[test]
    fn test_url_or_path_detection() {
        // Should detect URLs and paths
        assert!(is_url_or_path("https://example.com/script.js"));
        assert!(is_url_or_path("http://example.com/lib.js"));
        assert!(is_url_or_path("//cdn.example.com/lib.js"));
        assert!(is_url_or_path("./module.js"));
        assert!(is_url_or_path("data:text/javascript,alert(1)"));

        // Should NOT detect as URL/path
        assert!(!is_url_or_path("lodash"));
        assert!(!is_url_or_path("@babel/core"));
        assert!(!is_url_or_path("react-dom"));
    }

    #[test]
    fn test_go_package_validation() {
        // Valid Go packages
        assert!(is_valid_go_package_name("github.com/user/repo"));
        assert!(is_valid_go_package_name("gitlab.com/org/project"));
        assert!(is_valid_go_package_name("golang.org/x/tools"));

        // Invalid Go packages
        assert!(!is_valid_go_package_name("react")); // No domain
        assert!(!is_valid_go_package_name("lodash")); // No domain
        assert!(!is_valid_go_package_name("user/repo")); // No TLD
    }

    #[test]
    fn test_pip_package_validation() {
        // Invalid pip packages
        assert!(is_likely_invalid_pip_name("a")); // Too short
        assert!(is_likely_invalid_pip_name("import")); // Keyword
        assert!(is_likely_invalid_pip_name("from")); // Keyword

        // Valid pip packages (function returns false for valid)
        assert!(!is_likely_invalid_pip_name("requests"));
        assert!(!is_likely_invalid_pip_name("django"));
        assert!(!is_likely_invalid_pip_name("flask"));
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

    #[test]
    fn test_extract_multiple_packages() {
        // Test that multiple packages are detected in the same JS file
        let js_content = r#"
            import React from 'react';
            import { useState } from 'react';
            import axios from 'axios';
            import lodash from 'lodash';
            import moment from 'moment';
            const express = require('express');
            const bodyParser = require('body-parser');
        "#;
        let packages = extract_npm_packages(js_content, "https://test.com/app.js", None);

        // Should detect all unique packages (react only once due to dedup)
        assert!(packages.iter().any(|p| p.package_name == "react"), "Should detect react");
        assert!(packages.iter().any(|p| p.package_name == "axios"), "Should detect axios");
        assert!(packages.iter().any(|p| p.package_name == "lodash"), "Should detect lodash");
        assert!(packages.iter().any(|p| p.package_name == "moment"), "Should detect moment");
        assert!(packages.iter().any(|p| p.package_name == "express"), "Should detect express");
        assert!(packages.iter().any(|p| p.package_name == "body-parser"), "Should detect body-parser");

        // Should have at least 6 unique packages
        assert!(packages.len() >= 6, "Should detect at least 6 packages, got {}", packages.len());
    }

    #[test]
    fn test_extract_packages_minified_js() {
        // Test minified JS patterns
        let js_content = r#"from"react";from"axios";from"lodash";require("express");require("moment")"#;
        let packages = extract_npm_packages(js_content, "https://test.com/bundle.min.js", None);

        assert!(packages.iter().any(|p| p.package_name == "react"), "Should detect react in minified");
        assert!(packages.iter().any(|p| p.package_name == "axios"), "Should detect axios in minified");
        assert!(packages.iter().any(|p| p.package_name == "lodash"), "Should detect lodash in minified");
        assert!(packages.iter().any(|p| p.package_name == "express"), "Should detect express in minified");
        assert!(packages.iter().any(|p| p.package_name == "moment"), "Should detect moment in minified");
    }

    #[test]
    fn test_extract_scoped_packages() {
        let js_content = r#"
            import { render } from '@testing-library/react';
            import styled from '@emotion/styled';
            import { Button } from '@mui/material';
            const core = require('@babel/core');
        "#;
        let packages = extract_npm_packages(js_content, "https://test.com/app.js", None);

        assert!(packages.iter().any(|p| p.package_name == "@testing-library/react"), "Should detect @testing-library/react");
        assert!(packages.iter().any(|p| p.package_name == "@emotion/styled"), "Should detect @emotion/styled");
        assert!(packages.iter().any(|p| p.package_name == "@mui/material"), "Should detect @mui/material");
        assert!(packages.iter().any(|p| p.package_name == "@babel/core"), "Should detect @babel/core");
    }
}
