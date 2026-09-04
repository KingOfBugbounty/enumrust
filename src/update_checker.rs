// update_checker.rs - Auto-update checker for EnumRust
// Checks GitHub releases for new versions and auto-updates via git pull + cargo build

use colored::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const GITHUB_API_URL: &str =
    "https://api.github.com/repos/tools-ofjaaah/enumrust/releases/latest";
const CACHE_DURATION_SECS: u64 = 86400; // 24 hours
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize)]
struct UpdateCache {
    last_check: u64,
    latest_version: String,
}

/// GitHub release API response (only fields we need)
#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
}

/// Get cache file path (~/.enumrust_update_cache.json)
fn cache_path() -> PathBuf {
    dirs_or_home().join(".enumrust_update_cache.json")
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read cached version if still valid (< 24h old)
fn read_cache() -> Option<String> {
    let data = std::fs::read_to_string(cache_path()).ok()?;
    let cache: UpdateCache = serde_json::from_str(&data).ok()?;
    if now_secs().saturating_sub(cache.last_check) < CACHE_DURATION_SECS {
        Some(cache.latest_version)
    } else {
        None
    }
}

/// Write version to cache
fn write_cache(version: &str) {
    let cache = UpdateCache {
        last_check: now_secs(),
        latest_version: version.to_string(),
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(cache_path(), json);
    }
}

/// Fetch latest version from GitHub API
async fn fetch_latest_version() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("enumrust-updater")
        .build()
        .ok()?;

    let resp = client.get(GITHUB_API_URL).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let release: GitHubRelease = resp.json().await.ok()?;
    let version = release.tag_name.trim_start_matches('v').to_string();
    Some(version)
}

/// Compare semver: returns true if remote > local
fn is_newer(remote: &str, local: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.')
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };
    let r = parse(remote);
    let l = parse(local);
    for i in 0..3 {
        let rv = r.get(i).copied().unwrap_or(0);
        let lv = l.get(i).copied().unwrap_or(0);
        if rv > lv {
            return true;
        }
        if rv < lv {
            return false;
        }
    }
    false
}

/// Detect the repo directory (looks for .git from executable path or env var)
fn find_repo_dir() -> Option<PathBuf> {
    // 1. Check environment variable
    if let Ok(dir) = std::env::var("ENUMRUST_REPO_DIR") {
        let p = PathBuf::from(&dir);
        if p.join(".git").exists() {
            return Some(p);
        }
    }

    // 2. Walk up from executable location
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d.join(".git").exists() {
                return Some(d);
            }
            dir = d.parent().map(Path::to_path_buf);
        }
    }

    // 3. Check current working directory
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join(".git").exists() {
            return Some(cwd);
        }
    }

    // 4. Common install location
    let common = PathBuf::from("/root/PENTEST/enumrust");
    if common.join(".git").exists() {
        return Some(common);
    }

    None
}

/// Perform the git pull + cargo build update
async fn perform_update(repo_dir: &Path) -> Result<(), String> {
    println!(
        "{}",
        "  [*] Pulling latest changes from GitHub...".yellow()
    );

    let pull = tokio::process::Command::new("git")
        .args(["pull", "origin", "main"])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| format!("git pull failed: {}", e))?;

    if !pull.status.success() {
        let stderr = String::from_utf8_lossy(&pull.stderr);
        return Err(format!("git pull failed: {}", stderr));
    }

    println!(
        "{}",
        "  [*] Building new version (cargo build --release)..."
            .yellow()
    );

    let build = tokio::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "--bin",
            "enumrust",
            "--bin",
            "regen_report",
        ])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| format!("cargo build failed: {}", e))?;

    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr);
        return Err(format!("cargo build failed: {}", stderr));
    }

    // Copy binary to /usr/local/bin if that's where the current binary lives
    if let Ok(exe) = std::env::current_exe() {
        if exe.starts_with("/usr/local/bin") {
            let new_bin = repo_dir.join("target/release/enumrust");
            if new_bin.exists() {
                let _ = std::fs::copy(&new_bin, "/usr/local/bin/enumrust");
            }
        }
    }

    Ok(())
}

/// Check for updates (uses cache, silent on failure)
pub async fn check_and_update() {
    // Try cache first
    let latest = if let Some(cached) = read_cache() {
        cached
    } else {
        match fetch_latest_version().await {
            Some(v) => {
                write_cache(&v);
                v
            }
            None => return, // Network error, silently continue
        }
    };

    if !is_newer(&latest, CURRENT_VERSION) {
        return; // Up to date
    }

    show_update_banner(&latest);
    do_update(&latest).await;
}

/// Force check (bypasses cache), used with --check-update
pub async fn check_and_update_force() {
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        format!("  [*] Current version: v{}", CURRENT_VERSION)
            .white()
            .bold()
    );
    println!(
        "{}",
        "  [*] Checking GitHub for latest release...".white()
    );

    match fetch_latest_version().await {
        Some(latest) => {
            write_cache(&latest);
            if is_newer(&latest, CURRENT_VERSION) {
                show_update_banner(&latest);
                do_update(&latest).await;
            } else {
                println!(
                    "{}",
                    format!("  [✓] You are running the latest version (v{})", CURRENT_VERSION)
                        .green()
                        .bold()
                );
                println!(
                    "{}",
                    "═══════════════════════════════════════════════════════════════"
                        .cyan()
                        .bold()
                );
            }
        }
        None => {
            println!(
                "{}",
                "  [✗] Could not reach GitHub API. Check your internet connection."
                    .red()
            );
            println!(
                "{}",
                "═══════════════════════════════════════════════════════════════"
                    .cyan()
                    .bold()
            );
        }
    }
}

fn show_update_banner(latest: &str) {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .green()
            .bold()
    );
    println!(
        "{}",
        "║                        UPDATE AVAILABLE / ATUALIZAÇÃO                        ║"
            .green()
            .bold()
    );
    println!(
        "{}",
        "╠══════════════════════════════════════════════════════════════════════════════╣"
            .green()
            .bold()
    );
    println!(
        "{}",
        format!(
            "║  Current / Atual: v{:<20} Latest / Nova: v{:<20}║",
            CURRENT_VERSION, latest
        )
        .yellow()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .green()
            .bold()
    );
}

async fn do_update(latest: &str) {
    match find_repo_dir() {
        Some(repo_dir) => {
            println!(
                "{}",
                format!("  [*] Repo found: {}", repo_dir.display()).cyan()
            );
            match perform_update(&repo_dir).await {
                Ok(()) => {
                    println!();
                    println!(
                        "{}",
                        "╔══════════════════════════════════════════════════════════════════════════════╗"
                            .green()
                            .bold()
                    );
                    println!(
                        "{}",
                        format!(
                            "║  [✓] Updated to v{}! Please re-run enumrust.                              ║",
                            latest
                        )
                        .green()
                        .bold()
                    );
                    println!(
                        "{}",
                        "╚══════════════════════════════════════════════════════════════════════════════╝"
                            .green()
                            .bold()
                    );
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("  [!] Auto-update failed: {}", e).red()
                    );
                    eprintln!(
                        "{}",
                        "  [!] You can update manually: cd /root/PENTEST/enumrust && git pull && cargo build --release"
                            .yellow()
                    );
                    println!();
                }
            }
        }
        None => {
            eprintln!(
                "{}",
                "  [!] Could not find EnumRust repo directory for auto-update."
                    .yellow()
            );
            eprintln!(
                "{}",
                "  [!] Set ENUMRUST_REPO_DIR env var or update manually."
                    .yellow()
            );
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("2.4.0", "2.3.0"));
        assert!(is_newer("2.3.1", "2.3.0"));
        assert!(is_newer("3.0.0", "2.9.9"));
        assert!(!is_newer("2.3.0", "2.3.0"));
        assert!(!is_newer("2.2.0", "2.3.0"));
        assert!(!is_newer("1.0.0", "2.3.0"));
    }
}
