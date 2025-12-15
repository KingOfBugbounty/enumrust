// IP Validator Module
// Valida e limpa arquivos de IPs, removendo IPs inválidos e duplicados
// Também resolve domínios para IPs usando DNS
// Filtra IPs de CDN/Cloud que não pertencem ao domínio alvo

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::collections::HashSet;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;
use colored::*;

// ═══════════════════════════════════════════════════════════════════
// CDN/CLOUD IP RANGES - IPs que NÃO pertencem ao domínio alvo
// ═══════════════════════════════════════════════════════════════════

/// Ranges de IP conhecidos de CDNs e provedores de cloud
/// Esses IPs geralmente são compartilhados e não devem ser escaneados
const CDN_RANGES: &[(&str, &str, &str)] = &[
    // Cloudflare IPv4
    ("173.245.48.0", "173.245.63.255", "Cloudflare"),
    ("103.21.244.0", "103.21.247.255", "Cloudflare"),
    ("103.22.200.0", "103.22.203.255", "Cloudflare"),
    ("103.31.4.0", "103.31.7.255", "Cloudflare"),
    ("141.101.64.0", "141.101.127.255", "Cloudflare"),
    ("108.162.192.0", "108.162.255.255", "Cloudflare"),
    ("190.93.240.0", "190.93.255.255", "Cloudflare"),
    ("188.114.96.0", "188.114.111.255", "Cloudflare"),
    ("197.234.240.0", "197.234.243.255", "Cloudflare"),
    ("198.41.128.0", "198.41.255.255", "Cloudflare"),
    ("162.158.0.0", "162.159.255.255", "Cloudflare"),
    ("104.16.0.0", "104.31.255.255", "Cloudflare"),
    ("104.24.0.0", "104.27.255.255", "Cloudflare"),
    ("172.64.0.0", "172.71.255.255", "Cloudflare"),
    ("131.0.72.0", "131.0.75.255", "Cloudflare"),

    // Akamai (principais ranges)
    ("23.0.0.0", "23.79.255.255", "Akamai"),
    ("104.64.0.0", "104.127.255.255", "Akamai"),
    ("184.24.0.0", "184.31.255.255", "Akamai"),
    ("184.50.0.0", "184.51.255.255", "Akamai"),
    ("2.16.0.0", "2.23.255.255", "Akamai"),

    // Fastly
    ("151.101.0.0", "151.101.255.255", "Fastly"),
    ("199.232.0.0", "199.232.255.255", "Fastly"),

    // AWS CloudFront (principais)
    ("13.32.0.0", "13.35.255.255", "AWS CloudFront"),
    ("13.224.0.0", "13.227.255.255", "AWS CloudFront"),
    ("52.84.0.0", "52.85.255.255", "AWS CloudFront"),
    ("54.182.0.0", "54.182.255.255", "AWS CloudFront"),
    ("54.192.0.0", "54.207.255.255", "AWS CloudFront"),
    ("54.230.0.0", "54.231.255.255", "AWS CloudFront"),
    ("54.239.128.0", "54.239.255.255", "AWS CloudFront"),
    ("99.84.0.0", "99.84.255.255", "AWS CloudFront"),
    ("143.204.0.0", "143.204.255.255", "AWS CloudFront"),
    ("204.246.164.0", "204.246.191.255", "AWS CloudFront"),
    ("205.251.192.0", "205.251.255.255", "AWS CloudFront"),
    ("216.137.32.0", "216.137.63.255", "AWS CloudFront"),

    // Google Cloud CDN
    ("34.96.0.0", "34.127.255.255", "Google Cloud"),
    ("35.186.0.0", "35.199.255.255", "Google Cloud"),
    ("35.200.0.0", "35.247.255.255", "Google Cloud"),

    // Microsoft Azure CDN (principais)
    ("13.107.0.0", "13.107.255.255", "Azure CDN"),
    ("204.79.195.0", "204.79.195.255", "Azure CDN"),

    // Incapsula/Imperva
    ("199.83.128.0", "199.83.135.255", "Incapsula"),
    ("198.143.32.0", "198.143.63.255", "Incapsula"),
    ("149.126.72.0", "149.126.79.255", "Incapsula"),
    ("103.28.248.0", "103.28.251.255", "Incapsula"),
    ("45.64.64.0", "45.64.67.255", "Incapsula"),
    ("107.154.0.0", "107.154.255.255", "Incapsula"),

    // Sucuri
    ("192.88.134.0", "192.88.135.255", "Sucuri"),
    ("185.93.228.0", "185.93.231.255", "Sucuri"),
    ("66.248.200.0", "66.248.207.255", "Sucuri"),

    // StackPath/MaxCDN
    ("151.139.0.0", "151.139.255.255", "StackPath"),
    ("217.22.28.0", "217.22.31.255", "StackPath"),
];

/// Prefixos de hostname que indicam CDN (para verificação reversa)
const CDN_HOSTNAME_PATTERNS: &[&str] = &[
    "cloudflare",
    "cloudfront",
    "akamai",
    "akamaitechnologies",
    "fastly",
    "incap",
    "imperva",
    "sucuri",
    "stackpath",
    "maxcdn",
    "cdn",
    "edgecast",
    "limelight",
    "cachefly",
];

/// Converte string IP para u32 para comparação de ranges
fn ip_to_u32(ip: &str) -> Option<u32> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    Some(u32::from(addr))
}

/// Verifica se um IP está dentro de um range de CDN conhecida
pub fn is_cdn_ip(ip: &str) -> Option<&'static str> {
    let ip_num = match ip_to_u32(ip) {
        Some(n) => n,
        None => return None,
    };

    for (start, end, provider) in CDN_RANGES {
        if let (Some(start_num), Some(end_num)) = (ip_to_u32(start), ip_to_u32(end)) {
            if ip_num >= start_num && ip_num <= end_num {
                return Some(provider);
            }
        }
    }
    None
}

/// Resultado da validação de IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpValidationResult {
    pub ip: String,
    pub is_valid_target: bool,
    pub is_cdn: bool,
    pub cdn_provider: Option<String>,
    pub reverse_dns: Option<String>,
    pub matches_domain: bool,
}

/// Verifica se o hostname reverso pertence ao domínio alvo
fn hostname_matches_domain(hostname: &str, target_domain: &str) -> bool {
    let hostname_lower = hostname.to_lowercase();
    let domain_lower = target_domain.to_lowercase();

    // Remove trailing dot do hostname se existir
    let hostname_clean = hostname_lower.trim_end_matches('.');

    // Verifica se termina com o domínio alvo
    if hostname_clean.ends_with(&domain_lower) {
        return true;
    }

    // Verifica se é exatamente o domínio
    if hostname_clean == domain_lower {
        return true;
    }

    false
}

/// Verifica se o hostname reverso indica CDN
fn hostname_indicates_cdn(hostname: &str) -> bool {
    let hostname_lower = hostname.to_lowercase();
    for pattern in CDN_HOSTNAME_PATTERNS {
        if hostname_lower.contains(pattern) {
            return true;
        }
    }
    false
}

/// Valida um IP verificando se pertence ao domínio alvo
pub async fn validate_ip_for_domain(
    ip: &str,
    target_domain: &str,
) -> IpValidationResult {
    // 1. Verifica se é IP de CDN conhecida
    if let Some(provider) = is_cdn_ip(ip) {
        return IpValidationResult {
            ip: ip.to_string(),
            is_valid_target: false,
            is_cdn: true,
            cdn_provider: Some(provider.to_string()),
            reverse_dns: None,
            matches_domain: false,
        };
    }

    // 2. Faz reverse DNS lookup
    let resolver = match TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ) {
        r => r,
    };

    let ip_addr: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return IpValidationResult {
                ip: ip.to_string(),
                is_valid_target: false,
                is_cdn: false,
                cdn_provider: None,
                reverse_dns: None,
                matches_domain: false,
            };
        }
    };

    // Timeout de 3 segundos para reverse DNS
    let reverse_result = timeout(
        Duration::from_secs(3),
        resolver.reverse_lookup(ip_addr)
    ).await;

    match reverse_result {
        Ok(Ok(lookup)) => {
            let hostnames: Vec<String> = lookup
                .iter()
                .map(|name| name.to_string())
                .collect();

            if let Some(hostname) = hostnames.first() {
                // Verifica se hostname indica CDN
                if hostname_indicates_cdn(hostname) {
                    return IpValidationResult {
                        ip: ip.to_string(),
                        is_valid_target: false,
                        is_cdn: true,
                        cdn_provider: Some("Detected via reverse DNS".to_string()),
                        reverse_dns: Some(hostname.clone()),
                        matches_domain: false,
                    };
                }

                // Verifica se hostname pertence ao domínio alvo
                let matches = hostname_matches_domain(hostname, target_domain);

                return IpValidationResult {
                    ip: ip.to_string(),
                    is_valid_target: matches,
                    is_cdn: false,
                    cdn_provider: None,
                    reverse_dns: Some(hostname.clone()),
                    matches_domain: matches,
                };
            }
        }
        _ => {
            // Sem reverse DNS - considera válido se não é CDN conhecida
            // (muitos servidores não têm PTR configurado)
        }
    }

    // Se não há reverse DNS e não é CDN conhecida, considera válido
    // O usuário pode querer escanear mesmo sem PTR
    IpValidationResult {
        ip: ip.to_string(),
        is_valid_target: true, // Permite por padrão se não for CDN
        is_cdn: false,
        cdn_provider: None,
        reverse_dns: None,
        matches_domain: false,
    }
}

/// Filtra IPs de um arquivo, removendo CDNs e IPs que não pertencem ao domínio
pub async fn filter_ips_for_domain(
    input_file: &Path,
    target_domain: &str,
    strict_mode: bool, // Se true, só aceita IPs com reverse DNS matching
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    use futures::stream::{self, StreamExt};

    if !input_file.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(input_file)?;
    let ips: Vec<String> = content
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if ips.is_empty() {
        return Ok(Vec::new());
    }

    println!("{}", format!("[*] Validando {} IPs para o domínio {}...", ips.len(), target_domain).cyan());

    let mut cdn_count = 0;
    let mut non_matching_count = 0;
    let mut valid_ips = Vec::new();

    // Valida IPs em paralelo (max 50 concurrent)
    let results: Vec<IpValidationResult> = stream::iter(ips)
        .map(|ip| {
            let domain = target_domain.to_string();
            async move {
                validate_ip_for_domain(&ip, &domain).await
            }
        })
        .buffer_unordered(50)
        .collect()
        .await;

    for result in results {
        if result.is_cdn {
            cdn_count += 1;
            println!("{}", format!(
                "    [-] {} removido (CDN: {})",
                result.ip,
                result.cdn_provider.as_deref().unwrap_or("unknown")
            ).yellow());
        } else if strict_mode && !result.matches_domain {
            non_matching_count += 1;
            let reverse = result.reverse_dns.as_deref().unwrap_or("no PTR");
            println!("{}", format!(
                "    [-] {} removido (não pertence ao domínio, PTR: {})",
                result.ip,
                reverse
            ).yellow());
        } else if result.is_valid_target {
            valid_ips.push(result.ip.clone());
            if result.matches_domain {
                println!("{}", format!(
                    "    [+] {} válido (PTR: {})",
                    result.ip,
                    result.reverse_dns.as_deref().unwrap_or("-")
                ).green());
            }
        }
    }

    println!("{}", format!(
        "[+] IPs filtrados: {} válidos, {} CDN removidos, {} não pertencem ao domínio",
        valid_ips.len(),
        cdn_count,
        non_matching_count
    ).green().bold());

    Ok(valid_ips)
}

/// Salva IPs filtrados em arquivo
pub fn save_filtered_ips(ips: &[String], output_file: &Path) -> std::io::Result<()> {
    let content = ips.join("\n") + "\n";
    fs::write(output_file, content)
}

#[allow(dead_code)]
pub fn validate_and_clean_ip_file(file_path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    if !file_path.exists() {
        return Ok(0);
    }

    let content = fs::read_to_string(file_path)?;
    let mut valid_ips: HashSet<String> = HashSet::new();
    let mut invalid_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Pula linhas vazias
        if trimmed.is_empty() {
            continue;
        }

        // Valida se é um IP válido
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => {
                // Filtra IPs privados
                let ip_str = ip.to_string();
                if !is_private_ip(&ip_str) {
                    valid_ips.insert(ip_str);
                }
            }
            Err(_) => {
                // Tenta separar múltiplos IPs concatenados
                if let Some(extracted_ips) = try_extract_ips(trimmed) {
                    for ip in extracted_ips {
                        if !is_private_ip(&ip) {
                            valid_ips.insert(ip);
                        }
                    }
                } else {
                    invalid_count += 1;
                    eprintln!("[!] IP inválido removido: {}", trimmed);
                }
            }
        }
    }

    // Ordena IPs para facilitar leitura
    let mut sorted_ips: Vec<String> = valid_ips.into_iter().collect();
    sorted_ips.sort();

    // Escreve arquivo limpo
    let clean_content = sorted_ips.join("\n") + "\n";
    fs::write(file_path, clean_content)?;

    println!("[+] IPs validados: {} válidos, {} inválidos removidos", sorted_ips.len(), invalid_count);

    Ok(sorted_ips.len())
}

fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.") {
        return true;
    }
    if ip.starts_with("192.168.") {
        return true;
    }
    if ip.starts_with("172.") {
        if let Some(second_octet) = ip.split('.').nth(1) {
            if let Ok(num) = second_octet.parse::<u8>() {
                if (16..=31).contains(&num) {
                    return true;
                }
            }
        }
    }
    if ip.starts_with("127.") {
        return true;
    }
    if ip.starts_with("169.254.") {
        return true;
    }
    if ip == "0.0.0.0" || ip == "255.255.255.255" {
        return true;
    }
    false
}

#[allow(dead_code)]
fn try_extract_ips(text: &str) -> Option<Vec<String>> {
    let mut ips = Vec::new();

    // Regex pattern para encontrar IPs no formato x.x.x.x
    let parts: Vec<&str> = text.split(|c: char| !c.is_numeric() && c != '.').collect();

    for part in parts {
        if part.is_empty() {
            continue;
        }

        // Verifica se tem formato de IP (x.x.x.x)
        let octets: Vec<&str> = part.split('.').collect();
        if octets.len() == 4 {
            let mut valid = true;
            for octet in &octets {
                // u8 parse already validates 0-255 range
                if octet.parse::<u8>().is_err() {
                    valid = false;
                    break;
                }
            }
            if valid
                && part.parse::<IpAddr>().is_ok() {
                    ips.push(part.to_string());
                }
        }
    }

    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn test_try_extract_ips() {
        let result = try_extract_ips("10.145.229.1165.137.108.166");
        assert!(result.is_some());
        let ips = result.unwrap();
        assert!(ips.contains(&"165.137.108.166".to_string()));
    }
}

// ═══════════════════════════════════════════════════════════════════
// DOMAIN TO IP VALIDATION
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ValidatedHost {
    pub subdomain: String,
    pub resolved_ips: Vec<String>,
    pub is_resolvable: bool,
    pub resolution_time_ms: u64,
    pub cname: Option<String>,
}

/// Resolve um domínio para IPs usando trust-dns-resolver
#[allow(dead_code)]
pub async fn resolve_domain_to_ips(domain: &str) -> Result<ValidatedHost, Box<dyn std::error::Error + Send + Sync>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let start = std::time::Instant::now();

    // Timeout de 5 segundos para resolução DNS
    let lookup_result = timeout(
        Duration::from_secs(5),
        resolver.lookup_ip(domain)
    ).await;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    match lookup_result {
        Ok(Ok(lookup)) => {
            let ips: Vec<String> = lookup
                .iter()
                .filter(|ip| !is_private_ip(&ip.to_string()))
                .map(|ip| ip.to_string())
                .collect();

            Ok(ValidatedHost {
                subdomain: domain.to_string(),
                resolved_ips: ips.clone(),
                is_resolvable: !ips.is_empty(),
                resolution_time_ms: elapsed_ms,
                cname: None,
            })
        }
        Ok(Err(_e)) => {
            // Falha na resolução DNS
            Ok(ValidatedHost {
                subdomain: domain.to_string(),
                resolved_ips: Vec::new(),
                is_resolvable: false,
                resolution_time_ms: elapsed_ms,
                cname: None,
            })
        }
        Err(_) => {
            // Timeout
            Ok(ValidatedHost {
                subdomain: domain.to_string(),
                resolved_ips: Vec::new(),
                is_resolvable: false,
                resolution_time_ms: 5000,
                cname: None,
            })
        }
    }
}

/// Valida múltiplos domínios em paralelo
#[allow(dead_code)]
pub async fn validate_domains_batch(
    domains: Vec<String>,
    max_concurrent: usize,
) -> Vec<ValidatedHost> {
    use futures::stream::{self, StreamExt};

    stream::iter(domains)
        .map(|domain| async move {
            match resolve_domain_to_ips(&domain).await {
                Ok(validated) => validated,
                Err(_) => ValidatedHost {
                    subdomain: domain,
                    resolved_ips: Vec::new(),
                    is_resolvable: false,
                    resolution_time_ms: 0,
                    cname: None,
                },
            }
        })
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await
}

/// Salva hosts validados em arquivo JSON
#[allow(dead_code)]
pub fn save_validated_hosts(
    hosts: &[ValidatedHost],
    output_path: &Path,
) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(hosts)?;
    fs::write(output_path, json)?;
    Ok(())
}
