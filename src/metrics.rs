#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::Path;

/// Estrutura unificada de métricas do EnumRust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumRustMetrics {
    // Identificação do scan
    pub scan_id: String,
    pub scan_type: ScanType,
    pub target: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: f64,

    // Métricas de Web Scanning (modo domínio)
    pub web_metrics: Option<WebScanMetrics>,

    // Métricas de Infrastructure Scanning
    pub infrastructure_metrics: Option<InfrastructureMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    WebScan,
    InfrastructureScan,
}

/// Métricas de scanning web (domínios)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScanMetrics {
    // Subdomínios
    pub total_subdomains: usize,
    pub total_unique_ips: usize,
    pub subdomains_list: Vec<SubdomainInfo>,

    // URLs e Endpoints
    pub total_urls_crawled: usize,
    pub total_endpoints_found: usize,
    pub status_codes: HashMap<u16, usize>,

    // Vulnerabilidades
    pub total_vulnerabilities: usize,
    pub vulnerabilities_by_severity: HashMap<String, usize>,
    pub vulnerability_details: Vec<VulnerabilityInfo>,

    // Secrets/Exposures
    pub total_secrets_found: usize,
    pub secrets_by_type: HashMap<String, usize>,
    pub secret_details: Vec<SecretInfo>,

    // Tecnologias detectadas
    pub technologies: Vec<String>,
    pub server_types: HashMap<String, usize>,
}

/// Métricas de scanning de infraestrutura
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureMetrics {
    // Hosts
    pub ip_range_scanned: String,
    pub total_hosts_scanned: usize,
    pub total_hosts_up: usize,
    pub hosts_details: Vec<HostMetrics>,

    // Portas
    pub total_open_ports: usize,
    pub ports_by_service: HashMap<String, usize>,
    pub top_open_ports: Vec<(u16, usize)>,

    // Serviços
    pub services_detected: HashMap<String, usize>,
    pub vulnerable_services: usize,

    // Vulnerabilidades (se vuln_scan foi usado)
    pub vulnerabilities_found: usize,
    pub critical_issues: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub ip_addresses: Vec<String>,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub name: String,
    pub severity: String,
    pub target: String,
    pub description: Option<String>,
    pub found_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    pub secret_type: String,
    pub location: String,
    pub pattern_matched: String,
    pub found_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMetrics {
    pub ip: String,
    pub hostname: Option<String>,
    pub open_ports_count: usize,
    pub services: Vec<ServiceInfo>,
    pub os_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

impl EnumRustMetrics {
    /// Cria nova estrutura de métricas para web scanning
    pub fn new_web_scan(domain: String) -> Self {
        Self {
            scan_id: uuid::Uuid::new_v4().to_string(),
            scan_type: ScanType::WebScan,
            target: domain,
            start_time: Utc::now(),
            end_time: None,
            duration_seconds: 0.0,
            web_metrics: Some(WebScanMetrics {
                total_subdomains: 0,
                total_unique_ips: 0,
                subdomains_list: Vec::new(),
                total_urls_crawled: 0,
                total_endpoints_found: 0,
                status_codes: HashMap::new(),
                total_vulnerabilities: 0,
                vulnerabilities_by_severity: HashMap::new(),
                vulnerability_details: Vec::new(),
                total_secrets_found: 0,
                secrets_by_type: HashMap::new(),
                secret_details: Vec::new(),
                technologies: Vec::new(),
                server_types: HashMap::new(),
            }),
            infrastructure_metrics: None,
        }
    }

    /// Cria nova estrutura de métricas para infrastructure scanning
    pub fn new_infrastructure_scan(ip_range: String) -> Self {
        Self {
            scan_id: uuid::Uuid::new_v4().to_string(),
            scan_type: ScanType::InfrastructureScan,
            target: ip_range.clone(),
            start_time: Utc::now(),
            end_time: None,
            duration_seconds: 0.0,
            web_metrics: None,
            infrastructure_metrics: Some(InfrastructureMetrics {
                ip_range_scanned: ip_range,
                total_hosts_scanned: 0,
                total_hosts_up: 0,
                hosts_details: Vec::new(),
                total_open_ports: 0,
                ports_by_service: HashMap::new(),
                top_open_ports: Vec::new(),
                services_detected: HashMap::new(),
                vulnerable_services: 0,
                vulnerabilities_found: 0,
                critical_issues: 0,
            }),
        }
    }

    /// Finaliza o scan e calcula duração
    pub fn finalize(&mut self) {
        self.end_time = Some(Utc::now());
        if let Some(end) = self.end_time {
            self.duration_seconds = (end - self.start_time).num_milliseconds() as f64 / 1000.0;
        }
    }

    /// Salva métricas em arquivo JSON
    #[allow(dead_code)]
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Retorna resumo textual do scan
    #[allow(dead_code)]
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "Scan ID: {}\nType: {:?}\nTarget: {}\nDuration: {:.2}s\n",
            self.scan_id,
            self.scan_type,
            self.target,
            self.duration_seconds
        );

        match &self.scan_type {
            ScanType::WebScan => {
                if let Some(web) = &self.web_metrics {
                    summary.push_str(&format!(
                        "\nWeb Scan Results:\n\
                         - Subdomains: {}\n\
                         - Unique IPs: {}\n\
                         - URLs Crawled: {}\n\
                         - Endpoints Found: {}\n\
                         - Vulnerabilities: {}\n\
                         - Secrets Found: {}\n",
                        web.total_subdomains,
                        web.total_unique_ips,
                        web.total_urls_crawled,
                        web.total_endpoints_found,
                        web.total_vulnerabilities,
                        web.total_secrets_found
                    ));
                }
            }
            ScanType::InfrastructureScan => {
                if let Some(infra) = &self.infrastructure_metrics {
                    summary.push_str(&format!(
                        "\nInfrastructure Scan Results:\n\
                         - IP Range: {}\n\
                         - Hosts Scanned: {}\n\
                         - Hosts Up: {}\n\
                         - Open Ports: {}\n\
                         - Services Detected: {}\n\
                         - Vulnerabilities: {}\n",
                        infra.ip_range_scanned,
                        infra.total_hosts_scanned,
                        infra.total_hosts_up,
                        infra.total_open_ports,
                        infra.services_detected.len(),
                        infra.vulnerabilities_found
                    ));
                }
            }
        }

        summary
    }
}

// Funções auxiliares para construir métricas durante o scan

impl WebScanMetrics {
    pub fn add_subdomain(&mut self, subdomain: String, ips: Vec<String>) {
        self.total_subdomains += 1;
        self.subdomains_list.push(SubdomainInfo {
            subdomain,
            ip_addresses: ips,
            open_ports: Vec::new(),
        });
    }

    pub fn add_url(&mut self, status_code: u16) {
        self.total_urls_crawled += 1;
        *self.status_codes.entry(status_code).or_insert(0) += 1;
    }

    pub fn add_vulnerability(&mut self, name: String, severity: String, target: String) {
        self.total_vulnerabilities += 1;
        *self.vulnerabilities_by_severity.entry(severity.clone()).or_insert(0) += 1;
        self.vulnerability_details.push(VulnerabilityInfo {
            name,
            severity,
            target,
            description: None,
            found_at: Utc::now(),
        });
    }

    pub fn add_secret(&mut self, secret_type: String, location: String, pattern: String) {
        self.total_secrets_found += 1;
        *self.secrets_by_type.entry(secret_type.clone()).or_insert(0) += 1;
        self.secret_details.push(SecretInfo {
            secret_type,
            location,
            pattern_matched: pattern,
            found_at: Utc::now(),
        });
    }
}

impl InfrastructureMetrics {
    pub fn add_host(&mut self, ip: String, hostname: Option<String>, services: Vec<ServiceInfo>) {
        self.total_hosts_up += 1;
        let open_ports = services.len();
        self.total_open_ports += open_ports;

        for service in &services {
            *self.services_detected.entry(service.service_name.clone()).or_insert(0) += 1;
            *self.ports_by_service.entry(format!("{}:{}", service.port, service.service_name)).or_insert(0) += 1;
        }

        self.hosts_details.push(HostMetrics {
            ip,
            hostname,
            open_ports_count: open_ports,
            services,
            os_fingerprint: None,
        });
    }

    pub fn calculate_top_ports(&mut self) {
        let mut port_counts: HashMap<u16, usize> = HashMap::new();

        for host in &self.hosts_details {
            for service in &host.services {
                *port_counts.entry(service.port).or_insert(0) += 1;
            }
        }

        let mut ports: Vec<(u16, usize)> = port_counts.into_iter().collect();
        ports.sort_by(|a, b| b.1.cmp(&a.1));
        self.top_open_ports = ports.into_iter().take(10).collect();
    }
}

// Estrutura de geolocalização (compatibilidade com módulo geolocation)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: String,
    pub latitude: f64,
    pub longitude: f64,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub organization: Option<String>,
}
