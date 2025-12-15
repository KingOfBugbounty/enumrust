#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

/// Estrutura de evento de progresso
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub timestamp: DateTime<Utc>,
    pub scan_id: String,
    pub target: String,
    pub event_type: EventType,
    pub message: String,
    pub progress_percentage: f32,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventType {
    ScanStarted,
    ToolStarted { tool_name: String },
    ToolProgress { tool_name: String, current: usize, total: usize },
    ToolCompleted { tool_name: String },
    ToolFailed { tool_name: String, error: String },
    DataFound { data_type: String, count: usize },
    VulnerabilityFound { severity: String },
    ScanCompleted,
    ScanFailed { error: String },
}

/// Gerenciador de progresso
#[derive(Clone)]
pub struct ProgressTracker {
    scan_id: String,
    target: String,
    output_dir: PathBuf,
    events: Arc<Mutex<Vec<ProgressEvent>>>,
}

impl ProgressTracker {
    pub fn new(scan_id: String, target: String, output_dir: PathBuf) -> Self {
        let tracker = Self {
            scan_id,
            target,
            output_dir: output_dir.clone(),
            events: Arc::new(Mutex::new(Vec::new())),
        };

        // Criar diretório se não existir
        fs::create_dir_all(&output_dir).ok();

        tracker
    }

    /// Adiciona um evento e salva no arquivo
    pub fn add_event(&self, event_type: EventType, message: String, progress: f32, details: Option<serde_json::Value>) {
        let event = ProgressEvent {
            timestamp: Utc::now(),
            scan_id: self.scan_id.clone(),
            target: self.target.clone(),
            event_type,
            message,
            progress_percentage: progress,
            details,
        };

        // Adicionar ao vetor de eventos
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }

        // Salvar no arquivo
        self.save_to_file(&event);
    }

    /// Salva evento no arquivo JSON
    fn save_to_file(&self, event: &ProgressEvent) {
        let progress_file = self.output_dir.join("progress.jsonl");

        if let Ok(json) = serde_json::to_string(event) {
            if let Ok(mut file) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&progress_file)
            {
                use std::io::Write;
                writeln!(file, "{}", json).ok();
            }
        }

        // Também salvar um arquivo de status atual
        self.save_current_status();
    }

    /// Salva o status atual consolidado
    fn save_current_status(&self) {
        let status_file = self.output_dir.join("current_status.json");

        if let Ok(events) = self.events.lock() {
            let last_event = events.last();
            if let Some(event) = last_event {
                let status = serde_json::json!({
                    "scan_id": self.scan_id,
                    "target": self.target,
                    "last_update": event.timestamp,
                    "progress": event.progress_percentage,
                    "current_message": event.message,
                    "event_type": event.event_type,
                    "total_events": events.len(),
                });

                if let Ok(json) = serde_json::to_string_pretty(&status) {
                    fs::write(&status_file, json).ok();
                }
            }
        }
    }

    /// Métodos auxiliares para eventos comuns
    pub fn scan_started(&self) {
        self.add_event(
            EventType::ScanStarted,
            format!("Iniciando scan de {}", self.target),
            0.0,
            None,
        );
    }

    pub fn tool_started(&self, tool_name: &str) {
        self.add_event(
            EventType::ToolStarted { tool_name: tool_name.to_string() },
            format!("🔧 Iniciando ferramenta: {}", tool_name),
            0.0,
            None,
        );
    }

    #[allow(dead_code)]
    pub fn tool_progress(&self, tool_name: &str, current: usize, total: usize, progress: f32) {
        self.add_event(
            EventType::ToolProgress {
                tool_name: tool_name.to_string(),
                current,
                total
            },
            format!("⏳ {} - {}/{} ({:.1}%)", tool_name, current, total, progress),
            progress,
            Some(serde_json::json!({
                "current": current,
                "total": total,
            })),
        );
    }

    pub fn tool_completed(&self, tool_name: &str, progress: f32) {
        self.add_event(
            EventType::ToolCompleted { tool_name: tool_name.to_string() },
            format!("✅ {} concluído", tool_name),
            progress,
            None,
        );
    }

    pub fn tool_failed(&self, tool_name: &str, error: &str, progress: f32) {
        self.add_event(
            EventType::ToolFailed {
                tool_name: tool_name.to_string(),
                error: error.to_string(),
            },
            format!("❌ {} falhou: {}", tool_name, error),
            progress,
            None,
        );
    }

    pub fn data_found(&self, data_type: &str, count: usize, progress: f32) {
        self.add_event(
            EventType::DataFound {
                data_type: data_type.to_string(),
                count,
            },
            format!("📊 Encontrado: {} {} ", count, data_type),
            progress,
            Some(serde_json::json!({
                "data_type": data_type,
                "count": count,
            })),
        );
    }

    #[allow(dead_code)]
    pub fn vulnerability_found(&self, severity: &str, name: &str, progress: f32) {
        self.add_event(
            EventType::VulnerabilityFound {
                severity: severity.to_string(),
            },
            format!("🚨 Vulnerabilidade [{}]: {}", severity, name),
            progress,
            Some(serde_json::json!({
                "severity": severity,
                "name": name,
            })),
        );
    }

    pub fn scan_completed(&self) {
        self.add_event(
            EventType::ScanCompleted,
            format!("✅ Scan de {} concluído com sucesso!", self.target),
            100.0,
            None,
        );
    }

    pub fn scan_failed(&self, error: &str) {
        self.add_event(
            EventType::ScanFailed {
                error: error.to_string(),
            },
            format!("❌ Scan falhou: {}", error),
            0.0,
            None,
        );
    }

    /// Retorna todos os eventos
    #[allow(dead_code)]
    pub fn get_events(&self) -> Vec<ProgressEvent> {
        if let Ok(events) = self.events.lock() {
            events.clone()
        } else {
            Vec::new()
        }
    }

    /// Lê eventos de um arquivo de progresso
    pub fn read_events_from_file(progress_file: &Path) -> Vec<ProgressEvent> {
        let mut events = Vec::new();

        if let Ok(content) = fs::read_to_string(progress_file) {
            for line in content.lines() {
                if let Ok(event) = serde_json::from_str::<ProgressEvent>(line) {
                    events.push(event);
                }
            }
        }

        events
    }
}
