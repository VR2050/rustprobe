use serde::{Deserialize, Serialize};

use crate::model::AppIdentity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrafficDispositionMode {
    Forward,
    Capture,
}

impl TrafficDispositionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Capture => "capture",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppSelectionMode {
    Global,
    Single(String),
    Multiple(Vec<String>),
    AllowList(Vec<String>),
    DenyList(Vec<String>),
}

impl AppSelectionMode {
    pub fn matches(&self, app: Option<&AppIdentity>) -> bool {
        match self {
            Self::Global => true,
            Self::Single(package_name) => app
                .map(|app| app.package_name == *package_name)
                .unwrap_or(false),
            Self::Multiple(package_names) | Self::AllowList(package_names) => app
                .map(|app| {
                    package_names
                        .iter()
                        .any(|package| package == &app.package_name)
                })
                .unwrap_or(false),
            Self::DenyList(package_names) => app
                .map(|app| {
                    package_names
                        .iter()
                        .all(|package| package != &app.package_name)
                })
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub selection_mode: AppSelectionMode,
    pub disposition_mode: TrafficDispositionMode,
    pub capture_ipv6: bool,
    pub enable_quic_hints: bool,
    pub emit_object_aggregation: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            selection_mode: AppSelectionMode::Global,
            disposition_mode: TrafficDispositionMode::Forward,
            capture_ipv6: true,
            enable_quic_hints: true,
            emit_object_aggregation: true,
        }
    }
}
