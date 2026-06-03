use serde::{Deserialize, Serialize};

use crate::model::{AlertRecord, AppIdentity, AppMetricsSnapshot, FlowRecord, ObjectRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub source: String,
    pub raw_len: usize,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub flow: FlowRecord,
    pub objects: Vec<ObjectRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEvent {
    pub app: AppIdentity,
    pub flow_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub alert: AlertRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiEvent {
    pub topic: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlEvent {
    Start,
    Stop,
    ReloadConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PipelineEvent {
    Packet(PacketEvent),
    Flow(FlowEvent),
    App(AppEvent),
    Metrics(AppMetricsSnapshot),
    Alert(AlertEvent),
    Ui(UiEvent),
}
