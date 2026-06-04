use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolHint {
    Tcp,
    Udp,
    Icmp,
    Dns,
    Tls,
    Http,
    Quic,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainSource {
    Dns,
    TlsSni,
    QuicInitialSni,
    HttpHost,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    Domain,
    Url,
    Ip,
    Port,
    Mac,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppIdentity {
    pub uid: u32,
    pub package_name: String,
    pub app_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub id: String,
    pub src: NetworkEndpoint,
    pub dst: NetworkEndpoint,
    pub protocol: ProtocolHint,
    pub app: Option<AppIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub ip_version: IpVersion,
    pub protocol: ProtocolHint,
    pub transport_protocol: ProtocolHint,
    pub src_addr: String,
    pub dst_addr: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_sequence: Option<u32>,
    pub payload_len: usize,
    pub dns_query_name: Option<String>,
    pub tls_server_name: Option<String>,
    pub quic_server_name: Option<String>,
    pub http_host: Option<String>,
    pub http_request_target: Option<String>,
    pub application_protocols: Vec<String>,
    pub quic_destination_connection_id: Option<String>,
    pub dns_candidate: bool,
    pub tls_candidate: bool,
    pub quic_candidate: bool,
    pub quic_initial_candidate: bool,
    pub doh_candidate: bool,
    pub dot_candidate: bool,
    pub http3_candidate: bool,
    pub transport_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_addr: String,
    pub dst_addr: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ProtocolHint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowOwnerQuery {
    pub key: FlowKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowOwnerResolution {
    pub key: FlowKey,
    pub uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowState {
    pub key: FlowKey,
    pub protocol_hint: ProtocolHint,
    pub app: Option<AppIdentity>,
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
    pub dns_candidate: bool,
    pub tls_candidate: bool,
    pub quic_candidate: bool,
    pub quic_initial_candidate: bool,
    pub doh_candidate: bool,
    pub dot_candidate: bool,
    pub http3_candidate: bool,
    pub tls_server_name: Option<String>,
    pub quic_server_name: Option<String>,
    pub http_host: Option<String>,
    pub application_protocols: Vec<String>,
    pub packets: u64,
    pub payload_bytes: u64,
    pub first_seen_unix_ms: u128,
    pub last_seen_unix_ms: u128,
}

impl FlowState {
    pub fn new(key: FlowKey, payload_len: usize) -> Self {
        let now = now_unix_ms();
        let protocol_hint = key.protocol.clone();
        Self {
            key,
            protocol_hint,
            app: None,
            domain: None,
            domain_source: None,
            dns_candidate: false,
            tls_candidate: false,
            quic_candidate: false,
            quic_initial_candidate: false,
            doh_candidate: false,
            dot_candidate: false,
            http3_candidate: false,
            tls_server_name: None,
            quic_server_name: None,
            http_host: None,
            application_protocols: Vec::new(),
            packets: 1,
            payload_bytes: payload_len as u64,
            first_seen_unix_ms: now,
            last_seen_unix_ms: now,
        }
    }

    pub fn update(&mut self, payload_len: usize) {
        self.packets += 1;
        self.payload_bytes += payload_len as u64;
        self.last_seen_unix_ms = now_unix_ms();
    }

    pub fn set_app(&mut self, app: Option<AppIdentity>) {
        self.app = app;
    }

    pub fn set_protocol_hint(&mut self, protocol_hint: ProtocolHint) {
        self.protocol_hint = protocol_hint;
    }

    pub fn set_domain(&mut self, domain: Option<String>) {
        self.domain = domain;
    }

    pub fn set_domain_source(&mut self, domain_source: Option<DomainSource>) {
        self.domain_source = domain_source;
    }

    pub fn set_dns_candidate(&mut self, dns_candidate: bool) {
        self.dns_candidate = dns_candidate;
    }

    pub fn set_tls_candidate(&mut self, tls_candidate: bool) {
        self.tls_candidate = tls_candidate;
    }

    pub fn set_quic_candidate(&mut self, quic_candidate: bool) {
        self.quic_candidate = quic_candidate;
    }

    pub fn set_quic_initial_candidate(&mut self, quic_initial_candidate: bool) {
        self.quic_initial_candidate = quic_initial_candidate;
    }

    pub fn set_doh_candidate(&mut self, doh_candidate: bool) {
        self.doh_candidate = doh_candidate;
    }

    pub fn set_dot_candidate(&mut self, dot_candidate: bool) {
        self.dot_candidate = dot_candidate;
    }

    pub fn set_http3_candidate(&mut self, http3_candidate: bool) {
        self.http3_candidate = http3_candidate;
    }

    pub fn set_tls_server_name(&mut self, server_name: Option<String>) {
        self.tls_server_name = server_name;
    }

    pub fn set_quic_server_name(&mut self, server_name: Option<String>) {
        self.quic_server_name = server_name;
    }

    pub fn set_http_host(&mut self, host: Option<String>) {
        self.http_host = host;
    }

    pub fn set_application_protocols(&mut self, protocols: Vec<String>) {
        self.application_protocols = protocols;
    }
}

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRecord {
    pub kind: ObjectKind,
    pub value: String,
    pub related_flows: usize,
    pub risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    pub kind: ObjectKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectState {
    pub key: ObjectKey,
    pub hits: u64,
    pub bytes: u64,
    pub related_flows: usize,
    pub first_seen_unix_ms: u128,
    pub last_seen_unix_ms: u128,
    pub risk: RiskLevel,
}

impl ObjectState {
    pub fn new(key: ObjectKey, bytes: usize, related_flows: usize) -> Self {
        let now = now_unix_ms();
        Self {
            key,
            hits: 1,
            bytes: bytes as u64,
            related_flows,
            first_seen_unix_ms: now,
            last_seen_unix_ms: now,
            risk: RiskLevel::Info,
        }
    }

    pub fn update(&mut self, bytes: usize, related_flows: usize) {
        self.hits += 1;
        self.bytes += bytes as u64;
        self.related_flows = related_flows;
        self.last_seen_unix_ms = now_unix_ms();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMetricsSnapshot {
    pub app: AppIdentity,
    pub active_flows: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub cpu_percent: f32,
    pub memory_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub title: String,
    pub summary: String,
    pub risk: RiskLevel,
    pub app: Option<AppIdentity>,
}
