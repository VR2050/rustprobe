use rustprobe_core::{
    AppIdentity, FlowKey, FlowState, ObjectKey, ObjectKind, ObjectState, ParsedPacket, now_unix_ms,
};
use rustprobe_parse::parse_tls_client_hello_server_name;
use std::collections::{HashMap, HashSet};

const DEFAULT_FLOW_IDLE_TIMEOUT_MS: u128 = 60_000;
const TLS_BUFFER_LIMIT_BYTES: usize = 4096;

#[derive(Debug)]
pub struct FlowActor {
    flows_seen: usize,
    table: HashMap<FlowKey, FlowState>,
    objects: HashMap<ObjectKey, ObjectState>,
    tls_buffers: HashMap<FlowKey, Vec<u8>>,
    idle_timeout_ms: u128,
}

#[derive(Debug, Clone)]
pub struct FlowIngestResult {
    pub flow: FlowState,
    pub active_flows: usize,
    pub expired_flows: usize,
    pub top_objects: Vec<ObjectState>,
    pub touched_objects: Vec<ObjectState>,
}

impl FlowActor {
    pub fn new(idle_timeout_ms: u128) -> Self {
        Self {
            flows_seen: 0,
            table: HashMap::new(),
            objects: HashMap::new(),
            tls_buffers: HashMap::new(),
            idle_timeout_ms,
        }
    }

    pub fn ingest_packet(&mut self, packet: &ParsedPacket) -> Option<FlowIngestResult> {
        let src_port = packet.src_port?;
        let dst_port = packet.dst_port?;

        let key = FlowKey {
            src_addr: packet.src_addr.clone(),
            dst_addr: packet.dst_addr.clone(),
            src_port,
            dst_port,
            protocol: packet.protocol.clone(),
        };

        self.flows_seen += 1;

        let mut flow = self
            .table
            .entry(key.clone())
            .and_modify(|entry| {
                entry.update(packet.payload_len);
                merge_packet_metadata(entry, packet);
            })
            .or_insert_with(|| {
                let mut flow = FlowState::new(key, packet.payload_len);
                merge_packet_metadata(&mut flow, packet);
                flow
            })
            .clone();

        let derived_tls_server_name = if flow.tls_server_name.is_none() {
            self.maybe_extract_tls_server_name(&flow.key, packet)
        } else {
            None
        };

        if let Some(server_name) = derived_tls_server_name.as_ref() {
            flow.set_tls_server_name(Some(server_name.clone()));
            flow.set_domain(Some(server_name.clone()));
            let _ = self.table.get_mut(&flow.key).map(|entry| {
                entry.set_tls_server_name(Some(server_name.clone()));
                entry.set_domain(Some(server_name.clone()));
            });
        }

        let touched_objects = self.update_objects(packet, derived_tls_server_name.as_deref());
        let expired_flows = self.expire_idle_flows();
        let top_objects = self.top_objects(4);

        Some(FlowIngestResult {
            flow,
            active_flows: self.active_flows(),
            expired_flows,
            top_objects,
            touched_objects,
        })
    }

    pub fn flows_seen(&self) -> usize {
        self.flows_seen
    }

    pub fn active_flows(&self) -> usize {
        self.table.len()
    }

    pub fn snapshot(&self) -> Vec<FlowState> {
        self.table.values().cloned().collect()
    }

    pub fn object_snapshot(&self) -> Vec<ObjectState> {
        self.objects.values().cloned().collect()
    }

    pub fn set_flow_app(&mut self, key: &FlowKey, app: Option<AppIdentity>) -> bool {
        match self.table.get_mut(key) {
            Some(flow) => {
                flow.set_app(app);
                true
            }
            None => false,
        }
    }

    pub fn expire_idle_flows(&mut self) -> usize {
        let now = now_unix_ms();
        let before = self.table.len();
        self.table
            .retain(|_, flow| now.saturating_sub(flow.last_seen_unix_ms) <= self.idle_timeout_ms);
        self.tls_buffers
            .retain(|key, _| self.table.contains_key(key));
        before.saturating_sub(self.table.len())
    }

    fn update_objects(
        &mut self,
        packet: &ParsedPacket,
        derived_tls_server_name: Option<&str>,
    ) -> Vec<ObjectState> {
        let active_flows = self.active_flows();
        let mut touched = Vec::new();
        let mut seen_keys = HashSet::new();
        let ip_key = ObjectKey {
            kind: ObjectKind::Ip,
            value: packet.dst_addr.clone(),
        };
        touched.push(self.upsert_object(ip_key, packet.payload_len, active_flows));

        if let Some(dst_port) = packet.dst_port {
            let port_key = ObjectKey {
                kind: ObjectKind::Port,
                value: dst_port.to_string(),
            };
            touched.push(self.upsert_object(port_key, packet.payload_len, active_flows));
        }

        if let Some(domain) = packet.dns_query_name.as_ref() {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(domain.clone(), packet.payload_len, active_flows),
            );
        }

        if let Some(server_name) = packet.tls_server_name.as_ref() {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(server_name.clone(), packet.payload_len, active_flows),
            );
        }

        if let Some(server_name) = derived_tls_server_name {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(
                    server_name.to_string(),
                    packet.payload_len,
                    active_flows,
                ),
            );
        }

        touched
    }

    fn update_domain_object(
        &mut self,
        domain: String,
        bytes: usize,
        active_flows: usize,
    ) -> ObjectState {
        let domain_key = ObjectKey {
            kind: ObjectKind::Domain,
            value: domain,
        };
        self.upsert_object(domain_key, bytes, active_flows)
    }

    fn upsert_object(&mut self, key: ObjectKey, bytes: usize, active_flows: usize) -> ObjectState {
        let entry = self
            .objects
            .entry(key.clone())
            .and_modify(|entry| entry.update(bytes, active_flows))
            .or_insert_with(|| ObjectState::new(key, bytes, active_flows));
        entry.clone()
    }

    fn push_unique_object(
        objects: &mut Vec<ObjectState>,
        seen_keys: &mut HashSet<ObjectKey>,
        object: ObjectState,
    ) {
        if seen_keys.insert(object.key.clone()) {
            objects.push(object);
        }
    }

    fn maybe_extract_tls_server_name(
        &mut self,
        key: &FlowKey,
        packet: &ParsedPacket,
    ) -> Option<String> {
        if !matches!(
            packet.protocol,
            rustprobe_core::ProtocolHint::Tcp | rustprobe_core::ProtocolHint::Tls
        ) {
            return None;
        }

        let is_tls_candidate = key.src_port == 443 || key.dst_port == 443;
        if !is_tls_candidate || packet.transport_payload.is_empty() {
            return None;
        }

        let buffer = self.tls_buffers.entry(key.clone()).or_default();
        let remaining = TLS_BUFFER_LIMIT_BYTES.saturating_sub(buffer.len());
        if remaining == 0 {
            return parse_tls_client_hello_server_name(buffer);
        }

        let append_len = remaining.min(packet.transport_payload.len());
        buffer.extend_from_slice(&packet.transport_payload[..append_len]);

        let server_name = parse_tls_client_hello_server_name(buffer);
        if server_name.is_some() {
            self.tls_buffers.remove(key);
        }
        server_name
    }

    fn top_objects(&self, limit: usize) -> Vec<ObjectState> {
        let mut values: Vec<_> = self.objects.values().cloned().collect();
        values.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| right.bytes.cmp(&left.bytes))
        });
        values.truncate(limit);
        values
    }
}

impl Default for FlowActor {
    fn default() -> Self {
        Self::new(DEFAULT_FLOW_IDLE_TIMEOUT_MS)
    }
}

fn merge_packet_metadata(flow: &mut FlowState, packet: &ParsedPacket) {
    if let Some(domain) = packet.dns_query_name.as_ref() {
        flow.set_domain(Some(domain.clone()));
    }
    if let Some(server_name) = packet.tls_server_name.as_ref() {
        flow.set_domain(Some(server_name.clone()));
        flow.set_tls_server_name(Some(server_name.clone()));
    }
}
