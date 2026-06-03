use rustprobe_core::{
    now_unix_ms, FlowKey, FlowState, ObjectKey, ObjectKind, ObjectState, ParsedPacket,
};
use std::collections::HashMap;

const DEFAULT_FLOW_IDLE_TIMEOUT_MS: u128 = 60_000;

#[derive(Debug)]
pub struct FlowActor {
    flows_seen: usize,
    table: HashMap<FlowKey, FlowState>,
    objects: HashMap<ObjectKey, ObjectState>,
    idle_timeout_ms: u128,
}

#[derive(Debug, Clone)]
pub struct FlowIngestResult {
    pub flow: FlowState,
    pub active_flows: usize,
    pub expired_flows: usize,
    pub top_objects: Vec<ObjectState>,
}

impl FlowActor {
    pub fn new(idle_timeout_ms: u128) -> Self {
        Self {
            flows_seen: 0,
            table: HashMap::new(),
            objects: HashMap::new(),
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

        let flow = self
            .table
            .entry(key.clone())
            .and_modify(|entry| entry.update(packet.payload_len))
            .or_insert_with(|| FlowState::new(key, packet.payload_len))
            .clone();

        self.update_objects(packet);
        let expired_flows = self.expire_idle_flows();
        let top_objects = self.top_objects(4);

        Some(FlowIngestResult {
            flow,
            active_flows: self.active_flows(),
            expired_flows,
            top_objects,
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

    pub fn expire_idle_flows(&mut self) -> usize {
        let now = now_unix_ms();
        let before = self.table.len();
        self.table
            .retain(|_, flow| now.saturating_sub(flow.last_seen_unix_ms) <= self.idle_timeout_ms);
        before.saturating_sub(self.table.len())
    }

    fn update_objects(&mut self, packet: &ParsedPacket) {
        let active_flows = self.active_flows();
        let ip_key = ObjectKey {
            kind: ObjectKind::Ip,
            value: packet.dst_addr.clone(),
        };
        self.objects
            .entry(ip_key.clone())
            .and_modify(|entry| entry.update(packet.payload_len, active_flows))
            .or_insert_with(|| ObjectState::new(ip_key, packet.payload_len, active_flows));

        if let Some(dst_port) = packet.dst_port {
            let port_key = ObjectKey {
                kind: ObjectKind::Port,
                value: dst_port.to_string(),
            };
            self.objects
                .entry(port_key.clone())
                .and_modify(|entry| entry.update(packet.payload_len, active_flows))
                .or_insert_with(|| ObjectState::new(port_key, packet.payload_len, active_flows));
        }
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
