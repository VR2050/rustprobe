use rustprobe_core::{
    AppIdentity, DomainSource, FlowKey, FlowState, ObjectKey, ObjectKind, ObjectState,
    ParsedPacket, now_unix_ms,
};
use rustprobe_parse::{
    QuicCryptoFragment, extract_quic_initial_crypto_fragments, parse_dns_query_name_over_tcp,
    parse_http_request_metadata, parse_tls_client_hello_server_name,
    parse_tls_client_hello_server_name_from_handshake,
};
use std::collections::{BTreeMap, HashMap, HashSet};

const DEFAULT_FLOW_IDLE_TIMEOUT_MS: u128 = 60_000;
const TCP_BUFFER_LIMIT_BYTES: usize = 16 * 1024;
const QUIC_BUFFER_LIMIT_BYTES: usize = 16 * 1024;

#[derive(Debug, Default)]
struct TcpReassemblyBuffer {
    fragments: BTreeMap<u32, Vec<u8>>,
}

#[derive(Debug, Default)]
struct QuicCryptoReassemblyBuffer {
    destination_connection_id: Option<String>,
    fragments: BTreeMap<usize, Vec<u8>>,
}

#[derive(Debug, Default)]
struct TcpDerivedMetadata {
    dns_query_name: Option<String>,
    tls_server_name: Option<String>,
    http_host: Option<String>,
    doh_candidate: bool,
}

#[derive(Debug)]
pub struct FlowActor {
    flows_seen: usize,
    table: HashMap<FlowKey, FlowState>,
    objects: HashMap<ObjectKey, ObjectState>,
    tcp_buffers: HashMap<FlowKey, TcpReassemblyBuffer>,
    quic_buffers: HashMap<FlowKey, QuicCryptoReassemblyBuffer>,
    idle_timeout_ms: u128,
}

#[derive(Debug, Clone)]
pub struct FlowIngestResult {
    pub flow: FlowState,
    pub active_flows: usize,
    pub touched_objects: Vec<ObjectState>,
}

impl FlowActor {
    pub fn new(idle_timeout_ms: u128) -> Self {
        Self {
            flows_seen: 0,
            table: HashMap::new(),
            objects: HashMap::new(),
            tcp_buffers: HashMap::new(),
            quic_buffers: HashMap::new(),
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
            protocol: packet.transport_protocol.clone(),
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

        let derived_tcp_metadata = self.maybe_extract_tcp_metadata(&flow.key, packet);
        let derived_quic_server_name = if flow.quic_server_name.is_none() {
            self.maybe_extract_quic_server_name(&flow.key, packet)
        } else {
            None
        };

        if let Some(server_name) = derived_tcp_metadata
            .as_ref()
            .and_then(|metadata| metadata.tls_server_name.as_ref())
        {
            flow.set_protocol_hint(rustprobe_core::ProtocolHint::Tls);
            flow.set_tls_server_name(Some(server_name.clone()));
            prefer_domain(&mut flow, server_name.clone(), DomainSource::TlsSni);
            let _ = self.table.get_mut(&flow.key).map(|entry| {
                entry.set_protocol_hint(rustprobe_core::ProtocolHint::Tls);
                entry.set_tls_server_name(Some(server_name.clone()));
                prefer_domain(entry, server_name.clone(), DomainSource::TlsSni);
            });
        }

        if let Some(domain) = derived_tcp_metadata
            .as_ref()
            .and_then(|metadata| metadata.dns_query_name.as_ref())
        {
            flow.set_protocol_hint(rustprobe_core::ProtocolHint::Dns);
            prefer_domain(&mut flow, domain.clone(), DomainSource::Dns);
            let _ = self.table.get_mut(&flow.key).map(|entry| {
                entry.set_protocol_hint(rustprobe_core::ProtocolHint::Dns);
                prefer_domain(entry, domain.clone(), DomainSource::Dns);
            });
        }

        if let Some(host) = derived_tcp_metadata
            .as_ref()
            .and_then(|metadata| metadata.http_host.as_ref())
        {
            flow.set_protocol_hint(rustprobe_core::ProtocolHint::Http);
            flow.set_http_host(Some(host.clone()));
            prefer_domain(&mut flow, host.clone(), DomainSource::HttpHost);
            let _ = self.table.get_mut(&flow.key).map(|entry| {
                entry.set_protocol_hint(rustprobe_core::ProtocolHint::Http);
                entry.set_http_host(Some(host.clone()));
                prefer_domain(entry, host.clone(), DomainSource::HttpHost);
            });
        }

        if derived_tcp_metadata
            .as_ref()
            .map(|metadata| metadata.doh_candidate)
            .unwrap_or(false)
        {
            flow.set_doh_candidate(true);
            let _ = self
                .table
                .get_mut(&flow.key)
                .map(|entry| entry.set_doh_candidate(true));
        }

        if let Some(server_name) = derived_quic_server_name.as_ref() {
            flow.set_protocol_hint(rustprobe_core::ProtocolHint::Quic);
            flow.set_quic_server_name(Some(server_name.clone()));
            prefer_domain(&mut flow, server_name.clone(), DomainSource::QuicInitialSni);
            let _ = self.table.get_mut(&flow.key).map(|entry| {
                entry.set_protocol_hint(rustprobe_core::ProtocolHint::Quic);
                entry.set_quic_server_name(Some(server_name.clone()));
                prefer_domain(entry, server_name.clone(), DomainSource::QuicInitialSni);
            });
        }

        let touched_objects = self.update_objects(
            packet,
            derived_tcp_metadata
                .as_ref()
                .and_then(|metadata| metadata.tls_server_name.as_deref()),
            derived_tcp_metadata
                .as_ref()
                .and_then(|metadata| metadata.dns_query_name.as_deref()),
            derived_tcp_metadata
                .as_ref()
                .and_then(|metadata| metadata.http_host.as_deref()),
            derived_quic_server_name.as_deref(),
        );
        Some(FlowIngestResult {
            flow,
            active_flows: self.active_flows(),
            touched_objects,
        })
    }

    pub fn flows_seen(&self) -> usize {
        self.flows_seen
    }

    pub fn active_flows(&self) -> usize {
        self.table.len()
    }

    pub fn has_flow(&self, key: &FlowKey) -> bool {
        self.table.contains_key(key)
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
        self.tcp_buffers
            .retain(|key, _| self.table.contains_key(key));
        self.quic_buffers
            .retain(|key, _| self.table.contains_key(key));
        before.saturating_sub(self.table.len())
    }

    fn update_objects(
        &mut self,
        packet: &ParsedPacket,
        derived_tls_server_name: Option<&str>,
        derived_dns_query_name: Option<&str>,
        derived_http_host: Option<&str>,
        derived_quic_server_name: Option<&str>,
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

        if let Some(server_name) = packet.quic_server_name.as_ref() {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(server_name.clone(), packet.payload_len, active_flows),
            );
        }

        if let Some(host) = packet.http_host.as_ref() {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(host.clone(), packet.payload_len, active_flows),
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

        if let Some(domain) = derived_dns_query_name {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(domain.to_string(), packet.payload_len, active_flows),
            );
        }

        if let Some(host) = derived_http_host {
            Self::push_unique_object(
                &mut touched,
                &mut seen_keys,
                self.update_domain_object(host.to_string(), packet.payload_len, active_flows),
            );
        }

        if let Some(server_name) = derived_quic_server_name {
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
            value: normalize_domain(domain),
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

    fn maybe_extract_tcp_metadata(
        &mut self,
        key: &FlowKey,
        packet: &ParsedPacket,
    ) -> Option<TcpDerivedMetadata> {
        if !matches!(
            packet.protocol,
            rustprobe_core::ProtocolHint::Tcp
                | rustprobe_core::ProtocolHint::Tls
                | rustprobe_core::ProtocolHint::Dns
                | rustprobe_core::ProtocolHint::Http
        ) {
            return None;
        }

        if packet.transport_payload.is_empty() {
            return None;
        }

        let buffer = self.tcp_buffers.entry(key.clone()).or_default();
        append_tcp_payload(buffer, packet);
        let prefix = tcp_contiguous_prefix(buffer, TCP_BUFFER_LIMIT_BYTES)?;
        let metadata = TcpDerivedMetadata {
            dns_query_name: parse_dns_query_name_over_tcp(&prefix),
            tls_server_name: parse_tls_client_hello_server_name(&prefix),
            http_host: parse_http_request_metadata(&prefix).map(|metadata| metadata.host),
            doh_candidate: parse_http_request_metadata(&prefix)
                .map(|metadata| metadata.is_doh)
                .unwrap_or(false),
        };

        if metadata.dns_query_name.is_some()
            || metadata.tls_server_name.is_some()
            || metadata.http_host.is_some()
        {
            self.tcp_buffers.remove(key);
        }
        Some(metadata)
    }

    fn maybe_extract_quic_server_name(
        &mut self,
        key: &FlowKey,
        packet: &ParsedPacket,
    ) -> Option<String> {
        if !matches!(packet.protocol, rustprobe_core::ProtocolHint::Quic) {
            return None;
        }

        if !packet.quic_initial_candidate || packet.transport_payload.is_empty() {
            return None;
        }

        let fragments = extract_quic_initial_crypto_fragments(&packet.transport_payload)?;
        let buffer = self.quic_buffers.entry(key.clone()).or_default();
        append_quic_crypto_fragments(
            buffer,
            packet.quic_destination_connection_id.as_deref(),
            &fragments,
        );
        let handshake_prefix = quic_crypto_contiguous_prefix(buffer)?;
        let server_name = parse_tls_client_hello_server_name_from_handshake(&handshake_prefix);
        if server_name.is_some() {
            self.quic_buffers.remove(key);
        }
        server_name
    }

    pub fn top_objects(&self, limit: usize) -> Vec<ObjectState> {
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
    flow.set_protocol_hint(prefer_protocol_hint(
        flow.protocol_hint.clone(),
        packet.protocol.clone(),
    ));
    flow.set_dns_candidate(flow.dns_candidate || packet.dns_candidate);
    flow.set_tls_candidate(flow.tls_candidate || packet.tls_candidate);
    flow.set_quic_candidate(flow.quic_candidate || packet.quic_candidate);
    flow.set_quic_initial_candidate(flow.quic_initial_candidate || packet.quic_initial_candidate);
    flow.set_doh_candidate(flow.doh_candidate || packet.doh_candidate);
    flow.set_dot_candidate(flow.dot_candidate || packet.dot_candidate);
    flow.set_http3_candidate(flow.http3_candidate || packet.http3_candidate);
    if let Some(domain) = packet.dns_query_name.as_ref() {
        prefer_domain(flow, domain.clone(), DomainSource::Dns);
    }
    if let Some(server_name) = packet.tls_server_name.as_ref() {
        prefer_domain(flow, server_name.clone(), DomainSource::TlsSni);
        flow.set_tls_server_name(Some(server_name.clone()));
    }
    if let Some(server_name) = packet.quic_server_name.as_ref() {
        prefer_domain(flow, server_name.clone(), DomainSource::QuicInitialSni);
        flow.set_quic_server_name(Some(server_name.clone()));
    }
    if let Some(host) = packet.http_host.as_ref() {
        flow.set_http_host(Some(host.clone()));
        prefer_domain(flow, host.clone(), DomainSource::HttpHost);
    }
    if !packet.application_protocols.is_empty() {
        let mut merged = flow.application_protocols.clone();
        for protocol in &packet.application_protocols {
            if !merged.contains(protocol) {
                merged.push(protocol.clone());
            }
        }
        flow.set_application_protocols(merged);
    }
}

fn prefer_domain(flow: &mut FlowState, domain: String, source: DomainSource) {
    let normalized = normalize_domain(domain);
    let current_rank = flow
        .domain_source
        .as_ref()
        .map(domain_source_rank)
        .unwrap_or(0);
    let incoming_rank = domain_source_rank(&source);
    let should_replace = flow.domain.is_none()
        || incoming_rank > current_rank
        || (incoming_rank == current_rank
            && flow.domain.as_deref() != Some(normalized.as_str()));

    if should_replace {
        flow.set_domain(Some(normalized));
        flow.set_domain_source(Some(source));
    }
}

fn normalize_domain(domain: String) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_source_rank(source: &DomainSource) -> u8 {
    match source {
        DomainSource::Dns => 1,
        DomainSource::HttpHost => 2,
        DomainSource::TlsSni => 3,
        DomainSource::QuicInitialSni => 3,
    }
}

fn prefer_protocol_hint(
    current: rustprobe_core::ProtocolHint,
    incoming: rustprobe_core::ProtocolHint,
) -> rustprobe_core::ProtocolHint {
    if protocol_rank(incoming.clone()) >= protocol_rank(current.clone()) {
        incoming
    } else {
        current
    }
}

fn protocol_rank(protocol: rustprobe_core::ProtocolHint) -> u8 {
    use rustprobe_core::ProtocolHint;

    match protocol {
        ProtocolHint::Unknown => 0,
        ProtocolHint::Tcp | ProtocolHint::Udp | ProtocolHint::Icmp => 1,
        ProtocolHint::Quic | ProtocolHint::Http | ProtocolHint::Dns | ProtocolHint::Tls => 2,
    }
}

fn append_tcp_payload(buffer: &mut TcpReassemblyBuffer, packet: &ParsedPacket) {
    let Some(sequence) = packet.tcp_sequence else {
        return;
    };
    if packet.transport_payload.is_empty() {
        return;
    }

    buffer
        .fragments
        .entry(sequence)
        .and_modify(|existing| {
            if existing.len() < packet.transport_payload.len() {
                *existing = packet.transport_payload.clone();
            }
        })
        .or_insert_with(|| packet.transport_payload.clone());
}

fn tcp_contiguous_prefix(buffer: &TcpReassemblyBuffer, limit: usize) -> Option<Vec<u8>> {
    let (&start_sequence, _) = buffer.fragments.first_key_value()?;
    let mut prefix = Vec::new();
    let mut next_sequence = start_sequence;

    for (sequence, data) in &buffer.fragments {
        if *sequence > next_sequence {
            break;
        }

        let overlap = next_sequence.saturating_sub(*sequence) as usize;
        if overlap >= data.len() {
            continue;
        }

        let remaining = limit.saturating_sub(prefix.len());
        if remaining == 0 {
            break;
        }

        let append_len = remaining.min(data.len() - overlap);
        prefix.extend_from_slice(&data[overlap..overlap + append_len]);
        next_sequence = sequence.saturating_add(u32::try_from(data.len()).ok()?);
        if prefix.len() >= limit {
            break;
        }
    }

    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

fn append_quic_crypto_fragments(
    buffer: &mut QuicCryptoReassemblyBuffer,
    destination_connection_id: Option<&str>,
    fragments: &[QuicCryptoFragment],
) {
    if destination_connection_id != buffer.destination_connection_id.as_deref() {
        buffer.destination_connection_id = destination_connection_id.map(ToOwned::to_owned);
        buffer.fragments.clear();
    }
    for fragment in fragments {
        let Some(end) = fragment.offset.checked_add(fragment.data.len()) else {
            continue;
        };
        if end > QUIC_BUFFER_LIMIT_BYTES {
            continue;
        }
        buffer
            .fragments
            .insert(fragment.offset, fragment.data.clone());
    }
}

fn quic_crypto_contiguous_prefix(buffer: &QuicCryptoReassemblyBuffer) -> Option<Vec<u8>> {
    let mut prefix = Vec::new();
    let mut next_offset = 0usize;

    for (offset, data) in &buffer.fragments {
        if *offset > next_offset {
            break;
        }

        let overlap = next_offset.saturating_sub(*offset);
        if overlap >= data.len() {
            continue;
        }

        prefix.extend_from_slice(&data[overlap..]);
        next_offset = offset.checked_add(data.len())?;
    }

    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::FlowActor;
    use rustprobe_core::{DomainSource, IpVersion, ParsedPacket, ProtocolHint};

    fn base_packet() -> ParsedPacket {
        ParsedPacket {
            ip_version: IpVersion::V4,
            protocol: ProtocolHint::Tcp,
            transport_protocol: ProtocolHint::Tcp,
            src_addr: "10.0.0.2".into(),
            dst_addr: "1.1.1.1".into(),
            src_port: Some(50000),
            dst_port: Some(443),
            tcp_sequence: None,
            payload_len: 120,
            dns_query_name: None,
            tls_server_name: None,
            quic_server_name: None,
            http_host: None,
            http_request_target: None,
            application_protocols: Vec::new(),
            quic_destination_connection_id: None,
            dns_candidate: false,
            tls_candidate: false,
            quic_candidate: false,
            quic_initial_candidate: false,
            doh_candidate: false,
            dot_candidate: false,
            http3_candidate: false,
            transport_payload: Vec::new(),
        }
    }

    #[test]
    fn stronger_domain_sources_do_not_get_overwritten_by_weaker_ones() {
        let mut actor = FlowActor::default();

        let mut tls_packet = base_packet();
        tls_packet.protocol = ProtocolHint::Tls;
        tls_packet.tls_server_name = Some("Api.Example.com".into());
        actor.ingest_packet(&tls_packet).expect("tls flow");

        let mut dns_packet = base_packet();
        dns_packet.protocol = ProtocolHint::Dns;
        dns_packet.dns_query_name = Some("resolver.example".into());
        let result = actor.ingest_packet(&dns_packet).expect("dns flow");

        assert_eq!(result.flow.domain.as_deref(), Some("api.example.com"));
        assert_eq!(result.flow.domain_source, Some(DomainSource::TlsSni));
    }

    #[test]
    fn domain_objects_are_normalized() {
        let mut actor = FlowActor::default();

        let mut packet = base_packet();
        packet.protocol = ProtocolHint::Http;
        packet.http_host = Some("WWW.Example.COM.".into());
        let result = actor.ingest_packet(&packet).expect("http flow");

        assert_eq!(result.flow.domain.as_deref(), Some("www.example.com"));
        let objects = actor.object_snapshot();
        assert!(objects.iter().any(|object| object.key.value == "www.example.com"));
    }
}
