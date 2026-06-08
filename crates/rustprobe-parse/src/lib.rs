use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInPlace;
use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use rustprobe_core::{
    FlowEvent, FlowRecord, IpVersion, NetworkEndpoint, ObjectKind, ObjectRecord, PacketEvent,
    ParsedPacket, ProtocolHint, RiskLevel,
};
use sha2::Sha256;

#[derive(Debug, Default)]
pub struct ParserStage;

#[derive(Debug, Clone)]
pub struct QuicCryptoFragment {
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ClientHelloMetadata {
    pub server_name: Option<String>,
    pub application_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestMetadata {
    pub host: String,
    pub target: String,
    pub is_doh: bool,
}

const QUIC_V1_VERSION: u32 = 0x0000_0001;
const QUIC_V2_VERSION: u32 = 0x6b33_43cf;
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const QUIC_AEAD_TAG_LEN: usize = 16;
const QUIC_HP_SAMPLE_LEN: usize = 16;
const QUIC_INITIAL_SECRET_LEN: usize = 32;
const QUIC_INITIAL_KEY_LEN: usize = 16;
const QUIC_INITIAL_IV_LEN: usize = 12;
const MAX_QUIC_CRYPTO_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug)]
struct TransportParseResult {
    protocol: ProtocolHint,
    transport_protocol: ProtocolHint,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_sequence: Option<u32>,
    payload_len: usize,
    dns_query_name: Option<String>,
    tls_server_name: Option<String>,
    quic_server_name: Option<String>,
    http_host: Option<String>,
    http_request_target: Option<String>,
    application_protocols: Vec<String>,
    quic_destination_connection_id: Option<String>,
    dns_candidate: bool,
    tls_candidate: bool,
    quic_candidate: bool,
    quic_initial_candidate: bool,
    doh_candidate: bool,
    dot_candidate: bool,
    http3_candidate: bool,
    transport_payload: Vec<u8>,
}

impl ParserStage {
    pub fn parse_tun_packet(&self, bytes: &[u8]) -> Result<ParsedPacket> {
        let version = bytes
            .first()
            .map(|byte| byte >> 4)
            .ok_or_else(|| anyhow!("empty packet"))?;

        match version {
            4 => self.parse_ipv4(bytes),
            6 => self.parse_ipv6(bytes),
            other => Err(anyhow!("unsupported ip version nibble: {other}")),
        }
    }

    pub fn parse(&self, packet: &PacketEvent) -> FlowEvent {
        FlowEvent {
            flow: FlowRecord {
                id: format!("flow-{}", packet.source),
                src: NetworkEndpoint {
                    host: "10.0.0.2".into(),
                    port: 12345,
                },
                dst: NetworkEndpoint {
                    host: "93.184.216.34".into(),
                    port: 443,
                },
                protocol: ProtocolHint::Tls,
                app: None,
            },
            objects: vec![
                ObjectRecord {
                    kind: ObjectKind::Ip,
                    value: "93.184.216.34".into(),
                    related_flows: 1,
                    risk: RiskLevel::Info,
                },
                ObjectRecord {
                    kind: ObjectKind::Port,
                    value: "443".into(),
                    related_flows: 1,
                    risk: RiskLevel::Info,
                },
            ],
        }
    }

    fn parse_ipv4(&self, bytes: &[u8]) -> Result<ParsedPacket> {
        let packet = Ipv4Packet::new(bytes).ok_or_else(|| anyhow!("invalid ipv4 packet"))?;
        let payload = packet.payload();
        let transport = self.parse_transport(packet.get_next_level_protocol(), payload);

        Ok(ParsedPacket {
            ip_version: IpVersion::V4,
            protocol: transport.protocol,
            transport_protocol: transport.transport_protocol,
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            tcp_sequence: transport.tcp_sequence,
            payload_len: transport.payload_len,
            dns_query_name: transport.dns_query_name,
            tls_server_name: transport.tls_server_name,
            quic_server_name: transport.quic_server_name,
            http_host: transport.http_host,
            http_request_target: transport.http_request_target,
            application_protocols: transport.application_protocols,
            quic_destination_connection_id: transport.quic_destination_connection_id,
            dns_candidate: transport.dns_candidate,
            tls_candidate: transport.tls_candidate,
            quic_candidate: transport.quic_candidate,
            quic_initial_candidate: transport.quic_initial_candidate,
            doh_candidate: transport.doh_candidate,
            dot_candidate: transport.dot_candidate,
            http3_candidate: transport.http3_candidate,
            transport_payload: transport.transport_payload,
        })
    }

    fn parse_ipv6(&self, bytes: &[u8]) -> Result<ParsedPacket> {
        let packet = Ipv6Packet::new(bytes).ok_or_else(|| anyhow!("invalid ipv6 packet"))?;
        let payload = packet.payload();
        let transport = self.parse_transport(packet.get_next_header(), payload);

        Ok(ParsedPacket {
            ip_version: IpVersion::V6,
            protocol: transport.protocol,
            transport_protocol: transport.transport_protocol,
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            tcp_sequence: transport.tcp_sequence,
            payload_len: transport.payload_len,
            dns_query_name: transport.dns_query_name,
            tls_server_name: transport.tls_server_name,
            quic_server_name: transport.quic_server_name,
            http_host: transport.http_host,
            http_request_target: transport.http_request_target,
            application_protocols: transport.application_protocols,
            quic_destination_connection_id: transport.quic_destination_connection_id,
            dns_candidate: transport.dns_candidate,
            tls_candidate: transport.tls_candidate,
            quic_candidate: transport.quic_candidate,
            quic_initial_candidate: transport.quic_initial_candidate,
            doh_candidate: transport.doh_candidate,
            dot_candidate: transport.dot_candidate,
            http3_candidate: transport.http3_candidate,
            transport_payload: transport.transport_payload,
        })
    }

    fn parse_transport(
        &self,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        payload: &[u8],
    ) -> TransportParseResult {
        match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    let dns_candidate = looks_like_dns_message_over_tcp(tcp.payload());
                    let dns_query_name = if dns_candidate {
                        parse_dns_query_name_over_tcp(tcp.payload())
                    } else {
                        None
                    };
                    let tls_candidate = looks_like_tls_client_hello(tcp.payload());
                    let tls_metadata = if tls_candidate {
                        parse_tls_client_hello_metadata(tcp.payload())
                    } else {
                        None
                    };
                    let tls_server_name = tls_metadata
                        .as_ref()
                        .and_then(|metadata| metadata.server_name.clone());
                    let application_protocols = tls_metadata
                        .as_ref()
                        .map(|metadata| metadata.application_protocols.clone())
                        .unwrap_or_default();
                    let http_metadata = if tls_candidate {
                        None
                    } else {
                        parse_http_request_metadata(tcp.payload())
                    };
                    let http_host = http_metadata.as_ref().map(|metadata| metadata.host.clone());
                    let http_request_target = http_metadata
                        .as_ref()
                        .map(|metadata| metadata.target.clone());
                    let doh_candidate = http_metadata
                        .as_ref()
                        .map(|metadata| metadata.is_doh)
                        .unwrap_or(false)
                        || tls_server_name
                            .as_deref()
                            .map(is_known_dns_resolver_host)
                            .unwrap_or(false);
                    let dot_candidate = tls_candidate
                        && ((tcp.get_source() == 853 || tcp.get_destination() == 853)
                            || tls_server_name
                                .as_deref()
                                .map(is_known_dns_resolver_host)
                                .unwrap_or(false));

                    TransportParseResult {
                        protocol: if dns_candidate {
                            ProtocolHint::Dns
                        } else if tls_candidate {
                            ProtocolHint::Tls
                        } else if http_host.is_some() {
                            ProtocolHint::Http
                        } else {
                            ProtocolHint::Tcp
                        },
                        transport_protocol: ProtocolHint::Tcp,
                        src_port: Some(tcp.get_source()),
                        dst_port: Some(tcp.get_destination()),
                        tcp_sequence: Some(tcp.get_sequence()),
                        payload_len: tcp.payload().len(),
                        dns_query_name,
                        tls_server_name,
                        quic_server_name: None,
                        http_host,
                        http_request_target,
                        application_protocols,
                        quic_destination_connection_id: None,
                        dns_candidate,
                        tls_candidate,
                        quic_candidate: false,
                        quic_initial_candidate: false,
                        doh_candidate,
                        dot_candidate,
                        http3_candidate: false,
                        transport_payload: payload_prefix(tcp.payload()),
                    }
                } else {
                    TransportParseResult {
                        protocol: ProtocolHint::Tcp,
                        transport_protocol: ProtocolHint::Tcp,
                        src_port: None,
                        dst_port: None,
                        tcp_sequence: None,
                        payload_len: payload.len(),
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
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    let dns_candidate = looks_like_dns_message(udp.payload());
                    let quic_header = parse_quic_header_metadata(udp.payload());
                    let quic_candidate = quic_header.is_some();
                    let quic_initial_candidate = quic_header
                        .as_ref()
                        .map(|header| header.packet_type == QuicLongHeaderPacketType::Initial)
                        .unwrap_or(false);
                    let quic_metadata = if quic_initial_candidate {
                        parse_quic_initial_client_hello_metadata(udp.payload())
                    } else {
                        None
                    };
                    let quic_server_name = quic_metadata
                        .as_ref()
                        .and_then(|metadata| metadata.server_name.clone());
                    let application_protocols = quic_metadata
                        .as_ref()
                        .map(|metadata| metadata.application_protocols.clone())
                        .unwrap_or_default();
                    let http3_candidate = application_protocols
                        .iter()
                        .any(|protocol| protocol.starts_with("h3"));
                    let doh_candidate = quic_server_name
                        .as_deref()
                        .map(is_known_dns_resolver_host)
                        .unwrap_or(false)
                        && http3_candidate;
                    let dns_query_name = if dns_candidate {
                        parse_dns_query_name(udp.payload())
                    } else {
                        None
                    };

                    TransportParseResult {
                        protocol: if dns_candidate {
                            ProtocolHint::Dns
                        } else if quic_candidate {
                            ProtocolHint::Quic
                        } else {
                            ProtocolHint::Udp
                        },
                        transport_protocol: ProtocolHint::Udp,
                        src_port: Some(udp.get_source()),
                        dst_port: Some(udp.get_destination()),
                        tcp_sequence: None,
                        payload_len: udp.payload().len(),
                        dns_query_name,
                        tls_server_name: None,
                        quic_server_name,
                        http_host: None,
                        http_request_target: None,
                        application_protocols,
                        quic_destination_connection_id: quic_header
                            .as_ref()
                            .map(|header| header.destination_connection_id_hex.clone()),
                        dns_candidate,
                        tls_candidate: false,
                        quic_candidate,
                        quic_initial_candidate,
                        doh_candidate,
                        dot_candidate: false,
                        http3_candidate,
                        transport_payload: payload_prefix(udp.payload()),
                    }
                } else {
                    TransportParseResult {
                        protocol: ProtocolHint::Udp,
                        transport_protocol: ProtocolHint::Udp,
                        src_port: None,
                        dst_port: None,
                        tcp_sequence: None,
                        payload_len: payload.len(),
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
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => TransportParseResult {
                protocol: ProtocolHint::Icmp,
                transport_protocol: ProtocolHint::Icmp,
                src_port: None,
                dst_port: None,
                tcp_sequence: None,
                payload_len: payload.len(),
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
            },
            _ => TransportParseResult {
                protocol: ProtocolHint::Unknown,
                transport_protocol: ProtocolHint::Unknown,
                src_port: None,
                dst_port: None,
                tcp_sequence: None,
                payload_len: payload.len(),
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
            },
        }
    }
}

fn payload_prefix(payload: &[u8]) -> Vec<u8> {
    const MAX_CAPTURED_TRANSPORT_PAYLOAD: usize = 4096;
    payload
        .get(..payload.len().min(MAX_CAPTURED_TRANSPORT_PAYLOAD))
        .unwrap_or(&[])
        .to_vec()
}

fn looks_like_dns_message(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }

    let opcode = (payload[2] >> 3) & 0x0f;
    if opcode > 5 {
        return false;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    qdcount > 0 || ancount > 0 || nscount > 0 || arcount > 0
}

fn looks_like_dns_message_over_tcp(payload: &[u8]) -> bool {
    if payload.len() < 14 {
        return false;
    }

    let message_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if message_len == 0 {
        return false;
    }

    let Some(message_end) = 2usize.checked_add(message_len) else {
        return false;
    };
    let Some(message) = payload.get(2..message_end) else {
        return false;
    };

    looks_like_dns_message(message)
}

fn looks_like_quic_packet(payload: &[u8]) -> bool {
    if payload.len() < 7 {
        return false;
    }

    let first = payload[0];
    let fixed_bit_set = (first & 0x40) != 0;
    let long_header = (first & 0x80) != 0;
    if !fixed_bit_set || !long_header {
        return false;
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false;
    }

    let dst_cid_len = payload[5] as usize;
    if dst_cid_len > 20 {
        return false;
    }

    let src_cid_len_offset = 6usize.saturating_add(dst_cid_len);
    let Some(&src_cid_len_byte) = payload.get(src_cid_len_offset) else {
        return false;
    };
    let src_cid_len = src_cid_len_byte as usize;
    if src_cid_len > 20 {
        return false;
    }

    let src_cid_end = src_cid_len_offset
        .checked_add(1)
        .and_then(|offset| offset.checked_add(src_cid_len));
    match src_cid_end {
        Some(end) => payload.len() > end,
        None => false,
    }
}

fn looks_like_quic_initial_packet(payload: &[u8]) -> bool {
    if !looks_like_quic_packet(payload) {
        return false;
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    matches!(
        quic_long_header_packet_type(payload[0], version),
        Some(QuicLongHeaderPacketType::Initial)
    )
}

fn parse_dns_query_name(payload: &[u8]) -> Option<String> {
    if !looks_like_dns_message(payload) {
        return None;
    }

    if payload.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12usize;
    let mut labels = Vec::new();

    loop {
        let length = *payload.get(offset)? as usize;
        offset += 1;

        if length == 0 {
            break;
        }

        if length & 0b1100_0000 != 0 {
            return None;
        }

        let end = offset.checked_add(length)?;
        let label = std::str::from_utf8(payload.get(offset..end)?).ok()?;
        if label.is_empty() {
            return None;
        }
        labels.push(sanitize_dns_label(label)?);
        offset = end;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn parse_dns_query_name_over_tcp(payload: &[u8]) -> Option<String> {
    if !looks_like_dns_message_over_tcp(payload) {
        return None;
    }

    let message_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let message = payload.get(2..2usize.checked_add(message_len)?)?;
    parse_dns_query_name(message)
}

fn looks_like_tls_client_hello(payload: &[u8]) -> bool {
    if payload.len() < 9 {
        return false;
    }

    if payload[0] != 22 {
        return false;
    }

    if payload[1] != 0x03 || !(0x00..=0x04).contains(&payload[2]) {
        return false;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len == 0 {
        return false;
    }
    let Some(record_end) = 5usize.checked_add(record_len) else {
        return false;
    };
    let Some(record) = payload.get(5..record_end) else {
        return false;
    };

    if record.len() < 4 || record[0] != 1 {
        return false;
    }

    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    let Some(handshake_end) = 4usize.checked_add(handshake_len) else {
        return false;
    };
    let Some(body) = record.get(4..handshake_end) else {
        return false;
    };
    if body.len() < 34 {
        return false;
    }

    true
}

pub fn parse_tls_client_hello_server_name(payload: &[u8]) -> Option<String> {
    parse_tls_client_hello_metadata(payload).and_then(|metadata| metadata.server_name)
}

pub fn parse_tls_client_hello_server_name_from_handshake(body: &[u8]) -> Option<String> {
    parse_tls_client_hello_metadata_from_handshake(body).and_then(|metadata| metadata.server_name)
}

pub fn parse_tls_client_hello_metadata(payload: &[u8]) -> Option<ClientHelloMetadata> {
    if !looks_like_tls_client_hello(payload) {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?;
    let record = payload.get(5..record_end)?;
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    let body = record.get(4..4usize.checked_add(handshake_len)?)?;
    parse_tls_client_hello_metadata_from_handshake(body)
}

pub fn parse_tls_client_hello_metadata_from_handshake(body: &[u8]) -> Option<ClientHelloMetadata> {
    if body.len() < 34 {
        return None;
    }

    let mut offset = 34usize;

    let session_id_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + session_id_len)?;

    let cipher_suites_len =
        u16::from_be_bytes([*body.get(offset)?, *body.get(offset + 1)?]) as usize;
    offset = offset.checked_add(2 + cipher_suites_len)?;

    let compression_methods_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + compression_methods_len)?;

    let extensions_len = u16::from_be_bytes([*body.get(offset)?, *body.get(offset + 1)?]) as usize;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    let mut server_name = None;
    let mut application_protocols = Vec::new();

    while offset + 4 <= extensions_end && offset + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        let ext_end = offset.checked_add(ext_len)?;
        let ext_data = body.get(offset..ext_end)?;

        match ext_type {
            0 => {
                server_name = parse_tls_sni_extension(ext_data);
            }
            16 => {
                application_protocols = parse_tls_alpn_extension(ext_data).unwrap_or_default();
            }
            _ => {}
        }

        offset = ext_end;
    }

    Some(ClientHelloMetadata {
        server_name,
        application_protocols,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicLongHeaderPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

#[derive(Debug)]
struct QuicVersionCryptoParams {
    initial_salt: &'static [u8; 20],
    key_label: &'static str,
    iv_label: &'static str,
    hp_label: &'static str,
}

#[derive(Debug)]
struct QuicInitialHeader {
    version: u32,
    destination_connection_id: Vec<u8>,
    packet_number_offset: usize,
    payload_length: usize,
}

#[derive(Debug, Clone)]
struct QuicHeaderMetadata {
    packet_type: QuicLongHeaderPacketType,
    destination_connection_id_hex: String,
}

pub fn parse_quic_initial_server_name(payload: &[u8]) -> Option<String> {
    let crypto_fragments = extract_quic_initial_crypto_fragments(payload)?;
    let crypto_stream = assemble_contiguous_quic_crypto_prefix(&crypto_fragments)?;
    parse_tls_client_hello_server_name_from_handshake(&crypto_stream)
}

fn parse_quic_initial_client_hello_metadata(payload: &[u8]) -> Option<ClientHelloMetadata> {
    let crypto_fragments = extract_quic_initial_crypto_fragments(payload)?;
    let crypto_stream = assemble_contiguous_quic_crypto_prefix(&crypto_fragments)?;
    parse_tls_client_hello_metadata_from_handshake(&crypto_stream)
}

pub fn extract_quic_initial_crypto_fragments(payload: &[u8]) -> Option<Vec<QuicCryptoFragment>> {
    let decrypted_payload = decrypt_quic_initial_payload(payload)?;
    collect_quic_initial_crypto_fragments(&decrypted_payload)
}

fn decrypt_quic_initial_payload(payload: &[u8]) -> Option<Vec<u8>> {
    let header = parse_quic_initial_header(payload)?;
    let params = quic_version_crypto_params(header.version)?;
    let secrets = derive_quic_initial_secrets(params, &header.destination_connection_id)?;
    let sample_offset = header.packet_number_offset.checked_add(4)?;
    let sample = payload.get(sample_offset..sample_offset.checked_add(QUIC_HP_SAMPLE_LEN)?)?;
    let mask = quic_header_protection_mask(&secrets.header_protection_key, sample)?;

    let first_byte = *payload.first()? ^ (mask[0] & 0x0f);
    let packet_number_len = ((first_byte & 0x03) + 1) as usize;
    let packet_number_end = header.packet_number_offset.checked_add(packet_number_len)?;
    let protected_packet_number = payload.get(header.packet_number_offset..packet_number_end)?;

    let mut packet_number_bytes = Vec::with_capacity(packet_number_len);
    for (index, byte) in protected_packet_number.iter().enumerate() {
        packet_number_bytes.push(byte ^ mask.get(index + 1).copied()?);
    }

    let payload_end = header
        .packet_number_offset
        .checked_add(header.payload_length)?;
    if payload_end > payload.len() || header.payload_length < packet_number_len + QUIC_AEAD_TAG_LEN
    {
        return None;
    }

    let encrypted_payload_with_tag = payload.get(packet_number_end..payload_end)?;
    if encrypted_payload_with_tag.len() < QUIC_AEAD_TAG_LEN {
        return None;
    }
    let ciphertext_end = encrypted_payload_with_tag.len() - QUIC_AEAD_TAG_LEN;
    let (ciphertext, tag) = encrypted_payload_with_tag.split_at(ciphertext_end);

    let mut associated_data = payload.get(..packet_number_end)?.to_vec();
    associated_data[0] = first_byte;
    associated_data[header.packet_number_offset..packet_number_end]
        .copy_from_slice(&packet_number_bytes);

    let packet_number = decode_truncated_packet_number(&packet_number_bytes);
    let nonce = build_quic_packet_nonce(&secrets.initialization_vector, packet_number);
    let cipher = Aes128Gcm::new_from_slice(&secrets.packet_protection_key).ok()?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &associated_data,
            &mut plaintext,
            GenericArray::from_slice(tag),
        )
        .ok()?;

    Some(plaintext)
}

fn parse_quic_initial_header(payload: &[u8]) -> Option<QuicInitialHeader> {
    if !looks_like_quic_initial_packet(payload) || payload.len() < 7 {
        return None;
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let mut offset = 5usize;

    let dst_cid_len = *payload.get(offset)? as usize;
    offset += 1;
    let dst_cid_end = offset.checked_add(dst_cid_len)?;
    let destination_connection_id = payload.get(offset..dst_cid_end)?.to_vec();
    offset = dst_cid_end;

    let src_cid_len = *payload.get(offset)? as usize;
    offset += 1;
    let src_cid_end = offset.checked_add(src_cid_len)?;
    payload.get(offset..src_cid_end)?;
    offset = src_cid_end;

    let (token_length, token_length_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(token_length_len)?;
    let token_end = offset.checked_add(usize::try_from(token_length).ok()?)?;
    payload.get(offset..token_end)?;
    offset = token_end;

    let (payload_length, payload_length_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(payload_length_len)?;

    Some(QuicInitialHeader {
        version,
        destination_connection_id,
        packet_number_offset: offset,
        payload_length: usize::try_from(payload_length).ok()?,
    })
}

fn parse_quic_header_metadata(payload: &[u8]) -> Option<QuicHeaderMetadata> {
    if !looks_like_quic_packet(payload) || payload.len() < 7 {
        return None;
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let packet_type = quic_long_header_packet_type(*payload.first()?, version)?;
    let mut offset = 5usize;
    let dst_cid_len = *payload.get(offset)? as usize;
    offset += 1;
    let dst_cid = payload.get(offset..offset.checked_add(dst_cid_len)?)?;

    Some(QuicHeaderMetadata {
        packet_type,
        destination_connection_id_hex: encode_hex(dst_cid),
    })
}

fn collect_quic_initial_crypto_fragments(plaintext: &[u8]) -> Option<Vec<QuicCryptoFragment>> {
    let mut offset = 0usize;
    let mut fragments = Vec::new();
    let mut saw_crypto = false;

    while offset < plaintext.len() {
        let frame_type = *plaintext.get(offset)?;
        offset += 1;

        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                offset = skip_quic_ack_frame(plaintext, offset, frame_type == 0x03)?;
            }
            0x06 => {
                let (crypto_offset, crypto_offset_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(crypto_offset_len)?;
                let (crypto_len, crypto_len_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(crypto_len_len)?;
                let crypto_len = usize::try_from(crypto_len).ok()?;
                let frame_end = offset.checked_add(crypto_len)?;
                let crypto_payload = plaintext.get(offset..frame_end)?;
                fragments.push(QuicCryptoFragment {
                    offset: usize::try_from(crypto_offset).ok()?,
                    data: crypto_payload.to_vec(),
                });
                saw_crypto = true;
                offset = frame_end;
            }
            0x07 => {
                let (token_len, token_len_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(token_len_len)?;
                offset = offset.checked_add(usize::try_from(token_len).ok()?)?;
            }
            0x04 => {
                offset = skip_quic_varints(plaintext, offset, 3)?;
            }
            0x05 => {
                offset = skip_quic_varints(plaintext, offset, 2)?;
            }
            0x08..=0x0f => {
                offset = skip_quic_stream_frame(plaintext, offset, frame_type)?;
            }
            0x10 => {
                offset = skip_quic_varints(plaintext, offset, 1)?;
            }
            0x11 => {
                offset = skip_quic_varints(plaintext, offset, 2)?;
            }
            0x12 | 0x13 => {
                offset = skip_quic_varints(plaintext, offset, 1)?;
            }
            0x14 => {
                offset = skip_quic_varints(plaintext, offset, 1)?;
            }
            0x15 => {
                offset = skip_quic_varints(plaintext, offset, 2)?;
            }
            0x16 | 0x17 => {
                offset = skip_quic_varints(plaintext, offset, 1)?;
            }
            0x18 => {
                offset = skip_quic_new_connection_id_frame(plaintext, offset)?;
            }
            0x19 => {
                offset = skip_quic_varints(plaintext, offset, 1)?;
            }
            0x1a | 0x1b => {
                offset = offset.checked_add(8)?;
            }
            0x1c => {
                let (_, code_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(code_len)?;
                let (_, frame_type_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(frame_type_len)?;
                let (reason_len, reason_len_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(reason_len_len)?;
                offset = offset.checked_add(usize::try_from(reason_len).ok()?)?;
            }
            0x1d => {
                let (_, code_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(code_len)?;
                let (reason_len, reason_len_len) = parse_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(reason_len_len)?;
                offset = offset.checked_add(usize::try_from(reason_len).ok()?)?;
            }
            0x1e => {}
            0x30 | 0x31 => {
                offset = skip_quic_datagram_frame(plaintext, offset, frame_type)?;
            }
            _ => break,
        }
    }

    if saw_crypto && !fragments.is_empty() {
        Some(fragments)
    } else {
        None
    }
}

fn assemble_contiguous_quic_crypto_prefix(fragments: &[QuicCryptoFragment]) -> Option<Vec<u8>> {
    let mut ordered = fragments.to_vec();
    ordered.sort_by_key(|fragment| fragment.offset);

    let mut contiguous = Vec::new();
    let mut next_offset = 0usize;

    for fragment in ordered {
        let fragment_end = fragment.offset.checked_add(fragment.data.len())?;
        if fragment_end > MAX_QUIC_CRYPTO_BUFFER_BYTES {
            return None;
        }

        if fragment.offset > next_offset {
            break;
        }

        let overlap = next_offset.saturating_sub(fragment.offset);
        if overlap >= fragment.data.len() {
            continue;
        }

        contiguous.extend_from_slice(&fragment.data[overlap..]);
        next_offset = fragment_end;
    }

    if contiguous.is_empty() {
        None
    } else {
        Some(contiguous)
    }
}

fn skip_quic_ack_frame(payload: &[u8], mut offset: usize, has_ecn: bool) -> Option<usize> {
    let (_, largest_acknowledged_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(largest_acknowledged_len)?;
    let (_, ack_delay_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(ack_delay_len)?;
    let (ack_range_count, ack_range_count_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(ack_range_count_len)?;
    let (_, first_ack_range_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(first_ack_range_len)?;

    for _ in 0..ack_range_count {
        let (_, gap_len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(gap_len)?;
        let (_, ack_range_len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(ack_range_len)?;
    }

    if has_ecn {
        for _ in 0..3 {
            let (_, counter_len) = parse_quic_varint(payload, offset)?;
            offset = offset.checked_add(counter_len)?;
        }
    }

    Some(offset)
}

fn skip_quic_varints(payload: &[u8], mut offset: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let (_, len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(len)?;
    }
    Some(offset)
}

fn skip_quic_stream_frame(payload: &[u8], mut offset: usize, frame_type: u8) -> Option<usize> {
    let has_offset = (frame_type & 0x04) != 0;
    let has_length = (frame_type & 0x02) != 0;

    let (_, stream_id_len) = parse_quic_varint(payload, offset)?;
    offset = offset.checked_add(stream_id_len)?;
    if has_offset {
        let (_, offset_len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(offset_len)?;
    }

    if has_length {
        let (stream_len, stream_len_len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(stream_len_len)?;
        offset = offset.checked_add(usize::try_from(stream_len).ok()?)?;
    } else {
        offset = payload.len();
    }

    Some(offset)
}

fn skip_quic_new_connection_id_frame(payload: &[u8], mut offset: usize) -> Option<usize> {
    offset = skip_quic_varints(payload, offset, 2)?;
    let connection_id_len = *payload.get(offset)? as usize;
    offset += 1;
    offset = offset.checked_add(connection_id_len)?;
    offset = offset.checked_add(16)?;
    Some(offset)
}

fn skip_quic_datagram_frame(payload: &[u8], mut offset: usize, frame_type: u8) -> Option<usize> {
    let has_len = (frame_type & 0x01) != 0;
    if has_len {
        let (datagram_len, datagram_len_len) = parse_quic_varint(payload, offset)?;
        offset = offset.checked_add(datagram_len_len)?;
        offset = offset.checked_add(usize::try_from(datagram_len).ok()?)?;
        Some(offset)
    } else {
        Some(payload.len())
    }
}

fn quic_long_header_packet_type(first_byte: u8, version: u32) -> Option<QuicLongHeaderPacketType> {
    let packet_type_bits = (first_byte & 0x30) >> 4;
    match version {
        QUIC_V2_VERSION => match packet_type_bits {
            0b00 => Some(QuicLongHeaderPacketType::Retry),
            0b01 => Some(QuicLongHeaderPacketType::Initial),
            0b10 => Some(QuicLongHeaderPacketType::ZeroRtt),
            0b11 => Some(QuicLongHeaderPacketType::Handshake),
            _ => None,
        },
        _ => match packet_type_bits {
            0b00 => Some(QuicLongHeaderPacketType::Initial),
            0b01 => Some(QuicLongHeaderPacketType::ZeroRtt),
            0b10 => Some(QuicLongHeaderPacketType::Handshake),
            0b11 => Some(QuicLongHeaderPacketType::Retry),
            _ => None,
        },
    }
}

fn quic_version_crypto_params(version: u32) -> Option<QuicVersionCryptoParams> {
    match version {
        QUIC_V1_VERSION => Some(QuicVersionCryptoParams {
            initial_salt: &QUIC_V1_INITIAL_SALT,
            key_label: "quic key",
            iv_label: "quic iv",
            hp_label: "quic hp",
        }),
        QUIC_V2_VERSION => Some(QuicVersionCryptoParams {
            initial_salt: &QUIC_V2_INITIAL_SALT,
            key_label: "quicv2 key",
            iv_label: "quicv2 iv",
            hp_label: "quicv2 hp",
        }),
        _ => None,
    }
}

#[derive(Debug)]
struct QuicInitialSecrets {
    packet_protection_key: [u8; QUIC_INITIAL_KEY_LEN],
    initialization_vector: [u8; QUIC_INITIAL_IV_LEN],
    header_protection_key: [u8; QUIC_INITIAL_KEY_LEN],
}

fn derive_quic_initial_secrets(
    params: QuicVersionCryptoParams,
    destination_connection_id: &[u8],
) -> Option<QuicInitialSecrets> {
    let initial_secret_hkdf =
        Hkdf::<Sha256>::new(Some(params.initial_salt), destination_connection_id);
    let client_initial_secret =
        hkdf_expand_label_from_hkdf(&initial_secret_hkdf, "client in", QUIC_INITIAL_SECRET_LEN)?;
    let packet_protection_key = hkdf_expand_label(
        &client_initial_secret,
        params.key_label,
        QUIC_INITIAL_KEY_LEN,
    )?;
    let initialization_vector =
        hkdf_expand_label(&client_initial_secret, params.iv_label, QUIC_INITIAL_IV_LEN)?;
    let header_protection_key = hkdf_expand_label(
        &client_initial_secret,
        params.hp_label,
        QUIC_INITIAL_KEY_LEN,
    )?;

    Some(QuicInitialSecrets {
        packet_protection_key: packet_protection_key.try_into().ok()?,
        initialization_vector: initialization_vector.try_into().ok()?,
        header_protection_key: header_protection_key.try_into().ok()?,
    })
}

fn hkdf_expand_label(secret: &[u8], label: &str, out_len: usize) -> Option<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).ok()?;
    hkdf_expand_label_from_hkdf(&hkdf, label, out_len)
}

fn hkdf_expand_label_from_hkdf(
    hkdf: &Hkdf<Sha256>,
    label: &str,
    out_len: usize,
) -> Option<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(full_label.len() + 4);
    info.extend_from_slice(&u16::try_from(out_len).ok()?.to_be_bytes());
    info.push(u8::try_from(full_label.len()).ok()?);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);

    let mut output = vec![0u8; out_len];
    hkdf.expand(&info, &mut output).ok()?;
    Some(output)
}

fn quic_header_protection_mask(key: &[u8; QUIC_INITIAL_KEY_LEN], sample: &[u8]) -> Option<[u8; 5]> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let mut block = GenericArray::clone_from_slice(sample.get(..QUIC_HP_SAMPLE_LEN)?);
    cipher.encrypt_block(&mut block);
    Some([block[0], block[1], block[2], block[3], block[4]])
}

fn build_quic_packet_nonce(
    iv: &[u8; QUIC_INITIAL_IV_LEN],
    packet_number: u64,
) -> [u8; QUIC_INITIAL_IV_LEN] {
    let mut nonce = *iv;
    let packet_number_bytes = packet_number.to_be_bytes();
    let packet_number_offset = nonce.len().saturating_sub(packet_number_bytes.len());
    for (index, byte) in packet_number_bytes.iter().enumerate() {
        nonce[packet_number_offset + index] ^= byte;
    }
    nonce
}

fn decode_truncated_packet_number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

fn parse_quic_varint(payload: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *payload.get(offset)?;
    let encoded_len = 1usize << usize::from(first >> 6);
    let end = offset.checked_add(encoded_len)?;
    let bytes = payload.get(offset..end)?;
    let mut value = u64::from(first & 0x3f);

    for byte in bytes.iter().skip(1) {
        value = (value << 8) | u64::from(*byte);
    }

    Some((value, encoded_len))
}

pub fn parse_http_request_metadata(payload: &[u8]) -> Option<HttpRequestMetadata> {
    let text = std::str::from_utf8(payload).ok()?;
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let header_block = &text[..header_end];
    let mut lines = header_block.lines();
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?;
    let target = request_parts.next()?;
    let version = request_parts.next()?;

    if !is_http_method(method) || !version.starts_with("HTTP/") {
        return None;
    }

    let mut host = None;
    let mut content_type = None;
    let mut accept = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let header_name = name.trim().to_ascii_lowercase();
        let header_value = value.trim();
        match header_name.as_str() {
            "host" => host = Some(header_value.to_ascii_lowercase()),
            "content-type" => content_type = Some(header_value.to_ascii_lowercase()),
            "accept" => accept = Some(header_value.to_ascii_lowercase()),
            _ => {}
        }
    }

    let host = host?;
    let host = sanitize_host_like(&host)?;
    let target_lower = target.to_ascii_lowercase();
    let is_doh = target_lower.contains("dns-query")
        || content_type
            .as_deref()
            .map(|value| value.contains("application/dns-message"))
            .unwrap_or(false)
        || accept
            .as_deref()
            .map(|value| value.contains("application/dns-message"))
            .unwrap_or(false)
        || is_known_dns_resolver_host(&host);

    Some(HttpRequestMetadata {
        host,
        target: sanitize_visible_text(target)?,
        is_doh,
    })
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

fn parse_tls_alpn_extension(extension: &[u8]) -> Option<Vec<String>> {
    if extension.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    let mut offset = 2usize;
    let mut protocols = Vec::new();

    while offset < list_end && offset < extension.len() {
        let protocol_len = *extension.get(offset)? as usize;
        offset += 1;
        let protocol_end = offset.checked_add(protocol_len)?;
        let protocol = std::str::from_utf8(extension.get(offset..protocol_end)?).ok()?;
        let protocol = sanitize_token(protocol)?.to_ascii_lowercase();
        if !protocol.is_empty() {
            protocols.push(protocol);
        }
        offset = protocol_end;
    }

    Some(protocols)
}

fn is_known_dns_resolver_host(host: &str) -> bool {
    const KNOWN_RESOLVER_SUFFIXES: &[&str] = &[
        "dns.google",
        "cloudflare-dns.com",
        "one.one.one.one",
        "family.cloudflare-dns.com",
        "security.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "dns.quad9.net",
        "dns10.quad9.net",
        "dns11.quad9.net",
        "dns.adguard-dns.com",
        "dns.nextdns.io",
        "dns.alidns.com",
        "doh.pub",
    ];

    KNOWN_RESOLVER_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
    if extension.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    let mut offset = 2usize;

    while offset + 3 <= list_end && offset + 3 <= extension.len() {
        let name_type = extension[offset];
        let name_len = u16::from_be_bytes([extension[offset + 1], extension[offset + 2]]) as usize;
        offset += 3;
        let name_end = offset.checked_add(name_len)?;
        let name = extension.get(offset..name_end)?;

        if name_type == 0 {
            let server_name = std::str::from_utf8(name).ok()?;
            let server_name = sanitize_host_like(server_name)?;
            if !server_name.is_empty() {
                return Some(server_name);
            }
        }

        offset = name_end;
    }

    None
}

fn sanitize_dns_label(label: &str) -> Option<String> {
    let normalized = label.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 63 {
        return None;
    }
    if normalized.starts_with('-') || normalized.ends_with('-') {
        return None;
    }
    if normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        Some(normalized)
    } else {
        None
    }
}

fn sanitize_host_like(value: &str) -> Option<String> {
    let normalized = value.trim().trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 255 {
        return None;
    }
    if normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '[' | ']'))
    {
        Some(normalized)
    } else {
        None
    }
}

fn sanitize_visible_text(value: &str) -> Option<String> {
    let sanitized = value
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_ascii_control())
        .collect::<String>()
        .trim()
        .to_string();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

fn sanitize_token(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 64 {
        return None;
    }
    if normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        Some(normalized)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_dns_query_name_over_tcp, parse_http_request_metadata};

    #[test]
    fn rejects_dns_names_with_control_characters() {
        let payload = [
            0x00, 0x16, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, b'w', 0x00, b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert!(parse_dns_query_name_over_tcp(&payload).is_none());
    }

    #[test]
    fn parses_http_host_as_sanitized_lowercase() {
        let payload = b"GET /dns-query HTTP/1.1\r\nHost: Example.COM\r\nAccept: application/dns-message\r\n\r\n";
        let metadata = parse_http_request_metadata(payload).expect("http metadata");
        assert_eq!(metadata.host, "example.com");
        assert_eq!(metadata.target, "/dns-query");
        assert!(metadata.is_doh);
    }
}
