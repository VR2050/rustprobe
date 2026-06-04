use anyhow::{Result, anyhow};
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

#[derive(Debug, Default)]
pub struct ParserStage;

#[derive(Debug)]
struct TransportParseResult {
    protocol: ProtocolHint,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    payload_len: usize,
    dns_query_name: Option<String>,
    tls_server_name: Option<String>,
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
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            payload_len: transport.payload_len,
            dns_query_name: transport.dns_query_name,
            tls_server_name: transport.tls_server_name,
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
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port: transport.src_port,
            dst_port: transport.dst_port,
            payload_len: transport.payload_len,
            dns_query_name: transport.dns_query_name,
            tls_server_name: transport.tls_server_name,
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
                    let tls_server_name = if tcp.get_source() == 443 || tcp.get_destination() == 443
                    {
                        parse_tls_client_hello_server_name(tcp.payload())
                    } else {
                        None
                    };

                    TransportParseResult {
                        protocol: if tls_server_name.is_some() {
                            ProtocolHint::Tls
                        } else {
                            ProtocolHint::Tcp
                        },
                        src_port: Some(tcp.get_source()),
                        dst_port: Some(tcp.get_destination()),
                        payload_len: tcp.payload().len(),
                        dns_query_name: None,
                        tls_server_name,
                        transport_payload: payload_prefix(tcp.payload()),
                    }
                } else {
                    TransportParseResult {
                        protocol: ProtocolHint::Tcp,
                        src_port: None,
                        dst_port: None,
                        payload_len: payload.len(),
                        dns_query_name: None,
                        tls_server_name: None,
                        transport_payload: Vec::new(),
                    }
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    let dns_query_name = if udp.get_source() == 53 || udp.get_destination() == 53 {
                        parse_dns_query_name(udp.payload())
                    } else {
                        None
                    };

                    TransportParseResult {
                        protocol: if dns_query_name.is_some() {
                            ProtocolHint::Dns
                        } else {
                            ProtocolHint::Udp
                        },
                        src_port: Some(udp.get_source()),
                        dst_port: Some(udp.get_destination()),
                        payload_len: udp.payload().len(),
                        dns_query_name,
                        tls_server_name: None,
                        transport_payload: payload_prefix(udp.payload()),
                    }
                } else {
                    TransportParseResult {
                        protocol: ProtocolHint::Udp,
                        src_port: None,
                        dst_port: None,
                        payload_len: payload.len(),
                        dns_query_name: None,
                        tls_server_name: None,
                        transport_payload: Vec::new(),
                    }
                }
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => TransportParseResult {
                protocol: ProtocolHint::Icmp,
                src_port: None,
                dst_port: None,
                payload_len: payload.len(),
                dns_query_name: None,
                tls_server_name: None,
                transport_payload: Vec::new(),
            },
            _ => TransportParseResult {
                protocol: ProtocolHint::Unknown,
                src_port: None,
                dst_port: None,
                payload_len: payload.len(),
                dns_query_name: None,
                tls_server_name: None,
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

fn parse_dns_query_name(payload: &[u8]) -> Option<String> {
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
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn parse_tls_client_hello_server_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 9 {
        return None;
    }

    if payload[0] != 22 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_end = 5usize.checked_add(record_len)?;
    let record = payload.get(5..record_end)?;

    if record.len() < 4 || record[0] != 1 {
        return None;
    }

    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    let body = record.get(4..4usize.checked_add(handshake_len)?)?;
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

    while offset + 4 <= extensions_end && offset + 4 <= body.len() {
        let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let ext_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        let ext_end = offset.checked_add(ext_len)?;
        let ext_data = body.get(offset..ext_end)?;

        if ext_type == 0 {
            return parse_tls_sni_extension(ext_data);
        }

        offset = ext_end;
    }

    None
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
            let server_name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            if !server_name.is_empty() {
                return Some(server_name);
            }
        }

        offset = name_end;
    }

    None
}
