use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use rustprobe_core::{
    FlowEvent, FlowRecord, IpVersion, NetworkEndpoint, ObjectKind, ObjectRecord, PacketEvent,
    ParsedPacket, ProtocolHint, RiskLevel,
};

#[derive(Debug, Default)]
pub struct ParserStage;

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
        let (protocol, src_port, dst_port, payload_len) =
            self.parse_transport(packet.get_next_level_protocol(), payload);

        Ok(ParsedPacket {
            ip_version: IpVersion::V4,
            protocol,
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port,
            dst_port,
            payload_len,
        })
    }

    fn parse_ipv6(&self, bytes: &[u8]) -> Result<ParsedPacket> {
        let packet = Ipv6Packet::new(bytes).ok_or_else(|| anyhow!("invalid ipv6 packet"))?;
        let payload = packet.payload();
        let (protocol, src_port, dst_port, payload_len) =
            self.parse_transport(packet.get_next_header(), payload);

        Ok(ParsedPacket {
            ip_version: IpVersion::V6,
            protocol,
            src_addr: packet.get_source().to_string(),
            dst_addr: packet.get_destination().to_string(),
            src_port,
            dst_port,
            payload_len,
        })
    }

    fn parse_transport(
        &self,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        payload: &[u8],
    ) -> (ProtocolHint, Option<u16>, Option<u16>, usize) {
        match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    (
                        ProtocolHint::Tcp,
                        Some(tcp.get_source()),
                        Some(tcp.get_destination()),
                        tcp.payload().len(),
                    )
                } else {
                    (ProtocolHint::Tcp, None, None, payload.len())
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    (
                        ProtocolHint::Udp,
                        Some(udp.get_source()),
                        Some(udp.get_destination()),
                        udp.payload().len(),
                    )
                } else {
                    (ProtocolHint::Udp, None, None, payload.len())
                }
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
                (ProtocolHint::Icmp, None, None, payload.len())
            }
            _ => (ProtocolHint::Unknown, None, None, payload.len()),
        }
    }
}
