//! Function for parsing replies.
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use pcap::{Linktype, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{icmp, icmpv6, Packet as _};

use crate::models::Reply;
use crate::timestamp::{difference, tenth_ms};

/// Parse a packet into a reply.
pub fn parse(packet: &Packet, linktype: Linktype) -> Result<Reply> {
    let capture_timestamp = Duration::from_micros(
        packet.header.ts.tv_sec as u64 * 1_000_000 + packet.header.ts.tv_usec as u64,
    );

    let mut reply = Reply {
        capture_timestamp,
        ..Default::default()
    };

    // TODO: Add same comments as in caracat source code.
    // TODO: Split in functions for readability?
    // handle_ipv4 => handle_echo_reply ...
    match IpPacket::new(packet, linktype)? {
        IpPacket::Ipv4(ip) => {
            parse_outer_ipv4(&mut reply, &ip);
            match ip.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    // IPv4 → ICMP
                    let icmp = IcmpPacket::new(ip.payload()).context("Cannot build ICMP header")?;
                    match icmp.get_icmp_type() {
                        icmp::IcmpTypes::DestinationUnreachable | icmp::IcmpTypes::TimeExceeded => {
                            // IPv4 → ICMP (DE/TE)
                            parse_outer_icmp(&mut reply, &icmp);
                            // ICMP DE/TE messages contains the original payload 4 bytes after the ICMP checksum.
                            let inner_ip = icmp
                                .payload()
                                .get(4..)
                                .and_then(Ipv4Packet::new)
                                .context("Cannot build inner IP header")?;
                            // IPv4 → ICMP (DE/TE) → IPv4
                            parse_inner_ipv4(&mut reply, &inner_ip);
                            match inner_ip.get_next_level_protocol() {
                                IpNextHeaderProtocols::Icmp => {
                                    // IPv4 → ICMP (DE/TE) → IPv4 → ICMP
                                    let inner_icmp = IcmpPacket::new(inner_ip.payload())
                                        .context("Cannot build inner ICMP header")?;
                                    match inner_icmp.get_icmp_type() {
                                        icmp::IcmpTypes::EchoRequest => {
                                            // IPv4 → ICMP (DE/TE) → IPv4 → ICMP (ER)
                                            let inner_echo =
                                                icmp::echo_request::EchoRequestPacket::new(
                                                    inner_ip.payload(),
                                                )
                                                .context(
                                                    "Cannot build inner ICMP Echo Request header",
                                                )?;
                                            parse_inner_icmp(
                                                &mut reply,
                                                &inner_echo,
                                                capture_timestamp,
                                            );
                                            parse_inner_ttl_ipv4(&mut reply, &inner_ip);
                                        }
                                        other => {
                                            bail!(
                                                "Unsupported inner ICMP message type: {:?}",
                                                other
                                            )
                                        }
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    // IPv4 → ICMP (DE/TE) → IPv4 → UDP
                                    let inner_udp = UdpPacket::new(inner_ip.payload())
                                        .context("Cannot build inner UDP header")?;
                                    parse_inner_udp(&mut reply, &inner_udp, capture_timestamp);
                                }
                                other => bail!("Unsupported inner L4 protocol: {:?}", other),
                            }
                        }
                        icmp::IcmpTypes::EchoReply => {
                            // IPv4 → ICMPv4 (Echo Reply)
                            // NOTE: EchoRequestPacket is the same as EchoReplyPacket.
                            let echo = icmp::echo_request::EchoRequestPacket::new(ip.payload())
                                .context("Cannot build ICMP Echo Reply header")?;
                            parse_outer_icmp(&mut reply, &icmp);
                            parse_inner_icmp(&mut reply, &echo, capture_timestamp);
                            parse_inner_ttl_ipv4(&mut reply, &ip);
                            // Since there is no quoted ICMP header in an echo reply, we cannot retrieve
                            // the *true* probe destination address. In previous versions of caracat,
                            // we used to leave the `probe_dst_addr` field empty to indicate this.
                            // However, this complicates downstream code, and in the vast majority of
                            // the cases, the reply comes from the probe destination.
                            // Users can still filter-out echo replies if they fear to infer false
                            // links.
                            reply.probe_dst_addr = reply.reply_src_addr;
                        }
                        other => bail!("Unsupported ICMP message type: {:?}", other),
                    }
                }
                other => bail!("Unsupported L4 protocol: {:?}", other),
            }
        }
        IpPacket::Ipv6(ip) => {
            parse_outer_ipv6(&mut reply, &ip);
            match ip.get_next_header() {
                IpNextHeaderProtocols::Icmpv6 => {
                    // IPv6 → ICMP
                    let icmp =
                        Icmpv6Packet::new(ip.payload()).context("Cannot build ICMPv6 header")?;
                    match icmp.get_icmpv6_type() {
                        icmpv6::Icmpv6Types::DestinationUnreachable
                        | icmpv6::Icmpv6Types::TimeExceeded => {
                            // IPv6 → ICMPv6 (DE/TE)
                            parse_outer_icmpv6(&mut reply, &icmp);
                            // ICMPv6 DE/TE messages contains the original payload 4 bytes after the ICMP checksum.
                            let inner_ip = icmp
                                .payload()
                                .get(4..)
                                .and_then(Ipv6Packet::new)
                                .context("Cannot build inner IPv6 header")?;
                            // IPv6 → ICMPv6 (DE/TE) → IPv6
                            parse_inner_ipv6(&mut reply, &inner_ip);
                            match inner_ip.get_next_header() {
                                IpNextHeaderProtocols::Icmpv6 => {
                                    // IPv6 → ICMPv6 (DE/TE) → IPv6 → ICMPv6
                                    let inner_icmp = Icmpv6Packet::new(inner_ip.payload())
                                        .context("Cannot build inner ICMPv6 header")?;
                                    match inner_icmp.get_icmpv6_type() {
                                        icmpv6::Icmpv6Types::EchoRequest => {
                                            // IPv6 → ICMPv6 (DE/TE) → IPv6 → ICMPv6 (ER)
                                            let inner_echo =
                                                icmpv6::echo_request::EchoRequestPacket::new(
                                                    inner_ip.payload(),
                                                )
                                                .context(
                                                    "Cannot build inner ICMPv6 Echo Request header",
                                                )?;
                                            parse_inner_icmpv6(
                                                &mut reply,
                                                &inner_echo,
                                                capture_timestamp,
                                            );
                                            parse_inner_ttl_ipv6(&mut reply, &inner_ip);
                                        }
                                        other => {
                                            bail!(
                                                "Unsupported inner ICMPv6 message type: {:?}",
                                                other
                                            )
                                        }
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    // IPv6 → ICMPv6 (DE/TE) → IPv6 → UDP
                                    let inner_udp = UdpPacket::new(inner_ip.payload())
                                        .context("Cannot build inner UDP header")?;
                                    parse_inner_udp(&mut reply, &inner_udp, capture_timestamp);
                                }
                                other => bail!("Unsupported inner L4 protocol: {:?}", other),
                            }
                        }
                        icmpv6::Icmpv6Types::EchoReply => {
                            // IPv6 → ICMPv6 (Echo Reply)
                            // NOTE: EchoRequestPacket is the same as EchoReplyPacket.
                            let echo = icmpv6::echo_request::EchoRequestPacket::new(ip.payload())
                                .context("Cannot build ICMP Echo Reply header")?;
                            parse_outer_icmpv6(&mut reply, &icmp);
                            parse_inner_icmpv6(&mut reply, &echo, capture_timestamp);
                            parse_inner_ttl_ipv6(&mut reply, &ip);
                            // Same remark as for ICMP(v4) echo replies.
                            reply.probe_dst_addr = reply.reply_src_addr;
                        }
                        other => bail!("Unsupported ICMP message type: {:?}", other),
                    }
                }
                other => bail!("Unsupported L4 protocol: {:?}", other),
            }
        }
    }

    Ok(reply)
}

fn parse_outer_ipv4(reply: &mut Reply, ip: &Ipv4Packet) {
    reply.reply_src_addr = IpAddr::V4(ip.get_source());
    reply.reply_dst_addr = IpAddr::V4(ip.get_destination());
    reply.reply_id = ip.get_identification();
    reply.reply_size = ip.get_total_length();
    reply.reply_ttl = ip.get_ttl();
}

fn parse_outer_ipv6(reply: &mut Reply, ip: &Ipv6Packet) {
    reply.reply_src_addr = IpAddr::V6(ip.get_source());
    reply.reply_dst_addr = IpAddr::V6(ip.get_destination());
    reply.reply_id = 0; // Not implemented for IPv6.
    reply.reply_size = ip.get_payload_length();
    reply.reply_ttl = ip.get_hop_limit();
}

fn parse_outer_icmp(reply: &mut Reply, icmp: &IcmpPacket) {
    reply.reply_protocol = IpNextHeaderProtocols::Icmp.0;
    reply.reply_icmp_type = icmp.get_icmp_type().0;
    reply.reply_icmp_code = icmp.get_icmp_code().0;
    // TODO: Extensions
}

fn parse_outer_icmpv6(reply: &mut Reply, icmp: &Icmpv6Packet) {
    reply.reply_protocol = IpNextHeaderProtocols::Icmpv6.0;
    reply.reply_icmp_type = icmp.get_icmpv6_type().0;
    reply.reply_icmp_code = icmp.get_icmpv6_code().0;
    // TODO: Extensions
}

fn parse_inner_ipv4(reply: &mut Reply, ip: &Ipv4Packet) {
    reply.probe_dst_addr = IpAddr::V4(ip.get_destination());
    reply.probe_id = ip.get_identification();
    reply.probe_size = ip.get_total_length();
    reply.quoted_ttl = ip.get_ttl();
}

fn parse_inner_ipv6(reply: &mut Reply, ip: &Ipv6Packet) {
    reply.probe_dst_addr = IpAddr::V6(ip.get_destination());
    reply.probe_id = 0; // Not implemented for IPv6.
    reply.probe_size = ip.get_payload_length();
    reply.quoted_ttl = ip.get_hop_limit();
}

/// Parse the Echo Request packet embedded in ICMP Destination Unreachable and Time Exceeded messages.
/// This is also used to parse Echo Reply packets.
fn parse_inner_icmp(
    reply: &mut Reply,
    icmp: &icmp::echo_request::EchoRequestPacket,
    timestamp: Duration,
) {
    reply.probe_protocol = IpNextHeaderProtocols::Icmp.0;
    reply.probe_src_port = icmp.get_identifier();
    reply.probe_dst_port = 0;
    reply.rtt = difference(tenth_ms(timestamp), icmp.get_sequence_number());
}

fn parse_inner_icmpv6(
    reply: &mut Reply,
    icmp: &icmpv6::echo_request::EchoRequestPacket,
    timestamp: Duration,
) {
    reply.probe_protocol = IpNextHeaderProtocols::Icmpv6.0;
    reply.probe_src_port = icmp.get_identifier();
    reply.probe_dst_port = 0;
    reply.rtt = difference(tenth_ms(timestamp), icmp.get_sequence_number());
}

fn parse_inner_udp(reply: &mut Reply, udp: &UdpPacket, timestamp: Duration) {
    reply.probe_protocol = IpNextHeaderProtocols::Udp.0;
    reply.probe_src_port = udp.get_source();
    reply.probe_dst_port = udp.get_destination();
    // TODO: Use proper constants.
    let offset = UdpPacket::minimum_packet_size() as u16 + 2;
    if udp.get_length() >= offset {
        reply.probe_ttl = (udp.get_length() - offset) as u8;
    }
    reply.rtt = difference(tenth_ms(timestamp), udp.get_checksum());
}

/// Retrieve the TTL embedded in the IP packet length for ICMP probes.
fn parse_inner_ttl_ipv4(reply: &mut Reply, ip: &Ipv4Packet) {
    // TODO: Use proper constants.
    // TODO: This can overflow and panic.
    reply.probe_ttl =
        (ip.get_total_length() - Ipv4Packet::minimum_packet_size() as u16 - 8 - 2) as u8;
}

fn parse_inner_ttl_ipv6(reply: &mut Reply, ip: &Ipv6Packet) {
    // TODO: Use proper constants.
    // TODO: This can overflow and panic.
    reply.probe_ttl = (ip.get_payload_length() - 8 - 2) as u8;
}

enum IpPacket<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn new(packet: &Packet<'a>, linktype: Linktype) -> Result<Self> {
        match linktype {
            Linktype::NULL => {
                // TODO: This is u32 not u8.
                let loopback = packet
                    .data
                    .first()
                    .context("Cannot build loopback header")?;
                match loopback {
                    0x02 => packet
                        .data
                        .get(4..)
                        .and_then(Ipv4Packet::new)
                        .context("Cannot build IPv4 header")
                        .map(Self::Ipv4),
                    0x30 => packet
                        .data
                        .get(4..)
                        .and_then(Ipv6Packet::new)
                        .context("Cannot build IPv6 header")
                        .map(Self::Ipv6),
                    other => bail!("Unsupported L3 protocol: {}", other),
                }
            }
            Linktype::ETHERNET => {
                let ethernet =
                    EthernetPacket::new(packet.data).context("Cannot build Ethernet header")?;
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => packet
                        .data
                        // TODO: Use ethernet.payload() here (lifetime issue)?
                        .get(14..)
                        .and_then(Ipv4Packet::new)
                        .context("Cannot build IPv4 header")
                        .map(Self::Ipv4),
                    EtherTypes::Ipv6 => packet
                        .data
                        // TODO: Use ethernet.payload() here (lifetime issue)?
                        .get(14..)
                        .and_then(Ipv6Packet::new)
                        .context("Cannot build IPv6 header")
                        .map(Self::Ipv6),
                    other => bail!("Unsupported L3 protocol: {}", other),
                }
            }
            Linktype(12) => {
                let version = packet
                    .data
                    .first()
                    .map(|x| x >> 4)
                    .context("Empty packet")?;
                match version {
                    4 => Ipv4Packet::new(packet.data)
                        .context("Cannot build IPv4 header")
                        .map(Self::Ipv4),
                    6 => Ipv6Packet::new(packet.data)
                        .context("Cannot build IPv6 header")
                        .map(Self::Ipv6),
                    other => bail!("Unsupported IP version: {}", other),
                }
            }
            other => bail!("Unsupported link type: {:?}", other),
        }
    }
}
