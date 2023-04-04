use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::datalink::MacAddr;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{icmp, icmpv6, Packet as _};
use pnet::util;
use pnet::util::checksum;

use crate::builder::Packet;
use crate::models::L3;

/// Build the BSD/macOS Loopback header.
///
/// On Linux the loopback interface uses the Ethernet header,
/// but on macOS it uses a different 32-bit header.
pub fn build_loopback(packet: &mut Packet) {
    let l3_protocol = packet.l3_protocol();
    let loopback = packet.l2_mut();
    match l3_protocol {
        L3::IPv4 => {
            loopback[0] = 0x02;
            loopback[1] = 0x00;
            loopback[2] = 0x00;
            loopback[3] = 0x00;
        }
        L3::IPv6 => {
            loopback[0] = 0x30;
            loopback[1] = 0x00;
            loopback[2] = 0x00;
            loopback[3] = 0x00;
        }
    }
}

/// Build the Ethernet header.
pub fn build_ethernet(packet: &mut Packet, src_addr: MacAddr, dst_addr: MacAddr) {
    let ethertype = packet.l3_protocol();
    let mut ethernet = MutableEthernetPacket::new(packet.l2_mut()).unwrap();
    ethernet.set_source(src_addr);
    ethernet.set_destination(dst_addr);
    ethernet.set_ethertype(ethertype.into());
}

/// Build the IPv4 header.
///
/// In the IP header, the type of service, protocol, source and destination
/// address fields are used for per-flow load-balancing.
/// We also encode the TTL in the ID field in order to retrieve it in the ICMP
/// destination unreachable/TTL exceeded messages since the TTL field is
/// decreased/modified at each hop.
pub fn build_ipv4(packet: &mut Packet, src_addr: Ipv4Addr, dst_addr: Ipv4Addr, ttl: u8, id: u16) {
    let next_level_protocol = packet.l4_protocol();
    let total_length = packet.l3_size();
    let mut ip = MutableIpv4Packet::new(packet.l3_mut()).unwrap();
    ip.set_header_length(5);
    ip.set_version(4);
    ip.set_dscp(0);
    ip.set_ecn(0);
    ip.set_next_level_protocol(next_level_protocol.into());
    ip.set_source(src_addr);
    ip.set_destination(dst_addr);
    ip.set_ttl(ttl);
    ip.set_identification(id);
    ip.set_total_length(total_length);
    ip.set_checksum(checksum(ip.packet(), 5))
}

/// Build the IPv6 header.
pub fn build_ipv6(packet: &mut Packet, src_addr: Ipv6Addr, dst_addr: Ipv6Addr, ttl: u8) {
    let next_header = packet.l4_protocol();
    let payload_length = packet.l4_size();
    let mut ip = MutableIpv6Packet::new(packet.l3_mut()).unwrap();
    // We cannot store the TTL in the flow-ID field, since it is used for LB,
    // unlike IPv4. We rely on the payload length instead.
    // https://homepages.dcc.ufmg.br/~cunha/papers/almeida17pam-mda6.pdf
    ip.set_version(6);
    ip.set_traffic_class(0);
    ip.set_flow_label(0);
    ip.set_next_header(next_header.into());
    ip.set_source(src_addr);
    ip.set_destination(dst_addr);
    ip.set_hop_limit(ttl);
    ip.set_payload_length(payload_length);
}

/// Build the ICMP Echo Request header and payload.
///
/// In the ICMP echo header, the code and checksum fields are used for per-flow
/// load-balancing. We encode the flow ID in the checksum field to vary the flow
/// ID, and in the id field. We encode the timestamp in the sequence field.
/// Since echo replies, in contrast to destination unreachable messages, doesn't
/// contain the original probe packet (including the original TTL and flow ID),
/// we ignore them in the packet parser.
pub fn build_icmp(packet: &mut Packet, target_checksum: u16, target_sequence: u16) {
    let mut icmp = icmp::echo_request::MutableEchoRequestPacket::new(packet.l4_mut()).unwrap();
    icmp.set_icmp_type(icmp::IcmpTypes::EchoRequest);
    icmp.set_icmp_code(icmp::echo_request::IcmpCodes::NoCode);
    icmp.set_identifier(target_checksum);
    icmp.set_sequence_number(target_sequence);
    icmp.set_checksum(target_checksum);
    let original_checksum = util::checksum(icmp.packet(), 1);
    packet
        .payload_mut()
        .write_all(&payload_for_checksum(original_checksum, target_checksum).to_be_bytes())
        .unwrap();
}

/// Build the ICMPv6 Echo Request header and payload.
pub fn build_icmpv6(packet: &mut Packet, target_checksum: u16, target_sequence: u16) {
    let mut icmp = icmpv6::echo_request::MutableEchoRequestPacket::new(packet.l4_mut()).unwrap();
    icmp.set_icmpv6_type(icmpv6::Icmpv6Types::EchoRequest);
    icmp.set_icmpv6_code(icmpv6::echo_request::Icmpv6Codes::NoCode);
    icmp.set_identifier(target_checksum);
    icmp.set_sequence_number(target_sequence);
    icmp.set_checksum(target_checksum);
    let original_checksum = transport_checksum(packet, 1);
    packet
        .payload_mut()
        .write_all(&payload_for_checksum(original_checksum, target_checksum).to_be_bytes())
        .unwrap();
}

/// Build the UDP header and payload.
///
/// In the UDP header, the source and destination ports are used for per-flow
/// load-balancing. We use those for encoding the flow ID, and we encode the
/// timestamp in the checksum (which doesn't affect the flow ID).
/// The TTL is encoded in the payload length, in addition to the TTL field in
/// the IP header. The payload is all zeros, except two bytes used to ensure
/// that the custom checksum is valid.
pub fn build_udp(packet: &mut Packet, target_checksum: u16, src_port: u16, dst_port: u16) {
    let length = packet.l4_size();
    let mut udp = MutableUdpPacket::new(packet.l4_mut()).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length(length);
    udp.set_checksum(target_checksum);
    let original_checksum = transport_checksum(packet, 3);
    packet
        .payload_mut()
        .write_all(&payload_for_checksum(original_checksum, target_checksum).to_be_bytes())
        .unwrap();
}

/// Return the two bytes of the payload to ensure that the target checksum is valid.
fn payload_for_checksum(original_checksum: u16, target_checksum: u16) -> u16 {
    let original_ = !original_checksum as u32 & 0xFFFF;
    let mut target_ = !target_checksum as u32 & 0xFFFF;
    if target_ < original_ {
        target_ += 0xFFFF;
    }
    (target_ - original_) as u16
}

fn transport_checksum(packet: &Packet, skipword: usize) -> u16 {
    let l4 = packet.l4();
    match packet.l3_protocol() {
        L3::IPv4 => {
            let ip = Ipv4Packet::new(packet.l3()).unwrap();
            util::ipv4_checksum(
                l4,
                skipword,
                &[],
                &ip.get_source(),
                &ip.get_destination(),
                packet.l4_protocol().into(),
            )
        }
        L3::IPv6 => {
            let ip = Ipv6Packet::new(packet.l3()).unwrap();
            util::ipv6_checksum(
                l4,
                skipword,
                &[],
                &ip.get_source(),
                &ip.get_destination(),
                packet.l4_protocol().into(),
            )
        }
    }
}
