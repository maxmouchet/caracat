use std::net::Ipv4Addr;

use caracat::builder::{
    build_ethernet, build_icmp, build_icmpv6, build_ipv4, build_ipv6, build_udp, Packet,
};
use caracat::models::{L2, L3, L4};
use caracat::timestamp::encode;
use caracat::utilities::parse_as_ipv6;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{icmp, icmpv6, ipv4, udp, Packet as _};
use pnet::util::MacAddr;

#[test]
fn test_build_ipv4_icmp() {
    let src_addr = Ipv4Addr::new(192, 0, 2, 0);
    let dst_addr = Ipv4Addr::new(1, 1, 1, 1);
    let flow_id = 24000;
    let probe_id = 46837;
    let ttl = 8;
    let timestamp_enc = encode(123456);

    let mut buffer = [0u8; 65536];
    let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv4, L4::ICMP, 10);

    build_ethernet(&mut packet, MacAddr::zero(), MacAddr::zero());
    build_ipv4(&mut packet, src_addr, dst_addr, ttl, probe_id);
    build_icmp(&mut packet, flow_id, timestamp_enc);

    let ethernet = EthernetPacket::new(packet.l2()).unwrap();
    let ip = Ipv4Packet::new(ethernet.payload()).unwrap();
    assert_eq!(ip.get_checksum(), ipv4::checksum(&ip));
    assert_eq!(ip.get_source(), src_addr);
    assert_eq!(ip.get_destination(), dst_addr);
    assert_eq!(ip.get_identification(), probe_id);
    assert_eq!(ip.get_ttl(), ttl);

    let icmp = icmp::IcmpPacket::new(ip.payload()).unwrap();
    assert_eq!(icmp.get_checksum(), icmp::checksum(&icmp));
    assert_eq!(icmp.get_checksum(), flow_id);

    let echo = icmp::echo_request::EchoRequestPacket::new(ip.payload()).unwrap();
    assert_eq!(echo.get_identifier(), flow_id);
    assert_eq!(echo.get_sequence_number(), timestamp_enc);
}

#[test]
fn test_build_ipv6_icmpv6() {
    let src_addr = parse_as_ipv6("2a04:8ec0:0:164:620c:e59a:daf8:21e9").unwrap();
    let dst_addr = parse_as_ipv6("2001:4860:4860::8888").unwrap();
    let flow_id = 24000;
    let ttl = 8;
    let timestamp_enc = encode(123456);

    let mut buffer = [0u8; 65536];
    let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv6, L4::ICMPv6, 10);

    build_ethernet(&mut packet, MacAddr::zero(), MacAddr::zero());
    build_ipv6(&mut packet, src_addr, dst_addr, ttl);
    build_icmpv6(&mut packet, flow_id, timestamp_enc);

    let ethernet = EthernetPacket::new(packet.l2()).unwrap();
    let ip = Ipv6Packet::new(ethernet.payload()).unwrap();
    assert_eq!(ip.get_source(), src_addr);
    assert_eq!(ip.get_destination(), dst_addr);
    assert_eq!(ip.get_hop_limit(), ttl);

    let icmp = icmpv6::Icmpv6Packet::new(ip.payload()).unwrap();
    assert_eq!(
        icmp.get_checksum(),
        icmpv6::checksum(&icmp, &src_addr, &dst_addr)
    );
    assert_eq!(icmp.get_checksum(), flow_id);

    let echo = icmpv6::echo_request::EchoRequestPacket::new(ip.payload()).unwrap();
    assert_eq!(echo.get_identifier(), flow_id);
    assert_eq!(echo.get_sequence_number(), timestamp_enc);
}

#[test]
fn test_build_ipv4_udp() {
    let src_addr = Ipv4Addr::new(192, 0, 2, 0);
    let dst_addr = Ipv4Addr::new(1, 1, 1, 1);
    let src_port = 24000;
    let dst_port = 33434;
    let probe_id = 46837;
    let ttl = 8;
    let timestamp_enc = encode(123456);

    let mut buffer = [0u8; 65536];
    let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv4, L4::UDP, 10);

    build_ethernet(&mut packet, MacAddr::zero(), MacAddr::zero());
    build_ipv4(&mut packet, src_addr, dst_addr, ttl, probe_id);
    build_udp(&mut packet, timestamp_enc, src_port, dst_port);

    let ethernet = EthernetPacket::new(packet.l2()).unwrap();
    let ip = Ipv4Packet::new(ethernet.payload()).unwrap();
    assert_eq!(ip.get_checksum(), ipv4::checksum(&ip));
    assert_eq!(ip.get_source(), src_addr);
    assert_eq!(ip.get_destination(), dst_addr);
    assert_eq!(ip.get_identification(), probe_id);
    assert_eq!(ip.get_ttl(), ttl);

    let udp = UdpPacket::new(ip.payload()).unwrap();
    assert_eq!(
        udp.get_checksum(),
        udp::ipv4_checksum(&udp, &src_addr, &dst_addr)
    );
    assert_eq!(udp.get_checksum(), timestamp_enc);
    assert_eq!(udp.get_source(), src_port);
    assert_eq!(udp.get_destination(), dst_port);
}

#[test]
fn test_build_ipv6_udp() {
    let src_addr = parse_as_ipv6("2a04:8ec0:0:164:620c:e59a:daf8:21e9").unwrap();
    let dst_addr = parse_as_ipv6("2001:4860:4860::8888").unwrap();
    let src_port = 24000;
    let dst_port = 33434;
    let ttl = 8;
    let timestamp_enc = encode(123456);

    let mut buffer = [0u8; 65536];
    let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv6, L4::UDP, 10);

    build_ethernet(&mut packet, MacAddr::zero(), MacAddr::zero());
    build_ipv6(&mut packet, src_addr, dst_addr, ttl);
    build_udp(&mut packet, timestamp_enc, src_port, dst_port);

    let ethernet = EthernetPacket::new(packet.l2()).unwrap();
    let ip = Ipv6Packet::new(ethernet.payload()).unwrap();
    assert_eq!(ip.get_source(), src_addr);
    assert_eq!(ip.get_destination(), dst_addr);
    assert_eq!(ip.get_hop_limit(), ttl);

    let udp = UdpPacket::new(ip.payload()).unwrap();
    assert_eq!(
        udp.get_checksum(),
        udp::ipv6_checksum(&udp, &src_addr, &dst_addr)
    );
    assert_eq!(udp.get_checksum(), timestamp_enc);
    assert_eq!(udp.get_source(), src_port);
    assert_eq!(udp.get_destination(), dst_port);
}
