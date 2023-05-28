use std::net::Ipv6Addr;

use anyhow::{Context, Result};

use pcap::{Device, Direction};
use pnet::datalink::MacAddr;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6;
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborSolicitPacket};

use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::Packet;

use crate::utilities::{get_device_ipv6, get_device_mac};

/// Perform an NDP request to get the MAC address of the specified IPv6 address.
///
/// This function will timeout after 1s if no replies are received.
pub fn resolve_addr_v6(device: Device, addr: Ipv6Addr) -> Result<MacAddr> {
    let src_mac = get_device_mac(&device).context("Device has no MAC address")?;
    let src_ip = get_device_ipv6(&device).context("Device has no IPv6 address")?;
    let mut buffer = [0u8; EthernetPacket::minimum_packet_size()
        + Ipv6Packet::minimum_packet_size()
        + NeighborSolicitPacket::minimum_packet_size()];
    build_ndp_packet(&mut buffer, src_mac, src_ip, addr);

    let mut cap = pcap::Capture::from_device(device)?
        .immediate_mode(true)
        .timeout(1000)
        .open()?;
    cap.direction(Direction::In)?;
    cap.filter(
        &format!(
            "ip6 and icmp6 and icmp6[icmp6type] = icmp6-neighboradvert
            and src host {addr} and dst host {src_ip}"
        ),
        true,
    )?;
    cap.sendpacket(buffer)?;

    let packet = cap.next_packet()?;
    let eth = EthernetPacket::new(packet.data).unwrap();
    Ok(eth.get_source())
}

fn build_ndp_packet(buffer: &mut [u8], src_mac: MacAddr, src_ip: Ipv6Addr, target_ip: Ipv6Addr) {
    // TODO: Use solicited-node multicast address instead of ff02::1 (all nodes)?
    let dst_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1);

    let mut eth = MutableEthernetPacket::new(buffer).unwrap();
    eth.set_destination(MacAddr::new(0x33, 0x33, 0, 0, 0, 0x1));
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv6);

    let mut ip =
        MutableIpv6Packet::new(&mut buffer[EthernetPacket::minimum_packet_size()..]).unwrap();
    ip.set_version(6);
    ip.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    ip.set_hop_limit(255);
    ip.set_payload_length(NeighborSolicitPacket::minimum_packet_size() as u16);

    let mut icmp = MutableNeighborSolicitPacket::new(
        &mut buffer[EthernetPacket::minimum_packet_size() + Ipv6Packet::minimum_packet_size()..],
    )
    .unwrap();
    icmp.set_icmpv6_type(icmpv6::Icmpv6Types::NeighborSolicit);
    icmp.set_icmpv6_code(icmpv6::ndp::Icmpv6Codes::NoCode);
    icmp.set_target_addr(target_ip);
    icmp.set_checksum(
        icmpv6::checksum(&Icmpv6Packet::new(icmp.packet()).unwrap(), &src_ip, &dst_ip).to_le(),
    );
}
