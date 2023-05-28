use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use pcap::{Device, Direction};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

use crate::utilities::{get_device_ipv4, get_device_mac};

/// Perform an ARP request to get the MAC address of the specified IPv4 address.
///
/// This function will timeout after 1s if no replies are received.
pub fn resolve_addr_v4(device: Device, addr: Ipv4Addr) -> Result<MacAddr> {
    let src_mac = get_device_mac(&device).context("Device has no MAC address")?;
    let src_ip = get_device_ipv4(&device).context("Device has no IPv4 address")?;
    let mut buffer =
        [0u8; EthernetPacket::minimum_packet_size() + ArpPacket::minimum_packet_size()];
    build_arp_packet(&mut buffer, src_mac, src_ip, addr);

    let mut cap = pcap::Capture::from_device(device)?
        .immediate_mode(true)
        .timeout(1000)
        .open()?;
    cap.direction(Direction::In)?;
    cap.filter(
        &format!("arp and src host {addr} and dst host {src_ip}"),
        true,
    )?;
    cap.sendpacket(buffer)?;

    let packet = cap.next_packet()?;
    let eth = EthernetPacket::new(packet.data).unwrap();
    Ok(eth.get_source())
}

fn build_arp_packet(buffer: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(buffer).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);
    let mut arp =
        MutableArpPacket::new(&mut buffer[EthernetPacket::minimum_packet_size()..]).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);
}
