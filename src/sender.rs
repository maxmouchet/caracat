//! Send probes on the network.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use log::info;
use pcap::{Active, Capture, Linktype};
use pnet::util::MacAddr;

use crate::builder::{
    build_ethernet, build_icmp, build_icmpv6, build_ipv4, build_ipv6, build_loopback, build_tcp,
    build_udp, Packet,
};
use crate::models::{Probe, L2, L4};
use crate::neighbors::{resolve_mac_address, RoutingTable};
use crate::timestamp::{encode, tenth_ms};
use crate::utilities::{get_ipv4_address, get_ipv6_address, get_mac_address};

pub struct Sender {
    // TODO: Check that we do not allocate more than the C++ version.
    buffer: [u8; 65536],
    dry_run: bool,
    handle: Capture<Active>,
    instance_id: u16,
    l2_protocol: L2,
    src_mac: MacAddr,
    dst_mac_v4: MacAddr,
    dst_mac_v6: MacAddr,
    src_ip_v4: Ipv4Addr,
    src_ip_v6: Ipv6Addr,
}

impl Sender {
    // TODO: Parameter for gateway resolution address.
    //       Accept gateway MAC address and do resolution upstream?
    pub fn new(
        interface: &str,
        ipv4_src_addr: Option<Ipv4Addr>,
        ipv6_src_addr: Option<Ipv6Addr>,
        instance_id: u16,
        dry_run: bool,
    ) -> Result<Self> {
        let handle = pcap::Capture::from_device(interface)?
            .buffer_size(0)
            .snaplen(0)
            .open()?;

        let l2_protocol = match handle.get_datalink() {
            Linktype::NULL => L2::BSDLoopback,
            Linktype::ETHERNET => L2::Ethernet,
            Linktype(12) => L2::None,
            other => bail!(
                "Unsupported link type: {} ({})",
                other.get_name().unwrap(),
                other.0
            ),
        };

        let src_mac: MacAddr;
        let dst_mac_v4: MacAddr;
        let dst_mac_v6: MacAddr;

        if l2_protocol == L2::Ethernet {
            src_mac = get_mac_address(interface).context("Ethernet device has no MAC address")?;
            let table = RoutingTable::from_native()?;
            // TODO: Warn if no v4 or v6 dst MAC.
            dst_mac_v4 = table
                .default_route_v4()
                .and_then(|r| resolve_mac_address(interface, r.gateway).ok())
                .unwrap_or(MacAddr::zero());
            dst_mac_v6 = table
                .default_route_v6()
                .and_then(|r| resolve_mac_address(interface, r.gateway).ok())
                .unwrap_or(MacAddr::zero());
        } else {
            src_mac = MacAddr::zero();
            dst_mac_v4 = MacAddr::zero();
            dst_mac_v6 = MacAddr::zero();
        }

        let src_ip_v4 =
            ipv4_src_addr.unwrap_or(get_ipv4_address(interface).unwrap_or(Ipv4Addr::UNSPECIFIED));
        let src_ip_v6 =
            ipv6_src_addr.unwrap_or(get_ipv6_address(interface).unwrap_or(Ipv6Addr::UNSPECIFIED));

        info!(
            "src_mac={} dst_mac_v4={} dst_mac_v6={}",
            src_mac.to_string(),
            dst_mac_v4.to_string(),
            dst_mac_v6.to_string()
        );
        info!("src_ip_v4={} src_ip_v6={}", src_ip_v4, src_ip_v6);

        Ok(Sender {
            buffer: [0u8; 65536],
            dry_run,
            handle,
            instance_id,
            l2_protocol,
            src_mac,
            dst_mac_v4,
            dst_mac_v6,
            src_ip_v4,
            src_ip_v6,
        })
    }

    pub fn send(&mut self, probe: &Probe) -> Result<()> {
        let l3_protocol = probe.l3_protocol();
        let l4_protocol = probe.l4_protocol();

        let timestamp = tenth_ms(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        let timestamp_enc = encode(timestamp);

        // TODO: PAYLOAD_TWEAK_BYTES constant
        // TODO: ICMP_HEADER_SIZE constant
        // TCP probes don't need a payload; for other protocols we encode the TTL in the payload
        let payload_size = match l4_protocol {
            L4::TCP => 0,
            _ => probe.ttl as usize + 2,
        };
        let mut packet = Packet::new(
            &mut self.buffer,
            self.l2_protocol,
            l3_protocol,
            l4_protocol,
            payload_size,
        );
        packet.l2_mut().fill(0);

        match self.l2_protocol {
            L2::BSDLoopback => build_loopback(&mut packet),
            L2::Ethernet => match probe.dst_addr {
                IpAddr::V4(_) => build_ethernet(&mut packet, self.src_mac, self.dst_mac_v4),
                IpAddr::V6(_) => build_ethernet(&mut packet, self.src_mac, self.dst_mac_v6),
            },
            L2::None => {}
        }

        match probe.dst_addr {
            IpAddr::V4(dst_addr) => build_ipv4(
                &mut packet,
                self.src_ip_v4,
                dst_addr,
                probe.ttl,
                probe.checksum(self.instance_id),
            ),
            IpAddr::V6(dst_addr) => build_ipv6(&mut packet, self.src_ip_v6, dst_addr, probe.ttl),
        }

        match l4_protocol {
            L4::ICMP => build_icmp(&mut packet, probe.src_port, timestamp_enc),
            L4::ICMPv6 => build_icmpv6(&mut packet, probe.src_port, timestamp_enc),
            L4::UDP => build_udp(&mut packet, timestamp_enc, probe.src_port, probe.dst_port),
            L4::TCP => {
                // Encode both timestamp (lower 16 bits) and TTL (bits 16-23) in sequence number
                let sequence = (timestamp_enc as u32) | ((probe.ttl as u32) << 16);
                build_tcp(&mut packet, probe.src_port, probe.dst_port, sequence)
            }
        }

        if !self.dry_run {
            self.handle.sendpacket(packet.l2())?;
        }

        Ok(())
    }
}
