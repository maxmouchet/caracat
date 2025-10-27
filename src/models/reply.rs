use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{icmp, icmpv6};

use crate::checksum::caracat_checksum;

/// An MPLS label.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MPLSLabel {
    /// This 20-bit field carries the actual value of the label.
    pub label: u32,
    /// This three-bit field is reserved for experimental use.
    pub experimental: u8,
    /// This bit is set to one for the last entry in the label stack
    ///  (i.e., for the bottom of the stack), and zero for all other
    /// label stack entries.
    pub bottom_of_stack: bool,
    /// This eight-bit field is used to encode a time-to-live value.
    pub ttl: u8,
}

/// A reply to a probe packet.
#[derive(Debug)]
pub struct Reply {
    // * Capture attributes *
    /// The capture timestamp.
    pub capture_timestamp: Duration,
    // * Reply attributes (IP) *
    /// The source IP of the reply packet.
    pub reply_src_addr: IpAddr,
    /// The destination IP of the reply packet.
    pub reply_dst_addr: IpAddr,
    /// The ID field of the reply packet (0 for IPv6).
    pub reply_id: u16,
    /// The size in bytes of the reply packet.
    /// For IPv6 this doesn't include the IP header.
    pub reply_size: u16,
    /// The TTL of the reply packet.
    pub reply_ttl: u8,
    /// The L3 protocol of the reply.
    pub reply_protocol: u8,
    // * Reply attributes (IP → ICMP) *
    /// ICMP type (0 if not an ICMP reply)
    pub reply_icmp_type: u8,
    /// ICMP code (0 if not an ICMP reply)
    pub reply_icmp_code: u8,
    /// MPLS labels contained in the ICMP extension.
    pub reply_mpls_labels: Vec<MPLSLabel>,
    // * Probe attributes (IP → ICMP → IP) *
    /// The source IP of the probe packet.
    pub probe_src_addr: IpAddr,
    /// The IP that was targeted by the probe.
    pub probe_dst_addr: IpAddr,
    /// The ID field of the probe packet (0 for IPv6).
    pub probe_id: u16,
    /// The size in bytes of the probe packet.
    /// For IPv6 this doesn't include the IP header.
    pub probe_size: u16,
    /// The protocol of the probe packet.
    pub probe_protocol: u8,
    /// The TTL as seen by the host that emitted the ICMP reply.
    pub quoted_ttl: u8,
    // * Probe attributes (IP → ICMP → IP → ICMP/UDP) *
    /// The source port of the probe packet.
    /// For ICMP probes, we encode the source port in the ICMP checksum and ID fields in order to vary the flow ID.
    pub probe_src_port: u16,
    /// The destination port of the probe packet,
    /// 0 for ICMP probes.
    pub probe_dst_port: u16,
    /// The TTL that was encoded in the L4 header, 0 if not available.
    pub probe_ttl: u8,
    // * Estimated attributes *
    /// The estimated round-trip time, in tenth of milliseconds.
    pub rtt: u16,
}

impl Default for Reply {
    fn default() -> Self {
        Reply {
            capture_timestamp: Duration::default(),
            reply_src_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            reply_dst_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            reply_id: 0,
            reply_size: 0,
            reply_ttl: 0,
            reply_protocol: 0,
            reply_icmp_type: 0,
            reply_icmp_code: 0,
            reply_mpls_labels: vec![],
            probe_src_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            probe_dst_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            probe_id: 0,
            probe_size: 0,
            probe_protocol: 0,
            quoted_ttl: 0,
            probe_src_port: 0,
            probe_dst_port: 0,
            probe_ttl: 0,
            rtt: 0,
        }
    }
}

impl Reply {
    pub fn checksum(&self, instance_id: u16) -> u16 {
        // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
        let dst_addr_bytes = match self.probe_dst_addr {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(v6) => v6.octets()[12..].try_into().unwrap(),
        };
        let dst_addr = u32::from_le_bytes(dst_addr_bytes);
        caracat_checksum(instance_id, dst_addr, self.probe_src_port, self.probe_ttl)
    }

    pub fn is_valid(&self, instance_id: u16) -> bool {
        // Currently, we only validate IPv4 ICMP time exceeded and destination
        // unreachable messages. We cannot validate echo replies as they do not
        // contain the probe_id field contained in the source IP header.
        // TODO: IPv6 support?
        if self.reply_protocol == IpNextHeaderProtocols::Icmp.0
            && (self.reply_icmp_type == icmp::IcmpTypes::DestinationUnreachable.0
                || self.reply_icmp_type == icmp::IcmpTypes::TimeExceeded.0)
        {
            self.probe_id == self.checksum(instance_id)
        } else {
            true
        }
    }

    pub fn is_destination_unreachable(&self) -> bool {
        (self.reply_protocol == IpNextHeaderProtocols::Icmp.0
            && self.reply_icmp_type == icmp::IcmpTypes::DestinationUnreachable.0)
            || (self.reply_protocol == IpNextHeaderProtocols::Icmpv6.0
                && self.reply_icmp_type == icmpv6::Icmpv6Types::DestinationUnreachable.0)
    }

    pub fn is_echo_reply(&self) -> bool {
        (self.reply_protocol == IpNextHeaderProtocols::Icmp.0
            && self.reply_icmp_type == icmp::IcmpTypes::EchoReply.0)
            || (self.reply_protocol == IpNextHeaderProtocols::Icmpv6.0
                && self.reply_icmp_type == icmpv6::Icmpv6Types::EchoReply.0)
    }

    pub fn is_time_exceeded(&self) -> bool {
        (self.reply_protocol == IpNextHeaderProtocols::Icmp.0
            && self.reply_icmp_type == icmp::IcmpTypes::TimeExceeded.0)
            || (self.reply_protocol == IpNextHeaderProtocols::Icmpv6.0
                && self.reply_icmp_type == icmpv6::Icmpv6Types::TimeExceeded.0)
    }
}
