use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{icmp, icmpv6};
use serde::Serialize;

use crate::checksum::caracat_checksum;

/// An MPLS label.
#[derive(Copy, Clone, Debug, PartialEq, Serialize)]
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
#[derive(Debug, Serialize)]
pub struct Reply {
    // * Capture attributes *
    /// The capture timestamp in microseconds.
    pub capture_timestamp: u64,
    // * Reply attributes (IP) *
    /// The source IP of the reply packet.
    pub reply_src_addr: Ipv6Addr,
    /// The destination IP of the reply packet.
    pub reply_dst_addr: Ipv6Addr,
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
    /// The IP that was targeted by the probe.
    /// If we received a reply from this IP then `reply_src_addr == probe_dst_addr`.
    pub probe_dst_addr: Ipv6Addr,
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
    // * Extra attributes *
    /// An extra string that is appended at the end of the reply.
    pub extra: Option<String>,
}

impl Default for Reply {
    fn default() -> Self {
        Reply {
            capture_timestamp: 0,
            reply_src_addr: Ipv6Addr::UNSPECIFIED,
            reply_dst_addr: Ipv6Addr::UNSPECIFIED,
            reply_id: 0,
            reply_size: 0,
            reply_ttl: 0,
            reply_protocol: 0,
            reply_icmp_type: 0,
            reply_icmp_code: 0,
            reply_mpls_labels: vec![],
            probe_dst_addr: Ipv6Addr::UNSPECIFIED,
            probe_id: 0,
            probe_size: 0,
            probe_protocol: 0,
            quoted_ttl: 0,
            probe_src_port: 0,
            probe_dst_port: 0,
            probe_ttl: 0,
            rtt: 0,
            extra: None,
        }
    }
}

impl Display for Reply {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "capture_timestamp={}", self.capture_timestamp)?;
        write!(f, " reply_src_addr={}", self.reply_src_addr)?;
        write!(f, " reply_dst_addr={}", self.reply_dst_addr)?;
        write!(f, " reply_ttl={}", self.reply_ttl)?;
        write!(f, " reply_protocol={}", self.reply_protocol)?;
        write!(f, " reply_icmp_code={}", self.reply_icmp_code)?;
        write!(f, " reply_icmp_type={}", self.reply_icmp_type)?;
        // for (const auto& mpls_label : self.reply_mpls_labels) {
        //     write!(f, "reply_mpls_label={}", mpls_label_to_csv(mpls_label))?;
        // }
        write!(f, " probe_id={}", self.probe_id)?;
        write!(f, " probe_size={}", self.probe_size)?;
        write!(f, " probe_protocol={}", self.probe_protocol)?;
        write!(f, " probe_ttl={}", self.probe_ttl)?;
        write!(f, " probe_dst_addr={}", self.probe_dst_addr)?;
        write!(f, " probe_src_port={}", self.probe_src_port)?;
        write!(f, " probe_dst_port={}", self.probe_dst_port)?;
        write!(f, " quoted_ttl={}", self.quoted_ttl)?;
        write!(f, " rtt={}", self.rtt as f64 / 10.0)?;
        Ok(())
    }
}

impl Reply {
    pub fn checksum(&self, instance_id: u16) -> u16 {
        // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
        let dst_addr_bytes: [u8; 4] = self.probe_dst_addr.octets()[12..].try_into().unwrap();
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
