use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use serde::{Deserialize, Serialize};

/// Layer 2 protocol.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum L2 {
    /// 4-byte BSD Loopback header (e.g. lo0 on macOS).
    BSDLoopback,
    /// 14-byte Ethernet header.
    Ethernet,
    /// L3 link (e.g. VPN).
    None,
}

/// Layer 3 protocol.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum L3 {
    IPv4,
    IPv6,
}

impl From<L3> for EtherType {
    fn from(value: L3) -> Self {
        match value {
            L3::IPv4 => EtherTypes::Ipv4,
            L3::IPv6 => EtherTypes::Ipv6,
        }
    }
}

/// Layer 4 protocol.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum L4 {
    ICMP,
    ICMPv6,
    UDP,
    TCP,
}

impl From<L4> for u8 {
    fn from(value: L4) -> Self {
        let val: IpNextHeaderProtocol = value.into();
        val.0
    }
}

impl From<L4> for IpNextHeaderProtocol {
    fn from(value: L4) -> Self {
        match value {
            L4::ICMP => IpNextHeaderProtocols::Icmp,
            L4::ICMPv6 => IpNextHeaderProtocols::Icmpv6,
            L4::UDP => IpNextHeaderProtocols::Udp,
            L4::TCP => IpNextHeaderProtocols::Tcp,
        }
    }
}
