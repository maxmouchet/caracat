use std::mem::size_of;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::models::{L2, L3, L4};

/// A Packet holds pointers to the L2/L3/L4 layers over a buffer.
///
/// ```
/// use std::io::Write;
/// use caracat::builder::Packet;
/// use caracat::models::{L2, L3, L4};
///
/// let mut buffer = [0u8; 65535];
/// let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv4, L4::ICMP, 0);
///
/// // Write some data in the L3 header:
/// packet.l3_mut().write(&[0x20, 0x22]);
///
/// // Get the full packet, from the L2 header to the end of the payload:
/// println!("{:?}", packet.l2());
/// ```
pub struct Packet<'a> {
    buffer: &'a mut [u8],
    l2_protocol: L2,
    l3_protocol: L3,
    l4_protocol: L4,
    l2_start: usize,
    l3_start: usize,
    l4_start: usize,
    payload_start: usize,
    payload_end: usize,
}

impl Packet<'_> {
    /// Build a new packet over an existing buffer.
    pub fn new(
        buffer: &'_ mut [u8],
        l2_protocol: L2,
        l3_protocol: L3,
        l4_protocol: L4,
        payload_size: usize,
    ) -> Packet<'_> {
        // Pad the beginning of the packet to align on a four-byte boundary.
        // See https://lwn.net/Articles/89597/.
        let l2_header_size: usize;
        let padding: usize;

        match l2_protocol {
            L2::BSDLoopback => {
                l2_header_size = size_of::<u32>();
                padding = 0;
            }
            L2::Ethernet => {
                // TODO: Replace these minimum size with constants (in constants mod?).
                l2_header_size = EthernetPacket::minimum_packet_size();
                padding = 2;
            }
            L2::None => {
                l2_header_size = 0;
                padding = 0;
            }
        }

        let l3_header_size = match l3_protocol {
            L3::IPv4 => Ipv4Packet::minimum_packet_size(),
            L3::IPv6 => Ipv6Packet::minimum_packet_size(),
        };

        let l4_header_size = match l4_protocol {
            // `sizeof(icmp)` returns 28, but we use only the 8 byte header.
            L4::ICMP => 8,
            L4::ICMPv6 => 8,
            L4::UDP => UdpPacket::minimum_packet_size(),
            L4::TCP => TcpPacket::minimum_packet_size(),
        };

        let l2_start = padding;
        let l3_start = l2_start + l2_header_size;
        let l4_start = l3_start + l3_header_size;
        let payload_start = l4_start + l4_header_size;
        let payload_end = payload_start + payload_size;

        Packet {
            buffer,
            l2_protocol,
            l3_protocol,
            l4_protocol,
            l2_start,
            l3_start,
            l4_start,
            payload_start,
            payload_end,
        }
    }

    /// A slice from the start of the layer 2 header to the end of the payload.
    pub fn l2(&self) -> &[u8] {
        &self.buffer[self.l2_start..self.payload_end]
    }

    /// A slice from the start of the layer 3 header to the end of the payload.
    pub fn l3(&self) -> &[u8] {
        &self.buffer[self.l3_start..self.payload_end]
    }

    /// A slice from the start of the layer 4 header to the end of the payload.
    pub fn l4(&self) -> &[u8] {
        &self.buffer[self.l4_start..self.payload_end]
    }

    /// A slice from the start of the payload to the end of the payload.
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.payload_start..self.payload_end]
    }

    /// A mutable slice from the start of the layer 2 header to the end of the payload.
    pub fn l2_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.l2_start..self.payload_end]
    }

    /// A mutable slice from the start of the layer 3 header to the end of the payload.
    pub fn l3_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.l3_start..self.payload_end]
    }

    /// A mutable slice from the start of the layer 4 header to the end of the payload.
    pub fn l4_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.l4_start..self.payload_end]
    }

    /// A mutable slice from the start of the payload to the end of the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.payload_start..self.payload_end]
    }

    /// The layer 2 protocol.
    pub fn l2_protocol(&self) -> L2 {
        self.l2_protocol
    }

    /// The layer 3 protocol.
    pub fn l3_protocol(&self) -> L3 {
        self.l3_protocol
    }

    /// The layer 4 protocol.
    pub fn l4_protocol(&self) -> L4 {
        self.l4_protocol
    }

    /// The size of the packet from the start of the layer 2 header to the end of the payload.
    pub fn l2_size(&self) -> u16 {
        (self.payload_end - self.l2_start) as u16
    }

    /// The size of the packet from the start of the layer 3 header to the end of the payload.
    pub fn l3_size(&self) -> u16 {
        (self.payload_end - self.l3_start) as u16
    }

    /// The size of the packet from the start of the layer 4 header to the end of the payload.
    pub fn l4_size(&self) -> u16 {
        (self.payload_end - self.l4_start) as u16
    }
}
