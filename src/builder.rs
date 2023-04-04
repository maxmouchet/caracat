//! Functions for building probe packets.
//!
//! These functions are meant to be called in order, from the lowermost layer to the uppermost layer.
//!
//! # Examples
//!
//! To keep this example self-contained we use empty MAC and IP addresses.
//! Use [`crate::neighbors`] to get the gateway MAC address
//! .
//! ```
//! use std::net::Ipv4Addr;
//! use pnet::util::MacAddr;
//! use caracat::builder::{build_ethernet, build_icmp, build_ipv4, Packet};
//! use caracat::models::{L2, L3, L4};
//!
//! let mut buffer = [0u8; 65535];
//! let mut packet = Packet::new(&mut buffer, L2::Ethernet, L3::IPv4, L4::ICMP, 2);
//!
//! build_ethernet(&mut packet, MacAddr::zero(), MacAddr::zero());
//! build_ipv4(&mut packet, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 32, 42);
//! build_icmp(&mut packet, 42, 4242);
//!
//! println!("{:?}", packet.l2());
//! ```
mod builders;
mod packet;

pub use builders::*;
pub use packet::*;
