//! Find routes and resolve link-layer addresses.
//!
//! # Examples
//!
//! ```no_run
//! use anyhow::{Context, Result};
//! use pcap::Device;
//! use std::net::IpAddr;
//! use caracat::neighbors::{RoutingTable, resolve_mac_address};
//! use caracat::utilities::get_default_interface;
//!
//! fn main() -> Result<()> {
//!     let interface = get_default_interface();
//!     let target: IpAddr = "192.0.2.0".parse()?;
//!     let table = RoutingTable::from_native()?;
//!
//!     let route = table.get(target).context("route not found")?;
//!     let mac = resolve_mac_address(&interface, route.gateway)?;
//!
//!     println!("{:?} via {:?} ({:?})", target, route.gateway, mac);
//!     Ok(())
//! }
//! ```
mod arp;
mod ndp;
mod route;

pub use arp::*;
pub use ndp::*;
pub use route::*;

use anyhow::Result;

use pnet::util::MacAddr;
use std::net::IpAddr;

pub fn resolve_mac_address(interface: &str, addr: IpAddr) -> Result<MacAddr> {
    match addr {
        IpAddr::V4(addr) => resolve_mac_address_v4(interface, addr),
        IpAddr::V6(addr) => resolve_mac_address_v6(interface, addr),
    }
}
