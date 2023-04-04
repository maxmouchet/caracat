//! Find routes and resolve link-layer addresses.
//!
//! # Examples
//!
//! ```no_run
//! use anyhow::{Context, Result};
//! use pcap::Device;
//! use std::net::Ipv4Addr;
//! use caracat::neighbors::{RoutingTable, resolve_address};
//! use caracat::utilities::get_device;
//!
//! fn main() -> Result<()> {
//!     // See `get_device(&str)` to get a particular device.
//!     let device = Device::lookup()?.context("device not found")?;
//!     let target = Ipv4Addr::new(192, 0, 2, 0);
//!     let table = RoutingTable::from_native()?;
//!
//!     let route = table.get(target).context("route not found")?;
//!     let mac = resolve_address(device, route.gateway)?;
//!
//!     println!("{:?} via {:?} ({:?})", target, route.gateway, mac);
//!     Ok(())
//! }
//! ```
mod arp;
mod route;

pub use arp::*;
pub use route::*;
