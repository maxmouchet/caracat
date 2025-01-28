//! Utilities.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap::Device;
use pnet::datalink::MacAddr;

use crate::neighbors::RoutingTable;

/// Return the interface carrying the default route, if any.
pub fn get_default_interface() -> String {
    if let Ok(table) = RoutingTable::from_native() {
        if let Some(route) = table.default_route_v4() {
            return route.interface.clone();
        } else if let Some(route) = table.default_route_v6() {
            return route.interface.clone();
        }
    }
    "".to_string()
}

/// Return the pcap device for the given interface.
// NOTE: We need this function to get the IP addresses associated to an interface,
// as a device created using interface.into() will contain an empty list of addresses.
// See `impl From<&str> for Device` in pcap source code.
fn get_device(interface: &str) -> Option<Device> {
    Device::list()
        .unwrap()
        .into_iter()
        .find(|device| device.name.eq(interface))
}

/// Return the preferred IPv4 address for the device.
pub fn get_ipv4_address(interface: &str) -> Option<Ipv4Addr> {
    let mut addresses: Vec<Ipv4Addr> = get_device(interface)?
        .addresses
        .iter()
        .filter(|addr| addr.addr.is_ipv4())
        .map(|addr| match addr.addr {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .collect();

    // Prefer Internet-routable addresses over loopback over private unicast.
    // TODO: use `is_global()` when stabilized.
    addresses.sort_by_key(|addr| addr.is_private());
    addresses.first().copied()
}

/// Return the preferred IPv6 address for the device.
pub fn get_ipv6_address(interface: &str) -> Option<Ipv6Addr> {
    let mut addresses: Vec<Ipv6Addr> = get_device(interface)?
        .addresses
        .iter()
        .filter(|addr| addr.addr.is_ipv6())
        .map(|addr| match addr.addr {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        })
        .collect();

    // Prefer Internet-routable addresses over loopback over private over link-local.
    // TODO: Temporary hack to prefer GUAs over other kind of addresses.
    //       The proper solution below requires Rust nightly.
    // TODO: Prefer ULA over link-local?
    addresses.sort_by_key(|addr| addr.octets()[0] & 0b11100000 == 0b00100000);
    println!("{:?}", addresses);
    // addresses.sort_by_key(|addr| {
    //     (
    //         addr.is_global(),
    //         addr.is_loopback(),
    //         addr.is_unique_local(),
    //         addr.is_unicast_link_local(),
    //     )
    // });
    addresses.last().copied()
}

/// Return the MAC address of the device (if any).
pub fn get_mac_address(interface: &str) -> Option<MacAddr> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface)
        .and_then(|iface| iface.mac)
}
