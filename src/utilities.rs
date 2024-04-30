//! Utilities.
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::{panic, process};

use chrono::Utc;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use log::LevelFilter;
use pcap::Device;
use pnet::datalink::MacAddr;

/// Return the default device name (according to pcap).
pub fn get_default_interface() -> String {
    Device::lookup().unwrap().unwrap().name
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
    let addresses: Vec<Ipv4Addr> = get_device(interface)?
        .addresses
        .iter()
        .filter(|addr| addr.addr.is_ipv4())
        .map(|addr| match addr.addr {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .collect();
    // Prefer Internet-routable addresses over loopback over private unicast.
    // TODO: The following line requires Rust nightly:
    // addresses.sort_by_key(|addr| (addr.is_global(), addr.is_loopback(), addr.is_private()));
    addresses.last().copied()
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
    addresses.sort_by_key(|addr| addr.octets()[0] & 0b11100000 == 0b00100000);
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

pub fn prefix_filter_from_file(path: &PathBuf) -> Result<IpNetworkTable<()>> {
    let mut tree = IpNetworkTable::new();
    let reader = BufReader::new(File::open(path)?);
    // TODO: Remove calls to unwrap.
    #[allow(clippy::lines_filter_map_ok)]
    reader
        .lines()
        .flat_map(|line| line.ok())
        .filter(|line| !line.starts_with('#'))
        .flat_map(|line| {
            // If there are multiple columns, take only the first one.
            // e.g. pyasn or bgp.potaroo.net format.
            line.split_whitespace()
                .next()
                .and_then(|s| IpNetwork::from_str(s).ok())
        })
        .for_each(|network| tree.insert(network, ()).unwrap());
    Ok(tree)
}

/// Exit the whole process when a thread panic.
/// This is in until we find a better way to handle errors in the receive loop.
pub fn exit_process_on_panic() {
    // https://stackoverflow.com/questions/35988775/how-can-i-cause-a-panic-on-a-thread-to-immediately-end-the-main-thread
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        process::exit(1);
    }));
}

/// Initialize the logger.
pub fn configure_logger(level: LevelFilter) {
    env_logger::builder()
        .filter(None, level)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] [{}] {}",
                Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level().to_string().to_lowercase(),
                record.args(),
            )
        })
        .init();
}
