//! Utilities.
use std::io::Write;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use std::{panic, process};

use chrono::Utc;
use log::LevelFilter;
use pcap::Device;
use pnet::datalink::MacAddr;

/// Return the default device name (according to pcap).
pub fn get_default_interface() -> String {
    Device::lookup().unwrap().unwrap().name
}

/// Return the pcap device for the given interface.
pub fn get_device(interface: &str) -> Option<Device> {
    Device::list()
        .unwrap()
        .into_iter()
        .find(|device| device.name.eq(interface))
}

/// Return the preferred IPv4 address for the device.
pub fn get_device_ipv4(device: &Device) -> Option<Ipv4Addr> {
    let addresses: Vec<Ipv4Addr> = device
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
pub fn get_device_ipv6(device: &Device) -> Option<Ipv6Addr> {
    let addresses: Vec<Ipv6Addr> = device
        .addresses
        .iter()
        .filter(|addr| addr.addr.is_ipv6())
        .map(|addr| match addr.addr {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        })
        .collect();
    // Prefer Internet-routable addresses over loopback over private over link-local.
    // TODO: The following line requires Rust nightly:
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
pub fn get_device_mac(device: &Device) -> Option<MacAddr> {
    // TODO: Conversion between pcap device and pnet interface?
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == device.name)
        .and_then(|iface| iface.mac)
}

/// Return the extension of the given file.
pub fn get_extension(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap()
}

/// Parse IPv4 and IPv6 addresses as an IPv6 object.
/// IPv4 addresses are converted to IPv4-mapped IPv6 addresses
pub fn parse_as_ipv6(s: &str) -> Result<Ipv6Addr, AddrParseError> {
    match s.contains(':') {
        true => Ipv6Addr::from_str(s),
        false => Ipv6Addr::from_str(&format!("::ffff:{s}")),
    }
}

// TODO: Use IpAddr everywhere and remove these methods.
pub fn ip_to_ipv6(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
        IpAddr::V6(ipv6) => ipv6,
    }
}

pub fn ipv6_to_ip(addr: Ipv6Addr) -> IpAddr {
    match addr.to_ipv4_mapped() {
        Some(ipv4) => IpAddr::V4(ipv4),
        None => IpAddr::V6(addr),
    }
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
