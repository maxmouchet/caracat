use std::fmt::{Debug, Formatter};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;

use anyhow::{bail, Result};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// Path to the netstat binary.
pub const DEFAULT_NETSTAT_BINARY: &str = "/usr/sbin/netstat";
/// Path to the routing table in procfs.
pub const DEFAULT_PROCFS_ROUTE: &str = "/proc/net/route";

/// A routing table.
pub struct RoutingTable {
    table: IpNetworkTable<Route>,
}

impl RoutingTable {
    pub fn new(routes: Vec<Route>) -> Self {
        let mut table = IpNetworkTable::new();
        for route in routes {
            table.insert(route.network, route);
        }
        Self { table }
    }

    /// Build a routing table by using netstat or procfs depending on the operating system.
    pub fn from_native() -> Result<Self> {
        if cfg!(target_os = "linux") {
            Self::from_procfs(DEFAULT_PROCFS_ROUTE)
        } else {
            Self::from_netstat(DEFAULT_NETSTAT_BINARY)
        }
        // TODO: Windows
    }

    /// Build a routing table by parsing netstat output on BSD systems.
    ///
    /// A proper solution would be to use routing sockets to query the OS routing table.
    /// However this is complex as it relies on C data structures that are different for each OSes.
    /// Furthermore, there exists no Rust crate that implement this in a cross-platform way.
    ///
    /// This solution is not so bad, as netstat is present by default on macOS, FreeBSD, NetBSD and OpenBSD.
    /// Furthermore, this is typically called once per execution, so the overhead of spawning an external process is minimal.
    pub fn from_netstat(path: &str) -> Result<Self> {
        let result = Command::new(path).args(["-n", "-r"]).output()?;
        let output = String::from_utf8(result.stdout)?;
        let routes: Vec<Route> = output.lines().flat_map(Route::from_netstat_entry).collect();
        Ok(RoutingTable::new(routes))
    }

    /// Build a routing table by parsing procfs on Linux.
    pub fn from_procfs(path: &str) -> Result<Self> {
        let output = fs::read_to_string(path)?;
        let routes: Vec<Route> = output.lines().flat_map(Route::from_procfs_entry).collect();
        Ok(RoutingTable::new(routes))
    }

    pub fn get(&self, destination: IpAddr) -> Option<&Route> {
        self.table
            .longest_match(destination)
            .map(|(_, route)| route)
    }
}

impl Debug for RoutingTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (_, route) in self.table.iter() {
            writeln!(f, "{:?}", route)?
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Route {
    pub network: IpNetwork,
    pub gateway: IpAddr,
    pub interface: String,
}

/// An IPv4 or IPv6 route.
impl Route {
    pub fn from_netstat_entry(line: &str) -> Result<Self> {
        let elems: Vec<&str> = line.split_whitespace().collect();
        if elems.len() < 4 {
            bail!("invalid entry")
        }

        let gateway = IpAddr::from_str(elems[1].split('%').next().unwrap())?;
        let interface = elems[3].to_string();
        let network = if elems[0] == "default" {
            let addr = if gateway.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            IpNetwork::new(addr, 0)?
        } else if elems[0].contains('/') {
            IpNetwork::from_str(elems[0])?
        } else {
            let addr = IpAddr::from_str(elems[0])?;
            let mask = if gateway.is_ipv4() { 32 } else { 128 };
            IpNetwork::new(addr, mask)?
        };

        Ok(Self {
            network,
            gateway,
            interface,
        })
    }

    pub fn from_procfs_entry(line: &str) -> Result<Self> {
        let elems: Vec<&str> = line.split_whitespace().collect();
        if elems.len() < 8 {
            bail!("invalid entry")
        }
        // TODO: IPv6
        let iface = elems[0].to_string();
        let destination = Ipv4Addr::from(u32::from_str_radix(elems[1], 16)?.to_be());
        let gateway = Ipv4Addr::from(u32::from_str_radix(elems[2], 16)?.to_be());
        let masklen = u32::from_str_radix(elems[7], 16)?.to_be().leading_ones() as u8;
        Ok(Self {
            network: IpNetwork::new(destination, masklen)?,
            gateway: IpAddr::V4(gateway),
            interface: iface,
        })
    }
}
