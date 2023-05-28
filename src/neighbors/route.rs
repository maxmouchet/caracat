use std::fmt::{Debug, Formatter};
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

use anyhow::{bail, Result};
use ip_network_table_deps_treebitmap::IpLookupTable;

/// Path to the netstat binary.
pub const DEFAULT_NETSTAT_BINARY: &str = "/usr/sbin/netstat";
/// Path to the routing table in procfs.
pub const DEFAULT_PROCFS_ROUTE: &str = "/proc/net/route";

/// An IPv4 routing table.
pub struct RoutingTable {
    table: IpLookupTable<Ipv4Addr, Ipv4Addr>,
}

impl RoutingTable {
    pub fn new(routes: &[Route]) -> Self {
        let mut table = IpLookupTable::new();
        for route in routes {
            table.insert(route.network, route.length, route.gateway);
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
        let result = Command::new(path)
            .args(["-f", "inet", "-n", "-r"])
            .output()?;
        let output = String::from_utf8(result.stdout)?;
        let routes: Vec<Route> = output.lines().flat_map(Route::from_netstat_entry).collect();
        Ok(RoutingTable::new(&routes))
    }

    /// Build a routing table by parsing procfs on Linux.
    pub fn from_procfs(path: &str) -> Result<Self> {
        let output = fs::read_to_string(path)?;
        let routes: Vec<Route> = output.lines().flat_map(Route::from_procfs_entry).collect();
        Ok(RoutingTable::new(&routes))
    }

    pub fn all(&self) -> Vec<Route> {
        self.table
            .iter()
            .map(|(network, length, gateway)| Route {
                network,
                length,
                gateway: *gateway,
            })
            .collect()
    }

    pub fn get(&self, destination: Ipv4Addr) -> Option<Route> {
        self.table
            .longest_match(destination)
            .map(|(network, length, gateway)| Route {
                network,
                length,
                gateway: *gateway,
            })
    }
}

impl Debug for RoutingTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.all().fmt(f)
    }
}

#[derive(Debug)]
pub struct Route {
    pub network: Ipv4Addr,
    pub length: u32,
    pub gateway: Ipv4Addr,
}

/// An IPv4 route.
impl Route {
    pub fn from_netstat_entry(line: &str) -> Result<Self> {
        let elems: Vec<&str> = line.split_whitespace().collect();
        if elems.len() < 2 {
            bail!("invalid entry")
        }
        let destination_str = elems[0];
        let destination_network: Ipv4Addr;
        let destination_length: u32;
        if destination_str == "default" {
            destination_network = Ipv4Addr::UNSPECIFIED;
            destination_length = 0;
        } else if destination_str.contains('/') {
            let destination_split: Vec<&str> = destination_str.split('/').collect();
            destination_network = Ipv4Addr::from_str(destination_split[0])?;
            destination_length = destination_split[1].parse()?;
        } else {
            destination_network = Ipv4Addr::from_str(destination_str)?;
            destination_length = 32;
        }
        Ok(Self {
            network: destination_network,
            length: destination_length,
            gateway: Ipv4Addr::from_str(elems[1])?,
        })
    }

    pub fn from_procfs_entry(line: &str) -> Result<Self> {
        let elems: Vec<&str> = line.split_whitespace().collect();
        if elems.len() < 8 {
            bail!("invalid entry")
        }
        let network = Ipv4Addr::from(u32::from_str_radix(elems[1], 16)?.to_be());
        let gateway = Ipv4Addr::from(u32::from_str_radix(elems[2], 16)?.to_be());
        let length = u32::from_str_radix(elems[7], 16)?.to_be().leading_ones();
        Ok(Self {
            network,
            length,
            gateway,
        })
    }
}
