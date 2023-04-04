//! Data structures for filtering IP addresses.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ip_network_table_deps_treebitmap::IpLookupTable;
use log::error;

use crate::utilities::parse_as_ipv6;

/// A radix tree for fast IP lookups.
///
/// ```
/// use std::net::Ipv6Addr;
/// use caracat::IpTree;
/// use caracat::utilities::parse_as_ipv6;
///
/// let mut tree = IpTree::default();
/// tree.insert_string("8.8.8.0/24");
/// tree.insert_string("2001:4860:4860::/64");
///
/// assert!(tree.contains(parse_as_ipv6("8.8.8.1").unwrap()));
/// assert!(!tree.contains(parse_as_ipv6("8.8.9.1").unwrap()));
/// assert!(tree.contains(parse_as_ipv6("2001:4860:4860::8888").unwrap()));
/// assert!(!tree.contains(parse_as_ipv6("2001:4860:4861::8888").unwrap()));
/// ```
#[derive(Default)]
pub struct IpTree {
    table: IpLookupTable<Ipv6Addr, ()>,
}

impl IpTree {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let mut tree = Self::default();
        let reader = BufReader::new(File::open(path)?);
        reader
            .lines()
            .flat_map(|line| line.ok())
            .filter(|line| !line.starts_with('#'))
            .for_each(|line| match tree.insert_string(&line) {
                Ok(_) => {}
                Err(error) => error!("{}: {}", error, line),
            });
        Ok(tree)
    }

    pub fn insert_string(&mut self, line: &str) -> Result<()> {
        // If there are multiple columns, take only the first one.
        // e.g. pyasn or bgp.potaroo.net format.
        let first_col = line.split_whitespace().next().context("Empty line")?;
        let elems: Vec<&str> = first_col.split('/').collect();
        if elems.len() != 2 {
            bail!("Invalid line");
        }
        let addr = parse_as_ipv6(elems[0])?;
        let mut masklen: u32 = elems[1].parse()?;
        if addr.to_ipv4_mapped().is_some() {
            masklen += 96;
        }
        self.table.insert(addr, masklen, ());
        Ok(())
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        self.table.longest_match(addr).is_some()
    }
}

// TODO: Tests + Test with missing new line + Test empty tree
