use std::fmt::{Display, Formatter};
use std::net::Ipv6Addr;


use serde::{de, Deserialize, Serialize};
use serde_with::{serde_as};

use crate::checksum::caracat_checksum;
use crate::models::protocols::{L3, L4};
use crate::utilities::parse_as_ipv6;

/// The specification for a probe packet.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Probe {
    #[serde(deserialize_with = "deserialize_as_ipv6")]
    pub dst_addr: Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
    pub protocol: L4,
}

impl Display for Probe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "dst_addr={}", self.dst_addr)?;
        write!(f, " src_port={}", self.src_port)?;
        write!(f, " dst_port={}", self.dst_port)?;
        write!(f, " ttl={}", self.ttl)?;
        write!(f, " protocol={}", self.protocol)
    }
}

impl Probe {
    pub fn l3_protocol(&self) -> L3 {
        match self.dst_addr.to_ipv4_mapped() {
            Some(_) => L3::IPv4,
            None => L3::IPv6,
        }
    }

    pub fn l4_protocol(&self) -> L4 {
        self.protocol
    }

    pub fn checksum(&self, instance_id: u16) -> u16 {
        // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
        let dst_addr_bytes: [u8; 4] = self.dst_addr.octets()[12..].try_into().unwrap();
        let dst_addr = u32::from_le_bytes(dst_addr_bytes);
        caracat_checksum(instance_id, dst_addr, self.src_port, self.ttl)
    }
}

fn deserialize_as_ipv6<'de, D>(deserializer: D) -> Result<Ipv6Addr, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    parse_as_ipv6(&s).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ipv4_dotted() {}
}
