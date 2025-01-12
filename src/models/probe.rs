use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::checksum::caracat_checksum;
use crate::models::protocols::{L3, L4};

/// The specification for a probe packet.
#[derive(Debug, Serialize, Deserialize)]
pub struct Probe {
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
    pub protocol: L4,
}

impl Probe {
    pub fn l3_protocol(&self) -> L3 {
        match self.dst_addr {
            IpAddr::V4(_) => L3::IPv4,
            IpAddr::V6(_) => L3::IPv6,
        }
    }

    pub fn l4_protocol(&self) -> L4 {
        self.protocol
    }

    pub fn checksum(&self, instance_id: u16) -> u16 {
        // TODO: IPv6 support? Or just encode the last 32 bits for IPv6?
        let dst_addr_bytes = match self.dst_addr {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(v6) => v6.octets()[12..].try_into().unwrap(),
        };
        let dst_addr = u32::from_le_bytes(dst_addr_bytes);
        caracat_checksum(instance_id, dst_addr, self.src_port, self.ttl)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ipv4_dotted() {}
}
