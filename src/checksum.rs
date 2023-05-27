//! Functions for computing the caracat checksum.

/// Compute the caracat checksum.
pub fn caracat_checksum(instance_id: u16, dst_addr: u32, src_port: u16, ttl: u8) -> u16 {
    let sum = instance_id as u32 + dst_addr + src_port as u32 + ttl as u32;
    !(sum % 65535) as u16
}

#[cfg(test)]
mod tests {
    use crate::checksum::caracat_checksum;

    #[test]
    fn test_caracat_checksum() {
        let instance_id: u16 = 20643;
        let dst_addr: u32 = 134743044;
        let src_port: u16 = 24000;
        let ttl: u8 = 7;
        let checksum = caracat_checksum(instance_id, dst_addr, src_port, ttl);
        assert_eq!(
            caracat_checksum(instance_id, dst_addr, src_port, ttl),
            checksum
        );
        assert_ne!(
            caracat_checksum(instance_id, dst_addr - 1, src_port, ttl + 2),
            checksum
        );
        assert_ne!(
            caracat_checksum(instance_id, dst_addr, src_port + 2, ttl),
            checksum
        );
    }
}
