//! High-level interface for sending probes.
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use ip_network_table::IpNetworkTable;
use log::{error, info, trace};

use crate::models::Probe;
use crate::rate_limiter::RateLimiter;
use crate::sender::Sender;

pub struct SendLoop {
    batch_size: u64,
    instance_id: u16,
    min_ttl: Option<u8>,
    max_ttl: Option<u8>,
    max_probes: Option<u64>,
    packets: u64,
    allowed_prefixes: Option<IpNetworkTable<()>>,
    blocked_prefixes: Option<IpNetworkTable<()>>,
    rate_limiter: RateLimiter,
    sender: Sender,
    statistics: Arc<Mutex<SendStatistics>>,
}

impl SendLoop {
    pub fn new(
        batch_size: u64,
        instance_id: u16,
        min_ttl: Option<u8>,
        max_ttl: Option<u8>,
        max_probes: Option<u64>,
        packets: u64,
        allowed_prefixes: Option<IpNetworkTable<()>>,
        blocked_prefixes: Option<IpNetworkTable<()>>,
        rate_limiter: RateLimiter,
        sender: Sender,
    ) -> Self {
        let statistics = Arc::new(Mutex::new(SendStatistics::default()));
        SendLoop {
            batch_size,
            instance_id,
            min_ttl,
            max_ttl,
            max_probes,
            packets,
            blocked_prefixes,
            allowed_prefixes,
            rate_limiter,
            sender,
            statistics,
        }
    }

    pub fn probe<T: Iterator<Item = Probe>>(&mut self, probes: T) -> Result<()> {
        for probe in probes {
            let mut statistics = self.statistics.lock().unwrap();
            statistics.read += 1;

            if let Some(ttl) = self.min_ttl {
                if probe.ttl < ttl {
                    trace!("{} filter=ttl_too_low", probe);
                    statistics.filtered_low_ttl += 1;
                    continue;
                }
            }

            if let Some(ttl) = self.max_ttl {
                if probe.ttl > ttl {
                    trace!("{} filter=ttl_too_high", probe);
                    statistics.filtered_high_ttl += 1;
                    continue;
                }
            }

            if let Some(tree) = &self.allowed_prefixes {
                if tree.longest_match(probe.dst_addr).is_none() {
                    trace!("{} filter=prefix_not_allowed", probe);
                    statistics.filtered_prefix_not_allowed += 1;
                    continue;
                }
            }

            if let Some(tree) = &self.blocked_prefixes {
                if tree.longest_match(probe.dst_addr).is_some() {
                    trace!("{} filter=prefix_blocked", probe);
                    statistics.filtered_prefix_blocked += 1;
                    continue;
                }
            }

            for i in 0..self.packets {
                trace!(
                    "{} id={} packet={}",
                    probe,
                    probe.checksum(self.instance_id),
                    i + 1
                );
                match self.sender.send(&probe) {
                    Ok(_) => statistics.sent += 1,
                    Err(error) => {
                        statistics.failed += 1;
                        error!("{}", error);
                    }
                }
                // Rate limit every `batch_size` packets sent.
                if (statistics.sent + statistics.failed) % self.batch_size == 0 {
                    self.rate_limiter.wait();
                }
            }

            if let Some(max_probes) = self.max_probes {
                if statistics.sent >= max_probes {
                    info!("max_probes reached, exiting...");
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn statistics(&self) -> &Arc<Mutex<SendStatistics>> {
        &self.statistics
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct SendStatistics {
    pub read: u64,
    pub sent: u64,
    pub failed: u64,
    pub filtered_low_ttl: u64,
    pub filtered_high_ttl: u64,
    pub filtered_prefix_blocked: u64,
    pub filtered_prefix_not_allowed: u64,
}

impl Display for SendStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "probes_read={} packets_sent={} packets_failed={} filtered_low_ttl={} filtered_high_ttl={} filtered_prefix_not_allowed={} filtered_prefix_blocked={}",
               self.read, self.sent, self.failed, self.filtered_low_ttl, self.filtered_high_ttl,self.filtered_prefix_not_allowed, self.filtered_prefix_blocked)
    }
}
