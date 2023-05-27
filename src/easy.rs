//! High-level interface for sending probes and capturing replies.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//! use caracat::easy::{Config, probe_from_csv};
//!
//! let config = Config::default();
//! let input = File::open("probes.example").unwrap();
//! let (prober_statistics, receiver_statistics) = probe_from_csv(config, input).unwrap();
//!
//! println!("{:?} {:?}", prober_statistics, receiver_statistics);
//! ```
use std::fmt::{Display, Formatter};
use std::io::Read;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use anyhow::Result;
use log::{info, warn};
use rand::{thread_rng, Rng};

use crate::logger::StatisticsLogger;
use crate::models::Probe;
use crate::rate_limiter::{RateLimiter, RateLimitingMethod};
use crate::receive_loop::{ReceiveLoop, ReceiveStatistics};
use crate::send_loop::{SendLoop, SendStatistics};
use crate::sender::Sender;
use crate::tree::IpTree;
use crate::utilities::get_default_interface;

/// Send probes from an iterator.
pub fn probe<T: Iterator<Item = Probe>>(
    config: Config,
    probes: T,
) -> Result<(SendStatistics, ReceiveStatistics)> {
    info!("{}", config);

    let allowed_prefixes = match config.allowed_prefixes_file {
        None => None,
        Some(path) => Some(IpTree::from_file(&path)?),
    };

    let blocked_prefixes = match config.blocked_prefixes_file {
        None => None,
        Some(path) => Some(IpTree::from_file(&path)?),
    };

    let rate_limiter = RateLimiter::new(
        config.probing_rate,
        config.batch_size,
        config.rate_limiting_method,
    );
    let rate_statistics = rate_limiter.statistics().clone();

    let receiver = ReceiveLoop::new(
        config.interface.clone(),
        config.output_file_csv,
        config.instance_id,
        config.extra_string,
        config.integrity_check,
    );
    let receiver_statistics = receiver.statistics().clone();

    let mut prober = SendLoop::new(
        config.batch_size,
        config.instance_id,
        config.min_ttl,
        config.max_ttl,
        config.max_probes,
        config.packets,
        allowed_prefixes,
        blocked_prefixes,
        rate_limiter,
        Sender::new(&config.interface, config.instance_id, config.dry_run)?,
    );
    let prober_statistics = prober.statistics().clone();

    let logger = StatisticsLogger::new(prober_statistics, rate_statistics, receiver_statistics);

    prober.probe(probes)?;
    info!("Waiting {:?} for replies...", config.receiver_wait_time);
    sleep(config.receiver_wait_time);

    // TODO: Cleaner way?
    let final_prober_statistics = *prober.statistics().lock().unwrap();
    let final_receiver_statistics = receiver.statistics().lock().unwrap().clone();

    receiver.stop();
    logger.stop();

    Ok((final_prober_statistics, final_receiver_statistics))
}

/// Send probes from a CSV file.
pub fn probe_from_csv<T: Read>(
    config: Config,
    input: T,
) -> Result<(SendStatistics, ReceiveStatistics)> {
    let mut reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .flexible(true)
        .has_headers(false)
        .from_reader(input);

    let probes = reader.deserialize::<Probe>().filter_map(|x| match x {
        Ok(probe) => Some(probe),
        Err(error) => {
            warn!("{}", error);
            None
        }
    });

    probe(config, probes)
}

/// Probing configuration.
pub struct Config {
    /// Send probes only to the prefixes specified in the file (allow list).
    pub allowed_prefixes_file: Option<PathBuf>,
    /// Do not send probes to prefixes specified in file (block list).
    pub blocked_prefixes_file: Option<PathBuf>,
    /// Number of probes to send before calling the rate limiter.
    pub batch_size: u64,
    /// Identifier encoded in the probes (random by default).
    pub instance_id: u16,
    /// Whether to actually send the probes on the network or not.
    pub dry_run: bool,
    /// Extra column in the CSV output.
    pub extra_string: Option<String>,
    /// Do not send probes with ttl < min_ttl.
    pub min_ttl: Option<u8>,
    /// Do not send probes with ttl > max_ttl.
    pub max_ttl: Option<u8>,
    /// Check that replies match valid probes.
    pub integrity_check: bool,
    /// Interface from which to send the packets.
    pub interface: String,
    /// Maximum number of probes to send (unlimited by default).
    pub max_probes: Option<u64>,
    /// File to which the captured replies will be written.
    pub output_file_csv: Option<PathBuf>,
    /// Number of packets to send per probe.
    pub packets: u64,
    /// Probing rate in packets per second.
    pub probing_rate: u64,
    /// Method to use to limit the packets rate.
    pub rate_limiting_method: RateLimitingMethod,
    /// Time in seconds to wait after sending the probes to stop the receiver.
    pub receiver_wait_time: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            allowed_prefixes_file: None,
            blocked_prefixes_file: None,
            batch_size: 128,
            instance_id: thread_rng().gen_range(0..u16::MAX),
            dry_run: false,
            extra_string: None,
            min_ttl: None,
            max_ttl: None,
            integrity_check: true,
            interface: get_default_interface(),
            max_probes: None,
            output_file_csv: None,
            packets: 1,
            probing_rate: 100,
            rate_limiting_method: RateLimitingMethod::Auto,
            receiver_wait_time: Duration::from_secs(1),
        }
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "allowed_prefixes_file={:?}", self.allowed_prefixes_file)?;
        write!(f, " blocked_prefixes_file={:?}", self.blocked_prefixes_file)?;
        write!(f, " batch_size={:?}", self.batch_size)?;
        write!(f, " instance_id={:?}", self.instance_id)?;
        write!(f, " dry_run={:?}", self.dry_run)?;
        write!(f, " extra_string={:?}", self.extra_string)?;
        write!(f, " min_ttl={:?}", self.min_ttl)?;
        write!(f, " max_ttl={:?}", self.max_ttl)?;
        write!(f, " integrity_check={:?}", self.integrity_check)?;
        write!(f, " interface={:?}", self.interface)?;
        write!(f, " max_probes={:?}", self.max_probes)?;
        write!(f, " output_file_csv={:?}", self.output_file_csv)?;
        write!(f, " packets={:?}", self.packets)?;
        write!(f, " probing_rate={:?}", self.probing_rate)?;
        write!(f, " rate_limiting_method={:?}", self.rate_limiting_method)?;
        write!(f, " receiver_wait_time={:?}", self.receiver_wait_time)
    }
}
