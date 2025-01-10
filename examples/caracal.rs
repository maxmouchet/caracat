//! An implementation of caracal CLI on top of caracat.
//! See https://github.com/dioptra-io/caracal for the original tool.
use std::fmt::Debug;
use std::io::{stdin, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use caracat::high_level::{probe_from_csv, Config};
use caracat::rate_limiter::RateLimitingMethod;
use caracat::utilities::{configure_logger, exit_process_on_panic, get_default_interface};
use clap::Parser;
use log::{info, LevelFilter};
use rand::{thread_rng, Rng};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Probing rate in packets per second.
    #[arg(short = 'r', long, default_value_t = 100)]
    probing_rate: u64,
    /// Interface from which to send the packets.
    #[arg(short = 'z', long, default_value_t = get_default_interface())]
    interface: String,
    //// Specify the IPv4 source address to use in the packets (if probing in v4)
    #[arg(long)]
    source_address_v4: Option<Ipv4Addr>,
    //// Specify the IPv6 source address to use in the packets (if probing in v6)
    #[arg(long)]
    source_address_v6: Option<Ipv6Addr>,
    /// Number of probes to send before calling the rate limiter.
    #[arg(short = 'B', long, default_value_t = 128)]
    batch_size: u64,
    /// Minimum log level.
    #[arg(short = 'L', long, default_value_t = LevelFilter::Info)]
    log_level: LevelFilter,
    /// Number of packets to send per probe.
    #[arg(short = 'N', long, default_value_t = 1)]
    packets: u64,
    /// Maximum number of probes to send (unlimited by default).
    #[arg(short = 'P', long)]
    max_probes: Option<u64>,
    /// Time in seconds to wait after sending the probes to stop the receiver.
    #[arg(short = 'W', long, default_value_t = 1)]
    receiver_wait_time: u64,
    /// Method to use to limit the packets rate.
    #[arg(long, default_value_t = RateLimitingMethod::Auto)]
    rate_limiting_method: RateLimitingMethod,
    /// Do not send probes to prefixes *not* specified in file (allow list).
    #[arg(long)]
    allowed_prefixes_file: Option<PathBuf>,
    /// Do not send probes to prefixes specified in file (block list).
    #[arg(long)]
    blocked_prefixes_file: Option<PathBuf>,
    /// Do not send probes with ttl < min_ttl.
    #[arg(long)]
    min_ttl: Option<u8>,
    /// Do not send probes with ttl > max_ttl.
    #[arg(long)]
    max_ttl: Option<u8>,
    /// Identifier encoded in the probes (random by default).
    #[arg(long, default_value_t = thread_rng().gen_range(0..u16::MAX))]
    instance_id: u16,
    /// Extra column in the CSV output.
    #[arg(long)]
    extra_string: Option<String>,
    /// Do not send probes on the network.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Do not check that replies match valid probes.
    #[arg(long, default_value_t = false)]
    no_integrity_check: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    configure_logger(args.log_level);
    exit_process_on_panic();

    info!("Reading from stdin, press CTRL+D to stop...");
    let input: Box<dyn BufRead> = Box::new(stdin().lock());

    let config = Config {
        allowed_prefixes_file: args.allowed_prefixes_file,
        blocked_prefixes_file: args.blocked_prefixes_file,
        batch_size: args.batch_size,
        instance_id: args.instance_id,
        dry_run: args.dry_run,
        extra_string: args.extra_string,
        min_ttl: args.min_ttl,
        max_ttl: args.max_ttl,
        integrity_check: !args.no_integrity_check,
        interface: args.interface,
        src_ipv4_addr: args.source_address_v4,
        src_ipv6_addr: args.source_address_v6,
        max_probes: args.max_probes,
        packets: args.packets,
        probing_rate: args.probing_rate,
        rate_limiting_method: args.rate_limiting_method,
        receiver_wait_time: Duration::from_secs(args.receiver_wait_time),
    };

    probe_from_csv(config, input)?;
    Ok(())
}
