//! A partial implementation of Yarrp in Rust on top of caracat.
//! The CLI interface should be identical, but not all flags are implemented.
//! Furthermore, the output is in CSV and not in Yarrp format.
//! See https://github.com/cmand/yarrp for the original tool.
//! Run with `cargo run --example yarrp -- --help`.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Result};
use caracat::high_level::{probe, Config};
use caracat::models::{Probe, L4};
use caracat::utilities::{configure_logger, exit_process_on_panic, get_default_interface};
use clap::Parser;
use ip_network::IpNetwork;
use libm::{exp, lgamma, log};
use log::LevelFilter;
use permutation_iterator::Permutor;
use pnet::util::MacAddr;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use strum::Display;

// http://www.masaers.com/2013/10/08/Implementing-Poisson-pmf.html
fn poisson_pmf(k: f64, lambda: f64) -> f64 {
    exp(k * log(lambda) - lgamma(k + 1.0) - lambda)
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Display, clap::ValueEnum)]
#[strum(serialize_all = "lowercase")]
enum ProbeType {
    ICMP,
    ICMP_REPLY,
    TCP_SYN,
    TCP_ACK,
    UDP,
    ICMP6,
    UDP6,
    TCP6_SYN,
    TCP6_ACK,
}

impl From<ProbeType> for L4 {
    /// Convert Yarrp probe type to caracat probe type.
    fn from(value: ProbeType) -> Self {
        match value {
            ProbeType::ICMP => L4::ICMP,
            ProbeType::ICMP6 => L4::ICMPv6,
            ProbeType::UDP => L4::UDP,
            _ => todo!("Probe type not implemented in caracat"),
        }
    }
}

/// Iterates randomly over the (prefix, ttl) space.
struct ProbingSpace {
    permutor: Permutor,
    prefixes: Vec<IpNetwork>,
    ttls: Vec<u8>,
}

impl ProbingSpace {
    pub fn new(prefixes: Vec<IpNetwork>, ttls: Vec<u8>, seed: u64) -> ProbingSpace {
        let permutor = Permutor::new_with_u64_key((prefixes.len() * ttls.len()) as u64, seed);
        ProbingSpace {
            permutor,
            prefixes,
            ttls,
        }
    }

    fn get(&self, index: usize) -> (IpNetwork, u8) {
        let (index, coordinate) = (index / self.prefixes.len(), index % self.prefixes.len());
        let prefix = self.prefixes[coordinate];
        let (_, coordinate) = (index / self.ttls.len(), index % self.ttls.len());
        let ttl = self.ttls[coordinate];
        (prefix, ttl)
    }
}

impl Iterator for ProbingSpace {
    type Item = (IpNetwork, u8);

    fn next(&mut self) -> Option<Self::Item> {
        match self.permutor.next() {
            Some(index) => Some(self.get(index as usize)),
            None => None,
        }
    }
}

/// A partial implementation of Yarrp on top of caracat.
#[derive(Parser, Debug)]
#[command(author, version, long_about = None)]
struct Args {
    /// Output file (caracat CSV format).
    #[arg(short = 'o', long, default_value_os_t = PathBuf::from("output.csv"))]
    output: PathBuf,
    /// Probe type.
    #[arg(short = 't', long = "type", default_value_t = ProbeType::ICMP)]
    probe_type: ProbeType,
    /// Scan rate in pps.
    #[arg(short = 'r', long, default_value_t = 10)]
    rate: u64,
    /// Number of probes to issue [default: unlimited].
    #[arg(short = 'c', long)]
    count: Option<u64>,
    /// Verbose [default: off].
    #[arg(short = 'v', long, default_value_t = false)]
    verbose: bool,
    /// Seed [default: random].
    #[arg(short = 'S', long)]
    seed: Option<u64>,
    /// Source address of probes [default: auto].
    #[arg(short = 'a', long)]
    srcaddr: Option<Ipv4Addr>,
    /// Transport dst port.
    #[arg(short = 'p', long, default_value_t = 80)]
    port: u16,
    /// Don't send probes [default: off].
    #[arg(short = 'T', long, default_value_t = false)]
    test: bool,
    /// Prober instance.
    #[arg(short = 'E', long, default_value_t = 0)]
    instance: u16,
    /// Input target file [default: none].
    #[arg(short = 'i', long)]
    input: PathBuf,
    /// BGP table [default: none].
    #[arg(short = 'b', long)]
    bgp: Option<PathBuf>,
    /// Prefix blocklist [default: none].
    #[arg(short = 'B', long)]
    blocklist: Option<PathBuf>,
    /// Entire IPv4/IPv6 Internet [default: off].
    #[arg(short = 'Q', long, default_value_t = false)]
    entire: bool,
    /// Minimum TTL.
    #[arg(short = 'l', long, default_value_t = 1)]
    minttl: u8,
    /// Maximum TTL.
    #[arg(short = 'm', long, default_value_t = 16)]
    maxttl: u8,
    /// Fill mode maxttl [default: none].
    #[arg(short = 'F', long)]
    fillmode: Option<u8>,
    /// Scan sequentially [default: random].
    #[arg(short = 's', long, default_value_t = false)]
    sequential: bool,
    /// Neighborhood TTL [default: none].
    #[arg(short = 'n', long)]
    neighborhood: Option<u8>,
    /// Poisson TTLs [default: uniform].
    #[arg(short = 'Z', long)]
    poisson: Option<f64>,
    /// Network interface.
    #[arg(short = 'I', long, default_value_t = get_default_interface())]
    interface: String,
    /// MAC of gateway router [default: auto].
    #[arg(short = 'G', long)]
    dstmac: Option<MacAddr>,
    /// MAC of probing host [default: auto].
    #[arg(short = 'M', long)]
    srcmac: Option<MacAddr>,
    /// Granularity to probe input subnets [default: none].
    #[arg(short = 'g', long)]
    granularity: Option<u8>,
    /// Ext Header number to add [default: none].
    #[arg(short = 'X', long)]
    v6eh: Option<u8>,
    // /// Probes a target in each /24 (IPv4), or each /48 (IPv6), of the specified subnets.
    // TODO: Implement subnet splitting.
    // targets: Option<Vec<String>>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        configure_logger(LevelFilter::Trace);
    } else {
        configure_logger(LevelFilter::Info);
    }
    exit_process_on_panic();

    if args.entire {
        bail!("--entire is not implemented")
    }

    if args.fillmode.is_some() {
        bail!("--fillmode is not implemented")
    }

    if args.granularity.is_some() {
        bail!("--granularity is not implemented")
    }

    if args.neighborhood.is_some() {
        bail!("--neighborhood is not implemented")
    }

    if args.sequential {
        bail!("--sequential is not implemented")
    }

    if args.srcaddr.is_some() {
        bail!("--srcaddr is not implemented (determined automatically by caracat)")
    }

    if args.srcmac.is_some() {
        bail!("--srcmac is not implemented (determined automatically by caracat)")
    }

    if args.dstmac.is_some() {
        bail!("--dstmac is not implemented (determined automatically by caracat)")
    }

    if args.v6eh.is_some() {
        bail!("--v6eh is not implemented")
    }

    let config = Config {
        allowed_prefixes_file: args.bgp,
        blocked_prefixes_file: args.blocklist,
        instance_id: args.instance,
        dry_run: args.test,
        min_ttl: Some(args.minttl),
        max_ttl: Some(args.maxttl),
        interface: args.interface,
        max_probes: args.count,
        output_file_csv: Some(args.output),
        probing_rate: args.rate,
        ..Default::default()
    };

    let mut rng = match args.seed {
        None => SmallRng::from_entropy(),
        Some(seed) => SmallRng::seed_from_u64(seed),
    };

    let protocol = L4::from(args.probe_type);
    let ttls: Vec<u8> = (args.minttl..args.maxttl).collect();

    let input = BufReader::new(File::open(args.input)?);
    let prefixes = input
        .lines()
        .flatten()
        .flat_map(|line| IpNetwork::from_str(&line))
        .collect();

    let space = ProbingSpace::new(prefixes, ttls, rng.gen());

    let mut probes: Box<dyn Iterator<Item = Probe>>;
    probes = Box::new(space.map(|(prefix, ttl)| Probe {
        dst_addr: prefix.network_address(), // TODO: prefix splitting + "flow mapping"
        src_port: 24000,
        dst_port: args.port,
        ttl,
        protocol,
    }));

    // We cannot use `if let Some(lambda) = ...` here as lambda will be dropped before calling `probe`.
    let lambda = args.poisson.unwrap_or(0.);
    if lambda > 0. {
        probes = Box::new(probes.filter(|probe| {
            let p = poisson_pmf(probe.ttl as f64, lambda);
            rng.gen::<f64>() <= p
        }));
    }

    probe(config, probes)?;
    Ok(())
}
