//! A traceroute implementation on top of caracat,
//! inspired by Dmitry Butskoy traceroute for Linux:
//! https://traceroute.sourceforge.net
use anyhow::Result;
use caracat::models::{Probe, L4};
use clap::Parser;

use caracat::receiver::Receiver;
use caracat::sender::Sender;
use caracat::utilities::get_default_interface;
use dns_lookup::{lookup_addr, lookup_host};
use rand::{thread_rng, Rng};

use irrc::{Connection, IrrClient, Query};
use lazy_static::lazy_static;
use regex::Regex;
use std::net::IpAddr;

fn lookup_as(irr: &mut Connection, addr: IpAddr) -> Option<String> {
    // TODO: Better way to extract route/origin with RPSL?
    fn get_prefix(entry: &str) -> Option<u8> {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"route6?:\s+(.+)\/(\d+)").unwrap();
        }
        RE.captures(entry)
            .and_then(|captures| captures.get(2))
            .and_then(|m| m.as_str().parse::<u8>().ok())
    }

    fn get_origin(entry: &str) -> Option<String> {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"origin:\s+(AS\d+)").unwrap();
        }
        RE.captures(entry)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str().to_string())
    }

    irr.pipeline()
        .push(Query::RoutesLessEqual(addr.to_string()))
        .ok()?
        .responses::<String>()
        .filter_map(|result| result.ok())
        .max_by_key(|entry| get_prefix(entry.content()))
        .and_then(|entry| get_origin(entry.content()))
}

// Options are in the same order as `traceroute --help`.
#[derive(Parser, Debug)]
#[command(author, version, long_about = None)]
struct Args {
    /// Use IPv4
    #[arg(group = "af", short = '4', default_value_t = false)]
    ipv4: bool,
    /// Use IPv6
    #[arg(group = "af", short = '6', default_value_t = false)]
    ipv6: bool,
    /// Start from the first_ttl hop.
    #[arg(short = 'f', long = "first", default_value_t = 1)]
    first_ttl: u8,
    /// Use ICMP ECHO for tracerouting.
    #[arg(short = 'I', long = "icmp", default_value_t = false)]
    icmp: bool,
    /// Use TCP SYN for tracerouting.
    #[arg(short = 'T', long = "tcp", default_value_t = false)]
    tcp: bool,
    /// Specify a network interface to operate with.
    #[arg(short = 'i', long = "interface", default_value_t = get_default_interface())]
    device: String,
    /// Set the max number of hops (max TTL to be reached).
    #[arg(short = 'm', long = "max-hops", default_value_t = 30)]
    max_ttl: u8,
    /// Do not resolve IP addresses to their domain names
    #[arg(short = 'n', default_value_t = false)]
    do_not_resolve: bool,
    /// Set the destination port to use.
    #[arg(short = 'p', long = "port", default_value_t = 33434)]
    dport: u16,
    /// Wait for a probe no more than N seconds.
    #[arg(short = 'w', long = "wait", default_value_t = 5.0)]
    wait: f64,
    /// Show ICMP extensions (if present), including MPLS.
    #[arg(short = 'e', long = "extensions", default_value_t = false)]
    extensions: bool,
    /// Perform AS path lookups in routing registries and print results directly after the corresponding addresses.
    #[arg(short = 'A', long = "as-path-lookups", default_value_t = false)]
    as_path_lookups: bool,
    /// Use source port num for outgoing packets.
    #[arg(long = "sport", default_value_t = 24000)]
    sport: u16,
    /// The host to traceroute to.
    #[arg(index = 1)]
    host: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let instance_id = thread_rng().gen_range(0..u16::MAX);
    let mut sender = Sender::new(&args.device, None, None, instance_id, false)?;
    let mut receiver = Receiver::new_interactive(&args.device, (args.wait * 1000.0) as i32)?;

    let mut irr = if args.as_path_lookups {
        IrrClient::new("whois.radb.net:43").connect().ok()
    } else {
        None
    };

    let host = args.host;
    let addr = match host.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => lookup_host(&host)
            .unwrap()
            .into_iter()
            .filter(|addr| !(addr.is_ipv4() && args.ipv6))
            .filter(|addr| !(addr.is_ipv6() && args.ipv4))
            .next()
            .unwrap(),
    };

    let mut protocol = L4::UDP;
    if args.icmp {
        match addr {
            IpAddr::V4(_) => protocol = L4::ICMP,
            IpAddr::V6(_) => protocol = L4::ICMPv6,
        }
    } else if args.tcp {
        protocol = L4::TCP;
    }

    // TODO: Packet size
    println!(
        "traceroute to {} ({}), {} hops max, ?? byte packets",
        addr, host, args.max_ttl
    );

    for ttl in args.first_ttl..=args.max_ttl {
        let probe = Probe {
            dst_addr: addr,
            src_port: args.sport,
            dst_port: args.dport,
            ttl,
            protocol,
        };
        sender.send(&probe).unwrap();

        match receiver.next_reply() {
            Ok(reply) => {
                if !reply.is_valid(instance_id) || reply.probe_dst_addr != addr {
                    continue;
                }
                let host = if !args.do_not_resolve {
                    lookup_addr(&reply.reply_src_addr).ok()
                } else {
                    None
                };
                let asn = irr
                    .as_mut()
                    .and_then(|mut irr| lookup_as(&mut irr, reply.reply_src_addr));
                // TODO: Print [ASN*] only when -A is specified
                // TODO: Print MPLS labels when -e is specified
                // TODO: Do not print IP between parens if -n is specified
                println!(
                    "{:>2}  {} ({}) [{}] {:?}ms",
                    reply.probe_ttl,
                    host.unwrap_or(reply.reply_src_addr.to_string()),
                    reply.reply_src_addr,
                    asn.unwrap_or("*".to_string()),
                    reply.rtt as f64 / 10.0
                );
                if reply.reply_src_addr == probe.dst_addr {
                    break;
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}
