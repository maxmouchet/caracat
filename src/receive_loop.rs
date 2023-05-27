//! High-level interface for capturing replies.
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use log::{error, trace};
use pcap::{Direction, Error};
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::parser::parse;
use crate::utilities::{get_device, get_extension};

// The pcap crate doesn't support `pcap_loop` and `pcap_breakloop`,
// so we implement our own looping mechanism.
pub struct ReceiveLoop {
    handle: JoinHandle<()>,
    stopped: Arc<Mutex<bool>>,
    statistics: Arc<Mutex<ReceiverStatistics>>,
}

impl ReceiveLoop {
    pub fn new(
        interface: String,
        output_file_csv: Option<PathBuf>,
        output_file_pcap: Option<PathBuf>,
        caracat_id: u16,
        extra_string: Option<String>,
        integrity_check: bool,
    ) -> Self {
        // By default if a thread panic, the other threads are not affected and the error
        // is only surfaced when joining the thread. However since this is a long-lived thread,
        // we're not calling join until the end of the process. Since this loop is critical to
        // the process, we don't want it to crash silently. We currently rely on
        // `utilities::exit_process_on_panic` but we might find a better way in the future.
        let stopped = Arc::new(Mutex::new(false));
        let stopped_thr = stopped.clone();
        let statistics = Arc::new(Mutex::new(ReceiverStatistics::default()));
        let statistics_thr = statistics.clone();
        let handle = thread::spawn(move || {
            let device = get_device(&interface).unwrap();

            let mut cap = pcap::Capture::from_device(device)
                .unwrap()
                // A buffer of 64M is enough to store ~1M ICMPv6 Time Exceeded replies.
                // We probably don't need as much but this lets us handle burst of incoming packets.
                .buffer_size(64 * 1024 * 1024)
                // `timeout` has two uses here:
                // 1. Batch deliveries from pcap to reduce syscall overhead
                //    See "packet buffer timeout" in PCAP(3PCAP) man page.
                //    See also section 26.2 "BSD Packet Filter" in "Unix Network Programming vol. 1".
                // 2. Allow us to break the capture loop through the `stopped` variable.
                // This has no impact of RTT computation as packets are timestamped as soon as they are captured by pcap.
                .timeout(100)
                .open()
                .unwrap();

            // Filter as much as possible at the kernel level.
            // We're only interested in incoming ICMP packets.
            cap.direction(Direction::In).unwrap();
            cap.filter(
                "(ip and icmp and (
                    icmp[icmptype] = icmp-echoreply or
                    icmp[icmptype] = icmp-timxceed or
                    icmp[icmptype] = icmp-unreach))
                    or
                    (ip6 and icmp6 and (
                    icmp6[icmp6type] = icmp6-echoreply or
                    icmp6[icmp6type] = icmp6-timeexceeded or
                    icmp6[icmp6type] = icmp6-destinationunreach))",
                true,
            )
            .unwrap();

            let output_csv: Box<dyn Write> = match output_file_csv {
                None => Box::new(stdout().lock()),
                Some(path) => {
                    let file = File::create(&path).unwrap();
                    let writer = BufWriter::new(file);
                    match get_extension(&path).as_str() {
                        "zst" => Box::new(ZstdEncoder::new(writer, 1).unwrap().auto_finish()),
                        _ => Box::new(writer),
                    }
                }
            };

            let mut output_pcap = output_file_pcap.map(|path| cap.savefile(path).unwrap());

            let mut csv_writer = csv::WriterBuilder::new()
                .has_headers(false) // TODO: Set to true, but how to serialize MPLS labels?
                .from_writer(output_csv);

            loop {
                let pcap_statistics = cap.stats().unwrap();
                let linktype = cap.get_datalink();
                match cap.next_packet() {
                    Ok(packet) => {
                        let mut statistics = statistics_thr.lock().unwrap();
                        statistics.pcap_received = pcap_statistics.received;
                        statistics.pcap_dropped = pcap_statistics.dropped;
                        statistics.pcap_if_dropped = pcap_statistics.if_dropped;
                        statistics.received += 1;
                        match parse(&packet, linktype) {
                            // TODO: Avoid mut reply here?
                            Ok(mut reply) => {
                                if integrity_check && reply.is_valid(caracat_id) {
                                    trace!("{}", reply);
                                    statistics
                                        .icmp_messages_incl_dest
                                        .insert(reply.reply_src_addr);
                                    if reply.is_time_exceeded() {
                                        statistics
                                            .icmp_messages_excl_dest
                                            .insert(reply.reply_src_addr);
                                    }
                                    reply.extra = extra_string.clone();
                                    csv_writer.serialize(reply).unwrap();
                                    // TODO: Write round column.
                                    // TODO: Compare output with caracat (capture timestamp resolution?)
                                } else {
                                    trace!(
                                        "invalid_packet_reason={} invalid_packet_hex={}",
                                        "caracat_checksum",
                                        hex::encode(packet.data),
                                    );
                                    statistics.received_invalid += 1;
                                }
                            }
                            Err(error) => {
                                trace!(
                                    "invalid_packet_reason={} invalid_packet_hex={}",
                                    error,
                                    hex::encode(packet.data),
                                );
                                statistics.received_invalid += 1;
                            }
                        }
                        if let Some(o) = output_pcap.as_mut() {
                            o.write(&packet);
                        }
                    }
                    Err(Error::TimeoutExpired) => {}
                    Err(error) => error!("{:?}", error),
                }
                if *stopped_thr.lock().unwrap() {
                    break;
                }
            }
            csv_writer.flush().unwrap();
            if let Some(mut o) = output_pcap {
                o.flush().unwrap();
            }
        });
        ReceiveLoop {
            handle,
            stopped,
            statistics,
        }
    }

    pub fn stop(self) {
        *self.stopped.lock().unwrap() = true;
        self.handle.join().unwrap();
    }

    pub fn statistics(&self) -> &Arc<Mutex<ReceiverStatistics>> {
        &self.statistics
    }
}

// TODO: Cheaper clone (do not copy hashset).
#[derive(Clone, Default, Debug)]
pub struct ReceiverStatistics {
    /// Number of packets received.
    pub pcap_received: u32,
    /// Number of packets dropped because there was no room in the operating system's buffer when
    /// they arrived, because packets weren't being read fast enough.
    pub pcap_dropped: u32,
    /// Number of packets dropped by the network interface or its driver.
    pub pcap_if_dropped: u32,
    pub received: u64,
    pub received_invalid: u64,
    pub icmp_messages_incl_dest: HashSet<Ipv6Addr>,
    pub icmp_messages_excl_dest: HashSet<Ipv6Addr>,
}

impl Display for ReceiverStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "pcap_received={}", self.pcap_received)?;
        write!(f, " pcap_dropped={}", self.pcap_dropped)?;
        write!(f, " pcap_interface_dropped={}", self.pcap_if_dropped)?;
        write!(f, " packets_received={}", self.received)?;
        write!(f, " packets_received_invalid={}", self.received_invalid,)?;
        write!(
            f,
            " icmp_distinct_incl_dest={}",
            self.icmp_messages_incl_dest.len(),
        )?;
        write!(
            f,
            " icmp_distinct_excl_dest={}",
            self.icmp_messages_excl_dest.len(),
        )
    }
}
