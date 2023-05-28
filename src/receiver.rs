use crate::models::Reply;
use crate::parser::parse;
use anyhow::{anyhow, Context, Result};
use pcap::{Active, Capture, Direction, Linktype, Stat};

pub struct Receiver {
    cap: Capture<Active>,
    linktype: Linktype,
}

impl Receiver {
    pub fn new(
        interface: &str,
        buffer_size: i32,
        timeout_ms: i32,
        immediate_mode: bool,
    ) -> Result<Self> {
        let mut cap = pcap::Capture::from_device(interface)?
            .buffer_size(buffer_size)
            // `timeout` has two uses here:
            // 1. Batch deliveries from pcap to reduce syscall overhead
            //    See "packet buffer timeout" in PCAP(3PCAP) man page.
            //    See also section 26.2 "BSD Packet Filter" in "Unix Network Programming vol. 1".
            // 2. Allow us to break the capture loop through the `stopped` variable.
            // This has no impact of RTT computation as packets are timestamped as soon as they are captured by pcap.
            .timeout(timeout_ms)
            .immediate_mode(immediate_mode)
            .open()?;

        // Filter as much as possible at the kernel level.
        // We're only interested in incoming ICMP packets.
        cap.direction(Direction::In)?;
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
        )?;

        let linktype = cap.get_datalink();
        Ok(Self { cap, linktype })
    }

    pub fn new_batch(interface: &str) -> Result<Self> {
        // A buffer of 64M is enough to store ~1M ICMPv6 Time Exceeded replies.
        // We probably don't need as much but this lets us handle burst of incoming packets.
        Self::new(interface, 64 * 1024 * 1024, 100, false)
    }

    pub fn new_interactive(interface: &str, timeout_ms: i32) -> Result<Self> {
        Self::new(interface, 1024 * 1024, timeout_ms, true)
    }

    pub fn next_reply(&mut self) -> Result<Reply> {
        match self.cap.next_packet() {
            Ok(packet) => match parse(&packet, self.linktype) {
                Ok(reply) => Ok(reply),
                Err(error) => Err(anyhow!(error)),
            },
            Err(error) => Err(anyhow!(error)),
        }
    }

    pub fn statistics(&mut self) -> Result<Stat> {
        self.cap.stats().context("cannot get pcap statistics")
    }
}
