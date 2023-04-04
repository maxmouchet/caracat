use caracat::models::{MPLSLabel, Reply, L4};
use caracat::parser::parse;
use caracat::utilities::parse_as_ipv6;
use pcap::{Capture, Error};

fn parse_file(path: &str) -> Vec<Reply> {
    let mut replies = Vec::new();
    let mut cap = Capture::from_file(path).unwrap();
    let linktype = cap.get_datalink();
    loop {
        match cap.next_packet() {
            Ok(packet) => match parse(&packet, linktype) {
                Ok(reply) => replies.push(reply),
                Err(error) => println!("Parse error: {}", error),
            },
            Err(Error::NoMorePackets) => break,
            Err(_) => unreachable!(),
        }
    }
    replies
}

// TODO: Test is_valid() (needs new captures).

#[test]
fn test_icmp_icmp_ttl_exceeded() {
    let replies = parse_file("data/icmp-icmp-ttl-exceeded.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1613155623845580);
    assert_eq!(reply.reply_src_addr, parse_as_ipv6("72.14.204.68").unwrap());
    assert_eq!(reply.reply_dst_addr, parse_as_ipv6("192.168.1.5").unwrap());
    assert_eq!(reply.reply_size, 56);
    assert_eq!(reply.reply_ttl, 250);
    assert_eq!(reply.reply_protocol, L4::ICMP.into());
    assert_eq!(reply.reply_icmp_type, 11);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(reply.probe_dst_addr, parse_as_ipv6("8.8.8.8").unwrap());
    assert_eq!(reply.probe_size, 36);
    assert_eq!(reply.probe_ttl, 6);
    assert_eq!(reply.probe_protocol, L4::ICMP.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 0);
    assert_eq!(reply.quoted_ttl, 1);
    assert_eq!(reply.rtt, 66);
    assert!(!reply.is_destination_unreachable());
    assert!(!reply.is_echo_reply());
    assert!(reply.is_time_exceeded());
}

#[test]
fn test_icmp_icmp_ttl_exceeded_mpls() {
    let replies = parse_file("data/icmp-icmp-ttl-exceeded-mpls.pcap");
    assert_eq!(replies.len(), 1);

    // TODO: Parse MPLS labels
    let _label_1 = MPLSLabel {
        label: 25437,
        experimental: 0,
        bottom_of_stack: true,
        ttl: 1,
    };
    let _label_2 = MPLSLabel {
        label: 29567,
        experimental: 0,
        bottom_of_stack: false,
        ttl: 1,
    };

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1638522471773669);
    assert_eq!(reply.reply_src_addr, parse_as_ipv6("12.122.28.42").unwrap());
    assert_eq!(
        reply.reply_dst_addr,
        parse_as_ipv6("132.227.123.8").unwrap()
    );
    assert_eq!(reply.reply_size, 172);
    assert_eq!(reply.reply_ttl, 239);
    assert_eq!(reply.reply_protocol, L4::ICMP.into());
    assert_eq!(reply.reply_icmp_type, 11);
    assert_eq!(reply.reply_icmp_code, 0);
    // TODO: Parse MPLS labels
    // assert_eq!(reply.reply_mpls_labels.len(), 2);
    // assert_eq!(reply.reply_mpls_labels[0], label_1);
    // assert_eq!(reply.reply_mpls_labels[1], label_2);
    assert_eq!(
        reply.probe_dst_addr,
        parse_as_ipv6("65.83.239.127").unwrap()
    );
    assert_eq!(reply.probe_size, 42);
    assert_eq!(reply.probe_ttl, 12);
    assert_eq!(reply.probe_protocol, L4::ICMP.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 0);
    // The sequence number in the inner ICMP header of this reply
    // is different from the one in the probe packet, so we cannot
    // recover the RTT.
    // assert_eq!(reply.rtt , 553);
    assert_eq!(reply.quoted_ttl, 2);
    assert!(!reply.is_destination_unreachable());
    assert!(!reply.is_echo_reply());
    assert!(reply.is_time_exceeded());
}

#[test]
fn test_icmp_icmp_echo_reply() {
    let replies = parse_file("data/icmp-icmp-echo-reply.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1613155697130290);
    assert_eq!(reply.reply_src_addr, parse_as_ipv6("8.8.8.8").unwrap());
    assert_eq!(reply.reply_dst_addr, parse_as_ipv6("192.168.1.5").unwrap());
    assert_eq!(reply.reply_size, 40);
    assert_eq!(reply.reply_ttl, 117);
    assert_eq!(reply.reply_protocol, L4::ICMP.into());
    assert_eq!(reply.reply_icmp_type, 0);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(reply.probe_dst_addr, parse_as_ipv6("8.8.8.8").unwrap());
    assert_eq!(reply.probe_size, 0);
    assert_eq!(reply.probe_ttl, 10);
    assert_eq!(reply.probe_protocol, L4::ICMP.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 0);
    assert_eq!(reply.quoted_ttl, 0);
    assert_eq!(reply.rtt, 69);
    assert!(!reply.is_destination_unreachable());
    assert!(reply.is_echo_reply());
    assert!(!reply.is_time_exceeded());
}

#[test]
fn test_icmp6_icmp6_ttl_exceeded() {
    let replies = parse_file("data/icmp6-icmp6-ttl-exceeded.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1615987564867543);
    assert_eq!(
        reply.reply_src_addr,
        parse_as_ipv6("2a04:8ec0:0:a::1:119").unwrap()
    );
    assert_eq!(
        reply.reply_dst_addr,
        parse_as_ipv6("2a04:8ec0:0:164:620c:e59a:daf8:21e9").unwrap()
    );
    assert_eq!(reply.reply_size, 60);
    assert_eq!(reply.reply_ttl, 63);
    assert_eq!(reply.reply_protocol, L4::ICMPv6.into());
    assert_eq!(reply.reply_icmp_type, 3);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(
        reply.probe_dst_addr,
        parse_as_ipv6("2001:4860:4860::8888").unwrap()
    );
    assert_eq!(reply.probe_size, 12);
    assert_eq!(reply.probe_ttl, 2);
    assert_eq!(reply.probe_protocol, L4::ICMPv6.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 0);
    assert_eq!(reply.quoted_ttl, 1);
    assert_eq!(reply.rtt, 6);
    assert!(!reply.is_destination_unreachable());
    assert!(!reply.is_echo_reply());
    assert!(reply.is_time_exceeded());
}

#[test]
fn test_icmp6_icmp6_echo_reply() {
    let replies = parse_file("data/icmp6-icmp6-echo-reply.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1615987338565191);
    assert_eq!(
        reply.reply_src_addr,
        parse_as_ipv6("2001:4860:4860::8888").unwrap()
    );
    assert_eq!(
        reply.reply_dst_addr,
        parse_as_ipv6("2a04:8ec0:0:164:620c:e59a:daf8:21e9").unwrap()
    );
    assert_eq!(reply.reply_size, 18);
    assert_eq!(reply.reply_ttl, 118);
    assert_eq!(reply.reply_protocol, L4::ICMPv6.into());
    assert_eq!(reply.reply_icmp_type, 129);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(
        reply.probe_dst_addr,
        parse_as_ipv6("2001:4860:4860::8888").unwrap()
    );
    assert_eq!(reply.probe_size, 0);
    assert_eq!(reply.probe_ttl, 8);
    assert_eq!(reply.probe_protocol, L4::ICMPv6.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 0);
    assert_eq!(reply.quoted_ttl, 0);
    assert_eq!(reply.rtt, 13);
    assert!(!reply.is_destination_unreachable());
    assert!(reply.is_echo_reply());
    assert!(!reply.is_time_exceeded());
}

#[test]
fn test_udp_icmp_ttl_exceeded() {
    let replies = parse_file("data/udp-icmp-ttl-exceeded.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1613155487934429);
    assert_eq!(reply.reply_src_addr, parse_as_ipv6("72.14.204.68").unwrap());
    assert_eq!(reply.reply_dst_addr, parse_as_ipv6("192.168.1.5").unwrap());
    assert_eq!(reply.reply_size, 56);
    assert_eq!(reply.reply_ttl, 250);
    assert_eq!(reply.reply_protocol, L4::ICMP.into());
    assert_eq!(reply.reply_icmp_type, 11);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(reply.probe_dst_addr, parse_as_ipv6("8.8.8.8").unwrap());
    assert_eq!(reply.probe_size, 36);
    assert_eq!(reply.probe_ttl, 6);
    assert_eq!(reply.probe_protocol, L4::UDP.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 33434);
    assert_eq!(reply.quoted_ttl, 1);
    assert_eq!(reply.rtt, 83);
    assert!(!reply.is_destination_unreachable());
    assert!(!reply.is_echo_reply());
    assert!(reply.is_time_exceeded());
}

#[test]
fn test_udp_icmp6_ttl_exceeded() {
    let replies = parse_file("data/udp-icmp6-ttl-exceeded.pcap");
    assert_eq!(replies.len(), 1);

    let reply = &replies[0];
    assert_eq!(reply.capture_timestamp, 1615987632702320);
    assert_eq!(
        reply.reply_src_addr,
        parse_as_ipv6("2a04:8ec0:0:a::1:119").unwrap()
    );
    assert_eq!(
        reply.reply_dst_addr,
        parse_as_ipv6("2a04:8ec0:0:164:620c:e59a:daf8:21e9").unwrap()
    );
    assert_eq!(reply.reply_size, 60);
    assert_eq!(reply.reply_ttl, 63);
    assert_eq!(reply.reply_protocol, L4::ICMPv6.into());
    assert_eq!(reply.reply_icmp_type, 3);
    assert_eq!(reply.reply_icmp_code, 0);
    assert!(reply.reply_mpls_labels.is_empty());
    assert_eq!(
        reply.probe_dst_addr,
        parse_as_ipv6("2001:4860:4860::8888").unwrap()
    );
    assert_eq!(reply.probe_size, 12);
    assert_eq!(reply.probe_ttl, 2);
    assert_eq!(reply.probe_protocol, L4::UDP.into());
    assert_eq!(reply.probe_src_port, 24000);
    assert_eq!(reply.probe_dst_port, 33434);
    assert_eq!(reply.quoted_ttl, 1);
    assert_eq!(reply.rtt, 6);
    assert!(!reply.is_destination_unreachable());
    assert!(!reply.is_echo_reply());
    assert!(reply.is_time_exceeded());
}

#[test]
fn test_non_ip() {
    let replies = parse_file("data/arp.pcap");
    assert!(replies.is_empty());
}

// TODO: Test empty packet.
// TODO: Test other datalink types.
