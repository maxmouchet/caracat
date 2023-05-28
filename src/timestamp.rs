//! Utilities for encoding timestamps in probe packets.
//!
//! We only have 16 bits available, which is not enough to store a full 64-bit timestamp.
//! Our approach is the following:
//!
//! 1. Let's write `t_send` the send timestamp and `n` the maximum value that can be encoded: `(2^16 - 1)` in our case.
//! 2. We know that `t_send = ⌊t_send / n⌋ + t_send % n`. We store `t_send % n` in the packet.
//! 3. At `t_receive` we can retrieve `t_send` by computing `t_est = ⌊t_receive / n⌋ + t_send % n`.
//! 4. If `t_est > t_receive` then subtract `n`.
//! 5. This gives us `t_est = t_send` as-long as `t_receive - t_send < n`.
//!
//! If we use a resolution of 1/10ms for the timestamp this method works as long as the reply arrives less than 6.5535s later.
use std::time::Duration;

pub fn encode(timestamp: u64) -> u16 {
    (timestamp % 65535) as u16
}

pub fn decode(timestamp: u64, remainder: u16) -> u64 {
    let quotient = (timestamp as f64 / 65535.0).floor() as u64;
    let decoded = quotient * 65535 + remainder as u64;
    if decoded > timestamp {
        decoded - 65535
    } else {
        decoded
    }
}

pub fn difference(timestamp: u64, remainder: u16) -> u16 {
    (timestamp - decode(timestamp, remainder)) as u16
}

pub fn tenth_ms(duration: Duration) -> u64 {
    duration.as_micros() as u64 / 100
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::timestamp::{decode, difference, encode, tenth_ms};

    // TODO: Test when the current clock is below the encoded clock.
    // TODO: Test RTT recovery (sorted time from measurement time).

    #[test]
    fn test_timestamp_round_trip() {
        for i in 0..65535 {
            assert_eq!(decode(131069 + i, encode(131069)), 131069);
        }
    }

    #[test]
    #[ignore]
    fn test_timestamp_sleep() {
        let before = tenth_ms(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        let encoded = encode(before);
        sleep(Duration::from_millis(250));
        let after = tenth_ms(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        let diff = difference(after, encoded);
        assert!(diff / 10 >= 245);
        assert!(diff / 10 <= 255);
    }
}
