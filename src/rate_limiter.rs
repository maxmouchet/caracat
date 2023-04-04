//! Limit the rate at which packets are sent.
use std::cmp::max;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use strum::EnumString;

use circular_queue::CircularQueue;
use strum::Display;

/// A rate limiter to send packets at a precise rate.
pub struct RateLimiter {
    method: RateLimitingMethod,
    sleep_resolution: Duration,
    target_delta: Duration,
    curr_tp: Instant,
    last_tp: Instant,
    statistics: Arc<Mutex<RateLimiterStatistics>>,
}

impl RateLimiter {
    /// Build a new rate limiter with the specific target rate in items/s.
    pub fn new(target_rate: u64, steps: u64, method: RateLimitingMethod) -> Self {
        let target_delta = Duration::from_nanos(steps * 1_000_000_000 / target_rate);
        RateLimiter {
            method,
            sleep_resolution: RateLimiter::sleep_resolution(),
            target_delta,
            curr_tp: Instant::now(),
            last_tp: Instant::now(),
            statistics: Arc::new(Mutex::new(RateLimiterStatistics::new(steps, target_delta))),
        }
    }

    pub fn wait(&mut self) {
        self.curr_tp = Instant::now();
        let mut current_delta = self.curr_tp - self.last_tp;
        self.statistics
            .lock()
            .unwrap()
            .record_inter_call_delta(current_delta);

        // (1) Early return if we do not need to wait.
        if current_delta >= self.target_delta {
            self.last_tp = Instant::now();
            self.statistics
                .lock()
                .unwrap()
                .record_effective_delta(current_delta);
            return;
        }

        // (2) Wait if possible.
        if (self.method == RateLimitingMethod::Auto || self.method == RateLimitingMethod::Sleep)
            && self.sleep_resolution < (self.target_delta - current_delta)
        {
            sleep(self.target_delta - current_delta)
        }

        // (3) Spin wait.
        loop {
            self.curr_tp = Instant::now();
            current_delta = self.curr_tp - self.last_tp;
            if (self.method == RateLimitingMethod::Sleep || self.method == RateLimitingMethod::None)
                || current_delta >= self.target_delta
            {
                break;
            }
        }

        self.statistics
            .lock()
            .unwrap()
            .record_effective_delta(current_delta);
        self.last_tp = Instant::now();
    }

    /// Return a reference to the rate limiter statistics.
    /// This reference can be cloned to read the statistics from another thread.
    pub fn statistics(&self) -> &Arc<Mutex<RateLimiterStatistics>> {
        &self.statistics
    }

    fn sleep_resolution() -> Duration {
        let mut worst_case = Duration::from_nanos(0);
        for _ in 0..5 {
            let start = Instant::now();
            sleep(Duration::from_nanos(1));
            let delta = Instant::now() - start;
            worst_case = max(worst_case, delta);
        }
        worst_case
    }
}

#[derive(Debug)]
pub struct RateLimiterStatistics {
    steps: u64,
    target_delta: Duration,
    effective: CircularQueue<f64>,
    inter_call: CircularQueue<f64>,
}

impl RateLimiterStatistics {
    pub fn new(steps: u64, target_delta: Duration) -> Self {
        RateLimiterStatistics {
            steps,
            target_delta,
            effective: CircularQueue::with_capacity(64),
            inter_call: CircularQueue::with_capacity(64),
        }
    }

    pub fn record_effective_delta(&mut self, delta: Duration) {
        self.effective.push(delta.as_nanos() as f64);
    }

    pub fn record_inter_call_delta(&mut self, delta: Duration) {
        self.inter_call.push(delta.as_nanos() as f64);
    }

    /// The percentage of time that is spent oustide the rate limiter.
    pub fn average_utilization(&self) -> f64 {
        let average = if self.inter_call.len() > 1 {
            self.inter_call.iter().sum::<f64>() / self.inter_call.len() as f64
        } else {
            0.
        };
        average / self.target_delta.as_nanos() as f64
    }

    /// The effective rate achieved.
    pub fn average_rate(&self) -> f64 {
        let average = if self.effective.len() > 1 {
            self.effective.iter().sum::<f64>() / self.effective.len() as f64
        } else {
            0.
        };
        if average > 0. {
            self.steps as f64 * (1_000_000_000. / average)
        } else {
            0.
        }
    }
}

impl Display for RateLimiterStatistics {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "average_rate={:.0}", self.average_rate())?;
        write!(
            f,
            " average_utilization={:.0}",
            self.average_utilization() * 100.0
        )
    }
}

#[derive(Copy, Clone, Debug, Display, EnumString, PartialEq)]
#[strum(serialize_all = "lowercase")]
pub enum RateLimitingMethod {
    Auto,
    Active,
    Sleep,
    None,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::rate_limiter::{RateLimiter, RateLimitingMethod};

    fn measure_time(mut f: impl FnMut()) -> Duration {
        let start = Instant::now();
        f();
        let stop = Instant::now();
        stop - start
    }

    // These tests are ignored by default as they can fail on GitHub Actions.
    // Use `cargo test -- --ignored` to run them.

    #[test]
    #[ignore]
    fn test_500pps_1step() {
        // 750 packets at 500pps should take at-least 1.5s
        let mut rl = RateLimiter::new(500, 1, RateLimitingMethod::Auto);
        let delta = measure_time(|| {
            for _ in 0..750 {
                rl.wait();
            }
        });
        assert!(delta >= Duration::from_millis(1250));
        assert!(delta <= Duration::from_millis(2000));
    }

    #[test]
    #[ignore]
    fn test_500pps_10step() {
        // 750 packets at 500pps should take at-least 1.5s (steps = 10)
        let mut rl = RateLimiter::new(500, 10, RateLimitingMethod::Auto);
        let delta = measure_time(|| {
            for _ in 0..75 {
                rl.wait();
            }
        });
        assert!(delta >= Duration::from_millis(1250));
        assert!(delta <= Duration::from_millis(2000));
    }

    #[test]
    #[ignore]
    fn test_100kpps_1step() {
        // 50k packets at 100k pps should take at-least 0.5s
        let mut rl = RateLimiter::new(100_000, 1, RateLimitingMethod::Auto);
        let delta = measure_time(|| {
            for _ in 0..50_000 {
                rl.wait();
            }
        });
        assert!(delta >= Duration::from_millis(450));
        assert!(delta <= Duration::from_millis(1000));
    }

    #[test]
    #[ignore]
    fn test_100kpps_10step() {
        // 50k packets at 100k pps should take at-least 0.5s (steps = 100)
        let mut rl = RateLimiter::new(100_000, 100, RateLimitingMethod::Auto);
        let delta = measure_time(|| {
            for _ in 0..500 {
                rl.wait();
            }
        });
        assert!(delta >= Duration::from_millis(450));
        assert!(delta <= Duration::from_millis(1000));
    }
}
