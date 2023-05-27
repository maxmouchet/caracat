//! Utilities for logging probing statistics.
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::Duration;

use log::info;

use crate::rate_limiter::RateLimiterStatistics;
use crate::receive_loop::ReceiverStatistics;
use crate::send_loop::ProberStatistics;

pub struct StatisticsLogger {
    handle: JoinHandle<()>,
    stopped: Arc<Mutex<bool>>,
}

impl StatisticsLogger {
    pub fn new(
        prober_statistics: Arc<Mutex<ProberStatistics>>,
        rate_statistics: Arc<Mutex<RateLimiterStatistics>>,
        receiver_statistics: Arc<Mutex<ReceiverStatistics>>,
    ) -> Self {
        let stopped = Arc::new(Mutex::new(false));
        let stopped_thr = stopped.clone();
        let handle = thread::spawn(move || {
            let log = || {
                info!("{}", prober_statistics.lock().unwrap());
                info!("{}", rate_statistics.lock().unwrap());
                info!("{}", receiver_statistics.lock().unwrap());
            };
            // TODO: Simplify this logic with async?
            let refresh = Duration::from_millis(100);
            let interval = Duration::from_millis(5000);
            let mut elapsed = Duration::from_millis(0);
            while !*stopped_thr.lock().unwrap() {
                sleep(refresh);
                elapsed += refresh;
                if elapsed >= interval {
                    log();
                    elapsed = Duration::from_millis(0);
                }
            }
            log();
        });
        Self { stopped, handle }
    }

    pub fn stop(self) {
        *self.stopped.lock().unwrap() = true;
        self.handle.join().unwrap();
    }
}
