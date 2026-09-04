use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fires an alert once a single source touches several distinct decoy ports
/// within a trailing window. Every port here is bait — nothing legitimate
/// should ever connect to more than one — so the threshold can be much more
/// aggressive than a real-traffic port-scan heuristic.
const WINDOW: Duration = Duration::from_secs(10);
const THRESHOLD: usize = 3;

/// Once fired, a source won't fire again for this long, so one scanner
/// working through the whole port list doesn't produce one alert per port.
const COOLDOWN: Duration = Duration::from_secs(30);

pub struct ScanTracker {
    hits: Mutex<HashMap<IpAddr, VecDeque<(Instant, u16)>>>,
    last_alert: Mutex<HashMap<IpAddr, Instant>>,
}

impl ScanTracker {
    pub fn new() -> Self {
        ScanTracker {
            hits: Mutex::new(HashMap::new()),
            last_alert: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit on `port` from `ip` and returns an alert line if this
    /// source has just crossed the distinct-port threshold and isn't still
    /// in its cooldown from a previous alert.
    pub fn check(&self, ip: IpAddr, port: u16) -> Option<String> {
        let now = Instant::now();

        let distinct = {
            let mut hits = self.hits.lock().unwrap();
            let entry = hits.entry(ip).or_default();
            entry.push_back((now, port));
            entry.retain(|(seen, _)| now.duration_since(*seen) <= WINDOW);

            let mut ports: Vec<u16> = entry.iter().map(|(_, p)| *p).collect();
            ports.sort_unstable();
            ports.dedup();
            ports.len()
        };

        if distinct < THRESHOLD {
            return None;
        }

        let mut last_alert = self.last_alert.lock().unwrap();
        if let Some(last) = last_alert.get(&ip) {
            if now.duration_since(*last) < COOLDOWN {
                return None;
            }
        }
        last_alert.insert(ip, now);

        Some(format!(
            "ALERT  {} touched {} decoy ports in {}s — likely a scanner",
            ip,
            distinct,
            WINDOW.as_secs()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_once_threshold_crossed() {
        let tracker = ScanTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        assert_eq!(tracker.check(ip, 21), None);
        assert_eq!(tracker.check(ip, 22), None);
        assert!(tracker.check(ip, 23).is_some());
        // Cooldown suppresses an immediate re-fire.
        assert_eq!(tracker.check(ip, 25), None);
    }

    #[test]
    fn different_sources_tracked_independently() {
        let tracker = ScanTracker::new();
        let a: IpAddr = "10.0.0.5".parse().unwrap();
        let b: IpAddr = "10.0.0.6".parse().unwrap();

        assert_eq!(tracker.check(a, 21), None);
        assert_eq!(tracker.check(b, 21), None);
        assert_eq!(tracker.check(a, 22), None);
        assert_eq!(tracker.check(b, 22), None);
    }

    #[test]
    fn repeated_hits_on_one_port_dont_count_as_distinct() {
        let tracker = ScanTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        assert_eq!(tracker.check(ip, 21), None);
        assert_eq!(tracker.check(ip, 21), None);
        assert_eq!(tracker.check(ip, 21), None);
    }
}
