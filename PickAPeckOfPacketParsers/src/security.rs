use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const PORT_SCAN_WINDOW: Duration = Duration::from_secs(5);
const PORT_SCAN_THRESHOLD: usize = 15;

/// Flags a source IP that hits a lot of distinct destination ports on this
/// host in a short window — the same shape of traffic Portofino itself
/// generates.
pub struct PortScanTracker {
    recent: HashMap<IpAddr, VecDeque<(Instant, u16)>>,
    alerted: HashMap<IpAddr, Instant>,
}

impl PortScanTracker {
    pub fn new() -> Self {
        Self {
            recent: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    pub fn check(&mut self, src: IpAddr, dst_port: u16) -> Option<String> {
        let now = Instant::now();

        let hits = self.recent.entry(src).or_default();
        hits.push_back((now, dst_port));
        while let Some(&(t, _)) = hits.front() {
            if now.duration_since(t) > PORT_SCAN_WINDOW {
                hits.pop_front();
            } else {
                break;
            }
        }

        let distinct_ports: HashSet<u16> = hits.iter().map(|&(_, p)| p).collect();
        if distinct_ports.len() < PORT_SCAN_THRESHOLD {
            return None;
        }

        // Only alert once per window per source, rather than once per packet.
        if let Some(&last) = self.alerted.get(&src) {
            if now.duration_since(last) < PORT_SCAN_WINDOW {
                return None;
            }
        }
        self.alerted.insert(src, now);

        Some(format!(
            "ALERT  Possible port scan from {}: {} distinct ports in {}s",
            src,
            distinct_ports.len(),
            PORT_SCAN_WINDOW.as_secs()
        ))
    }
}

/// Flags an IP that shows up claiming a different MAC address than it did
/// last time it was seen in an ARP packet.
pub struct ArpSpoofTracker {
    known: HashMap<Ipv4Addr, MacAddr>,
}

impl ArpSpoofTracker {
    pub fn new() -> Self {
        Self { known: HashMap::new() }
    }

    pub fn check(&mut self, ip: Ipv4Addr, mac: MacAddr) -> Option<String> {
        if mac == MacAddr::new(0, 0, 0, 0, 0, 0) {
            return None;
        }

        match self.known.insert(ip, mac) {
            Some(prev) if prev != mac => Some(format!(
                "ALERT  Possible ARP spoofing: {} now claimed by {} (was {})",
                ip, mac, prev
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_scan_fires_at_threshold() {
        let mut tracker = PortScanTracker::new();
        let src: IpAddr = "10.0.0.5".parse().unwrap();

        for port in 0..PORT_SCAN_THRESHOLD as u16 - 1 {
            assert!(tracker.check(src, port).is_none(), "should not fire before threshold");
        }
        let alert = tracker.check(src, PORT_SCAN_THRESHOLD as u16).unwrap();
        assert!(alert.contains("10.0.0.5"));
    }

    #[test]
    fn port_scan_has_cooldown() {
        let mut tracker = PortScanTracker::new();
        let src: IpAddr = "10.0.0.5".parse().unwrap();

        for port in 0..PORT_SCAN_THRESHOLD as u16 {
            tracker.check(src, port);
        }
        // Already alerted above; one more distinct port shouldn't re-fire immediately.
        assert!(tracker.check(src, 9999).is_none());
    }

    #[test]
    fn port_scan_ignores_repeated_port() {
        let mut tracker = PortScanTracker::new();
        let src: IpAddr = "10.0.0.5".parse().unwrap();

        for _ in 0..50 {
            assert!(tracker.check(src, 443).is_none(), "same port repeated isn't a scan");
        }
    }

    #[test]
    fn arp_spoof_ignores_first_sighting() {
        let mut tracker = ArpSpoofTracker::new();
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        assert!(tracker.check(ip, mac).is_none());
    }

    #[test]
    fn arp_spoof_ignores_unchanged_mac() {
        let mut tracker = ArpSpoofTracker::new();
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        tracker.check(ip, mac);
        assert!(tracker.check(ip, mac).is_none());
    }

    #[test]
    fn arp_spoof_fires_on_mac_change() {
        let mut tracker = ArpSpoofTracker::new();
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let old_mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let new_mac = MacAddr::new(6, 5, 4, 3, 2, 1);

        tracker.check(ip, old_mac);
        let alert = tracker.check(ip, new_mac).unwrap();
        assert!(alert.contains("192.168.1.1"));
        assert!(alert.contains(&old_mac.to_string()));
        assert!(alert.contains(&new_mac.to_string()));
    }

    #[test]
    fn arp_spoof_ignores_zero_mac() {
        let mut tracker = ArpSpoofTracker::new();
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert!(tracker.check(ip, MacAddr::new(0, 0, 0, 0, 0, 0)).is_none());
    }
}
