use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Failed-login window: an alert fires once one source has this many
/// failures within this many seconds of each other (by event time, not
/// wall-clock time — see `journal::JournalEntry::event_time`).
const WINDOW: Duration = Duration::from_secs(60);
const FAILURE_THRESHOLD: usize = 5;

/// A successful login counts as alert-worthy once at least this many recent
/// failures from the same source preceded it.
const SUCCESS_AFTER_FAILURES_MIN: usize = 3;

/// Once an alert of a given kind fires for a source, that same kind won't
/// fire again for this long — the two alert kinds cool down independently,
/// since a successful-login-after-failures alert is a distinct, more
/// urgent signal than the brute-force alert that likely just preceded it.
const COOLDOWN: Duration = Duration::from_secs(60);

pub struct BruteForceTracker {
    failures: Mutex<HashMap<String, VecDeque<SystemTime>>>,
    last_failure_alert: Mutex<HashMap<String, SystemTime>>,
    last_success_alert: Mutex<HashMap<String, SystemTime>>,
}

impl BruteForceTracker {
    pub fn new() -> Self {
        BruteForceTracker {
            failures: Mutex::new(HashMap::new()),
            last_failure_alert: Mutex::new(HashMap::new()),
            last_success_alert: Mutex::new(HashMap::new()),
        }
    }

    /// Prunes and counts `source`'s failures within `WINDOW` of
    /// `event_time`, without recording a new one.
    fn recent_failures(&self, source: &str, event_time: SystemTime) -> usize {
        let mut failures = self.failures.lock().unwrap();
        let Some(entry) = failures.get_mut(source) else {
            return 0;
        };
        entry.retain(|seen| event_time.duration_since(*seen).is_ok_and(|d| d <= WINDOW));
        entry.len()
    }

    /// True (and records `event_time` as the new high-water mark) if
    /// `source` isn't still in `map`'s cooldown as of `event_time`.
    fn cooldown_ok(map: &Mutex<HashMap<String, SystemTime>>, source: &str, event_time: SystemTime) -> bool {
        let mut map = map.lock().unwrap();
        let ok = match map.get(source) {
            Some(last) => event_time.duration_since(*last).is_ok_and(|d| d >= COOLDOWN),
            None => true,
        };
        if ok {
            map.insert(source.to_string(), event_time);
        }
        ok
    }

    /// Records a failed login from `source` at `event_time` and returns a
    /// brute-force alert line once the threshold is crossed (subject to
    /// this alert kind's own cooldown).
    pub fn check_failure(&self, source: &str, event_time: SystemTime) -> Option<String> {
        let count = {
            let mut failures = self.failures.lock().unwrap();
            let entry = failures.entry(source.to_string()).or_default();
            entry.push_back(event_time);
            entry.retain(|seen| event_time.duration_since(*seen).is_ok_and(|d| d <= WINDOW));
            entry.len()
        };

        if count < FAILURE_THRESHOLD || !Self::cooldown_ok(&self.last_failure_alert, source, event_time) {
            return None;
        }

        Some(format!(
            "ALERT  {} had {} failed SSH logins in {}s — possible brute force",
            source,
            count,
            WINDOW.as_secs()
        ))
    }

    /// Checks whether a successful login from `source` follows enough
    /// recent failures to itself be alert-worthy (a likely compromised
    /// credential), without disturbing the failure window.
    pub fn check_success(&self, source: &str, event_time: SystemTime, user: &str) -> Option<String> {
        let prior_failures = self.recent_failures(source, event_time);
        if prior_failures < SUCCESS_AFTER_FAILURES_MIN
            || !Self::cooldown_ok(&self.last_success_alert, source, event_time)
        {
            return None;
        }

        Some(format!(
            "ALERT  {} logged in as {} after {} failed attempts in the last {}s — possible compromised credential",
            source,
            user,
            prior_failures,
            WINDOW.as_secs()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn t(offset_secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000 + offset_secs)
    }

    #[test]
    fn fires_once_threshold_crossed_then_cools_down() {
        let tracker = BruteForceTracker::new();
        for i in 0..4 {
            assert_eq!(tracker.check_failure("203.0.113.5", t(i)), None);
        }
        let alert = tracker.check_failure("203.0.113.5", t(4));
        assert!(alert.is_some_and(|a| a.contains("possible brute force")));

        // Cooldown suppresses an immediate re-fire on the next failure.
        assert_eq!(tracker.check_failure("203.0.113.5", t(5)), None);
    }

    #[test]
    fn old_failures_fall_out_of_the_window() {
        let tracker = BruteForceTracker::new();
        for i in 0..4 {
            assert_eq!(tracker.check_failure("203.0.113.5", t(i)), None);
        }
        // The first 4 have aged out of the 60s window by the time this one
        // lands, so this shouldn't trigger even though it's the 5th call.
        assert_eq!(tracker.check_failure("203.0.113.5", t(120)), None);
    }

    #[test]
    fn independent_sources_tracked_separately() {
        let tracker = BruteForceTracker::new();
        for i in 0..4 {
            assert_eq!(tracker.check_failure("203.0.113.5", t(i)), None);
            assert_eq!(tracker.check_failure("198.51.100.9", t(i)), None);
        }
    }

    #[test]
    fn success_after_enough_failures_alerts_independently_of_failure_cooldown() {
        let tracker = BruteForceTracker::new();
        for i in 0..3 {
            tracker.check_failure("203.0.113.5", t(i));
        }
        let alert = tracker.check_success("203.0.113.5", t(3), "root");
        assert!(alert.is_some_and(|a| a.contains("compromised credential")));
    }

    #[test]
    fn success_without_prior_failures_is_silent() {
        let tracker = BruteForceTracker::new();
        assert_eq!(tracker.check_success("203.0.113.5", t(0), "root"), None);
    }
}
