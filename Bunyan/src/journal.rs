use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One line of `journalctl -o json` output. Only the fields Bunyan actually
/// uses are named — journald includes dozens more per entry, and serde
/// ignores anything not listed here. Missing fields default to empty rather
/// than failing the whole line, since not every entry carries every field.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct JournalEntry {
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    pub identifier: String,
    #[serde(rename = "MESSAGE")]
    pub message: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    pub realtime_timestamp: String,
}

impl JournalEntry {
    /// journald's own timestamp for this entry (microseconds since the Unix
    /// epoch, as a string) — used instead of the wall clock so that alert
    /// windows are correct both live and when replaying a saved `--file`,
    /// where an entire historical burst can be read from disk in
    /// milliseconds.
    pub fn event_time(&self) -> SystemTime {
        self.realtime_timestamp
            .parse::<u64>()
            .map(|micros| UNIX_EPOCH + Duration::from_micros(micros))
            .unwrap_or_else(|_| SystemTime::now())
    }
}
