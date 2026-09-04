mod classify;
mod journal;
mod tracker;

use clap::Parser;
use classify::{parse_sshd, parse_sudo, SshEvent, SudoEvent};
use journal::JournalEntry;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracker::BruteForceTracker;

/// Bunyan — a systemd-journal auth log analyzer.
///
/// Tails the journal's auth facility (sshd + sudo activity) live by
/// default, or replays a saved `journalctl ... -o json` export with
/// `--file`.
#[derive(Parser)]
#[command(name = "bunyan", about = "Systemd-journal auth log analyzer")]
struct Cli {
    /// Analyze a saved `journalctl -o json` export instead of tailing the live journal
    #[arg(long)]
    file: Option<PathBuf>,
}

/// Spawns `journalctl -f -o json --no-pager SYSLOG_FACILITY=10` and returns
/// a reader over its stdout. This child keeps running for the rest of the
/// program's life; if Bunyan itself is killed outright rather than given a
/// chance to exit (e.g. the dashboard's Stop button, which signals only
/// this process, not its children), the journalctl process can be left
/// running as an orphan. Acceptable for a personal tool — the same kind of
/// tradeoff 4P documents for its own setcap-per-rebuild step — rather than
/// pulling in process-group signal handling for it.
fn live_journal() -> std::io::Result<Box<dyn BufRead>> {
    let mut child = Command::new("journalctl")
        .args(["-f", "-o", "json", "--no-pager", "SYSLOG_FACILITY=10"])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout piped");
    Ok(Box::new(BufReader::new(stdout)))
}

fn process_line(line: &str, tracker: &BruteForceTracker) {
    let Ok(entry) = serde_json::from_str::<JournalEntry>(line) else {
        return;
    };
    let event_time = entry.event_time();

    match entry.identifier.as_str() {
        "sshd" => {
            let Some(event) = parse_sshd(&entry.message) else {
                return;
            };
            match event {
                SshEvent::Failed { user, invalid_user, source_ip } => {
                    let tag = if invalid_user { "  [invalid user]" } else { "" };
                    println!("LOGIN  fail  {} from {}{}", user, source_ip, tag);
                    if let Some(alert) = tracker.check_failure(&source_ip, event_time) {
                        println!("{}", alert);
                    }
                }
                SshEvent::Accepted { method, user, source_ip } => {
                    println!("LOGIN  ok    {} from {}  ({})", user, source_ip, method);
                    if let Some(alert) = tracker.check_success(&source_ip, event_time, &user) {
                        println!("{}", alert);
                    }
                }
            }
        }
        "sudo" => {
            let Some(event) = parse_sudo(&entry.message) else {
                return;
            };
            match event {
                SudoEvent::Command { invoking_user, target_user, command } => {
                    println!("SUDO   {} -> {}  {}", invoking_user, target_user, command);
                }
                SudoEvent::AuthFailure { user } => {
                    println!("SUDO   fail  {}", user);
                }
            }
        }
        _ => {}
    }
}

fn main() {
    let cli = Cli::parse();

    let reader: Box<dyn BufRead> = match cli.file {
        Some(path) => match File::open(&path) {
            Ok(file) => Box::new(BufReader::new(file)),
            Err(err) => {
                println!("Failed to open {}: {}", path.display(), err);
                std::process::exit(1);
            }
        },
        None => match live_journal() {
            Ok(reader) => {
                println!(
                    "Bunyan watching the auth log live (journalctl SYSLOG_FACILITY=10)... (Ctrl+C to stop)"
                );
                reader
            }
            Err(err) => {
                println!("Failed to start journalctl: {}", err);
                std::process::exit(1);
            }
        },
    };

    let tracker = BruteForceTracker::new();

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                println!("Error reading input: {}", err);
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        process_line(&line, &tracker);
    }
}
