// FuckAroundFindOut (FAFO) — network isolation canary
//
// Runs inside a malware-analysis VM and screams the moment the VM can reach the
// outside world, so you never forget to re-disable the adapter after pulling a
// sample. In this tool's worldview, "can connect to the internet" == BAD.
//
// Detection is a TCP connect (not an ICMP ping) to public DNS servers:
//   - No admin/root needed (raw ICMP sockets do).
//   - A completed TCP handshake is *proof* of real routable connectivity.
//   - Targets are numeric ip:port, so the probe itself performs NO DNS lookup
//     (a lookup would be its own tiny leak). Non-numeric targets are rejected.
//
// Output follows the rusty-tools convention: plain, prefixed lines (SAFE /
// ALERT / ERROR) so it reads cleanly on a raw terminal AND through the
// dashboard's stdout stream. On an interactive terminal it additionally uses
// color and the bell; when piped (e.g. into the dashboard) it stays plain.

mod alert;
mod probe;

use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

use probe::sweep;

/// Probed when the user supplies no `--target`. Multiple providers, plus a
/// `:443` in case port 53 egress is filtered but web traffic isn't.
const DEFAULT_TARGETS: &[&str] = &[
    "8.8.8.8:53",  // Google DNS
    "8.8.4.4:53",  // Google DNS (secondary)
    "1.1.1.1:53",  // Cloudflare DNS
    "1.1.1.1:443", // Cloudflare, TLS port
    "9.9.9.9:53",  // Quad9 DNS
];

#[derive(Parser)]
#[command(
    name = "FuckAroundFindOut",
    about = "Network isolation canary — screams when a locked-down VM can reach the outside world."
)]
struct Args {
    /// Target to probe as ip:port (repeatable). NUMERIC ONLY — FAFO never
    /// resolves DNS, so the probe can't leak. Defaults to public DNS servers.
    /// Add your host/gateway IP here to also catch host-only networking.
    #[arg(short = 't', long = "target", value_name = "IP:PORT")]
    targets: Vec<String>,

    /// Milliseconds between probe sweeps.
    #[arg(short = 'i', long, default_value_t = 1000)]
    interval_ms: u64,

    /// Per-connection timeout in milliseconds.
    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,

    /// Seconds between "still isolated" heartbeat lines while safe (0 = every tick).
    #[arg(long, default_value_t = 15)]
    heartbeat_secs: u64,

    /// Do a single sweep, print the result, and exit (exit 0 = isolated, 1 = exposed).
    #[arg(long)]
    once: bool,

    /// Never ring the terminal bell on alert.
    #[arg(long)]
    no_bell: bool,

    /// (Windows) Suppress the native OS popup on breach — rely on the console
    /// or dashboard alarm instead. No effect on other platforms.
    #[arg(long)]
    no_popup: bool,
}

/// Wrap `s` in an ANSI color escape (`code`) when `on`, otherwise return it
/// unchanged — so piped/dashboard output never contains escape sequences.
fn paint(s: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Resolve the target list (defaults if none supplied) and parse each to a
    // real SocketAddr up front. Parsing is strictly numeric ip:port — anything
    // needing a DNS lookup is rejected by design.
    let raw: Vec<String> = if args.targets.is_empty() {
        DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect()
    } else {
        args.targets.clone()
    };

    let mut targets: Vec<SocketAddr> = Vec::new();
    for r in &raw {
        match r.parse::<SocketAddr>() {
            Ok(addr) => targets.push(addr),
            Err(_) => eprintln!("ERROR  '{r}' is not a numeric ip:port (FAFO never resolves DNS) — skipping"),
        }
    }
    if targets.is_empty() {
        eprintln!("ERROR  no valid targets to probe");
        return ExitCode::from(2);
    }

    let interval = Duration::from_millis(args.interval_ms);
    let timeout = Duration::from_millis(args.timeout_ms);
    let color = std::io::stdout().is_terminal();

    // --once: a single sweep, for scripting or a dashboard "check" button.
    if args.once {
        let s = sweep(&targets, timeout);
        return match s.hit {
            Some(hit) => {
                println!("{}", paint(&format!("ALERT  internet reachable via {hit}"), "1;31", color));
                ExitCode::from(1)
            }
            None => {
                println!("{}", paint(&format!("SAFE   isolated — {} targets unreachable", targets.len()), "32", color));
                ExitCode::SUCCESS
            }
        };
    }

    // Continuous monitoring.
    let target_list = targets.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
    println!(
        "FAFO   watching [{target_list}] every {}ms (timeout {}ms) — Ctrl+C to stop",
        args.interval_ms, args.timeout_ms
    );

    let start = Instant::now();
    let heartbeat = Duration::from_secs(args.heartbeat_secs);
    let mut checks: u64 = 0;
    let mut exposed = false;
    // `None` until we've printed our first safe heartbeat, so status shows up
    // immediately on the first isolated tick rather than after `heartbeat`.
    let mut last_heartbeat: Option<Instant> = None;
    // True while a native popup is on screen, so a flapping connection can't
    // stack up a pile of message boxes. Shared with the popup thread.
    let popup_open = Arc::new(AtomicBool::new(false));

    loop {
        let s = sweep(&targets, timeout);
        checks += 1;

        if s.reachable {
            let hit = s.hit.expect("reachable implies a hit");

            if !exposed {
                // SAFE -> EXPOSED transition: the loud banner, once.
                exposed = true;
                let banner = format!(
                    "\n\
                    ======================================================\n\
                    ==  ISOLATION BREACH — THE INTERNET IS REACHABLE    ==\n\
                    ==  reached: {hit}\n\
                    ==  STOP ALL ANALYSIS — DISABLE THE VM ADAPTER NOW  ==\n\
                    ======================================================\n"
                );
                println!("{}", paint(&banner, "1;31", color));

                // Fire the native OS popup (Windows) on a background thread so
                // the modal doesn't freeze monitoring. The flag prevents a
                // second box stacking on top if we flap before it's dismissed.
                if !args.no_popup && !popup_open.swap(true, Ordering::SeqCst) {
                    let flag = Arc::clone(&popup_open);
                    let target = hit.to_string();
                    thread::spawn(move || {
                        alert::popup(
                            "ISOLATION BREACH — internet reachable",
                            &format!(
                                "FuckAroundFindOut detected outbound connectivity to {target}.\n\n\
                                 STOP ALL ANALYSIS and disable the VM network adapter now."
                            ),
                        );
                        flag.store(false, Ordering::SeqCst);
                    });
                }
            }

            // Nag every tick for as long as we stay exposed.
            println!("{}", paint(&format!("ALERT  internet reachable via {hit} — DISABLE THE ADAPTER"), "1;31", color));
            // Bell only on a real terminal: when piped (dashboard), a stray
            // \x07 would corrupt the start of the next streamed line.
            if color && !args.no_bell {
                print!("\x07");
                let _ = std::io::stdout().flush();
            }
        } else if exposed {
            // EXPOSED -> SAFE transition.
            exposed = false;
            println!("{}", paint("SAFE   connectivity lost — isolated again", "32", color));
            last_heartbeat = Some(Instant::now());
        } else {
            // Steady-state safe: a periodic heartbeat proves FAFO is still
            // alive (silence could otherwise be mistaken for "isolated").
            let due = heartbeat.is_zero() || last_heartbeat.map_or(true, |t| t.elapsed() >= heartbeat);
            if due {
                let secs = start.elapsed().as_secs();
                println!("{}", paint(&format!("SAFE   isolated — {checks} checks, up {secs}s"), "32", color));
                last_heartbeat = Some(Instant::now());
            }
        }

        thread::sleep(interval);
    }
}
