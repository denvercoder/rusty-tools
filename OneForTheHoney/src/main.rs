mod tracker;

use clap::Parser;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracker::ScanTracker;

/// OneForTheHoney — a decoy-service honeypot listener.
///
/// Binds a curated list of commonly-targeted ports and logs every connection
/// attempt against them. Run with no arguments to start immediately with
/// sensible defaults.
#[derive(Parser)]
#[command(name = "honey", about = "Decoy-service honeypot listener")]
struct Cli {
    /// Address to bind decoy listeners on (0.0.0.0 = every interface)
    #[arg(long, default_value = "0.0.0.0")]
    bind: IpAddr,

    /// Comma-separated decoy ports to listen on (defaults to a curated bait list)
    #[arg(long, value_delimiter = ',')]
    ports: Option<Vec<u16>>,

    /// Don't send fake service banners (sent by default on SSH/FTP/Telnet/SMTP)
    #[arg(long)]
    no_banner: bool,
}

/// A curated set of the ports most commonly probed by scanners and bots.
const DEFAULT_PORTS: &[u16] = &[21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5900, 8080];

/// How long to wait for a connecting side to send anything after connect
/// (and after any banner), before giving up and closing the connection.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Caps how much of a captured payload gets printed, so a large or binary
/// probe can't flood the log (or the dashboard's line-based SSE stream)
/// with one enormous line.
const MAX_DATA_CHARS: usize = 200;

fn port_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        80 => "HTTP",
        443 => "HTTPS",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5900 => "VNC",
        8080 => "HTTP-alt",
        _ => "unknown",
    }
}

/// Plausible plaintext greetings for the protocols that send one. Binary
/// protocols (SMB/MSSQL/MySQL/RDP/VNC) and request-first protocols
/// (HTTP/HTTPS) are left out — a completed TCP handshake against those is
/// already the useful signal, and faking their real handshake isn't worth
/// the complexity for a decoy.
fn banner(port: u16) -> Option<&'static [u8]> {
    match port {
        21 => Some(b"220 ProFTPD 1.3.5 Server ready.\r\n"),
        22 => Some(b"SSH-2.0-OpenSSH_8.9\r\n"),
        23 => Some(b"\r\nlogin: "),
        25 => Some(b"220 mail.local ESMTP Postfix\r\n"),
        _ => None,
    }
}

/// Renders captured bytes as a single printable, length-capped line —
/// replaces control/non-UTF8 bytes with '.' so a raw binary probe can't
/// corrupt the terminal or break the dashboard's line-based streaming.
fn printable(data: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(data)
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    let text = text.trim();

    if text.chars().count() > MAX_DATA_CHARS {
        let truncated: String = text.chars().take(MAX_DATA_CHARS).collect();
        format!("{}…", truncated)
    } else {
        text.to_string()
    }
}

fn handle_connection(mut stream: TcpStream, port: u16, send_banner: bool, tracker: &ScanTracker) {
    let Ok(peer) = stream.peer_addr() else {
        return;
    };

    println!("CONN   {} ({}) from {}", port, port_name(port), peer);

    if let Some(alert) = tracker.check(peer.ip(), port) {
        println!("{}", alert);
    }

    if send_banner {
        if let Some(bytes) = banner(port) {
            let _ = stream.write_all(bytes);
        }
    }

    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut buf = [0u8; 1024];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            println!("DATA   {} from {}  \"{}\"", port, peer.ip(), printable(&buf[..n]));
        }
    }
}

/// Binds one decoy port and loops accepting connections against it. Runs on
/// its own thread for the lifetime of the program — a failure to bind (most
/// often a privileged port without CAP_NET_BIND_SERVICE) is logged and this
/// thread simply exits, leaving every other port unaffected.
fn listen_on_port(bind: IpAddr, port: u16, send_banner: bool, tracker: Arc<ScanTracker>) {
    let listener = match TcpListener::bind((bind, port)) {
        Ok(listener) => listener,
        Err(err) => {
            println!(
                "Skipping port {}: {} (ports below 1024 need elevated privileges — try sudo, \
                 or grant it once: sudo setcap cap_net_bind_service+ep <path to binary>)",
                port, err
            );
            return;
        }
    };

    for stream in listener.incoming().flatten() {
        let tracker = Arc::clone(&tracker);
        thread::spawn(move || handle_connection(stream, port, send_banner, &tracker));
    }
}

fn main() {
    let cli = Cli::parse();
    let ports: Vec<u16> = cli.ports.unwrap_or_else(|| DEFAULT_PORTS.to_vec());
    let send_banner = !cli.no_banner;
    let tracker = Arc::new(ScanTracker::new());

    let port_list = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    println!(
        "OneForTheHoney listening on {} — ports: {}{} (Ctrl+C to stop)",
        cli.bind,
        port_list,
        if send_banner { "" } else { " (banners off)" }
    );

    let handles: Vec<_> = ports
        .into_iter()
        .map(|port| {
            let tracker = Arc::clone(&tracker);
            let bind = cli.bind;
            thread::spawn(move || listen_on_port(bind, port, send_banner, tracker))
        })
        .collect();

    for handle in handles {
        let _ = handle.join();
    }
}
