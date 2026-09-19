//! The actual connectivity probe.
//!
//! One "sweep" tries to open a TCP connection to every target at once and
//! reports whether *any* of them answered. A completed TCP handshake is proof
//! of real, routable connectivity — which, for this tool, is the bad case.

use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

/// The outcome of probing every target once.
pub struct Sweep {
    /// True if at least one target accepted a TCP connection.
    pub reachable: bool,
    /// The first target found reachable, if any (for the alert message).
    pub hit: Option<SocketAddr>,
}

/// Probe all `targets` in parallel, each with its own `timeout`, and report
/// whether ANY of them accepted a TCP connection.
///
/// We run one thread per target (via [`std::thread::scope`], which lets the
/// threads borrow `targets` without it needing to be `'static`) so a whole
/// sweep takes about one `timeout` regardless of how many targets there are.
/// If we probed serially instead, a handful of *silently firewalled* targets
/// (which make `connect_timeout` block for the full duration rather than fail
/// fast) could stack up into several seconds and blow past our once-a-second
/// cadence. Note: a truly disconnected adapter fails *instantly* with
/// "network unreachable" — the timeout only matters for the filtered case.
pub fn sweep(targets: &[SocketAddr], timeout: Duration) -> Sweep {
    let hit = thread::scope(|scope| {
        // Spawn a probe for each target. `addr` is `Copy` (a small plain
        // struct), so `move` copies it into the thread rather than borrowing.
        let handles: Vec<_> = targets
            .iter()
            .map(|&addr| scope.spawn(move || (addr, TcpStream::connect_timeout(&addr, timeout).is_ok())))
            .collect();

        // Collect results. `join()` waits for each thread (each ≤ `timeout`),
        // so the whole loop is bounded by the slowest single probe.
        let mut hit: Option<SocketAddr> = None;
        for handle in handles {
            if let Ok((addr, connected)) = handle.join() {
                if connected && hit.is_none() {
                    hit = Some(addr);
                }
            }
        }
        hit
    });

    Sweep { reachable: hit.is_some(), hit }
}
