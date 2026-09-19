# FuckAroundFindOut (FAFO) — network isolation canary

A tripwire for malware analysis. When you're reversing a sample you keep the VM's
network disabled — but sometimes you enable it to pull a sample, and forgetting to
re-disable it leaves your host exposed to whatever you're dissecting. FAFO runs
inside the VM and, once per second, checks whether the outside world is reachable.
As long as it isn't, it stays quiet (with a periodic heartbeat so you know it's
alive). The instant it *is*, it prints a breach banner, an `ALERT` line every
second, and rings the terminal bell — until you kill the connection.

## How it decides "reachable"

It attempts a **TCP connection** to a list of public DNS servers, not an ICMP ping:

- **No privileges needed.** Raw ICMP sockets require root/admin; a normal TCP
  `connect` does not — so FAFO runs as an ordinary user in any VM.
- **A completed handshake is proof.** Getting a real SYN/ACK back from `8.8.8.8:53`
  means you have genuine routable connectivity, not just a half-configured adapter.
- **The probe never leaks.** Targets are numeric `ip:port`, so FAFO performs **no
  DNS lookup of its own** (that would itself be outbound traffic). Any target that
  isn't a literal `ip:port` is rejected, by design.

Targets are probed **in parallel**, so a full sweep takes about one timeout no
matter how many you list. Defaults cover Google, Cloudflare, and Quad9 DNS, plus a
`:443` target in case UDP/53 egress is filtered but web traffic isn't.

## Catching host-only networking

Probing the internet won't notice a **host-only** adapter (VM can reach your host
but not the internet) — which for malware work is exactly the exposure you care
about. Add your host or gateway IP as a target to catch it:

```
cargo run -p FuckAroundFindOut -- --target 192.168.56.1:445 --target 8.8.8.8:53
```

(Point it at a port your host actually has open — 445/SMB, 139, 3389/RDP, or an SSH
port — so the handshake completes.)

## Cross-platform

Unlike the Linux-specific tools here, FAFO is pure `std` + `clap` and runs on
Windows, Linux, or macOS — so it works whatever your analysis VM runs. On Windows
it also raises a native OS popup on breach.

## Usage

```
# Defaults: public DNS servers, once per second
cargo run -p FuckAroundFindOut

# Also watch a host-only adapter, check twice a second
cargo run -p FuckAroundFindOut -- --target 192.168.56.1:445 --interval-ms 500

# One-shot check for scripting (exit 0 = isolated, 1 = exposed)
cargo run -p FuckAroundFindOut -- --once

# Quieter: no bell, heartbeat once a minute
cargo run -p FuckAroundFindOut -- --no-bell --heartbeat-secs 60

# Suppress the native Windows popup (rely on the console/dashboard alarm)
cargo run -p FuckAroundFindOut -- --no-popup
```

On an interactive terminal, output is colored (green safe / red alert) and the bell
rings on breach; when piped (e.g. through the dashboard) it degrades to plain
prefixed lines automatically.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `SAFE` | Isolated — no target was reachable this sweep (printed on a heartbeat, or when connectivity is lost again) |
| `ALERT` | A target answered — the VM can reach the outside world **right now**. Printed every second until it can't |
| `ERROR` | A configured target wasn't a valid numeric `ip:port` and was skipped |

There's no separate heartbeat prefix — a `SAFE` line *is* the "still isolated"
signal, and its absence (no lines at all) is itself a cue that something's wrong.

> Part of [Rusty Toolz](../README.md).
