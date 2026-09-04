# Rusty Tools

A local collection of Rust cybersecurity tools, sharing one Cargo workspace and one optional web dashboard. Every tool works two ways: directly on the command line for people comfortable there, or through a local, point-and-click web UI for people who aren't.

## Prerequisites

- The Rust toolchain (`cargo`)
- Linux — several pieces are Linux-specific (packet capture via raw sockets, interface listing via `/sys/class/net`, granting capabilities via `setcap`)

## Project layout

```
Rusty Tools/
  Portofino/                 Multithreaded TCP port scanner
  PickAPeckOfPacketParsers/  Live packet capture & parsing (aka "4P")
  dashboard/                 Local web UI for the tools above
```

Each tool directory is an independent, self-contained binary crate — the dashboard just launches them as subprocesses and streams their output. All three are members of one Cargo workspace (`Cargo.toml` at this level), so a single `cargo build --release` here builds everything.

## Building

```
cargo build --release
```

## Running

### Command line

Every tool is a normal binary you can run directly:

```
cargo run -p Portofino -- --help
cargo run -p PickAPeckOfPacketParsers -- --help
```

Portofino is also this workspace's default member, so a bare `cargo run` (or `cargo run --release`) from this directory goes straight to it — and its first prompt lets you pick `[C]ommand Line` (its own interactive wizard) or `[I]nteractive` (which launches the web dashboard below). So in practice, that one command is the entry point into everything.

### Web dashboard (no command-line knowledge needed)

```
cargo run -p dashboard --release
```

or double-click `dashboard/run.sh`. Both build and start a small local web server that opens your browser automatically to a tool picker — click a tool, fill in a short form, and watch its output stream in live. It binds to `127.0.0.1` only and is never reachable from another machine.

## Safety and scope

This is a personal toolkit for testing systems and networks you own or are explicitly authorized to test. Portofino's scanning and 4P's packet capture are both active, and in 4P's case privileged — only point them at hosts/interfaces you have permission to examine.

---

## Portofino — TCP port scanner

Multithreaded scanner for a single IP, a range (`10.0.0.1-50`), or a CIDR block (`10.0.0.0/24`), with live progress and an "Open Ports" summary that stays readable even when scanning hundreds of hosts.

```
# Interactive wizard — just answer the prompts
cargo run -p Portofino

# Non-interactive / scriptable
cargo run -p Portofino -- --threads 500 --target 10.0.0.0/24 --ports common
```

- `--threads` / `-n`: shared across every host being scanned at once, clamped to 2000.
- `--target` / `-t`: single IP, range, or CIDR block (`/16` or smaller).
- `--ports` / `-p`: `all` (full 1–65535 sweep) or `common` (a curated list of ~20 frequently-exposed ports) — defaults to `all`.

## PickAPeckOfPacketParsers (4P) — live packet capture & parsing

Sniffs a chosen network interface and decodes each frame — Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP — with basic DNS and plaintext HTTP decoding, live port-scan/ARP-spoof alerting, and optional `.pcap` export.

### Why this one needs elevated privileges

Capturing raw packets means the OS hands your program a copy of *every* frame arriving on a network interface — not just traffic addressed to that program. Because that's powerful, Linux gates it behind a specific permission, `CAP_NET_RAW`, that a program doesn't have by default.

This isn't specific to this tool — **every** packet-capture tool works this way, including `tcpdump`, Wireshark (via its `dumpcap` helper), and `nmap`'s raw-packet scan modes. It's the same OS-level safeguard in every case, and it exists precisely so nothing can silently sniff network traffic without someone deliberately granting that access. 4P never captures anything unless you've explicitly done one of the two things below.

### One-time setup (recommended)

From the workspace root, after building:

```
sudo setcap cap_net_raw+ep target/release/PickAPeckOfPacketParsers
```

(On this machine specifically, that's `sudo setcap cap_net_raw+ep ~/RustroverProjects/"Rusty Tools"/target/release/PickAPeckOfPacketParsers` — adjust the path if you cloned it somewhere else.)

After this, the compiled binary runs without `sudo` — directly, or through the dashboard (which always runs as your normal user, never as root, so this is the only way it works through the web UI).

**Note:** the capability is attached to that specific compiled file. Rebuilding (e.g. `cargo build` after a source change) produces a new file and wipes it — re-run the command above once after any rebuild. Once the code is stable this is rare in practice, and it's the same tradeoff Wireshark's own capture helper makes on Linux — not a shortcut specific to this project. (See "avoiding this after every rebuild" below if it ever becomes annoying enough to be worth fixing properly.)

### Alternative: sudo per run

```
sudo ./target/release/PickAPeckOfPacketParsers <interface>
```

Simpler for a one-off test, but asks for your password every time and doesn't work through the dashboard.

Either way: **build normally first, and only elevate the final run/setcap step.** Don't run `cargo build`/`cargo run` itself with `sudo` — that leaves root-owned files in the shared workspace `target/` directory and breaks your next unprivileged build.

### Usage

```
# List interfaces
cargo run -p PickAPeckOfPacketParsers -- --list

# Capture everything on an interface
./target/release/PickAPeckOfPacketParsers wlp13s0

# Only TCP traffic on port 443
./target/release/PickAPeckOfPacketParsers wlp13s0 --protocol tcp --port 443

# Only traffic to/from a specific host
./target/release/PickAPeckOfPacketParsers wlp13s0 --host 192.168.1.1

# Save the (filtered) capture to a .pcap file, openable in Wireshark
./target/release/PickAPeckOfPacketParsers wlp13s0 --pcap-out captures/session.pcap
```

Through the dashboard: click the **PPPP** card, pick an interface from the auto-populated dropdown, optionally set a filter, and click **Start capture**.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `TCP` / `UDP` / `ICMP` / `ICMPv6` / `ARP` | Base per-protocol summary line |
| `DNS` | Decoded query/response name + record type (`A`, `AAAA`, `CNAME`, ...) |
| `HTTP` | Plaintext request/status line + Host header, when a TCP/80 payload looks like HTTP |
| `ALERT` | A possible port scan (one source hitting many destination ports fast) or ARP spoof (an IP suddenly claimed by a new MAC), detected live |

### Avoiding the setcap-after-every-rebuild step entirely

Not possible without meaningfully more architecture. `setcap` attaches to a specific file's data, and cargo produces a new file on every rebuild. The pattern real capture tools use to dodge this — Wireshark's `dumpcap` — is to split the privileged part into a small, separate helper binary that almost never changes, so its capability survives indefinitely regardless of how often the main program is rebuilt. That's a real chunk of added complexity (a second binary, a way to hand off the open capture socket) that isn't worth it unless re-running `setcap` becomes a genuine annoyance — it's not built here for that reason, but it's a well-understood next step if it ever is.

## dashboard — web UI

A small Axum server that's a thin, tool-agnostic launcher: each tool page builds a query string from a form, opens a Server-Sent Events connection, and the server builds (quietly) and runs that tool as a subprocess, streaming its stdout/stderr back live. A shared per-tool Stop button works by killing the subprocess (or aborting the build) via a cancellation signal, so it works even for 4P's capture, which otherwise runs forever.

Always binds to `127.0.0.1:7878` — by design, never configurable to anything else, since it launches active scans/captures on demand.
