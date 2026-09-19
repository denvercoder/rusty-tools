# PickAPeckOfPacketParsers (4P) — live packet capture & parsing

Sniffs a chosen network interface and decodes each frame — Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP — with basic DNS and plaintext HTTP decoding, live port-scan/ARP-spoof alerting, and optional `.pcap` export.

## Why this one needs elevated privileges

Capturing raw packets means the OS hands your program a copy of *every* frame arriving on a network interface — not just traffic addressed to that program. Because that's powerful, Linux gates it behind a specific permission, `CAP_NET_RAW`, that a program doesn't have by default.

This isn't specific to this tool — **every** packet-capture tool works this way, including `tcpdump`, Wireshark (via its `dumpcap` helper), and `nmap`'s raw-packet scan modes. It's the same OS-level safeguard in every case, and it exists precisely so nothing can silently sniff network traffic without someone deliberately granting that access. 4P never captures anything unless you've explicitly done one of the two things below.

## One-time setup (recommended)

From the workspace root, after building:

```
sudo setcap cap_net_raw+ep target/release/PickAPeckOfPacketParsers
```

After this, the compiled binary runs without `sudo` — directly, or through the dashboard (which always runs as your normal user, never as root, so this is the only way it works through the web UI).

**Note:** the capability is attached to that specific compiled file. Rebuilding (e.g. `cargo build` after a source change) produces a new file and wipes it — re-run the command above once after any rebuild. It's the same tradeoff Wireshark's own capture helper makes on Linux.

## Alternative: sudo per run

```
sudo ./target/release/PickAPeckOfPacketParsers <interface>
```

Simpler for a one-off test, but asks for your password every time and doesn't work through the dashboard.

Either way: **build normally first, and only elevate the final run/setcap step.** Don't run `cargo build`/`cargo run` itself with `sudo` — that leaves root-owned files in the shared workspace `target/` directory and breaks your next unprivileged build.

## Usage

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

## Avoiding the setcap-after-every-rebuild step entirely

Not possible without meaningfully more architecture. `setcap` attaches to a specific file's data, and cargo produces a new file on every rebuild. The pattern real capture tools use to dodge this — Wireshark's `dumpcap` — is to split the privileged part into a small, separate helper binary that almost never changes, so its capability survives indefinitely regardless of how often the main program is rebuilt. That's a real chunk of added complexity (a second binary, a way to hand off the open capture socket) that isn't worth it unless re-running `setcap` becomes a genuine annoyance — it's not built here for that reason, but it's a well-understood next step if it ever is.

> Part of [Rusty Toolz](../README.md). Capture is active and privileged — only point it at interfaces/hosts you have permission to examine.
