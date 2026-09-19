# Rusty Toolz

A local collection of Rust cybersecurity tools, sharing one Cargo workspace and one optional web dashboard. Every tool works two ways: directly on the command line for people comfortable there, or through a local, point-and-click web UI for people who aren't.

## Prerequisites

- The Rust toolchain (`cargo`)
- Linux — several pieces are Linux-specific (packet capture via raw sockets, interface listing via `/sys/class/net`, granting capabilities via `setcap`)

## Quickstart (fresh machine)

Clone the repo, then run the installer for your OS. It checks for prerequisites and
installs only what's missing (the Rust toolchain, and the platform's C/build tools —
including the MSVC linker on Windows), optionally adds a `rustytoolz.local` hosts
alias, builds, and launches the dashboard.

**Linux / macOS:**

```
git clone https://github.com/denvercoder/rusty-tools.git
cd rusty-tools
chmod +x install.sh && ./install.sh
```

**Windows (PowerShell):**

```
git clone https://github.com/denvercoder/rusty-tools.git
cd rusty-tools
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Then open **http://rustytoolz.local** if you added the alias, or **http://localhost** — the
dashboard binds port **80** on loopback by default, so no `:port` suffix is needed. (The host
is always `127.0.0.1`; only the port is configurable, via `RUSTYTOOLZ_PORT` — set it to e.g.
`7878` for a non-privileged port.) Several tools are Linux-only; the dashboard
builds each tool on first click, so a wrong-OS tool simply fails when you open it
rather than blocking the install. To change the alias, edit the variable at the top
of the install script (e.g. `rustytoolz.test` if macOS's `.local`/mDNS resolution
gives you trouble).

## Project layout

```
Rusty Toolz/
  Portofino/                 Multithreaded TCP port scanner
  PickAPeckOfPacketParsers/  Live packet capture & parsing (aka "4P")
  OneForTheHoney/            Decoy-service honeypot listener
  Bunyan/                    Systemd-journal auth log analyzer
  FeeFiFoFIM/                File integrity monitor
  HardHat/                   Security config auditor
  FuckAroundFindOut/         Network isolation canary (aka "FAFO")
  FluShot/                   Encrypted sample vault
  HumptyDumpty/              Static malware triage
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
cargo run -p OneForTheHoney -- --help
cargo run -p Bunyan -- --help
cargo run -p FeeFiFoFIM -- --help
cargo run -p HardHat
cargo run -p FuckAroundFindOut -- --help
cargo run -p FluShot -- --help
cargo run -p HumptyDumpty -- --help
```

Portofino is also this workspace's default member, so a bare `cargo run` (or `cargo run --release`) from this directory goes straight to it — and its first prompt lets you pick `[C]ommand Line` (its own interactive wizard) or `[I]nteractive` (which launches the web dashboard below). So in practice, that one command is the entry point into everything.

### Web dashboard (no command-line knowledge needed)

```
cargo run -p dashboard --release
```

or double-click `dashboard/run.sh`. Both build and start a small local web server that opens your browser automatically to a tool picker — click a tool, fill in a short form, and watch its output stream in live. It binds to `127.0.0.1` only and is never reachable from another machine.

## Safety and scope

This is a personal toolkit for testing systems and networks you own or are explicitly authorized to test. Portofino's scanning and 4P's packet capture are both active, and in 4P's case privileged — only point them at hosts/interfaces you have permission to examine. OneForTheHoney binds to every network interface by default, which means it will log connection attempts from **any** device that can reach this machine on that network — not just your own. Only run it on networks you own or are explicitly authorized to monitor.

FAFO, FluShot, and HumptyDumpty are malware-analysis aids. FluShot deliberately stores samples as encrypted blobs so AV won't quarantine them — use it only for samples you're authorized to analyze, and only ever `open` (decrypt) them inside a disposable analysis VM, never on your host. HumptyDumpty only ever *reads* a sample (never runs it), but the file is still live malware, so triage it inside that same VM.

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

## OneForTheHoney — decoy service listener

A honeypot: binds a curated list of the ports scanners and bots most commonly probe (FTP, SSH, Telnet, SMTP, HTTP(S), SMB, MSSQL, MySQL, RDP, VNC) and logs every connection attempt against them, with a fake plaintext banner on the protocols that have one and live scanner detection when one source touches several decoy ports in quick succession.

### Why some ports need elevated privileges

Several of the default decoy ports (21, 22, 23, 25, 80, 443) are below 1024, and Linux only lets a process bind those without a specific permission, `CAP_NET_BIND_SERVICE` — the same OS-level gate every real service on those ports (sshd, an actual web server, etc.) has to satisfy. OneForTheHoney binds each decoy port independently: if one fails for lack of privilege, it prints a warning for that port and keeps the rest running, so it's still useful unprivileged (any ports ≥1024 in the list still work).

### One-time setup (recommended)

From the workspace root, after building:

```
sudo setcap cap_net_bind_service+ep target/release/OneForTheHoney
```

After this, the compiled binary can bind the privileged ports without `sudo` — directly, or through the dashboard. As with 4P's `cap_net_raw`, the capability is attached to that specific compiled file, so re-run this once after any rebuild.

### Alternative: sudo per run

```
sudo ./target/release/OneForTheHoney
```

Simpler for a one-off, but asks for your password every time and doesn't work through the dashboard.

### Usage

```
# Start with defaults: bind 0.0.0.0, the full curated port list, banners on
./target/release/OneForTheHoney

# Only a couple of ports
./target/release/OneForTheHoney --ports 22,80,3389

# Loopback only, for local testing
./target/release/OneForTheHoney --bind 127.0.0.1

# No fake banners — bare accept-and-log
./target/release/OneForTheHoney --no-banner
```

Through the dashboard: click the **OneForTheHoney** card, optionally adjust the bind address or port list, and click **Start listening**.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `CONN` | A connection landed on a decoy port — source IP, source port, decoy port, and service name |
| `DATA` | Whatever the connecting side sent within 3 seconds of connecting (or of the banner, if one was sent) |
| `ALERT` | One source touched 3+ distinct decoy ports within 10 seconds — likely a scanner |

## Bunyan — auth log analyzer

Watches the systemd journal's auth facility — sshd and sudo activity — and prints only what's actually signal: logins (success/fail), sudo command executions and auth failures, and live alerts for brute-force and compromise patterns. Named for the log-splitting kind of Bunyan, not the WHOIS-adjacent kind.

### No privileges needed

Unlike 4P and OneForTheHoney, Bunyan doesn't need `sudo` or `setcap` — reading the journal's auth facility (`journalctl SYSLOG_FACILITY=10`) works as a normal user on this machine out of the box.

### Live vs. saved logs

By default Bunyan tails the journal live (`journalctl -f -o json SYSLOG_FACILITY=10` under the hood). Since this machine doesn't run `sshd`, the practical way to exercise (or just try out) the brute-force detection is to point it at a saved export instead:

```
# Live (default) — watches sshd/sudo activity as it happens
./target/release/Bunyan

# Save a chunk of the real journal to replay/inspect later
journalctl SYSLOG_FACILITY=10 -o json --no-pager -n 200 > sample.jsonl

# Replay a saved export — reads to the end, then exits
./target/release/Bunyan --file sample.jsonl
```

`--file` accepts anything in the same JSON-lines shape `journalctl -o json` produces — including a hand-crafted sample with synthetic `sshd`/`sudo` entries, useful for testing the alert thresholds without needing a real attack (or a running `sshd`) to generate one.

Through the dashboard: click the **Bunyan** card, optionally point it at a saved export, and click **Start**.

### A known limitation

Bunyan spawns `journalctl -f` as a child process for live mode. If Bunyan is killed outright rather than allowed to exit on its own — notably, the dashboard's Stop button, which signals only Bunyan's own process — that `journalctl` child can be left running in the background. Harmless (it just keeps tailing quietly), but worth knowing about; a full fix would mean either process-group signaling in the dashboard or replacing the long-lived `-f` stream with short-lived polling, neither of which felt worth the added complexity for a personal tool. Plain `Ctrl+C` on the command line doesn't have this problem — it's delivered to the whole foreground process group, journalctl included.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `LOGIN` | An sshd login attempt — `ok` (with method) or `fail` (tagged `[invalid user]` when the username itself doesn't exist) |
| `SUDO` | A sudo command execution (`invoking user -> target user  command`) or a sudo auth failure |
| `ALERT` | 5+ failed SSH logins from one source within 60s (brute force), or a successful login from a source with 3+ recent failures (possible compromised credential) |

## FeeFiFoFIM — file integrity monitor

Baselines a directory's contents (a SHA-256 hash of every file), then checks it again later and reports anything added, removed, or changed. Classic host-based integrity monitoring — pairs with Bunyan as the toolkit's second host-based (rather than network-based) detection skill.

### No privileges needed

Like Bunyan, this is plain file I/O — no `sudo` or `setcap` required.

### Three modes

```
# Create (or refresh) a baseline for a directory
./target/release/FeeFiFoFIM /etc --init

# One-shot check against that baseline
./target/release/FeeFiFoFIM /etc

# Keep checking every 30 seconds, printing only newly-detected changes
./target/release/FeeFiFoFIM /etc --watch 30
```

`--baseline <file>` overrides where the baseline is stored/read (default: `fim-baseline.json` in the current directory) — keep it outside the directory being monitored, or the baseline file itself will show up as a change on the next run. Through the dashboard, leaving the baseline field blank auto-names one after the monitored path and stores it alongside the tool, so repeated runs against the same directory stay consistent without you having to track a file path yourself.

`--watch` re-checks against the *original* baseline on every tick, but only prints changes that are new since the previous tick — so an ongoing difference doesn't get reprinted forever. A `.git` directory (if present) and any symlinks in the monitored tree are skipped automatically.

Through the dashboard: click the **FeeFiFoFIM** card, set a directory, and use **Create/Update Baseline** or **Check** (with an optional watch interval).

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `ADDED` | A file exists now that wasn't in the baseline |
| `REMOVED` | A file in the baseline no longer exists |
| `MODIFIED` | A file's content hash no longer matches the baseline |

There's no separate `ALERT` line here — unlike the other tools, every line above already *is* the alert.

## HardHat — security config auditor

A proactive posture check, unlike every other tool here — it reads local system configuration once and reports hardening gaps, rather than watching for events over time. Checks SSH config, `/etc/passwd` for unexpected UID-0 accounts, firewall service status, unusual setuid binaries, and a watchlist of sensitive files for world-writable permissions — plus, when run as root, sudoers `NOPASSWD: ALL` rules and `/etc/shadow` for empty-password accounts.

### Privileges: more checks unlock with `sudo`

This one has a different privilege story than the rest of the toolkit. Bunyan and FeeFiFoFIM never need privilege; 4P and OneForTheHoney need it for everything. HardHat sits in between: it runs fully unprivileged and still produces real findings (SSH config, firewall presence, account anomalies, SUID audit, file permissions), but two checks — sudoers and shadow — need root to read their target files at all, and print as `SKIP` (not a failure) when they can't.

```
# Unprivileged — most checks run, sudoers/shadow show as SKIP
./target/release/HardHat

# Full audit, including sudoers and shadow
sudo ./target/release/HardHat
```

**Dashboard note:** the dashboard always runs tools as your normal user, by design, and never elevates — so the sudoers and shadow checks will always show as skipped there. Run the CLI directly with `sudo` for the full audit.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `PASS` | The check found nothing concerning |
| `WARN` | Worth a look, but not necessarily wrong (e.g. password auth enabled, an unusual setuid binary) |
| `FAIL` | A clear hardening gap (e.g. `PermitRootLogin yes`, a world-writable `/etc/passwd`, an empty-password account) |
| `SKIP` | The check needs root and this run doesn't have it |

There's no separate `ALERT` line here either — same reasoning as FeeFiFoFIM: `WARN`/`FAIL`/`SKIP` already communicate what matters directly.

## FluShot — encrypted sample vault

Malware samples can't sit on disk as plaintext: AV scans files on write and
quarantines anything it recognizes — often mid-download, before you can use them.
FluShot never lets a recognizable byte hit the disk. It downloads samples *itself*
(no browser, so no SmartScreen), encrypts them in memory, and writes only
ciphertext; the resulting blob has a novel hash and noise contents, so neither
content nor hash/reputation scanning has anything to bite. Decrypt them back only
inside your analysis VM.

### Cross-platform

Like FAFO, FluShot is pure Rust with no OS-specific APIs, so it runs on Windows,
Linux, or macOS — wherever you handle samples.

### How it defeats the download block

- **The tool downloads, not the browser** — no SmartScreen prompt, and the
  plaintext never lands on disk for the on-write real-time scan.
- **Output is a novel encrypted blob** — unknown hash and noise content, so both
  hash/reputation and content scanning come up empty.
- **Encrypting after a browser download is too late** — by then AV has already
  quarantined it, which is why `fetch` does the download itself.

### Encryption

Keyfile-based ChaCha20-Poly1305 (authenticated). A 32-byte key file
(`.flushot.key`) is generated in the vault on first use — no passphrase to type.
To decrypt inside your VM, copy that key file into the VM's vault once. The
original filename is stored *inside* the encrypted payload, so `open` restores it
exactly while a blob on disk reveals nothing about what it holds.

### Usage

```
# Download URL(s) straight into the vault as encrypted blobs
cargo run -p FluShot -- fetch https://example.com/sample1 https://example.com/sample2

# Encrypt file(s) you already have
cargo run -p FluShot -- stash ./suspicious.bin

# Decrypt blob(s) back out — run this INSIDE your analysis VM
cargo run -p FluShot -- open vault/suspicious.bin.enc --out ./work

# List the vault
cargo run -p FluShot -- list

# Point at a different vault directory (default: ./vault)
cargo run -p FluShot -- --vault /path/to/vault list
```

Through the dashboard: the **FluShot** card has an **ENCRYPT** tab (paste sample
URLs — a new box appears as you fill each in) and a **DECRYPT** tab (pick blobs
from the vault to restore, with a loud reminder to only do that inside your VM).

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `FETCH` | Started downloading a URL |
| `SAVED` | A sample was encrypted into the vault |
| `OPENED` | A blob was decrypted back to a file |
| `BLOB` | A blob listed from the vault (`list`) |
| `KEY` | A new vault key was generated — copy it into your VM to decrypt |
| `FAIL` | A download, encrypt, or decrypt step failed |

## FuckAroundFindOut (FAFO) — network isolation canary

A tripwire for malware analysis. When you're reversing a sample you keep the VM's
network disabled — but sometimes you enable it to pull a sample, and forgetting to
re-disable it leaves your host exposed to whatever you're dissecting. FAFO runs
inside the VM and, once per second, checks whether the outside world is reachable.
As long as it isn't, it stays quiet (with a periodic heartbeat so you know it's
alive). The instant it *is*, it prints a breach banner, an `ALERT` line every
second, and rings the terminal bell — until you kill the connection.

### How it decides "reachable"

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

### Catching host-only networking

Probing the internet won't notice a **host-only** adapter (VM can reach your host
but not the internet) — which for malware work is exactly the exposure you care
about. Add your host or gateway IP as a target to catch it:

```
cargo run -p FuckAroundFindOut -- --target 192.168.56.1:445 --target 8.8.8.8:53
```

(Point it at a port your host actually has open — 445/SMB, 139, 3389/RDP, or an SSH
port — so the handshake completes.)

### Cross-platform

Unlike the Linux-specific tools here, FAFO is pure `std` + `clap` and runs on
Windows, Linux, or macOS — so it works whatever your analysis VM runs.

### Usage

```
# Defaults: public DNS servers, once per second
cargo run -p FuckAroundFindOut

# Also watch a host-only adapter, check twice a second
cargo run -p FuckAroundFindOut -- --target 192.168.56.1:445 --interval-ms 500

# One-shot check for scripting (exit 0 = isolated, 1 = exposed)
cargo run -p FuckAroundFindOut -- --once

# Quieter: no bell, heartbeat once a minute
cargo run -p FuckAroundFindOut -- --no-bell --heartbeat-secs 60
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

## HumptyDumpty — static malware triage

The automated first pass on a sample: point it at a file and it cracks it open
into everything you'd pull by hand before deciding what's worth a closer look —
and it never runs the file. Static only, by design: dynamic behaviour is a job for
a human watching a detonation. Pairs with FluShot — decrypt a sample in your VM,
then triage it.

What it pulls:

- **Hashes** — MD5, SHA-256, and (for PE) **imphash** for clustering related samples.
- **Identification** — PE/ELF/Mach-O, architecture, subsystem, and compile
  timestamp (flagged when it's an implausible reproducible-build value rather than
  a real time).
- **Per-section entropy** — flags sections above ~7.2 bits/byte as likely packed
  or encrypted.
- **Suspicious imports** — Windows APIs commonly abused for injection, execution,
  download, persistence, anti-analysis, etc., grouped by intent.
- **Carved IOCs** — URLs, IPs, domains, emails, and registry keys, from both ASCII
  and UTF-16 "wide" strings.

### Usage

```
# Triage a sample
cargo run -p HumptyDumpty -- ./suspicious.exe

# Several at once, and also dump notable (keyword-matched) strings
cargo run -p HumptyDumpty -- --strings sample1.bin sample2.dll
```

Through the dashboard: click the **HumptyDumpty** card, paste the path to a sample,
optionally tick "notable strings", and click **Analyze**.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `FILE` | The file being analyzed, and its format/arch line |
| `HASH` | md5 / sha256 / imphash |
| `SECTION` | A PE/ELF section with its size and entropy |
| `IMPORT` | A suspicious imported API, with its category |
| `IOC` | A carved indicator (`url=`, `ip=`, `domain=`, `email=`, `regkey=`) |
| `STRING` | A notable string (only with `--strings`) |
| `INFO` | Summary counts and non-finding notes |
| `ALERT` | A high-entropy section or a capability-rich import profile |
| `FAIL` | The file couldn't be read |

## dashboard — web UI

A small Axum server that's a thin, tool-agnostic launcher: each tool page builds a query string from a form, opens a Server-Sent Events connection, and the server builds (quietly) and runs that tool as a subprocess, streaming its stdout/stderr back live. A shared per-tool Stop button works by killing the subprocess (or aborting the build) via a cancellation signal, so it works even for 4P's capture, which otherwise runs forever.

Always binds to **loopback only** (`127.0.0.1`) — never a public interface, by design, since it launches active scans/captures on demand. The port is the one thing you can change: it defaults to **80** (so a `rustytoolz.local` hosts alias works with no port suffix) and is overridable via the `RUSTYTOOLZ_PORT` env var (e.g. `7878`).
