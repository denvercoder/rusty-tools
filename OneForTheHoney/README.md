# OneForTheHoney — decoy service listener

A honeypot: binds a curated list of the ports scanners and bots most commonly probe (FTP, SSH, Telnet, SMTP, HTTP(S), SMB, MSSQL, MySQL, RDP, VNC) and logs every connection attempt against them, with a fake plaintext banner on the protocols that have one and live scanner detection when one source touches several decoy ports in quick succession.

## Why some ports need elevated privileges

Several of the default decoy ports (21, 22, 23, 25, 80, 443) are below 1024, and Linux only lets a process bind those without a specific permission, `CAP_NET_BIND_SERVICE` — the same OS-level gate every real service on those ports (sshd, an actual web server, etc.) has to satisfy. OneForTheHoney binds each decoy port independently: if one fails for lack of privilege, it prints a warning for that port and keeps the rest running, so it's still useful unprivileged (any ports ≥1024 in the list still work).

## One-time setup (recommended)

From the workspace root, after building:

```
sudo setcap cap_net_bind_service+ep target/release/OneForTheHoney
```

After this, the compiled binary can bind the privileged ports without `sudo` — directly, or through the dashboard. As with 4P's `cap_net_raw`, the capability is attached to that specific compiled file, so re-run this once after any rebuild.

## Alternative: sudo per run

```
sudo ./target/release/OneForTheHoney
```

Simpler for a one-off, but asks for your password every time and doesn't work through the dashboard.

## Usage

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

> Part of [Rusty Toolz](../README.md). Binds every interface by default, so it logs connection attempts from **any** device that can reach this machine — only run it on networks you own or are authorized to monitor.
