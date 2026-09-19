# Bunyan — auth log analyzer

Watches the systemd journal's auth facility — sshd and sudo activity — and prints only what's actually signal: logins (success/fail), sudo command executions and auth failures, and live alerts for brute-force and compromise patterns. Named for the log-splitting kind of Bunyan, not the WHOIS-adjacent kind.

## No privileges needed

Unlike 4P and OneForTheHoney, Bunyan doesn't need `sudo` or `setcap` — reading the journal's auth facility (`journalctl SYSLOG_FACILITY=10`) works as a normal user on this machine out of the box.

## Live vs. saved logs

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

## A known limitation

Bunyan spawns `journalctl -f` as a child process for live mode. If Bunyan is killed outright rather than allowed to exit on its own — notably, the dashboard's Stop button, which signals only Bunyan's own process — that `journalctl` child can be left running in the background. Harmless (it just keeps tailing quietly), but worth knowing about; a full fix would mean either process-group signaling in the dashboard or replacing the long-lived `-f` stream with short-lived polling, neither of which felt worth the added complexity for a personal tool. Plain `Ctrl+C` on the command line doesn't have this problem — it's delivered to the whole foreground process group, journalctl included.

Output line prefixes:

| Prefix | Meaning |
|---|---|
| `LOGIN` | An sshd login attempt — `ok` (with method) or `fail` (tagged `[invalid user]` when the username itself doesn't exist) |
| `SUDO` | A sudo command execution (`invoking user -> target user  command`) or a sudo auth failure |
| `ALERT` | 5+ failed SSH logins from one source within 60s (brute force), or a successful login from a source with 3+ recent failures (possible compromised credential) |

> Part of [Rusty Toolz](../README.md).
