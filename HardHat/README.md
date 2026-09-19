# HardHat — security config auditor

A proactive posture check, unlike every other tool here — it reads local system configuration once and reports hardening gaps, rather than watching for events over time. Checks SSH config, `/etc/passwd` for unexpected UID-0 accounts, firewall service status, unusual setuid binaries, and a watchlist of sensitive files for world-writable permissions — plus, when run as root, sudoers `NOPASSWD: ALL` rules and `/etc/shadow` for empty-password accounts.

## Privileges: more checks unlock with `sudo`

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

> Part of [Rusty Toolz](../README.md).
