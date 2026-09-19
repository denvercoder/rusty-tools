# FeeFiFoFIM — file integrity monitor

Baselines a directory's contents (a SHA-256 hash of every file), then checks it again later and reports anything added, removed, or changed. Classic host-based integrity monitoring — pairs with Bunyan as the toolkit's second host-based (rather than network-based) detection skill.

## No privileges needed

Like Bunyan, this is plain file I/O — no `sudo` or `setcap` required.

## Three modes

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

> Part of [Rusty Toolz](../README.md).
