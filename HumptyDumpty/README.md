# HumptyDumpty — static malware triage

The automated first pass on a sample: point it at a file and it cracks it open
into everything you'd pull by hand before deciding what's worth a closer look —
and it never runs the file. Static only, by design: dynamic behaviour is a job for
a human watching a detonation. Pairs with FluShot — decrypt a sample in your VM,
then triage it.

## What it pulls

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

## Usage

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

> Part of [Rusty Toolz](../README.md). It only reads a sample (never runs it), but the file is still live malware — triage it inside your analysis VM.
