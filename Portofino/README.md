# Portofino — TCP port scanner

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

Portofino is also the workspace's default member, so a bare `cargo run` from the
repo root goes straight to it, and its first prompt lets you pick `[C]ommand Line`
or `[I]nteractive` (which launches the web dashboard).

> Part of [Rusty Toolz](../README.md). Only scan hosts you own or are explicitly authorized to test.
