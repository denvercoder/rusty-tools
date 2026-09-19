# dashboard — web UI

A small Axum server that's a thin, tool-agnostic launcher: each tool page builds a query string from a form, opens a Server-Sent Events connection, and the server builds (quietly) and runs that tool as a subprocess, streaming its stdout/stderr back live. A shared per-tool Stop button works by killing the subprocess (or aborting the build) via a cancellation signal, so it works even for 4P's capture, which otherwise runs forever.

Always binds to **loopback only** (`127.0.0.1`) — never a public interface, by design, since it launches active scans/captures on demand. Only the port is configurable, via the `RUSTYTOOLZ_PORT` env var (default `80`, e.g. `7878` for a non-privileged port).

```
cargo run -p dashboard --release
```

or double-click `dashboard/run.sh`. Both build and start the local server and open your browser to a tool picker.

> Part of [Rusty Toolz](../README.md).
