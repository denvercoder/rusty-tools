#!/bin/sh
# Double-click (or `./run.sh`) to build and start the Rusty Tools dashboard.
# It listens on 127.0.0.1 only and opens your browser automatically.
cd "$(dirname "$0")" || exit 1
cargo run --release
