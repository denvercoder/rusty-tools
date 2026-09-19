#!/usr/bin/env bash
#
# Rusty Toolz installer — Linux & macOS.
# (On Windows, run install.ps1 in PowerShell instead.)
#
#   1. clone the repo
#   2. ./install.sh
#   3. it checks/install prerequisites, adds a hosts alias, builds, and runs the dashboard.
#
set -euo pipefail
cd "$(dirname "$0")"

# ---- config -----------------------------------------------------------------
HOSTNAME_ALIAS="rustytoolz.local"   # change to e.g. rustytoolz.test if macOS mDNS fights .local
PORT=80                             # so http://rustytoolz.local works with no port; loopback-only either way
# Tools known to build on every OS; the rest are Linux-specific and are built
# only on Linux (the dashboard builds any tool lazily on first click anyway).
PORTABLE_TOOLS=(dashboard Portofino FuckAroundFindOut FluShot HumptyDumpty)

# ---- pretty output ----------------------------------------------------------
info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! \033[0m %s\n' "$*"; }
err()  { printf '\033[1;31mXX \033[0m %s\n' "$*" >&2; }

# ---- detect OS --------------------------------------------------------------
case "$(uname -s)" in
  Linux)  PLATFORM=linux ;;
  Darwin) PLATFORM=macos ;;
  *) err "This script handles Linux and macOS. On Windows, run install.ps1 in PowerShell."; exit 1 ;;
esac
info "Detected platform: $PLATFORM"

# ---- 1. Rust toolchain ------------------------------------------------------
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" || true
if command -v cargo >/dev/null 2>&1; then
  info "Rust present — $(cargo --version)"
else
  info "Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  . "$HOME/.cargo/env"
  info "Installed $(cargo --version)"
fi

# ---- 2. C toolchain / linker ------------------------------------------------
if [ "$PLATFORM" = linux ]; then
  if command -v cc >/dev/null 2>&1; then
    info "C toolchain present — $(cc --version | head -1)"
  else
    info "Installing a C toolchain (needed to link Rust and build ring/rustls)..."
    if   command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y build-essential pkg-config perl
    elif command -v dnf     >/dev/null 2>&1; then sudo dnf install -y gcc make pkgconf-pkg-config perl
    elif command -v pacman  >/dev/null 2>&1; then sudo pacman -Sy --noconfirm base-devel perl
    else warn "Unrecognized package manager — install a C compiler (gcc), make and perl yourself."; fi
  fi
  command -v setcap >/dev/null 2>&1 || warn "setcap not found (install libcap2-bin) — 4P and OneForTheHoney need it for capture / low ports."
else
  # macOS: the Command Line Tools give you clang (the linker) + system headers.
  if xcode-select -p >/dev/null 2>&1; then
    info "Xcode Command Line Tools present"
  else
    info "Triggering Xcode Command Line Tools install (accept the dialog)..."
    xcode-select --install || true
    warn "When the Command Line Tools finish installing, re-run ./install.sh"
    exit 0
  fi
fi

# ---- 3. hosts alias ---------------------------------------------------------
HOSTS=/etc/hosts
if grep -qiE "[[:space:]]${HOSTNAME_ALIAS}([[:space:]]|\$)" "$HOSTS" 2>/dev/null; then
  info "hosts entry for $HOSTNAME_ALIAS already present"
else
  read -r -p "Add '127.0.0.1 $HOSTNAME_ALIAS' to $HOSTS (needs sudo)? [y/N] " ans
  if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
    echo "127.0.0.1 $HOSTNAME_ALIAS" | sudo tee -a "$HOSTS" >/dev/null
    if [ "$PLATFORM" = macos ]; then sudo dscacheutil -flushcache 2>/dev/null || true; sudo killall -HUP mDNSResponder 2>/dev/null || true; fi
    info "Added — the dashboard will also be at http://$HOSTNAME_ALIAS:$PORT"
  else
    warn "Skipped — use http://localhost:$PORT instead."
  fi
fi

# ---- 4. build ---------------------------------------------------------------
if [ "$PLATFORM" = linux ]; then
  info "Building the whole suite (release)..."
  cargo build --release
else
  info "Building the cross-platform tools + dashboard (release)..."
  build_args=(); for t in "${PORTABLE_TOOLS[@]}"; do build_args+=(-p "$t"); done
  cargo build --release "${build_args[@]}"
fi

DASH=target/release/dashboard

# ---- 5. grant port privilege (loopback only) --------------------------------
# Ports < 1024 need privilege. On Linux we grant just the bind capability to the
# dashboard binary (no root at runtime); macOS needs sudo, so we fall back.
RUN_PORT=$PORT
if [ "$PORT" -lt 1024 ]; then
  if [ "$PLATFORM" = linux ]; then
    if command -v setcap >/dev/null 2>&1; then
      info "Granting the dashboard permission to bind port $PORT (setcap cap_net_bind_service)..."
      sudo setcap 'cap_net_bind_service=+ep' "$DASH"
    else
      warn "setcap unavailable (install libcap2-bin) — can't bind port $PORT unprivileged. Falling back to 7878."
      RUN_PORT=7878
    fi
  else
    warn "macOS needs sudo to bind port $PORT. Falling back to 7878 for this run."
    warn "For bare http://$HOSTNAME_ALIAS, run:  sudo RUSTYTOOLZ_PORT=$PORT $DASH"
    RUN_PORT=7878
  fi
fi

# ---- 6. run -----------------------------------------------------------------
if [ "$RUN_PORT" = 80 ]; then
  info "Starting the dashboard: http://localhost  and  http://$HOSTNAME_ALIAS"
else
  info "Starting the dashboard: http://localhost:$RUN_PORT  and  http://$HOSTNAME_ALIAS:$RUN_PORT"
fi
info "Ctrl+C to stop."
exec env RUSTYTOOLZ_PORT="$RUN_PORT" "$DASH"
