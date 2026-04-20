#!/usr/bin/env bash
# drederick bootstrap for Debian/Ubuntu/Kali CTF VPN workstations.
# Run this once, manually, on the operator's host. It installs the recon
# toolchain drederick's `doctor` subcommand expects. This NEVER touches a
# target — it only modifies the operator workstation.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "bootstrap: re-running under sudo..." >&2
  exec sudo -E "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  nmap \
  exploitdb \
  python3 \
  python2 \
  golang-go \
  ruby \
  git \
  curl \
  jq \
  pipx

# pipx / datasette must live in the invoking user's home, not root's.
REAL_USER="${SUDO_USER:-$USER}"
sudo -u "$REAL_USER" -H bash -lc 'pipx ensurepath && pipx install datasette'

echo "bootstrap: done. run 'drederick doctor' to verify."
