#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

echo "[1/3] Running regression tests"
python3 -m unittest discover -s tests -v

echo
echo "[2/3] Cleaning stale Mininet state"
sudo mn -c >/dev/null 2>&1 || true
sudo ovs-vsctl --if-exists del-br s1

echo
echo "[3/3] Running live SDN ACL verification"
sudo python3 verify_access.py
