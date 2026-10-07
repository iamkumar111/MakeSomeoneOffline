#!/bin/sh
# Read-only Linux/macOS report; redirect stdout/stderr to retain it.
set -u
echo 'Open-NetCut platform diagnostics (UTC)'
date -u '+%Y-%m-%dT%H:%M:%SZ'
uname -a
id
if command -v go >/dev/null 2>&1; then go version; fi
if command -v node >/dev/null 2>&1; then node --version; fi
if command -v npm >/dev/null 2>&1; then npm --version; fi
case "$(uname -s)" in
    Darwin)
        /sbin/route -n get default
        /usr/sbin/arp -an
        /sbin/ifconfig
        ;;
    Linux)
        ip -brief address
        ip route
        ip neigh
        cat /proc/sys/net/ipv4/ip_forward
        if command -v nft >/dev/null 2>&1; then nft list table inet open_netcut; fi
        ;;
    *) echo 'Use Windows-Diagnostics.ps1 on Windows.' ;;
esac
echo 'Retained server logs (run from the repo root):'
for file in logs/control-plane.log logs/control-plane.log.1 logs/control-plane.log.2 logs/control-plane.log.3; do
    if [ -f "$file" ]; then ls -l "$file"; fi
done
