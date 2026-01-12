#!/usr/bin/env bash
set -e

# Remove NFQUEUE rules from INPUT/OUTPUT (ignore errors)
sudo iptables -D INPUT  -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -D OUTPUT -p tcp -m conntrack --ctstate NEW -j NFQUEUE --queue-num 1 2>/dev/null || true

# Remove PREROUTING jump to MTD_REDIRECT and delete chain (ignore errors)
sudo iptables -t nat -D PREROUTING -j MTD_REDIRECT 2>/dev/null || true
sudo iptables -t nat -F MTD_REDIRECT 2>/dev/null || true
sudo iptables -t nat -X MTD_REDIRECT 2>/dev/null || true
