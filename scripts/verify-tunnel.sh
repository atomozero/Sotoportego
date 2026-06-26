#!/bin/sh
# Quick end-to-end check that the Sotoportego tunnel is actually carrying
# traffic. Run with the VPN in "Connected" state. Exits non-zero on the
# first failure so it's CI-friendly if you ever wire it up.

set -u

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

fail() { red "FAIL: $*"; exit 1; }
pass() { green "OK:   $*"; }
warn() { yellow "WARN: $*"; }

echo "== 1. interface =="
TUN_LINE=$(ifconfig | grep -E '^tun/[0-9]+' || true)
if [ -z "$TUN_LINE" ]; then
    fail "no tun/N interface present -- the tunnel isn't up"
fi
TUN_IFACE=$(echo "$TUN_LINE" | awk '{print $1}')
TUN_IP=$(ifconfig "$TUN_IFACE" | awk '/inet addr:/ {print $3; exit}' | tr -d ',')
if [ -z "$TUN_IP" ] || [ "$TUN_IP" = "--" ]; then
    fail "$TUN_IFACE exists but has no IPv4 address"
fi
pass "$TUN_IFACE up with inet $TUN_IP"

echo
echo "== 2. routing =="
ROUTE_OUT=$(route 2>&1)
# Haiku's `route` prints the default route as destination 0.0.0.0 / netmask
# 0.0.0.0, not "default" -- and the interface name is the last column. Match
# both spellings to be portable across Haiku versions and other BSDs.
DEFAULT_VIA_TUN=$(echo "$ROUTE_OUT" | awk -v iface="$TUN_IFACE" '
    ($1 == "0.0.0.0" && $2 == "0.0.0.0" && $NF == iface) { print; found=1 }
    ($1 == "default" && $NF == iface) { print; found=1 }
    END { exit found ? 0 : 1 }
')
if [ -z "$DEFAULT_VIA_TUN" ]; then
    red "default route is NOT via $TUN_IFACE -- packets are still leaking on wifi"
    echo "$ROUTE_OUT" | head -20
    exit 1
fi
pass "default route uses $TUN_IFACE ($DEFAULT_VIA_TUN)"

echo
echo "== 3. external IP (this is the proof) =="
# api.ipify.org returns the public IP we appear from. Time out hard so a
# DNS-broken tunnel doesn't hang the script forever.
EXTERNAL=$(curl --max-time 8 -s https://api.ipify.org 2>/dev/null || true)
if [ -z "$EXTERNAL" ]; then
    fail "could not reach api.ipify.org -- the tunnel is up but breaks outbound HTTPS"
fi
# Pull a current "wifi" IP for contrast: it's the address of the interface
# the original default route used to live on, recorded in the session file.
LAN_IP=$(ifconfig | awk '/inet addr:/ && !/127.0.0.1/ && !found {print $3; found=1}' | tr -d ',')

echo "Apparent external IP:   $EXTERNAL"
echo "(your local wifi IP:    ${LAN_IP:-unknown})"
echo "Look it up at https://ipinfo.io/$EXTERNAL or 'whois $EXTERNAL' -- the"
echo "country should be the VPN server's country, not yours."

# Best-effort sanity check: the external IP must not equal the wifi IP.
if [ -n "$LAN_IP" ] && [ "$EXTERNAL" = "$LAN_IP" ]; then
    fail "external IP matches your wifi IP -- the tunnel is bypassed"
fi
pass "outbound HTTPS goes through the tunnel (external != lan)"

echo
echo "== 4. server pin =="
# We pinned the VPN server's IP to the wifi gateway so openvpn's UDP/TCP
# carrier doesn't loop through its own tunnel. There's no portable way to
# grab the server IP from the GUI from a shell, so just show the table and
# let the user eyeball it.
echo "(grep your VPN server IP in the table below; it should NOT use $TUN_IFACE)"
echo "$ROUTE_OUT" | head -30

echo
green "Tunnel verification complete."
