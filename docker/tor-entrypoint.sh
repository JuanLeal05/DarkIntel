#!/bin/sh
set -eu
: "${TOR_CONTROL_PASSWORD:?TOR_CONTROL_PASSWORD no definido}"
HASH=$(tor --quiet --hash-password "$TOR_CONTROL_PASSWORD" | tail -n 1)
exec tor -f /etc/tor/torrc --HashedControlPassword "$HASH"