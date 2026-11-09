#!/bin/sh
# Shapes the container's network, then runs sshd.
#
# NETEM        netem options for the packets this container sends, e.g.
#              "delay 50ms" or "delay 50ms loss 1%". The delay also holds
#              back the ACKs and window adjusts for uploads, so it adds to
#              the round-trip time in both directions.
# UPLOAD_RATE  drop incoming packets above this rate, e.g. 20mbit. TCP
#              then sends uploads to this container at about that rate.
set -e
if [ -n "${NETEM:-}" ]; then
    # shellcheck disable=SC2086 # NETEM is a list of tc options
    tc qdisc add dev eth0 root netem $NETEM
fi
if [ -n "${UPLOAD_RATE:-}" ]; then
    tc qdisc add dev eth0 handle ffff: ingress
    tc filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 \
        police rate "$UPLOAD_RATE" burst 256k drop
fi
exec /usr/sbin/sshd -D -e
