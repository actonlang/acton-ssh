#!/usr/bin/env bash
# A fleet of SSH servers in Docker containers, for running ScpPut/ScpGet
# against many devices from one machine. Every container has its own IP,
# sshd, filesystem and limits. Needs only the docker group, not sudo.
#
#   ./fleet.sh build [PUBKEY]        build the image; PUBKEY may log in as root
#                                    (default: $SCP_KEY.pub, else ~/.ssh/id_ed25519.pub)
#   ./fleet.sh add PREFIX COUNT [DOCKER_RUN_OPTION...]
#                                    start COUNT more containers scp-PREFIX-NNN
#   ./fleet.sh hosts REMOTE_PATH [PASSWORD]
#                                    print a hosts file for example_scp_multi with
#                                    every container (PASSWORD default -: the key;
#                                    the root password is scp-fleet)
#   ./fleet.sh list                  name and IP of every container
#   ./fleet.sh down                  remove every container and the network
#
# DOCKER_RUN_OPTIONs make devices different:
#   -e NETEM="delay 50ms loss 1%"    netem on what the container sends
#   -e UPLOAD_RATE=20mbit            limit uploads to the container
#   --cpus 0.2                       a slow CPU
#   --tmpfs /tmp:size=32m            a small /tmp in RAM, as on OpenWrt: a
#                                    bigger upload fails with "No space left"
#   --memory 64m --memory-swap 64m --tmpfs /tmp
#                                    little RAM: a big upload into /tmp gets
#                                    the remote side OOM-killed
#
# Faults while a test runs (NAME from ./fleet.sh list):
#   docker pause NAME, docker unpause NAME
#                                    the device freezes, the TCP connection
#                                    stays open: only client timeouts help
#   docker exec NAME pkill -KILL -x scp
#                                    the remote scp is killed
#   docker exec NAME tc qdisc replace dev eth0 root netem loss 100%
#                                    the link goes dead without a reset
#   docker restart NAME              the device reboots
#
# Every container gets NET_ADMIN, which only reaches its own network.
# All containers share one host key and accept the same public key.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
image=scp-fleet
network=scp-fleet
label=scp-fleet

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 2
}

names() {
    docker ps --filter "label=$label" --format '{{.Names}}' | sort
}

ip_of() {
    docker inspect -f "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$1"
}

cmd=${1:-}
[ -n "$cmd" ] || usage
shift

case $cmd in
build)
    pub=${1:-}
    if [ -z "$pub" ]; then
        if [ -n "${SCP_KEY:-}" ]; then pub=$SCP_KEY.pub; else pub=$HOME/.ssh/id_ed25519.pub; fi
    fi
    [ -r "$pub" ] || { echo "cannot read public key $pub" >&2; exit 1; }
    docker build -t "$image" --build-arg PUBKEY="$(cat "$pub")" "$here"
    ;;
add)
    [ $# -ge 2 ] || usage
    prefix=$1 count=$2
    shift 2
    docker network inspect "$network" >/dev/null 2>&1 \
        || docker network create --label "$label" "$network" >/dev/null
    have=$(docker ps -aq --filter "label=$label.prefix=$prefix" | wc -l)
    start_one() {
        docker run -d --name "$1" --hostname "$1" --network "$network" \
            --label "$label=1" --label "$label.prefix=$prefix" \
            --cap-add NET_ADMIN "${@:2}" "$image" >/dev/null
        echo "$1 $(ip_of "$1")"
    }
    # Start 16 at a time; a failed docker run stops the script.
    pids=()
    for i in $(seq $((have + 1)) $((have + count))); do
        start_one "$(printf 'scp-%s-%03d' "$prefix" "$i")" "$@" &
        pids+=($!)
        if [ ${#pids[@]} -ge 16 ]; then
            for p in "${pids[@]}"; do wait "$p"; done
            pids=()
        fi
    done
    for p in "${pids[@]}"; do wait "$p"; done
    ;;
hosts)
    [ $# -ge 1 ] || usage
    remote=$1 password=${2:--}
    names | while read -r name; do
        echo "# $name"
        echo "$(ip_of "$name") root $password 22 $remote"
    done
    ;;
list)
    names | while read -r name; do
        echo "$name $(ip_of "$name")"
    done
    ;;
down)
    ids=$(docker ps -aq --filter "label=$label")
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086 # one id per word
        docker rm -f $ids >/dev/null
    fi
    if docker network inspect "$network" >/dev/null 2>&1; then
        docker network rm "$network" >/dev/null
    fi
    ;;
*)
    usage
    ;;
esac
