#!/bin/bash
# OpenSSH interop tests for the Acton ssh module.
#
#   Direction A: OpenSSH `ssh` client -> Acton ssh.Server (password auth)
#                - exec request + exit status
#                - wrong password rejected
#                - subsystem channel data round-trip
#   Direction B: Acton ssh.Client -> OpenSSH `sshd` (public key auth)
#                - exec + output + exit status
#                - wrong key rejected
#
# Requires: ssh (>= 8.4 for SSH_ASKPASS_REQUIRE), sshd, ssh-keygen.
# Run from the project root after `acton build`:
#   ./interop/run_interop.sh

set -u
cd "$(dirname "$0")/.."

BIN=out/bin
TMP=$(mktemp -d /tmp/acton-ssh-interop.XXXXXX)
PASS=0
FAIL=0
SERVER_PID=""
SSHD_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

note() { echo "== $*"; }
ok()   { echo "PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $*"; FAIL=$((FAIL+1)); }

# Password feeder for the OpenSSH client (avoids needing a TTY)
cat > "$TMP/askpass-good" <<'EOF'
#!/bin/sh
echo interop-pass
EOF
cat > "$TMP/askpass-bad" <<'EOF'
#!/bin/sh
echo wrong-pass
EOF
chmod +x "$TMP/askpass-good" "$TMP/askpass-bad"

ssh_to_acton() {
    local askpass="$1"; shift
    SSH_ASKPASS_REQUIRE=force SSH_ASKPASS="$askpass" DISPLAY=none \
    ssh -p "$PORT" -F /dev/null \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$TMP/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        "$@"
}

#
# Direction A: OpenSSH client -> Acton server
#
note "Direction A: OpenSSH ssh client -> Acton ssh.Server"

"$BIN/interop_server" > "$TMP/server.out" 2>"$TMP/server.err" &
SERVER_PID=$!

PORT=""
for i in $(seq 1 50); do
    PORT=$(awk '/^PORT /{print $2; exit}' "$TMP/server.out" 2>/dev/null)
    [ -n "$PORT" ] && break
    sleep 0.1
done
if [ -z "$PORT" ]; then
    bad "Acton interop server did not report a port"
    cat "$TMP/server.err"
else
    note "Acton server listening on port $PORT"

    # exec: expect "pong" and exit 0
    out=$(ssh_to_acton "$TMP/askpass-good" interop@127.0.0.1 ping 2>"$TMP/sshA1.err")
    rc=$?
    if [ $rc -eq 0 ] && [ "$out" = "pong" ]; then
        ok "exec 'ping' -> pong, exit 0"
    else
        bad "exec 'ping' (rc=$rc out=$out)"
        sed -n 1,10p "$TMP/sshA1.err"
    fi

    # exec unknown command: expect exit 127 and stderr message
    out=$(ssh_to_acton "$TMP/askpass-good" interop@127.0.0.1 bogus 2>"$TMP/sshA2.err")
    rc=$?
    if [ $rc -eq 127 ] && grep -q "unknown command" "$TMP/sshA2.err"; then
        ok "exec unknown command -> exit 127 with stderr"
    else
        bad "exec unknown command (rc=$rc)"
        sed -n 1,10p "$TMP/sshA2.err"
    fi

    # wrong password: must fail
    out=$(ssh_to_acton "$TMP/askpass-bad" interop@127.0.0.1 ping 2>"$TMP/sshA3.err")
    rc=$?
    if [ $rc -ne 0 ]; then
        ok "wrong password rejected (rc=$rc)"
    else
        bad "wrong password unexpectedly accepted"
    fi

    # subsystem echo round-trip
    out=$(printf 'marco\n' | ssh_to_acton "$TMP/askpass-good" -s interop@127.0.0.1 echo 2>"$TMP/sshA4.err")
    rc=$?
    if [ $rc -eq 0 ] && [ "$out" = "marco" ]; then
        ok "subsystem 'echo' data round-trip, exit 0"
    else
        bad "subsystem 'echo' (rc=$rc out=$out)"
        sed -n 1,10p "$TMP/sshA4.err"
    fi

    # larger payload through the subsystem (1000 lines)
    seq 1 1000 > "$TMP/payload.txt"
    out_file="$TMP/payload.out"
    ssh_to_acton "$TMP/askpass-good" -s interop@127.0.0.1 echo < "$TMP/payload.txt" > "$out_file" 2>"$TMP/sshA5.err"
    rc=$?
    if [ $rc -eq 0 ] && cmp -s "$TMP/payload.txt" "$out_file"; then
        ok "subsystem 'echo' 1000-line payload integrity"
    else
        bad "subsystem payload (rc=$rc, diff: $(cmp "$TMP/payload.txt" "$out_file" 2>&1 | head -1))"
        sed -n 1,10p "$TMP/sshA5.err"
    fi
fi

kill "$SERVER_PID" 2>/dev/null
SERVER_PID=""

#
# Direction B: Acton client -> OpenSSH sshd (pubkey auth)
#
note "Direction B: Acton ssh.Client -> OpenSSH sshd"

SSHD_BIN=$(command -v sshd || echo /usr/sbin/sshd)
if [ ! -x "$SSHD_BIN" ]; then
    note "sshd not found; skipping direction B"
else
    SSHD_PORT=$((20000 + RANDOM % 20000))
    mkdir -p "$TMP/sshd"
    chmod 700 "$TMP/sshd"
    ssh-keygen -q -t ed25519 -N "" -f "$TMP/sshd/host_ed25519"
    ssh-keygen -q -t ed25519 -N "" -f "$TMP/sshd/client_ed25519"
    cp "$TMP/sshd/client_ed25519.pub" "$TMP/sshd/authorized_keys"
    chmod 600 "$TMP/sshd/authorized_keys"

    cat > "$TMP/sshd/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $TMP/sshd/host_ed25519
PidFile $TMP/sshd/sshd.pid
AuthorizedKeysFile $TMP/sshd/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes no
UsePAM no
LogLevel ERROR
EOF
    # UsePAM is illegal on some platforms when not root; retry without it
    "$SSHD_BIN" -t -f "$TMP/sshd/sshd_config" 2>/dev/null || \
        sed -i.bak '/UsePAM/d' "$TMP/sshd/sshd_config"

    "$SSHD_BIN" -D -e -f "$TMP/sshd/sshd_config" > "$TMP/sshd/log" 2>&1 &
    SSHD_PID=$!
    sleep 1

    if ! kill -0 "$SSHD_PID" 2>/dev/null; then
        note "sshd failed to start; skipping direction B"
        sed -n 1,10p "$TMP/sshd/log"
        SSHD_PID=""
    else
        out=$("$BIN/interop_client" 127.0.0.1 "$SSHD_PORT" "$(id -un)" "echo interop-ok" "$TMP/sshd/client_ed25519" 2>&1)
        rc=$?
        if [ $rc -eq 0 ] && echo "$out" | grep -q "interop-ok"; then
            ok "Acton client pubkey auth + exec against OpenSSH sshd"
        else
            bad "Acton client against OpenSSH sshd (rc=$rc)"
            echo "$out" | sed -n 1,20p
            sed -n 1,10p "$TMP/sshd/log"
        fi

        # Remote exit status must propagate
        out=$("$BIN/interop_client" 127.0.0.1 "$SSHD_PORT" "$(id -un)" "exit 42" "$TMP/sshd/client_ed25519" 2>&1)
        rc=$?
        if [ $rc -eq 42 ]; then
            ok "Acton client receives remote exit status (42)"
        else
            bad "Acton client remote exit status (rc=$rc, want 42)"
            echo "$out" | sed -n 1,10p
        fi

        # Wrong key must fail
        ssh-keygen -q -t ed25519 -N "" -f "$TMP/sshd/wrong_key"
        out=$("$BIN/interop_client" 127.0.0.1 "$SSHD_PORT" "$(id -un)" "echo nope" "$TMP/sshd/wrong_key" 2>&1)
        rc=$?
        if [ $rc -ne 0 ] && echo "$out" | grep -q "CONNECT-ERROR"; then
            ok "Acton client with wrong key is rejected"
        else
            bad "Acton client with wrong key not rejected (rc=$rc)"
            echo "$out" | sed -n 1,20p
        fi
    fi
fi

echo
echo "interop results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
