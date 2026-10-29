#!/usr/bin/env bash
#
# Reproduce the reported first-data corruption ("Window exceeded") in-process.
#
# Why this needs a patched libssh: channel_rcv_data discards a DATA packet when
# len > channel->local_window (libssh 0.12.2 src/channels.c:670), but
# packet.c caps any transport packet at MAX_PACKET_LEN = 262144 B, far below a
# fresh WINDOW_DEFAULT = 2097152 B window. No compliant -- or even hostile --
# sender can reach that branch. It is reachable only by a receiver whose window
# has diverged BELOW the incoming packet size. This script builds a libssh that
# fakes exactly that divergence for a chosen packet, so the discard is real and
# the bytes are really lost.
#
# It then runs test_ssh_hello_storm twice -- against stock libssh, and against
# the candidate RFC 4254 5.2 clamp patch (see LIBSSH-window-clamp.md) -- and
# reports how often the corrupt stream reaches the application in each.
#
# It does NOT touch src/lib.ext.c. The pre_fatal guard that used to be A/B'd
# here was never committed to a branch and is not in the tree; commit 21dd241
# replaced session_apply_poll_events with session_event_poll and dropped it.
# (ssh_event_dopoll does not compensate: ssh_poll_ctx_dopoll returns SSH_ERROR
# only on an empty context, a failed poll(), or a socket callback returning -2
# -- read error and EOF only -- so an SSH_FATAL recorded by channel_rcv_data
# never surfaces.) If you restore the guard, run this before and after to
# compare.
#
# Everything it touches is restored on exit, including on Ctrl-C.
#
# Usage:
#   src/test_ssh_hello_storm.sh [repeats]     # default 12
#
# Runs from anywhere -- it resolves the repo root from its own location.
#
# Environment:
#   LIBSSH_SRC   libssh source to build from. Default: the exact tarball this
#                tree pins, unpacked from acton's package cache. Override only
#                if the source matches deps/libssh/build.zig's file list -- an
#                older checkout will be missing sources the wrapper compiles
#                (e.g. src/hybrid_mlkem.c after the 0.12 upgrade) and the build
#                dies with "file_hash FileNotFound".
#   ACTON        acton binary                    (default: ../acton/bin/acton)
#   ACTON_CACHE  acton cache root                (default: ~/.cache/acton)
#   LIBSSH_REPRO_DROP_WINDOW
#                fake window for the dropped 1024 B packet (default 0). 0 means
#                nothing fits, so both variants lose the whole packet and only
#                the error behaviour differs. Set e.g. 500 to see the clamp
#                deliver the part that fits while stock libssh drops it all.

set -uo pipefail

REPEATS="${1:-12}"
# This script lives in src/; everything it touches is relative to the repo root.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBSSH_SRC="${LIBSSH_SRC:-}"
ACTON="${ACTON:-/usr/bin/acton}"
ACTON_CACHE="${ACTON_CACHE:-$HOME/.cache/acton}"

LOCAL_LIBSSH="$REPO/deps/libssh/libssh-local"
BACKUP="$(mktemp -d)"

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

restore() {
    say "Restoring tree"
    for f in deps/libssh/build.zig deps/libssh/build.zig.zon; do
        [ -f "$BACKUP/$(basename "$f")" ] && cp "$BACKUP/$(basename "$f")" "$REPO/$f"
    done
    rm -rf "$LOCAL_LIBSSH" "$BACKUP"
    "$ACTON" build >/dev/null 2>&1
    git -C "$REPO" status --short -- deps
}
trap restore EXIT INT TERM

[ -x "$ACTON" ] || die "acton not found at $ACTON (set ACTON=)"
cd "$REPO"

cp deps/libssh/build.zig deps/libssh/build.zig.zon "$BACKUP/"

# ------------------------------------------------------- 0. which libssh source
# Building the repro against a different libssh than deps/libssh/build.zig was
# written for is the easiest way to get a silent false negative, so default to
# the source this tree actually pins.
if [ -z "$LIBSSH_SRC" ]; then
    say "Resolving the pinned libssh source"
    pinhash=$(sed -n 's/.*\.hash = "\([^"]*\)".*/\1/p' deps/libssh/build.zig.zon | head -1)
    [ -n "$pinhash" ] || die "no .hash found in deps/libssh/build.zig.zon"
    tarball="$ACTON_CACHE/zig-global-cache/p/$pinhash.tar.gz"
    [ -f "$tarball" ] || die "pinned tarball not in the cache: $tarball
  run '$ACTON build' once to fetch it, or set LIBSSH_SRC= to a matching source"
    mkdir -p "$BACKUP/pinned"
    tar xf "$tarball" -C "$BACKUP/pinned" || die "could not unpack $tarball"
    found=$(find "$BACKUP/pinned" -maxdepth 2 -type d -name src -print -quit)
    [ -n "$found" ] || die "no src/ directory inside $tarball"
    LIBSSH_SRC="${found%/src}"
    echo "  using $(basename "$tarball")"
fi
[ -d "$LIBSSH_SRC/src" ] || die "libssh source not found at $LIBSSH_SRC"

# ---------------------------------------------------------------- 1. local copy
# zig rejects absolute and escaping .path values, so the copy must live inside
# the build root (deps/libssh/).
say "Copying libssh from $LIBSSH_SRC"
rm -rf "$LOCAL_LIBSSH"
cp -a "$LIBSSH_SRC" "$LOCAL_LIBSSH" || die "copy failed"
rm -rf "$LOCAL_LIBSSH/.git"

# The wrapper's file list and the source have to agree, or zig fails with an
# opaque "file_hash FileNotFound" that is easy to mistake for "no bug here".
missing=$(python3 -c "
import re, os
srcs = re.findall(r'\"(src/[^\"]+[.]c)\"', open('deps/libssh/build.zig').read())
print(' '.join(x for x in srcs if not os.path.exists(os.path.join('deps/libssh/libssh-local', x))))
")
[ -z "$missing" ] || die "this libssh source is missing files deps/libssh/build.zig compiles:
  $missing
  It does not match the pin. Unset LIBSSH_SRC to use the pinned tarball."

# ---------------------------------------------------------------- 2. the hook
say "Patching channels.c with the window-divergence hook"
python3 - "$LOCAL_LIBSSH/src/channels.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = """    if (len > channel->local_window) {
        SSH_LOG(SSH_LOG_RARE,
                "Data packet too big for our window(%" PRIu32 " vs %" PRIu32 ")",
                len,
                channel->local_window);"""
new = """    /* REPRO HOOK: pretend our local window diverged below this packet, for the
     * first DROP_FIRST packets of at least DROP_MIN_LEN bytes. The discard
     * below is then real -- the payload is freed and never delivered.
     * DROP_WINDOW is the fake window (0 = nothing fits, the default). */
    uint32_t effective_window = channel->local_window;
    static int clamp_fix = -1;
    {
        static int drop_left = -1;
        static uint32_t drop_min_len = 0, drop_window = 0;
        if (drop_left == -1) {
            const char *df = getenv("LIBSSH_REPRO_DROP_FIRST");
            const char *ml = getenv("LIBSSH_REPRO_DROP_MIN_LEN");
            const char *dw = getenv("LIBSSH_REPRO_DROP_WINDOW");
            drop_left = (df && *df) ? (int)strtol(df, NULL, 10) : 0;
            drop_min_len = (ml && *ml) ? (uint32_t)strtoul(ml, NULL, 10) : 0;
            drop_window = (dw && *dw) ? (uint32_t)strtoul(dw, NULL, 10) : 0;
        }
        if (clamp_fix == -1)
            clamp_fix = getenv("LIBSSH_CLAMP_FIX") != NULL;
        if (drop_left > 0 && len >= drop_min_len) {
            drop_left--;
            effective_window = drop_window;
        }
    }
    /* CANDIDATE FIX (LIBSSH_CLAMP_FIX=1): RFC 4254 5.2 permits ignoring "all
     * extra data sent after the allowed window is empty" -- the EXTRA data.
     * Deliver what fits, drop only the excess, and record no error, because
     * this is sanctioned behaviour rather than a fault. Clamping len here makes
     * the stock test below false, so we fall through to the normal bufferize
     * path. Stock libssh frees the whole payload and sets SSH_FATAL instead. */
    if (len > effective_window && clamp_fix) {
        SSH_LOG(SSH_LOG_RARE,
                "Data packet exceeds our window (%" PRIu32 " vs %" PRIu32
                "), delivering what fits and ignoring the rest",
                len,
                effective_window);
        len = effective_window;
        if (len == 0) {
            SSH_STRING_FREE(str);
            return SSH_PACKET_USED;
        }
    }
    if (len > effective_window) {
        SSH_LOG(SSH_LOG_RARE,
                "Data packet too big for our window(%" PRIu32 " vs %" PRIu32 ")",
                len,
                effective_window);"""
if old not in s:
    sys.exit("channels.c does not match the expected source; hook not applied")
open(p, "w").write(s.replace(old, new, 1))
print("  hook applied")
PY
[ $? -eq 0 ] || die "could not patch channels.c"

# ---------------------------------------------------------------- 3. build wiring
say "Pointing deps/libssh at the local copy"
python3 - <<'PY'
import re
p = 'deps/libssh/build.zig.zon'
s = open(p).read()
s = re.sub(r'\.libssh_upstream = \.\{.*?\},',
           '.libssh_upstream = .{\n            .path = "libssh-local",\n        },',
           s, count=1, flags=re.S)
open(p, 'w').write(s)

# Older libssh checkouts carry src/alloc.c, which some wrappers do not list;
# without it the link fails on libssh_calloc and friends.
import os
if os.path.exists('deps/libssh/libssh-local/src/alloc.c'):
    b = open('deps/libssh/build.zig').read()
    if '"src/alloc.c"' not in b:
        b = b.replace('        "src/agent.c",', '        "src/alloc.c",\n        "src/agent.c",', 1)
        open('deps/libssh/build.zig', 'w').write(b)
        print("  added src/alloc.c to the wrapper source list")
PY
[ $? -eq 0 ] || die "could not point deps/libssh at the local copy"

# ---------------------------------------------------------------- 4. run
# The storm server writes its hello in 1024 B chunks; its client writes a 174 B
# hello. A 1000 B threshold therefore targets only the server->client stream.
# LIBSSH_REPRO_DROP_WINDOW is the fake window for the chosen packet: 0 means
# nothing fits, 500 means a 1024 B packet overruns by 524 -- which is where the
# clamp fix differs from the stock discard.
export LIBSSH_REPRO_DROP_FIRST=1
export LIBSSH_REPRO_DROP_MIN_LEN=1000
export LIBSSH_REPRO_DROP_WINDOW="${LIBSSH_REPRO_DROP_WINDOW:-0}"
export ACTON_SSH_STORM_NUM=1

buildlog=$("$ACTON" build 2>&1)
if [ $? -ne 0 ]; then
    echo "$buildlog" | grep -iE "error" | head -5
    die "build failed -- results would be meaningless"
fi

run_mode() {
    local label="$1"
    say "$label -- $REPEATS runs"
    local corrupt=0 blocked=0 other=0 sample=""
    for _ in $(seq 1 "$REPEATS"); do
        out=$("$ACTON" test --no-cache --show-log --module test_ssh_hello_storm \
                  --max-time 60000 --min-iter 1 --max-iter 1 2>&1)
        if grep -q "corrupt hello" <<<"$out"; then
            corrupt=$((corrupt+1))
            [ -z "$sample" ] && sample=$(grep -m1 "corrupt hello" <<<"$out")
        elif grep -qE "Exception|errored" <<<"$out"; then
            blocked=$((blocked+1))
        else
            other=$((other+1))
        fi
    done
    printf '  corrupt data reached the application : %d/%d\n' "$corrupt" "$REPEATS"
    printf '  session failed first (no bad data)   : %d/%d\n' "$blocked" "$REPEATS"
    [ "$other" -gt 0 ] && printf '  test passed (drop missed the stream) : %d/%d\n' "$other" "$REPEATS"
    [ -n "$sample" ] && printf '  sample:%s\n' "${sample#*Exception:}"
}

echo
echo "  fake window for the dropped packet: $LIBSSH_REPRO_DROP_WINDOW bytes (packet is 1024)"

unset LIBSSH_CLAMP_FIX
run_mode "STOCK libssh (drops the whole packet, sets SSH_FATAL)"

export LIBSSH_CLAMP_FIX=1
run_mode "CLAMP PATCH (delivers what fits, records no error)"

say "Done"
