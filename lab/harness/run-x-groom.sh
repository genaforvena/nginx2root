#!/bin/sh
# Stage-A-mechanics GROOMING runner (owner directive #47 + standing
# approval item 1, SYNTHETIC/mechanics-only label): same forced-ledger
# sequence as run-x-mechanics.sh, but the probe (xgroom.py) sprays the
# canary corpus via stream 1 so the victims window past the 16 KiB SSL
# buffer holds identifiable sprayed victims. The stock-glibc wall stands
# unwalled; no rung-4 claim on any stock build may come out of this
# harness. Writes its own logs (x-groom-*) so mechanics/survey/plain
# logs stay untouched.
# Usage: lab/harness/run-x-groom.sh [build]      (default 1.31.8-plain)
set -u
BUILD="${1:-1.31.8-plain}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
SHIM_SRC="$ROOT/lab/harness/storefirst-memcpy.c"
SHIM_SO="$ROOT/lab/tmp/storefirst-memcpy.so"
CANARY="$ROOT/lab/corpus/canary"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

if [ ! -x "$SHIM_SO" ] || [ "$SHIM_SRC" -nt "$SHIM_SO" ]; then
    echo "building $SHIM_SO" >&2
    cc -O0 -g -shared -fPIC -o "$SHIM_SO" "$SHIM_SRC" -ldl || exit 1
fi
if [ ! -f "$CANARY" ]; then
    echo "generating $CANARY" >&2
    python3 "$ROOT/lab/harness/xgroom-verify.py" --make-canary "$CANARY" \
        || exit 1
fi

rm -f "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/gdb-x-groom-$BUILD.log" \
      "$ROOT/lab/tmp/x-groom-$BUILD.log" \
      "$ROOT/lab/tmp/x-groom-pre-follow.bin" \
      "$ROOT/lab/tmp/x-groom-pre-src.bin" \
      "$ROOT/lab/tmp/x-groom-post-follow.bin" \
      "$ROOT/lab/tmp/x-groom-ovw-dst.bin" \
      "$ROOT/lab/tmp/x-groom-ovw-src.bin"

if nc -z 127.0.0.1 8443 2>/dev/null; then
    echo "port 8443 is already in use; kill the stale worker first" >&2
    exit 1
fi

GDB_PID=""
cleanup() {
    if [ -s "$ROOT/lab/logs/nginx.pid" ]; then
        kill "$(cat "$ROOT/lab/logs/nginx.pid")" 2>/dev/null || true
    fi
    sleep 1
    if [ -n "$GDB_PID" ]; then
        kill "$GDB_PID" 2>/dev/null || true
        wait "$GDB_PID" 2>/dev/null || true
    fi
    if [ -f "$ROOT/lab/logs/error.log" ]; then
        cp "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/x-groom-$BUILD.log"
    fi
}
trap cleanup EXIT INT TERM

gdb -batch -x "$ROOT/lab/harness/gdb-x-groom.cmd" \
    --args "$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2.conf \
    >"$ROOT/lab/tmp/gdb-x-groom-$BUILD.log" 2>&1 &
GDB_PID=$!

# wait for the listener (worker binds it after the fork)
i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
        echo "nginx $BUILD under gdb did not start; gdb log follows" >&2
        cat "$ROOT/lab/tmp/gdb-x-groom-$BUILD.log" >&2
        exit 1
    fi
    sleep 0.2
done

python3 "$ROOT/lab/harness/xgroom.py" "$BUILD"
status=$?

# give the worker/gdb a moment to flush the log tail, then verify offline
sleep 2
grep -c "SIGSEGV" "$ROOT/lab/tmp/gdb-x-groom-$BUILD.log" || true
python3 "$ROOT/lab/harness/xgroom-verify.py" "$BUILD" || true

exit $status
