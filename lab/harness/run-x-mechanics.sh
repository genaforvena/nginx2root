#!/bin/sh
# Stage-A-mechanics runner (owner directive #47, SYNTHETIC/mechanics-only
# label): same probe sequence as run-x-survey.sh, but the worker is run
# with LD_PRELOAD pointing at a store-first memcpy so the wrapped 2^63
# copy executes a naive forward byte loop instead of stock glibc's
# tail-load-first path. The stock-glibc wall stands unwalled; no rung-4
# claim on any stock build may come out of this harness.
# Writes its own logs (x-mechanics-*) so survey/plain logs stay untouched.
# Usage: lab/harness/run-x-mechanics.sh [build]      (default 1.31.8-plain)
set -u
BUILD="${1:-1.31.8-plain}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
SHIM_SRC="$ROOT/lab/harness/storefirst-memcpy.c"
SHIM_SO="$ROOT/lab/tmp/storefirst-memcpy.so"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

if [ ! -x "$SHIM_SO" ] || [ "$SHIM_SRC" -nt "$SHIM_SO" ]; then
    echo "building $SHIM_SO" >&2
    cc -O0 -g -shared -fPIC -o "$SHIM_SO" "$SHIM_SRC" -ldl || exit 1
fi

rm -f "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/gdb-x-mechanics-$BUILD.log" \
      "$ROOT/lab/tmp/x-mechanics-$BUILD.log" \
      "$ROOT/lab/tmp/x-mechanics-pre-follow.bin" \
      "$ROOT/lab/tmp/x-mechanics-pre-src.bin" \
      "$ROOT/lab/tmp/x-mechanics-post-follow.bin" \
      "$ROOT/lab/tmp/x-mechanics-post-src.bin" \
      "$ROOT/lab/tmp/x-mechanics-ovw-dst.bin" \
      "$ROOT/lab/tmp/x-mechanics-ovw-src.bin"

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
        cp "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/x-mechanics-$BUILD.log"
    fi
}
trap cleanup EXIT INT TERM

gdb -batch -x "$ROOT/lab/harness/gdb-x-mechanics.cmd" \
    --args "$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2.conf \
    >"$ROOT/lab/tmp/gdb-x-mechanics-$BUILD.log" 2>&1 &
GDB_PID=$!

# wait for the listener (worker binds it after the fork)
i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
        echo "nginx $BUILD under gdb did not start; gdb log follows" >&2
        cat "$ROOT/lab/tmp/gdb-x-mechanics-$BUILD.log" >&2
        exit 1
    fi
    sleep 0.2
done

python3 "$ROOT/lab/harness/xprobe.py" "$BUILD"
status=$?

# give the worker/gdb a moment to flush the log tail, then report
sleep 2
grep -c "SIGSEGV" "$ROOT/lab/tmp/gdb-x-mechanics-$BUILD.log" || true

exit $status
