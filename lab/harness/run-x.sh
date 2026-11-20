#!/bin/sh
# Run the extreme-value consumer probe against one build, worker under gdb.
# Usage: lab/harness/run-x.sh 1.31.8
#
# Same launch pattern as run-wu.sh: nginx with daemon off, gdb follows the
# fork (yama ptrace_scope=1 forbids attaching to a non-child). The gdb script
# forces h2c->send_window = 2^63 + 2^32 at the client's mkX0ping marker.
set -u
BUILD="${1:?usage: run-x.sh 1.31.8}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"
rm -f "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/gdb-x-$BUILD.log" \
      "$ROOT/lab/tmp/x-$BUILD.log"

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
        cp "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/x-$BUILD.log"
    fi
}
trap cleanup EXIT INT TERM

gdb -batch -x "$ROOT/lab/harness/gdb-x.cmd" \
    --args "$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2.conf \
    >"$ROOT/lab/tmp/gdb-x-$BUILD.log" 2>&1 &
GDB_PID=$!

# wait for the listener (worker binds it after the fork)
i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
        echo "nginx $BUILD under gdb did not start; gdb log follows" >&2
        cat "$ROOT/lab/tmp/gdb-x-$BUILD.log" >&2
        exit 1
    fi
    sleep 0.2
done

python3 "$ROOT/lab/harness/xprobe.py" "$BUILD"
status=$?

# give the worker/gdb a moment to flush the log tail, then report
sleep 2
grep -c "ERROR: AddressSanitizer" "$ROOT/lab/logs/error.log" 2>/dev/null \
    || true

exit $status
