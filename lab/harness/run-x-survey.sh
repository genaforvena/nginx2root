#!/bin/sh
# Stage-A survey runner: same probe sequence as run-x-plain.sh, but the gdb
# script additionally records the heap layout after the 16 KiB SSL send buffer
# at the wrapped memcpy and the SIGSEGV fault geometry (see gdb-x-survey.cmd).
# Writes its own logs (x-survey-*) so the preserved rung-3 logs are untouched.
# Usage: lab/harness/run-x-survey.sh [build]      (default 1.31.8-plain)
set -u
BUILD="${1:-1.31.8-plain}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

rm -f "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/gdb-x-survey-$BUILD.log" \
      "$ROOT/lab/tmp/x-survey-$BUILD.log" \
      "$ROOT/lab/tmp/x-survey-pre-follow.bin" \
      "$ROOT/lab/tmp/x-survey-pre-src.bin" \
      "$ROOT/lab/tmp/x-survey-post-follow.bin"

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
        cp "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/x-survey-$BUILD.log"
    fi
}
trap cleanup EXIT INT TERM

gdb -batch -x "$ROOT/lab/harness/gdb-x-survey.cmd" \
    --args "$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2.conf \
    >"$ROOT/lab/tmp/gdb-x-survey-$BUILD.log" 2>&1 &
GDB_PID=$!

# wait for the listener (worker binds it after the fork)
i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
        echo "nginx $BUILD under gdb did not start; gdb log follows" >&2
        cat "$ROOT/lab/tmp/gdb-x-survey-$BUILD.log" >&2
        exit 1
    fi
    sleep 0.2
done

python3 "$ROOT/lab/harness/xprobe.py" "$BUILD"
status=$?

# give the worker/gdb a moment to flush the log tail, then report
sleep 2
grep -c "SIGSEGV" "$ROOT/lab/tmp/gdb-x-survey-$BUILD.log" || true

exit $status
