#!/bin/sh
# Extreme-value consumer probe against an UNSANITIZED build (no ASan/UBSan):
# same client sequence and same gdb force at mkX0ping as run-x.sh, but the
# wrapped ~2^63 memcpy executes for real in glibc -> worker SIGSEGV (rung 3,
# no-sanitizer control). The gdb log gains a full backtrace at the stop.
# Usage: lab/harness/run-x-plain.sh [build]      (default 1.31.8-plain)
#
# Build first (same pinned tree, configure minus the sanitizer flags):
#   cd lab/nginx-src/nginx-1.31.8 && ./configure \
#     --with-http_v2_module --with-http_ssl_module --with-debug \
#     --prefix=$PWD/../../build/1.31.8-plain \
#     --with-cc-opt='-g -O1 -fno-omit-frame-pointer' \
#     && make -j$(nproc) && make install
set -u
BUILD="${1:-1.31.8-plain}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

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

gdb -batch -x "$ROOT/lab/harness/gdb-x-plain.cmd" \
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
grep -c "SIGSEGV" "$ROOT/lab/tmp/gdb-x-$BUILD.log" || true

exit $status
