#!/bin/sh
# Run the accounting probe against one build (1.31.8 or 1.31.9).
# Usage: lab/harness/run-probe.sh 1.31.8
set -e
BUILD="${1:?usage: run-probe.sh 1.31.8|1.31.9}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
mkdir -p "$ROOT/lab/tmp" "$ROOT/lab/logs"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"
rm -f "$ROOT/lab/logs/error.log"
"$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2.conf \
    >/dev/null 2>&1 &
NGINX_PID=$!
# wait for the listener
i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "nginx $BUILD did not start; error log follows" >&2
        cat "$ROOT/lab/logs/error.log" >&2 || true
        kill "$NGINX_PID" 2>/dev/null || true
        exit 1
    fi
    sleep 0.1
done

python3 "$ROOT/lab/harness/h2probe.py" "$BUILD"
status=$?

kill "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null || true
cp "$ROOT/lab/logs/error.log" "$ROOT/lab/tmp/probe-$BUILD.log"
exit $status
