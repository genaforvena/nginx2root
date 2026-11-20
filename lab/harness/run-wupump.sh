#!/bin/sh
# Stage B wire-pure pump launcher (owner DM #59). Usage:
#   lab/harness/run-wupump.sh BUILD TOTAL_WUS TRIGGER(0|1) [MARKER] [CAP_S]
#
# Starts the build's worker with the NOTICE-level pump conf, runs
# wupump.py (progress JSONL -> lab/logs/wupump-<BUILD>.jsonl), tears the
# worker down, archives logs. Designed to run detached for hours-scale
# pumps:
#   setsid nohup sh lab/harness/run-wupump.sh 1.31.8 4294967300 1 \
#       >/dev/null 2>&1 &
# Kill the whole tree with:  kill -TERM -- -<runner_pid>   (setsid makes
# the runner its own process-group leader; its pid is in the .status file).
set -u
BUILD="${1:?usage: run-wupump.sh BUILD TOTAL_WUS TRIGGER [MARKER] [CAP_S]}"
TOTAL="${2:?total WUs}"
TRIGGER="${3:?0|1}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="$ROOT/lab/build/$BUILD"
mkdir -p "$ROOT/lab/logs" "$ROOT/lab/tmp"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0"

JSONL="$ROOT/lab/logs/wupump-$BUILD.jsonl"
STATUS="$ROOT/lab/logs/wupump-$BUILD.status"
STDERR="$ROOT/lab/tmp/wupump-stderr-$BUILD.log"
CLIENT_ERR="$ROOT/lab/tmp/wupump-client-$BUILD.err"
rm -f "$JSONL" "$STATUS" "$ROOT/lab/logs/pump-error.log" \
      "$STDERR" "$CLIENT_ERR" \
      "$ROOT/lab/tmp/wupump-error-$BUILD.log"

if nc -z 127.0.0.1 8443 2>/dev/null; then
    echo "port 8443 is already in use; kill the stale worker first" >&2
    exit 1
fi

"$PREFIX/sbin/nginx" -p "$ROOT/lab/" -c conf/nginx-h2-pump.conf \
    >"$STDERR" 2>&1 &
NGINX_PID=$!

cleanup() {
    kill "$NGINX_PID" 2>/dev/null || true
}
trap cleanup INT TERM

printf '%s RUNNING build=%s total=%s trigger=%s start=%s runner_pid=%s nginx_pid=%s\n' \
    "$(date -u +%FT%TZ)" "$BUILD" "$TOTAL" "$TRIGGER" \
    "$(date -u +%s)" "$$" "$NGINX_PID" >"$STATUS"

i=0
while ! nc -z 127.0.0.1 8443 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 150 ]; then
        echo "nginx $BUILD did not start; stderr follows" >&2
        cat "$STDERR" >&2
        printf '%s FAILED nginx-start\n' "$(date -u +%FT%TZ)" >>"$STATUS"
        cleanup
        exit 1
    fi
    sleep 0.2
done

python3 "$ROOT/lab/harness/wupump.py" "$TOTAL" "$TRIGGER" "${4:-}" "${5:-}" \
    >"$JSONL" 2>"$CLIENT_ERR"
RC=$?

cleanup
wait "$NGINX_PID" 2>/dev/null || true
sleep 1
if [ -f "$ROOT/lab/logs/pump-error.log" ]; then
    cp "$ROOT/lab/logs/pump-error.log" \
       "$ROOT/lab/tmp/wupump-error-$BUILD.log"
fi
printf '%s DONE rc=%s\n' "$(date -u +%FT%TZ)" "$RC" >>"$STATUS"
exit $RC
