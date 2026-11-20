# NGINX2Root / CVE-2026-123007 — nginx HTTP/2 flow-control investigation

Status: **suspected vulnerability, with the flow-control accounting violation
now OBSERVED at runtime** (see "Observed over-credit" below). No crash and no
memory corruption yet — ladder rungs 3-4 remain unfounded. Every claim below
is either cited to `file:line` in the extracted 1.31.8 tree, backed by
observed worker bytes (log lines / gdb memory reads), or marked UNKNOWN.

## Scope and method

Reproduce, in a loopback-only lab, the memory-safety failure behind
CVE-2026-123007 (NGINX2Root's claimed HTTP/2 flow-control integer underflow in
`ngx_http_v2_module`), by diffing the affected release against the fixed one,
building both with ASan/UBSan, and driving the claimed frame sequence with our
own client against 127.0.0.1 only. Nothing here probes off-loopback.

## Builds (reproducible)

Both built 2026-11-20 from the checksum-pinned trees provisioned by the
committed `lab/provision.sh` (tarball sha256 recorded in the wall of 2026-11-20):

```
cd lab/nginx-src/nginx-1.31.8 && ./configure \
  --with-http_v2_module --with-http_ssl_module --with-debug \
  --prefix=$PWD/../../build/1.31.8 \
  --with-cc-opt='-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer' \
  --with-ld-opt='-fsanitize=address,undefined' && make -j$(nproc) && make install
```

- `lab/build/1.31.8/` — affected. `sbin/nginx -V`: nginx/1.31.8, gcc 13.3.0,
  OpenSSL 3.0.13, ASan+UBSan, `--with-debug`.
- `lab/build/1.31.9/` — patched control, same flags.

## The patch (1.31.8 → 1.31.9), complete hunk inventory

`diff -ru lab/nginx-src/nginx-1.31.8/src/http/v2/ lab/nginx-src/nginx-1.31.9/src/http/v2/`
confirms the fix is confined to three files; nothing outside `src/http/v2/`
changes:

1. `ngx_http_v2.h` — new connection field `size_t send_queued`; the frame-queue
   helper is split into `ngx_http_v2_queue_position(h2c, stream)` (find the
   stream's insertion slot once) and `ngx_http_v2_queue_frame(out, frame)`
   (insert at that slot), with the comment "all frames of a stream are queued
   at the same position".
2. `ngx_http_v2.c`
   - connection-level WINDOW_UPDATE guard becomes
     `window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window - h2c->send_queued`
     (was `... - h2c->send_window`), i.e. the guard now counts window committed
     to queued-but-unsent DATA frames.
   - SETTINGS ACK check `state.flags == NGX_HTTP_V2_ACK_FLAG` becomes
     `state.flags & NGX_HTTP_V2_ACK_FLAG`.
   - `ngx_http_v2_create_stream` gains `ngx_reusable_connection(h2c->connection, 0)`.
3. `ngx_http_v2_filter_module.c`
   - DATA frames queued in `ngx_http_v2_send_chain` now charge BOTH ledgers:
     `h2c->send_window -= frame_size;` (pre-existing) plus new
     `h2c->send_queued += frame_size;`; trailers get `trailers->blocked = 0`;
     the per-stream insertion slot `fn` is computed once before the loop.
   - `ngx_http_v2_data_frame_handler` (send completion) gains
     `h2c->send_queued -= frame->length;`.
   - `ngx_http_v2_filter_cleanup` (stream cancellation) now refunds only
     frames whose `handler == ngx_http_v2_data_frame_handler` (was: every
     frame of the stream), and mirrors the refund into
     `h2c->send_queued -= window`.

Cross-check against upstream nginx commit
`b89c4100bf6762a45e4a6463eaf4b70368277c94`: NOT DONE (commit not at a ref
tip on the GitHub mirror; the tag diff above is the working evidence).
UNKNOWN whether the tag diff is byte-identical to that commit.

## Fault sites in 1.31.8 (the affected tree), with evidence

| # | Site | 1.31.8 `file:line` | What it does |
|---|------|--------------------|--------------|
| 1 | connection WINDOW_UPDATE guard | `ngx_http_v2.c:2564` | `window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window` — unsigned `size_t` arithmetic, ignores window already committed to queued-unsent DATA |
| 2 | guard passes → credit | `ngx_http_v2.c:2575` | `h2c->send_window += window`, unbounded above `MAX_WINDOW` only by the guard |
| 3 | queue-time charge | `ngx_http_v2_filter_module.c:1241` | `h2c->send_window -= frame_size` at QUEUE time (not send time) |
| 4 | queue-time limit | `ngx_http_v2_filter_module.c:1144-1150` | `limit = min(h2c->send_window, stream->send_window)` bounds how much DATA may be queued |
| 5 | refund loop | `ngx_http_v2_filter_module.c:1723-1743` | unlinks every unsent unblocked frame of the cancelled stream, adds `frame->length` |
| 6 | unguarded refund credit | `ngx_http_v2_filter_module.c:1767` | `h2c->send_window += window` — no upper bound, bypasses site 1 |
| 7 | refund skip condition | `ngx_http_v2_filter_module.c:1730` | `frame->stream == stream && !frame->blocked` — blocked frames never refunded |
| 8 | constants | `ngx_http_v2.h:50-51` | `MAX_WINDOW = (1U<<31)-1`, `DEFAULT_WINDOW = 65535`; connection `send_window` is `size_t` (h:137), stream `send_window` is `ssize_t` (h:193) |

Supporting facts pinned while reading:

- Headers frames are created `blocked = 1` (`filter:864`), queued via
  `queue_blocked_frame` (`filter:633`) — so they are never refunded at site 5.
- Trailers are built by `create_headers_frame` (`filter:1058`) — also
  `blocked = 1` in 1.31.8; hence not refunded either.
- DATA frames are created `blocked = 0` (`filter:1401`), and a frame whose
  send was attempted-but-incomplete gets `blocked = 1` from
  `ngx_http_v2.c:578` and returns `NGX_AGAIN` without touching `frame->length`
  (`filter:1594-1605`) — partially-sent frames are therefore NOT refunded.
- `frame->length = len` is set unconditionally for fresh and recycled DATA
  frames (`filter:1400`), and the charge uses the same value — so a DATA
  refund is exactly 1:1 with its charge.
- `NGX_HTTP_V2_MAX_WINDOW` is an **unsigned int** constant; the 1.31.8
  connection guard computes in 64-bit `size_t` on this build (no 32-bit
  truncation), but the expression still wraps to a huge value if
  `h2c->send_window > 2^31-1`.

## Causal analysis — what the paper evidence supports

**Confirmed on paper (1.31.8):** the connection-window guard at site 1 only
bounds `h2c->send_window`, but queue-time charging (site 3) means the true
protocol window `P = h2c->send_window + Q` where `Q` is DATA committed to
queued-unsent frames. The guard lets the client drive `P` past the RFC 7540
§6.9.1 ceiling `2^31-1` (bounded: `Q ≤ MAX_WINDOW`, so `P ≤ 2^32-2`). The
1.31.9 guard (`- h2c->send_queued`) closes exactly this hole. This is the
`--safe`-oracle-visible accounting violation and is the first experiment's
detector: over-credit `h2c->send_window + Q > 2^31-1` while the connection
window's bookkeeping stays "legal".

**Refuted on paper (as far as static reading goes):** NGINX2Root's claimed
mechanism — "repeated cancellations refund `send_window` past 0x7fffffff, so
the guard `MAX_WINDOW - send_window` underflows and a WINDOW_UPDATE
over-credits the connection" — does **not** hold via the sites it names:

- the only unguarded credit (site 6) refunds DATA frames 1:1 against their
  queue-time charges (see pinned facts above);
- all non-DATA frames of the stream are `blocked = 1` in 1.31.8 and skipped
  by the refund loop (site 7), so "uncharged headers/trailers refunds" do
  not exist either;
- therefore no static path was found by which `h2c->send_window` itself
  exceeds `NGX_HTTP_V2_MAX_WINDOW`, and without that the 1.31.8 guard does
  not underflow.

This refutation is a claim about *my reading*, not about the binary: the next
rung must measure the actual accounting (instrument the worker or read the
debug log) before any stronger conclusion. A synthetic tree may also differ
from upstream intent; runtime behavior is the arbiter. Failed hypotheses stay
recorded here per the evidence discipline.

**Open questions (UNKNOWN, each with a planned observation):**

1. Does the cancellation route reach site 5 at all with unblocked unsent DATA
   (RST_STREAM mid-response), and does the refund really stay 1:1 in the
   running worker? → instrumented run of the cancellation sequence (next
   wake).
2. Is there a second credit path outside `src/http/v2/` that can inflate
   `h2c->send_window` (e.g. via `ngx_http_v2_adjust_windows`, `ngx_http_v2.c:5043`,
   which currently looks stream-only and sign-safe)? → grep for all writers
   done; the ladder will re-check at runtime with a watchpoint.
3. The queue-ordering change (`queue_position` refactor): 1.31.8's
   `ngx_http_v2_stream_precedes` returns true for a stream compared with
   itself (`id <= id`, `ngx_http_v2.h:260`), so per-frame re-scanning seems to
   place successive same-stream frames at the same slot — the on-wire order
   within one `send_chain` call needs observing (`ngx_http_v2.c:538` debug
   line) before trusting my reading of it either way.
4. Where, if anywhere, does an over-credited window become a memory-safety
   fault (allocation sized by a window, or a size_t wrap consumed by a
   length)? Nothing found on paper in `src/http/v2/`; this is the gap between
   "accounting violation" and "memory corruption", and it is the difference
   between rung 2 and rung 4. Do not upgrade the ladder without ASan bytes.

## Observed over-credit (wake 4, 2026-11-20 — rung-2 evidence)

Harness (all committed under `lab/`): `lab/conf/nginx-h2.conf` (one worker,
`listen 127.0.0.1:8443 ssl; http2 on;`, debug log), `lab/harness/h2probe.py`
(hand-rolled HTTP/2 client, binds 127.0.0.1 only), `lab/harness/run-probe.sh`
(start one build, run the probe, rotate the log to `lab/tmp/probe-<v>.log`).

Reproduce: `lab/harness/run-probe.sh 1.31.8` and `lab/harness/run-probe.sh
1.31.9`. Probe shape: SETTINGS with stream window `2^31-1`; connection WU
`2^31-1 - 65535` (→ `send_window = MAX`); GET `/blob` (64 MiB); after the
first burst blocks the socket, open 100 fresh GET streams (each new
`send_chain` charges one 32 KiB chunk at queue time and its flush fails on
the full socket); then one connection WU of 2,621,440 bytes.

**Observed, 1.31.8 (affected), 3 runs, deterministic:** the WU is accepted
and the connection keeps streaming. Worker memory read via gdb at the credit
site (`break ngx_http_v2.c:2575`, worker launched under gdb; log excerpt
`lab/tmp/gdb-wu.log`):

```
CONNWU window=2147418112 send_window(pre)=65535 queued_data=0 post_true=2147483647
CONNWU window=2621440 send_window(pre)=2139095039 queued_data=6594560 post_true=2148311039
```

`post_true = send_window + queued DATA` = 2,148,311,039 > NGX_HTTP_V2_MAX_WINDOW
(2,147,483,647) by 827,392 bytes: the true protocol window is over-committed
past the RFC ceiling while the worker's own guard saw only
`send_window = 2,139,095,039` and its bookkeeping stayed "legal".

**Observed, 1.31.9 (control), 3 runs:** the identical WU is rejected —
`probe-1.31.9.log`: "client violated connection flow control: received
WINDOW_UPDATE frame with window increment 2621440 not allowed for window
2145689599" (that value is `send_window + send_queued` per the .9 guard,
`v2.c:2564/2570`: 2,139,095,039 + 6,594,560) — followed by
GOAWAY(FLOW_CONTROL_ERROR) and connection close. The client-side
differential (`over_credit_accepted` in the probe JSON): 1.31.8 `true`
(no GOAWAY, no EOF, 16.7 MB more DATA streamed), 1.31.9 `false`
(`conn_eof: true`, worker closed without flushing the queued GOAWAY).
The control's `send_queued` (6,594,560) is byte-identical to the queue
the gdb read summed in the 1.31.8 worker — cross-validated.

### Falsified models (preserved per evidence discipline)

Three paper models died in this wake's runs; each is recorded with the
observation that killed it:

1. **"The whole 64 MiB queues in one `send_chain` call"** — FALSE. Static
   file reads are capped at ~2 MiB per wake cycle ("http write filter limit
   2097152", `ngx_http_write_filter_module.c:297`); a single-shot
   64 MB WU was correctly rejected with only 1,966,080 bytes charged
   (`probe-1.31.8.log`, first probe run).
2. **"Accepted connection WUs pump more file into the queue"** — FALSE. The
   stream is socket-blocked, not flow-control-blocked, so it is not in
   `h2c->waiting` and the WU wake loop (`v2.c:2577-2598`) never re-runs it.
   Observed: pump1 (1.8 MB) accepted, pump2 rejected with headroom reduced to
   exactly the pump size.
3. **"Single-stream suffices"** — the working shape is NGINX2Root's
   multi-stream one: each NEW stream runs its own `send_chain` and charges
   one 32 KiB chunk before its flush fails on the full socket; 100 streams
   built 8,388,608 bytes charged / 6,594,560 queued-unsent.

Environment facts measured on this host: a loopback socket absorbs
~1.79 MB unread before blocking (measured: 1,792,000 bytes with
SO_RCVBUF=8192; server sndbuf autotunes to 2.6 MB and the advertised client
window is not enforced on this host's loopback). UBSan emits pre-existing
benign misaligned-store reports in nginx's frame serialization
(`v2.c:2837-2904`, `v2.c:892-897`) — not CVE-related, non-fatal.

What this does NOT show: `h2c->send_window` itself never exceeded MAX in any
run (max observed 2,147,483,647 after W1, 2,141,716,479 after the final WU),
so the 1.31.8 guard never underflowed — the original NGINX2Root refund
narrative stays refuted. No crash, no ASan report, no corruption: the ladder
does not move past rung 1 + the observed accounting violation.

## Reproduction plan (rungs, in order)

1. **Accounting probe — DONE, see "Observed over-credit".** The committed
   harness reproduces it from a clean checkout (plus `openssl req` and one
   `dd` for the gitignored cert/corpus, see `lab/provision.sh` comments).
2. **Cancellation refund measurement (NEXT):** same harness, RST_STREAM
   mid-flight on a stream with queued-unsent DATA; log every
   `h2c->send_window += window` (site 6) with before/after; verify the 1:1
   refund or find the divergence the paper analysis missed.
3. **Corruption attempt (rung 3):** with the over-credit now observed, hunt
   the consumer that turns an over-committed window into a memory fault
   (allocation or length sized by window arithmetic) and drive it under
   ASan; nothing found on paper yet, so this may end in a honest negative.
4. **Control:** DONE as part of 1 — 1.31.9 rejects every attempt at the
   guard (`v2.c:2564/2565`).

## Evidence ledger

| Ladder rung | Status | Evidence |
|---|---|---|
| Suspected vulnerability | YES | patch diff + fault sites above |
| Accounting violation observed (protocol window over-committed past 2^31-1) | YES | gdb memory read: post-credit `send_window + queued` = 2,148,311,039 > MAX; .9 rejects the same WU at 2,145,689,599 (`send_window + send_queued`) |
| Reproducible crash | NO | no fault in any run; worker stayed healthy through 3 runs/build |
| Confirmed memory corruption | NO | — |
| Demonstrated security impact | NO | — |

Negative results preserved: toolchain smoke (previous wake), the refutation of
the refund-inflation narrative above, the three falsified queueing models in
"Falsified models", and the un-verified upstream-commit cross-check.
