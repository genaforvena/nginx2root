# NGINX2Root / CVE-2026-123007 — nginx HTTP/2 flow-control investigation

Status: **suspected vulnerability** (evidence ladder rung 1 of 4). No trigger has
been run yet. This report records the patch-level (paper) analysis, the builds,
and the exact next experiment; every claim below is either cited to
`file:line` in the extracted 1.31.8 tree, or explicitly marked UNKNOWN.

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

## Reproduction plan (rungs, in order)

1. **Accounting probe (rung 1→2):** loopback TLS + h2 instance of
   `lab/build/1.31.8`, one worker, debug log; client opens a stream for a
   multi-MiB static file, exhausts the stream window so DATA accumulates
   queued-unsent, keeps sending connection WINDOW_UPDATEs sized to pass the
   1.31.8 guard, and observes — via the worker debug log / a
   `send_queued`-equivalent instrumentation patch — whether the committed
   window exceeds `2^31-1`. Detector: our own accounting of
   `send_window + queued` mirrored from the debug log.
2. **Cancellation refund measurement:** same harness, RST_STREAM mid-flight;
   log every `h2c->send_window +=` (site 6) with before/after values; verify
   1:1 or find the divergence the paper analysis missed.
3. **Corruption attempt (rung 3):** only after 1-2 produce observed over-credit
   bytes, drive the sequence under ASan and let the detector speak.
4. **Control:** every positive re-run against `lab/build/1.31.9` must show the
   guard rejecting the increment (log line "client violated connection flow
   control", `ngx_http_v2.c:2565-2572`).

Harness details (cert, corpus, conf) will be committed under `lab/` as they
are built; the client binds 127.0.0.1 only.

## Evidence ledger

| Ladder rung | Status | Evidence |
|---|---|---|
| Suspected vulnerability | YES | patch diff + fault sites above |
| Reproducible crash | NO | nothing run yet |
| Confirmed memory corruption | NO | — |
| Demonstrated security impact | NO | — |

Negative results preserved: toolchain smoke (previous wake), the refutation of
the refund-inflation narrative above, and the un-verified upstream-commit
cross-check.
