# NGINX2Root / CVE-2026-123007 — nginx HTTP/2 flow-control investigation

Status: **rung 3 reached (debugger-assisted): the over-credited connection
window becomes a confirmed heap buffer overflow.** At
`h2c->send_window >= 2^63` the queue-time limit cast in
`ngx_http_v2_send_chain` goes negative, a DATA frame body is built from a
wrapped ~2^63-byte length, and the SSL send chain `memcpy`s `2^63 + 2^32`
bytes into a 16 KiB heap buffer — ASan report, worker abort (rung 3
below; independently reproduced by the witness from a clean checkout,
and on an unsanitized build the same probe makes the raw glibc memcpy
execute and SIGSEGV the worker). The ledger state feeding it is
wire-proven unbounded past MAX (rung 2.75: interleave double-credit, guard
underflow, patched build refuses the same sequence) and wire-pumped to
10,002,978,926,030 ≈ 4658x MAX with no debugger involvement; the final
jump from there to 2^63 was forced in gdb (~2^32 more max-WUs, ≈ 56 GB
of client traffic — the order of magnitude NGINX2Root claims for its
full `--exploit`). Every
claim is either cited to `file:line` in the extracted 1.31.8 tree, backed
by observed worker bytes (log lines / gdb memory reads), or marked
UNKNOWN.

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
- `lab/build/1.31.8-plain/` — affected, UNSANITIZED control for rung 3:
  same configure line minus the `-fsanitize` options (`-g -O1
  -fno-omit-frame-pointer`, `--with-debug`), built by the witness
  2026-11-20 from the same pinned tree; used by
  `lab/harness/run-x-plain.sh`.

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
`b89c4100bf6762a45e4a6463eaf4b70368277c94` (witness, 2026-11-20): the
commit IS reachable on github.com/nginx/nginx. All six of its added lines
match the 1.31.9 tag diff exactly, but the tag diff is a SUPERSET — it
also bundles the `ngx_http_v2_data_frame_handler` refund filter, the
SETTINGS ACK `&` check, `ngx_reusable_connection`, and the
`queue_position`/trailers refactor — so the tag diff is NOT
byte-identical to that commit. Upstream's commit message corroborates the
exact mechanism and consumer found here: a WINDOW_UPDATE arriving between
queue and terminate drives `send_window` past `MAX_WINDOW`, causing
"broken buffer size control in `ngx_http_v2_send_chain()` followed by
memory corruption and a possible segmentation fault".

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

**Partially refuted on paper, then CONFIRMED at runtime with the missing
ingredient (wake 6):** NGINX2Root's claimed mechanism — "repeated
cancellations refund `send_window` past 0x7fffffff, so the guard
`MAX_WINDOW - send_window` underflows and a WINDOW_UPDATE over-credits the
connection" — is right about the ledger state and the underflow, wrong about
the route:

- the only unguarded credit (site 6) refunds DATA frames 1:1 against their
  queue-time charges (confirmed at runtime, wake 5), and all non-DATA
  frames of the stream are `blocked = 1` in 1.31.8, skipped by the refund
  loop (site 7) — so neither repeated cancellation alone (wake 5: 81
  refunds, baseline-exact) nor phantom uncharged frames drive
  `send_window` past MAX;
- **but** a connection WU granted *between* a stream's queue-time charge
  and its cancellation re-fills the same bytes the refund later credits:
  the guard (site 1) evaluates the post-charge value, the refund (site 6)
  is unguarded, so each charge→WU→RST interleave nets +charge on the
  connection ledger. 33 interleaves drive `h2c->send_window` past
  `NGX_HTTP_V2_MAX_WINDOW` (observed MAX + 32,768), the guard expression
  underflows, and every further WU is accepted — see "WU-interleave
  double-credit and connection-window underflow". My wake-5 conclusion
  that no path drives `send_window` past MAX was FALSE; it assumed WUs
  never interleave with the charge/refund pair.

**Open questions (UNKNOWN, each with a planned observation):**

1. ~~Does the cancellation route reach site 5 at all with unblocked unsent
   DATA (RST_STREAM mid-response), and does the refund really stay 1:1 in
   the running worker?~~ **ANSWERED (wake 5):** yes it reaches the refund
   loop synchronously via the terminate-cleanup path, and the refund is
   byte-exactly 1:1 — see "Cancellation refund measurement".
2. Is there a second credit path outside `src/http/v2/` that can inflate
   `h2c->send_window` (e.g. via `ngx_http_v2_adjust_windows`, `ngx_http_v2.c:5043`,
   which currently looks stream-only and sign-safe)? → grep for all writers
   done; the ladder will re-check at runtime with a watchpoint.
   **DISPOSITIONED (2026-11-20, final):** not load-bearing — the
   demonstrated inflation route (wake 6's charge→WU→RST interleave) is
   entirely inside `src/http/v2/`, and the writer grep found no other
   credit site. The runtime watchpoint sweep was never run, so "no second
   path exists" remains UNVERIFIED; no claim in this report depends on it.
3. The queue-ordering change (`queue_position` refactor): 1.31.8's
   `ngx_http_v2_stream_precedes` returns true for a stream compared with
   itself (`id <= id`, `ngx_http_v2.h:260`), so per-frame re-scanning seems
   to place successive same-stream frames at the same slot — the on-wire order
   within one `send_chain` call needs observing (`ngx_http_v2.c:538` debug
   line) before trusting my reading of it either way.
   **DISPOSITIONED (2026-11-20, final): remains UNKNOWN and not
   load-bearing.** The preserved logs carry thousands of `http2 frame out`
   debug lines (`v2.c:537`), but same-stream body order cannot be read from
   them — equal frame lengths, opaque frame pointers — and no claim in this
   report depends on within-call frame order: the refund loop unlinks by
   stream membership, not queue position, and the rung-3 consumer is
   per-frame. Answering it would need a probe serving distinguishable
   per-chunk body content and a client that checks reassembly order.
4. Where, if anywhere, does an over-credited window become a memory-safety
   fault (allocation sized by a window, or a size_t wrap consumed by a
   length)? **ANSWERED (wake 7): at `h2c->send_window >= 2^63` exactly** —
   not an allocation and not a scaling effect, but a **cast boundary**: the
   `(off_t)` cast in the queue-time limit (`filter:1144`) goes negative,
   `frame_size = (size_t) limit` wraps (`filter:1165`), the DATA-frame
   body buf gets `last = pos + 2^63 + 2^32` (`get_shadow`, `filter:1308`),
   and the SSL send chain memcpy's the wrapped length into its 16 KiB
   buffer (`ngx_event_openssl.c:3137/3150`) — ASan-observed heap buffer
   overflow, worker abort. Below 2^63 the wake-6 negative holds unchanged:
   no allocation, length or index scales with the window value. See
   "Extreme-window consumer" (rung 3).

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
*(Snapshot of wake 4's runs only, superseded as a ladder statement: wake 6
later drove `send_window` past MAX and underflowed the guard — see
"WU-interleave double-credit".)*

## Cancellation refund measurement (wake 5, 2026-11-20 — rung 2.5 evidence)

Harness: `lab/harness/rstprobe.py` (client), `lab/harness/run-rst.sh
<build>` (starts the worker under gdb, `daemon off` + `follow-fork-mode
child`), `lab/harness/gdb-rst.cmd` (breakpoints at the connection-WU credit
`v2.c:2575`, PING-marker snapshots `state_ping`, the RST dispatch `v2.c:2184`,
`close_stream` entry `v2.c:4704`, the queue-time charge `filter:1241` and the
refund credit `filter:1767`).

Probe shape: same setup as the over-credit probe (SETTINGS stream window MAX,
connection WU W1, GET `/blob`), then 40 fresh GET streams on the blocked
socket, RST_STREAM(CANCEL) on all 40, a second identical round with 40 more
streams, and finally RST on stream 1 itself after ~43 MB have drained. PING
markers snapshot `h2c->send_window` at each phase boundary.

**Observed (2 runs, refund arithmetic byte-identical):**

1. **The refund site fires — synchronously, at RST processing time.** Call
   chain from the worker debug log: `state_rst_stream` sets `fc->error`
   (`v2.c:2182`) and invokes `fc->read->handler` (`v2.c:2204-2205`) →
   `ngx_http_request_handler` → `ngx_http_test_reading` → "client
   prematurely closed connection" → finalize 499 → `ngx_http_terminate_request`
   → the request cleanup handlers, including `ngx_http_v2_filter_cleanup`
   (`filter:1700`). A static hypothesis that `close_stream`'s
   queued-!=-0 postponement (`v2.c:4721`) would make the refund unreachable
   while socket-blocked was **falsified**: the refund runs via the terminate
   cleanup BEFORE `close_stream` even completes; `close_stream`'s entry
   breakpoint then shows `queued=1` (the stream's blocked HEADERS frame,
   created `blocked=1`, never refunded — consistent with the pinned facts
   above).
2. **The refund is exactly 1:1.** Each fresh stream charged 8 DATA frames ×
   8192 = 65,536 at queue time (CHARGE lines, `filter:1241`); each
   cancellation refunded exactly 65,536 (delta of consecutive REFUND/RST
   snapshots at `filter:1767`). Round 1: `send_window` 2,142,666,751 →
   2,145,288,191 across 40 RSTs — byte-exactly the pre-charge baseline
   (marker mk00 == post-RST marker, both runs). Round 2: identical. Stream 1,
   cancelled after ~43 MB had drained: refunded 32,768 = its 4 remaining
   queued-unsent 8K DATA charges. No refund in either run exceeded the sum of
   its stream's charges; `send_window` never exceeded its baseline, let alone
   `NGX_HTTP_V2_MAX_WINDOW`; the 1.31.8 guard never underflowed.

**Verdict:** NGINX2Root's narrative — "repeated cancellations refund
`send_window` past 0x7fffffff so the guard underflows and a WINDOW_UPDATE
over-credits the connection" — is refuted at runtime on 1.31.8, on top of
the static refutation: 81 cancellations across 2 runs (80 fresh streams +
the blob stream), every refund byte-exact against its queue-time charges.
Combined with wake 4 (the refund never inflated `send_window`, and the
observed over-credit is the queued-DATA shape the 1.31.9 guard closes), the
CVE's claimed mechanism has no observed support on either ledger: neither
the refund path nor the WU-guard path drives `h2c->send_window` past MAX.
*(Snapshot of wake 5's runs only, superseded as a verdict: the missing
ingredient was a connection WU interleaved between a stream's queue-time
charge and its RST, which wake-5 probes never sent — wake 6 confirmed the
ledger state NGINX2Root claims; see the causal-analysis correction and
"WU-interleave double-credit". The 1:1 refund observation itself stands.)*

Negative results preserved from this wake: my own postponement model
(refund unreachable while blocked) — falsified by the REFUND hits; probe bug
found and fixed (PING must be exactly 8 bytes; 4-byte markers drew
FRAME_SIZE_ERROR and a GOAWAY, `NGX_HTTP_V2_PING_SIZE`, `v2.c:34`); a runner
cleanup gap (a probe failure used to strand the worker holding port 8443,
invalidating one run — now a trap in `run-rst.sh`).

## WU-interleave double-credit and connection-window underflow (wake 6, 2026-11-20 — rung 2.75 evidence)

Harness: `lab/harness/wuprobe.py` (client), `lab/harness/run-wu.sh <build>
[soak]` (worker under gdb, same launch pattern as run-rst.sh),
`lab/harness/gdb-wu.cmd` (breakpoints: the connection-WU credit `v2.c:2575`,
PING-marker snapshots, the queue-time charge `filter:1241`, the refund credit
`filter:1767`).

**The mechanism (all numbers observed in worker bytes, 2 runs,
byte-identical).** One pump cycle sends HEADERS(stream n) + connection
WU(65536) + RST(n) in a single segment; the worker processes them in wire
order:

1. charge -65536 at queue time (`filter:1241`) — `R -> R - 65536`;
2. WU +65536 (`v2.c:2575`) — the guard at `v2.c:2564` evaluates the
   **post-charge** value, so it only enforces `R <= MAX`, never seeing the
   refund that follows;
3. refund +65536 (`filter:1767`, unguarded) — lands **on top of the WU
   refill**, `R_{n+1} = R_n + 65536` per cycle.

The refund is still 1:1 against its stream's charges (wake 5 holds); the
double-credit is on the **connection ledger**: the WU re-filled what the
charge took, and the refund credits it again. From baseline
`R_0 = MAX - 2,195,456` (the blob's queue-time charge, mkA0), 33 cycles
drive `R` to **mkB1 = 2,147,516,415 = MAX + 32,768**: `h2c->send_window`
above `NGX_HTTP_V2_MAX_WINDOW` — the ledger state NGINX2Root claims, now
observed (also visible in the worker's own `http2:71 windows: conn:2147516415`
debug line).

A cycle WU never sees `R > MAX` (it evaluates post-charge, and cycle 33's WU
at `MAX - 32768` is correctly rejected). The underflow needs a **standalone
WU arriving after the refund and before the next charge**, while
`R > MAX`:

```
CONNWU inc=65536 send_window(pre)=2147516415     <- pre > MAX: guard RHS wrapped
PINGMARK mkC1 = 2147581951                        = MAX + 98,304
CONNWU inc=2147483647 send_window(pre)=2147581951 <- a full 2^31-1 increment
PINGMARK mkC2 = 4295065598                        ≈ 2x MAX
```

With the guard expression `MAX - send_window` (64-bit `size_t`) wrapped,
every further WINDOW_UPDATE of any legal size is accepted: a soak run with 4
extra max-size WUs drove `send_window` to **12,885,000,186 ≈ 6x MAX**
(mkS9), after which the connection streamed 36.7 MB of the blob with no
GOAWAY, no EOF, all 8 PING markers answered, and **zero ASan/UBSan reports**
beyond the pre-existing benign misaligned-store noise. The client had pushed
cumulative accepted WU increments of ~12.9 GB through a 2^31-1 ceiling.

**Wake-9 extension (wire-only pump to 10^13):** the same harness with
`run-wu.sh 1.31.8 4656` — `wuprobe.py` phase C2a batches the WU sends,
frames byte-identical to phase C's — drove `send_window` to
**10,002,978,926,030 ≈ 1.0e13 ≈ 4658x MAX** — exactly
`4658 × MAX + 98,304`: mkC2 (2×MAX plus the 98,304 interleave residue
of `mkC1` above) plus 4656 max-WUs. Preserved log
`lab/tmp/gdb-wu-1.31.8-1e13.log`: `PINGMARK
send_window=10002978926030`; all 4693 CONNWU credits accepted;
independently reproduced author 1/1 + witness 1/1 (worker PIDs 566660
and 624758; the earlier "2/2" was one run under two byte-identical log
files — caught by the witness, duplicate removed). No debugger forcing
anywhere on this path: the
gdb breakpoints only observe. All 8 markers answered, no GOAWAY, the
worker exited normally under ASan, and the drain streamed 37 MB. The
remaining gap to the 2^63 cast threshold is ~2^32 further max-WUs
(≈ 4.3 billion, ~922,000x this run's pump, ≈ 56 GB of wire traffic),
so the 2^63 ledger of the rung-3 chain
remains debugger-forced — but the wire path to it is now exercised to
10^13, shrinking the debugger's role from "creates the ledger" to "skips
the last ~922,000x of pumping". Rung 3 is unchanged; rung 4 remains NO.
Measured pace of the preserved run: all 4693 credits fall inside the
worker log's 49-second span (`wu-1.31.8-1e13-author.log`, 05:41:31 →
05:42:20) — ≥ ~96 WU/s under gdb observation, so the remaining ~2^32-WU
stretch is over a year of grinding at that pace even before its ~56 GB of
wire traffic; the debugger's compression of that stretch is what makes the
2^63 ledger reachable in this lab at all.

**Control (1.31.9, identical probe):** the very first cycle WU is refused —
"client violated connection flow control: received WINDOW_UPDATE frame
with window increment 65536 not allowed for window 2147442687" (the value
is `send_window + send_queued` per the .9 guard, `v2.c:2564`), GOAWAY
(FLOW_CONTROL_ERROR), EOF, zero pongs. The patched guard closes the
interleave from the first cycle; the pump never starts.

**What this does and does not show.** Demonstrated (rung 2.75): a
deterministic client-only input sequence that (a) pushes the connection
send window past the RFC 7540 §6.9.1 ceiling, (b) underflows the 1.31.8
guard exactly as NGINX2Root claims, and (c) converts that into unbounded
window credit on the live connection, with the patched build refusing the
same sequence. NOT shown: any memory fault. The static consumer sweep this
wake found no allocation, length or index ever derived from a window value
(`limit` in `ngx_http_v2_send_chain` only slices real buffer extents via
`ngx_http_v2_filter_get_shadow`, `filter:1144-1260`; the grpc/proxy v2
modules keep their own separate ledgers; gating uses `== 0` / `> 0`
checks), and the ASan soak over the fully-inflated state stayed clean.
Rungs 3-4 remain unfounded; on this 64-bit ASan build the demonstrated
impact is a protocol-enforcement failure (unbounded over-credit), not
memory corruption.
*(Snapshot of wake 6 only, superseded as a ladder statement: wake 7 found
the exact consumer threshold at 2^63 — a cast boundary this static sweep's
"no consumer" conclusion missed below 2^63 — and observed the heap buffer
overflow; see "Extreme-window consumer". The soak negative below 2^63
stands.)*

**Wake-6 falsified models, preserved:**

1. **"Wake 5 closed the door: refunds are 1:1 so `send_window` can never
   exceed MAX"** — FALSE as a conclusion, TRUE as an observation: the refund
   is 1:1 against its own stream's charges, but a WU granted between the
   charge and the RST re-fills the same bytes first; the unguarded refund
   then double-credits the connection ledger. Wake 5's probe never
   interleaved a WU, so it could not see this.
2. **"The cycle WU will trigger the underflow once R crosses MAX"** —
   FALSE: the guard evaluates post-charge, at `R - 65536 <= MAX`; the first
   probe attempt pumped one cycle too far (34 cycles), the 34th cycle's WU
   was correctly rejected at `MAX - 32768`, and the connection died before
   the standalone underflow WU could be sent. The crossing cycle count is
   load-bearing: 33 cycles leave `R = MAX + 32768` for the standalone WU.
3. **"Any refund inflation would need a non-DATA frame in the refund loop"**
   — FALSE and unnecessary: server-sent WU/RST/GOAWAY frames queue blocked
   (`v2.c:2906/2933/2960`), HEADERS/TRAILERS are `blocked = 1`
   (`filter:864`), so only DATA frames are ever refunded in 1.31.8 — the
   double-credit needs the interleave, not a phantom uncharged frame.


## Extreme-window consumer: confirmed heap buffer overflow (wake 7, 2026-11-20 — rung 3, debugger-assisted)

Harness: `lab/harness/xprobe.py` (client), `lab/harness/run-x.sh 1.31.8`
(runner), `lab/harness/gdb-x.cmd` (breakpoints + the forced value).
Phases A-C are the wake-6 wuprobe sequence verbatim (pump to the wrapped
guard, `mkC2 = 4,295,065,598 ≈ 2x MAX`). Phase X: at the `mkX0ping` PING
marker, gdb FORCES `h2c->send_window = 2^63 + 2^32` =
9,223,372,041,149,743,104 — the ledger the wire path would reach after
~2^32 further standalone max-size WUs (13 bytes each, ≈ 56 GB of client
traffic; NGINX2Root claims ~119 GiB for its full `--exploit`, the same
order of magnitude — consistency, not proof). A fresh GET on stream 71
then runs `ngx_http_v2_send_chain` with that ledger. Debugger-assisted by
design and labeled so: the pump below MAX and the guard underflow are
wire-proven (rung 2.75); only the 2^32-fold repetition of an already
observed accepted-WU step was compressed into one gdb assignment.

**Why 2^63 is the exact threshold (static).** `filter:1144` computes the
queue-time limit as `limit = h2c->send_window` behind the test
`limit > (off_t) h2c->send_window`. At or above 2^63 the cast is negative,
so any caller limit takes the branch and `limit` becomes negative; below
2^63 the cast is positive and nothing scales with the window (wake-6
negative). With `limit` negative: `frame_size = (size_t) limit`
(`filter:1165`) wraps to `2^63 + 2^32`; `get_shadow` (`filter:1308` — the
in-memory branch: over TLS the copy filter turns static-file bufs into
memory bufs via `ngx_http_copy_filter`/`ngx_output_chain`, so the
`in_file` branch at 1311-1313 is dead in this lab shape) builds the
DATA-frame body with `last = pos + (2^63 + 2^32)` (mod 2^64), i.e.
`last - pos` = `-2^63 + 2^32` as a signed value. The frame's on-wire
header length is the low 24 bits (`0x000000`, a zero-length DATA frame) —
the corruption is entirely in the heap bookkeeping, not the wire bytes.

**Observed chain (2 runs byte-identical, plus an independent witness
re-run from a clean checkout: 3/3; `lab/tmp/gdb-x-1.31.8.log`, ASan
report `lab/tmp/x-1.31.8.log`):**

```
XFORCE     send_window=9223372041149743104              <- forced at mkX0ping
LIMITWRAP  limit=-9223372032559808512 frame_size=9223372041149743104
SHADOW     size=-9223372032559808512 pos=0x52d0002bc400
CHARGE     sid=71 frame_size=9223372041149743104        <- send_window -> 0
SSLMEMCPY  size=-9223372032559808512 dst=0x52900006a52a src=0x52d0002bc400
```

Every wrapped constant is the same number: `2^63 + 2^32` unsigned =
`-9223372032559808512` signed. (gdb -O1 note: the breakpoint at
`filter:1165` stops on the hoisted store; the printed `frame_size` is
already the wrapped value, cross-checked by the CHARGE line.)

**The consuming fault.** `ngx_http_v2_send_output_queue` hands the frame
chain to the TLS send chain (`v2.c:544`). `ngx_ssl_send_chain` coalesces
frame bufs into its 16 KiB buffer: `size = in->buf->last - in->buf->pos`
(`ngx_event_openssl.c:3137`) evaluates to `-2^63 + 2^32` as `ssize_t`;
both guards — `size > buf->end - buf->last` (`:3139`) and
`send + size > limit` (`:3143`) — are signed compares and **skip** a
negative size; `ngx_memcpy(buf->last, in->buf->pos, size)` (`:3150`)
converts it back to `size_t`:

```
ERROR: AddressSanitizer: memcpy-param-overlap: memory ranges
  [0x52900006a52a, 0x800052910006a52a) and [0x52d0002bc400, 0x800052d1002bc400) overlap
    #2 ngx_ssl_send_chain src/event/ngx_event_openssl.c:3150
    #3 ngx_http_v2_send_output_queue src/http/v2/ngx_http_v2.c:544
    #4 ngx_http_v2_write_handler src/http/v2/ngx_http_v2.c:489
  dst = 16 KiB c->ssl->buf (ngx_event_openssl.c:3098) + 4906 bytes in
  src = 32 KiB copy-filter buf (ngx_http_copy_filter -> ngx_output_chain_get_buf)
==...==ABORTING   worker exits 1; master respawns a fresh worker
```

Both ranges are exactly `2^63 + 2^32` bytes. The destination is a 16 KiB
heap allocation and the source a 32 KiB one. **No-ASan control (witness +
author re-run):** on an unsanitized 1.31.8 build
(`lab/build/1.31.8-plain`, `-g -O1 -fno-omit-frame-pointer`) the same
probe and the same gdb force make the real glibc memcpy execute —
`__memcpy_avx_unaligned_erms` with `__len = 9223372041149743104` from
`ngx_ssl_send_chain:3150` via `v2.c:544/489` — and the worker SIGSEGVs,
4/4 runs, no sanitizer involved (`lab/tmp/gdb-x-1.31.8-plain-bt.log` has
the full backtrace; harness `lab/harness/run-x-plain.sh`). A heap buffer
overflow followed by worker death — the CVE's own wording — is therefore
observed both sanitizer-labeled and raw, not inferred. ASan labels it
`memcpy-param-overlap` because the two enormous ranges nominally
intersect; the substantive violations are the `2^63 + 2^32`-byte copy into
a 16 KiB buffer (OOB write) and out of a 32 KiB buffer (OOB read).

**Ladder: rung 3 — confirmed memory corruption** (ASan-observed,
deterministic client input + one debugger-forced ledger jump; 2 runs
byte-identical + witness 3/3 + plain-build SIGSEGV 4/4). NOT rung 4: no
control exercised over the overflow's contents or placement beyond its
length, and the 2^63 ledger was not
wire-pumped (wire-pumping reached 10^13, wake 9). The consumer code
(`send_chain` limit cast, `get_shadow`,
`ngx_ssl_send_chain`) is IDENTICAL in 1.31.9 — the patch fixes the guard
and the ledger, not the consumer — so a .9 control run of this experiment
would be meaningless (forcing the value bypasses the guard in any build);
the .9 differential is rung 2.75's.

**Wake-7 falsified models, preserved:**

1. **"Nothing on paper suggests a threshold" (wake 6)** — FALSE: the
   threshold is exactly `2^63`, and it is a cast boundary, not a scaling
   effect. The wake-6 soak over `6x MAX` could never have found it; the
   static sweep's "no consumer" conclusion was correct only below 2^63.
2. **"The bogus shadow will be caught at the `in_file` branch
   (`filter:1313`)"** — FALSE in this lab shape: over TLS the copy filter
   has already turned the file buf into a memory buf, so the `in_memory`
   branch (`:1307-1308`) runs. Cost: one probe run with a silent
   breakpoint.
3. **gdb command-file structural failure:** an edit that swallowed a
   `continue`/`end` pair made gdb -batch parse the rest of the file as
   command-list body and exit 0 after three breakpoints with no `run` —
   no error text. Diagnosis cost one runner attempt; the runner's
   port-wait timeout surfaced it.

## Stage-A survey: the wrapped memcpy writes NOTHING before dying (wake 14, 2026-11-20 — rung-4 pursuit, negative)

The owner-directed rung-4 Stage A premise ("convert the blind 2^63 memcpy
into a controlled write" by grooming victims adjacent to the 16 KiB SSL
buffer and letting the partial copy overwrite them) is FALSIFIED on this
lab's glibc: the huge memcpy performs ZERO stores before faulting.

Harness: `lab/harness/run-x-survey.sh 1.31.8-plain` +
`lab/harness/gdb-x-survey.cmd` — the same forced-ledger probe as
`run-x-plain.sh`, with the fault context captured at the SIGSEGV stop
(`lab/tmp/gdb-x-survey-1.31.8-plain.log`; the conditional breakpoint meant
to dump the heap pre-state never fired on this -O1 build — its
`file:line if size < 0` form resolves to a location where `size` is
unavailable, a harness defect to fix before any future dump-based
experiment — but the stop-time capture alone settles the question).

**Observed (1 run, complete register cross-check):** fault at
`__memcpy_avx_unaligned_erms+363` = `vmovdqu -0x20(%rsi,%rdx,1),%ymm5`,
a TAIL-VEC **load** from `src + n - 0x20`; with the wrapped
`n = 2^63 + 2^32` and a heap src this address has bit 63 set →
non-canonical → #GP → SIGSEGV with `si_code = 128 (SI_KERNEL)` and
`si_addr = 0` (kernel cannot encode a non-canonical fault address) — both
observed. Disassembly of the taken path (libc file offset 0x188d80,
Ubuntu glibc 2.39-0ubuntu8.12; runtime base 0x7ffff7400000 = fault RIP
0x7ffff7588eeb − file offset 0x188eeb):

```
188d8d  vmovdqu (%rsi),%ymm0        head-VEC LOAD (valid heap) — succeeds
188e40  cmp [non_temporal_threshold],%rdx ; ja 189040        taken (n huge)
189040  mov %rdi,%rcx ; sub %rsi,%rcx ; cmp %rdx,%rcx ; jb  not taken
18904f  mov %rdi,%r8                                       r8 = dst (observed)
189052  cmp [rep_movsb_threshold],%rdx ; jae 1890a0         taken
1890a0  mov [0x20b230],%r11 ; cmp %r11,%rdx ; jb            not taken
        (r11 = 0x1800000 = 24 MB shared-cached-size, observed)
1890b0  neg %rcx                    rcx = src - dst = 0x2abae6 (observed)
1890b3  cmp %rcx,%rdx ; ja 188eeb   taken (n > src-dst)
188eeb  vmovdqu -0x20(%rsi,%rdx,1),%ymm5   FAULT — first unmapped access
```

Every register the trace predicts matches the observed stop state
(`r8 = 0x5555557799ca = dst`, `rcx = 0x2abae6 = src − dst`,
`r11 = 0x1800000`, `rdx = n` unchanged). The path contains exactly two
memory accesses: one valid head load and the faulting tail load. No store
instruction executes. Consequences:

1. **The "partial copy before the fault" window on this build is ZERO
   bytes** — the plain-build worker death (rung 3's 4/4 SIGSEGV) is a
   tail-VEC LOAD fault, not a progressive overwrite; the heap is never
   written by the wrapped memcpy. This refines (does not revoke) rung 3:
   the OOB write is the ASan-observed call (ASan rejects the huge ranges
   before execution), while the unsanitized build dies before its first
   store.
2. **No survivable wrapped length exists on this build.** Any negative
   `ssize_t` size converts to a `size_t ≥ 2^63`; for any canonical user
   src, `src + n` is non-canonical, and glibc's tail-first access hits it
   before the main loop. The owner's open question "whether a smaller
   survivable wrapped length can be shaped" is answered NO for this
   glibc/hardware combination — not by calibration but structurally.
3. **Stage A as specified (canary adjacent to the SSL buffer receiving
   chosen bytes from the partial copy) is unreachable via this consumer
   on this build.** Placement control has no write to land. The owner's
   named obstacle ("the 2^63 overshoot may fault before a useful object
   executes") is now an observed wall, not a risk.

Per-build caveat, dispositioned at source level (wake 15, 2026-11-20):
this host is AMD Zen 3 (AVX2 only), so the IFUNC dispatcher selects
`__memcpy_avx_unaligned_erms` and the fault-context observation above is
the EXECUTED path — and its fault instruction, `vmovdqu
-0x20(%rsi,%rdx,1),%ymm5`, is exactly source line 461 of the template
(finding 3 below) with VEC_SIZE = 32, which validates reading this template as a predictor of
its built code. NGINX2Root's claimed profile is Debian 13, glibc 2.41,
AVX-512 target, whose IFUNC pick would be
`__memmove_avx512_unaligned_erms`. Checked by fetching the shipped glibc
source (provisioning, allowed):

```
curl -fsSL -o glibc-2.41-memmove-vec-unaligned-erms.S \
  'https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S;hb=glibc-2.41'
```

Findings, honestly labeled SOURCE-LEVEL STATIC evidence — the shipped
`.S` template, not disassembled bytes of a Debian 2.41 build, and not
executable on this host (no AVX-512 hardware) — one rung below the 2.39
fault-context observation:

1. `memmove-avx512-unaligned-erms.S` (2.41) is a 12-line wrapper that
   includes `memmove-vec-unaligned-erms.S` with VEC_SIZE = 64 (evex512
   vecs): the AVX-512 path IS the same template at a wider vector.
2. The 2.41 template vs this host's 2.39 template differ ONLY in the
   copyright-year line (unified diff verified; sha256 pinned below) —
   the access ordering is byte-identical.
3. In that template, for a wrapped `n ≥ 2^63` and canonical src, every
   huge-length entry (`L(more_8x_vec)`, `L(movsb)`,
   `L(large_memcpy_2x[_check])`) routes through megabyte-scale
   threshold branches into a load-first block — forward
   (`L(more_8x_vec_forward)`, line 461: the observed faulting tail load)
   or backward (`L(more_8x_vec_backward)`, line 523: the same wrapped
   tail load as its 4th access) — whose first non-canonical access is
   the tail load `VMOVU -VEC_SIZE(%rsi, %rdx)`, strictly before the
   first store (forward loop line 488 / backward line 540). The only
   store-first fallthrough (`L(large_memcpy_2x)` line 695+) requires
   `n ≤ src − dst`, impossible for `n ≥ 2^63` with canonical addresses
   (`|src − dst| < 2^47`); the `rep movsb` tails are gated by the same
   megabyte-scale thresholds, unreachable at exabyte `n`.

So the wake-14 wall is STRUCTURAL, not calibration: no survivable
wrapped length exists on glibc 2.39-AVX2 (executed, fault-observed) or
on glibc 2.41-AVX-512 per its shipped template (displacement −0x40
instead of −0x20, same non-canonical address). What this implies for
NGINX2Root's claimed Debian-13/glibc-2.41/AVX-512 profile, without
upgrading our ladder: the "partial copy before the fault" premise would
need a different libc, a locally patched glibc, or a different consumer
than the one observed here; the template glibc 2.41 actually ships
cannot provide that window. Scope: this disposition covers the avx2 and
avx512 instantiations of this template (all erms/non-erms variants it
builds); the legacy SSE2 template was not checked — irrelevant to the
claimed profile. All rung-4 claims remain labeled for this lab's
1.31.8-plain build, extended by this static check only.

Fetched-file sha256 (2026-11-20 evidence pin; copies under
`lab/tmp/glibc-src/`, gitignored): 2.41 template
`47926a9056c1805d9cd8109ef80e0c7f3a52f950e6ddec6a03dc10b6260848c1`,
2.39 template
`3cba1478f5b496e9be5d14e5a0fb5e5759fcef20423b570825843628f72329fb`
(diff: copyright line only), avx512 wrapper (both tags)
`4c6806b0c1ede898a790996d0b88bd3480953584ff526f1b04f567b8d68ecb65`.

**Wake-14 falsified model, preserved:** "the raw glibc memcpy runs forward
until it hits an unmapped page, overwriting everything between" — FALSE on
this build: it faults on its second access, a wrapped-address tail load,
having written nothing.
## Reproduction plan (rungs, in order)

1. **Accounting probe — DONE, see "Observed over-credit".** The committed
   harness reproduces it from a clean checkout (plus `openssl req` and one
   `dd` for the gitignored cert/corpus, see `lab/provision.sh` comments).
2. **Cancellation refund measurement — DONE, see "Cancellation refund
   measurement".** 81 cancellations across 2 runs, every refund byte-exact
   (65,536 per fresh stream = 8×8192 charged; round aggregates return
   `send_window` exactly to baseline) — **without an interleaving WU**;
   see rung 2.75 for what changes when one is present.
3. **WU-interleave double-credit — DONE, see "WU-interleave double-credit
   and connection-window underflow".** `lab/harness/run-wu.sh 1.31.8`
   (and `run-wu.sh 1.31.8 4` for the wake-6 ASan soak, `run-wu.sh
   1.31.8 4656` for the wake-9 wire-only pump to 10^13) reproduce the
   full chain: `send_window` past MAX, guard underflow, unbounded credit;
   byte-identical across 2 runs. `run-wu.sh 1.31.9` reproduces the
   control GOAWAY.
4. **Corruption attempt (rung 3) — DONE as a POSITIVE, debugger-assisted:
   see "Extreme-window consumer".** `lab/harness/run-x.sh 1.31.8`
   reproduces the confirmed heap buffer overflow (ASan report + worker
   abort, byte-identical 2 runs + witness 3/3): ledger forced to
   `2^63 + 2^32` after the wire-proven pump. `lab/harness/run-x-plain.sh`
   does the same against the unsanitized `1.31.8-plain` build: raw glibc
   memcpy executes with `__len = 2^63 + 2^32` and the worker SIGSEGVs
   (witness 3/3 + author re-run 1/1). The negative below 2^63 stands:
   the wake-6 soak (6x MAX) and the wake-9 wire-only pump through
   10^13 (4658x MAX, worker clean) both traversed the range without
   any consumer firing; no consumer exists between `6x MAX` and
   `2^63 - 1`.
5. **Control:** DONE — 1.31.9 rejects the over-credit probe (wake 4) and
   the interleave probe (wake 6) at the guard (`v2.c:2564/2565`, with
   `- h2c->send_queued` in the .9 guard).
6. **Stage-A survey (rung 4 pursuit) — DONE as a NEGATIVE: see "Stage-A
   survey".** `lab/harness/run-x-survey.sh 1.31.8-plain` captures the
   fault context of the wrapped memcpy: glibc's tail-VEC load from the
   wrapped non-canonical `src + n - 0x20` faults before any store, so the
   "partial copy" window is zero bytes on this build.
   The glibc-2.41/AVX-512 extension of the negative is re-checkable
   offline with the `curl` command quoted in the survey section (fetch
   both tags, `diff -u`: only the copyright line differs).

## Evidence ledger

| Ladder rung | Status | Evidence |
|---|---|---|
| Suspected vulnerability | YES | patch diff + fault sites above |
| Observed accounting violation (true window > MAX via queued-DATA ledger gap) | YES | wake 4: gdb `post_true = 2,148,311,039 > MAX`; 1.31.9 rejects the same WU |
| Cancellation refunds exactly 1:1 **without an interleaving WU** | YES | 81 refunds across 2 runs: per-stream refund == queue-time charges; `close_stream` postponement does not gate the refund (terminate-cleanup path) |
| **`h2c->send_window` itself driven past MAX; 1.31.8 guard underflowed; unbounded WU credit accepted** | **YES** | wake 6: mkB1 = MAX + 32,768; standalone WU accepted at pre = 2,147,516,415; `inc=2147483647` accepted; soak to 12,885,000,186 with 36.7 MB streamed, no GOAWAY; byte-identical 2 runs; 1.31.9 refuses the same sequence at cycle 0. Wake 9: wire-only pump (no debugger forcing) to 10,002,978,926,030 = 4658x MAX + 98,304, all 4693 credits accepted, author 1/1 + witness 1/1 (the earlier "2/2" was one run under two byte-identical log files, same worker PID 566660; witness run PID 624758), worker clean under ASan (`gdb-wu-1.31.8-1e13.log`, witness log `gdb-wu-1.31.8-4656-witness.log`) |
| Reproducible crash (debugger-assisted ledger) | YES | wake 7: worker aborts (ASan `ABORTING`, exit 1) on every `run-x.sh 1.31.8` run, 2/2 + witness 3/3; on the unsanitized build the same probe SIGSEGVs the worker in real glibc memcpy (witness 3/3 + author 1/1, `run-x-plain.sh`); the wire path to that ledger is wire-pumped to 10^13 (wake 9, 4658x MAX) and the remaining ~2^32-WU stretch to 2^63 was skipped by the debugger |
| **Confirmed memory corruption (rung 3)** | **YES** | wake 7: ASan `memcpy-param-overlap`, `2^63+2^32`-byte memcpy into a 16 KiB heap buf (`ngx_event_openssl.c:3150` via `v2.c:544`); full chain breakpoint-observed: negative `(off_t)` cast (`filter:1144`), wrapped `frame_size` (`:1165`), bogus shadow (`:1308`), huge charge (`:1241`); 2 byte-identical runs + witness 3/3 + plain-build SIGSEGV 4/4. Consumer code identical in 1.31.9 — the patch blocks the ledger, not the consumer |
| Demonstrated memory-safety impact (rung 4) | NO | no control over the overflow's contents/placement beyond length; the 2^63 ledger was debugger-forced, not wire-pumped (wire-pumped to 10^13, ~922,000x short of 2^63). Wake 14: on the plain build the wrapped memcpy performs ZERO stores before faulting (glibc tail-VEC load wall, see "Stage-A survey") — Stage A's canary placement via the partial copy is unreachable on this glibc/hardware. Wake 15: glibc 2.41's shipped AVX-512 template differs from 2.39's only in its copyright line, same tail-load-first order — the wall is structural on both the executed 2.39-AVX2 path and the claimed 2.41-AVX-512 profile (source-level static evidence, one rung below the fault-context observation; not executable on this host). **Stage B (wire-pure 2^63 pump, ~2^32 max-WUs ≈ 56 GB loopback) NOT RUN — open owner question, not a lab blocker:** its only consumer (Stage C) has no write to hijack on any build this lab can execute, and its residual value is upgrading rung 3 from debugger-assisted to wire-pure; a stage that fails is preserved as a negative, not retried into existence (docs/task.md) |

Negative results preserved: toolchain smoke (previous wake), the refutation of
the naive refund-inflation narrative (wake 5 — superseded, not erased, by the
interleave finding of wake 6), the three falsified queueing models in
"Falsified models", the wake-6 falsified models in the rung-2.75 section, the
wake-6 "no threshold on paper" model killed at 2^63 (rung-3 section), the
wake-14 "progressive forward overwrite" model (Stage-A survey), the
wake-15 kill of the "glibc 2.41 AVX-512 might store first" hypothesis
(shipped 2.41 template = 2.39's modulo copyright line — Stage-A
survey), and
the upstream-commit cross-check (witness-verified: six-line match, tag diff
a superset — see "The patch").
