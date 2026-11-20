# Research task: nginx HTTP/2 flow-control vulnerability investigation

Investigate CVE-2026-123007 ("NGINX2Root") in a local, isolated nginx
environment. Determine whether we can independently identify and reproduce the
underlying memory-safety failure.

You may inspect source code, build nginx, create test harnesses, instrument
the worker, run debuggers, and conduct experiments. Maintain evidence for
every finding. Distinguish suspected vulnerability, reproducible crash,
confirmed memory corruption and demonstrated security impact. Preserve failed
hypotheses and contradictory results. Treat unknowns as unknowns. All testing
remains within the laboratory; never contact external systems or scan public
infrastructure. Produce a reproducible technical report containing methods,
observations, evidence and remaining uncertainties.

## Verified ground truth (2026-11-20)

Read from the CVE record JSON (CNA F5, published 2026-11-18) and the vendor
advisory. These are starting claims, not conclusions.

| Field | Value |
|---|---|
| Title | NGINX ngx_http_v2_module vulnerability |
| CWE | CWE-191 integer underflow; CWE-787 out-of-bounds write |
| CVSS | 8.1 HIGH (3.1) / 9.2 CRITICAL (4.0), unauthenticated network, AC:HIGH |
| Description | HTTP/2 configurations: flow-control window can exceed the allowed threshold → heap buffer overflow typically followed by worker segfault; code execution possible with ASLR disabled or bypassed. Data plane only. |
| Affected | NGINX OSS 1.9.5–<1.31.9 and 1.30.x <1.30.7 (`ngx_http_v2_module`); NGINX Plus R33–<37.0.8.1/37.3.0.1 |
| Fixed | 1.31.9, 1.30.7 (Plus 37.0.8.1 / 37.3.0.1) |
| Reporter credit | Stephen Fewer (Rapid7), Tomer Schwartz (Wiz), Xint.io, Ikotas Labs |
| Patch commit | `b89c4100bf6762a45e4a6463eaf4b70368277c94` (nginx/nginx) |
| Advisory | F5 K000163926; GHSA-m4q8-cf44-f42r |
| Related | CVE-2026-123633 (connection reuse, separate fix in same range) |

The public research client `arkrwn/NGINX2Root-CVE-2026-123007` (Rust) claims:
a `--safe` mode (~14 MiB) proving the accounting bug without corruption
(queued-DATA refund, public-byte release, underflowed window-update guard,
connection still usable) and a full RCE chain (`--exploit`/`--shell`,
~119 GiB, requiring an embedded binary profile: nginx 1.31.8 Debian 13 amd64,
glibc 2.41, AVX-512 target, 4 workers). Its `scripts/validate-safe.sh` builds
1.31.8 (VULNERABLE) and 1.31.10 (NOT PROVEN) locally. Its reverse-read of the
patch claims the bug is a lost `send_queued` credit on stream cancellation:
`ngx_http_v2_filter_cleanup` refunds `send_window` without bounds, the guard
`NGX_HTTP_V2_MAX_WINDOW - send_window` wraps once `send_window` passes
0x7fffffff. All of this is claims to reproduce, not evidence.

## Deliverable

`reports/nginx2root-investigation.md`: methods, environment (exact nginx
commits and build flags), observations, evidence for each ladder step reached,
failed hypotheses preserved, and remaining uncertainties. A reproduction script
per claimed finding, committed alongside.

## First plan (to be revised by nginxsec with evidence)

1. Vendor nginx `release-1.31.8` and `release-1.31.9` into `lab/`; build both
   with ASan+UBSan and debug symbols, HTTP/2 enabled.
2. Diff `src/http/v2/` between the tags; name the predicted fault site from
   the patch (`send_queued`, the window guard, the refund path) before any
   trigger attempt.
3. Loopback harness: local TLS+h2 nginx instance with a sized static resource;
   drive the claimed refund/over-credit sequence with our own minimal client.
4. Attempt the accounting proof first (the `--safe` equivalent); only then
   the corruption question; classify every fault on the ladder.
5. witness re-runs everything independently.

## Rung 4 pursuit (owner directive, 2026-11-20)

The report stands at rung 3 (confirmed corruption) with rung 4 honestly NO.
The owner directs the plant to pursue demonstrated security impact in
stages, in this order:

- **Stage A — placement control.** Heap-groom the lab worker (connection
  spray, echoed buffers with chosen content near the SSL send chain) and
  prove chosen bytes land at a chosen offset via a canary region. This
  converts the blind 2^63 memcpy into a controlled write.
- **Stage B — wire-pure trigger.** Build a bulk pipelined WINDOW_UPDATE
  pump and wire-pump the ledger to 2^63 without debugger forcing
  (~2^32 max-WUs, ~56 GB on loopback; budget hours of lab compute).
- **Stage C — control-flow hijack.** With placement control, overwrite an
  adjacent callback (pool cleanup handler, connection event pointer) and
  demonstrate pointer control / a benign marker execution in the lab
  build, ASLR disabled, honestly labeled per-build.

Known obstacles to carry, not hide: the 2^63 overshoot may fault before a
useful object executes (the exploitable window is the partial copy before
the fault); whether a smaller survivable wrapped length can be shaped is
open; calibration is per-build and every claim is labeled for this lab's
1.31.8. All testing stays loopback-only. Witness re-runs each stage's
claims exactly as before; a stage that fails is preserved as a negative
result, not retried into existence.
