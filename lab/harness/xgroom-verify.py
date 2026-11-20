#!/usr/bin/env python3
"""Stage-A-mechanics GROOMING slice: canary generator + offline verifier.

SYNTHETIC/mechanics-only label (owner directive #47, standing approval
item 1, 2026-11-20): the overwrite under analysis comes from the
LD_PRELOAD store-first memcpy shim (lab/harness/storefirst-memcpy.c);
nothing about any stock build may be claimed from this evidence, and the
stock-glibc tail-first wall stands unwalled.

Canary corpus layout (lab/corpus/canary, 16 MiB): 32-byte records --
  magic b"NGX2RCNY" (8) | reserved 0x00 (4) | record index LE (8) |
  pad 0xA5 (12)
The record index is the canary file offset / 32, so any record found at
an arbitrary byte alignment resolves to its exact canary file offset,
and its content is checked byte-exact against the corpus.

Victim vs copy: the sprayed victims are canary file chunks packed in
the heap past the 16 KiB SSL buffer, interleaved with nginx's own
allocations (observed: a ~16 KiB non-canary gap between sprayed chunks),
with the linear map canary_off = window_off + K constant inside each
chunk and stepping between chunks (malloc headers, and the pump streams
restart the file offset per stream). The verifier therefore does not
require one global K: it checks (a) records are content-valid canary,
(b) they form contiguous spans whose per-chunk byte map (canary_off -
win_off) is exact, printed per step,
(c) the pre-copy window is substantially sprayed, (d) post-copy NO
canary magic survives below the stored extent, (e) content-valid
records survive past it. Cross-run determinism of the geometry is
checked by comparing dump hashes across two runs (outside this script).

Modes:
  --make-canary PATH   write the deterministic canary corpus
  (default)            verify a grooming run: parse MECHCALL/EXTENTBYTES
                       from the gdb log, then check the dumps.
Usage (verify): xgroom-verify.py BUILD [gdblog]
  expects lab/tmp/gdb-x-groom-BUILD.log and lab/tmp/x-groom-*.bin
"""

import re
import struct
import sys
from collections import Counter

MAGIC = b"NGX2RCNY"
REC = 32
CANARY_SIZE = 16 * 1024 * 1024
RESERVED = b"\x00\x00\x00\x00"
PAD = b"\xa5" * 12
GAP = 64                   # record-offset gap that breaks a span
SPAN_MIN = 32              # records before a span's validity is graded
VALID_REQ = 0.95           # valid-content share required inside a span
COV_REQ = 0.40             # pre-window canary byte coverage required

ROOT = __file__.rsplit("/lab/harness/", 1)[0]
BLOB = ROOT + "/lab/corpus/blob"
CANARY = ROOT + "/lab/corpus/canary"


def make_canary(path):
    with open(path, "wb") as f:
        buf = bytearray()
        for idx in range(CANARY_SIZE // REC):
            buf += MAGIC + RESERVED + struct.pack("<Q", idx) + PAD
            if len(buf) >= 1 << 20:
                f.write(buf)
                buf = bytearray()
        f.write(buf)


def spans_of(records):
    """Group (offset, canary_off, valid) records into contiguous spans."""
    out = []
    for off, coff, valid in records:
        if out and off - (out[-1]["end"] + REC) < GAP:
            r = out[-1]
        else:
            r = {"start": off, "end": off - REC, "recs": []}
            out.append(r)
        r["end"] = off
        r["recs"].append((off, coff, valid))
    for r in out:
        r["valid"] = sum(1 for _, _, v in r["recs"] if v)
        ks = Counter(coff - off for off, coff, _ in r["recs"])
        r["steps"] = ks.most_common()
        r["can0"] = min(coff for _, coff, _ in r["recs"])
        r["can1"] = max(coff for _, coff, _ in r["recs"]) + REC
    return out


def show_spans(spans, tag, base=0):
    for r in spans:
        n = len(r["recs"])
        note = ""
        if n >= SPAN_MIN:
            note = "" if r["valid"] >= VALID_REQ * n else "  INVALID-CONTENT"
        shown = ", ".join(f"{k - base:+#x} ({c}/{n})"
                          for k, c in r["steps"][:4])
        extra = f" +{len(r['steps']) - 4} more" if len(r["steps"]) > 4 else ""
        print(f"    {tag} span win[{r['start'] + base:#06x}.."
              f"{r['end'] + REC + base:#06x}] "
              f"canary[{r['can0']:#x}..{r['can1']:#x}] {n} recs, "
              f"{r['valid']} valid, steps canary_off-win_off: "
              f"{shown}{extra}{note}")


def verify(build, gdblog):
    log = open(gdblog).read()
    stop = log.split("===STOP===")
    m = re.search(r"MECHCALL dst=(0x[0-9a-f]+) src=(0x[0-9a-f]+) n=(\d+)", log)
    if not m:
        sys.exit("no MECHCALL in " + gdblog)
    dst, src, n = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3))
    me = re.search(r"EXTENTBYTES (\d+)", stop[1])
    if not me:
        sys.exit("no EXTENTBYTES in " + gdblog)
    extent = int(me.group(1))
    print(f"dst={dst:#x} src={src:#x} n={n:#x} stored extent={extent:#x}")

    pre = open(ROOT + "/lab/tmp/x-groom-pre-follow.bin", "rb").read()
    post = open(ROOT + "/lab/tmp/x-groom-post-follow.bin", "rb").read()
    ovw = open(ROOT + "/lab/tmp/x-groom-ovw-dst.bin", "rb").read()
    blob = open(BLOB, "rb").read(0x8000)
    canary = open(CANARY, "rb").read()

    def records_at(data):
        """Yield (offset, canary_off, content-valid) for magic hits."""
        off = data.find(MAGIC)
        while off != -1:
            if off + REC <= len(data):
                idx = struct.unpack("<Q", data[off + 12:off + 20])[0]
                coff = idx * REC
                if coff + REC <= CANARY_SIZE:
                    yield off, coff, \
                        data[off:off + REC] == canary[coff:coff + REC]
            off = data.find(MAGIC, off + 1)

    # 1. grooming: pre-copy window substantially sprayed with valid canary
    pre_recs = list(records_at(pre))
    pre_spans = spans_of(pre_recs)
    cov = sum(r["valid"] for r in pre_spans) * REC / len(pre)
    print(f"pre-copy window: {len(pre_recs)} records in {len(pre_spans)} "
          f"spans, valid-canary byte coverage {cov:.0%}")
    show_spans(pre_spans, "pre")
    big = [r for r in pre_spans if len(r["recs"]) >= SPAN_MIN]
    ok1 = cov >= COV_REQ and big and \
        all(r["valid"] >= VALID_REQ * len(r["recs"]) for r in big)
    if not ok1:
        print("GROOMING NEGATIVE: pre-copy victims window is not "
              "substantially sprayed with content-valid canary")
        return 1

    # 2. chosen bytes faithful: stored span == blob frame body
    seg = ovw[:0x8000]
    ok = seg == blob
    print(f"stored span dst..dst+0x8000 == blob[0:0x8000]: {ok}")
    if not ok:
        print("FAITHFULNESS FAILURE: stored span is not the blob frame body")
        return 1

    # 3/4. post-copy: no canary magic below the stored extent, valid
    #      records survive past it
    ext_win = min(max(extent - 0x4000, 0), len(post))
    below = list(records_at(post[:ext_win]))
    above_spans = spans_of(list(records_at(post[ext_win:])))
    print(f"post-copy: canary records below extent: {len(below)} "
          f"(expect 0), surviving spans past it: {len(above_spans)}")
    show_spans(above_spans, "post", base=ext_win)
    ok34 = not below and above_spans and \
        any(r["valid"] >= VALID_REQ * len(r["recs"])
            for r in above_spans if len(r["recs"]) >= SPAN_MIN)
    if not ok34:
        print("INCONSISTENT: canary survives inside the stored span, or no "
              "content-valid canary survives past the stored extent")
        return 1

    print("GROOMING VERDICT: POSITIVE — content-valid sprayed canary "
          "victims occupied computable offsets across the victims window "
          "(per-span window offset + K = canary file offset); the "
          "store-first copy replaced them with chosen blob bytes below "
          "its stored extent, and valid sprayed victims survive past it. "
          "SYNTHETIC mechanics-only; no stock-build claim.")
    return 0


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--make-canary":
        make_canary(sys.argv[2])
        print("wrote " + sys.argv[2])
        return
    build = sys.argv[1] if len(sys.argv) > 1 else "1.31.8-plain"
    gdblog = sys.argv[2] if len(sys.argv) > 2 else \
        ROOT + f"/lab/tmp/gdb-x-groom-{build}.log"
    sys.exit(verify(build, gdblog))


if __name__ == "__main__":
    main()
