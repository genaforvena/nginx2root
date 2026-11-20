# Stage-A-mechanics (owner directive #47): same client sequence and same
# gdb force at mkX0ping as gdb-x-survey.cmd, but the worker runs with a
# LD_PRELOAD store-first memcpy (lab/harness/storefirst-memcpy.c, built by
# run-x-mechanics.sh into lab/tmp/storefirst-memcpy.so). SYNTHETIC,
# mechanics-only label: the stock-glibc tail-load wall stands; no rung-4
# claim on any stock build. The wrapped call executes a naive forward
# byte loop; the expected stop is a SEGV_MAPERR on the src side, AFTER
# the loop has stored src bytes from the SSL buffer's fill point forward.
# NOTE: the ngx_ssl_send_chain entry break never fires on this -O1 build
# (wake-14 harness defect, prologue clobbers $rsi) — the capture here
# breaks on the shim's storefirst symbol instead, whose -O0 args are
# reliable. At the call: geometry + pre-copy dumps of the victims window
# (dst+0x4000 .. +0xC000 is entirely past the 16 KiB SSL buffer end, since
# buf->last <= buf->end = buf->start + 0x4000). At the stop: siginfo, shim
# globals, and post-copy dumps for the offline faithfulness check.
set pagination off
set confirm off
set follow-fork-mode child
set breakpoint pending on
set environment LD_PRELOAD /home/mesh-home/nginx2root/lab/tmp/storefirst-memcpy.so

break ngx_http_v2.c:2575
commands
silent
printf "CONNWU inc=%lu send_window(pre)=%lu\n", window, h2c->send_window
continue
end

break ngx_http_v2_state_ping
commands
silent
printf "PINGMARK send_window=%lu\n", h2c->send_window
if (pos[0] == 'm' && pos[1] == 'k' && pos[2] == 'X' && pos[3] == '0')
    set h2c->send_window = 0x8000000100000000
    printf "XFORCE send_window=%lu\n", h2c->send_window
end
continue
end

break ngx_http_v2_filter_module.c:1165
commands
silent
printf "LIMITWRAP limit=%ld frame_size=%lu send_window=%lu\n", limit, frame_size, h2c->send_window
continue
end

break ngx_http_v2_filter_module.c:1241
commands
silent
printf "CHARGE sid=%lu frame_size=%lu send_window(pre)=%lu\n", stream->node->id, frame_size, h2c->send_window
continue
end

break storefirst
commands
silent
if (n >= 0x10000000000)
    printf "MECHCALL dst=%p src=%p n=%lu\n", dst, src, n
    set $mdst = (unsigned long) dst
    set $msrc = (unsigned long) src
    set $sslwin = $mdst + 0x4000
    printf "VICTWIN %lx..%lx (SSL buf end <= %lx)\n", $sslwin, $sslwin + 0x8000, $mdst + 0x4000
    info proc mappings
    dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-mechanics-pre-follow.bin $sslwin $sslwin + 0x8000
    dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-mechanics-pre-src.bin $msrc $msrc + 0x8000
    printf "PREDUMP done (victims window from %lx, src from %lx)\n", $sslwin, $msrc
end
continue
end

run
echo \n===STOP===\n
p $_siginfo
info registers rdi rsi rcx rdx rip
p g_mech_bytes
p g_mech_dst
p g_mech_src
p g_mech_n
set $mdst = (unsigned long) g_mech_dst
set $msrc = (unsigned long) g_mech_src
set $sslwin = $mdst + 0x4000
set $mbytes = (unsigned long) g_mech_bytes
x/8i $rip-16
echo POSTDUMP begin\n
dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-mechanics-ovw-dst.bin $mdst $mdst + $mbytes + 0x1000
dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-mechanics-ovw-src.bin $msrc $msrc + $mbytes + 0x1000
dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-mechanics-post-follow.bin $sslwin $sslwin + 0x8000
printf "POSTDUMP done (extent %lu bytes)\n", $mbytes
bt 8
