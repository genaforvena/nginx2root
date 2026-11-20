# Stage-A survey (rung-4 pursuit): same client sequence and same gdb force at
# mkX0ping as gdb-x-plain.cmd. The wrapped-frame capture breaks at
# ngx_ssl_send_chain ENTRY with a register-based condition ($rsi chain with
# buf->last < buf->pos is the wrapped negative-length frame) because the
# plain -O1 build's line table makes "break file:3150 if size < 0" unreliable
# (survey run 1 never matched it). At the hit: record copy geometry, dump
# 32 KiB of heap after the 16 KiB c->ssl->buf chunk (its malloc chunk ends
# exactly at buf->end) and the 32 KiB source buf (pre-state). After the
# SIGSEGV: siginfo, registers, disassembly around rip, same post-window dump.
# Chunk-layout walking is done OFFLINE on the dumps (an unmapped read inside
# a breakpoint command list would abort the list and stall the worker).
set pagination off
set confirm off
set follow-fork-mode child

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

break ngx_ssl_send_chain
commands
silent
if ($rsi != 0 && ((ngx_chain_t *) $rsi)->buf != 0 && ((ngx_chain_t *) $rsi)->buf->last < ((ngx_chain_t *) $rsi)->buf->pos)
    set $c = (ngx_connection_t *) $rdi
    set $in = (ngx_chain_t *) $rsi
    set $b = $c->ssl->buf
    printf "SURVEY size=%ld dst_last=%p buf_start=%p buf_end=%p src=%p src_last=%p\n", $in->buf->last - $in->buf->pos, $b->last, $b->start, $b->end, $in->buf->pos, $in->buf->last
    set $sslend = (char *) $b->end
    set $dstlast = (char *) $b->last
    set $srcpos = (char *) $in->buf->pos
    printf "SSLCHUNK hdr=%p sizefield=%lu\n", (char *) $b->start - 0x10, *(unsigned long *)((char *) $b->start - 8)
    info proc mappings
    printf "PREDUMP begin\n"
    dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-survey-pre-follow.bin $sslend $sslend + 0x8000
    dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-survey-pre-src.bin $srcpos $srcpos + 0x8000
    printf "PREDUMP done (follow from %p, src from %p)\n", $sslend, $srcpos
end
continue
end

run
echo \n===STOP===\n
p $_siginfo
info registers rdi rsi rcx rdx rip r8 r9 r10 r11
x/12i $rip-32
dump binary memory /home/mesh-home/nginx2root/lab/tmp/x-survey-post-follow.bin $sslend $sslend + 0x8000
echo POSTDUMP done\n
bt 6
