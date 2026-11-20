set pagination off
set confirm off
set follow-fork-mode child

# connection WINDOW_UPDATE credit (shows every accepted increment)
break ngx_http_v2.c:2575
commands
silent
printf "CONNWU inc=%lu send_window(pre)=%lu\n", window, h2c->send_window
continue
end

# PING marker: snapshot the connection window; at the mkX0ping marker force
# h2c->send_window = 2^63 + 2^32 (the wire path would need ~2^32 more
# max-size WUs after the phase-C underflow to land here).
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

# the queue-time limit wrap: frame_size = (size_t) limit (filter:1165).
# limit is live here (used on this line and at the loop tail).
break ngx_http_v2_filter_module.c:1165
commands
silent
printf "LIMITWRAP limit=%ld frame_size=%lu send_window=%lu\n", limit, frame_size, h2c->send_window
continue
end
# the bogus shadow buf, in-memory branch (over TLS the copy filter turns
# static-file bufs into memory bufs, so the 1307-1308 branch runs, not the
# in_file one at 1311-1313). chunk->last = chunk->pos + size with the
# wrapped (negative) size on this exact line.
break ngx_http_v2_filter_module.c:1308
commands
silent
if (size < 0)
    printf "SHADOW size=%ld pos=%p file_tag_in_memory=%d\n", size, chunk->pos, chunk->in_file
end
continue
end

# the consuming memcpy: ngx_memcpy(buf->last, in->buf->pos, size) with the
# wrapped negative size (signed cap at 3139/3143 skips, memcpy converts
# back to a huge size_t).
break ngx_event_openssl.c:3150
commands
silent
if (size < 0)
    printf "SSLMEMCPY size=%ld dst=%p src=%p src_last_minus_pos=%ld\n", size, buf->last, in->buf->pos, in->buf->last - in->buf->pos
end
continue
end

break ngx_http_v2_filter_module.c:1241
commands
silent
printf "CHARGE sid=%lu frame_size=%lu send_window(pre)=%lu\n", stream->node->id, frame_size, h2c->send_window
continue
end

# the unguarded refund credit (site 6); size delta taken to the next event.
break ngx_http_v2_filter_module.c:1767
commands
silent
printf "REFUND send_window(pre)=%lu\n", h2c->send_window
continue
end

run
