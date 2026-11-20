set pagination off
set confirm off
set follow-fork-mode child

# connection WINDOW_UPDATE credit (also the W1 setup snapshot)
break ngx_http_v2.c:2575
commands
silent
printf "CONNWU inc=%lu send_window(pre)=%lu\n", window, h2c->send_window
continue
end

# PING marker: snapshot connection window without mutating it
break ngx_http_v2_state_ping
commands
silent
printf "PINGMARK send_window=%lu\n", h2c->send_window
continue
end

# RST_STREAM: stream located, before the switch. NB stream->queued is
# optimized out at -O1 here; the sid comes from the parse state instead.
break ngx_http_v2.c:2184
commands
silent
printf "RST sid=%lu send_window=%lu\n", h2c->state.sid, h2c->send_window
continue
end

# close_stream entry: shows the queued!=0 postponement dance
break ngx_http_v2.c:4704
commands
silent
printf "CLOSE sid=%lu queued=%lu\n", stream->node->id, stream->queued
continue
end

# queue-time charge site (per DATA frame)
break ngx_http_v2_filter_module.c:1241
commands
silent
printf "CHARGE sid=%lu frame_size=%lu send_window(pre)=%lu\n", stream->node->id, frame_size, h2c->send_window
continue
end

# the refund credit (site 6). At -O1 `window` and the `data` argument are
# dead/unreliable here, so print only the pre-add send_window; each refund's
# size is the delta to the next observed event (next REFUND or a marker).
break ngx_http_v2_filter_module.c:1767
commands
silent
printf "REFUND send_window(pre)=%lu\n", h2c->send_window
continue
end

run
