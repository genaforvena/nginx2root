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

# PING marker: snapshot connection window
break ngx_http_v2_state_ping
commands
silent
printf "PINGMARK send_window=%lu\n", h2c->send_window
continue
end

# queue-time charge site (per DATA frame)
break ngx_http_v2_filter_module.c:1241
commands
silent
printf "CHARGE sid=%lu frame_size=%lu send_window(pre)=%lu\n", stream->node->id, frame_size, h2c->send_window
continue
end

# the unguarded refund credit (site 6); `window` is dead at -O1 here,
# take the delta to the next event. NB the signature moment is a REFUND
# that lands when send_window is already back at/near MAX.
break ngx_http_v2_filter_module.c:1767
commands
silent
printf "REFUND send_window(pre)=%lu\n", h2c->send_window
continue
end

run
