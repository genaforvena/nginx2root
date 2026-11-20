# gdb script for the UNSANITIZED rung-3 run: same breakpoints and force as
# gdb-x.cmd, but when the worker SIGSEGVs in the wrapped memcpy, `run`
# returns and gdb prints the backtrace before exiting.
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

break ngx_http_v2_filter_module.c:1308
commands
silent
if (size < 0)
    printf "SHADOW size=%ld pos=%p file_tag_in_memory=%d\n", size, chunk->pos, chunk->in_file
end
continue
end

break ngx_http_v2_filter_module.c:1241
commands
silent
printf "CHARGE sid=%lu frame_size=%lu send_window(pre)=%lu\n", stream->node->id, frame_size, h2c->send_window
continue
end

break ngx_http_v2_filter_module.c:1767
commands
silent
printf "REFUND send_window(pre)=%lu\n", h2c->send_window
continue
end

run
echo \n===STOP===\n
bt 10
