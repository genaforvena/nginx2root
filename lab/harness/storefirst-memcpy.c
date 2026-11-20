/* Stage-A-mechanics synthetic memcpy (owner directive #47, 2026-11-20).
 *
 * PURPOSE: interpose the wrapped ~2^63-byte memcpy that the over-credited
 * ledger drives in ngx_ssl_send_chain (ngx_event_openssl.c:3150, nginx
 * 1.31.8) with a NAIVE STORE-FIRST forward copy, to exercise the heap
 * mechanics (source bytes written past the 16 KiB SSL buffer) that the
 * stock glibc path never performs: on this host (glibc 2.39, AVX2) the
 * stock memcpy faults on its second access — a tail-VEC load from the
 * wrapped non-canonical `src + n - 0x20` — writing nothing (see the
 * report's "Stage-A survey").
 *
 * LABEL: SYNTHETIC, mechanics-only. All lengths < 2^40 are delegated to
 * the real glibc memcpy; only a pathological wrapped length takes the
 * store-first loop. Nothing about any stock build may be claimed from
 * behavior under this shim; the stock-glibc result stands unwalled.
 *
 * Build: cc -O0 -g -shared -fPIC -o storefirst-memcpy.so \
 *          storefirst-memcpy.c -ldl
 * Use:   LD_PRELOAD=/abs/path/storefirst-memcpy.so
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <dlfcn.h>

/* Fault-context readout: how many bytes the store-first loop had
 * written when it faulted (updated per 4 KiB), plus the call geometry. */
volatile unsigned long  g_mech_bytes;
void * volatile        g_mech_dst;
const void * volatile  g_mech_src;
volatile unsigned long g_mech_n;

static void *(*real_memcpy)(void *, const void *, size_t);

__attribute__((constructor))
static void mech_init(void)
{
    real_memcpy = (void *(*)(void *, const void *, size_t))
                  dlsym(RTLD_NEXT, "memcpy");
}

/* Deliberately naive: load src[i], store dst[i], forward. No tail
 * prefetch, no backward copy, no rep movsb. This is the "progressive
 * forward overwrite" model that the stock glibc path falsified. */
static void *storefirst(void *dst, const void *src, size_t n)
{
    unsigned char       *d = dst;
    const unsigned char *s = src;

    g_mech_dst    = dst;
    g_mech_src    = src;
    g_mech_n      = (unsigned long) n;
    g_mech_bytes  = 0;

    for (size_t i = 0; i < n; i++) {
        unsigned char v = s[i];
        d[i] = v;
        if ((i & 0xfff) == 0xfff)
            g_mech_bytes = i + 1;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    if (n < ((size_t) 1 << 40)) {
        if (real_memcpy)
            return real_memcpy(dst, src, n);
        return storefirst(dst, src, n); /* pre-constructor bootstrap */
    }
    return storefirst(dst, src, n);
}

void *memmove(void *dst, const void *src, size_t n)
{
    return memcpy(dst, src, n);
}
