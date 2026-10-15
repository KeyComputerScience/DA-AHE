/* SPDX-License-Identifier: MIT */
/* Independent core MICROBENCHMARK, never full DA-AHE/Contiki firmware. */
#include "daahe_core.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef FIRMWARE_BUILD_ID
#error "Use firmware/build.py to bind source/config/compiler identity"
#endif
#ifndef BENCH_REPEATS
#define BENCH_REPEATS 20u
#endif
#ifndef BENCH_CIPHER_BYTES
#error "Use firmware/build.py to bind the compiled ciphertext byte size"
#endif
_Static_assert(DAAHE_CIPHER_BYTES == BENCH_CIPHER_BYTES, "rank/ciphertext size mismatch");
#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)
#define REG(addr) (*(volatile uint32_t *)(uintptr_t)(addr))
#define DWT_CTRL REG(0xe0001000u)
#define DWT_CYCCNT REG(0xe0001004u)
#define DEMCR REG(0xe000edfcu)
#define UART(off) REG(0x40002000u + (off))
#define TIMER(off) REG(0x40009000u + (off))
#define STACK_BYTES 8192u
#define STACK_GUARD 32u
#define CANARY 0xa5u

static uint8_t bench_stack[STACK_BYTES] __attribute__((aligned(8)));
static uint32_t ring_a[256], ring_b[256], packed[256];
static uint32_t data[240], tag[16], offset[16];
static int32_t signed_data[240];
static uint8_t accumulator[DAAHE_CIPHER_BYTES], block_payload[64], mac_placeholder[16];
static daahe_stream stream;
static volatile uint32_t elapsed_cycles, elapsed_us, measured_ok, selected_operation;
static const char *const operations[] = {
    "empty_harness", "ring_mul_d256", "pack_l240",
    "linear_tag_l240_fixture_provider", "decode_d256",
    "stream_16x" STRINGIFY(BENCH_CIPHER_BYTES) "_b64_fixture_callback"
};
extern void bench_on_stack(void (*function)(void), void *stack_top);

static inline void barrier(void) { __asm volatile("dsb\nisb" ::: "memory"); }
static uint32_t timer_us(void) {
    TIMER(0x040u) = 1; /* TASKS_CAPTURE[0] */
    return TIMER(0x540u); /* CC[0] */
}
static void uart_init(void) {
    /* nRF52840 DK virtual COM: P0.06 TX, P0.08 RX. TX-only, no flow control. */
    REG(0x50000508u) = 1u << 6; /* GPIO OUTSET: idle high */
    REG(0x50000718u) = 3u; /* P0.06 output, input buffer disconnected */
    UART(0x500u) = 0;
    UART(0x508u) = UINT32_MAX; /* RTS disconnected */
    UART(0x50cu) = 6u;
    UART(0x510u) = UINT32_MAX; /* CTS disconnected */
    UART(0x514u) = UINT32_MAX; /* RX disconnected */
    UART(0x524u) = 0x01d7e000u; /* nominal 115200, actual 115942 */
    UART(0x56cu) = 0;
    UART(0x500u) = 4u; /* legacy UART mode, not UARTE */
    UART(0x008u) = 1u;
}
static void putc_uart(char value) {
    UART(0x11cu) = 0;
    UART(0x51cu) = (uint32_t)(unsigned char)value;
    while (!UART(0x11cu)) { }
}
static void puts_uart(const char *s) { while (*s) putc_uart(*s++); }
static void uint_uart(uint32_t value) {
    char digits[10];
    unsigned n = 0;
    do { digits[n++] = (char)('0' + value % 10u); value /= 10u; } while (value);
    while (n) putc_uart(digits[--n]);
}
static void bool_uart(uint32_t value) { puts_uart(value ? "true" : "false"); }
static void parameters_uart(void) {
    puts_uart("{\"module_rank\":"); uint_uart(DAAHE_K);
    puts_uart(",\"ring_degree\":"); uint_uart(DAAHE_D);
    puts_uart(",\"plaintext_modulus\":"); uint_uart(DAAHE_P);
    puts_uart(",\"ciphertext_modulus\":4294967296,\"ciphertext_bytes\":");
    uint_uart(DAAHE_CIPHER_BYTES);
    puts_uart(",\"ciphertexts_per_stream\":1,\"stream_roster_size\":16,\"stream_block_bytes\":64}");
}
static void sample_prefix(uint32_t seq) {
    puts_uart("{\"schema_version\":2,\"record\":\"sample\",\"firmware_id\":\"");
    puts_uart(FIRMWARE_BUILD_ID);
    puts_uart("\",\"seq\":"); uint_uart(seq);
}
static int fixture_matrix(void *ctx, size_t row, size_t col, uint32_t *value) {
    (void)ctx;
    *value = (uint32_t)((row + 1u) * (col + 1u));
    return 1; /* Arithmetic fixture: no SHAKE/KDF/provisioning work. */
}
static int fixture_accept(void *ctx, size_t source, size_t block, size_t count,
                          const uint8_t *payload, size_t length, const uint8_t mac[16]) {
    (void)ctx; (void)source; (void)block; (void)count;
    (void)payload; (void)length; (void)mac;
    return 1; /* Deliberate test double: NOT HMAC/signature authentication. */
}
static void initialize_fixtures(void) {
    size_t i;
    ring_a[255] = 1; ring_b[1] = 1;
    for (i = 0; i < 240; ++i) { signed_data[i] = 1; data[i] = 1; }
    for (i = 0; i < 16; ++i) offset[i] = (uint32_t)i;
    for (i = 0; i < 64; i += 4) block_payload[i] = 1;
}
static void timed_wrapper(void) {
    uint32_t start, begin_us;
    size_t i, source, block;
    measured_ok = 1;
    begin_us = timer_us();
    barrier(); start = DWT_CYCCNT; barrier();
    switch (selected_operation) {
    case 0: __asm volatile("" ::: "memory"); break;
    case 1:
        daahe_ring_mul(packed, ring_a, ring_b);
        break;
    case 2:
        measured_ok = (uint32_t)daahe_pack(packed, signed_data, 240, tag, 2048, 16);
        break;
    case 3:
        measured_ok = (uint32_t)daahe_linear_tag_stream(tag, data, 240, offset,
                                                       fixture_matrix, NULL);
        break;
    case 4:
        for (i = 0; i < 256; ++i) packed[i] = daahe_decode_word(65535u);
        break;
    case 5:
        measured_ok = (uint32_t)daahe_stream_init(&stream, accumulator, sizeof accumulator,
                                                  DAAHE_CIPHER_BYTES, 16, 64);
        for (source = 0; source < 16; ++source)
            for (block = 0; block < DAAHE_CIPHER_BYTES / 64u; ++block)
                measured_ok &= (uint32_t)daahe_stream_push(&stream, source, block, DAAHE_CIPHER_BYTES / 64u,
                    block_payload, 64, mac_placeholder, fixture_accept, NULL);
        measured_ok &= (uint32_t)daahe_stream_finish(&stream);
        break;
    default: measured_ok = 0;
    }
    barrier(); elapsed_cycles = DWT_CYCCNT - start; barrier();
    elapsed_us = timer_us() - begin_us;
    /* Correctness checks are outside the cycle interval but on the same PSP. */
    if (selected_operation == 1) {
        measured_ok &= packed[0] == UINT32_MAX;
        for (i = 1; i < 256; ++i) measured_ok &= packed[i] == 0;
    } else if (selected_operation == 2) {
        for (i = 0; i < 240; ++i) measured_ok &= packed[i] == 1;
        for (i = 0; i < 16; ++i) measured_ok &= packed[240+i] == tag[i];
    } else if (selected_operation == 3) {
        for (i = 0; i < 16; ++i)
            measured_ok &= tag[i] == (uint32_t)(((i+1u)*28920u + i) % 65537u);
    } else if (selected_operation == 4) {
        for (i = 0; i < 256; ++i) measured_ok &= packed[i] == 1;
    } else if (selected_operation == 5) {
        for (i = 0; i < DAAHE_CIPHER_BYTES; i += 4)
            measured_ok &= accumulator[i] == 16 && accumulator[i+1] == 0 &&
                           accumulator[i+2] == 0 && accumulator[i+3] == 0;
    }
}
int main(void) {
    uint32_t op, repeat, seq = 0, failures = 0, untouched, guard_ok;
    DEMCR |= (1u << 24); DWT_CYCCNT = 0; DWT_CTRL |= 1u;
    TIMER(0x004u) = 1; /* STOP */
    TIMER(0x504u) = 0; TIMER(0x508u) = 3; TIMER(0x510u) = 4; /* 32-bit, 1 MHz */
    TIMER(0x00cu) = 1; TIMER(0x000u) = 1; /* CLEAR, START */
    uart_init(); initialize_fixtures();
    /* Give an already-open collector time to observe a manually reset target. */
    { uint32_t initial = timer_us(); while (timer_us() - initial < 1000000u) { } }
    puts_uart("{\"schema_version\":2,\"record\":\"boot\",\"firmware_id\":\"");
    puts_uart(FIRMWARE_BUILD_ID);
    puts_uart("\",\"target\":\"nrf52840\",\"clock_hz\":64000000,\"repeats\":");
    uint_uart(BENCH_REPEATS);
    puts_uart(",\"scope\":\"embedded_core_microbenchmarks\",\"stack_capacity_bytes\":8192,\"parameters\":");
    parameters_uart(); puts_uart("}\n");
    puts_uart("{\"schema_version\":2,\"record\":\"capabilities\",\"supported\":[");
    for (op = 0; op < 6; ++op) {
        if (op) putc_uart(',');
        putc_uart('"'); puts_uart(operations[op]); putc_uart('"');
    }
    puts_uart("],\"unsupported\":[\"mlwe_keygen_encrypt_decrypt\",\"mldsa44\",\"hmac_sha3\",\"shake_kdf\",\"intdb2\",\"network_radio\",\"energy\",\"full_protocol\",\"contiki_ng\"],\"parameters\":");
    parameters_uart(); puts_uart("}\n");
    for (op = 0; op < 6; ++op) {
        selected_operation = op;
        for (repeat = 0; repeat < BENCH_REPEATS; ++repeat) {
            memset(bench_stack, CANARY, sizeof bench_stack);
            bench_on_stack(timed_wrapper, bench_stack + sizeof bench_stack);
            for (untouched = 0; untouched < STACK_BYTES && bench_stack[untouched] == CANARY;
                 ++untouched) { }
            guard_ok = untouched >= STACK_GUARD;
            /* Independent 1-MHz timer constrains DWT wrap (67.1 s at 64 MHz). */
            measured_ok &= elapsed_cycles > 0 && elapsed_us < 60000000u;
            if (!measured_ok || !guard_ok) ++failures;
            sample_prefix(seq++);
            puts_uart(",\"operation\":\""); puts_uart(operations[op]);
            puts_uart("\",\"repeat\":"); uint_uart(repeat);
            puts_uart(",\"cycles\":"); uint_uart(elapsed_cycles);
            puts_uart(",\"elapsed_us\":"); uint_uart(elapsed_us);
            puts_uart(",\"stack_hwm_bytes\":"); uint_uart(STACK_BYTES - untouched);
            puts_uart(",\"stack_guard_ok\":"); bool_uart(guard_ok);
            puts_uart(",\"result_ok\":"); bool_uart(measured_ok);
            puts_uart(",\"irq_disabled\":true}\n");
        }
    }
    puts_uart("{\"schema_version\":2,\"record\":\"complete\",\"samples\":");
    uint_uart(seq); puts_uart(",\"failures\":"); uint_uart(failures); puts_uart("}\n");
    for (;;) __asm volatile("wfi");
}
