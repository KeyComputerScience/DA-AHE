/* SPDX-License-Identifier: MIT */
#include "daahe_core.h"
#include <string.h>

void daahe_wipe(void *ptr, size_t bytes) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (bytes--) *p++ = 0;
}

void daahe_ring_mul(uint32_t out[DAAHE_D], const uint32_t a[DAAHE_D],
                    const uint32_t b[DAAHE_D]) {
    size_t i, j, index;
    uint32_t product;
    memset(out, 0, DAAHE_D * sizeof(*out));
    for (i = 0; i < DAAHE_D; ++i) {
        for (j = 0; j < DAAHE_D; ++j) {
            index = i + j;
            product = (uint32_t)((uint64_t)a[i] * (uint64_t)b[j]);
            if (index < DAAHE_D) out[index] += product;
            else out[index - DAAHE_D] -= product;
        }
    }
}

int daahe_pack(uint32_t out[DAAHE_D], const int32_t *data, size_t length,
              const uint32_t tag[DAAHE_TAG_DIM], uint32_t bx, uint32_t batch_size) {
    size_t i;
    int64_t value;
    if (!out || !data || !tag || length == 0 || length > 240 || bx == 0 ||
        batch_size == 0 || (uint64_t)bx * batch_size > (DAAHE_P - 1) / 2) return 0;
    for (i = 0; i < length; ++i) {
        value = data[i];
        if (value < -(int64_t)bx || value > (int64_t)bx) return 0;
    }
    for (i = 0; i < DAAHE_TAG_DIM; ++i) if (tag[i] >= DAAHE_P) return 0;
    memset(out, 0, DAAHE_D * sizeof(*out));
    for (i = 0; i < length; ++i)
        out[i] = data[i] < 0 ? (uint32_t)((int64_t)DAAHE_P + data[i]) : (uint32_t)data[i];
    for (i = 0; i < DAAHE_TAG_DIM; ++i) out[length + i] = tag[i];
    return 1;
}

void daahe_linear_tag(uint32_t out[DAAHE_TAG_DIM], const uint32_t *matrix,
                      const uint32_t *data, size_t length,
                      const uint32_t offset[DAAHE_TAG_DIM]) {
    size_t row, col;
    uint64_t sum;
    for (row = 0; row < DAAHE_TAG_DIM; ++row) {
        sum = offset[row] % DAAHE_P;
        for (col = 0; col < length; ++col) {
            sum += (uint64_t)(matrix[row * length + col] % DAAHE_P) * (data[col] % DAAHE_P);
            sum %= DAAHE_P;
        }
        out[row] = (uint32_t)sum;
    }
}

int daahe_linear_tag_stream(uint32_t out[DAAHE_TAG_DIM], const uint32_t *data,
                            size_t length, const uint32_t offset[DAAHE_TAG_DIM],
                            daahe_matrix_element_fn next_element, void *context) {
    size_t row, col;
    uint32_t element, partial[DAAHE_TAG_DIM];
    uint64_t sum;
    if (!out) return 0;
    if (!data || !offset || !next_element || length == 0 || length > 480) {
        daahe_wipe(out, DAAHE_TAG_DIM * sizeof(*out));
        return 0;
    }
    for (col = 0; col < length; ++col) {
        if (data[col] >= DAAHE_P) {
            daahe_wipe(out, DAAHE_TAG_DIM * sizeof(*out));
            return 0;
        }
    }
    for (row = 0; row < DAAHE_TAG_DIM; ++row) {
        if (offset[row] >= DAAHE_P) goto reject;
        sum = offset[row];
        for (col = 0; col < length; ++col) {
            if (next_element(context, row, col, &element) != 1 || element >= DAAHE_P)
                goto reject;
            sum = (sum + (uint64_t)element * data[col]) % DAAHE_P;
        }
        partial[row] = (uint32_t)sum;
    }
    memcpy(out, partial, sizeof(partial));
    daahe_wipe(partial, sizeof(partial));
    return 1;
reject:
    daahe_wipe(partial, sizeof(partial));
    daahe_wipe(out, DAAHE_TAG_DIM * sizeof(*out));
    return 0;
}

uint32_t daahe_decode_word(uint32_t word) {
    /* q/p floor = 65535. Ties round away from zero, matching the host. */
    int64_t centered = word <= UINT32_C(2147483647) ? (int64_t)word : (int64_t)word - INT64_C(4294967296);
    int64_t rounded = centered >= 0 ? (centered + 32767) / 65535 : -((-centered + 32767) / 65535);
    int64_t reduced = rounded % DAAHE_P;
    return (uint32_t)(reduced < 0 ? reduced + DAAHE_P : reduced);
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int daahe_stream_init(daahe_stream *s, uint8_t *acc, size_t capacity,
                     size_t ciphertext_bytes, size_t roster_size, size_t block_bytes) {
    if (!s || !acc || capacity < ciphertext_bytes || roster_size == 0 || roster_size > 16 ||
        (ciphertext_bytes != DAAHE_CIPHER_BYTES && ciphertext_bytes != 2u * DAAHE_CIPHER_BYTES) ||
        (block_bytes != 32 && block_bytes != 64)) return 0;
    memset(acc, 0, ciphertext_bytes);
    s->accumulator = acc; s->ciphertext_bytes = ciphertext_bytes;
    s->roster_size = roster_size; s->source_index = 0; s->block_index = 0;
    s->block_bytes = block_bytes; s->poisoned = 0;
    return 1;
}

int daahe_stream_push(daahe_stream *s, size_t source, size_t block, size_t count,
                     const uint8_t *payload, size_t length, const uint8_t mac[16],
                     daahe_verify_block_fn verify, void *context) {
    size_t offset, i;
    uint32_t sum;
    if (!s || s->poisoned) return 0;
    if (!payload || !mac || !verify || source != s->source_index || block != s->block_index ||
        source >= s->roster_size || length != s->block_bytes ||
        count != s->ciphertext_bytes / s->block_bytes || block >= count ||
        verify(context, source, block, count, payload, length, mac) != 1) {
        s->poisoned = 1;
        daahe_wipe(s->accumulator, s->ciphertext_bytes);
        return 0;
    }
    offset = block * length;
    for (i = 0; i < length; i += 4) {
        sum = read_le32(s->accumulator + offset + i) + read_le32(payload + i);
        write_le32(s->accumulator + offset + i, sum);
    }
    if (++s->block_index == count) {
        s->block_index = 0; ++s->source_index;
    }
    return 1;
}

int daahe_stream_finish(const daahe_stream *s) {
    return s && !s->poisoned && s->source_index == s->roster_size && s->block_index == 0;
}

