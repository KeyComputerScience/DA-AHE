/* SPDX-License-Identifier: MIT */
#ifndef DAAHE_CORE_H
#define DAAHE_CORE_H
#include <stddef.h>
#include <stdint.h>

#define DAAHE_D 256u
#define DAAHE_K 3u
#define DAAHE_P 65537u
#define DAAHE_CIPHER_BYTES 4096u
#define DAAHE_TAG_DIM 16u

/* No heap; all input/output storage is caller owned and must not overlap. */
void daahe_ring_mul(uint32_t out[DAAHE_D], const uint32_t a[DAAHE_D],
                    const uint32_t b[DAAHE_D]);
int daahe_pack(uint32_t out[DAAHE_D], const int32_t *data, size_t length,
              const uint32_t tag[DAAHE_TAG_DIM], uint32_t bx, uint32_t batch_size);
void daahe_linear_tag(uint32_t out[DAAHE_TAG_DIM], const uint32_t *matrix,
                      const uint32_t *data, size_t length,
                      const uint32_t offset[DAAHE_TAG_DIM]);
uint32_t daahe_decode_word(uint32_t v_minus_su);

/* Callback must authenticate ticket digest, source, nonce, j, J and bytes using
 * the exact wire framing documented by the host. Return 1 only on successful
 * signature/profile/roster/block authentication. It runs before accumulator write.
 * Authentication implementations and transport are external vetted dependencies. */
typedef int (*daahe_verify_block_fn)(void *context, size_t source_index,
                                    size_t block_index, size_t block_count,
                                    const uint8_t *payload, size_t payload_len,
                                    const uint8_t mac[16]);
typedef struct {
    uint8_t *accumulator;
    size_t ciphertext_bytes;
    size_t roster_size;
    size_t source_index;
    size_t block_index;
    size_t block_bytes;
    int poisoned;
} daahe_stream;

int daahe_stream_init(daahe_stream *stream, uint8_t *accumulator, size_t capacity,
                     size_t ciphertext_bytes, size_t roster_size, size_t block_bytes);
int daahe_stream_push(daahe_stream *stream, size_t source_index, size_t block_index,
                     size_t block_count, const uint8_t *payload, size_t length,
                     const uint8_t mac[16], daahe_verify_block_fn verify, void *context);
/* Returns 1 only for the complete exact roster; failure means discard whole batch. */
int daahe_stream_finish(const daahe_stream *stream);
void daahe_wipe(void *ptr, size_t bytes);
#endif

