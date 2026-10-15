/* SPDX-License-Identifier: MIT */
#ifndef DAAHE_CORE_H
#define DAAHE_CORE_H
#include <stddef.h>
#include <stdint.h>

#define DAAHE_D 256u
#ifndef DAAHE_K
/* Legacy default only. A selected build must pass the calibrated module rank. */
#define DAAHE_K 3u
#endif
#if DAAHE_K < 3 || DAAHE_K > 16
#error "DAAHE_K must be between 3 and 16"
#endif
#define DAAHE_P 65537u
#define DAAHE_CIPHER_BYTES ((DAAHE_K + 1u) * DAAHE_D * 4u)
#define DAAHE_TAG_DIM 16u

/* No heap; all input/output storage is caller owned and must not overlap. */
void daahe_ring_mul(uint32_t out[DAAHE_D], const uint32_t a[DAAHE_D],
                    const uint32_t b[DAAHE_D]);
int daahe_pack(uint32_t out[DAAHE_D], const int32_t *data, size_t length,
              const uint32_t tag[DAAHE_TAG_DIM], uint32_t bx, uint32_t batch_size);
void daahe_linear_tag(uint32_t out[DAAHE_TAG_DIM], const uint32_t *matrix,
                      const uint32_t *data, size_t length,
                      const uint32_t offset[DAAHE_TAG_DIM]);
/* The compatibility function above reads 16*length uint32_t matrix words:
 * L=240 requires 15,360 bytes if materialized in SRAM. Prefer the streaming
 * callback below when the complete K matrix cannot fit the workspace budget.
 * A provider derives consecutive canonical F_p elements from the exact host
 * KDF/rejection stream; it must return 1 and set *value on success. The callback
 * is invoked in row-major order. KDF state and scratch remain caller owned. */
typedef int (*daahe_matrix_element_fn)(void *context, size_t row, size_t column,
                                       uint32_t *value);
/* Writes out only after all matrix elements validate; on failure wipes out.
 * This computes the tag with 16 words of internal scratch, not a full matrix.
 * It does not supply SHAKE, source offsets, provisioning, or a memory certificate. */
int daahe_linear_tag_stream(uint32_t out[DAAHE_TAG_DIM], const uint32_t *data,
                            size_t length, const uint32_t offset[DAAHE_TAG_DIM],
                            daahe_matrix_element_fn next_element, void *context);
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
/* ciphertext_bytes must be DAAHE_CIPHER_BYTES or twice that size for a raw
 * two-ciphertext report, always using this build's compiled module rank. */
int daahe_stream_push(daahe_stream *stream, size_t source_index, size_t block_index,
                     size_t block_count, const uint8_t *payload, size_t length,
                     const uint8_t mac[16], daahe_verify_block_fn verify, void *context);
/* Returns 1 only for the complete exact roster; failure means discard whole batch. */
int daahe_stream_finish(const daahe_stream *stream);
void daahe_wipe(void *ptr, size_t bytes);
#endif

