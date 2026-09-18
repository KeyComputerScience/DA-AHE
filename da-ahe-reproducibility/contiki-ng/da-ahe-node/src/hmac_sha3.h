#ifndef DA_HMAC_SHA3_H_
#define DA_HMAC_SHA3_H_

#include <stddef.h>
#include <stdint.h>

void da_hmac_sha3_256(const uint8_t *key, size_t key_len,
                      const uint8_t *message, size_t message_len,
                      uint8_t output[32]);

#endif
