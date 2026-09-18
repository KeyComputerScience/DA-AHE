#ifndef DA_MLWE_H_
#define DA_MLWE_H_

#include <stdint.h>
#include "da_ahe_params.h"

typedef struct {
  uint8_t matrix_seed[32];
  uint32_t b[DA_K][DA_D];
} da_public_key_t;

typedef struct {
  int16_t s[DA_K][DA_D];
} da_secret_key_t;

typedef struct {
  uint32_t words[DA_CT_WORDS];
} da_ciphertext_t;

void da_mlwe_encrypt(const da_public_key_t *pk, const uint32_t message[DA_D],
                     uint8_t sigma_index, const uint8_t seed[32],
                     da_ciphertext_t *ciphertext);
void da_mlwe_decrypt(const da_secret_key_t *sk, const da_ciphertext_t *ciphertext,
                     uint32_t message[DA_D]);
void da_mlwe_add(da_ciphertext_t *accumulator, const da_ciphertext_t *input);

#endif
