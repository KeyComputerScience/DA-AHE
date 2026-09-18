#include "hmac_sha3.h"
#include "fips202.h"
#include <string.h>

#define SHA3_BLOCK 136u

void
da_hmac_sha3_256(const uint8_t *key, size_t key_len,
                 const uint8_t *message, size_t message_len,
                 uint8_t output[32])
{
  uint8_t key_block[SHA3_BLOCK];
  uint8_t inner_digest[32];
  uint8_t hashed_key[32];
  sha3_256incctx context;
  size_t i;
  memset(key_block, 0, sizeof(key_block));
  if(key_len > SHA3_BLOCK) {
    sha3_256(hashed_key, key, key_len);
    key = hashed_key;
    key_len = sizeof(hashed_key);
  }
  memcpy(key_block, key, key_len);
  for(i = 0; i < sizeof(key_block); i++) {
    key_block[i] ^= 0x36;
  }
  sha3_256_inc_init(&context);
  sha3_256_inc_absorb(&context, key_block, sizeof(key_block));
  sha3_256_inc_absorb(&context, message, message_len);
  sha3_256_inc_finalize(inner_digest, &context);
  for(i = 0; i < sizeof(key_block); i++) {
    key_block[i] ^= 0x36 ^ 0x5c;
  }
  sha3_256_inc_init(&context);
  sha3_256_inc_absorb(&context, key_block, sizeof(key_block));
  sha3_256_inc_absorb(&context, inner_digest, sizeof(inner_digest));
  sha3_256_inc_finalize(output, &context);
}
