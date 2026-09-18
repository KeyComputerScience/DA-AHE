#include "da_ahe_params.h"
#include "db2.h"
#include "linear_auth.h"
#include "mlwe.h"
#include "test_vectors.h"
#include <stdio.h>

int
main(void)
{
  static int16_t raw[DA_RAW_CHANNELS][DA_SAMPLES_PER_CHANNEL];
  static int32_t coefficients[DA_DATA_SLOTS];
  static uint32_t tags[DA_TAG_SLOTS];
  static uint32_t message[DA_D];
  static uint32_t recovered[DA_D];
  static da_ciphertext_t ciphertext;
  uint8_t secret[32] = {0};
  uint8_t ticket[32] = {1};
  uint8_t label[32] = {2};
  uint8_t seed[32] = {3};
  uint16_t channel;
  uint16_t i;

  for(channel = 0; channel < DA_RAW_CHANNELS; channel++) {
    for(i = 0; i < DA_SAMPLES_PER_CHANNEL; i++) {
      raw[channel][i] = (int16_t)((i * (channel + 3)) % 401 - 200);
    }
  }
  da_db2_quantize(raw, &da_profiles[0], coefficients);
  da_linear_tags(secret, ticket, label, coefficients, tags);
  da_pack_codeword(coefficients, tags, message);
  da_mlwe_encrypt(&da_test_public_key, message, 0, seed, &ciphertext);
  da_mlwe_decrypt(&da_test_secret_key, &ciphertext, recovered);
  for(i = 0; i < DA_D; i++) {
    if(message[i] != recovered[i]) {
      fprintf(stderr, "M-LWE mismatch at %u: %u != %u\n",
              i, message[i], recovered[i]);
      return 1;
    }
  }
  printf("PASS protocol-smoke ciphertext_bytes=%zu\n", sizeof(ciphertext));
  return 0;
}
