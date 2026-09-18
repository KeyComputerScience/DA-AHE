#include "mlwe.h"
#include "gaussian.h"
#include "fips202.h"
#include <string.h>

static int16_t small[DA_K][DA_D];
static int16_t error1[DA_K][DA_D];
static int16_t error2[DA_D];
static uint32_t polynomial[DA_D];
static int64_t convolution[DA_D];

static void
expand_a_poly(const uint8_t matrix_seed[32], uint8_t row, uint8_t column,
              uint32_t output[DA_D])
{
  uint8_t input[43];
  memcpy(input, "DA-AHE/A/", 9);
  memcpy(input + 9, matrix_seed, 32);
  input[41] = row;
  input[42] = column;
  shake256((uint8_t *)output, DA_D * sizeof(uint32_t), input, sizeof(input));
}

static void
multiply_add(const uint32_t a[DA_D], const int16_t b[DA_D], int reset)
{
  uint16_t i;
  uint16_t j;
  if(reset) {
    memset(convolution, 0, sizeof(convolution));
  }
  for(i = 0; i < DA_D; i++) {
    for(j = 0; j < DA_D; j++) {
      uint16_t degree = (uint16_t)(i + j);
      int64_t product = (int64_t)(uint64_t)a[i] * b[j];
      if(degree < DA_D) {
        convolution[degree] += product;
      } else {
        convolution[degree - DA_D] -= product;
      }
    }
  }
}

static int64_t
center_u32(uint32_t value)
{
  return value > 0x7fffffffu ? (int64_t)value - 0x100000000LL : value;
}

void
da_mlwe_encrypt(const da_public_key_t *pk, const uint32_t message[DA_D],
                uint8_t sigma_index, const uint8_t seed[32],
                da_ciphertext_t *ciphertext)
{
  uint8_t stream_seed[32];
  uint16_t i;
  uint16_t row;
  uint16_t column;

  memcpy(stream_seed, seed, 32);
  da_gaussian_sample(stream_seed, sigma_index, &small[0][0], DA_K * DA_D);
  stream_seed[0] ^= 0x51;
  da_gaussian_sample(stream_seed, sigma_index, &error1[0][0], DA_K * DA_D);
  stream_seed[0] ^= 0xa3;
  da_gaussian_sample(stream_seed, sigma_index, error2, DA_D);

  for(column = 0; column < DA_K; column++) {
    for(row = 0; row < DA_K; row++) {
      expand_a_poly(pk->matrix_seed, row, column, polynomial);
      multiply_add(polynomial, small[row], row == 0);
    }
    for(i = 0; i < DA_D; i++) {
      ciphertext->words[column * DA_D + i] =
        (uint32_t)(convolution[i] + error1[column][i]);
    }
  }

  for(row = 0; row < DA_K; row++) {
    multiply_add(pk->b[row], small[row], row == 0);
  }
  for(i = 0; i < DA_D; i++) {
    int64_t centered_message = message[i] > DA_P / 2 ?
      (int64_t)message[i] - DA_P : message[i];
    ciphertext->words[DA_K * DA_D + i] =
      (uint32_t)(convolution[i] + error2[i] + DA_DELTA * centered_message);
  }
}

void
da_mlwe_decrypt(const da_secret_key_t *sk, const da_ciphertext_t *ciphertext,
                uint32_t message[DA_D])
{
  uint16_t row;
  uint16_t i;
  for(row = 0; row < DA_K; row++) {
    multiply_add(ciphertext->words + row * DA_D, sk->s[row], row == 0);
  }
  for(i = 0; i < DA_D; i++) {
    int64_t phase = center_u32(ciphertext->words[DA_K * DA_D + i] -
                               (uint32_t)convolution[i]);
    int64_t decoded = phase >= 0 ?
      (phase + DA_DELTA / 2) / DA_DELTA :
      -((-phase + DA_DELTA / 2) / DA_DELTA);
    decoded %= DA_P;
    if(decoded < 0) {
      decoded += DA_P;
    }
    message[i] = (uint32_t)decoded;
  }
}

void
da_mlwe_add(da_ciphertext_t *accumulator, const da_ciphertext_t *input)
{
  uint16_t i;
  for(i = 0; i < DA_CT_WORDS; i++) {
    accumulator->words[i] += input->words[i];
  }
}
