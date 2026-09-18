#include "linear_auth.h"
#include "fips202.h"
#include <string.h>

static uint32_t
load32(const uint8_t in[4])
{
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
         ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static uint32_t
field_value(int32_t value)
{
  int64_t reduced = value % (int32_t)DA_P;
  if(reduced < 0) {
    reduced += DA_P;
  }
  return (uint32_t)reduced;
}

void
da_linear_tags(const uint8_t auth_secret[32],
               const uint8_t ticket_digest[32],
               const uint8_t label_digest[32],
               const int32_t data[DA_DATA_SLOTS],
               uint32_t tags[DA_TAG_SLOTS])
{
  uint8_t seed[98];
  uint8_t stream[4 * (DA_DATA_SLOTS + 8)];
  uint16_t row;
  memcpy(seed, "DA-AHE/K/", 9);
  memcpy(seed + 9, auth_secret, 32);
  memcpy(seed + 41, ticket_digest, 32);
  memcpy(seed + 73, label_digest, 24);
  for(row = 0; row < DA_TAG_SLOTS; row++) {
    uint16_t column = 0;
    uint16_t cursor = 0;
    uint64_t accumulator = field_value((int32_t)load32(label_digest + (row % 8) * 4));
    seed[97] = (uint8_t)row;
    shake256(stream, sizeof(stream), seed, sizeof(seed));
    while(column < DA_DATA_SLOTS) {
      uint32_t candidate = load32(stream + cursor);
      cursor += 4;
      if(candidate == 0xffffffffu) {
        continue;
      }
      accumulator += (uint64_t)(candidate % DA_P) * field_value(data[column]);
      accumulator %= DA_P;
      column++;
    }
    tags[row] = (uint32_t)accumulator;
  }
}

void
da_pack_codeword(const int32_t data[DA_DATA_SLOTS],
                 const uint32_t tags[DA_TAG_SLOTS],
                 uint32_t message[DA_D])
{
  uint16_t i;
  for(i = 0; i < DA_DATA_SLOTS; i++) {
    message[i] = field_value(data[i]);
  }
  for(i = 0; i < DA_TAG_SLOTS; i++) {
    message[DA_DATA_SLOTS + i] = tags[i] % DA_P;
  }
}
