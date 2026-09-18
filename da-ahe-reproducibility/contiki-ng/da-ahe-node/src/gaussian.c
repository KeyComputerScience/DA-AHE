#include "gaussian.h"
#include "fips202.h"
#include <string.h>

/* Generated from P(X=x) proportional to exp(-x^2/(2 sigma^2)). */
static const uint32_t cdf[3][20] = {
  {535451265u, 1555319721u, 2436220114u, 3126297630u, 3616592536u,
   3932533045u, 4117179798u, 4215053602u, 4262105775u, 4282621239u,
   4290734051u, 4293643763u, 4294590254u, 4294869491u, 4294944207u,
   4294962340u, 4294966330u, 4294967127u, 4294967271u, 0xffffffffu},
  {503954136u, 1469197103u, 2316977862u, 2999885136u, 3504396781u,
   3846228158u, 4058642544u, 4179698790u, 4242972274u, 4273303333u,
   4286638077u, 4292014743u, 4294003000u, 4294677317u, 4294887059u,
   4294946892u, 4294962545u, 4294966302u, 4294967128u, 0xffffffffu},
  {475956706u, 1391844471u, 2207631306u, 2880299279u, 3393768520u,
   3756610674u, 3993972386u, 4137717542u, 4218304616u, 4260128773u,
   4280223338u, 4289160912u, 4292840933u, 4294243652u, 4294738624u,
   4294900313u, 4294949208u, 4294962896u, 4294966444u, 0xffffffffu}
};

static uint32_t
load32(const uint8_t in[4])
{
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
         ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

void
da_gaussian_sample(const uint8_t seed[32], uint8_t sigma_index,
                   int16_t *output, size_t count)
{
  uint8_t input[36];
  uint8_t bytes[64];
  uint32_t counter = 0;
  size_t produced = 0;
  if(sigma_index > 2) {
    sigma_index = 0;
  }
  memcpy(input, seed, 32);
  while(produced < count) {
    size_t offset;
    input[32] = (uint8_t)counter;
    input[33] = (uint8_t)(counter >> 8);
    input[34] = (uint8_t)(counter >> 16);
    input[35] = (uint8_t)(counter >> 24);
    shake256(bytes, sizeof(bytes), input, sizeof(input));
    counter++;
    for(offset = 0; offset + 8 <= sizeof(bytes) && produced < count; offset += 8) {
      uint32_t uniform = load32(bytes + offset);
      uint32_t sign = load32(bytes + offset + 4) & 1u;
      uint16_t magnitude = 0;
      while(magnitude < 19 && uniform > cdf[sigma_index][magnitude]) {
        magnitude++;
      }
      output[produced++] = (int16_t)(sign && magnitude ? -(int16_t)magnitude : magnitude);
    }
  }
}
