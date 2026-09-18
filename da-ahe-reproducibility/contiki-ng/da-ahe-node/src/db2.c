#include "db2.h"

/* Orthonormal Db2 low-pass taps in Q15: h0,h1,h2,h3. */
static const int16_t h_q15[4] = {15826, 27411, 7345, -4240};

static int32_t
round_div(int32_t value, int32_t divisor)
{
  if(value >= 0) {
    return (value + divisor / 2) / divisor;
  }
  return -((-value + divisor / 2) / divisor);
}

void
da_db2_quantize(const int16_t input[DA_RAW_CHANNELS][DA_SAMPLES_PER_CHANNEL],
                const da_profile_t *profile,
                int32_t output[DA_DATA_SLOTS])
{
  uint16_t channel;
  uint16_t n;
  for(n = 0; n < DA_DATA_SLOTS; n++) {
    output[n] = 0;
  }
  for(channel = 0; channel < DA_RAW_CHANNELS; channel++) {
    for(n = 0; n < DA_SAMPLES_PER_CHANNEL / 2; n++) {
      int64_t acc = 0;
      uint16_t tap;
      uint16_t out_index = (uint16_t)(2u * n + channel);
      if(out_index >= profile->support) {
        continue;
      }
      for(tap = 0; tap < 4; tap++) {
        uint16_t index = (uint16_t)((2u * n + tap) % DA_SAMPLES_PER_CHANNEL);
        acc += (int32_t)h_q15[tap] * input[channel][index];
      }
      {
        int32_t coefficient = (int32_t)((acc + (acc >= 0 ? 16384 : -16384)) >> 15);
        int32_t quantized = round_div(coefficient, profile->quant_step);
        if(quantized > profile->coefficient_bound) {
          quantized = profile->coefficient_bound;
        } else if(quantized < -(int32_t)profile->coefficient_bound) {
          quantized = -(int32_t)profile->coefficient_bound;
        }
        output[out_index] = quantized;
      }
    }
  }
}
