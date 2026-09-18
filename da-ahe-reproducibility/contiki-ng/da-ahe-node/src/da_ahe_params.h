#ifndef DA_AHE_PARAMS_H_
#define DA_AHE_PARAMS_H_

#include <stdint.h>

#define DA_D 256u
#define DA_K 3u
#define DA_P 65537u
#define DA_DELTA 65535u
#define DA_DATA_SLOTS 240u
#define DA_TAG_SLOTS 16u
#define DA_RAW_CHANNELS 2u
#define DA_SAMPLES_PER_CHANNEL 240u
#define DA_RAW_SAMPLES 480u
#define DA_CT_WORDS ((DA_K + 1u) * DA_D)
#define DA_CT_BYTES (DA_CT_WORDS * 4u)
#define DA_BLOCK_BYTES 64u
#define DA_BLOCKS (DA_CT_BYTES / DA_BLOCK_BYTES)

typedef struct {
  uint8_t id;
  uint16_t support;
  uint16_t quant_step;
  uint16_t batch_max;
  uint16_t coefficient_bound;
  uint16_t block_bytes;
  uint8_t sigma_index; /* 0=3.2, 1=3.4, 2=3.6 */
} da_profile_t;

extern const da_profile_t da_profiles[3];

#endif
