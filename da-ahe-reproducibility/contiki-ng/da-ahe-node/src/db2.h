#ifndef DA_DB2_H_
#define DA_DB2_H_

#include <stdint.h>
#include "da_ahe_params.h"

void da_db2_quantize(const int16_t input[DA_RAW_CHANNELS][DA_SAMPLES_PER_CHANNEL],
                     const da_profile_t *profile,
                     int32_t output[DA_DATA_SLOTS]);

#endif
