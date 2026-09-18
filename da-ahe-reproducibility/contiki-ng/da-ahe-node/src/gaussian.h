#ifndef DA_GAUSSIAN_H_
#define DA_GAUSSIAN_H_

#include <stddef.h>
#include <stdint.h>

void da_gaussian_sample(const uint8_t seed[32], uint8_t sigma_index,
                        int16_t *output, size_t count);

#endif
