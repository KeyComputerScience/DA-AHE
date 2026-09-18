#ifndef DA_LINEAR_AUTH_H_
#define DA_LINEAR_AUTH_H_

#include <stdint.h>
#include "da_ahe_params.h"

void da_linear_tags(const uint8_t auth_secret[32],
                    const uint8_t ticket_digest[32],
                    const uint8_t label_digest[32],
                    const int32_t data[DA_DATA_SLOTS],
                    uint32_t tags[DA_TAG_SLOTS]);

void da_pack_codeword(const int32_t data[DA_DATA_SLOTS],
                      const uint32_t tags[DA_TAG_SLOTS],
                      uint32_t message[DA_D]);

#endif
