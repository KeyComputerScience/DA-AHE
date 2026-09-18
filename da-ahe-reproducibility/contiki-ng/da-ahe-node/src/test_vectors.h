#ifndef DA_TEST_VECTORS_H_
#define DA_TEST_VECTORS_H_

#include <stdint.h>
#include "mlwe.h"

extern const da_public_key_t da_test_public_key;
extern const da_secret_key_t da_test_secret_key;
extern const uint8_t da_test_ticket[];
extern const uint16_t da_test_ticket_len;
extern const uint8_t da_test_ticket_pk[];
extern const uint8_t da_test_ticket_sig[];

#endif
