#include "randombytes.h"
#include "lib/random.h"

int
PQCLEAN_randombytes(uint8_t *output, size_t n)
{
  size_t i;
  for(i = 0; i < n; i += 2) {
    uint16_t value = random_rand();
    output[i] = (uint8_t)value;
    if(i + 1 < n) {
      output[i + 1] = (uint8_t)(value >> 8);
    }
  }
  return 0;
}
