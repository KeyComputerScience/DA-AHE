#include "randombytes.h"

int
PQCLEAN_randombytes(uint8_t *output, size_t count)
{
  size_t i;
  for(i = 0; i < count; i++) {
    output[i] = (uint8_t)(i * 17u + 3u);
  }
  return 0;
}
