#include "api.h"
#include "test_vectors.h"
#include <stdio.h>

int
main(void)
{
  int result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
    da_test_ticket_sig, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
    da_test_ticket, da_test_ticket_len, da_test_ticket_pk);
  printf("%s mldsa44-verify result=%d\n", result == 0 ? "PASS" : "FAIL", result);
  return result != 0;
}
