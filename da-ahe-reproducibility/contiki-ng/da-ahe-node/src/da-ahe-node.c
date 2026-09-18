#include "contiki.h"
#include "coap-engine.h"
#include "sys/log.h"
#include "api.h"
#include "da_ahe_params.h"
#include "db2.h"
#include "hmac_sha3.h"
#include "linear_auth.h"
#include "mlwe.h"
#include "stack_watermark.h"
#include "test_vectors.h"
#include <string.h>

#define LOG_MODULE "DA-AHE"
#define LOG_LEVEL LOG_LEVEL_INFO

extern coap_resource_t res_da_ahe_status;

volatile uint8_t da_selftest_ok;
volatile uint32_t da_last_stack_hwm;

static int16_t raw_signal[DA_RAW_CHANNELS][DA_SAMPLES_PER_CHANNEL];
static int32_t coefficients[DA_DATA_SLOTS];
static uint32_t tags[DA_TAG_SLOTS];
static uint32_t message[DA_D];
static uint32_t recovered[DA_D];
static da_ciphertext_t ciphertext;

static int
selftest(void)
{
  static const uint8_t auth_secret[32] = {
    0x31,0x22,0x13,0x04,0x55,0x46,0x77,0x68,
    0x99,0x8a,0xbb,0xac,0xdd,0xce,0xff,0xe0,
    0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
    0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x00
  };
  static const uint8_t ticket_digest[32] = {1,2,3,4,5,6,7,8};
  static const uint8_t label_digest[32] = {8,7,6,5,4,3,2,1};
  static const uint8_t encryption_seed[32] = {0x42,0x19,0x26,0x09,0x18};
  uint8_t hmac[32];
  uint16_t channel;
  uint16_t i;
  int signature_ok;

  for(channel = 0; channel < DA_RAW_CHANNELS; channel++) {
    for(i = 0; i < DA_SAMPLES_PER_CHANNEL; i++) {
      raw_signal[channel][i] = (int16_t)((i * (channel + 3u)) % 401u - 200);
    }
  }
  da_db2_quantize(raw_signal, &da_profiles[0], coefficients);
  da_linear_tags(auth_secret, ticket_digest, label_digest, coefficients, tags);
  da_pack_codeword(coefficients, tags, message);
  da_mlwe_encrypt(&da_test_public_key, message, da_profiles[0].sigma_index,
                  encryption_seed, &ciphertext);
  da_mlwe_decrypt(&da_test_secret_key, &ciphertext, recovered);
  for(i = 0; i < DA_D; i++) {
    if(recovered[i] != message[i]) {
      LOG_ERR("M-LWE mismatch at %u: %lu != %lu\n", i,
              (unsigned long)recovered[i], (unsigned long)message[i]);
      return 0;
    }
  }
  da_hmac_sha3_256(auth_secret, sizeof(auth_secret),
                   (const uint8_t *)&ciphertext, sizeof(ciphertext), hmac);
  signature_ok = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
    da_test_ticket_sig, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
    da_test_ticket, da_test_ticket_len, da_test_ticket_pk);
  LOG_INFO("SELFTEST mlwe=ok mldsa=%s hmac128=%02x%02x%02x%02x ct=%u\n",
           signature_ok == 0 ? "ok" : "fail",
           hmac[0], hmac[1], hmac[2], hmac[3], (unsigned)sizeof(ciphertext));
  return signature_ok == 0;
}

PROCESS(da_ahe_process, "DA-AHE reproducibility firmware");
AUTOSTART_PROCESSES(&da_ahe_process);

PROCESS_THREAD(da_ahe_process, ev, data)
{
  static struct etimer timer;
  (void)ev;
  (void)data;
  PROCESS_BEGIN();

  da_stack_watermark_init();
  coap_activate_resource(&res_da_ahe_status, "da-ahe/status");
  da_selftest_ok = (uint8_t)selftest();
  etimer_set(&timer, 10 * CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    da_last_stack_hwm = da_stack_high_water_bytes();
    LOG_INFO("DA_AHE_STACK_HWM role=node static=%lu stack=%lu peak=%lu ok=%u\n",
             (unsigned long)da_static_ram_bytes(),
             (unsigned long)da_last_stack_hwm,
             (unsigned long)(da_static_ram_bytes() + da_last_stack_hwm),
             da_selftest_ok);
    etimer_reset(&timer);
  }
  PROCESS_END();
}
