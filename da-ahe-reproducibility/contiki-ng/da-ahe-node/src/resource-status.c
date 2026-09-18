#include "coap-engine.h"
#include <stdio.h>
#include <string.h>

extern volatile uint8_t da_selftest_ok;
extern volatile uint32_t da_last_stack_hwm;

static void
get_handler(coap_message_t *request, coap_message_t *response,
            uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  int length;
  (void)request;
  (void)preferred_size;
  (void)offset;
  length = snprintf((char *)buffer, REST_MAX_CHUNK_SIZE,
                    "{\"ok\":%u,\"stack_hwm\":%lu,\"ct_bytes\":4096}",
                    da_selftest_ok, (unsigned long)da_last_stack_hwm);
  if(length < 0) {
    length = 0;
  }
  coap_set_header_content_format(response, APPLICATION_JSON);
  coap_set_payload(response, buffer, (size_t)length);
}

RESOURCE(res_da_ahe_status,
         "title=\"DA-AHE status\";rt=\"application/json\"",
         get_handler, NULL, NULL, NULL);
