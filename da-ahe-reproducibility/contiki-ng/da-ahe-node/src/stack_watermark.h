#ifndef DA_STACK_WATERMARK_H_
#define DA_STACK_WATERMARK_H_

#include <stdint.h>

void da_stack_watermark_init(void);
uint32_t da_stack_high_water_bytes(void);
uint32_t da_static_ram_bytes(void);

#endif
