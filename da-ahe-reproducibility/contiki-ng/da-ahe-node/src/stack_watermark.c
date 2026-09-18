#include "stack_watermark.h"
#include <stddef.h>
#include <stdint.h>

#define PATTERN UINT32_C(0xa55aa55a)
#define RAM_ORIGIN UINT32_C(0x20000000)

extern uint32_t _stack;
extern uint32_t _stack_origin;

void
da_stack_watermark_init(void)
{
  register uintptr_t current_sp __asm("sp");
  volatile uint32_t *cursor = &_stack;
  uintptr_t limit = current_sp > 96u ? current_sp - 96u : current_sp;
  while((uintptr_t)cursor + sizeof(uint32_t) <= limit) {
    *cursor++ = PATTERN;
  }
}

uint32_t
da_stack_high_water_bytes(void)
{
  volatile const uint32_t *cursor = &_stack;
  volatile const uint32_t *top = &_stack_origin;
  while(cursor < top && *cursor == PATTERN) {
    cursor++;
  }
  return (uint32_t)((uintptr_t)top - (uintptr_t)cursor);
}

uint32_t
da_static_ram_bytes(void)
{
  return (uint32_t)((uintptr_t)&_stack - RAM_ORIGIN);
}
