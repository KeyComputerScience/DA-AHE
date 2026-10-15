/* SPDX-License-Identifier: MIT */
/* Bare nRF52840: no SoftDevice, bootloader, RTOS or reserved radio RAM. */
MEMORY {
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 256K
}
ENTRY(Reset_Handler)
__StackTop = ORIGIN(RAM) + LENGTH(RAM);
__StackLimit = __StackTop - 4096;
SECTIONS {
  .vectors : { KEEP(*(.vectors)) } > FLASH
  .text : { *(.text*) *(.rodata*) . = ALIGN(4); } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH
  .data : {
    . = ALIGN(4); __data_start__ = .; *(.data*) . = ALIGN(4); __data_end__ = .;
  } > RAM AT > FLASH
  __data_load__ = LOADADDR(.data);
  .bss (NOLOAD) : {
    . = ALIGN(8); __bss_start__ = .; *(.bss*) *(COMMON) . = ALIGN(8); __bss_end__ = .;
  } > RAM
  __static_ram_bytes__ = SIZEOF(.data) + SIZEOF(.bss);
  ASSERT(__bss_end__ <= __StackLimit, "RAM collides with reserved main stack")
  /DISCARD/ : { *(.comment) *(.note*) }
}
