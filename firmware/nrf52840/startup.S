/* SPDX-License-Identifier: MIT */
.syntax unified
.cpu cortex-m4
.thumb
.section .vectors,"a",%progbits
.global vector_table
vector_table:
  .word __StackTop
  .word Reset_Handler
  .rept 14
  .word Default_Handler
  .endr
  /* nRF52840 has 48 peripheral interrupt slots; all are disabled. */
  .rept 48
  .word Default_Handler
  .endr
.section .text.Reset_Handler,"ax",%progbits
.thumb_func
.global Reset_Handler
Reset_Handler:
  cpsid i
  ldr r0, =__data_load__
  ldr r1, =__data_start__
  ldr r2, =__data_end__
1: cmp r1, r2
  bcs 2f
  ldr r3, [r0], #4
  str r3, [r1], #4
  b 1b
2: ldr r1, =__bss_start__
  ldr r2, =__bss_end__
  movs r3, #0
3: cmp r1, r2
  bcs 4f
  str r3, [r1], #4
  b 3b
4: bl main
  b Default_Handler
.thumb_func
Default_Handler:
  bkpt #0
  b Default_Handler

/* Run the timed C wrapper on a separately painted PSP. Main remains on MSP.
 * r0=function, r1=stack top. Preserve ABI alignment and prior CONTROL/PRIMASK. */
.section .text.bench_on_stack,"ax",%progbits
.thumb_func
.global bench_on_stack
bench_on_stack:
  push {r4-r8, lr}
  mrs r4, control
  mrs r5, primask
  cpsid i
  msr psp, r1
  mov r6, r0
  orr r0, r4, #2
  msr control, r0
  isb
  blx r6
  msr control, r4
  isb
  msr primask, r5
  pop {r4-r8, pc}
