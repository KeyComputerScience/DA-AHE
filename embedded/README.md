# Portable embedded arithmetic and accumulator

`daahe_core.c` implements negacyclic multiplication modulo 2^32, bounded packing,
linear tags, coefficient decoding, and authenticated sequential block accumulation
without heap allocation. Callers supply storage and a block-authentication callback.
Any failed block poisons and wipes the complete batch; only a complete canonical
roster can finish. The callback must also bind the verified ticket and nonce context.

Build, when permitted: `cmake -S embedded -B build/embedded` then
`cmake --build build/embedded`. This delivery has not been compiled or run.

This library is **not** the missing Contiki-NG firmware. It does not include RPL,
radio drivers, device key provisioning, ML-DSA, a side-channel resistant Gaussian
sampler, or a constant-time optimized M-LWE implementation. Those are explicit
integration dependencies, not success-returning stubs. The host reference supplies
the complete mathematical encryption and verification path. A board port must
compare host/C arithmetic vectors and remeasure its own ELF and stack peak.

Measure role-specific peak SRAM as `.data + .bss + stack_HWM`; take the maximum
across mutually exclusive roles. Do not add the 10-KiB workspace again if its
buffers are already included in `.data/.bss`. This package asserts no board timing,
Flash footprint, workspace certificate, or 128-bit hardware security result.

