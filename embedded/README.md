# Portable embedded arithmetic and accumulator

`daahe_core.c` implements negacyclic multiplication modulo 2^32, bounded packing,
linear tags, coefficient decoding, and authenticated sequential block accumulation
without heap allocation. Callers supply storage and a block-authentication callback.
Any failed block poisons and wipes the complete batch; only a complete canonical
roster can finish. The callback must also bind the verified ticket and nonce context.

`daahe_linear_tag_stream` accepts a row-major matrix-element callback and keeps
only 16 partial tag words (64 bytes), avoiding a complete matrix allocation.
The provider must derive canonical elements using the exact host KDF and
rejection stream, returning failure immediately on derivation errors. The older
`daahe_linear_tag` API remains available for compatibility but reads a complete
16-by-L uint32 matrix: at L=240 that matrix alone costs 15,360 bytes if placed in
SRAM. It cannot support a 10-KiB workspace claim in that form. The streaming API
still needs the real SHAKE/HMAC provider, caller-owned buffers, and stack/memory
measurements; its 64-byte partial array is not a whole-firmware certificate.

Build, when permitted: `cmake -S embedded -B build/embedded` then
`cmake --build build/embedded`. This delivery has not been compiled or run.

This library is **not** the missing Contiki-NG firmware. It does not include RPL,
radio drivers, device key provisioning, ML-DSA, a side-channel resistant Gaussian
sampler, or a constant-time optimized M-LWE implementation. Those are explicit
integration dependencies, not success-returning stubs. The host reference supplies
the complete mathematical encryption and verification path. A board port must
compare host/C arithmetic vectors and remeasure its own ELF and stack peak.
It must also persist the one-report-per-ticket/source binding and retransmission
cache before emitting ciphertext. The host `SourceEmissionStore` documents this
contract; a crash-safe, rollback-protected device storage port is still required.

Measure role-specific peak SRAM as `.data + .bss + stack_HWM`; take the maximum
across mutually exclusive roles. Do not add the 10-KiB workspace again if its
buffers are already included in `.data/.bss`. This package asserts no board timing,
Flash footprint, workspace certificate, or 128-bit hardware security result.

