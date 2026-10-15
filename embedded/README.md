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
SRAM. It cannot support a 10-KiB workspace claim in that form. 
Build with an explicit selected rank (integer 3..16), for example:

```bash
cmake -S embedded -B build/embedded -DDAAHE_MODULE_RANK=6
cmake --build build/embedded
ctest --test-dir build/embedded --output-on-failure
```

The example rank is not a security claim. CMake's default rank 3 is the legacy
tuple. Direct C builds may set `-DDAAHE_K=K`. Ciphertext bytes are derived as
`(K+1)*256*4`; the accumulator accepts exactly one or two ciphertexts of that
compiled rank. It does not silently accept a legacy 4096-byte payload in a
larger-rank build. Tests cover both derived lengths and rejection of stale sizes.
This core still does not implement full M-LWE encryption or certify security.
