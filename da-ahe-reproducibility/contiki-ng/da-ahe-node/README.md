# DA-AHE Contiki-NG v4.8 project

This is a self-contained application directory for the nRF52840 DK.  It
contains the two-channel integer Db2 path, 240+16 plaintext packing,
`q=2^32, d=256, k=3` M-LWE encryption/decryption, field-linear tags,
HMAC-SHA3-256, ML-DSA-44 ticket verification, a 4,096-byte ciphertext, a CoAP
status resource, and a runtime stack watermark.

The bundled ML-DSA-44 implementation is the clean PQClean implementation.
Its FIPS-202 context was changed from dynamic allocation to embedded state so
the firmware performs no heap allocation.

The supplied target artifacts report 91,188 bytes of Flash (`text+data`) and
27,976 bytes of static SRAM (`data+bss`). Runtime peak SRAM is intentionally
left unreported until `tools/capture_stack.sh` is run on the physical board.

## Exact dependencies

- Contiki-NG release/v4.8 commit
  `9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f`;
- GNU Arm Embedded toolchain (`arm-none-eabi-gcc`);
- nRF52840 DK (`BOARD=dk`) for the stack log.

Initialize the Contiki submodules required by the target:

```sh
git -C "$CONTIKI" submodule update --init arch/cpu/arm/CMSIS
git -C "$CONTIKI" submodule update --init arch/cpu/nrf52840/lib/nrf52-sdk
```

Generate vectors, build, and copy the real ELF/map files:

```sh
python3 tools/generate_vectors.py
CONTIKI=/absolute/path/to/contiki-ng tools/build_release.sh
```

The host smoke tests exercise the same M-LWE/Db2/tag code and verify the
bundled ML-DSA-44 ticket vector before a board is used:

```sh
tools/run_host_tests.sh
```

Flash with Contiki-NG's normal target, then capture the board log:

```sh
make CONTIKI=/absolute/path/to/contiki-ng TARGET=nrf52840 BOARD=dk da-ahe-node.upload
PORT=/dev/ttyACM0 SECONDS=180 tools/capture_stack.sh
```

The expected serial record has the machine-readable form:

```text
DA_AHE_STACK_HWM role=node static=<bytes> stack=<bytes> peak=<bytes> ok=1
```

The package includes the real cross-linked `artifacts/da-ahe-node.elf` and
`artifacts/da-ahe-node.map`. The board-dependent
`artifacts/stack-watermark.log` becomes evidence only after capture succeeds;
the package intentionally does not ship a fabricated board log.
