# Independent nRF52840 core measurement firmware

This is a new standalone measurement implementation. It is **not the original
paper firmware**, does not run Contiki-NG, and has not been flashed or measured
on a physical board in the delivered evidence. Actual cross-compilation and
host C known-answer execution are recorded separately from pending board data.

## Build and actual evidence

Install the official Arm GNU Toolchain for `arm-none-eabi` (tested with
14.3.Rel1, GCC 14.3.1). The toolchain stays outside this repository; no large SDK
or private key is vendored. A native `clang` or GCC is also required.

```bash
python firmware/build.py --cc /path/to/arm-none-eabi-gcc --module-rank 6 \
  --output evidence/independent/firmware/new-build
```

The output directory must not exist. The build first compiles and actually runs
`embedded/test_core.c` on the host, then cross-compiles the shared C core and
measurement harness for Cortex-M4 with `-O2`, Thumb and software floating-point
ABI. It writes ELF, HEX, BIN, linker map, compiler stack-usage listings, size and
ELF-header reports, full command/output log, source/compiler/config identity and
artifact SHA256 hashes. `board-pending.json` records zero board samples. A failed
build retains its log and is never upgraded to a successful build record.

Select `--module-rank` explicitly (integer 3..16). Its default of 3 is the
**legacy** tuple, not a calibrated security recommendation. The shared C core
and native test receive the same `-DDAAHE_K` as the ARM compile. Ciphertext length
is `(K+1)*256*4` bytes: K=3 gives 4096, selected K=6 gives 7168, K=7 gives 8192. Source/build identity,
metadata and both UART boot/capabilities records bind the complete parameter
tuple and size-dependent stream operation name. New rank-bound logs use schema
version 2; the current collector/verifier rejects old unbound schema-1 logs.
The earlier rank-3 cross-build remains baseline evidence, never relabelled as a
new security-selected build.

The delivered selected-rank build is `evidence/independent/firmware/selected-k6`,
with separate `selected-status.json`. Its actual native test and ARM compilation
passed; board sampling remains zero/pending. Selection/security-estimator evidence
is separate from these core microbenchmarks. The old `arm-gcc-14.3.1` directory
and original status remain the rank-3 baseline.

The linker starts at flash address zero and reserves all 256 KiB RAM for a bare
nRF52840. There is **no SoftDevice/bootloader compatibility**. Flash only a
dedicated development board using its normal programmer and the generated HEX
or ELF; this task did not flash or erase any device. Existing applications must
be preserved by the operator before replacing firmware.

## What can be measured

| Operation logged | Included | Explicitly absent |
|---|---|---|
| `empty_harness` | Branch/barrier/counter baseline | No baseline subtraction |
| `ring_mul_d256` | One existing negacyclic product, 256 coefficients | M-LWE keygen/encryption/decryption, sampling |
| `pack_l240` | Existing packing and bounds checks, 240 data + 16 tags | Transform, quantization, tag generation |
| `linear_tag_l240_fixture_provider` | Existing streaming tag arithmetic, 16×240 elements | SHAKE/KDF, secret provisioning; provider uses public arithmetic fixtures |
| `decode_d256` | 256 scalar existing decoders | Secret-key dot product or full decrypt |
| `stream_16xB_b64_fixture_callback` (B is compiled byte length) | Init, 16×(B/64) pushes and finish; B-byte accumulator | HMAC/signature verification; callback deliberately accepts fixtures |

ML-DSA-44, HMAC-SHA3, SHAKE, full M-LWE encryption, IntDb2, sensing, radio,
network stack, persistent ledgers, energy and the full DA-AHE protocol are
**unsupported**. These microbenchmarks cannot substantiate the paper's
3.6-million-cycle encryption, 58.125-ms CPU, 1.395-mJ energy, 10-KiB full
workspace, 28.64-KiB peak SRAM or 91,188-byte flash figures.

## Exact boundaries

The harness enables the Cortex-M4 DWT cycle counter and records unsigned
`CYCCNT` differences around the dispatch and kernel. Barriers, branch dispatch,
kernel calls and loop work inside the interval are included. UART, fixture setup,
stack painting/scanning and result checks are outside the cycle interval.
Raw empty-harness samples remain visible; no subtraction or inferred energy is
applied. A separate TIMER1 counter runs at nominal 1 MHz and constrains a sample
to less than 60 seconds, below the 32-bit DWT wrap at nominal 64 MHz. Both clocks
derive from the SoC clock; TIMER1 is not an external time or frequency standard.
Interrupts are disabled throughout this bare benchmark. Results describe this
build, fixed operands, cold-start/repeated execution and interrupt policy only;
they do not estimate network-loaded or worst-case operand performance.

Each sample runs the C wrapper on a dedicated 8,192-byte PSP stack painted
with `0xA5`; the main/UART stack remains on MSP. The scanned high-water value
includes wrapper, kernel **and the subsequent known-answer checks**. The bottom
32-byte guard must remain untouched. Painting gives an observed watermark, not
a proof of worst-case stack use; untouched bytes may coincidentally equal the
canary. Compiler `.su` files are separate static function-frame reports and do
not establish transitive call-chain/interrupt stack maxima. The linker map
includes all static fixtures, accumulator, PSP allocation and the separately
reserved 4,096-byte MSP. Do not add the allocated PSP twice when totaling RAM;
do not interpret ELF debug-section/file size as flash use. A full-role memory
certificate requires real complete firmware and role-specific measurements.

## Capture a physical board later

The serial output uses the nRF52840 DK virtual COM TX on P0.06, nominal 115200
8N1, without flow control. It uses the documented legacy UART0 peripheral
(deprecated by Nordic, still implemented); other boards require an appropriate
wiring/port configuration. The minimal startup does not import Nordic SDK
`SystemInit` or apply board-specific errata workarounds. Its boot, peripheral
behavior and counter operation are **pending physical validation**.

Open the collector first, then manually reset the board. It waits for the boot,
capabilities, exactly six operations × twenty repeats, and complete records.

```bash
python tools/collect_board_measurements.py --port /dev/cu.usbmodemXXXX \
  --board-id YOUR_PHYSICAL_BOARD_ID --build-dir evidence/independent/firmware/new-build \
  --output evidence/independent/firmware/new-board-capture --timeout 60
python tools/verify_board_measurements.py evidence/independent/firmware/new-board-capture \
  --build-dir evidence/independent/firmware/new-build \
  --output evidence/independent/firmware/new-board-verification.json
```

Both tools are Python-standard-library only on POSIX/macOS/Linux. Capture has
no file-replay mode; incomplete/failed serial captures retain their literal bytes
and manifest. Verification checks raw/build hashes, firmware ID, exact operation
scope/order/count, known-answer flags, stack guards and DWT/TIMER consistency.
It reports `structurally_valid_operator_asserted_board_capture`, not hardware
attestation. A fabricated serial device could supply bytes: board identity,
flashing the stated binary, debugger state and actual physical provenance remain
operator responsibilities. Host parser fixtures in tests are never retained as
board measurements or substituted for missing hardware evidence.

## Official register and toolchain references

- [nRF52840 product specification](https://docs-be.nordicsemi.com/bundle/nRF52840_PS_v1.8/raw/resource/enus/nRF52840_PS_v1.8.pdf), UART/GPIO/TIMER register maps.
- [nRF52840 DK virtual COM pins](https://docs.nordicsemi.com/r/bundle/ug_nrf52840_dk/page/ug/dk/vir_com_port.html).
- [Nordic UART documentation](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/uart.html), baud and legacy peripheral operation.
- [Arm Cortex-M4 technical reference](https://documentation-service.arm.com/static/5f19da2a20b7cf4bc524d99a), DWT and stack-selection semantics.
- [Official Arm GNU Toolchain](https://developer.arm.com/Tools%20and%20Software/GNU%20Toolchain).

Register-access code and startup here are independently written; no Nordic SDK
implementation is redistributed.
