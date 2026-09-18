# DA-AHE reproducibility package

This package separates three kinds of evidence so the manuscript does not
confuse an executable protocol model, a lattice-security estimate, and a
target-firmware measurement.

## Contents

- `python/`: executable DA-AHE reference matching the stated `d=256`, `k=3`,
  `q=2^32`, `p=65537`, 240+16 packing, three profiles, ML-DSA-44 tickets,
  HMAC-SHA3-256, aggregation, and robust five-regime controller.
- `security_estimator/`: an independent SageMath/lattice-estimator run for
  the fixed long-term LWE instance. It verifies the exact estimator commit,
  emits every attack result, and fails if the computed minimum does not round
  to 128.1 bits.
- `contiki-ng/da-ahe-node/`: nRF52840 Contiki-NG v4.8 application, vendored
  ML-DSA-44 clean implementation, generated test vectors, host smoke tests,
  target build scripts, ELF, linker map, HEX, symbol sizes, and hashes.

## Verification performed in this environment

- Python: 12 unit tests passed; deterministic aggregate demo passed.
- C host tests: M-LWE/codec/tag round trip passed; ML-DSA-44 vector passed.
- ARM target: linked as a 32-bit ARM EABI5 nRF52840 ELF with Contiki-NG
  commit `9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f` and xPack GNU Arm
  Embedded GCC 13.3.1.
- GNU `size`: 91,188 bytes Flash (`text+data`) and 27,976 bytes static SRAM
  (`data+bss`). These are the actual included implementation values and do
  not support the manuscript's 70.6-KiB/8.14-KiB table.

## Evidence not generated here

SageMath is not installed, so the security-estimator result was not executed
in this environment. A physical nRF52840 DK is also unavailable, so no
runtime stack-watermark log is claimed. The estimator and board-capture
scripts are included; both preserve failing exit codes and generate
machine-readable JSON. Do not report 128.1 bits or a peak-SRAM number as
reproduced until those two runs are completed.
