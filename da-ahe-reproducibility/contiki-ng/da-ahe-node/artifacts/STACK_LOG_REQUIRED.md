# Physical-board evidence required

No stack-watermark log is included because this build environment has no
nRF52840 DK. Flash `artifacts/da-ahe-node.hex`, let the firmware complete its
self-test, and run:

```sh
PORT=/dev/ttyACM0 SECONDS=180 tools/capture_stack.sh
```

The capture is accepted only if it contains at least one record of the form

```text
DA_AHE_STACK_HWM role=node static=<bytes> stack=<bytes> peak=<bytes> ok=1
```

The script then writes `artifacts/stack-report.json`. Preserve the raw
`artifacts/stack-watermark.log` together with the board ID, firmware hash,
toolchain version, workload, trial duration, and number of repetitions.
