#!/bin/sh
set -eu

: "${PORT:?Set PORT to the nRF52840 serial port, e.g. /dev/ttyACM0}"
: "${SECONDS:=180}"
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOG="$PROJECT_DIR/artifacts/stack-watermark.log"

stty -F "$PORT" 115200 raw -echo
echo "Capturing $PORT for $SECONDS seconds..."
timeout "$SECONDS" sh -c "cat '$PORT'" | tee "$LOG" || true
grep 'DA_AHE_STACK_HWM' "$LOG" >/dev/null || {
  echo "No stack-watermark record captured" >&2
  exit 3
}
python3 "$PROJECT_DIR/tools/stack_report.py" "$LOG" \
  > "$PROJECT_DIR/artifacts/stack-report.json"
