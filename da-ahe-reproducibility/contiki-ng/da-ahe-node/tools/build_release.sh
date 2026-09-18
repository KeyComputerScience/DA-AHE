#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${CONTIKI:?Set CONTIKI to the Contiki-NG v4.8 checkout}"
: "${TARGET:=nrf52840}"
: "${BOARD:=dk}"

EXPECTED=9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f
if COMMIT=$(git -C "$CONTIKI" rev-parse HEAD 2>/dev/null); then
  :
elif [ -f "$CONTIKI/.da-ahe-source-commit" ]; then
  COMMIT=$(sed -n '1p' "$CONTIKI/.da-ahe-source-commit")
else
  echo "Cannot verify the Contiki-NG source revision" >&2
  exit 2
fi
if [ "$COMMIT" != "$EXPECTED" ]; then
  echo "Contiki-NG commit mismatch: $COMMIT (expected $EXPECTED)" >&2
  exit 2
fi

cd "$PROJECT_DIR"
make TARGET="$TARGET" BOARD="$BOARD" clean
BUILD_DIR="build/$TARGET/$BOARD"
make TARGET="$TARGET" BOARD="$BOARD" "$BUILD_DIR/da-ahe-node.elf"

ELF=$(find build -type f -name 'da-ahe-node.elf' -print | head -n 1)
MAP=$(find build -type f -name 'da-ahe-node.map' -print | head -n 1)
test -n "$ELF" && test -f "$ELF"
test -n "$MAP" && test -f "$MAP"

cp "$ELF" artifacts/da-ahe-node.elf
cp "$MAP" artifacts/da-ahe-node.map
arm-none-eabi-objcopy -O ihex artifacts/da-ahe-node.elf \
  artifacts/da-ahe-node.hex
arm-none-eabi-size -A artifacts/da-ahe-node.elf > artifacts/size-sections.txt
arm-none-eabi-size artifacts/da-ahe-node.elf > artifacts/size-summary.txt
arm-none-eabi-nm --print-size --size-sort --radix=d artifacts/da-ahe-node.elf \
  > artifacts/symbol-sizes.txt
sha256sum artifacts/da-ahe-node.elf artifacts/da-ahe-node.map \
  artifacts/da-ahe-node.hex \
  > artifacts/SHA256SUMS
python3 tools/resource_report.py artifacts/da-ahe-node.elf \
  > artifacts/resource-report.json
echo "Created real target artifacts under $PROJECT_DIR/artifacts"
