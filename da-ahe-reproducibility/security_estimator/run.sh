#!/bin/sh
set -eu

: "${SAGE:=sage}"
: "${ESTIMATOR_ROOT:?Set ESTIMATOR_ROOT to lattice-estimator checkout}"

mkdir -p results
set +e
"$SAGE" -python estimate_1281.sage.py \
  --estimator-root "$ESTIMATOR_ROOT" \
  --output-dir results "$@" >results/stdout.log 2>&1
STATUS=$?
set -e
cat results/stdout.log
exit "$STATUS"
