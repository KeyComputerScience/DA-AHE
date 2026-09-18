#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="${TMPDIR:-/tmp}/da-ahe-host-tests"
mkdir -p "$BUILD_DIR"
cd "$PROJECT_DIR"

cc -std=c99 -O2 -Wall -Wextra \
  -Isrc -Ithird_party/pqclean_common \
  tests/host_smoke.c \
  src/da_ahe_params.c src/db2.c src/gaussian.c src/linear_auth.c \
  src/mlwe.c src/test_vectors.c third_party/pqclean_common/fips202.c \
  -o "$BUILD_DIR/protocol-smoke"
"$BUILD_DIR/protocol-smoke"

cc -std=c99 -O2 -Wall -Wextra \
  -Isrc -Ithird_party/pqclean_common -Ithird_party/ml_dsa_44 \
  tests/host_mldsa.c tests/host_randombytes.c src/test_vectors.c \
  third_party/pqclean_common/fips202.c third_party/ml_dsa_44/*.c \
  -o "$BUILD_DIR/mldsa44-smoke"
"$BUILD_DIR/mldsa44-smoke"
