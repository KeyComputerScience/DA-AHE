#!/bin/sh
# SPDX-License-Identifier: MIT
# Sage 10.9 environments expose Sage through their Python; older images used -python.
set -eu
runner=/opt/daahe/tools/estimate_security.sage
if [ "${1-}" = "--parameterized" ]; then
    runner=/opt/daahe/tools/estimate_security_parameters.py
    shift
fi
if python -c 'import sage.all' >/dev/null 2>&1; then
    exec python "$runner" --estimator /opt/lattice-estimator "$@"
elif sage --python -c 'import sage.all' >/dev/null 2>&1; then
    exec sage --python "$runner" --estimator /opt/lattice-estimator "$@"
elif sage -python -c 'import sage.all' >/dev/null 2>&1; then
    exec sage -python "$runner" --estimator /opt/lattice-estimator "$@"
fi
printf '%s\n' 'No Sage-enabled Python entry point is available.' >&2
exit 2
