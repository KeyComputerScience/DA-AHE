# Reproduction procedure and evidence boundaries

## 1. Host reference

Use CPython 3.11.11 on Linux as the initial review environment. Create a virtual
environment, install `.[dev]`, and run `python -m pytest -q`. 

###bash

git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs external/liboqs
cmake -S external/liboqs -B external/liboqs/build -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="$PWD/external/oqs-install"
cmake --build external/liboqs/build --parallel 2
cmake --install external/liboqs/build
export OQS_INSTALL_PATH="$PWD/external/oqs-install"
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
python -m pip install -r requirements-pq.txt
python -m pytest -q -m pq
python -m daahe demo --participants 3 --output runs/demo
python tools/capture_environment.py --output runs/environment.json


On macOS configure the dynamic loader for the installation path as required by
the provider. Native build recipes are platform dependent. Record the actual
upstream Git commit and `OQS_version()` output in the environment evidence;
requirements only pin the wrapper.

The source scenario uses CSPRNG keys and encryption randomness; independent fresh
tickets produce different ciphertexts. Retries under the same ticket/source/nonce
use persistent SourceEmissionStore and return exactly the cached bytes. 

## 2. Controller review

Use the synthetic telemetry and model only to inspect control decisions:

```bash
python -m daahe replay-control --config configs/control_synthetic.json \
  --telemetry examples/telemetry_synthetic.csv --method da-ahe \
  --allow-synthetic --output runs/replay-da-ahe.json
```

Repeat with `--method dpp` and `hys`. Synthetic bounds always have
`certified=false`. Without `--allow-synthetic` this config must be rejected or
produce a fail-closed decision.

For real calibration, provide separate **training**, **heldout calibration** and
**evaluation** seed manifests. CSV schema is documented in `calibration.py`.
The calibration CLI uses an action library and nominal admissible transition
masks from the input config:

```bash
python -m daahe calibrate --config external/control_input.json \
  --training external/training.csv --holdout external/heldout.csv \
  --evaluation-seeds 1001 1002 1003 --output runs/calibration-bundle.json
```

## 3. Security estimation

Install a chosen SageMath version and record its version and full environment.

```bash
git clone https://github.com/malb/lattice-estimator external/lattice-estimator
git -C external/lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
sage -python tools/estimate_security.sage --estimator external/lattice-estimator \
  --output runs/security-estimator
```

## 4. Original experiments and statistics

Acquire the original simulator, traces and board evidence listed by `daahe audit`.
Implement all methods within the same original INET packet-level model and freeze
common configurations before looking at evaluation results. Use 20 paired seeds,
300-s runs, 30-s warm-up, disturbance at100s and the disclosed workload/PHY.
See `experiments/METRICS_SCHEMA.md` and `tools/import_omnet.py --help` for import
contracts. 

```bash
python -m daahe stats external/metrics.csv --matrix experiments/matrix.json --output runs/summary.json
python tools/plot_results.py runs/summary.json --nodes 3000 --metric residual_plr \
  --normalized --title 'Residual loss relative to DA-AHE' --unit ratio --output runs/loss.svg
```

## 5. Archive exactly the evidence that exists

Preserve source commit, config/trace/calibration hashes, environment capture, test
logs and simulation stdout. Add original evidence to
`author_artifacts/evidence-index.json` using the roles in `evidence.py`; refer to
relative paths and SHA256. Then run source/evidence manifest verification. 

Verify the supplied release manifest **before** creating a current-state manifest.
The builder refuses to overwrite an existing file; use a new output such as
`runs/current-source-manifest.json`. 
