# Reproduction procedure and evidence boundaries

All commands below are future reviewer instructions. None was executed to prepare
this artifact. Direct Python dependencies are pinned; the complete OS, compiler,
wheel hashes, native-library commit, transitive dependency lock and container
digest must be captured from the actual verified environment. The Dockerfile is
a proposed environment, not a built or archived image.

## 1. Host reference

Use CPython 3.11.11 on Linux as the initial review environment. Create a virtual
environment, install `.[dev]`, and run `python -m pytest -q`. The default tests use
test-only ticket verifiers where necessary; they do not establish ML-DSA security.
The optional PQ test must be executed separately with a real local provider.

Prepare native OQS explicitly (no automatic installation by this package):

```bash
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
```

On macOS configure the dynamic loader for the installation path as required by
the provider. Native build recipes are platform dependent. Record the actual
upstream Git commit and `OQS_version()` output in the environment evidence;
requirements only pin the wrapper. Do not publish private signing/epoch keys.

The source scenario uses CSPRNG keys and encryption randomness; independent fresh
tickets produce different ciphertexts. Retries under the same ticket/source/nonce
use persistent SourceEmissionStore and return exactly the cached bytes. A changed
sampling window under that identity is rejected. Seeded RNG injection is a test-only hook, not a
production setting. Packet-level experiments must pair traffic/topology seeds
across methods while keeping cryptographic key material secret.

## 2. Controller review

Use the synthetic telemetry and model only to inspect control decisions:

```bash
python -m daahe replay-control --config configs/control_synthetic.json \
  --telemetry examples/telemetry_synthetic.csv --method da-ahe \
  --allow-synthetic --output runs/replay-da-ahe.json
```

Repeat with `--method dpp` and `hys`. Synthetic bounds always have
`certified=false`. Without `--allow-synthetic` this config must be rejected or
produce a fail-closed decision. Replay does not close the network loop and cannot
support a latency, loss, energy, recovery or controller-ranking claim.

For real calibration, provide separate **training**, **heldout calibration** and
**evaluation** seed manifests. CSV schema is documented in `calibration.py`.
The calibration CLI uses an action library and nominal admissible transition
masks from the input config:

```bash
python -m daahe calibrate --config external/control_input.json \
  --training external/training.csv --holdout external/heldout.csv \
  --evaluation-seeds 1001 1002 1003 --output runs/calibration-bundle.json
```

That short evaluation list illustrates CLI syntax, not the required 20-seed
paper evaluation. Calibration returns a schema-v2 bundle containing a frozen
model and causally fitted DPP violation models, not a deployment certificate.
The CSV separates `obs_noise_utilization`, `next_noise_utilization`, and `next_loss`;
see `calibration.py` for the full schema. Do not reuse the old ambiguous noise column.
Supply full reviewed uniform error/transition bounds, fallback inequality,
resource bounds, runtime region and the actual full profile/context digests.
Replace both the config's model and DPP violation models from the bundle, bind
its digest in the evidence and freeze it before
evaluation. Keep empirical residuals separate from universal bounds.

## 3. Security estimation

Install a chosen SageMath version and record its version and full environment.
The paper did not disclose the exact original Sage environment, so the artifact
does not invent one. Clone the official estimator and check out the exact commit:

```bash
git clone https://github.com/malb/lattice-estimator external/lattice-estimator
git -C external/lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
sage -python tools/estimate_security.sage --estimator external/lattice-estimator \
  --output runs/security-estimator
```

The script checks a clean pinned checkout, uses fixed public-key sigma=3.2,
explicit ADPS16 quantum mode for reduction attacks and GSA where applicable,
records each attack's operation count, and rejects missing/failed required attacks.
The adapter distinguishes original independent public-key samples from legitimate
derived samples produced by the pinned estimator's amplification routine; it
records the returned problem/noise metadata rather than treating every m>768 as
a request for new independent samples. Inspect that provenance before interpreting
the global minimum. No estimator was executed during this revision.
The reported minimum may differ from 128.1. A below-threshold or incomplete result
must be retained and investigated; never replace it with the manuscript value.

This estimator input is not identical to the finite reference sampler's exact
distribution, and generic flattened-LWE estimates do not certify a full
Module-LWE implementation. Decoding probability, aggregate-noise carry, transport,
memory and fallback certificates are separate inputs.

## 4. Original experiments and statistics

Acquire the original simulator, traces and board evidence listed by `daahe audit`.
Implement all methods within the same original INET packet-level model and freeze
common configurations before looking at evaluation results. Use 20 paired seeds,
300-s runs, 30-s warm-up, disturbance at100s and the disclosed workload/PHY.
See `experiments/METRICS_SCHEMA.md` and `tools/import_omnet.py --help` for import
contracts. The importer is not a network model.

```bash
python -m daahe stats external/metrics.csv --matrix experiments/matrix.json --output runs/summary.json
python tools/plot_results.py runs/summary.json --nodes 3000 --metric residual_plr \
  --normalized --title 'Residual loss relative to DA-AHE' --unit ratio --output runs/loss.svg
```

Compute residual PLR after application-layer recovery with a recorded denominator.
Recovery starts at disturbance onset and is censored if five consecutive healthy
control intervals are never reached; never substitute the simulation horizon.
All-loss runs must remain in the paired seed set; PLR is defined as one while
latency and delivered-aggregate coverage are unavailable. Their paired metric
comparisons are blocked, not imputed or silently dropped. Raw means and ratio-of-means CIs must be reported separately. Do not reconstruct
confidence intervals from printed mean bars.

## 5. Archive exactly the evidence that exists

Preserve source commit, config/trace/calibration hashes, environment capture, test
logs and simulation stdout. Add original evidence to
`author_artifacts/evidence-index.json` using the roles in `evidence.py`; refer to
relative paths and SHA256. Then run source/evidence manifest verification. A
complete evidence index still means “requires execution and review”, never an
automatic proof that the paper has been reproduced.

Verify the supplied release manifest **before** creating a current-state manifest.
The builder refuses to overwrite an existing file; use a new output such as
`runs/current-source-manifest.json`. Release maintainers regenerate the committed
manifest only after reviewing intended source changes, then separately publish
the source-archive checksum. A self-generated checksum is not an author attestation.

Reviewers should sign or attest the final independent result package with their
own identity. This reconstruction includes no invented attestation or performance
badge. The released source ZIP is only an integrity-preserved source delivery.

