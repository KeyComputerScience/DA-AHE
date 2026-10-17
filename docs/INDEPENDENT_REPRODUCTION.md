# Execution and verification workflow

DA-AHE provides a rank-6 host reference, a synthetic packet-service study,
aggregate-reconstruction experiments, decoding-risk calculations and a board
measurement workflow. [Evaluation](EVALUATION.md),
[complete results](../experiments/CURRENT_RESULTS.md) and the
[protocol implementation](../src/daahe/protocol.py) define the
method and its evidence boundaries. Execution receipts identify the exact
source, inputs, environment, outputs and limitations of each run.

## 1. Canonical code and functional validation

Use Python 3.12 with the pinned dependencies and a fresh virtual environment:

```bash
python -m pip install -e '.[dev]'
python tools/run_logged.py --output runs/tests -- python -m pytest -q
cmake -S embedded -B build/embedded -DDAAHE_MODULE_RANK=6
cmake --build build/embedded
ctest --test-dir build/embedded --output-on-failure
```

Installed packages and checkout imports execute the canonical `src/daahe/`
package. Test receipts retain exit status, stdout/stderr and the source snapshot
at execution. They document software behavior within the tested scope and are
not attestations from an independent laboratory.

## 2. Real ML-DSA and aggregation behavior

The recorded native provider is liboqs 0.16.0 at upstream commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`, with liboqs-python 0.16.0.1.
Install the provider explicitly:

```bash
python -m pip install -r requirements-pq.txt
git clone https://github.com/open-quantum-safe/liboqs.git external/liboqs
git -C external/liboqs checkout --detach 5a1a854b0dc9f2141bdc771c555ee60c37950183
cmake -S external/liboqs -B build/liboqs -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=SIG_ml_dsa_44 \
  -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX="$PWD/external/oqs-install"
cmake --build build/liboqs --parallel 2
cmake --install build/liboqs
export OQS_INSTALL_PATH="$PWD/external/oqs-install"
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib:$OQS_INSTALL_PATH/lib64"
# macOS uses DYLD_LIBRARY_PATH for the corresponding dynamic-loader path.
python -m pytest -q -m pq
python tools/run_logged.py --output runs/protocol-execution -- \
  python tools/run_protocol_trials.py --module-rank 6 --trials 20 --output runs/protocol
```

Trials use fresh real-provider keys and encryption randomness, synthetic
waveforms, three participants and pi0/pi1/pi2 in rotation. Reports include
honest aggregation, a compromised-gateway ciphertext modification with a valid
transport MAC, persistent replay rejection and synthetic aggregate reconstruction
errors. Private keys, epoch secrets and replay databases are created in an
automatically deleted private temporary directory. The twenty fresh-key trials
are separate from the twenty network seeds. Host wall time is not an embedded
CPU measurement; zero observed failures does not establish a rare-failure
probability or cryptographic strength.

## 3. Paired network experiment

```bash
python tools/run_logged.py --timeout 10000 --output runs/campaign-execution -- \
  python tools/run_simulation_campaign.py --config simulation/config.json \
  --output runs/simulation
python tools/verify_simulation_campaign.py runs/simulation
```

The Python discrete-event model's topology, channel, traffic, processing, wire
and energy assumptions are specified in the configuration and
[simulation/README.md](../simulation/README.md). Cryptographic and signal
operations inside this model are represented by configured costs. The controller
uses the declared reference coefficients; its recorded decisions are uncertified.
The study is not a physical radio, RPL or nRF52840 measurement and does not
establish a uniform uncertainty certificate or physical-plant theorem.

A seed fixes method-independent topology, sampling opportunities and disturbance
inputs. Semantic keyed random streams prevent a policy from shifting exogenous
randomness by consuming a different number of draws. Methods receive causal
telemetry from their own queues and outcomes. Sampling skips, packet loss,
report loss, accepted invalid reports and valid reports have distinct counters.
All seven methods and all 140 recorded outcomes remain in the result export.
Recovery is right-censored when its criterion is not observed; the censoring
endpoint is not assigned as a recovery duration. The recorded campaign did not
trigger route repair and does not establish overall method dominance.

The verifier checks byte hashes, pairing/completeness and raw-to-summary
consistency. Network replay is a separate execution. Additional configurations
are prospective workloads until corresponding execution records exist.

## 4. Aggregate fidelity and finite-task risk

```bash
python tools/check_aggregate_fidelity.py --verify evidence/independent/aggregate-fidelity/run-01
python tools/check_decoding_horizon.py --batches 5 --target-bits 128
python tools/reproduce_paper_evidence.py --output runs/reviewer-evidence
```

The [fidelity study](AGGREGATE_FIDELITY.md) has 72 declared synthetic cases,
including 54 capacity-admissible cases and 18 diagnostics. It compares aggregate
reconstruction with the true integer-count sum and separates rounding, selection
and quantization effects. It does not establish physical scaling or a universal
fidelity threshold. The network model does not include signal values or
utility-dependent feedback.

The [risk budget](DECODING_RISK_BUDGET.md) uses an exact rational endpoint from
the finite-CDT certificate. Its joint random-key/fresh-noise scope, finite
configuration library, preselection conditions and task attempt cap are explicit.
A rejected budget means the bound cannot certify that target, not that an actual
decoding failure occurred.

## 5. Firmware and physical measurement

Follow [firmware/README.md](../firmware/README.md). The ELF/map and native
known-answer execution belong to a bare-metal core microbenchmark. Register
setup, cycle/stack boundaries, fixture callbacks, supported kernels and complete
protocol coverage are documented. Compilation is not physical device execution.
The supplied records establish ARM compilation, ELF/map and host known-answer
behavior. Complete protocol timing, power, stack and memory claims require
the corresponding firmware and device capture records.

The collector records literal serial bytes and binds them to a firmware build.
The verifier checks raw/build hashes, sequence and known answers. These checks
do not authenticate a device or substitute for operator provenance, an external
energy meter, calibration or complete firmware scope.

## 6. Security estimates and admission gates

Use the official Lattice Estimator commit
`53da5982597709ba0fdf94ea37a84d822310fd84`. See
[security/README.md](../security/README.md) for SageMath invocation, timeouts and
per-attack logs. Failed, missing, below-threshold and timed-out outcomes remain
visible; none can be substituted by a configured target.

The k=6 tuple has a recorded 136.475-bit minimum across seven successful attacks
under their declared heuristic models. [DECODING_BOUND.md](../security/DECODING_BOUND.md)
documents a separate SageMath 256-bit outward-interval calculation using the
implemented finite CDT. The 42-choice single-batch union log2 upper endpoint is
approximately -130.5101731584115. It is jointly scoped over random keys and
fresh honest noises, not conditioned on every fixed key or arbitrary observed
history, and does not cover unlimited attempts.

`tools/check_reference_bounds.py` checks exact integer data no-wrap arithmetic
for supplied profiles. Its output remains uncertified: it does not establish
workspace/airtime limits, control uncertainty, domain invariance or fallback
feasibility. Strict controller execution requires its external evidence gates;
synthetic demonstrations remain labeled uncertified.

## 7. Raw archive and replay identity

The [public bundle](PUBLIC_EVIDENCE.md) retains the raw campaign records and the
frozen source that generated them. Raw recomputation can use multiple jobs
without rerunning the network. Replay must execute the identity-matched source
snapshot; a different source tree is rejected rather than treated as equivalent.
The publication helper selects that snapshot when replay is requested.

After extracting the full archive, the frozen entry point can also be used:

```bash
CAMPAIGN="$PWD/evidence/independent/simulation"
PYTHONPATH="$CAMPAIGN/source/src" python \
  "$CAMPAIGN/source/tools/verify_simulation_campaign.py" "$CAMPAIGN" --replay
```

This reruns all 140 cases and is more expensive than record recomputation.
Exact byte replay is scoped to the recorded execution environment; consult
[REPLAY_PORTABILITY.md](REPLAY_PORTABILITY.md) for the macOS/Python identity,
Linux raw-recomputation check and observed one-ULP epoch difference. Full replay
and raw verification require distinct receipts.

## 8. Evidence integrity

```bash
python tools/independent_manifest.py build --root runs
python tools/independent_manifest.py verify --root runs
```

Finish all processes before creating a manifest. Keep source/config snapshots,
raw inputs/results, command receipts, environment and manifest together. Existing
manifests and output directories are not overwritten. The verifier detects
changed or missing listed bytes; it does not establish measurement truth or
mathematical validity. CI executions have their own source/input identity and
receipts. Workflow presence alone is not execution evidence.
