# Reproduction procedure and evidence boundaries

The method uses fixed rank-6 parameters and an explicitly specified synthetic
network study. Read [EVALUATION.md](EVALUATION.md),
[CURRENT_RESULTS.md](../experiments/CURRENT_RESULTS.md) and the
[protocol implementation](../src/daahe/protocol.py) for the
experimental design, complete method comparison and supported claims.

Use Python 3.12 and the pinned dependencies. Each command that creates outputs
requires a fresh destination; retain its execution receipt and source/input
identity. Software tests, raw metric recomputation, network replay, mathematical
calculations and physical measurements are separate verification stages.

## 1. Verify the complete result export

```bash
python -m pip install -e '.[dev]'
python tools/build_current_evaluation.py --check experiments
python tools/build_current_evaluation.py --output-dir runs/current-evaluation
python tools/check_paper_evidence.py
```

The export recomputes descriptive statistics from all 140 per-seed rows and
binds the recorded security, fidelity and horizon evidence. It does not rerun
the network. All seven methods, failed/unadmitted opportunities, invalid
acceptances, modeled resource costs and right-censored outcomes are retained.

## 2. Host reference and real-provider protocol trials

```bash
python tools/run_logged.py --output runs/tests -- python -m pytest -q
python tools/capture_environment.py --output runs/environment.json
```

The demo requires the explicitly installed ML-DSA provider. Follow
[INDEPENDENT_REPRODUCTION.md](INDEPENDENT_REPRODUCTION.md) for the pinned native
liboqs/liboqs-python build recipe and loader setup, then run:

```bash
python -m pytest -q -m pq
python -m daahe demo --participants 3 --module-rank 6 --output runs/demo
python tools/run_logged.py --output runs/protocol-execution -- \
  python tools/run_protocol_trials.py --module-rank 6 --trials 20 --output runs/protocol
```

Capture the actual provider Git commit, `OQS_version()` and environment. Native
loader configuration is platform dependent. The source uses CSPRNG keys and
fresh encryption randomness. Persistent SourceEmissionStore binds each raw
payload to its ticket/source/nonce; retries return the committed cached envelope
and its cached signature. Sampling a different payload requires fresh authorization.
Functional success does not establish rare-event probabilities, constant-time
behavior or physical-board performance.

## 3. Inspect controller decisions and calibration inputs

```bash
python -m daahe replay-control --config configs/control.json \
  --telemetry examples/telemetry_synthetic.csv --method da-ahe \
  --allow-synthetic --output runs/replay-da-ahe.json
```

Repeat with `--method dpp` or `hys`. The reference configuration remains uncertified.
Without `--allow-synthetic`, missing external certificates must produce rejection
or a fail-closed decision. The [controller specification](CONTROL_IMPLEMENTATION_SPEC.md)
defines the robust admission test, nominal objective and deployment requirements.

A calibration study requires separate training, heldout calibration and
evaluation seed manifests. The CSV schema is defined in `src/daahe/calibration.py`.
For an explicitly supplied input bundle:

```bash
python -m daahe calibrate --config external/control_input.json \
  --training external/training.csv --holdout external/heldout.csv \
  --evaluation-seeds 1001 1002 1003 --output runs/calibration-bundle.json
```

The campaign's synthetic model is not a uniform uncertainty or domain-invariance
certificate. Hash/tuple checks establish identity, not the truth of a bound.

## 4. Security estimate and actual-sampler correctness

The encryption tuple is k=6, d=256, n=m=1536 with 7,168-byte ciphertexts. Its
recorded seven-attack minimum is 136.475 bits under the stated heuristic models.
The recorded calculation used SageMath 10.9. To run the estimator, use a
Sage-enabled Python interpreter and record the full environment:

```bash
git clone https://github.com/malb/lattice-estimator external/lattice-estimator
git -C external/lattice-estimator checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
python tools/estimate_security_parameters.py --estimator external/lattice-estimator \
  --output runs/security-k6 --module-rank 6 --ring-degree 256 \
  --q 4294967296 --sigma-key 3.2 --minimum-bits 128.1 --attack-timeout 600
```

See [security/README.md](../security/README.md) for cost-model and timeout scope.
An estimator threshold is not a module-specific, actual-CDT, implementation or
all-attack security proof. The separate finite-CDT record is checked with:

```bash
python tools/verify_decoding_record.py evidence/independent/decoding/k6-cdt-03
python tools/check_decoding_horizon.py --batches 5 --target-bits 128
```

Fresh interval calculations require Sage-enabled Python. The one-fresh-batch
random-key/noise scope and finite-task conditions are in
[DECODING_BOUND.md](../security/DECODING_BOUND.md) and
[DECODING_RISK_BUDGET.md](DECODING_RISK_BUDGET.md). A missed risk budget is not an
observed decoding failure or an unlimited-lifetime guarantee.

## 5. Aggregate fidelity

```bash
python tools/check_aggregate_fidelity.py --verify evidence/independent/aggregate-fidelity/run-01
python tools/check_aggregate_fidelity.py --output runs/fidelity
python tools/check_aggregate_fidelity.py --verify runs/fidelity
python tools/reproduce_paper_evidence.py --output runs/reviewer-evidence
```

The [72-case study](AGGREGATE_FIDELITY.md) retains raw integer inputs,
intermediate vectors, error decomposition, source snapshots and recomputation.
Its 54 admissible cases and 18 diagnostics are separate. Physical signal units,
a deployment corpus and utility-dependent network feedback are outside this
experiment. Large errors and undefined zero-reference PRD remain visible.

## 6. Network generation, raw recomputation and replay

For a complete campaign:

```bash
python tools/run_logged.py --timeout 10000 --output runs/campaign-execution -- \
  python tools/run_simulation_campaign.py --config simulation/config.json \
  --output runs/simulation
python tools/verify_simulation_campaign.py runs/simulation
```

The model and omitted costs are defined in [simulation/README.md](../simulation/README.md).
CPU/TX costs are modeled; the archived reference parameters are declared inputs
and the recorded controller decisions are uncertified. Independent calibration
and model-relative verification are described in
[CONTROLLER_CALIBRATION.md](CONTROLLER_CALIBRATION.md).
A configuration or workflow is not an execution receipt. Additional workloads
or scales need their own inputs and runs.

Follow [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) to download the four archive
parts, verify the recorded source identity and recompute all 140 saved cases.
Frozen-source network replay is a separate operation. The recorded byte-replay
environment is macOS ARM64/Python 3.12.10, with separate Linux raw recomputation.
The observed one-ULP epoch difference is retained in
[REPLAY_PORTABILITY.md](REPLAY_PORTABILITY.md); package version support alone
does not establish cross-environment byte equality.

## 7. Board measurement and evidence integrity

[firmware/README.md](../firmware/README.md) defines core build, physical capture
and record verification. Supplied firmware records cover ARM builds and host
known-answer behavior. Those records do not establish full-protocol cycles,
power, stack, memory or workspace claims.

Keep each completed execution's source/config snapshots, raw inputs/results,
provider/environment capture, command logs and manifest together. Build a
manifest only after all processes finish. Existing records and hashes remain
immutable; use separate output directories for independent executions.
`STATUS.json` records execution state for its bundle, while
[publication.json](../evidence/independent/publication.json) identifies the public
assets. Hash verification establishes bytes, not measurement authenticity,
mathematical validity or full-system certification.
