# DA-AHE: compact, verifiable aggregation with belief-aware admission

DA-AHE integrates compact protected representation, aggregate verification and
causal belief-based admission in one executable research workflow. Its main
contribution is the coupling of the data representation, integrity checks and
resource-aware action selection.

## Evidence-supported advantages

| Contribution | Recorded result | Comparison and evidence |
|---|---|---|
| Compact protected representation | **50% smaller ciphertext payload** | 14,336 to 7,168 bytes at the same rank-6 tuple; [packing arithmetic](docs/ABLATION_ADVANTAGES.md#payload) |
| CPU efficiency of the complete policy | **25.59% lower modeled CPU cost per valid report** | 1.037129 to 0.771703 mJ relative to fixed nominal; paired 95% CI 24.22–26.95%; [calculation](docs/ABLATION_ADVANTAGES.md#cpu-normalization-and-paired-uncertainty) |
| IntDb2 contribution to valid delivery | **+2.18 percentage points** | 33.3950% without IntDb2 to 35.5717% with DA-AHE; paired 95% CI +1.77 to +2.61 pp; [paired ablation](docs/ABLATION_ADVANTAGES.md) |
| Aggregate verification contribution | **0 modeled invalid acceptance** | 2.0870% of admitted reports without HVE, versus 0 with DA-AHE; [validity accounting](docs/ABLATION_ADVANTAGES.md#aggregate-validity-and-recovery) |

The network comparisons use the archived 3,000-node, 20-paired-seed service
study. CPU and validity outcomes are modeled. The fixed policy admits 100% of
opportunities and delivers 44.01%; DA-AHE admits 52.60% and delivers 35.57%, so
the CPU result describes a service-cost tradeoff between complete policies.
Payload arithmetic excludes tickets, MACs, headers and retries. Modeled invalid
acceptance uses injected validity labels rather than a cryptographic forgery
probability. [Complete seven-method results](experiments/CURRENT_RESULTS.md)
retain every comparison and denominator.

## Design contributions

- **Representation and admission are coupled.** Each action binds a sampling
  rate, support/quantization profile, batch size, fragmentation choice and repair
  setting; the configured profile determines the protected representation.
- **Belief updates are causal.** The controlled HMM uses the previously applied
  action and current observations, then predicts next-regime probabilities for
  action scoring. Robust drift and resource gates precede the cost objective.
- **Verification spans the batch lifecycle.** Signed exact-roster tickets bind
  contributors and profiles; hidden aggregate tags, durable source emission and
  sink replay state support authorized aggregation and at-most-once acceptance.

These are implemented mechanisms. Their code and evidence are mapped in
[method traceability](docs/CLAIM_TRACEABILITY.md); the
[controller specification](docs/CONTROL_IMPLEMENTATION_SPEC.md) defines the
conditional guarantees and their assumptions.

## Evaluation

The fixed **k=6** study provides [all-method results](experiments/CURRENT_RESULTS.md),
[machine-readable values and provenance](experiments/current-results.json), and
[the evaluation specification](docs/EVALUATION.md). The tables are regenerated
from all 140 saved per-seed rows and checked against the published summaries.
Every method, admission denominator and censored observation is included.

The [performance reproduction pipeline](docs/PERFORMANCE_REPRODUCTION.md)
provides a size-by-seed matrix, paired bootstrap statistics and five figure
exports from the same records. Its configuration fixes the seven-method
comparison and binds source, inputs and runtime identities.

```bash
python tools/build_current_evaluation.py --check experiments
python tools/build_current_evaluation.py --output-dir runs/current-evaluation
```

## Tables and calculations

[Tables and calculations](docs/MANUSCRIPT_TABLES.md) contain the Fig. 6/cost-table
export, nRF52840 memory quantities, reconstruction-fidelity values, units and
calculation formulas.

## Controller calibration

The separate 3,000-node identification study executes 35 cases and records
630 causal transitions: 270 training, 180 holdout and 180 evaluation rows.
Every action/operating-condition cell is covered. The fitted HMM, prediction
models and action-specific DPP coefficients are available in
[the active controller](configs/control.json), with
[input data and calculations](evidence/controller-calibration/) and
[the calibration specification](docs/CONTROLLER_CALIBRATION.md).

The recorded mathematical certificate fails domain-ball containment, fallback
drift and transition-set containment under the original thresholds. All numerical
checks and independent prediction diagnostics are preserved; this fit does not
certify the archived network comparison or a deployment.

## Methods

The [aggregation protocol](src/daahe/protocol.py),
[controller and baseline specification](docs/CONTROL_IMPLEMENTATION_SPEC.md), and
[evaluation specification](docs/EVALUATION.md) describe the declared
implementation, parameters and comparison scope.

## Security parameterization

This repository contains the DA-AHE host reference, an independent network
experiment implementation, and a board-measurement workflow.
The default encryption tuple is **k=6, d=256, n=m=1536, q=2^32,
sigma_key=3.2**. The pinned seven-attack estimator run gives a minimum of
**136.475 bits**, above the requested 128.1-bit heuristic threshold. Single
ciphertexts are **7,168 bytes** (raw two-polynomial reports: 14,336 bytes).
The selected estimator inputs and outputs are recorded in
`configs/security_profile.json` and
`evidence/independent/security-parameter-search/selected-k6-full/verification.json`.
The separate finite-CDT decoding proof gives a one-fresh-batch, 42-choice
adaptive union failure bound below 2^-128; see `security/DECODING_BOUND.md`
for its random-key probability scope and executed interval-arithmetic record.

The disclosed experiments bind their simulator, configuration, seeds and raw
records. Manuscript target values are not used as simulator outputs or
acceptance tolerances.

- `src/daahe/`: canonical encryption, signed tickets, exact-roster aggregation,
  authentication, controller, calibration and statistical code.
- `simulation/`: executable closed-loop packet/block simulation, explicit model
  configuration, independently generated exogenous traces and paired seed runs.
- `firmware/`: independent nRF52840 measurement firmware and build instructions.
- `security/` and `tools/estimate_security.sage`: pinned Lattice Estimator runner
  and per-attack execution logs. Failed or incomplete attacks are retained.
- `evidence/independent/`: public evidence produced by actual new executions;
  see `STATUS.json` for the historical execution snapshot and
  `publication.json` for the current complete archive location and hashes.
- `tools/run_logged.py`: argv, timestamps, source hashes, stdout/stderr and exit
  status for successful **and failed** commands.
- `tools/independent_manifest.py`: independent evidence byte-integrity checks.

The root `daahe/` directory is only a checkout import shim. Installed packages
and checkout commands both execute `src/daahe/`, avoiding duplicate source drift.

## Install and test

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest --strict-ci -q -m 'not pq' --ignore=tests/test_decoding_bound_interval.py
```

Real ML-DSA tests additionally need the pinned native provider (see
`docs/INDEPENDENT_REPRODUCTION.md`). They do not silently install a library:

```bash
python -m pip install -r requirements-pq.txt
python -m pytest --strict-ci -q -m pq --ignore=tests/test_decoding_bound_interval.py
python tools/run_protocol_trials.py --trials 20 --output runs/protocol
```

## Execute the new simulation

```bash
python tools/run_logged.py --timeout 10000 --output runs/campaign-execution -- \
  python tools/run_simulation_campaign.py --config simulation/config.json \
  --output runs/simulation
python tools/verify_simulation_campaign.py runs/simulation
```

The default configuration defines its own prospective workload and 20 seeds.
It is **not OMNeT++/INET and not the manuscript's original experiment**. Its
physical/channel/routing and controller simplifications are documented in
`simulation/README.md`. Generated metrics must be reported with that boundary.
Every method uses the same seed-specific exogenous inputs, not a common fixed
telemetry replay. Full packet/epoch logs permit independent metric recomputation.
See `simulation/paper_like_config.json` for an optional longer prospective
scenario; the existence of a configuration is not evidence that it was run.

## Measure the board and estimate security

Follow `firmware/README.md` to build, flash and collect device output. A firmware
ELF/map and a host C test are build evidence, **not board timing or energy
measurements**. There are no invented nRF52840 cycle, energy or stack readings.
The collector verifies firmware identity and logs raw input for later review.

See `security/README.md` and `docs/INDEPENDENT_REPRODUCTION.md` for the SageMath
runner. The reported minimum is computed from actual attack outputs. The
manuscript's 128.1-bit value is not substituted when the estimator is unavailable
or when an attack fails. Heuristic attack estimates are not formal guarantees.

## Calibrate and check the controller model

The [controller calibration workflow](docs/CONTROLLER_CALIBRATION.md) generates
separate training, holdout and evaluation records from the declared packet-service
model. It exports fitted controller parameters, prediction diagnostics, raw run
records and source/input hashes. A separate verifier checks domain invariance,
fallback drift and transition-set containment under explicit model assumptions.

Every report retains its actual pass or failure outcome. These checks concern
the declared mathematical model; empirical residual maxima do not establish
uniform physical-process coverage, numerical gate accuracy or full-system
deployment certification. The frozen 140-run comparison keeps its original
controller and results.

## Verify and archive evidence

```bash
python tools/independent_manifest.py build --root runs
python tools/independent_manifest.py verify --root runs
```

Generate the manifest only after all processes finish. It refuses overwrites.
Keep the entire bundle, including its manifest, source/config snapshots, inputs,
raw results and execution receipts. A hash verifies bytes, not the truth of a
measurement or proof. `daahe audit` checks the presence and identity of author-supplied artifacts;
execution receipts identify the study that produced each result.

Historical external-import contracts are under
`docs/archive/original-experiment-contract/`; they are separate from the
executed independent study. Archived source manifests identify their own immutable snapshots.
The root `manifest.json` identifies the current source files.

Full generated network traces are excluded from Git and from the small source
ZIP. The complete immutable `DA-AHE-independent-evidence.tar` is distributed as
four assets in the [independent evidence release](https://github.com/KeyComputerScience/DA-AHE/releases/tag/independent-evidence-2026-10-15).
Its SHA-256 is `079aa14358b83d5cf6e132b2c4b653ac2937feeae217c6c6965e1369cff511c0`.
See [PUBLIC_EVIDENCE.md](docs/PUBLIC_EVIDENCE.md) for download, safe extraction,
all-140 raw metric recomputation and archived-source deterministic replay.
The repository's
`evidence/independent/campaign-report/` directory is only a metadata/per-seed
extract; the release supplies the full raw records, all 20 exogenous inputs and
28-file frozen simulator source. Execution status is recorded by each receipt;
`publication.json` identifies the public evidence assets.

## Mandatory CI coverage and claim scope

Every push to main, pull request and manual run executes source integrity,
real-provider protocol/native tests, ARM microbenchmark compilation, small-case
replay, historical 140-case raw recomputation on Linux and strict frozen-source
replay on macOS ARM64/Python 3.12.10, a fresh
20-seed/140-case campaign with replay, paired performance-matrix integration
and statistical/figure exports, seven fresh pinned attack estimates and
exact-CDT Sage decoding checks. The aggregate check fails if any required job is
missing, skipped, cancelled or unsuccessful. Full runs can take substantially
longer than functional tests; workflow configuration alone is not a successful
execution receipt. [Replay environment and diagnosis](docs/REPLAY_PORTABILITY.md)
preserves the observed Linux one-ULP historical difference and both hosted probes.

The [claim coverage matrix](docs/REPRODUCTION_COVERAGE.md) distinguishes the
independent implementation from unverified manuscript claims. Complete software
CI and public synthetic records do not establish original-paper reproduction,
physical-board timing/energy/stack measurements or full-system certification.
Those states remain false in the machine-readable claim contract.

Original code is under MIT. See `LICENSE` and `THIRD_PARTY.md` for dependencies.
