# DA-AHE independent reproduction and evidence

## Verified capabilities

- Profile-bound coefficient/tag packing uses one 7,168-byte ciphertext instead
  of two 7,168-byte ciphertexts for the raw two-channel representation, reducing
  the sensitive ciphertext payload by 50% at the same selected parameters.
- The selected rank-6 tuple has a recorded seven-attack minimum of 136.475 bits
  under the pinned heuristic estimator models.
- Signed exact-roster tickets, hidden aggregate tags, durable source emission
  and sink replay checks provide an executable verifiable-aggregation workflow.
- The public 20-seed, seven-method archive supplies raw records, independent
  metric recomputation and frozen-source replay for the disclosed experiment.

## Manuscript correction status

Reviewers can now inspect a [13-claim evidence map](docs/REVIEWER_EVIDENCE.md),
[72 aggregate-fidelity cases](docs/AGGREGATE_FIDELITY.md), an
[exact finite-task decoding budget](docs/DECODING_RISK_BUDGET.md), and the
[explicit controller specification](docs/CONTROL_IMPLEMENTATION_SPEC.md).
Generate and verify fresh targeted evidence with one command:

```bash
python tools/reproduce_paper_evidence.py --output runs/paper-evidence
```

The suite retains raw outputs, expected rejection checks, source/input hashes
and an integrity manifest. GitHub CI executes it and separately recomputes the
preserved fidelity cases. The supplied `TSMC_DA (1).pdf` has the same extracted
text as `TSMC_DA.pdf`; both identities are recorded without claiming the PDFs
were edited. These new synthetic and analytic results retain their stated scope.

The current implementation uses **k=6, n=m=1536, 7,168-byte ciphertexts** and
the independently recorded **136.475-bit** heuristic estimate. The original
14-page `TSMC_DA.pdf` uses k=3/768/4,096 bytes and has **not been edited** here.
Its 128.1-bit estimate is not supported by the preserved rank-3 run; 128.1 is
the required threshold, not a replacement for an observed attack result.
Original board and network measurements remain unverified for the new tuple.

Use [the manuscript correction text](docs/MANUSCRIPT_CORRECTIONS.md) for the
parameter, airtime, integrity assumptions and result-scope revisions. The
[machine-readable alignment contract](configs/manuscript_alignment.json)
binds the current code to its evidence and preserves the old execution record.
Check it with:

```bash
python tools/check_manuscript_alignment.py
```

A successful repository check still reports `manuscript_aligned=false`.
`--require-manuscript-aligned` exits nonzero while the original PDF remains
unrevised. Historical logs are retained byte-for-byte; they are not overwritten
with target values or outputs from a different parameter set.

This repository contains the DA-AHE host reference plus a **new independent
reimplementation** of the network experiment and board-measurement workflow.
The default encryption tuple is now **k=6, d=256, n=m=1536, q=2^32,
sigma_key=3.2**. The pinned seven-attack estimator run gives a minimum of
**136.475 bits**, above the requested 128.1-bit heuristic threshold. Single
ciphertexts are **7,168 bytes** (raw two-polynomial reports: 14,336 bytes).
The old k=3 manuscript tuple is retained explicitly as a legacy baseline and
does not meet that threshold. See `configs/security_profile.json` and
`evidence/independent/security-parameter-search/selected-k6-full/verification.json`.
The separate finite-CDT decoding proof gives a one-fresh-batch, 42-choice
adaptive union failure bound below 2^-128; see `security/DECODING_BOUND.md`
for its random-key probability scope and executed interval-arithmetic record.

The original author's simulator, firmware and historical measurements are not
available. New executions are identified separately; no manuscript number is
used as a simulator output or as an acceptance tolerance.

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
python -m pytest -q
```

Real ML-DSA tests additionally need the pinned native provider (see
`docs/INDEPENDENT_REPRODUCTION.md`). They do not silently install a library:

```bash
python -m pip install -r requirements-pq.txt
python -m pytest -q -m pq
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

## Verify and archive evidence

```bash
python tools/independent_manifest.py build --root runs
python tools/independent_manifest.py verify --root runs
```

Generate the manifest only after all processes finish. It refuses overwrites.
Keep the entire bundle, including its manifest, source/config snapshots, inputs,
raw results and execution receipts. A hash verifies bytes, not the truth of a
measurement or proof. `daahe audit` retains its original meaning: it checks for
original-author artifacts and does not relabel new independent runs as originals.

`experiments/paper_targets.json` contains comparison targets from the manuscript;
it is not consumed by the independent simulator. The previous published source
manifest is preserved in `docs/archive/manifest-v0.2.0-original.json`; it is an
archive and does not describe the current tree.

Full generated network traces are excluded from Git and from the small source
ZIP. The complete immutable `DA-AHE-independent-evidence.tar` is distributed as
four assets in the [independent evidence release](https://github.com/KeyComputerScience/DA-AHE/releases/tag/independent-evidence-2026-10-15).
Its SHA-256 is `079aa14358b83d5cf6e132b2c4b653ac2937feeae217c6c6965e1369cff511c0`.
See [PUBLIC_EVIDENCE.md](docs/PUBLIC_EVIDENCE.md) for download, safe extraction,
all-140 raw metric recomputation and archived-source deterministic replay.
The repository's
`evidence/independent/campaign-report/` directory is only a metadata/per-seed
extract; the release supplies the full raw records, all 20 exogenous inputs and
28-file frozen simulator source. Historical `STATUS.json` files remain unchanged;
the new `publication.json` records the current publication state.

## Mandatory CI coverage and claim scope

Every push to main, pull request and manual run executes source integrity,
real-provider protocol/native tests, ARM microbenchmark compilation, small-case
replay, historical 140-case raw recomputation on Linux and strict frozen-source
replay on macOS ARM64/Python 3.12.10, a fresh
20-seed/140-case campaign with replay, seven fresh pinned attack estimates and
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
