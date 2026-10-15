# DA-AHE independent reproduction and evidence

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
replay, historical 140-case download/recomputation/frozen-source replay, a fresh
20-seed/140-case campaign with replay, seven fresh pinned attack estimates and
exact-CDT Sage decoding checks. The aggregate check fails if any required job is
missing, skipped, cancelled or unsuccessful. Full runs can take substantially
longer than functional tests; workflow configuration alone is not a successful
execution receipt.

The [claim coverage matrix](docs/REPRODUCTION_COVERAGE.md) distinguishes the
independent implementation from unverified manuscript claims. Complete software
CI and public synthetic records do not establish original-paper reproduction,
physical-board timing/energy/stack measurements or full-system certification.
Those states remain false in the machine-readable claim contract.

Original code is under MIT. See `LICENSE` and `THIRD_PARTY.md` for dependencies.
