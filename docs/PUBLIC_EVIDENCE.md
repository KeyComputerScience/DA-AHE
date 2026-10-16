# Public twenty-seed campaign evidence

The hash-pinned bundle contains the synthetic campaign completed on
2026-10-15: seeds 1000–1019, seven methods and 140 runs. The experiment uses the
specified Python packet/block service model, not a physical nRF52840 or full
radio/RPL implementation. Its controller fixture is uncalibrated and its costs
are modeled. [Evaluation](EVALUATION.md) and
[complete results](../experiments/CURRENT_RESULTS.md) describe the measurements,
denominators, all seven methods and scientific scope.

Download the bundle from
[independent-evidence-2026-10-15](https://github.com/KeyComputerScience/DA-AHE/releases/tag/independent-evidence-2026-10-15).
[publication.json](../evidence/independent/publication.json) records the asset
URLs, sizes, SHA-256 values and verified availability state.

## Bundle identity and contents

The four assets are consecutive parts of `DA-AHE-independent-evidence.tar`.
They cannot be extracted individually. The first three are 838,860,800 bytes
each and the fourth is 510,842,880 bytes. Concatenated size is 3,027,425,280 bytes,
with SHA-256:

```text
079aa14358b83d5cf6e132b2c4b653ac2937feeae217c6c6965e1369cff511c0
```

The archive has 1,194 regular files: 1,193 manifest entries and the manifest
itself. It includes all 140 run manifests/summaries, raw events/packets/reports/
epochs gzip logs, paired exogenous inputs for all twenty seeds, controller and
configuration data, bound cryptographic reports, a 28-file frozen simulator
source snapshot, protocol/security/decoding records and core firmware build
evidence. The archived `STATUS.json` identifies execution state at bundle
creation; `publication.json` identifies the public assets.

## Download, verify and recompute every record

From the repository root, use Python 3.12 with pinned dependencies:

```sh
python -m pip install -e '.[dev]'
python tools/verify_published_evidence.py \
  --extract-dir work/published-evidence \
  --recompute --jobs 2 \
  --report runs/published-evidence-verification.json
```

The extraction destination must not exist. Downloads are cached under
`work/release-cache`; `--cache-dir` selects another cache. To use already
available parts without network downloads, pass `--assets-dir /path/to/parts`.
Allow approximately 7 GB of free space for parts and extracted evidence.

The helper streams the parts without making a second tar copy, rejects unsafe
paths, links and duplicate members, checks every manifest entry, verifies the
20-by-7 design and independently derives all saved metrics and the paired
summary from raw records. Every method, failed/unadmitted opportunity, invalid
acceptance and censored recovery remains in the evidence. All 140 recoveries
are right-censored; repair was not triggered. These outcomes are not converted
into successful recovery times or a claimed repair benefit.

## Replay the saved cases with their frozen source

Use macOS ARM64 with Python 3.12.10 for the documented byte-replay environment.
The recorded single-case probe matched its archived macOS output; a full
140-case replay is a separate check with its own completion receipt. Add
`--replay` to rerun every seed/method case and compare each run's four raw gzip
SHA-256 values:

```sh
python tools/verify_published_evidence.py \
  --extract-dir work/published-evidence-replay \
  --recompute --replay --jobs 2 \
  --report runs/published-evidence-replay.json
```

The helper launches isolated subprocesses from the archive's frozen source and
runs up to `--jobs` cases concurrently. The recorded source digest is:

```text
ba9749ce35d4b401afabae8e333aaedc1521dfcedd7d7b35f44affc4cc8f579a
```

Replay is bound to this source identity. Invoking a different checkout's
simulator directly against the bundle can fail the source check; the helper
selects the correct snapshot. Exact gzip equality is checked in the recorded
environment, not promised for every Python/zlib/platform combination. A
mismatch fails verification. The Linux probe found a one-ULP belief-record
difference while events, packets and reports matched. Both probe records and
the separate Linux raw-recomputation check are documented in
[REPLAY_PORTABILITY.md](REPLAY_PORTABILITY.md).

## Meaning of a successful check

Archive checks establish asset identity, listed-byte integrity, raw-to-summary
consistency and, when requested and completed, replay of the saved cases.
They do not turn modeled CPU/TX energy into physical measurements, calibrate the
controller, establish a physical signal distribution or certify a deployment.
Physical-board samples remain zero. Configuration, host tests, cryptographic
cost estimates, decoding bounds and network outcomes retain their distinct
assumptions and evidence boundaries.
