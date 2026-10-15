# Public independent 20-seed evidence

The immutable bundle contains the **independent** campaign completed on
2026-10-15: seeds 1000–1019, seven methods, **140 runs**. These are newly
generated synthetic experiments from an independent implementation. They are
not recovered original-author experiments, OMNeT++/INET results, or measured
nRF52840 data. Publishing their raw files does not establish that all manuscript
claims have been reproduced.

The release location is
[independent-evidence-2026-10-15](https://github.com/KeyComputerScience/DA-AHE/releases/tag/independent-evidence-2026-10-15).
The machine-readable download URLs, sizes, and pinned SHA-256 values are in
[`publication.json`](../evidence/independent/publication.json). Its
`publication_state` records whether remote asset availability has been verified.

## Bundle identity and contents

The four assets are consecutive pieces of `DA-AHE-independent-evidence.tar`.
They are not individually extractable tar files. The first three pieces are
838,860,800 bytes each; the fourth is 510,842,880 bytes. Their concatenation is
3,027,425,280 bytes with SHA-256:

```text
079aa14358b83d5cf6e132b2c4b653ac2937feeae217c6c6965e1369cff511c0
```

The archive has 1,194 regular files: 1,193 entries in the evidence manifest and
the manifest itself. It includes all 140 run manifests and summaries, raw
events/packets/reports/epochs gzip logs, the paired exogenous inputs for all
20 seeds, the controller/configuration and bound cryptographic reports, the
28-file frozen simulation source, and the previously recorded protocol,
security, decoding and firmware build evidence.

No historical byte is replaced. In particular, the archived `STATUS.json`
describes the state when the bundle was created; the current publication state
is recorded separately in `publication.json`.

## Download, checksum and recompute every saved run

Use a Python 3.12 environment with the repository's pinned dependencies. From
the repository root:

```sh
python -m pip install -e '.[dev]'
python tools/verify_published_evidence.py \
  --extract-dir work/published-evidence \
  --recompute --jobs 2 \
  --report runs/published-evidence-verification.json
```

The destination must not already exist. Downloads are cached under
`work/release-cache`; use `--cache-dir` to change it. For already downloaded
parts, use `--assets-dir /path/to/parts` to prohibit network downloads. Allow
approximately 7 GB of free disk space for the downloaded parts and extracted
evidence. The helper streams consecutive pieces without writing another copy of
the tar, rejects unsafe archive paths, links and duplicate members, checks every
manifest entry, verifies the exact 20 × 7 design, then independently rederives
all 140 saved metrics and the paired campaign summary from the raw records.

## Replay every historical case with the frozen source

Use **macOS ARM64 with Python 3.12.10** for the hosted historical byte-replay
check. The published single-case probe matched the original macOS records in
this environment; the full 140-case CI remains the actual full-run test.
Add `--replay` to rerun all 140 historical seed/method cases and compare the four
raw gzip SHA-256 values for each run:

```sh
python tools/verify_published_evidence.py \
  --extract-dir work/published-evidence-replay \
  --recompute --replay --jobs 2 \
  --report runs/published-evidence-replay.json
```

This is substantially more expensive than checksum validation or raw metric
recomputation. The helper starts isolated subprocesses from the **archived frozen
source** and runs up to `--jobs` cases in parallel. Historical source digest:

```text
ba9749ce35d4b401afabae8e333aaedc1521dfcedd7d7b35f44affc4cc8f579a
```

Current verifier improvements changed source files after the original
independent campaign. Running the current verifier directly with `--replay`
against that old campaign correctly refuses the drift; use the publication
helper above to select the preserved source. Exact gzip replay is an explicit
check in the tested environment, rather than a promise of byte equality under
every Python/zlib/platform combination. A mismatch fails verification and must
be investigated. The preserved Linux probe found a one-ULP belief-record
difference; events, packets and reports matched. See
[REPLAY_PORTABILITY.md](REPLAY_PORTABILITY.md) for both actual probe results and
the separate mandatory Linux raw recomputation check. Neither the historical
archive nor its strict replay comparison was modified.

## What the evidence can establish

Successful checks establish public availability and integrity of the bundle,
raw-to-summary consistency for the declared independent experiment, and (when
requested) deterministic rerunning of its saved cases. They do not turn modeled
radio/CPU energy into physical measurements, certify the synthetic controller,
validate an unavailable original simulator, or justify transferring manuscript
`k=3` performance numbers to the independently selected `k=6` parameters. The
number of physical-board samples remains zero.
