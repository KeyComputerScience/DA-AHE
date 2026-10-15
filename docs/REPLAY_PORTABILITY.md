# Historical replay environment and preserved diagnosis

The immutable independent 140-run archive was generated on macOS ARM64. Exact
replay compares all four compressed raw logs for each seed/method by SHA-256.
It is an environment-scoped check. Raw metric recomputation is a separate
check, using the existing numerical audit rules; it does not imply byte identity
of newly executed floating-point trajectories.

## Observed failure and single-case probes

The complete workflow [38706910917](https://github.com/KeyComputerScience/DA-AHE/actions/runs/38706910917)
failed its historical replay and aggregate gate. Its fresh 140-case campaign,
full same-environment replay, functional/native checks, ARM build and seven
fresh attack/decoding checks passed. The historical download, archive integrity
and raw recomputation completed before exact replay failed for seed 1004,
method `da-ahe`.

A diagnostic probe of that case ran from the same 28 frozen source files and
saved exogenous input, and compared the original expected hashes:

| Hosted probe | Environment | Exact raw gzip hashes | Epoch record difference |
|---|---|---|---|
| [Linux 38718421735](https://github.com/KeyComputerScience/DA-AHE/actions/runs/38718421735) | Linux x86_64, CPython 3.12.15, zlib 1.3 | events, packets, reports match; epochs differs | Record 5, `belief[1]`, one ULP |
| [macOS 38728771700](https://github.com/KeyComputerScience/DA-AHE/actions/runs/38728771700) | macOS 26.6.2 ARM64, CPython 3.12.10, runtime zlib 1.2.12 | All four match | All 26 records match exactly |

The expected belief is `1.5280280276262672e-168`; the Linux result is
`1.5280280276262675e-168`. Their binary64 representations differ by one ULP.
The uncompressed epoch hashes also differ, so this is not solely a gzip
compression difference. OS, architecture, Python and zlib changed together;
these probes do not isolate a single responsible component or establish that
other Linux cases match.

The probe jobs are diagnostic: their exit status alone does not assert equality.
The saved `diagnostic.json` files carry the actual comparisons. Original failed
execution receipts, both probe outputs, exact epoch bytes and local parallel
verifier checks are preserved under
[`evidence/independent/replay-portability/`](../evidence/independent/replay-portability/)
with a separate byte manifest. `classification.json` records findings at the
time of this diagnosis; it is not a receipt for a later full 140-case run.

## Mandatory current checks

The current workflow runs both:

- `history`: macOS 26 ARM64 with Python 3.12.10, full download/integrity check,
  all 140 raw result recomputations and strict frozen-source replay of all 140
  cases, with three isolated workers.
- `history_linux`: Linux, the same immutable download/integrity and all 140
  raw result recomputations. It does not assert cross-platform byte equality.

Both jobs are required by the aggregate gate. The fresh Linux 20-seed campaign
also replays all 140 newly generated cases in its own environment. Its verifier
uses isolated workers and propagates every source-drift or raw-hash failure.
The historical tar, frozen source, target hashes and exact replay criterion
remain unchanged; no tolerance was added to the byte comparison. Each completed
historical verification report records actual Python, platform, architecture,
NumPy and zlib versions.

A single-case match is insufficient to claim a completed full replay. Consult
the actual completed workflow and its `history-verification.json` receipt for
the full-run result. A successful independent CI run cannot verify missing
original-author experiments or physical-board measurements.
