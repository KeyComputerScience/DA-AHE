# Changelog

## 0.2.0 - 2026-10-14

- Restore missing ignore files and add commit-pinned push/PR/manual CI source.
- Add persistent one-report-per-ticket/source emission and byte-identical retries.
- Replace time-window truncation with two-level full-window reference lifting;
  bind transform identity into the immutable profile digest.
- Bind strict model evidence to current model, action, context and controller identity.
- Separate observed and next-action noise in calibration and fit DPP queue increments.
- Preserve unavailable metrics/all-loss seeds; validate complete experiment matrices;
  connect statistics JSON directly to plots and handle estimator-derived samples.
- Add streaming C tag interface and independent portable-core known-answer tests.
- Preserve source-manifest baseline instead of overwriting it before verification.

All fixes and new tests are source-prepared and statically reviewed, unexecuted.
The transform/schema changes require new profiles and calibration; they do not
retroactively validate original paper results or absent author certificates.

## 0.1.0 - 2026-10-14

- Independent DA-AHE mathematical/protocol reference implementation.
- Safety-gated robust control, DPP/HYS baselines and explicit synthetic replay.
- Paired-seed statistics, source/evidence hashing and pinned-estimator entry point.
- Portable no-heap embedded arithmetic and block accumulator.
- MIT license, provenance boundaries, reviewer/deployment documentation.

Validation status: source prepared and statically reviewed; no project execution,
build, tests, simulations, training, hardware profiling or estimator execution.

