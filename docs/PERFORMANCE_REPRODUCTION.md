# Performance records, tables and figures

The evaluation pipeline binds each comparison to its configuration, controller,
source hashes, paired seeds and runtime identity. Numerical tables and figure
panels are derived from per-seed records. Manuscript values are not inputs to
the metric calculation or acceptance tolerances.

## Install

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,evaluation]'
```

Python dependencies are pinned in `pyproject.toml` and `requirements-dev.txt`.
The matrix plan also records Python, NumPy, architecture and byte order. Keep
this identity with the source and configuration snapshots when comparing runs.

## Export the published paired records

```bash
python tools/export_performance_evaluation.py \
  evidence/independent/campaign-report \
  --output runs/performance-published \
  --bootstrap-resamples 100000 --bootstrap-seed 20261016
```

The repository report bundle contains the 140 paired per-seed records, their
summary and declared provenance. Export checks the complete declared
seed-by-method matrix, configuration and summary hashes, denominators and
paired differences. Event-level recomputation uses the full raw archive and
commands in [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md). Each export states which
input snapshots were available and which checks it performed.

The output directory contains:

| Artifact | Content |
|---|---|
| `per-seed.csv` | Every declared method and seed, including undefined and censored observations |
| `summary.json` | Means, sample SD, paired differences and ratios of means, percentile intervals and availability counts |
| `tables.md`, `table.tex` | Tables generated from those records |
| `revised-DA_energy_comparison.pdf` | Modeled CPU and transmit-radio cost by method |
| `revised-packetC.pdf` | Delivery and loss fractions with their explicit denominators |
| `revised-MarkovR.pdf` | Recorded controller telemetry for the prespecified smallest seed, or recorded evidence coverage |
| `revised-baseline.pdf` | Paired DA-AHE, DPP and HYS comparisons |
| `revised-ablationA.pdf` | Valid delivery per opportunity, conditional delay and modeled invalid acceptance |
| `export-manifest.json` | Input identities, export parameters and output hashes |

Captions and axes identify the statistic actually plotted. Conditional valid
delivery delay is reported alongside valid delivery per offered opportunity.
Recovery completion is measured from disturbance onset; right-censored runs
retain their censoring status rather than becoming recovery durations. An
undefined seed metric remains in the dataset and prevents a complete-cohort
paired estimate for that metric. Zero denominator ratios are withheld.

Bootstrap resampling uses seeds as the statistical unit and the same PCG64
index matrix for every method. The default is 100,000 resamples and a 95%
percentile interval. The index-matrix hash, random seed, NumPy version and
quantile rule are included in the export. Ratios compare means on the complete
paired cohort; they are not means of per-seed ratios.

## Generate a size-by-seed comparison

```bash
python tools/run_performance_matrix.py \
  --output runs/performance-matrix --jobs 4
```

`simulation/performance_matrix.json` specifies five source counts
(1,000--5,000), 20 paired seeds (1000--1019), and seven methods: DA-AHE, DPP,
HYS and four component ablations. The complete product is 700 cases.
The default scenario has 300 s of report generation, a 30-s warm-up,
disturbance from 100 to 130 s, the base configuration's drain interval and
5-s control intervals. Timing and network assumptions are preserved in each
effective configuration.

The runner freezes its inputs and sources, generates each campaign, invokes
independent event-level metric recomputation, and exports the resulting tables
and panels. It publishes the matrix result manifest only after all cases and
their checks succeed. The result binds every campaign, verification record and
export. Existing evidence directories are protected against replacement.

For a smaller reproducible integration cohort:

```bash
python tools/run_performance_matrix.py \
  --output runs/performance-small --node-counts 10 --seeds 61,62 \
  --jobs 2 --bootstrap-resamples 1000
```

A duration override scales warm-up and disturbance times by `duration/300`.
The control interval, sampling period, deadlines and drain retain their declared
values. Gateway and contention-domain counts are capped by available nodes
for small cohorts. The plan records every effective value.

## Model and comparison contract

The independent Python discrete-event model represents two-hop transfers,
fragmentation, transmitter queues, retries and whole-roster completion. The
rank-6 wire contract is `k=6`, `d=256`, `q=2^32`, `p=65537`: one protected
ciphertext is 7,168 bytes; the raw two-polynomial representation is 14,336
bytes. Payload-only serialization at 250 kbit/s is respectively 229.376 and
458.752 ms. Total wire cost additionally includes tickets, block tags, headers
and retransmissions.

CPU service times and transmit-radio energy follow the configured cost model.
Their units and accounting horizon accompany the results. Board measurements,
OMNeT++/INET records and receive/listen accounting are separate evidence
categories. The matrix preserves the existing synthetic controller coefficients
and uses an explicitly declared common nominal initialization. Its candidate
library is shared; DA-AHE retains its additional robust drift gate. Identical
DPP queue-increment coefficients remain disclosed in the plan, so this reference comparison
does not establish action-specific queue calibration. A final partial roster is
fixed at authorization under the service-model grouping-cap convention; the
protocol's exact-cardinality adapter is a separate contract.

External packet-level records use `tools/import_omnet.py` and the schema in
`docs/archive/original-experiment-contract/METRICS_SCHEMA.md`. Preserve their
backend, versions, workload and metric definitions. A Python service-model
export must retain its own model identity.

## Continuous integration

The performance job checks matrix/export contracts, exports the published
paired records with 100,000 bootstrap resamples, and exercises the complete
pipeline on two paired integration seeds. The full source, functional,
firmware, replay, historical, campaign and security jobs remain required by
the aggregate coverage gate. Workflow-trigger checks reject commit directives
and conditional filters that suppress required coverage. Strict pytest mode
treats a skipped test or collection report as a coverage failure; host, native
PQC and Sage suites use explicit environment partitions.
