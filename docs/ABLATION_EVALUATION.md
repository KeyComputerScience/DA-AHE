# Ablation evidence and measurement definitions

The ablation exporter derives five-method comparisons from a validated campaign:
DA-AHE, Without Markov, Without IntDb2, Without route repair and Without HVE.
The input remains the complete seven-method campaign; selecting the five ablation
methods does not change its provenance, seed identities or accounting rules.
The public rank-6 anchor contains 20 paired seeds (1000--1019), 3,000 source
nodes, 60 gateways and 140 method/seed records.

## Export and artifacts

Install the pinned NumPy, plotting and test dependencies:

```bash
python -m pip install -e '.[dev,evaluation]'
```

Export into a new directory:

```bash
python tools/export_ablation_evaluation.py \
  evidence/independent/campaign-report \
  --output runs/ablation-published --figures \
  --expected-seeds 20 \
  --bootstrap-resamples 100000 --bootstrap-seed 20261017
```

| Artifact | Content |
|---|---|
| `ablation-summary.json` | Metric definitions, scope, availability, estimates and provenance |
| `ablation-per-seed.csv` | Retained method/seed observations and their metric sources |
| `ablation-statistics.csv` | Seed means and percentile-bootstrap confidence intervals |
| `ablation-bars.pdf` | Requested metric panels with their units and confidence intervals |
| `ablation-caption.tex`, `ablation-caption.txt` | Captions generated with the same measurement scope |
| `export-manifest.json` | Input identities, export settings and output hashes |

The campaign loader checks the declared seed/method product, configuration,
controller, summary, input hashes and report-denominator identities. A published
report bundle contains per-seed records and metadata; event-level recomputation
and frozen-source replay use the companion raw archive described in
[PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md). The export retains that distinction and
does not imply that absent raw logs or source snapshots were inspected.
Inputs under `evidence/` are immutable; generated artifacts have their own
directory and manifest.

### Coordinated manuscript Fig. 6 and cost table

Use effective valid delivery, conditional valid-report delay and modeled invalid
acceptance for the manuscript's three-panel ablation figure. Export its companion
cost table from the complete seven-method campaign using the same bootstrap bank:

```bash
python tools/export_ablation_evaluation.py \
  evidence/independent/campaign-report \
  --output runs/manuscript-fig6 --figures --performance-table \
  --metrics valid_delivery_fraction_per_opportunity \
            valid_delay_mean_s invalid_acceptance_fraction_per_admitted \
  --expected-seeds 20 \
  --bootstrap-resamples 100000 --bootstrap-seed 20261017
```

`performance-costs.tex` retains DPP and HYS alongside the five ablation methods;
`performance-costs.json` supplies all table statistics, recovery counts, input
provenance and bootstrap settings. The exporter requires the figure and table to
share the same bootstrap index digest and includes both files in its manifest.
It does not replace the archived inputs.

The recovery column is **20/20 right-censored** for every method. Effective
delivery is normalized by all source opportunities, conditional delay by valid
deliveries, and invalid acceptance by admitted reports.

The LaTeX snippets, parameters and formulas are listed in
[MANUSCRIPT_TABLES.md](MANUSCRIPT_TABLES.md).

## Report and frame denominators

For each seed, let O be offered source opportunities, A admitted reports, V valid
deliveries and I invalid deliveries accepted by the modeled sink. Accepted
delivery is V+I. The principal report metrics are:

- Admission: A/O; effective valid service: V/O.
- Valid delivery among admitted reports: V/A.
- Report loss: (A-V-I)/A, the complement of transport acceptance.
- Modeled invalid acceptance: I/A.

Report loss is neither valid-delivery loss (A-V)/A nor frame loss. Removing HVE
can increase transport acceptance while leaving valid service unchanged.
Undefined denominators retain their seed observations and availability labels;
they do not become zeros or silently disappear from a paired comparison.

`fragment_loss_fraction` requires a separate matched frame-count input through
`--fragment-metrics`. Its denominator is unique offered data frames from source
and aggregate transfers, and its numerator is their terminal frame losses.
Retries are attempts of an existing frame and do not add offered frames. Unresolved
or administratively censored frames remain separate from terminal losses.
Channel-attempt failures, unique-frame outcomes and source-report outcomes have
different denominators. The published report CSV cannot supply frame loss by
renaming its report-loss column. Extra counts must match the campaign's methods,
seeds and configuration identity.

The supplemental input is JSON with schema_version=1,
kind="terminal_frame_counts", the campaign config_digest, and records covering
every selected method/seed pair. Each record contains seed, method,
measurement_unit="network_frame", counting_policy="terminal_after_retries",
scope="source_and_aggregate_transfers_all_run", and integer frames_offered,
frames_delivered, frames_lost, frames_unresolved. The last three counts must
sum to frames_offered. A HVE capability supplement uses kind="hve_capabilities"
and a boolean enabled per selected method/seed, constant within each method.
Fresh raw-log diagnostics under ablation_counts/network_frames retain the
same frame partition; retries remain in the separate attempt counters.

## Recovery and HVE scope

`recovery_event_fraction` describes the fraction of seed records with an observed
qualifying recovery, rather than an average recovery duration. Recovery first
requires an observed excursion and then two sufficiently populated consecutive
five-second good windows under the frozen queue, loss and delay thresholds.
No-excursion records retain a separate label. The archived campaign contains
140/140 right-censored recovery records; its observation horizon is not a
recovery time. A recovery-time mean cannot be obtained by replacing censored
values with that horizon. If `--rmst-horizon` is used, the restricted-mean result
must retain the common horizon, event/censoring counts and survival estimand.

The default `hve_enabled_coverage` panel is a declared method capability: the
modeled end-to-end validity check is enabled for DA-AHE and the first three
variants, and disabled for Without HVE. Values of one and zero describe this
configuration; they are not measured attack-detection probabilities. Fresh
instrumentation also records whether the modeled check was enabled/applied to
eligible reports. Such application coverage retains its own report denominator
and source identity. A `--hve-capabilities` input supplies explicitly matched
capability metadata, not a cryptographic success-rate measurement. Injected
invalidity labels and modeled verification outcomes do not estimate a
cryptographic forgery bound.

## Action identity and immutable variants

All methods keep k=6, d=256, n=m=1536, q=2^32 and p=65537. A ciphertext contains
(6+1) degree-256 polynomials of 32-bit words, totaling 7,168 bytes. The raw
Without IntDb2 path uses two protected ciphertexts, totaling 14,336 bytes before
tickets, headers and retries. Changing encryption noise or retained support is
not a change in long-term public-key rank.

| Variant | Restriction and interpretation |
|---|---|
| Without Markov | Hold the archived nominal row: rho=1, delta_Q=8, N=16, block=64 bytes, repair=0; remove belief-based adaptive selection |
| Without IntDb2 | Retain the policy action library; use two protected ciphertext payloads and remove the configured compression delay |
| Without route repair | Disable repair actuation without rewriting shared profile/action objects |
| Without HVE | Disable the modeled sink aggregate-validity check and its service cost; retain block authentication |

Variant restrictions are immutable configuration properties. They do not
authorize mutation of the common profile library, encryption tuple or stored
archive. The frozen archive's static quantization step is **8**. A step of 16 in
a manuscript Eq. (22) identifies a different action parameterization; it cannot
relabel these records or inherit their numerical results. The archived repair
variant's published delivery, delay and cost records coincide with DA-AHE's;
this equality does not establish a repair improvement.

## Statistics and CI

Seeds are the independent resampling units. The default uses 100,000 percentile
bootstrap resamples with random seed 20261017 and a shared index bank across
methods. Every interval identifies its metric, denominator and availability.
These are mean confidence intervals, not sample SD or prediction intervals.
The paired design alone does not establish statistical significance, controller
certification, a physical-board result or an isolated causal mechanism effect.

The independent [ablation workflow](../.github/workflows/ablation-evidence.yml)
runs on main pushes, every pull request and manual dispatch. It installs the
declared dependencies, exercises ablation/statistical and network-audit tests,
exports the public anchor into `runs/ablation-evidence`, checks that the archived
inputs remain unchanged, and uploads the JSON, CSV, PDF, captions and command
receipts. It is separate from the main reproduction workflow and its required
job set. Local equivalents are:

```bash
python -m pytest --strict-ci -q \
  tests/test_ablation_analysis.py tests/test_ablation_instrumentation.py \
  tests/test_performance_export.py \
  tests/test_simulation_network.py tests/test_simulation_rosters.py
```

The evidence concerns an independent synthetic service model with uncalibrated
controller fixtures and modeled CPU/TX costs. Network report records, frame
instrumentation, capability metadata, aggregate reconstruction and cryptographic
security analysis retain their separate scopes.
