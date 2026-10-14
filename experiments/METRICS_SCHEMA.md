<!-- SPDX-License-Identifier: MIT -->
# External experiment input contract

No packet traces or metric results are supplied. `paper_targets.json` contains manuscript targets only. `matrix.json` defines 35 method/size configurations and 20 prospective paired seeds each, totaling 700 runs. `configurations.csv` enumerates those configurations; it references the shared specification rather than pretending to be an executable OMNeT++ INI. Original NED/INI/modules and physical/channel parameters are unavailable.

## Metric CSV consumed by `daahe.statistics`

Use exactly these headers, one row per method/node-count/independent seed:

```csv
run_id,method,nodes,seed,latency_ms,residual_plr,recovery_s,recovery_censored,hve_coverage,warmup_s,duration_s,disturbance_s,measured_window_start_s,measured_window_end_s,trace_sha256,configuration_sha256,calibration_sha256,simulator,measurement_unit
```

- `method`: `da-ahe`, `dpp`, `hys`, `without_markov`, `without_intdb2`, `without_route_repair`, `without_hve`.
- `latency_ms`: nonnegative mean latency of delivered units generated during `[30,300)` seconds, source generation to sink delivery. Author boundary confirmation is required.
- `residual_plr`: fraction in `[0,1]`, not a percentage. Publication value `0.074%` is CSV value `0.00074`.
- `measurement_unit`: `network_packet` or `application_report`. The supplied article does not identify enough instrumentation to equate these automatically. A report-loss result must not be presented as reproduced packet-loss data.
- `recovery_s`: seconds since disturbance onset, ending at the **fifth** consecutive safe control interval. Empty if recovery was not observed by 300 s.
- `recovery_censored`: exact literal `true`/`false`. Do not substitute the observation limit or discard a failed-to-recover seed. If any seed is censored, ordinary mean recovery and normalized recovery CIs are withheld for the entire paired size group. A survival analysis would require a separately specified estimand and protocol.
- `hve_coverage`: fraction of delivered aggregates for which sink end-to-end verification is available. This is neither forgery resistance nor attack-detection probability.
- `warmup_s,duration_s,disturbance_s,measured_window_start_s,measured_window_end_s`: `30,300,100,30,300` for manuscript comparison. Warm-up arrivals do not become valid latency samples simply because they arrived after 30 s.
- `trace_sha256`: checksum of the shared **exogenous** topology/traffic/channel/disturbance bundle for that seed, identical across paired methods. Event-output checksums differ and belong in provenance files.
- `configuration_sha256`: checksum of common experimental boundary/configuration excluding the differing controller choice. Include same initialization, PHY/RPL settings, action library and fixed workload. Version controller-specific configs separately in the evidence index.
- `calibration_sha256`: checksum of the common frozen calibration/certificate bundle. Evaluation seeds must be disjoint from calibration seeds.
- `simulator`: exact string `OMNeT++ 6.0 / INET 4.4`. Do not use this label for any Python surrogate.

The reader rejects missing/nonfinite/out-of-range values, duplicate seeds or run IDs, unpaired seed sets, inconsistent comparison provenance and measurements that include warm-up. Statistical resampling cannot establish that seed streams are truly independent; retain RNG stream configuration and original simulator logs for review.

## Canonical packet-level external export importer

`tools/import_omnet.py` imports instrumented **external** events, not arbitrary `.sca`/`.vec` files. The author simulator must export a complete row for every generated unit, including losses. A source-side counter exported only for successes would make the loss denominator invalid.

Event CSV headers:

```csv
packet_id,created_s,delivered_s,aggregate_id,hve_available
```

`packet_id` must be globally unique. `delivered_s` is empty for units not delivered to the sink by run end. `aggregate_id` identifies the delivered aggregate, with duplicates allowed across constituent units; `hve_available` is `true`/`false` for that aggregate. Both are empty on undelivered units. All constituent rows of an aggregate must agree on HVE availability. No actual event example is shipped because it could be mistaken for measured data.

Recovery telemetry CSV headers:

```csv
time_s,queue_utilization,residual_plr
```

Provide a strictly increasing, complete 1-s sequence covering disturbance onset through 300 s. Fraction-valued queue utilization and residual loss are compared strictly below the original calibrated `S1` thresholds. Missing samples are rejected, never interpolated.

Metadata JSON fields (all required): `schema_version=1`, `run_id`, `method`, `nodes`, `seed`, `simulator`, `measurement_unit`, `event_export_complete=true`, `warmup_s=30`, `duration_s=300`, `disturbance_s=100`, `normal_queue_threshold`, `normal_plr_threshold`, `trace_sha256`, `configuration_sha256`, `calibration_sha256`. Thresholds have no invented defaults.

After author event export, a reviewer may run:

```sh
python tools/import_omnet.py --events AUTHOR-events.csv --telemetry AUTHOR-telemetry.csv --metadata AUTHOR-metadata.json --output results/imported-run.csv
```

Concatenate the metric rows with one header before the statistics command. The importer writes actual source-file hashes to a companion provenance JSON only when executed. It supplies no network implementation and is not an OMNeT++ reproduction by itself.

## Bootstrap protocol

The default is 20 paired independent seeds, 100,000 seed resamples, pointwise 95% percentile intervals. In each resample, use one shared index vector for method and DA-AHE rows and compute `mean(method)/mean(DA-AHE)`. This differs from the mean of per-seed ratios. Raw unnormalized means and their intervals are reported separately. Self-normalized DA-AHE equals one identically when the reference metric is strictly positive. Zero reference values yield an explicitly undefined ratio.

The bootstrap RNG seed (`20261014`) belongs only to analysis and is separate from evaluation seeds. Confidence intervals cannot be reconstructed from the publication's rounded means. No tests, simulations, imports or statistical analyses were executed during package preparation.
