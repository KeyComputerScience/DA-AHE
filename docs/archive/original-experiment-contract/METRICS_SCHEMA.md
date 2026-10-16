<!-- SPDX-License-Identifier: MIT -->
# External experiment input contract

`matrix.json` defines 35 method/size configurations and 20 prospective paired seeds each, totaling 700 runs. `configurations.csv` enumerates those configurations.

## Metric CSV consumed by `daahe.statistics`

Use exactly these headers, one row per method/node-count/independent seed:

```csv
run_id,method,nodes,seed,latency_ms,residual_plr,recovery_s,recovery_censored,hve_coverage,warmup_s,duration_s,disturbance_s,measured_window_start_s,measured_window_end_s,trace_sha256,configuration_sha256,calibration_sha256,simulator,measurement_unit
```

- `method`: `da-ahe`, `dpp`, `hys`, `without_markov`, `without_intdb2`, `without_route_repair`, `without_hve`.
- `latency_ms`: nonnegative mean latency of delivered units generated during `[30,300)` seconds, source generation to sink delivery. 
- `residual_plr`: fraction in `[0,1]`, not a percentage. Publication value `0.074%` is CSV value `0.00074`.
- `measurement_unit`: `network_packet` or `application_report`. 
- `recovery_s`: seconds since disturbance onset, ending at the **fifth** consecutive safe control interval. 
- `recovery_censored`: exact literal `true`/`false`. 
- `hve_coverage`: fraction of delivered aggregates for which sink end-to-end verification is available. 
- `warmup_s,duration_s,disturbance_s,measured_window_start_s,measured_window_end_s`: `30,300,100,30,300` for manuscript comparison.
- `trace_sha256`: checksum of the shared **exogenous** topology/traffic/channel/disturbance bundle for that seed, identical across paired methods.
- `configuration_sha256`: checksum of common experimental boundary/configuration excluding the differing controller choice. Include same initialization, PHY/RPL settings, action library and fixed workload. Version controller-specific configs separately in the evidence index.
- `calibration_sha256`: checksum of the common frozen calibration/certificate bundle.
- `simulator`: exact string `OMNeT++ 6.0 / INET 4.4`. 

## Canonical packet-level external export importer

Event CSV headers:

```csv
packet_id,created_s,delivered_s,aggregate_id,hve_available
```

`packet_id` must be globally unique. `delivered_s` is empty for units not delivered to the sink by the observation cutoff. Every delivered event must identify its nonempty `aggregate_id` and explicit `hve_available=true/false`, with duplicates allowed across constituent units. Both are empty on undelivered units. All constituent rows of an aggregate must agree on HVE availability. A lower-layer packet exporter that cannot meet this association contract must use a reviewed aggregate-event adapter; it may not silently remove missing-ID deliveries from the coverage denominator.

Recovery telemetry CSV headers:

```csv
time_s,queue_utilization,residual_plr
```

Provide a strictly increasing, complete 1-s sequence covering disturbance onset through 300 s. Timestamps are interval ends: the sample at onset describes the preceding interval and is excluded from the five post-onset healthy intervals. Earliest recovery is therefore 5 s. Fraction-valued queue utilization and residual loss are compared strictly below the original calibrated `S1` thresholds.

Metadata JSON fields (all required): `schema_version=1`, `run_id`, `method`, `nodes`, `seed`, `simulator`, `measurement_unit`, `event_export_complete=true`, `warmup_s=30`, `duration_s=300`, `disturbance_s=100`, `normal_queue_threshold`, `normal_plr_threshold`, `trace_sha256`, `configuration_sha256`, `calibration_sha256`, `loss_observation_boundary="window_endpoint_loss"`, `delivery_cutoff_s=300`, `drain_s=0`, `telemetry_timestamp_semantics="interval_end"`.

```sh
python tools/import_omnet.py --events AUTHOR-events.csv --telemetry AUTHOR-telemetry.csv --metadata AUTHOR-metadata.json --output results/imported-run.csv
```


## Bootstrap protocol

The default is 20 paired independent seeds, 100,000 seed resamples, pointwise 95% percentile intervals. In each resample, use one shared index vector for method and DA-AHE rows and compute `mean(method)/mean(DA-AHE)`. This differs from the mean of per-seed ratios. Raw unnormalized means and their intervals are reported separately. Self-normalized DA-AHE equals one identically when the reference metric is strictly positive.
