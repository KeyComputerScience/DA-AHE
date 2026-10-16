# Current independent rank-6 evaluation

This generated report replaces unsupported manuscript experiment claims with the available executed independent evidence. It does not modify the original PDF or claim original-paper reproduction, physical-board measurements or full-system certification.

The network table describes the **previously published** 20-seed independent synthetic campaign. It is **not** the fresh CI campaign currently executing. Rebuilding this report recomputes CSV statistics and evidence checks; it does not rerun the network.

Parameters: k=6, d=256, n=m=1536, q=2^32, p=65537, sigma_key=3.2; single ciphertext 7,168 bytes. The seven-attack heuristic minimum is 136.475 bits under the pinned estimator model; it is not a universal security proof.

## Complete network comparison

All seven methods and all 20 paired seeds (1000–1019), including failed deliveries, are retained. All 140 per-seed rows and all recorded metrics/paired differences are public in [current-results.json](current-results.json). Means below give equal weight to seeds.

| Method | Valid delivery / opportunity (%) | Admission / opportunity (%) | Observed loss / admitted (%) | Invalid acceptance / admitted (%) | Mean valid delay (s) | Modeled CPU energy (J/run) | Modeled TX energy (J/run) | Wire bytes / opportunity | Recovery right-censored |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| da-ahe | 35.571667 | 52.603333 | 32.351838 | 0.000000 | 6.858764 | 0.822478 | 65.051240 | 13552.341633 | 20/20 |
| dpp | 34.280000 | 49.613333 | 30.871702 | 0.000000 | 6.606346 | 0.786398 | 62.277996 | 12974.582450 | 20/20 |
| hys | 38.823333 | 58.155000 | 33.239996 | 0.000000 | 6.286537 | 0.898533 | 68.649717 | 14302.024417 | 20/20 |
| without_markov | 44.010000 | 100.000000 | 55.990000 | 0.000000 | 10.840103 | 1.366798 | 105.060650 | 21887.635500 | 20/20 |
| without_intdb2 | 33.395000 | 52.603333 | 36.507686 | 0.000000 | 3.625465 | 0.833538 | 53.389246 | 11122.759550 | 20/20 |
| without_route_repair | 35.571667 | 52.603333 | 32.351838 | 0.000000 | 6.858764 | 0.822478 | 65.051240 | 13552.341633 | 20/20 |
| without_hve | 35.571667 | 52.603333 | 30.264877 | 2.086961 | 6.858631 | 0.820828 | 65.051240 | 13552.341633 | 20/20 |

Configuration: 3000 sensors, 60 gateways, 90 s generation plus 35 s drain, 5 s control interval. Current simulator config matches the archived config byte-for-byte: True. This equality does not make the historical and fresh executions the same run.

Denominators matter: delivery and admission use all raw source opportunities; observed loss and invalid acceptance use admitted reports. Mean valid delay conditions on valid delivery. Lower admitted-only loss can result from suppression or invalid acceptance. without_hve retains its invalid-acceptance result, and without_route_repair retains its identical recorded outcomes; no route-repair benefit is inferred.

Energy is modeled CPU and radio-transmit energy over the complete run, not physical energy or complete protocol energy. Receive/listen, OS and other omitted costs are not silently added. Wire bytes include the model's complete-run accounting per raw opportunity. Packets/nodes are not independent statistical repetitions; no new significance claim is made.

All 140 recoveries are right-censored at the configured 125 s observation end. The 95 s interval from disturbance onset is a censoring interval, **not an observed recovery time**.

## Aggregate-domain fidelity

The executed synthetic matrix contains 72 cases: **54 capacity-admissible and 18 inadmissible diagnostics**. Diagnostic rows remain visible and are not pooled into admitted results. Integer lifting, selection and quantization increments are separated as vectors with their cross terms; RMSE components must not be added. These arbitrary integer-count signals do not reproduce the original Table III or physical sensor units.

| Profile | N | Admissible cases | Diagnostic cases | Aggregate RMSE (integer counts) | Aggregate PRD mean (%) | Aggregate minus summed individual RMSE |
|---|---:|---:|---:|---:|---:|---:|
| pi0 | 1 | 6 | 0 | 2.743673 | 26.935668 | 0.000000 |
| pi0 | 12 | 6 | 0 | 12.656603 | 25.352799 | 1.332865 |
| pi0 | 14 | 6 | 0 | 14.096064 | 24.978106 | 1.466621 |
| pi0 | 16 | 6 | 0 | 15.704628 | 24.802633 | 1.565380 |
| pi1 | 1 | 6 | 0 | 3.112613 | 30.374859 | 0.000000 |
| pi1 | 12 | 6 | 0 | 16.305121 | 28.408065 | 1.423091 |
| pi1 | 14 | 6 | 0 | 18.265965 | 27.701706 | 1.529213 |
| pi1 | 16 | 0 | 6 | 20.340340 | 27.541948 | 1.629458 |
| pi2 | 1 | 6 | 0 | 3.296051 | 31.319363 | 0.000000 |
| pi2 | 12 | 6 | 0 | 18.545900 | 30.702926 | 1.367113 |
| pi2 | 14 | 0 | 6 | 20.800474 | 30.226058 | 1.490560 |
| pi2 | 16 | 0 | 6 | 23.189603 | 30.316357 | 1.607845 |

PRD is null/undefined whenever the true aggregate reference energy is zero, including cancellation. No PRD pass threshold is used to certify the manuscript. Full raw cases, signal definitions, frozen source and recomputation are in evidence/independent/aggregate-fidelity/run-01.

## Structure and finite-horizon arithmetic

At fixed rank 6, two ciphertext payloads (14,336 bytes) become one (7,168 bytes): a 50% sensitive ciphertext payload reduction. At 250 kbps, ideal payload-only airtimes are 458.752 ms and 229.376 ms. These are structural arithmetic/lower bounds, not full-protocol communication or measured latency/energy savings.

| Predeclared fresh-noise batch-attempt cap | Target risk | Exact union-budget decision |
|---:|---:|---|
| 5 | 2^-128 | passes |
| 6 | 2^-128 | rejected |
| 300 | 2^-120 | passes |

The rejected 6-attempt/2^-128 budget is retained. The horizon is an attempt cap, not a number of successful deliveries or seconds. Shared keys and dependence across batches are allowed under the stated fresh-noise/preauthorization assumptions. This is joint random-key/history/noise arithmetic, not an every-fixed-key, arbitrary conditional-history, unlimited-lifetime, network or controller certificate. The Sage bound is consumed without rerunning its proof.

## Provenance and reproduction

current-results.json binds every consumed public input and every report-builder dependency by relative path, byte size and SHA256. The archived network summary/config/controller and completion manifest are crosschecked against all 140 CSV rows; the report builder does not itself replay the full companion raw network archive.

Generate into a new directory: `python tools/build_current_evaluation.py --output-dir <new-dir>`. Check installed generated files: `python tools/build_current_evaluation.py --check`. Both outputs are deterministic; overwriting prior evidence is refused.

Input fingerprint: `bc2df36f83ce8ddaf10263a5981010d8617bf8fb16305638530d61c2d3ddf65c`.

Source fingerprint: `e50229909d2b6bbcb2a331a0a3d435ac05e41fec6c72c56c52979d209b6e1890`.
