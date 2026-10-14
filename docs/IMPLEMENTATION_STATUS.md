# Implementation and validation status

Artifact date: 2026-10-14. Delivery status: **SOURCE PREPARED, NOT EXECUTED**.

| Component | Source status | Validation status | Limit |
|---|---|---|---|
| Fixed-tuple M-LWE and packing | implemented | not run | research sampler and Python arithmetic, no constant-time or estimator certificate |
| Tickets, exact roster, HMAC, hidden linear tags, durable Seen | implemented | not run | reference wire format completes missing manuscript choices; not a protocol proof |
| Fixed-support integer signal path | implemented | not run | original IntDb2 lifting constants, boundary rule, support sets and raw sensor data absent |
| Robust control, DPP, HYS | implemented | not run | original model, action library, thresholds and uncertainty certificates absent |
| Calibration and causal replay | implemented | not run | replay cannot measure counterfactual network outcomes; empirical maxima are not universal bounds |
| Paired statistical pipeline and attack tests | implemented | not run | require independent external run data and execution logs |
| Portable embedded arithmetic/stream core | implemented | not compiled | not the Contiki-NG image, not a complete sensor-node firmware |
| Original INET experiment | specification/import path provided | unavailable | original NED/INI/C++ modules, traffic and topology traces absent |
| 128.1-bit estimate and failure <=2^-128 | estimator entry/gates provided | unverified | pinned estimator must execute; certification must match actual sampler/profiles |
| 10-KiB workspace / 28.64-KiB peak | resource-accounting guidance | unverified | require actual ELF/map/role stack measurements |
| Figures 2-6 and Table III numerical results | targets transcribed separately | unverified | no generated per-seed measurements exist in delivery |

No PASS badge, fabricated execution log, trained model, measured value, or synthetic
confidence interval is bundled. `experiments/paper_targets.json` (if present) is an
expectation record, never input to metrics, the controller, or a simulator.

Strict certificate checks reject missing or synthetic evidence. A successful JSON
parse or correct file checksum only establishes structural/integrity properties
of an artifact; it does not establish its claimed experimental or security truth.

This project can be inspected and independently validated by reviewers. It cannot
honestly be described as the complete original paper artifact or as a validated
production deployment until the missing inputs and actual verification are supplied.

