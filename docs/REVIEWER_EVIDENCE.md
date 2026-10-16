# Reviewer evidence map for DA-AHE

This map connects the supplied manuscript to the current independent reference
implementation and the evidence that actually exists. The machine-readable
companion is [configs/paper_claims.json](../configs/paper_claims.json). Neither
file edits the PDF, certifies the system, nor predicts an editorial decision.

The inspected file is **TSMC_DA (1).pdf**, 14 pages, SHA-256
`ad09feb7fa00a87bf0dd342a1b929a0d776cb087e8420169556d85f3139d3fc5`.
Its extracted text is identical to the previously inspected manuscript despite
the changed PDF hash. It still states k=3/n=768, 4,096-byte ciphertexts,
128.1 bits and the historical board/network results. No editable manuscript
source has been supplied. The repository's revised k=6 evidence is therefore
not evidence that those PDF claims have been corrected. See
[MANUSCRIPT_CORRECTIONS.md](MANUSCRIPT_CORRECTIONS.md).

## How to read the evidence

- **reproduced_independent_scope** means a preserved independent result exists
  within the explicitly stated scope. It never means original-paper reproduction.
- **implemented_not_original_measurement** means code and review/test interfaces
  exist, without treating implementation as the original experiment.
- **requires_original_data**, **requires_hardware** and **requires_proof** identify
  the missing evidence needed for the associated manuscript claim.

Verification commands are instructions for a new run, not execution receipts.
Use new output directories. ML-DSA trials require the explicitly installed real
provider; fresh decoding calculations require Sage-enabled Python and the
pinned estimator source where specified. Successful unit tests cannot establish
a 2^-128 tail or validate a physical measurement. Current public release
locations are in [publication.json](../evidence/independent/publication.json);
historical logs/status snapshots and their hashes remain unchanged.

The [seven-step execution receipt](../evidence/independent/reviewer-suite/run-01/suite-receipt.json) records the new suite, its source/input snapshots and raw outputs. Its 72 case bytes match the published fidelity bundle. The [43-test receipt](../evidence/independent/reviewer-suite/run-01/tests-receipt.json) covers the four new test modules; it is not a replacement for the full host/PQ/Sage CI suite.

## Claim-to-implementation-to-evidence matrix

Module links below identify the canonical `src/daahe/` implementation. Full
commands and the required evidence for each original claim are in the JSON
companion under the same claim IDs.

| Claim and exact manuscript locus | Current code | Existing evidence and check | Scope and evidence still required |
|---|---|---|---|
| **security_parameter_estimate** — pp. 3-4, p. 6, p. 12 Eq. (24) | [mlwe.py](../src/daahe/mlwe.py), [parameterized estimator](../tools/estimate_security_parameters.py), [selected profile](../configs/security_profile.json) | [k=6 report](../evidence/independent/security-parameter-search/selected-k6-full/security.json), [preserved k=3 report](../evidence/independent/security/run-01/security.json); `python tools/check_manuscript_alignment.py` | k=6 complete seven-attack minimum 136.475 bits. The incomplete legacy run already contains a successful 51.94-bit attack estimate. A changed tuple does not repair the original record. The estimate is heuristic generic flattened-LWE analysis, not an actual-CDT/module/all-attack proof. |
| **single_ciphertext_payload** — abstract, p. 4 Algorithm 1, p. 8 Eq. (16), p. 9 Eqs. (17)/(19), p. 11 Eq. (23) | [profiles.py](../src/daahe/profiles.py), [pack_values](../src/daahe/protocol.py), [alignment checker](../tools/check_manuscript_alignment.py) | [alignment contract](../configs/manuscript_alignment.json); parameter/encryption tests | Current structural ciphertext payload is 14,336→7,168 bytes; one-hop payload-only serialization is 458.752→229.376 ms at 250 kbit/s. Tickets, MACs, headers, fragmentation and retries remain additional. Complete communication and fidelity benefits require measurement. |
| **encoded_additive_aggregation** — p. 3 pipeline, p. 4 Eq. (7), pp. 4-5 Algorithms 1-3 | [ring.py](../src/daahe/ring.py), [mlwe.py](../src/daahe/mlwe.py), [protocol.py](../src/daahe/protocol.py) | [claim coverage](../evidence/independent/claim-coverage.json), public archive host tests/trials; `python -m pytest -q tests/test_crypto_protocol.py tests/test_parameterized_encryption.py` | Encoded quantized coefficient/tag sums modulo p, with data no-wrap and decoding assumptions. Rounded inverse lifting of an aggregate is not necessarily the physical sum. Aggregate-domain distortion must be evaluated separately. |
| **roster_integrity_and_postquantum_authorization** — pp. 5-7, Eqs. (9)-(14) | [protocol.py](../src/daahe/protocol.py), [signatures.py](../src/daahe/signatures.py), [derivation.py](../src/daahe/derivation.py) | Indexed real-provider fresh-key trials in the public archive; `python tools/run_protocol_trials.py --module-rank 6 --trials 20 --output runs/reviewer-integrity-trials` | Functional rejection of tested tampering, roster/profile changes and replay. Trusted sources/sink and secret derivations remain assumptions. Gateway HMACs do not protect against that gateway; tag guessing is one reduction term, not an overall security level. A reviewed reduction remains separate evidence. |
| **durable_source_emission_and_replay** — p. 4 Algorithm 1, p. 6 one-envelope statement, p. 7 Seen/Eq. (13) | [SourceEmissionStore and ReplayStore](../src/daahe/protocol.py), [source-ledger tests](../tests/test_source_ledger.py) | Source inspection and targeted tests; [alignment contract](../configs/manuscript_alignment.json) | Add the required one-distinct-report-per-ticket/source-offset condition to Algorithm 1 and the theorem. Reusing an offset for two reports can enable affine recombination. SQLite is not a board anti-rollback driver; Seen is at-most-once acceptance, not durable exactly-once delivery. |
| **finite_sampler_decoding** — p. 3 Eq. (3), p. 4 capacities, p. 7 Eq. (13), p. 10 profiles | [CDT implementation](../src/daahe/mlwe.py), [interval calculation](../tools/certify_decoding_bound.py), [record verifier](../tools/verify_decoding_record.py) | [bound](../evidence/independent/decoding/k6-cdt-03/decoding-bound.json), [actual CDT](../evidence/independent/decoding/k6-cdt-03/sampler-cdts.json), [record verification](../evidence/independent/decoding/k6-cdt-03/record-verification.json); `python tools/verify_decoding_record.py evidence/independent/decoding/k6-cdt-03` | Executed k=6 actual-CDT interval bound, including scaling carry; 42-choice single-batch union log2 upper bound about -130.5101732. Joint random-key/fresh-batch probability, not every fixed key, arbitrary observed history or unlimited lifetime. |
| **finite_horizon_decoding_budget** — p. 3 Eq. (3), p. 7 Eq. (13), pp. 7-8 adaptive controller | [exact budget checker](../tools/check_decoding_horizon.py), [risk specification](DECODING_RISK_BUDGET.md) | [executed records](../evidence/independent/decoding-horizon/run-01/execution.json): B=5/target128 passes, B=6 rejects, B=300/target120 passes | Exact union budgeting, with no independence assumption. Maximum B is 5 for 2^-128 and 1458 for 2^-120. Joint random-key/fresh-noise scope; the deployment horizon and attempt/roster/key lifecycle remain to be declared. |
| **aggregate_physical_fidelity** — p. 3 pipeline, p. 5 Algorithm 3, p. 13 Eq. (25)/Table III/2.50% threshold | [fidelity tool](../tools/check_aggregate_fidelity.py), [method specification](AGGREGATE_FIDELITY.md), [signal.py](../src/daahe/signal.py) | [72-case index/raw records](../evidence/independent/aggregate-fidelity/run-01/index.json), [summary](../evidence/independent/aggregate-fidelity/run-01/summary.json), frozen source and hashes; `--verify` recomputes every case | 54 capacity-admissible cases plus 18 explicitly inadmissible diagnostics; integer-lifting, selection and quantization attribution; zero/cancelling PRD is null. Declared synthetic integer counts only. Original Table III still requires its corpus and physical scaling. |
| **strict_belief_control_and_stability** — p. 3 Eqs. (1)-(4), pp. 7-8 Eq. (15)/Algorithm 6/theorem, p. 9 calibration | [control.py](../src/daahe/control.py), [calibration.py](../src/daahe/calibration.py), [safety.py](../src/daahe/safety.py), [implementation specification](CONTROL_IMPLEMENTATION_SPEC.md) | [synthetic fixture](../configs/control_synthetic.json), [claim coverage](../evidence/independent/claim-coverage.json); control/binding/evidence tests | Implemented equations and fail-closed evidence gates; the fixture is uncertified. Need separated training/holdout/evaluation traces, valid uniform radii, exact action/model coefficients, fallback certificate and invariance/exit handling. Mean-square ultimate boundedness does not mean zero QoS violations. |
| **full_protocol_workspace_and_memory** — p. 3 Eq. (3), pp. 4/8 streaming, p. 13 Table II | [core C](../embedded/daahe_core.c), [board harness](../firmware/nrf52840/benchmark.c), [collector/verifier](../tools/verify_board_measurements.py) | [board-pending record](../evidence/independent/firmware/selected-k6/board-pending.json), indexed core-build metadata | Physical samples=0. Core build sizes are not the complete Contiki-NG protocol, measured stack high-water, 29,328-byte peak or full-role 10-KiB workspace certificate. Supply full linked firmware, buffer lifetimes and physical per-role stress captures. |
| **board_timing_energy_and_airtime** — pp. 8-10, Eqs. (17)-(21), Table I, p. 13 prototype | [firmware build](../firmware/build.py), [measurement verifier](../tools/verify_board_measurements.py), [simulation accounting](../simulation/engine.py) | Board-pending and alignment records | 58.125 ms/1.395 mJ and the weighted 77.199-ms bound are historical k=3 claims. No new k=6 board timing/power samples exist. Include signatures/KDF/MACs, ledger, OS/interrupt, receive/listen, relay and full framing costs before comparing complete protocols. |
| **original_network_and_ablation_figures** — pp. 9-12, Figs. 2-6, Eqs. (22)-(23) | [independent simulator](../simulation/engine.py), [policy](../simulation/policy.py), [statistics](../src/daahe/statistics.py), [external importer](../tools/import_omnet.py) | [independent summary](../evidence/independent/campaign-report/summary.json), [public archive index](../evidence/independent/publication.json) | Independent Python: 3,000 sensors/60 gateways, 90+35 s. PDF: OMNeT++/INET/RPL, up to 5,000 nodes/16 gateways, 300 s. Historical low-loss/latency/recovery/comparative percentages remain unverified; all independent recoveries are censored and repair was not triggered. |
| **public_independent_campaign_audit** — supports p. 9 paired seeds and p. 12 reproducibility, without validating historical figures | [published-evidence verifier](../tools/verify_published_evidence.py), [raw verifier](../tools/verify_simulation_campaign.py), [manifest checker](../tools/independent_manifest.py) | Publication index: 20 seeds × 7 methods = 140 independent runs, immutable four-part archive; commands in [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) | Verifies archive identity and raw-to-summary consistency. Frozen-source replay has a documented environment boundary; Linux one-ULP differences remain disclosed. Hashes do not establish measurement truth, certification or original-paper reproduction. |

## What the existing contribution can responsibly support

The clearest contribution is the inspectable connection between a signed
aggregation configuration and a controller's admissible action library:
configuration/roster binding, one-time source emission, encoded aggregation,
an actual-sampler decoding analysis, and explicit resource/model evidence gates.
The controller can be reviewed as a constrained sensing-to-sink service rather
than as a claim to control a downstream physical plant.

This is a candidate system contribution, not evidence of novelty merely from
combining named components. [SLAP's formal 2023 publication](https://link.springer.com/article/10.1007/s00145-023-09450-w)
already treats optimized RLWE private stream aggregation.
[SoA-SDA](https://www.sciencedirect.com/science/article/abs/pii/S0167739X25006156)
already describes compression-based lattice encryption with adaptive in-network
aggregation/routing and integrity mechanisms.
[Predictive safety filtering](https://www.sciencedirect.com/science/article/pii/S0005109821001175)
and [belief-space barrier filtering](https://arxiv.org/abs/1903.07823) are existing
methods. The paper should identify its additional configuration-dependent
feasibility/acceptance conditions, prove their scope, and measure the associated
useful-service gain. Do not describe a standard Lyapunov recursion or an HMM
alone as new control theory.

A useful focused research question is:

> Under one fixed primitive parameter set and declared key/mission lifecycle,
> can belief-aware selection among jointly admissible aggregation profiles
> increase deadline- and fidelity-qualified verified delivery, compared with
> static or more conservative controllers, while preserving explicit
> configuration correctness and resource/model constraints?

The minimum convincing controller comparison holds the crypto envelope,
offered sensing workload, fidelity constraint and action library constant:
static admissible configuration; DPP with the same filter; worst-case
all-regime filter without belief; nominal belief control without uncertainty
margin; and the full method. External crypto/system comparisons must disclose
different threat models and include their missing authentication costs where
matched capability is claimed. Count all exogenous sensing opportunities;
sampling less or refusing reports cannot remove unmet work from the denominator.

## Completed additions and remaining priority evidence

1. **Aggregate fidelity completed within synthetic scope:** 72 cases, raw inputs,
   frozen source, exact error decomposition and complete recomputation are public.
   Original Table III still requires its real trace corpus and physical scaling.
2. **Finite horizon arithmetic completed:** exact budgets and the expected
   six-batch rejection are public. Declare the actual deployment horizon, attempt
   count and lifecycle before interpreting any task-level target.
3. **Control certificate:** publish the training/holdout/evaluation split,
   model/radius scope and a fallback/invariant-domain argument. A source hash or
   a sampled-trajectory pass cannot substitute for these hypotheses.
4. **Complete board path:** acquire real k=6 per-role cycle, power and stack
   captures for the complete protocol. Keep core microbenchmarks separate.
5. **Matched network campaign:** run scenarios with actual constraint/fallback
   and repair activation; publish all seeds, useful-delivery denominators,
   censoring and full protocol costs. Preserve adverse outcomes.

## Archive-level evidence locations

The small source checkout does not contain every raw historical record.
The public archive expands beneath `evidence/independent/`; relevant
archive-relative records include:

- `tests/final-host-02/execution.json` and the associated host-test logs;
- `protocol/selected-k6-trials/summary.json`;
- `security-parameter-search/selected-k6-full/verification.json` and per-attack logs;
- `firmware/selected-k6/build-metadata.json` and `firmware/selected-status.json`;
- `simulation/`, `simulation-execution/execution.json` and
  `simulation-verification/stdout.log`.

Use the publication helper to fetch/check the complete archive before relying
on any not-yet-local raw path. Preserved indices report prior executions; the
commands in this map do not assert that those executions were repeated in the
current source tree. Newly generated fidelity/horizon or other evidence belongs
in separate records with new source/config/input hashes. Never change historical
logs, statuses or digests to make them agree with a later manuscript or source.

