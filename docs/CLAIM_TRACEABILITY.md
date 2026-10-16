# Method, implementation and evidence traceability

DA-AHE uses fixed Module-LWE parameters k=6, d=256, n=m=1536, q=2^32,
p=65537 and sigma_key=3.2. The method specification is
[PARAMETER_PROTOCOL.tex](manuscript/PARAMETER_PROTOCOL.tex); experimental
boundaries and complete results are in [Evaluation](EVALUATION.md) and
[CURRENT_RESULTS.md](../experiments/CURRENT_RESULTS.md).

Module filenames in the table refer to the canonical `src/daahe/` package.
The [machine-readable index](../configs/paper_claims.json) retains implementation
paths, verification commands, evidence hashes and scope requirements.

| Method claim | Code | Evidence and scope |
|---|---|---|
| Fixed-parameter M-LWE encryption | `ring.py`, `mlwe.py`; `tools/estimate_security_parameters.py` | [Selected profile](../configs/security_profile.json) and [seven-attack report](../evidence/independent/security-parameter-search/selected-k6-full/security.json): minimum 136.475 bits under the recorded heuristic models. |
| Profile-bound packing | `profiles.py`, `protocol.pack_values` | Up to 240 data coefficients plus 16 tags fit in one polynomial. A ciphertext is 7,168 bytes; the raw two-polynomial path is 14,336 bytes. Headers and authentication add wire cost. |
| Canonical signed authorization | `protocol.Ticket`, `signatures.py`, `profiles.py` | Ticket/roster/profile/context/nonce/parameter binding is exercised by host and real-provider tests. Key provisioning and trusted-endpoint assumptions remain explicit. |
| Hidden linear aggregate tag | `derivation.py`, `protocol.aggregate`, `protocol.Sink.accept` | [Protocol trials and host records](PUBLIC_EVIDENCE.md) cover tested valid, tampered and replayed aggregates. Functional rejection is separate from the conditional security reduction. |
| Durable source emission | `protocol.SourceEmissionStore` | [Ledger regressions](../tests/test_source_ledger.py) exercise raw-payload binding, concurrent cache selection, persistent reuse and rejection of changed inputs. No uncached ciphertext is released. |
| At-most-once acceptance | `protocol.ReplayStore`, `protocol.Sink.accept` | The validated batch digest is committed before returning an acceptance result. Storage anti-rollback and transactional application delivery are deployment requirements. |
| Exact encoded addition/no-wrap | `mlwe.py`, `protocol.py`, `profiles.py` | Parameterized encryption/protocol tests check coefficient addition and signed-data bounds. Exact physical-signal addition does not follow through rounded reconstruction. |
| Finite-CDT decoding correctness | `mlwe.py`, `tools/certify_decoding_bound.py` | [Actual-CDT record](../evidence/independent/decoding/k6-cdt-03/decoding-bound.json), exact probabilities and outward intervals; 42-choice single-batch log2 upper bound approximately -130.5101732. |
| Finite-task risk | `tools/check_decoding_horizon.py` | [Executed budgets](../evidence/independent/decoding-horizon/run-01/manifest.json) compare exact rational bounds with a declared task target; all conditions and rejected budget examples are retained. |
| Aggregate reconstruction | `signal.py`, `profiles.py`, `tools/check_aggregate_fidelity.py` | [72-case evidence](../evidence/independent/aggregate-fidelity/run-01/index.json): raw integer signals, intermediate vectors, ordered error decomposition and complete recomputation. Physical-signal generalization requires a calibrated corpus. |
| Controlled HMM and action scoring | `control.py`, `calibration.py`, `replay.py` | [Controller specification](CONTROL_IMPLEMENTATION_SPEC.md), binding tests and synthetic closed-loop records. Calibration, uniform uncertainty and invariance require deployment evidence. |
| Resource/certificate admission | `safety.py`, `control.RobustController` | Hard gates precede the nominal performance objective. Hash/tuple checks establish artifact identity, not the validity of external proof claims. |
| Seven-method packet-service study | `simulation/`, `statistics.py`, `tools/verify_simulation_campaign.py` | [Current results](../experiments/current-results.json): every method, 20 paired seeds, all denominators/censoring and modeled costs. |
| Embedded core build | `embedded/`, `firmware/`, board collector/verifier | [Board status](../evidence/independent/firmware/selected-k6/board-pending.json): no physical samples. Core build evidence is not full-protocol timing, power, stack or workspace certification. |
| Public artifact audit | `tools/verify_published_evidence.py`, `tools/independent_manifest.py` | [Archive index](../evidence/independent/publication.json), raw recomputation and environment-scoped frozen-source replay. Hashes verify bytes, not measurement truth. |

## Interpretation of the reported comparisons

The [complete seven-method tables](../experiments/CURRENT_RESULTS.md) retain all
favorable and unfavorable metrics. HYS and the fixed nominal action deliver more
source opportunities than DA-AHE; delay, admission, admitted-only loss and cost
must accompany those observations. Without IntDb2 has lower delivery and lower
conditional delay/TX cost, so a matched-service benefit cannot be inferred.
Every recovery observation is right-censored, and repair was not triggered.
Without HVE accepts modeled invalid aggregates without improving valid delivery.

The parameter estimate, algebraic correctness, signal distortion, model-based
controller conditions and physical-resource requirements are separate claims.
Full-system certification is false. See [Coverage and scope](REPRODUCTION_COVERAGE.md)
for the evidence boundary of each component.
