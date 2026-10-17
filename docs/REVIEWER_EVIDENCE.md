# Method and evidence guide

DA-AHE couples profile-bound Module-LWE aggregation with causal network-service
control. The fixed parameters are k=6, d=256, n=m=1536, q=2^32, p=65537 and
sigma_key=3.2. A packed protected report has a 7,168-byte ciphertext; the raw
480-coefficient representation uses two ciphertexts totaling 14,336 bytes.

The main entry points are [Evaluation](EVALUATION.md),
[Complete results](../experiments/CURRENT_RESULTS.md) and the
[protocol implementation](../src/daahe/protocol.py).
The machine-readable evidence index is
[configs/paper_claims.json](../configs/paper_claims.json).

## Executed network comparison

The study contains 20 paired seeds, 1000–1019, for seven methods: 140 runs at
3,000 sensors and 60 gateways, with 90 seconds of generation and 35 seconds of
draining. It is a synthetic Python two-hop packet/block service model.
Cryptographic and signal operations inside this model have declared service
costs rather than being executed per packet. The archived comparison uses its
declared controller parameters and records uncertified decisions. The separate
[calibration workflow](CONTROLLER_CALIBRATION.md) retains new data splits,
model identities and verification reports.

| Method | Valid / opportunity (%) | Loss / admitted (%) | Invalid accepted / admitted (%) | Mean valid delay (s) | Modeled CPU (J/run) | Modeled TX (J/run) |
|---|---:|---:|---:|---:|---:|---:|
| DA-AHE | 35.572 | 32.352 | 0.000 | 6.859 | 0.822 | 65.051 |
| DPP | 34.280 | 30.872 | 0.000 | 6.606 | 0.786 | 62.278 |
| HYS | 38.823 | 33.240 | 0.000 | 6.287 | 0.899 | 68.650 |
| Without Markov adaptation | 44.010 | 55.990 | 0.000 | 10.840 | 1.367 | 105.061 |
| Without IntDb2 | 33.395 | 36.508 | 0.000 | 3.625 | 0.834 | 53.389 |
| Without route repair | 35.572 | 32.352 | 0.000 | 6.859 | 0.822 | 65.051 |
| Without HVE | 35.572 | 30.265 | 2.087 | 6.859 | 0.821 | 65.051 |

Values are descriptive means across seeds. Valid delivery uses all offered
opportunities; loss and invalid acceptance use admitted reports. Delay is
conditional on valid delivery. Complete seed statistics, admission rates,
per-seed p95 delays, wire costs and paired differences are in the linked result
export. Packets and nodes are not independent statistical repetitions.

The methods exhibit service/resource tradeoffs. HYS and the fixed nominal
action deliver more offered reports than DA-AHE; the fixed action also incurs
higher delay, admitted-only loss and modeled cost. The two-ciphertext ablation's
lower conditional delay and TX cost occur with lower delivery and whole-batch
failures; they do not establish a payload advantage at matched valid service.
All 140 recoveries are right-censored. Route repair was not triggered, so its
ablation cannot establish repair efficacy. Disabling HVE admits modeled pollution
without increasing valid delivery; that acceptance rate is not a cryptographic
forgery probability.

## Method-to-evidence map

| Component | Implementation and evidence | Supported scope |
|---|---|---|
| Fixed-parameter encryption and packing | [mlwe.py](../src/daahe/mlwe.py), [profiles.py](../src/daahe/profiles.py), [selected profile](../configs/security_profile.json), [estimator report](../evidence/independent/security-parameter-search/selected-k6-full/security.json) | Seven attacks give a 136.475-bit minimum under the declared generic flattened-LWE heuristic models; payload arithmetic is exact. Neither establishes an implementation or all-attack security proof. |
| Authorization, encoded aggregation and verification | [protocol.py](../src/daahe/protocol.py), [signatures.py](../src/daahe/signatures.py), [derivation.py](../src/daahe/derivation.py), host/PQ records in the [public archive](PUBLIC_EVIDENCE.md) | Functional tests and real-provider trials cover the tested roster/context/tampering/replay behavior under trusted-endpoint assumptions. |
| Durable emission and acceptance | [source ledger](../src/daahe/protocol.py), [ledger tests](../tests/test_source_ledger.py) | Transactional one-payload binding, first committed envelope reuse and at-most-once sink acceptance. Embedded anti-rollback and durable application delivery require deployment mechanisms. |
| Actual-sampler decoding | [finite-CDT report](../evidence/independent/decoding/k6-cdt-03/decoding-bound.json), [record verification](../evidence/independent/decoding/k6-cdt-03/record-verification.json) | Outward-interval single-batch bound including shared-key noise and scaling carry; joint random-key/fresh-noise scope. |
| Finite-task budget | [budget records](../evidence/independent/decoding-horizon/run-01/manifest.json), [risk definitions](DECODING_RISK_BUDGET.md) | Exact union budgeting permits at most 5 attempts at 2^-128 and 1458 at 2^-120. A failed comparison means the requested bound is not certified, not an observed failure. |
| Aggregate reconstruction | [72-case index](../evidence/independent/aggregate-fidelity/run-01/index.json), [summary](../evidence/independent/aggregate-fidelity/run-01/summary.json), [method](AGGREGATE_FIDELITY.md) | Synthetic integer-count signals: 54 admissible cases and 18 diagnostics, with exact error attribution and explicit undefined PRD at zero reference energy. |
| Belief-state control | [control.py](../src/daahe/control.py), [calibration.py](../src/daahe/calibration.py), [safety.py](../src/daahe/safety.py), [specification](CONTROL_IMPLEMENTATION_SPEC.md), [calibration and certificate checks](CONTROLLER_CALIBRATION.md) | Inspectable HMM, robust drift gates, nominal objective and fail-closed interfaces. Empirical calibration and declared-model verification have distinct scopes; neither is a physical-deployment certificate. |
| Compiled core | [firmware](../firmware/README.md), [measurement inventory](../evidence/independent/firmware/selected-k6/board-pending.json), collector and verifier | ARM ELF/map, compiler stack-usage and host known-answer evidence. Whole-protocol board timing, energy, stack and memory require complete firmware and corresponding capture records. |
| Audit and recomputation | [current result export](../experiments/current-results.json), [public raw archive](PUBLIC_EVIDENCE.md), [seven-step receipt](../evidence/independent/reviewer-suite/run-01/suite-receipt.json), [43-test receipt](../evidence/independent/reviewer-suite/run-01/tests-receipt.json) | Raw-to-summary recomputation, source/input snapshots and bounded executable checks. The 43 tests cover four evidence-tool modules; they are not the entire host/PQ/Sage suite. |

## Scientific scope

Ciphertext addition is exact in the encoded coefficient domain under the stated
correctness conditions. Rounded lifting, selection and quantization yield an
approximation to the physical source sum. At the profiles' admissible maximum
batch sizes, the synthetic equal-case aggregate PRD means are 24.80%, 27.70%
and 30.70%; these results do not establish a universal physical-fidelity bound.
The network model has no signal values or distortion-dependent feedback.

The security estimate, single-batch tail and finite-task budget have distinct
assumptions. A task specifies its attempt cap, fresh-noise retries, profile and
roster selection, and key lifecycle. No uniform fixed-key/arbitrary-history,
unlimited-lifetime, malicious-ciphertext or full-system guarantee follows from
the decoding arithmetic. Gateway HMACs do not protect against the gateway holding
the key, and the authenticated plaintext path is not confidential.

A deployment safety certificate requires valid uniform model-error/transition
bounds, fallback nonemptiness, domain invariance or explicit exit handling and
conservative numerical-error treatment. The network study is not an OMNeT++/INET,
full IEEE 802.15.4, RPL or physical-board execution. CPU/TX energy excludes stated
receive/listen, OS and other costs. Full-system certification remains false.

## Reproduce and inspect

Use a new output directory for each execution. Real-provider trials require the
explicitly installed ML-DSA dependency; fresh interval calculations require
Sage-enabled Python.

```bash
python tools/check_paper_evidence.py
python tools/check_aggregate_fidelity.py --verify evidence/independent/aggregate-fidelity/run-01
python tools/check_decoding_horizon.py --batches 5 --target-bits 128
python tools/reproduce_paper_evidence.py --output runs/reviewer-evidence
```

The claim-index checker validates paths, scope metadata and bound hashes; it
does not execute the listed commands or validate a mathematical proof.
[Public evidence instructions](PUBLIC_EVIDENCE.md) distinguish raw metric
recomputation from frozen-source network replay and document environment limits.
