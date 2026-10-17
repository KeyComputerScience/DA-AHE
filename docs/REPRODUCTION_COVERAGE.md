# Evaluation coverage and scientific scope

The primary evaluation is a fixed-parameter rank-6 packet-service study with
20 paired seeds and seven methods. [EVALUATION.md](EVALUATION.md) defines the
study, [CURRENT_RESULTS.md](../experiments/CURRENT_RESULTS.md) reports the full
comparison, and [PARAMETER_PROTOCOL.tex](manuscript/PARAMETER_PROTOCOL.tex)
specifies the parameter and protocol operations.

Implementation availability, an executed experiment, a mathematical certificate
and a physical measurement have different meanings. The following table states
which evidence exists and the scope in which it can be used.

| Component | Available evidence | Scientific boundary |
|---|---|---|
| Rank-6 primitive and serialization | Canonical host code, parameterized tests, fixed profile/config identity; 7,168-byte ciphertext | Research additive-encryption reference with nonconstant-time Python arithmetic, sampler and memory handling. It is not a hardened deployment primitive. |
| Concrete attack costs | Seven successful pinned attack calculations; minimum 136.475 bits | Generic flattened-LWE heuristic under recorded native models, not module-specific, finite-CDT, side-channel, all-attack or worst-case proof. |
| Roster authorization/integrity | ML-DSA provider trials, signed-context and profile binding, hidden linear tags, tampering/replay tests | Trusted source/sink, protected derivation secrets and one-report-per-offset assumptions. Gateway HMAC and transport acceptance are distinct from end-to-end integrity. |
| Durable host state | Transactional source cache and sink acceptance set with regression tests | No embedded flash/anti-rollback driver or transactional application outbox is established. |
| Decoding correctness | Exact finite-CDT probabilities, outward intervals, shared-key product/carry analysis | One fresh honest batch, jointly over random key generation and noise; not every fixed key or arbitrary-history conditioning. |
| Finite-task risk | Exact-rational union budgets and accepted/rejected examples | A declared attempt cap and lifecycle are required. A bound that misses its target is not an observed failure; unlimited lifetime is not certified. |
| Network-service comparison | 140 complete per-seed records, seven methods, shared exogenous inputs, raw-to-summary recomputation | Synthetic Python two-hop service model with declared processing and channel assumptions. Cryptographic/signal operations are represented by costs within this model. |
| Aggregate fidelity | 72 synthetic integer-count cases, frozen source, exact vectors and recomputed metrics | 54 capacity-admissible cases and 18 diagnostics. No calibrated physical corpus, universal error bound or distortion feedback in the network study. |
| Belief/robust controller | HMM, robust drift admission, nominal objective, certificate interfaces and functional tests | Every campaign decision is uncertified. Uniform bounds, fallback feasibility, invariance and numerical margins require reviewed evidence. |
| Core firmware | Cross-compilation and host known answers | Physical samples=0. No full-protocol timing/energy/stack/peak-memory measurement or complete per-role workspace certificate. |
| Audit/replay | Public raw bundle, manifests, record recomputation and frozen-source replay interfaces | Byte integrity is not measurement authentication. Exact replay is scoped to the recorded environment. |

## Results retained in the service study

All seven methods and all seed outcomes are reported, including failed or
unadmitted opportunities and modeled invalid acceptances. Valid delivery is
normalized by offered source opportunities; admitted-only loss cannot substitute
for that service measure. Valid-delay distributions condition on delivered
reports. HYS and the fixed nominal action show higher effective delivery than
DA-AHE, with distinct resource/loss/delay tradeoffs. No blanket dominance is
established.

All 140 recovery records are right-censored at the common observation endpoint.
There is no observed recovery-time mean or ranking. Route repair was not
triggered, so its ablation is not a test of repair efficacy. Disabling HVE
increases accepted invalid delivery without increasing valid delivery.
The two-ciphertext ablation's lower conditional delay and TX cost coexist with
lower valid delivery and are not a matched-service efficiency result.

CPU and transmit-radio energy are modeled over the whole run. Receive/listen,
OS/interrupt and other stated costs are outside that boundary. These values are
not physical-board energy or complete-protocol measurements. The two-hop model
is not a full radio or RPL implementation.

## Audit the records

The [machine-readable claim index](../configs/paper_claims.json) contains code,
record paths, verification commands, bound hashes and component requirements.
The [method/evidence guide](REVIEWER_EVIDENCE.md) and
[traceability table](CLAIM_TRACEABILITY.md) provide human-readable navigation.

The small campaign-report extract supplies per-seed rows and summary metadata.
Full packets, events, reports, epochs and frozen source are distributed through
the companion release. Follow [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md) to fetch
all parts, verify the archive and independently rederive the 140 saved metrics.
Rebuilding the result export recomputes statistics; it does not rerun the network.

Frozen-source network re-execution is a separate check. Exact byte replay uses
the documented macOS ARM64/Python 3.12.10 environment, while Linux raw metric
recomputation is separate. The [replay scope](REPLAY_PORTABILITY.md) includes the
observed one-ULP epoch difference. A command or CI job definition is not itself
an execution receipt. Existing receipts identify the source/input state of
their own execution.

## Conditions for deployment claims

Full-system certification remains false. A deployment claim requires complete
per-role firmware and measured hardware costs; a calibrated physical signal
corpus and stated utility target; uniform state/transition uncertainty and
fallback/domain evidence; conservative numerical-error treatment; protected
persistent state; and an explicitly budgeted task/key lifecycle. Additional
workloads or scales require their own matched executions and archived raw data.
No physical or population-wide conclusion is inferred merely from a passing
software test, a manifest hash, a compiled image or a synthetic trajectory.
