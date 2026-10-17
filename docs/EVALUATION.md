# Evaluation of profile selection at fixed security parameters

The study evaluates the executed independent rank-6 campaign and auxiliary
cryptographic and aggregate-reconstruction evidence. Network values come from
all 140 published per-seed records and their verified summaries. The platform,
accounting boundaries and certification scope are stated below.

[Performance reproduction](PERFORMANCE_REPRODUCTION.md) defines the complete
size-by-seed matrix and the common record-to-table/figure exporter, including
paired bootstrap intervals, denominator checks and censored recovery handling.

[Ablation evidence](ABLATION_EVALUATION.md) defines report/frame denominators,
recovery censoring, HVE capability scope and the independent ablation export/CI
contract for the archived rank-6 campaign.

## Experimental question and fixed cryptographic parameters

We evaluate how causal profile selection changes source admission, valid
delivery and modeled resource consumption while keeping the long-term public-key
parameters fixed. All seven methods use module rank k=6, ring degree d=256,
flattened dimension n=m=1536, q=2^32, p=65537 and key-generation standard
deviation 3.2. The selected generic flattened-LWE estimator run evaluates seven
attacks and reports a minimum operation-cost estimate of 136.475 bits under its
recorded models, exceeding the requested 128.1-bit estimator threshold. This is
a heuristic estimate, not a module-specific, actual-finite-CDT, side-channel or
full-system security proof. The reduction attacks use the recorded ADPS16
quantum cost model; coded-BKW retains its upstream native operation-count model.

A canonical ciphertext contains six u polynomials and one v polynomial,
serialized as 32-bit words: (6+1)*256*4=7,168 bytes. Up to 240 data coefficients
and 16 authentication coefficients fit into one degree-256 plaintext
polynomial. The 480 raw data coefficients plus authentication require two
polynomials. Thus the protected ciphertext payload comparison is 14,336 versus
7,168 bytes. At 250 kbit/s, their payload-only serialization times are 458.752
and 229.376 ms, respectively. These are arithmetic quantities, excluding
tickets, protocol headers, fragmentation, contention, retries and computation.
Changing the retained support within a single polynomial does not shorten its
7,168-byte ciphertext.

The declared encryption-noise/batch library is sigma=3.2 with N<=16, sigma=3.4
with N<=14, and sigma=3.6 with N<=12. These are jointly declared operating
choices, not ordered long-term security levels. The common fixed public-key
instance is maintained during profile selection.

## Executed network model and paired design

We executed an independent Python discrete-event service model with 3,000 source
sensors, 60 gateways and one sink over a nominal 1,000 m by 1,000 m region.
Each source has one potential report with an independent uniform phase during
90 s of generation, followed by 35 s of draining. The configured protected-path
share is 0.30. A disturbance occurs from 30 to 50 s and affects the configured
35% gateway fraction. The model has 60 local and 10 backhaul contention domains,
a 250-kbit/s bit rate, 32,768-byte transmitter queues, at most three retries,
30-s report deadlines and 5-s controller intervals.

This is a two-hop source-to-gateway-to-sink model with explicit framing,
fragmentation, queueing, retries and whole-roster completion. It is not an
OMNeT++/INET execution, a full IEEE 802.15.4 radio implementation or an RPL
DODAG implementation. Coordinates assign gateways; they do not provide measured
propagation, fading or interference geometry. Every source envelope and its
aggregate carry the same preauthorized roster ticket. The configured inline
ticket budget is 2,420 signature bytes, 128 fixed-field bytes and 20 bytes per
member. A missing or expired authorized member rejects its whole original
batch; the model does not shrink a roster after observing losses.

Processing times are explicit assumptions. In particular, the source encryption
proxy is 0.004 s per ciphertext, obtained by scaling an assumed rank-3 matrix
stage by 36/9. This is neither a full encryption operation count nor an MCU
measurement. Source transform, encryption and homomorphic arithmetic
are represented by configured costs and wire sizes inside the network model,
rather than executed cryptographic or signal-processing operations. Advance
ticket distribution and signing, receive/listen energy, OS/interrupt work and
complete embedded memory lifetimes are outside the model. CPU and transmit-radio
energy are modeled separately; neither is measured board energy.

Twenty paired evaluation seeds, 1000--1019, are used for seven methods, giving
140 completed runs. Within each seed, all methods reuse the frozen topology,
source opportunities/classes, sampling uniforms, disturbance inputs and
counter-based channel streams. DA-AHE uses the existing HMM/robust selection
implementation; DPP and HYS use the corresponding causal virtual-queue and
hysteresis rules. The four ablations fix the nominal action, use two protected
ciphertexts without the compression delay, disable route-repair actuation, or
disable sink aggregate validity checking, respectively. All methods use the
same synthetic controller fixture. Its costs, emissions, transitions and
admission certificates are uncalibrated assumptions; all 140 records explicitly
mark their decisions uncertified. This experiment tests an auditable closed
loop under declared assumptions, not a proven invariant operating domain.

## Delivery denominators and descriptive results

We distinguish all offered source opportunities, admitted reports, accepted
deliveries and valid deliveries. Admission can reduce offered load; therefore
an admitted-only success rate is insufficient to characterize effective
service. Our primary throughput measure is valid deliveries per offered source
opportunity. Accepted delivery additionally includes an invalid aggregate that
the modeled sink accepts when its end-to-end check is disabled. That hidden
invalidity label is available to the offline auditor, not the controller.

Table 1 reports the mean and sample standard deviation across 20 seeds. Entries
are percentages. They are descriptive seed statistics, not bootstrap confidence
intervals or a population significance test. Every displayed metric is defined
for all 20 seeds.

| Method | Admission / opportunity (%) | Valid / admitted (%) | Valid / opportunity (%) | Accepted / admitted (%) | Invalid accepted / admitted (%) |
|---|---:|---:|---:|---:|---:|
| DA-AHE | 52.60 +/- 0.91 | 67.65 +/- 2.90 | 35.57 +/- 1.30 | 67.65 +/- 2.90 | 0.00 +/- 0.00 |
| DPP | 49.61 +/- 1.06 | 69.13 +/- 2.88 | 34.28 +/- 1.17 | 69.13 +/- 2.88 | 0.00 +/- 0.00 |
| HYS | 58.16 +/- 0.81 | 66.76 +/- 2.58 | 38.82 +/- 1.57 | 66.76 +/- 2.58 | 0.00 +/- 0.00 |
| Without Markov adaptation | 100.00 +/- 0.00 | 44.01 +/- 2.01 | 44.01 +/- 2.01 | 44.01 +/- 2.01 | 0.00 +/- 0.00 |
| Without IntDb2 | 52.60 +/- 0.91 | 63.49 +/- 1.85 | 33.40 +/- 1.00 | 63.49 +/- 1.85 | 0.00 +/- 0.00 |
| Without route repair | 52.60 +/- 0.91 | 67.65 +/- 2.90 | 35.57 +/- 1.30 | 67.65 +/- 2.90 | 0.00 +/- 0.00 |
| Without HVE | 52.60 +/- 0.91 | 67.65 +/- 2.90 | 35.57 +/- 1.30 | 69.74 +/- 2.99 | 2.09 +/- 0.68 |

DA-AHE delivers 35.57% of offered opportunities, compared with 34.28% for DPP,
38.82% for HYS and 44.01% for the fixed nominal action. The fixed action admits
every opportunity but has a lower admitted-only delivery fraction. These results
show an admission/resource/service tradeoff; they do not show that DA-AHE
dominates all baselines. The admitted-only residual-loss mean for DA-AHE is
32.35%, not the earlier manuscript's sub-0.1% result.

Disabling HVE increases accepted delivery without increasing valid delivery.
The modeled invalid-acceptance fraction is 2.09% of admitted reports. This
demonstrates why validity must be separated from transport acceptance. The
model injects specified gateway forgeries and applies a modeled verification
decision; these percentages are not empirical cryptographic forgery bounds.

## Conditional delay, modeled cost and censored recovery

Table 2 reports mean +/- sample SD across seeds. The delay mean and p95 are
computed on validly delivered reports within each seed; the displayed p95 is
the mean of the 20 per-seed p95 values, not a pooled percentile. Failed, skipped
or expired reports are absent from these conditional delay distributions.
CPU and transmit-radio energy cover the entire run and are expressed in joules.
Wire bytes are normalized by all offered source opportunities.

| Method | Valid delay mean (s) | Valid delay p95 (s) | Modeled CPU (J/run) | Modeled radio TX (J/run) | Wire bytes / opportunity |
|---|---:|---:|---:|---:|---:|
| DA-AHE | 6.859 +/- 0.394 | 14.403 +/- 1.035 | 0.822 +/- 0.014 | 65.051 +/- 1.428 | 13552 +/- 298 |
| DPP | 6.606 +/- 0.361 | 14.061 +/- 1.009 | 0.786 +/- 0.016 | 62.278 +/- 1.562 | 12975 +/- 325 |
| HYS | 6.287 +/- 0.251 | 13.986 +/- 1.038 | 0.899 +/- 0.015 | 68.650 +/- 1.556 | 14302 +/- 324 |
| Without Markov adaptation | 10.840 +/- 0.622 | 21.123 +/- 1.305 | 1.367 +/- 0.008 | 105.061 +/- 1.731 | 21888 +/- 361 |
| Without IntDb2 | 3.625 +/- 0.305 | 8.147 +/- 1.992 | 0.834 +/- 0.017 | 53.389 +/- 1.262 | 11123 +/- 263 |
| Without route repair | 6.859 +/- 0.394 | 14.403 +/- 1.035 | 0.822 +/- 0.014 | 65.051 +/- 1.428 | 13552 +/- 298 |
| Without HVE | 6.859 +/- 0.394 | 14.402 +/- 1.035 | 0.821 +/- 0.014 | 65.051 +/- 1.428 | 13552 +/- 298 |

The two-ciphertext ablation has a lower valid-delivery fraction yet lower
observed conditional delay and total transmitted cost. These quantities depend
on which transfers complete and which whole batches fail. They do not establish
that the larger payload provides lower latency or greater energy efficiency at
matched valid delivery. Comparison of completed-service counts and admission is
necessary alongside these conditional quantities. The unchanged controller
fixture is also not recalibrated for the ablated service model.

Route repair was not triggered in this campaign. DA-AHE and the route-repair
ablation have identical reported metrics; the experiment cannot validate a
route-repair improvement or identify its causal contribution. A separate
experiment that actually activates the mechanism is needed for that claim.

Recovery requires an observed excursion followed by two consecutive good
5-s windows, each with at least three completed reports, satisfying the declared
queue, loss and delay thresholds. All 20 seeds for every method have an excursion
and remain right-censored: 140/140 runs contain no observed qualifying recovery
within the common observation horizon. There is consequently no observed mean
recovery time or recovery-time ranking. The censoring horizon is not a recovery
duration, and a 33-s recovery claim is not supported by these results.

## Aggregate-domain fidelity experiment

A separate executed experiment contains 72 deterministic synthetic cases:
three signal families (`smooth_triangle`, `sparse_pulses`, `mixed_step_noise`),
two seeds, three profiles and batch sizes 1, 12, 14 and 16. Inputs and RMSE are
in integer counts. There are 54 capacity-admissible cases and 18 diagnostic
cases outside the selected profile capacity; the latter are not admissible
encrypted operating points. This experiment executes signal transforms and
reconstruction separately from the network model and does not execute
encryption/decryption.

We compare reconstruction of summed encoded coefficients with the physical
integer-count sum of source signals. Rounded integer lifting is nonlinear, so
inverse(sum_i T(m_i)) need not equal sum_i m_i even with full support and no
quantization. The saved cases distinguish lifting aggregation, selection and
quantization effects and the difference from summing individually reconstructed
signals. Their RMSE components are diagnostic comparisons, not additive error
norms or a universal error certificate.

For illustration, Table 3 reports equal-case means over the six family/seed
cases at each profile's admissible maximum batch size. These are descriptive
case averages, not physical measurements or population confidence intervals.

| Profile | Batch size | Aggregate RMSE (integer counts) | Aggregate PRD (%) |
|---|---:|---:|---:|
| pi0 | 16 | 15.705 | 24.80 |
| pi1 | 14 | 18.266 | 27.70 |
| pi2 | 12 | 18.546 | 30.70 |

The cases establish reproducible aggregate-domain error measurements for the
declared synthetic inputs. They do not reproduce the earlier Table III, provide
mV/mA calibration, establish a real CPS signal distribution or support a
universal PRD<=2.5% guarantee. The network campaign contains no signal values or
distortion-dependent feedback, so it does not yet evaluate utility-constrained
profile selection on a physical sensor corpus.

## Finite-task decoding budget

The independent finite-CDT report provides an outward interval bound for one
choice from the 42 declared profile/size configurations, with at most two
plaintext polynomials, chosen before fresh honest batch noises. Its exact
rational probability upper endpoint is approximately
U=5.15849649769099e-40. The calculation includes shared-key products and the
q-p*floor(q/p)=1 scaling carry. Its probability is joint over random key
generation, history and fresh noises, rather than conditional on every fixed
key or arbitrary observed history.

For a predeclared cap B on fresh-noise batch attempts, a union bound gives
P(any covered decoding failure)<=min(1,B*U), without assuming independence
between batch outcomes. The exact integer budget is floor(R/U) for target risk
R in (0,1). The executed budget records admit B=5 at R=2^-128 and reject B=6;
at R=2^-120 the maximum is 1458 and the B=300 record passes. Failure of this
conservative comparison means that the bound cannot certify the requested
budget, not that an actual decoding failure was observed.

These are analytical task-budget examples separate from the network simulation,
which does not sample or decrypt ciphertext noise. The network campaign is not
thereby certified to have 2^-128 task risk: fresh encryption attempts, including
fresh-noise retries, must be counted against an explicitly selected task target.
No unlimited-lifetime, malicious-ciphertext, physical-fidelity, network or
controller-invariance claim follows from this decoding calculation.

## Evidence identity and evaluation scope

The public campaign has a completed 20-by-7 manifest, frozen configuration and
controller, per-seed records and a raw companion archive. The campaign-report
configuration is identical to the current `simulation/config.json`; its fixed
rank-6 parameters, 7,168-byte ciphertext budget and security/decoding artifact
hashes agree. The summary SHA256 is
`b73918c7c9bf9422c0b8c9121dbb1dfa27dac479ac72520a8813fbc35d844a7d`.
It matches the manifest and public archive index. All table means and sample
SDs can be recomputed from the 140 per-seed rows. Raw-to-summary recomputation
and archived-source replay are distinct checks; exact historical byte replay
has a documented execution-environment boundary.

This evaluation supports an auditable comparison of profile-selection policies
under fixed security parameters and declared synthetic service assumptions.
It provides no physical-board timing, energy, stack or complete-protocol memory
table. Physical-board samples remain zero. The unavailable original simulator,
physical calibration and signal corpus are not reconstructed by these results;
network simulation, build evidence and synthetic reconstruction therefore have
distinct experimental boundaries.

Reproducibility sources:

- [Campaign summary](../evidence/independent/campaign-report/summary.json),
  [per-seed rows](../evidence/independent/campaign-report/per-seed.csv),
  [executed configuration](../evidence/independent/campaign-report/config.json),
  [campaign manifest](../evidence/independent/campaign-report/manifest.json).
- [Public raw-evidence instructions](PUBLIC_EVIDENCE.md) and
  [simulation model specification](../simulation/README.md).
- [Selected security profile](../configs/security_profile.json) and
  [finite-CDT decoding report](../evidence/independent/decoding/k6-cdt-03/decoding-bound.json).
- [Executed task-risk budgets](../evidence/independent/decoding-horizon/run-01/manifest.json)
  and [risk-budget definitions](DECODING_RISK_BUDGET.md).
- [Aggregate fidelity cases](../evidence/independent/aggregate-fidelity/run-01/index.json)
  and [fidelity summary](../evidence/independent/aggregate-fidelity/run-01/summary.json).
