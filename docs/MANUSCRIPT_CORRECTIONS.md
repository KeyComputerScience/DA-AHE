# Manuscript corrections for the independently selected rank-6 implementation

This document supplies replacement text and consistency requirements for a
future manuscript revision. It does **not** modify `TSMC_DA.pdf`, reproduce the
original experiments, or certify the complete system. Historical execution
records remain historical records: the observed legacy rank-3 estimate must not
be relabeled as 128.1 bits or overwritten with the rank-6 result.

## 1. Parameter and arithmetic replacements

| Quantity | Historical PDF | Revised independent implementation |
|---|---:|---:|
| Module rank k | 3 | 6 |
| Ring degree d | 256 | 256 |
| Flattened dimension n = k*d | 768 | 1536 |
| Public-key sample count m | 768 | 1536 |
| Ciphertext modulus q | 2^32 | 2^32 |
| Plaintext modulus p | 65537 | 65537 |
| Key-noise standard deviation | 3.2 | 3.2 |
| Canonical ciphertext bytes = (k+1)*d*4 | 4096 | 7168 |
| Compressed protected report, one ciphertext | 4096 bytes | 7168 bytes |
| Raw protected report, two ciphertexts | 8192 bytes | 14336 bytes |
| Single-ciphertext payload serialization at 250 kbit/s | 131.072 ms | 229.376 ms |
| Two-ciphertext payload serialization at 250 kbit/s | 262.144 ms | 458.752 ms |
| Minimum successful recorded attack estimate | PDF states 128.1 bits | 136.475 bits for the independent rank-6 run |
| Required estimator threshold | 128.1 bits | 128.1 bits, a threshold rather than the measured estimate |

The legacy rank-3 execution reports a successful `primal_usvp` estimate of
approximately 51.94 bits. It therefore does not establish the PDF's stated
128.1-bit floor. The rank-6 result is a new independent parameter selection,
not a correction to the historical output of the rank-3 execution.

### Replacement parameter paragraph: Sections IV-A and VIII-A

> The revised independent implementation operates over
> R_q = Z_q[X]/(X^256+1), with module rank k=6, flattened dimension n=1536,
> m=1536 public-key samples, q=2^32, p=65537, and tag dimension lambda_tag=16.
> The key-generation standard deviation is 3.2. A canonical ciphertext consists
> of six u polynomials and one v polynomial, serialized as 32-bit words, and
> therefore contains 7,168 bytes. The pinned estimator execution reports a
> minimum operation-cost estimate of 136.475 bits across its seven successfully
> evaluated attacks, under the recorded generic flattened-LWE models. This is
> a heuristic attack-cost estimate, not a module-specific or worst-case security
> proof. The 128.1-bit value is the required estimator threshold. The selected
> parameters differ from the earlier k=3 manuscript tuple; earlier measurements
> and resource certificates do not transfer automatically to this revision.

The estimator's reduction attacks use the recorded ADPS16 quantum Core-SVP
cost model and GSA shape model. Coded-BKW retains its upstream native
word-operation model; its result must not be described as an independently
proved quantum attack cost. The run's source hashes, successful attack list,
sample accounting, outputs and cost-model scope must accompany the result.

### Replacement packing and airtime paragraph: Section VI-A, equations (16)--(19)

> With at most 240 retained data coefficients and 16 tag coefficients, a
> compressed protected report occupies one degree-256 plaintext polynomial.
> The 480 raw data coefficients and 16 tag coefficients require two
> polynomials. At the revised rank-6 parameters, the sensitive ciphertext
> payload is consequently reduced from 14,336 to 7,168 bytes. The ideal
> single-hop payload serialization bound at 250 kbit/s is
> 7168*8/250000 = 0.229376 s, or 229.376 ms; two ciphertexts require
> 458.752 ms. These values exclude protocol headers, ticket and authentication
> metadata, fragmentation overhead, contention, retransmissions, processing
> and multihop forwarding. They are arithmetic bounds rather than measured
> end-to-end latency.

The workload-weighted lower-bound expression must use newly established
rank-6 service times, for example

`T_weighted >= 0.30*(T_CPU,protected,rank6 + 229.376 ms) + 0.70*T_lightweight`.

Do not substitute the PDF's 58.125-ms protected CPU measurement to produce a
new rank-6 total. The 77.199-ms historical weighted bound is not a rank-6
result. The PDF's 3.72-million-cycle, 58.125-ms, 1.395-mJ, 28.64-KiB and
10-KiB claims require fresh full-path evidence before reuse. Cross-compiling
an independent core harness is separate from board measurement and full
protocol resource certification.

## 2. Required one-time source emission condition

### Replacement security assumption and Algorithm 1 preamble

> For each authorized (ticket digest, source identifier, source nonce) tuple,
> an honest source releases at most one distinct protected report. Before
> releasing any ciphertext bytes, the source durably binds the exact input
> payload to this tuple and commits the resulting envelope to a persistent
> emission store. Retries return the same cached envelope and original signed
> ticket. Resampling or changing a payload requires a new authorization with
> a fresh signed batch nonce. The emission store must resist rollback or
> deletion that would permit reuse of the authentication offset.

Algorithm 1 must perform the durable check and commit before returning the
envelope. Merely generating fresh encryption randomness for a second report
under the same source offset is insufficient.

### Replacement integrity explanation

> The aggregate-integrity argument assumes one distinct report per source
> offset. If two different reports use the same K_B and xi_i, their tags satisfy
> t_1=K_B*x_1+xi_i and t_2=K_B*x_2+xi_i. A malicious gateway could then form
> the affine combination 2*c_1-c_2, whose decoded tag authenticates
> 2*x_1-x_2 under the same offset, subject to decoding correctness. The source
> emission rule prevents this reuse. The sink's persistent Seen set remains
> necessary for at-most-once batch acceptance, but it does not replace the
> source emission rule.

The theorem should retain its trusted-source/sink and key-secrecy assumptions.
It must not suggest resistance after source compromise or offset/key leakage.
The single-attempt tag-guessing term is not the security level of the complete
signature, derivation, encryption and verification construction.

## 3. Aggregation semantics and reconstruction distortion

### Replacement transform and correctness paragraph

> Ciphertext addition recovers the sum of the encoded quantized coefficient
> vectors modulo p; the data no-wrap check permits interpreting those data
> coordinates as signed integer sums. This algebraic correctness statement
> concerns encoded coefficients. The reference transform uses rounded integer
> lifting, which is nonlinear. In general, T^{-1}(sum_i T(m_i)) differs from
> sum_i m_i even before coefficient selection and quantization. Selection,
> quantization and inverse lifting introduce further reconstruction error. The
> decoded physical telemetry is therefore an approximation to the physical
> sum, and its aggregate distortion must be evaluated separately.

For a common signed profile with transform T, support S and quantizer Q,
define the evaluated aggregate output and error explicitly:

`m_hat_B = T^{-1}(Scatter_S(delta_Q * sum_i Q(T(m_i)[S])))`

`error_B = m_hat_B - sum_i m_i`.

Use the actual implementation's normalization, physical-unit scaling,
rounding rule, support and boundary convention in these definitions. This
notation does not assert a linearity property or an unproved error bound.
Report aggregate PRD/RMSE against the physical sum for each profile and batch
size, including 1, 12, 14 and 16 where admissible, on identified traces. Keep
per-source reconstruction results distinct. The historical Table III values
do not establish aggregate fidelity for the current transform or profiles.

## 4. Decoding, control and certification scope

### Replacement decoding scope paragraph

> The independent finite-CDT decoding calculation covers the implemented
> sampler and includes the scaling carry caused by q-p*floor(q/p)=1.
> Fixed-profile whole-batch bounds and a finite union over the 42 declared
> profile/batch-size choices are archived. The latter has a recorded log2
> upper endpoint of approximately -130.510173 for one fresh honest batch,
> jointly over random key generation, history and fresh encryption noise,
> when the action and roster are selected before that batch's fresh noises.
> This is not a uniform bound for every realized fixed key or arbitrary
> conditional history. A specified finite multi-batch horizon requires a
> further union bound. This calculation does not certify controller dynamics,
> network behavior, adversarial ciphertexts, memory or airtime.

### Replacement control theorem scope paragraph

> The exponential mean-square ultimate-boundedness result is conditional on
> valid uniform model-error and transition-probability bounds, a verified
> fallback certificate, and the closed-loop state remaining in Z_cert. The
> current independent controller fixture is explicitly synthetic and does not
> establish these hypotheses. No forward-invariance, population-wide
> calibration, deployment airtime or full-system safety certificate is claimed
> for that fixture. Strict certification mode must reject absent evidence and
> operation outside the certified region.

To make a future certificate auditable, publish P_V, Z_cert, gamma, beta, all
state/action model coefficients, observation/emission assumptions, calibrated
error radii and their validity scope, the explicit ambiguity set, the complete
J_t objective, and the bound on the fallback supremum. A successful numerical
recursion check on sampled trajectories is not a proof of domain invariance.

## 5. Treatment of historical performance claims

The original PDF has **not** been edited by this repository correction. Its
450.0-ms latency, 0.074%/0.098% residual loss, 33.0-s recovery, comparative
percentages, energy curves and Table III values remain historical manuscript
claims. They are unverified for the revised rank-6 implementation and must not
be presented as newly reproduced measurements. New independent experiments
must bind their own code, parameters, network model, traces, seeds and output
hashes. The current full-system certification status remains `false`.

## 6. Executable repository-alignment contract

Run `python tools/check_manuscript_alignment.py`. The checker binds canonical
code parameters, the selected security profile, the hash-bound seven-attack
report and its recomputed minimum, payload arithmetic and preserved legacy
record. It also requires the current claim contract to retain the absence of
original-paper reproduction, board measurements and full-system certification.

The historical `security/run-01/security.json` remains byte-for-byte unchanged,
with SHA256
`e6547315520c55a82cf349ab1df4483cdd816b192f61de9ea6cf1ac4186dea78`.
The current report is selected through `configs/security_profile.json`; never
copy its outputs over the historical rank-3 execution.

Successful repository alignment does not mean that this original PDF was
edited: the result explicitly returns `manuscript_aligned=false`.
`--require-manuscript-aligned` exits nonzero while the original manuscript is
unrevised. This is a metadata and arithmetic check, not a fresh estimator run,
board measurement, physical-signal fidelity evaluation or certificate proof.

Behavioral source-emission, strict certificate and encryption tests remain
separate checks. Historical evidence snapshots and frozen-source campaign
records must not be rewritten when current documentation or tools change.
