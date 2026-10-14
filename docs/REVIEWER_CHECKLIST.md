<!-- SPDX-License-Identifier: MIT -->
# Reviewer checklist / 审稿核验清单

本包提供文章算法的可读参考实现、接口、实验输入约定与审计路径。**交付时未运行代码、测试、仿真、估计器或硬件实验；不声称已经复现论文数值。** 原始作者固件、仿真工程、校准证书和原始数据缺失，必须明确记录为未完成证据项。

## 1. Establish the artifact boundary

- [ ] Record the supplied PDF's SHA256 and source-package manifest. Verify listed byte hashes before executing. A checksum is an integrity check, not an author signature or a correctness proof.
- [ ] Read `docs/CLAIM_TRACEABILITY.md`. Separate mathematical statements, implemented interfaces, illustrative completions, and claims needing original author evidence.
- [ ] Inspect `LICENSE`, `NOTICE`/third-party notices and dependency declarations. Project code is MIT; external libraries, SageMath, Contiki-NG, OMNeT++/INET and lattice-estimator retain their own licenses. They are not relicensed by this package.
- [ ] Record operating system, Python, native ML-DSA provider, compiler and dependency versions. The lack of executed results is intentional under the user's instruction.

## 2. Inspect source invariants before measurements

- [ ] `ring.py`: exact integer negacyclic multiplication with `X^256=-1`, power-of-two `q=2^32`, no floating-point convolution.
- [ ] `mlwe.py`: module rank three, degree 256, one ciphertext `(u_0,u_1,u_2,v)` is 4×256×4=4,096 bytes. Inspect the discrete-Gaussian reference sampler's finite approximation and matrix-expansion completion; neither implies a concrete security or decoding certificate.
- [ ] `protocol.py`: 240 data + 16 tag coefficients fit one polynomial; 480 data + 16 tags require two. Complete source identity/nonce/ticket/position/total-count binding is included in block MACs.
- [ ] Confirm exact-roster checks, signed full profile digest, aggregate tag and durable replay storage at the sink. HMACs held by a compromised gateway must not be credited as end-to-end integrity.
- [ ] Confirm absent native ML-DSA fails explicitly. Test-only signers must remain under `tests/`; they must never be selected as a production fallback.
- [ ] Read `signal.py` limitations. The article omits the integer Db2 lifting coefficients, rounding and boundary details. The supplied illustrative reversible lifting is not the original transform. Rounding is not exactly additive; aggregate reconstruction fidelity cannot be inferred from per-source reversible lifting alone.

## 3. Inspect control and certificate gates

- [ ] Hard gates check complete tuple/profile/context binding, workspace ≤10 KiB, airtime, plaintext no-wrap, batch decoding ≤2^-128, noise margin, and estimated security ≥128.1 bits. Synthetic examples must remain uncertified.
- [ ] `control.py`: inspect causal HMM filtering, five regimes, action-conditioned prediction, the exact simplex/L1 worst-case expectation, Lyapunov admission, and Algorithms 4–6 baseline differences.
- [ ] Verify the fallback supremum uses analytic bounds, including interior stationary points, rather than a sampled grid declared as a proof.
- [ ] Audit required evidence for state-error, transition, domain and any adaptive-kernel bounds. Empirical residual maxima and ridge fits are not uniform certificates.
- [ ] Outside `Z_cert` or without usable evidence, check failure/recertification behavior. The theorem is conditional on staying within the certified region; this reference code does not establish the network's invariance of that region.
- [ ] Recover original objective normalizers, hysteresis thresholds/actions/hold time, DPP tuning and full profile support/action definitions before claiming baseline equivalence.

## 4. Supply original experimental evidence

Create `author_artifacts/evidence-index.json` with schema version one and the roles described by `daahe.evidence.REQUIRED_AUTHOR_ARTIFACTS`. Each role maps to a nonempty list of `{path,sha256}` records relative to the repository root. Required roles are:

`evaluation_seeds`, `omnet_source`, `traffic_disturbance`, `calibration`, `certificates`, `board_measurements`, `firmware`, `security_logs`, `sensor_signals`, `packet_results`.

- [ ] Obtain the original 20 evaluation seeds and separate training/holdout/calibration seeds. Illustrative seeds in `experiments/matrix.json` cannot identify the original runs.
- [ ] Obtain original OMNeT++ 6.0 / INET 4.4 NED/INI/modules, packet counters and RNG-stream assignments. No Python surrogate is supplied or labeled as OMNeT++.
- [ ] Obtain exact topology, channel parameters, 30/70 workload, 100-s burst/link-failure event, node/link identities and shared exogenous traces. Controller-dependent RNG consumption must not alter the paired disturbance realization.
- [ ] Obtain exact queue/loss recovery thresholds. A recovery event ends only after five consecutive safe 1-s control intervals; retain right censoring for nonrecovery by 300 s.
- [ ] Obtain ground-truth signals and original transform/support definitions for Table III and any aggregate-fidelity claim.
- [ ] Obtain nRF52840 firmware, ELF/map, compiler flags, raw cycle measurements, role-specific stack high-water marks and CPU/radio state accounting. A Python workspace estimate is not an embedded SRAM measurement.
- [ ] Confirm the loss denominator and latency boundaries. Do not substitute application-report loss for packet loss or a one-hop serialization bound for end-to-end latency.

## 5. Reviewer-chosen execution sequence (not performed)

1. Inspect and build the environment using the package README. Retain actual dependency/version captures.
2. Run authored source-invariant tests and retain genuine logs. No prewritten passing log or fabricated coverage report is supplied.
3. Run the pinned lattice estimator using `tools/estimate_security.sage` and save its actual JSON/CSV/stdout. It explicitly instantiates `ADPS16(mode="quantum")`; the upstream `RC.ADPS16` default is classical. Any required attack failure/infinite result/missing operation count blocks the final estimate. The minimum is taken over successful operation costs only after required-attack completeness is established.
4. Build and measure the original nRF52840 firmware. Check the distinction between the action-dependent 10-KiB workspace and the paper's whole-firmware 29,328-byte runtime peak.
5. Freeze models and reviewed certificates before evaluation. Verify all training/holdout/evaluation seeds are disjoint.
6. Run the paired external simulator matrix and export complete packet/source/sink and recovery telemetry. Use `tools/import_omnet.py` only when its explicit instrumentation contract matches the author definitions.
7. Compute raw means separately from ratios of means with 100,000 paired bootstrap resamples. Preserve all 20 seeds and censored observations. Check the figure axes use percent only for display, while CSV loss is a fraction.
8. Compare actual estimates and intervals against `experiments/paper_targets.json`, which is a transcription of targets, never generated results. Pre-register numerical tolerances and any multiple-comparison procedure before viewing results.

## Evidence status at delivery

| Item | Status |
|---|---|
| Readable reference source and authored tests | Supplied, unexecuted |
| Source hash manifest | Source integrity record only |
| Original author artifact bundle | Missing / blocks exact reproduction |
| Python test execution | Not performed |
| Sage estimator execution and 128.1-bit confirmation | Not performed |
| OMNeT++ and embedded build/run | Not performed |
| Numerical reproduction of figures/tables | Not established |
| Hardware/deployment security certification | Not established |

The audit API returns `blocked_incomplete_author_evidence` while evidence is missing. Even complete file/hash presence yields only `evidence_present_requires_execution_and_review`, never an automatic “reproduced” verdict.

Official API references used to author the estimator wrapper: [pinned LWE attack interfaces](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe.py), [explicit ADPS16 quantum mode](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/reduction.py), [discrete-Gaussian standard-deviation convention](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/nd.py). These are interface references, not evidence that the wrapper has run.
