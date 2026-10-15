# What is reproduced and what a reviewer can verify

The available evidence supports an **independent reference implementation and
an independently executed 20-seed, seven-method synthetic campaign**. It does
not support the statement “the original paper is fully reproduced and every
manuscript metric is verified.” Publishing all 140 independent runs and making
CI exercise every executable verification stage improves auditability; it
cannot create missing original measurements or physical-board observations.

The machine-readable companion is
[`claim-coverage.json`](../evidence/independent/claim-coverage.json).
Its `paper_reproduced` and `all_manuscript_metrics_verified` values deliberately
remain `false`. A green workflow means its declared checks passed. It is not
permission to change those values or to interpret independent synthetic runs
as original-author experiments.

## Claim and evidence matrix

| Claim or manuscript quantity | Evidence that exists | What remains unverified |
|---|---|---|
| Additive encryption/decryption, exact-roster authorization, hidden-tag rejection and durable replay rejection | Canonical host source, functional tests and fresh-key real ML-DSA protocol trials | Original implementation equivalence; complete board protocol and security of every deployment integration |
| Original `k=3`, `n=m=768`, 4,096-byte tuple and 128.1-bit estimate | Legacy tuple is explicit; original estimator source is pinned | Original estimator log/environment is missing. The executed generic estimate for this tuple does not meet 128.1 bits |
| Selected `k=6`, `n=m=1536`, 7,168-byte tuple | Seven executed attacks, unmodified logs, environment/source identities and independent cost arithmetic; minimum 136.475 bits | Estimate is heuristic generic flattened-LWE with a Gaussian-like model and ADPS16 quantum reduction cost. It is not a proof for the finite CDT, module structure, side channels or every attack |
| Correct decoding of the selected finite sampler | Exact 256-bit integer CDT and outward-interval bound; all six fixed cases and one 42-choice adaptive union below `2^-128` | Scope is one preauthorized fresh honest batch, jointly over key/history/noise. It is not a per-fixed-key, arbitrary conditional-history or lifetime guarantee; semantic signal no-wrap and deployment resource certificates are separate |
| Historical **independent** 20 seeds × seven methods = 140 runs | Full source/config/controller snapshots, seed-specific common inputs, raw event/packet/report/epoch logs, per-run manifests, per-seed metrics and independent recomputation receipts in the companion raw archive | These records are not the unavailable original manuscript runs. Byte hashes authenticate file consistency, not the physical truth of a model |
| Original 300-s run, 30-s warm-up, 16 gateways, OMNeT++ 6.0/INET 4.4/RPL MRHOF network | Manuscript target/configuration mapping; prospective `paper_like_config.json` | Executed independent default instead uses a synthetic Python model, 3,000 sensors/60 gateways, 90-s generation plus 35-s drain. A prospective config does not establish its execution or INET/RPL equivalence |
| Original latency/loss/recovery comparisons and Figs. 2–6 | Original numbers are comparison targets only; independent raw data yields its own metrics | No original raw runs, exact original baselines or original model. Independent results do not establish the manuscript's claimed numerical superiority |
| Original recovery time (e.g. 33.0 s) | Explicit independent recovery rule and right-censor flags | All 140 independent records are right-censored. The 95-s censoring interval is not an observed recovery time |
| Original 5,000-node loss of 0.098% | Transcribed comparison target | No executed 5,000-node original-equivalent campaign or raw result |
| Integer Db2 fidelity: RMSE/PRD for all three profiles | Independent transform, exact inversion and synthetic signal regression checks | Original lifting/normalization/support details, raw sensor windows/scaling and original reconstruction logs are absent. Synthetic regressions do not verify manuscript RMSE/PRD |
| HMM uncertainty, calibration, invariant domain, fallback and certified stability | Host controller gates and synthetic closed-loop fixture | Separate training/calibration/evaluation data and reviewed model/domain/adaptation/fallback certificates are absent. Independent decisions remain uncertified |
| Full-protocol airtime/traffic and energy | Synthetic byte/fragment/retry accounting and explicitly assumed processing/energy costs | Original network model; measured PHY/radio losses; complete ticket lifecycle, receive/listen/OS/interrupt costs; measured energy calibration |
| nRF52840 encryption/transform cycles, CPU time and energy | Cross-compiled independent core harness and host known-answer tests; serial capture and verification tools | Physical samples = **0**. Harness does not implement complete M-LWE encryption, ML-DSA, HMAC/KDF, IntDb2, radio or Contiki. A build cannot verify 3.6M cycles, 58.125 ms or 1.395 mJ |
| Original SRAM, flash and stack high-water values | ELF/map/compiler stack-use records for the independent core harness | Original complete firmware and role-specific execution/measurement. Current core build sizes do not verify 27,976-byte static SRAM, 1,352-byte stack HWM, 29,328-byte peak SRAM or 91,188-byte flash |
| Complete 10-KiB streaming workspace and deployment resource feasibility | Core buffer layout and explicit action-certificate interface | Complete-role crypto/transport/sensing/state/stack layout and external certificate under the selected tuple, compiler and operating conditions |
| CI coverage | Tests/builds/raw recomputation, replay and pinned mathematical/security checks can be made mandatory as declared by the workflow | Hosted CI cannot observe a physical board, restore missing original-author files, certify an RF/calibration model, or turn a heuristic estimate into a security theorem |

The per-quantity target values and their historical meaning are listed in
[`experiments/paper_targets.json`](../experiments/paper_targets.json). They are
not supplied to the independent simulator as outputs, tuning objectives or
acceptance tolerances. Historical claim mapping is in
[`CLAIM_TRACEABILITY.md`](CLAIM_TRACEABILITY.md); model assumptions are in
[`simulation/README.md`](../simulation/README.md).

## How to audit the independent 140-run campaign

Obtain every part of the published companion evidence release, verify its
declared SHA256 values, and extract it to a new directory. Preserve the full
archive; the small `campaign-report/` extract cannot replace raw logs. Use the
archive's byte manifest to detect missing or modified evidence files.

From a checkout with the required Python dependencies, the current verifier
can independently reconstruct all raw denominators, terminal outcomes, causal
windows, paired metrics and summaries without rerunning the network:

```bash
python tools/verify_simulation_campaign.py /absolute/path/to/evidence/independent/simulation --jobs 4
```

Deterministic **network re-execution** is an additional, more expensive check.
Use the historical campaign's frozen source, because the verifier intentionally
rejects source drift, including later verifier-only changes:

```bash
CAMPAIGN=/absolute/path/to/evidence/independent/simulation
PYTHONPATH="$CAMPAIGN/source/src" python \
  "$CAMPAIGN/source/tools/verify_simulation_campaign.py" "$CAMPAIGN" --replay
```

The full raw recomputation receipt and a completed deterministic replay receipt
are distinct evidence. A replay command or CI job definition alone is not an
execution result. Raw bitwise identity is scoped to the recorded software
environment. The mandatory historical byte replay uses macOS ARM64/Python
3.12.10; Linux independently recomputes all historical raw metrics. The observed
one-ULP cross-environment epoch difference and the two single-case probes are
preserved in [REPLAY_PORTABILITY.md](REPLAY_PORTABILITY.md). These diagnostics do
not substitute for the full 140-case CI receipt.

## What is still required for a full-paper claim

1. Recover the original simulator, firmware, configurations, seed identities,
   trace/calibration inputs and original execution records, **or revise the
   manuscript explicitly around a new, fully specified independent experiment**.
   These alternatives must not be conflated. Replacing the paper's model and
   parameters changes the claim being tested.
2. Freeze a complete, equal-treatment network/baseline implementation, execute
   the manuscript's full size/workload matrix and 20 paired seeds, and publish
   inputs/raw logs/uncensored or correctly censored outcomes, estimands and CIs.
   A 140-run execution of the different synthetic workload does not meet this
   requirement.
3. Implement the complete selected-parameter board protocol, physically run it
   on identified nRF52840 hardware, and capture raw cycles, stack/memory and
   external calibrated power traces with build identity and all processing and
   radio boundaries disclosed. Existing core microbenchmarks are insufficient.
4. Supply the actual signal corpus/scaling, training/heldout/evaluation split,
   model fit, uncertainty/adaptation/domain/fallback evidence, action-specific
   no-wrap/memory/airtime certificates and signal reconstruction results.
5. Bind every manuscript table/figure/metric to the exact input, code, executed
   artifact and independent verification recipe. Update wire, runtime, energy
   and memory figures together for the new `k=6` tuple. Keep cryptanalytic
   estimates and decoding probability bounds within their stated scopes.

Until those evidence-bearing steps are complete, accurate author-facing wording
is:

> We release an independently implemented reference and the complete raw
> evidence for a 20-seed, seven-method synthetic campaign. The records support
> independent metric recomputation and frozen-source replay under the disclosed
> model. CI verifies the executable artifacts within its declared scope. These
> results do not establish reproduction of the manuscript's original network,
> calibration or physical-board measurements. The selected parameter set has
> a 136.475-bit minimum under the stated pinned heuristic estimator model.
