# Controller calibration and declared-model verification

Calibration fits the controller to newly executed packet-service records.
Certificate verification checks mathematical conditions for the declared model.
These operations produce separate reports and do not change the controller,
metrics or certification status of the archived 140-run comparison.

## Recorded 3,000-node calculation

The published [calibration bundle](../evidence/controller-calibration/)
contains 35 completed cases: five predefined scenarios for each of seven
independent seeds. The three actions have observations in all five operational
annotations in every partition.

| Partition | Cases | Causal rows | State residual L2 RMSE | Holdout-radius exceedances |
|---|---:|---:|---:|---:|
| Training | 15 | 270 | 122.976683 | 11 |
| Holdout | 10 | 180 | 123.356975 | 0 |
| Evaluation | 10 | 180 | 125.063171 | 7 |

State residuals use the declared dimensionless delay/loss/noise normalization.
A holdout maximum includes its own calibration observations, so zero holdout
exceedances is descriptive. Seven of 180 independent evaluation transitions
exceed their corresponding holdout radius.

The [certificate calculations](../evidence/controller-calibration/controller-certificate.json)
use the original gamma=0.10, beta=0.02, P=I, kappa=0.3 and domain [100,500,1].
Domain-ball containment, fallback drift and transition-set containment fail;
frozen online adaptation is verified. For the fallback, regime-wise drift
upper bounds are 139921.438773, 280765.128630, 28147.879359,
264012.564411 and 266149.434751, versus beta=0.02.
These failures are retained in the data and do not change any threshold.
The [exact zero-state counterexamples](../evidence/controller-calibration/drift-counterexamples.json)
also show a violated fallback inequality with prediction error zero: the five
regimes give V(z_next)=3235.376144, 39794.699544, 4640.789089,
64304.485656 and 62201.961929, all exceeding beta=0.02. These successors lie
inside the original cube, so this fallback failure is not merely an artifact
of a loose global upper bound.

The [full raw audit](../evidence/controller-calibration/verification-full.json)
re-extracts all 35 cases and recomputes packet outcomes, the fitted model,
causal HMM predictions, integer signal reconstruction and the certificate.
The [separate 30-node feedback check](../evidence/controller-calibration-feedback/verification.json)
independently recomputes and exactly replays all 14 seven-method/two-seed cases.
It checks execution and cannot establish a 3,000-node performance advantage.

The compact public bundle includes causal epochs, signal vectors, case CSVs,
input/controller snapshots, frozen source, fitted coefficients and mathematical
reports. Large network events/packets/reports and topology/traffic bytes have
separate SHA256 commitments in `publication-index.json`; the generator recreates
them from the preserved inputs. Compact auditing does not claim to have
re-extracted those omitted network bytes.

```bash
python tools/verify_controller_calibration.py evidence/controller-calibration
python tools/verify_controller_calibration.py runs/controller-calibration \
  --raw-root runs/controller-calibration --output runs/controller-full-audit.json
```

The first command refits all CSV partitions and recomputes causal HMM scores,
actual integer signal reconstruction and the exact certificate. The second also
checks every raw input/output file, re-extracts the causal traces and independently
recomputes packet summaries. Bundle integrity and certificate validity are
reported as separate fields.

## Generate the calibration records

Use Python 3.12 with the repository's pinned dependencies and a new output
directory:

```bash
python -m pip install -e '.[dev,evaluation]'
python tools/run_controller_calibration.py \
  --output runs/controller-calibration --nodes 3000 --jobs 2
```

The runner uses the independent two-hop packet-service model and separates
training, holdout and evaluation seeds before fitting. Its default partitions
are:

| Partition | Seeds | Purpose |
|---|---|---|
| Training | 20000, 20001, 20002 | Fit controller prediction parameters |
| Holdout | 21000, 21001 | Estimate residual envelopes and report diagnostics |
| Evaluation | 22000, 22001 | Assess predictions without fitting on these records |

Each partition exercises the runner's five declared scenarios. Topology,
traffic, disturbance inputs, controller actions and resulting network records
belong to these new executions. They are not substituted for the original
20-seed archive. The effective node count and all other inputs are recorded
with the run.

To reproduce the recorded input/parameter identity, use the frozen source and
explicit snapshots from the compact publication (macOS ARM64, Python 3.12.14):

```bash
cd evidence/controller-calibration
python source/tools/run_controller_calibration.py \
  --config input-config.json --controller input-controller.json \
  --output ../../runs/controller-frozen-replay --nodes 3000 --jobs 2
```

The copied security/decoding artifacts retain the bound source-relative paths.
Execution timestamps are new; model/trace checks use the saved numerical inputs.
The repository's prospective default uses the newly fitted controller, so a new
default run has its own input identity.

For a smaller software check, use a separate output directory:

```bash
python tools/run_controller_calibration.py \
  --output runs/controller-calibration-smoke --nodes 120 --jobs 2
```

A smaller run has its own workload identity and cannot establish the 3,000-node
calibration results.

## Inspect the outputs

| File or directory | Contents |
|---|---|
| `controller.json` | Fitted controller configuration and calibration metadata |
| `training.csv` | Training records used by the fit |
| `holdout.csv` | Separate residual-calibration records |
| `evaluation.csv` | Evaluation records excluded from fitting |
| `calibration-report.json` | Fit, prediction and residual diagnostics with scope metadata |
| `plan.json` | Immutable seed/scenario schedule, fit settings, source and input identities |
| `manifest.json` | Completed cases, output hashes and execution status |
| `source/` | Source snapshot for the execution |
| `cases/` | Partition/seed/scenario inputs, configurations and raw network records |
| `cases/.../signal-cases.jsonl.gz` | Exact source, transformed, reference and reconstructed integer vectors |

The CSV partitions and raw cases allow the reported fit and diagnostics to be
traced to their inputs. Residual maxima and finite-sample evaluation describe
these records. They are not, by themselves, uniform error bounds for every
permitted state, history or physical deployment. The signal vectors use their
declared model units; physical scaling requires a corresponding calibrated
sensor corpus.

## Verify the declared mathematical model

```bash
python tools/verify_controller_certificate.py \
  --controller runs/controller-calibration/controller.json \
  --output runs/controller-calibration/controller-certificate.json
```

The verifier requires explicit certificate assumptions and checks the complete
configuration rather than substituting manuscript target values. Its report
retains each condition, the calculation used, and its pass or failure outcome.

| Condition | Calculation and scope |
|---|---|
| Domain invariance | Check that every declared action/regime successor-error ball remains inside the declared state cube |
| Fallback drift | Bound the fallback's piecewise quadratic drift over the cube, including its prediction-error term, and compare with the configured drift allowance |
| Transition-set containment | Compare the declared kernel discrepancy and posterior-error allowance with the online ambiguity radius |

Missing assumptions or a failed inequality produce a failed report. The tool
preserves that report and returns a nonzero exit status; it does not enlarge
the domain, relax the drift allowance or overwrite an existing result to
manufacture a passing certificate.

Recompute an existing report without replacing it:

```bash
python tools/verify_controller_certificate.py \
  --controller runs/controller-calibration/controller.json \
  --verify-report runs/controller-calibration/controller-certificate.json
```

Report recomputation checks integrity and agreement with the calculation.
That audit can succeed for a faithfully recorded failed certificate; its exit
status must not be substituted for the report's scientific pass/failure state.

The certificate report has `scope="declared_model_only"`. A successful check
establishes the listed conditions under its stated mathematical assumptions.
It does not prove that empirical residual maxima cover the physical process,
that an estimated posterior equals the true conditional law, or that the online
floating-point gate has a certified roundoff margin. Its deployment and
full-system certification states remain separate from this model-relative
verification.

## Preserve the historical comparison

The public campaign's frozen source, controller snapshot, input hashes and
per-seed outputs retain their original identities. Calibration runs use new
directories and manifests. Activating a fitted configuration for a later study
requires that study's own executed records; neither fitting a model nor
verifying its declared assumptions retroactively certifies the earlier
network decisions.

Related specifications are [controller equations](CONTROL_IMPLEMENTATION_SPEC.md),
[hard resource/evidence gates](CERTIFICATION.md),
[evaluation scope](REPRODUCTION_COVERAGE.md) and
[public archive checks](PUBLIC_EVIDENCE.md).
