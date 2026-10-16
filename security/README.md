# Parameterized security estimation

The selected input is k=6, d=256, n=m=1536, q=2^32 and sigma_key=3.2.
The archived complete seven-attack minimum is 136.475 bits under the recorded
generic flattened-LWE models. Lattice-reduction attacks use ADPS16 quantum
costs; coded-BKW retains its upstream native cost convention. The finite
reference sampler, module structure, side channels and all possible attacks
are not certified by this heuristic estimate.

## Execute

Use a Sage-enabled Python interpreter and the exact upstream source commit:

```bash
git clone https://github.com/malb/lattice-estimator.git external/lattice-estimator
git -C external/lattice-estimator checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
python tools/estimate_security_parameters.py --estimator external/lattice-estimator \
  --module-rank 6 --ring-degree 256 --q 4294967296 --sigma-key 3.2 \
  --minimum-bits 128.1 --attack-timeout 900 --output runs/security-k6
python security/verify_run.py runs/security-k6 --upstream external/lattice-estimator \
  --minimum-bits 128.1
```

The parameterized runner defaults to the canonical encryption tuple. Pass an
explicit module rank when selecting another input. Its estimator dimensions
satisfy n=k*d and m=k*d. These are flattened-model inputs, not a claim that the
module instance consists of independent unstructured LWE samples.

Every attempt uses a new output directory. Seven attacks execute separately,
with deadlines covering imports and computation. An incomplete attack set
leaves the complete minimum null and exits nonzero. Individual successful costs,
failed attempts, raw logs, source hashes and runtime records remain available.
A requested threshold is compared with actual outputs and is never substituted
for a computed cost.

## Outputs and scope

The report records inputs, per-attack status and raw fields, source identity,
environment and the minimum of all seven successful costs. Unknown memory or
sample fields remain null. Derived coded-BKW samples are distinct from the
specified input sample count. Verification checks the pinned implementation
and saved output consistency; it is not a security reduction.

The optional container entry point accepts `--parameterized` followed by the
same explicit parameters. Record an immutable image identity and an actual
execution receipt when using a container.

Ciphertexts have (k+1)*d*4=7,168 bytes. No-wrap, finite-CDT decoding, workspace,
airtime and control-model certification are separate conditions. The executed
finite-sampler calculation is described in [DECODING_BOUND.md](DECODING_BOUND.md),
and finite-task budgeting in [DECODING_RISK_BUDGET.md](../docs/DECODING_RISK_BUDGET.md).
Public evidence locations are indexed in `evidence/independent/publication.json`.

## Continuous integration

The [reproduction workflow](../.github/workflows/reproduce.yml) includes the
`security` job on every pull request and main-branch push. It verifies the saved
seven-attack record, computes fresh estimates against the pinned upstream
commit, validates exact finite-sampler bounds and runs the Sage interval tests.
The `source` job checks parameter and evidence bindings, while `coverage`
requires every reproduction job to succeed.

The [CI policy guard](../tools/check_ci_triggers.py) includes this directory,
configuration directories and experiment directories in its active-source
checks.
