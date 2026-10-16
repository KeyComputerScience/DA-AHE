# Independent security-estimation execution

This workflow generates **independent reproduction** evidence. It does not
recover the authors' missing logs, certify the original 128.1-bit claim, or
provide a module-specific/worst-case security proof. Nothing generates a
plaintext-wrap, airtime or embedded-memory certificate in this estimator
workflow. The separate actual-finite-CDT correctness calculation is documented
in [`DECODING_BOUND.md`](DECODING_BOUND.md).

The current independent encryption default is **k=6, d=256, n=m=1536** and
7,168-byte ciphertexts. Its archived seven-attack minimum is **136.475 bits**
under the declared generic flattened-LWE and ADPS16 quantum heuristic model.
The fixed-tuple runner below retains the historical **k=3/n=m=768** problem,
which did not meet 128.1 bits in the independent run. For current k=6 inputs use
the explicit parameterized command in the candidate-validation section.
Current publication locations are in `evidence/independent/publication.json`;
historical logs and status snapshots remain unchanged.

## Run the legacy manuscript tuple in SageMath

Clone the official source and select exactly the paper's commit:

```bash
git clone https://github.com/malb/lattice-estimator.git external/lattice-estimator
git -C external/lattice-estimator checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
python tools/estimate_security.sage \
  --estimator external/lattice-estimator \
  --output runs/security-legacy-k3 \
  --attack-timeout 300
```

The `python` command above must be the Python interpreter inside an active
SageMath environment. The executed local environment is SageMath 10.9, where
historical `sage -python` syntax is no longer accepted. For the older 10.6
container, the entrypoint probes Sage-enabled Python and then the newer
`sage --python` and historical `sage -python` launch forms. The runner itself
is ordinary Python source despite its `.sage` filename.

For sandboxed local execution, set `DOT_SAGE`, `MAXIMA_USERDIR`, and
`XDG_CACHE_HOME` to writable task-local directories. `MAXIMA_USERDIR` is needed
by coded-BKW's symbolic calculations; a failed attempt is preserved rather than
being reclassified as an attack result.

Use a new output directory for every attempt. Each of the seven attacks runs in
its own process. The deadline covers import/setup and computation. Increase it
for attacks that time out; preserve the failed attempt. A diagnostic subset can
be selected with `--attacks primal_usvp`, but it always remains an incomplete
estimate and exits with code 2. Optional `--minimum-bits NUMBER` compares an
**actually computed complete** minimum to a reviewer-specified threshold; it
never substitutes that number into output. There is no default security result
or threshold.

Exit 0 means all required attacks produced finite operation counts and any
explicit threshold was met. Exit 2 means incomplete attacks, a threshold failure
or invalid input. Successful individual costs remain available when other attacks
fail. `lambda_est_bits` is null until all seven required attacks succeed.

## Auditable outputs

- `security.json`: incremental result, inputs, status, timestamps, scope, script
  hashes, each attack's raw fields and the actual minimum.
- `ATTACK.json` and `ATTACK.log`: isolated outcome and unmodified stdout/stderr;
  failures and timeout logs are retained.
- `security.csv` and `stdout.log`: comparison table and combined raw log.
- `upstream-source.json`: exact Git commit/tree, origin, tracked-file SHA256
  manifest. The checkout must be clean and is checked again after execution.
- `environment.json`: executable, Sage/Python/platform, installed Python
  distributions and available conda package URLs/builds/checksums.

Unknown upstream memory or sample-count fields remain null. Coded-BKW's derived
sample count is distinguished from the original 768 independent public-key
samples. Its effective problem, signed-combination count and amplified noise
are recorded and checked against the pinned implementation. These derived
samples are an estimator heuristic, not fresh independent observations.

The legacy fixed problem is n=768, m=768, q=2^32, independent centered Gaussian secret
and error with standard deviation 3.2. Module rank 3 and ring degree 256 are
metadata; the estimator evaluates the **generic flattened** instance. Lattice
reduction is explicitly `ADPS16(mode='quantum')`, with GSA for primal attacks.
Coded-BKW and nonreduction attack stages retain their upstream cost conventions;
this is not an exhaustive analysis of every possible quantum attack.

## Isolated container/CI entry point

`security/Dockerfile` provides a version-selected SageMath environment and
fetches the exact estimator commit. Its build/run has not been claimed executed
merely by shipping these files. For an immutable base, set SAGE_IMAGE to a
verified `sagemath/sagemath:10.6@sha256:...` image reference and archive the actual
image ID. The version tag alone is not an immutable dependency lock.

```bash
docker build --file security/Dockerfile --tag daahe-estimator .
mkdir -p evidence/independent/security
docker image inspect daahe-estimator > evidence/independent/security/container-image.json
docker run --rm --mount type=bind,src="$PWD/evidence/independent/security",dst=/evidence \
  daahe-estimator --output /evidence/container-run-01 --attack-timeout 900
```

CI can run the same commands with its own artifact upload step. Upload the
entire output directory even when the runner exits 2. Do not turn failed or
missing attacks into passing results. The container runs as root only inside
its isolated filesystem to make the bind-mounted evidence writable; it does
not need privileged mode or the host Docker socket inside the container.

The Sage installation attempts, actual executed run directories and their
outcomes must be described in the top-level independent-evidence index by the
integrating task. The instructions above do not assert that a run succeeded.

## Explicit parameter search and full candidate validation

`tools/search_security_parameters.py` screens the requested ranks with
primal-uSVP only. Screening cannot establish the security target. Inputs and
raw costs are preserved for every attempted rank, including failures/timeouts.
Use Sage-enabled Python:

```bash
python tools/search_security_parameters.py --estimator external/lattice-estimator \
  --output evidence/independent/security-parameter-search/ranks-04-10 \
  --ranks 4 5 6 7 8 9 10 --target-bits 128.1
python tools/estimate_security_parameters.py --estimator external/lattice-estimator \
  --output evidence/independent/security-parameter-search/selected-k6-repeat \
  --module-rank 6 --ring-degree 256 --q 4294967296 --sigma-key 3.2 \
  --minimum-bits 128.1 --attack-timeout 600
```

The second command repeats the selected rank-6 inputs in a new evidence directory.
The actual executed result is archived in
`evidence/independent/security-parameter-search/selected-k6-full/`: all seven
attacks succeeded and the computed minimum was 136.475 bits, exceeding 128.1.
`PARAMETER_SELECTION.md` in its parent directory describes the rank screening
and tradeoffs. This is a changed parameter set, not the manuscript k=3 estimate. Its public full-run interface always attempts all seven attacks and
cannot prune an unfavorable attack. An explicit `--n` is an optional consistency
assertion and must equal k*d; the public-key sample count is also k*d. The
parameterized estimator runner's argument defaults retain k=3, d=256, q=2^32
and sigma=3.2; these are distinct from the encryption implementation's current
k=6 default. Always pass `--module-rank 6` to estimate the selected candidate.
Changing estimator arguments does not silently change the manuscript tuple or
the encryption implementation.

At q=2^32 and d=256, a ciphertext has `(k+1)*256*4` bytes: 7,168 bytes at
the current k=6 instead of 4,096 bytes at legacy k=3. RAM, airtime, decryption
failure and batch capacities must therefore be recertified. The selected
finite-CDT decoding bound is separate evidence; complete deployment resource
and control certificates remain unestablished. An estimator threshold pass is only a result
under the pinned generic attack models, never a full deployment certificate.

The container also includes the configurable runner. Add `--parameterized` as
its first argument to select it, followed by the explicit candidate parameters;
without that argument it continues to run the original fixed-tuple script.
Container execution remains a separate unexecuted fallback until actually built
and run and its image identity and raw logs are archived.

Verify the preserved full result independently of the Sage execution process:

```bash
python security/verify_run.py \
  evidence/independent/security-parameter-search/selected-k6-full \
  --upstream external/lattice-estimator --minimum-bits 128.1
```

The verifier recomputes log2 costs with Decimal, the actual minimum, all seven
attack statuses and process exits, raw-log checksums, per-attack/aggregate JSON
agreement, and the source-byte manifest. This verifies record integrity and
arithmetic, not the validity of the estimator's cryptanalytic assumptions.
