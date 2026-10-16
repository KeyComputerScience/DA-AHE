# Finite task decoding risk budget

`tools/check_decoding_horizon.py` turns the archived rank-6 decoding interval
bound into an explicit finite task budget. It checks artifact identity and
parameter/scope consistency, then uses exact rational arithmetic. It does not
rerun the MGF calculation, Sage interval proof or security estimator.

## What is covered

The input is `evidence/independent/decoding/k6-cdt-03/decoding-bound.json`, with
SHA256 `2be1b88b34bdee74c852fd12c9020c4fed1870a117f4a63ab00d057944991335`.
The tool also checks the report's local archived CDT hash and binding to the
selected security report through `configs/security_profile.json`. Absolute
paths recorded in historical execution logs are provenance only and are never
opened by this tool.

The report describes k=6, d=256, n=1536, q=2^32, p=65537 and key sigma 3.2.
Its finite library contains 42 profile/size choices:

| Encryption sigma | Allowed batch sizes | Number of choices |
|---:|---:|---:|
| 3.2 | 1 through 16 | 16 |
| 3.4 | 1 through 14 | 14 |
| 3.6 | 1 through 12 | 12 |

At most two plaintext polynomials are covered. The archived proof establishes
smaller-batch dominance for each profile and takes a union over these 42
choices. This does not mean 42 batches: it protects **one selected batch**,
including a choice depending on past observations, when its profile and roster
are selected before its fresh honest encryption noises are generated. Selecting
source subsets after inspecting current-batch ciphertexts/noises is excluded.

The probability is joint over random key generation, history and fresh honest
batch encryption noise. Shared key coefficients are accounted for inside the
MGF expectation. It is **not** a bound for every fixed realized key or a bound
conditioned on every arbitrary observed history. The finite reference CDT,
including the report's q-p*floor(q/p)=1 scaling carry, is the sampler model
covered; another sampler or parameter tuple requires new bound evidence.

The outward interval's **exact rational upper endpoint** is used, approximately

`U = 5.1584964976909909632264946143879767e-40`.

The report's approximate log2 upper endpoint is -130.5101731584115. Neither a
rounded decimal nor a rounded logarithm is used to decide whether a task passes.

## A finite horizon

For a predeclared cap of B fresh-noise batch attempts, the union bound gives

`P(any covered decoding failure during the task) <= min(1, B*U)`.

No independence between batch outcomes is assumed. The same sampled key may
be reused, and later actions may depend on past observations. Each future
batch must still satisfy the archived one-batch assumptions, including fresh
honest encryption noises independent of the past and selection before those
noises. The finite-library union covers the adaptive choice unconditionally;
it does not turn into an arbitrary-history conditional probability guarantee.

Count attempts rather than successful deliveries. A new encryption with fresh
noise consumes another attempt, even if it is dropped or retried later.
Replaying the identical cached envelope does not generate fresh noise and is
not a new cryptographic draw, although it can affect network or replay logic.
A random stopping rule is covered by a finite, predeclared upper cap on all
attempts; counting only accepted outputs would omit selection and retry risk.

For an exact target risk R strictly between zero and one, the maximum integer
cap justified by this bound is

`B_max = floor(R/U)`.

| Target R | Last passing B | First failing B |
|---:|---:|---:|
| 2^-128 | 5 | 6 |
| 2^-120 | 1458 | 1459 |
| 2^-100 | 1529245790 | 1529245791 |

Consequently, a single batch below 2^-128 does not establish a 300-batch task
below 2^-128. The same 300-batch cap passes the weaker 2^-120 decoding-risk
target. Selecting the task target is an explicit application requirement; this
tool does not silently weaken it or regenerate the one-batch proof.

## Run

```bash
python tools/check_decoding_horizon.py --batches 5 --target-bits 128
python tools/check_decoding_horizon.py --batches 300 --target-bits 120
python tools/check_decoding_horizon.py --batches 10 --target-risk 1e-30
python tools/check_decoding_horizon.py --batches 5 --target-bits 128 \
  --output evidence/independent/new-task-budget/b5-target128.json
```

Successful validation and budget comparison exit 0. A failed risk budget,
wrong artifact hash, wrong parameter tuple, unsupported scope or malformed
input exits 2 and emits JSON. `--batches 6 --target-bits 128` deliberately
fails. `--target-risk` accepts an exact decimal or rational such as `1/1000`;
`--target-bits 128` represents exactly 1/2^128. The tool returns the exact upper
endpoint, exact task bound, maximum integer cap and explicit scope flags.

`--root` can select a local checkout containing the same pinned evidence.
Artifacts must be regular in-tree files; current security metadata must match
the decoding tuple. The checker does not follow the archival command's paths
or rewrite any evidence file. A changed report cannot be approved merely by
changing its declared hash in the current security profile.

`--output` creates a new JSON record, including an expected budget rejection
such as B=6 at target 2^-128. Relative output paths are resolved within `--root`;
absolute output paths must also remain within that root. Existing files are
never overwritten. A runner recording the B=6 case should mark exit 2 as the
expected rejection, not relabel that budget as passing. Standard output returns
the same record; normal records contain no local absolute execution paths,
usernames, environment variables or hostnames.

## What a passing result does not establish

The result retains `conditional_per_fixed_key_guarantee=false`,
`full_system_certified=false` and `proof_reexecuted=false`. It does not establish
unlimited lifetime correctness, malicious-ciphertext decoding, confidentiality,
aggregate integrity, plaintext data no-wrap, physical aggregation fidelity,
network availability, controller invariance, airtime, RAM or board execution.
Those require their own evidence and budgets. A decoding target is only one
component of a task-level reliability or security argument.

The tests exercise exact last-pass/first-fail boundaries, dependent-outcome
union arithmetic, zero and saturated horizons, corrupted artifact hashes,
wrong parameters, widened libraries, missing shared-key/dominance conditions
and unsupported probability scope. They validate the budget consumer and
rejection behavior; they are not a replacement for the archived interval proof.

Run the standard-library tests with
`python -m unittest discover -s tests -p test_decoding_horizon.py -v`.
Pytest can also collect these unittest cases when available.
