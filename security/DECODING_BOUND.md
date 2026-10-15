# Finite-reference-sampler decoding tail bound

This is an independently calculated correctness bound for the actual finite
reference sampler. It is not a claim to recover the authors' missing proof or
logs. The probability is joint over random key generation and fresh honest
batch encryption. It is **not a worst-case guarantee for every fixed realized
key**, nor a bound conditioned on an arbitrary observed past history.

## Exact distribution and independence

`daahe.mlwe._gaussian_cdt(sigma)` uses 120-digit Decimal calculations to build
an integer CDF on a 256-bit uniform sample space, with finite support
`[-ceil(16*sigma), +ceil(16*sigma)]`. Whatever approximation that construction
makes to a Gaussian, the implemented distribution itself has exact masses

`P[X=a] = (CDF[a] - CDF[a-1]) / 2^256`.

The tool reads those actual integers. It does not replace them by an ideal
Gaussian. Full CDFs, integer counts and their SHA256 values are archived.
CDF endpoints and normalization are checked. Uniform 256-bit draws and distinct
noise coefficients are assumed independent; default CSPRNG sampling is the
reference implementation of that randomness assumption. Python sampling and
arithmetic are not constant-time, and seeded test RNGs are not a deployment RNG.

At one fixed output coefficient of a negacyclic product, each key coordinate
pairs with exactly one, distinct ephemeral-noise coordinate. Across the k
components this gives n=k*d independent pairs. The e/r family and s/e1 family
are also independent. Coefficients at different output positions can be
correlated; the final union bound does not assume otherwise.

For N honest ciphertexts using the same public key, the integer error polynomial
before reduction modulo q is

`E = e^T (sum_i r_i) - s^T (sum_i e1_i) + sum_i e2_i`.

For the exact encryption-noise MGF `M(t)=E[exp(t X_enc)]`, each product term has
MGF `G(t)=E_{A~key}[M(t*A)^N]`. The exponent N must be **inside** the key
expectation because the same key coefficient is reused across the reports.
Putting N outside that expectation would incorrectly resample the key for each
report. Tests compare this expression to explicit tiny-PMF enumeration.

The integer CDT has a very small asymmetry, so the proof uses
`Gmax(t)=max(G(t),G(-t))` and `Mmax(t)=max(M(t),M(-t))`. These cover both tails
and every sign introduced by the negacyclic convolution and the subtracted
s/e1 product. Independence holds within a fixed coefficient, yielding

`E[exp(±t E_coeff)] <= Gmax(t)^(2*n) * Mmax(t)^N`.

## Exact scaling carry and decoder

For q=2^32, p=65537, `Delta=floor(q/p)=65535` and `q-p*Delta=1`.
Write the sum of centered plaintext lifts as `S=m+p*h`, with m its centered
Fp representative. Uniformly over all plaintexts, `|h|<=ceil(N/2)`. Then

`Delta*S = Delta*m + h*(q-1) = Delta*m - h (mod q)`.

The effective decoding noise is therefore `E-h`, including plaintext/tag wrap.
For odd Delta, the actual integer-rounding decoder is correct whenever
`|E-h| <= floor(Delta/2)`. The extreme centered plaintext values also remain
strictly inside the centered q interval under this margin. The tool uses the
more conservative integer tail threshold

`T = floor(Delta/2) - ceil(N/2) - 1`.

Thus `|E|<T` is sufficient for correct decoding. Small-parameter exhaustive
tests check every plaintext combination and every noise below T, including
positive/negative carry. This is a modulo-p decoding statement. Semantic
sensor-data no-wrap constraints are separate and are not certified here.

For any positive rational t and at most C plaintext polynomials, Chernoff and
union bounds give

`P(any bad decoded coefficient) <= 2*d*C*Gmax(t)^(2*n)*Mmax(t)^N*exp(-t*T)`.

The Gaussian variance expression is used only to select the legal rational
`t=T/(2*n*N*sigma_key^2*sigma_enc^2 + N*sigma_enc^2)`. It is not substituted into
the probability calculation. Every MGF sum uses the exact finite-CDT masses.

## Outward interval calculation and actual results

SageMath 10.9 `RealIntervalField(256)` evaluates the positive sums, powers,
exponentials and natural logarithms with outward rounding. Both endpoints,
including the final upper endpoint as an **exact rational**, are archived.
The pass comparison to -128 uses that exact upper endpoint, not a rounded
printed decimal or floating-point decision.

For rank k=6, d=256, n=1536, q=2^32, p=65537 and key sigma 3.2, the executed
bounds are:

| Encryption sigma | Maximum N | log2 upper, C=1 | log2 upper, C=2 |
|---:|---:|---:|---:|
| 3.2 | 16 | -135.853052277877 | -134.853052277877 |
| 3.4 | 14 | -137.581795824483 | -136.581795824483 |
| 3.6 | 12 | -143.304555758723 | -142.304555758723 |

All six are below -128. The full exact endpoint values are in
`evidence/independent/decoding/k6-cdt-03/decoding-bound.json`, bound to the actual
CDT/source hashes and the selected seven-attack security-report hash and tuple.
The security estimator uses its own Gaussian model; this hash binding does not
turn the decoding calculation into a security reduction for the finite sampler.

Attempt `k6-cdt-01` failed because Sage QQ rejects decimal strings directly;
its failure record and generated CDFs are preserved. `k6-cdt-02` passed the six
fixed-profile checks. `k6-cdt-03` additionally checks the finite adaptive union
below. No failed attempt was overwritten or relabeled as successful.

## One adaptive choice from the finite action library

For each profile, the tool explicitly verifies with interval lower endpoints
that `M_enc(±t*a)>=1` at every nonzero key-support point; at a=0, normalization
gives M(0)=1 exactly. It also verifies `M_enc(±t)>=1`. Therefore, at the fixed
rational t selected for Nmax, all the MGF factors are nondecreasing with N,
while `T_N>=T_Nmax` for N<=Nmax. The Nmax bound dominates every smaller batch
size under that same profile.

The library `(sigma,N)` with N=1..16, 1..14 and 1..12 contains 42 combinations.
Using C=2, a conservative finite union is

`U_adapt <= 16*U(3.2,16,2) + 14*U(3.4,14,2) + 12*U(3.6,12,2)`.

The executed adaptive-union log2 upper endpoint is
**-130.51017315841150379938...**, or probability at most
5.158496497691e-40, below 2^-128. The exact interval and 42-configuration check are preserved
in `finite_adaptive_union` in the actual report. This covers one selection from
that declared library, including dependence on past key-related observations,
**unconditionally over random key generation and the past**, provided the next
batch's fresh encryption noises are independent and the action/roster is
selected before those noises are generated. It does not claim a conditional
per-history or per-fixed-key certificate. Selecting source subsets after
observing the current batch's ciphertexts/noises would require a larger, explicit
selection-event analysis and is excluded.

Across a specified finite number B of batches, another union bound is required;
independence between batches is unnecessary but a factor B is still incurred.
No unlimited-lifetime guarantee or full-domain controller certificate is given.
Network loss, adversarial malformed ciphertexts, control-model validity, airtime,
embedded RAM, key protection and constant-time behavior remain separate claims.

## Reproduce

Use the Python interpreter inside SageMath and writable task-local Sage/Maxima
cache directories:

```bash
python tools/certify_decoding_bound.py --module-rank 6 --ring-degree 256 \
  --q 4294967296 --p 65537 --sigma-key 3.2 \
  --profiles 3.2:16 3.4:14 3.6:12 --poly-counts 1 2 --precision 256 \
  --target-bits 128 \
  --security-report evidence/independent/security-parameter-search/selected-k6-full/security.json \
  --output evidence/independent/decoding/k6-cdt-repeat
```

Use a new output directory for every attempt. The tuple is explicit; defaults
of the encryption API cannot silently change the proof inputs.
