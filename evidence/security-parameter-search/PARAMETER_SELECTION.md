# Independently selected security parameters

Actual SageMath 10.9 execution against the official lattice-estimator commit
`53da5982597709ba0fdf94ea37a84d822310fd84` completed all seven required attacks.
This is a new parameter selection, not reproduction of the manuscript k=3 result.

## Screening

Ring degree 256, modulus 2^32, Gaussian secret/error standard deviation 3.2 and
public-key independent sample count m=n=k*256 were held fixed. Primal-uSVP was
used only to reject inadequate candidates before full validation.

| Rank k | n=m | Ciphertext bytes | Primal-uSVP log2(rop) |
|---:|---:|---:|---:|
| 4 | 1024 | 5120 | 78.970000 |
| 5 | 1280 | 6144 | 107.325000 |
| 6 | 1536 | 7168 | 136.475000 |
| 7 | 1792 | 8192 | 166.950000 |
| 8 | 2048 | 9216 | 197.955000 |
| 9 | 2304 | 10240 | 229.755000 |
| 10 | 2560 | 11264 | 262.085000 |

Rank 6 is the smallest candidate meeting the target in this tested rank family:
rank 5 already has a computed generic attack cost below 128.1 bits. This is not
a global optimum across different degrees, moduli, distributions or attack models.

## Selected rank 6: complete required attack set

| Attack | log2(rop) | Status |
|---|---:|---|
| primal_usvp | 136.475000000 | success |
| primal_bdd | 137.475000000 | success |
| primal_hybrid | 137.475000000 | success |
| primal_mitm_hybrid | 337.365105414 | success |
| dual | 139.125000000 | success |
| dual_hybrid | 138.595004881 | success |
| coded_bkw | 435.299954756 | success |

Computed minimum: **136.475000 bits**, from primal-uSVP.
Explicit threshold 128.1 passed; all seven attacks succeeded; exit code 0;
upstream tracked bytes remained unchanged. Independent record/hash/arithmetic
verification is preserved in `selected-k6-full/verification.json`.

## Implementation consequences

- Ciphertext size becomes 7168 bytes, 75% above the original 4096-byte tuple.
- Plaintext degree remains 256, so the existing 240-data/16-tag packing capacity
  is unchanged. A raw two-polynomial report would transmit 14336 ciphertext bytes.
- Rank-dependent public-key vectors, matrix arithmetic, decryption-noise bounds,
  aggregation capacities, airtime and embedded workspace must be updated and
  independently tested. No old 10-KiB, timing or decoding certificate is inherited.
- Costs are heuristic generic flattened-LWE attack estimates under quantum
  ADPS16 reduction/GSA and the pinned algorithms' native other-stage conventions.
  They are not a module-specific, side-channel, implementation or worst-case proof.

The full raw logs, exact inputs, per-attack costs, environment/package metadata,
source-file SHA256 manifest and executed command are in `selected-k6-full/`.
