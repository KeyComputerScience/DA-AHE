# Independent 128.1-bit estimator run

This directory is deliberately independent from the DA-AHE protocol code.
It recomputes the fixed long-term flattened-LWE estimate for
`n=768`, `q=2^32`, `m=768`, and `Xs=Xe=D_Z,3.2`.

Required lattice-estimator commit:
`53da5982597709ba0fdf94ea37a84d822310fd84`.

Run under SageMath from this directory:

```sh
git clone https://github.com/malb/lattice-estimator.git
git -C lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
ESTIMATOR_ROOT="$PWD/lattice-estimator" SAGE=sage ./run.sh
```

The script writes `results/security_1281.json`,
`results/security_1281.csv`, and `results/stdout.log`.  It exits with status 2
if the actual minimum does not round to 128.1 bits.  No table entry is
hardcoded as an estimator result.
