# Third-party provenance

- Contiki-NG: release/v4.8 commit
  `9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f`.
- PQClean ML-DSA-44 clean implementation and FIPS-202 source: PQClean commit
  `0586a824fc0d49df0b6b6e9179d8d15d06d0974f`. The upstream license is
  included under `third_party/ml_dsa_44/LICENSE`.
- lattice-estimator: required commit
  `53da5982597709ba0fdf94ea37a84d822310fd84`.
- Python ML-DSA-44 binding: `pqcrypto==0.4.0` as pinned in
  `python/requirements.txt`.

The local PQClean FIPS-202 context representation was changed from dynamic
allocation to an embedded fixed-size state for heap-free firmware use. The
cryptographic permutation and ML-DSA-44 algorithm code are otherwise the
vendored clean implementation.
