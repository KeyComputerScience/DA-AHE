<!-- SPDX-License-Identifier: MIT -->
# Claim-to-code-to-evidence traceability

**Historical manuscript mapping.** Actual new execution status is recorded in
the historical `evidence/independent/STATUS.json` snapshot; current public archive
locations are in `evidence/independent/publication.json` and
[`PUBLIC_EVIDENCE.md`](PUBLIC_EVIDENCE.md). “Implemented” describes source
availability; execution receipts are separate. “Target” means transcribed from
the manuscript, not independently measured. Module filenames below refer to
the canonical `src/daahe/` directory unless another directory is specified.

The current independent default uses k=6/n=1536: its seven-attack heuristic
minimum is 136.475 bits and its ciphertext is 7,168 bytes. The separate finite-CDT
decoding proof is in `security/DECODING_BOUND.md`. These results do not validate
the historical k=3 experiment or its timing, energy and memory figures.

| Paper item / source | Source implementation |
|---|---|
| Eq. (3), safety action set, pp. 2–3 | `safety.py`, `profiles.py` |
| Historical M-LWE tuple `(k,d,n,q,p,lambda_tag)=(3,256,768,2^32,65537,16)`, pp. 3–4 | `ring.py`, `mlwe.py`; explicit legacy tuple, current default k=6/n=1536 |
| Eq. (7), additive aggregate decryption | `mlwe.py`, `protocol.py`; authored `test_crypto_protocol.py` |
| Algorithms 1–3, signed authorization, p. 4–5 | `protocol.py`, `signatures.py`, `derivation.py` |
| End-to-end aggregate integrity, Eq. (13), pp. 6–7 | `derivation.py`, `protocol.py` |
| Replay protection, `Seen`, p. 7 | `protocol.ReplayStore` |
| 96-bit `ProfileID`, p. 6 | `profiles.py`, `protocol.py` |
| Single polynomial, Eq. (16), p. 8 | `protocol.pack_values`, `profiles.Profile.polynomial_count` |
| Integer Db2 pipeline and fidelity, pp. 3, 13 | `signal.py` |
| Controlled HMM, Eq. (15), Algorithms 4–6, pp. 5–9 | `control.py`, `calibration.py` |
| Robust fallback and conditional stability theorem, p. 8 | `control.fallback_bound`, `RobustController.select` |
| Historical security estimate `lambda_est=128.1`, Eq. (24), p. 12 | `tools/estimate_security.sage` diagnoses legacy k=3; current k=6 estimate uses `tools/estimate_security_parameters.py` and `configs/security_profile.json` |
| 10-KiB streaming workspace, pp. 4,8 | `embedded/` source hooks and safety certificate field |
| nRF52840 time/energy and Table II memory, pp. 8,13 | External measurement interface; `experiments/paper_targets.json` |
| 20 independent paired seeds, 300-s run, 30-s warm-up, p. 9 | `experiments/matrix.json`, `configurations.csv`, `statistics.py` |
| Recovery criterion, p. 9 | `tools/import_omnet.py`, `statistics.py` |
| Fig. 5 paired normalized means/CIs, p. 11 | `statistics.paired_bootstrap`, `statistics.summarize` |
| Fig. 6 ablation results, pp. 11–12 | `experiments/matrix.json`, protocol raw/two-ciphertext and no-HVE variants, controller repair/static variants |
| 0.098% loss at 5,000 nodes and 0.074%/33.0 s reference | `experiments/paper_targets.json` only |
| Figs. 2–4 comparisons with SLAP/PQC-DL/B-HE | Target/reference documentation only |

## Supported advantages and the evidence needed to demonstrate them

1. **Payload structure:** one protected packed plaintext versus two raw plaintexts gives an inspectable 14,336→7,168-byte reduction at the current k=6 tuple (8,192→4,096 for the historical k=3 tuple). Tickets, headers and authentication metadata are additional wire costs.
2. **Trust separation:** block HMACs filter external pollution while the signed roster and hidden aggregate tag address the compromised-gateway setting under the paper's trusted-source/sink assumptions.
3. **Safety before optimization:** admission gates are designed to reject actions that fail bound checks before objective optimization. Their guarantees require valid reviewed certificates; hashing a supplied artifact establishes byte identity, not proof validity. The shipped synthetic fixture is uncertified.
4. **Reviewer-verifiable analysis:** the package keeps source hashes, paired-seed provenance, raw values, ratio estimands, censoring and missing evidence explicit.

The current attack estimates and finite-CDT single-batch decoding bound have
executed evidence under their stated assumptions. Numerical superiority,
original-paper security calibration, reconstruction PRD, complete embedded
workspace bounds and exact OMNeT++ reproduction remain unestablished.
The independent campaign's recovery records are all right-censored and its
route-repair ablation did not trigger repair. See
[`MANUSCRIPT_CORRECTIONS.md`](MANUSCRIPT_CORRECTIONS.md) for paper claims that
must be corrected or withheld pending matching evidence.
