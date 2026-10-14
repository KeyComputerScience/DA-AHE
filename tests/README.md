<!-- SPDX-License-Identifier: MIT -->
# Test status

**All tests are authored and unexecuted.** No pass count, coverage percentage, timing or numerical experiment result is claimed.

The suite checks independent algebraic expectations and rejection conditions: negacyclic sign reduction; 240+16 versus 480+16 packing; additive encryption; exact 4,096-byte transport; reversible illustrative lifting; signed roster/profile binding; missing/duplicate/reassigned contributions; a compromised gateway that can recompute transport HMACs; persistent replay suppression; an ambiguity LP compared with independent rational-simplex enumeration; interior fallback extrema; safety/no-wrap/security gates; seed disjointness; paired bootstrap estimands; censored recovery; warm-up exclusion; provenance hashes and traversal rejection.

Cryptographic protocol tests inject a clearly named `TestOnlySigner` so message binding can be tested without silently substituting a signature provider at runtime. This fixture is never a claim about ML-DSA security. MLWE fixtures inject deterministic `random.Random` only in tests. Production randomness and native ML-DSA have separate deployment requirements. Neither an algebraic test nor a seed sample can establish a `2^-128` decryption bound.

When the reviewer chooses to execute, install the declared test dependencies and run `python -m pytest`. The optional real ML-DSA provider test is skipped by default; execute it explicitly with `python -m pytest -m pq` after installing the documented native prerequisites. Missing prerequisites then fail explicitly, without automatic downloads. Keep the actual environment and machine-generated output as evidence. A future pass would validate these source invariants in that environment; it would not reproduce the paper's unpublished board firmware, OMNeT++ source, calibration, or experimental traces.
