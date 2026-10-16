# Implementation and validation status

This checkout adds an independent experiment and measurement workflow to the
host reference. Actual execution status, commands, outputs and limitations are
recorded in the historical `evidence/independent/STATUS.json` snapshot and the
corresponding execution receipts. Current public archive locations are recorded
separately in `evidence/independent/publication.json` and
[`PUBLIC_EVIDENCE.md`](PUBLIC_EVIDENCE.md). Source availability alone is never
listed as a passed experiment.

The current independent default is k=6, d=256, n=m=1536, with 7,168-byte
ciphertexts. The legacy k=3 manuscript tuple is retained explicitly; its old
security, timing, energy and memory claims cannot be transferred to k=6.

| Component | Implementation and evidence boundary |
|---|---|
| Parameterized M-LWE, packing, tickets, HMAC, aggregate tags and replay | Current k=6 host reference plus explicit legacy k=3; functional tests and real ML-DSA fresh-key trials |
| Signal transform and profiles | Explicit independent completion; synthetic reconstruction only |
| Robust control, DPP/HYS and statistics | Existing equations; analytic/functional tests; new synthetic closed-loop experiment |
| Independent network simulator | Python packet/fragment event model; new paired seeds and raw logs; not INET/RPL or original data |
| Core nRF52840 measurement firmware | New standalone build; ELF/map and host known answers; physical capture pending |
| Security estimator | Selected k=6 seven-attack minimum 136.475 bits under the declared generic flattened-LWE heuristic; legacy k=3 does not meet 128.1 bits |
| Decoding reliability | Executed exact finite-CDT interval bound; 42-choice one-fresh-batch union log2 upper bound -130.5101732; not a guarantee for every fixed key or arbitrary history |
| No-wrap | Exact reference-profile integer arithmetic logged; other proof/resource gates remain separate |
| Whole-protocol embedded cost, energy and worst-case memory | Not established by a core microbenchmark |
| Original manuscript figures and Table III | Historical targets; no claim of exact numerical reproduction |

The archived independent campaign comprises 20 seeds and 140 runs with a
synthetic, uncalibrated controller. All recovery records are right-censored;
the route-repair ablation did not trigger repair. These runs do not demonstrate
the manuscript's low-loss figures, measured recovery times, overall superiority
or conditional stability certificate. Physical-board samples remain zero.

See [`MANUSCRIPT_CORRECTIONS.md`](MANUSCRIPT_CORRECTIONS.md) for the associated
paper edits. Historical execution receipts and evidence bytes are preserved.

The current source manifest and the independent evidence bundle have separate
scopes. The old v0.2.0 source manifest is preserved as an archive under
`docs/archive/`; it must not be used to validate the changed checkout.
