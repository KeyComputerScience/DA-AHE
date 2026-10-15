# Implementation and validation status

This checkout adds an independent experiment and measurement workflow to the
host reference. Actual execution status, commands, outputs and limitations are
recorded in `evidence/independent/STATUS.json` and the corresponding execution
receipts. Source availability alone is never listed as a passed experiment.

| Component | Implementation and evidence boundary |
|---|---|
| Fixed-tuple M-LWE, packing, tickets, HMAC, aggregate tags and replay | Host reference; functional tests and real ML-DSA fresh-key trials |
| Signal transform and profiles | Explicit independent completion; synthetic reconstruction only |
| Robust control, DPP/HYS and statistics | Existing equations; analytic/functional tests; new synthetic closed-loop experiment |
| Independent network simulator | Python packet/fragment event model; new paired seeds and raw logs; not INET/RPL or original data |
| Core nRF52840 measurement firmware | New standalone build; ELF/map and host known answers; physical capture pending |
| Security estimator | Pinned upstream actual per-attack logs; inspect computed costs rather than the paper target |
| No-wrap | Exact reference-profile integer arithmetic logged; other proof/resource gates remain separate |
| Whole-protocol embedded cost, energy and worst-case memory | Not established by a core microbenchmark |
| Original manuscript figures and Table III | Historical targets; no claim of exact numerical reproduction |

The current source manifest and the independent evidence bundle have separate
scopes. The old v0.2.0 source manifest is preserved as an archive under
`docs/archive/`; it must not be used to validate the changed checkout.
