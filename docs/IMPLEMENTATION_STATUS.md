# Implementation and validation status

The reference uses k=6, d=256, n=m=1536 and 7,168-byte ciphertexts.
Execution receipts, public source identities and raw results are indexed in
`evidence/independent/publication.json` and [PUBLIC_EVIDENCE.md](PUBLIC_EVIDENCE.md).
The current method and complete tables are [EVALUATION.md](EVALUATION.md) and
[CURRENT_RESULTS.md](../experiments/CURRENT_RESULTS.md).

| Component | Implementation and evidence scope |
|---|---|
| M-LWE packing, tickets, block MACs, aggregate tags and durable emission | Host implementation, functional tests and real ML-DSA trials |
| Signal transform and profiles | Explicit two-level integer transform; 72 synthetic aggregate-domain cases with complete recomputation |
| Robust control, DPP/HYS | Executable decision rules, functional and analytic checks; [calibration and declared-model verification](CONTROLLER_CALIBRATION.md) use separate run records |
| Network simulator | Two-hop Python packet/block service model, 20 paired seeds, seven methods and all 140 records |
| Embedded core | Standalone ARM build, ELF/map, compiler stack-usage and native known-answer records; device acquisition has separate collector/verifier tools and capture identities |
| Security estimate | Seven-attack minimum 136.475 bits under the recorded generic flattened-LWE models |
| Decoding | Exact finite-CDT outward interval analysis, including carry and a finite 42-choice one-batch union |
| Finite task budgeting | Exact rational union bounds; predeclared attempt cap, not successful deliveries |
| Whole-protocol embedded costs and controller invariance | Require dedicated measurement and certificate evidence |

The archived campaign uses declared processing/radio assumptions and records
uncertified controller decisions. Later calibration runs retain separate source,
input and model identities; they do not relabel that campaign. All archived
recovery observations are right-censored and route repair is not activated.
All seven methods and these outcomes remain in the tables.
Source integrity, raw-metric recomputation, frozen-source replay, security
estimation and physical measurement are distinct verification activities.
