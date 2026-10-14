# Parameters, explicit completion choices, unresolved manuscript details

Manuscript anchors use printed page numbers in the supplied 14-page PDF.

| Item | Manuscript | Artifact treatment |
|---|---|---|
| Ring | d=256, k=3, n=768, q=2^32, p=65537, lambda_tag=16 (p.3) | fixed; delta=floor(q/p)=65535; uint32 little-endian u0,u1,u2,v |
| Secret / public-key error | discrete Gaussian sigma_key=3.2 (pp.3,12) | finite reference CDT; statistical and implementation differences explicitly documented |
| Online noise | sigma_enc=3.2/3.4/3.6 (pp.3-4) | profile-bound; never represented as ordered security levels |
| Capacities | 16/14/12 (p.4) | reference limits only; no original certificate provided |
| Signal windows | two channels of 240 readings (p.8) | input integer physical units, common scale required |
| Table III | (L,step)=(240,8),(180,12),(120,16) (p.13) | pi0/pi1/pi2 examples follow Table III |
| Static ablation | [1.0,16,16,64,0,0] (Eq.22, p.11) | separate `static_eq22` profile; not silently equated with Table III pi0 step8 |
| Fallback | [0.50,16,1,64,0,0] (pp.3,9) | separate reference profile; joint support/certificate unspecified |
| Supports | deterministic S subset of 0..479, L<=240 | original positions absent; example supports are a documented completion, signed full digest binds them |
| IntDb2 | integer Db2, no exact lifting definition | one-level rational integer lifting with periodic edges; see signal.py; not author-byte-compatible |
| Quantization bound Bx | inequality N*Bx<=32768 | example Bx2048 is a reconstruction choice, not author calibration; out-of-range input is rejected |
| Ticket | Eq.9 vs earlier notation uses ctx/CID and batch nonce | explicit versioned canonical JSON binds epoch,batch,context,full profile digest,roster,nonce,block length |
| Key identity | CID/epoch pk context | integrator must bind context to provisioned public key fingerprint and calibration/action digest |
| ProfileID | local 96-bit index | full 256-bit profile digest also bound; no dynamic remote definitions accepted |
| Verification | ticket ML-DSA-44, HMAC-SHA3-256, tags16 | official OQS provider; independent keys; no classical signature fallback |
| Belief/stability | Eq.15, gamma.10 beta.02 | code accepts explicit model and certificate; synthetic values are not certified |
| P_V, zmax, delay/loss thresholds | not fully specified | required config inputs, example values synthetic |
| Original estimator | commit53da5982597709ba0fdf94ea37a84d822310fd84, GSA, ADPS16 quantum | source-pinned tool; original Sage environment and stdout absent |
| Bootstrap | 20 paired seeds, B100000, percentile95% | seed IDs absent; example IDs marked reconstructed; pair checked by seed and trace hash |
| Network | OMNeT++6.0/INET4.4, RPL MRHOF,20-entry queues | external original model required; no surrogate output labeled INET |

Two arithmetic distinctions matter. The no-wrap bound applies to **data**
coefficients so a signed sum can be recovered; random authentication coefficients
are intentionally summed in F_p. Since q is not a multiple of p, decoding must
also account for scaling carry (`q - p*delta = 1`) in a genuine noise certificate.
For N<=16 centered lifts, the correction is at most 8 in absolute value: if
sum Lift(m_i)=Lift(sum m_i mod p)+h*p, the effective error is e_agg-h.
The implementation's arithmetic alone does not establish batch failure <=2^-128.

Rounded integer lifting is invertible for one full unquantized signal but is not
strictly linear under summation. Therefore inverse transforming an aggregate may
differ from the sum of individually reconstructed signals even with full support.
Report aggregate RMSE/PRD on the actual telemetry; do not transfer Table III values
to this reconstructed transform. Original authors should resolve their exact
transform and aggregation-fidelity definition before claiming a faithful match.

Additional missing experiment details include path-loss exponent, shadowing
variance, fading coherence, node placement and RPL module source, exact noise
certification derivation, controller error bounds and admissible-transition masks,
Pareto pruning inputs, lightweight packet encoding and sensitivity classifier,
wire/header accounting, initialization, trace labels, simulation seed mapping,
all baseline implementations and their measured service costs. These affect
reproduction and must be recorded, not guessed as published facts.

