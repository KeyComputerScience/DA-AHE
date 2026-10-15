# Parameters, explicit completion choices

The table distinguishes the manuscript's historical parameters from the current
independent implementation. The default is now **k=6, n=m=1536**, with 7,168-byte
ciphertexts. The pinned seven-attack run reports a minimum of **136.475 bits**
under its stated generic flattened-LWE heuristic model. The legacy k=3 tuple
remains available explicitly and does not meet the requested 128.1-bit floor.
See `configs/security_profile.json`, `security/README.md` and
`security/DECODING_BOUND.md`. Old wire, timing, energy and workspace figures
cannot be inherited by the new parameters.

| Item | Manuscript | Artifact treatment |
|---|---|---|
| Ring | d=256, k=3, n=768, q=2^32, p=65537, lambda_tag=16 (p.3) | current k=6/n=1536, same d/q/p/tag; delta=65535; uint32 little-endian u0..u5,v; legacy k=3 is explicit |
| Secret / public-key error | discrete Gaussian sigma_key=3.2 (pp.3,12) | finite reference CDT; statistical and implementation differences explicitly documented |
| Online noise | sigma_enc=3.2/3.4/3.6 (pp.3-4) | profile-bound; never represented as ordered security levels |
| Capacities | 16/14/12 (p.4) | independently bounded for the current finite CDT and k=6; original certificates remain unavailable; see DECODING_BOUND.md for probability scope |
| Signal windows | two channels of 240 readings (p.8) | input integer physical units, common scale required |
| Table III | (L,step)=(240,8),(180,12),(120,16) (p.13) | pi0/pi1/pi2 examples follow Table III |
| Static ablation | [1.0,16,16,64,0,0] (Eq.22, p.11) | separate `static_eq22` profile; not silently equated with Table III pi0 step8 |
| Fallback | [0.50,16,1,64,0,0] (pp.3,9) | separate reference profile; joint support/certificate unspecified |
| Supports | deterministic S subset of 0..479, L<=240 | original positions absent; reference L=120/180/240 retain both channels' full-window coarsest coefficients before level-2 details; signed full digest binds them |
| IntDb2 | integer Db2, no exact lifting definition | two-level rational integer lifting with periodic edges, [a2(60),d2(60),d1(120)] per channel; see signal.py; not author-byte-compatible |
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

The former one-level approximation-prefix support discarded the tail of the
sampling window for L<240. The reference now uses two levels so all three bundled
profiles retain all 120 coarsest positions across both channels. This fixes that
coverage defect; it does not establish the original paper's distortion values or
a universally optimal support. `tests/test_signal_quality.py` supplies synthetic
full-window impulse, constant, trend and exact inversion regressions.
`Profile.transform_id` is included in the full profile digest. The current ID is
`reference-intdb2-two-level-periodic-unnormalized-q30-v2`; explicit old transform
versions are rejected. The raw profile has its own quantization-version ID. These
fields change profile IDs/digests, so old tickets, allowlists, action models and
certificates must be regenerated and reviewed.

Protected sources must supply a durable `SourceEmissionStore` to `encapsulate`.
It binds the exact raw payload before encryption and caches the original signed
envelope before releasing bytes. Retries return that same envelope; resampling
requires a new ticket. Reusing a ticket/source offset for two different encrypted
reports would let a compromised gateway form the affine forgery `2*c1-c2`.
Retransmission must reuse the original `SignedTicket`, including its signature.
Re-signing an unchanged ticket body may change the ML-DSA signature, but leaves
the ticket digest/ledger identity unchanged: the source returns the original
cached envelope, and aggregation against the newly generated signature rejects
the mismatch. A fresh authorization must include a fresh signed batch nonce.
Source databases therefore require the same rollback/deletion protection as keys
and epoch state. The SQLite host implementation is not a board flash driver.
Sink Seen is still an at-most-once acceptance set: durable result/outbox storage
and an idempotent consumer remain necessary to recover a result after a crash
between Seen commit and application delivery.
