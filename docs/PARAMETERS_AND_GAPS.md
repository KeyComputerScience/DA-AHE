# Parameters and implementation definitions

| Item | Definition |
|---|---|
| Ring and tuple | k=6, d=256, n=1536, q=2^32, p=65537, lambda_tag=16 |
| Estimator sample input | m=1536 in the generic flattened-LWE model |
| Encoding | delta=65535, q=p*delta+1; uint32 little-endian u0..u5,v; 7,168 bytes |
| Key noise | sigma_key=3.2; finite, 256-bit-quantized reference CDT |
| Encryption noise and capacity | (3.2,16), (3.4,14), (3.6,12); sigma_enc is not an ordered security level |
| Signals | Two synchronized 240-sample integer channels with declared units and scaling |
| Profile examples | (L,step)=(240,8),(180,12),(120,16) |
| Support | Fixed ordered subset of 0..479; both channels' coarsest coefficients are retained |
| Transform | Two-level rational integer lifting with periodic edges; [a2(60),d2(60),d1(120)] per channel |
| Quantization | Nearest integer, ties away from zero; out-of-range coefficients are rejected |
| Data no-wrap | N*Bx<=32768; authentication coefficients remain field residues |
| Action | Indivisible row binding sampling, step, batch cap, block size, repair and full profile digest |
| Fallback | Its complete row and immutable profile are configured together; its name does not certify feasibility |
| Ticket | Versioned canonical JSON binds epoch, batch, context, full profile digest, canonical roster, nonce, block size and encryption tuple |
| Key identity | Provisioning binds context/epoch to the intended public key and policy |
| Integrity | ML-DSA-44 authorization, HMAC-SHA3-256 transport checks and 16 hidden field tags |
| Model scope | Declared reference coefficients do not establish uniform bounds or invariant-domain certificates; [calibration and model-relative checks](CONTROLLER_CALIBRATION.md) retain their own assumptions and reports |

The transform identifier is
`reference-intdb2-two-level-periodic-unnormalized-q30-v2` and is part of the full
profile digest. Rounded integer lifting is reversible per source but is not
additive across sources. Aggregate error is evaluated separately from encoded
coefficient correctness; [the fidelity evidence](AGGREGATE_FIDELITY.md) defines
its attribution and zero-reference handling.

The scaling carry q-p*delta=1 is included in the finite-CDT decoding bound.
The no-wrap condition concerns data coefficients; random authentication tags
are intentionally added modulo p. See [DECODING_RISK_BUDGET.md](DECODING_RISK_BUDGET.md)
for the one-batch probability model and finite-task attempt budget.

Protected encapsulation requires a durable SourceEmissionStore. It atomically
binds the raw input before encryption and caches the exact signed envelope
before releasing it. Repeated calls return the cached envelope; different raw
inputs are rejected. Retransmission uses the original SignedTicket and its
signature. Fresh authorization includes a fresh signed batch nonce.
Ledger rollback/deletion protection is a deployment requirement.

Sink Seen provides at-most-once acceptance. A durable result/outbox and an
idempotent consumer are separate requirements for recovering delivery after a
crash between Seen commit and application receipt. The Python ledger is not a
board flash driver, and host block iteration does not prove a 10-KiB firmware
workspace. See [the protocol source](../src/daahe/protocol.py).
