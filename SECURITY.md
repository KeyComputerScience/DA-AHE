# Security scope and reporting

This is an independent research reference, not a certified deployment. The
current default is k=6, d=256, n=m=1536 with 7,168-byte ciphertexts.
The selected seven-attack minimum of 136.475 bits is a generic flattened-LWE
heuristic estimate, not a proof for the actual finite sampler, module structure,
implementation or all attacks. See `configs/security_profile.json`,
`security/README.md`, `security/DECODING_BOUND.md` and
[the protocol specification](docs/manuscript/PARAMETER_PROTOCOL.tex).

## 1. Security Architecture and Trust Model

DA-AHE establishes a structured security architecture for post-quantum secure aggregation in cyber-physical systems. The framework integrates authenticated source reporting, sink-authorized participant rosters, confidential batch authentication parameters, and persistent replay protection.

The security model assumes trusted, uncompromised source devices and a trusted sink while supporting aggregation through potentially compromised intermediate gateways. Source compromise, source-gateway collusion, endpoint-secret leakage and availability are outside the claimed model. Block-level and transport-level HMAC mechanisms provide early filtering only while the holder of the corresponding key remains trusted; a gateway-held HMAC does not protect against that gateway. End-to-end aggregate integrity relies on sink-signed exact-roster authorization, confidential batch authentication matrices, source-specific offsets, and persistent replay-state management under the manuscript's assumptions. Confidentiality applies to the protected encrypted path; the authenticated plaintext lightweight path does not provide it.

Domain-separated key derivation establishes independent cryptographic contexts for authentication and aggregation. Epoch-root secrets and batch authentication parameters remain within the trusted source–sink security domain, maintaining the confidentiality of the end-to-end verification mechanism.

The resulting architecture defines a precise trust boundary for authenticated aggregation. Endpoint protection, root-key management, physical security, availability, and side-channel protection are treated as complementary deployment security responsibilities.

## 2. Source Emission Consistency and Replay Protection

DA-AHE incorporates `SourceEmissionStore` to maintain deterministic and consistent source reporting throughout each authorized aggregation batch.

Each unique combination of ticket, source identity, and nonce is associated with one immutable sampling window and its corresponding authenticated ciphertext envelope. The source securely retains the original envelope and reuses it for retransmission requests.

This mechanism preserves the uniqueness of source authentication offsets and maintains the integrity of affine authentication relationships across repeated network transmissions.

Device-level persistent storage, access control, and anti-rollback protection are required to preserve source-emission records across execution cycles and device restarts. The reference implementation uses SQLite; it does not implement a board flash driver or anti-rollback storage. Deleting or rolling back the source ledger can permit two reports under one ticket/source offset and invalidate the integrity argument.

Together with sink-side persistent `Seen` records, source-emission consistency addresses ciphertext recombination, replay, and unauthorized aggregate modification under those assumptions. `Seen` enforces at-most-once acceptance; durable result/outbox storage and an idempotent consumer are still needed for crash recovery after acceptance but before result delivery.

## 3. Post-Quantum Cryptographic Implementation

DA-AHE integrates ML-DSA-44 for post-quantum digital signatures through an explicitly installed local Open Quantum Safe (OQS) dependency. This provides a consistent signature mechanism for batch-ticket authorization and verification.

The encryption layer implements a research-oriented, additively homomorphic Module-LWE construction supporting encrypted aggregation over a shared polynomial representation. Its CPA-style design enables ciphertext combination while preserving the mathematical structure required for aggregate recovery.

This specialized construction is designed for homomorphic aggregation, with a functional role distinct from standardized ML-KEM key encapsulation and conventional authenticated encryption.

Cryptographic operations follow a structured processing pipeline comprising canonical message encoding, authenticated ticket validation, ciphertext aggregation, protected decryption, and end-to-end aggregate verification.

The protected sink verification gateway controls the release of authenticated aggregate results, ensuring that plaintext recovery is integrated with the prescribed authorization and integrity checks.

## 4. Aggregate Authentication and Security Analysis

The aggregate authentication mechanism combines post-quantum signatures, domain-separated pseudorandom derivation, Module-LWE confidentiality, and hidden linear authentication.

Its security analysis considers classical aggregate submissions, a uniform verification-response interface, independently derived secret authentication parameters, and trusted source–sink endpoints.

For a batch authentication matrix

\[
K_B\in\mathbb{F}_p^{\lambda\times L},
\]

each source computes its authentication vector as

\[
t_i=(K_Bx_i+\xi_i)\bmod p.
\]

The sink verifies the corresponding aggregate relationship:

\[
t_{\mathrm{agg}}
=
K_Bx_{\mathrm{agg}}
+
\sum_{i\in I_B^\star}\xi_i
\pmod p.
\]

In the manuscript's idealized hidden-key authentication model, the classical
single-attempt tag-guessing term is

\[
P_{\mathrm{forge}}\leq p^{-\lambda}.
\]

For \(p=65537\) and \(\lambda=16\),

\[
p^{-16}<2^{-256}.
\]

This expression is a tag-guessing term, not the complete system failure
probability. At most Q_v classical verification submissions contribute
Q_v/p^lambda in addition to the primitive-security terms and assumptions in the
manuscript's reduction. Functional rejection tests do not prove that reduction
or cover compromised sources, leaked endpoint secrets, side channels or
denial of service.

The adversarial model considers classical submission interfaces and quantum-capable computation against the cryptographic primitives. The security analysis also distinguishes this interface from the stronger hypothetical model of coherent quantum verification queries.

## 5. Reference Implementation and Reproducibility

The DA-AHE reference implementation provides a reproducible foundation for investigating secure aggregation, post-quantum encryption, authenticated communication, and adaptive network control.

Its implementation includes:

- A finite 256-bit cumulative distribution table (CDT) Gaussian sampler.
- Deterministic seeded-matrix generation and encoding.
- Canonical ciphertext and message serialization.
- Integer lifting transforms and profile-bound coefficient processing.
- Single-polynomial data and authentication-vector packing.
- ML-DSA-44-based signed batch authorization.
- Persistent source-emission and sink replay-state management.
- End-to-end aggregate authentication and controlled result release.

The reference package documents these concrete implementation choices to support consistent reconstruction and reproducible functional evaluation.

The manuscript's four quantitative targets must be distinguished from the
current independent evidence:

| Evaluation dimension | Current independent evidence |
|---|---|
| Post-quantum security estimation | k=6 seven-attack minimum 136.475 bits under the stated heuristic model; the required threshold is 128.1 bits |
| Aggregate decryption reliability | Executed actual-CDT interval calculation: 42-choice one-fresh-batch union log2 upper bound -130.5101732; joint random-key/fresh-noise probability, not every fixed key, arbitrary observed history or lifetime |
| Action-dependent streaming workspace | Manuscript target 10 KiB; complete k=6 role-specific workspace certificate and measured stack high-water remain unavailable |
| Closed-loop stability | The separate 35-case calibration supplies fitted models and exact checks; original domain, fallback and transition conditions fail, as recorded in the certificate report |

Available firmware evidence comprises core compilation, host known answers,
device collection interfaces and capture-verification rules. Its scope is
distinct from measured per-role timing, energy and complete-protocol memory.
The [controller verification](docs/CONTROLLER_CALIBRATION.md) records its inputs,
exact arithmetic and condition outcomes. Historical receipts retain their byte
identities; current public archive
locations are in `evidence/independent/publication.json` and
[`docs/PUBLIC_EVIDENCE.md`](docs/PUBLIC_EVIDENCE.md).

## 6. Security Issue Reporting and Responsible Disclosure

DA-AHE supports responsible security research through reproducible issue documentation and clearly defined security assumptions.

Implementation reports should include a minimal reproducible example, the affected component, relevant operating conditions, and the associated security assumptions. For security-sensitive reports, establish a private channel with the repository owner before sending sensitive details; this file does not designate a reporting address.

Reports should use sanitized test data and synthetic credentials to protect operational secrets, confidential telemetry, and deployment environments.

This process supports systematic issue analysis, reproducible investigation, and continuous improvement of the DA-AHE implementation.
