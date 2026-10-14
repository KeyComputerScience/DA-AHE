# Security scope and reporting

## 1. Security Architecture and Trust Model

DA-AHE establishes a structured security architecture for post-quantum secure aggregation in cyber-physical systems. The framework integrates authenticated source reporting, sink-authorized participant rosters, confidential batch authentication parameters, and persistent replay protection.

The security model assumes trusted source devices and a trusted sink while supporting aggregation through potentially compromised intermediate gateways. Block-level and transport-level HMAC mechanisms provide efficient traffic authentication and early filtering. End-to-end aggregate integrity is established through sink-signed exact-roster authorization, confidential batch authentication matrices, source-specific offsets, and persistent replay-state management.

Domain-separated key derivation establishes independent cryptographic contexts for authentication and aggregation. Epoch-root secrets and batch authentication parameters remain within the trusted source–sink security domain, maintaining the confidentiality of the end-to-end verification mechanism.

The resulting architecture defines a precise trust boundary for authenticated aggregation. Endpoint protection, root-key management, physical security, availability, and side-channel protection are treated as complementary deployment security responsibilities.

## 2. Source Emission Consistency and Replay Protection

DA-AHE incorporates `SourceEmissionStore` to maintain deterministic and consistent source reporting throughout each authorized aggregation batch.

Each unique combination of ticket, source identity, and nonce is associated with one immutable sampling window and its corresponding authenticated ciphertext envelope. The source securely retains the original envelope and reuses it for retransmission requests.

This mechanism preserves the uniqueness of source authentication offsets and maintains the integrity of affine authentication relationships across repeated network transmissions.

Device-level persistent storage, access control, and anti-rollback protection support the continuity of source-emission records across execution cycles and device restarts. The reference implementation uses SQLite to demonstrate persistent emission management and provides a foundation for integration with embedded nonvolatile storage.

Together with sink-side persistent `Seen` records, source-emission consistency strengthens protection against ciphertext recombination, replay, and unauthorized aggregate modification.

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

Under the specified security assumptions, the linear-authentication construction yields the classical per-attempt forgery bound

\[
P_{\mathrm{forge}}\leq p^{-\lambda}.
\]

For \(p=65537\) and \(\lambda=16\),

\[
p^{-16}<2^{-256}.
\]

This expression characterizes the theoretical authentication bound under the stated assumptions. The implementation provides the corresponding cryptographic processing and verification procedures, while the manuscript supplies the associated security arguments.

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

The broader DA-AHE research framework further defines four quantitative evaluation targets:

| Evaluation dimension | Specification |
|---|---|
| Post-quantum security estimation | 128.1-bit estimated computational security |
| Aggregate decryption reliability | \(\epsilon_{\mathrm{dec}}\leq 2^{-128}\) |
| Action-dependent streaming workspace | 10 KiB |
| Closed-loop stability | Conditional exponential mean-square ultimate boundedness |

These specifications belong to the manuscript's cryptographic parameter analysis, resource certification, and stochastic stability framework. Their quantitative assessment relies on the corresponding estimator configurations, hardware measurements, and certified control-model assumptions, complementing the reference software's functional implementation.

## 6. Security Issue Reporting and Responsible Disclosure

DA-AHE supports responsible security research through reproducible issue documentation and clearly defined security assumptions.

Implementation reports should include a minimal reproducible example, the affected component, relevant operating conditions, and the associated security assumptions. Security-sensitive reports are directed through a private communication channel designated by the repository owner.

Reports should use sanitized test data and synthetic credentials to protect operational secrets, confidential telemetry, and deployment environments.

This process supports systematic issue analysis, reproducible investigation, and continuous improvement of the DA-AHE implementation.
