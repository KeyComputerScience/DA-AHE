# Security scope and reporting

The manuscript assumes honest uncompromised sources and sink. A compromised
gateway may know block and transport HMAC keys, so neither HMAC proves end-to-end
integrity against that gateway. The intended end-to-end relation uses a valid
sink-signed exact roster, hidden batch matrix/offsets and durable replay state.
Source compromise, source/gateway collusion, epoch-root leakage, availability,
and Python side-channel resistance are outside this reference implementation's
claims. Provisioning an epoch root to a gateway destroys the hidden-tag boundary.

ML-DSA-44 is provided by an explicitly installed local OQS dependency. There is
no alternative signature used when it is unavailable. The M-LWE encryption code
is a research additive CPA-style primitive, not standardized ML-KEM, an AEAD
scheme, or a production-vetted cryptosystem. Do not expose raw decryption as a
network service. Only the protected sink gate may release a verified aggregate.

The aggregate authentication model assumes classical submissions and a uniform
rejection interface, independent domain-separated derivations, hidden matrix and
uncompromised endpoints. This package implements checks; it does not independently
prove the manuscript theorem. It does not offer a coherent quantum verification
oracle or claim that tests measure a 2^-256 forgery probability.

The reference's finite 256-bit CDT Gaussian sampler, seeded-matrix encoding,
canonical wire format and lifting transform are reconstruction choices. No
128.1-bit cryptographic security, <=2^-128 failure probability, 10-KiB workspace,
or conditional stability certificate has been verified in this delivery.

For an implementation issue, preserve a minimal test case and describe the
affected assumptions in a private channel chosen by the repository owner. No
maintainer contact or response deadline was supplied, so none is invented here.
Do not attach live keys, raw confidential telemetry, or operational credentials.

