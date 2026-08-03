# DA-AHE research reference

This project implements the revised paper construction as an executable,
deterministic research prototype:

- one Module-LWE ciphertext over `R_q = Z_q[X]/(X^256 + 1)`;
- `q = 2^32`, `p = 65537`, `k = 3`, and eight linear authentication values;
- one-level periodized Db2 transform with 248 retained data coefficients;
- sink-signed batch tickets, per-block HMACs, and a fixed batch roster;
- block-aligned gateway aggregation without a second ciphertext buffer;
- decryption-failure, wrap, network, and RAM certification calculations;
- five-state bounded-Softmax control and the weak-ergodicity bound.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
python -m da_ahe.demo
```

The demo prints a JSON report containing the ciphertext size, aggregate
verification result, reconstruction error, certified profile values, and one
controller decision.

## Paper-to-code mapping

| Paper element | Module |
|---|---|
| M-LWE key generation, encryption, addition, and decryption | `da_ahe/mlwe.py` |
| Db2 transform, retention, quantization, and reconstruction | `da_ahe/codec.py` |
| Eight field-linear authentication equations | `da_ahe/auth.py` |
| Batch ticket and block HMAC format | `da_ahe/transport.py` |
| Sensor, streaming gateway, and sink protocol | `da_ahe/protocol.py` |
| `K_0`, `t_safe`, failure bound, and `N_max` constraints | `da_ahe/certification.py` |
| Bounded-Softmax DTMC and predictive action selection | `da_ahe/controller.py` |

## Security and implementation boundary

This is research code, not a production cryptographic library.

- The Gaussian sampler is deterministic and simulation-oriented. A deployment
  must use a constant-time, cryptographically secure discrete-Gaussian sampler.
- NumPy polynomial arithmetic is not constant-time.
- Ed25519 is used only as a readily executable batch-ticket signature adapter.
  A fully post-quantum deployment must replace it with ML-DSA, SLH-DSA, or an
  authenticated pre-provisioned ticket mechanism.
- The Db2 implementation is a deterministic floating-point reference. The
  nRF52840 port must replace it with the paper's fixed-point lifting routine and
  certify the resulting coefficient bound.
- The supplied effective-goodput and stack-memory values are simulation
  assumptions. Paper tables must use measured `R_min` and linker/runtime RAM
  watermarks from the actual Contiki-NG build.
- The included `128.1` estimator value is metadata matching the manuscript. It
  is not recomputed by this project; publish it only with the exact estimator
  script, commit, distributions, and cost models.
- The linear-authentication seeds are shared by authorized sensors and the
  sink. Compromise of an authorized sensor is outside this construction's
  threat model and requires a per-source homomorphic signature or secure
  element in a stronger deployment model.

## Transport behavior

A ciphertext contains 1,024 aligned 32-bit words, or 4,096 bytes. With a
64-byte block payload, each node sends 64 authenticated blocks. The gateway
authenticates a block before adding its 16 words to the fixed aggregate
positions. Any invalid, duplicate, or missing block aborts the complete batch.
