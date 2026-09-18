# DA-AHE executable Python reference

This package follows the parameterization used in the manuscript:

- M-LWE: `d=256`, `k=3`, `n=768`, `q=2^32`, `p=65537`;
- packing: 240 data coefficients plus 16 field-linear authenticator values;
- input: two synchronized 240-sample channels;
- profiles: `(L, delta_Q, sigma_enc, N_max) = (240,8,3.2,16)`,
  `(180,12,3.4,14)`, and `(120,16,3.6,12)`;
- one ciphertext: `(k+1)d` 32-bit words = 4,096 bytes;
- ticket signature: ML-DSA-44;
- transport authentication: 128-bit-truncated HMAC-SHA3-256;
- online selection: five-regime belief update, exact L1 ambiguity maximization,
  robust Lyapunov screening, and an offline-named fallback action.

The fixed long-term 128.1-bit estimate is not a dynamic action attribute and
is not recomputed here.  Use the separate `security_estimator` directory.

## Run

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=. python -m unittest discover -s tests -v
PYTHONPATH=. python -m da_ahe.demo
```

The deterministic discrete-Gaussian and NumPy ring implementation are for
functional reproducibility.  They are not constant-time production code.

## Paper-to-code mapping

| Manuscript element | File |
|---|---|
| M-LWE key generation, encryption, aggregation, decryption | `da_ahe/mlwe.py` |
| Two-channel Db2 transform, profile truncation, reconstruction | `da_ahe/codec.py` |
| 16-dimensional linear authenticator | `da_ahe/auth.py` |
| ML-DSA-44 ticket and HMAC-SHA3 blocks | `da_ahe/transport.py` |
| Streaming gateway and sink verification | `da_ahe/protocol.py` |
| Correctness/no-wrap/network/RAM certification | `da_ahe/certification.py` |
| Robust Markov control and L1 ambiguity solver | `da_ahe/robust_control.py` |
