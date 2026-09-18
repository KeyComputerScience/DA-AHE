#!/usr/bin/env python3
"""Generate fixed M-LWE and ML-DSA-44 self-test vectors for firmware."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import numpy as np
from pqcrypto.sign import ml_dsa_44

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "python"))

from da_ahe.mlwe import keygen  # noqa: E402
from da_ahe.params import LatticeParams  # noqa: E402
from da_ahe.sampling import ResearchSampler  # noqa: E402


def rows(values, width=8, fmt=str):
    values = list(values)
    return "\n".join(
        "  " + ", ".join(fmt(v) for v in values[i : i + width]) + ","
        for i in range(0, len(values), width)
    )


def main():
    destination = Path(__file__).resolve().parents[1] / "src"
    params = LatticeParams()
    matrix_seed = hashlib.sha3_256(b"DA-AHE/firmware/test-matrix").digest()
    pair = keygen(params, ResearchSampler(20260918), matrix_seed)
    public_values = pair.public.b.astype(np.uint32).reshape(-1)
    secret_values = pair.secret.s.astype(np.int16).reshape(-1)

    pk, sk = ml_dsa_44.generate_keypair()
    ticket = b"DA-AHE/TICKET/v1" + hashlib.sha3_256(
        b"epoch=1;batch=selftest;profile=0;roster=node-0"
    ).digest()
    signature = ml_dsa_44.sign(sk, ticket)

    header = """#ifndef DA_TEST_VECTORS_H_\n#define DA_TEST_VECTORS_H_\n\n#include <stdint.h>\n#include \"mlwe.h\"\n\nextern const da_public_key_t da_test_public_key;\nextern const da_secret_key_t da_test_secret_key;\nextern const uint8_t da_test_ticket[];\nextern const uint16_t da_test_ticket_len;\nextern const uint8_t da_test_ticket_pk[];\nextern const uint8_t da_test_ticket_sig[];\n\n#endif\n"""
    source = """#include \"test_vectors.h\"\n\n"""
    source += "const da_public_key_t da_test_public_key = {\n  {\n"
    source += rows(matrix_seed, 8, lambda v: f"0x{v:02x}") + "\n  },\n  {\n"
    for vector in pair.public.b.astype(np.uint32):
        source += "    {\n" + rows(vector, 8, lambda v: f"UINT32_C({int(v)})") + "\n    },\n"
    source += "  }\n};\n\nconst da_secret_key_t da_test_secret_key = {\n  {\n"
    for vector in pair.secret.s.astype(np.int16):
        source += "    {\n" + rows(vector, 12, lambda v: str(int(v))) + "\n    },\n"
    source += "  }\n};\n\n"
    source += "const uint8_t da_test_ticket[] = {\n" + rows(ticket, 12, lambda v: f"0x{v:02x}") + "\n};\n"
    source += f"const uint16_t da_test_ticket_len = {len(ticket)};\n"
    source += "const uint8_t da_test_ticket_pk[] = {\n" + rows(pk, 12, lambda v: f"0x{v:02x}") + "\n};\n"
    source += "const uint8_t da_test_ticket_sig[] = {\n" + rows(signature, 12, lambda v: f"0x{v:02x}") + "\n};\n"
    (destination / "test_vectors.h").write_text(header, encoding="utf-8")
    (destination / "test_vectors.c").write_text(source, encoding="utf-8")


if __name__ == "__main__":
    main()
