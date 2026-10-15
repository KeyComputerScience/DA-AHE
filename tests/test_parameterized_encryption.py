from dataclasses import replace
import random

import pytest

from daahe.mlwe import Ciphertext, MLWEParameters, decrypt, deserialize_ciphertext, encrypt, keygen
from daahe.profiles import Profile, ProfileLibrary
from daahe.protocol import Contributor, SourceEmissionStore, Ticket, encapsulate, issue_ticket


@pytest.mark.parametrize("rank", [3, 6])
def test_parameterized_addition_and_serialization(rank):
    params = MLWEParameters(k=rank)
    keys = keygen(random.Random(800 + rank), params)
    left = encrypt(keys.pk, (7, 65530), rng=random.Random(900 + rank))
    right = encrypt(keys.pk, (65535, 11), rng=random.Random(1000 + rank))
    result = left + right
    assert decrypt(keys.sk, result)[:2] == (5, 4)
    assert len(result.to_bytes()) == (rank + 1) * 256 * 4
    assert Ciphertext.from_bytes(result.to_bytes(), params) == result
    assert deserialize_ciphertext(result.to_bytes(), params) == result
    with pytest.raises(ValueError):
        Ciphertext.from_bytes(result.to_bytes(), MLWEParameters(k=4 if rank == 3 else 3))


def test_signed_ticket_binds_encryption_parameters_before_source_state_commit(tmp_path):
    import hmac
    class FramingOnlySigner:
        def sign(self, message):
            return hmac.digest(b"public-test-fixture-key", message, "sha3_256")
        def verify(self, message, signature):
            return hmac.compare_digest(self.sign(message), signature)
    signer = FramingOnlySigner()
    profile = Profile("bind-test", 2, 1, 3.2, 1, (0, 1), 2048)
    library = ProfileLibrary([profile])
    source = Contributor("node", b"n" * 16)
    params = MLWEParameters(k=6)
    ticket = Ticket(0, 0, "parameter-test", profile.profile_id, profile.digest,
                    (source,), b"b" * 32, encryption_parameters=params)
    assert ticket.digest != replace(ticket, encryption_parameters=MLWEParameters(k=3)).digest
    signed = issue_ticket(ticket, signer)
    wrong_key = keygen(random.Random(53), MLWEParameters(k=3)).pk
    with pytest.raises(ValueError, match="key parameters differ"):
        encapsulate(((1,) * 240,) * 2, signed, source, wrong_key, b"e" * 32,
                    b"k" * 32, signer, library,
                    source_store=SourceEmissionStore(tmp_path / "state.sqlite"))
