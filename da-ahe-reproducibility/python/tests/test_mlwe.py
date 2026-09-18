import unittest

import numpy as np

from da_ahe.mlwe import add_ciphertexts, decrypt, encrypt, keygen
from da_ahe.params import LatticeParams
from da_ahe.sampling import ResearchSampler


class MlweTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = LatticeParams()
        cls.key_pair = keygen(cls.params, ResearchSampler(1), b"M" * 32)

    def test_encrypt_decrypt(self) -> None:
        message = np.zeros(self.params.d, dtype=np.int64)
        message[:20] = np.arange(-10, 10)
        ciphertext = encrypt(
            self.key_pair.public,
            message,
            3.2,
            self.params,
            ResearchSampler(2),
        )
        recovered = decrypt(self.key_pair.secret, ciphertext, self.params)
        np.testing.assert_array_equal(recovered, message % self.params.p)
        self.assertEqual(len(ciphertext.to_bytes(self.params)), 4_096)

    def test_homomorphic_addition(self) -> None:
        messages = []
        ciphertexts = []
        for index in range(4):
            message = np.zeros(self.params.d, dtype=np.int64)
            message[:8] = index + np.arange(8)
            messages.append(message)
            ciphertexts.append(
                encrypt(
                    self.key_pair.public,
                    message,
                    3.2,
                    self.params,
                    ResearchSampler(10 + index),
                )
            )
        aggregate = add_ciphertexts(ciphertexts, self.params)
        recovered = decrypt(self.key_pair.secret, aggregate, self.params)
        expected = np.sum(np.stack(messages), axis=0) % self.params.p
        np.testing.assert_array_equal(recovered, expected)


if __name__ == "__main__":
    unittest.main()

