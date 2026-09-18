import unittest

from da_ahe.certification import (
    batch_failure_log2,
    certify_profile,
    cryptographic_utilization,
    good_key_threshold,
)
from da_ahe.params import LatticeParams, default_profiles


class CertificationControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.params = LatticeParams()
        self.profiles = default_profiles()

    def test_paper_values(self) -> None:
        self.assertAlmostEqual(good_key_threshold(self.params), 25_193.285, places=2)
        eta_fallback = cryptographic_utilization(1, 3.2, self.params)
        self.assertAlmostEqual(eta_fallback, 0.214, places=3)
        self.assertAlmostEqual(
            cryptographic_utilization(16, 3.2, self.params), 0.856, places=3
        )
        self.assertAlmostEqual(
            batch_failure_log2(32, 3.2, self.params), -84.716, places=2
        )

    def test_default_profiles_are_accepted(self) -> None:
        reports = [certify_profile(profile, self.params) for profile in self.profiles]
        self.assertTrue(all(report.accepted for report in reports))
        self.assertEqual([report.n_effective for report in reports], [16, 14, 12])

if __name__ == "__main__":
    unittest.main()
