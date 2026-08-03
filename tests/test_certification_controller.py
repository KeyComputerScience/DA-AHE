import unittest

import numpy as np

from da_ahe.certification import (
    batch_failure_log2,
    certify_profile,
    cryptographic_utilization,
    good_key_threshold,
)
from da_ahe.controller import (
    BoundedSoftmaxModel,
    Controller,
    candidate_actions,
    scrambling_horizon,
    weak_ergodicity_constants,
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

    def test_transition_matrix_and_controller(self) -> None:
        model = BoundedSoftmaxModel(0.01)
        controller = Controller(self.params, model)
        actions = candidate_actions(self.profiles, self.params)
        distribution = np.array([1.0, 0.0, 0.0, 0.0, 0.0])
        feedback = np.array([0.5, 0.05, 0.214])
        selected, score, next_distribution = controller.choose(
            distribution, feedback, actions
        )
        matrix = model.matrix(selected, feedback)
        np.testing.assert_allclose(matrix.sum(axis=1), np.ones(5))
        self.assertTrue(np.all(matrix[matrix > 0] >= model.epsilon0))
        self.assertAlmostEqual(float(np.sum(next_distribution)), 1.0)
        self.assertTrue(np.isfinite(score))

    def test_weak_ergodicity_constants(self) -> None:
        self.assertGreaterEqual(scrambling_horizon(), 1)
        constants = weak_ergodicity_constants(0.01)
        self.assertGreater(constants["rho"], 0.0)
        self.assertLess(constants["rho"], 1.0)


if __name__ == "__main__":
    unittest.main()

