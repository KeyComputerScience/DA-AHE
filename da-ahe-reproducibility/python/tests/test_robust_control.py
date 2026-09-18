import unittest

import numpy as np

from da_ahe.params import LatticeParams, default_profiles
from da_ahe.robust_control import (
    RobustAction,
    RobustMarkovController,
    belief_update,
    safety_state,
    worst_case_l1_expectation,
)


def kernel(diagonal: float) -> np.ndarray:
    off = (1.0 - diagonal) / 4.0
    return np.full((5, 5), off) + np.eye(5) * (diagonal - off)


class RobustControlTests(unittest.TestCase):
    def setUp(self):
        params = LatticeParams()
        profiles = default_profiles()
        self.actions = [
            RobustAction(
                "nominal", profiles[0], 16, 1.0, 0.0, kernel(0.72),
                np.array([0.04, 0.03, 0.04]), np.full(5, 0.02),
                np.array([0.2, 0.8, 0.6, 0.9, 1.2]),
            ),
            RobustAction(
                "fallback", profiles[0], 1, 0.5, 1.0, kernel(0.80),
                np.array([0.40, 0.40, 0.40]), np.full(5, 0.01),
                np.array([0.5, 0.6, 0.6, 0.7, 0.8]),
            ),
        ]
        self.controller = RobustMarkovController(
            params=params,
            p_v=np.eye(3),
            gamma=0.10,
            beta=0.02,
            epsilon_transition=0.10,
            kappa_z=0.80,
            disturbances=np.array(
                [[0, 0, 0], [.16, .10, .08], [.12, .08, .05],
                 [.25, .18, .12], [.38, .30, .20]]
            ),
            fallback_name="fallback",
        )

    def test_safety_state(self):
        z = safety_state(0.08, 0.10, 0.01, 0.02, 100, 200, 20)
        np.testing.assert_array_equal(z, np.zeros(3))

    def test_l1_solver_moves_half_epsilon_mass(self):
        value, distribution = worst_case_l1_expectation(
            np.array([.5, .5, 0, 0, 0]), np.arange(5.0), .2
        )
        self.assertAlmostEqual(np.linalg.norm(distribution - np.array([.5, .5, 0, 0, 0]), 1), .2)
        self.assertGreater(value, .5)

    def test_belief_update(self):
        posterior = belief_update(
            np.array([1, 0, 0, 0, 0.0]), kernel(.8), np.zeros(2),
            np.zeros((5, 2)), np.ones(2),
        )
        self.assertAlmostEqual(float(posterior.sum()), 1.0)

    def test_fallback_is_returned_when_nominal_is_not_feasible(self):
        selected = self.controller.select(
            np.array([1.0, 1.0, 1.0]), np.array([0, 0, 0, 0, 1.0]),
            self.actions, self.actions[0],
        )
        self.assertEqual(selected.name, "fallback")


if __name__ == "__main__":
    unittest.main()
