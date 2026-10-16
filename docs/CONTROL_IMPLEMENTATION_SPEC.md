# Executable controller specification

This document supplies explicit definitions for the host reference corresponding
to Algorithm 6 (paper p.8). It is a specification of the independent code, not a
recovery of missing original calibration data. The canonical implementation is
`src/daahe/control.py`; `tests/test_control.py` exercises its admission and causal
filtering behavior. Parameters are fixed in `ControllerParams` unless supplied
explicitly by the caller.

## Objective and uncertainty set

Let `mu` be the current five-state posterior, and let
`p = mu T_a` be the prediction using the action and stress-bin transition kernel.
The robust drift test uses the simplex ambiguity set

\[
\mathcal U_t(a)=\{q\in\mathbb R_+^5:\mathbf1^Tq=1,
             \|q-p\|_1\le r_a\}.
\]

Here `r_a = model.transition_radii[a]`, constrained to `[0,2]`. The implementation
`l1_worst_case` maximizes `q dot psi` by moving at most `r_a/2` probability mass
from the smallest occupied values to the largest unsaturated values. Radius
zero returns the nominal expectation; radius two allows a point mass at a
maximizer. The test is

\[
\max_{q\in\mathcal U_t(a)}q^T\psi_a(z_t)
 \le (1-\gamma)V(z_t)+\beta.
\]

Only actions passing the resource/security filter and this drift test enter the
objective minimization. Predicted metrics are the nominal `p`-weighted regime
regressions when all five regime models exist; otherwise the pooled regression
is used. Each regression uses features `(1,z_delay,z_loss,z_noise)` and clips
negative predicted values to zero. With predictions `(E,D,X,U_noise)`,

\[
J_t(a)=w_E E/E_{ref}+w_D D/D_{max}+w_X X/X_{max}+w_U U_{noise}
 +w_S\left[\sum_{h=1}^5 s_h(v_h(a)-v_h(a_{t-1}))^2
 +s_6\mathbf1[\mathrm{ID}(a)\ne\mathrm{ID}(a_{t-1})]\right].
\]

The first five switching coordinates are `Action.vector()[:5]`; the sixth is
the indicator that the profile ID changed. With no previous action, switching
cost is zero. Default weights are `(0.22,0.28,0.15,0.25,0.10)`; normalizers default
to one and must be positive. `U_noise` is the declared normalized noise
utilization, not a measured failure probability. Ties are resolved by the
lexicographically smallest action ID. Thus the code robustifies the drift gate;
its performance objective is a nominal predicted cost.

## Evidence needed for the safety interpretation

Strict execution binds external state-error, transition and domain evidence to
the immutable model/action/context digests. Enabled online adaptation also
requires adaptation evidence. The analytic fallback bound must satisfy `beta`.
If the state is outside the certified region, evidence is missing, or no action
passes every gate, `RobustController.select` returns no action and an alarm.
It does not apply an unchecked fallback.

The synthetic configuration is a demonstration with empirical bounds and
adaptation disabled. Its results cannot establish forward invariance or the
original theorem's assumptions. A deployment certificate must establish the
uncertainty bounds, a nonempty feasible action set throughout the operating
domain, and successor-state containment under the allowed disturbances. The
online drift calculations and threshold comparison currently use ordinary
floating-point arithmetic; a deployment proof must include their numerical
errors in conservative margins or replace them with outward-rounded bounds.
The existing exact fallback calculation does not certify every online comparison. An
assertion that the trajectory stays in the region is insufficient evidence of
recursive feasibility.

For a focused systems contribution, report the joint admission of payload,
no-wrap, aggregate reconstruction quality and finite-task decoding risk for
each profile/batch action. Keep performance optimization inside that declared
action domain. The new fidelity and decoding-horizon tools supply two measurable
parts of this coupling; they do not by themselves certify the control model.
