# Hard gates and external certificate contract

`safety.Certificate` binds one complete `Action.digest()`, the actual immutable
256-bit `Profile.digest` and `RuntimeContext.context_digest`. The context must
include the actual public-key instance, signal scaling, sampler implementation,
PHY/headers/retries, role, platform/compiler/firmware and budgets. Changing any
of these invalidates the certificate, even if the short ProfileID stays the same.

Required numerical bounds are:

- `workspace_bytes <= 10240` for the action-specific working set, including
  cryptographic live buffers, transport/authentication state, sensing, metadata
  and stack margin, with a stated memory-layout/measurement method.
- `airtime_s <= runtime.max_airtime_s`, including actual headers, authentication,
  fragmentation, retries and the certified transmission boundary. Payload-only
  4096-byte airtime is not a certificate for this gate.
- `single_node_plain_bound * action.batch_size <= (65537-1)/2`; finite-range
  quantization must reject or otherwise account for every out-of-range sample.
- `log2_epsilon_dec <= -128` for the whole selected batch, all coefficients and
  actual distributions. Empirical zero-failure testing is not this tail bound.
- `noise_bound <= tau_dec-zeta`, with positive margin and scaling carry included.
- `lambda_est_bits >= 128.1` for the fixed key instance and stated attack set,
  pinned source and cost model. Estimator failure is an unavailable certificate.

Each external certificate includes six `EvidenceArtifact` objects under keys
`security`, `decoding`, `noise`, `no_wrap`, `memory`, `airtime`. Each contains a
relative traversal-free `path`, `sha256`, and a substantive `method` description.
The evidence must itself identify the same tuple/profile/context. Hash checking
verifies file integrity, not that a report is truthful or a proof sound.

`kind="synthetic"` exists only for explicit demonstrations. It cannot produce a
certified decision. `kind="external"` requires reviewed artifacts; the package
does not create external attestations from example numbers.

RobustController additionally requires `ControlModel.bound_kind="external"`,
model-bound uniform state-error and transition radii, certified-domain evidence,
and complete action digests in model metadata. Online transition adaptation also
requires an `adaptation` artifact showing that radii cover that update rule.
Its analytic `fallback_bound` must be <=beta over the declared cube.

The code computes a conservative analytic fallback supremum using piecewise
quadratic maxima plus an interval bound for the radius cross term. This proves
an inequality **for the provided model and radii only**; it cannot prove that
those inputs bound a real network. An empirical heldout maximum is not a uniform
population bound. Conditional stability also does not establish domain invariance.

No action is released outside the certified region. If robust admission has no
member, the controller raises an alarm and returns no action; under valid theorem
assumptions, the fallback certificate should make that case impossible inside the
region. Baselines use the same hard Eq.3 gates but do not inherit the DA-AHE
Lyapunov theorem. A production management layer must handle recertification.

