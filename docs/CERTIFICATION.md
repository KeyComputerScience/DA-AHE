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

Version 0.2.0 additionally requires machine-readable JSON identity for each
action report:


{
  "schema_version": 1,
  "artifact_type": "daahe-action-bound",
  "claim": "security",
  "subject": "Replace this string with the complete Certificate.evidence_subject() object"
}

`kind="synthetic"` exists only for explicit demonstrations. It cannot produce a
certified decision. `kind="external"` requires reviewed artifacts; the package
does not create external attestations from example numbers.

RobustController additionally requires `ControlModel.bound_kind="external"`,
model-bound uniform state-error and transition radii, certified-domain evidence,
and complete action digests in model metadata. Online transition adaptation also
requires an `adaptation` artifact showing that radii cover that update rule.
Its analytic `fallback_bound` must be <=beta over the declared cube.

Each model report similarly uses `artifact_type="daahe-model-bound"`, the
specific claim `state_error`, `transition`, `domain` or `adaptation`, and the
complete object returned by `controller.evidence_subject(runtime)`. That object
binds current model digest, action digests, fallback identity, deployment context,
model/runtime regions, all ControllerParams and enabled HMM adaptation settings.
Do not hand-copy a shortened subject.
