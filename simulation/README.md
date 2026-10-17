# Independent experimental packet simulation

**This is a newly authored, independent, synthetic experiment. It is not the
unavailable original OMNeT++/INET implementation, and it does not reproduce or
validate the manuscript's numerical results.** The simulator runs its own queues,
packets, losses, batching, actions, and repair events. No manuscript result is
inserted as an output or used as an optimization target. Every run is permanently
labeled `independent_experimental_uncertified`. The reportable protocol model is
version **2**, with fixed sink-preauthorized whole-batch rosters. Earlier dynamic-
roster debugging outputs are superseded and must not be used as final evidence.

The default workload intentionally differs from the manuscript: **3,000 source
sensors plus 60 gateways and one sink**, 90 seconds of source generation, one
potential report per sensor with independent uniform phase, a 30–50 second
disturbance, and 35 seconds of draining. It uses 60 local contention domains and
10 backhaul domains. It is not the manuscript's 300-second/30-second-period,
16-gateway reference workload. `paper_like_config.json` provides a prospective
300-second, 30-second-period, 30-second-warmup configuration with a 100–130 second
disturbance. A configuration file does not establish that this longer campaign
has been executed; only an actual completed campaign manifest establishes that.

## Bound k6 parameters and remaining model assumptions

The final independent configuration uses module rank **6**, ring degree 256,
flattened dimension 1,536, modulus 2^32, plaintext modulus 65,537, and key-noise
sigma 3.2. A ciphertext has `(6 + 1) × 256 × 4 = 7,168` configured bytes;
`without_intdb2` therefore transmits 14,336 protected data bytes before tickets
and network headers. The earlier 4,096-byte debugging assumption is superseded.
Configuration validation rejects a tuple/wire-length mismatch and checks the
actual bound security profile/report identities before a campaign starts.

`configs/security_profile.json` binds the independently executed seven-attack
flattened-LWE estimate: minimum 136.475 estimated bits against the requested
128.1-bit threshold. Its scope is the stated heuristic estimator and cost model,
not a module-specific proof or system/security/implementation certification.
The configuration also pins `k6-cdt-03/decoding-bound.json`, including its precise
joint random-key/fresh-honest-encryption probability scope. The declared
noise/batch library is sigma 3.2/N<=16, sigma 3.4/N<=14, sigma 3.6/N<=12. The
reported decoding tail and finite-library union bounds are not worst-case
certificates conditioned on every fixed key, arbitrary realized history,
malicious ciphertext, or unlimited lifetime batches. Nothing in these metadata
bindings makes the reference controller or network model externally certified.

Every campaign snapshots the security profile, security report, and decoding
report under `bound_artifacts/` and verifies their hashes and tuple/capacity
agreement. The reference controller carries the same metadata while keeping its
admission bounds explicitly synthetic. Its lambda/epsilon fields are reference
inputs, not substitutes for these separate evidence files.

The source encryption time is **0.004 seconds per ciphertext**, solely a declared
operation-count proxy: an assumed 0.001-second k=3 matrix stage multiplied by
36/9 for k=6. This is not a full encryption operation count, hardware timing,
MCU measurement, or binding of runtime cost to the estimator. Other processing
times remain explicit independent assumptions. Byte counts and queue pressure
change with the selected tuple; modeled timing/energy still require future
hardware calibration. `paper_like_config.json` carries the same final tuple and
evidence bindings but remains prospective until a completed run exists.

## Run and verify

Run from the repository root with Python 3.11–3.13 and the repository dependencies:

```sh
python tools/run_simulation_campaign.py --config simulation/config.json \
  --output evidence/independent/simulation --jobs 4
python tools/verify_simulation_campaign.py evidence/independent/simulation
```

The reference configuration requires all seven methods and evaluation seeds
1000–1019. That historical comparison has no calibration partition: it uses
declared reference coefficients. The separate
[calibration workflow](../docs/CONTROLLER_CALIBRATION.md) generates new training,
holdout and evaluation partitions with their own execution records.
Configuration validation rejects seed overlap.
Each seed is a paired experimental unit; packets and nodes are not treated as
independent replicates. Workers only read the frozen exogenous inputs and write
their own run directory. The summary sorts seeds and methods; parallel scheduling
does not change any run's random draws or raw content.

For a small deterministic smoke test, use a separate empty output directory:

```sh
python tools/run_simulation_campaign.py --config simulation/config.json \
  --output work/network-smoke --nodes 30 --seeds 51 \
  --methods da-ahe,hys,without_markov --jobs 3
python tools/verify_simulation_campaign.py work/network-smoke --replay
```

Overrides are saved in the effective configuration. Output directories must be
empty, so an invocation cannot silently overwrite existing evidence. `--replay`
reruns every selected seed/method pair and compares all four raw gzip checksums.
It checks local source identities first and refuses drifted source. For a large
campaign, the ordinary verifier independently recomputes every raw denominator,
outcome, energy sum, causal observation window, and paired summary without the
extra cost of rerunning the network.

## What executes

Each source has a nearest gateway in a seeded two-dimensional topology. Reports
are transferred source-to-gateway and, after successful complete reception of every
preauthorized member, gateway-to-sink. At each control-window start, the sink
uses the public periodic sampling plan, the current action, and its sampling
admission rule to preauthorize immutable groups by gateway and protected/lightweight
path. Each group has at most the selected maximum batch size. A final partial
group is fixed upfront, before packet outcomes exist. Every source contribution
and its aggregate must use that original whole-roster ticket. There is no
arrival-based roster selection, partial flush, or post-expiration pruning. A
missing or expired member rejects its entire original batch. The configured
`batch_ready_hold_s` only adds holding time **after all members have arrived**;
it cannot justify emitting an incomplete aggregate. A protected aggregate has a configured
one-ciphertext data budget; `without_intdb2` has two. Lightweight aggregates have
their own explicit payload budget. No actual sensor transform, reconstruction,
encryption, signature, or homomorphic arithmetic is run inside this simulator.
Those operations are represented by byte counts and declared processing delays.

The network evolves through a priority queue of events:

1. Sink preauthorization of immutable rosters at the control-window start, then
   source opportunity arrival and previously determined sampling admission.
2. Configured source CPU reservation and packet construction.
3. Byte-queue admission at each transmitting sensor or gateway.
4. Contention-domain service, explicit random backoff, transmission, ACK wait,
   frame outcome, and retries up to the common retry limit.
5. Complete envelope reception, registration against the original roster, and
   second-hop transmission only after all authorized members have arrived.
6. Sink verification delay, accepted delivery, integrity rejection, or report
   deadline expiration.
7. Periodic observation of already realized window outcomes and selection of the
   action governing subsequent report arrivals.

Actual blocks become UDP/CoAP-style datagrams. Their declared IPv6, UDP, CoAP,
block-option, and block-HMAC bytes occur once per block; 6LoWPAN fragmentation
repeats its configured fragment/MAC/PHY overhead for each actual transmitted MAC
frame. The maximum PSDU is checked separately from the PHY header. Each fragment
has its own queue admission and retry state. ACK wire bytes are counted only for
successful attempts; ACK wait and random backoff occupy channel service time.
Retry exhaustion, queue overflow, and deadline expiration remain separate raw
categories. Incomplete transfers cannot produce delivered reports.

**Ticket overhead and whole-roster consistency are included.** Every source
envelope in a batch and its aggregate carry the **same preauthorized full-roster
ticket**, rather than a single-member source ticket or an arrival-dependent roster:
`2420 + 128 + 20 × roster_members` configured bytes. The signature-size assumption
is 2,420 bytes; 128 bytes represent explicitly assumed fixed binary fields; 20
bytes per member represent an identifier and nonce. These are wire-model
assumptions, not the size of this repository's canonical JSON serializer. The
ticket bytes are part of the transmitted and fragmented payload, and the raw
verifier checks both their inclusion and exact consistency with the prior
authorization for every source and aggregate transfer. The common batch deadline
is the earliest member generation time plus the configured report lifetime.
All members receive one common whole-batch terminal outcome. A source that reaches
the gateway successfully can still be rejected because another authorized source
is missing; this is deliberately counted, not silently removed from the roster.
The backhaul also includes the separately configured aggregate roster
fixed/per-member bytes and the same
block-authentication/network/MAC model.

Advance sink-to-source ticket distribution, signature creation, caching, cache
misses, and provisioning are **not modeled**. Inline source/aggregate transmission
of a ticket is counted; this does not model the original ticket distribution
lifecycle or execute actual signatures. Authorization identities/rosters are
nevertheless fixed before source transmission and enforced throughout this
independent simulator. Consequently the simulation cannot establish the complete
wire/CPU cost of the original protocol. CPU categories are explicit assumptions:
source encryption/compression, ticket verification, tag construction and block
MAC construction; successful complete gateway-envelope MAC verification and
aggregation; sink ticket/HVE verification. Incomplete-envelope verification,
management, operating-system/interrupt costs, receive/listen energy, and MCU peak
workspace are not modeled. Configured CPU power and radio transmit energy are
assumptions, never hardware measurements or a full-protocol energy estimate.

An externally specified primary gateway-to-sink outage affects selected gateways.
Repair is triggered only by **already observed exhausted retransmissions** when
the selected action enables it. Repair control messages incur the common queue,
header, loss and retry costs. A repair only enables an alternate route after all
control transfers succeed and the configured latency passes. The alternate route
then persists for this single-outage experiment. There is no RPL DODAG protocol,
multi-hop route discovery implementation, or route safety theorem here.

The RF model serializes a contention domain, adds a configured collision
probability depending on the currently contending transmitters, and applies a
seeded, externally varying bit-error probability. Topology coordinates select
gateways but do not produce path loss, fading, interference geometry, hidden
terminals, or measured link quality. This approximation must not be called an
IEEE 802.15.4/CSMA/INET implementation.

## Controllers and ablations

The simulator directly imports `daahe.control` and reuses its HMM, robust
selection, DPP virtual queues, and hysteresis implementations. The active
reference file is `simulation/controller_reference.json`, selected by the
configuration's `controller_config` field. All methods use the same reference
coefficients with `strict=False`. These costs, emissions, transitions,
uncertainty values and admission bounds are declared model inputs; they are
not fitted parameters or uniform physical-process certificates.

The independent [calibration runner](../docs/CONTROLLER_CALIBRATION.md) produces
a new `controller.json`, fit diagnostics and partitioned raw records. Its
certificate verifier checks domain, fallback and transition conditions under
explicit model assumptions and preserves failed checks. A fitted configuration
and a model-relative verification report have separate identities from this
reference comparison. Neither is silently substituted into the frozen archive.
The evidence pipeline reports actual outcomes rather than targeting a
predetermined numerical advantage for DA-AHE.

Frozen campaign snapshots preserve their original controller filenames,
coefficients and hashes. The active reference-file name does not rewrite those
historical inputs.

The reference state region is explicitly `[100, 500, 1]`: with a 0.002 loss
threshold, normalized loss can reach 499. Declaring this cube does not prove
domain invariance. Reference-comparison decisions retain their uncertified
status; strict-mode production admission is not changed. The reference
controller has five regimes, while the network's outage/interference generator
and the fitted controller model require their own stated relationship and
coverage assumptions.

| Method | Executed difference |
|---|---|
| `da-ahe` | Robust controller equations and HMM with the reference coefficients |
| `dpp` | Causal virtual-queue controller with the same action library and reference model |
| `hys` | Held-mode hysteresis controller with the same library and reference model |
| `without_markov` | Fixed configured nominal action, no HMM or adaptive selection |
| `without_intdb2` | Robust policy; two configured protected ciphertext payloads; compression delay removed |
| `without_route_repair` | Robust policy; route-repair actuation disabled |
| `without_hve` | Robust policy; sink end-to-end aggregate validity check/delay disabled; block authentication retained |

For both the protected and lightweight paths, this independent service model
requires the same fixed-roster all-members rule. Applying that conservative
service rule to lightweight traffic does not establish homomorphic integrity or
post-quantum confidentiality for plaintext aggregates. The selected action
specifies a maximum grouping size; smaller final groups are determined at
authorization, never after loss. Reference action bounds do not certify
those actual group sizes or the protocol instantiation.

The two-ciphertext ablation has twice the configured encryption time. Ticket
verification and all nonremoved common processing/network budgets apply to all
methods. Ablations leave the reference policy model unchanged, so its predictions
need not accurately describe the modified plant. Nothing in these experiments
certifies those predictions. In particular, the pooled cost model may favor
fallback, and a selected action may not enable route repair; identical outcomes
for some ablations are admissible findings rather than a reason to tune toward
the manuscript's claimed ordering.

## Causality and paired randomness

For each seed, topology, source classes, raw sampling opportunities, sampling
uniforms, gateway outages, interference, and malicious-gateway forgery intervals
are generated **before any method runs**. All seven methods read exactly those
files. Channel errors, external tampering, collisions, and backoff use separate
counter-based SHA-256 streams keyed by semantic frame ID and attempt number.
Methods cannot advance or consume each other's exogenous random stream. Different
endogenous aggregate membership naturally produces different aggregate frame
identities; pairing does not assert otherwise.

The controller only receives completed previous-window outcomes, measured queue
occupancy at its observation cutoff, a realized transmission-failure fraction,
observed integrity detections, and the declared batch-size noise proxy. This
failure fraction occupies the fixture's BER input coordinate; it is explicitly
an observable proxy, **not** an oracle value read from the disturbance trace.
The noise input is likewise an operational proxy, not a cryptographic noise bound.
The public source schedule used by authorization is never provided as future
performance telemetry or combined with future link/attack outcomes. Source
values are not known at authorization; only scheduled identities/times and the
already selected sampling rule are used. The audit records cross-file emission
order to resolve events exactly at an observation boundary and independently
reconstructs causal observation windows. It independently checks that all
source and aggregate tickets retain the prior whole roster and that no batch is
partially accepted after a member is missing or expired.

For a malicious gateway forgery, hop-level block authentication still passes.
With HVE, a successful corrupt aggregate is rejected at the sink. Without HVE,
it is labeled `delivered_invalid` **only for the offline auditor**. The controller
observes accepted delivery and cannot use the hidden invalidity label. Loss and
validity metrics report both accepted and valid delivery so disabling verification
cannot silently improve the reported security outcome.

## Outputs, denominators and recovery

Each campaign contains:

- Effective `config.json`, frozen `controller.json`, source-file checksums and
  an executable `source/` snapshot; a completion manifest listing every paired run.
- `exogenous/seed-N/`: topology, raw traffic opportunities, disturbance trace and
  their content hashes.
- `runs/seed-N/method/`: `events.jsonl.gz` (every transmission attempt, CPU
  reservation, transfer, prior batch authorization, member registration,
  whole-batch expiration, repair and aggregate-reception event),
  `packets.jsonl.gz` (every terminal MAC-frame outcome), `reports.jsonl.gz` (every
  source opportunity's terminal outcome, including skipped opportunities), and
  `epochs.jsonl.gz` (causal observations and complete decision audit).
- Per-run manifest, independently reconstructed per-seed summary, and campaign
  per-seed differences/means/standard deviations. Recovery censor counts are
  explicit; censored times are not averaged as if recovery had been observed.

Every offered source opportunity is conserved as sampling skipped, controller
stopped, or admitted. Every admitted report has exactly one terminal outcome.
All preauthorized members
of a batch share its status and outcome timestamp. Any absent member causes the
whole original roster to fail at the common deadline; surviving members cannot
be reclassified into a smaller accepted aggregate.
Admitted-only residual loss can be improved merely by sampling less, so source
admission and valid deliveries **per raw opportunity** are always reported too.
Energy and wire totals cover the entire run, including warmup when a configuration
uses it; the names explicitly say `all_run`. Delay and delivery metrics honor the
configured source-generation measurement window. Generated data values and
reconstruction distortion are absent, so no accuracy/distortion result is claimed.

Recovery starts from the configured disturbance onset and is armed only after an
observed queue/loss/delay excursion. It requires the configured number of
consecutive good windows, each with a minimum number of completed reports. Empty
windows cannot establish recovery after reporting stops. The timestamp is the
end of the last required good window. A remaining excursion is right-censored
at the common observation horizon; no-excursion runs are separately labeled.
This operational recovery definition differs from any unpublished original
criterion and must be stated when reporting results.

The verifier checks source/config/controller/exogenous/raw hashes, the complete
seed-by-method Cartesian product, packet retry/PSDU limits, packet/attempt count
conservation, common report/batch deadlines, prior authorization and whole-roster
consistency, ticket inclusion, rejection of incomplete batches, and causal
telemetry counts,
wire and modeled-energy sums, per-seed metrics, right-censoring, and the paired
summary. The hashes establish what was run; they do not establish that the
synthetic assumptions match a physical deployment or certify security/stability.

No OMNeT++ execution is claimed. A future OMNeT++/INET backend would require its
own executable model/configuration, actual run logs, and matching packet-level
validation; this simulator is not an export or bridge to such a backend.
