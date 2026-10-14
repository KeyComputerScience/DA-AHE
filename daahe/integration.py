# SPDX-License-Identifier: MIT
"""Bind a reviewed control decision to immutable data-plane ticket parameters.

This adapter is fail-closed by default. It supplies a concrete integration point,
not network drivers or a hardware-security attestation. Trusted sink-side callers
must enforce their ticket issuance authorization and epoch policy externally.
"""
import hashlib
import secrets
from .profiles import canonical_json
from .protocol import Ticket, issue_ticket
from .safety import SafetyFilter


def public_key_fingerprint(public_key) -> str:
    value = {"a_seed":public_key.a_seed.hex(),"b":[list(poly) for poly in public_key.b],
             "q":public_key.params.q,"p":public_key.params.p,
             "d":public_key.params.d,"k":public_key.params.k}
    return hashlib.sha3_256(canonical_json(value)).hexdigest()


def decision_context(deployment_digest: str, action, public_key) -> str:
    value = {"deployment_digest":deployment_digest,"action_digest":action.digest(),
             "public_key_digest":public_key_fingerprint(public_key)}
    return hashlib.sha3_256(canonical_json(value)).hexdigest()


def issue_decision_ticket(decision, *, certificates, runtime, library, public_key,
                          signer, roster, epoch, batch_id, state,
                          allow_reference=False):
    """Return SignedTicket binding the selected tuple and provisioned M-LWE key.

    In strict use, accept only a certified decision and independently recheck its
    Eq.3 certificate. Robust model certification is the caller's controller gate;
    DPP/HYS certification does not imply a Lyapunov proof.
    """
    if decision.action is None:
        raise ValueError("no action was authorized")
    if not allow_reference and (not runtime.strict or not decision.certified):
        raise ValueError("deployment ticket requires a certified strict decision")
    action = decision.action
    safe = SafetyFilter(certificates).check(action,runtime,state)
    if not safe.allowed or (not allow_reference and not safe.certified):
        raise ValueError("action certificate rejected at issuance")
    profile = library.lookup(action.profile_id)
    if (runtime.profile_digests.get(action.profile_id) != profile.digest
            or profile.delta_q != action.delta_q or action.batch_size > profile.nmax):
        raise ValueError("control tuple and data profile disagree")
    if certificates[action.id].single_node_plain_bound < profile.coefficient_bound:
        raise ValueError("certificate understates the source profile's admitted coefficient bound")
    canonical_roster = tuple(sorted(roster))
    if len(canonical_roster) != action.batch_size:
        raise ValueError("exact roster cardinality must match selected batch size")
    context = decision_context(runtime.context_digest,action,public_key)
    ticket = Ticket(epoch,batch_id,context,profile.profile_id,profile.digest,
                    canonical_roster,secrets.token_bytes(32),action.block_bytes)
    return issue_ticket(ticket,signer)

