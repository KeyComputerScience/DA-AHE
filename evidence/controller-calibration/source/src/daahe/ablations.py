# SPDX-License-Identifier: MIT
"""Behavioral ablation constructors without silently changing certified tuples.

Compression and HVE ablations are separate immutable profiles in profiles.py.
Static/route-repair ablations reuse the same hard admission logic. Their actual
network performance still requires external packet-level experiments.
"""
from .control import Decision, RobustController
from .safety import SafetyFilter


class StaticController:
    """without_markov: exactly the Eq.22 joint tuple, with no HMM/adaptation."""
    def __init__(self, actions, certificates, static_id):
        self.actions = {a.id:a for a in actions}
        self.action = self.actions[static_id]
        expected = (1.0,16,16,64,0.0)
        if tuple(self.action.vector()[:5]) != expected:
            raise ValueError("static ablation must implement Eq.22 [1,16,16,64,0,pi0]")
        self.safety = SafetyFilter(certificates)

    def select(self,state,belief,last_action,runtime):
        safe = self.safety.check(self.action,runtime,state)
        if not safe.allowed:
            return Decision(None,False,True,"static action rejected: "+"; ".join(safe.reasons))
        return Decision(self.action,safe.certified,False,
                        "Eq.22 static certified tuple" if safe.certified else "uncertified static demonstration")


class WithoutRouteRepairController(RobustController):
    """without_route_repair: retain robust decisions, admit only repair==0 tuples.

    Reusing a certificate after changing action.repair is forbidden. The external
    action library must already contain the repair-zero tuples it can use. Model,
    profile and context identities remain unchanged from the full controller.
    """
    def __init__(self,model,actions,certificates,fallback_id,params=None,*,hmm=None):
        allowed = {a.id for a in actions if a.repair == 0.0}
        if fallback_id not in allowed:
            raise ValueError("route-repair ablation requires a repair-zero fallback")
        restricted = {k:v for k,v in certificates.items() if k in allowed}
        super().__init__(model,actions,restricted,fallback_id,params,hmm=hmm)

