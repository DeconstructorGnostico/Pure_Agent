"""NEXUS · transverse control plane (side of CONTROLLER EXTERNAL).

READ_ONLY_AUTO: tools without effect are authorized by permanent control policy (and v3 only if `decide` darn. darn. darn. darn. darn. darn. darn. darn. darn. darn. darn. darn EXECUTE: everything critical confirmed). PENDING_AUTHORIZATION: everything else awaits an external decision (humano/service) signing a token. Zero-Trust: NEXUS does not emit a token for a tool without explicit concession (I12). Effect limit per session (I10). The model never refers to NEXUS.
"""


class Nexus:
    def __init__(self, controller, max_effects_by_session=10, zero_trust=None, main="controller-external"):
        self._c = controller
        self.max_effects = max_effects_by_session
        self.effects_authorized = 0
        self.decisions: list[dict] = []
        self._zt = zero_trust
        self._main = main

    def authorize(self, pending, approved_by: str):
        if self._zt is not None and not self._zt.allowed(self._main, "AUTHORIZE:" + pending.tool):
            self.decisions.append({"id": pending.id, "decision": "DENIED", "reason": "Zero-Trust (I12)"})
            return None
        if self.effects_authorized >= self.max_effects:
            self.decisions.append({"id": pending.id, "decision": "DENIED", "reason": "session limit"})
            return None
        self.effects_authorized += 1
        self.decisions.append({"id": pending.id, "decision": "AUTHORIZED", "by": approved_by})
        return self._c.authorize(pending, approved_by=approved_by)

    def refuse(self, pending, by: str):
        self.decisions.append({"id": pending.id, "decision": "DENIED", "by": by})
