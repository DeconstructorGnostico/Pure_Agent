"""§15 Self-modification · §9 (BG) CHANGE_PROPOSAL.

CHANGE_PROPOSAL → IMPACT_ANALYSIS → CONFLICT_CHECK → VALIDATION → AUTHORIZATION → VERSION_CHANGE → AUDIT. No one applies a change without token CHANGE_AUTH from the controller; and the protected objectives (root, invariants, auditor, authority, verifiers) give CONFLICT even with token.
"""
import copy

from .root import PROTECTED
from .useful import sha256

OPERATIONS = ("set", "add", "remove")


class ChangeProtocol:
    def __init__(self, policies: dict, keyring, audit_log, clock, id_model: str):
        self.policies = policies
        self.version = 1
        self._keyring = keyring
        self._audit = audit_log
        self._clock = clock
        self._id_model = id_model
        self.records: dict[str, dict] = {}
        self._used: set = set()

    def propose(self, change, proposer: str) -> dict:
        cid = f"chg-{len(self.records) + 1:04d}"
        impact = {"target": change.target, "operation": change.operation,
                   "layer": "G1/G2 (RAIZ)" if change.target.startswith(PROTECTED) else "G3 (POLITICS)",
                   "before": self._read(change.target)}
        conflicts = []
        if change.target.startswith(PROTECTED):
            conflicts.append(f"{change.target}: Root Layer protected target (INV-R00)")
        if self._id_model and self._id_model in str(change.value_) and "authoriz" in change.target:
            conflicts.append("grants authority to the model (INV-R01/INV-R07)")
        if not change.target.startswith("policies."):
            conflicts.append("solo se pueden cambiar claves 'politicas.*'")
        if change.operation not in OPERATIONS:
            conflicts.append(f"invalid operation {change.operation}")
        state = "CONFLICT" if conflicts else "PENDING_AUTHORIZATION"
        reg = {"id": cid, "target": change.target, "operation": change.operation,
               "value_": change.value_, "proposer": proposer, "impact": impact,
               "conflicts": conflicts, "state": state}
        reg["hash"] = sha256({k: reg[k] for k in ("id", "target", "operation", "value_")})
        self.records[cid] = reg
        self._audit.register("CHANGE_PROPOSAL", request_id=cid, proposal=reg["hash"],
                              validation_results={"conflicts": conflicts}, state_after=state,
                              proposer=proposer)
        return reg

    def _read(self, target):
        key_ = target.split(".", 1)[-1]
        return copy.deepcopy(self.policies.get(key_))

    def apply(self, cid: str, token) -> dict:
        reg = self.records.get(cid)
        if reg is None:
            return {"state": "REJECTED", "reason": "non-existent change"}
        actual = sha256({k: reg[k] for k in ("id", "target", "operation", "value_")})
        if actual != reg["hash"]:
            return {"state": "REJECTED", "reason": "proposal altered after analysis"}
        # Closed scheme: do not allow new policies to introduce fictitious roles or permissions.
        key_ = reg["target"].split(".", 1)[-1]
        if key_ not in {"tools_allowed", "auto_authorize_only_reading", "zero_padding"}:
            return {"state": "REJECTED", "reason": "policy outside of the allowed scheme."}
        if reg["state"] != "PENDING_AUTHORIZATION":
            return {"state": "REJECTED", "reason": f"estado {reg['state']}: {reg['conflicts']}"}
        if not self._keyring.verify(token, "AUTHORIZER", "CHANGE_AUTH"):
            self._audit.register("CHANGE_REJECTED", request_id=cid, error="invalid token",
                                  state_after="REJECTED")
            return {"state": "REJECTED", "reason": "without valid authorization of the controller (INV-R02)"}
        if token.subject != reg["hash"] or token.datum("nonce") in self._used \
                or token.datum("expires", 0) < self._clock.now_():
            return {"state": "REJECTED", "reason": "token does not correspond, reused or expired"}
        self._used.add(token.datum("nonce"))
        key_ = reg["target"].split(".", 1)[1]
        before = copy.deepcopy(self.policies.get(key_))
        if reg["operation"] == "set":
            self.policies[key_] = reg["value_"]
        elif reg["operation"] == "add":
            self.policies.setdefault(key_, [])
            if reg["value_"] not in self.policies[key_]:
                self.policies[key_].append(reg["value_"])
        elif reg["operation"] == "remove" and reg["value_"] in self.policies.get(key_, []):
            self.policies[key_].remove(reg["value_"])
        self.version += 1
        reg["state"] = "APPLIED"
        self._audit.register("VERSION_CHANGE", request_id=cid, authorization=token.datum("approved_by"),
                              state_before=str(before), state_after=str(self.policies.get(key_)),
                              version=self.version)
        return {"state": "APPLIED", "version": self.version}
