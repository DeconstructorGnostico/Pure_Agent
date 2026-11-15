"""Zero-Trust Engine (NRE) · I12 PRIVILEGE_MUST_BE_EXPLICIT · deny-by-default.

Each capacity (main, action) must be granted EXPLICITLY. There are no wildcards or inheritance: the unlisted is denied. The concessions are fixed when building (from the policy of the controller) and are frozen (frozenset). The model can only PROPOSE and READ_CONTEXT. Correct the original engine finding v5: there ZeroTrust existed but no one called him.
"""
from types import MappingProxyType

DENY, ALLOW = "DENY", "ALLOW"


class ZeroTrust:
    default_action = DENY

    def __init__(self, concessions):
        g = {}
        for main, actions in dict(concessions).items():
            if not isinstance(main, str) or not main:
                raise ValueError("main invalid")
            acc = frozenset(actions)
            if any((not isinstance(a, str)) or "*" in a for a in acc):
                raise ValueError("Zero-Trust does not admit wildcards or non-textual actions")
            g[main] = acc
        self._g = MappingProxyType(g)
        self.decisions: list = []

    def allowed(self, main: str, act: str, register: bool = True) -> bool:
        ok = isinstance(main, str) and isinstance(act, str) and act in self._g.get(main, frozenset())
        if register:
            self.decisions.append((main, act, ALLOW if ok else DENY))
            del self.decisions[:-1000]          # limited registrations:
        return ok

    def require(self, main: str, act: str):
        if not self.allowed(main, act):
            raise PermissionError(f"Zero-Trust: {main} has no explicit concession for {act}")

    def concessions(self) -> dict:
        return {k: sorted(v) for k, v in self._g.items()}


def concessions_by_default(tools_allowed, model_id):
    """Basic policy: the controller authorizes effects; the executor executes only tools
    allowed; the model proposes and reads context; no one else has anything."""
    h = sorted(tools_allowed)
    return {
        model_id: ["PROPOSE", "READ_CONTEXT"],
        "controller-external": ["AUTHORIZE:" + x for x in h] + ["AUTHORIZE_CHANGE", "RESET"],
        "executor-sandbox": ["EXECUTE:" + x for x in h],
        "verifier-post": ["VERIFY"],
        "persistence": ["PERSIST"],
        "auditor": ["AUDIT"],
    }
