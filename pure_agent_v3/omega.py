"""L5 · OMEGA: decision table + cycle BOUNDED (steps, plans, time) · I10."""
import time

from .root.model_ import Proposal

PROCESS, REJECT, HALT, PENDING, UNDETERMINED = "PROCESS", "REJECT", "HALT", "PENDING_AUTHORIZATION", "UNDETERMINED"
NEED_INPUT = "NEED_INPUT"   # v3: unknown critical data (intent compiler)


class PlanExceeded(Exception):
    pass


def decide(fw_decision, decon, instr) -> tuple[str, str]:
    """Table of decision prior to the model."""
    if fw_decision == "REJECT":
        return REJECT, "firewall"
    if decon.C:
        return REJECT, "contradiction in the entry: " + "; ".join(decon.C)
    if instr.class_action == "EFFECT":
        return PENDING, "action with external effect: requires authorization"
    return PROCESS, "consulta"


class BoundedModel:
    """It involves the model: it limits steps of the plan and time per proposal. It does not give authority."""

    def __init__(self, model_, max_steps=5, time_max=10.0):
        self._m = model_
        self.id = model_.id
        self.version = getattr(model_, "version", "?")
        self.max_steps = max_steps
        self.time_max = time_max

    def propose(self, ctx):
        t0 = time.monotonic()
        p = self._m.propose(ctx)
        if time.monotonic() - t0 > self.time_max:
            raise PlanExceeded(f"the model took more than {self.time_max}s (I10)")
        if isinstance(p, Proposal) and len(p.actions) > self.max_steps:
            raise PlanExceeded(f"plan {len(p.actions)} steps > max_steps={self.max_steps} (I10)")
        return p
