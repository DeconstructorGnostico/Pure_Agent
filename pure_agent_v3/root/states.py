"""§4 (Behavior Governor) and §10 (Root Layer): operational states and explicit transitions.

PROPOSED VERIFIED AUTHORIZED EXECUTED SUCCESS COMMITTED. Each "strong" jump requires an artifact SIGNED for the correct role; a model text that reads "VERIFIED" is useless here (§12 anti-imulation).
"""
from enum import Enum


class State(str, Enum):
    IDLE = "IDLE"
    INGESTING = "INGESTING"
    FILTERED = "FILTERED"
    VALIDATING = "VALIDATING"
    PROCESSING = "PROCESSING"
    PROPOSED = "PROPOSED"
    UNCERTAIN = "UNCERTAIN"
    VERIFIED = "VERIFIED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    SUCCESS = "SUCCESS"
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    HALTED = "HALTED"


E = State
TERMINAL = {E.COMMITTED, E.REJECTED, E.UNCERTAIN, E.FAILED, E.HALTED}

TRANSITIONS: dict[State, set[State]] = {
    E.IDLE: {E.INGESTING, E.HALTED},
    E.INGESTING: {E.VALIDATING, E.FILTERED, E.REJECTED, E.HALTED},
    E.FILTERED: {E.VALIDATING, E.REJECTED, E.HALTED},
    E.VALIDATING: {E.PROCESSING, E.REJECTED, E.UNCERTAIN, E.HALTED},
    E.PROCESSING: {E.PROPOSED, E.UNCERTAIN, E.REJECTED, E.HALTED},
    E.PROPOSED: {E.VERIFIED, E.UNCERTAIN, E.REJECTED, E.HALTED},
    E.VERIFIED: {E.AUTHORIZED, E.COMMITTED, E.REJECTED, E.UNCERTAIN, E.HALTED},
    E.AUTHORIZED: {E.EXECUTING, E.REJECTED, E.HALTED},
    E.EXECUTING: {E.EXECUTED, E.FAILED, E.HALTED},
    E.EXECUTED: {E.SUCCESS, E.FAILED, E.UNCERTAIN, E.HALTED},
    E.SUCCESS: {E.COMMITTED, E.HALTED},
    E.COMMITTED: {E.IDLE},
    E.REJECTED: {E.IDLE},
    E.UNCERTAIN: {E.IDLE},
    E.FAILED: {E.IDLE},
    E.HALTED: {E.IDLE},
}

# destination -> (role required, type of artifact accepted)
GUARDS: dict[State, tuple[str, set[str]]] = {
    E.VERIFIED: ("VALIDATOR", {"VALID"}),
    E.AUTHORIZED: ("AUTHORIZER", {"AUTHORIZED"}),
    E.EXECUTED: ("EXECUTOR", {"RECEIPT"}),
    E.FAILED: ("", set()),            # the failure is recorded with or without receipt
    E.SUCCESS: ("VERIFIER", {"POST_OK"}),
    E.COMMITTED: ("PERSISTENCE", {"PERSISTED"}),
}


class InvalidTransition(Exception):
    """Transition not allowed: critical breach (INV-R09) → HALT."""


class Machine:
    """S(t) → T → S(t+1). It only moves along declared edges and with guards."""

    def __init__(self, keyring, to_transition=None):
        self.state = E.IDLE
        self.history: list[tuple[str, str, str]] = []
        self._keyring = keyring
        self._cb = to_transition
        self.without_effects = True

    def go(self, destination: State, artifact=None, reason: str = "") -> State:
        origin = self.state
        if destination not in TRANSITIONS[origin]:
            raise InvalidTransition(f"{origin.value} → {destination.value} is not allowed")
        if destination == E.IDLE and origin == E.HALTED:
            if not self._keyring.verify(artifact, "AUTHORIZER", "RESET"):
                raise InvalidTransition("exit HALTED requires RESET signed by controller")
        saves = GUARDS.get(destination)
        if saves and saves[0]:
            role, core_types = saves
            if artifact is None or not self._keyring.verify(artifact, role) or artifact.type_ not in core_types:
                raise InvalidTransition(
                    f"{origin.value} → {destination.value} requires artifact {core_types} signed by {role}")
        if destination == E.COMMITTED and origin == E.VERIFIED and not self.without_effects:
            raise InvalidTransition("VERIFIED → COMMITTED only without pending action")
        self.state = destination
        self.history.append((origin.value, destination.value, reason))
        if self._cb:
            self._cb(origin, destination, reason)
        return destination

    def force_halt(self, reason: str):
        if self.state != E.HALTED:
            self.history.append((self.state.value, E.HALTED.value, reason))
            if self._cb:
                self._cb(self.state, E.HALTED, reason)
            self.state = E.HALTED


def derive(machine: "Machine") -> "Machine":
    """Sub-machine for a specific action, starting from the current state (e.g. VERIFIED)."""
    m = Machine(machine._keyring, machine._cb)
    m.state = machine.state
    m.history = list(machine.history)
    m.without_effects = False
    return m
