"""Plug-in model (§2: MODEL = RAZONAMIENTO, without authority).

The governor only gives you an immutable `ModelContext`; the model returns a `Proposal`. It does not receive keychain, audit, controller or tools.
"""
from dataclasses import dataclass, field
from typing import Callable, Protocol

# INV-05 (BG) Traceability: categories to be distinguished
TYPES = ("FACT", "EVIDENCE", "INFERENCE", "PROPOSAL", "DECISION", "ACTION", "RESULT")
# What the YES model can produce by itself (§11)
TYPES_OF_MODEL = ("INFERENCE", "PROPOSAL")


@dataclass(frozen=True)
class ModelContext:
    instruction: str
    data_: tuple = ()
    policies_visible: tuple = ()
    request_id: str = ""


@dataclass
class Statement:
    content: str
    type_: str = "FACT"
    proposition: str = ""        # verifiable key, e.g. "capital(fund)=paris"
    value_: bool = True


@dataclass
class ActionRequest:
    tool: str
    params_: dict = field(default_factory=dict)
    authorization_: object = None   # if the model "brings" its own authorization → self-authorization


@dataclass
class ProposedChange:
    target: str                 # e.g. "politics.tools_allowed" or "invariants.INV-R02"
    operation: str                # "set" | "add" | "remove"
    value_: object = None
    apply_direct: bool = False  # attempt to skip protocol → INV-R00


@dataclass
class Proposal:
    text: str = ""
    affirmations: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    changes: list = field(default_factory=list)
    memory: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)         # "evidence"/"tokens" attaching the model
    tools_used_declared: list = field(default_factory=list)
    persistence_declared: bool = False


class Model(Protocol):
    id: str
    version: str

    def propose(self, context: ModelContext) -> Proposal: ...


class SimulatedModel:
    """Deterministic Stub: a function, an answer list or a fixed text."""

    def __init__(self, response: Callable | list | Proposal | str = "", id="model-simulado",
                 version="0.1"):
        self.id, self.version = id, version
        self._r = response
        self._i = 0
        self.contexts: list[ModelContext] = []

    def propose(self, context: ModelContext):
        self.contexts.append(context)
        r = self._r
        if callable(r):
            return r(context)
        if isinstance(r, list):
            r = r[min(self._i, len(r) - 1)]
            self._i += 1
        return r
