"""§1 (Behavior Governor) Hierarchy L0.L7 · §1 (Root Layer) "no lower layer can unilaterally modify a higher layer" · INV-R07 Non-scaling.

To avoid confusing them with Pure Agent layers L0–L7, here they are called G0–G7.
"""
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType


class Layer(IntEnum):
    G0_RUNTIME = 0
    G1_ROOT = 1
    G2_INVARIANTS = 2
    G3_POLICIES = 3
    G4_STATE = 4
    G5_TARGET = 5
    G6_INSTRUCTION = 6
    G7_FORMAT = 7


# Higher layer (lower number) than each source can write.
CEILING_BY_ORIGIN = {
    "RUNTIME": Layer.G0_RUNTIME,
    "CONTROLLER": Layer.G3_POLICIES,   # protocol of change (§15)
    "USER": Layer.G5_TARGET,
    "MODEL": None,                     # the model does not write rules
    "DATA": None,
    "TOOL": None,
}


class Escalacion(Exception):
    pass


class Conflict(Exception):
    pass


@dataclass(frozen=True)
class Directive:
    layer: Layer
    key_: str
    value_: object
    origin: str


class Hierarchy:
    def __init__(self):
        self._dirs: dict[str, Directive] = {}
        self._sealed = False

    def seal(self):
        self._sealed = True

    def apply(self, d: Directive) -> Directive:
        ceiling = CEILING_BY_ORIGIN.get(d.origin)
        if ceiling is None or d.layer < ceiling:
            raise Escalacion(f"INV-R07: {d.origin} cannot write to {d.layer.name}")
        if self._sealed and d.layer <= Layer.G2_INVARIANTS:
            raise Escalacion(f"INV-R00: {d.layer.name} is read-only during execution")
        actual = self._dirs.get(d.key_)
        if actual and actual.layer < d.layer and actual.value_ != d.value_:
            raise Conflict(f"{d.key_}: {d.layer.name} cannot invalidate {actual.layer.name}")
        if not actual or d.layer <= actual.layer:
            self._dirs[d.key_] = d
        return self._dirs[d.key_]

    def value_(self, key_, default=None):
        d = self._dirs.get(key_)
        return d.value_ if d else default

    def view(self):
        return MappingProxyType({k: (v.layer.name, v.value_) for k, v in self._dirs.items()})
