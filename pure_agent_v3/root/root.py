"""§0 Identity · §3 Architectural identity · §4 Root invariants · INV-R00 Integrity.

The Root Layer is read-only (MappingProxyType) and its hash is checked before each cycle: if it changes, HALT.
"""
from types import MappingProxyType

from .useful import sha256

IDENTITY = MappingProxyType({
    "system": "INVARIANT CORE",
    "layer": "LAYER RACE",
    "denominacion": "AZUL DEEP",
    "arquitecto": "ADRIAN MENDEZ MILLAN",   # provenance, no permit (IDENTITY PERMISO)
    "role_of_model": "subordinate cognitive component",
    "principio": "the system authority does not reside in the model",
})

INVARIANTS = MappingProxyType({
    "INV-R00": "INTEGRITY: Root Layer cannot be modified by model",
    "INV-R01": "AUTHORITY EXTERNAL: the model does not possess sovereign authority",
    "INV-R02": "no SELF-AUTHORIZATION: the model cannot be granted permits",
    "INV-R03": "no AUTHOVALIDATION: the affirmation of the model is not evidence",
    "INV-R04": "non MANUFACTURING: never declare as happened what did not happen",
    "INV-R05": "TRAZABILIDAD: any critical transition is reconstructable",
    "INV-R06": "FAIL-CLOSED: if it cannot be verified, it cannot be authorized",
    "INV-R07": "NO SCALE: no instruction elevates its own authority",
    "INV-R08": "SEPARATION of FUNCTIONS: generate, validate, authorize, execute and audit are separated",
    "INV-R09": "INTEGRITY OF STATE: a proposal does not change status until authorized and compromised",
    "INV-R10": "DETENTION: a critical violation produces HALT",
})

# Mapping of the "Behavior Governor" invariants (INV-01..08) to the Root Layer.
EQUIVALENCES_BG = MappingProxyType({
    "INV-01 CONSISTENCIA": "determinism rule (§13 BG) · deterministic governor",
    "INV-02 non-IMROVISATION": "INV-R04 + non-existent tools → UNCERTAIN",
    "INV-03 non-SELF-AUTHORIZATION": "INV-R02",
    "INV-04 no VALIDATION": "INV-R03",
    "INV-05 TRAZABILIDAD": "INV-R05 + types FACT/EVIDENCE/INFERENCE/...",
    "INV-06 FAIL-CLOSED": "INV-R06",
    "INV-07 NO SCALE": "INV-R07",
    "INV-08 INTEGRITY": "INV-R00",
})

AXIOM = ("MODEL AUTHORITY", "PROPOSAL • VALIDATION", "VALIDATION",
          "AUTHORISATION WITH REGARD TO THE IMPLEMENTATION OF THE", "EXECUTION • SUCCESSFUL", "EVIDENCE AFFIRATION",
          "MEMORY TRUTH", "IDENTITY PERMISO")

ROOT = MappingProxyType({"identity": IDENTITY, "invariants": INVARIANTS,
                         "equivalences_bg": EQUIVALENCES_BG, "axioma": AXIOM})

# Prefixes that not even an authorized CHANGE_PROPOSAL can play in normal execution.
PROTECTED = ("root.", "invariants.", "identity.", "audit_log.", "authority.", "verifiers.",
              "roles.")


def hash_root() -> str:
    return sha256({k: (dict(v) if isinstance(v, MappingProxyType) else v) for k, v in ROOT.items()})
