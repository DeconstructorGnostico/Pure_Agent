"""L0 · Root Kernel: Invariants I01–I10 of Pure Agent + INV-R00.R10 of Root Layer.

Everything is read-only; `root_hash()` is compared before and after each cycle (I08).
"""
from types import MappingProxyType

from .root.root import INVARIANTS as INV_ROOT, hash_root
from .root.useful import sha256

NAME = "Pure Agent v3 · NRE–AMM–OMEGA NEXUS · governed by the Root Layer (AZUL DEEP)"
ARCHITECT = "ADRIAN MENDEZ MILLAN"
MOTTO = "The model proposes, the system governs."

INVARIANTS_AP = MappingProxyType({
    "I01": "INFERENCE != FACT",
    "I02": "RESPONSE != REALITY",
    "I03": "CLAIM != EVIDENCE",
    "I04": "MEMORY != EVIDENCE",
    "I05": "EXTERNAL_CONTEXT != AUTHORITY",
    "I06": "PROPOSAL != AUTHORIZATION",
    "I07": "UNVERIFIED_RESULT != ACCEPTED_RESULT",
    "I08": "MODEL_CANNOT_MODIFY_ROOT_KERNEL",
    "I09": "LEARNING_CANNOT_SELF_APPROVE",
    "I10": "BOUNDED_EXECUTION_REQUIRED",
    "I11": "UNKNOWN != FALSE",
    "I12": "PRIVILEGE_MUST_BE_EXPLICIT",
})

# Invariants of the spec NRE–AMM–OMEGA v5.0 and what invariant executable(s) are mapped here.
INVARIANTS_NRE = ("INFERENCE != FACT", "MODEL_OUTPUT != EVIDENCE", "INSTRUCTION != AUTHORIZATION",
                   "UNKNOWN != FALSE", "CONTEXT != AUTHORITY", "UNVERIFIED_CHANGE != ACCEPTED_CHANGE",
                   "RESPONSE != REALITY", "PRIVILEGE_MUST_BE_EXPLICIT")
MAP_NRE = MappingProxyType({
    "INFERENCE != FACT": "I01",
    "MODEL_OUTPUT != EVIDENCE": "I03 + INV-R03",
    "INSTRUCTION != AUTHORIZATION": "I06 + INV-R02",
    "UNKNOWN != FALSE": "I11",
    "CONTEXT != AUTHORITY": "I05",
    "UNVERIFIED_CHANGE != ACCEPTED_CHANGE": "I07 + I09 + protocolo CHANGE_PROPOSAL",
    "RESPONSE != REALITY": "I02",
    "PRIVILEGE_MUST_BE_EXPLICIT": "I12 (Zero-Trust deny-by-default)",
})

LAYERS = MappingProxyType({
    "L0": "Root Kernel (invariants, root hash)",
    "L1": "SIPE / Context Compiler",
    "L2": "Semantic Firewall",
    "L3": "AMM-CORE / Gnostic Deconstructor",
    "L4": "Evidence Engine / Model Gateway",
    "L5": "OMEGA (decision, limited plan, executive sandbox)",
    "L6": "Independent Verification / Learning with reviewer",
    "L7": "Truth State / Audit / Persistence (SQLite)",
    "NRE": "Runtime: life cycle, configuration and storage",
    "AMM-CORE": "Orquestador",
    "OMEGA": "Run engine: status machine, decision failed-closed, limited cycles.",
    "ZERO-TRUST": "Explicit concessions, deny-by-default",
    "NEXUS": "External authorization by request and tool",
    "ROOT": "Root Layer: governs all layers (G0–G7, INV-R00.R10)",
})

FLOW = ("INPUT", "SIPE", "FIREWALL", "DECONSTRUCT", "EVIDENCE", "OMEGA", "VERIFY", "LEARN",
         "PERSIST", "OUTPUT")

STATES_TRUTH = ("SUPPORTED", "REFUTED", "CONTRADICTED", "UNDETERMINED")

# Categories that learning can never touch (I09)
PROTECTED = ("FACT", "ROOT", "INVARIANT", "AUDIT", "AUTHORITY", "NEXUS")


def root_hash() -> str:
    return sha256({"root": hash_root(), "inv_ap": dict(INVARIANTS_AP), "inv_r": dict(INV_ROOT),
                   "layers": dict(LAYERS), "nre": dict(MAP_NRE), "flow": FLOW, "truth": STATES_TRUTH,
                   "protegidas": PROTECTED, "arquitecto": ARCHITECT})
