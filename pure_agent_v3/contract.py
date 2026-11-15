"""Standard data contract (spec NRE–AMM–OMEGA v5.0, §2) adapted to the Pure Agent v3.

All modules display their result in this structure. `validate_contract` checks the schema (types and closed values) without external dependencies (Pydatic → manual validation).
"""
from .kernel import INVARIANTS_NRE, MAP_NRE

STATES_EXECUTION = ("RECEIVED", "IDLE", "COMMITTED", "REJECTED", "HALTED", "UNCERTAIN", "FAILED",
                     "PENDING_AUTHORIZATION", "CHANGE_PROPOSAL", "DENIED", "INCOMPLETE")
STATES_VERIFICATION = ("PENDING", "PROVEN", "NO_PROVEN", "STRUCTURAL", "FAILED")
LIMITATIONS_BASE = (
    "Structural verification is not factual verification.",
    "Only registered sources count as evidence; without sources, everything remains UNDETERMINED.",
    "The departure of the model is never independent evidence.",
    "The authenticity of the evidence provided in the application is not established (it is CLAIM).",
    "The firewall is by pattern: a new paraphrase may not be detected (authorization is still mandatory).",
)


def new_contract(version, request_id, intent, constraints=(), context=None, evidence=(),
                   state="RECEIVED", max_cycles=3):
    return {
        "system": "NRE",
        "version": version,
        "request": {"request_id": request_id, "intent": intent, "constraints": list(constraints),
                    "context": dict(context or {}), "evidence": list(evidence)},
        "policy": {"default_action": "DENY", "invariants": list(INVARIANTS_NRE),
                   "mapping_agent_pure": dict(MAP_NRE)},
        "execution": {"engine": "OMEGA", "state": state, "max_cycles": max_cycles,
                      "halt_on_verification_failure": True},
        "verification": {"status": "PENDING", "checks": {}, "limitations": list(LIMITATIONS_BASE)},
        "persistence": {"state_store": "SQLite", "audit_store": "SQLite", "hash_algorithm": "SHA-256"},
    }


class InvalidContract(ValueError):
    pass


def validate_contract(c) -> dict:
    def req(cond, msg):
        if not cond:
            raise InvalidContract(msg)
    req(isinstance(c, dict), "contract is not subject")
    for k in ("system", "version", "request", "policy", "execution", "verification", "persistence"):
        req(k in c, f"falta {k}")
    req(c["system"] == "NRE", "system must be NRE")
    r = c["request"]
    req(isinstance(r, dict) and isinstance(r.get("intent"), str), "request.int must be text")
    req(isinstance(r.get("constraints"), list) and isinstance(r.get("evidence"), list)
        and isinstance(r.get("context"), dict), "badly formed request")
    req(c["policy"].get("default_action") == "DENY", "policy.default_action should be DENY")
    req(set(INVARIANTS_NRE) <= set(c["policy"].get("invariants", [])), "missing invariants NRE")
    e = c["execution"]
    req(e.get("engine") == "OMEGA" and e.get("state") in STATES_EXECUTION, f"execution.state invalid: {e.get('state')}")
    req(isinstance(e.get("max_cycles"), int) and 1 <= e["max_cycles"] <= 10, "max_cycles outside [1,10]")
    req(e.get("halt_on_verification_failure") is True, "halt_on_verification_failure debe ser true")
    v = c["verification"]
    req(v.get("status") in STATES_VERIFICATION, "verification.status invalid")
    req(isinstance(v.get("limitations"), list) and len(v["limitations"]) >= 1, "mandatory explicit limitations")
    req(c["persistence"].get("hash_algorithm") == "SHA-256", "hash_algorithm should be SHA-256")
    return c


def request_from_json(obj) -> dict:
    """Normalizes an external request {intent, constraints?, context?, evidence?[]}.
    Evidence: up to 100 objects {source, claim_id, content, polarity(positivenegative}."""
    if not isinstance(obj, dict):
        raise InvalidContract("the application must be an object JSON")
    intent = obj.get("intent")
    if not isinstance(intent, str) or not intent.strip():
        raise InvalidContract("mandatory intent (text)")
    ev = obj.get("evidence", [])
    if not isinstance(ev, list) or len(ev) > 100:
        raise InvalidContract("evidence must be a list of ≤100 items")
    norm = []
    for it in ev:
        if not isinstance(it, dict):
            raise InvalidContract("each evidence must be subject")
        pol = it.get("polarity", "positive")
        if pol not in ("positive", "negative"):
            raise InvalidContract("polarity debe ser positive|negative")
        norm.append({"source": str(it.get("source", "")).strip()[:200],
                     "claim_id": str(it.get("claim_id", "")).strip()[:200],
                     "content": str(it.get("content", ""))[:5000], "polarity": pol})
    cons = obj.get("constraints", [])
    ctx = obj.get("context", {})
    if not isinstance(cons, list) or not isinstance(ctx, dict):
        raise InvalidContract("constraints must be list and context object")
    return {"intent": intent, "constraints": [str(x)[:300] for x in cons][:50],
            "context": {str(k)[:100]: str(v)[:5000] for k, v in list(ctx.items())[:50]}, "evidence": norm}
