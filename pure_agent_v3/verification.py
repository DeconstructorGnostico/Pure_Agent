"""L6 · Independent Verification + Mutable Learning (DGM) with reviewer.

Post-execution verifiers are DIFFERENT functions of the executor (I07): recalculate or reread the effect from the disk. Learning only AGREGA locks and is never self-tested (I09).
"""
import re

from .kernel import PROTECTED
from .root.useful import sha256
from .sandbox import calculate_exact


def verify_calculation(result, params):
    exact = calculate_exact(params["expression"])
    return abs(float(exact) - float(result)) <= 1e-9 * max(1.0, abs(float(exact)))


def verifier_file(sandbox):
    def v(result, params):
        return sha256(sandbox.read_file(params["name_"])) == result["sha256"] == sha256(params["content"])
    return v


def verifier_message(sandbox):
    def v(result, params):
        expected = {"for_": params["for_"], "subject": params["subject"], "body_": params["body_"]}
        return any(sha256(m) == result["sha256"] == sha256(expected) for m in sandbox.inbox())
    return v


KEYWORD = re.compile(r"^[a-z0-9áéíóúüñ _'\-]{3,60}$", re.IGNORECASE)


class Learning:
    """Mutations: FIREWALL_BLOCK:<word>. Hypothesis → adverse validation → proposer reviewer"""

    def __init__(self, keyring, audit_log, max_rules=100):
        self._keyring = keyring
        self._audit = audit_log
        self.max_rules = max_rules
        self.mutations: dict[str, dict] = {}
        self.rules: list[str] = []
        self.version = 1

    def propose(self, word: str, proposer: str, category="FIREWALL_BLOCK") -> dict:
        mid = f"mut-{len(self.mutations) + 1:04d}"
        problems = []
        if category.upper() in PROTECTED or category != "FIREWALL_BLOCK":
            problems.append(f"protected or not permitted category {category}")
        if not KEYWORD.match(word or ""):
            problems.append("invalid keyword")
        if word and len(word.strip()) < 3:
            problems.append("too short (it would block everything)")
        if len(self.rules) >= self.max_rules:
            problems.append("limit of rules")
        m = {"id": mid, "word": word, "category": category, "proposer": proposer,
             "state": "REJECTED" if problems else "PENDING_REVIEW", "problems": problems}
        m["hash"] = sha256({k: m[k] for k in ("id", "word", "category", "proposer")})
        self.mutations[mid] = m
        self._audit.register("MUTATION_PROPOSED", request_id=mid, proposal=m["hash"], state_after=m["state"],
                              proposer=proposer)
        return m

    def review(self, mid: str, verdict) -> dict:
        m = self.mutations.get(mid)
        if not m or m["state"] != "PENDING_REVIEW":
            return {"state": "REJECTED", "reason": "non-existent or already revised mutation"}
        if not self._keyring.verify(verdict, "VERIFIER") or verdict.subject != m["hash"]:
            return {"state": "REJECTED", "reason": "unsigned verdict of registered reviewer (I09)"}
        if verdict.issuer == m["proposer"]:
            return {"state": "REJECTED", "reason": "the reviewer cannot be the proposer (I09)"}
        if verdict.type_ != "VALID":
            m["state"] = "REJECTED"
            return {"state": "REJECTED", "reason": "the reviewer refused"}
        self.rules.append(m["word"])
        self.version += 1
        m["state"] = "APPLIED"
        self._audit.register("MUTATION_APPLIED", request_id=mid, authorization=verdict.issuer,
                              state_after="APPLIED", version=self.version)
        return {"state": "APPLIED", "version": self.version}


class Reviewer:
    """Reviewer humano/external registered as VERIFIER. He is the one who signs the verdict."""

    def __init__(self, signer):
        self._f = signer
        self.id = signer.main

    def rule(self, mutation: dict, approve: bool):
        return self._f.issue("VALID" if approve else "INVALID", mutation["hash"], reviewer=self.id)
