"""§12 Anti-imulation · INV-R03 Non-self-validation · INV-04 (BG) · §11 Separation model_/verifier.

MODEL_CLAIM: what the model says. It's just text. EXTERNAL_EVIDENCE: a verdict SIGNED by a registered verifier.
"""
from dataclasses import dataclass

from .useful import sha256

MODEL_CLAIM, EXTERNAL_EVIDENCE = "MODEL_CLAIM", "EXTERNAL_EVIDENCE"
SUPPORTED, REFUTED, UNDETERMINED = "SUPPORTED", "REFUTED", "UNDETERMINED"


class Verifier:
    """Interface: check(proposition, value) -> True/False/None (None = I don't know)."""
    id = "verifier"

    def check(self, proposition: str, value_: bool):
        raise NotImplementedError


class TableVerifier(Verifier):
    """Test checker with a table of known facts (simulated external source)."""

    def __init__(self, facts: dict, id="verifier-tabla"):
        self.id = id
        self.facts = dict(facts)

    def check(self, proposition, value_):
        if proposition not in self.facts:
            return None
        return self.facts[proposition] == value_


@dataclass
class Verdict:
    content: str
    type_declared: str
    class_: str                 # MODEL_CLAIM | EXTERNAL_EVIDENCE
    truth: str                # SUPPORTED | REFUTED | UNDETERMINED
    verification: str          # PROVEN | NOT PROVEN
    artifact: object = None


def rule(af, verifiers, signers, keyring) -> Verdict:
    """A fact of the model becomes evidence only if it is verified by an external verifier."""
    if not af.proposition:
        return Verdict(af.content, af.type_, MODEL_CLAIM, UNDETERMINED, "NOT PROVEN")
    results = []
    for v in verifiers:
        r = v.check(af.proposition, af.value_)
        if r is None:
            continue
        art = signers[v.id].issue("VALID" if r else "INVALID", sha256([af.proposition, af.value_]),
                                     verifier=v.id, proposition=af.proposition)
        results.append((r, art))
    if not results:
        return Verdict(af.content, af.type_, MODEL_CLAIM, UNDETERMINED, "NOT PROVEN")
    values_ = {r for r, _ in results}
    art = results[0][1]
    if not keyring.verify(art, "VERIFIER"):
        return Verdict(af.content, af.type_, MODEL_CLAIM, UNDETERMINED, "NOT PROVEN")
    if len(values_) > 1:
        return Verdict(af.content, af.type_, EXTERNAL_EVIDENCE, "CONTRADICTED", "NOT PROVEN", art)
    ok = values_.pop()
    return Verdict(af.content, af.type_, EXTERNAL_EVIDENCE, SUPPORTED if ok else REFUTED,
                    "PROVEN", art)
