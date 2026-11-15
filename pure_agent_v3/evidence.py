"""L4 · Evidence Engine / Model Gateway.

Four states: SUPPORTED · REFUTED · CONTRADICTED · UNDETERMINED. Required provenance: only count SOURCES recorded as VERIFIER (= model, } sender). Memory is never source (I04). External data are CLAIM (I03/I05).
"""
from .deconstructor import canon
from .root.evidence import Verifier


class TableSource(Verifier):
    """Recorded external source: table of canonical propositions → truth."""

    def __init__(self, facts: dict, id="source-tabla"):
        self.id = id
        self.facts = {}
        for text, v in facts.items():
            key_, parity = canon(text)
            self.facts[key_] = bool(v) if parity == 0 else (not bool(v))

    def check(self, proposition, value_):
        if not isinstance(proposition, str) or not isinstance(value_, bool):
            return None
        if proposition in self.facts:                     # already canonical (deconstructor route)
            return self.facts[proposition] == value_
        # v3 (H-25): the proposition of a real model comes in free text; it never matched before
        key_, parity = canon(proposition)
        if key_ not in self.facts:
            return None
        return self.facts[key_] == (value_ if parity == 0 else not value_)


def evaluate(proposition: dict, sources, signers, keyring, contradicted=frozenset()):
    """It returns dict with a state of truth and provenance."""
    if proposition["text"] in contradicted:
        return dict(proposition, truth="CONTRADICTED", sources=[], class_="CLAIM")
    votes = []
    for f in sources:
        r = f.check(proposition["key_"], proposition["value_"])
        if r is None:
            continue
        art = signers[f.id].issue("VALID" if r else "INVALID", proposition["key_"], source=f.id)
        if keyring.verify(art, "VERIFIER"):
            votes.append((r, f.id))
    if not votes:
        return dict(proposition, truth="UNDETERMINED", sources=[], class_="CLAIM")
    vals = {r for r, _ in votes}
    if len(vals) > 1:
        return dict(proposition, truth="CONTRADICTED", sources=[i for _, i in votes], class_="EVIDENCE")
    return dict(proposition, truth="SUPPORTED" if vals.pop() else "REFUTED",
                sources=[i for _, i in votes], class_="EVIDENCE")
