"""L3 · AMM-CORE / Gnostic Deconstructor.

D(x) = {O, F, A, H, C, V, U, K, E, R}
  O objetive · F statements asserted (CLAIMS, never facts) · A assumptions · H hypothesis C contradictions · V variables/cantidades · U unknowns (questions) · K restrictions E evidence provided in external data (it is still CLAIM up to L4) · R risks
"""
import re
from dataclasses import dataclass, field

from .root.normalization import normalize_text

NEG = {"no", "not", "nunca", "jamas", "never", "tampoco", "ni"}
ANTONIMOS = {"inseguro": "seguro", "insegura": "segura", "falso": "verdadero", "falsa": "verdadera",
             "false": "true", "insecure": "secure", "unsafe": "safe", "inactivo": "activo",
             "imposible": "posible", "incorrecto": "correcto", "ilegal": "legal", "invalido": "valido",
             "desconectado": "conectado", "offline": "online", "apagado": "encendido"}
VAR = re.compile(r"\d+(?:[.,]\d+)?\s?(?:%|ms|s|gb|mb|tb|kb|usd|mxn|pesos|dolares|horas|dias|km|kg|m)?\b")
ASSUMPTION = re.compile(r"^(supon\w*|asum\w*|si |dado que|assume|suppose|if )")
HYPOTHESIS = re.compile(r"\b(quiza\w*|tal vez|podria\w*|posiblemente|probablemente|maybe|might|perhaps|probably)\b")
COPULA = re.compile(r"\b(es|son|esta|estan|era|fue|tiene|tienen|mide|cuesta|pesa|vale|usa|contiene|"
                    r"is|are|was|has|have|costs?|weighs?|uses?|contains?)\b")


@dataclass
class Deconstruccion:
    O: str = ""
    F: list = field(default_factory=list)
    A: list = field(default_factory=list)
    H: list = field(default_factory=list)
    C: list = field(default_factory=list)
    V: list = field(default_factory=list)
    U: list = field(default_factory=list)
    K: list = field(default_factory=list)
    E: list = field(default_factory=list)
    R: list = field(default_factory=list)
    contradicted: set = field(default_factory=set)   # texts involved in C

    def summary(self) -> dict:
        return {k: (v if isinstance(v, str) else len(v)) for k, v in vars(self).items() if k != "contradicted"}


def propositions(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"(?<=[.!?;])\s+|\n+", text or "") if len(p.strip()) > 1][:60]


def canon(p: str):
    """Canonical form (no denials or antonyms) + parity of denial."""
    toks, parity = [], 0
    for t in re.findall(r"[a-z0-9]+", normalize_text(p).replace("n't", " not")):
        if t in NEG:
            parity ^= 1
            continue
        if t in ANTONIMOS:
            parity ^= 1
            t = ANTONIMOS[t]
        toks.append(t)
    return " ".join(toks), parity


def _subject_value(p: str):
    n = normalize_text(p)
    m = COPULA.search(n)
    if not m:
        return None
    nums = VAR.findall(n[m.end():])
    if not nums:
        return None
    return n[:m.start()].strip(), nums[0].strip()


def deconstruct(instr, risks=()) -> Deconstruccion:
    d = Deconstruccion(O=instr.target, K=list(instr.restrictions), R=list(risks))
    seen_, values_, by_key, by_subject = {}, {}, {}, {}
    for p in propositions(instr.original):
        n = normalize_text(p)
        d.V += [v.strip() for v in VAR.findall(n) if v.strip()]
        if p.endswith("?") or n.startswith(("que ", "cual ", "como ", "cuanto", "quien", "what", "how", "why")):
            d.U.append(p)
            continue
        if ASSUMPTION.search(n):
            d.A.append(p)
            continue
        if HYPOTHESIS.search(n):
            d.H.append(p)
            continue
        if not COPULA.search(n):
            continue
        key_, parity = canon(p)
        d.F.append({"text": p, "key_": key_, "value_": parity == 0})
        by_key.setdefault(key_, []).append(p)
        if key_ in seen_ and seen_[key_] != parity:
            d.C.append(f"negation: ‘{p}’ contradicts ‘{by_key[key_][0]}’")
            d.contradicted.update(by_key[key_])
        seen_[key_] = parity
        sv = _subject_value(p)
        if sv:
            subj, val = sv
            by_subject.setdefault(subj, []).append(p)
            if subj in values_ and values_[subj] != val:
                d.C.append(f"valor: «{subj}» = {values_[subj]} y {val}")
                d.contradicted.update(by_subject[subj])
            values_.setdefault(subj, val)
    for s in instr.data_external:
        txt = getattr(s, "text", str(s))
        for p in propositions(txt):
            if COPULA.search(normalize_text(p)):
                key_, parity = canon(p)
                d.E.append({"text": p, "key_": key_, "value_": parity == 0, "origin": "externo"})
    return d


def contradictions_evidence(evidence: list) -> dict:
    """Gnostic Deconstructor of spec NRE v5: contradictions between evidences by `claim_id`.
    Correction included (spec §6): two evidences without claim_id are never considered contradictory by accident. In addition claim_id (espacios/mayúsculas) is normalized."""
    conflicts = []
    for i, a in enumerate(evidence):
        for b in evidence[i + 1:]:
            ca, cb = normalize_text(a.get("claim_id", "")), normalize_text(b.get("claim_id", ""))
            if not ca or not cb:
                continue
            if ca == cb and a.get("polarity") != b.get("polarity"):
                conflicts.append({"claim_id": ca, "sources": [a.get("source"), b.get("source")],
                                   "type": "CONTRADICTORY_ASSERTIONS"})
    return {"conflicts": conflicts, "consistent": not conflicts}
