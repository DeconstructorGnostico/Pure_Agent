"""Decision failed-closed, prioritization and quality control (corrected and stdlib version of Adrian's numpy file). Differences with the original, all found when trying it:

* `decide`: the original never said "no" (80 % unknown → "execute with assumptions") and with
  empty data released ZeroDivisionError. Here: EXECUTE only if all critical is confirmed; NEED_INPUT if something critical is missing; always stated assumptions; empty → NEED_INPUT.
* `choose_candidate`: the original returned the first candidate even if none were aligned
  (argmax of zeros). Here it filters first (aligned and verified) and if none passes → None.
* `p_truth`: DERIVA of evidence (verdicts from registered sources), never of what
  say model (MODEL_OUTPUT != EVIDENCE).
* `control_quality`: the original averaged (a good note covered a bad one) and accepted values
  out of range. Here: minimum by criterion, validated ranges [0.1], reprocess with limit.
* The merge vector `phi_root` is not adopted: the file does not define what each vector represents,
  So it does not govern any verifiable decision (see README «Unadopted»).
"""
import math
from dataclasses import dataclass, field

CONFIRMED, INFERRED, UNKNOWN = "confirmed", "inferido", "unknown"
VALUES = (CONFIRMED, INFERRED, UNKNOWN)
EXECUTE, CONFIRM_ASSUMPTIONS, NEED_INPUT = "EXECUTE", "CONFIRM_ASSUMPTIONS", "NEED_INPUT"


class InvalidData(ValueError):
    pass


@dataclass
class Decision:
    mode: str
    assumptions: list = field(default_factory=list)      # Inferred variables (always declared)
    missing_items: list = field(default_factory=list)      # unknown criticisms
    limitations: list = field(default_factory=list)   # non-criticism unknown
    clarity: float = 0.0

    def as_dict(self):
        return {"mode": self.mode, "assumptions": self.assumptions, "missing_items": self.missing_items,
                "limitations": self.limitations, "clarity": self.clarity}


def decide(data_: dict, critical_items=None) -> Decision:
    """data: {variable: confirmedinferredunknown}. criticisms: iterable (by default, all)."""
    if not isinstance(data_, dict):
        raise InvalidData("data must be dict")
    for k, v in data_.items():
        if v not in VALUES:
            raise InvalidData(f"invalid value for {k!r}: {v!r}")
    critical_items = set(data_) if critical_items is None else set(critical_items)
    missing_declared = sorted(c for c in critical_items if c not in data_)   # uninformed criticism = unknown
    if not data_ and not critical_items:
        return Decision(NEED_INPUT, missing_items=["(no data)"], clarity=0.0)
    n = len(data_) or 1
    clarity = round(sum(v == CONFIRMED for v in data_.values()) / n, 4)
    missing_items = sorted([k for k, v in data_.items() if k in critical_items and v == UNKNOWN] + missing_declared)
    assumptions = sorted(k for k, v in data_.items() if v == INFERRED)
    limit = sorted(k for k, v in data_.items() if k not in critical_items and v == UNKNOWN)
    if missing_items:
        mode = NEED_INPUT
    elif any(data_[k] == INFERRED for k in critical_items if k in data_):
        mode = CONFIRM_ASSUMPTIONS
    else:
        mode = EXECUTE
    return Decision(mode, assumptions, missing_items, limit, clarity)


def _positive(x, name_):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or x <= 0:
        raise InvalidData(f"{name_} should be finite number > 0 (received {x!r})")
    return float(x)


def score(t: dict) -> float:
    i = t["I"]
    if isinstance(i, bool) or not isinstance(i, (int, float)) or not math.isfinite(i) or i < 0:
        raise InvalidData(f"I should be finite number ≥ 0 (received {i!r})")
    return float(i) / (_positive(t["E"], "E") * _positive(t["T"], "T"))


def prioritize(tasks: list) -> list:
    """Order by I/(E×T) descending; draw → less complexity; then original order (stable)."""
    keys = []
    for idx, t in enumerate(tasks):
        c = t.get("complexity", 0)
        if isinstance(c, bool) or not isinstance(c, (int, float)) or not math.isfinite(c):
            raise InvalidData("Invalid complexity")
        keys.append(((-round(score(t), 12), c, idx), t))
    return [t for _, t in sorted(keys, key=lambda x: x[0])]


def _range(v, name_):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0.0 <= v <= 1.0:
        raise InvalidData(f"{name_} out of range [0.1]: {v!r}")
    return float(v)


def control_quality(criteria: dict, thresholds=None, threshold=0.8) -> dict:
    """Each criterion must exceed ITS threshold (not averaged). DELIVER|REPROCESS."""
    if not criteria:
        raise InvalidData("without quality criteria")
    thresholds = thresholds or {}
    fail = {}
    for k, v in criteria.items():
        u = _range(thresholds.get(k, threshold), f"umbral:{k}")
        if _range(v, k) < u:
            fail[k] = {"value_": v, "threshold": u}
    return {"verdict": "REPROCESS" if fail else "DELIVER", "fail": fail,
            "minimo": min(criteria.values())}


def with_reproceso(generate, evaluate, max_cycles=3):
    """Reprocess cycle BOUNDED that really iterates (the original of NRE came out on the 1st round).
    generate(retro) → candidate; evaluate(candidate) → dict de control_quality. Return (candidateNone, history). None = did not achieve quality in max_cycles (fail-closed)."""
    if not isinstance(max_cycles, int) or max_cycles < 1:
        raise InvalidData("max_cycles must be integer ≥ 1")
    history, retro = [], None
    for cycle_ in range(1, max_cycles + 1):
        cand = generate(retro)
        cal = evaluate(cand)
        history.append({"cycle_": cycle_, **cal})
        if cal["verdict"] == "DELIVER":
            return cand, history
        retro = cal["fail"]
    return None, history


def p_truth(verdicts) -> float:
    """Operational probability of truth derived only from verdicts from registered sources.
    verdicts: list of states SUPPORTED/REFUTED/CONTRADICTED/UNDETERMINED (one per statement). No verifiable statements → 0.0 (no evidence, no presumption of truth)."""
    v = list(verdicts)
    if not v:
        return 0.0
    if any(x in ("REFUTED", "CONTRADICTED") for x in v):
        return 0.0
    return round(sum(x == "SUPPORTED" for x in v) / len(v), 4)


def choose_candidate(candidates: list):
    """Filter first (aligned and verified), then sort by p_truth × impact.
    Each candidate: {"aligned": bool, "verified": bool, "p_truth": [0.1], "impact": [0.1], ...}. Returns the chosen candidate or None if none passes the filter."""
    eligible = []
    for i, c in enumerate(candidates):
        if c.get("aligned") is not True or c.get("verified") is not True:
            continue
        eligible.append((-(_range(c.get("p_truth", 0.0), "p_truth") * _range(c.get("impact", 0.0), "impact")), i, c))
    if not eligible:
        return None
    eligible.sort(key=lambda x: (x[0], x[1]))
    return eligible[0][2]
