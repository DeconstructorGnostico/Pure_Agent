"""COMPILER of INTENTION · converts the implied intention into an explicit and verifiable SPECIFICATION (new layer of v3, between DOOR and FIREWALL).

spec = {objective, type_task, restrictions, data_criticalslot: {value, status}, missing,
        assumptions_declared, criteria_acceptance, risk, effects_external, tools_reading
state of each data: confirmed (literal in the instruction) · inferred (implicit reference, e.g. "mandal") · unknown (not appearing). If a CRITICAL data is missing → INCOMPLETE / NEED_INPUT with the missing list: the system does not invent. Use `decide` fail-closed (corrected numpy file). Extraction is deterministic and by pattern: does not understand the language (see limits in README).
"""
import re

from .decision import decide
from .root.firewall import AUTHORITY_DECLARED, EFFECT_EXTERNAL
from .root.normalization import normalize_text
from .root.useful import sha256

TYPES_TASK = ("QUERY", "ANALYSIS", "CALCULATION", "WRITING", "MESSAGE", "EFFECT_GENERICO")
V = r"\w*"
MESSAGE = re.compile(rf"\b(envi{V}|mand{V}|pas{V}selo|pas{V}sela|pasale|pasalo|reenvi{V}|remit{V}|compart{V}|"
                     rf"send|forward|share|email|e-mail|correo|whatsapp|escribele|notific{V}|avisa{V}|haz(le|selo)? llegar|hacer(le)? llegar|shoot|drop)\b")
WRITING = re.compile(r"\b(guarda\w*|escrib\w*|save|write|graba\w*|crea\w*)\b.{0,80}\b(archivo|fichero|file)\b")
WRITING_SLOTS = re.compile(r"(?:guarda\w*|escrib\w*|save|write|graba\w*|crea\w*)\s+[\"«']?(.+?)[\"»']?\s+(?:en|to|in|into)\s+"
                             r"(?:el\s+|the\s+|un\s+|a\s+)?(?:archivo|fichero|file)\s+([^\s,;]+)", re.IGNORECASE)
CALCULATION = re.compile(r"\b(calcula\w*|computa\w*|cuanto es|cuanto da|compute|calculate|how much is|what is)\b")
EXPR = re.compile(r"(?<![\w.])[-(]*\d[\d.\s]*(?:[-+*/x×%^]\s*[-(]*\s*\d[\d.\s]*\)*\s*)+")
ANALYSIS = re.compile(r"\b(analiza\w*|evalua\w*|compara\w*|resume\w*|resumen|revisa\w*|analyze|analyse|summarize|review|compare)\b")
DEST = re.compile(r"\b(?:a|al|para|to|con)\s+((?:[\w.+-]+@[\w-]+\.[\w.]+)|(?:(?:el|la|los|las|mi|mis|the|my)\s+)?[\w-]{2,}(?:\s+[A-ZÁÉÍÓÚ][\w-]+)?)",
                  re.UNICODE)
PRONOUN = re.compile(r"\b(\w+(?:lo|la|los|las|selo|sela|melo|mela)|esto|eso|aquello|it|this|that)\b")
EMPTY = {"el", "la", "los", "las", "un", "una", "a", "al", "de", "del", "por", "para", "con", "en", "y", "o", "the", "to",
          "of", "and", "my", "mi", "mis", "me", "te", "le", "les", "su", "sus", "correo", "email", "whatsapp", "mensaje",
          "please", "favor", "porfa", "ahora", "ya", "now", "gracias", "thanks", "thank", "you", "hazle", "hacerle",
          "llegar", "message", "shoot", "drop", "line", "note", "text"}
OBJECT_GENERICO = re.compile(rf"(?:{EFFECT_EXTERNAL})\s+(.{{3,}})")
QUERY_ABOUT = re.compile(r"^[¿¡\s]*(como|que es|que significa|explica\w*|por que|porque|what is|what does|how (do|to|does|can)|"
                            r"why|en que consiste|describe|cual es|cuales son|which|define)\b")


def _state_from(value_, confirmed):
    return {"value_": value_, "state": "confirmed" if confirmed else ("inferido" if value_ else "unknown")}


def _recipient(original):
    m = DEST.search(original)
    if not m:
        return None
    d = m.group(1).strip()
    if normalize_text(d) in EMPTY:
        return None
    return d


def compile_intent(instr, findings=()) -> dict:
    """instr: Instruction of SIPE. Returns the spec (dict) with your hash."""
    original, n = instr.original, instr.normalized
    from .sipe import COURTESY
    query = bool(QUERY_ABOUT.search(COURTESY.sub("", n.lstrip("¿¡ ")).lstrip("¿¡ ")))
    slots, critical, criteria, effects, reading = {}, [], [], [], []
    type_ = "QUERY"
    ce = re.compile(EFFECT_EXTERNAL)
    if not query and WRITING.search(n):
        type_ = "WRITING"
        m = WRITING_SLOTS.search(original)
        slots["content"] = _state_from(m.group(1).strip() if m else None, bool(m))
        slots["name_"] = _state_from(m.group(2).strip() if m else None, bool(m))
        critical = ["name_", "content"]
        effects = ["write_file"]
        criteria = ["act == write_file", "params_.name_ == spec.name_",
                     "params_.content == spec.content", "requires_authorization", "verification_post_ok"]
    elif not query and MESSAGE.search(n) and instr.class_action == "EFFECT":
        type_ = "MESSAGE"
        dest = _recipient(original)
        slots["recipient"] = _state_from(dest, bool(dest))
        rest = n
        for patron in (MESSAGE.pattern, r"\b(?:a|al|para|to|con)\s+" + re.escape(normalize_text(dest or "\x00"))):
            rest = re.sub(patron, " ", rest)
        words = [w for w in re.findall(r"[a-z0-9]+", rest) if w not in EMPTY]
        if words:
            slots["content"] = _state_from(" ".join(words), True)
        elif PRONOUN.search(n):
            slots["content"] = {"value_": "(referente implícito: «lo/esto»)", "state": "inferido"}
        else:
            slots["content"] = _state_from(None, False)
        critical = ["recipient", "content"]
        effects = ["send_message"]
        criteria = ["act == send_message", "params_.for_ == spec.recipient", "requires_authorization",
                     "verification_post_ok"]
    elif not query and instr.class_action == "EFFECT" and ce.search(n):
        type_ = "EFFECT_GENERICO"
        m = OBJECT_GENERICO.search(n)
        obj = None
        if m:
            obj = " ".join(w for w in re.findall(r"[a-z0-9]+", m.group(1)) if w not in EMPTY) or None
        slots["object_"] = _state_from(obj, bool(obj))
        critical = ["object_"]
        verb = ce.search(n).group(0)
        effects = [f"efecto:{verb}"]
        criteria = ["without_execution_without_capacity_real", "requires_authorization"]
    elif CALCULATION.search(n) and EXPR.search(original.replace("×", "*")):
        type_ = "CALCULATION"
        expr = EXPR.search(original.replace("×", "*")).group(0).strip()
        slots["expression"] = _state_from(expr, True)
        critical = ["expression"]
        reading = ["calcular"]
        criteria = ["act == calcular", "params_.expression == spec.expression", "result_verified"]
    elif re.search(r"\b(calcula\w*|computa\w*|compute|calculate)\b", n):
        type_ = "CALCULATION"
        slots["expression"] = _state_from(None, False)
        critical = ["expression"]
        reading = ["calcular"]
        criteria = ["result_verified"]
    else:
        type_ = "ANALYSIS" if ANALYSIS.search(n) else "QUERY"
        criteria = ["without_actions_with_effect", "without_fabrication", "response_no_empty",
                     "affirmations_without_source_marked"]
    data_ = {k: v["state"] for k, v in slots.items()}
    d = decide(data_, critical) if data_ else None
    missing_items = d.missing_items if d else []
    authority = bool(re.search(AUTHORITY_DECLARED, n))
    risk = "alto" if effects or authority or any(h in ("effect_external",) for h in findings) else \
        ("medio" if findings else "bajo")
    spec = {
        "target": instr.target,
        "type_task": type_,
        "restrictions": list(instr.restrictions),
        "data_critical": slots,
        "criticos": critical,
        "missing_items": missing_items,
        "assumptions_declared": d.assumptions if d else [],
        "decision": d.mode if d else "EXECUTE",
        "criteria_acceptance": criteria,
        "riesgo": risk,
        "effects_external": effects,
        "tools_reading": reading,
        "state": "INCOMPLETE" if missing_items else "COMPLETE",
    }
    spec["id"] = "spec-" + sha256(spec)[:16]
    return spec


def _contains(a, b) -> bool:
    fa = re.sub(r"\s+", "", normalize_text(str(a)).replace("×", "*").replace("x", "*"))
    fb = re.sub(r"\s+", "", normalize_text(str(b)).replace("×", "*").replace("x", "*"))
    return bool(fa) and bool(fb) and (fa in fb or fb in fa)


def _tokens(t):
    return {w for w in re.findall(r"[a-z0-9]+", normalize_text(str(t))) if w not in EMPTY}


def _matches(param, action_value, spec_value) -> bool:
    """Strict coincidence: expressions by standardized form; texts by tokens with content
    (one subset of the other). Avoid 'la' 'coincinding' with 'the manager' or 'evil@x.com' with 'juan@x.com'."""
    if param == "expression":
        return _contains(action_value, spec_value)
    a, b = _tokens(action_value), _tokens(spec_value)
    return bool(a) and bool(b) and (a <= b or b <= a)


def evaluate_action_against_spec(spec, tool, params_, texts_data=()) -> dict:
    """Is the proposed action ROOTED in the intent of the user and meets the spec?
    Returns {rooted, origin, motif, mode, assumptions}. origin USER_INTENT  EVIDENCE  MODEL."""
    allowed_items = set(spec["effects_external"]) | set(spec["tools_reading"])
    # Where do the values of the action come from? (external data → EVIDENCE; nothing → MODEL)
    values_ = [str(v) for v in params_.values() if v not in (None, "")]
    in_data = any(_contains(v, t) for v in values_ for t in texts_data if len(normalize_text(v)) >= 3)
    if tool not in allowed_items:
        return {"rooted": False, "origin": "EVIDENCE" if in_data else "MODEL",
                "reason": f"ORPHAN_ACTION: '{tool}' does not derive from intent ({spec['type_task']})",
                "mode": "BLOCK", "assumptions": []}
    data_, assumptions = {}, []
    map_ = {"send_message": {"for_": "recipient"}, "write_file": {"name_": "name_", "content": "content"},
            "calcular": {"expression": "expression"}}.get(tool, {})
    for p, slot in map_.items():
        s = spec["data_critical"].get(slot, {})
        v = params_.get(p)
        if v in (None, ""):
            data_[p] = "unknown"
        elif s.get("state") == "confirmed":
            if not _matches(p, v, s["value_"]):
                return {"rooted": False, "origin": "EVIDENCE" if in_data else "MODEL",
                        "reason": f"VIOLATES_SPEC: {p}={v!r} does not coincide with the intention ({slot}={s['value_']!r})",
                        "mode": "BLOCK", "assumptions": []}
            data_[p] = "confirmed"
        else:
            data_[p] = "inferido"
    for p, v in params_.items():
        if p not in map_:
            data_[p] = "inferido" if v not in (None, "") else "unknown"
    d = decide(data_, list(map_) or list(params_))
    return {"rooted": True, "origin": "USER_INTENT", "reason": "", "mode": d.mode, "assumptions": d.assumptions}


def verify_criteria(spec, out) -> dict:
    """Verifier FINAL against the spec acceptance criteria (not just structure)."""
    res = {}
    pend = out.get("pending", [])
    for c in spec["criteria_acceptance"]:
        if c.startswith("act == "):
            h = c.split("== ")[1]
            res[c] = bool(pend) and all(p["tool"] == h for p in pend)
        elif c.startswith("params_."):
            p, slot = c[len("params_."):].split(" == spec.")
            s = spec["data_critical"].get(slot, {})
            res[c] = bool(pend) and all(s.get("state") != "confirmed" or _matches(p, x["params_"].get(p, ""), s["value_"])
                                        for x in pend)
        elif c == "requires_authorization":
            res[c] = all(x["state"] != "COMMITTED" or out.get("_authorized") for x in pend
                         if x["tool"] in ("send_message", "write_file"))
        elif c == "verification_post_ok":
            res[c] = None if not any(x["state"] == "COMMITTED" for x in pend) else \
                ("PROVEN" in (out.get("verification") or ""))
        elif c == "result_verified":
            res[c] = out.get("result_verified") is not None
        elif c == "without_actions_with_effect":
            res[c] = not any(x["tool"] in ("send_message", "write_file") for x in pend)
        elif c == "without_fabrication":
            res[c] = out.get("decision") != "HALT" or "INV-R04" not in (out.get("reason") or "")
        elif c == "response_no_empty":
            res[c] = bool((out.get("response") or "").strip())
        elif c == "affirmations_without_source_marked":
            res[c] = all(h.get("sources") for h in out.get("facts", []))
        elif c == "without_execution_without_capacity_real":
            res[c] = not any(x["state"] == "COMMITTED" for x in pend)
        else:
            res[c] = None
    return res
