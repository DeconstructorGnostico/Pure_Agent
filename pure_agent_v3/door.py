"""DOOR of INPUT STRICT (idea of AGENT_HARDENED_CORE_V2, corrected).

* Text or mode mode JSON with schema ESTRICTO: exact types, no extra fields, maximum sizes.
* List CLOSED of permitted tasks; the declared task must match the compiled intent
  (a shipment cannot be entered within a ‘consultation’).
* Structured output {state: okerrorincomplete, type, result, details}; errors separate
  FORMAT (the input does not meet the schema) of SECURITY (firewall, HALT, task not allowed).
* Internal failure = failure-closed: internal error/type_ status and nothing is executed.
* does not use blacklist by sub-strings (had false positives as "ignorance" and allowed to pass "1gn0ra" or
  ‘do as if there were no rules’ means the safety is decided by the normalized firewall of the agent.
* The rule ‘do not interpret implicit intention’ is not adopted as follows: it is replaced by the COMPILER of
  INTENTION (the intention becomes explicit or the result is INCOMPLETE / NEED_INPUT).
"""
import json

TASKS_ALLOWED = ("consulta", "analisis", "summary", "calculo", "write_file", "send_message")
TYPES_BY_TASK = {"consulta": {"QUERY", "ANALYSIS"}, "analisis": {"ANALYSIS", "QUERY"},
                   "summary": {"ANALYSIS", "QUERY"}, "calculo": {"CALCULATION"},
                   "write_file": {"WRITING"}, "send_message": {"MESSAGE"}}
FIELDS = {"task": str, "input_": str, "data_": list, "evidence": list, "context": dict, "restrictions": list}
MANDATORY = ("task", "input_")
MAX_JSON = 200_000
MAX_INPUT = 20_000


class FormatError(ValueError):
    pass


def _about(state, type_, result=None, **details):
    return {"state": state, "type_": type_, "result": result, "details": details}


def validate_schema(obj) -> dict:
    if not isinstance(obj, dict):
        raise FormatError("the entry JSON must be an object")
    extra = sorted(set(obj) - set(FIELDS))
    if extra:
        raise FormatError(f"fields not allowed: {extra}")
    for k in MANDATORY:
        if k not in obj:
            raise FormatError(f"Required field '{k}' is missing")
    for k, t in FIELDS.items():
        if k in obj and (type(obj[k]) is not t):
            raise FormatError(f"'{k}' must be {t.__name__}")
    if not obj["input_"].strip() or len(obj["input_"]) > MAX_INPUT:
        raise FormatError(f"empty or greater than {MAX_INPUT} characters")
    if "\x00" in obj["input_"]:
        raise FormatError("'entry' contains null bytes")
    data_ = obj.get("data_", [])
    if len(data_) > 20 or any(type(d) is not str or len(d) > 5000 for d in data_):
        raise FormatError("'data' must be a list of ≤20 texts of ≤5000 characters")
    rs = obj.get("restrictions", [])
    if len(rs) > 50 or any(type(r) is not str or len(r) > 300 for r in rs):
        raise FormatError("'restrictions' must be a list of ≤50 texts of ≤300 characters")
    ctx = obj.get("context", {})
    if len(ctx) > 50 or any(type(v) is not str or len(v) > 5000 for v in ctx.values()):
        raise FormatError("'context' must be the subject of ≤50 texts")
    ev = obj.get("evidence", [])
    permit_ev = {"source", "claim_id", "content", "polarity"}
    if len(ev) > 100 or any(type(e) is not dict or set(e) - permit_ev or type(e.get("content", "")) is not str
                            or e.get("polarity", "positive") not in ("positive", "negative") for e in ev):
        raise FormatError("'evidence' must be list of ≤100 objects {source, claim_id, content, polarity}")
    return obj


class Door:
    def __init__(self, agent):
        self.agent = agent

    def enter_json(self, raw) -> dict:
        try:
            if isinstance(raw, (bytes, str)):
                if len(raw) > MAX_JSON:
                    raise FormatError("JSON too big")
                try:
                    obj = json.loads(raw)
                except ValueError as e:
                    raise FormatError(f"JSON malformed ({type(e).__name__})") from None
            else:
                obj = raw
            obj = validate_schema(obj)
        except FormatError as e:
            return _about("error", "formato", None, reason=str(e), executed=False)
        if obj["task"] not in TASKS_ALLOWED:
            return _about("error", "seguridad", None, reason=f"not allowed: {obj['task']!r}",
                          allowed_items=list(TASKS_ALLOWED), executed=False)
        return self._execute(obj["input_"], obj["task"], obj.get("data_", []), obj.get("evidence", []),
                              obj.get("context", {}), obj.get("restrictions", []))

    def enter_text(self, text) -> dict:
        if type(text) is not str or not text.strip() or len(text) > MAX_INPUT or "\x00" in text:
            return _about("error", "formato", None, reason="empty text, not textual, with null or too long bytes",
                          executed=False)
        return self._execute(text, None, [], [], {}, [])

    def _execute(self, input_, task, data_, evidence, context, restrictions) -> dict:
        try:
            if task is not None:
                from .intent import compile_intent
                from .sipe import compile_
                spec = compile_intent(compile_(input_, data_))
                if spec["type_task"] not in TYPES_BY_TASK[task]:
                    return _about("error", "seguridad", None, executed=False,
                                  reason=f"the declared task '{task}' does not correspond to the intention "
                                         f"compilada ({spec['type_task']})")
            out = self.agent.process(input_, data_, evidence=evidence, context=context,
                                       restrictions=restrictions)
        except Exception as e:  # failure-closed: an internal failure never executes anything
            try:
                self.agent.audit_log.register("DOOR_FAILURE_INTERNAL", error=type(e).__name__, state_after="REJECTED")
            except Exception:
                pass
            return _about("error", "interno", None, reason=f"internal failure ({type(e).__name__}): failure-closed",
                          executed=False)
        return self.translate(out, task)

    @staticmethod
    def translate(out, task=None) -> dict:
        dec = out.get("decision")
        type_ = (out.get("spec") or {}).get("type_task", task or "unknown").lower()
        base = {"request_id": out.get("request_id"), "decision": dec, "audit_log_ok": out.get("audit_log", {}).get("ok")}
        if dec == "HALT":
            return _about("error", "seguridad", None, reason=out.get("reason"), **base)
        if dec == "REJECT":
            fw = out.get("firewall", {})
            security = fw.get("decision") == "REJECT" or "INV" in (out.get("reason") or "") or \
                "ORPHAN" in (out.get("reason") or "") or "VIOLATES_SPEC" in (out.get("reason") or "")
            return _about("error", "seguridad" if security else "rechazo", None, reason=out.get("reason"), **base)
        if dec == "NEED_INPUT":
            return _about("incompleto", type_, None, missing_items=(out.get("spec") or {}).get("missing_items", []),
                          reason=out.get("reason"), **base)
        res = {"response": out.get("response"), "result_verified": out.get("result_verified"),
               "pending": out.get("pending", []), "verification": out.get("verification"),
               "criteria": out.get("criteria")}
        return _about("ok", type_, res, reason=out.get("reason"),
                      assumptions=[s for p in out.get("pending", []) for s in p.get("assumptions", [])], **base)
