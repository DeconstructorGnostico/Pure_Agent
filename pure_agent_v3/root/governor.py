"""Governor EXTERNAL: orchestrate the complete architecture of the Root Layer (§23).

LAYER ROAD → CONTROLLER → FIREWALL SEMANTIC → VALIDATION MULTICAPA → MODEL → PROPOSAL → VERIFIER → AUTORIZADOR → EXECUTOR → VERIFICATION POST → PERSISTENCE → AUDIT → STATE NEW → SIGUIENTE CYCLE.
"""
import re
from dataclasses import dataclass, field

from . import padding
from .audit_log import Audit
from .changes import ChangeProtocol
from .layers import Layer, Conflict, Directive, Escalacion, Hierarchy
from .cycle_ import ControlCycle
from .controller import Controller
from .states import State as E, Machine, InvalidTransition, derive
from .evidence import EXTERNAL_EVIDENCE, MODEL_CLAIM, rule
from .firewall import (TOOL, INJECTION, MODEL, USER, Segment, affirmations_of_state,
                       analyze, wrap_data, scan)
from .tools import Executor, hash_action
from .memory import Memory
from .model_ import (TYPES, TYPES_OF_MODEL, Statement, ProposedChange, ModelContext,
                     Proposal, ActionRequest)
from .root import hash_root
from .report import format_
from .roles import Artifact, Keyring
from .useful import Clock, sha256

FABRICATION = re.compile(
    r"\b(ya )?(envie|mande|reenvie|comparti|ejecute|publique|borre|elimine|guarde|persisti|transferi|pague|"
    r"compre|use la herramienta|consulte la herramienta|he (enviado|mandado|ejecutado|publicado|borrado|"
    r"eliminado|guardado|usado|consultado|persistido|transferido|pagado)|lo (envie|mande|guarde|ejecute)|"
    r"i (sent|executed|ran|saved|deleted|posted|stored)|i have (sent|executed|run|saved|deleted|posted|stored))\b")

POLICIES_BY_DEFAULT = {
    "tools_allowed": [],
    "auto_authorize_only_reading": True,
    "zero_padding": True,
}


@dataclass
class Request:
    text: str
    attachments: list = field(default_factory=list)       # Segment(DATA|TOOL, ...)
    directives: list = field(default_factory=list)     # (Capa, key, value)
    identity_declared: str | None = None             # provenance, never permission
    target: str | None = None


@dataclass
class Pending:
    id: str
    request_id: str
    tool: str
    params_: dict
    hash: str
    machine: Machine
    state: str = "PENDING_AUTHORIZATION"
    assumptions: list = field(default_factory=list)
    decision: str = ""


@dataclass
class Result:
    request_id: str
    state: str
    response: str = ""
    reason: str = ""
    verdicts: list = field(default_factory=list)
    pending: list = field(default_factory=list)
    changes: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    layers_validation: dict = field(default_factory=dict)
    execution_request: bool = False
    history: list = field(default_factory=list)
    output_tool: object = None
    report: str = ""


class Governor:
    def __init__(self, model_, verifiers=(), tools=(), policies=None, clock=None,
                 max_cycles=100, max_reject_streak=3, path_audit=None, path_memory=None,
                 audit_log=None, zero_trust=None, evaluator_action=None):
        self.clock = clock or Clock()
        self.keyring = Keyring()
        self.model_ = model_
        self.keyring.register(model_.id, "MODEL")                       # without a signatory
        self._f_validator = self.keyring.register("validator-multicapa", "VALIDATOR")
        self._f_post = self.keyring.register("verifier-post", "VERIFIER")
        self._f_verif = {}
        for v in verifiers:
            self._f_verif[v.id] = self.keyring.register(v.id, "VERIFIER")  # Model (INV-R08)
        self.verifiers = list(verifiers)
        self.controller = Controller(self.keyring.register("controller-external", "AUTHORIZER"),
                                       self.clock)
        self.tools = {h.name_: h for h in tools}
        self._executor = Executor(self.keyring.register("executor-sandbox", "EXECUTOR"),
                                  self.tools)
        self.memory = Memory(self.keyring.register("persistence", "PERSISTENCE"), path_memory)
        self.keyring.register("auditor", "AUDITOR")
        self.audit_log = audit_log if audit_log is not None else Audit(self.clock, path_audit)
        self.zero_trust = zero_trust          # None = no Zero-Trust layer (compatibility v2)
        self.evaluator_action = evaluator_action  # decide() fail-closed per action (v3)
        self.policies = dict(POLICIES_BY_DEFAULT, **(policies or {}))
        self.hierarchy = Hierarchy()
        for k, v in self.policies.items():
            self.hierarchy.apply(Directive(Layer.G3_POLICIES, k, v, "CONTROLLER"))
        self.hierarchy.seal()
        self.changes = ChangeProtocol(self.policies, self.keyring, self.audit_log, self.clock, model_.id)
        self.cycle_ = ControlCycle(max_cycles, max_reject_streak)
        self._hash_root = hash_root()
        self.halted = False
        self.halt_reason = None
        self.pending: dict[str, Pending] = {}
        self._nonces: set = set()
        self._n = 0
        self.audit_log.register("GENESIS", state_after="IDLE", model_id=model_.id,
                                 model_version=getattr(model_, "version", None),
                                 context_hash=self._hash_root)

    # ------------------------------------- -------------------------------------------------------------------- utilities
    def _id(self, pref):
        self._n += 1
        return f"{pref}-{self._n:04d}"

    def _machine(self, rid):
        def cb(a, b, reason):
            self.cycle_.state_events.append((rid, a.value, b.value, reason))
            self.audit_log.register("TRANSITION", request_id=rid, state_before=a.value,
                                     state_after=b.value, error=reason or None,
                                     halt_reason=reason if b == E.HALTED else None)
        return Machine(self.keyring, cb)

    def _integrity(self) -> tuple[bool, str]:
        if hash_root() != self._hash_root:
            return False, "INV-R00: Root Layer hash changed"
        ok, msg = self.audit_log.verify()
        if not ok:
            return False, f"INV-R05: altered audit chain ({msg})"
        return True, "OK"

    def _halt(self, m, res: Result, reason: str) -> Result:
        m.force_halt(reason)
        self.halted, self.halt_reason = True, reason
        res.state, res.reason = E.HALTED.value, reason
        return self._close(m, res)

    def _close(self, m, res: Result, metrics=None) -> Result:
        res.history = list(m.history)
        if not self.halted:
            rationale = self.cycle_.close_(res.state, metrics or {})
            if rationale:
                self.halted, self.halt_reason = True, rationale
                self.audit_log.register("HALT", request_id=res.request_id, halt_reason=rationale,
                                         state_before=res.state, state_after="HALTED")
                res.reason = (res.reason + " · " if res.reason else "") + f"HALT: {rationale}"
        else:
            self.cycle_.omega_history.append({"cycle": self.cycle_.cycle, "state": res.state})
        res.report = self._report(res)
        return res

    # ----------------------------------------------------- Main Cycle
    def process(self, sol: Request) -> Result:
        rid = self._id("req")
        res = Result(rid, E.IDLE.value)
        m = self._machine(rid)
        self._target = sol.target or sol.text[:80]
        if self.halted:
            res.state = E.HALTED.value
            res.reason = f"system stopped ({self.halt_reason}); controller required RESET"
            res.report = self._report(res)
            return res
        rationale = self.cycle_.start()
        if rationale:
            return self._halt(m, res, f"INV-R10 · {rationale}")
        ok, msg = self._integrity()
        if not ok:
            return self._halt(m, res, msg)
        try:
            return self._process(sol, rid, res, m)
        except InvalidTransition as e:
            return self._halt(m, res, f"INV-R09: {e}")

    def _process(self, sol, rid, res, m):
        m.go(E.INGESTING)
        segs = [Segment(USER, sol.text)] + list(sol.attachments)
        fw = analyze(segs)
        res.findings = [(h.origin, h.category, h.fragment) for h in fw.findings]
        res.execution_request = fw.request_execution
        self.audit_log.register("INGEST", request_id=rid, input_hash=sha256(sol.text),
                                 context_hash=sha256([s.text for s in sol.attachments]),
                                 identity_declared=sol.identity_declared,
                                 authority_declared=fw.authority_declared,
                                 execution_request=fw.request_execution)
        # User directives: hierarchy G0..G7 (inferior does not invalidate superior)
        for layer, key_, value_ in sol.directives:
            try:
                self.hierarchy.apply(Directive(Layer(layer), key_, value_, USER))
            except Escalacion as e:
                res.violations.append(("INV-R07", str(e), False))
            except Conflict as e:
                res.violations.append(("HIERARCHY", str(e), False))
        if fw.injection_in(USER):
            cats = sorted(fw.categories(USER) & set(INJECTION))
            res.violations.append(("INV-R07/§20", f"injection attempt in instruction: {cats}", False))
        if res.violations:
            m.go(E.REJECTED, reason="; ".join(v[1] for v in res.violations))
            res.state, res.reason = E.REJECTED.value, res.violations[0][1]
            return self._close(m, res)
        quarantine = [s for s in sol.attachments if s in fw.quarantine]
        if quarantine:
            m.go(E.FILTERED, reason=f"{len(quarantine)} quarantine data segment(s)")
        m.go(E.VALIDATING)
        m.go(E.PROCESSING)
        ctx = ModelContext(
            instruction=sol.text,
            data_=tuple(wrap_data(s, s in quarantine) for s in sol.attachments),
            policies_visible=tuple(sorted(self.policies.get("tools_allowed", []))),
            request_id=rid)
        try:
            prop = self.model_.propose(ctx)
        except Exception as e:  # fail-closed
            m.go(E.UNCERTAIN, reason=f"model failed: {e}")
            res.state, res.reason = E.UNCERTAIN.value, f"model failed ({type(e).__name__})"
            return self._close(m, res)
        if isinstance(prop, str):
            prop = Proposal(text=prop)
        m.go(E.PROPOSED)
        layers, viol, info = self._validate(prop)
        res.layers_validation, res.violations = layers, viol
        self.audit_log.register(
            "VALIDATION", request_id=rid, model_id=self.model_.id,
            model_version=getattr(self.model_, "version", None),
            invariants_checked=sorted(self._invariants_reviewed()),
            validation_results=layers, proposal=sha256(repr(prop)),
            error="; ".join(v[1] for v in viol) or None)
        critical_items = [v for v in viol if v[2]]
        if critical_items:
            return self._halt(m, res, f"{critical_items[0][0]}: {critical_items[0][1]}")
        if viol:
            m.go(E.REJECTED, reason=viol[0][1])
            res.state, res.reason = E.REJECTED.value, f"{viol[0][0]}: {viol[0][1]}"
            return self._close(m, res)
        if info["inexistentes"] or info["missing_items"]:
            parts = []
            if info["inexistentes"]:
                parts.append(f"no actual capacity exists for {info['inexistentes']}: NOT SIMULATED")
            if info["missing_items"]:
                parts.append(f"REQUEST PARAMETER: {info['missing_items']}")
            m.go(E.UNCERTAIN, reason="; ".join(parts))
            res.state, res.reason = E.UNCERTAIN.value, "; ".join(parts)
            return self._close(m, res)
        if res.execution_request and not prop.actions:
            m.go(E.UNCERTAIN, reason="EXECUTION_REQUEST without identifiable action")
            res.state = E.UNCERTAIN.value
            res.reason = "IMPLEMENTATION → EXECUTION_REQUEST: no action identified (REQUEST PARAMETER)"
            return self._close(m, res)
        # VERIFIER: affirmations → external evidence or MODEL_CLAIM
        res.verdicts = [rule(a, self.verifiers, self._f_verif, self.keyring)
                          for a in prop.affirmations]
        contradicted = [d for d in res.verdicts if d.truth == "CONTRADICTED"]
        res.response = self._annotate(info["text"], res.verdicts, info["claims"])
        art_valid = self._f_validator.issue("VALID", sha256(repr(prop)), layers=str(layers))
        m.go(E.VERIFIED, art_valid, reason="multilayer validation exceeded")
        metrics = self._metrics(res, info)
        # Proposed changes → CHANGE_PROPOSAL (never applicable here)
        for c in prop.changes:
            res.changes.append(self.changes.propose(c, proposer=self.model_.id))
        # Actions → PENDING_AUTHORIZATION (or permanent authorization of the controller if read only)
        if prop.actions:
            m.without_effects = False
            for a in prop.actions:
                p = Pending(self._id("act"), rid, a.tool, dict(a.params_),
                              hash_action(a.tool, a.params_), derive(m))
                self.pending[p.id] = p
                h = self.tools[a.tool]
                auto = True
                if self.evaluator_action is not None:
                    mode, p.assumptions = self.evaluator_action(p, sol)
                    p.decision = mode
                    auto = mode == "EXECUTE"      # read only runs on its own only if everything critical is confirmed
                    if mode.startswith("BLOCK"):  # v3: orphan action or violation of the spec of intent
                        p.state = E.REJECTED.value
                        res.findings.append(("NEXUS", "action_blocked", mode[:200]))
                        self.audit_log.register("ACTION_BLOCKED", request_id=rid, error=mode[:300],
                                                 state_after="REJECTED", act=p.id, tool=a.tool)
                        res.pending.append(p)
                        continue
                if not h.effect_external and auto and self.policies.get("auto_authorize_only_reading"):
                    tok = self.controller.authorize(p, approved_by="permanent policy: read only")
                    r = self.execute_(p.id, tok)
                    res.output_tool = r.output_tool
                    res.findings += r.findings
                    p.state = r.state
                res.pending.append(p)
            open_ = [p for p in res.pending if p.state == "PENDING_AUTHORIZATION"]
            if open_:
                res.state = "PENDING_AUTHORIZATION"
                res.reason = f"{len(open_)} action(s) with effect expect token from external controller"
                return self._close(m, res, metrics)
            if not all(p.state == "COMMITTED" for p in res.pending):
                final = next(p.state for p in res.pending if p.state != "COMMITTED")
                if self.halted:
                    res.state = E.HALTED.value
                    return self._close(m, res, metrics)
                block = [p.decision for p in res.pending if p.decision.startswith("BLOCK")]
                m.go(E.UNCERTAIN if final == "UNCERTAIN" else E.REJECTED, reason=f"action ended in {final}")
                res.state, res.reason = final, (block[0].split(":", 1)[1].strip() if block else
                                                 f"the action ended in {final}; does not commit")
                return self._close(m, res, metrics)
            res.state = "COMMITTED"
            m.without_effects = True
        if res.changes and not prop.actions:
            res.state = "CHANGE_PROPOSAL"
            res.reason = "; ".join(f"{c['id']}={c['state']}" for c in res.changes)
            return self._close(m, res, metrics)
        # Failure-closed on unproven facts; do not confuse structural VERIFIED with truth.
        no_demonstrated = [d for d in res.verdicts if d.truth != "SUPPORTED"]
        if no_demonstrated and not prop.actions:
            self._learn(prop, res.verdicts)
            m.go(E.UNCERTAIN, reason="not all facts are externally proven")
            res.state = E.UNCERTAIN.value
            res.reason = "non-exceeded factual verification: " + ", ".join(d.truth for d in no_demonstrated)
            return self._close(m, res, metrics)
        # LEARN selectivo + PERSIST + COMMIT
        if contradicted:
            res.reason = "Contradictory external evidence: you don't learn"
        self._learn(prop, res.verdicts)
        art = self.memory.persist({"type_": "response", "request_id": rid,
                                      "response_hash": sha256(res.response)})
        if m.state == E.VERIFIED:
            m.go(E.COMMITTED, art, reason="compromised response")
        if not prop.actions:
            res.state = E.COMMITTED.value
        return self._close(m, res, metrics)

    # ------------------------------------ multilayer validation (§6, §7)
    def _validate(self, prop):
        layers = {k: True for k in ("STRUCTURE_OK", "SEMANTICS_OK", "LOGIC_OK", "POLICY_OK",
                                   "INVARIANTS_OK", "AUTHORIZATION_OK", "STATE_INTEGRITY_OK")}
        viol = []
        info = {"inexistentes": [], "missing_items": [], "claims": [], "text": "", "noise": 0}

        def fails(layer, inv, msg, critical=False):
            layers[layer] = False
            viol.append((inv, msg, critical))

        # 1 STRUCTURAL
        if not isinstance(prop, Proposal):
            fails("STRUCTURE_OK", "STRUCTURE", f"the output of the model is not a Proposal ({type(prop).__name__})")
            return layers, viol, info
        core_types = [(prop.affirmations, Statement), (prop.actions, ActionRequest), (prop.changes, ProposedChange)]
        for list_, cls in core_types:
            if not isinstance(list_, list) or any(not isinstance(x, cls) for x in list_):
                fails("STRUCTURE_OK", "STRUCTURE", f"invalid elements (expected {cls.__name__})")
        for a in prop.affirmations if layers["STRUCTURE_OK"] else []:
            if a.type_ not in TYPES:
                fails("STRUCTURE_OK", "INV-05", f"type of statement unknown: {a.type_}")
        if not layers["STRUCTURE_OK"]:
            return layers, viol, info
        # 2 SEMANTIC (the text of the model also passes through the firewall)
        text = prop.text or ""
        if self.policies.get("zero_padding"):
            text, info["noise"] = padding.clean(text)
        info["text"] = text
        cats = {h.category for h in scan(text, MODEL)} & set(INJECTION)
        if cats:
            fails("SEMANTICS_OK", "INV-R07", f"the output of the model tries {sorted(cats)}")
        info["claims"] = affirmations_of_state(text)
        # 3 LOGIC: Internal Contradictions
        seen_ = {}
        for a in prop.affirmations:
            if a.proposition:
                if a.proposition in seen_ and seen_[a.proposition] != a.value_:
                    fails("LOGIC_OK", "LOGIC", f"internal contradiction in '{a.proposition}'")
                seen_[a.proposition] = a.value_
        # 4 POLICY: availability • permission; not improvising tools
        allowed_items = set(self.policies.get("tools_allowed", []))
        for a in prop.actions:
            h = self.tools.get(a.tool)
            if h is None:
                info["inexistentes"].append(a.tool)
                continue
            if a.tool not in allowed_items:
                fails("POLICY_OK", "§13", f"tool '{a.tool}' available but not allowed")
            falt = [p for p in h.params_required if a.params_.get(p) in (None, "")]
            if falt:
                info["missing_items"].append(f"{a.tool}:{','.join(falt)}")
        # 5 INVARIANTS
        if prop.artifacts:
            fails("INVARIANTS_OK", "INV-R02/R03",
                  "the model attached own authority/evidence artifacts (falsification)", True)
        for a in prop.actions:
            if a.authorization_ is not None:
                fails("INVARIANTS_OK", "INV-R02", f"the model tries to self-authorize '{a.tool}'", True)
        for c in prop.changes:
            if c.apply_direct:
                fails("INVARIANTS_OK", "INV-R00", f"the model tries to apply '{c.target}' without protocol", True)
        from .normalization import normalize_text
        if prop.tools_used_declared or prop.persistence_declared or FABRICATION.search(normalize_text(text)):
            fails("INVARIANTS_OK", "INV-R04",
                  "the model states that there is executed/usado/persistido something without receipt from the executor")
        # 6 AUTHORISATION: proposal is not authorized; actions remain pending.
        # 7 STATE
        ok, msg = self._integrity()
        if not ok:
            fails("STATE_INTEGRITY_OK", "INV-R09", msg, True)
        return layers, viol, info

    def _invariants_reviewed(self):
        return {"INV-R00", "INV-R01", "INV-R02", "INV-R03", "INV-R04", "INV-R05", "INV-R06",
                "INV-R07", "INV-R08", "INV-R09", "INV-R10"}

    def _annotate(self, text, verdicts, claims):
        notes = []
        if claims:
            notes.append(f"[MODEL_CLAIM {claims}: is model text only · VERIFICATION = NOT PROVEN]")
        for d in verdicts:
            notes.append(f"[{d.class_} · {d.truth} · {d.verification}] {d.content}")
        if not verdicts and not claims:
            notes.append("[MODEL_CLAIM: model text; not external evidence]")
        return text + ("\n" + "\n".join(notes) if notes else "")

    def _metrics(self, res, info):
        """§22 Structural syntropy: only metrics, not a physical guarantee."""
        n = len(res.verdicts) or 1
        return {"contradictions": sum(d.truth == "CONTRADICTED" for d in res.verdicts),
                "noise_deleted": info["noise"],
                "trazabilidad": round(sum(d.class_ == EXTERNAL_EVIDENCE for d in res.verdicts) / n, 2)}

    def _learn(self, prop, verdicts):
        """§8 LEARN selective: only what has external evidence enters SUPPORTED."""
        by_content = {d.content: d for d in verdicts}
        for d in verdicts:
            c = self.memory.candidate(d.content, "afirmación")
            if self.memory.validate(c, d):
                self.memory.persist({"type_": "learning", "content": d.content})
        for text in prop.memory:
            c = self.memory.candidate(text, "model_")
            if self.memory.validate(c, by_content.get(text)):
                self.memory.persist({"type_": "learning", "content": text})

    # --------------------- Execution (§13, §16).
    def execute_(self, pending_id: str, token) -> Result:
        p = self.pending.get(pending_id)
        rid = p.request_id if p else pending_id
        res = Result(rid, E.REJECTED.value)
        if p is None:
            res.reason = "non-existent action"
            res.report = self._report(res)
            return res
        m = p.machine
        if self.halted:
            res.state, res.reason = E.HALTED.value, f"system stopped: {self.halt_reason}"
            res.report = self._report(res)
            return res
        if p.state != "PENDING_AUTHORIZATION":
            res.reason = f"the action is already in {p.state}"
            res.report = self._report(res)
            return res
        try:
            return self._execute(p, m, token, res)
        except InvalidTransition as e:
            return self._halt(m, res, f"INV-R09: {e}")

    def _execute(self, p, m, token, res):
        res.pending = [p]
        ok, msg = self._integrity()
        if not ok:
            return self._halt(m, res, msg)
        if hash_action(p.tool, p.params_) != p.hash:
            return self._halt(m, res, "INV-R09: altered action parameters after proposing")
        if token is None:
            res.state, res.reason = "PENDING_AUTHORIZATION", "without authorization: No EXECUTION"
            res.report = self._report(res)
            return res
        if not isinstance(token, Artifact) or not self.keyring.verify(token, "AUTHORIZER", "AUTHORIZED"):
            p.state = E.HALTED.value
            return self._halt(m, res, "INV-R02: token of false authorization or not issued by the controller")
        if token.subject != p.hash or token.datum("ticket") != p.id:
            reason = "token does not correspond to this acción/parámetros"
        elif token.datum("nonce") in self._nonces:
            reason = "token already used (replay)"
        elif token.datum("expires", 0) < self.clock.now_():
            reason = "Token expired"
        elif p.tool not in self.policies.get("tools_allowed", []):
            reason = "the policy no longer allows this tool"
        elif self.zero_trust is not None and not (
                self.zero_trust.allowed(token.issuer, "AUTHORIZE:" + p.tool)
                and self.zero_trust.allowed(self._executor._f.main, "EXECUTE:" + p.tool)):
            reason = "Zero-Trust: no explicit concession (I12 PRIVILEGE_MUST_BE_EXPLICIT)"
        else:
            reason = ""
        if reason:
            m.go(E.REJECTED, reason=reason)
            p.state, res.state, res.reason = E.REJECTED.value, E.REJECTED.value, reason
            return self._close(m, res)
        self._nonces.add(token.datum("nonce"))
        m.go(E.AUTHORIZED, token, reason=f"authorized by {token.datum('approved_by')}")
        m.go(E.EXECUTING)
        ok, output, error, receipt = self._executor.execute_(p.tool, p.params_)
        self.audit_log.register("EXECUTION", request_id=p.request_id, authorization=token.datum("approved_by"),
                                 execution={"tool": p.tool, "ok": ok,
                                            "output_hash": receipt.datum("output_hash")}, error=error)
        if not ok:
            m.go(E.FAILED, receipt, reason=error)
            p.state, res.state, res.reason = E.FAILED.value, E.FAILED.value, error
            return self._close(m, res)
        m.go(E.EXECUTED, receipt, reason="receipt from the executor")
        res.output_tool = output
        # RESULT_VALIDATION: the exit is DATA; if you bring instructions, it is quarantined.
        fwh = analyze([Segment(TOOL, str(output))])
        if fwh.quarantine:
            res.findings = [(h.origin, h.category, h.fragment) for h in fwh.findings]
            res.output_tool = wrap_data(fwh.quarantine[0], True)
        h = self.tools[p.tool]
        if h.validate_result is None:
            m.go(E.UNCERTAIN, reason="EXECUTED SUCCESS: no post-execution verification")
            p.state, res.state = E.UNCERTAIN.value, E.UNCERTAIN.value
            res.reason = "executed, but without post verifier success is not proven"
            return self._close(m, res)
        try:
            import inspect
            n = len(inspect.signature(h.validate_result).parameters)
            good = bool(h.validate_result(output, dict(p.params_)) if n >= 2 else h.validate_result(output))
        except Exception:
            good = False
        if not good:
            m.go(E.FAILED, reason="post-execution verification failed")
            p.state, res.state, res.reason = E.FAILED.value, E.FAILED.value, "post verification failed"
            return self._close(m, res)
        post = self._f_post.issue("POST_OK", p.hash, receipt=receipt.signature_[:16])
        m.go(E.SUCCESS, post, reason="post verification OK")
        art = self.memory.persist({"type_": "ejecucion", "act": p.id, "tool": p.tool})
        m.go(E.COMMITTED, art, reason="persistido")
        p.state, res.state = E.COMMITTED.value, E.COMMITTED.value
        res.reason = f"{p.tool} executed, verified and committed"
        return self._close(m, res)

    # ----------------------------------------------------------- persistence (v3).
    def rehydrate(self, pid, request_id, tool, params_, hash_saved, assumptions=()):
        """Recovers an action PENDING_AUTHORIZATION after restart. It REVALIDA from scratch:
        existing and allowed tool, complete parameters and hash identical to the saved one. The tokens of the previous session do not work (keys HMAC are new)."""
        h = self.tools.get(tool)
        problems = []
        if h is None or tool not in self.policies.get("tools_allowed", []):
            problems.append("tool missing or not allowed")
        elif any(not isinstance(params_.get(k), str) or params_.get(k) == "" for k in h.params_required):
            problems.append("incomplete parameters")
        if hash_action(tool, params_) != hash_saved:
            problems.append("hash of action does not match (disk altered)")
        if problems:
            self.audit_log.register("REHIDRATACION_REJECTED", request_id=request_id, error="; ".join(problems),
                                     state_after="REJECTED", act=pid)
            return None
        m = self._machine(request_id)
        for e in (E.INGESTING, E.VALIDATING, E.PROCESSING, E.PROPOSED):
            m.go(e, reason="rehydration from SQLite")
        m.go(E.VERIFIED, self._f_validator.issue("VALID", hash_saved, rehidratado=pid), reason="revalidated after restart")
        m.without_effects = False
        p = Pending(pid, request_id, tool, dict(params_), hash_saved, m, assumptions=list(assumptions))
        self.pending[pid] = p
        self.audit_log.register("REHIDRATACION", request_id=request_id, state_after="PENDING_AUTHORIZATION", act=pid)
        return p

    # ------------------------------------ Changes and Reset
    def propose_change(self, change: ProposedChange, proposer="USER", identity=None) -> dict:
        reg = self.changes.propose(change, proposer)
        if change.apply_direct or identity:
            # IDENTITY PERMISO: say "I am the architect" does not skip protocol
            reg["note"] = "identity/aplicación Direct ignored: requires token CHANGE_AUTH"
        return reg

    def apply_change(self, change_id: str, token) -> dict:
        if self.halted:
            return {"state": "HALTED", "reason": self.halt_reason}
        r = self.changes.apply(change_id, token)
        if r["state"] == "APPLIED":
            self.hierarchy = Hierarchy()
            for k, v in self.policies.items():
                self.hierarchy.apply(Directive(Layer.G3_POLICIES, k, v, "CONTROLLER"))
            self.hierarchy.seal()
        return r

    def reset(self, token) -> bool:
        if not self.keyring.verify(token, "AUTHORIZER", "RESET"):
            self.audit_log.register("RESET_REJECTED", error="RESET without checker signature")
            return False
        ok, msg = self._integrity()
        if not ok and "audit" in msg:
            return False  # a broken audit is not "forgived": research is done outside the band
        self.audit_log.register("RESET", authorization=token.datum("reason"), state_before="HALTED",
                                 state_after="IDLE", halt_reason=self.halt_reason)
        self.halted, self.halt_reason = False, None
        self.cycle_.restart()
        return True

    # ------------------------------------- report (§17).
    def _report(self, res: Result) -> str:
        layers = res.layers_validation
        val = None
        if layers:
            failed = [k for k, v in layers.items() if not v]
            val = "all OK" if not failed else f"fallan {failed}"
        aut = None
        if res.pending:
            aut = "; ".join(f"{p.id} {p.tool} → {p.state}" for p in res.pending)
        risk = []
        cats = sorted({c for _, c, _ in res.findings})
        if cats:
            risk.append(f"firewall: {cats}")
        if res.violations:
            risk.append("violaciones: " + "; ".join(f"{v[0]}{' (CRÍTICA)' if v[2] else ''}" for v in res.violations))
        tactic = []
        if res.execution_request:
            tactic.append("IMPLEMENTATION → EXECUTION_REQUEST (no privileges)")
        if res.changes:
            tactic.append("cambios → " + ", ".join(f"{c['id']}:{c['state']}" for c in res.changes))
        claims = [d for d in res.verdicts if d.class_ == MODEL_CLAIM]
        evid = [d for d in res.verdicts if d.class_ == EXTERNAL_EVIDENCE]
        technique = None
        if res.verdicts:
            technique = f"{len(evid)} con EXTERNAL_EVIDENCE, {len(claims)} MODEL_CLAIM"
        trans = " → ".join([res.history[0][0]] + [h[1] for h in res.history]) if res.history else None
        return format_({
            "TARGET": getattr(self, "_target", None),
            "STATE": res.state,
            "TECHNICAL LAYER": technique,
            "TACTICAL LAYER": tactic,
            "RISK LAYER": risk,
            "INVARIANTS": [v[0] for v in res.violations] or ("no violations" if layers else None),
            "PROPOSED TRANSITION": trans,
            "VALIDATION": val,
            "AUTHORIZATION": aut,
            "RESULT": res.reason or (res.response.splitlines()[0][:120] if res.response else None),
        })
