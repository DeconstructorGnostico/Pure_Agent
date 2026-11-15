"""AMM-CORE · Pure Agent Orchestrator v3 (NRE–AMM–OMEGA + NEXUS, governed by the Root Layer).

INPUT → SIPE → FIREWALL → DECONSTRUCT → EVIDENCE → OMEGA(gateway, ciclos, decidir) → NEXUS/ZERO-TRUST
      → VERIFY → LEARN → PERSIST (SQLite) → OUTPUT (standardized NRE contract)
"""
import os
import re
import tempfile

from . import firewall as fw_ap
from .contract import LIMITATIONS_BASE, new_contract, validate_contract
from .decision import decide as decide_fc, prioritize
from .deconstructor import contradictions_evidence, deconstruct
from .evidence import evaluate
from .causal import CausalChain
from .gateway import MotorOmega
from .intent import compile_intent, evaluate_action_against_spec, verify_criteria
from .kernel import INVARIANTS_AP, NAME, root_hash
from .model_ import StubModel
from .nexus import Nexus
from .omega import HALT, NEED_INPUT, PENDING, PROCESS, REJECT, UNDETERMINED, decide
from .persistence import Store, AuditSQLite, VersionedState
from .root.normalization import normalize_text
from .zero_trust import ZeroTrust, concessions_by_default
from .root.evidence import Verdict
from .root.firewall import DATA, TOOL, Segment
from .root.governor import Governor, Request
from .root.tools import Tool
from .root.report import format_
from .root.useful import Clock, sha256
from .sandbox import Sandbox, calculate, with_limit
from .sipe import InvalidInput, compile_
from .verification import Learning, Reviewer, verifier_file, verifier_message, verify_calculation

VERSION = "3.0.0"
# critical parameters per tool (decid fail-closed) and priority metadata I/(E×T)
CRITICAL = {"calcular": ("expression",), "write_file": ("name_", "content"),
            "send_message": ("for_", "body_")}
PRIORITY = {"calcular": {"I": 3, "E": 1, "T": 1, "complexity": 1},
             "write_file": {"I": 5, "E": 2, "T": 1, "complexity": 2},
             "send_message": {"I": 8, "E": 2, "T": 2, "complexity": 3}}


def _form(t: str) -> str:
    return re.sub(r"\s+", "", normalize_text(str(t)).replace("×", "*").replace("x", "*"))


def _path_safe(path_) -> bool:
    import posixpath
    r = str(path_).replace("\\", "/")
    if not r or len(r) > 255 or any(ord(c) < 32 for c in r) or r.startswith(("/", "~")) or re.match(r"^[a-zA-Z]:", r):
        return False
    return ".." not in posixpath.normpath(r).split("/") and ".." not in r.split("/")


class PersistentLearning(Learning):
    """Learning with reviewer (I09) persisted in SQLite. When loading, a rule APPLIED will only be
    reactivates if your MUTATION_APPLIED exists in a full audit (editing the database is not enough)."""

    def __init__(self, keyring, audit_log, store):
        super().__init__(keyring, audit_log)
        self._alm = store
        applied = {r.get("request_id") for r in audit_log.records if r.get("event") == "MUTATION_APPLIED"}
        ok, _ = audit_log.verify()
        for m in store.mutations():
            if not isinstance(m, dict) or "id" not in m:
                continue
            if m.get("state") == "APPLIED" and not (ok and m["id"] in applied):
                m = dict(m, state="REJECTED", problems=list(m.get("problems", [])) + ["APPLIED without full audit"])
            self.mutations[m["id"]] = m
            if m["state"] == "APPLIED":
                self.rules.append(m["word"])
                self.version += 1

    def propose(self, word, proposer, category="FIREWALL_BLOCK"):
        m = super().propose(word, proposer, category)
        self._alm.save_mutation(m)
        return m

    def review(self, mid, verdict):
        r = super().review(mid, verdict)
        if mid in self.mutations:
            self._alm.save_mutation(self.mutations[mid])
        return r

MAP_DECISION = {"COMMITTED": PROCESS, "REJECTED": REJECT, "HALTED": HALT, "UNCERTAIN": UNDETERMINED,
                 "FAILED": REJECT, "PENDING_AUTHORIZATION": PENDING, "CHANGE_PROPOSAL": "CHANGE_PROPOSAL"}


class PureAgent:
    """AMM-CORE: coordinates all modules; Root Layer rules, OMEGA executes, NEXUS controls."""
    def __init__(self, model_=None, sources=(), directory=None, max_steps=5, max_replanes=1,
                 time_max=10.0, timeout_tool=2.0, max_effects_by_session=10, clock=None,
                 max_reject_streak=5, max_cycles=3, key_audit=None):
        self.dir = directory or tempfile.mkdtemp(prefix="agent_pure_v3_")
        os.makedirs(self.dir, exist_ok=True)
        self.sandbox = Sandbox(os.path.join(self.dir, "sandbox"))
        self.model_ = model_ or StubModel()
        self.max_replanes = max_replanes
        self.max_steps = max_steps
        sb = self.sandbox
        tools = [
            Tool("calcular", with_limit(calculate, timeout_tool), effect_external=False,
                        params_required=("expression",), validate_result=verify_calculation),
            Tool("write_file", with_limit(sb.write_file, timeout_tool), effect_external=True,
                        params_required=("name_", "content"), validate_result=verifier_file(sb)),
            Tool("send_message", with_limit(sb.send_message, timeout_tool), effect_external=True,
                        params_required=("for_", "subject", "body_"), validate_result=verifier_message(sb)),
        ]
        self.sources = list(sources)
        clock = clock or Clock()
        self.store = Store(self.dir, key_audit)
        audit_log = AuditSQLite(clock, self.store)
        allowed_items = ["calcular", "write_file", "send_message"]
        self.zero_trust = ZeroTrust(concessions_by_default(allowed_items, self.model_.id))
        self.motor = MotorOmega(self.model_, max_steps, time_max, max_cycles,
                                required={h.name_: h.params_required for h in tools})
        self.max_cycles = max_cycles
        self.gob = Governor(
            self.motor, verifiers=self.sources, tools=tools,
            policies={"tools_allowed": allowed_items}, clock=clock,
            max_reject_streak=max_reject_streak, path_memory=os.path.join(self.dir, "memoria.jsonl"),
            audit_log=audit_log, zero_trust=self.zero_trust, evaluator_action=self._evaluate_action)
        self.gob._n = max(self.gob._n, self.store.counter("ids"))
        self.nexus = Nexus(self.gob.controller, max_effects_by_session, self.zero_trust)
        self.state = VersionedState(self.store, self.gob.audit_log)
        self.learning = PersistentLearning(self.gob.keyring, self.gob.audit_log, self.store)
        self._root = root_hash()
        self.halted = False
        self.last = None
        reason_halt = self.store.counter("halted")
        if reason_halt:
            # a HALT survives the restart: restarting the process is not a RESET controller
            self.halted = True
            self.gob.halted, self.gob.halt_reason = True, "HALT persisted from a previous session"
        self.causal = CausalChain(self.gob.audit_log)       # reconstructed from the audit
        self._specs = {}                                        # request_id -> spec (and per action)
        self._spec_actual, self._data_actual, self._prop_link = None, (), None
        self._nreq = sum(1 for e in self.causal.links if e["id"].startswith("intent-"))
        self.rehidratadas = []
        for d in self.store.pending_open():
            p = None if d.get("corrupt") else self.gob.rehydrate(
                d["id"], d["request_id"], d["tool"], d["params_"], d["hash"], d.get("assumptions", []))
            if p is None:
                self.store.db.execute("UPDATE pending SET state='REJECTED' WHERE id=?", (d["id"],))
            else:
                self.rehidratadas.append(p.id)
                if d.get("spec"):
                    self._specs[p.id] = d["spec"]

    # --------------------------------------------------------------------------- decide fail-closed (B)
    def _evaluate_action(self, p, sol):
        """v3: the action is evaluated against the SPEC intention and is causally chained.
        BLOCK if it is orphan (ORPHAN_ACTION) or violates the spec; if not, decide() fail-closed on its parameters (confirmed/inferido/desconocido) with declared assumptions."""
        path_ = p.params_.get("name_") if p.tool == "write_file" else None
        if path_ is not None and not _path_safe(path_):
            # v3 (H-20): Controller is not kept waiting for an action that the sandbox will reject
            return "BLOCK: path outside the sandbox (absolute, '..' or control characters)", []
        spec = self._spec_actual
        if spec is None:
            return self._evaluate_action_literal(p, sol)
        ev = evaluate_action_against_spec(spec, p.tool, p.params_, self._data_actual)
        if self._prop_link is None:
            self._prop_link = self.causal.add_item(f"prop-{p.request_id}", self._root_actual, "GENERATES", "MODEL",
                                                     {"request_id": p.request_id})["id"]
        if ev["rooted"]:
            self.causal.add_item(p.id, self._prop_link, "CAUSES", "MODEL", {"act": p.hash})
        elif ev["origin"] == "EVIDENCE":
            datum = self.causal.add_item(f"dato-{p.id}", None, "TRANSFORMS", "EVIDENCE", list(self._data_actual))
            self.causal.add_item(p.id, datum["id"], "DRIVES", "EVIDENCE", {"act": p.hash})
        else:
            self.causal.add_item(p.id, None, "GENERATES", "MODEL", {"act": p.hash})
        self._specs[p.id] = spec
        if not self.causal.rooted_in_intent(p.id):
            return "BLOCK: " + (ev["reason"] or "ORPHAN_ACTION: no causal chain to intent"), []
        if ev["mode"] == "BLOCK":
            return "BLOCK: " + ev["reason"], []
        return ev["mode"], ev["assumptions"]

    def _evaluate_action_literal(self, p, sol):
        """Mode v2-compatible without spec: confirmed = literal in the instruction; inferred = put it the model."""
        text = _form(sol.text)
        data_ = {}
        for k, v in p.params_.items():
            if v in (None, ""):
                data_[k] = "unknown"
            else:
                data_[k] = "confirmed" if _form(v) and _form(v) in text else "inferido"
        d = decide_fc(data_, CRITICAL.get(p.tool, tuple(p.params_)))
        return d.mode, d.assumptions

    def _persist_pending(self, pending):
        for p in pending:
            self.store.save_pending(p, getattr(p, "assumptions", []), self._specs.get(p.id))
        self.store.set_counter("ids", self.gob._n)

    # ------------------------------------------------------------------------- API public.
    @property
    def audit_log(self):
        return self.gob.audit_log

    def register_reviewer(self, id_reviewer: str) -> Reviewer:
        return Reviewer(self.gob.keyring.register(id_reviewer, "VERIFIER"))

    def propose_rule(self, word, proposer="model-stub", category="FIREWALL_BLOCK"):
        return self.learning.propose(word, proposer, category)

    def review_rule(self, mid, verdict):
        return self.learning.review(mid, verdict)

    def reset(self, reason="controller review"):
        ok = self.gob.reset(self.gob.controller.reset(reason))
        if ok and root_hash() == self._root:
            self.halted = False
            self.store.db.execute("UPDATE contadores SET value_=0 WHERE key_='halted'")
        return ok and not self.halted

    # ------------------------------------------------------------------------------- flow
    def process_request(self, request: dict) -> dict:
        """Entry with the contract NRE: {intent, constraints?, context?, evidence?[]}."""
        from .contract import InvalidContract, request_from_json
        try:
            s = request_from_json(request)
        except InvalidContract as e:
            out = {"version": VERSION, "system": NAME}
            return self._output(out, [("CONTRACT", str(e))], REJECT, f"invalid application: {e}")
        return self.process(s["intent"], evidence=s["evidence"], context=s["context"],
                             restrictions=s["constraints"])

    def process(self, text, data_external=(), evidence=(), context=None, restrictions=()) -> dict:
        stages = []
        rid = None
        evidence = list(evidence or [])
        context = dict(context or {})
        data_external = list(data_external)
        # Evidence and context of untrustworthy request = DATA (CONTEXT != AUTHORITY)
        for ev in evidence:
            data_external.append(Segment(DATA, str(ev.get("content", "")),
                                           f"evidence source={ev.get('source', '')} claim_id={ev.get('claim_id', '')}"))
        for k, v in context.items():
            data_external.append(Segment(DATA, f"{k}: {v}", "context"))
        out = {"version": VERSION, "system": NAME, "input_hash": sha256(str(text)),
               "_req": {"intent": text if isinstance(text, str) else repr(text)[:200],
                        "constraints": [str(r) for r in restrictions], "context": context, "evidence": evidence}}
        if self.halted or self.gob.halted:
            return self._output(out, stages, HALT, f"system stopped: {self.gob.halt_reason or 'I08'}")
        if root_hash() != self._root:                                   # I08 before
            return self._stop(out, stages, "I08: Root Kernel changed")
        stages.append(("INPUT", "OK"))
        # L1 SIPE
        try:
            instr = compile_(text, data_external)
        except InvalidInput as e:
            stages.append(("SIPE", str(e)))
            return self._output(out, stages, REJECT, f"invalid entry: {e}")
        stages.append(("SIPE", f"clase={instr.class_action}" + (" · EXECUTION_REQUEST" if instr.execution_request else "")))
        if restrictions:
            instr.restrictions = list(instr.restrictions) + [str(r) for r in restrictions]
        # COMPILER INTENTION: implicit intent → verifiable explicit spec (causal root)
        spec = compile_intent(instr)
        out["spec"] = spec
        self._nreq += 1
        self._root_actual = self.causal.add_item(f"intent-{self._nreq:06d}", None, "TRANSFORMS", "USER_INTENT", spec)["id"]
        self._spec_actual, self._prop_link = spec, None
        self._data_actual = tuple(getattr(s, "text", str(s)) for s in instr.data_external)
        stages.append(("INTENT", f"{spec['type_task']} · {spec['state']}"
                       + (f" · faltan {spec['missing_items']}" if spec["missing_items"] else "")))
        against_ev = contradictions_evidence(evidence)
        out["contradictions_evidence"] = against_ev["conflicts"]
        out.update(class_action=instr.class_action, verbs_effect=instr.verbs_effect,
                   execution_request=instr.execution_request, restrictions=instr.restrictions)
        # L2 FIREWALL
        dec_fw, reasons, rep, segs = fw_ap.inspect(instr, self.learning.rules)
        out["firewall"] = {"decision": dec_fw, "reasons": reasons,
                           "findings": sorted({h.category for h in rep.findings}),
                           "quarantine": len(rep.quarantine)}
        stages.append(("FIREWALL", dec_fw))
        self.audit_log.register("AP_FIREWALL", input_hash=sha256(instr.original), validation_results=out["firewall"])
        if dec_fw == "REJECT":
            return self._reject(out, stages, "firewall: " + "; ".join(reasons))
        if spec["missing_items"]:
            # unknown critical data → NEED_INPUT: the model is not called or invented
            stages.append(("OMEGA", NEED_INPUT))
            self.audit_log.register("NEED_INPUT", input_hash=sha256(instr.original), state_after="INCOMPLETE",
                                     missing_items=spec["missing_items"])
            return self._output(out, stages, NEED_INPUT, f"INCOMPLETE · Critical data missing: {spec['missing_items']} "
                                "(does not infer or invent)", persist=True)
        # L3 DECONSTRUCT
        decon = deconstruct(instr, risks=out["firewall"]["findings"])
        out["deconstruccion"] = decon.summary()
        out["contradictions"] = decon.C
        stages.append(("DECONSTRUCT", f"F={len(decon.F)} C={len(decon.C)} U={len(decon.U)}"))
        # L4 EVIDENCE (input and external data statements: CLAIM until demonstrated)
        truth = [evaluate(p, self.sources, self.gob._f_verif, self.gob.keyring, decon.contradicted)
                  for p in decon.F + decon.E]
        out["truth"] = [{"text": v["text"], "truth": v["truth"], "sources": v["sources"],
                          "origin": v.get("origin", "user")} for v in truth]
        stages.append(("EVIDENCE", ", ".join(sorted({v["truth"] for v in truth})) or "no assertions"))
        if not against_ev["consistent"]:
            stages.append(("EVIDENCE", "CONTRADICTORY_ASSERTIONS"))
            return self._reject(out, stages, "contradictory evidence (same claim_id with opposite polarity): "
                                  + ", ".join(c["claim_id"] for c in against_ev["conflicts"]))
        # OMEGA: Pre-decision table
        dec, reason = decide(dec_fw, decon, instr)
        if dec == REJECT:
            stages.append(("OMEGA", REJECT))
            return self._reject(out, stages, reason)
        # Root Layer governs the model, authorization and execution
        adj = [s for s in segs[1:]]
        summary = {k: v for k, v in decon.summary().items() if k != "O"}
        adj.append(Segment(DATA, f"D(x)={summary} · states_of_truth={[v['truth'] for v in truth]}",
                            "deconstruccion"))
        res = self.gob.process(Request(instr.original, attachments=adj, target=instr.target))
        replanes = 0
        while res.state in ("FAILED", "UNCERTAIN") and res.pending and replanes < self.max_replanes:
            replanes += 1                                                  # critical: replanning (checked)
            adj2 = adj + [Segment(TOOL, f"FAILURE_TOOL: {res.reason}", "critico")]
            res = self.gob.process(Request(instr.original, attachments=adj2, target=instr.target))
        rid = res.request_id
        out["replanes"] = replanes
        stages.append(("OMEGA", f"{dec} → {res.state}"))
        decision = MAP_DECISION.get(res.state, UNDETERMINED)
        if res.state == "UNCERTAIN" and "PlanExceeded" in res.reason:
            decision, res.reason = REJECT, "I10: off-limits plan or time"
        if instr.class_action == "EFFECT" and decision == PROCESS and not res.pending:
            decision = UNDETERMINED
            res.reason = "the request has external effect, but no action was identified that could be authorized."
        return self._close(out, stages, res, decision, truth)

    def _reject(self, out, stages, reason):
        rationale = self.gob.cycle_.close_("REJECTED", {})
        self.audit_log.register("AP_REJECT", error=reason, state_after="REJECTED")
        if rationale:
            return self._stop(out, stages, f"INV-R10/I10: {rationale}")
        return self._output(out, stages, REJECT, reason, persist=True)

    def authorize(self, pending_id: str, approved_by="human controller") -> dict:
        """AUTORIZADOR EXTERNAL (humano/service) decision, never model."""
        p = self.gob.pending.get(pending_id)
        out = {"version": VERSION, "system": NAME, "act": pending_id}
        if p is None:
            return self._output(out, [], REJECT, "non-existent action")
        if p.state == "PENDING_AUTHORIZATION" and not self.causal.rooted_in_intent(p.id):
            self.audit_log.register("ORPHAN_ACTION", request_id=p.request_id, error="without causal chain", act=p.id)
            return self._output(out, [("CAUSAL", "ORPHAN_ACTION")], REJECT,
                                "ORPHAN_ACTION: action does not have uninterrupted causal chain until intention")
        tok = self.nexus.authorize(p, approved_by)
        if tok is None:
            return self._output(out, [("NEXUS", "DENIED")], REJECT, "NEXUS: effect limit per session")
        res = self.gob.execute_(pending_id, tok)
        stages = [("NEXUS", "AUTHORIZED"), ("OMEGA", f"execution → {res.state}")]
        return self._close(out, stages, res, MAP_DECISION.get(res.state, UNDETERMINED), [], post=True)

    def execute_with_token(self, pending_id, token) -> dict:
        """Route for tokens arriving from outside (e.g. a controller service)."""
        res = self.gob.execute_(pending_id, token)
        return self._close({"version": VERSION, "act": pending_id}, [], res,
                            MAP_DECISION.get(res.state, UNDETERMINED), [], post=True)

    def refuse(self, pending_id, by="human controller") -> dict:
        p = self.gob.pending.get(pending_id)
        if p:
            self.nexus.refuse(p, by)
            p.state = "DENIED"
            self.store.save_pending(p, p.assumptions)
            self.audit_log.register("AP_DENIED", request_id=p.request_id, authorization=by, state_after="DENIED")
        return self._output({"act": pending_id}, [("NEXUS", "DENIED")], REJECT, "denied by the controller")

    # -------------------------------------------------------------
    def _close(self, out, stages, res, decision, truth, post=False):
        facts = [{"text": v["text"], "sources": v["sources"]} for v in truth if v["truth"] == "SUPPORTED"]
        for d in res.verdicts:
            if d.class_ == "EXTERNAL_EVIDENCE" and d.truth == "SUPPORTED":
                facts.append({"text": d.content, "sources": [d.artifact.datum("verifier")]})
        inferences = [l for l in res.response.splitlines()[:1] if l] if res.response else []
        inferences += [d.content for d in res.verdicts if d.class_ == "MODEL_CLAIM"]
        verified = [v for v in truth if v["truth"] != "UNDETERMINED"]
        response = res.response
        result_verified = None
        if res.output_tool is not None and res.state == "COMMITTED":
            result_verified = res.output_tool     # accepted only after SUCCESS of the verifier (I07)
            response = f"{response}\nRESULT VERIFIED (independent verifier): {res.output_tool}"
        self._persist_pending(res.pending)
        order = prioritize([dict(PRIORITY.get(p.tool, {"I": 1, "E": 1, "T": 1, "complexity": 9}), id=p.id)
                           for p in res.pending])
        range_ = {t["id"]: i for i, t in enumerate(order)}
        res.pending = sorted(res.pending, key=lambda p: range_[p.id])
        out.update(request_id=res.request_id, state_execution=res.state, response=response,
                   result_verified=result_verified,
                   facts=facts, inferences=inferences,
                   verification="PROVEN" if (facts and all(v["truth"] == "SUPPORTED" for v in verified)
                                                 and not any(d.class_ == "MODEL_CLAIM" for d in res.verdicts))
                   else "NOT PROVEN",
                   pending=[{"id": p.id, "tool": p.tool, "params_": p.params_,
                                "state": p.state, "assumptions": list(getattr(p, "assumptions", [])),
                                "decision_fc": getattr(p, "decision", "")} for p in res.pending],
                   cycles_omega=len(self.motor.history_cycles[-1]) if self.motor.history_cycles and not post else None,
                   transitions=[h[1] for h in res.history],
                   output_tool=res.output_tool)
        if res.state == "COMMITTED" and ("SUCCESS" in out["transitions"] or result_verified is not None):
            out["verification"] = "PROVEN (independent post-execution verification)"
        if res.state == "COMMITTED" or post:
            stages.append(("VERIFY", "OK" if res.state == "COMMITTED" else res.state))
        # LEARN: facts of INPUT with evidence SUPPORTED → memory (I04: memory is never source)
        learned = 0
        if res.state == "COMMITTED":
            for v in truth:
                if v["truth"] == "SUPPORTED" and v.get("origin", "user") == "user":
                    c = self.gob.memory.candidate(v["text"], "input_")
                    if self.gob.memory.validate(c, Verdict(v["text"], "FACT", "EXTERNAL_EVIDENCE", "SUPPORTED",
                                                           "PROVEN")):
                        self.gob.memory.persist({"type_": "learning", "content": v["text"]})
                        learned += 1
        stages.append(("LEARN", f"{learned} verified fact(s) to memory"))
        out["reason"] = res.reason
        spec = self._spec_actual if not post else self._specs.get(res.pending[0].id if res.pending else None)
        if spec is not None:
            out["spec_id"] = spec["id"]
            crit = verify_criteria(spec, dict(out, decision=decision, _authorized=post))
            out["criteria"] = crit
            fail = [k for k, v in crit.items() if v is False]
            if fail and decision == PROCESS:
                decision = UNDETERMINED
                res.reason = out["reason"] = f"does not meet spec acceptance criteria: {fail}"
        if post and res.pending and res.state == "COMMITTED":
            self.causal.add_item(f"exec-{res.pending[0].id}", res.pending[0].id, "TRIGGERS", "TOOL",
                                {"output": str(res.output_tool)[:500]})
        if self.gob.halted:
            decision = HALT
        return self._output(out, stages, decision, res.reason, persist=True, report_root=res.report)

    def _mark_halt(self):
        self.store.set_counter("halted", 1)

    def _stop(self, out, stages, reason):
        self._mark_halt()
        self.halted = True
        self.gob.halted, self.gob.halt_reason = True, reason
        self.audit_log.register("AP_HALT", halt_reason=reason, state_after="HALTED")
        return self._output(out, stages, HALT, reason)

    def _invariants(self, out) -> dict:
        ok_audit, _ = self.audit_log.verify()
        facts = out.get("facts", [])
        registered = {f.id for f in self.sources}
        exec_ = [r for r in self.audit_log.records if r["event"] == "EXECUTION"]
        commits_without_post = [h for h in out.get("transitions", []) if False]
        ctxs = getattr(self.model_, "contexts", [])
        inv = {
            # I01: no fact without a registered source; an inference of the model that MATCHES with a given fact
            # SUPPORTED by source does not convert it into inference (before → HALT spurt, finding H-24)
            "I01": all(h["sources"] for h in facts) and not (
                set(map(str, out.get("inferences", []))) & {h["text"] for h in facts}
                - {v["text"] for v in out.get("truth", []) if v["truth"] == "SUPPORTED" and v["sources"]}),
            "I02": out.get("verification") != "PROVEN" or bool(facts),
            "I03": all(v["truth"] == "SUPPORTED" for v in out.get("truth", []) if v["text"] in {h["text"] for h in facts}),
            "I04": all(set(h["sources"]) <= registered for h in facts),
            "I05": all(c.instruction == c.instruction and "QUARANTINE" not in c.instruction for c in ctxs),
            "I06": all(r.get("authorization") for r in exec_),
            "I07": "SUCCESS" in out.get("transitions", []) or "EXECUTED" not in out.get("transitions", []) or out.get("state_execution") != "COMMITTED",
            "I08": root_hash() == self._root,
            "I09": all(m["proposer"] != "?" for m in self.learning.mutations.values()),
            "I10": out.get("replanes", 0) <= self.max_replanes and len(out.get("pending", [])) <= self.max_steps
                   and (out.get("cycles_omega") or 0) <= self.max_cycles,
            # I11 UNKNOWN != FALSE: without responding sources, the state is UNDETERMINED, never REFUTED
            "I11": all(v["truth"] in ("UNDETERMINED", "CONTRADICTED") for v in out.get("truth", []) if not v["sources"]),
            # I12 PRIVILEGE_MUST_BE_EXPLICIT: all execution is authorized and Zero-Trust explicit concession
            "I12": all(r.get("authorization") and self.zero_trust.allowed(
                "executor-sandbox", "EXECUTE:" + (r.get("execution") or {}).get("tool", "?"), register=False) for r in exec_),
            "AUDIT": ok_audit,
            # CHAIN CAUSAL: whole and any execution with an effect rooted in the user's intention
            "CAUSAL": self.causal.verify()[0] and all(
                self.causal.rooted_in_intent(e["cause_id"]) for e in self.causal.links
                if e["id"].startswith("exec-")),
        }
        del commits_without_post
        return inv

    def _output(self, out, stages, decision, reason, persist=False, report_root=None):
        out["decision"] = decision
        out.setdefault("reason", reason)
        out["reason"] = out["reason"] or reason
        inv = self._invariants(out)
        out["invariants"] = inv
        if not all(inv.values()) and decision != HALT:
            failed = [k for k, v in inv.items() if not v]
            self.halted = True
            self.gob.halted, self.gob.halt_reason = True, f"invariants raped: {failed}"
            out["decision"], out["reason"] = HALT, f"invariants raped: {failed}"
        if out["decision"] == HALT or self.gob.halted:
            self._mark_halt()
        if persist and out["decision"] != HALT:
            reg = self.state.compromise({"request_id": out.get("request_id"), "decision": out["decision"],
                                           "response_hash": sha256(out.get("response", ""))})
            stages.append(("PERSIST", f"estado v{reg['version']}"))
        stages.append(("OUTPUT", out["decision"]))
        out["flow"] = stages
        out["audit_log"] = {"ok": self.audit_log.verify()[0], "records": len(self.audit_log)}
        out["contract"] = self._contract(out)
        out["report"] = self._report(out)
        self.last = out
        return out

    def _contract(self, out) -> dict:
        req = out.pop("_req", None) or {"intent": "", "constraints": [], "context": {}, "evidence": []}
        state = out.get("state_execution") or {"REJECT": "REJECTED", "HALT": "HALTED", "NEED_INPUT": "INCOMPLETE"}.get(out["decision"], "UNCERTAIN")
        if out["decision"] == HALT:
            state = "HALTED"
        c = new_contract(VERSION, out.get("request_id") or out.get("act") or "-", req["intent"], req["constraints"],
                           req["context"], req["evidence"], state, self.max_cycles)
        see = out.get("verification") or ""
        c["verification"]["status"] = ("PROVEN" if see.startswith("PROVEN") else
                                       "NO_PROVEN" if see else "PENDING")
        c["verification"]["checks"] = {k: bool(v) for k, v in out.get("invariants", {}).items()}
        lim = list(LIMITATIONS_BASE)
        if not self.sources:
            lim.append("There are no sources registered for this session: no statements can be left SUPPORTED.")
        if any(p.get("assumptions") for p in out.get("pending", [])):
            lim.append("There are parameters INFERIDOS for the model (stated assumptions) that the controller must confirm.")
        c["verification"]["limitations"] = lim
        return validate_contract(c)

    def _report(self, out) -> str:
        failed = [k for k, v in out.get("invariants", {}).items() if not v]
        truths = {}
        for v in out.get("truth", []):
            truths[v["truth"]] = truths.get(v["truth"], 0) + 1
        return format_({
            "TARGET": out.get("deconstruccion", {}).get("O"),
            "STATE": f"{out['decision']} · execution={out.get('state_execution', '-')}",
            "TECHNICAL LAYER": " → ".join(f"{e}:{s}" for e, s in out.get("flow", [])) or None,
            "TACTICAL LAYER": f"clase={out.get('class_action')}" + (" · EXECUTION_REQUEST" if out.get("execution_request") else "")
            if out.get("class_action") else None,
            "RISK LAYER": (out.get("firewall", {}).get("reasons") or out.get("firewall", {}).get("findings")
                               or out.get("contradictions")) or None,
            "INVARIANTS": "I01–I12 + INV-R00..R10 OK" if not failed else f"FALLAN {failed}",
            "PROPOSED TRANSITION": " → ".join(out.get("transitions", [])) or None,
            "VALIDATION": "; ".join(x for x in (
                f"input truth={truths}" if truths else "",
                f"facts with source={len(out.get('facts', []))}" if out.get("facts") else "",
                f"verification={out.get('verification')}" if out.get("verification") else "") if x) or None,
            "AUTHORIZATION": "; ".join(f"{p['id']} {p['tool']} → {p['state']}" for p in out.get("pending", [])) or None,
            "RESULT": out.get("reason") or (out.get("response") or "").splitlines()[0][:140] if (out.get("reason") or out.get("response")) else None,
        })
