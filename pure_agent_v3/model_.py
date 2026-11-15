"""Model Gateway: plug-in model. Its output is PROPOSAL/INFERENCE, never evidence.

`StubModel` is deterministic and unnetworked: it is used for tests and demo. A real LLM is plugged in with the same interface (`id`, `version`, `propose(ModelContext) -> Proposal`).
"""
import re

from .root.model_ import Statement, ProposedChange, ModelContext, Proposal, ActionRequest  # noqa: F401
from .root.normalization import normalize_text

EXPR = re.compile(r"[-+*/().%\d\s]{3,}")
DEST = re.compile(r"\b(?:a|al|para|con)\s+([\w.@-]+(?:\s+[A-ZÁÉÍÓÚ][\w-]+)?)", re.UNICODE)
EFFECT = re.compile(r"\b(envi\w*|mand\w*|pas\w*selo|pasale|compart\w*|reenvi\w*|remit\w*|send|forward|share|email|"
                    r"haz\w* llegar|shoot|drop)\b")


class StubModel:
    id = "model-stub"
    version = "3.0"

    def __init__(self):
        self.contexts = []

    def propose(self, ctx: ModelContext) -> Proposal:
        self.contexts.append(ctx)
        t = ctx.instruction
        n = normalize_text(t)
        failure_prior = any("FAILURE_TOOL" in d for d in ctx.data_)
        if "calcula" in n or "how much it is" in n:
            m = EXPR.search(t.replace("x", "*").replace("×", "*"))
            expr = m.group(0).strip() if m else ""
            return Proposal(text=f"I propose to calculate {expr}.",
                             actions=[ActionRequest("calcular", {"expression": expr})])
        m = re.search(r"(?:guarda\w*|escribe|escribir|save|write)\s+[\"«]?(.+?)[\"»]?\s+(?:en|to|in|into)\s+(?:el\s+|the\s+)?(?:archivo|file)\s+([\w./-]+)",
                      t, re.IGNORECASE)
        if m:
            return Proposal(text=f"I propose to write the file {m.group(2)}.",
                             actions=[ActionRequest("write_file",
                                                       {"name_": m.group(2), "content": m.group(1)})])
        # v3 (H-28): the stub does not have its own effects sorter; it uses SIPE (formerly, "shoot a photo"
        # or "content filter in email clients" made him propose send_message → ORPHAN_ACTION → false positive)
        from .sipe import compile_ as _sipe
        try:
            is_effect = _sipe(t).class_action == "EFFECT"
        except ValueError:
            is_effect = False
        if is_effect and EFFECT.search(n):
            from .intent import _recipient
            for_ = _recipient(t) or ""
            return Proposal(text=f"I propose to send the message to {for_ or '(not addressed)'}.",
                             actions=[ActionRequest("send_message",
                                                       {"for_": for_, "subject": "Message from Pure Agent",
                                                        "body_": t})])
        return Proposal(text="Inference of the model: with the available evidence I can no longer affirm "
                               "beyond what is verified by registered sources.")
