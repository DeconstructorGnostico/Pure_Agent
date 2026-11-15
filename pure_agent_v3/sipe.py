"""L1 · SIPE / Context Compiler: normalizes, compiles target, constraints and action class; separates the user channel from external (untrusted) data."""
import re
from dataclasses import dataclass, field

from .root.firewall import EFFECT_EXTERNAL, TRIGGER_EXECUTION
from .root.normalization import normalize_text

MAX_INPUT = 20000
QUERY_ABOUT = re.compile(r"^(como|que es|que significa|explica\w*|por que|porque|what is|what does|what are|how (do|to|does|can)|"
                            r"why|en que consiste|describe|cual es|cuales son|which|define|que son)\b")
# v3: courtesy prefixes that prevented you from recognizing a question ("Please, how do I send...?")
COURTESY = re.compile(r"^(por favor|porfa|oye|hola|please|hey|hi)[\s,:;!.]+")
# v3: expressions sociales/abstractas which are not effects (‘welfare’, ‘share knowledge’)
SOCIAL = re.compile(r"\b(mand\w*|envi\w*|send|share|compart\w*)\s+(\w+\s+)?(saludos|recuerdos|un abrazo|abrazos|besos|regards|greetings|"
                    r"knowledge|conocimiento\w*|tips|consejos|thoughts|opinion\w*|ideas|experience|experiencia\w*)\b")


@dataclass
class Instruction:
    original: str
    normalized: str
    target: str
    restrictions: list = field(default_factory=list)
    class_action: str = "QUERY"        # QUERY  EFFECT
    execution_request: bool = False
    data_external: list = field(default_factory=list)
    verbs_effect: list = field(default_factory=list)


class InvalidInput(ValueError):
    pass


def compile_(text, data_external=()) -> Instruction:
    if not isinstance(text, str):
        raise InvalidInput("INPUT_MUST_BE_STRING")
    if not text.strip():
        raise InvalidInput("EMPTY_INPUT")
    if len(text) > MAX_INPUT:
        raise InvalidInput("INPUT_TOO_LONG")
    n = normalize_text(text)
    restr = re.findall(r"\b(sin [a-z ]{3,30}?|maximo [^,.;]{1,30}|como maximo [^,.;]{1,30}|solo [^,.;]{1,30}|"
                       r"no (uses|incluyas|menciones) [^,.;]{1,30})(?=[,.;]|$)", n)
    verbs = [m.group(0) for m in re.finditer(EFFECT_EXTERNAL, n)]
    without_trigger = re.sub(TRIGGER_EXECUTION + r"\s*:?\s*", "", n).strip()
    base = COURTESY.sub("", without_trigger.lstrip("¿¡ ")).lstrip("¿¡ ")
    social = bool(SOCIAL.search(n)) and not re.search(r"\b(a|al|to|con|para)\s+[\w@.-]+@", n)
    if social:
        verbs = [v for v in verbs if not SOCIAL.search(v + " " + n[n.find(v) + len(v):][:40])]
    class_ = "EFFECT" if verbs and not QUERY_ABOUT.search(base) else "QUERY"
    obj = re.split(r"(?<=[.!?])\s", text.strip())[0][:160]
    return Instruction(text, n, obj, restr, class_, bool(re.search(TRIGGER_EXECUTION, n)),
                       list(data_external), verbs)
