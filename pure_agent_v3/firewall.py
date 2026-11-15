"""L2 · Semantic Firewall: injection (Root Layer §5/§20) + bilingual damage categories with protective exemptions + rules learned (only AGREGAN locks, I09)."""
import re

from .root.firewall import DATA, INJECTION, USER, Segment, analyze
from .root.normalization import normalize_text, variants

DANO = {
    "WEAPONS_EXPLOSIVES": r"\b(fabric\w*|constru\w*|arm\w*|hacer|make|build)\b.{0,30}\b(bomba|explosivo\w*|bomb|explosive\w*|arma quimica|chemical weapon|pipe bomb)\b",
    "MALWARE": r"\b(crea\w*|escrib\w*|desarroll\w*|write|create|build)\b.{0,30}\b(ransomware|malware|keylogger|troyano|trojan|botnet|virus informatico)\b",
    "FRAUD": r"\b(launder\w* (the )?money|lavar dinero|blanquear dinero|blanqueo de capitales|phishing|clonar tarjeta\w*|robar (contrasenas|credenciales|tarjetas)|steal (passwords|credentials)|lavar dinero|money laundering)\b",
    "DANO_PEOPLE": r"\b(matar|asesinar|envenenar|kill|murder|poison)\b.{0,20}\b(a (mi|un|una|el|la)|someone|my|a person|persona)\b",
    "AUTOLESION": r"\b(como (suicidarme|matarme|hacerme dano)|how to (kill myself|commit suicide|self harm))\b",
}
PROTECTIVE = re.compile(r"\b(prevenir|prevencion|protegerme|detectar|defender\w*|evitar|reconocer|prevent|protect|detect|"
                        r"defend|avoid|recognize|historia de|history of|ayuda|help line|linea de ayuda)\b")


def scan_dano(text: str, learned=()) -> list[str]:
    hits = []
    for v in variants(text):
        protector = bool(PROTECTIVE.search(v))
        for cat, pat in DANO.items():
            if re.search(pat, v) and not (protector and cat != "AUTOLESION"):
                hits.append(cat)
        for kw in learned:
            if re.search(rf"\b{re.escape(normalize_text(kw))}\b", v):
                hits.append(f"FIREWALL_BLOCK:{kw}")
    return sorted(set(hits))


def inspect(instr, learned=()):
    """Returns (decision, reasons, report_root). decision: OK  REJECT  FILTER."""
    segs = [Segment(USER, instr.original)] + [
        s if isinstance(s, Segment) else Segment(DATA, str(s), "externo") for s in instr.data_external]
    rep = analyze(segs)
    reasons = []
    dano = scan_dano(instr.original, learned)
    if dano:
        reasons.append(f"daño: {dano}")
    iny = sorted(rep.categories(USER) & set(INJECTION))
    if iny:
        reasons.append(f"injection into the user channel: {iny}")
    for s in segs[1:]:
        if scan_dano(s.text, learned) and s not in rep.quarantine:
            rep.quarantine.append(s)        # dangerous fact: it is isolated, it is never obeyed
    if reasons:
        return "REJECT", reasons, rep, segs
    return ("FILTER" if rep.quarantine else "OK"), [], rep, segs
