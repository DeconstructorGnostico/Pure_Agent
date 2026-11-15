"""§18 Zero cognitive trash · §10 (BG) Zero filling. Heuristic: removes known courtesy and filling formulas from the model output. It does not guarantee style."""
import re

PHRASES = [
    r"^(¡?claro!?|¡?por supuesto!?|¡?con gusto!?|¡?excelente pregunta!?|¡?buena pregunta!?|"
    r"¡?gran pregunta!?|sure!?|of course!?|great question!?|certainly!?)[\s,.!]*",
    r"\s*(espero que (esto|esta informacion|esta información) te (ayude|sirva)[^.]*\.?)\s*$",
    r"\s*(i hope (this|that) helps[^.]*\.?)\s*$",
    r"\s*(no dudes en (preguntar|consultar)[^.]*\.?)\s*$",
    r"\s*(si tienes (mas|más) preguntas[^.]*\.?)\s*$",
]


def clean(text: str) -> tuple[str, int]:
    n = 0
    t = text or ""
    change = True
    while change:
        change = False
        for p in PHRASES:
            new = re.sub(p, "", t, flags=re.IGNORECASE)
            if new != t:
                t, n, change = new.strip(), n + 1, True
    return t, n
