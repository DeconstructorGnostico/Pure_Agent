"""§17 Field report (and §12 BG). "Do not fill non-existent fields": Empty fields are omitted."""
FIELDS = ("TARGET", "STATE", "TECHNICAL LAYER", "TACTICAL LAYER", "RISK LAYER", "INVARIANTS",
          "PROPOSED TRANSITION", "VALIDATION", "AUTHORIZATION", "RESULT")


def format_(fields: dict) -> str:
    lines = ["FIELD REPORT"]
    for c in FIELDS:
        v = fields.get(c)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = "; ".join(str(x) for x in v)
        lines.append(f"{c}: {v}")
    return "\n".join(lines)
