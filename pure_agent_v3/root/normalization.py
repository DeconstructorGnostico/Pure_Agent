"""Standardisation prior to firewall (§5): NFKC, no accents, no invisible characters, lowercase, basic Leetspeak and collapsed spaces."""
import re
import unicodedata

_INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


# v3: more common homoglyphs cirílicos/griegos (finding DEV: {gnora’ with I Cyrillic passed)
_HOMOGLIFOS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
                             "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "ɡ": "g", "α": "a", "ο": "o", "ι": "i", "ε": "e",
                             "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "χ": "x", "ѵ": "v", "ԛ": "q", "ԝ": "w"})
_SEPARATORS = re.compile(r"(?<=\w)[.\-_*·•|](?=\w)")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def normalize_text(text: str) -> str:
    t = unicodedata.normalize("NFKC", text or "")
    t = _INVISIBLE.sub("", t)
    t = "".join(c for c in unicodedata.normalize("NFD", t) if unicodedata.category(c) != "Mn")
    t = t.lower().translate(_HOMOGLIFOS)
    return re.sub(r"\s+", " ", t).strip()


def variants(text: str) -> list[str]:
    n = normalize_text(text)
    leet = n.translate(_LEET)
    # separate letters: "i g n o r a" -> "ignora"
    together = re.sub(r"\b(\w) (?=\w\b)", r"\1", n)
    vs = [n, leet, together]
    # 'i g n o r a t u s r e g l a s': two or more spaces separate words, one separates letters
    if re.search(r"\S {2,}\S", text or ""):
        blocks = [re.sub(r"(?<=\S) (?=\S)", "", b) for b in re.split(r" {2,}", text)]
        vs.append(normalize_text(" ".join(blocks)))
    without_sep = _SEPARATORS.sub("", n)            # ‘i.g.n.o.r.e’, ‘ig-no-ra’
    if without_sep != n:
        vs += [without_sep, without_sep.translate(_LEET)]
    for b in _B64.findall(text or ""):          # base64 embedded: decoded for inspection only
        try:
            import base64
            dec = base64.b64decode(b + "=" * (-len(b) % 4), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if dec and sum(c.isprintable() for c in dec) / len(dec) > 0.9:
            vs.append(normalize_text(dec))
    return list(dict.fromkeys(vs))
