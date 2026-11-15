"""Mutation testing light (without dependencies): applies mutants to a COPY package in a temporary directory and executes v3 + inherited suites. A mutant "dies" if any test fails. Usage: Python tools/mutation.py → prints table and writes tools/mutation_results.md"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (id, package file, original, mutant, what breaks)
MUTANTS = [
    ("M01", "decision.py", "        modo = NEED_INPUT\n    elif", "        modo = EJECUTAR\n    elif", "decidir: crítica desconocida ejecuta"),
    ("M02", "decision.py", 'if c.get("alineada") is not True or c.get("verificada") is not True:', 'if False:', "choose_candidate sin filtro"),
    ("M03", "decision.py", "    return None, historial", "    return cand, historial", "reproceso entrega lo que no pasó calidad"),
    ("M04", "decision.py", "        if _range(v, k) < u:", "        if _range(v, k) < 0:", "control de calidad sin umbral"),
    ("M05", "zero_trust.py", "act in self._g.get(main, frozenset())", "True", "Zero-Trust allow-all"),
    ("M06", "causal.py", '            if e["origen"] in ("EVIDENCE", "TOOL"):\n                return False', '            if False:\n                return False', "acción provocada por dato pasa como enraizada"),
    ("M07", "causal.py", "            if e.get(\"prev_hash\") != prev:", "            if False:", "cadena causal sin prev_hash"),
    ("M08", "intent.py", '"modo": "BLOQUEAR"', '"modo": "EJECUTAR"', "violación de spec no bloquea"),
    ("M09", "persistence.py", "            if not ok:\n                self.error_load = f\"{msg} al cargar\"", "            if False:\n                pass", "ancla no se verifica al cargar (H-22)"),
    ("M10", "persistence.py", "            if dv != self._dv:", "            if False:", "sin verificación en disco ante otra conexión"),
    ("M11", "root/governor.py", 'elif token.datum("expires", 0) < self.clock.now_():', 'elif False:', "token expirado aceptado"),
    ("M12", "root/governor.py", 'elif token.datum("nonce") in self._nonces:', 'elif False:', "replay de token aceptado"),
    ("M13", "root/normalization.py", "    t = t.lower().translate(_HOMOGLIFOS)", "    t = t.lower()", "sin mapa de homóglifos"),
    ("M14", "root/firewall.py", '"pretend_without_rules": rf"', '"fingir_sin_reglas": rf"(?!)', "sin patrón pretend_without_rules"),
    ("M15", "amm_core.py", "        if ruta is not None and not _ruta_segura(ruta):", "        if False:", "ruta insegura llega al controlador (H-20)"),
    ("M16", "amm_core.py", '        if not self.causal.rooted_in_intent(p.id):\n            return "BLOQUEAR: "', '        if False:\n            return "BLOQUEAR: "', "acción huérfana no se bloquea"),
    ("M17", "gateway.py", '    artifacts = [obj[k] for k in ("artifacts", "tokens", "evidence_signed", "signature_") if obj.get(k)]', '    artefactos = []', "tokens inventados por el modelo se descartan en silencio"),
    ("M18", "door.py", "TASKS_ALLOWED = (", "TASKS_ALLOWED = ('shell', 'execute_shell', ", "lista cerrada ampliada"),
    ("M19", "deconstructor.py", "            if not ca or not cb:\n                continue", "            if False:\n                continue", "claim_id vacío contradice"),
    ("M21", "amm_core.py", 'if p.state == "PENDING_AUTHORIZATION" and not self.causal.rooted_in_intent(p.id):', 'if False:', "autorizar acepta acción huérfana"),
    ("M22", "root/normalization.py", '    if re.search(r"\\S {2,}\\S", texto or ""):', '    if False:', "sin variante de letras separadas (H-23)"),
    ("M20", "evidence.py", "        return self.facts[key_] == (value_ if paridad == 0 else not value_)", "        return None", "afirmaciones del modelo nunca verificadas (H-25)"),
]


def main():
    rows, dead_list = [], 0
    for mid, arch, orig, mut, desc in MUTANTS:
        tmp = tempfile.mkdtemp(prefix="ap3mut_")
        shutil.copytree(ROOT, os.path.join(tmp, "p"), ignore=shutil.ignore_patterns("__pycache__", "bench", "*.tar.gz", ".git"))
        path_ = os.path.join(tmp, "p", "pure_agent_v3", arch)
        s = open(path_, encoding="utf-8").read()
        if s.count(orig) < 1:
            rows.append((mid, arch, desc, "NO APLICA (patrón no encontrado)", 0))
            continue
        open(path_, "w", encoding="utf-8").write(s.replace(orig, mut, 1))
        t0 = time.time()
        r = subprocess.run([sys.executable, "-m", "unittest", "-q", "tests.test_v3_unit", "tests.test_v3_adversarial",
                            "tests.test_v3_integration", "tests.test_v3_ollama", "tests.test_v2_inherited",
                            "tests.test_root_inherited_layer_root"],
                           cwd=os.path.join(tmp, "p"), capture_output=True, text=True, timeout=900)
        dead = r.returncode != 0
        dead_list += dead
        rows.append((mid, arch, desc, "MUERTO" if dead else "SOBREVIVE", round(time.time() - t0, 1)))
        shutil.rmtree(tmp, ignore_errors=True)
        print(*rows[-1], sep=" · ", flush=True)
    applied = sum(1 for f in rows if not f[3].startswith("NO APLICA"))
    L = ["# Mutation testing ligero", "", f"Mutantes aplicados: {applied} · muertos: {dead_list} · "
         f"puntuación: {dead_list}/{applied}", "", "| id | archivo | mutación | resultado | s |", "|---|---|---|---|---|"]
    L += [f"| {a} | {b} | {c} | {d} | {e} |" for a, b, c, d, e in rows]
    L += ["", "Nota M12: el control de nonce repetido es defensa en profundidad. Un token está ligado a UNA acción "
          "(sujeto = hash de la acción, ticket = id) y la máquina de estados ya impide ejecutar dos veces la misma "
          "acción; tras reiniciar, las llaves de la sesión cambian y el token viejo es inválido (HALT). No encontramos "
          "una ruta en la que solo el nonce lo detenga: mutante equivalente en la práctica actual, se conserva el control."]
    open(os.path.join(ROOT, "tools", "mutation_results.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    return 0 if dead_list == applied else 1


if __name__ == "__main__":
    sys.exit(main())
