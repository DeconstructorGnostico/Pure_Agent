"""CLI of Pure Agent v3.

python -m pure_agent_v3 --demo
python -m pure_agent_v3 --input "text" [--datum "external"] [--json] [--dir D] [--sources f.json]
python -m pure_agent_v3 --input-file request.json      (contract NRE: intent/constraints/context/evidence)
python -m pure_agent_v3 --interactive                     (tú eres el CONTROLLER EXTERNAL)
python -m pure_agent_v3 --audit-check --dir D             (verificación de only reading)
python -m pure_agent_v3 --bench [--bench-dir bench]       (bank adversarial reproducible)
Modelo: NRE_MODEL_PROVIDER=stub|ollama (OLLAMA_URL, NRE_MODEL, NRE_MODEL_TIMEOUT).
"""
import argparse
import json
import os
import sys

from .amm_core import VERSION


def _display(o, as_json):
    if as_json:
        print(json.dumps({k: v for k, v in o.items() if k != "report"}, ensure_ascii=False, indent=2, default=str))
        return
    print(o["report"])
    if o.get("response"):
        print("RESPUESTA:", o["response"])
    for p in o.get("pending", []):
        if p.get("assumptions"):
            print(f"  ASSUMPTIONS DECLARED in {p['id']}: {p['assumptions']} (inferred by model; confirm)")


def audit_check(directory) -> dict:
    from .persistence import Store, AuditSQLite, VersionedState
    from .root.useful import Clock
    if not directory or not os.path.exists(os.path.join(directory, "agente_puro_v3.db")):
        return {"ok": False, "reason": "no base pure_agent_v3.db in the directory (use --dir or AP3_HOME)"}
    alm = Store(directory)
    try:
        au = AuditSQLite(Clock(), alm)
        ok_a, msg_a = au.verify()
        ok_e, msg_e = VersionedState(alm, au).verify_detail()
        return {"ok": ok_a and ok_e, "audit_log": msg_a, "state": msg_e, "records": len(au.records),
                "mode": "HMAC-SHA256" if alm.key_ else "SHA-256",
                "halt_active": bool(alm.counter("halted")),
                "pending_open": len(alm.pending_open())}
    finally:
        alm.close_()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pure_agent_v3", description=f"Pure Agent v{VERSION} (NRE–AMM–OMEGA + Root Layer)")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--input", help="text to process")
    ap.add_argument("--input-file", help="JSON with the application contract NRE")
    ap.add_argument("--datum", action="append", default=[], help="external (untrustable) data; repeatable")
    ap.add_argument("--sources", help="JSON {proposition: true/false} as a registered source")
    ap.add_argument("--dir", help="data directory (SQLite, sandbox); default AP3_HOME or temporary")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--interactive", action="store_true")
    ap.add_argument("--audit-check", action="store_true")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--bench-dir", help="bench/ folder (default, project folder)")
    ap.add_argument("--version", action="store_true")
    a = ap.parse_args(argv)
    if a.version:
        print(VERSION)
        return 0
    if a.demo:
        from .demo import main as demo
        return demo()
    if a.bench:
        from .bank import main as bank
        return bank(a.bench_dir)
    if a.audit_check:
        r = audit_check(a.dir or os.environ.get("AP3_HOME"))
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if r["ok"] else 3
    if not (a.input or a.input_file or a.interactive):
        ap.print_help()
        return 0
    from .nre import InvalidConfiguration, Runtime, load_sources
    try:
        rt = Runtime(directory=a.dir, sources=load_sources(a.sources))
    except (InvalidConfiguration, OSError, ValueError) as e:
        print(f"invalid configuration: {e}", file=sys.stderr)
        return 4
    agent = rt.agent
    try:
        if a.input_file:
            try:
                with open(a.input_file, encoding="utf-8") as f:
                    sol = json.load(f)
            except (OSError, ValueError) as e:
                print(f"could not read request: {type(e).__name__}", file=sys.stderr)
                return 4
            o = agent.process_request(sol)
            _display(o, a.json)
            return 0 if o["decision"] != "HALT" else 2
        if a.input:
            o = agent.process(a.input, a.datum)
            _display(o, a.json)
            return 0 if o["decision"] != "HALT" else 2
        print(f"Pure Agent v{VERSION} · 'come out' to finish · you are the CONTROLLER EXTERNAL · data in {agent.dir}")
        for pid in agent.rehidratadas:
            print(f"(recovered action after restart: {pid})")
        while True:
            try:
                t = input("> ").strip()
            except EOFError:
                break
            if t.lower() in ("salir", "exit", "quit"):
                break
            if not t:
                continue
            o = agent.process(t)
            _display(o, a.json)
            for p in o.get("pending", []):
                if p["state"] != "PENDING_AUTHORIZATION":
                    continue
                extra = f" · SUPUESTOS {p['assumptions']}" if p.get("assumptions") else ""
                try:
                    r = input(f"¿Autorizas {p['tool']} {p['params_']}{extra}? (s/N) ").strip().lower()
                except EOFError:
                    r = ""
                _display(agent.authorize(p["id"], "interactive controller") if r == "s"
                         else agent.refuse(p["id"]), a.json)
        print(f"audit: {agent.audit_log.verify()} · directory: {agent.dir}")
        return 0
    finally:
        rt.close_()


if __name__ == "__main__":
    sys.exit(main())
