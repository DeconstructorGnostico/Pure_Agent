"""NRE · Application Runtime: initialization, setting by environment variables and life cycle.

Variables: AP3_HOME (data directory), NRE_MODEL_PROVIDER (stubllama), OLLAMA_URL, NRE_MODEL, NRE_MODEL_TIMEOUT, AP3_AUDIT_KEY (seal HMAC optional audit), AP3_MAX_CYCLES.
"""
import json
import os

from .amm_core import PureAgent
from .evidence import TableSource
from .gateway import OllamaModel
from .model_ import StubModel


class InvalidConfiguration(ValueError):
    pass


def configuration(env=None) -> dict:
    env = os.environ if env is None else env
    prov = env.get("NRE_MODEL_PROVIDER", "stub").lower()
    if prov not in ("stub", "ollama"):
        raise InvalidConfiguration(f"NRE_MODEL_PROVIDER desconocido: {prov} (stub|ollama)")
    try:
        cycles = int(env.get("AP3_MAX_CYCLES", "3"))
    except ValueError:
        raise InvalidConfiguration("AP3_MAX_CYCLES must be integer") from None
    if not 1 <= cycles <= 10:
        raise InvalidConfiguration("AP3_MAX_CYCLES outside [1,10]")
    return {"provider": prov, "home": env.get("AP3_HOME") or None, "max_cycles": cycles}


def create_model(cfg):
    return OllamaModel() if cfg["provider"] == "ollama" else StubModel()


def load_sources(path_):
    if not path_:
        return []
    with open(path_, encoding="utf-8") as f:
        data_ = json.load(f)
    if not isinstance(data_, dict) or not all(isinstance(v, bool) for v in data_.values()):
        raise InvalidConfiguration("el archivo de fuentes debe ser {proposition: true|false}")
    return [TableSource(data_, id="source-file")]


class Runtime:
    """Lifecycle: start → AMM-CORE → close. A restart preserves state, audit,
    pending actions, rules learned approved and an active HALT (does not delete rebooting)."""

    def __init__(self, directory=None, sources=(), model_=None, env=None, **kw):
        self.cfg = configuration(env)
        self.agent = PureAgent(model_=model_ or create_model(self.cfg), sources=sources,
                                 directory=directory or self.cfg["home"], max_cycles=self.cfg["max_cycles"], **kw)

    def __enter__(self):
        return self.agent

    def __exit__(self, *exc):
        self.close_()

    def close_(self):
        self.agent.store.close_()
