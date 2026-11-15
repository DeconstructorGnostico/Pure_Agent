"""Utilities shared by tests v3."""
import tempfile

from pure_agent_v3 import PureAgent, TableSource
from pure_agent_v3.root.model_ import SimulatedModel

SOURCES = {"París es la capital de Francia": True, "La Luna es un planeta": False}


def directory():
    return tempfile.mkdtemp(prefix="ap3t_")


def agent(model_=None, d=None, **kw):
    return PureAgent(model_=model_, sources=[TableSource(SOURCES, id="source")], directory=d or directory(), **kw)


def hostile(proposal, id="modelo-hostil"):
    return SimulatedModel(proposal, id=id)


PROTECTIVE = {"REJECT", "HALT", "NEED_INPUT", "PENDING_AUTHORIZATION"}
