"""Compatibility: `PureAgent` is the orchestrator AMM-CORE (see amm_core.py)."""
from .amm_core import VERSION, PureAgent  # noqa: F401

AMMCore = PureAgent
