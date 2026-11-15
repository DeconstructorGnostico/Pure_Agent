"""§13 Tool control · §7 (BG) · §5/§16 Run trigger.

Availability permission. Flow: TOOL_REQUEST → PERMISSION_CHECK → INVARIANT_CHECK → AUTHORIZATION → EXECUTION → RESULT_VALIDATION → AUDIT. If the tool does not exist, it is not simulated: the result is UNCERTAIN.
"""
from dataclasses import dataclass, field
from typing import Callable

from .useful import sha256


@dataclass
class Tool:
    name_: str
    function: Callable
    effect_external: bool = True
    params_required: tuple = ()
    validate_result: Callable | None = None    # post-execution verification (EXECUTED SUCCESS)
    calls: list = field(default_factory=list)  # spy for tests: test that it was not executed


def hash_action(tool: str, params_: dict) -> str:
    return sha256({"tool": tool, "params_": params_})


class Executor:
    """Only component that invokes tools. Issues a signed RECEIPT (evidence of use)."""

    def __init__(self, signer, tools: dict):
        self._f = signer
        self._h = tools

    def execute_(self, name_: str, params_: dict):
        h = self._h[name_]
        try:
            output = h.function(**params_)
            h.calls.append(dict(params_))
            ok, error = True, None
        except Exception as e:  # failure is recorded; never becomes success
            output, ok, error = None, False, f"{type(e).__name__}: {e}"
        receipt = self._f.issue("RECEIPT", hash_action(name_, params_), ok=ok,
                                output_hash=sha256(str(output)), error=error)
        return ok, output, error, receipt
