"""Utilities: canonical hashing and clock for injection."""
import hashlib
import json
import time


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256(obj) -> str:
    data = obj if isinstance(obj, str) else canon(obj)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class Clock:
    """Clock for injection (test determinism)."""

    def __init__(self, fixed: float | None = None):
        self.fixed = fixed

    def now_(self) -> float:
        return self.fixed if self.fixed is not None else time.time()
