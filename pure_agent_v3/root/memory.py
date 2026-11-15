"""§14 Memory control · §8 selective learning · MEMORY TRUTH.

INPUT → MEMORY_CANDIDATE → VALIDATED_MEMORY → PERSISTED_STATE. Only what you have EXTERNAL_EVIDENCE SUPPORTED is validated. Persisting requires a signed receipt PERSISTED.
"""
import json
import os

from .useful import sha256


class Memory:
    def __init__(self, signer, path_: str | None = None):
        self._f = signer
        self.candidates: list[dict] = []
        self.validated: list[dict] = []
        self.persistida: list[dict] = []
        self.path_ = path_

    def candidate(self, content: str, origin: str):
        c = {"content": content, "origin": origin, "state": "MEMORY_CANDIDATE"}
        self.candidates.append(c)
        return c

    def validate(self, c: dict, verdict) -> bool:
        if verdict is None or verdict.class_ != "EXTERNAL_EVIDENCE" or verdict.truth != "SUPPORTED":
            c["state"] = "DESCARTADO (without external evidence)"
            return False
        c["state"] = "VALIDATED_MEMORY"
        self.validated.append(c)
        return True

    def persist(self, record: dict):
        """Real persistence (file with fsync if there is route) and signed receipt."""
        record = dict(record, state="PERSISTED_STATE")
        self.persistida.append(record)
        if self.path_:
            with open(self.path_, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
        return self._f.issue("PERSISTED", sha256(record), n=len(self.persistida))

    def remember(self):
        """Remembered is returned as MEMORY, not as true."""
        return [{"memory": m["content"], "class_": "MEMORY (≠ TRUTH)"} for m in self.persistida
                if m.get("type_") == "learning"]
