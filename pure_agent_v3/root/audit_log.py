"""§21 Structural audit · INV-R05 Traceability.

String SHA-256: each record includes the hash of the previous one. `verify()` recalculates the whole chain: if someone alters, deletes or reorders a record, it fails. The model does not receive reference to this object.
"""
from .useful import canon, sha256

GENESIS = "0" * 64
FIELDS = ("timestamp", "request_id", "state_before", "input_hash", "context_hash",
          "model_id", "model_version", "invariants_checked", "validation_results",
          "proposal", "authorization", "execution", "state_after", "error", "halt_reason")


class Audit:
    def __init__(self, clock, path_: str | None = None):
        self._clock = clock
        self.records: list[dict] = []
        self.path_ = path_

    def register(self, event: str, **fields) -> dict:
        prev = self.records[-1]["hash"] if self.records else GENESIS
        reg = {"seq": len(self.records), "event": event, "prev_hash": prev}
        for c in FIELDS:
            reg[c] = fields.pop(c, None)
        if reg["timestamp"] is None:
            reg["timestamp"] = self._clock.now_()
        reg["extra"] = fields or None
        reg["hash"] = sha256(_body(reg))
        self.records.append(reg)
        if self.path_:
            with open(self.path_, "a", encoding="utf-8") as f:
                f.write(canon(reg) + "\n")
        return reg

    def verify(self) -> tuple[bool, str]:
        return verify_chain(self.records)

    def __len__(self):
        return len(self.records)


def _body(reg: dict) -> dict:
    return {k: v for k, v in reg.items() if k != "hash"}


def verify_chain(records: list[dict]) -> tuple[bool, str]:
    prev = GENESIS
    for i, reg in enumerate(records):
        if reg.get("seq") != i:
            return False, f"broken sequence in {i}"
        if reg.get("prev_hash") != prev:
            return False, f"prev_hash does not match {i}"
        if sha256(_body(reg)) != reg.get("hash"):
            return False, f"hash altered in {i}"
        prev = reg["hash"]
    return True, f"OK ({len(records)} records)"
