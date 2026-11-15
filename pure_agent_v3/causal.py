"""CHAIN CAUSAL AUDITED. Each step records a link {id, cause_id, relation, origin, content_hash, prev_hash, hash}. The root of the whole chain of a request is the SPEC of user intention (origin USER_INTENT). Any action with effect must have a chain ININTERRUMPIDA to that root; if it is born from a document, tool output or rootless model in the intention → ORPHAN_ACTION (locked). The links are chained with SHA-256 and recorded in the audit (event CAUSAL): they can be reconstructed and verified after a restart.
"""
from .root.useful import sha256

RELATIONSHIPS = ("GENERATES", "CAUSES", "TRIGGERS", "DRIVES", "POWER", "MULTIPLIES", "AMPLIFIED", "EXPANDS",
              "TRANSFORMS")
ORIGINS = ("USER_INTENT", "MODEL", "EVIDENCE", "TOOL")
GENESIS = "0" * 64


class BrokenChain(ValueError):
    pass


class CausalChain:
    def __init__(self, audit_log=None):
        self.audit = audit_log
        self.links: list[dict] = []
        self._by_id: dict[str, dict] = {}
        if audit_log is not None:                       # reconstruction from the audit
            for r in audit_log.records:
                if r.get("event") == "CAUSAL" and isinstance(r.get("extra"), dict) and "link" in r["extra"]:
                    e = r["extra"]["link"]
                    self.links.append(e)
                    self._by_id[e.get("id")] = e

    def add_item(self, id, cause_id, relationship, origin, content) -> dict:
        if relationship not in RELATIONSHIPS:
            raise BrokenChain(f"unknown ratio: {relationship}")
        if origin not in ORIGINS:
            raise BrokenChain(f"unknown origin: {origin}")
        if cause_id is not None and cause_id not in self._by_id:
            raise BrokenChain(f"non-existent cause: {cause_id}")
        if id in self._by_id:
            raise BrokenChain(f"duplicate link: {id}")
        e = {"id": id, "cause_id": cause_id, "relationship": relationship, "origin": origin,
             "content_hash": sha256(content),
             "prev_hash": self.links[-1]["hash"] if self.links else GENESIS}
        e["hash"] = sha256(e)
        self.links.append(e)
        self._by_id[id] = e
        if self.audit is not None:
            self.audit.register("CAUSAL", request_id=id, link=e)
        return e

    def root(self, id) -> dict | None:
        """Follow cause_id to the root. None if the chain breaks or has cycles."""
        seen_ = set()
        e = self._by_id.get(id)
        while e is not None:
            if e["id"] in seen_:
                return None
            seen_.add(e["id"])
            if e["cause_id"] is None:
                return e
            e = self._by_id.get(e["cause_id"])
        return None

    def rooted_in_intent(self, id) -> bool:
        """Uninterruptible string to root USER_INTENT and all intermediate links with
        origin USER_INTENT or MODEL (the model can PROPOSE from the intention, but a link EVIDENCE/TOOL on the path means that the action was caused by a data)."""
        r = self.root(id)
        if r is None or r["origin"] != "USER_INTENT":
            return False
        e = self._by_id[id]
        while e["cause_id"] is not None:
            if e["origin"] in ("EVIDENCE", "TOOL"):
                return False
            e = self._by_id[e["cause_id"]]
        return True

    def verify(self) -> tuple[bool, str]:
        prev, ids = GENESIS, set()
        for i, e in enumerate(self.links):
            body_ = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev_hash") != prev:
                return False, f"prev_hash broken in link {i}"
            if sha256(body_) != e.get("hash"):
                return False, f"hash altered link {i}"
            if e.get("relationship") not in RELATIONSHIPS or e.get("origin") not in ORIGINS:
                return False, f"relación/origin invalid link {i}"
            if e.get("cause_id") is not None and e["cause_id"] not in ids:
                return False, f"non-existent or subsequent cause in link {i}"
            ids.add(e["id"])
            prev = e["hash"]
        return True, f"OK ({len(self.links)} links)"
