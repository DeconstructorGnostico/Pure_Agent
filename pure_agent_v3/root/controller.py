"""CONTROLLER EXTERNAL = AUTHORITY OPERACIONAL (§14/§15 BG, §2 Root Layer).

In production lives OUT of the model process (another service, a human with a key). Here it is simulated in-process: it is the only one that has the Signant AUTORIZADOR. `approved_by` is only source: what authorizes is the signature.
"""
import secrets

from .useful import sha256


class Controller:
    def __init__(self, signer, clock, ttl=300.0):
        self._f = signer
        self._clock = clock
        self.ttl = ttl
        self.issued: list = []

    def authorize(self, pending, approved_by="controller"):
        t = self._f.issue("AUTHORIZED", pending.hash, ticket=pending.id,
                           nonce=secrets.token_hex(8), expires=self._clock.now_() + self.ttl,
                           approved_by=approved_by)
        self.issued.append(t)
        return t

    def authorize_change(self, record, approved_by="controller"):
        return self._f.issue("CHANGE_AUTH", record["hash"], change=record["id"],
                              nonce=secrets.token_hex(8), expires=self._clock.now_() + self.ttl,
                              approved_by=approved_by)

    def reset(self, reason="controller review"):
        return self._f.issue("RESET", sha256(reason), reason=reason, nonce=secrets.token_hex(8))
