"""§2 Sovereignty / INV-R08 Separation of functions.

Each component is a *main* with A critical role only. The artifacts (verdicts, tokens, receipts) are signed with HMAC-SHA256 with the key of the main emitter; the model never receives a Firmer, so it cannot issue valid artifacts (INV-R02, INV-R03).
"""
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from .useful import canon

ROLES = ("MODEL", "VALIDATOR", "VERIFIER", "AUTHORIZER", "EXECUTOR",
         "PERSISTENCE", "AUDITOR")


class SeparationOfDuties(Exception):
    pass


@dataclass(frozen=True)
class Artifact:
    type_: str          # VALID, INVALID, AUTHORIZED, RECIBO, POST_OK, POST_FAIL, PERSISTED, RESET, CHANGE_AUTH
    issuer: str
    role: str
    subject: str        # hash of what you mean
    data_: tuple = field(default_factory=tuple)   # Unchangeable pairs (key, value)
    signature_: str = ""

    def payload(self) -> str:
        return canon([self.type_, self.issuer, self.role, self.subject, list(self.data_)])

    def datum(self, key_, default=None):
        for k, v in self.data_:
            if k == key_:
                return v
        return default


class Signer:
    """Main A signature capability. Only your component receives it."""

    def __init__(self, main: str, role: str, secret_key: bytes):
        self.main, self.role, self._key = main, role, secret_key

    def issue(self, type_: str, subject: str, **data_) -> Artifact:
        a = Artifact(type_, self.main, self.role, subject, tuple(sorted(data_.items())))
        signature_ = hmac.new(self._key, a.payload().encode(), hashlib.sha256).hexdigest()
        return Artifact(a.type_, a.issuer, a.role, a.subject, a.data_, signature_)


class Keyring:
    """Registration of principals. It imposes a role per principal."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}
        self._roles: dict[str, str] = {}

    def register(self, main: str, role: str) -> Signer | None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role}")
        if main in self._roles and self._roles[main] != role:
            raise SeparationOfDuties(
                f"INV-R08: {main} already has a role {self._roles[main]}; it cannot be {role}")
        if main in self._roles:
            raise SeparationOfDuties(f"INV-R08: {main} already registered")
        self._roles[main] = role
        if role == "MODEL":
            return None          # the model does not receive signature capacity
        secret_key = secrets.token_bytes(32)
        self._keys[main] = secret_key
        return Signer(main, role, secret_key)

    def role_of(self, main: str) -> str | None:
        return self._roles.get(main)

    def verify(self, art, role_expected: str | None = None, type_: str | None = None) -> bool:
        if not isinstance(art, Artifact):
            return False
        if self._roles.get(art.issuer) != art.role:
            return False
        if role_expected and art.role != role_expected:
            return False
        if type_ and art.type_ != type_:
            return False
        secret_key = self._keys.get(art.issuer)
        if secret_key is None:
            return False
        expected = hmac.new(secret_key, art.payload().encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, art.signature_)
