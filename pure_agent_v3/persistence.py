"""L7 · State Manager + Audit Ledger en SQLite (stdlib `sqlite3`).

Tables: `states` (versioned with hashes chain), `audit_log` (append-only, SHA-256 chained, seal HMAC optional with AP3_AUDIT_KEY), `pending` (actions awaiting authorization: survive a restart), `learning` (proposals for rules and their revision), `contadores`. External anchor `audit_head.json` (account + last hash, written in atomic form) to detect the deletion of the tail or the complete replacement of the table (re-used engine idea v5.0.1). Cross states∫audit: each compromised state must appear in the audit. Corrupt tolerance: any JSON/row malformed → verification FAILS (never exception).
"""
import hashlib
import hmac
import json
import os
import sqlite3

from .root.audit_log import GENESIS, Audit, verify_chain
from .root.useful import canon, sha256

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (seq INTEGER PRIMARY KEY, event TEXT NOT NULL, record TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL, seal TEXT);
CREATE TABLE IF NOT EXISTS states (version INTEGER PRIMARY KEY, request_id TEXT, content TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, request_id TEXT, tool TEXT NOT NULL,
    params_ TEXT NOT NULL, hash TEXT NOT NULL, state TEXT NOT NULL, assumptions TEXT, creado REAL, spec TEXT);
CREATE TABLE IF NOT EXISTS learning (id TEXT PRIMARY KEY, data_ TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS contadores (key_ TEXT PRIMARY KEY, value_ INTEGER NOT NULL);
"""


class Store:
    def __init__(self, directory: str, key_hmac: bytes | None = None):
        os.makedirs(directory, exist_ok=True)
        self.dir = directory
        self.path_ = os.path.join(directory, "agente_puro_v3.db")
        self.anchor = os.path.join(directory, "audit_head.json")
        k = key_hmac if key_hmac is not None else os.environ.get("AP3_AUDIT_KEY", "").encode() or None
        self.key_ = k
        self.db = sqlite3.connect(self.path_, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)

    def seal(self, h: str) -> str | None:
        return hmac.new(self.key_, h.encode(), hashlib.sha256).hexdigest() if self.key_ else None

    def version_data(self) -> int:
        return self.db.execute("PRAGMA data_version").fetchone()[0]

    # -------- counters
    def counter(self, key_: str) -> int:
        r = self.db.execute("SELECT value_ FROM contadores WHERE key_=?", (key_,)).fetchone()
        return r[0] if r else 0

    def set_counter(self, key_: str, value_: int):
        self.db.execute("INSERT INTO contadores VALUES(?,?) ON CONFLICT(key_) DO UPDATE SET value_=excluded.value_ "
                        "WHERE excluded.value_ > contadores.value_", (key_, int(value_)))

    # -------- pending
    def save_pending(self, p, assumptions=(), spec=None):
        self.db.execute("INSERT INTO pending VALUES(?,?,?,?,?,?,?,strftime('%s','now'),?) ON CONFLICT(id) DO UPDATE "
                        "SET state=excluded.state, assumptions=excluded.assumptions",
                        (p.id, p.request_id, p.tool, canon(p.params_), p.hash, p.state,
                         canon(list(assumptions)), canon(spec) if spec is not None else None))

    def pending_open(self) -> list[dict]:
        out = []
        for row in self.db.execute("SELECT id, request_id, tool, params_, hash, state, assumptions, spec "
                                   "FROM pending WHERE state='PENDING_AUTHORIZATION' ORDER BY id"):
            try:
                out.append({"id": row[0], "request_id": row[1], "tool": row[2],
                            "params_": json.loads(row[3]), "hash": row[4], "state": row[5],
                            "assumptions": json.loads(row[6] or "[]"), "spec": json.loads(row[7]) if row[7] else None})
            except (ValueError, TypeError):
                out.append({"id": row[0], "corrupt": True})
        return out

    def state_pending(self, pid):
        r = self.db.execute("SELECT state FROM pending WHERE id=?", (pid,)).fetchone()
        return r[0] if r else None

    # -------- learning
    def save_mutation(self, m: dict):
        self.db.execute("INSERT INTO learning VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data_=excluded.data_, "
                        "state=excluded.state", (m["id"], canon(m), m["state"]))

    def mutations(self) -> list[dict]:
        out = []
        for d, in self.db.execute("SELECT data_ FROM learning ORDER BY id"):
            try:
                out.append(json.loads(d))
            except ValueError:
                pass
        return out

    def close_(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass

    def __of__(self):                       # meetings not explicitly closed (tests, REPL)
        db = getattr(self, "db", None)
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


class AuditSQLite(Audit):
    """Audit of the Root Layer supported by SQLite. When booting, load the existing chain
    (and continues). `verify()` checks the chain in memory, the chain in DISK (when another proceso/conexión changed the base), the optional seal HMAC and the external anchor."""

    def __init__(self, clock, store: Store):
        super().__init__(clock, None)
        self.alm = store
        self._dv = None
        self.error_load = None
        try:
            for (reg,) in self.alm.db.execute("SELECT record FROM audit_log ORDER BY seq"):
                self.records.append(json.loads(reg))
        except (ValueError, sqlite3.Error) as e:
            self.error_load = f"unreadable audit: {type(e).__name__}"
        if not self.error_load:
            ok, msg = verify_chain(self.records)
            if not ok:
                self.error_load = f"audit on altered disk when loading ({msg})"
        if not self.error_load:
            # the anchor is checked before the first writing of the session: if not, the first
            # register() rewrote it and a deleted tail went unnoticed after restarting (H-22)
            try:
                ok, msg = self._verify_anchor()
            except (ValueError, OSError, AttributeError, TypeError) as e:
                ok, msg = False, f"Illegible anchor ({type(e).__name__})"
            if not ok:
                self.error_load = f"{msg} when loading"

    def register(self, event: str, **fields) -> dict:
        reg = super().register(event, **fields)
        try:
            self.alm.db.execute("INSERT INTO audit_log VALUES(?,?,?,?,?,?)",
                                (reg["seq"], event, canon(reg), reg["prev_hash"], reg["hash"], self.alm.seal(reg["hash"])))
        except sqlite3.Error as e:
            # e.g. sequence collision because someone deleted rows: never throws, marks and verify() fails (HALT)
            self.error_load = f"inconsistent disc audio when writing ({type(e).__name__})"
            return reg
        tmp = self.alm.anchor + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(canon({"count": len(self.records), "head": reg["hash"]}))
        os.replace(tmp, self.alm.anchor)
        # does not update self._dv here: own scriptures do not change data_version, and mark the
        # base as "view" when writing concealed external alterations (finding H-01).
        return reg

    def verify(self) -> tuple[bool, str]:
        if self.error_load:
            return False, self.error_load
        ok, msg = verify_chain(self.records)
        if not ok:
            return ok, msg
        try:
            dv = self.alm.version_data()
            if dv != self._dv:                      # someone else touched the base: complete verification on disk
                ok, msg = self.verify_disk()
                if not ok:
                    return ok, msg
                self._dv = dv
            return self._verify_anchor()
        except (sqlite3.Error, ValueError, TypeError, OSError) as e:
            return False, f"malformed audit ({type(e).__name__})"

    def _verify_anchor(self):
        n = len(self.records)
        if not os.path.exists(self.alm.anchor):
            return (False, "anchor audit_head.json absent") if n else (True, "OK (0 records)")
        with open(self.alm.anchor, encoding="utf-8") as f:
            a = json.load(f)
        head = self.records[-1]["hash"] if n else GENESIS
        if not isinstance(a, dict) or a.get("count") != n or a.get("head") != head:
            return False, "Anchor does not match (deleted glue or replaced table)"
        return True, f"OK ({n} records)"

    def verify_disk(self) -> tuple[bool, str]:
        try:
            rows = self.alm.db.execute("SELECT seq, event, record, prev_hash, hash, seal FROM audit_log ORDER BY seq").fetchall()
            if len(rows) != len(self.records):
                return False, f"the base has {len(rows)} records and the live chain {len(self.records)}"
            regs = []
            for seq, event, reg, prev, h, seal in rows:
                r = json.loads(reg)
                if r.get("seq") != seq or r.get("event") != event or r.get("prev_hash") != prev or r.get("hash") != h:
                    return False, f"inconsistent columns in sec {seq}"
                if self.alm.key_ and not hmac.compare_digest(self.alm.seal(h) or "", seal or ""):
                    return False, f"seal HMAC invalid in seq {seq}"
                regs.append(r)
            ok, msg = verify_chain(regs)
            if not ok:
                return False, "disco: " + msg
            for a, b in zip(regs, self.records):
                if a["hash"] != b["hash"]:
                    return False, f"disk and memory diverge in seq {a['seq']}"
            return True, "OK"
        except (sqlite3.Error, ValueError, TypeError, AttributeError) as e:
            return False, f"malformed audit ({type(e).__name__})"


class VersionedState:
    """Truth State versioned in SQLite (same API as v2: compromise/verify)."""

    def __init__(self, store: Store, audit_log=None):
        self.alm = store
        self.audit = audit_log
        self.history: list[dict] = []
        self.version, self.hash = 0, GENESIS
        for v, rid, cont, prev, h in store.db.execute(
                "SELECT version, request_id, content, prev_hash, hash FROM states ORDER BY version"):
            try:
                c = json.loads(cont)
            except ValueError:
                c = {"_corrupt": cont}
            self.history.append({"version": v, "prev_hash": prev, "content": c, "hash": h})
            self.version, self.hash = v, h

    def compromise(self, content: dict) -> dict:
        reg = {"version": self.version + 1, "prev_hash": self.hash, "content": content}
        reg["hash"] = sha256(canon(reg))
        self.alm.db.execute("INSERT INTO states VALUES(?,?,?,?,?)", (reg["version"], content.get("request_id"),
                                                                     canon(content), reg["prev_hash"], reg["hash"]))
        self.version, self.hash = reg["version"], reg["hash"]
        self.history.append(reg)
        if self.audit is not None:
            self.audit.register("STATE_COMMIT", request_id=content.get("request_id"),
                                 state_after=content.get("decision"), state_hash=reg["hash"], version=reg["version"])
        return reg

    def verify(self) -> bool:
        return self.verify_detail()[0]

    def verify_detail(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, r in enumerate(self.history, 1):            # viva chain (memory)
            body_ = {k: v for k, v in r.items() if k != "hash"}
            if r.get("version") != i or r.get("prev_hash") != prev or sha256(canon(body_)) != r.get("hash"):
                return False, f"altered memory status in version {i}"
            prev = r["hash"]
        prev = GENESIS
        try:
            rows = self.alm.db.execute("SELECT version, content, prev_hash, hash FROM states ORDER BY version").fetchall()
            for i, (v, cont, p, h) in enumerate(rows, 1):
                body_ = {"version": v, "prev_hash": p, "content": json.loads(cont)}
                if v != i or p != prev or sha256(canon(body_)) != h:
                    return False, f"altered status in version {i}"
                prev = h
            if [f[3] for f in rows] != [r["hash"] for r in self.history]:
                return False, "disk and memory diverge"
            if self.audit is not None:
                in_audit = {(r.get("extra") or {}).get("state_hash") for r in self.audit.records
                            if r.get("event") == "STATE_COMMIT"}
                missing = [v for v, _, _, h in rows if h not in in_audit]
                if missing:
                    return False, f"states without audit record: {missing[:5]}"
            return True, f"OK ({len(rows)} versions)"
        except (sqlite3.Error, ValueError, TypeError) as e:
            return False, f"malformed ({type(e).__name__})"
