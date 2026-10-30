"""Human approval store. Only a human (scripts/approve.py) can approve; the gateway can only ask.
An approval is bound to the exact tool+args, expires, and is single-use."""
from __future__ import annotations
import hashlib, json, sqlite3, threading, time

SCHEMA = """CREATE TABLE IF NOT EXISTS approvals(
  id INTEGER PRIMARY KEY, tool TEXT NOT NULL, args_json TEXT NOT NULL, args_sha256 TEXT NOT NULL,
  requested_at REAL NOT NULL, status TEXT NOT NULL, decided_at REAL, decided_by TEXT, expires_at REAL)"""


def _key(tool: str, args: dict):
    a = json.dumps(args, sort_keys=True)
    return a, hashlib.sha256(f"{tool}|{a}".encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path: str, ttl_s: float = 900.0, clock=time.time):
        self.db, self.ttl, self.clock = sqlite3.connect(path, check_same_thread=False), ttl_s, clock
        self._lock = threading.RLock()
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute(SCHEMA)

    def request(self, tool: str, args: dict) -> int:
        with self._lock:
            a, h = _key(tool, args)
            r = self.db.execute("SELECT id FROM approvals WHERE args_sha256=? AND status='pending'", (h,)).fetchone()
            if r:
                return r[0]
            cur = self.db.execute("INSERT INTO approvals(tool, args_json, args_sha256, requested_at, status) VALUES(?,?,?,?, 'pending')",
                                  (tool, a, h, self.clock()))
            self.db.commit()
            return cur.lastrowid

    def decide(self, approval_id: int, approve: bool, who: str) -> bool:
        with self._lock:
            now = self.clock()
            cur = self.db.execute("UPDATE approvals SET status=?, decided_at=?, decided_by=?, expires_at=? WHERE id=? AND status='pending'",
                                  ("approved" if approve else "denied", now, who, now + self.ttl if approve else None, approval_id))
            self.db.commit()
            return cur.rowcount == 1

    def find_approved(self, tool: str, args: dict):
        with self._lock:
            _, h = _key(tool, args)
            r = self.db.execute("SELECT id FROM approvals WHERE args_sha256=? AND status='approved' AND expires_at > ? ORDER BY id DESC LIMIT 1",
                                (h, self.clock())).fetchone()
            return r[0] if r else None

    def reserve_approved(self, tool: str, args: dict):
        """Atomically claim one matching approval before execution.

        SQLite's BEGIN IMMEDIATE serializes competing writers so two gateway instances cannot
        both observe and use the same single-use approval. The reservation is committed before
        the tool handler runs, then either consumed on success or released on handler failure.
        """
        with self._lock:
            _, h = _key(tool, args)
            now = self.clock()
            try:
                self.db.execute("BEGIN IMMEDIATE")
                r = self.db.execute(
                    "SELECT id FROM approvals WHERE args_sha256=? AND status='approved' AND expires_at > ? "
                    "ORDER BY id DESC LIMIT 1", (h, now)).fetchone()
                if r is None:
                    self.db.commit()
                    return None
                cur = self.db.execute(
                    "UPDATE approvals SET status='executing' WHERE id=? AND status='approved' AND expires_at > ?",
                    (r[0], now))
                self.db.commit()
                return r[0] if cur.rowcount == 1 else None
            except Exception:
                self.db.rollback()
                raise

    def release(self, approval_id: int) -> bool:
        """Return a reservation after a tool failure, unless it expired while executing."""
        with self._lock:
            now = self.clock()
            cur = self.db.execute(
                "UPDATE approvals SET status=CASE WHEN expires_at > ? THEN 'approved' ELSE 'expired' END "
                "WHERE id=? AND status='executing'", (now, approval_id))
            self.db.commit()
            return cur.rowcount == 1

    def consume(self, approval_id: int) -> bool:
        with self._lock:
            cur = self.db.execute("UPDATE approvals SET status='used' WHERE id=? AND status='executing'", (approval_id,))
            self.db.commit()
            return cur.rowcount == 1

    def pending(self) -> list:
        with self._lock:
            return self.db.execute("SELECT id, tool, args_json, requested_at FROM approvals WHERE status='pending' ORDER BY id").fetchall()
