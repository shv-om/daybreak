"""Append-only, hash-chained JSONL audit log (tamper-evident, not tamper-proof)."""
from __future__ import annotations
import hashlib, json, time


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        try:
            with open(self.path, "rb") as f:
                lines = f.read().splitlines()
            return json.loads(lines[-1])["hash"] if lines else "0" * 64
        except FileNotFoundError:
            return "0" * 64

    def record(self, event: str, **fields) -> dict:
        entry = {"ts": time.time(), "event": event, "prev": self._prev, **fields}
        body = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256(body.encode()).hexdigest()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        self._prev = entry["hash"]
        return entry

    @staticmethod
    def verify(path: str) -> bool:
        prev = "0" * 64
        with open(path, encoding="utf-8") as f:
            for line in f:
                e = json.loads(line)
                h = e.pop("hash")
                if e["prev"] != prev:
                    return False
                if hashlib.sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest() != h:
                    return False
                prev = h
        return True
