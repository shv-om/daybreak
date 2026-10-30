"""Knowledge-base store: every record traces back to a snapshot (source, URL, time, content hash)."""
from __future__ import annotations
import hashlib, json, sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_snapshots(
  id INTEGER PRIMARY KEY, source TEXT NOT NULL, source_url TEXT NOT NULL, retrieved_at TEXT NOT NULL,
  content_sha256 TEXT NOT NULL, source_version TEXT, raw_path TEXT, accepted INTEGER, rejected INTEGER, license_note TEXT);
CREATE TABLE IF NOT EXISTS kev_entries(
  cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT, due_date TEXT,
  ransomware_use TEXT, cwes_json TEXT, short_description TEXT, required_action TEXT,
  first_snapshot_id INTEGER, last_snapshot_id INTEGER, row_sha256 TEXT);
CREATE TABLE IF NOT EXISTS cwe_entries(
  cwe_id TEXT PRIMARY KEY, name TEXT, abstraction TEXT, status TEXT, description TEXT,
  first_snapshot_id INTEGER, last_snapshot_id INTEGER, row_sha256 TEXT);
"""
KEV_FIELDS = ("vendor", "product", "name", "date_added", "due_date", "ransomware_use", "cwes_json",
              "short_description", "required_action")
CWE_FIELDS = ("name", "abstraction", "status", "description")


def _sha(d: dict) -> str:
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()


class KBStore:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def latest_snapshot(self, source: str):
        r = self.db.execute("SELECT id, content_sha256, accepted FROM kb_snapshots WHERE source=? ORDER BY id DESC LIMIT 1", (source,)).fetchone()
        return dict(zip(("id", "content_sha256", "accepted"), r)) if r else None

    def add_snapshot(self, source, url, sha, version, raw_path, accepted, rejected, license_note) -> int:
        cur = self.db.execute(
            "INSERT INTO kb_snapshots(source, source_url, retrieved_at, content_sha256, source_version, raw_path, accepted, rejected, license_note)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (source, url, datetime.now(timezone.utc).isoformat(), sha, version, raw_path, accepted, rejected, license_note))
        self.db.commit()
        return cur.lastrowid

    def _upsert(self, table, key, fields, entries, snap_id):
        added = updated = 0
        for e in entries:
            row = {f: e[f] for f in fields}
            h = _sha(row)
            old = self.db.execute(f"SELECT row_sha256 FROM {table} WHERE {key}=?", (e[key],)).fetchone()
            if old is None:
                cols = ",".join([key, *fields, "first_snapshot_id", "last_snapshot_id", "row_sha256"])
                self.db.execute(f"INSERT INTO {table}({cols}) VALUES({','.join('?' * (len(fields) + 4))})",
                                (e[key], *[row[f] for f in fields], snap_id, snap_id, h))
                added += 1
            elif old[0] != h:
                sets = ",".join(f"{f}=?" for f in fields)
                self.db.execute(f"UPDATE {table} SET {sets}, last_snapshot_id=?, row_sha256=? WHERE {key}=?",
                                (*[row[f] for f in fields], snap_id, h, e[key]))
                updated += 1
            else:
                self.db.execute(f"UPDATE {table} SET last_snapshot_id=? WHERE {key}=?", (snap_id, e[key]))
        self.db.commit()
        return added, updated

    def upsert_kev(self, entries, snap_id):
        return self._upsert("kev_entries", "cve_id", KEV_FIELDS, entries, snap_id)

    def upsert_cwe(self, entries, snap_id):
        return self._upsert("cwe_entries", "cwe_id", CWE_FIELDS, entries, snap_id)

    def _lookup(self, table, key, value):
        cur = self.db.execute(f"SELECT * FROM {table} WHERE {key}=?", (value,))
        r = cur.fetchone()
        return dict(zip([c[0] for c in cur.description], r)) if r else None

    def kev_lookup(self, cve_id: str):
        return self._lookup("kev_entries", "cve_id", cve_id.strip().upper())

    def cwe_lookup(self, cwe_id: str):
        return self._lookup("cwe_entries", "cwe_id", cwe_id.strip().upper())

    def stale_in_latest(self, table: str, source: str) -> list:
        """IDs present in the store but absent from the newest snapshot (removed or renamed upstream)."""
        snap = self.latest_snapshot(source)
        key = "cve_id" if table == "kev_entries" else "cwe_id"
        return [r[0] for r in self.db.execute(f"SELECT {key} FROM {table} WHERE last_snapshot_id < ?", (snap["id"],))] if snap else []

    def latest_snapshot_info(self, source: str):
        r = self.db.execute("SELECT id, source_version, retrieved_at FROM kb_snapshots WHERE source=? ORDER BY id DESC LIMIT 1", (source,)).fetchone()
        return dict(zip(("id", "source_version", "retrieved_at"), r)) if r else None
