"""Knowledge-base store. Each source keeps its own table with provenance; nothing is merged into one 'truth' row."""
from __future__ import annotations
import json, sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_sources(
  id INTEGER PRIMARY KEY, source TEXT NOT NULL, dataset_version TEXT, url TEXT, retrieved_at REAL NOT NULL,
  content_sha256 TEXT NOT NULL, record_count INTEGER, license_note TEXT);
CREATE TABLE IF NOT EXISTS cwe(id TEXT PRIMARY KEY, name TEXT, abstraction TEXT, status TEXT, source_id INTEGER);
CREATE TABLE IF NOT EXISTS kev(cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, vuln_name TEXT, date_added TEXT,
  due_date TEXT, ransomware_use TEXT, cwes_json TEXT, source_id INTEGER);
CREATE TABLE IF NOT EXISTS nvd_cve(cve_id TEXT PRIMARY KEY, found INTEGER NOT NULL, published TEXT, last_modified TEXT,
  vuln_status TEXT, description_en TEXT, weaknesses_json TEXT, raw_sha256 TEXT, retrieved_at REAL, source_id INTEGER);
CREATE TABLE IF NOT EXISTS epss(cve_id TEXT PRIMARY KEY, found INTEGER NOT NULL, epss REAL, percentile REAL,
  score_date TEXT, retrieved_at REAL, source_id INTEGER);
"""
LICENSE_NOTE = "See the publisher's terms of use; not independently reviewed. Check before redistributing."


class KB:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def add_source(self, source, version, url, retrieved_at, sha256, count) -> int:
        cur = self.db.execute("INSERT INTO kb_sources(source, dataset_version, url, retrieved_at, content_sha256, record_count, license_note)"
                              " VALUES(?,?,?,?,?,?,?)", (source, version, url, retrieved_at, sha256, count, LICENSE_NOTE))
        self.db.commit()
        return cur.lastrowid

    def latest_source(self, source: str):
        r = self.db.execute("SELECT id, dataset_version, retrieved_at, content_sha256, record_count FROM kb_sources "
                            "WHERE source=? ORDER BY id DESC LIMIT 1", (source,)).fetchone()
        return None if r is None else dict(zip(("id", "version", "retrieved_at", "sha256", "count"), r))

    def replace_cwe(self, rows, source_id):
        with self.db:
            self.db.execute("DELETE FROM cwe")
            self.db.executemany("INSERT INTO cwe VALUES(?,?,?,?,?)", [(r["id"], r["name"], r["abstraction"], r["status"], source_id) for r in rows])

    def replace_kev(self, rows, source_id):
        with self.db:
            self.db.execute("DELETE FROM kev")
            self.db.executemany("INSERT INTO kev VALUES(?,?,?,?,?,?,?,?,?)", [
                (r["cve_id"], r["vendor"], r["product"], r["vuln_name"], r["date_added"], r["due_date"],
                 r["ransomware_use"], json.dumps(r["cwes"]), source_id) for r in rows])

    def upsert_nvd(self, rec, source_id, retrieved_at):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO nvd_cve VALUES(?,?,?,?,?,?,?,?,?,?)", (
                rec["cve_id"], int(rec["found"]), rec.get("published"), rec.get("last_modified"), rec.get("vuln_status"),
                rec.get("description_en"), json.dumps(rec.get("weaknesses", [])), rec.get("raw_sha256"), retrieved_at, source_id))

    def upsert_epss(self, rec, source_id, retrieved_at):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO epss VALUES(?,?,?,?,?,?,?)", (
                rec["cve_id"], int(rec["found"]), rec.get("epss"), rec.get("percentile"), rec.get("date"), retrieved_at, source_id))

    def _one(self, sql, args, cols):
        r = self.db.execute(sql, args).fetchone()
        return None if r is None else dict(zip(cols, r))

    def get_cwe(self, cwe_id: str):
        return self._one("SELECT c.id, c.name, s.dataset_version, s.retrieved_at FROM cwe c JOIN kb_sources s ON s.id=c.source_id WHERE c.id=?",
                         (cwe_id,), ("id", "name", "catalog_version", "retrieved_at"))

    def get_kev(self, cve_id):
        return self._one("SELECT k.cve_id, k.vendor, k.product, k.date_added, k.due_date, k.ransomware_use, s.dataset_version, s.retrieved_at "
                         "FROM kev k JOIN kb_sources s ON s.id=k.source_id WHERE k.cve_id=?", (cve_id,),
                         ("cve_id", "vendor", "product", "date_added", "due_date", "ransomware_use", "catalog_version", "retrieved_at"))

    def get_nvd(self, cve_id):
        r = self._one("SELECT cve_id, found, published, last_modified, vuln_status, description_en, weaknesses_json, retrieved_at FROM nvd_cve WHERE cve_id=?",
                      (cve_id,), ("cve_id", "found", "published", "last_modified", "vuln_status", "description_en", "weaknesses", "retrieved_at"))
        if r:
            r["weaknesses"] = json.loads(r["weaknesses"] or "[]")
        return r

    def get_epss(self, cve_id):
        return self._one("SELECT cve_id, found, epss, percentile, score_date, retrieved_at FROM epss WHERE cve_id=?", (cve_id,),
                         ("cve_id", "found", "epss", "percentile", "score_date", "retrieved_at"))
