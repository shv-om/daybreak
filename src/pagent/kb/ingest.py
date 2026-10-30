from __future__ import annotations
import hashlib, os
from .sources import KBError, parse_cwe_xml, parse_kev, read_zip_text
from .store import KBStore

LICENSE_NOTE = "UNVERIFIED - check the publisher's terms before redistributing this data"
MIN_RATIO = 0.5   # refuse a snapshot that shrinks below this fraction of the previous one


def ingest(kb: KBStore, source: str, raw: bytes, url: str, raw_dir: str) -> dict:
    sha = hashlib.sha256(raw).hexdigest()
    last = kb.latest_snapshot(source)
    if last and last["content_sha256"] == sha:
        return {"status": "unchanged", "snapshot_id": last["id"]}
    if source == "kev":
        parsed, ext = parse_kev(raw.decode("utf-8")), "json"
    elif source == "cwe":
        parsed, ext = parse_cwe_xml(read_zip_text(raw) if raw[:2] == b"PK" else raw.decode("utf-8")), "xml"
    else:
        raise KBError(f"unknown source {source!r}")
    n = len(parsed["entries"])
    if n == 0:
        raise KBError("no valid entries; refusing to ingest")
    if last and last["accepted"] and n < MIN_RATIO * last["accepted"]:
        raise KBError(f"snapshot shrank from {last['accepted']} to {n} entries; refusing to ingest")
    os.makedirs(raw_dir, exist_ok=True)
    raw_path = os.path.join(raw_dir, f"{source}-{sha[:12]}.{ext if raw[:2] != b'PK' else 'zip'}")
    with open(raw_path, "wb") as f:
        f.write(raw)
    snap = kb.add_snapshot(source, url, sha, parsed["version"], raw_path, n, len(parsed["rejects"]), LICENSE_NOTE)
    added, updated = (kb.upsert_kev if source == "kev" else kb.upsert_cwe)(parsed["entries"], snap)
    return {"status": "ingested", "snapshot_id": snap, "source_version": parsed["version"], "accepted": n,
            "rejected": len(parsed["rejects"]), "duplicates": len(parsed["duplicates"]), "added": added,
            "updated": updated, "warnings": parsed["warnings"][:10], "reject_samples": parsed["rejects"][:5]}
