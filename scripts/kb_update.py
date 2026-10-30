"""python scripts/kb_update.py kev            (downloads from the fixed CISA URL)
   python scripts/kb_update.py cwe            (downloads from the fixed MITRE URL)
   python scripts/kb_update.py kev --file x.json   (offline: ingest a local copy)"""
import argparse, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.kb.fetch import ALLOWED, fetch_source
from pagent.kb.ingest import ingest
from pagent.kb.store import KBStore

ap = argparse.ArgumentParser()
ap.add_argument("source", choices=sorted(ALLOWED))
ap.add_argument("--file")
ap.add_argument("--db", default="data/kb.db")
ap.add_argument("--raw-dir", default="data/kb/raw")
a = ap.parse_args()
os.makedirs(os.path.dirname(a.db), exist_ok=True)
if a.file:
    url, raw = "local-file:" + os.path.basename(a.file), open(a.file, "rb").read()
else:
    url, raw = fetch_source(a.source)
print(json.dumps(ingest(KBStore(a.db), a.source, raw, url, a.raw_dir), indent=2))
