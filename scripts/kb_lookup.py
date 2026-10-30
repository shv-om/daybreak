"""python scripts/kb_lookup.py CVE-2021-44228   |   python scripts/kb_lookup.py CWE-79"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pagent.kb.store import KBStore
kb, q = KBStore("data/kb.db"), sys.argv[1]
r = kb.kev_lookup(q) if q.upper().startswith("CVE-") else kb.cwe_lookup(q)
print(json.dumps(r, indent=2) if r else f"{q}: not in the local knowledge base (absence from KEV does not mean 'not exploited')")
